//! Remote Desktop (RDP) sessions, with IronRDP doing the protocol work.
//!
//! Connecting goes: TCP (directly, or tunnelled through an SSH jump host) → TLS, with the
//! server's certificate checked like an SSH host key (trusted on first use, a change is
//! flagged) → Network Level Authentication with the host's saved password → the desktop.
//!
//! The screen is decoded here and streamed to the tab's canvas (see desktop.rs). When the tab's
//! area changes size, the remote desktop is resized to match (Display Control channel), so
//! there's no scaling or scrollbars.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse,
    FormatDataRequest, FormatDataResponse, LockDataId, OwnedFormatDataResponse,
};
use ironrdp_cliprdr::{Cliprdr, CliprdrClient};
use ironrdp_connector::connection_activation::ConnectionActivationState;
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{ClientConnector, ConnectionResult, ConnectorErrorKind, ConnectorResult, Credentials, DesktopSize};
use ironrdp_core::{impl_as_any, WriteBuf};
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_displaycontrol::pdu::MonitorLayoutEntry;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags, SynchronizeFlags};
use ironrdp_pdu::input::mouse::PointerFlags;
use ironrdp_pdu::input::mouse_x::PointerXFlags;
use ironrdp_pdu::input::{MousePdu, MouseXPdu};
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput, GracefulDisconnectReason};
use ironrdp_tokio::{single_sequence_step_read, split_tokio_framed, FramedWrite as _};
use serde_json::{json, Value};
use tauri::ipc::InvokeResponseBody;
use tokio::sync::mpsc;

use crate::desktop::{self, boxed, error_chain, ClipState, Clipboard, Cmd, Ev, Rect, Screen, Stream, RESIZE_SETTLE};
use crate::ssh::{self, Ctx, Input, Relay};
use crate::store::Host;

pub async fn run_session(
    ctx: Ctx,
    host_id: String,
    width: u32,
    height: u32,
    scale: u32,
    data: Relay<InvokeResponseBody>,
    clipboard: Option<Arc<dyn Clipboard>>,
    mut rx: mpsc::UnboundedReceiver<Input>,
) {
    match session(&ctx, &host_id, (width, height, scale), &data, clipboard, &mut rx).await {
        Ok(msg) => ctx.status("closed", msg),
        Err(e) => ctx.status("error", format!("{e:#}")),
    }
}

type Framed = ironrdp_tokio::TokioFramed<Box<dyn Stream>>;

/// Kerberos would need to reach a domain controller; Nimbus signs in with NTLM, which works
/// for local and domain accounts alike.
struct NoKerberos;

impl ironrdp_tokio::NetworkClient for NoKerberos {
    async fn send(&mut self, _: &NetworkRequest) -> ConnectorResult<Vec<u8>> {
        Err(ironrdp_connector::general_err!("Kerberos is not supported"))
    }
}

fn even_size(w: u32, h: u32) -> (u16, u16) {
    let (w, h) = MonitorLayoutEntry::adjust_display_size(w, h);
    (u16::try_from(w).unwrap_or(1920), u16::try_from(h).unwrap_or(1080))
}

fn clamp_scale(scale: u32) -> u32 {
    scale.clamp(100, 500)
}

/// "DOMAIN\user" splits into user and domain; "user@domain" is passed as it is.
fn split_user(user: &str, domain: Option<&str>) -> (String, Option<String>) {
    if let Some((d, u)) = user.split_once('\\') {
        return (u.to_string(), Some(d.to_string()).filter(|d| !d.is_empty()));
    }
    (user.to_string(), domain.map(str::trim).filter(|d| !d.is_empty()).map(String::from))
}

fn cert_key(target: &str) -> String {
    format!("rdp://{target}")
}

enum Attempt {
    Ok(Box<(ConnectionResult, Framed)>),
    Untrusted(String),
    BadLogin(String),
    Failed(anyhow::Error),
}

async fn session(
    ctx: &Ctx,
    host_id: &str,
    (width, height, scale): (u32, u32, u32),
    data: &Relay<InvokeResponseBody>,
    clipboard: Option<Arc<dyn Clipboard>>,
    rx: &mut mpsc::UnboundedReceiver<Input>,
) -> anyhow::Result<String> {
    let host = ctx
        .store
        .lock()
        .unwrap()
        .effective_host(host_id)
        .ok_or_else(|| anyhow!("This host no longer exists"))?;
    let name = ssh::display_name(&host);
    if host.address.trim().is_empty() {
        bail!("“{name}” has no address");
    }
    let port = host.port.unwrap_or(3389);
    let target = format!("{}:{port}", host.address);

    let user = match host.username.clone().filter(|u| !u.trim().is_empty()) {
        Some(u) => u,
        None => {
            let v = ctx
                .ask("text", json!({ "title": "Username", "message": format!("Which user should sign in to {name}?") }))
                .await
                .ok_or_else(|| anyhow!("Cancelled"))?;
            v.get("value").and_then(Value::as_str).unwrap_or("").trim().to_string()
        }
    };
    let (username, domain) = split_user(&user, host.domain.as_deref());
    let (mut password, mut trusted) = {
        let s = ctx.store.lock().unwrap();
        (s.secret(&host.id).password, s.known_host(&cert_key(&target)).map(|k| k.fingerprint.clone()))
    };
    let mut save = false;
    let mut failures = 0;
    if password.is_none() {
        let (p, s) = ctx
            .ask_secret("password", "Password", format!("Password for {user} on {name}"), true)
            .await
            .ok_or_else(|| anyhow!("Cancelled"))?;
        password = Some(p);
        save = s;
    }

    let size = even_size(width, height);
    let scale = clamp_scale(scale);
    let share_clipboard = host.share_clipboard && clipboard.is_some();
    let mut jumps = Vec::new();
    let (connection, framed) = loop {
        ctx.status("connecting", format!("Connecting to {target}…"));
        let config = connector_config(&username, password.clone().unwrap_or_default(), domain.clone(), size, scale);
        let (clip_tx, clip_rx) = mpsc::unbounded_channel();
        let backend = share_clipboard.then(|| ClipBackend { tx: clip_tx });
        let attempt = attempt(ctx, &host, &target, config, trusted.clone(), backend, &mut jumps).await;
        match attempt {
            Attempt::Ok(done) => {
                if save {
                    let (id, pw) = (host.id.clone(), password.clone());
                    ctx.save_store(|s| s.update_secret(&id, |sec| sec.password = pw));
                }
                let (connection, framed) = *done;
                break (connection, (framed, clip_rx));
            }
            Attempt::Untrusted(fp) => {
                let note = "Remote Desktop servers usually identify themselves with a certificate they made themselves, so your computer can't vouch for it. Trust it if this is the computer you meant to reach; Nimbus will warn you if it ever changes.";
                if !desktop::trust_certificate(ctx, &cert_key(&target), &format!("{target} (Remote Desktop)"), &fp, trusted.as_deref(), note).await {
                    bail!("The certificate for {target} was not trusted, so the connection was cancelled");
                }
                trusted = Some(fp);
            }
            Attempt::BadLogin(why) => {
                failures += 1;
                if failures > 3 {
                    bail!("Sign-in failed for {user} on {name}: {why}");
                }
                ctx.status("authenticating", format!("Signing in as {user}…"));
                let (p, s) = ctx
                    .ask_secret("password", "Password", format!("That didn't work ({why}). Try the password for {user} on {name} again."), true)
                    .await
                    .ok_or_else(|| anyhow!("Cancelled"))?;
                password = Some(p);
                save = s;
            }
            Attempt::Failed(e) => return Err(e),
        }
    };
    let (framed, clip_rx) = framed;

    desktop::connected(ctx, host_id);
    let result = active(framed, connection, data, rx, clip_rx, clipboard.filter(|_| share_clipboard), scale).await;
    desktop::close_jumps(&mut jumps).await;
    result
}

fn connector_config(username: &str, password: String, domain: Option<String>, size: (u16, u16), scale: u32) -> ironrdp_connector::Config {
    ironrdp_connector::Config {
        credentials: Credentials::UsernamePassword { username: username.to_string(), password },
        domain,
        // NLA when the server offers it; plain TLS for servers without it (xrdp, older Windows).
        enable_tls: true,
        enable_credssp: true,
        enable_standard_rdp_security: false,
        monitor_layout: None,
        connection_type: ironrdp_pdu::gcc::ConnectionType::Lan,
        remote_application_mode: false,
        rail_support_level: ironrdp_pdu::rdp::capability_sets::RailSupportLevel::empty(),
        enable_audio_capture: false,
        support_dyn_vc_gfx_protocol: false,
        keyboard_type: ironrdp_pdu::gcc::KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize { width: size.0, height: size.1 },
        desktop_scale_factor: scale,
        bitmap: Some(ironrdp_connector::BitmapConfig {
            lossy_compression: true,
            color_depth: 32,
            codecs: ironrdp_pdu::rdp::capability_sets::client_codecs_capabilities(&[]).unwrap_or_default(),
        }),
        client_build: 0,
        client_name: "Nimbus".into(),
        client_dir: String::new(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        platform: if cfg!(target_os = "macos") {
            MajorPlatformType::MACINTOSH
        } else if cfg!(windows) {
            MajorPlatformType::WINDOWS
        } else {
            MajorPlatformType::UNIX
        },
        hardware_id: None,
        request_data: None,
        // Without NLA, the server uses these credentials instead of showing its sign-in screen.
        autologon: true,
        enable_audio_playback: false,
        performance_flags: PerformanceFlags::default(),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        // Bulk compression is off: screen updates are already compressed by their codecs, and
        // IronRDP can't yet read compressed messages while a resize re-activates the session.
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: false,
        multitransport_flags: None,
    }
}

/// One go at connecting: network, TLS, sign-in.
async fn attempt(
    ctx: &Ctx,
    host: &Host,
    target: &str,
    config: ironrdp_connector::Config,
    trusted: Option<String>,
    clipboard: Option<ClipBackend>,
    jumps: &mut Vec<russh::client::Handle<ssh::Client>>,
) -> Attempt {
    let (stream, client_addr) = match desktop::open_stream(ctx, host, host.port.unwrap_or(3389), jumps).await {
        Ok(s) => s,
        Err(e) => return Attempt::Failed(e),
    };

    let mut connector = ClientConnector::new(config, client_addr).with_static_channel(
        ironrdp_dvc::DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new()))),
    );
    if let Some(backend) = clipboard {
        connector.attach_static_channel(Cliprdr::new(Box::new(backend)));
    }

    match tokio::time::timeout(Duration::from_secs(45), handshake(ctx, stream, connector, &host.address, trusted)).await {
        Ok(r) => r,
        Err(_) => Attempt::Failed(anyhow!("{target} stopped responding while connecting")),
    }
}

async fn handshake(ctx: &Ctx, stream: Box<dyn Stream>, mut connector: ClientConnector, server: &str, trusted: Option<String>) -> Attempt {
    let mut framed = ironrdp_tokio::TokioFramed::new(stream);
    let should_upgrade = match boxed(ironrdp_tokio::connect_begin(&mut framed, &mut connector)).await {
        Ok(u) => u,
        Err(e) => return Attempt::Failed(connect_error(e)),
    };
    let (stream, leftover) = framed.into_inner();

    let rejected = Arc::new(Mutex::new(None));
    let tls = match crate::files::tofu_tls_config(trusted, rejected.clone(), true).map(Arc::new) {
        Ok(c) => tokio_rustls::TlsConnector::from(c),
        Err(e) => return Attempt::Failed(e),
    };
    let server_name = match tokio_rustls::rustls::pki_types::ServerName::try_from(server.to_string()) {
        Ok(n) => n,
        Err(_) => return Attempt::Failed(anyhow!("“{server}” isn't a valid host name")),
    };
    let tls_stream = match tls.connect(server_name, stream).await {
        Ok(s) => s,
        Err(e) => {
            if let Some(fp) = rejected.lock().unwrap().take() {
                return Attempt::Untrusted(fp);
            }
            return Attempt::Failed(anyhow!("Secure connection failed: {e}"));
        }
    };
    let public_key = match tls_stream.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| server_public_key(c.as_ref())) {
        Some(Ok(k)) => k,
        Some(Err(e)) => return Attempt::Failed(e),
        None => return Attempt::Failed(anyhow!("The server sent no certificate")),
    };

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let stream: Box<dyn Stream> = Box::new(tls_stream);
    let mut framed = ironrdp_tokio::TokioFramed::new_with_leftover(stream, leftover);
    ctx.status("authenticating", "Signing in…");
    let result = boxed(ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut NoKerberos,
        ironrdp_connector::ServerName::new(server),
        public_key,
        None,
    ))
    .await;
    match result {
        Ok(r) => Attempt::Ok(Box::new((r, framed))),
        Err(e) => match e.kind() {
            ConnectorErrorKind::Credssp(err) => Attempt::BadLogin(credssp_reason(err)),
            ConnectorErrorKind::AccessDenied => Attempt::BadLogin("access denied".into()),
            _ => Attempt::Failed(connect_error(e)),
        },
    }
}

fn credssp_reason(e: &ironrdp_connector::sspi::Error) -> String {
    use ironrdp_connector::sspi::ErrorKind as K;
    match e.error_type {
        K::LogonDenied => "wrong user name or password".into(),
        _ => e.description.clone(),
    }
}

fn connect_error(e: ironrdp_connector::ConnectorError) -> anyhow::Error {
    match e.kind() {
        ConnectorErrorKind::Negotiation(f) => anyhow!("The server refused the connection: {f}"),
        _ => anyhow!("Remote Desktop connection failed: {}", error_chain(&e)),
    }
}

fn server_public_key(der: &[u8]) -> anyhow::Result<Vec<u8>> {
    use x509_cert::der::Decode as _;
    let cert = x509_cert::Certificate::from_der(der).map_err(|e| anyhow!("The server's certificate can't be read: {e}"))?;
    cert.tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow!("The server's certificate has no usable public key"))
}

// ---------- clipboard ----------

enum ClipMsg {
    /// The remote is ready for our clipboard (or asked for it).
    Offer,
    /// The remote copied something: fetch it in this format.
    Fetch(ClipboardFormatId),
    /// The remote wants the clipboard we offered, in this format.
    Request(ClipboardFormatId),
    /// What the remote had copied.
    Received(String),
}

#[derive(Debug)]
struct ClipBackend {
    tx: mpsc::UnboundedSender<ClipMsg>,
}

impl ClipBackend {
    fn send(&self, m: ClipMsg) {
        let _ = self.tx.send(m);
    }
}

impl std::fmt::Debug for ClipMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClipMsg")
    }
}

impl_as_any!(ClipBackend);

impl CliprdrBackend for ClipBackend {
    fn temporary_directory(&self) -> &str {
        ""
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }

    fn on_ready(&mut self) {
        self.send(ClipMsg::Offer);
    }

    fn on_request_format_list(&mut self) {
        self.send(ClipMsg::Offer);
    }

    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}

    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        let has = |id: ClipboardFormatId| formats.iter().any(|f| f.id() == id);
        if has(ClipboardFormatId::CF_UNICODETEXT) {
            self.send(ClipMsg::Fetch(ClipboardFormatId::CF_UNICODETEXT));
        } else if has(ClipboardFormatId::CF_TEXT) {
            self.send(ClipMsg::Fetch(ClipboardFormatId::CF_TEXT));
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        self.send(ClipMsg::Request(request.format));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if response.is_error() {
            return;
        }
        // Text arrives as UTF-16 (CF_UNICODETEXT) or 8-bit (CF_TEXT), ending with a nul.
        let text = response.to_unicode_string().ok().filter(|t| !t.contains('\u{fffd}')).or_else(|| response.to_string().ok());
        if let Some(t) = text {
            self.send(ClipMsg::Received(t));
        }
    }

    fn on_file_contents_request(&mut self, _: FileContentsRequest) {}
    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}
    fn on_lock(&mut self, _: LockDataId) {}
    fn on_unlock(&mut self, _: LockDataId) {}
}

// ---------- the running session ----------

fn to_fastpath(ev: &Ev) -> Option<FastPathInputEvent> {
    Some(match *ev {
        Ev::Move { x, y } => FastPathInputEvent::MouseEvent(MousePdu { flags: PointerFlags::MOVE, number_of_wheel_rotation_units: 0, x_position: x, y_position: y }),
        Ev::Button { x, y, b, d } => {
            let down = |f| if d { f } else { PointerFlags::empty() };
            match b {
                0 => FastPathInputEvent::MouseEvent(MousePdu { flags: PointerFlags::LEFT_BUTTON | down(PointerFlags::DOWN), number_of_wheel_rotation_units: 0, x_position: x, y_position: y }),
                1 => FastPathInputEvent::MouseEvent(MousePdu { flags: PointerFlags::MIDDLE_BUTTON_OR_WHEEL | down(PointerFlags::DOWN), number_of_wheel_rotation_units: 0, x_position: x, y_position: y }),
                2 => FastPathInputEvent::MouseEvent(MousePdu { flags: PointerFlags::RIGHT_BUTTON | down(PointerFlags::DOWN), number_of_wheel_rotation_units: 0, x_position: x, y_position: y }),
                3 | 4 => {
                    let button = if b == 3 { PointerXFlags::BUTTON1 } else { PointerXFlags::BUTTON2 };
                    let flags = if d { button | PointerXFlags::DOWN } else { button };
                    FastPathInputEvent::MouseEventEx(MouseXPdu { flags, x_position: x, y_position: y })
                }
                _ => return None,
            }
        }
        Ev::Wheel { x, y, v, h } => FastPathInputEvent::MouseEvent(MousePdu {
            flags: if h { PointerFlags::HORIZONTAL_WHEEL } else { PointerFlags::VERTICAL_WHEEL },
            number_of_wheel_rotation_units: v.clamp(-255, 255),
            x_position: x,
            y_position: y,
        }),
        Ev::Key { c, e, d, .. } => {
            let mut f = KeyboardFlags::empty();
            if !d {
                f |= KeyboardFlags::RELEASE;
            }
            if e {
                f |= KeyboardFlags::EXTENDED;
            }
            FastPathInputEvent::KeyboardEvent(f, c)
        }
        Ev::Unicode { c, d } => FastPathInputEvent::UnicodeKeyboardEvent(if d { KeyboardFlags::empty() } else { KeyboardFlags::RELEASE }, c),
        Ev::Sync { f } => FastPathInputEvent::SyncEvent(SynchronizeFlags::from_bits_truncate(f)),
        Ev::Clipboard => return None,
    })
}

async fn active(
    framed: Framed,
    connection: ConnectionResult,
    out: &Relay<InvokeResponseBody>,
    rx: &mut mpsc::UnboundedReceiver<Input>,
    mut clip_rx: mpsc::UnboundedReceiver<ClipMsg>,
    clipboard: Option<Arc<dyn Clipboard>>,
    mut scale: u32,
) -> anyhow::Result<String> {
    let (mut reader, mut writer) = split_tokio_framed(framed);
    let desktop = connection.desktop_size;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, desktop.width, desktop.height);
    let activation_factory = connection.activation_factory;
    let mut stage: ActiveStage = ActiveStageBuilder {
        static_channels: connection.static_channels,
        user_channel_id: connection.user_channel_id,
        io_channel_id: connection.io_channel_id,
        message_channel_id: connection.message_channel_id,
        share_id: connection.share_id,
        compression_type: connection.compression_type,
        enable_server_pointer: connection.enable_server_pointer,
        pointer_software_rendering: connection.pointer_software_rendering,
    }
    .build();

    let mut screen = Screen::default();
    let _ = out.send(desktop::size_msg(image.width(), image.height()));
    // What the desktop is now; and the size the tab wants, and when it last changed (resizes
    // wait for it to settle).
    let mut size = (image.width(), image.height());
    let mut wanted: Option<((u16, u16), u32, Instant)> = None;
    let mut resize_supported = true;
    let mut clip = ClipState::default();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_clip_drive = Instant::now();

    let reason = 'outer: loop {
        let outputs: Vec<ActiveStageOutput> = tokio::select! {
            frame = boxed(reader.read_pdu()) => {
                let (action, payload) = frame.map_err(|e| anyhow!("The connection was lost: {e}"))?;
                stage.process(&mut image, action, &payload).map_err(|e| anyhow!("Remote Desktop error: {}", error_chain(&e)))?
            }
            input = rx.recv() => match input {
                None | Some(Input::Close) => {
                    if let Ok(frames) = stage.graceful_shutdown() {
                        for o in frames {
                            if let ActiveStageOutput::ResponseFrame(f) = o {
                                let _ = boxed(writer.write_all(&f)).await;
                            }
                        }
                    }
                    break 'outer None;
                }
                Some(Input::Desktop(Cmd::Input(events))) => {
                    let mut fast = Vec::with_capacity(events.len());
                    for ev in &events {
                        if matches!(ev, Ev::Clipboard) {
                            // Offer before the keys that follow (a paste), so they find it there.
                            if let Some(frames) = offer_clipboard(&mut stage, clipboard.as_deref(), &mut clip, false)? {
                                boxed(writer.write_all(&frames)).await?;
                            }
                        } else if let Some(f) = to_fastpath(ev) {
                            fast.push(f);
                        }
                    }
                    if fast.is_empty() { Vec::new() } else { stage.process_fastpath_input(&mut image, &fast)? }
                }
                Some(Input::Desktop(Cmd::Type(text))) => {
                    let mut fast = Vec::new();
                    for ch in text.chars() {
                        if ch == '\r' {
                            fast.push(FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), 0x1c));
                            fast.push(FastPathInputEvent::KeyboardEvent(KeyboardFlags::RELEASE, 0x1c));
                            continue;
                        }
                        let mut units = [0u16; 2];
                        for &u in ch.encode_utf16(&mut units).iter() {
                            fast.push(FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::empty(), u));
                            fast.push(FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::RELEASE, u));
                        }
                    }
                    stage.process_fastpath_input(&mut image, &fast)?
                }
                Some(Input::Desktop(Cmd::Resize { width, height, scale: s })) => {
                    wanted = Some((even_size(width, height), clamp_scale(s), Instant::now()));
                    Vec::new()
                }
                Some(Input::Desktop(Cmd::Ack(seq))) => {
                    screen.ack(seq);
                    screen.flush(image.width(), image.height(), image.data(), out);
                    Vec::new()
                }
                Some(Input::Desktop(Cmd::Refresh)) => {
                    screen.refresh(image.width(), image.height(), image.data(), out);
                    Vec::new()
                }
                Some(_) => Vec::new(),
            },
            Some(m) = clip_rx.recv() => {
                let frames = match m {
                    ClipMsg::Offer => offer_clipboard(&mut stage, clipboard.as_deref(), &mut clip, true)?,
                    ClipMsg::Fetch(format) => match stage.get_svc_processor_mut::<CliprdrClient>() {
                        Some(c) => {
                            let msgs = c.initiate_paste(format)?;
                            Some(stage.process_svc_processor_messages(msgs)?)
                        }
                        None => None,
                    },
                    ClipMsg::Request(format) => {
                        let text = clip.offered.clone().unwrap_or_default();
                        let response: OwnedFormatDataResponse = if format == ClipboardFormatId::CF_UNICODETEXT {
                            FormatDataResponse::new_unicode_string(&text)
                        } else if format == ClipboardFormatId::CF_TEXT {
                            FormatDataResponse::new_string(&text)
                        } else {
                            FormatDataResponse::new_error()
                        };
                        match stage.get_svc_processor_mut::<CliprdrClient>() {
                            Some(c) => {
                                let msgs = c.submit_format_data(response)?;
                                Some(stage.process_svc_processor_messages(msgs)?)
                            }
                            None => None,
                        }
                    }
                    ClipMsg::Received(text) => {
                        if let Some(cb) = &clipboard {
                            cb.write(text.clone());
                        }
                        clip.received = Some(text);
                        None
                    }
                };
                match frames {
                    Some(f) if !f.is_empty() => vec![ActiveStageOutput::ResponseFrame(f)],
                    _ => Vec::new(),
                }
            }
            _ = tick.tick() => {
                let mut outs = Vec::new();
                screen.unstick();
                screen.flush(image.width(), image.height(), image.data(), out);
                if let Some((sz, sc, at)) = wanted {
                    if (sz, sc) == (size, scale) {
                        wanted = None;
                    } else if resize_supported && at.elapsed() >= RESIZE_SETTLE {
                        let available = stage.get_dvc::<DisplayControlClient>().is_some();
                        match stage.encode_resize(u32::from(sz.0), u32::from(sz.1), Some(sc), None) {
                            Some(frame) => {
                                outs.push(ActiveStageOutput::ResponseFrame(frame?));
                                (size, scale) = (sz, sc);
                                wanted = None;
                            }
                            // Not connected yet: try again on the next tick. Not offered at all:
                            // the UI scales the desktop to fit instead.
                            None if !available => resize_supported = false,
                            None => {}
                        }
                    }
                }
                if last_clip_drive.elapsed() > Duration::from_secs(5) {
                    last_clip_drive = Instant::now();
                    if let Some(c) = stage.get_svc_processor_mut::<CliprdrClient>() {
                        if let Ok(msgs) = c.drive_timeouts() {
                            let f = stage.process_svc_processor_messages(msgs)?;
                            if !f.is_empty() {
                                outs.push(ActiveStageOutput::ResponseFrame(f));
                            }
                        }
                    }
                }
                outs
            }
        };

        let mut drew = false;
        for o in outputs {
            match o {
                ActiveStageOutput::ResponseFrame(f) => boxed(writer.write_all(&f)).await.map_err(|e| anyhow!("The connection was lost: {e}"))?,
                ActiveStageOutput::GraphicsUpdate(r) => {
                    screen.add(rect(&r));
                    drew = true;
                }
                ActiveStageOutput::PointerDefault => {
                    screen.pointer = None;
                    let _ = out.send(InvokeResponseBody::Raw(vec![5u8]));
                }
                ActiveStageOutput::PointerHidden => screen.set_pointer(vec![4u8], out),
                ActiveStageOutput::PointerBitmap(p) => {
                    screen.set_pointer(desktop::pointer_msg(p.width, p.height, p.hotspot_x, p.hotspot_y, &p.bitmap_data), out)
                }
                ActiveStageOutput::Terminate(reason) => break 'outer Some(reason),
                ActiveStageOutput::DeactivateAll => {
                    // The desktop is being resized (or reconfigured): run the reactivation, then
                    // start over with a fresh screen.
                    let mut activation = activation_factory.create();
                    let mut buf = WriteBuf::new();
                    loop {
                        let written = boxed(single_sequence_step_read(&mut reader, &mut activation, &mut buf))
                            .await
                            .map_err(|e| anyhow!("Remote Desktop error while resizing: {}", error_chain(&e)))?;
                        if written.size().is_some() {
                            boxed(writer.write_all(buf.filled())).await?;
                        }
                        if let ConnectionActivationState::Finalized {
                            desktop_size,
                            share_id,
                            enable_server_pointer,
                            pointer_software_rendering,
                            static_channel_chunk_size,
                            ..
                        } = activation.connection_activation_state()
                        {
                            image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            if !stage.reactivate(
                                activation.io_channel_id(),
                                activation.user_channel_id(),
                                share_id,
                                enable_server_pointer,
                                pointer_software_rendering,
                                static_channel_chunk_size,
                            ) {
                                bail!("The server sent an invalid configuration while resizing");
                            }
                            screen.reset();
                            let _ = out.send(desktop::size_msg(desktop_size.width, desktop_size.height));
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
        if drew {
            screen.flush(image.width(), image.height(), image.data(), out);
        }
    };

    Ok(match reason {
        None => "Disconnected".into(),
        Some(r) => disconnect_message(&r),
    })
}

fn disconnect_message(r: &GracefulDisconnectReason) -> String {
    match r {
        GracefulDisconnectReason::UserInitiated => "Disconnected".into(),
        other => {
            let d = other.description();
            let mut c = d.chars();
            match c.next() {
                Some(f) => format!("Session ended: {}{}", f.to_lowercase(), c.as_str()),
                None => "Session ended".into(),
            }
        }
    }
}

/// Offer this computer's clipboard text to the remote. `always` re-sends it even when unchanged
/// (the remote asked); otherwise only new text is offered.
fn offer_clipboard(
    stage: &mut ActiveStage,
    clipboard: Option<&dyn Clipboard>,
    clip: &mut ClipState,
    always: bool,
) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(cb) = clipboard else { return Ok(None) };
    let Some(text) = clip.fresh(cb, always) else { return Ok(None) };
    let formats: Vec<ClipboardFormat> = match &text {
        Some(_) => vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)],
        None => vec![],
    };
    let Some(c) = stage.get_svc_processor_mut::<CliprdrClient>() else { return Ok(None) };
    let msgs = c.initiate_copy(&formats)?;
    Ok(Some(stage.process_svc_processor_messages(msgs)?))
}

fn rect(r: &InclusiveRectangle) -> Rect {
    Rect { left: r.left, top: r.top, right: r.right, bottom: r.bottom }
}
