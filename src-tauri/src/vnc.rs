//! VNC sessions (the RFB protocol, RFC 6143, plus the common extensions), for Linux desktops
//! (TigerVNC, x11vnc, wayvnc), Raspberry Pis, Mac Screen Sharing and virtual machine consoles.
//!
//! Connecting goes: TCP (directly, or tunnelled through an SSH jump host) → version and
//! security handshake → the desktop. Sign-in, best first:
//!   - VeNCrypt with a certificate (TigerVNC, Proxmox): TLS, the certificate trusted on first
//!     use like an SSH host key, then a VNC password or user name and password inside it;
//!   - Apple's Screen Sharing sign-in (a Mac user name and password, sent encrypted);
//!   - the classic VNC password (a challenge, so the password itself isn't sent, though the
//!     session isn't encrypted: use a jump host to protect it on untrusted networks);
//!   - none, when the server asks for nothing.
//!
//! The screen is decoded into an RGBA frame buffer here (Tight with JPEG, ZRLE, Hextile,
//! CopyRect, Raw) and streamed to the tab like a Remote Desktop one (see desktop.rs). When the
//! server supports it, the remote desktop is resized to fit the tab; otherwise the tab scales
//! the picture. Keys go as X11 keysyms (what the key types), or as keysym plus scancode where
//! the server takes both (QEMU / Proxmox consoles), which keeps any keyboard layout right.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _};
use flate2::{Decompress, FlushDecompress};
use num_bigint::BigUint;
use serde_json::{json, Value};
use tauri::ipc::InvokeResponseBody;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::desktop::{self, ClipState, Clipboard, Cmd, Ev, Rect, Screen, Stream, RESIZE_SETTLE};
use crate::ssh::{self, Ctx, Input, Relay};

// Encodings (RFC 6143 §7.7, and the registry at rfbproto).
const RAW: i32 = 0;
const COPY_RECT: i32 = 1;
const HEXTILE: i32 = 5;
const TIGHT: i32 = 7;
const ZRLE: i32 = 16;
const CURSOR: i32 = -239;
const DESKTOP_SIZE: i32 = -223;
const LAST_RECT: i32 = -224;
const QEMU_KEY: i32 = -258;
const EXT_DESKTOP_SIZE: i32 = -308;
const EXT_CLIPBOARD: i32 = 0xC0A1E5CEu32 as i32;
/// Tight's JPEG quality 8 of 9, and zlib level 2 (quick to compress).
const JPEG_QUALITY: i32 = -24;
const COMPRESS_LEVEL: i32 = -254;

/// What Nimbus asks for, best first.
const ENCODINGS: &[i32] = &[COPY_RECT, TIGHT, ZRLE, HEXTILE, RAW, CURSOR, DESKTOP_SIZE, EXT_DESKTOP_SIZE, LAST_RECT, QEMU_KEY, EXT_CLIPBOARD, JPEG_QUALITY, COMPRESS_LEVEL];

/// Tests: ask for only these encodings, to exercise each decoder.
#[cfg(test)]
pub(crate) static TEST_ENCODINGS: Mutex<Option<Vec<i32>>> = Mutex::new(None);

fn encodings() -> Vec<i32> {
    #[cfg(test)]
    if let Some(e) = TEST_ENCODINGS.lock().unwrap().clone() {
        return e;
    }
    ENCODINGS.to_vec()
}

// Extended clipboard flags.
const CLIP_TEXT: u32 = 1;
const CLIP_CAPS: u32 = 1 << 24;
const CLIP_REQUEST: u32 = 1 << 25;
const CLIP_NOTIFY: u32 = 1 << 27;
const CLIP_PROVIDE: u32 = 1 << 28;

/// Larger than any real screen or clipboard; stops a broken or hostile server asking us to
/// allocate without limit.
const MAX_DIM: u16 = 16384;
const MAX_TEXT: usize = 32 << 20;

pub async fn run_session(
    ctx: Ctx,
    host_id: String,
    width: u32,
    height: u32,
    data: Relay<InvokeResponseBody>,
    clipboard: Option<Arc<dyn Clipboard>>,
    mut rx: mpsc::UnboundedReceiver<Input>,
) {
    match session(&ctx, &host_id, (width, height), &data, clipboard, &mut rx).await {
        Ok(msg) => ctx.status("closed", msg),
        Err(e) => ctx.status("error", format!("{e:#}")),
    }
}

fn cert_key(target: &str) -> String {
    format!("vnc://{target}")
}

enum Attempt {
    Ok(Box<Connected>),
    Untrusted(String),
    /// The password (or user name and password) was refused.
    BadLogin(String),
    /// This kind of sign-in needs a user name.
    NeedUser,
    Failed(anyhow::Error),
}

struct Connected {
    stream: Box<dyn Stream>,
    width: u16,
    height: u16,
    name: String,
}

struct Login {
    user: Option<String>,
    password: Option<String>,
}

async fn session(
    ctx: &Ctx,
    host_id: &str,
    wanted: (u32, u32),
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
    let port = host.port.unwrap_or(5900);
    let target = format!("{}:{port}", host.address);
    let (password, mut trusted) = {
        let s = ctx.store.lock().unwrap();
        (s.secret(&host.id).password, s.known_host(&cert_key(&target)).map(|k| k.fingerprint.clone()))
    };
    let mut login = Login { user: host.username.clone().filter(|u| !u.trim().is_empty()), password };
    let mut save = false;
    let mut failures = 0;
    let mut jumps = Vec::new();

    let conn = loop {
        ctx.status("connecting", format!("Connecting to {target}…"));
        let attempt = match desktop::open_stream(ctx, &host, port, &mut jumps).await {
            Ok((stream, _)) => match tokio::time::timeout(Duration::from_secs(45), handshake(ctx, stream, &host.address, &mut login, trusted.clone())).await {
                Ok(a) => a,
                Err(_) => Attempt::Failed(anyhow!("{target} stopped responding while connecting")),
            },
            Err(e) => Attempt::Failed(e),
        };
        match attempt {
            Attempt::Ok(c) => break c,
            Attempt::Untrusted(fp) => {
                let note = "VNC servers usually identify themselves with a certificate they made themselves, so your computer can't vouch for it. Trust it if this is the computer you meant to reach; Nimbus will warn you if it ever changes.";
                if !desktop::trust_certificate(ctx, &cert_key(&target), &format!("{target} (VNC)"), &fp, trusted.as_deref(), note).await {
                    bail!("The certificate for {target} was not trusted, so the connection was cancelled");
                }
                trusted = Some(fp);
            }
            Attempt::NeedUser => {
                let v = ctx
                    .ask("text", json!({ "title": "User name", "message": format!("{name} asks for a user name and password. Which user?") }))
                    .await
                    .ok_or_else(|| anyhow!("Cancelled"))?;
                login.user = v.get("value").and_then(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
                if login.password.is_none() {
                    let (p, s) = ctx.ask_secret("password", "Password", format!("Password for {name}"), true).await.ok_or_else(|| anyhow!("Cancelled"))?;
                    login.password = Some(p);
                    save = s;
                }
            }
            Attempt::BadLogin(why) => {
                failures += 1;
                if failures > 3 {
                    bail!("Sign-in to {name} failed: {why}");
                }
                let msg = if login.password.is_none() { format!("Password for {name}") } else { format!("That didn't work ({why}). Try the password for {name} again.") };
                let (p, s) = ctx.ask_secret("password", "Password", msg, true).await.ok_or_else(|| anyhow!("Cancelled"))?;
                login.password = Some(p);
                save = s;
            }
            Attempt::Failed(e) => return Err(e),
        }
    };
    if save {
        let (id, pw) = (host.id.clone(), login.password.clone());
        ctx.save_store(|s| s.update_secret(&id, |sec| sec.password = pw));
    }

    desktop::connected(ctx, host_id);
    let share = host.share_clipboard;
    let result = active(*conn, wanted, data, rx, clipboard.filter(|_| share)).await;
    desktop::close_jumps(&mut jumps).await;
    result
}

// ---------- connecting ----------

async fn read_u8<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<u8> {
    r.read_u8().await
}

async fn read_string<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> anyhow::Result<String> {
    let len = r.read_u32().await? as usize;
    if len > max {
        bail!("The server sent a message that's too long");
    }
    let mut b = vec![0; len];
    r.read_exact(&mut b).await?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// Version, security and initialisation.
async fn handshake(ctx: &Ctx, mut s: Box<dyn Stream>, server: &str, login: &mut Login, trusted: Option<String>) -> Attempt {
    match handshake_inner(ctx, &mut s, server, login, trusted).await {
        Ok(Step::Done(stream, width, height, name)) => Attempt::Ok(Box::new(Connected { stream, width, height, name })),
        Ok(Step::Plain) => match init(s).await {
            Ok((stream, width, height, name)) => Attempt::Ok(Box::new(Connected { stream, width, height, name })),
            Err(e) => Attempt::Failed(e),
        },
        Ok(Step::Untrusted(fp)) => Attempt::Untrusted(fp),
        Ok(Step::BadLogin(why)) => Attempt::BadLogin(why),
        Ok(Step::NeedUser) => Attempt::NeedUser,
        Err(e) => Attempt::Failed(e),
    }
}

enum Step {
    /// Signed in on the plain connection: carry on with it.
    Plain,
    /// Signed in inside TLS, and initialised.
    Done(Box<dyn Stream>, u16, u16, String),
    Untrusted(String),
    BadLogin(String),
    NeedUser,
}

async fn handshake_inner(ctx: &Ctx, s: &mut Box<dyn Stream>, server: &str, login: &mut Login, trusted: Option<String>) -> anyhow::Result<Step> {
    let mut v = [0u8; 12];
    s.read_exact(&mut v).await.context("The server closed the connection (is this a VNC server?)")?;
    let text = std::str::from_utf8(&v).unwrap_or("");
    let (major, minor) = text
        .strip_prefix("RFB ")
        .and_then(|t| t.trim_end().split_once('.'))
        .and_then(|(a, b)| Some((a.parse::<u32>().ok()?, b.parse::<u32>().ok()?)))
        .ok_or_else(|| anyhow!("This isn't a VNC server (it said {:?})", text.trim_end()))?;
    // 3.8 is the newest; Apple's "003.889" behaves like it.
    let minor = if major > 3 || minor >= 8 { 8 } else if minor >= 7 { 7 } else { 3 };
    s.write_all(format!("RFB 003.00{minor}\n").as_bytes()).await?;

    let offered: Vec<u8> = if minor >= 7 {
        let n = read_u8(s).await? as usize;
        if n == 0 {
            let why = read_string(s, 4096).await.unwrap_or_default();
            bail!("The server refused the connection: {why}");
        }
        let mut t = vec![0; n];
        s.read_exact(&mut t).await?;
        t
    } else {
        let t = s.read_u32().await?;
        if t == 0 {
            let why = read_string(s, 4096).await.unwrap_or_default();
            bail!("The server refused the connection: {why}");
        }
        vec![t as u8]
    };

    // Best first. Apple's sign-in needs a user name, so with none saved the VNC password
    // (if the Mac offers it) comes first.
    let has = |t: u8| offered.contains(&t);
    let order: Vec<u8> = if login.user.is_some() { vec![19, 30, 2, 1] } else { vec![19, 2, 1, 30] };
    let chosen = order
        .into_iter()
        .find(|t| has(*t))
        .ok_or_else(|| anyhow!("Nimbus can't sign in to this server: it only offers {} (supported: VNC password, VeNCrypt with a certificate, Apple sign-in)", offered.iter().map(|t| security_name(*t)).collect::<Vec<_>>().join(", ")))?;
    if minor >= 7 {
        s.write_u8(chosen).await?;
    }

    match chosen {
        1 => {
            if minor >= 8 {
                return security_result(s, minor).await;
            }
            Ok(Step::Plain)
        }
        2 => {
            let Some(pw) = login.password.clone() else { return Ok(Step::BadLogin("a password is needed".into())) };
            vnc_auth(s, &pw).await?;
            security_result(s, minor).await
        }
        30 => {
            let (Some(user), Some(pw)) = (login.user.clone(), login.password.clone()) else {
                return Ok(if login.user.is_none() { Step::NeedUser } else { Step::BadLogin("a password is needed".into()) });
            };
            apple_auth(s, &user, &pw).await?;
            security_result(s, minor).await
        }
        19 => vencrypt(ctx, s, server, login, trusted, minor).await,
        _ => unreachable!(),
    }
}

fn security_name(t: u8) -> String {
    match t {
        1 => "no password".into(),
        2 => "VNC password".into(),
        5..=16 => "RealVNC encryption".into(),
        18 => "TLS".into(),
        19 => "VeNCrypt".into(),
        30 => "Apple sign-in".into(),
        33 | 35 | 36 => "Apple encrypted sign-in".into(),
        n => format!("type {n}"),
    }
}

async fn security_result<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, minor: u32) -> anyhow::Result<Step> {
    match s.read_u32().await? {
        0 => Ok(Step::Plain),
        _ => {
            let why = if minor >= 8 { read_string(s, 4096).await.unwrap_or_default() } else { String::new() };
            Ok(Step::BadLogin(if why.trim().is_empty() { "the server refused the password".into() } else { why.trim().to_string() }))
        }
    }
}

/// The classic VNC password: DES-encrypt the server's challenge with the password (8
/// characters at most) as the key, each byte's bits mirrored, as the original VNC did.
async fn vnc_auth<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, password: &str) -> anyhow::Result<()> {
    use des::cipher::{BlockEncrypt, KeyInit};
    let mut challenge = [0u8; 16];
    s.read_exact(&mut challenge).await?;
    let mut key = [0u8; 8];
    for (k, b) in key.iter_mut().zip(password.bytes()) {
        *k = b.reverse_bits();
    }
    let cipher = des::Des::new_from_slice(&key).map_err(|_| anyhow!("bad key"))?;
    for block in challenge.chunks_exact_mut(8) {
        cipher.encrypt_block(block.into());
    }
    s.write_all(&challenge).await?;
    Ok(())
}

/// Apple's Screen Sharing sign-in: Diffie-Hellman with the server's numbers, then the user
/// name and password encrypted with AES under the MD5 of the shared secret.
async fn apple_auth<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, user: &str, password: &str) -> anyhow::Result<()> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use md5::Digest as _;
    let generator = s.read_u16().await?;
    let len = s.read_u16().await? as usize;
    if !(8..=1024).contains(&len) {
        bail!("The Mac sent an unexpected sign-in request");
    }
    let mut prime = vec![0; len];
    s.read_exact(&mut prime).await?;
    let mut server_key = vec![0; len];
    s.read_exact(&mut server_key).await?;
    let p = BigUint::from_bytes_be(&prime);
    let private = BigUint::from_bytes_be(&crate::vault::random_bytes::<128>()) % &p;
    let public = BigUint::from(generator).modpow(&private, &p);
    let shared = BigUint::from_bytes_be(&server_key).modpow(&private, &p);
    let pad = |n: BigUint| {
        let b = n.to_bytes_be();
        let mut out = vec![0u8; len.saturating_sub(b.len())];
        out.extend_from_slice(&b[b.len().saturating_sub(len)..]);
        out
    };
    let key = md5::Md5::digest(pad(shared));
    // 64 bytes of user name, 64 of password, each ending in a nul; the rest random.
    let mut creds = crate::vault::random_bytes::<128>();
    for (field, text) in [(0usize, user), (64, password)] {
        let b = text.as_bytes();
        let n = b.len().min(63);
        creds[field..field + n].copy_from_slice(&b[..n]);
        creds[field + n] = 0;
    }
    let cipher = aes::Aes128::new_from_slice(&key).map_err(|_| anyhow!("bad key"))?;
    for block in creds.chunks_exact_mut(16) {
        cipher.encrypt_block(block.into());
    }
    s.write_all(&creds).await?;
    s.write_all(&pad(public)).await?;
    Ok(())
}

/// VeNCrypt: TLS with the server's certificate (trusted on first use), then the sign-in inside.
/// Anonymous TLS isn't offered by modern TLS libraries, so the certificate kinds are the ones
/// Nimbus uses.
async fn vencrypt(ctx: &Ctx, s: &mut Box<dyn Stream>, server: &str, login: &mut Login, trusted: Option<String>, minor: u32) -> anyhow::Result<Step> {
    let (major, sub) = (read_u8(s).await?, read_u8(s).await?);
    if (major, sub) < (0, 2) {
        bail!("This server's VeNCrypt is too old (version {major}.{sub})");
    }
    s.write_all(&[0, 2]).await?;
    if read_u8(s).await? != 0 {
        bail!("The server refused VeNCrypt version 0.2");
    }
    let n = read_u8(s).await? as usize;
    let mut types = Vec::with_capacity(n);
    for _ in 0..n {
        types.push(s.read_u32().await?);
    }
    // X509None, X509Vnc, X509Plain: TLS with a certificate.
    let x509_vnc = types.contains(&261);
    let x509_plain = types.contains(&262);
    let x509_none = types.contains(&260);
    let pick = if x509_plain && (login.user.is_some() || !x509_vnc) {
        262
    } else if x509_vnc {
        261
    } else if x509_none {
        260
    } else {
        bail!("This server only offers VeNCrypt without a certificate (anonymous TLS), which Nimbus can't use. Give the server a certificate (X509 security types) or allow a VNC password, and connect through a jump host to keep it private.");
    };
    if pick == 262 && login.user.is_none() {
        return Ok(Step::NeedUser);
    }
    s.write_u32(pick).await?;
    if read_u8(s).await? != 1 {
        bail!("The server refused the VeNCrypt sign-in it offered");
    }

    let rejected = Arc::new(Mutex::new(None));
    let tls = tokio_rustls::TlsConnector::from(Arc::new(crate::files::tofu_tls_config(trusted, rejected.clone(), false)?));
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(server.to_string()).map_err(|_| anyhow!("“{server}” isn't a valid host name"))?;
    let plain = std::mem::replace(s, Box::new(tokio::io::duplex(1).0));
    let mut tls = match tls.connect(name, plain).await {
        Ok(t) => t,
        Err(e) => {
            if let Some(fp) = rejected.lock().unwrap().take() {
                return Ok(Step::Untrusted(fp));
            }
            bail!("Secure connection failed: {e}");
        }
    };
    let _ = ctx;
    match pick {
        261 => {
            let Some(pw) = login.password.clone() else { return Ok(Step::BadLogin("a password is needed".into())) };
            vnc_auth(&mut tls, &pw).await?;
        }
        262 => {
            let (user, pw) = (login.user.clone().unwrap_or_default(), login.password.clone());
            let Some(pw) = pw else { return Ok(Step::BadLogin("a password is needed".into())) };
            tls.write_u32(user.len() as u32).await?;
            tls.write_u32(pw.len() as u32).await?;
            tls.write_all(user.as_bytes()).await?;
            tls.write_all(pw.as_bytes()).await?;
        }
        _ => {}
    }
    match security_result(&mut tls, minor).await? {
        Step::Plain => {
            let (stream, w, h, name) = init(Box::new(tls)).await?;
            Ok(Step::Done(stream, w, h, name))
        }
        other => Ok(other),
    }
}

/// Share the desktop (don't disconnect others), learn its size, and set the pixel format:
/// 32-bit, red in the lowest byte, so pixels arrive as R, G, B, unused — RGBA without alpha.
async fn init(mut s: Box<dyn Stream>) -> anyhow::Result<(Box<dyn Stream>, u16, u16, String)> {
    s.write_u8(1).await?;
    let width = s.read_u16().await?;
    let height = s.read_u16().await?;
    let mut format = [0u8; 16];
    s.read_exact(&mut format).await?;
    let name = read_string(&mut s, 4096).await?;
    if width > MAX_DIM || height > MAX_DIM {
        bail!("The remote screen is too large ({width}×{height})");
    }
    let mut m = vec![0u8, 0, 0, 0];
    m.extend_from_slice(&[32, 24, 0, 1]);
    for v in [255u16, 255, 255] {
        m.extend_from_slice(&v.to_be_bytes());
    }
    m.extend_from_slice(&[0, 8, 16, 0, 0, 0]);
    s.write_all(&m).await?;
    Ok((s, width, height, name))
}

// ---------- the running session ----------

/// The remote screen as RGBA.
struct Fb {
    width: u16,
    height: u16,
    data: Vec<u8>,
}

impl Fb {
    fn new(width: u16, height: u16) -> Fb {
        Fb { width, height, data: vec![0; usize::from(width) * usize::from(height) * 4] }
    }

    fn check(&self, x: u16, y: u16, w: u16, h: u16) -> anyhow::Result<()> {
        if u32::from(x) + u32::from(w) > u32::from(self.width) || u32::from(y) + u32::from(h) > u32::from(self.height) {
            bail!("The server sent an update outside the screen");
        }
        Ok(())
    }

    /// Write rows of 4-byte pixels (R, G, B, x) into the rectangle.
    fn put(&mut self, x: u16, y: u16, w: u16, h: u16, px: &[u8]) {
        let stride = usize::from(self.width) * 4;
        let row = usize::from(w) * 4;
        for r in 0..usize::from(h) {
            let at = (usize::from(y) + r) * stride + usize::from(x) * 4;
            self.data[at..at + row].copy_from_slice(&px[r * row..r * row + row]);
        }
    }

    fn fill(&mut self, x: u16, y: u16, w: u16, h: u16, c: [u8; 4]) {
        let stride = usize::from(self.width) * 4;
        for r in 0..usize::from(h) {
            let at = (usize::from(y) + r) * stride + usize::from(x) * 4;
            for p in self.data[at..at + usize::from(w) * 4].chunks_exact_mut(4) {
                p.copy_from_slice(&c);
            }
        }
    }

    fn copy(&mut self, sx: u16, sy: u16, x: u16, y: u16, w: u16, h: u16) {
        let stride = usize::from(self.width) * 4;
        let row = usize::from(w) * 4;
        let rows: Vec<usize> = if sy < y { (0..usize::from(h)).rev().collect() } else { (0..usize::from(h)).collect() };
        for r in rows {
            let from = (usize::from(sy) + r) * stride + usize::from(sx) * 4;
            let to = (usize::from(y) + r) * stride + usize::from(x) * 4;
            self.data.copy_within(from..from + row, to);
        }
    }
}

/// What the reader sends the session loop.
enum Event {
    Damaged(Rect),
    /// A whole update has arrived: send it to the tab, and ask for the next.
    UpdateDone,
    Resized { width: u16, height: u16 },
    /// The server can resize its desktop (ExtendedDesktopSize), with this screen id.
    CanResize(u32),
    QemuKeys,
    Pointer(Vec<u8>),
    /// Text the remote copied.
    Cut(String),
    /// The server speaks the extended clipboard (UTF-8) and wants our capabilities.
    ClipCaps,
    /// The remote copied something (extended clipboard): ask for the text.
    ClipNotify,
    /// The remote wants the text we offered.
    ClipRequest,
}

async fn active(
    conn: Connected,
    (want_w, want_h): (u32, u32),
    out: &Relay<InvokeResponseBody>,
    rx: &mut mpsc::UnboundedReceiver<Input>,
    clipboard: Option<Arc<dyn Clipboard>>,
) -> anyhow::Result<String> {
    let _ = conn.name;
    let fb = Arc::new(Mutex::new(Fb::new(conn.width, conn.height)));
    let (read_half, mut w) = tokio::io::split(conn.stream);
    let (ev_tx, mut events) = mpsc::unbounded_channel();
    let mut reader = tauri::async_runtime::spawn(read_loop(BufReader::with_capacity(256 * 1024, read_half), fb.clone(), ev_tx));

    // Encodings, then a full update.
    let enc = encodings();
    let mut m = vec![2u8, 0];
    m.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    for e in &enc {
        m.extend_from_slice(&e.to_be_bytes());
    }
    w.write_all(&m).await?;
    request_update(&mut w, &fb, false).await?;

    let mut screen = Screen::default();
    let _ = out.send(desktop::size_msg(conn.width, conn.height));
    let _ = out.send(InvokeResponseBody::Raw(vec![5u8]));
    let mut resize: Option<u32> = None; // the screen id, once the server says it can resize
    let mut wanted: Option<((u16, u16), Instant)> = Some((fit(want_w, want_h), Instant::now() - RESIZE_SETTLE));
    let mut asked: Option<(u16, u16)> = None;
    let mut qemu_keys = false;
    let mut ext_clip = false;
    let mut clip = ClipState::default();
    let mut buttons = 0u8;
    let mut wheel = (0i32, 0i32);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let result: anyhow::Result<String> = loop {
        tokio::select! {
            ev = events.recv() => match ev {
                None => {
                    // The reader stopped: why?
                    break match (&mut reader).await {
                        Ok(Err(e)) => Err(e),
                        _ => Ok("Connection closed".into()),
                    };
                }
                Some(Event::Damaged(r)) => screen.add(r),
                Some(Event::UpdateDone) => {
                    {
                        let f = fb.lock().unwrap();
                        screen.flush(f.width, f.height, &f.data, out);
                    }
                    request_update(&mut w, &fb, true).await?;
                }
                Some(Event::Resized { width, height }) => {
                    screen.reset();
                    let _ = out.send(desktop::size_msg(width, height));
                    if asked == Some((width, height)) {
                        asked = None;
                    }
                }
                Some(Event::CanResize(id)) => resize = Some(id),
                Some(Event::QemuKeys) => qemu_keys = true,
                Some(Event::Pointer(m)) => screen.set_pointer(m, out),
                Some(Event::Cut(text)) => {
                    if let Some(cb) = &clipboard {
                        if clip.received.as_deref() != Some(&text) {
                            cb.write(text.clone());
                        }
                        clip.received = Some(text);
                    }
                }
                Some(Event::ClipCaps) => {
                    ext_clip = true;
                    // We handle text, up to the limit, and ask, notify and provide.
                    let mut m = clip_header(CLIP_CAPS | CLIP_REQUEST | CLIP_NOTIFY | CLIP_PROVIDE | CLIP_TEXT, 4);
                    m.extend_from_slice(&(MAX_TEXT as u32).to_be_bytes());
                    w.write_all(&m).await?;
                    if let Some(cb) = clipboard.as_deref() {
                        offer(&mut w, cb, &mut clip, ext_clip, true).await?;
                    }
                }
                Some(Event::ClipNotify) => {
                    if clipboard.is_some() {
                        w.write_all(&clip_header(CLIP_REQUEST | CLIP_TEXT, 0)).await?;
                    }
                }
                Some(Event::ClipRequest) => {
                    let text = clip.offered.clone().unwrap_or_default();
                    let mut body = Vec::new();
                    let mut t = text.into_bytes();
                    t.push(0);
                    body.extend_from_slice(&(t.len() as u32).to_be_bytes());
                    body.extend_from_slice(&t);
                    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                    std::io::Write::write_all(&mut z, &body)?;
                    let packed = z.finish()?;
                    let mut m = clip_header(CLIP_PROVIDE | CLIP_TEXT, packed.len());
                    m.extend_from_slice(&packed);
                    w.write_all(&m).await?;
                }
            },
            input = rx.recv() => match input {
                None | Some(Input::Close) => break Ok("Disconnected".into()),
                Some(Input::Desktop(Cmd::Input(evs))) => {
                    let mut m = Vec::new();
                    for ev in evs {
                        match ev {
                            Ev::Move { x, y } => pointer(&mut m, buttons, x, y),
                            Ev::Button { x, y, b, d } => {
                                let bit = match b { 0 => 1, 1 => 2, 2 => 4, _ => 0 };
                                if bit == 0 { continue; }
                                if d { buttons |= bit } else { buttons &= !bit }
                                pointer(&mut m, buttons, x, y);
                            }
                            Ev::Wheel { x, y, v, h } => {
                                // A click of the wheel per 120 units (trackpads send fractions).
                                let acc = if h { &mut wheel.1 } else { &mut wheel.0 };
                                *acc += i32::from(v);
                                while acc.abs() >= 120 {
                                    let up = *acc > 0;
                                    *acc -= if up { 120 } else { -120 };
                                    let bit = match (h, up) { (false, true) => 8, (false, false) => 16, (true, false) => 32, (true, true) => 64 };
                                    pointer(&mut m, buttons | bit, x, y);
                                    pointer(&mut m, buttons, x, y);
                                }
                            }
                            Ev::Key { c, e, d, k } => key(&mut m, qemu_keys, k, Some((c, e)), d),
                            Ev::Unicode { c, d } => key(&mut m, false, char_keysym(u32::from(c)), None, d),
                            Ev::Sync { .. } => {}
                            Ev::Clipboard => {
                                // Offer before the keys that follow (a paste), so they find it there.
                                w.write_all(&m).await?;
                                m.clear();
                                if let Some(cb) = clipboard.as_deref() {
                                    offer(&mut w, cb, &mut clip, ext_clip, false).await?;
                                }
                            }
                        }
                    }
                    if !m.is_empty() {
                        w.write_all(&m).await?;
                    }
                }
                Some(Input::Desktop(Cmd::Type(text))) => {
                    let mut m = Vec::new();
                    for ch in text.chars() {
                        let k = if ch == '\r' { 0xff0d } else { char_keysym(ch as u32) };
                        key(&mut m, false, k, None, true);
                        key(&mut m, false, k, None, false);
                    }
                    w.write_all(&m).await?;
                }
                Some(Input::Desktop(Cmd::Resize { width, height, .. })) => wanted = Some((fit(width, height), Instant::now())),
                Some(Input::Desktop(Cmd::Ack(seq))) => {
                    screen.ack(seq);
                    let f = fb.lock().unwrap();
                    screen.flush(f.width, f.height, &f.data, out);
                }
                Some(Input::Desktop(Cmd::Refresh)) => {
                    let f = fb.lock().unwrap();
                    screen.refresh(f.width, f.height, &f.data, out);
                }
                Some(_) => {}
            },
            _ = tick.tick() => {
                screen.unstick();
                {
                    let f = fb.lock().unwrap();
                    screen.flush(f.width, f.height, &f.data, out);
                }
                // Resize the remote desktop to the tab, once the size has settled.
                if let (Some(id), Some((size, at))) = (resize, wanted) {
                    let current = { let f = fb.lock().unwrap(); (f.width, f.height) };
                    if size == current || Some(size) == asked {
                        wanted = None;
                    } else if at.elapsed() >= RESIZE_SETTLE {
                        let mut m = vec![251u8, 0];
                        m.extend_from_slice(&size.0.to_be_bytes());
                        m.extend_from_slice(&size.1.to_be_bytes());
                        m.extend_from_slice(&[1, 0]);
                        m.extend_from_slice(&id.to_be_bytes());
                        m.extend_from_slice(&[0, 0, 0, 0]);
                        m.extend_from_slice(&size.0.to_be_bytes());
                        m.extend_from_slice(&size.1.to_be_bytes());
                        m.extend_from_slice(&[0, 0, 0, 0]);
                        w.write_all(&m).await?;
                        asked = Some(size);
                        wanted = None;
                    }
                }
            }
        }
    };
    reader.abort();
    let _ = w.shutdown().await;
    result
}

/// The tab's size in whole pixels, within what servers accept.
fn fit(w: u32, h: u32) -> (u16, u16) {
    (w.clamp(320, 8192) as u16, h.clamp(200, 8192) as u16)
}

async fn request_update<W: AsyncWrite + Unpin>(w: &mut W, fb: &Arc<Mutex<Fb>>, incremental: bool) -> anyhow::Result<()> {
    let (fw, fh) = { let f = fb.lock().unwrap(); (f.width, f.height) };
    let mut m = vec![3u8, u8::from(incremental), 0, 0, 0, 0];
    m.extend_from_slice(&fw.to_be_bytes());
    m.extend_from_slice(&fh.to_be_bytes());
    w.write_all(&m).await?;
    Ok(())
}

fn pointer(m: &mut Vec<u8>, mask: u8, x: u16, y: u16) {
    m.push(5);
    m.push(mask);
    m.extend_from_slice(&x.to_be_bytes());
    m.extend_from_slice(&y.to_be_bytes());
}

/// A key press or release: the keysym, plus the scancode where the server takes it (QEMU).
fn key(m: &mut Vec<u8>, qemu: bool, keysym: u32, scancode: Option<(u8, bool)>, down: bool) {
    match scancode.filter(|(c, _)| qemu && *c != 0) {
        Some((c, e)) => {
            m.extend_from_slice(&[255, 0]);
            m.extend_from_slice(&u16::from(down).to_be_bytes());
            m.extend_from_slice(&keysym.to_be_bytes());
            let code = u32::from(c & 0x7f) | if e { 0x80 } else { 0 };
            m.extend_from_slice(&code.to_be_bytes());
        }
        None if keysym != 0 => {
            m.extend_from_slice(&[4, u8::from(down), 0, 0]);
            m.extend_from_slice(&keysym.to_be_bytes());
        }
        None => {}
    }
}

/// The keysym for a character: Latin-1 directly, anything else as a Unicode keysym.
fn char_keysym(c: u32) -> u32 {
    match c {
        0x20..=0x7e | 0xa0..=0xff => c,
        _ => 0x0100_0000 | c,
    }
}

fn clip_header(flags: u32, len: usize) -> Vec<u8> {
    let mut m = vec![6u8, 0, 0, 0];
    // A negative length marks an extended clipboard message.
    m.extend_from_slice(&(-((len + 4) as i32)).to_be_bytes());
    m.extend_from_slice(&flags.to_be_bytes());
    m
}

/// Offer this computer's clipboard to the remote (only when it changed, unless `always`).
async fn offer<W: AsyncWrite + Unpin>(w: &mut W, cb: &dyn Clipboard, clip: &mut ClipState, ext: bool, always: bool) -> anyhow::Result<()> {
    let Some(text) = clip.fresh(cb, always) else { return Ok(()) };
    if ext {
        // Tell the server there's text; it asks for it when someone pastes.
        let flags = if text.is_some() { CLIP_NOTIFY | CLIP_TEXT } else { CLIP_NOTIFY };
        w.write_all(&clip_header(flags, 0)).await?;
    } else if let Some(t) = text {
        // The original clipboard message carries Latin-1 only.
        let latin1: Vec<u8> = t.chars().map(|c| if (c as u32) < 256 { c as u8 } else { b'?' }).collect();
        let mut m = vec![6u8, 0, 0, 0];
        m.extend_from_slice(&(latin1.len() as u32).to_be_bytes());
        m.extend_from_slice(&latin1);
        w.write_all(&m).await?;
    }
    Ok(())
}

// ---------- reading what the server sends ----------

struct Decoders {
    zrle: Decompress,
    tight: [Decompress; 4],
    buf: Vec<u8>,
}

async fn read_loop<R: AsyncRead + Unpin>(mut r: R, fb: Arc<Mutex<Fb>>, tx: mpsc::UnboundedSender<Event>) -> anyhow::Result<()> {
    let mut dec = Decoders { zrle: Decompress::new(true), tight: std::array::from_fn(|_| Decompress::new(true)), buf: Vec::new() };
    let send = |e: Event| tx.send(e).map_err(|_| anyhow!("session ended"));
    loop {
        let kind = match r.read_u8().await {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => bail!("The server closed the connection"),
            Err(e) => bail!("The connection was lost: {e}"),
        };
        match kind {
            0 => {
                r.read_u8().await?;
                let n = r.read_u16().await?;
                for _ in 0..n {
                    let (x, y, w, h) = (r.read_u16().await?, r.read_u16().await?, r.read_u16().await?, r.read_u16().await?);
                    let enc = r.read_i32().await?;
                    match enc {
                        LAST_RECT => break,
                        DESKTOP_SIZE | EXT_DESKTOP_SIZE => {
                            let mut screen_id = None;
                            if enc == EXT_DESKTOP_SIZE {
                                let screens = r.read_u8().await?;
                                let mut pad = [0u8; 3];
                                r.read_exact(&mut pad).await?;
                                for i in 0..screens {
                                    let mut s = [0u8; 16];
                                    r.read_exact(&mut s).await?;
                                    if i == 0 {
                                        screen_id = Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]));
                                    }
                                }
                                send(Event::CanResize(screen_id.unwrap_or(0)))?;
                                // x is why it changed (1: our request), y is whether it worked.
                                if x == 1 && y != 0 {
                                    continue;
                                }
                            }
                            if w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM {
                                continue;
                            }
                            let changed = { let f = fb.lock().unwrap(); (f.width, f.height) != (w, h) };
                            if changed {
                                *fb.lock().unwrap() = Fb::new(w, h);
                                send(Event::Resized { width: w, height: h })?;
                            }
                        }
                        CURSOR => {
                            let px = usize::from(w) * usize::from(h) * 4;
                            let mask_len = usize::from(w).div_ceil(8) * usize::from(h);
                            let mut b = vec![0; px + mask_len];
                            r.read_exact(&mut b).await?;
                            if w == 0 || h == 0 {
                                // No shape (a bare X desktop): a small dot, so the pointer
                                // never disappears.
                                send(Event::Pointer(dot_cursor()))?;
                                continue;
                            }
                            let (pixels, mask) = b.split_at_mut(px);
                            let row = usize::from(w).div_ceil(8);
                            for yy in 0..usize::from(h) {
                                for xx in 0..usize::from(w) {
                                    let on = mask[yy * row + xx / 8] & (0x80 >> (xx % 8)) != 0;
                                    pixels[(yy * usize::from(w) + xx) * 4 + 3] = if on { 255 } else { 0 };
                                }
                            }
                            send(Event::Pointer(desktop::pointer_msg(w, h, x.min(w - 1), y.min(h - 1), pixels)))?;
                        }
                        QEMU_KEY => send(Event::QemuKeys)?,
                        _ => {
                            fb.lock().unwrap().check(x, y, w, h)?;
                            decode_rect(&mut r, &fb, &mut dec, enc, x, y, w, h).await?;
                            if let Some(rect) = Rect::at(x, y, w, h) {
                                send(Event::Damaged(rect))?;
                            }
                        }
                    }
                }
                send(Event::UpdateDone)?;
            }
            1 => {
                // Colour map: not used with true colour.
                let mut b = [0u8; 5];
                r.read_exact(&mut b).await?;
                let n = u16::from_be_bytes([b[3], b[4]]) as usize;
                let mut skip = vec![0u8; n * 6];
                r.read_exact(&mut skip).await?;
            }
            2 => {} // bell
            3 => {
                let mut pad = [0u8; 3];
                r.read_exact(&mut pad).await?;
                let len = r.read_i32().await?;
                if len >= 0 {
                    let len = len as usize;
                    if len > MAX_TEXT {
                        bail!("The server sent clipboard text that's too long");
                    }
                    let mut b = vec![0; len];
                    r.read_exact(&mut b).await?;
                    // Latin-1.
                    send(Event::Cut(b.iter().map(|&c| c as char).collect::<String>().replace("\r\n", "\n")))?;
                } else {
                    let len = (len as i64).unsigned_abs() as usize;
                    if !(4..=MAX_TEXT).contains(&len) {
                        bail!("The server sent a clipboard message that's too long");
                    }
                    let mut b = vec![0; len];
                    r.read_exact(&mut b).await?;
                    let flags = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                    if flags & CLIP_CAPS != 0 {
                        send(Event::ClipCaps)?;
                    } else if flags & CLIP_PROVIDE != 0 {
                        if let Some(t) = provided_text(&b[4..], flags) {
                            send(Event::Cut(t))?;
                        }
                    } else if flags & CLIP_NOTIFY != 0 && flags & CLIP_TEXT != 0 {
                        send(Event::ClipNotify)?;
                    } else if flags & CLIP_REQUEST != 0 && flags & CLIP_TEXT != 0 {
                        send(Event::ClipRequest)?;
                    }
                }
            }
            150 => {} // end of continuous updates
            248 => {
                // A fence (we don't ask for them, but skip one if it comes).
                let mut b = [0u8; 8];
                r.read_exact(&mut b).await?;
                let mut skip = vec![0u8; usize::from(b[7])];
                r.read_exact(&mut skip).await?;
            }
            k => bail!("The server sent a message Nimbus doesn't understand (type {k})"),
        }
    }
}

fn dot_cursor() -> Vec<u8> {
    let mut px = vec![0u8; 5 * 5 * 4];
    for y in 0..5usize {
        for x in 0..5usize {
            let d = (x as i32 - 2).pow(2) + (y as i32 - 2).pow(2);
            let c: [u8; 4] = if d <= 1 { [255, 255, 255, 255] } else if d <= 5 { [0, 0, 0, 255] } else { [0, 0, 0, 0] };
            px[(y * 5 + x) * 4..][..4].copy_from_slice(&c);
        }
    }
    desktop::pointer_msg(5, 5, 2, 2, &px)
}

/// The text in an extended clipboard "provide": zlib, then a length and the bytes for each
/// format in the flags, text first.
fn provided_text(packed: &[u8], flags: u32) -> Option<String> {
    if flags & CLIP_TEXT == 0 {
        return None;
    }
    // Servers flush rather than finish the zlib stream, so inflate what's there.
    let mut buf = Vec::new();
    let out = inflate(&mut Decompress::new(true), packed, &mut buf).ok()?;
    let len = u32::from_be_bytes(out.get(0..4)?.try_into().ok()?) as usize;
    let text = out.get(4..4 + len)?;
    let text = text.strip_suffix(&[0]).unwrap_or(text);
    Some(String::from_utf8_lossy(text).replace("\r\n", "\n"))
}

#[allow(clippy::too_many_arguments)]
async fn decode_rect<R: AsyncRead + Unpin>(r: &mut R, fb: &Arc<Mutex<Fb>>, dec: &mut Decoders, enc: i32, x: u16, y: u16, w: u16, h: u16) -> anyhow::Result<()> {
    let n = usize::from(w) * usize::from(h);
    match enc {
        RAW => {
            let mut px = vec![0; n * 4];
            r.read_exact(&mut px).await?;
            fb.lock().unwrap().put(x, y, w, h, &px);
        }
        COPY_RECT => {
            let (sx, sy) = (r.read_u16().await?, r.read_u16().await?);
            let mut f = fb.lock().unwrap();
            f.check(sx, sy, w, h)?;
            f.copy(sx, sy, x, y, w, h);
        }
        HEXTILE => hextile(r, fb, x, y, w, h).await?,
        ZRLE => {
            let len = r.read_u32().await? as usize;
            if len > 64 << 20 {
                bail!("The server sent an update that's too large");
            }
            let mut z = vec![0; len];
            r.read_exact(&mut z).await?;
            let data = inflate(&mut dec.zrle, &z, &mut dec.buf)?;
            zrle(&data, &mut fb.lock().unwrap(), x, y, w, h)?;
        }
        TIGHT => tight(r, fb, dec, x, y, w, h).await?,
        e => bail!("The server sent an update in an encoding Nimbus didn't ask for ({e})"),
    }
    Ok(())
}

/// Inflate all of `input` with a stream that carries on from earlier rectangles.
fn inflate<'a>(d: &mut Decompress, input: &[u8], out: &'a mut Vec<u8>) -> anyhow::Result<&'a [u8]> {
    out.clear();
    let start = d.total_in();
    loop {
        if out.capacity() - out.len() < 16 * 1024 {
            out.reserve(out.len().max(64 * 1024));
        }
        let used = (d.total_in() - start) as usize;
        let before = d.total_out();
        d.decompress_vec(&input[used..], out, FlushDecompress::Sync).map_err(|e| anyhow!("Bad compressed update: {e}"))?;
        let now_used = (d.total_in() - start) as usize;
        let room_left = out.capacity() > out.len();
        // Done when all the input is in and the output had room to spare.
        if now_used >= input.len() && room_left {
            break;
        }
        if now_used == used && d.total_out() == before && room_left {
            bail!("A compressed update was cut short");
        }
        if out.len() > 256 << 20 {
            bail!("A compressed update was too large");
        }
    }
    Ok(&out[..])
}

fn rgbx(p: &[u8]) -> [u8; 4] {
    [p[0], p[1], p[2], 255]
}

async fn hextile<R: AsyncRead + Unpin>(r: &mut R, fb: &Arc<Mutex<Fb>>, x: u16, y: u16, w: u16, h: u16) -> anyhow::Result<()> {
    let (mut bg, mut fg) = ([0u8, 0, 0, 255], [255u8, 255, 255, 255]);
    let mut ty = y;
    while ty < y + h {
        let th = 16.min(y + h - ty);
        let mut tx = x;
        while tx < x + w {
            let tw = 16.min(x + w - tx);
            let sub = r.read_u8().await?;
            if sub & 1 != 0 {
                let mut px = vec![0; usize::from(tw) * usize::from(th) * 4];
                r.read_exact(&mut px).await?;
                fb.lock().unwrap().put(tx, ty, tw, th, &px);
            } else {
                let mut p = [0u8; 4];
                if sub & 2 != 0 {
                    r.read_exact(&mut p).await?;
                    bg = rgbx(&p);
                }
                if sub & 4 != 0 {
                    r.read_exact(&mut p).await?;
                    fg = rgbx(&p);
                }
                fb.lock().unwrap().fill(tx, ty, tw, th, bg);
                if sub & 8 != 0 {
                    let count = r.read_u8().await?;
                    let coloured = sub & 16 != 0;
                    let mut b = vec![0u8; usize::from(count) * if coloured { 6 } else { 2 }];
                    r.read_exact(&mut b).await?;
                    let mut f = fb.lock().unwrap();
                    for s in b.chunks_exact(if coloured { 6 } else { 2 }) {
                        let (c, xy, wh) = if coloured { (rgbx(&s[..4]), s[4], s[5]) } else { (fg, s[0], s[1]) };
                        let (sx, sy) = (u16::from(xy >> 4), u16::from(xy & 15));
                        let (sw, sh) = (u16::from(wh >> 4) + 1, u16::from(wh & 15) + 1);
                        if sx + sw <= tw && sy + sh <= th {
                            f.fill(tx + sx, ty + sy, sw, sh, c);
                        }
                    }
                }
            }
            tx += 16;
        }
        ty += 16;
    }
    Ok(())
}

/// ZRLE: 64×64 tiles, each raw, solid, palette-packed or run-length encoded, with 3-byte pixels.
fn zrle(data: &[u8], fb: &mut Fb, x: u16, y: u16, w: u16, h: u16) -> anyhow::Result<()> {
    let mut at = 0usize;
    let mut take = |n: usize| -> anyhow::Result<&[u8]> {
        let s = data.get(at..at + n).ok_or_else(|| anyhow!("A ZRLE update was cut short"))?;
        at += n;
        Ok(s)
    };
    let mut ty = y;
    while ty < y + h {
        let th = 64.min(y + h - ty);
        let mut tx = x;
        while tx < x + w {
            let tw = 64.min(x + w - tx);
            let n = usize::from(tw) * usize::from(th);
            let sub = take(1)?[0];
            let mut px = vec![0u8; n * 4];
            match sub {
                0 => {
                    let raw = take(n * 3)?;
                    for (d, s) in px.chunks_exact_mut(4).zip(raw.chunks_exact(3)) {
                        d.copy_from_slice(&rgbx(s));
                    }
                }
                1 => {
                    let c = rgbx(take(3)?);
                    for d in px.chunks_exact_mut(4) {
                        d.copy_from_slice(&c);
                    }
                }
                2..=16 => {
                    let palette: Vec<[u8; 4]> = take(usize::from(sub) * 3)?.chunks_exact(3).map(rgbx).collect();
                    let bits = match sub { 2 => 1, 3..=4 => 2, _ => 4 };
                    let row = (usize::from(tw) * bits).div_ceil(8);
                    let packed = take(row * usize::from(th))?;
                    for yy in 0..usize::from(th) {
                        for xx in 0..usize::from(tw) {
                            let bit = xx * bits;
                            let byte = packed[yy * row + bit / 8];
                            let idx = (byte >> (8 - bits - bit % 8)) & ((1 << bits) - 1) as u8;
                            let c = palette.get(usize::from(idx)).copied().unwrap_or([0, 0, 0, 255]);
                            px[(yy * usize::from(tw) + xx) * 4..][..4].copy_from_slice(&c);
                        }
                    }
                }
                128 | 130..=255 => {
                    let palette: Vec<[u8; 4]> = if sub == 128 { vec![] } else { take((usize::from(sub) - 128) * 3)?.chunks_exact(3).map(rgbx).collect() };
                    let mut i = 0usize;
                    while i < n {
                        let (c, run) = if sub == 128 {
                            let c = rgbx(take(3)?);
                            (c, run_length(&mut take)?)
                        } else {
                            let b = take(1)?[0];
                            let c = palette.get(usize::from(b & 0x7f)).copied().unwrap_or([0, 0, 0, 255]);
                            (c, if b & 0x80 != 0 { run_length(&mut take)? } else { 1 })
                        };
                        for _ in 0..run.min(n - i) {
                            px[i * 4..i * 4 + 4].copy_from_slice(&c);
                            i += 1;
                        }
                    }
                }
                _ => bail!("A ZRLE update used an unknown tile type"),
            }
            fb.put(tx, ty, tw, th, &px);
            tx += 64;
        }
        ty += 64;
    }
    Ok(())
}

fn run_length<'a>(take: &mut impl FnMut(usize) -> anyhow::Result<&'a [u8]>) -> anyhow::Result<usize> {
    let mut n = 1usize;
    loop {
        let b = take(1)?[0];
        n += usize::from(b);
        if b != 255 {
            return Ok(n);
        }
    }
}

async fn compact_len<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<usize> {
    let mut n = 0usize;
    for i in 0..3 {
        let b = r.read_u8().await?;
        n |= usize::from(b & if i == 2 { 0xff } else { 0x7f }) << (7 * i);
        if b & 0x80 == 0 || i == 2 {
            break;
        }
    }
    Ok(n)
}

/// Tight: solid fills, JPEG, or zlib-compressed pixels (optionally palette or gradient filtered).
async fn tight<R: AsyncRead + Unpin>(r: &mut R, fb: &Arc<Mutex<Fb>>, dec: &mut Decoders, x: u16, y: u16, w: u16, h: u16) -> anyhow::Result<()> {
    let ctl = r.read_u8().await?;
    for i in 0..4 {
        if ctl & (1 << i) != 0 {
            dec.tight[i] = Decompress::new(true);
        }
    }
    let n = usize::from(w) * usize::from(h);
    match ctl >> 4 {
        8 => {
            let mut p = [0u8; 3];
            r.read_exact(&mut p).await?;
            fb.lock().unwrap().fill(x, y, w, h, rgbx(&p));
        }
        9 => {
            let len = compact_len(r).await?;
            let mut jpeg = vec![0; len];
            r.read_exact(&mut jpeg).await?;
            let mut d = jpeg_decoder::Decoder::new(&jpeg[..]);
            let pixels = d.decode().map_err(|e| anyhow!("Bad JPEG update: {e}"))?;
            let info = d.info().ok_or_else(|| anyhow!("Bad JPEG update"))?;
            if (info.width, info.height) != (w, h) {
                bail!("A JPEG update was the wrong size");
            }
            let mut px = vec![0u8; n * 4];
            match info.pixel_format {
                jpeg_decoder::PixelFormat::RGB24 => {
                    for (d, s) in px.chunks_exact_mut(4).zip(pixels.chunks_exact(3)) {
                        d.copy_from_slice(&rgbx(s));
                    }
                }
                jpeg_decoder::PixelFormat::L8 => {
                    for (d, &s) in px.chunks_exact_mut(4).zip(pixels.iter()) {
                        d.copy_from_slice(&[s, s, s, 255]);
                    }
                }
                _ => bail!("A JPEG update used an unsupported colour format"),
            }
            fb.lock().unwrap().put(x, y, w, h, &px);
        }
        c if c & 8 == 0 => {
            let stream = usize::from(c & 3);
            let filter = if c & 4 != 0 { r.read_u8().await? } else { 0 };
            let mut palette: Vec<[u8; 4]> = Vec::new();
            let row_bytes = match filter {
                0 | 2 => usize::from(w) * 3,
                1 => {
                    let colours = usize::from(r.read_u8().await?) + 1;
                    let mut b = vec![0u8; colours * 3];
                    r.read_exact(&mut b).await?;
                    palette = b.chunks_exact(3).map(rgbx).collect();
                    if colours == 2 { usize::from(w).div_ceil(8) } else { usize::from(w) }
                }
                f => bail!("A Tight update used an unknown filter ({f})"),
            };
            let size = row_bytes * usize::from(h);
            let data: Vec<u8> = if size < 12 {
                let mut b = vec![0; size];
                r.read_exact(&mut b).await?;
                b
            } else {
                let len = compact_len(r).await?;
                let mut z = vec![0; len];
                r.read_exact(&mut z).await?;
                inflate(&mut dec.tight[stream], &z, &mut dec.buf)?.to_vec()
            };
            if data.len() < size {
                bail!("A Tight update was cut short");
            }
            let mut px = vec![0u8; n * 4];
            match filter {
                0 => {
                    for (d, s) in px.chunks_exact_mut(4).zip(data.chunks_exact(3)) {
                        d.copy_from_slice(&rgbx(s));
                    }
                }
                1 => {
                    for yy in 0..usize::from(h) {
                        for xx in 0..usize::from(w) {
                            let idx = if palette.len() == 2 {
                                (data[yy * row_bytes + xx / 8] >> (7 - xx % 8)) & 1
                            } else {
                                data[yy * row_bytes + xx]
                            };
                            let c = palette.get(usize::from(idx)).copied().unwrap_or([0, 0, 0, 255]);
                            px[(yy * usize::from(w) + xx) * 4..][..4].copy_from_slice(&c);
                        }
                    }
                }
                _ => {
                    // Gradient: each value is predicted from its left, upper and upper-left neighbours.
                    let ww = usize::from(w);
                    let mut prev = vec![0u16; ww * 3];
                    let mut cur = vec![0u16; ww * 3];
                    for yy in 0..usize::from(h) {
                        for xx in 0..ww {
                            for c in 0..3 {
                                let left = if xx > 0 { cur[(xx - 1) * 3 + c] as i32 } else { 0 };
                                let up = prev[xx * 3 + c] as i32;
                                let ul = if xx > 0 { prev[(xx - 1) * 3 + c] as i32 } else { 0 };
                                let pred = (left + up - ul).clamp(0, 255);
                                let v = (pred + i32::from(data[(yy * ww + xx) * 3 + c])) & 0xff;
                                cur[xx * 3 + c] = v as u16;
                                px[(yy * ww + xx) * 4 + c] = v as u8;
                            }
                            px[(yy * ww + xx) * 4 + 3] = 255;
                        }
                        std::mem::swap(&mut prev, &mut cur);
                    }
                }
            }
            fb.lock().unwrap().put(x, y, w, h, &px);
        }
        _ => bail!("A Tight update used an unknown type"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plays the Mac's side of Apple's sign-in: the user name and password must come out of the
    /// key exchange and AES intact.
    #[tokio::test]
    async fn apple_sign_in_delivers_the_credentials() {
        use aes::cipher::{BlockDecrypt, KeyInit};
        use md5::Digest as _;
        // The 1024-bit MODP group (RFC 2409), as Macs use.
        let prime_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
        let p = BigUint::parse_bytes(prime_hex.as_bytes(), 16).unwrap();
        let server_private = BigUint::from_bytes_be(&crate::vault::random_bytes::<64>());
        let server_public = BigUint::from(2u32).modpow(&server_private, &p);
        let (mut client, mut server) = tokio::io::duplex(4096);
        let mac = tokio::spawn(async move {
            let mut m = vec![0u8, 2, 0, 128];
            m.extend_from_slice(&p.to_bytes_be());
            let mut pk = server_public.to_bytes_be();
            while pk.len() < 128 {
                pk.insert(0, 0);
            }
            m.extend_from_slice(&pk);
            server.write_all(&m).await.unwrap();
            let mut creds = [0u8; 128];
            server.read_exact(&mut creds).await.unwrap();
            let mut client_key = [0u8; 128];
            server.read_exact(&mut client_key).await.unwrap();
            let shared = BigUint::from_bytes_be(&client_key).modpow(&server_private, &p);
            let mut sb = shared.to_bytes_be();
            while sb.len() < 128 {
                sb.insert(0, 0);
            }
            let key = md5::Md5::digest(&sb);
            let cipher = aes::Aes128::new_from_slice(&key).unwrap();
            for block in creds.chunks_exact_mut(16) {
                cipher.decrypt_block(block.into());
            }
            let field = |b: &[u8]| String::from_utf8(b.iter().take_while(|c| **c != 0).copied().collect()).unwrap();
            (field(&creds[..64]), field(&creds[64..]))
        });
        apple_auth(&mut client, "ben", "correct horse ✓").await.unwrap();
        assert_eq!(mac.await.unwrap(), ("ben".to_string(), "correct horse ✓".to_string()));
    }

    #[test]
    fn keysyms_for_characters() {
        assert_eq!(char_keysym('a' as u32), 0x61);
        assert_eq!(char_keysym('é' as u32), 0xe9);
        assert_eq!(char_keysym('✓' as u32), 0x0100_2713);
    }
}
