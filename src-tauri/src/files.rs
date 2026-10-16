//! File browsing and transfers for the Files tab: this computer, SFTP (over an SSH host's
//! connection, including jump hosts) and FTP / FTPS.
//!
//! The UI names a pane by session id, with `"local"` meaning this computer. Paths always come
//! from the backend (each listing's `path` and each entry's `path`), so the UI never joins
//! paths itself: Windows paths and the POSIX paths servers use differ.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail};
use base64::Engine;
use russh::client::Handle;
use russh::Disconnect;
use russh_sftp::client::SftpSession;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use suppaftp::list::File as FtpFile;
use suppaftp::tokio::{AsyncRustlsConnector, AsyncRustlsFtpStream as FtpStream};
use suppaftp::types::FileType;
use suppaftp::FtpError;
use tauri::ipc::Channel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio_rustls::rustls;

use crate::ssh::{self, Client, Ctx};
use crate::store::{now_ms, Host, KnownHost};

pub const LOCAL: &str = "local";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_link: bool,
    pub size: u64,
    /// Milliseconds since the epoch.
    pub modified: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Listing {
    pub path: String,
    pub parent: Option<String>,
    pub entries: Vec<Entry>,
}

/// One selected item, as the UI sends it for delete / download.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub path: String,
    #[serde(default)]
    pub is_dir: bool,
}

fn ms(t: SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_millis() as i64)
}

/// A new file or folder name typed by the user: one path component, nothing that climbs out.
pub fn check_name(name: &str) -> anyhow::Result<&str> {
    let n = name.trim();
    if n.is_empty() || n == "." || n == ".." || n.contains(['/', '\\', '\0']) {
        bail!("“{name}” can't be used as a name");
    }
    Ok(n)
}

// ---------- POSIX paths on the server ----------

fn rjoin(dir: &str, name: &str) -> String {
    if dir.ends_with('/') { format!("{dir}{name}") } else { format!("{dir}/{name}") }
}

fn rparent(path: &str) -> Option<String> {
    let t = path.trim_end_matches('/');
    match t.rfind('/') {
        _ if t.is_empty() => None,
        Some(0) => Some("/".into()),
        Some(i) => Some(t[..i].into()),
        None => None,
    }
}

fn rname(path: &str) -> String {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string()
}

/// A name from the server, made safe to use as one component of a local path. A hostile
/// server could otherwise send names like `..` or `a\..\..\x` (Windows) to escape the folder.
fn local_component(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if matches!(c, '/' | '\\' | '\0') || (cfg!(windows) && matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|')) { '_' } else { c })
        .collect();
    if s.is_empty() || s == "." || s == ".." {
        s = format!("_{s}");
    }
    s
}

// ---------- this computer ----------

pub fn local_home() -> String {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")).to_string_lossy().into_owned()
}

fn local_entry(path: &Path, name: String) -> Option<Entry> {
    let lmeta = std::fs::symlink_metadata(path).ok()?;
    let is_link = lmeta.file_type().is_symlink();
    let meta = if is_link { std::fs::metadata(path).unwrap_or(lmeta) } else { lmeta };
    Some(Entry {
        name,
        path: path.to_string_lossy().into_owned(),
        is_dir: meta.is_dir(),
        is_link,
        size: if meta.is_dir() { 0 } else { meta.len() },
        modified: meta.modified().ok().and_then(ms),
    })
}

/// An empty path means home (or, on Windows, the list of drives).
pub fn local_list(path: &str) -> anyhow::Result<Listing> {
    #[cfg(windows)]
    if path.is_empty() {
        let entries = (b'A'..=b'Z')
            .map(|c| format!("{}:\\", c as char))
            .filter(|d| Path::new(d).exists())
            .map(|d| Entry { name: d.trim_end_matches('\\').into(), path: d, is_dir: true, is_link: false, size: 0, modified: None })
            .collect();
        return Ok(Listing { path: String::new(), parent: None, entries });
    }
    let p = if path.is_empty() { PathBuf::from(local_home()) } else { std::path::absolute(path)? };
    let rd = std::fs::read_dir(&p).map_err(|e| anyhow!("Can't open {}: {e}", p.display()))?;
    let entries = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| local_entry(&e.path(), e.file_name().to_string_lossy().into_owned()))
        .collect();
    let parent = match p.parent() {
        Some(par) => Some(par.to_string_lossy().into_owned()),
        // A drive root's parent is the drive list.
        None if cfg!(windows) => Some(String::new()),
        None => None,
    };
    Ok(Listing { path: p.to_string_lossy().into_owned(), parent, entries })
}

pub fn local_mkdir(dir: &str, name: &str) -> anyhow::Result<()> {
    let p = Path::new(dir).join(check_name(name)?);
    std::fs::create_dir(&p).map_err(|e| anyhow!("Can't create {}: {e}", p.display()))
}

pub fn local_rename(dir: &str, from: &str, to: &str) -> anyhow::Result<()> {
    let (a, b) = (Path::new(dir).join(check_name(from)?), Path::new(dir).join(check_name(to)?));
    if b.exists() {
        bail!("“{to}” already exists");
    }
    std::fs::rename(&a, &b).map_err(|e| anyhow!("Can't rename: {e}"))
}

/// Local deletes go to the Trash / Recycle Bin, so a slip can be undone.
pub fn local_delete(paths: &[String]) -> anyhow::Result<()> {
    trash::delete_all(paths).map_err(|e| anyhow!("Couldn't move to the Trash: {e}"))
}

/// Everything under a local folder, parents before children. Symlinked folders are not
/// followed, so a link loop can't run forever.
fn walk_local(root: &Path) -> anyhow::Result<Vec<(PathBuf, bool, u64)>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).map_err(|e| anyhow!("Can't read {}: {e}", dir.display()))? {
            let e = e?;
            let ft = e.file_type()?;
            let p = e.path();
            if ft.is_dir() {
                stack.push(p.clone());
                out.push((p, true, 0));
            } else if let Ok(m) = std::fs::metadata(&p) {
                if m.is_file() {
                    out.push((p, false, m.len()));
                }
            }
        }
        if out.len() > 500_000 {
            bail!("That folder has too many files to copy in one go");
        }
    }
    Ok(out)
}

// ---------- FTPS certificates ----------

fn cert_fingerprint(der: &[u8]) -> String {
    format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(der)))
}

/// The system's normal certificate check, plus trust-on-first-use: a certificate the system
/// rejects (self-signed, as on most NAS boxes, or an IP address) is accepted only if the user
/// has trusted its exact fingerprint before. A rejection is recorded so the caller can ask.
#[derive(Debug)]
struct TofuVerifier {
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    trusted: Option<String>,
    rejected: Arc<Mutex<Option<String>>>,
}

impl rustls::client::danger::ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = cert_fingerprint(end_entity);
        if self.trusted.as_deref() == Some(fp.as_str()) {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        let r = self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
        if r.is_err() {
            *self.rejected.lock().unwrap() = Some(fp);
        }
        r
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn tls_connector(trusted: Option<String>, rejected: Arc<Mutex<Option<String>>>) -> anyhow::Result<AsyncRustlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = Arc::new(rustls_platform_verifier::Verifier::new(provider.clone())?);
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TofuVerifier { inner, trusted, rejected }))
        .with_no_client_auth();
    Ok(AsyncRustlsConnector::from(tokio_rustls::TlsConnector::from(Arc::new(config))))
}

// ---------- FTP connections ----------

/// Everything needed to open another FTP connection without asking the user again
/// (transfers use their own connection so browsing stays responsive).
#[derive(Clone)]
pub struct FtpLogin {
    address: String,
    port: u16,
    tls: bool,
    user: String,
    password: String,
    trusted_cert: Option<String>,
}

enum DialError {
    Untrusted(String),
    Login(String),
    Other(anyhow::Error),
}

impl From<DialError> for anyhow::Error {
    fn from(e: DialError) -> Self {
        match e {
            DialError::Untrusted(_) => anyhow!("The server's certificate is no longer the one you trusted"),
            DialError::Login(m) => anyhow!("Login failed: {m}"),
            DialError::Other(e) => e,
        }
    }
}

fn ftp_msg(e: &FtpError) -> String {
    match e {
        FtpError::UnexpectedResponse(r) => {
            let body = String::from_utf8_lossy(&r.body);
            let body = body.trim();
            // "550 No such file or directory" reads better without the code.
            body.split_once(' ').filter(|(code, _)| code.len() == 3 && code.chars().all(|c| c.is_ascii_digit()))
                .map(|(_, rest)| rest.trim().to_string())
                .unwrap_or_else(|| body.to_string())
        }
        other => other.to_string(),
    }
}

async fn ftp_dial(l: &FtpLogin) -> Result<FtpStream, DialError> {
    let target = format!("{}:{}", l.address, l.port);
    let mut s = match tokio::time::timeout(Duration::from_secs(20), FtpStream::connect(target.as_str())).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(DialError::Other(anyhow!("Could not connect to {target}: {}", ftp_msg(&e)))),
        Err(_) => return Err(DialError::Other(anyhow!("Timed out connecting to {target}"))),
    };
    if l.tls {
        let rejected = Arc::new(Mutex::new(None));
        let connector = tls_connector(l.trusted_cert.clone(), rejected.clone()).map_err(DialError::Other)?;
        s = match s.into_secure(connector, &l.address).await {
            Ok(s) => s,
            Err(e) => {
                if let Some(fp) = rejected.lock().unwrap().take() {
                    return Err(DialError::Untrusted(fp));
                }
                return Err(DialError::Other(anyhow!("{target} didn't accept a secure (FTPS) connection: {}", ftp_msg(&e))));
            }
        };
    }
    s.login(l.user.as_str(), l.password.as_str()).await.map_err(|e| DialError::Login(ftp_msg(&e)))?;
    s.transfer_type(FileType::Binary).await.map_err(|e| DialError::Other(anyhow!(ftp_msg(&e))))?;
    // Servers behind NAT often advertise a private address for passive mode.
    s.set_passive_nat_workaround(true);
    Ok(s)
}

/// First connection to an FTP host: asks for a password and certificate trust as needed.
async fn ftp_open(ctx: &Ctx, host: &Host) -> anyhow::Result<(FtpLogin, FtpStream)> {
    let name = ssh::display_name(host);
    let port = host.port.unwrap_or(21);
    let target = format!("{}:{port}", host.address);
    let cert_key = format!("ftps://{target}");
    let user = host.username.clone().filter(|u| !u.trim().is_empty()).unwrap_or_else(|| "anonymous".into());
    let anonymous = user.eq_ignore_ascii_case("anonymous") || user.eq_ignore_ascii_case("ftp");
    let (saved, trusted) = {
        let s = ctx.store.lock().unwrap();
        (s.secret(&host.id).password, s.known_host(&cert_key).map(|k| k.fingerprint.clone()))
    };
    let mut login = FtpLogin { address: host.address.clone(), port, tls: host.protocol == "ftps", user: user.clone(), password: String::new(), trusted_cert: trusted };
    let mut save = false;
    let mut failures = 0;
    login.password = match saved {
        Some(p) => p,
        None if anonymous => "nimbus@".into(),
        None => {
            let (p, s) = ctx
                .ask_secret("password", "Password", format!("Password for {user}@{name}"), true)
                .await
                .ok_or_else(|| anyhow!("Cancelled"))?;
            save = s;
            p
        }
    };
    loop {
        ctx.status("connecting", format!("Connecting to {target}…"));
        match ftp_dial(&login).await {
            Ok(stream) => {
                if save {
                    let (id, pw) = (host.id.clone(), login.password.clone());
                    ctx.save_store(|s| s.update_secret(&id, |sec| sec.password = Some(pw)));
                }
                return Ok((login, stream));
            }
            Err(DialError::Untrusted(fp)) => {
                let answer = ctx
                    .ask(
                        "hostkey",
                        json!({
                            "host": format!("{target} (FTPS)"),
                            "keyType": "TLS certificate",
                            "fingerprint": fp,
                            "previous": login.trusted_cert,
                            "note": "Your computer doesn't recognise who issued this server's certificate. That's normal for a NAS or a server with a self-signed certificate.",
                        }),
                    )
                    .await;
                if !answer.and_then(|v| v.get("accept").and_then(Value::as_bool)).unwrap_or(false) {
                    bail!("The certificate for {target} was not trusted, so the connection was cancelled");
                }
                let kh = KnownHost { host: cert_key.clone(), key_type: "TLS certificate".into(), fingerprint: fp.clone(), added: now_ms() };
                ctx.save_store(|s| s.set_known_host(kh));
                login.trusted_cert = Some(fp);
            }
            Err(DialError::Login(msg)) => {
                failures += 1;
                if failures > 3 {
                    bail!("Login failed for {user}@{name}: {msg}");
                }
                ctx.status("authenticating", format!("Logging in as {user}…"));
                let (p, s) = ctx
                    .ask_secret("password", "Password", format!("The server said “{msg}”. Try the password for {user}@{name} again."), true)
                    .await
                    .ok_or_else(|| anyhow!("Cancelled"))?;
                login.password = p;
                save = s;
            }
            Err(DialError::Other(e)) => return Err(e),
        }
    }
}

fn parse_ftp_lines(dir: &str, lines: &[String], mlsd: bool) -> Vec<Entry> {
    lines
        .iter()
        .filter_map(|l| if mlsd { suppaftp::list::ListParser::parse_mlsd(l).ok() } else { FtpFile::from_str(l).ok() })
        .filter(|f| f.name() != "." && f.name() != ".." && !f.name().is_empty())
        .map(|f| Entry {
            name: f.name().to_string(),
            path: rjoin(dir, f.name()),
            is_dir: f.is_directory(),
            is_link: f.is_symlink(),
            size: if f.is_directory() { 0 } else { f.size() as u64 },
            modified: ms(f.modified()),
        })
        .collect()
}

// ---------- a connected remote ----------

pub enum Backend {
    Sftp { sftp: SftpSession, handle: Handle<Client>, jumps: Vec<Handle<Client>> },
    Ftp { login: FtpLogin, ctl: tokio::sync::Mutex<Option<FtpStream>>, mlsd: AtomicBool },
}

pub struct Remote {
    backend: Backend,
    events: Channel<Value>,
    slots: Semaphore,
    cancels: Mutex<HashMap<String, Arc<AtomicBool>>>,
}

/// Run one FTP command on the browsing connection, reconnecting once if the server dropped
/// it (most servers close idle connections after a few minutes).
macro_rules! ftp_op {
    ($remote:expr, |$s:ident| $body:expr) => {{
        let Backend::Ftp { login, ctl, .. } = &$remote.backend else { unreachable!() };
        let mut guard = ctl.lock().await;
        let mut attempt = 0;
        loop {
            if guard.is_none() {
                *guard = Some(ftp_dial(login).await?);
            }
            let $s = guard.as_mut().unwrap();
            match $body.await {
                Ok(v) => break Ok::<_, anyhow::Error>(v),
                Err(e) if attempt == 0 && connection_lost(&e) => {
                    attempt += 1;
                    *guard = None;
                }
                Err(e) => break Err(anyhow!(ftp_msg(&e))),
            }
        }
    }};
}

/// The server closed the connection: a dropped socket, or the reply servers send as they time
/// out an idle session ("421 Service not available", or "221 Closing" from some).
fn connection_lost(e: &FtpError) -> bool {
    match e {
        FtpError::ConnectionError(_) => true,
        FtpError::UnexpectedResponse(r) => matches!(r.status, suppaftp::Status::NotAvailable | suppaftp::Status::Closing),
        _ => false,
    }
}

fn sftp_err(e: russh_sftp::client::error::Error) -> anyhow::Error {
    use russh_sftp::client::error::Error as E;
    match e {
        E::Status(s) => anyhow!("{}", if s.error_message.is_empty() { format!("{:?}", s.status_code) } else { s.error_message }),
        other => anyhow!("{other}"),
    }
}

pub async fn connect(ctx: &Ctx, host_id: &str) -> anyhow::Result<(Remote, String)> {
    let host = ctx.store.lock().unwrap().effective_host(host_id).ok_or_else(|| anyhow!("This host no longer exists"))?;
    if host.is_serial() {
        bail!("“{}” is a serial device, which has no files to browse", ssh::display_name(&host));
    }
    if host.address.trim().is_empty() {
        bail!("“{}” has no address", ssh::display_name(&host));
    }
    let (backend, home) = if host.is_ssh() {
        let mut jumps = Vec::new();
        let handle = ssh::connect_host(ctx, host, 0, &mut jumps).await?;
        ctx.status("connecting", "Starting SFTP…");
        let channel = handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| anyhow!("The server didn't start SFTP ({e}). It may have SFTP turned off."))?;
        let home = sftp.canonicalize(".").await.unwrap_or_else(|_| "/".into());
        (Backend::Sftp { sftp, handle, jumps }, home)
    } else {
        let (login, mut stream) = ftp_open(ctx, &host).await?;
        let home = stream.pwd().await.unwrap_or_else(|_| "/".into());
        (Backend::Ftp { login, ctl: tokio::sync::Mutex::new(Some(stream)), mlsd: AtomicBool::new(true) }, home)
    };
    let parallel = if matches!(backend, Backend::Sftp { .. }) { 3 } else { 1 };
    let id = host_id.to_string();
    ctx.save_store(|s| {
        if let Some(h) = s.data.hosts.iter_mut().find(|h| h.id == id) {
            h.last_connected = Some(now_ms());
        }
    });
    Ok((Remote { backend, events: ctx.events.clone(), slots: Semaphore::new(parallel), cancels: Mutex::new(HashMap::new()) }, home))
}

impl Remote {
    pub async fn close(&self) {
        for c in self.cancels.lock().unwrap().values() {
            c.store(true, Ordering::SeqCst);
        }
        match &self.backend {
            Backend::Sftp { sftp, handle, jumps } => {
                let _ = sftp.close().await;
                let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
                for j in jumps.iter().rev() {
                    let _ = j.disconnect(Disconnect::ByApplication, "", "en").await;
                }
            }
            Backend::Ftp { ctl, .. } => {
                if let Some(mut s) = ctl.lock().await.take() {
                    let _ = s.quit().await;
                }
            }
        }
    }

    /// An empty path means the login folder.
    pub async fn list(&self, path: &str) -> anyhow::Result<Listing> {
        match &self.backend {
            Backend::Sftp { sftp, .. } => {
                let target = if path.is_empty() { "." } else { path };
                let path = sftp.canonicalize(target).await.map_err(sftp_err)?;
                let dir = sftp.read_dir(path.clone()).await.map_err(sftp_err)?;
                let mut entries = Vec::new();
                for e in dir {
                    let name = e.file_name();
                    if name == "." || name == ".." {
                        continue;
                    }
                    let p = rjoin(&path, &name);
                    let meta = e.metadata();
                    let is_link = meta.is_symlink();
                    // Follow links so a link to a folder opens like a folder.
                    let m = if is_link { sftp.metadata(p.clone()).await.unwrap_or(meta) } else { meta };
                    entries.push(Entry {
                        name,
                        path: p,
                        is_dir: m.is_dir(),
                        is_link,
                        size: if m.is_dir() { 0 } else { m.len() },
                        modified: m.mtime.map(|t| t as i64 * 1000),
                    });
                }
                Ok(Listing { parent: rparent(&path), path, entries })
            }
            Backend::Ftp { mlsd, .. } => {
                let (cwd, lines, used_mlsd) = ftp_op!(self, |s| async {
                    if !path.is_empty() {
                        s.cwd(path).await?;
                    }
                    let cwd = s.pwd().await?;
                    if mlsd.load(Ordering::SeqCst) {
                        match s.mlsd(None).await {
                            Ok(l) => return Ok((cwd, l, true)),
                            Err(FtpError::UnexpectedResponse(_)) => mlsd.store(false, Ordering::SeqCst),
                            Err(e) => return Err(e),
                        }
                    }
                    Ok((cwd, s.list(None).await?, false))
                })?;
                let entries = parse_ftp_lines(&cwd, &lines, used_mlsd);
                Ok(Listing { parent: rparent(&cwd), path: cwd, entries })
            }
        }
    }

    pub async fn mkdir(&self, dir: &str, name: &str) -> anyhow::Result<()> {
        let p = rjoin(dir, check_name(name)?);
        match &self.backend {
            Backend::Sftp { sftp, .. } => sftp.create_dir(p).await.map_err(sftp_err),
            Backend::Ftp { .. } => ftp_op!(self, |s| s.mkdir(&p)),
        }
    }

    pub async fn rename(&self, dir: &str, from: &str, to: &str) -> anyhow::Result<()> {
        let (a, b) = (rjoin(dir, check_name(from)?), rjoin(dir, check_name(to)?));
        match &self.backend {
            Backend::Sftp { sftp, .. } => {
                if sftp.try_exists(b.clone()).await.unwrap_or(false) {
                    bail!("“{to}” already exists");
                }
                sftp.rename(a, b).await.map_err(sftp_err)
            }
            Backend::Ftp { .. } => ftp_op!(self, |s| s.rename(&a, &b)),
        }
    }

    /// Everything under a remote folder, parents before children. Linked folders aren't entered.
    async fn walk(&self, root: &str) -> anyhow::Result<Vec<Entry>> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_string()];
        while let Some(dir) = stack.pop() {
            for e in self.list(&dir).await?.entries {
                if e.is_dir && !e.is_link {
                    stack.push(e.path.clone());
                }
                out.push(e);
            }
            if out.len() > 500_000 {
                bail!("That folder has too many files to handle in one go");
            }
        }
        Ok(out)
    }

    async fn remove(&self, path: &str, is_dir: bool) -> anyhow::Result<()> {
        match &self.backend {
            Backend::Sftp { sftp, .. } if is_dir => sftp.remove_dir(path.to_string()).await.map_err(sftp_err),
            Backend::Sftp { sftp, .. } => sftp.remove_file(path.to_string()).await.map_err(sftp_err),
            Backend::Ftp { .. } if is_dir => ftp_op!(self, |s| s.rmdir(path)),
            Backend::Ftp { .. } => ftp_op!(self, |s| s.rm(path)),
        }
    }

    /// Permanently deletes files and folders (with everything in them) on the server.
    pub async fn delete(&self, items: &[Item]) -> anyhow::Result<()> {
        for it in items {
            // Re-check: the UI's idea of what's a folder may be stale, and a link to a folder
            // must be removed as a link, not emptied.
            let (is_dir, is_link) = match &self.backend {
                Backend::Sftp { sftp, .. } => {
                    let m = sftp.symlink_metadata(it.path.clone()).await.map_err(sftp_err)?;
                    (m.is_dir(), m.is_symlink())
                }
                Backend::Ftp { .. } => (it.is_dir, false),
            };
            if is_dir && !is_link {
                for e in self.walk(&it.path).await?.iter().rev() {
                    self.remove(&e.path, e.is_dir && !e.is_link).await?;
                }
            }
            self.remove(&it.path, is_dir && !is_link).await?;
        }
        Ok(())
    }

    // ---------- transfers ----------

    pub fn cancel(&self, id: &str) {
        if let Some(c) = self.cancels.lock().unwrap().get(id) {
            c.store(true, Ordering::SeqCst);
        }
    }

    fn emit(&self, v: Value) {
        let _ = self.events.send(v);
    }

    /// Copy `items` into `dest` (upload: local → remote folder; download: remote → local folder).
    /// Existing files with the same name are overwritten; the UI asks first.
    pub async fn transfer(self: Arc<Self>, id: String, upload: bool, items: Vec<Item>, dest: String) {
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancels.lock().unwrap().insert(id.clone(), cancel.clone());
        self.emit(json!({ "type": "transfer", "id": id, "state": "queued", "upload": upload, "dest": dest }));
        let result = match self.slots.acquire().await {
            Ok(_permit) => self.transfer_inner(&id, upload, &items, &dest, &cancel).await,
            Err(_) => Err(anyhow!("Closed")),
        };
        self.cancels.lock().unwrap().remove(&id);
        let ev = match result {
            Ok(n) => json!({ "type": "transfer", "id": id, "state": "done", "files": n, "dest": dest, "upload": upload }),
            Err(_) if cancel.load(Ordering::SeqCst) => json!({ "type": "transfer", "id": id, "state": "cancelled", "dest": dest, "upload": upload }),
            Err(e) => json!({ "type": "transfer", "id": id, "state": "error", "message": format!("{e:#}"), "dest": dest, "upload": upload }),
        };
        self.emit(ev);
    }

    async fn transfer_inner(&self, id: &str, upload: bool, items: &[Item], dest: &str, cancel: &AtomicBool) -> anyhow::Result<usize> {
        // 1. Plan: every folder to create and every file to copy, so progress has a total.
        struct Job {
            src: String,
            dst: String,
            dir: bool,
            size: u64,
        }
        let mut jobs = Vec::new();
        for it in items {
            if upload {
                let src = Path::new(&it.path);
                let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).ok_or_else(|| anyhow!("Can't upload {}", it.path))?;
                let top = rjoin(dest, &name);
                let meta = std::fs::metadata(src).map_err(|e| anyhow!("Can't read {}: {e}", it.path))?;
                if meta.is_dir() {
                    jobs.push(Job { src: it.path.clone(), dst: top.clone(), dir: true, size: 0 });
                    for (p, dir, size) in walk_local(src)? {
                        let rel = p.strip_prefix(src)?.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/");
                        jobs.push(Job { src: p.to_string_lossy().into_owned(), dst: rjoin(&top, &rel), dir, size });
                    }
                } else {
                    jobs.push(Job { src: it.path.clone(), dst: top, dir: false, size: meta.len() });
                }
            } else {
                let top = Path::new(dest).join(local_component(&rname(&it.path)));
                if it.is_dir {
                    jobs.push(Job { src: it.path.clone(), dst: top.to_string_lossy().into_owned(), dir: true, size: 0 });
                    let base = it.path.trim_end_matches('/');
                    for e in self.walk(&it.path).await? {
                        let rel = e.path.strip_prefix(base).unwrap_or(&e.name).trim_start_matches('/');
                        let mut local = top.clone();
                        for part in rel.split('/').filter(|p| !p.is_empty()) {
                            local.push(local_component(part));
                        }
                        jobs.push(Job { src: e.path.clone(), dst: local.to_string_lossy().into_owned(), dir: e.is_dir && !e.is_link, size: e.size });
                    }
                } else {
                    let size = match &self.backend {
                        Backend::Sftp { sftp, .. } => sftp.metadata(it.path.clone()).await.map(|m| m.len()).unwrap_or(0),
                        Backend::Ftp { .. } => 0,
                    };
                    jobs.push(Job { src: it.path.clone(), dst: top.to_string_lossy().into_owned(), dir: false, size });
                }
            }
            if cancel.load(Ordering::SeqCst) {
                bail!("Cancelled");
            }
        }
        let total: u64 = jobs.iter().map(|j| j.size).sum();
        let count = jobs.iter().filter(|j| !j.dir).count();
        let name = items.first().map(|i| if upload { Path::new(&i.path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default() } else { rname(&i.path) }).unwrap_or_default();
        let label = if items.len() > 1 { format!("{name} and {} more", items.len() - 1) } else { name };

        // 2. Copy. FTP transfers use their own connection, so browsing keeps working meanwhile.
        let mut ftp = match &self.backend {
            Backend::Ftp { login, .. } => Some(ftp_dial(login).await?),
            Backend::Sftp { .. } => None,
        };
        let mut progress = Progress { remote: self, id, label: &label, total, count, done: 0, files: 0, last: Instant::now() - Duration::from_secs(1) };
        progress.tick(true);
        for job in &jobs {
            if cancel.load(Ordering::SeqCst) {
                bail!("Cancelled");
            }
            if job.dir {
                if upload {
                    self.remote_mkdir_p(&job.dst, ftp.as_mut()).await?;
                } else {
                    tokio::fs::create_dir_all(&job.dst).await.map_err(|e| anyhow!("Can't create {}: {e}", job.dst))?;
                }
                continue;
            }
            let r = self.copy_file(upload, &job.src, &job.dst, ftp.as_mut(), cancel, &mut progress).await;
            if let Err(e) = r {
                // Don't leave a half-written file behind.
                if upload {
                    let _ = match &self.backend {
                        Backend::Sftp { sftp, .. } => sftp.remove_file(job.dst.clone()).await.map_err(sftp_err),
                        Backend::Ftp { login, .. } => match ftp_dial(login).await {
                            Ok(mut s) => s.rm(&job.dst).await.map_err(|e| anyhow!(ftp_msg(&e))),
                            Err(e) => Err(e.into()),
                        },
                    };
                } else {
                    let _ = tokio::fs::remove_file(&job.dst).await;
                }
                return Err(e);
            }
            progress.files += 1;
            progress.tick(true);
        }
        if let Some(mut s) = ftp {
            let _ = s.quit().await;
        }
        Ok(count)
    }

    async fn remote_mkdir_p(&self, path: &str, ftp: Option<&mut FtpStream>) -> anyhow::Result<()> {
        match (&self.backend, ftp) {
            (Backend::Sftp { sftp, .. }, _) => {
                if !sftp.try_exists(path.to_string()).await.unwrap_or(false) {
                    sftp.create_dir(path.to_string()).await.map_err(|e| anyhow!("Can't create {path}: {}", sftp_err(e)))?;
                }
                Ok(())
            }
            (Backend::Ftp { .. }, Some(s)) => {
                // Most servers refuse MKD for a folder that exists; that's fine as long as it's a folder.
                if let Err(e) = s.mkdir(path).await {
                    if s.cwd(path).await.is_err() {
                        bail!("Can't create {path}: {}", ftp_msg(&e));
                    }
                }
                Ok(())
            }
            (Backend::Ftp { .. }, None) => unreachable!(),
        }
    }

    async fn copy_file(
        &self,
        upload: bool,
        src: &str,
        dst: &str,
        ftp: Option<&mut FtpStream>,
        cancel: &AtomicBool,
        progress: &mut Progress<'_>,
    ) -> anyhow::Result<()> {
        let mut buf = vec![0u8; 256 * 1024];
        macro_rules! pump {
            ($r:expr, $w:expr) => {
                loop {
                    if cancel.load(Ordering::SeqCst) {
                        bail!("Cancelled");
                    }
                    let n = $r.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    $w.write_all(&buf[..n]).await?;
                    progress.done += n as u64;
                    progress.tick(false);
                }
            };
        }
        let local_err = |e: std::io::Error| anyhow!("{}: {e}", if upload { src } else { dst });
        match (&self.backend, ftp) {
            (Backend::Sftp { sftp, .. }, _) => {
                if upload {
                    let mut r = tokio::fs::File::open(src).await.map_err(local_err)?;
                    let mut w = sftp.create(dst.to_string()).await.map_err(|e| anyhow!("Can't write {dst}: {}", sftp_err(e)))?;
                    pump!(r, w);
                    w.shutdown().await?;
                } else {
                    let mut r = sftp.open(src.to_string()).await.map_err(|e| anyhow!("Can't read {src}: {}", sftp_err(e)))?;
                    let mut w = tokio::fs::File::create(dst).await.map_err(local_err)?;
                    pump!(r, w);
                    w.flush().await?;
                }
            }
            (Backend::Ftp { .. }, Some(s)) => {
                if upload {
                    let mut r = tokio::fs::File::open(src).await.map_err(local_err)?;
                    let mut w = s.put_with_stream(dst).await.map_err(|e| anyhow!("Can't write {dst}: {}", ftp_msg(&e)))?;
                    pump!(r, w);
                    w.finish().await.map_err(|e| anyhow!("Upload of {dst} failed: {}", ftp_msg(&e)))?;
                } else {
                    let mut r = s.retr_as_stream(src).await.map_err(|e| anyhow!("Can't read {src}: {}", ftp_msg(&e)))?;
                    let mut w = tokio::fs::File::create(dst).await.map_err(local_err)?;
                    pump!(r, w);
                    w.flush().await?;
                    r.finish().await.map_err(|e| anyhow!("Download of {src} failed: {}", ftp_msg(&e)))?;
                }
            }
            (Backend::Ftp { .. }, None) => unreachable!(),
        }
        Ok(())
    }
}

struct Progress<'a> {
    remote: &'a Remote,
    id: &'a str,
    label: &'a str,
    total: u64,
    count: usize,
    done: u64,
    files: usize,
    last: Instant,
}

impl Progress<'_> {
    /// At most ~6 updates a second, plus one whenever a file finishes.
    fn tick(&mut self, force: bool) {
        if !force && self.last.elapsed() < Duration::from_millis(150) {
            return;
        }
        self.last = Instant::now();
        self.remote.emit(json!({
            "type": "transfer", "id": self.id, "state": "running", "label": self.label,
            "done": self.done, "total": self.total, "files": self.files, "count": self.count,
        }));
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn remote_paths() {
        assert_eq!(rjoin("/", "a"), "/a");
        assert_eq!(rjoin("/home/u", "a"), "/home/u/a");
        assert_eq!(rparent("/home/u"), Some("/home".into()));
        assert_eq!(rparent("/home"), Some("/".into()));
        assert_eq!(rparent("/"), None);
        assert_eq!(rname("/home/u/file.txt"), "file.txt");
        assert_eq!(rname("/home/u/dir/"), "dir");
    }

    #[test]
    fn hostile_names_stay_inside() {
        assert_eq!(local_component(".."), "_..");
        assert_eq!(local_component("a/b"), "a_b");
        assert_eq!(local_component("a\\..\\x"), "a_.._x");
        assert!(check_name("../x").is_err());
        assert!(check_name("..").is_err());
        assert!(check_name("ok name.txt").is_ok());
    }

    #[test]
    fn parses_ftp_listings() {
        let posix = vec![
            "drwxr-xr-x   2 ftp ftp 4096 Jan 10 12:00 docs".to_string(),
            "-rw-r--r--   1 ftp ftp 1234 Jan 10 12:00 notes.txt".to_string(),
            "lrwxrwxrwx   1 ftp ftp    9 Jan 10 12:00 link -> notes.txt".to_string(),
        ];
        let e = parse_ftp_lines("/pub", &posix, false);
        assert_eq!(e.len(), 3);
        assert!(e[0].is_dir && e[0].path == "/pub/docs");
        assert_eq!((e[1].name.as_str(), e[1].size), ("notes.txt", 1234));
        assert!(e[2].is_link && e[2].name == "link");
        let mlsd = vec![
            "type=cdir;modify=20240110120000; .".to_string(),
            "type=dir;modify=20240110120000; docs".to_string(),
            "type=file;size=99;modify=20240110120000; a b.txt".to_string(),
        ];
        let e = parse_ftp_lines("/", &mlsd, true);
        assert_eq!(e.len(), 2);
        assert_eq!((e[1].path.as_str(), e[1].size), ("/a b.txt", 99));
    }
}
