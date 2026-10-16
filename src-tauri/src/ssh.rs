//! SSH sessions: connect (optionally through jump hosts), verify the host key, authenticate,
//! then pump bytes between a remote PTY and the terminal in the UI.
//!
//! Anything that needs the user — trusting a new host key, a password, a key passphrase,
//! a 2FA code — is sent to the UI as a `prompt` event on the session's event channel and the
//! session waits for `prompt_reply`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail};
use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::{decode_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, MethodKind, MethodSet};
use serde_json::{json, Value};
use tauri::ipc::{Channel, InvokeResponseBody};
use tokio::sync::{mpsc, oneshot};

use crate::store::{now_ms, KnownHost, Host, Store};

pub enum Input {
    Data(Vec<u8>),
    Resize(u32, u32),
    /// Serial only: hold the line in the break state briefly (e.g. to reach a router's ROMMON).
    Break,
    Close,
}

pub struct Session {
    pub input: mpsc::UnboundedSender<Input>,
    pub task: tauri::async_runtime::JoinHandle<()>,
}

#[derive(Default)]
pub struct Prompts {
    pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
}

impl Prompts {
    pub fn reply(&self, id: &str, value: Value) {
        if let Some(tx) = self.pending.lock().unwrap().remove(id) {
            let _ = tx.send(value);
        }
    }
}

#[derive(Clone)]
pub struct Ctx {
    pub store: Arc<Mutex<Store>>,
    pub prompts: Arc<Prompts>,
    pub events: Channel<Value>,
}

impl Ctx {
    pub(crate) fn status(&self, state: &str, message: impl Into<String>) {
        let _ = self.events.send(json!({ "type": "status", "state": state, "message": message.into() }));
    }

    /// Ask the UI something and wait. `None` means the user cancelled.
    pub(crate) async fn ask(&self, kind: &str, data: Value) -> Option<Value> {
        let id = crate::store::new_id();
        let (tx, rx) = oneshot::channel();
        self.prompts.pending.lock().unwrap().insert(id.clone(), tx);
        let _ = self.events.send(json!({ "type": "prompt", "id": id, "kind": kind, "data": data }));
        let answer = rx.await.ok();
        self.prompts.pending.lock().unwrap().remove(&id);
        answer.filter(|v| !v.is_null())
    }

    /// Ask for a secret; returns (value, save).
    pub(crate) async fn ask_secret(&self, kind: &str, title: &str, message: String, allow_save: bool) -> Option<(String, bool)> {
        let v = self
            .ask(kind, json!({ "title": title, "message": message, "allowSave": allow_save }))
            .await?;
        let value = v.get("value")?.as_str()?.to_string();
        let save = v.get("save").and_then(Value::as_bool).unwrap_or(false);
        Some((value, save))
    }

    pub(crate) fn save_store(&self, f: impl FnOnce(&mut Store)) {
        let mut s = self.store.lock().unwrap();
        f(&mut s);
        if let Err(e) = s.save() {
            eprintln!("nimbus: failed to save data: {e:#}");
        }
    }
}

pub struct Client {
    ctx: Ctx,
    target: String,
    rejected: Arc<AtomicBool>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let pk = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(c) => PublicKey::new(c.public_key().clone(), ""),
        };
        let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();
        let key_type = pk.algorithm().as_str().to_string();
        let known = self.ctx.store.lock().unwrap().known_host(&self.target).cloned();
        if known.as_ref().is_some_and(|k| k.fingerprint == fingerprint) {
            return Ok(true);
        }
        let answer = self
            .ctx
            .ask(
                "hostkey",
                json!({
                    "host": self.target,
                    "keyType": key_type,
                    "fingerprint": fingerprint,
                    "previous": known.map(|k| k.fingerprint),
                }),
            )
            .await;
        let accept = answer
            .and_then(|v| v.get("accept").and_then(Value::as_bool))
            .unwrap_or(false);
        if accept {
            let target = self.target.clone();
            self.ctx.save_store(|s| {
                s.set_known_host(KnownHost { host: target, key_type, fingerprint, added: now_ms() })
            });
        } else {
            self.rejected.store(true, Ordering::SeqCst);
        }
        Ok(accept)
    }
}

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub(crate) fn display_name(h: &Host) -> String {
    if h.label.trim().is_empty() { h.address.clone() } else { h.label.clone() }
}

pub(crate) fn connect_host<'a>(
    ctx: &'a Ctx,
    host: Host,
    depth: u8,
    jumps: &'a mut Vec<Handle<Client>>,
) -> BoxFut<'a, anyhow::Result<Handle<Client>>> {
    Box::pin(async move {
        if host.address.trim().is_empty() {
            bail!("“{}” has no address", display_name(&host));
        }
        let port = host.port.unwrap_or(22);
        let target = format!("{}:{}", host.address, port);
        let keepalive = ctx.store.lock().unwrap().data.settings.keepalive_secs;
        let config = Arc::new(client::Config {
            keepalive_interval: (keepalive > 0).then(|| Duration::from_secs(keepalive as u64)),
            keepalive_max: 3,
            inactivity_timeout: None,
            ..Default::default()
        });
        let rejected = Arc::new(AtomicBool::new(false));
        let handler = Client { ctx: ctx.clone(), target: target.clone(), rejected: rejected.clone() };

        let connected = if let Some(jump_id) = host.jump_host_id.as_deref().filter(|s| !s.is_empty()) {
            if depth >= 4 {
                bail!("Too many jump hosts in a row — check for a loop in the Jump host settings");
            }
            let jump = ctx
                .store
                .lock()
                .unwrap()
                .effective_host(jump_id)
                .ok_or_else(|| anyhow!("The jump host for “{}” no longer exists", display_name(&host)))?;
            let jump_handle = connect_host(ctx, jump, depth + 1, jumps).await?;
            ctx.status("connecting", format!("Tunnelling to {target}…"));
            let channel = jump_handle
                .channel_open_direct_tcpip(host.address.clone(), port as u32, "127.0.0.1", 0)
                .await
                .map_err(|e| anyhow!("The jump host could not reach {target}: {e}"))?;
            jumps.push(jump_handle);
            client::connect_stream(config, channel.into_stream(), handler).await
        } else {
            ctx.status("connecting", format!("Connecting to {target}…"));
            match tokio::time::timeout(
                Duration::from_secs(20),
                client::connect(config, (host.address.as_str(), port), handler),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => bail!("Timed out connecting to {target}"),
            }
        };
        let mut handle = match connected {
            Ok(h) => h,
            Err(_) if rejected.load(Ordering::SeqCst) => {
                bail!("Host key for {target} was not trusted, so the connection was cancelled")
            }
            Err(e) => bail!("Could not connect to {target}: {e}"),
        };
        authenticate(ctx, &mut handle, &host).await?;
        Ok(handle)
    })
}

fn allowed(methods: &Option<MethodSet>, m: MethodKind) -> bool {
    methods.as_ref().is_none_or(|s| s.contains(&m))
}

async fn authenticate(ctx: &Ctx, handle: &mut Handle<Client>, host: &Host) -> anyhow::Result<()> {
    let name = display_name(host);
    let user = match host.username.clone().filter(|u| !u.trim().is_empty()) {
        Some(u) => u,
        None => {
            let v = ctx
                .ask("text", json!({ "title": "Username", "message": format!("Which user should log in to {name}?") }))
                .await
                .ok_or_else(|| anyhow!("Cancelled"))?;
            v.get("value").and_then(Value::as_str).unwrap_or("").to_string()
        }
    };
    ctx.status("authenticating", format!("Authenticating as {user}…"));

    // Ask the server which methods it accepts before prompting the user for anything.
    let mut methods: Option<MethodSet> = None;
    match handle.authenticate_none(&user).await? {
        r if r.success() => return Ok(()),
        russh::client::AuthResult::Failure { remaining_methods, .. } => methods = Some(remaining_methods),
        _ => {}
    }

    // 1. The host's (or group's) saved key.
    if let Some(key_id) = host.key_id.as_deref().filter(|_| allowed(&methods, MethodKind::PublicKey)) {
        let (secret, label) = {
            let s = ctx.store.lock().unwrap();
            (s.secret(key_id), s.key(key_id).map(|k| k.label.clone()).unwrap_or_default())
        };
        if let Some(pem) = secret.private_key {
            if let Some(key) = unlock_key(ctx, key_id, &label, &pem, secret.passphrase).await? {
                let hash = handle.best_supported_rsa_hash().await?.flatten();
                match handle
                    .authenticate_publickey(&user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                    .await?
                {
                    r if r.success() => return Ok(()),
                    russh::client::AuthResult::Failure { remaining_methods, .. } => {
                        methods = Some(remaining_methods)
                    }
                    _ => {}
                }
            }
        }
    }

    // 2. The SSH agent (ssh-agent, 1Password, Secretive, Pageant, …).
    if host.use_agent && allowed(&methods, MethodKind::PublicKey) {
        let sock = ctx.store.lock().unwrap().data.settings.agent_socket.clone();
        match try_agent(handle, &user, sock).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => eprintln!("nimbus: agent auth skipped: {e:#}"),
        }
    }

    // 3. Password, or keyboard-interactive (which is how many servers ask for a password).
    let mut candidate = ctx.store.lock().unwrap().secret(&host.id).password;
    let mut failed_once = false;
    for _ in 0..4 {
        let pw_ok = allowed(&methods, MethodKind::Password);
        let kbd_ok = allowed(&methods, MethodKind::KeyboardInteractive);
        if !pw_ok && !kbd_ok {
            break;
        }
        let mut save = false;
        if pw_ok {
            let password = match candidate.take() {
                Some(p) => p,
                None => {
                    let msg = if failed_once {
                        format!("That didn't work. Try the password for {user}@{name} again.")
                    } else {
                        format!("Password for {user}@{name}")
                    };
                    let (p, s) = ctx
                        .ask_secret("password", "Password", msg, true)
                        .await
                        .ok_or_else(|| anyhow!("Cancelled"))?;
                    save = s;
                    p
                }
            };
            match handle.authenticate_password(&user, password.clone()).await? {
                r if r.success() => {
                    if save {
                        let id = host.id.clone();
                        ctx.save_store(|s| s.update_secret(&id, |sec| sec.password = Some(password)));
                    }
                    return Ok(());
                }
                russh::client::AuthResult::Failure { remaining_methods, .. } => {
                    methods = Some(remaining_methods)
                }
                _ => {}
            }
        } else {
            let mut entered: Option<(String, bool)> = None;
            let mut resp = handle.authenticate_keyboard_interactive_start(&user, None).await?;
            loop {
                match resp {
                    KeyboardInteractiveAuthResponse::Success => {
                        if let Some((password, true)) = entered {
                            let id = host.id.clone();
                            ctx.save_store(|s| s.update_secret(&id, |sec| sec.password = Some(password)));
                        }
                        return Ok(());
                    }
                    KeyboardInteractiveAuthResponse::Failure { remaining_methods, .. } => {
                        methods = Some(remaining_methods);
                        break;
                    }
                    KeyboardInteractiveAuthResponse::InfoRequest { name: title, instructions, prompts } => {
                        let answers = if prompts.is_empty() {
                            vec![]
                        } else if prompts.len() == 1 && !prompts[0].echo && prompts[0].prompt.to_lowercase().contains("password") {
                            // A plain password prompt: use the saved one, or ask like a password.
                            let p = match candidate.take() {
                                Some(p) => p,
                                None => {
                                    let msg = if failed_once {
                                        format!("That didn't work. Try the password for {user}@{name} again.")
                                    } else {
                                        format!("Password for {user}@{name}")
                                    };
                                    let (p, s) = ctx
                                        .ask_secret("password", "Password", msg, true)
                                        .await
                                        .ok_or_else(|| anyhow!("Cancelled"))?;
                                    entered = Some((p.clone(), s));
                                    p
                                }
                            };
                            vec![p]
                        } else {
                            let v = ctx
                                .ask(
                                    "kbdint",
                                    json!({
                                        "title": if title.is_empty() { format!("{name} asks") } else { title },
                                        "message": instructions,
                                        "prompts": prompts.iter().map(|p| json!({ "prompt": p.prompt, "echo": p.echo })).collect::<Vec<_>>(),
                                    }),
                                )
                                .await
                                .ok_or_else(|| anyhow!("Cancelled"))?;
                            v.get("responses")
                                .and_then(Value::as_array)
                                .map(|a| a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect())
                                .unwrap_or_default()
                        };
                        resp = handle.authenticate_keyboard_interactive_respond(answers).await?;
                    }
                }
            }
        }
        failed_once = true;
    }
    bail!("Authentication failed for {user}@{name}. Check the username, key or password.")
}

/// Decode a stored private key, asking for its passphrase if it's encrypted and none is saved.
async fn unlock_key(
    ctx: &Ctx,
    key_id: &str,
    label: &str,
    pem: &str,
    saved: Option<String>,
) -> anyhow::Result<Option<russh::keys::PrivateKey>> {
    let mut pass = saved;
    let mut asked = 0;
    loop {
        match decode_secret_key(pem, pass.as_deref()) {
            Ok(k) => return Ok(Some(k)),
            Err(e) => {
                let needs_pass = matches!(e, russh::keys::Error::KeyIsEncrypted) || pass.is_some();
                if !needs_pass || asked >= 3 {
                    eprintln!("nimbus: key “{label}” unusable: {e}");
                    return Ok(None);
                }
                let msg = if asked == 0 {
                    format!("Key “{label}” is protected. Enter its passphrase.")
                } else {
                    format!("Wrong passphrase for “{label}”. Try again.")
                };
                let Some((p, save)) = ctx.ask_secret("passphrase", "Key passphrase", msg, true).await else {
                    return Ok(None);
                };
                asked += 1;
                if decode_secret_key(pem, Some(&p)).is_ok() && save {
                    let id = key_id.to_string();
                    let p2 = p.clone();
                    ctx.save_store(|s| s.update_secret(&id, |sec| sec.passphrase = Some(p2)));
                }
                pass = Some(p);
            }
        }
    }
}

async fn agent_auth<S>(mut agent: AgentClient<S>, handle: &mut Handle<Client>, user: &str) -> anyhow::Result<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ids = agent.request_identities().await?;
    let hash = handle.best_supported_rsa_hash().await?.flatten();
    // Servers usually allow ~6 attempts in total, so don't spray every agent key.
    for id in ids.into_iter().take(5) {
        let pk = id.public_key().into_owned();
        if let Ok(r) = handle.authenticate_publickey_with(user, pk, hash, &mut agent).await {
            if r.success() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(unix)]
async fn try_agent(handle: &mut Handle<Client>, user: &str, sock: Option<String>) -> anyhow::Result<bool> {
    let path = match sock.filter(|s| !s.trim().is_empty()) {
        Some(s) => expand_tilde(&s),
        None => std::env::var("SSH_AUTH_SOCK").map_err(|_| anyhow!("SSH_AUTH_SOCK not set"))?,
    };
    let agent = AgentClient::connect_uds(path).await?;
    agent_auth(agent, handle, user).await
}

#[cfg(windows)]
async fn try_agent(handle: &mut Handle<Client>, user: &str, sock: Option<String>) -> anyhow::Result<bool> {
    let pipe = sock
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| r"\\.\pipe\openssh-ssh-agent".to_string());
    if let Ok(agent) = AgentClient::connect_named_pipe(&pipe).await {
        if agent_auth(agent, handle, user).await? {
            return Ok(true);
        }
    }
    match AgentClient::connect_pageant().await {
        Ok(agent) => agent_auth(agent, handle, user).await,
        Err(_) => Ok(false),
    }
}

pub fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/").or_else(|| p.strip_prefix("~\\")) {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().into_owned();
        }
    }
    p.to_string()
}

pub async fn run_session(
    ctx: Ctx,
    host_id: String,
    cols: u32,
    rows: u32,
    data: Channel<InvokeResponseBody>,
    mut rx: mpsc::UnboundedReceiver<Input>,
) {
    match session_inner(&ctx, &host_id, cols, rows, &data, &mut rx).await {
        Ok(msg) => ctx.status("closed", msg),
        Err(e) => ctx.status("error", format!("{e:#}")),
    }
}

async fn session_inner(
    ctx: &Ctx,
    host_id: &str,
    cols: u32,
    rows: u32,
    data: &Channel<InvokeResponseBody>,
    rx: &mut mpsc::UnboundedReceiver<Input>,
) -> anyhow::Result<String> {
    let host = ctx
        .store
        .lock()
        .unwrap()
        .effective_host(host_id)
        .ok_or_else(|| anyhow!("This host no longer exists"))?;
    let mut jumps = Vec::new();
    let handle = connect_host(ctx, host, 0, &mut jumps).await?;

    let mut channel = handle.channel_open_session().await?;
    channel.request_pty(false, "xterm-256color", cols, rows, 0, 0, &[]).await?;
    channel.request_shell(false).await?;
    ctx.status("connected", "");
    let id = host_id.to_string();
    ctx.save_store(|s| {
        if let Some(h) = s.data.hosts.iter_mut().find(|h| h.id == id) {
            h.last_connected = Some(now_ms());
        }
    });

    let mut exit_code = None;
    loop {
        tokio::select! {
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data: d }) | Some(ChannelMsg::ExtendedData { data: d, .. }) => {
                    let _ = data.send(InvokeResponseBody::Raw(d.to_vec()));
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => exit_code = Some(exit_status),
                Some(ChannelMsg::Close) | None => break,
                _ => {}
            },
            input = rx.recv() => match input {
                Some(Input::Data(bytes)) => channel.data(&bytes[..]).await?,
                Some(Input::Resize(c, r)) => { let _ = channel.window_change(c, r, 0, 0).await; }
                Some(Input::Break) => {}
                Some(Input::Close) | None => { let _ = channel.close().await; break; }
            },
        }
    }
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    for j in jumps.into_iter().rev() {
        let _ = j.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    Ok(match exit_code {
        Some(0) | None => "Connection closed".into(),
        Some(c) => format!("Session ended (exit code {c})"),
    })
}
