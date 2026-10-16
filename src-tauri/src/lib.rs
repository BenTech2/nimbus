mod files;
mod keys;
mod serial;
mod ssh;
mod sshconfig;
mod store;
mod transfer;
mod vault;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::Value;
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{Manager, State};
use tokio::sync::mpsc;

use ssh::{Ctx, Input, Prompts, Session};
use store::{new_id, now_ms, upsert, ApiCredential, Data, Group, Host, Key, PasswordEntry, PasswordGroup, SecretFlags, Settings, Snippet, Store};

/// A Files tab's connection: still connecting (so closing the tab can stop it), or ready.
enum FsSlot {
    Connecting(tauri::async_runtime::JoinHandle<()>),
    Ready(Arc<files::Remote>),
}

struct AppState {
    store: Arc<Mutex<Store>>,
    sessions: Mutex<HashMap<String, Session>>,
    files: Arc<Mutex<HashMap<String, FsSlot>>>,
    prompts: Arc<Prompts>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    data: Data,
    secrets: HashMap<String, SecretFlags>,
    vault_mode: String,
    data_dir: String,
    warning: Option<String>,
    platform: String,
    version: String,
}

type CmdResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn snapshot(s: &Store) -> Snapshot {
    Snapshot {
        data: s.data.clone(),
        secrets: s.secret_flags(),
        vault_mode: s.vault_mode().into(),
        data_dir: s.dir().to_string_lossy().into_owned(),
        warning: s.secrets_warning.clone(),
        platform: std::env::consts::OS.into(),
        version: env!("CARGO_PKG_VERSION").into(),
    }
}

/// Run a mutation, save, and hand the UI the new state.
fn mutate(state: &State<AppState>, f: impl FnOnce(&mut Store) -> anyhow::Result<()>) -> CmdResult<Snapshot> {
    let mut s = state.store.lock().unwrap();
    f(&mut s).map_err(|e| format!("{e:#}"))?;
    s.save().map_err(|e| format!("Could not save: {e:#}"))?;
    Ok(snapshot(&s))
}

fn blank_to_none(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[tauri::command]
fn get_state(state: State<AppState>) -> Snapshot {
    snapshot(&state.store.lock().unwrap())
}

/// `password`: None leaves the saved password alone, Some("") clears it.
#[tauri::command]
fn save_host(state: State<AppState>, mut host: Host, password: Option<String>) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        if host.id.is_empty() {
            host.id = new_id();
        }
        host.address = host.address.trim().to_string();
        host.label = host.label.trim().to_string();
        if host.label.is_empty() {
            host.label = host.address.clone();
        }
        host.username = blank_to_none(host.username);
        host.group_id = blank_to_none(host.group_id);
        host.key_id = blank_to_none(host.key_id);
        host.jump_host_id = blank_to_none(host.jump_host_id).filter(|j| *j != host.id);
        host.port = host.port.filter(|p| *p != 0);
        if !matches!(host.protocol.as_str(), "ssh" | "ftp" | "ftps" | "serial") {
            host.protocol = "ssh".into();
        }
        if !host.is_serial() {
            (host.baud_rate, host.data_bits, host.parity, host.stop_bits, host.flow_control, host.newline) = (None, None, None, None, None, None);
            host.local_echo = false;
        } else {
            host.baud_rate = host.baud_rate.filter(|b| *b > 0);
            host.data_bits = host.data_bits.filter(|b| (5..=8).contains(b));
            host.stop_bits = host.stop_bits.filter(|b| (1..=2).contains(b));
            host.parity = blank_to_none(host.parity).filter(|p| p == "odd" || p == "even");
            host.flow_control = blank_to_none(host.flow_control).filter(|f| f == "software" || f == "hardware");
            host.newline = blank_to_none(host.newline).filter(|n| n == "lf" || n == "crlf");
            host.port = None;
        }
        if !host.is_ssh() {
            host.key_id = None;
            host.jump_host_id = None;
        }
        if let Some(pw) = password {
            s.update_secret(&host.id, |sec| sec.password = (!pw.is_empty()).then_some(pw));
        }
        upsert(&mut s.data.hosts, host, |h| &h.id);
        Ok(())
    })
}

#[tauri::command]
fn duplicate_host(state: State<AppState>, id: String) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        let mut h = s.host(&id).cloned().ok_or_else(|| anyhow::anyhow!("Host not found"))?;
        let secret = s.secret(&id);
        h.id = new_id();
        h.label = format!("{} copy", h.label);
        h.last_connected = None;
        let nid = h.id.clone();
        s.update_secret(&nid, |sec| *sec = secret);
        s.data.hosts.push(h);
        Ok(())
    })
}

#[tauri::command]
fn delete_host(state: State<AppState>, id: String) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        s.data.hosts.retain(|h| h.id != id);
        for h in s.data.hosts.iter_mut() {
            if h.jump_host_id.as_deref() == Some(&id) {
                h.jump_host_id = None;
            }
        }
        s.update_secret(&id, |sec| *sec = Default::default());
        Ok(())
    })
}

#[tauri::command]
fn save_group(state: State<AppState>, mut group: Group) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        if group.id.is_empty() {
            group.id = new_id();
        }
        group.name = group.name.trim().to_string();
        if group.name.is_empty() {
            anyhow::bail!("Give the group a name");
        }
        group.username = blank_to_none(group.username);
        group.key_id = blank_to_none(group.key_id);
        group.port = group.port.filter(|p| *p != 0);
        upsert(&mut s.data.groups, group, |g| &g.id);
        Ok(())
    })
}

/// Deleting a group keeps its hosts; they move to "no group".
#[tauri::command]
fn delete_group(state: State<AppState>, id: String) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        s.data.groups.retain(|g| g.id != id);
        for h in s.data.hosts.iter_mut() {
            if h.group_id.as_deref() == Some(&id) {
                h.group_id = None;
            }
        }
        Ok(())
    })
}

/// `private_key`: None keeps the stored key (label-only edit). `passphrase`: None keeps, Some("") clears.
#[tauri::command]
fn save_key(
    state: State<AppState>,
    mut key: Key,
    private_key: Option<String>,
    passphrase: Option<String>,
) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        if key.id.is_empty() {
            key.id = new_id();
        }
        let existing = s.secret(&key.id);
        let pem = private_key
            .filter(|p| !p.trim().is_empty())
            .or(existing.private_key.clone())
            .ok_or_else(|| anyhow::anyhow!("Paste a private key, choose a key file, or generate one"))?;
        let pass = match &passphrase {
            Some(p) => (!p.is_empty()).then(|| p.clone()),
            None => existing.passphrase.clone(),
        };
        let info = keys::describe(&pem, pass.as_deref())?;
        key.key_type = info.key_type;
        key.public_key = info.public_key;
        key.fingerprint = info.fingerprint;
        key.encrypted = info.encrypted;
        key.label = key.label.trim().to_string();
        if key.label.is_empty() {
            key.label = format!("{} key", key.key_type);
        }
        let pem = pem.trim().to_string() + "\n";
        s.update_secret(&key.id, |sec| {
            sec.private_key = Some(pem);
            sec.passphrase = pass;
        });
        upsert(&mut s.data.keys, key, |k| &k.id);
        Ok(())
    })
}

#[tauri::command]
fn generate_key(label: String) -> CmdResult<String> {
    keys::generate_ed25519(&label).map_err(err)
}

#[tauri::command]
fn read_text_file(path: String) -> CmdResult<String> {
    let meta = std::fs::metadata(&path).map_err(err)?;
    if meta.len() > 1024 * 1024 {
        return Err("That file is too large to be a key".into());
    }
    std::fs::read_to_string(&path).map_err(err)
}

#[tauri::command]
fn delete_key(state: State<AppState>, id: String) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        s.data.keys.retain(|k| k.id != id);
        for h in s.data.hosts.iter_mut() {
            if h.key_id.as_deref() == Some(&id) {
                h.key_id = None;
            }
        }
        for g in s.data.groups.iter_mut() {
            if g.key_id.as_deref() == Some(&id) {
                g.key_id = None;
            }
        }
        s.update_secret(&id, |sec| *sec = Default::default());
        Ok(())
    })
}

#[tauri::command]
fn save_snippet(state: State<AppState>, mut snippet: Snippet) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        if snippet.id.is_empty() {
            snippet.id = new_id();
        }
        if snippet.name.trim().is_empty() {
            snippet.name = snippet.command.lines().next().unwrap_or("Snippet").chars().take(40).collect();
        }
        upsert(&mut s.data.snippets, snippet, |x| &x.id);
        Ok(())
    })
}

#[tauri::command]
fn delete_snippet(state: State<AppState>, id: String) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        s.data.snippets.retain(|x| x.id != id);
        Ok(())
    })
}

/// `password`: None keeps the saved one, Some("") clears it.
#[tauri::command]
fn save_password(state: State<AppState>, mut entry: PasswordEntry, password: Option<String>) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        if entry.id.is_empty() {
            entry.id = new_id();
        }
        entry.name = entry.name.trim().to_string();
        if entry.name.is_empty() {
            anyhow::bail!("Give the password a name");
        }
        entry.username = blank_to_none(entry.username);
        entry.group_id = blank_to_none(entry.group_id);
        entry.url = blank_to_none(entry.url);
        entry.notes = blank_to_none(entry.notes);
        entry.updated = now_ms();
        if let Some(pw) = password {
            s.update_secret(&entry.id, |sec| sec.password = (!pw.is_empty()).then_some(pw));
        }
        upsert(&mut s.data.passwords, entry, |x| &x.id);
        Ok(())
    })
}

#[tauri::command]
fn delete_password(state: State<AppState>, id: String) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        s.data.passwords.retain(|x| x.id != id);
        s.update_secret(&id, |sec| *sec = Default::default());
        Ok(())
    })
}

#[tauri::command]
fn save_password_group(state: State<AppState>, mut group: PasswordGroup) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        if group.id.is_empty() {
            group.id = new_id();
        }
        group.name = group.name.trim().to_string();
        if group.name.is_empty() {
            anyhow::bail!("Give the group a name");
        }
        upsert(&mut s.data.password_groups, group, |g| &g.id);
        Ok(())
    })
}

/// Deleting a password group keeps its passwords; they move to "no group".
#[tauri::command]
fn delete_password_group(state: State<AppState>, id: String) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        s.data.password_groups.retain(|g| g.id != id);
        for p in s.data.passwords.iter_mut() {
            if p.group_id.as_deref() == Some(&id) {
                p.group_id = None;
            }
        }
        Ok(())
    })
}

// ---------- API keys ----------

const API_KINDS: [&str; 5] = ["apiKey", "bearer", "basic", "oauth2", "custom"];

/// Save an API credential. `secrets` holds secret field values by field id: a missing id or
/// null keeps what's saved, "" clears it. Saved values for fields that no longer exist (or
/// stopped being secret) are dropped.
#[tauri::command]
fn save_api_key(
    state: State<AppState>,
    entry: ApiCredential,
    secrets: HashMap<String, Option<String>>,
) -> CmdResult<Snapshot> {
    mutate(&state, |s| apply_api_key(s, entry, secrets))
}

pub(crate) fn apply_api_key(s: &mut Store, mut entry: ApiCredential, secrets: HashMap<String, Option<String>>) -> anyhow::Result<()> {
    {
        if entry.id.is_empty() {
            entry.id = new_id();
        }
        entry.name = entry.name.trim().to_string();
        if entry.name.is_empty() {
            anyhow::bail!("Give the credential a name");
        }
        if !API_KINDS.contains(&entry.kind.as_str()) {
            entry.kind = "custom".into();
        }
        entry.group_id = blank_to_none(entry.group_id);
        entry.service = blank_to_none(entry.service);
        entry.environment = blank_to_none(entry.environment);
        entry.base_url = blank_to_none(entry.base_url);
        entry.notes = blank_to_none(entry.notes);
        let mut seen = std::collections::HashSet::new();
        entry.fields.retain_mut(|f| {
            f.label = f.label.trim().to_string();
            if f.id.trim().is_empty() {
                f.id = new_id();
            }
            if f.secret {
                f.value = None;
            } else {
                f.value = blank_to_none(f.value.take());
            }
            seen.insert(f.id.clone())
        });
        entry.updated = now_ms();
        let secret_ids: std::collections::HashSet<String> = entry.fields.iter().filter(|f| f.secret).map(|f| f.id.clone()).collect();
        s.update_secret(&entry.id, |sec| {
            sec.fields.retain(|k, _| secret_ids.contains(k));
            for (fid, v) in secrets {
                if !secret_ids.contains(&fid) {
                    continue;
                }
                match v {
                    None => {}
                    Some(v) if v.is_empty() => {
                        sec.fields.remove(&fid);
                    }
                    Some(v) => {
                        sec.fields.insert(fid, v);
                    }
                }
            }
        });
        upsert(&mut s.data.api_keys, entry, |x| &x.id);
        Ok(())
    }
}

#[tauri::command]
fn delete_api_key(state: State<AppState>, id: String) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        s.data.api_keys.retain(|x| x.id != id);
        s.update_secret(&id, |sec| *sec = Default::default());
        Ok(())
    })
}

/// One secret field of an API credential, for show / copy.
#[tauri::command]
fn reveal_api_secret(state: State<AppState>, id: String, field_id: String) -> CmdResult<String> {
    api_secret(&state.store.lock().unwrap(), &id, &field_id)
}

pub(crate) fn api_secret(s: &Store, id: &str, field_id: &str) -> Result<String, String> {
    let entry = s.data.api_keys.iter().find(|a| a.id == id).ok_or("That credential no longer exists")?;
    if !entry.fields.iter().any(|f| f.id == field_id && f.secret) {
        return Err("Not a secret field of this credential".into());
    }
    s.secret(id).fields.get(field_id).cloned().ok_or_else(|| "Nothing saved for that field".into())
}

#[tauri::command]
fn save_api_group(state: State<AppState>, mut group: PasswordGroup) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        if group.id.is_empty() {
            group.id = new_id();
        }
        group.name = group.name.trim().to_string();
        if group.name.is_empty() {
            anyhow::bail!("Give the group a name");
        }
        upsert(&mut s.data.api_groups, group, |g| &g.id);
        Ok(())
    })
}

/// Deleting a group keeps its credentials; they move to "no group".
#[tauri::command]
fn delete_api_group(state: State<AppState>, id: String) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        s.data.api_groups.retain(|g| g.id != id);
        for a in s.data.api_keys.iter_mut() {
            if a.group_id.as_deref() == Some(&id) {
                a.group_id = None;
            }
        }
        Ok(())
    })
}

/// For "show" and "copy" in the Passwords view. Only password entries can be read this way;
/// host passwords are never handed to the UI.
#[tauri::command]
fn reveal_password(state: State<AppState>, id: String) -> CmdResult<String> {
    let s = state.store.lock().unwrap();
    if !s.data.passwords.iter().any(|p| p.id == id) {
        return Err("Not a saved password".into());
    }
    s.secret(&id).password.ok_or_else(|| "No password saved for this entry".into())
}

/// The bytes to send for "Type password": a host's own saved password or a Passwords entry,
/// plus Enter if that setting is on. Anything else (e.g. a key's passphrase) is refused.
pub(crate) fn password_keystrokes(s: &Store, secret_id: &str) -> Result<Vec<u8>, String> {
    let known = s.host(secret_id).is_some() || s.data.passwords.iter().any(|p| p.id == secret_id);
    if !known {
        return Err("That password no longer exists".into());
    }
    let mut bytes = s.secret(secret_id).password.ok_or("No password is saved for that")?.into_bytes();
    if s.data.settings.type_password_enter {
        bytes.push(b'\r');
    }
    Ok(bytes)
}

/// Type a saved password (a host's own, or a Passwords entry) into a session as keystrokes.
/// The password goes straight from the encrypted store to the SSH channel.
#[tauri::command]
fn ssh_type_password(state: State<AppState>, session_id: String, secret_id: String) -> CmdResult<()> {
    let bytes = password_keystrokes(&state.store.lock().unwrap(), &secret_id)?;
    let sessions = state.sessions.lock().unwrap();
    let session = sessions.get(&session_id).ok_or("This session is not connected")?;
    session.input.send(Input::Data(bytes)).map_err(|_| "This session is not connected".to_string())
}

#[tauri::command]
fn delete_known_host(state: State<AppState>, host: String) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        s.data.known_hosts.retain(|k| k.host != host);
        Ok(())
    })
}

#[tauri::command]
fn save_settings(state: State<AppState>, settings: Settings) -> CmdResult<Snapshot> {
    mutate(&state, |s| {
        s.data.settings = settings;
        Ok(())
    })
}

/// Everything is encrypted with `password`; there's no unprotected export.
#[tauri::command]
fn export_data(state: State<AppState>, path: String, password: String) -> CmdResult<()> {
    let s = state.store.lock().unwrap();
    transfer::export(&s, &PathBuf::from(path), &password).map_err(|e| format!("{e:#}"))
}

/// Decrypts the file to show what's in it, so a wrong password is caught before anything changes.
#[tauri::command]
async fn import_preview(path: String, password: String) -> CmdResult<transfer::Preview> {
    // scrypt is deliberately slow; keep it off the UI thread.
    tauri::async_runtime::spawn_blocking(move || transfer::preview(&PathBuf::from(path), &password))
        .await
        .map_err(err)?
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn import_apply(state: State<AppState>, path: String, mode: String, password: String) -> CmdResult<Snapshot> {
    mutate(&state, |s| transfer::apply(s, &PathBuf::from(path), &mode, &password))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SshConfigResult {
    report: sshconfig::ImportReport,
    state: Snapshot,
}

#[tauri::command]
fn import_ssh_config(state: State<AppState>) -> CmdResult<SshConfigResult> {
    let mut report = None;
    let snap = mutate(&state, |s| {
        report = Some(sshconfig::import(s));
        Ok(())
    })?;
    Ok(SshConfigResult { report: report.unwrap_or_default(), state: snap })
}

#[tauri::command]
fn ssh_connect(
    state: State<AppState>,
    session_id: String,
    host_id: String,
    cols: u32,
    rows: u32,
    events: Channel<Value>,
    data: Channel<InvokeResponseBody>,
) -> CmdResult<()> {
    let (tx, rx) = mpsc::unbounded_channel();
    let serial = state.store.lock().unwrap().host(&host_id).is_some_and(|h| h.is_serial());
    let ctx = Ctx { store: state.store.clone(), prompts: state.prompts.clone(), events };
    let task = if serial {
        tauri::async_runtime::spawn(serial::run_serial(ctx, host_id, data, rx))
    } else {
        tauri::async_runtime::spawn(ssh::run_session(ctx, host_id, cols.max(1), rows.max(1), data, rx))
    };
    let old = state.sessions.lock().unwrap().insert(session_id, Session { input: tx, task });
    if let Some(old) = old {
        old.task.abort();
    }
    Ok(())
}

#[tauri::command]
fn ssh_write(state: State<AppState>, session_id: String, data: String) {
    if let Some(s) = state.sessions.lock().unwrap().get(&session_id) {
        let _ = s.input.send(Input::Data(data.into_bytes()));
    }
}

#[tauri::command]
fn ssh_break(state: State<AppState>, session_id: String) {
    if let Some(s) = state.sessions.lock().unwrap().get(&session_id) {
        let _ = s.input.send(Input::Break);
    }
}

#[tauri::command]
fn serial_ports() -> CmdResult<Vec<serial::PortInfo>> {
    serial::list_ports().map_err(anyhow_err)
}

#[tauri::command]
fn ssh_resize(state: State<AppState>, session_id: String, cols: u32, rows: u32) {
    if let Some(s) = state.sessions.lock().unwrap().get(&session_id) {
        let _ = s.input.send(Input::Resize(cols.max(1), rows.max(1)));
    }
}

#[tauri::command]
fn ssh_close(state: State<AppState>, session_id: String) {
    if let Some(s) = state.sessions.lock().unwrap().remove(&session_id) {
        // A connected shell closes politely; anything still connecting or waiting on a
        // prompt after a few seconds is stopped.
        let _ = s.input.send(Input::Close);
        let task = s.task;
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            task.abort();
        });
    }
}

// ---------- Files tab ----------

/// Connect a Files tab to a host (SFTP for SSH hosts, FTP/FTPS otherwise). Progress, prompts
/// and the result arrive on `events`, like a terminal's connection.
#[tauri::command]
fn fs_open(state: State<AppState>, session_id: String, host_id: String, events: Channel<Value>) -> CmdResult<()> {
    let ctx = Ctx { store: state.store.clone(), prompts: state.prompts.clone(), events };
    let slots = state.files.clone();
    let sid = session_id.clone();
    // Hold the lock while spawning, so the task can't finish before its slot exists.
    let mut map = state.files.lock().unwrap();
    let task = tauri::async_runtime::spawn(async move {
        match files::connect(&ctx, &host_id).await {
            Ok((remote, home)) => {
                let remote = Arc::new(remote);
                let wanted = {
                    let mut m = slots.lock().unwrap();
                    let wanted = matches!(m.get(&sid), Some(FsSlot::Connecting(_)));
                    if wanted {
                        m.insert(sid, FsSlot::Ready(remote.clone()));
                    }
                    wanted
                };
                if wanted {
                    let _ = ctx.events.send(serde_json::json!({ "type": "status", "state": "connected", "message": "", "home": home }));
                } else {
                    remote.close().await;
                }
            }
            Err(e) => ctx.status("error", format!("{e:#}")),
        }
    });
    if let Some(old) = map.insert(session_id, FsSlot::Connecting(task)) {
        close_slot(old);
    }
    Ok(())
}

fn close_slot(slot: FsSlot) {
    match slot {
        FsSlot::Connecting(task) => task.abort(),
        FsSlot::Ready(r) => {
            tauri::async_runtime::spawn(async move { r.close().await });
        }
    }
}

#[tauri::command]
fn fs_close(state: State<AppState>, session_id: String) {
    if let Some(slot) = state.files.lock().unwrap().remove(&session_id) {
        close_slot(slot);
    }
}

fn remote(state: &State<'_, AppState>, session_id: &str) -> CmdResult<Arc<files::Remote>> {
    match state.files.lock().unwrap().get(session_id) {
        Some(FsSlot::Ready(r)) => Ok(r.clone()),
        _ => Err("Not connected".into()),
    }
}

fn anyhow_err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

/// `session_id` "local" is this computer. An empty path is the home / login folder.
#[tauri::command]
async fn fs_list(state: State<'_, AppState>, session_id: String, path: String) -> CmdResult<files::Listing> {
    if session_id == files::LOCAL {
        return files::local_list(&path).map_err(anyhow_err);
    }
    remote(&state, &session_id)?.list(&path).await.map_err(anyhow_err)
}

#[tauri::command]
async fn fs_mkdir(state: State<'_, AppState>, session_id: String, dir: String, name: String) -> CmdResult<()> {
    if session_id == files::LOCAL {
        return files::local_mkdir(&dir, &name).map_err(anyhow_err);
    }
    remote(&state, &session_id)?.mkdir(&dir, &name).await.map_err(anyhow_err)
}

#[tauri::command]
async fn fs_rename(state: State<'_, AppState>, session_id: String, dir: String, from: String, to: String) -> CmdResult<()> {
    if session_id == files::LOCAL {
        return files::local_rename(&dir, &from, &to).map_err(anyhow_err);
    }
    remote(&state, &session_id)?.rename(&dir, &from, &to).await.map_err(anyhow_err)
}

/// Local items go to the Trash; remote items are deleted for good (the UI confirms first).
#[tauri::command]
async fn fs_delete(state: State<'_, AppState>, session_id: String, items: Vec<files::Item>) -> CmdResult<()> {
    if session_id == files::LOCAL {
        let paths: Vec<String> = items.into_iter().map(|i| i.path).collect();
        return files::local_delete(&paths).map_err(anyhow_err);
    }
    remote(&state, &session_id)?.delete(&items).await.map_err(anyhow_err)
}

/// Start copying; progress arrives as "transfer" events on the tab's event channel.
#[tauri::command]
fn fs_transfer(
    state: State<AppState>,
    session_id: String,
    transfer_id: String,
    upload: bool,
    items: Vec<files::Item>,
    dest: String,
) -> CmdResult<()> {
    let r = remote(&state, &session_id)?;
    tauri::async_runtime::spawn(r.transfer(transfer_id, upload, items, dest));
    Ok(())
}

#[tauri::command]
fn fs_cancel(state: State<AppState>, session_id: String, transfer_id: String) {
    if let Ok(r) = remote(&state, &session_id) {
        r.cancel(&transfer_id);
    }
}

#[tauri::command]
fn prompt_reply(state: State<AppState>, id: String, value: Value) {
    state.prompts.reply(&id, value);
}

/// macOS shows a menu bar; replace the default one so ⌘W closes a tab rather than the window.
/// Tab commands are forwarded to the UI as a "menu" event.
#[cfg(target_os = "macos")]
fn install_mac_menu(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder};
    use tauri::Emitter;
    let item = |id: &str, label: &str, accel: &str| MenuItemBuilder::with_id(id, label).accelerator(accel).build(app);
    let app_menu = SubmenuBuilder::new(app, "Nimbus")
        .about(None)
        .separator()
        .services()
        .separator()
        .hide()
        .hide_others()
        .show_all()
        .separator()
        .quit()
        .build()?;
    let shell = SubmenuBuilder::new(app, "Shell")
        .item(&item("new-tab", "New Tab", "CmdOrCtrl+T")?)
        .item(&item("duplicate-tab", "Duplicate Tab", "CmdOrCtrl+D")?)
        .item(&item("type-password", "Type Password", "CmdOrCtrl+Shift+P")?)
        .item(&item("open-sftp", "Open SFTP", "CmdOrCtrl+Shift+O")?)
        .separator()
        .item(&item("next-tab", "Next Tab", "CmdOrCtrl+Shift+]")?)
        .item(&item("prev-tab", "Previous Tab", "CmdOrCtrl+Shift+[")?)
        .separator()
        .item(&item("close-tab", "Close Tab", "CmdOrCtrl+W")?)
        .build()?;
    let edit = SubmenuBuilder::new(app, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;
    let view = SubmenuBuilder::new(app, "View").fullscreen().build()?;
    let window = SubmenuBuilder::new(app, "Window").minimize().maximize().build()?;
    let menu = MenuBuilder::new(app).items(&[&app_menu, &shell, &edit, &view, &window]).build()?;
    app.set_menu(menu)?;
    app.on_menu_event(|app, event| {
        let id = event.id().0.as_str();
        if matches!(id, "new-tab" | "duplicate-tab" | "type-password" | "open-sftp" | "next-tab" | "prev-tab" | "close-tab") {
            let _ = app.emit("menu", id);
        }
    });
    Ok(())
}

/// Pages that belong to Nimbus itself: the bundled UI, or the dev server while developing.
/// Anything else must never load inside the app window.
pub(crate) fn is_app_url(url: &tauri::Url) -> bool {
    match url.scheme() {
        "tauri" | "asset" => true,
        "http" | "https" => matches!(url.host_str(), Some("tauri.localhost" | "localhost" | "127.0.0.1")),
        "about" => url.as_str() == "about:blank",
        _ => false,
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let dir = match std::env::var_os("NIMBUS_DATA_DIR") {
                Some(d) => PathBuf::from(d),
                None => app.path().app_data_dir()?,
            };
            let store = Store::open(dir)?;
            // The window is created here rather than from the config so that every navigation
            // can be checked: a link to a website opens in the default browser, never in Nimbus.
            let config = app
                .config()
                .app
                .windows
                .iter()
                .find(|w| w.label == "main")
                .cloned()
                .ok_or("no main window in tauri.conf.json")?;
            let handle = app.handle().clone();
            tauri::WebviewWindowBuilder::from_config(app.handle(), &config)?
                .on_navigation(move |url| {
                    if is_app_url(url) {
                        return true;
                    }
                    if matches!(url.scheme(), "http" | "https" | "mailto") {
                        use tauri_plugin_opener::OpenerExt;
                        let _ = handle.opener().open_url(url.as_str(), None::<&str>);
                    }
                    false
                })
                .build()?;
            #[cfg(target_os = "macos")]
            install_mac_menu(app)?;
            app.manage(AppState {
                store: Arc::new(Mutex::new(store)),
                sessions: Mutex::new(HashMap::new()),
                files: Arc::new(Mutex::new(HashMap::new())),
                prompts: Arc::new(Prompts::default()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            save_host,
            duplicate_host,
            delete_host,
            save_group,
            delete_group,
            save_key,
            generate_key,
            read_text_file,
            delete_key,
            save_snippet,
            delete_snippet,
            delete_known_host,
            save_settings,
            save_password,
            delete_password,
            reveal_password,
            save_password_group,
            delete_password_group,
            save_api_key,
            delete_api_key,
            reveal_api_secret,
            save_api_group,
            delete_api_group,
            ssh_type_password,
            export_data,
            import_preview,
            import_apply,
            import_ssh_config,
            ssh_connect,
            ssh_write,
            ssh_resize,
            ssh_break,
            serial_ports,
            ssh_close,
            fs_open,
            fs_close,
            fs_list,
            fs_mkdir,
            fs_rename,
            fs_delete,
            fs_transfer,
            fs_cancel,
            prompt_reply,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Nimbus");
}
