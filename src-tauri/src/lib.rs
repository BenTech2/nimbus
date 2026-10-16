mod keys;
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
use store::{new_id, now_ms, upsert, Data, Group, Host, Key, PasswordEntry, SecretFlags, Settings, Snippet, Store};

struct AppState {
    store: Arc<Mutex<Store>>,
    sessions: Mutex<HashMap<String, Session>>,
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
        if host.protocol.is_empty() {
            host.protocol = "ssh".into();
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

#[tauri::command]
fn export_data(state: State<AppState>, path: String, passphrase: Option<String>) -> CmdResult<()> {
    let s = state.store.lock().unwrap();
    transfer::export(&s, &PathBuf::from(path), passphrase.as_deref()).map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn import_preview(path: String) -> CmdResult<transfer::Preview> {
    transfer::preview(&PathBuf::from(path)).map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn import_apply(
    state: State<AppState>,
    path: String,
    mode: String,
    passphrase: Option<String>,
) -> CmdResult<Snapshot> {
    mutate(&state, |s| transfer::apply(s, &PathBuf::from(path), &mode, passphrase.as_deref()))
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
    let ctx = Ctx { store: state.store.clone(), prompts: state.prompts.clone(), events };
    let task = tauri::async_runtime::spawn(ssh::run_session(ctx, host_id, cols.max(1), rows.max(1), data, rx));
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
        if matches!(id, "new-tab" | "duplicate-tab" | "type-password" | "next-tab" | "prev-tab" | "close-tab") {
            let _ = app.emit("menu", id);
        }
    });
    Ok(())
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
            #[cfg(target_os = "macos")]
            install_mac_menu(app)?;
            app.manage(AppState {
                store: Arc::new(Mutex::new(store)),
                sessions: Mutex::new(HashMap::new()),
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
            ssh_type_password,
            export_data,
            import_preview,
            import_apply,
            import_ssh_config,
            ssh_connect,
            ssh_write,
            ssh_resize,
            ssh_close,
            prompt_reply,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Nimbus");
}
