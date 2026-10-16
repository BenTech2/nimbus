//! Backend tests. The SSH ones need a reachable test server and are skipped unless
//! NIMBUS_TEST_SSHD=<dir> points at a folder containing `client` (plain key) and
//! `client_enc` (key with passphrase "secretpass"), with sshd listening on 127.0.0.1:2222.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tauri::ipc::{Channel, InvokeResponseBody};
use tokio::sync::mpsc;

use crate::ssh::{self, Ctx, Input, Prompts};
use crate::store::{new_id, Host, Key, Snippet, Store};

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nimbus-test-{name}-{}", new_id()));
    std::fs::create_dir_all(&d).unwrap();
    // A key file makes the vault skip the real OS keychain during tests.
    std::fs::write(d.join("master.key"), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
    d
}

fn sshd_dir() -> Option<PathBuf> {
    std::env::var_os("NIMBUS_TEST_SSHD").map(PathBuf::from)
}

fn user() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap()
}

/// Run one session; `answers` are replies to prompts in order. Returns (events, output).
async fn session(
    store: Arc<Mutex<Store>>,
    host_id: &str,
    answers: Vec<Value>,
    input: &[&str],
) -> (Vec<Value>, String) {
    let prompts = Arc::new(Prompts::default());
    let events_log = Arc::new(Mutex::new(Vec::<Value>::new()));
    let output = Arc::new(Mutex::new(Vec::<u8>::new()));
    let answers = Arc::new(Mutex::new(VecDeque::from(answers)));

    let (p, log, ans) = (prompts.clone(), events_log.clone(), answers.clone());
    let events = Channel::<Value>::new(move |body| {
        if let InvokeResponseBody::Json(s) = body {
            let v: Value = serde_json::from_str(&s).unwrap();
            if v["type"] == "prompt" {
                let reply = ans.lock().unwrap().pop_front().unwrap_or(Value::Null);
                p.reply(v["id"].as_str().unwrap(), reply);
            }
            log.lock().unwrap().push(v);
        }
        Ok(())
    });
    let out = output.clone();
    let data = Channel::new(move |body| {
        if let InvokeResponseBody::Raw(b) = body {
            out.lock().unwrap().extend_from_slice(&b);
        }
        Ok(())
    });

    let (tx, rx) = mpsc::unbounded_channel();
    let ctx = Ctx { store, prompts, events };
    let task = tokio::spawn(ssh::run_session(ctx, host_id.to_string(), 120, 30, data, rx));

    // Wait until connected (or finished), then type.
    for _ in 0..100 {
        let done = events_log.lock().unwrap().iter().any(|e| {
            e["type"] == "status" && matches!(e["state"].as_str(), Some("connected" | "error" | "closed"))
        });
        if done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for line in input {
        let _ = tx.send(Input::Data(line.as_bytes().to_vec()));
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    let ev = events_log.lock().unwrap().clone();
    let out = String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
    (ev, out)
}

fn add_key(store: &mut Store, path: PathBuf, passphrase: Option<&str>) -> String {
    let pem = std::fs::read_to_string(path).unwrap();
    let info = crate::keys::describe(&pem, None).unwrap();
    let id = new_id();
    store.data.keys.push(Key {
        id: id.clone(),
        label: "test".into(),
        key_type: info.key_type,
        public_key: info.public_key,
        fingerprint: info.fingerprint,
        encrypted: info.encrypted,
    });
    store.update_secret(&id, |s| {
        s.private_key = Some(pem);
        s.passphrase = passphrase.map(String::from);
    });
    id
}

fn add_host(store: &mut Store, key_id: Option<String>, jump: Option<String>) -> String {
    let id = new_id();
    store.data.hosts.push(Host {
        id: id.clone(),
        label: "local".into(),
        address: "127.0.0.1".into(),
        port: Some(2222),
        username: Some(user()),
        key_id,
        use_agent: false,
        jump_host_id: jump,
        ..Default::default()
    });
    id
}

fn states(ev: &[Value]) -> Vec<String> {
    ev.iter().filter(|e| e["type"] == "status").map(|e| e["state"].as_str().unwrap().to_string()).collect()
}

fn prompt_kinds(ev: &[Value]) -> Vec<String> {
    ev.iter().filter(|e| e["type"] == "prompt").map(|e| e["kind"].as_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn ssh_key_login_trust_and_shell() {
    let Some(dir) = sshd_dir() else { return };
    let mut s = Store::open(temp_dir("key")).unwrap();
    let k = add_key(&mut s, dir.join("client"), None);
    let h = add_host(&mut s, Some(k), None);
    let store = Arc::new(Mutex::new(s));

    // First connect: asked to trust the host key; shell runs our command.
    let (ev, out) = session(store.clone(), &h, vec![json!({ "accept": true })], &["echo NIMBUS_$((40+2))\r", "exit\r"]).await;
    assert_eq!(prompt_kinds(&ev), vec!["hostkey"], "{ev:?}");
    assert!(states(&ev).contains(&"connected".into()), "{ev:?}");
    assert!(out.contains("NIMBUS_42"), "output was: {out}");
    assert_eq!(states(&ev).last().unwrap(), "closed");
    assert_eq!(store.lock().unwrap().data.known_hosts.len(), 1);
    assert!(store.lock().unwrap().host(&h).unwrap().last_connected.is_some());

    // Second connect: host is known, so no prompt at all.
    let (ev, _) = session(store.clone(), &h, vec![], &["exit\r"]).await;
    assert!(prompt_kinds(&ev).is_empty(), "{ev:?}");

    // Tamper with the stored fingerprint: user is warned with the previous value, and refusing aborts.
    store.lock().unwrap().data.known_hosts[0].fingerprint = "SHA256:not-the-real-one".into();
    let (ev, _) = session(store.clone(), &h, vec![json!({ "accept": false })], &[]).await;
    let p = ev.iter().find(|e| e["type"] == "prompt").unwrap();
    assert_eq!(p["data"]["previous"], "SHA256:not-the-real-one");
    assert_eq!(states(&ev).last().unwrap(), "error");
    let msg = ev.iter().rev().find(|e| e["type"] == "status").unwrap()["message"].as_str().unwrap().to_string();
    assert!(msg.contains("not trusted"), "{msg}");
}

#[tokio::test]
async fn ssh_encrypted_key_prompts_then_remembers() {
    let Some(dir) = sshd_dir() else { return };
    let mut s = Store::open(temp_dir("enc")).unwrap();
    let k = add_key(&mut s, dir.join("client_enc"), None);
    let h = add_host(&mut s, Some(k.clone()), None);
    let store = Arc::new(Mutex::new(s));

    let answers = vec![
        json!({ "accept": true }),
        json!({ "value": "wrong", "save": true }),
        json!({ "value": "secretpass", "save": true }),
    ];
    let (ev, out) = session(store.clone(), &h, answers, &["echo ENC_OK\r", "exit\r"]).await;
    assert_eq!(prompt_kinds(&ev), vec!["hostkey", "passphrase", "passphrase"], "{ev:?}");
    assert!(out.contains("ENC_OK"), "{out}");
    // Only the correct passphrase is saved.
    assert_eq!(store.lock().unwrap().secret(&k).passphrase.as_deref(), Some("secretpass"));

    let (ev, out) = session(store.clone(), &h, vec![], &["echo AGAIN\r", "exit\r"]).await;
    assert!(prompt_kinds(&ev).is_empty(), "{ev:?}");
    assert!(out.contains("AGAIN"));
}

#[tokio::test]
async fn ssh_password_fallback_is_offered_and_cancel_stops() {
    let Some(_) = sshd_dir() else { return };
    // No key and no agent: the test server only allows publickey, so nothing to try → clear failure, no hang.
    let mut s = Store::open(temp_dir("nokey")).unwrap();
    let h = add_host(&mut s, None, None);
    let store = Arc::new(Mutex::new(s));
    let (ev, _) = session(store, &h, vec![json!({ "accept": true })], &[]).await;
    assert_eq!(states(&ev).last().unwrap(), "error");
    let msg = ev.iter().rev().find(|e| e["type"] == "status").unwrap()["message"].as_str().unwrap().to_string();
    assert!(msg.contains("Authentication failed"), "{msg}");
}

#[tokio::test]
async fn ssh_through_jump_host() {
    let Some(dir) = sshd_dir() else { return };
    let mut s = Store::open(temp_dir("jump")).unwrap();
    let k = add_key(&mut s, dir.join("client"), None);
    let jump = add_host(&mut s, Some(k.clone()), None);
    let target = add_host(&mut s, Some(k), Some(jump));
    let store = Arc::new(Mutex::new(s));
    // Both hops are the same server, so the key is trusted once and recognised on the second hop.
    let (ev, out) = session(store, &target, vec![json!({ "accept": true })], &["echo VIA_JUMP\r", "exit\r"]).await;
    assert_eq!(prompt_kinds(&ev), vec!["hostkey"], "{ev:?}");
    assert!(ev.iter().any(|e| e["message"].as_str().is_some_and(|m| m.starts_with("Tunnelling"))), "{ev:?}");
    assert!(out.contains("VIA_JUMP"), "{out}");
}

#[test]
fn export_import_round_trip() {
    let src_dir = temp_dir("exp");
    let mut a = Store::open(src_dir.clone()).unwrap();
    let pem = crate::keys::generate_ed25519("t").unwrap();
    let info = crate::keys::describe(&pem, None).unwrap();
    a.data.keys.push(Key { id: "k1".into(), label: "gen".into(), key_type: info.key_type, public_key: info.public_key, fingerprint: info.fingerprint, encrypted: false });
    a.update_secret("k1", |s| s.private_key = Some(pem.clone()));
    a.data.groups.push(crate::store::Group { id: "g1".into(), name: "Prod".into(), ..Default::default() });
    a.data.hosts.push(Host { id: "h1".into(), label: "web".into(), address: "10.0.0.1".into(), group_id: Some("g1".into()), key_id: Some("k1".into()), ..Default::default() });
    a.update_secret("h1", |s| s.password = Some("hunter2".into()));
    a.data.snippets.push(Snippet { id: "s1".into(), name: "up".into(), command: "uptime".into(), run: true });
    a.save().unwrap();

    let file = src_dir.join("export.json");
    // Too-short passwords are refused, so there's no weak or unprotected export.
    assert!(crate::transfer::export(&a, &file, "short").is_err());
    crate::transfer::export(&a, &file, "correct horse").unwrap();
    // Nothing readable in the file: not secrets, and not even host names or addresses.
    let raw = std::fs::read_to_string(&file).unwrap();
    for leak in ["hunter2", "OPENSSH PRIVATE", "10.0.0.1", "web", "Prod", "uptime"] {
        assert!(!raw.contains(leak), "{leak} visible in the export");
    }

    // Fresh "other computer".
    let mut b = Store::open(temp_dir("imp")).unwrap();
    for wrong in ["wrong password", "", "Correct horse"] {
        assert!(crate::transfer::preview(&file, wrong).is_err());
        assert!(crate::transfer::apply(&mut b, &file, "merge", wrong).is_err());
    }
    assert!(b.data.hosts.is_empty() && b.secrets.is_empty(), "a failed import must change nothing");
    let p = crate::transfer::preview(&file, "correct horse").unwrap();
    assert_eq!((p.hosts, p.groups, p.keys, p.snippets), (1, 1, 1, 1));
    crate::transfer::apply(&mut b, &file, "merge", "correct horse").unwrap();
    assert_eq!(b.secret("h1").password.as_deref(), Some("hunter2"));
    assert_eq!(b.secret("k1").private_key.as_deref(), Some(pem.as_str()));
    assert_eq!(b.effective_host("h1").unwrap().group_id.as_deref(), Some("g1"));
    // Merging the same file again doesn't duplicate.
    crate::transfer::apply(&mut b, &file, "merge", "correct horse").unwrap();
    assert_eq!(b.data.hosts.len(), 1);
    // Secrets survive a save + reopen through the vault.
    b.save().unwrap();
    let dir_b = b.dir().to_path_buf();
    drop(b);
    let b2 = Store::open(dir_b).unwrap();
    assert_eq!(b2.secret("h1").password.as_deref(), Some("hunter2"));

    // A tampered file is rejected rather than half-imported.
    let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let data = v["encrypted"]["data"].as_str().unwrap().to_string();
    let flipped = format!("{}{}", if data.starts_with('A') { 'B' } else { 'A' }, &data[1..]);
    v["encrypted"]["data"] = json!(flipped);
    let tampered = src_dir.join("tampered.json");
    std::fs::write(&tampered, v.to_string()).unwrap();
    assert!(crate::transfer::preview(&tampered, "correct horse").is_err());
}

#[test]
fn old_exports_need_their_password_and_unprotected_ones_are_refused() {
    use crate::vault::seal_with_passphrase;
    let dir = temp_dir("v1");
    let data = json!({ "hosts": [{ "id": "h1", "label": "old", "address": "10.9.9.9" }] });
    // Version 1 with sealed secrets: needs that passphrase.
    let sealed = seal_with_passphrase("old passphrase", br#"{"h1":{"password":"pw"}}"#).unwrap();
    let v1 = json!({ "format": "nimbus-export", "version": 1, "exportedAt": 1, "appVersion": "0.1.0", "data": data, "secrets": sealed });
    let f = dir.join("v1.json");
    std::fs::write(&f, v1.to_string()).unwrap();
    let mut s = Store::open(temp_dir("v1-in")).unwrap();
    assert!(crate::transfer::apply(&mut s, &f, "merge", "not it").is_err());
    crate::transfer::apply(&mut s, &f, "merge", "old passphrase").unwrap();
    assert_eq!(s.secret("h1").password.as_deref(), Some("pw"));
    // Version 1 without a passphrase: refused with an explanation.
    let plain = json!({ "format": "nimbus-export", "version": 1, "exportedAt": 1, "appVersion": "0.1.0", "data": data });
    let g = dir.join("v1-plain.json");
    std::fs::write(&g, plain.to_string()).unwrap();
    let e = crate::transfer::preview(&g, "anything").err().unwrap().to_string();
    assert!(e.contains("without a password"), "{e}");
}

#[test]
fn group_defaults_fill_blank_host_fields() {
    let mut s = Store::open(temp_dir("grp")).unwrap();
    s.data.groups.push(crate::store::Group { id: "g".into(), name: "G".into(), username: Some("deploy".into()), port: Some(2200), key_id: Some("k".into()), ..Default::default() });
    s.data.hosts.push(Host { id: "a".into(), address: "x".into(), group_id: Some("g".into()), ..Default::default() });
    s.data.hosts.push(Host { id: "b".into(), address: "x".into(), group_id: Some("g".into()), username: Some("root".into()), port: Some(22), ..Default::default() });
    let a = s.effective_host("a").unwrap();
    assert_eq!((a.username.as_deref(), a.port, a.key_id.as_deref()), (Some("deploy"), Some(2200), Some("k")));
    let b = s.effective_host("b").unwrap();
    assert_eq!((b.username.as_deref(), b.port), (Some("root"), Some(22)));
}

#[test]
fn describe_rejects_public_keys_and_reads_encrypted_ones() {
    assert!(crate::keys::describe("ssh-ed25519 AAAAC3Nza test", None).unwrap_err().to_string().contains("public key"));
    if let Some(dir) = sshd_dir() {
        let pem = std::fs::read_to_string(dir.join("client_enc")).unwrap();
        let info = crate::keys::describe(&pem, None).unwrap();
        assert!(info.encrypted);
        assert!(crate::keys::describe(&pem, Some("nope")).is_err());
        assert!(crate::keys::describe(&pem, Some("secretpass")).is_ok());
    }
}

/// Not a real test: builds a demo data folder for trying the UI.
/// NIMBUS_SEED_DIR=<dir> NIMBUS_TEST_SSHD=<dir> cargo test seed_demo -- --ignored
#[test]
#[ignore]
fn seed_demo() {
    let dir = PathBuf::from(std::env::var("NIMBUS_SEED_DIR").unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("master.key"), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
    let mut s = Store::open(dir).unwrap();
    let k = sshd_dir().map(|d| add_key(&mut s, d.join("client"), None));
    if let Some(k) = &k {
        s.data.keys[0].label = "Laptop ed25519".into();
        let h = add_host(&mut s, Some(k.clone()), None);
        let host = s.data.hosts.iter_mut().find(|x| x.id == h).unwrap();
        host.label = "Local test server".into();
        host.tags = vec!["test".into()];
    }
    let g = |s: &mut Store, name: &str, color: &str, user: &str| {
        let id = new_id();
        s.data.groups.push(crate::store::Group { id: id.clone(), name: name.into(), color: Some(color.into()), username: Some(user.into()), ..Default::default() });
        id
    };
    let prod = g(&mut s, "Production", "#f2555a", "deploy");
    let home = g(&mut s, "Home lab", "#34c77b", "pi");
    let _ = g(&mut s, "Clients", "#7b5cff", "admin");
    for (label, addr, grp) in [
        ("web-01", "10.0.1.11", &prod), ("web-02", "10.0.1.12", &prod), ("db-primary", "10.0.2.5", &prod),
        ("Raspberry Pi", "192.168.1.40", &home), ("NAS", "192.168.1.10", &home),
    ] {
        s.data.hosts.push(Host { id: new_id(), label: label.into(), address: addr.into(), group_id: Some(grp.clone()), ..Default::default() });
    }
    s.data.hosts.push(Host { id: new_id(), label: "Bastion".into(), address: "bastion.example.com".into(), username: Some("ben".into()), port: Some(2022), ..Default::default() });
    s.data.snippets.push(Snippet { id: new_id(), name: "Disk usage".into(), command: "df -h".into(), run: true });
    s.data.snippets.push(Snippet { id: new_id(), name: "Follow syslog".into(), command: "sudo journalctl -f".into(), run: false });
    s.save().unwrap();
}

#[test]
fn password_keystrokes_only_for_hosts_and_entries() {
    let mut s = Store::open(temp_dir("pwk")).unwrap();
    s.data.hosts.push(Host { id: "h".into(), address: "x".into(), ..Default::default() });
    s.update_secret("h", |x| x.password = Some("hostpw".into()));
    s.data.passwords.push(crate::store::PasswordEntry { id: "p".into(), name: "sudo".into(), ..Default::default() });
    s.update_secret("p", |x| x.password = Some("entrypw".into()));
    s.update_secret("k", |x| x.passphrase = Some("keypass".into()));
    assert_eq!(crate::password_keystrokes(&s, "h").unwrap(), b"hostpw\r");
    assert_eq!(crate::password_keystrokes(&s, "p").unwrap(), b"entrypw\r");
    assert!(crate::password_keystrokes(&s, "k").is_err(), "key passphrases must not be typeable");
    s.data.settings.type_password_enter = false;
    assert_eq!(crate::password_keystrokes(&s, "h").unwrap(), b"hostpw");
}

#[tokio::test]
async fn ssh_typed_password_reaches_a_hidden_prompt() {
    let Some(dir) = sshd_dir() else { return };
    let mut s = Store::open(temp_dir("typepw")).unwrap();
    let k = add_key(&mut s, dir.join("client"), None);
    let h = add_host(&mut s, Some(k), None);
    s.update_secret(&h, |x| x.password = Some("s3cret pass!".into()));
    let typed = String::from_utf8(crate::password_keystrokes(&s, &h).unwrap()).unwrap();
    let store = Arc::new(Mutex::new(s));
    // A no-echo read behaves like a sudo prompt: input hidden, ends at Enter.
    let (_, out) = session(
        store,
        &h,
        vec![json!({ "accept": true })],
        &["stty -echo; read P; stty echo; echo \"GOT[$P]\"\r", &typed, "exit\r"],
    )
    .await;
    assert!(out.contains("GOT[s3cret pass!]"), "output was: {out}");
}

// ---------- Files tab (SFTP / FTP) ----------

/// A context whose prompts are answered from `answers` in order, logging every event.
fn auto_ctx(store: Arc<Mutex<Store>>, answers: Vec<Value>) -> (Ctx, Arc<Mutex<Vec<Value>>>) {
    let prompts = Arc::new(Prompts::default());
    let log = Arc::new(Mutex::new(Vec::<Value>::new()));
    let answers = Arc::new(Mutex::new(VecDeque::from(answers)));
    let (p, l) = (prompts.clone(), log.clone());
    let events = Channel::<Value>::new(move |body| {
        if let InvokeResponseBody::Json(s) = body {
            let v: Value = serde_json::from_str(&s).unwrap();
            if v["type"] == "prompt" {
                let reply = answers.lock().unwrap().pop_front().unwrap_or(Value::Null);
                p.reply(v["id"].as_str().unwrap(), reply);
            }
            l.lock().unwrap().push(v);
        }
        Ok(())
    });
    (Ctx { store, prompts, events }, log)
}

/// Start a transfer and wait for its final event.
async fn transfer(remote: &Arc<crate::files::Remote>, log: &Arc<Mutex<Vec<Value>>>, upload: bool, items: Vec<crate::files::Item>, dest: &str) -> Value {
    let id = new_id();
    tokio::spawn(remote.clone().transfer(id.clone(), upload, items, dest.to_string()));
    for _ in 0..300 {
        let end = log.lock().unwrap().iter().find(|e| e["id"] == id.as_str() && matches!(e["state"].as_str(), Some("done" | "error" | "cancelled"))).cloned();
        if let Some(e) = end {
            return e;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("transfer never finished: {:?}", log.lock().unwrap());
}

/// A local folder tree to copy: a small text file and a larger binary one in a subfolder.
fn sample_tree(root: &std::path::Path) -> Vec<u8> {
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("a file.txt"), "hello nimbus\n").unwrap();
    let big: Vec<u8> = (0..700_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    std::fs::write(root.join("nested").join("big.bin"), &big).unwrap();
    big
}

fn item(path: &std::path::Path, is_dir: bool) -> crate::files::Item {
    crate::files::Item { path: path.to_string_lossy().into_owned(), is_dir }
}

/// Exercises a connected remote whose files live at `remote_base` on this machine
/// (`remote_dir` is the same folder as the server names it).
async fn exercise_remote(remote: Arc<crate::files::Remote>, log: Arc<Mutex<Vec<Value>>>, remote_base: &std::path::Path, remote_dir: &str) {
    let work = temp_dir("files-local");
    let src = work.join("upload me");
    let big = sample_tree(&src);

    // mkdir + list
    remote.mkdir(remote_dir, "inbox").await.unwrap();
    let l = remote.list(remote_dir).await.unwrap();
    let inbox = l.entries.iter().find(|e| e.name == "inbox").expect("inbox listed");
    assert!(inbox.is_dir);
    assert!(remote.mkdir(remote_dir, "../escape").await.is_err());

    // Upload a folder: structure and bytes arrive intact, progress reaches the total.
    let done = transfer(&remote, &log, true, vec![item(&src, true)], &inbox.path).await;
    assert_eq!(done["state"], "done", "{done}");
    assert_eq!(done["files"], 2);
    let up = remote_base.join("inbox").join("upload me");
    assert_eq!(std::fs::read_to_string(up.join("a file.txt")).unwrap(), "hello nimbus\n");
    assert_eq!(std::fs::read(up.join("nested").join("big.bin")).unwrap(), big);
    let last_progress = log.lock().unwrap().iter().filter(|e| e["state"] == "running").last().cloned().unwrap();
    assert_eq!(last_progress["done"], last_progress["total"]);

    // Download it back into a fresh local folder.
    let back = work.join("downloaded");
    std::fs::create_dir_all(&back).unwrap();
    let up_remote = format!("{}/upload me", inbox.path);
    let done = transfer(&remote, &log, false, vec![crate::files::Item { path: up_remote.clone(), is_dir: true }], &back.to_string_lossy()).await;
    assert_eq!(done["state"], "done", "{done}");
    assert_eq!(std::fs::read(back.join("upload me").join("nested").join("big.bin")).unwrap(), big);

    // A single file download.
    let one = work.join("one");
    std::fs::create_dir_all(&one).unwrap();
    let f = format!("{up_remote}/a file.txt");
    let done = transfer(&remote, &log, false, vec![crate::files::Item { path: f, is_dir: false }], &one.to_string_lossy()).await;
    assert_eq!(done["state"], "done", "{done}");
    assert_eq!(std::fs::read_to_string(one.join("a file.txt")).unwrap(), "hello nimbus\n");

    // Rename refuses to overwrite, then works.
    assert!(remote.rename(&up_remote, "a file.txt", "nested").await.is_err());
    remote.rename(&up_remote, "a file.txt", "renamed.txt").await.unwrap();
    assert!(up.join("renamed.txt").exists() && !up.join("a file.txt").exists());

    // Missing source: a clear error, no crash.
    let done = transfer(&remote, &log, false, vec![crate::files::Item { path: format!("{remote_dir}/nope.txt"), is_dir: false }], &one.to_string_lossy()).await;
    assert_eq!(done["state"], "error", "{done}");
    assert!(!one.join("nope.txt").exists(), "partial file left behind");

    // Recursive delete of the whole inbox.
    remote.delete(&[crate::files::Item { path: inbox.path.clone(), is_dir: true }]).await.unwrap();
    assert!(!remote_base.join("inbox").exists());
    remote.close().await;
}

#[tokio::test]
async fn sftp_browse_transfer_and_delete() {
    let Some(dir) = sshd_dir() else { return };
    let mut s = Store::open(temp_dir("sftp")).unwrap();
    let k = add_key(&mut s, dir.join("client"), None);
    let h = add_host(&mut s, Some(k), None);
    let store = Arc::new(Mutex::new(s));
    let (ctx, log) = auto_ctx(store, vec![json!({ "accept": true })]);
    let (remote, home) = crate::files::connect(&ctx, &h).await.unwrap();
    assert!(home.starts_with('/'), "{home}");
    // The test server is this machine, so a local temp folder is also a remote folder.
    let base = std::fs::canonicalize(temp_dir("sftp-remote")).unwrap();
    exercise_remote(Arc::new(remote), log, &base, &base.to_string_lossy()).await;
}

#[tokio::test]
async fn sftp_listing_follows_folder_links() {
    let Some(dir) = sshd_dir() else { return };
    let mut s = Store::open(temp_dir("sftp-link")).unwrap();
    let k = add_key(&mut s, dir.join("client"), None);
    let h = add_host(&mut s, Some(k), None);
    let (ctx, _) = auto_ctx(Arc::new(Mutex::new(s)), vec![json!({ "accept": true })]);
    let (remote, _) = crate::files::connect(&ctx, &h).await.unwrap();
    let base = std::fs::canonicalize(temp_dir("sftp-link-remote")).unwrap();
    std::fs::create_dir(base.join("real")).unwrap();
    std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
    let l = remote.list(&base.to_string_lossy()).await.unwrap();
    let link = l.entries.iter().find(|e| e.name == "link").unwrap();
    assert!(link.is_link && link.is_dir);
    // Deleting the link removes only the link.
    remote.delete(&[crate::files::Item { path: link.path.clone(), is_dir: true }]).await.unwrap();
    assert!(base.join("real").exists() && !base.join("link").exists());
}

/// An FTP server (libunftp) running inside the test, serving a fresh temp folder. User
/// "nimbus", password "ftp-pass". With `tls`, it requires explicit TLS using a self-signed
/// certificate from testdata/. Returns (port, root folder).
async fn ftp_server(tls: bool, idle_secs: u64) -> (u16, PathBuf) {
    #[derive(Debug)]
    struct Auth;
    #[async_trait::async_trait]
    impl unftp_core::auth::Authenticator for Auth {
        async fn authenticate(&self, user: &str, creds: &unftp_core::auth::Credentials) -> Result<unftp_core::auth::Principal, unftp_core::auth::AuthenticationError> {
            if user == "nimbus" && creds.password.as_deref() == Some("ftp-pass") {
                Ok(unftp_core::auth::Principal { username: user.into() })
            } else {
                Err(unftp_core::auth::AuthenticationError::BadPassword)
            }
        }
    }
    let root = std::fs::canonicalize(temp_dir("ftp-root")).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let r = root.clone();
    let mut b = libunftp::ServerBuilder::with_authenticator(Box::new(move || unftp_sbe_fs::Filesystem::new(r.clone()).unwrap()), Arc::new(Auth))
        .idle_session_timeout(idle_secs);
    if tls {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata");
        b = b
            .ftps(dir.join("ftps-cert.pem"), dir.join("ftps-key.pem"))
            .ftps_required(libunftp::options::FtpsRequired::All, libunftp::options::FtpsRequired::All);
    }
    let server = b.build().unwrap();
    tokio::spawn(async move { server.listen(format!("127.0.0.1:{port}")).await });
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (port, root)
}

fn add_ftp_host(store: &mut Store, protocol: &str, port: u16, password: Option<&str>) -> String {
    let id = new_id();
    store.data.hosts.push(Host {
        id: id.clone(),
        label: "ftp".into(),
        protocol: protocol.into(),
        address: "127.0.0.1".into(),
        port: Some(port),
        username: Some("nimbus".into()),
        ..Default::default()
    });
    if let Some(p) = password {
        store.update_secret(&id, |s| s.password = Some(p.into()));
    }
    id
}

#[tokio::test(flavor = "multi_thread")]
async fn ftp_login_prompts_then_transfers() {
    let (port, root) = ftp_server(false, 300).await;
    let mut s = Store::open(temp_dir("ftp")).unwrap();
    let h = add_ftp_host(&mut s, "ftp", port, None);
    let store = Arc::new(Mutex::new(s));
    // Wrong password first: asked again, and only the right one is saved.
    let (ctx, log) = auto_ctx(store.clone(), vec![json!({ "value": "nope", "save": true }), json!({ "value": "ftp-pass", "save": true })]);
    let (remote, home) = crate::files::connect(&ctx, &h).await.unwrap();
    assert_eq!(home, "/");
    let kinds: Vec<_> = log.lock().unwrap().iter().filter(|e| e["type"] == "prompt").map(|e| e["kind"].clone()).collect();
    assert_eq!(kinds, vec![json!("password"), json!("password")]);
    assert_eq!(store.lock().unwrap().secret(&h).password.as_deref(), Some("ftp-pass"));
    let sub = format!("t-{}", new_id());
    std::fs::create_dir(root.join(&sub)).unwrap();
    exercise_remote(Arc::new(remote), log, &root.join(&sub), &format!("/{sub}")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ftp_reconnects_after_the_server_drops_the_connection() {
    let (port, _) = ftp_server(false, 2).await;
    let mut s = Store::open(temp_dir("ftp-drop")).unwrap();
    let h = add_ftp_host(&mut s, "ftp", port, Some("ftp-pass"));
    let (ctx, _) = auto_ctx(Arc::new(Mutex::new(s)), vec![]);
    let (remote, _) = crate::files::connect(&ctx, &h).await.unwrap();
    assert!(remote.list("/").await.is_ok());
    // This server times out idle sessions after 2 s.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let r = remote.list("/").await;
    assert!(r.is_ok(), "listing after an idle disconnect should reconnect: {:?}", r.err());
}

#[tokio::test(flavor = "multi_thread")]
async fn ftps_asks_to_trust_a_self_signed_certificate_once() {
    let (port, root) = ftp_server(true, 300).await;
    let mut s = Store::open(temp_dir("ftps")).unwrap();
    let h = add_ftp_host(&mut s, "ftps", port, Some("ftp-pass"));
    let store = Arc::new(Mutex::new(s));

    // Refusing the certificate stops the connection.
    let (ctx, _) = auto_ctx(store.clone(), vec![json!({ "accept": false })]);
    let err = crate::files::connect(&ctx, &h).await.err().unwrap().to_string();
    assert!(err.contains("not trusted"), "{err}");

    // Trusting it connects, saves the fingerprint, and transfers work over TLS data channels.
    let (ctx, log) = auto_ctx(store.clone(), vec![json!({ "accept": true })]);
    let (remote, _) = crate::files::connect(&ctx, &h).await.unwrap();
    let p = log.lock().unwrap().iter().find(|e| e["type"] == "prompt").cloned().unwrap();
    assert_eq!(p["data"]["keyType"], "TLS certificate");
    assert!(p["data"]["previous"].is_null());
    let kh = store.lock().unwrap().known_host(&format!("ftps://127.0.0.1:{port}")).cloned().unwrap();
    assert_eq!(Some(kh.fingerprint.as_str()), p["data"]["fingerprint"].as_str());
    let sub = format!("t-{}", new_id());
    std::fs::create_dir(root.join(&sub)).unwrap();
    exercise_remote(Arc::new(remote), log, &root.join(&sub), &format!("/{sub}")).await;

    // Next time: no prompt.
    let (ctx, log) = auto_ctx(store.clone(), vec![]);
    crate::files::connect(&ctx, &h).await.unwrap();
    assert!(!log.lock().unwrap().iter().any(|e| e["type"] == "prompt"));

    // A different certificate than the trusted one: warned, with the previous fingerprint.
    store.lock().unwrap().data.known_hosts.iter_mut().for_each(|k| k.fingerprint = "SHA256:old".into());
    let (ctx, log) = auto_ctx(store.clone(), vec![json!({ "accept": false })]);
    assert!(crate::files::connect(&ctx, &h).await.is_err());
    let p = log.lock().unwrap().iter().find(|e| e["type"] == "prompt").cloned().unwrap();
    assert_eq!(p["data"]["previous"], "SHA256:old");
}

#[test]
fn local_listing_and_trash() {
    let d = temp_dir("local-fs");
    crate::files::local_mkdir(&d.to_string_lossy(), "folder").unwrap();
    std::fs::write(d.join("f.txt"), "x").unwrap();
    let l = crate::files::local_list(&d.to_string_lossy()).unwrap();
    assert!(l.entries.iter().any(|e| e.name == "folder" && e.is_dir));
    assert!(l.entries.iter().any(|e| e.name == "f.txt" && !e.is_dir && e.size == 1));
    assert!(l.parent.is_some());
    assert!(crate::files::local_rename(&d.to_string_lossy(), "f.txt", "folder").is_err());
    crate::files::local_rename(&d.to_string_lossy(), "f.txt", "g.txt").unwrap();
    assert!(d.join("g.txt").exists());
    let home = crate::files::local_list("").unwrap();
    assert_eq!(home.path, crate::files::local_home());
}

#[test]
fn password_groups_survive_export_and_delete_ungroups() {
    use crate::store::{PasswordEntry, PasswordGroup};
    let mut s = Store::open(temp_dir("pwg")).unwrap();
    s.data.password_groups.push(PasswordGroup { id: "g1".into(), name: "Servers".into(), color: None });
    s.data.passwords.push(PasswordEntry { id: "p1".into(), name: "root".into(), group_id: Some("g1".into()), ..Default::default() });
    let f = temp_dir("pwg-out").join("x.json");
    crate::transfer::export(&s, &f, "group export pw").unwrap();
    let mut t = Store::open(temp_dir("pwg-in")).unwrap();
    crate::transfer::apply(&mut t, &f, "merge", "group export pw").unwrap();
    assert_eq!(t.data.password_groups.len(), 1);
    assert_eq!(t.data.passwords[0].group_id.as_deref(), Some("g1"));
}

// ---------- serial ----------

/// A serial session against one end of a pseudo-terminal pair; the test plays the device on
/// the other end. Returns (device end, data from the device, events, input sender, task).
#[cfg(unix)]
async fn serial_session(
    configure: impl FnOnce(&mut Host),
) -> (serialport::TTYPort, Arc<Mutex<Vec<u8>>>, Arc<Mutex<Vec<Value>>>, mpsc::UnboundedSender<Input>, tokio::task::JoinHandle<()>) {
    use serialport::SerialPort;
    let (mut device, ours) = serialport::TTYPort::pair().unwrap();
    device.set_timeout(Duration::from_millis(200)).unwrap();
    let path = ours.name().unwrap();
    drop(ours);
    let mut s = Store::open(temp_dir("serial")).unwrap();
    let id = new_id();
    // Baud 0 tells the serial library this is a pseudo-terminal (macOS refuses to set a speed on one).
    let mut h = Host { id: id.clone(), label: "console".into(), protocol: "serial".into(), address: path, baud_rate: Some(0), ..Default::default() };
    configure(&mut h);
    s.data.hosts.push(h);
    let (ctx, log) = auto_ctx(Arc::new(Mutex::new(s)), vec![]);
    let received = Arc::new(Mutex::new(Vec::new()));
    let r = received.clone();
    let data = Channel::new(move |body| {
        if let InvokeResponseBody::Raw(b) = body {
            r.lock().unwrap().extend_from_slice(&b);
        }
        Ok(())
    });
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(crate::serial::run_serial(ctx, id, data, rx));
    for _ in 0..50 {
        if log.lock().unwrap().iter().any(|e| e["state"] == "connected" || e["state"] == "error") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (device, received, log, tx, task)
}

#[cfg(unix)]
fn read_device(device: &mut serialport::TTYPort, want: usize) -> Vec<u8> {
    use std::io::Read;
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    for _ in 0..20 {
        if got.len() >= want {
            break;
        }
        if let Ok(n) = device.read(&mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
    }
    got
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn serial_sends_and_receives() {
    use std::io::Write;
    let (mut device, received, log, tx, task) = serial_session(|_| {}).await;
    assert!(log.lock().unwrap().iter().any(|e| e["state"] == "connected"), "{:?}", log.lock().unwrap());
    // Typing reaches the device, with Enter sent as a carriage return by default.
    tx.send(Input::Data(b"show version\r".to_vec())).unwrap();
    assert_eq!(read_device(&mut device, 13), b"show version\r");
    // The device's output reaches the terminal.
    device.write_all(b"Router uptime is 3 weeks\r\n").unwrap();
    for _ in 0..40 {
        if received.lock().unwrap().ends_with(b"weeks\r\n") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(String::from_utf8_lossy(&received.lock().unwrap()), "Router uptime is 3 weeks\r\n");
    tx.send(Input::Close).unwrap();
    task.await.unwrap();
    assert_eq!(log.lock().unwrap().last().unwrap()["state"], "closed");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn serial_line_endings_and_local_echo() {
    let (mut device, received, _, tx, _task) = serial_session(|h| {
        h.newline = Some("crlf".into());
        h.local_echo = true;
    })
    .await;
    tx.send(Input::Data(b"AT\r".to_vec())).unwrap();
    assert_eq!(read_device(&mut device, 4), b"AT\r\n");
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Local echo shows what was typed, with Enter as a new line.
    assert_eq!(&received.lock().unwrap()[..], b"AT\r\n");
}

#[test]
fn serial_enter_translation() {
    use crate::serial::translate_enter;
    assert_eq!(translate_enter(b"a\rb", None), b"a\rb");
    assert_eq!(translate_enter(b"a\rb", Some("lf")), b"a\nb");
    assert_eq!(translate_enter(b"a\r", Some("crlf")), b"a\r\n");
}

#[tokio::test]
async fn serial_missing_port_explains_itself() {
    let mut s = Store::open(temp_dir("serial-missing")).unwrap();
    let id = new_id();
    s.data.hosts.push(Host { id: id.clone(), label: "gone".into(), protocol: "serial".into(), address: "/dev/cu.nimbus-does-not-exist".into(), ..Default::default() });
    let (ctx, log) = auto_ctx(Arc::new(Mutex::new(s)), vec![]);
    let (_tx, rx) = mpsc::unbounded_channel();
    crate::serial::run_serial(ctx, id, Channel::new(|_| Ok(())), rx).await;
    let last = log.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last["state"], "error");
    let msg = last["message"].as_str().unwrap();
    assert!(msg.contains("/dev/cu.nimbus-does-not-exist"), "{msg}");
}

#[test]
fn serial_settings_are_kept_only_for_serial_hosts_and_ports_list() {
    // Listing ports must not fail just because none are plugged in.
    assert!(crate::serial::list_ports().is_ok());
    let h = Host { protocol: "serial".into(), baud_rate: Some(115200), parity: Some("even".into()), stop_bits: Some(2), data_bits: Some(7), ..Default::default() };
    assert_eq!(crate::serial::describe(&h), "115200 baud, 7E2");
    assert_eq!(crate::serial::describe(&Host::default()), "9600 baud, 8N1");
}

#[test]
fn hosts_view_is_saved_and_defaults_to_grid() {
    // Settings files from before the option existed open in grid view.
    let old: crate::store::Settings = serde_json::from_str(r#"{ "fontSize": 14 }"#).unwrap();
    assert_eq!(old.hosts_view, "grid");
    let dir = temp_dir("view");
    let mut s = Store::open(dir.clone()).unwrap();
    s.data.settings.hosts_view = "list".into();
    s.save().unwrap();
    drop(s);
    assert_eq!(Store::open(dir).unwrap().data.settings.hosts_view, "list");
}

// ---------- API keys ----------

fn api_entry(fields: &[(&str, bool, Option<&str>)]) -> crate::store::ApiCredential {
    crate::store::ApiCredential {
        id: "api1".into(),
        name: "GitHub".into(),
        kind: "oauth2".into(),
        fields: fields
            .iter()
            .map(|(id, secret, value)| crate::store::ApiField { id: (*id).into(), label: (*id).into(), secret: *secret, value: value.map(String::from) })
            .collect(),
        ..Default::default()
    }
}

#[test]
fn api_secrets_are_encrypted_kept_cleared_and_dropped() {
    use std::collections::HashMap;
    let dir = temp_dir("api");
    let mut s = Store::open(dir.clone()).unwrap();
    let fields = [("clientId", false, Some("abc123")), ("clientSecret", true, Some("leak?")), ("refreshToken", true, None)];
    let secrets = HashMap::from([("clientSecret".to_string(), Some("s3cr3t".to_string())), ("refreshToken".to_string(), Some("r-tok".to_string()))]);
    crate::apply_api_key(&mut s, api_entry(&fields), secrets).unwrap();
    s.save().unwrap();

    // The secret never sits in the plain data file, even if the UI sent it as a value.
    let plain = std::fs::read_to_string(dir.join("nimbus-data.json")).unwrap();
    assert!(plain.contains("abc123") && !plain.contains("s3cr3t") && !plain.contains("leak?"));
    assert!(!std::fs::read(dir.join("secrets.bin")).unwrap().windows(6).any(|w| w == b"s3cr3t"));
    assert_eq!(crate::api_secret(&s, "api1", "clientSecret").unwrap(), "s3cr3t");
    // Non-secret fields can't be read through the secret path.
    assert!(crate::api_secret(&s, "api1", "clientId").is_err());

    // Saving again without values keeps them; "" clears one.
    let secrets = HashMap::from([("clientSecret".to_string(), None), ("refreshToken".to_string(), Some(String::new()))]);
    crate::apply_api_key(&mut s, api_entry(&fields), secrets).unwrap();
    assert_eq!(crate::api_secret(&s, "api1", "clientSecret").unwrap(), "s3cr3t");
    assert!(crate::api_secret(&s, "api1", "refreshToken").is_err());

    // Removing a field drops its saved secret.
    crate::apply_api_key(&mut s, api_entry(&[("clientId", false, Some("abc123"))]), HashMap::new()).unwrap();
    assert!(s.secret("api1").fields.is_empty());
    // An empty name is refused.
    let mut bad = api_entry(&[]);
    bad.name = "  ".into();
    assert!(crate::apply_api_key(&mut s, bad, HashMap::new()).is_err());
}

#[test]
fn api_keys_travel_in_exports() {
    use std::collections::HashMap;
    let mut s = Store::open(temp_dir("api-exp")).unwrap();
    s.data.api_groups.push(crate::store::PasswordGroup { id: "ag".into(), name: "Payments".into(), color: None });
    let mut e = api_entry(&[("token", true, None)]);
    e.group_id = Some("ag".into());
    crate::apply_api_key(&mut s, e, HashMap::from([("token".to_string(), Some("tok-1".to_string()))])).unwrap();
    let f = temp_dir("api-exp-out").join("x.json");
    crate::transfer::export(&s, &f, "export-pass-123").unwrap();
    assert_eq!(crate::transfer::preview(&f, "export-pass-123").unwrap().api_keys, 1);
    let mut t = Store::open(temp_dir("api-exp-in")).unwrap();
    crate::transfer::apply(&mut t, &f, "merge", "export-pass-123").unwrap();
    assert_eq!(t.data.api_groups.len(), 1);
    assert_eq!(t.data.api_keys[0].group_id.as_deref(), Some("ag"));
    assert_eq!(crate::api_secret(&t, "api1", "token").unwrap(), "tok-1");
}

#[test]
fn only_nimbus_pages_load_in_the_window() {
    let ok = |u: &str| crate::is_app_url(&tauri::Url::parse(u).unwrap());
    assert!(ok("tauri://localhost/index.html"));
    assert!(ok("http://tauri.localhost/"));
    assert!(ok("http://localhost:1420/"));
    assert!(!ok("https://github.com/"));
    assert!(!ok("http://192.168.1.1/"));
    assert!(!ok("https://localhost.evil.com/"));
    assert!(!ok("file:///etc/passwd"));
}
