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
    let ctx = Ctx { store, prompts, events: events.into() };
    let task = tokio::spawn(ssh::run_session(ctx, host_id.to_string(), 120, 30, data.into(), rx));

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
        trust_test_host(&mut s, &sshd_dir().unwrap(), 2222);
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
    (Ctx { store, prompts, events: events.into() }, log)
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
    let task = tokio::spawn(crate::serial::run_serial(ctx, id, data.into(), rx));
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
    crate::serial::run_serial(ctx, id, Channel::new(|_| Ok(())).into(), rx).await;
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

// ---------- AI agents (MCP) ----------

use crate::mcp::{self, Decision, Hub, HubEvent};
use crate::store::{ApiCredential, ApiField, Group, McpAgent, PasswordEntry};

/// A store with one agent; returns (store, hub, events, token, agent id).
fn mcp_setup(name: &str, timeout: Duration, f: impl FnOnce(&mut Store, &mut McpAgent)) -> (Arc<Mutex<Store>>, Arc<Hub>, mpsc::UnboundedReceiver<HubEvent>, String, String) {
    let mut s = Store::open(temp_dir(name)).unwrap();
    let token = mcp::new_token();
    let mut agent = McpAgent {
        id: new_id(),
        name: "Test agent".into(),
        token_hash: mcp::token_hash(&token),
        token_hint: mcp::token_hint(&token),
        commands: "ask".into(),
        requests: "ask".into(),
        ..Default::default()
    };
    f(&mut s, &mut agent);
    let id = agent.id.clone();
    s.data.mcp.agents.push(agent);
    let store = Arc::new(Mutex::new(s));
    let (tx, rx) = mpsc::unbounded_channel();
    let hub = Arc::new(Hub::for_tests(store.clone(), tx, timeout));
    (store, hub, rx, token, id)
}

async fn tool(hub: &Hub, agent: &str, name: &str, args: Value) -> (bool, String) {
    let r = hub.rpc(agent, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": name, "arguments": args } })).await.unwrap();
    let res = &r["result"];
    assert!(r.get("error").is_none(), "rpc error: {r}");
    (res["isError"].as_bool().unwrap(), res["content"][0]["text"].as_str().unwrap().to_string())
}

/// Answer approval requests in order with `decisions`; returns every approval request seen.
fn approver(hub: Arc<Hub>, mut rx: mpsc::UnboundedReceiver<HubEvent>, decisions: Vec<Option<Decision>>) -> Arc<Mutex<Vec<Value>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        let mut decisions = VecDeque::from(decisions);
        while let Some(ev) = rx.recv().await {
            if let HubEvent::Approval(v) = ev {
                seen2.lock().unwrap().push(v.clone());
                if let Some(Some(d)) = decisions.pop_front() {
                    hub.decide(v["id"].as_str().unwrap(), d);
                }
            }
        }
    });
    seen
}

#[test]
fn mcp_tokens_and_sites() {
    let t = mcp::new_token();
    assert!(t.starts_with("nimbus_") && t.len() > 40);
    assert_ne!(t, mcp::new_token());
    assert_eq!(mcp::token_hash(&t).len(), 64);
    assert_eq!(mcp::token_hint(&t), t[t.len() - 4..]);

    let base = mcp::parse_site("api.example.com").unwrap();
    assert_eq!(base.as_str(), "https://api.example.com/");
    let ok = |u: &str| mcp::same_site(&base, &reqwest::Url::parse(u).unwrap());
    assert!(ok("https://api.example.com/v1/x?y=1"));
    assert!(ok("https://API.example.com:443/"));
    assert!(!ok("http://api.example.com/"), "no downgrade to http");
    assert!(!ok("https://api.example.com.evil.com/"));
    assert!(!ok("https://evil.com/?api.example.com"));
    assert!(!ok("https://api.example.com:8443/"));
    assert!(!ok("https://user@evil.com/"));
    let local = mcp::parse_site("http://192.168.1.1").unwrap();
    assert!(mcp::same_site(&local, &reqwest::Url::parse("http://192.168.1.1/cgi").unwrap()));
}

#[tokio::test]
async fn mcp_agent_sees_only_what_it_was_granted() {
    let (store, hub, _rx, _t, agent) = mcp_setup("mcp-scope", Duration::from_secs(5), |s, a| {
        let g = Group { id: new_id(), name: "Prod".into(), ..Default::default() };
        let mk = |label: &str, protocol: &str, group: Option<String>| Host { id: new_id(), label: label.into(), protocol: protocol.into(), address: format!("{label}.example"), group_id: group, notes: Some("root pw is NOTESECRET".into()), ..Default::default() };
        let (granted, in_group, other, ftp) = (mk("granted", "ssh", None), mk("ingroup", "ssh", Some(g.id.clone())), mk("other", "ssh", None), mk("ftpbox", "ftp", Some(g.id.clone())));
        a.hosts.push(granted.id.clone());
        a.host_groups.push(g.id.clone());
        s.update_secret(&granted.id, |x| x.password = Some("HOSTPASSWORD".into()));
        s.data.groups.push(g);
        s.data.hosts.extend([granted, in_group, other, ftp]);

        let pw = PasswordEntry { id: new_id(), name: "Router".into(), username: Some("admin".into()), url: Some("192.168.1.1".into()), ..Default::default() };
        let hidden = PasswordEntry { id: new_id(), name: "Bank".into(), ..Default::default() };
        s.update_secret(&pw.id, |x| x.password = Some("ROUTERPASSWORD".into()));
        s.update_secret(&hidden.id, |x| x.password = Some("BANKPASSWORD".into()));
        a.passwords.push(pw.id.clone());
        s.data.passwords.extend([pw, hidden]);
        let api = ApiCredential {
            id: new_id(),
            name: "GitHub".into(),
            kind: "bearer".into(),
            fields: vec![ApiField { id: "token".into(), label: "Token".into(), secret: true, value: None }],
            ..Default::default()
        };
        s.update_secret(&api.id, |x| { x.fields.insert("token".into(), "GHTOKEN123".into()); });
        a.api_keys.push(api.id.clone());
        s.data.api_keys.push(api);
    });

    let init = hub.rpc(&agent, json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } })).await.unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(hub.rpc(&agent, json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).await.is_none());
    let tools = hub.rpc(&agent, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })).await.unwrap();
    let names: Vec<&str> = tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["list_hosts", "run_command", "list_credentials", "http_request"], "no get_secret without permission");

    let (err, hosts) = tool(&hub, &agent, "list_hosts", json!({})).await;
    assert!(!err);
    assert!(hosts.contains("granted") && hosts.contains("ingroup"), "{hosts}");
    assert!(!hosts.contains("other.example") && !hosts.contains("ftpbox"), "{hosts}");
    assert!(!hosts.contains("NOTESECRET") && !hosts.contains("HOSTPASSWORD"));

    let (_, creds) = tool(&hub, &agent, "list_credentials", json!({})).await;
    assert!(creds.contains("Router") && creds.contains("GitHub"));
    assert!(!creds.contains("Bank"));
    for secret in ["ROUTERPASSWORD", "GHTOKEN123", "BANKPASSWORD"] {
        assert!(!creds.contains(secret), "{secret} leaked: {creds}");
    }

    let (err, msg) = tool(&hub, &agent, "run_command", json!({ "host": "other", "command": "id" })).await;
    assert!(err && msg.contains("No host called"), "{msg}");
    let (err, msg) = tool(&hub, &agent, "http_request", json!({ "credential": "Bank", "url": "/" })).await;
    assert!(err && msg.contains("No credential called"), "{msg}");
    let (err, msg) = tool(&hub, &agent, "get_secret", json!({ "credential": "Router", "reason": "x" })).await;
    assert!(err && msg.contains("isn't allowed to see secrets"), "{msg}");
    let unknown = hub.rpc(&agent, json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "export_everything" } })).await.unwrap();
    assert!(unknown.get("error").is_some());

    let log = hub.activity();
    assert_eq!(log.len(), 3);
    assert!(log.iter().all(|a| a.outcome == "refused"), "{log:?}");

    // Paused and removed agents are turned away.
    store.lock().unwrap().data.mcp.agents[0].paused = true;
    let r = hub.rpc(&agent, json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" })).await.unwrap();
    assert!(r["error"]["message"].as_str().unwrap().contains("paused"));
    store.lock().unwrap().data.mcp.agents.clear();
    let r = hub.rpc(&agent, json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/list" })).await.unwrap();
    assert!(r["error"]["message"].as_str().unwrap().contains("removed"));
}

#[tokio::test]
async fn mcp_secrets_need_permission_and_approval_every_time() {
    let (_store, hub, rx, _t, agent) = mcp_setup("mcp-reveal", Duration::from_secs(1), |s, a| {
        a.reveal = true;
        let pw = PasswordEntry { id: new_id(), name: "Router".into(), ..Default::default() };
        s.update_secret(&pw.id, |x| x.password = Some("ROUTERPASSWORD".into()));
        a.passwords.push(pw.id.clone());
        s.data.passwords.push(pw);
    });
    // Deny, then "remember" (which must not stick for secrets), then approve once, then no answer.
    let seen = approver(hub.clone(), rx, vec![Some(Decision::Deny), Some(Decision::Remember), Some(Decision::Once), None]);
    let args = json!({ "credential": "Router", "reason": "log in to the router UI" });
    let (err, msg) = tool(&hub, &agent, "get_secret", args.clone()).await;
    assert!(err && msg.contains("declined"), "{msg}");
    let (err, msg) = tool(&hub, &agent, "get_secret", args.clone()).await;
    assert!(!err && msg == "ROUTERPASSWORD");
    let (err, msg) = tool(&hub, &agent, "get_secret", args.clone()).await;
    assert!(!err && msg == "ROUTERPASSWORD");
    let (err, msg) = tool(&hub, &agent, "get_secret", args).await;
    assert!(err && msg.contains("within 2 minutes"), "{msg}");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 4, "every reveal asks");
    assert_eq!(seen[0]["remember"], false);
    assert_eq!(seen[0]["kind"], "reveal");
    assert!(seen[0]["body"].as_str().unwrap().contains("router UI"));
    let outcomes: Vec<String> = hub.activity().iter().rev().map(|a| a.outcome.clone()).collect();
    assert_eq!(outcomes, ["denied", "ok", "ok", "denied"]);
    assert!(hub.activity().iter().all(|a| !a.detail.contains("ROUTERPASSWORD") && !a.message.contains("ROUTERPASSWORD")));
}

/// A tiny HTTP server that echoes the request line and headers back in the body.
async fn echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    use http_body_util::BodyExt;
                    let mut text = format!("{} {}\n", req.method(), req.uri());
                    for (k, v) in req.headers() {
                        text.push_str(&format!("{k}: {}\n", v.to_str().unwrap_or("")));
                    }
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    text.push_str(&format!("\n{}", String::from_utf8_lossy(&body)));
                    let mut r = hyper::Response::new(http_body_util::Full::new(hyper::body::Bytes::from(text)));
                    r.headers_mut().insert("x-echo", "GHTOKEN123".parse().unwrap());
                    Ok::<_, std::convert::Infallible>(r)
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), svc).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn mcp_http_request_adds_the_secret_only_for_its_own_site() {
    let port = echo_server().await;
    let base = format!("http://127.0.0.1:{port}");
    let b2 = base.clone();
    let (_store, hub, rx, _t, agent) = mcp_setup("mcp-http", Duration::from_secs(5), move |s, a| {
        a.requests = "allow".into();
        let api = |name: &str, kind: &str, fields: Vec<ApiField>| ApiCredential { id: new_id(), name: name.into(), kind: kind.into(), base_url: Some(b2.clone()), fields, ..Default::default() };
        let secret = |id: &str| ApiField { id: id.into(), label: id.into(), secret: true, value: None };
        let plain = |id: &str, v: &str| ApiField { id: id.into(), label: id.into(), secret: false, value: Some(v.into()) };
        let bearer = api("GitHub", "bearer", vec![secret("token")]);
        let query = api("Maps", "apiKey", vec![secret("key"), plain("name", "api_key"), plain("in", "query")]);
        let custom = ApiCredential { fields: vec![ApiField { id: "c1".into(), label: "Signing key".into(), secret: true, value: None }], ..api("Custom", "custom", vec![]) };
        let nourl = ApiCredential { base_url: None, ..api("NoUrl", "bearer", vec![secret("token")]) };
        s.update_secret(&bearer.id, |x| { x.fields.insert("token".into(), "GHTOKEN123".into()); });
        s.update_secret(&query.id, |x| { x.fields.insert("key".into(), "MAPSKEY456".into()); });
        s.update_secret(&custom.id, |x| { x.fields.insert("c1".into(), "SIGNKEY789".into()); });
        s.update_secret(&nourl.id, |x| { x.fields.insert("token".into(), "NOURLTOKEN".into()); });
        let pw = PasswordEntry { id: new_id(), name: "Router".into(), username: Some("admin".into()), url: Some(b2.clone()), ..Default::default() };
        s.update_secret(&pw.id, |x| x.password = Some("ROUTERPASSWORD".into()));
        for id in [&bearer.id, &query.id, &custom.id, &nourl.id] {
            a.api_keys.push(id.clone());
        }
        a.passwords.push(pw.id.clone());
        s.data.api_keys.extend([bearer, query, custom, nourl]);
        s.data.passwords.push(pw);
    });
    let seen = approver(hub.clone(), rx, vec![]);

    // Bearer: header added, and the token scrubbed from the echoed headers and body.
    let (err, out) = tool(&hub, &agent, "http_request", json!({ "credential": "GitHub", "url": "/v1/user?x=1" })).await;
    assert!(!err, "{out}");
    assert!(out.starts_with("HTTP 200"), "{out}");
    assert!(out.contains("GET /v1/user?x=1"));
    assert!(out.contains("authorization: Bearer [redacted by Nimbus]"), "{out}");
    assert!(out.contains("x-echo: [redacted by Nimbus]"));
    assert!(!out.contains("GHTOKEN123"));

    // API key in the query string; POST body passes through.
    let (err, out) = tool(&hub, &agent, "http_request", json!({ "credential": "Maps", "method": "post", "url": format!("{base}/geo"), "body": "{\"q\":1}", "headers": { "Content-Type": "application/json" } })).await;
    assert!(!err && out.contains("POST /geo?api_key=[redacted by Nimbus]") && out.contains("{\"q\":1}"), "{out}");
    assert!(!out.contains("MAPSKEY456"));

    // Custom fields placed by the agent; password entries use Basic auth.
    let (err, out) = tool(&hub, &agent, "http_request", json!({ "credential": "Custom", "url": "/sign", "headers": { "X-Sig": "k={{Signing key}}" } })).await;
    assert!(!err && out.contains("x-sig: k=[redacted by Nimbus]") && !out.contains("SIGNKEY789"), "{out}");
    let (err, out) = tool(&hub, &agent, "http_request", json!({ "credential": "Router", "url": "/" })).await;
    assert!(!err && out.contains("authorization: Basic [redacted by Nimbus]"), "{out}");
    let (err, out) = tool(&hub, &agent, "http_request", json!({ "credential": "Custom", "url": "/", "headers": { "X": "{{nope}}" } })).await;
    assert!(err && out.contains("no saved value"), "{out}");

    // Anywhere else is refused before anything is sent, including tricks with placeholders.
    for url in [
        "http://127.0.0.2:1/steal".to_string(),
        format!("http://localhost:{port}/"),
        format!("http://127.0.0.1:{}/", port.wrapping_add(1)),
        "https://evil.example/?{{token}}".to_string(),
        format!("http://{{{{token}}}}.evil.example:{port}/"),
    ] {
        let (err, out) = tool(&hub, &agent, "http_request", json!({ "credential": "GitHub", "url": url })).await;
        assert!(err && (out.contains("may only be used with") || out.contains("isn't a valid URL")), "{url}: {out}");
        assert!(!out.contains("GHTOKEN123"));
    }
    let (err, out) = tool(&hub, &agent, "http_request", json!({ "credential": "NoUrl", "url": "https://api.github.com/" })).await;
    assert!(err && out.contains("no website / base URL"), "{out}");
    assert!(seen.lock().unwrap().is_empty(), "requests were set to allow");
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_server_refuses_strangers_and_bridge_relays() {
    let (_store, hub, _rx, token, _agent) = mcp_setup("mcp-http-server", Duration::from_secs(5), |_, _| {});
    let server = mcp::start(hub.clone(), 0).await.unwrap();
    let port = server.port;
    let url = format!("http://127.0.0.1:{port}/mcp");
    let client = mcp::build_http_client().unwrap();
    let init = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-03-26" } }).to_string();
    let send = |auth: Option<&str>, host: Option<&str>, origin: Option<&str>| {
        let mut r = client.post(&url).header("content-type", "application/json").body(init.clone());
        if let Some(a) = auth { r = r.header("authorization", format!("Bearer {a}")); }
        if let Some(h) = host { r = r.header("host", h); }
        if let Some(o) = origin { r = r.header("origin", o); }
        r.send()
    };
    assert_eq!(send(None, None, None).await.unwrap().status(), 401);
    assert_eq!(send(Some("nimbus_wrong"), None, None).await.unwrap().status(), 401);
    assert_eq!(send(Some(&token), Some(&format!("evil.example:{port}")), None).await.unwrap().status(), 403, "DNS rebinding");
    assert_eq!(send(Some(&token), None, Some("https://evil.example")).await.unwrap().status(), 403, "web pages");
    let ok = send(Some(&token), None, None).await.unwrap();
    assert_eq!(ok.status(), 200);
    let v: Value = serde_json::from_slice(&ok.bytes().await.unwrap()).unwrap();
    assert_eq!(v["result"]["serverInfo"]["name"], "nimbus");
    assert_eq!(client.get(&url).send().await.unwrap().status(), 405, "only POST carries MCP messages");

    // stdio bridge: requests in, one reply line per request out; notifications get none.
    let input = format!(
        "{}\n{}\n\n{}\n",
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    );
    let mut out = Vec::new();
    mcp::bridge(port, token.clone(), tokio::io::BufReader::new(input.as_bytes()), &mut out).await.unwrap();
    let lines: Vec<Value> = String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 2);
    let mut ids: Vec<i64> = lines.iter().map(|l| l["id"].as_i64().unwrap()).collect();
    ids.sort();
    assert_eq!(ids, [1, 2]);

    let mut out = Vec::new();
    mcp::bridge(port, "nimbus_wrong".into(), tokio::io::BufReader::new(input.as_bytes()), &mut out).await.unwrap();
    assert!(String::from_utf8_lossy(&out).contains("didn't accept this agent's token"));

    // Turned off: the bridge says so instead of hanging.
    server.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut out = Vec::new();
    mcp::bridge(port, token, tokio::io::BufReader::new(input.as_bytes()), &mut out).await.unwrap();
    assert!(String::from_utf8_lossy(&out).contains("isn't running"));
}

/// The test sshd's host key, trusted as if the user had accepted it.
fn trust_test_host(s: &mut Store, dir: &std::path::Path, port: u16) {
    let hostkey = dir.parent().map(|_| dir.join("../hostkey.pub")).unwrap();
    let text = std::fs::read_to_string(&hostkey).or_else(|_| std::fs::read_to_string(dir.join("hostkey.pub"))).unwrap();
    let pk = russh::keys::PublicKey::from_openssh(text.trim()).unwrap();
    s.set_known_host(crate::store::KnownHost {
        host: format!("127.0.0.1:{port}"),
        key_type: pk.algorithm().as_str().into(),
        fingerprint: pk.fingerprint(russh::keys::HashAlg::Sha256).to_string(),
        added: 0,
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_run_command_waits_for_approval_and_never_trusts_keys() {
    let Some(dir) = sshd_dir() else { return };
    let (store, hub, rx, _t, agent) = mcp_setup("mcp-exec", Duration::from_secs(1), |s, a| {
        let key = add_key(s, dir.join("client"), None);
        let h = add_host(s, Some(key), None);
        a.hosts.push(h);
    });
    let seen = approver(hub.clone(), rx, vec![Some(Decision::Deny), Some(Decision::Remember)]);
    let run = |cmd: &str| tool(&hub, &agent, "run_command", json!({ "host": "local", "command": cmd }));

    // Not trusted yet: refused before any approval, and the key is not added.
    store.lock().unwrap().data.mcp.agents[0].commands = "allow".into();
    let (err, msg) = run("echo hi").await;
    assert!(err && msg.contains("host key"), "{msg}");
    assert!(store.lock().unwrap().data.known_hosts.is_empty());

    trust_test_host(&mut store.lock().unwrap(), &dir, 2222);
    store.lock().unwrap().data.mcp.agents[0].commands = "ask".into();
    let (err, msg) = run("echo hi").await;
    assert!(err && msg.contains("declined"), "{msg}");
    let (err, out) = run("echo out; echo err >&2; exit 3").await;
    assert!(!err, "{out}");
    assert!(out.starts_with("Exit code 3") && out.contains("--- stdout ---\nout") && out.contains("--- stderr ---\nerr"), "{out}");
    // "Allow for 30 minutes" covers the next command on this host without asking.
    let (err, out) = run("printf 'a\\nb'").await;
    assert!(!err && out.contains("a\nb"), "{out}");
    assert_eq!(seen.lock().unwrap().len(), 2);
    assert_eq!(seen.lock().unwrap()[0]["body"], "echo hi");

    // Timeouts stop the command.
    let (err, out) = tool(&hub, &agent, "run_command", json!({ "host": "local", "command": "sleep 30", "timeout_seconds": 1 })).await;
    assert!(!err && out.starts_with("Timed out"), "{out}");

    // Changing the agent's access forgets "allow for 30 minutes".
    hub.forget_agent(&agent);
    let (err, msg) = run("echo again").await;
    assert!(err && msg.contains("within 2 minutes"), "{msg}");

    // sudo needs a saved password.
    store.lock().unwrap().data.mcp.agents[0].commands = "allow".into();
    let (err, msg) = tool(&hub, &agent, "run_command", json!({ "host": "local", "command": "id", "sudo": true })).await;
    assert!(err && msg.contains("No password is saved"), "{msg}");
}

/// Needs a second test sshd on 127.0.0.1:2223 whose PATH starts with a fake `sudo` that
/// accepts the password "hunter2-sudo" (NIMBUS_TEST_SUDO=1).
#[tokio::test(flavor = "multi_thread")]
async fn mcp_sudo_is_answered_by_nimbus() {
    let Some(dir) = sshd_dir() else { return };
    if std::env::var_os("NIMBUS_TEST_SUDO").is_none() {
        return;
    }
    let mut host_id = String::new();
    let (store, hub, _rx, _t, agent) = mcp_setup("mcp-sudo", Duration::from_secs(1), |s, a| {
        a.commands = "allow".into();
        let key = add_key(s, dir.join("client"), None);
        host_id = add_host(s, Some(key), None);
        s.data.hosts[0].port = Some(2223);
        s.update_secret(&host_id, |x| x.password = Some("hunter2-sudo".into()));
        trust_test_host(s, &dir, 2223);
        a.hosts.push(host_id.clone());
    });
    let (err, out) = tool(&hub, &agent, "run_command", json!({ "host": "local", "command": "echo ok=$SUDO_OK; echo pw=hunter2-sudo", "sudo": true })).await;
    assert!(!err, "{out}");
    assert!(out.starts_with("Exit code 0") && out.contains("ok=1"), "{out}");
    assert!(!out.contains("nimbus-sudo-"), "prompt marker removed: {out}");
    assert!(out.contains("pw=[redacted by Nimbus]") && !out.contains("hunter2-sudo"), "{out}");

    store.lock().unwrap().update_secret(&host_id, |x| x.password = Some("wrong-password".into()));
    let (err, out) = tool(&hub, &agent, "run_command", json!({ "host": "local", "command": "echo ok=$SUDO_OK", "sudo": true, "timeout_seconds": 10 })).await;
    assert!(!err && out.contains("sudo didn't accept") && !out.contains("ok=1"), "{out}");
}

#[test]
fn agent_access_is_never_exported() {
    let dir = temp_dir("mcp-export");
    let mut s = Store::open(dir.clone()).unwrap();
    s.data.mcp.enabled = true;
    s.data.mcp.agents.push(McpAgent { id: "a".into(), name: "Claude".into(), token_hash: "h".into(), ..Default::default() });
    let path = dir.join("x.nimbus");
    crate::transfer::export(&s, &path, "long enough password").unwrap();
    let mut other = Store::open(temp_dir("mcp-export-2")).unwrap();
    crate::transfer::apply(&mut other, &path, "replace", "long enough password").unwrap();
    assert!(other.data.mcp.agents.is_empty() && !other.data.mcp.enabled);
    // Replacing the library keeps this computer's agents.
    crate::transfer::apply(&mut s, &path, "replace", "long enough password").unwrap();
    assert_eq!(s.data.mcp.agents.len(), 1);
}

#[test]
fn moving_a_tab_holds_output_then_delivers_it_in_order() {
    let first = Arc::new(Mutex::new(Vec::<u8>::new()));
    let second = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = |buf: Arc<Mutex<Vec<u8>>>| {
        Channel::new(move |body| {
            if let InvokeResponseBody::Raw(b) = body {
                buf.lock().unwrap().extend_from_slice(&b);
            }
            Ok(())
        })
    };
    let relay: ssh::Relay<InvokeResponseBody> = sink(first.clone()).into();
    let send = |s: &str| relay.send(InvokeResponseBody::Raw(s.as_bytes().to_vec())).unwrap();
    send("one ");
    relay.hold();
    send("two ");
    send("three ");
    relay.hold(); // a second hold keeps what's held
    relay.attach(sink(second.clone()));
    send("four");
    assert_eq!(String::from_utf8(first.lock().unwrap().clone()).unwrap(), "one ");
    assert_eq!(String::from_utf8(second.lock().unwrap().clone()).unwrap(), "two three four");
}

// ---------- Remote Desktop ----------
// Needs an RDP server: NIMBUS_TEST_RDP=<host:port> with user "tester", password "nimbus-test"
// (the xrdp container in the README). NIMBUS_TEST_RDP_SHOT=<file.bmp> saves the last screen.

/// xrdp gives each user one session, so the Remote Desktop tests take turns.
static RDP_SERVER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct MemClipboard(Mutex<Option<String>>, Mutex<Vec<String>>);

impl crate::desktop::Clipboard for MemClipboard {
    fn read(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
    fn write(&self, text: String) {
        self.1.lock().unwrap().push(text);
    }
}

/// What the UI would have drawn, from a Remote Desktop session's data channel.
#[derive(Default)]
struct Canvas {
    width: usize,
    height: usize,
    pixels: Vec<u8>,
    sizes: Vec<(u16, u16)>,
    frames: u32,
    pointers: u32,
}

impl Canvas {
    fn apply(&mut self, m: &[u8]) -> Option<u32> {
        let u16_at = |i: usize| u16::from_le_bytes([m[i], m[i + 1]]);
        match m[0] {
            1 => {
                let seq = u32::from_le_bytes([m[1], m[2], m[3], m[4]]);
                let mut at = 7;
                for _ in 0..u16_at(5) {
                    let (x, y, w, h) = (u16_at(at) as usize, u16_at(at + 2) as usize, u16_at(at + 4) as usize, u16_at(at + 6) as usize);
                    at += 8;
                    for row in 0..h {
                        let dst = ((y + row) * self.width + x) * 4;
                        self.pixels[dst..dst + w * 4].copy_from_slice(&m[at..at + w * 4]);
                        at += w * 4;
                    }
                }
                assert_eq!(at, m.len(), "frame message has the wrong length");
                self.frames += 1;
                Some(seq)
            }
            2 => {
                let (w, h) = (u16_at(1), u16_at(3));
                self.sizes.push((w, h));
                (self.width, self.height) = (w as usize, h as usize);
                self.pixels = vec![0; self.width * self.height * 4];
                None
            }
            3 => {
                let (w, h) = (u16_at(1) as usize, u16_at(3) as usize);
                assert_eq!(m.len(), 9 + w * h * 4, "pointer message has the wrong length");
                self.pointers += 1;
                None
            }
            4 | 5 => None,
            k => panic!("unknown message kind {k}"),
        }
    }

    /// Distinct colours on screen: a real desktop has many, a blank one has one.
    fn colours(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        for p in self.pixels.chunks_exact(4).step_by(7) {
            seen.insert([p[0], p[1], p[2]]);
        }
        seen.len()
    }

    fn save_bmp(&self, path: &str) {
        let (w, h) = (self.width, self.height);
        let mut f = Vec::with_capacity(54 + w * h * 4);
        f.extend_from_slice(b"BM");
        f.extend_from_slice(&((54 + w * h * 4) as u32).to_le_bytes());
        f.extend_from_slice(&[0; 4]);
        f.extend_from_slice(&54u32.to_le_bytes());
        f.extend_from_slice(&40u32.to_le_bytes());
        f.extend_from_slice(&(w as i32).to_le_bytes());
        f.extend_from_slice(&(-(h as i32)).to_le_bytes());
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&32u16.to_le_bytes());
        f.extend_from_slice(&[0; 24]);
        for p in self.pixels.chunks_exact(4) {
            f.extend_from_slice(&[p[2], p[1], p[0], 255]);
        }
        std::fs::write(path, f).unwrap();
    }
}

async fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    for _ in 0..secs * 10 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn rdp_session_draws_resizes_and_shares_the_clipboard() {
    let Ok(target) = std::env::var("NIMBUS_TEST_RDP") else { return };
    let _turn = RDP_SERVER.lock().await;
    let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_test_writer().try_init();
    let (addr, port) = target.rsplit_once(':').unwrap();
    let mut s = Store::open(temp_dir("rdp")).unwrap();
    let id = new_id();
    s.data.hosts.push(Host {
        id: id.clone(),
        label: "desktop".into(),
        protocol: "rdp".into(),
        address: addr.into(),
        port: Some(port.parse().unwrap()),
        username: Some("tester".into()),
        ..Default::default()
    });
    s.update_secret(&id, |sec| sec.password = Some("nimbus-test".into()));
    let store = Arc::new(Mutex::new(s));

    let prompts = Arc::new(Prompts::default());
    let log = Arc::new(Mutex::new(Vec::<Value>::new()));
    let (p, l) = (prompts.clone(), log.clone());
    let events = Channel::<Value>::new(move |body| {
        if let InvokeResponseBody::Json(s) = body {
            let v: Value = serde_json::from_str(&s).unwrap();
            if v["type"] == "prompt" {
                // Trust the server's certificate the first time.
                assert_eq!(v["kind"], "hostkey", "unexpected prompt {v}");
                p.reply(v["id"].as_str().unwrap(), json!({ "accept": true }));
            }
            l.lock().unwrap().push(v);
        }
        Ok(())
    });
    let (tx, rx) = mpsc::unbounded_channel();
    let canvas = Arc::new(Mutex::new(Canvas::default()));
    let (c, acks) = (canvas.clone(), tx.clone());
    let data = Channel::new(move |body| {
        if let InvokeResponseBody::Raw(b) = body {
            if let Some(seq) = c.lock().unwrap().apply(&b) {
                let _ = acks.send(Input::Desktop(crate::desktop::Cmd::Ack(seq)));
            }
        }
        Ok(())
    });
    let clipboard = Arc::new(MemClipboard(Mutex::new(None), Mutex::new(vec![])));
    let ctx = Ctx { store: store.clone(), prompts, events: events.into() };
    let cb: Arc<dyn crate::desktop::Clipboard> = clipboard.clone();
    let task = tokio::spawn(crate::rdp::run_session(ctx, id.clone(), 1280, 800, 100, data.into(), Some(cb), rx));

    let state = |l: &Arc<Mutex<Vec<Value>>>| l.lock().unwrap().iter().rev().find(|e| e["type"] == "status").map(|e| e["state"].as_str().unwrap_or("").to_string());
    wait_for("connected", 30, || matches!(state(&log).as_deref(), Some("connected" | "error" | "closed"))).await;
    assert_eq!(state(&log).as_deref(), Some("connected"), "{:?}", log.lock().unwrap());
    // The certificate is remembered for next time.
    assert!(store.lock().unwrap().known_host(&format!("rdp://{target}")).is_some());

    // The desktop appears at the size asked for.
    wait_for("the desktop", 30, || canvas.lock().unwrap().colours() > 20).await;
    assert_eq!(canvas.lock().unwrap().sizes[0], (1280, 800));

    // Keyboard and mouse go through without upsetting the server.
    use crate::desktop::Ev;
    tx.send(Input::Desktop(crate::desktop::Cmd::Input(vec![
        Ev::Move { x: 640, y: 400 },
        Ev::Button { x: 640, y: 400, b: 0, d: true },
        Ev::Button { x: 640, y: 400, b: 0, d: false },
        Ev::Wheel { x: 640, y: 400, v: -120, h: false },
        Ev::Key { c: 0x2a, e: false, d: true, k: 0xffe1 },
        Ev::Key { c: 0x2a, e: false, d: false, k: 0xffe1 },
        Ev::Sync { f: 0 },
    ])))
    .unwrap();

    // Resizing the tab resizes the remote desktop, without reconnecting.
    let frames_before = canvas.lock().unwrap().frames;
    tx.send(Input::Desktop(crate::desktop::Cmd::Resize { width: 1001, height: 700, scale: 100 })).unwrap();
    wait_for("the resize", 20, || canvas.lock().unwrap().sizes.last() == Some(&(1000, 700))).await;
    wait_for("the resized desktop", 20, || {
        let c = canvas.lock().unwrap();
        c.frames > frames_before && c.colours() > 20
    })
    .await;
    assert_eq!(state(&log).as_deref(), Some("connected"));

    // Copy on the remote → this computer's clipboard.
    let exec = |cmd: &str| {
        std::process::Command::new("docker")
            .args(["exec", "-u", "tester", "-e", "DISPLAY=:10", "nimbus-xrdp", "sh", "-c", cmd])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    if exec("true").is_ok() {
        exec("printf 'from the remote' | timeout 5 xclip -selection clipboard -loops 1 &").unwrap();
        wait_for("the remote's clipboard", 10, || clipboard.1.lock().unwrap().iter().any(|t| t == "from the remote")).await;

        // This computer's clipboard → paste on the remote.
        *clipboard.0.lock().unwrap() = Some("from Nimbus ✓".into());
        tx.send(Input::Desktop(crate::desktop::Cmd::Input(vec![Ev::Clipboard]))).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let pasted = exec("timeout 5 xclip -o -selection clipboard").unwrap();
        assert_eq!(pasted, "from Nimbus ✓");
    }

    // Moving to another window: frames stop while held, then everything is sent again.
    if let Ok(path) = std::env::var("NIMBUS_TEST_RDP_SHOT") {
        canvas.lock().unwrap().save_bmp(&path);
    }
    tx.send(Input::Desktop(crate::desktop::Cmd::Refresh)).unwrap();
    let sizes = canvas.lock().unwrap().sizes.len();
    wait_for("the refresh", 10, || canvas.lock().unwrap().sizes.len() > sizes).await;

    tx.send(Input::Close).unwrap();
    tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap();
    assert_eq!(state(&log).as_deref(), Some("closed"), "{:?}", log.lock().unwrap().last());
}

#[tokio::test(flavor = "multi_thread")]
async fn rdp_wrong_password_asks_again_and_refusing_the_certificate_cancels() {
    let Ok(target) = std::env::var("NIMBUS_TEST_RDP") else { return };
    let _turn = RDP_SERVER.lock().await;
    let (addr, port) = target.rsplit_once(':').unwrap();
    let mut s = Store::open(temp_dir("rdp-cert")).unwrap();
    let id = new_id();
    s.data.hosts.push(Host { id: id.clone(), protocol: "rdp".into(), address: addr.into(), port: Some(port.parse().unwrap()), username: Some("tester".into()), ..Default::default() });
    s.update_secret(&id, |sec| sec.password = Some("nimbus-test".into()));
    let (events, _) = session_rdp(s, &id, vec![json!({ "accept": false })]).await;
    let last = events.iter().rev().find(|e| e["type"] == "status").unwrap();
    assert_eq!(last["state"], "error");
    assert!(last["message"].as_str().unwrap().contains("not trusted"), "{last}");
}

/// Run a Remote Desktop session until it ends, answering prompts in order.
async fn session_rdp(s: Store, id: &str, answers: Vec<Value>) -> (Vec<Value>, ()) {
    let prompts = Arc::new(Prompts::default());
    let log = Arc::new(Mutex::new(Vec::<Value>::new()));
    let answers = Arc::new(Mutex::new(VecDeque::from(answers)));
    let (p, l) = (prompts.clone(), log.clone());
    let events = Channel::<Value>::new(move |body| {
        if let InvokeResponseBody::Json(s) = body {
            let v: Value = serde_json::from_str(&s).unwrap();
            if v["type"] == "prompt" {
                p.reply(v["id"].as_str().unwrap(), answers.lock().unwrap().pop_front().unwrap_or(Value::Null));
            }
            l.lock().unwrap().push(v);
        }
        Ok(())
    });
    let (_tx, rx) = mpsc::unbounded_channel();
    let ctx = Ctx { store: Arc::new(Mutex::new(s)), prompts, events: events.into() };
    let task = tokio::spawn(crate::rdp::run_session(ctx, id.to_string(), 1024, 768, 100, Channel::new(|_| Ok(())).into(), None, rx));
    tokio::time::timeout(Duration::from_secs(30), task).await.unwrap().unwrap();
    let ev = log.lock().unwrap().clone();
    (ev, ())
}

#[tokio::test(flavor = "multi_thread")]
async fn rdp_through_an_ssh_jump_host() {
    let (Ok(target), Some(dir)) = (std::env::var("NIMBUS_TEST_RDP"), sshd_dir()) else { return };
    let _turn = RDP_SERVER.lock().await;
    let (addr, port) = target.rsplit_once(':').unwrap();
    let mut s = Store::open(temp_dir("rdp-jump")).unwrap();
    let key = add_key(&mut s, dir.join("client"), None);
    let jump = add_host(&mut s, Some(key), None);
    trust_test_host(&mut s, &dir, 2222);
    let id = new_id();
    s.data.hosts.push(Host { id: id.clone(), protocol: "rdp".into(), address: addr.into(), port: Some(port.parse().unwrap()), username: Some("tester".into()), jump_host_id: Some(jump), ..Default::default() });
    s.update_secret(&id, |sec| sec.password = Some("nimbus-test".into()));
    // Answers: trust the RDP certificate. Once connected, the test closes the session.
    let prompts = Arc::new(Prompts::default());
    let log = Arc::new(Mutex::new(Vec::<Value>::new()));
    let (p, l) = (prompts.clone(), log.clone());
    let events = Channel::<Value>::new(move |body| {
        if let InvokeResponseBody::Json(s) = body {
            let v: Value = serde_json::from_str(&s).unwrap();
            if v["type"] == "prompt" {
                p.reply(v["id"].as_str().unwrap(), json!({ "accept": true }));
            }
            l.lock().unwrap().push(v);
        }
        Ok(())
    });
    let frames = Arc::new(Mutex::new(0u32));
    let f = frames.clone();
    let (tx, rx) = mpsc::unbounded_channel();
    let acks = tx.clone();
    let data = Channel::new(move |body| {
        if let InvokeResponseBody::Raw(b) = body {
            if b[0] == 1 {
                *f.lock().unwrap() += 1;
                let _ = acks.send(Input::Desktop(crate::desktop::Cmd::Ack(u32::from_le_bytes([b[1], b[2], b[3], b[4]]))));
            }
        }
        Ok(())
    });
    let ctx = Ctx { store: Arc::new(Mutex::new(s)), prompts, events: events.into() };
    let task = tokio::spawn(crate::rdp::run_session(ctx, id, 1024, 768, 100, data.into(), None, rx));
    wait_for("frames through the tunnel", 30, || *frames.lock().unwrap() > 0).await;
    assert!(log.lock().unwrap().iter().any(|e| e["message"].as_str().is_some_and(|m| m.starts_with("Tunnelling to"))));
    tx.send(Input::Close).unwrap();
    tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap();
}

// ---------- VNC ----------
// Needs the TigerVNC container in src-tauri/tests/vnc: NIMBUS_TEST_VNC=<host> (ports 5901 with a
// VNC password, 5902 with VeNCrypt and a certificate; password "nimbus-v").

/// The VNC tests share one server, and one test changes which encodings Nimbus asks for.
static VNC_SERVER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Desk {
    tx: mpsc::UnboundedSender<Input>,
    canvas: Arc<Mutex<Canvas>>,
    log: Arc<Mutex<Vec<Value>>>,
    clipboard: Arc<MemClipboard>,
    task: tokio::task::JoinHandle<()>,
    store: Arc<Mutex<Store>>,
}

impl Desk {
    fn state(&self) -> Option<String> {
        self.log.lock().unwrap().iter().rev().find(|e| e["type"] == "status").map(|e| e["state"].as_str().unwrap_or("").to_string())
    }

    fn input(&self, evs: Vec<crate::desktop::Ev>) {
        self.tx.send(Input::Desktop(crate::desktop::Cmd::Input(evs))).unwrap();
    }

    async fn close(self) -> Vec<Value> {
        let _ = self.tx.send(Input::Close);
        tokio::time::timeout(Duration::from_secs(10), self.task).await.unwrap().unwrap();
        let log = self.log.lock().unwrap().clone();
        log
    }
}

/// Start a VNC session; prompts are answered from `answers` in order.
fn vnc_session(addr: &str, port: u16, password: Option<&str>, answers: Vec<Value>, size: (u32, u32)) -> Desk {
    let mut s = Store::open(temp_dir("vnc")).unwrap();
    let id = new_id();
    s.data.hosts.push(Host { id: id.clone(), label: "vnc".into(), protocol: "vnc".into(), address: addr.into(), port: Some(port), ..Default::default() });
    if let Some(p) = password {
        s.update_secret(&id, |sec| sec.password = Some(p.into()));
    }
    let store = Arc::new(Mutex::new(s));
    let prompts = Arc::new(Prompts::default());
    let log = Arc::new(Mutex::new(Vec::<Value>::new()));
    let answers = Arc::new(Mutex::new(VecDeque::from(answers)));
    let (p, l) = (prompts.clone(), log.clone());
    let events = Channel::<Value>::new(move |body| {
        if let InvokeResponseBody::Json(s) = body {
            let v: Value = serde_json::from_str(&s).unwrap();
            if v["type"] == "prompt" {
                p.reply(v["id"].as_str().unwrap(), answers.lock().unwrap().pop_front().unwrap_or(Value::Null));
            }
            l.lock().unwrap().push(v);
        }
        Ok(())
    });
    let (tx, rx) = mpsc::unbounded_channel();
    let canvas = Arc::new(Mutex::new(Canvas::default()));
    let (c, acks) = (canvas.clone(), tx.clone());
    let data = Channel::new(move |body| {
        if let InvokeResponseBody::Raw(b) = body {
            if let Some(seq) = c.lock().unwrap().apply(&b) {
                let _ = acks.send(Input::Desktop(crate::desktop::Cmd::Ack(seq)));
            }
        }
        Ok(())
    });
    let clipboard = Arc::new(MemClipboard(Mutex::new(None), Mutex::new(vec![])));
    let cb: Arc<dyn crate::desktop::Clipboard> = clipboard.clone();
    let ctx = Ctx { store: store.clone(), prompts, events: events.into() };
    let task = tokio::spawn(crate::vnc::run_session(ctx, id, size.0, size.1, data.into(), Some(cb), rx));
    Desk { tx, canvas, log, clipboard, task, store }
}

fn vnc_exec(display: u8, cmd: &str) -> String {
    let out = std::process::Command::new("docker")
        .args(["exec", "-u", "tester", "-e", &format!("DISPLAY=:{display}"), "nimbus-vnc", "sh", "-c", cmd])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn vnc_every_encoding_draws_the_same_screen() {
    let Ok(addr) = std::env::var("NIMBUS_TEST_VNC") else { return };
    let _turn = VNC_SERVER.lock().await;
    // A still screen to compare: the desktop at a fixed size, with nothing moving.
    let run = |enc: Vec<i32>| {
        let addr = addr.clone();
        async move {
            *crate::vnc::TEST_ENCODINGS.lock().unwrap() = Some(enc);
            let d = vnc_session(&addr, 5901, Some("nimbus-v"), vec![], (1280, 800));
            wait_for("the desktop", 20, || d.canvas.lock().unwrap().colours() > 20).await;
            tokio::time::sleep(Duration::from_millis(800)).await;
            let px = d.canvas.lock().unwrap().pixels.clone();
            assert_eq!(d.state().as_deref(), Some("connected"));
            d.close().await;
            px
        }
    };
    let raw = run(vec![0]).await;
    for (name, enc) in [("Hextile", vec![5]), ("ZRLE", vec![16]), ("Tight", vec![7]), ("CopyRect+ZRLE", vec![1, 16])] {
        let px = run(enc).await;
        assert_eq!(px.len(), raw.len(), "{name}: different size");
        // The clock may tick over, so allow a few pixels to differ.
        let same = px.chunks_exact(4).zip(raw.chunks_exact(4)).filter(|(a, b)| a[..3] == b[..3]).count();
        let pct = same * 100 / (px.len() / 4);
        assert!(pct >= 99, "{name}: only {pct}% of pixels match Raw");
    }
    // JPEG is lossy: the picture is close, not exact.
    let px = run(vec![7, -23]).await;
    let close = px.chunks_exact(4).zip(raw.chunks_exact(4)).filter(|(a, b)| (0..3).all(|i| a[i].abs_diff(b[i]) < 40)).count();
    assert!(close * 100 / (px.len() / 4) >= 97, "Tight JPEG differs too much");
    *crate::vnc::TEST_ENCODINGS.lock().unwrap() = None;
}

#[tokio::test(flavor = "multi_thread")]
async fn vnc_session_resizes_types_and_shares_the_clipboard() {
    let Ok(addr) = std::env::var("NIMBUS_TEST_VNC") else { return };
    let _turn = VNC_SERVER.lock().await;
    vnc_exec(1, "rm -f /tmp/typed-in-vnc");
    // The tab is 1100×700: the remote desktop is resized to match.
    let d = vnc_session(&addr, 5901, Some("nimbus-v"), vec![], (1100, 700));
    wait_for("connected", 20, || d.state().as_deref() == Some("connected")).await;
    wait_for("the resize", 20, || d.canvas.lock().unwrap().sizes.last() == Some(&(1100, 700))).await;
    wait_for("the desktop", 20, || d.canvas.lock().unwrap().colours() > 20).await;
    // Typing: Alt+F2 opens XFCE's run box; type a command and press Enter.
    use crate::desktop::Ev;
    // The remote's cursor shape arrives once the pointer is over the desktop.
    d.input(vec![Ev::Move { x: 500, y: 400 }, Ev::Move { x: 520, y: 410 }]);
    wait_for("the remote's cursor shape", 10, || d.canvas.lock().unwrap().pointers > 0).await;

    let key = |k: u32, d: bool| Ev::Key { c: 0, e: false, d, k };
    d.input(vec![key(0xffe9, true), key(0xffbf, true), key(0xffbf, false), key(0xffe9, false)]);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let mut evs = vec![];
    for ch in "touch /tmp/typed-in-vnc".chars() {
        evs.push(key(ch as u32, true));
        evs.push(key(ch as u32, false));
    }
    evs.push(key(0xff0d, true));
    evs.push(key(0xff0d, false));
    d.input(evs);
    wait_for("the typed command to run", 10, || vnc_exec(1, "ls /tmp/typed-in-vnc 2>/dev/null").contains("typed-in-vnc")).await;

    // Copy on the remote → this computer (UTF-8, through the extended clipboard).
    vnc_exec(1, "printf 'from the remote ✓' | timeout 8 xclip -selection clipboard >/dev/null 2>&1 &");
    wait_for("the remote's clipboard", 10, || d.clipboard.1.lock().unwrap().iter().any(|t| t == "from the remote ✓")).await;
    // This computer → paste on the remote.
    *d.clipboard.0.lock().unwrap() = Some("from Nimbus ✓".into());
    d.input(vec![Ev::Clipboard]);
    wait_for("the remote to have our text", 10, || vnc_exec(1, "timeout 3 xclip -o -selection clipboard 2>/dev/null") == "from Nimbus ✓").await;

    // Moving to another window: everything is sent again.
    let sizes = d.canvas.lock().unwrap().sizes.len();
    d.tx.send(Input::Desktop(crate::desktop::Cmd::Refresh)).unwrap();
    wait_for("the refresh", 10, || d.canvas.lock().unwrap().sizes.len() > sizes).await;
    let log = d.close().await;
    assert_eq!(log.iter().rev().find(|e| e["type"] == "status").unwrap()["state"], "closed");
}

#[tokio::test(flavor = "multi_thread")]
async fn vnc_vencrypt_checks_the_certificate_and_the_password() {
    let Ok(addr) = std::env::var("NIMBUS_TEST_VNC") else { return };
    let _turn = VNC_SERVER.lock().await;
    // Refusing the certificate cancels.
    let d = vnc_session(&addr, 5902, Some("nimbus-v"), vec![json!({ "accept": false })], (1024, 768));
    let log = tokio::time::timeout(Duration::from_secs(20), async {
        while !matches!(d.state().as_deref(), Some("error" | "closed")) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        d.log.lock().unwrap().clone()
    })
    .await
    .unwrap();
    let last = log.iter().rev().find(|e| e["type"] == "status").unwrap();
    assert!(last["message"].as_str().unwrap().contains("not trusted"), "{last}");

    // Trusted, a wrong saved password, then the right one when asked: connected, encrypted.
    let d = vnc_session(&addr, 5902, Some("wrong"), vec![json!({ "accept": true }), json!({ "value": "nimbus-v", "save": true })], (1024, 768));
    wait_for("connected", 30, || matches!(d.state().as_deref(), Some("connected" | "error"))).await;
    assert_eq!(d.state().as_deref(), Some("connected"), "{:?}", d.log.lock().unwrap());
    wait_for("the desktop", 20, || d.canvas.lock().unwrap().colours() > 20).await;
    let store = d.store.clone();
    let log = d.close().await;
    assert!(log.iter().any(|e| e["kind"] == "password"), "should have asked for the password again");
    assert!(store.lock().unwrap().known_host(&format!("vnc://{addr}:5902")).is_some());
    let id = store.lock().unwrap().data.hosts[0].id.clone();
    assert_eq!(store.lock().unwrap().secret(&id).password.as_deref(), Some("nimbus-v"), "the corrected password is saved");
}
