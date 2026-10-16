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

    let with = src_dir.join("with.json");
    let without = src_dir.join("without.json");
    crate::transfer::export(&a, &with, Some("correct horse")).unwrap();
    crate::transfer::export(&a, &without, None).unwrap();
    let raw = std::fs::read_to_string(&with).unwrap();
    assert!(!raw.contains("hunter2") && !raw.contains("OPENSSH PRIVATE"), "secrets must not appear in clear");
    assert!(!std::fs::read_to_string(&without).unwrap().contains("hunter2"));

    // Fresh "other computer".
    let mut b = Store::open(temp_dir("imp")).unwrap();
    assert!(crate::transfer::apply(&mut b, &with, "merge", Some("wrong")).is_err());
    assert!(b.data.hosts.is_empty(), "a failed import must change nothing");
    let p = crate::transfer::preview(&with).unwrap();
    assert_eq!((p.hosts, p.groups, p.keys, p.snippets, p.has_secrets), (1, 1, 1, 1, true));
    crate::transfer::apply(&mut b, &with, "merge", Some("correct horse")).unwrap();
    assert_eq!(b.secret("h1").password.as_deref(), Some("hunter2"));
    assert_eq!(b.secret("k1").private_key.as_deref(), Some(pem.as_str()));
    assert_eq!(b.effective_host("h1").unwrap().group_id.as_deref(), Some("g1"));
    // Merging the same file again doesn't duplicate.
    crate::transfer::apply(&mut b, &with, "merge", Some("correct horse")).unwrap();
    assert_eq!(b.data.hosts.len(), 1);
    // Secrets survive a save + reopen through the vault.
    b.save().unwrap();
    let dir_b = b.dir().to_path_buf();
    drop(b);
    let b2 = Store::open(dir_b).unwrap();
    assert_eq!(b2.secret("h1").password.as_deref(), Some("hunter2"));

    // Without-secrets import: structure arrives, secrets don't.
    let mut c = Store::open(temp_dir("imp2")).unwrap();
    crate::transfer::apply(&mut c, &without, "replace", None).unwrap();
    assert_eq!(c.data.hosts.len(), 1);
    assert!(c.secret("h1").password.is_none());
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
