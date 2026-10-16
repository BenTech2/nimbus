//! Local data model and persistence.
//!
//! Everything lives in the app data directory:
//!   nimbus-data.json  — hosts, groups, keys (public half only), snippets, known hosts, settings
//!   secrets.bin       — passwords, private keys and passphrases, AES-256-GCM encrypted with a
//!                       master key held in the OS keychain (see `vault.rs`)

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::vault::Vault;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    /// Defaults inherited by hosts in this group when the host leaves them blank.
    pub username: Option<String>,
    pub port: Option<u16>,
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Host {
    pub id: String,
    pub label: String,
    /// "ssh" today; "rdp" is reserved so RDP hosts can share the same list later.
    pub protocol: String,
    pub address: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub group_id: Option<String>,
    pub key_id: Option<String>,
    pub use_agent: bool,
    pub jump_host_id: Option<String>,
    pub color: Option<String>,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub last_connected: Option<i64>,
}

impl Default for Host {
    fn default() -> Self {
        Host {
            id: String::new(),
            label: String::new(),
            protocol: "ssh".into(),
            address: String::new(),
            port: None,
            username: None,
            group_id: None,
            key_id: None,
            use_agent: true,
            jump_host_id: None,
            color: None,
            tags: vec![],
            notes: None,
            last_connected: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Key {
    pub id: String,
    pub label: String,
    pub key_type: String,
    pub public_key: String,
    pub fingerprint: String,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Snippet {
    pub id: String,
    pub name: String,
    pub command: String,
    /// Press Enter after pasting the command.
    pub run: bool,
}

/// A password-manager entry. The password itself lives in the encrypted secrets under `id`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PasswordEntry {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub updated: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct KnownHost {
    /// "address:port"
    pub host: String,
    pub key_type: String,
    pub fingerprint: String,
    pub added: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub font_size: u16,
    pub font_family: String,
    pub cursor_style: String,
    pub cursor_blink: bool,
    pub scrollback: u32,
    pub copy_on_select: bool,
    pub keepalive_secs: u32,
    /// Press Enter after "Type password" in a terminal.
    pub type_password_enter: bool,
    /// Overrides SSH_AUTH_SOCK (Unix) or the OpenSSH agent pipe (Windows) when set.
    pub agent_socket: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            font_size: 13,
            font_family: "\"SF Mono\", \"Cascadia Mono\", Menlo, Consolas, \"DejaVu Sans Mono\", monospace".into(),
            cursor_style: "block".into(),
            cursor_blink: true,
            scrollback: 10000,
            copy_on_select: false,
            keepalive_secs: 30,
            type_password_enter: true,
            agent_socket: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Data {
    pub version: u32,
    pub groups: Vec<Group>,
    pub hosts: Vec<Host>,
    pub keys: Vec<Key>,
    pub snippets: Vec<Snippet>,
    pub passwords: Vec<PasswordEntry>,
    pub known_hosts: Vec<KnownHost>,
    pub settings: Settings,
}

/// Secret material for one host (password) or one key (private key + passphrase).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Secret {
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
}

impl Secret {
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.private_key.is_none() && self.passphrase.is_none()
    }
}

/// Which secrets exist, without revealing them, for the UI.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecretFlags {
    pub password: bool,
    pub private_key: bool,
    pub passphrase: bool,
}

pub struct Store {
    dir: PathBuf,
    pub data: Data,
    pub secrets: HashMap<String, Secret>,
    vault: Vault,
    pub secrets_warning: Option<String>,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Write to a temp file then rename, so a crash mid-write never leaves a half file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path)
}

impl Store {
    pub fn open(dir: PathBuf) -> anyhow::Result<Store> {
        fs::create_dir_all(&dir)?;
        let data_path = dir.join("nimbus-data.json");
        let data = match fs::read(&data_path) {
            Ok(bytes) => match serde_json::from_slice::<Data>(&bytes) {
                Ok(d) => d,
                Err(e) => {
                    // Keep the unreadable file rather than silently overwriting it.
                    let backup = dir.join(format!("nimbus-data.corrupt-{}.json", now_ms()));
                    let _ = fs::rename(&data_path, &backup);
                    eprintln!("nimbus: data file unreadable ({e}); moved to {}", backup.display());
                    Data::default()
                }
            },
            Err(_) => Data::default(),
        };
        let vault = Vault::open(&dir)?;
        let mut secrets_warning = None;
        let secrets_path = dir.join("secrets.bin");
        let secrets = match fs::read(&secrets_path) {
            Ok(blob) => match vault.decrypt(&blob).and_then(|p| Ok(serde_json::from_slice(&p)?)) {
                Ok(s) => s,
                Err(e) => {
                    // Set the unreadable file aside so saving can't overwrite it.
                    let aside = dir.join(format!("secrets.unreadable-{}.bin", now_ms()));
                    let _ = fs::rename(&secrets_path, &aside);
                    secrets_warning = Some(format!(
                        "Saved passwords and keys could not be unlocked ({e:#}). The old file was kept as {}.",
                        aside.display()
                    ));
                    HashMap::new()
                }
            },
            Err(_) => HashMap::new(),
        };
        let mut store = Store { dir, data, secrets, vault, secrets_warning };
        store.data.version = 1;
        Ok(store)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn vault_mode(&self) -> &'static str {
        self.vault.mode()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let json = serde_json::to_vec_pretty(&self.data)?;
        write_atomic(&self.dir.join("nimbus-data.json"), &json)?;
        let plain = serde_json::to_vec(&self.secrets)?;
        let blob = self.vault.encrypt(&plain)?;
        write_atomic(&self.dir.join("secrets.bin"), &blob)?;
        Ok(())
    }

    pub fn secret_flags(&self) -> HashMap<String, SecretFlags> {
        self.secrets
            .iter()
            .map(|(id, s)| {
                (
                    id.clone(),
                    SecretFlags {
                        password: s.password.is_some(),
                        private_key: s.private_key.is_some(),
                        passphrase: s.passphrase.is_some(),
                    },
                )
            })
            .collect()
    }

    pub fn secret(&self, id: &str) -> Secret {
        self.secrets.get(id).cloned().unwrap_or_default()
    }

    pub fn update_secret(&mut self, id: &str, f: impl FnOnce(&mut Secret)) {
        let mut s = self.secret(id);
        f(&mut s);
        if s.is_empty() {
            self.secrets.remove(id);
        } else {
            self.secrets.insert(id.to_string(), s);
        }
    }

    pub fn host(&self, id: &str) -> Option<&Host> {
        self.data.hosts.iter().find(|h| h.id == id)
    }

    pub fn group(&self, id: &str) -> Option<&Group> {
        self.data.groups.iter().find(|g| g.id == id)
    }

    pub fn key(&self, id: &str) -> Option<&Key> {
        self.data.keys.iter().find(|k| k.id == id)
    }

    /// A host with its group's defaults filled in where the host leaves a field blank.
    pub fn effective_host(&self, id: &str) -> Option<Host> {
        let mut h = self.host(id)?.clone();
        if let Some(g) = h.group_id.as_deref().and_then(|g| self.group(g)) {
            if h.username.as_deref().unwrap_or("").is_empty() {
                h.username = g.username.clone();
            }
            if h.port.is_none() {
                h.port = g.port;
            }
            if h.key_id.is_none() {
                h.key_id = g.key_id.clone();
            }
        }
        Some(h)
    }

    pub fn known_host(&self, host: &str) -> Option<&KnownHost> {
        self.data.known_hosts.iter().find(|k| k.host == host)
    }

    pub fn set_known_host(&mut self, kh: KnownHost) {
        self.data.known_hosts.retain(|k| k.host != kh.host);
        self.data.known_hosts.push(kh);
    }
}

/// Insert or replace by id.
pub fn upsert<T, F: Fn(&T) -> &str>(list: &mut Vec<T>, item: T, id_of: F) {
    let id = id_of(&item).to_string();
    match list.iter().position(|x| id_of(x) == id) {
        Some(i) => list[i] = item,
        None => list.push(item),
    }
}
