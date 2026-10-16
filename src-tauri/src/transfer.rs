//! Export / import of hosts, groups, keys and snippets as one portable JSON file.
//!
//! Secrets (passwords, private keys, passphrases) are only included when the user sets an
//! export passphrase; they are then sealed with scrypt + AES-256-GCM inside the file.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::store::{now_ms, upsert, Group, Host, Key, KnownHost, PasswordEntry, Secret, Snippet, Store};
use crate::vault::{open_with_passphrase, seal_with_passphrase, Sealed};

const FORMAT: &str = "nimbus-export";

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ExportData {
    pub groups: Vec<Group>,
    pub hosts: Vec<Host>,
    pub keys: Vec<Key>,
    pub snippets: Vec<Snippet>,
    pub passwords: Vec<PasswordEntry>,
    pub known_hosts: Vec<KnownHost>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFile {
    pub format: String,
    pub version: u32,
    pub exported_at: i64,
    pub app_version: String,
    pub data: ExportData,
    #[serde(default)]
    pub secrets: Option<Sealed>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub groups: usize,
    pub hosts: usize,
    pub keys: usize,
    pub snippets: usize,
    pub passwords: usize,
    pub known_hosts: usize,
    pub has_secrets: bool,
    pub exported_at: i64,
}

pub fn export(store: &Store, path: &Path, passphrase: Option<&str>) -> anyhow::Result<()> {
    let d = &store.data;
    let secrets = match passphrase.filter(|p| !p.is_empty()) {
        Some(p) => Some(seal_with_passphrase(p, &serde_json::to_vec(&store.secrets)?)?),
        None => None,
    };
    let file = ExportFile {
        format: FORMAT.into(),
        version: 1,
        exported_at: now_ms(),
        app_version: env!("CARGO_PKG_VERSION").into(),
        data: ExportData {
            groups: d.groups.clone(),
            hosts: d.hosts.clone(),
            keys: d.keys.clone(),
            snippets: d.snippets.clone(),
            passwords: d.passwords.clone(),
            known_hosts: d.known_hosts.clone(),
        },
        secrets,
    };
    crate::store::write_atomic(path, &serde_json::to_vec_pretty(&file)?)?;
    Ok(())
}

pub fn read(path: &Path) -> anyhow::Result<ExportFile> {
    let meta = fs::metadata(path)?;
    if meta.len() > 64 * 1024 * 1024 {
        bail!("That file is too large to be a Nimbus export");
    }
    let file: ExportFile = serde_json::from_slice(&fs::read(path)?)
        .map_err(|e| anyhow!("Not a Nimbus export file ({e})"))?;
    if file.format != FORMAT {
        bail!("Not a Nimbus export file");
    }
    if file.version > 1 {
        bail!("This export was made by a newer Nimbus (format {}). Update Nimbus to import it.", file.version);
    }
    Ok(file)
}

pub fn preview(path: &Path) -> anyhow::Result<Preview> {
    let f = read(path)?;
    Ok(Preview {
        groups: f.data.groups.len(),
        hosts: f.data.hosts.len(),
        keys: f.data.keys.len(),
        snippets: f.data.snippets.len(),
        passwords: f.data.passwords.len(),
        known_hosts: f.data.known_hosts.len(),
        has_secrets: f.secrets.is_some(),
        exported_at: f.exported_at,
    })
}

/// mode "merge": add new items and update items with the same id; keep everything else.
/// mode "replace": the file becomes the whole library (settings are kept).
pub fn apply(store: &mut Store, path: &Path, mode: &str, passphrase: Option<&str>) -> anyhow::Result<()> {
    let f = read(path)?;
    let secrets: HashMap<String, Secret> = match (&f.secrets, passphrase.filter(|p| !p.is_empty())) {
        (Some(sealed), Some(p)) => serde_json::from_slice(&open_with_passphrase(p, sealed)?)?,
        _ => HashMap::new(),
    };
    let d = f.data;
    match mode {
        "replace" => {
            store.data.groups = d.groups;
            store.data.hosts = d.hosts;
            store.data.keys = d.keys;
            store.data.snippets = d.snippets;
            store.data.passwords = d.passwords;
            store.data.known_hosts = d.known_hosts;
            store.secrets = secrets;
        }
        "merge" => {
            for g in d.groups {
                upsert(&mut store.data.groups, g, |x| &x.id);
            }
            for h in d.hosts {
                upsert(&mut store.data.hosts, h, |x| &x.id);
            }
            for k in d.keys {
                upsert(&mut store.data.keys, k, |x| &x.id);
            }
            for s in d.snippets {
                upsert(&mut store.data.snippets, s, |x| &x.id);
            }
            for p in d.passwords {
                upsert(&mut store.data.passwords, p, |x| &x.id);
            }
            for kh in d.known_hosts {
                store.set_known_host(kh);
            }
            store.secrets.extend(secrets);
        }
        other => bail!("Unknown import mode {other}"),
    }
    Ok(())
}
