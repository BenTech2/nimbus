//! Export / import of everything (hosts, groups, keys, passwords, API keys, snippets, trusted
//! host keys) as one portable file.
//!
//! The whole file is encrypted with a password the user chooses at export (scrypt +
//! AES-256-GCM), and that password is needed to import it. Only the format name, version and
//! export time are readable without it.
//!
//! Format history: version 1 kept the data readable and only sealed the secrets (optionally).
//! Version 1 files are still accepted when they were password-protected; unprotected ones are
//! refused, since importing them would bypass the password requirement.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::store::{now_ms, upsert, ApiCredential, Group, Host, Key, KnownHost, PasswordEntry, PasswordGroup, Secret, Snippet, Store};
use crate::vault::{open_with_passphrase, seal_with_passphrase, Sealed};

const FORMAT: &str = "nimbus-export";
const VERSION: u32 = 2;
/// Long enough to make guessing impractical against scrypt; the UI asks for it twice.
pub const MIN_PASSWORD: usize = 10;

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ExportData {
    pub groups: Vec<Group>,
    pub hosts: Vec<Host>,
    pub keys: Vec<Key>,
    pub snippets: Vec<Snippet>,
    pub passwords: Vec<PasswordEntry>,
    pub password_groups: Vec<PasswordGroup>,
    pub api_keys: Vec<ApiCredential>,
    pub api_groups: Vec<PasswordGroup>,
    pub known_hosts: Vec<KnownHost>,
}

/// What's inside the encrypted part of a version 2 file.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(default)]
struct Payload {
    data: ExportData,
    secrets: HashMap<String, Secret>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFile {
    pub format: String,
    pub version: u32,
    pub exported_at: i64,
    pub app_version: String,
    /// Version 2: the whole payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<Sealed>,
    /// Version 1 only: readable data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<ExportData>,
    /// Version 1 only: sealed secrets, present when a passphrase was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    pub api_keys: usize,
    pub known_hosts: usize,
    pub exported_at: i64,
}

pub fn check_password(password: &str) -> anyhow::Result<()> {
    if password.chars().count() < MIN_PASSWORD {
        bail!("Use a password of at least {MIN_PASSWORD} characters");
    }
    Ok(())
}

pub fn export(store: &Store, path: &Path, password: &str) -> anyhow::Result<()> {
    check_password(password)?;
    let d = &store.data;
    let payload = Payload {
        data: ExportData {
            groups: d.groups.clone(),
            hosts: d.hosts.clone(),
            keys: d.keys.clone(),
            snippets: d.snippets.clone(),
            passwords: d.passwords.clone(),
            password_groups: d.password_groups.clone(),
            api_keys: d.api_keys.clone(),
            api_groups: d.api_groups.clone(),
            known_hosts: d.known_hosts.clone(),
        },
        secrets: store.secrets.clone(),
    };
    let file = ExportFile {
        format: FORMAT.into(),
        version: VERSION,
        exported_at: now_ms(),
        app_version: env!("CARGO_PKG_VERSION").into(),
        encrypted: Some(seal_with_passphrase(password, &serde_json::to_vec(&payload)?)?),
        data: None,
        secrets: None,
    };
    crate::store::write_atomic(path, &serde_json::to_vec_pretty(&file)?)?;
    Ok(())
}

const WRONG_PASSWORD: &str = "That password doesn't open this file. Check it and try again (it's case-sensitive).";

/// Read and decrypt an export. Fails without the right password.
fn read(path: &Path, password: &str) -> anyhow::Result<(i64, Payload)> {
    let meta = fs::metadata(path)?;
    if meta.len() > 64 * 1024 * 1024 {
        bail!("That file is too large to be a Nimbus export");
    }
    let file: ExportFile = serde_json::from_slice(&fs::read(path)?).map_err(|_| anyhow!("Not a Nimbus export file"))?;
    if file.format != FORMAT {
        bail!("Not a Nimbus export file");
    }
    if file.version > VERSION {
        bail!("This export was made by a newer Nimbus (format {}). Update Nimbus to import it.", file.version);
    }
    if password.is_empty() {
        bail!("Enter the password this file was exported with");
    }
    let payload = match (file.version, file.encrypted, file.secrets) {
        (2, Some(sealed), _) => {
            let plain = open_with_passphrase(password, &sealed).map_err(|_| anyhow!(WRONG_PASSWORD))?;
            serde_json::from_slice(&plain).map_err(|e| anyhow!("The file decrypted but its contents are damaged ({e})"))?
        }
        (1, _, Some(sealed)) => {
            let plain = open_with_passphrase(password, &sealed).map_err(|_| anyhow!(WRONG_PASSWORD))?;
            Payload { data: file.data.unwrap_or_default(), secrets: serde_json::from_slice(&plain)? }
        }
        (1, _, None) => bail!(
            "This file was exported by an older Nimbus without a password. Nimbus now only imports \
             password-protected files: export again from the other computer with Nimbus 0.4 or later."
        ),
        _ => bail!("This export file is damaged"),
    };
    Ok((file.exported_at, payload))
}

pub fn preview(path: &Path, password: &str) -> anyhow::Result<Preview> {
    let (exported_at, p) = read(path, password)?;
    let d = &p.data;
    Ok(Preview {
        groups: d.groups.len(),
        hosts: d.hosts.len(),
        keys: d.keys.len(),
        snippets: d.snippets.len(),
        passwords: d.passwords.len(),
        api_keys: d.api_keys.len(),
        known_hosts: d.known_hosts.len(),
        exported_at,
    })
}

/// mode "merge": add new items and update items with the same id; keep everything else.
/// mode "replace": the file becomes the whole library (settings are kept).
pub fn apply(store: &mut Store, path: &Path, mode: &str, password: &str) -> anyhow::Result<()> {
    let (_, Payload { data: d, secrets }) = read(path, password)?;
    match mode {
        "replace" => {
            store.data.groups = d.groups;
            store.data.hosts = d.hosts;
            store.data.keys = d.keys;
            store.data.snippets = d.snippets;
            store.data.passwords = d.passwords;
            store.data.password_groups = d.password_groups;
            store.data.api_keys = d.api_keys;
            store.data.api_groups = d.api_groups;
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
            for g in d.password_groups {
                upsert(&mut store.data.password_groups, g, |x| &x.id);
            }
            for g in d.api_groups {
                upsert(&mut store.data.api_groups, g, |x| &x.id);
            }
            for a in d.api_keys {
                upsert(&mut store.data.api_keys, a, |x| &x.id);
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
