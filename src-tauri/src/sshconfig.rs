//! Import hosts from ~/.ssh/config.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::store::{new_id, Group, Host, Key, Store};

#[derive(Debug, Default)]
struct Entry {
    alias: String,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub hosts_added: usize,
    pub hosts_skipped: usize,
    pub keys_added: usize,
    pub warnings: Vec<String>,
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

fn ssh_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh"))
}

fn expand(path: &str) -> PathBuf {
    let p = unquote(path).replace("%d", &dirs::home_dir().unwrap_or_default().to_string_lossy());
    let p = crate::ssh::expand_tilde(&p);
    let pb = PathBuf::from(&p);
    if pb.is_relative() {
        ssh_dir().unwrap_or_default().join(pb)
    } else {
        pb
    }
}

fn parse_file(path: &Path, out: &mut Vec<Entry>, depth: u8, warnings: &mut Vec<String>) {
    let Ok(text) = fs::read_to_string(path) else {
        if depth == 0 {
            warnings.push(format!("Could not read {}", path.display()));
        }
        return;
    };
    // Indexes into `out` for the aliases of the Host block we're in.
    let mut current: Vec<usize> = vec![];
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (k.to_lowercase(), v.trim().trim_start_matches('=').trim().to_string()),
            None => continue,
        };
        match k.as_str() {
            "host" => {
                current.clear();
                for alias in v.split_whitespace() {
                    let alias = unquote(alias);
                    if alias.contains(['*', '?', '!']) {
                        continue; // wildcard patterns are defaults, not connectable hosts
                    }
                    out.push(Entry { alias, ..Default::default() });
                    current.push(out.len() - 1);
                }
            }
            "match" => current.clear(),
            "include" if depth < 3 => {
                for p in v.split_whitespace() {
                    let p = expand(p);
                    if p.to_string_lossy().contains('*') {
                        warnings.push(format!("Skipped wildcard Include {}", p.display()));
                    } else {
                        parse_file(&p, out, depth + 1, warnings);
                    }
                }
                current.clear();
            }
            _ => {
                for &i in &current {
                    let e = &mut out[i];
                    // ssh uses the first value it sees for each option.
                    match k.as_str() {
                        "hostname" if e.hostname.is_none() => e.hostname = Some(unquote(&v)),
                        "user" if e.user.is_none() => e.user = Some(unquote(&v)),
                        "port" if e.port.is_none() => e.port = v.parse().ok(),
                        "identityfile" if e.identity_file.is_none() => e.identity_file = Some(v.clone()),
                        "proxyjump" if e.proxy_jump.is_none() => e.proxy_jump = Some(unquote(&v)),
                        _ => {}
                    }
                }
            }
        }
    }
}

pub fn import(store: &mut Store) -> ImportReport {
    let mut report = ImportReport::default();
    let Some(dir) = ssh_dir() else {
        report.warnings.push("No home folder found".into());
        return report;
    };
    let mut entries = vec![];
    parse_file(&dir.join("config"), &mut entries, 0, &mut report.warnings);
    if entries.is_empty() {
        return report;
    }

    let group_id = match store.data.groups.iter().find(|g| g.name == "SSH config") {
        Some(g) => g.id.clone(),
        None => {
            let g = Group { id: new_id(), name: "SSH config".into(), ..Default::default() };
            let id = g.id.clone();
            store.data.groups.push(g);
            id
        }
    };

    let mut added: Vec<(String, Option<String>)> = vec![]; // (host id, proxy jump)
    for e in entries {
        let address = e.hostname.clone().unwrap_or_else(|| e.alias.clone());
        if address.contains('%') {
            report.warnings.push(format!("Skipped {}: HostName uses % tokens", e.alias));
            report.hosts_skipped += 1;
            continue;
        }
        if store.data.hosts.iter().any(|h| h.label == e.alias && h.address == address) {
            report.hosts_skipped += 1;
            continue;
        }
        let key_id = e.identity_file.as_deref().and_then(|f| import_key(store, f, &mut report));
        let host = Host {
            id: new_id(),
            label: e.alias.clone(),
            address,
            port: e.port.filter(|p| *p != 22),
            username: e.user.clone(),
            group_id: Some(group_id.clone()),
            key_id,
            ..Default::default()
        };
        added.push((host.id.clone(), e.proxy_jump.clone()));
        store.data.hosts.push(host);
        report.hosts_added += 1;
    }

    // Resolve ProxyJump aliases now that every host exists.
    for (id, jump) in added {
        let Some(jump) = jump else { continue };
        let first = jump.split(',').next().unwrap_or("");
        let name = first.rsplit('@').next().unwrap_or(first).split(':').next().unwrap_or("");
        let target = store.data.hosts.iter().find(|h| h.label == name || h.address == name).map(|h| h.id.clone());
        let label = store.host(&id).map(|h| h.label.clone()).unwrap_or_default();
        match target {
            Some(t) if t != id => {
                if let Some(h) = store.data.hosts.iter_mut().find(|h| h.id == id) {
                    h.jump_host_id = Some(t);
                }
            }
            _ => report.warnings.push(format!("{label}: ProxyJump {jump} isn't a saved host, so it was not set")),
        }
    }
    report
}

fn import_key(store: &mut Store, file: &str, report: &mut ImportReport) -> Option<String> {
    let path = expand(file);
    if path.to_string_lossy().contains('%') {
        return None;
    }
    let pem = match fs::read_to_string(&path) {
        Ok(p) => p,
        Err(_) => {
            report.warnings.push(format!("Key file {} not found", path.display()));
            return None;
        }
    };
    let info = match crate::keys::describe(&pem, None) {
        Ok(i) => i,
        Err(e) => {
            report.warnings.push(format!("{}: {e}", path.display()));
            return None;
        }
    };
    if let Some(k) = store.data.keys.iter().find(|k| k.fingerprint == info.fingerprint) {
        return Some(k.id.clone());
    }
    let key = Key {
        id: new_id(),
        label: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "key".into()),
        key_type: info.key_type,
        public_key: info.public_key,
        fingerprint: info.fingerprint,
        encrypted: info.encrypted,
    };
    let id = key.id.clone();
    store.update_secret(&id, |s| s.private_key = Some(pem));
    store.data.keys.push(key);
    report.keys_added += 1;
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_skips_wildcards_and_first_value_wins() {
        let dir = std::env::temp_dir().join(format!("nimbus-cfg-{}", new_id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config");
        fs::write(
            &file,
            "# comment\nHost *\n  User nobody\n\nHost web web-alias\n  HostName 10.0.0.5\n  User deploy\n  User ignored\n  Port=2200\n  ProxyJump admin@bastion:22\n\nHost bastion\n  Hostname bastion.example.com\n\nMatch host foo\n  User matched\n",
        )
        .unwrap();
        let mut out = vec![];
        let mut warnings = vec![];
        parse_file(&file, &mut out, 0, &mut warnings);
        let aliases: Vec<_> = out.iter().map(|e| e.alias.as_str()).collect();
        assert_eq!(aliases, ["web", "web-alias", "bastion"]);
        assert_eq!(out[0].hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(out[0].user.as_deref(), Some("deploy"));
        assert_eq!(out[0].port, Some(2200));
        assert_eq!(out[0].proxy_jump.as_deref(), Some("admin@bastion:22"));
        assert_eq!(out[2].hostname.as_deref(), Some("bastion.example.com"));
        assert_eq!(out[2].user, None, "Match block values must not leak into the previous Host");
    }
}
