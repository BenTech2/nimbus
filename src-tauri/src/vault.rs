//! Encryption for secrets at rest and for password-protected exports.
//!
//! At rest: a random 256-bit master key is kept in the OS credential store (macOS Keychain,
//! Windows Credential Manager, Secret Service on Linux). If no credential store is available
//! (e.g. a minimal Linux install), the key falls back to a 0600 file next to the data, and the
//! UI says so.
//!
//! Exports: the secrets section is encrypted with a key derived from the user's passphrase
//! (scrypt), so an export file can be carried to another computer and opened there.

use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

const SERVICE: &str = "app.nimbus.ssh";
const ACCOUNT: &str = "master-key";
const MAGIC: &[u8; 4] = b"NMB1";

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS random number generator unavailable");
    b
}

fn seal(key: &[u8; 32], plain: &[u8]) -> anyhow::Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("bad key length"))?;
    let nonce = random_bytes::<12>();
    let ct = cipher
        .encrypt(&Nonce::from(nonce), plain)
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok((ct, nonce))
}

fn open(key: &[u8; 32], nonce: &[u8], ct: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("bad key length"))?;
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| anyhow!("bad nonce"))?;
    cipher
        .decrypt(&Nonce::from(nonce), ct)
        .map_err(|_| anyhow!("decryption failed"))
}

enum KeySource {
    Keychain,
    File,
}

pub struct Vault {
    key: [u8; 32],
    source: KeySource,
}

impl Vault {
    pub fn open(dir: &Path) -> anyhow::Result<Vault> {
        let file = dir.join("master.key");
        // A key file from an earlier fallback run wins, so we never orphan existing secrets.
        if let Ok(text) = fs::read_to_string(&file) {
            return Ok(Vault { key: decode_key(&text)?, source: KeySource::File });
        }
        match keychain_key() {
            Ok(key) => Ok(Vault { key, source: KeySource::Keychain }),
            Err(e) => {
                eprintln!("nimbus: OS keychain unavailable ({e}); using a local key file");
                let key = random_bytes::<32>();
                crate::store::write_atomic(&file, B64.encode(key).as_bytes())?;
                Ok(Vault { key, source: KeySource::File })
            }
        }
    }

    pub fn mode(&self) -> &'static str {
        match self.source {
            KeySource::Keychain => "keychain",
            KeySource::File => "file",
        }
    }

    pub fn encrypt(&self, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (ct, nonce) = seal(&self.key, plain)?;
        let mut out = Vec::with_capacity(4 + 12 + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&self, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
        if blob.len() < 16 || &blob[..4] != MAGIC {
            return Err(anyhow!("secrets file is not in Nimbus format"));
        }
        open(&self.key, &blob[4..16], &blob[16..]).context(
            "could not decrypt saved secrets — the master key in the OS keychain does not match secrets.bin",
        )
    }
}

fn decode_key(text: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = B64.decode(text.trim())?;
    bytes.try_into().map_err(|_| anyhow!("master key has the wrong length"))
}

fn keychain_key() -> anyhow::Result<[u8; 32]> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)?;
    match entry.get_password() {
        Ok(text) => decode_key(&text),
        Err(keyring::Error::NoEntry) => {
            let key = random_bytes::<32>();
            entry.set_password(&B64.encode(key))?;
            // Read it back: some stores accept a write and then fail reads.
            let check = decode_key(&entry.get_password()?)?;
            if check != key {
                return Err(anyhow!("keychain round-trip mismatch"));
            }
            Ok(key)
        }
        Err(e) => Err(e.into()),
    }
}

/// Passphrase-protected envelope used in export files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sealed {
    pub cipher: String,
    pub kdf: String,
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    pub salt: String,
    pub nonce: String,
    pub data: String,
}

fn derive(passphrase: &str, salt: &[u8], log_n: u8, r: u32, p: u32) -> anyhow::Result<[u8; 32]> {
    let params = scrypt::Params::new(log_n, r, p).map_err(|e| anyhow!("scrypt params: {e}"))?;
    let mut key = [0u8; 32];
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut key)
        .map_err(|e| anyhow!("scrypt: {e}"))?;
    Ok(key)
}

pub fn seal_with_passphrase(passphrase: &str, plain: &[u8]) -> anyhow::Result<Sealed> {
    let (log_n, r, p) = (17u8, 8u32, 1u32);
    let salt = random_bytes::<16>();
    let key = derive(passphrase, &salt, log_n, r, p)?;
    let (ct, nonce) = seal(&key, plain)?;
    Ok(Sealed {
        cipher: "aes-256-gcm".into(),
        kdf: "scrypt".into(),
        log_n,
        r,
        p,
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
        data: B64.encode(ct),
    })
}

pub fn open_with_passphrase(passphrase: &str, sealed: &Sealed) -> anyhow::Result<Vec<u8>> {
    if sealed.cipher != "aes-256-gcm" || sealed.kdf != "scrypt" {
        return Err(anyhow!("unsupported export encryption"));
    }
    if sealed.log_n > 22 || sealed.r > 32 || sealed.p > 16 {
        return Err(anyhow!("export encryption parameters are out of range"));
    }
    let key = derive(passphrase, &B64.decode(&sealed.salt)?, sealed.log_n, sealed.r, sealed.p)?;
    open(&key, &B64.decode(&sealed.nonce)?, &B64.decode(&sealed.data)?)
        .map_err(|_| anyhow!("wrong passphrase, or the file has been altered"))
}
