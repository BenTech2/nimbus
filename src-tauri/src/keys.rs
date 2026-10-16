//! Reading and generating SSH private keys for the keychain.

use anyhow::anyhow;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::{LineEnding, PrivateKey};
use russh::keys::{decode_secret_key, HashAlg};

#[derive(Debug)]
pub struct KeyInfo {
    pub key_type: String,
    pub public_key: String,
    pub fingerprint: String,
    pub encrypted: bool,
}

/// Work out a key's public half. Encrypted OpenSSH keys expose their public key without the
/// passphrase; if a passphrase is supplied it is checked.
pub fn describe(pem: &str, passphrase: Option<&str>) -> anyhow::Result<KeyInfo> {
    let pem = pem.trim();
    if pem.is_empty() {
        return Err(anyhow!("The private key is empty"));
    }
    if pem.contains("PUBLIC KEY") || pem.starts_with("ssh-") || pem.starts_with("ecdsa-") {
        return Err(anyhow!("That's a public key. Paste or choose the private key (the file without .pub)."));
    }
    if let Ok(k) = PrivateKey::from_openssh(pem) {
        let encrypted = k.is_encrypted();
        if encrypted {
            if let Some(p) = passphrase.filter(|p| !p.is_empty()) {
                k.decrypt(p).map_err(|_| anyhow!("Wrong passphrase for this key"))?;
            }
        }
        let pk = k.public_key();
        return Ok(KeyInfo {
            key_type: pk.algorithm().as_str().to_string(),
            public_key: pk.to_openssh()?,
            fingerprint: pk.fingerprint(HashAlg::Sha256).to_string(),
            encrypted,
        });
    }
    // PEM / PKCS#8 / PuTTY formats need decrypting to see the public key.
    let k = decode_secret_key(pem, passphrase.filter(|p| !p.is_empty())).map_err(|e| match e {
        russh::keys::Error::KeyIsEncrypted => anyhow!("This key is encrypted. Enter its passphrase to add it."),
        other => anyhow!("Not a private key Nimbus can read ({other})"),
    })?;
    let pk = k.public_key();
    Ok(KeyInfo {
        key_type: pk.algorithm().as_str().to_string(),
        public_key: pk.to_openssh()?,
        fingerprint: pk.fingerprint(HashAlg::Sha256).to_string(),
        encrypted: passphrase.is_some_and(|p| !p.is_empty()),
    })
}

/// A new unencrypted Ed25519 key in OpenSSH format.
pub fn generate_ed25519(comment: &str) -> anyhow::Result<String> {
    let seed = crate::vault::random_bytes::<32>();
    let kp = Ed25519Keypair::from_seed(&seed);
    let key = PrivateKey::new(KeypairData::Ed25519(kp), comment)?;
    Ok(key.to_openssh(LineEnding::LF)?.to_string())
}
