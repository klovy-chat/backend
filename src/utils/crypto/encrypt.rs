// encrypt.rs
// AES-GCM pól (treść, searchText).
// Zakres:
//  - sealed at rest
//  - AES-GCM treści i searchText; rotacja klucza bez re-encrypt = śmieci
// Rotacja FIELD_ENCRYPTION_KEY bez re-encrypt = nieczytelna historia.
// Przy zmianach: messages.rs, encrypt_old.rs, FE encrypt.ts.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use std::env;
use std::sync::OnceLock;

use super::hmac::derive_subkey;

const NONCE_LEN: usize = 12;
const FIELD_ENCRYPT_CONTEXT: &str = "field-encrypt-v2";

fn legacy_key_from_jwt() -> Result<[u8; 32], String> {
    let jwt_key = env::var("JWT_KEY").map_err(|_| "JWT_KEY is not defined".to_string())?;
    let digest = Sha256::digest(jwt_key.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    Ok(key)
}

fn encryption_key_uncached() -> Result<[u8; 32], String> {
    if let Ok(raw) = env::var("FIELD_ENCRYPTION_KEY") {
        let raw = raw.trim();
        if !raw.is_empty() {
            if raw.len() < 32 {
                return Err("FIELD_ENCRYPTION_KEY must be at least 32 characters".to_string());
            }
            return Ok(derive_subkey(raw, FIELD_ENCRYPT_CONTEXT));
        }
    }
    legacy_key_from_jwt()
}

fn encryption_key() -> Result<[u8; 32], String> {
    static PRIMARY: OnceLock<[u8; 32]> = OnceLock::new();
    if let Some(key) = PRIMARY.get() {
        return Ok(*key);
    }
    let key = encryption_key_uncached()?;
    Ok(*PRIMARY.get_or_init(|| key))
}

fn decrypt_candidate_keys() -> &'static [[u8; 32]] {
    static KEYS: OnceLock<Vec<[u8; 32]>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut keys = Vec::with_capacity(3);
        if let Ok(primary) = encryption_key_uncached() {
            keys.push(primary);
        }
        if let Ok(raw) = env::var("FIELD_ENCRYPTION_KEY") {
            let raw = raw.trim();
            if raw.len() >= 32 {
                let digest = Sha256::digest(raw.as_bytes());
                let mut legacy_derived = [0u8; 32];
                legacy_derived.copy_from_slice(&digest);
                if !keys.iter().any(|k| k == &legacy_derived) {
                    keys.push(legacy_derived);
                }
            }
        }
        if let Ok(legacy) = legacy_key_from_jwt() {
            if !keys.iter().any(|k| k == &legacy) {
                keys.push(legacy);
            }
        }
        keys
    })
    .as_slice()
}

fn encrypt_cipher() -> Result<&'static Aes256Gcm, String> {
    static CIPHER: OnceLock<Aes256Gcm> = OnceLock::new();
    if let Some(c) = CIPHER.get() {
        return Ok(c);
    }
    let key = encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    Ok(CIPHER.get_or_init(|| cipher))
}

fn decrypt_ciphers() -> &'static [Aes256Gcm] {
    static CIPHERS: OnceLock<Vec<Aes256Gcm>> = OnceLock::new();
    CIPHERS
        .get_or_init(|| {
            decrypt_candidate_keys()
                .iter()
                .filter_map(|key| Aes256Gcm::new_from_slice(key).ok())
                .collect()
        })
        .as_slice()
}

fn decrypt_with_cipher(cipher: &Aes256Gcm, encoded: &str) -> Result<String, String> {
    let data = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, encoded)
        .ok_or_else(|| "Invalid encrypted field".to_string())?;
    if data.len() <= NONCE_LEN {
        return Err("Invalid encrypted field".to_string());
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Failed to decrypt field".to_string())?;
    String::from_utf8(plain).map_err(|_| "Invalid decrypted field".to_string())
}

pub fn encrypt_field(plain: &str) -> Result<String, String> {
    let cipher = encrypt_cipher()?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plain.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        &out,
    ))
}

pub fn decrypt_field(encoded: &str) -> Result<String, String> {
    let ciphers = decrypt_ciphers();
    if ciphers.is_empty() {
        return Err("No encryption key configured".to_string());
    }
    let mut last_err = None;
    for cipher in ciphers {
        match decrypt_with_cipher(cipher, encoded) {
            Ok(value) => return Ok(value),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| "Failed to decrypt field".to_string()))
}
