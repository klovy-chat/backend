// totp.rs
// Weryfikacja kodu TOTP (okno, replay).
// Zakres:
//  - login 2FA
//  - okno czasowe i replay; nie loguj kodu
// Nie loguj kodu.
// Przy zmianach: two_factor.rs, controllers/auth.rs.

use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::utils::crypto::{
    encrypt::{decrypt_field, encrypt_field},
    passwords::{hash_reset_token, verify_reset_token},
};

pub const BACKUP_CODE_COUNT: usize = 8;
const ISSUER: &str = "KlovyChat";

const PRIMARY_TOTP_ALGORITHM: Algorithm = Algorithm::SHA1;
const LEGACY_TOTP_ALGORITHM: Algorithm = Algorithm::SHA256;

pub fn generate_totp_secret() -> String {
    secret_base32(&Secret::generate_secret())
}

fn secret_base32(secret: &Secret) -> String {
    match secret.to_encoded() {
        Secret::Encoded(value) => value,
        Secret::Raw(bytes) => base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes),
    }
}

fn normalize_secret(secret: &str) -> String {
    secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase()
}

fn totp_for_account(username: &str, secret: &str, algorithm: Algorithm) -> Result<TOTP, String> {
    let normalized = normalize_secret(secret);
    TOTP::new(
        algorithm,
        6,
        2,
        30,
        Secret::Encoded(normalized)
            .to_bytes()
            .map_err(|e| e.to_string())?,
        Some(ISSUER.to_string()),
        username.to_string(),
    )
    .map_err(|e| e.to_string())
}

pub fn build_otpauth_url(username: &str, secret: &str) -> String {
    totp_for_account(username, secret, PRIMARY_TOTP_ALGORITHM)
        .map(|totp| totp.get_url())
        .unwrap_or_default()
}

fn totp_digits(code: &str) -> Option<String> {
    let compact: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if compact.len() == 6 && compact.chars().all(|c| c.is_ascii_digit()) {
        Some(compact)
    } else {
        None
    }
}

pub fn verify_totp_code(username: &str, secret: &str, code: &str) -> Result<bool, ()> {
    let Some(normalized) = totp_digits(code) else {
        return Ok(false);
    };

    let mut constructed = false;
    let mut saw_check_err = false;
    for algorithm in [PRIMARY_TOTP_ALGORITHM, LEGACY_TOTP_ALGORITHM] {
        let Ok(totp) = totp_for_account(username, secret, algorithm) else {
            continue;
        };
        constructed = true;
        match totp.check_current(&normalized) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(_) => saw_check_err = true,
        }
    }
    if !constructed || saw_check_err {
        Err(())
    } else {
        Ok(false)
    }
}

pub fn encrypt_totp_secret(secret: &str) -> Result<String, String> {
    encrypt_field(&normalize_secret(secret))
}

pub fn decrypt_totp_secret(encrypted: &str) -> Result<String, String> {
    decrypt_field(encrypted)
}

pub fn generate_backup_codes() -> Vec<String> {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            let part1: String = (0..4)
                .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
                .collect();
            let part2: String = (0..4)
                .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
                .collect();
            format!("{part1}-{part2}")
        })
        .collect()
}

pub fn normalize_backup_code(code: &str) -> String {
    code.trim()
        .to_uppercase()
        .replace('-', "")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

pub async fn hash_backup_codes(codes: &[String]) -> Result<Vec<String>, String> {
    let mut hashed = Vec::with_capacity(codes.len());
    for code in codes {
        let normalized = normalize_backup_code(code);
        let hash = hash_reset_token(&normalized)
            .await
            .map_err(|e| e.to_string())?;
        hashed.push(hash);
    }
    Ok(hashed)
}

pub async fn verify_and_consume_backup_code(
    code: &str,
    stored_hashes: &[String],
) -> Result<Option<usize>, ()> {
    let normalized = normalize_backup_code(code);
    if normalized.len() != 8 {
        return Ok(None);
    }
    for (index, hash) in stored_hashes.iter().enumerate() {
        match verify_reset_token(&normalized, hash).await {
            Ok(true) => return Ok(Some(index)),
            Ok(false) => {}
            Err(()) => return Err(()),
        }
    }
    Ok(None)
}

pub fn is_totp_code(code: &str) -> bool {
    totp_digits(code).is_some()
}
