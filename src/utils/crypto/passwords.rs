// passwords.rs
// Argon2 hash/verify haseł.
// Zakres:
//  - koszt
//  - Argon2; zmiana kosztu = ostrożna migracja
// Zmiana parametrów = wszyscy re-login przy verify fail — migruj ostrożnie.
// Przy zmianach: controllers/auth.rs.

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref ARGON2_HASH_PREFIX: Regex = Regex::new(r"^\$argon2(id|i|d)\$").unwrap();
}

fn password_hasher() -> Argon2<'static> {
    let params = Params::new(19456, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn token_hasher() -> Argon2<'static> {
    let params = Params::new(8192, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn is_stored_password_hash(value: &str) -> bool {
    ARGON2_HASH_PREFIX.is_match(value)
}

fn hash_with(
    hasher: Argon2<'static>,
    plain: String,
) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = hasher.hash_password(plain.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

pub async fn hash_user_password(plain: &str) -> Result<String, argon2::password_hash::Error> {
    let plain = plain.to_string();
    match tokio::task::spawn_blocking(move || hash_with(password_hasher(), plain)).await {
        Ok(result) => result,
        Err(_) => {
            log::error!("argon2 password hashing task failed to join");
            Err(argon2::password_hash::Error::Crypto)
        }
    }
}

pub async fn hash_reset_token(plain: &str) -> Result<String, argon2::password_hash::Error> {
    let plain = plain.to_string();
    match tokio::task::spawn_blocking(move || hash_with(token_hasher(), plain)).await {
        Ok(result) => result,
        Err(_) => {
            log::error!("argon2 token hashing task failed to join");
            Err(argon2::password_hash::Error::Crypto)
        }
    }
}

fn verify_with(plain: String, stored_hash: String) -> Result<bool, ()> {
    match PasswordHash::new(&stored_hash) {
        Ok(parsed) => Ok(Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok()),
        Err(_) => Err(()),
    }
}

pub async fn verify_user_password(plain: &str, stored_hash: &str) -> Result<bool, ()> {
    let plain = plain.to_string();
    let stored_hash = stored_hash.to_string();
    match tokio::task::spawn_blocking(move || verify_with(plain, stored_hash)).await {
        Ok(inner) => inner,
        Err(e) => {
            log::error!("password verify join failed: {e}");
            Err(())
        }
    }
}

pub async fn verify_reset_token(plain: &str, stored_hash: &str) -> Result<bool, ()> {
    verify_user_password(plain, stored_hash).await
}
