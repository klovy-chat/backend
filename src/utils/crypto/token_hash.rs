// token_hash.rs
// Hash tokenów refresh/invite przed Mongo.
// Zakres:
//  - nie plaintext
//  - hash refresh/invite; zmiana algorytmu unieważnia tokeny
// Lookup po hash — zmiana algorytmu unieważnia tokeny.
// Przy zmianach: refresh.rs, invites.rs.

use std::env;

use super::hmac::{derive_subkey, hmac_sha256_hex, sha256_hex};

const REFRESH_TOKEN_CONTEXT: &str = "refresh-token-v2";
const REFRESH_HASH_PREFIX: &str = "v2:";

pub fn refresh_token_hmac_key() -> Result<Vec<u8>, String> {
    if let Ok(key) = env::var("TOKEN_HASH_KEY") {
        let key = key.trim();
        if !key.is_empty() {
            if crate::utils::env::is_production() && key.len() < 32 {
                return Err(
                    "TOKEN_HASH_KEY must be at least 32 characters in production".to_string(),
                );
            }
            return Ok(key.as_bytes().to_vec());
        }
    }

    if crate::utils::env::is_production() {
        return Err("TOKEN_HASH_KEY must be set in production".to_string());
    }

    let jwt_key = env::var("JWT_KEY").map_err(|_| "JWT_KEY is not defined".to_string())?;
    if jwt_key.trim().is_empty() {
        return Err("JWT_KEY is empty".to_string());
    }
    Ok(derive_subkey(&jwt_key, REFRESH_TOKEN_CONTEXT).to_vec())
}

pub fn hash_refresh_token_for_storage(raw: &str) -> Result<String, String> {
    let key = refresh_token_hmac_key()?;
    Ok(format!(
        "{REFRESH_HASH_PREFIX}{}",
        hmac_sha256_hex(&key, raw)
    ))
}

pub fn legacy_refresh_token_hash(raw: &str) -> String {
    sha256_hex(raw)
}

pub fn is_legacy_refresh_hash(stored: &str) -> bool {
    !stored.starts_with(REFRESH_HASH_PREFIX)
}
