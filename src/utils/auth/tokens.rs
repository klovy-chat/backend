// tokens.rs
// Losowe tokeny (2FA login, WS crypto, reset).
// Zakres:
//  - hash przed zapisem
//  - losowe one-shot (2FA login, WS crypto); hash przed Mongo
// TTL krótki dla one-shot.
// Przy zmianach: two_factor.rs, ws/keys.rs.

use jsonwebtoken::{encode, EncodingKey};
use mongodb::bson::oid::ObjectId;
use mongodb::Database;

use crate::middlewares::auth::TokenPayload;
use crate::utils::auth::validation::{hs256_header, JWT_AUDIENCE, JWT_ISSUER};

pub const ACCESS_MAX_AGE_MS: i64 = 30 * 24 * 60 * 60 * 1000;
pub const REFRESH_MAX_AGE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

pub async fn create_access_token(
    db: &Database,
    _username: &str,
    user_id: &str,
    session_family_id: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    use crate::model::users::User;

    let token_version = match ObjectId::parse_str(user_id) {
        Ok(oid) => User::find_by_id(db, oid)
            .await?
            .map(|u| u.token_version)
            .unwrap_or(0),
        Err(_) => 0,
    };

    let key =
        std::env::var("JWT_KEY").map_err(|_| "JWT_KEY is not defined in environment variables")?;
    let exp = (chrono::Utc::now().timestamp() + ACCESS_MAX_AGE_MS / 1000) as usize;

    let claims = TokenPayload {
        user_id: user_id.to_string(),
        token_version,
        session_family_id: session_family_id.map(|s| s.to_string()),
        exp,
        iss: JWT_ISSUER.to_string(),
        aud: JWT_AUDIENCE.to_string(),
    };

    let token = encode(
        &hs256_header(),
        &claims,
        &EncodingKey::from_secret(key.as_bytes()),
    )?;
    Ok(token)
}
