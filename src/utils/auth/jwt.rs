// jwt.rs
// Issuing/verify JWT w cookie.
// Zakres:
//  - expiry, secret JWT_KEY
//  - issue/verify cookie; rotacja JWT_KEY wyloguje wszystkich
// Rotacja klucza wyloguje wszystkich — komunikuj deploy.
// Przy zmianach: middlewares/auth.rs.

use jsonwebtoken::{decode, DecodingKey};
use mongodb::bson::oid::ObjectId;
use std::env;

use crate::middlewares::auth::TokenPayload;
use crate::model::refresh_tokens::RefreshToken;
use crate::model::users::User;
use crate::utils::auth::refresh::{family_id_from_refresh_token, RefreshAuthError};
use crate::utils::auth::validation::hs256_validation;
use crate::utils::db::get_db;
use crate::utils::env::is_production;

pub fn jwt_secret() -> Result<String, String> {
    let key = env::var("JWT_KEY").map_err(|_| "JWT_KEY is not defined".to_string())?;
    if key.trim().is_empty() {
        return Err("JWT_KEY is empty".to_string());
    }
    if is_production() && key.len() < 32 {
        return Err("JWT_KEY must be at least 32 characters in production".to_string());
    }
    Ok(key)
}

pub fn jwt_decoding_key() -> Result<DecodingKey, String> {
    Ok(DecodingKey::from_secret(jwt_secret()?.as_bytes()))
}

pub fn parse_jwt_from_cookie_header(cookie_header: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("jwt=") {
            let token = value.trim();
            if !token.is_empty() && token.len() <= 1000 {
                return Some(token.to_string());
            }
        }
    }
    None
}

pub fn parse_refresh_from_cookie_header(cookie_header: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("refreshToken=") {
            let token = value.trim();
            if !token.is_empty() && token.len() <= 128 {
                return Some(token.to_string());
            }
        }
    }
    None
}

pub async fn resolve_session_family_id(
    payload: &TokenPayload,
    refresh_token: Option<&str>,
) -> Result<Option<String>, JwtUserError> {
    if let Some(ref family_id) = payload.session_family_id {
        if !family_id.is_empty() {
            return Ok(Some(family_id.clone()));
        }
        return Ok(None);
    }

    if let Some(raw) = refresh_token {
        return match family_id_from_refresh_token(raw).await {
            Ok(v) => Ok(v),
            Err(RefreshAuthError::Unavailable) => Err(JwtUserError::Unavailable),
            Err(RefreshAuthError::Denied) => Ok(None),
        };
    }

    Ok(None)
}

pub fn session_family_from_jwt(token: &str) -> Option<String> {
    if token.is_empty() || token.len() > 1000 {
        return None;
    }

    let key = jwt_decoding_key().ok()?;
    let payload = decode::<TokenPayload>(token, &key, &hs256_validation())
        .ok()?
        .claims;

    payload.session_family_id.filter(|id| !id.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtUserError {
    Denied,
    Unavailable,
}

pub async fn user_from_jwt(token: &str) -> Result<User, JwtUserError> {
    user_from_jwt_with_refresh(token, None).await
}

pub async fn user_from_jwt_with_refresh(
    token: &str,
    refresh_token: Option<&str>,
) -> Result<User, JwtUserError> {
    if token.is_empty() || token.len() > 1000 {
        return Err(JwtUserError::Denied);
    }

    let key = jwt_decoding_key().map_err(|_| JwtUserError::Unavailable)?;
    let payload = decode::<TokenPayload>(token, &key, &hs256_validation())
        .map_err(|_| JwtUserError::Denied)?
        .claims;

    user_from_token_payload(&payload, refresh_token).await
}

pub async fn user_from_token_payload(
    payload: &TokenPayload,
    refresh_token: Option<&str>,
) -> Result<User, JwtUserError> {
    if payload.user_id.is_empty() {
        return Err(JwtUserError::Denied);
    }

    let user_id = ObjectId::parse_str(&payload.user_id).map_err(|_| JwtUserError::Denied)?;
    let db = get_db();
    let user = match User::find_by_id(&db, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(JwtUserError::Denied),
        Err(_) => return Err(JwtUserError::Unavailable),
    };

    if user.token_version != payload.token_version {
        return Err(JwtUserError::Denied);
    }
    if !user.is_login_allowed() {
        return Err(JwtUserError::Denied);
    }

    let family_id = resolve_session_family_id(payload, refresh_token).await?;
    if let Some(ref family_id) = family_id {
        match RefreshToken::family_is_active(&db, family_id).await {
            Ok(true) => {}
            Ok(false) => return Err(JwtUserError::Denied),
            Err(_) => return Err(JwtUserError::Unavailable),
        }
    }

    Ok(user)
}
