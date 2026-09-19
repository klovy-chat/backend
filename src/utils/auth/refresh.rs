// refresh.rs
// Rotacja refresh, family, reuse = revoke.
// Zakres:
//  - hash w Mongo
//  - rotacja family; reuse tokenu = revoke (kradzież cookie)
// Reuse = kradzież cookie — nie ignoruj.
// Przy zmianach: refresh_tokens.rs, token_hash.rs.

use chrono::{Duration, Utc};
use mongodb::bson::oid::ObjectId;
use rand::Rng;
use serde::Serialize;
use uuid::Uuid;

use crate::model::refresh_tokens::RefreshToken;
use crate::model::users::User;
use crate::utils::auth::session::{normalize_browser_name, resolved_os_label};
use crate::utils::auth::metadata::SessionClientMetadata;
use crate::utils::crypto::hmac::verify_hmac_sha256_hex;
use crate::utils::crypto::token_hash::{
    hash_refresh_token_for_storage, is_legacy_refresh_hash, legacy_refresh_token_hash,
    refresh_token_hmac_key,
};
use crate::utils::auth::tokens::REFRESH_MAX_AGE_MS;
use crate::utils::db::get_db;

pub const REFRESH_COOKIE: &str = "refreshToken";

pub struct IssuedRefreshToken {
    pub raw_token: String,
    pub family_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSessionInfo {
    pub id: String,
    pub label: String,
    pub browser: String,
    pub os: String,
    pub user_agent: Option<String>,
    pub is_known: bool,
    pub is_current: bool,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}

fn generate_raw_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

pub async fn find_stored_refresh_token(
    db: &mongodb::Database,
    raw_token: &str,
) -> Result<Option<RefreshToken>, String> {
    let v2_hash = hash_refresh_token_for_storage(raw_token)?;
    if let Some(found) = RefreshToken::find_by_hash(db, &v2_hash)
        .await
        .map_err(|e| e.to_string())?
    {
        let stored_hex = found
            .token_hash
            .strip_prefix("v2:")
            .unwrap_or(found.token_hash.as_str());
        let key = refresh_token_hmac_key()?;
        if !verify_hmac_sha256_hex(&key, raw_token, stored_hex) {
            return Ok(None);
        }
        return Ok(Some(found));
    }

    let legacy_hash = legacy_refresh_token_hash(raw_token);
    RefreshToken::find_by_hash(db, &legacy_hash)
        .await
        .map_err(|e| e.to_string())
}

fn iso(dt: &mongodb::bson::DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

fn session_label(token: &RefreshToken) -> (String, String, String, bool) {
    let browser = normalize_browser_name(
        &token
            .client_browser
            .clone()
            .unwrap_or_else(|| "Nieznana przeglądarka".to_string()),
    );
    let ua = token.client_user_agent.as_deref().unwrap_or("");
    let os = resolved_os_label(
        token.client_os.as_deref().unwrap_or(""),
        ua,
    );
    let label = os.clone();
    let is_known = token.client_browser.is_some() && browser != "Nieznana przeglądarka";
    (label, browser, os, is_known)
}

pub async fn list_user_sessions(
    user_id: ObjectId,
    current_family_id: Option<&str>,
) -> Result<Vec<UserSessionInfo>, String> {
    let db = get_db();
    let tokens = RefreshToken::find_active_for_user(&db, user_id)
        .await
        .map_err(|e| e.to_string())?;

    let mut seen_families = std::collections::HashSet::new();
    let mut sessions = Vec::new();

    for token in tokens {
        if !seen_families.insert(token.family_id.clone()) {
            continue;
        }

        let (label, browser, os, is_known) = session_label(&token);
        let is_current = current_family_id == Some(token.family_id.as_str());
        let created_at = iso(&token.created_at);
        let last_used_at = token
            .last_used_at
            .as_ref()
            .and_then(iso)
            .or_else(|| created_at.clone());

        sessions.push(UserSessionInfo {
            id: token.family_id,
            label,
            browser,
            os,
            user_agent: token
                .client_user_agent
                .clone()
                .filter(|ua| !ua.trim().is_empty()),
            is_known,
            is_current,
            created_at,
            last_used_at,
        });
    }

    Ok(sessions)
}

pub async fn issue_refresh_token(
    user_id: ObjectId,
    metadata: SessionClientMetadata,
) -> Result<IssuedRefreshToken, String> {
    let db = get_db();
    let raw_token = generate_raw_token();
    let token_hash = hash_refresh_token_for_storage(&raw_token)?;
    let family_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = now + Duration::milliseconds(REFRESH_MAX_AGE_MS);
    let now_bson = RefreshToken::bson_expiry(now);

    let doc = RefreshToken {
        id: None,
        user_id,
        token_hash,
        family_id: family_id.clone(),
        expires_at: RefreshToken::bson_expiry(expires_at),
        created_at: now_bson,
        revoked: false,
        client_fingerprint: metadata.fingerprint,
        client_user_agent: if metadata.user_agent.is_empty() {
            None
        } else {
            Some(metadata.user_agent)
        },
        client_browser: Some(metadata.browser),
        client_os: Some(metadata.os),
        client_label: Some(metadata.label),
        last_used_at: Some(now_bson),
    };

    RefreshToken::insert(&db, &doc)
        .await
        .map_err(|e| e.to_string())?;

    Ok(IssuedRefreshToken {
        raw_token,
        family_id,
    })
}

pub struct RotatedSession {
    pub user: User,
    pub new_refresh_token: String,
    pub family_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshAuthError {
    Denied,
    Unavailable,
}

pub async fn rotate_refresh_token(
    raw_token: &str,
    metadata: SessionClientMetadata,
) -> Result<RotatedSession, RefreshAuthError> {
    if raw_token.is_empty() || raw_token.len() > 128 {
        return Err(RefreshAuthError::Denied);
    }

    let db = get_db();
    let stored = match find_stored_refresh_token(&db, raw_token).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(RefreshAuthError::Denied),
        Err(_) => return Err(RefreshAuthError::Unavailable),
    };

    if stored.revoked {
        let _ = RefreshToken::revoke_family(&db, &stored.family_id).await;
        let _ = User::invalidate_tokens(&db, stored.user_id).await;
        crate::ws::registry::revoke_session_remotely(&stored.user_id.to_hex(), &stored.family_id);
        return Err(RefreshAuthError::Denied);
    }

    if let Some(stored_fp) = stored.client_fingerprint.as_deref() {
        match metadata.fingerprint.as_deref() {
            Some(current) if crate::utils::auth::fingerprint::fingerprints_match(
                stored_fp, current,
            ) => {}
            _ => {
                let _ = RefreshToken::revoke_family(&db, &stored.family_id).await;
                let _ = User::invalidate_tokens(&db, stored.user_id).await;
                crate::ws::registry::revoke_session_remotely(&stored.user_id.to_hex(), &stored.family_id);
                return Err(RefreshAuthError::Denied);
            }
        }
    } else {
        if let Some(id) = stored.id {
            let _ = RefreshToken::revoke_by_id(&db, id).await;
        }
        return Err(RefreshAuthError::Denied);
    }

    let expires_at_ms = stored.expires_at.timestamp_millis();
    if expires_at_ms < Utc::now().timestamp_millis() {
        return Err(RefreshAuthError::Denied);
    }

    let user = match User::find_by_id(&db, stored.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(RefreshAuthError::Denied),
        Err(_) => return Err(RefreshAuthError::Unavailable),
    };

    if !user.is_login_allowed() {
        return Err(RefreshAuthError::Denied);
    }

    if let Some(id) = stored.id {
        RefreshToken::revoke_by_id(&db, id)
            .await
            .map_err(|_| RefreshAuthError::Unavailable)?;
    }

    let new_raw = generate_raw_token();
    let new_hash =
        hash_refresh_token_for_storage(&new_raw).map_err(|_| RefreshAuthError::Unavailable)?;
    let now = Utc::now();
    let new_expires = now + Duration::milliseconds(REFRESH_MAX_AGE_MS);
    let now_bson = RefreshToken::bson_expiry(now);

    let (user_agent, browser, os, label) = if !metadata.user_agent.trim().is_empty() {
        (
            Some(metadata.user_agent.clone()),
            Some(metadata.browser.clone()),
            Some(metadata.os.clone()),
            Some(metadata.label.clone()),
        )
    } else {
        (
            stored
                .client_user_agent
                .clone()
                .filter(|ua| !ua.trim().is_empty()),
            stored.client_browser.clone(),
            stored.client_os.clone(),
            stored.client_label.clone(),
        )
    };

    let new_doc = RefreshToken {
        id: None,
        user_id: stored.user_id,
        token_hash: new_hash,
        family_id: stored.family_id.clone(),
        expires_at: RefreshToken::bson_expiry(new_expires),
        created_at: stored.created_at,
        revoked: false,
        client_fingerprint: metadata.fingerprint.or(stored.client_fingerprint),
        client_user_agent: user_agent,
        client_browser: browser,
        client_os: os,
        client_label: label,
        last_used_at: Some(now_bson),
    };

    RefreshToken::insert(&db, &new_doc)
        .await
        .map_err(|_| RefreshAuthError::Unavailable)?;

    if is_legacy_refresh_hash(&stored.token_hash) {
        log::info!(
            "Upgraded legacy refresh token hash to HMAC for user {}",
            stored.user_id.to_hex()
        );
    }

    Ok(RotatedSession {
        user,
        new_refresh_token: new_raw,
        family_id: stored.family_id,
    })
}

pub async fn family_id_from_refresh_token(
    raw_token: &str,
) -> Result<Option<String>, RefreshAuthError> {
    if raw_token.is_empty() || raw_token.len() > 128 {
        return Ok(None);
    }
    let db = get_db();
    let stored = match find_stored_refresh_token(&db, raw_token).await {
        Ok(v) => v,
        Err(_) => return Err(RefreshAuthError::Unavailable),
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    if stored.revoked {
        return Ok(None);
    }
    Ok(Some(stored.family_id))
}

pub async fn revoke_refresh_token_family(
    raw_token: &str,
) -> Result<Option<ObjectId>, RefreshAuthError> {
    if raw_token.is_empty() || raw_token.len() > 128 {
        return Ok(None);
    }
    let db = get_db();
    let stored = match find_stored_refresh_token(&db, raw_token).await {
        Ok(v) => v,
        Err(_) => return Err(RefreshAuthError::Unavailable),
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    RefreshToken::revoke_family(&db, &stored.family_id)
        .await
        .map_err(|_| RefreshAuthError::Unavailable)?;
    Ok(Some(stored.user_id))
}

pub async fn revoke_session_for_user(
    user_id: ObjectId,
    family_id: &str,
) -> Result<bool, String> {
    let db = get_db();
    let belongs = RefreshToken::family_belongs_to_user(&db, user_id, family_id)
        .await
        .map_err(|e| e.to_string())?;
    if !belongs {
        return Err("Session not found".to_string());
    }

    RefreshToken::revoke_family(&db, family_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(true)
}

pub async fn revoke_other_sessions_for_user(
    user_id: ObjectId,
    except_family_id: &str,
) -> Result<u64, String> {
    let db = get_db();
    RefreshToken::revoke_all_except_family(&db, user_id, except_family_id)
        .await
        .map_err(|e| e.to_string())
}

pub async fn revoke_all_sessions_for_user(user_id: ObjectId) -> Result<u64, String> {
    let db = get_db();
    let families = RefreshToken::active_family_ids_for_user(&db, user_id)
        .await
        .map_err(|e| e.to_string())?;

    let revoked = RefreshToken::revoke_all_for_user(&db, user_id)
        .await
        .map_err(|e| e.to_string())?;

    // The revoke_all_for_user call itself returns Mongo's modified count, but the
    // API here is used for UX feedback and a stream of websocket disconnects.
    let _ = families;
    Ok(revoked)
}

pub async fn revoke_user_refresh_tokens(user_id: ObjectId) -> Result<(), String> {
    let db = get_db();
    RefreshToken::revoke_all_for_user(&db, user_id)
        .await
        .map_err(|e| e.to_string())
}
