// voice.rs
// HTTP token LiveKit / join voice.
// Zakres:
//  - signaling CALL_* na WS
//  - token LiveKit / join; signaling CALL_* na WS
// Nie emituj tokenu bez auth i membership.
// Przy zmianach: utils/voice/*.rs, CallContext.tsx.

use actix_web::{web, HttpRequest, HttpResponse};
use jsonwebtoken::{encode, EncodingKey};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

use crate::middlewares::auth::request_user_id;
use crate::model::channels::Channel;
use crate::utils::channel::can_access_channel;
use crate::utils::db::get_db;
use crate::utils::ratelimit::Store;
use crate::utils::voice::calls::{active_session_for_user, token_allowed, CallSessionError};
use mongodb::bson::oid::ObjectId;

const TOKEN_TTL_SECS: i64 = 3 * 60;

static VOICE_TOKEN_LIMIT: Lazy<Store> = Lazy::new(|| Store::new(20, Duration::from_secs(60)));

pub fn build_dm_room_name(user_a: &str, user_b: &str) -> String {
    let mut ids = [user_a, user_b];
    ids.sort();
    format!("dm_{}_{}", ids[0], ids[1])
}

pub fn build_channel_room_name(channel_id: &str) -> String {
    format!("channel_{channel_id}")
}

#[derive(Deserialize)]
pub struct VoiceTokenBody {
    #[serde(rename = "peerId")]
    pub peer_id: Option<String>,
    #[serde(rename = "channelId")]
    pub channel_id: Option<String>,
}

#[derive(Serialize)]
struct VideoGrant {
    room: String,
    #[serde(rename = "roomJoin")]
    room_join: bool,
    #[serde(rename = "canPublish")]
    can_publish: bool,
    #[serde(rename = "canSubscribe")]
    can_subscribe: bool,
    #[serde(rename = "canPublishData")]
    can_publish_data: bool,
}

#[derive(Serialize)]
struct LiveKitClaims {
    exp: usize,
    iss: String,
    sub: String,
    nbf: usize,
    jti: String,
    video: VideoGrant,
}

fn token_denied_message(err: CallSessionError) -> &'static str {
    match err {
        CallSessionError::NotFound
        | CallSessionError::InvalidPhase
        | CallSessionError::Expired(_) => {
            "Połączenie nie jest aktywne lub wygasło. Zaakceptuj rozmowę przed dołączeniem."
        }
        CallSessionError::WrongRole | CallSessionError::InProgress => {
            "Brak uprawnień do dołączenia do tej rozmowy."
        }
    }
}

pub async fn get_voice_token(req: HttpRequest, body: web::Json<VoiceTokenBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Not authenticated." }));
    };

    let rate_key = format!("voice-token:{user_id}");
    if !VOICE_TOKEN_LIMIT.check_and_increment_with_window(&rate_key, 20, Duration::from_secs(60)) {
        return HttpResponse::TooManyRequests().json(json!({
            "message": "Zbyt wiele prób dołączenia do rozmowy. Spróbuj za chwilę."
        }));
    }

    let peer_id = body
        .peer_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let channel_id = body
        .channel_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let room = match (peer_id, channel_id) {
        (Some(peer_id), None) => {
            if peer_id == user_id {
                return HttpResponse::BadRequest()
                    .json(json!({ "message": "Cannot call yourself." }));
            }

            let session = match token_allowed(&user_id, peer_id) {
                Ok(session) => session,
                Err(err) => {
                    return HttpResponse::Forbidden().json(json!({
                        "message": token_denied_message(err),
                        "code": "CALL_NOT_ACCEPTED"
                    }));
                }
            };

            let db = get_db();
            match crate::utils::friends::try_are_friends(&db, &user_id, peer_id).await {
                Ok(true) => {}
                Ok(false) => {
                    return HttpResponse::Forbidden()
                        .json(json!({ "message": "Możesz dzwonić tylko do znajomych." }));
                }
                Err(()) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "message": "Temporarily unavailable",
                        "retryable": true,
                    }));
                }
            }

            let _ = session;
            build_dm_room_name(&user_id, peer_id)
        }
        (None, Some(channel_id)) => {
            let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {
                return HttpResponse::BadRequest()
                    .json(json!({ "message": "Invalid channel ID." }));
            };
            let db = get_db();
            let channel = match Channel::find_by_id(&db, channel_oid).await {
                Ok(Some(channel)) => channel,
                Ok(None) => {
                    return HttpResponse::NotFound()
                        .json(json!({ "message": "Channel not found." }));
                }
                Err(_) => {
                    return HttpResponse::InternalServerError()
                        .json(json!({ "message": "Failed to load channel." }));
                }
            };
            if !can_access_channel(&channel, Some(&user_id)) {
                return HttpResponse::Forbidden()
                    .json(json!({ "message": "Nie masz dostępu do tego kanału." }));
            }
            build_channel_room_name(channel_id)
        }
        (Some(_), Some(_)) => {
            return HttpResponse::BadRequest()
                .json(json!({ "message": "Podaj wyłącznie peerId albo channelId." }));
        }
        (None, None) => {
            return HttpResponse::BadRequest()
                .json(json!({ "message": "peerId or channelId is required." }));
        }
    };

    let (Ok(api_key), Ok(api_secret), Ok(url)) = (
        std::env::var("LIVEKIT_API_KEY"),
        std::env::var("LIVEKIT_API_SECRET"),
        std::env::var("LIVEKIT_URL"),
    ) else {
        log::error!("LiveKit env vars are missing (LIVEKIT_API_KEY/SECRET/URL).");
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Voice service is not configured." }));
    };

    if !crate::utils::security::urls::is_allowed_livekit_url(&url) {
        log::error!("LIVEKIT_URL is not allowed: blocked host or scheme");
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Voice service is not configured." }));
    }

    let now = chrono::Utc::now().timestamp();
    let jti = format!("voice:{user_id}:{}", Uuid::new_v4());
    let claims = LiveKitClaims {
        exp: (now + TOKEN_TTL_SECS) as usize,
        iss: api_key,
        sub: user_id.clone(),
        nbf: now as usize,
        jti,
        video: VideoGrant {
            room: room.clone(),
            room_join: true,
            can_publish: true,
            can_subscribe: true,
            can_publish_data: true,
        },
    };

    let token = match encode(
        &crate::utils::auth::validation::hs256_header(),
        &claims,
        &EncodingKey::from_secret(api_secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Error in getVoiceToken: {}", e);
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Failed to create voice token." }));
        }
    };

    HttpResponse::Ok().json(json!({ "token": token, "url": url, "room": room }))
}

pub async fn get_active_call(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Not authenticated." }));
    };

    let Some(session) = active_session_for_user(&user_id) else {
        return HttpResponse::Ok().json(json!({ "active": false }));
    };

    let peer_id = if session.caller_id == user_id {
        session.callee_id.clone()
    } else {
        session.caller_id.clone()
    };

    HttpResponse::Ok().json(json!({
        "active": true,
        "peerId": peer_id,
        "mode": session.mode,
    }))
}
