// users.rs
// Snapshot obecności oraz prywatność statusu.
// Zakres:
//  - snapshot obecności filtrowany dla odbiorcy
//  - zapis ustawień prywatności oraz czasowego ukrycia
// Przy zmianach: routes/users.rs, utils/user/presence.rs.

use actix_web::{web, HttpRequest, HttpResponse};
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth::request_user_id;
use crate::model::users::{PresenceVisibility, User};
use crate::utils::db::get_db;
use crate::utils::friends::{try_are_friends, try_friend_ids};
use crate::utils::user::presence::presence_payload;

const MAX_PRESENCE_EXCEPTIONS: usize = 500;
const MAX_TEMPORARY_HIDE_MS: i64 = 26 * 60 * 60 * 1000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceSettingsBody {
    presence_visibility: PresenceVisibility,
    presence_visible_to: Vec<String>,
    presence_hidden_until: Option<String>,
}

fn presence_settings_json(user: &User) -> serde_json::Value {
    json!({
        "presenceVisibility": user.presence_visibility,
        "presenceVisibleTo": user.presence_visible_to.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
        "presenceHiddenUntil": user.presence_hidden_until.as_ref()
            .filter(|date| **date > DateTime::now())
            .and_then(|date| date.try_to_rfc3339_string().ok()),
    })
}

pub async fn get_user_status(req: HttpRequest) -> HttpResponse {
    let viewer_id = match request_user_id(&req) {
        Some(id) if !id.is_empty() => id,
        _ => {
            return HttpResponse::Unauthorized()
                .json(json!({ "error": "Authentication required" }));
        }
    };

    let user_id = req.match_info().get("userId").unwrap_or("");
    let Ok(oid) = ObjectId::parse_str(user_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "User not found" }));
    };

    let db = get_db();
    match User::find_by_id(&db, oid).await {
        Ok(Some(user)) => {
            let is_self = viewer_id == user_id;
            let is_friend = if is_self {
                true
            } else {
                match try_are_friends(&db, &viewer_id, user_id).await {
                    Ok(is_friend) => is_friend,
                    Err(()) => {
                        return HttpResponse::ServiceUnavailable().json(json!({
                            "error": "Temporarily unavailable",
                            "retryable": true,
                        }));
                    }
                }
            };
            if !is_self
                && !is_friend
                && !crate::utils::user::presence::can_view_presence(&user, &viewer_id, false)
            {
                return HttpResponse::Forbidden().json(json!({ "error": "Forbidden" }));
            }
            let mut response = presence_payload(&user, &viewer_id, is_friend);
            if let Some(obj) = response.as_object_mut() {
                obj.insert("image".to_string(), json!(user.image));
                obj.insert("color".to_string(), json!(user.color));
            }
            HttpResponse::Ok().json(response)
        }
        Ok(None) => HttpResponse::NotFound().json(json!({ "error": "User not found" })),
        Err(_) => HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    }
}

pub async fn get_presence_settings(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    match User::find_by_id(&get_db(), user_oid).await {
        Ok(Some(user)) => HttpResponse::Ok().json(presence_settings_json(&user)),
        Ok(None) => HttpResponse::Unauthorized().json(json!({ "error": "User not found" })),
        Err(error) => {
            log::error!("get_presence_settings: user lookup failed: {error}");
            HttpResponse::InternalServerError().json(json!({ "error": "Server error" }))
        }
    }
}

pub async fn update_presence_settings(
    req: HttpRequest,
    body: web::Json<PresenceSettingsBody>,
) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));
    };
    if body.presence_visible_to.len() > MAX_PRESENCE_EXCEPTIONS {
        return HttpResponse::BadRequest().json(json!({ "error": "Too many presence exceptions" }));
    }

    let db = get_db();
    let friend_ids = match try_friend_ids(&db, &user_id).await {
        Ok(ids) => ids,
        Err(()) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Contacts temporarily unavailable",
                "retryable": true,
            }));
        }
    };
    let mut visible_to = Vec::with_capacity(body.presence_visible_to.len());
    for id in &body.presence_visible_to {
        let Ok(oid) = ObjectId::parse_str(id) else {
            return HttpResponse::BadRequest().json(json!({ "error": "Invalid contact ID" }));
        };
        if id == &user_id || !friend_ids.iter().any(|friend_id| friend_id == id) {
            return HttpResponse::BadRequest().json(json!({
                "error": "Presence exceptions must be current friends",
            }));
        }
        if !visible_to.contains(&oid) {
            visible_to.push(oid);
        }
    }

    let hidden_until = match body.presence_hidden_until.as_deref() {
        Some(value) => {
            let Ok(date) = DateTime::parse_rfc3339_str(value) else {
                return HttpResponse::BadRequest()
                    .json(json!({ "error": "Invalid hide expiration" }));
            };
            let remaining = date.timestamp_millis() - DateTime::now().timestamp_millis();
            if remaining > MAX_TEMPORARY_HIDE_MS {
                return HttpResponse::BadRequest().json(json!({
                    "error": "Hide expiration must be within the next 26 hours",
                }));
            }
            (remaining > 0).then_some(date)
        }
        None => None,
    };

    let fields = doc! {
        "presenceVisibility": match body.presence_visibility {
            PresenceVisibility::Everyone => "everyone",
            PresenceVisibility::Friends => "friends",
            PresenceVisibility::Nobody => "nobody",
        },
        "presenceVisibleTo": visible_to,
        "presenceHiddenUntil": hidden_until,
    };
    match User::set_fields(&db, user_oid, fields).await {
        Ok(Some(user)) => {
            if let Some(expiry) = user.presence_hidden_until.clone() {
                let db = db.clone();
                let user_id = user_id.clone();
                tokio::spawn(async move {
                    let remaining =
                        (expiry.timestamp_millis() - DateTime::now().timestamp_millis()).max(0);
                    tokio::time::sleep(std::time::Duration::from_millis(remaining as u64)).await;
                    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
                        return;
                    };
                    match User::find_by_id(&db, user_oid).await {
                        Ok(Some(current))
                            if current.presence_hidden_until.as_ref().is_some_and(
                                |current_expiry| {
                                    current_expiry.timestamp_millis() == expiry.timestamp_millis()
                                        && current_expiry <= &DateTime::now()
                                },
                            ) =>
                        {
                            match User::collection(&db)
                                .update_one(
                                    doc! { "_id": user_oid, "presenceHiddenUntil": expiry },
                                    doc! { "$set": {
                                        "presenceHiddenUntil": mongodb::bson::Bson::Null,
                                        "updatedAt": DateTime::now(),
                                    }},
                                )
                                .await
                            {
                                Ok(result) if result.modified_count > 0 => {
                                    crate::utils::friends::emit_status_event(
                                        &db,
                                        &user_id,
                                        json!({ "userId": user_id }),
                                    )
                                    .await;
                                }
                                Ok(_) => {}
                                Err(error) => {
                                    log::error!("presence hide expiry update failed: {error}");
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            log::error!("presence hide expiry lookup failed: {error}");
                        }
                    }
                });
            }
            crate::utils::friends::emit_status_event(&db, &user_id, json!({ "userId": user_id }))
                .await;
            HttpResponse::Ok().json(presence_settings_json(&user))
        }
        Ok(None) => HttpResponse::Unauthorized().json(json!({ "error": "User not found" })),
        Err(error) => {
            log::error!("update_presence_settings: save failed: {error}");
            HttpResponse::InternalServerError().json(json!({ "error": "Server error" }))
        }
    }
}
