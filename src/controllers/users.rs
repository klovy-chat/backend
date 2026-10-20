// users.rs
// Publiczny profil, search userów, snapshot obecności.
// Zakres:
//  - projekcja bez sekretów
//  - publiczny profil, search, snapshot online/offline
// Live status i tak idzie WS — tu snapshot.
// Przy zmianach: utils/user/json.rs, PresenceContext.

use actix_web::{HttpRequest, HttpResponse};
use mongodb::bson::oid::ObjectId;
use serde_json::json;

use crate::middlewares::auth::request_user_id;
use crate::model::users::User;
use crate::utils::db::get_db;
use crate::utils::friends::try_are_friends;

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
    if viewer_id != user_id {
        match try_are_friends(&db, &viewer_id, user_id).await {
            Ok(true) => {}
            Ok(false) => {
                return HttpResponse::Forbidden().json(json!({ "error": "Forbidden" }));
            }
            Err(()) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        }
    }

    match User::find_by_id(&db, oid).await {
        Ok(Some(user)) => HttpResponse::Ok().json(json!({
            "isOnline": user.is_online,
            "lastSeen": user.last_seen.as_ref().and_then(|d| d.try_to_rfc3339_string().ok()),
            "image": user.image,
            "color": user.color,
        })),
        Ok(None) => HttpResponse::NotFound().json(json!({ "error": "User not found" })),
        Err(_) => HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    }
}
