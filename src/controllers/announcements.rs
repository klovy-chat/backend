// announcements.rs
// Lista aktywnych ogłoszeń dla zalogowanego klienta.
// Zakres:
//  - filter dat
//  - aktywne ogłoszenia w oknie dat; treść z modelu
// Treść z modelu, nie z env.
// Przy zmianach: model/announcements.rs, Announcements.tsx.

use actix_web::{web, HttpRequest, HttpResponse};
use mongodb::bson::oid::ObjectId;
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth::request_user_id;
use crate::model::announcements::{Announcement, AnnouncementDismissal};
use crate::utils::db::get_db;

fn serialize_announcement(a: &Announcement) -> serde_json::Value {
    a.to_api_json()
}

pub async fn get_my_announcements(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "User not authenticated." }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id." }));
    };

    let db = get_db();
    let active = match Announcement::list_active(&db).await {
        Ok(items) => items,
        Err(e) => {
            log::error!("get_my_announcements list: {e}");
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się pobrać ogłoszeń." }));
        }
    };

    let dismissed = AnnouncementDismissal::dismissed_ids_for_user(&db, uid)
        .await
        .unwrap_or_default();
    let unread: Vec<_> = active
        .into_iter()
        .filter(|a| a.id.map(|id| !dismissed.contains(&id)).unwrap_or(false))
        .map(|a| serialize_announcement(&a))
        .collect();

    HttpResponse::Ok().json(json!({
        "announcements": unread,
        "total": unread.len(),
    }))
}

#[derive(Deserialize)]
pub struct DismissAnnouncementsBody {
    #[serde(rename = "announcementIds")]
    pub announcement_ids: Option<Vec<String>>,
}

pub async fn dismiss_announcements(
    req: HttpRequest,
    body: web::Json<DismissAnnouncementsBody>,
) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "User not authenticated." }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id." }));
    };

    let ids: Vec<ObjectId> = body
        .announcement_ids
        .as_ref()
        .map(|list| {
            list.iter()
                .filter_map(|s| ObjectId::parse_str(s.trim()).ok())
                .collect()
        })
        .unwrap_or_default();

    if ids.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "error": "Brak ogłoszeń do zamknięcia." }));
    }

    let db = get_db();
    match AnnouncementDismissal::dismiss_all(&db, uid, &ids).await {
        Ok(count) => HttpResponse::Ok().json(json!({
            "message": "Ogłoszenia zostały zamknięte.",
            "dismissed": count,
        })),
        Err(e) => {
            log::error!("dismiss_announcements: {e}");
            HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się zamknąć ogłoszeń." }))
        }
    }
}
