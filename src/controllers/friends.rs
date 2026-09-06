// friends.rs
// Zaproszenia, accept (ew. mutual), block, usunięcie znajomości.
// Zakres:
//  - zawsze fan-out friendship-removed gdy rekord już zniknął
//  - invite/accept/block; fan-out nawet gdy rekord już zniknął
// Blokada = natychmiast inwalidacja typing/DM cache.
// Przy zmianach: friend_requests.rs, utils/friends/*, ws/typing.rs.

use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth::request_user_id;
use crate::model::friend_requests::{FriendRequest, FriendRequestStatus};
use crate::model::users::User;
use crate::utils::db::get_db;
use crate::utils::friends::{
    invalidate_friend_ids_pair, map_friend_user, try_are_friends,
};
use crate::ws::typing;
use crate::utils::validators::username::normalize_username;

const FRIEND_REQUEST_UNAVAILABLE: &str = "Nie można wysłać zaproszenia do tego użytkownika.";

fn recipient_available(user: &User) -> bool {
    user.is_login_allowed()
}

fn status_str(status: &FriendRequestStatus) -> &'static str {
    match status {
        FriendRequestStatus::Pending => "pending",
        FriendRequestStatus::Accepted => "accepted",
        FriendRequestStatus::Rejected => "rejected",
    }
}

fn iso(dt: &DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

async fn fetch_users_map(
    db: &mongodb::Database,
    ids: &[ObjectId],
) -> Option<std::collections::HashMap<ObjectId, User>> {
    let mut map = std::collections::HashMap::new();
    if ids.is_empty() {
        return Some(map);
    }
    let cursor = match User::collection(db)
        .find(doc! { "_id": { "$in": ids } })
        .await
    {
        Ok(c) => c,
        Err(_) => return None,
    };
    let users: Vec<User> = match cursor.try_collect().await {
        Ok(u) => u,
        Err(_) => return None,
    };
    for u in users {
        if let Some(id) = u.id {
            map.insert(id, u);
        }
    }
    Some(map)
}

#[derive(Deserialize)]
pub struct SendFriendRequestBody {
    pub username: Option<String>,
}

pub async fn send_friend_request(
    req: HttpRequest,
    body: web::Json<SendFriendRequestBody>,
) -> HttpResponse {
    let Some(sender_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(sender_oid) = ObjectId::parse_str(&sender_id) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let raw = body.username.clone().unwrap_or_default();
    if raw.trim().is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Podaj nazwę użytkownika (@username)." }));
    }
    let username = normalize_username(&raw);
    if username.is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nieprawidłowa nazwa użytkownika." }));
    }

    let db = get_db();
    let recipient = match User::find_by_username(&db, &username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::BadRequest().json(json!({
                "error": FRIEND_REQUEST_UNAVAILABLE
            }))
        }
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    let recipient_oid = match recipient.id {
        Some(o) => o,
        None => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };
    let recipient_id = recipient_oid.to_hex();

    if !recipient_available(&recipient) {
        return HttpResponse::BadRequest().json(json!({ "error": FRIEND_REQUEST_UNAVAILABLE }));
    }

    if recipient_id == sender_id {
        return HttpResponse::BadRequest().json(json!({ "error": FRIEND_REQUEST_UNAVAILABLE }));
    }

    match try_are_friends(&db, &sender_id, &recipient_id).await {
        Ok(true) => {
            return HttpResponse::BadRequest().json(json!({ "error": FRIEND_REQUEST_UNAVAILABLE }));
        }
        Ok(false) => {}
        Err(()) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    }

    let col = FriendRequest::collection(&db);
    let existing = match col
        .find_one(doc! {
            "$or": [
                { "from": sender_oid, "to": recipient_oid },
                { "from": recipient_oid, "to": sender_oid },
            ]
        })
        .await
    {
        Ok(v) => v,
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if let Some(existing) = existing {
        let existing_id = existing.id.unwrap_or_default();
        match existing.status {
            FriendRequestStatus::Accepted => {
                return HttpResponse::BadRequest()
                    .json(json!({ "error": FRIEND_REQUEST_UNAVAILABLE }));
            }
            FriendRequestStatus::Pending => {
                if existing.from == recipient_oid {
                    match col
                        .update_one(
                            doc! { "_id": existing_id, "status": "pending" },
                            doc! { "$set": { "status": "accepted", "updatedAt": DateTime::now() } },
                        )
                        .await
                    {
                        Ok(r) if r.modified_count > 0 => {}
                        Ok(_) => {
                            return HttpResponse::BadRequest().json(json!({
                                "error": FRIEND_REQUEST_UNAVAILABLE
                            }));
                        }
                        Err(_) => {
                            return HttpResponse::InternalServerError().json(json!({
                                "error": "Internal Server Error",
                                "retryable": true,
                            }));
                        }
                    }
                    invalidate_friend_ids_pair(&sender_id, &recipient_oid.to_hex());
                    typing::invalidate_pair(&sender_id, &recipient_oid.to_hex());
                    return HttpResponse::Ok().json(json!({
                        "message": "Wzajemne zaproszenie — jesteście teraz znajomymi.",
                        "autoAccepted": true,
                        "friend": map_friend_user(&recipient),
                    }));
                }
                return HttpResponse::BadRequest().json(json!({
                    "error": FRIEND_REQUEST_UNAVAILABLE
                }));
            }
            FriendRequestStatus::Rejected => {
                let now = DateTime::now();
                match col
                    .update_one(
                        doc! { "_id": existing_id },
                        doc! { "$set": {
                            "from": sender_oid,
                            "to": recipient_oid,
                            "status": "pending",
                            "updatedAt": now,
                        }},
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(_) => {
                        return HttpResponse::ServiceUnavailable().json(json!({
                            "error": "Temporarily unavailable",
                            "retryable": true,
                        }));
                    }
                }
                return HttpResponse::Ok().json(json!({
                    "message": "Zaproszenie wysłane.",
                    "request": {
                        "_id": existing_id.to_hex(),
                        "to": map_friend_user(&recipient),
                        "status": "pending",
                        "createdAt": iso(&existing.created_at),
                    }
                }));
            }
        }
    }

    match FriendRequest::create(&db, sender_oid, recipient_oid).await {
        Ok(request) => HttpResponse::Created().json(json!({
            "message": "Zaproszenie wysłane.",
            "request": {
                "_id": request.id.map(|o| o.to_hex()),
                "to": map_friend_user(&recipient),
                "status": "pending",
                "createdAt": iso(&request.created_at),
            }
        })),
        Err(_) => HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    }
}

pub async fn get_received_requests(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let db = get_db();
    let requests: Vec<FriendRequest> = match FriendRequest::collection(&db)
        .find(doc! { "to": uid, "status": "pending" })
        .sort(doc! { "createdAt": -1 })
        .await
    {
        Ok(c) => match c.try_collect().await {
            Ok(r) => r,
            Err(_) => {
                return HttpResponse::ServiceUnavailable()
                    .json(json!({ "error": "Friends temporarily unavailable. Please retry." }));
            }
        },
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    let sender_ids: Vec<ObjectId> = requests.iter().map(|r| r.from).collect();
    let Some(user_map) = fetch_users_map(&db, &sender_ids).await else {
        return HttpResponse::ServiceUnavailable()
            .json(json!({ "error": "Friends temporarily unavailable. Please retry." }));
    };

    let out: Vec<_> = requests
        .iter()
        .filter_map(|r| {
            user_map.get(&r.from).map(|from_user| {
                json!({
                    "_id": r.id.map(|o| o.to_hex()),
                    "from": map_friend_user(from_user),
                    "status": status_str(&r.status),
                    "createdAt": iso(&r.created_at),
                })
            })
        })
        .collect();

    HttpResponse::Ok().json(json!({ "requests": out }))
}

pub async fn get_sent_requests(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let db = get_db();
    let requests: Vec<FriendRequest> = match FriendRequest::collection(&db)
        .find(doc! { "from": uid, "status": "pending" })
        .sort(doc! { "createdAt": -1 })
        .await
    {
        Ok(c) => match c.try_collect().await {
            Ok(r) => r,
            Err(_) => {
                return HttpResponse::ServiceUnavailable()
                    .json(json!({ "error": "Friends temporarily unavailable. Please retry." }));
            }
        },
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    let recipient_ids: Vec<ObjectId> = requests.iter().map(|r| r.to).collect();
    let Some(user_map) = fetch_users_map(&db, &recipient_ids).await else {
        return HttpResponse::ServiceUnavailable()
            .json(json!({ "error": "Friends temporarily unavailable. Please retry." }));
    };

    let out: Vec<_> = requests
        .iter()
        .filter_map(|r| {
            user_map.get(&r.to).map(|to_user| {
                json!({
                    "_id": r.id.map(|o| o.to_hex()),
                    "to": map_friend_user(to_user),
                    "status": status_str(&r.status),
                    "createdAt": iso(&r.created_at),
                })
            })
        })
        .collect();

    HttpResponse::Ok().json(json!({ "requests": out }))
}

pub async fn accept_friend_request(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let request_id = req.match_info().get("requestId").unwrap_or("");
    let Ok(rid) = ObjectId::parse_str(request_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Nieprawidłowe zaproszenie." }));
    };

    let db = get_db();
    let col = FriendRequest::collection(&db);
    let request = match col.find_one(doc! { "_id": rid }).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Zaproszenie nie istnieje." })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    if request.to.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({ "error": "Brak uprawnień do tego zaproszenia." }));
    }
    if request.status != FriendRequestStatus::Pending {
        return HttpResponse::BadRequest().json(json!({ "error": "To zaproszenie nie jest już aktywne." }));
    }

    match col
        .update_one(
            doc! { "_id": rid, "status": "pending" },
            doc! { "$set": { "status": "accepted", "updatedAt": DateTime::now() } },
        )
        .await
    {
        Ok(r) if r.modified_count > 0 => {}
        Ok(_) => {
            return HttpResponse::BadRequest()
                .json(json!({ "error": "To zaproszenie nie jest już aktywne." }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Internal Server Error",
                "retryable": true,
            }));
        }
    }

    invalidate_friend_ids_pair(&user_id, &request.from.to_hex());
    typing::invalidate_pair(&user_id, &request.from.to_hex());

    let Ok(accepter_oid) = ObjectId::parse_str(&user_id) else {

        let from_hex = request.from.to_hex();
        crate::ws::registry::emit_to_user(
            &user_id,
            "friendship-added",
            json!({ "contact": { "_id": from_hex } }),
        );
        crate::ws::registry::emit_to_user(
            &from_hex,
            "friendship-added",
            json!({ "contact": { "_id": user_id } }),
        );
        return HttpResponse::Ok().json(json!({
            "message": "Zaproszenie zaakceptowane.",
            "friend": { "_id": from_hex },
        }));
    };
    let (from_user, accepter) = tokio::join!(
        User::find_by_id(&db, request.from),
        User::find_by_id(&db, accepter_oid),
    );
    let from_hex = request.from.to_hex();
    let (friend_for_accepter, friend_for_requester) = match (from_user, accepter) {
        (Ok(Some(from_user)), Ok(Some(accepter))) => {
            (
                map_friend_user(&from_user),
                map_friend_user(&accepter),
            )
        }
        _ => (
            json!({ "_id": from_hex }),
            json!({ "_id": user_id }),
        ),
    };
    crate::ws::registry::emit_to_user(
        &user_id,
        "friendship-added",
        json!({ "contact": friend_for_accepter }),
    );
    crate::ws::registry::emit_to_user(
        &from_hex,
        "friendship-added",
        json!({ "contact": friend_for_requester }),
    );

    HttpResponse::Ok().json(json!({
        "message": "Zaproszenie zaakceptowane.",
        "friend": friend_for_accepter,
    }))
}

pub async fn reject_friend_request(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let request_id = req.match_info().get("requestId").unwrap_or("");
    let Ok(rid) = ObjectId::parse_str(request_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Nieprawidłowe zaproszenie." }));
    };

    let db = get_db();
    let col = FriendRequest::collection(&db);
    let request = match col.find_one(doc! { "_id": rid }).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Zaproszenie nie istnieje." })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    if request.to.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({ "error": "Brak uprawnień do tego zaproszenia." }));
    }
    if request.status != FriendRequestStatus::Pending {
        return HttpResponse::BadRequest().json(json!({ "error": "To zaproszenie nie jest już aktywne." }));
    }

    match col
        .update_one(
            doc! { "_id": rid, "status": "pending" },
            doc! { "$set": { "status": "rejected", "updatedAt": DateTime::now() } },
        )
        .await
    {
        Ok(r) if r.modified_count > 0 => {}
        Ok(_) => {
            return HttpResponse::BadRequest()
                .json(json!({ "error": "To zaproszenie nie jest już aktywne." }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Internal Server Error",
                "retryable": true,
            }));
        }
    }

    HttpResponse::Ok().json(json!({ "message": "Zaproszenie odrzucone." }))
}

pub async fn cancel_friend_request(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let request_id = req.match_info().get("requestId").unwrap_or("");
    let Ok(rid) = ObjectId::parse_str(request_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Nieprawidłowe zaproszenie." }));
    };

    let db = get_db();
    let col = FriendRequest::collection(&db);
    let request = match col.find_one(doc! { "_id": rid }).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Zaproszenie nie istnieje." })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    if request.from.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({ "error": "Brak uprawnień do tego zaproszenia." }));
    }
    if request.status != FriendRequestStatus::Pending {
        return HttpResponse::BadRequest().json(json!({ "error": "To zaproszenie nie jest już aktywne." }));
    }

    match col
        .update_one(
            doc! { "_id": rid, "status": "pending" },
            doc! { "$set": { "status": "rejected", "updatedAt": DateTime::now() } },
        )
        .await
    {
        Ok(r) if r.modified_count > 0 => {}
        Ok(_) => {
            return HttpResponse::BadRequest()
                .json(json!({ "error": "To zaproszenie nie jest już aktywne." }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Internal Server Error",
                "retryable": true,
            }));
        }
    }

    HttpResponse::Ok().json(json!({ "message": "Zaproszenie anulowane." }))
}

pub async fn get_friends(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let db = get_db();
    let friendships: Vec<FriendRequest> = match FriendRequest::collection(&db)
        .find(doc! { "status": "accepted", "$or": [ { "from": uid }, { "to": uid } ] })
        .sort(doc! { "updatedAt": -1 })
        .await
    {
        Ok(c) => match c.try_collect().await {
            Ok(f) => f,
            Err(_) => {
                return HttpResponse::ServiceUnavailable()
                    .json(json!({ "error": "Friends temporarily unavailable. Please retry." }));
            }
        },
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    };

    let ordered_ids: Vec<ObjectId> = friendships
        .iter()
        .map(|f| if f.from == uid { f.to } else { f.from })
        .collect();

    let Some(user_map) = fetch_users_map(&db, &ordered_ids).await else {
        return HttpResponse::ServiceUnavailable()
            .json(json!({ "error": "Friends temporarily unavailable. Please retry." }));
    };

    let mut friends = Vec::with_capacity(ordered_ids.len());
    for id in &ordered_ids {
        let Some(user) = user_map.get(id) else {
            continue;
        };
        friends.push(map_friend_user(user));
    }

    HttpResponse::Ok().json(json!({ "friends": friends }))
}

pub async fn check_friendship(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let other_user_id = req.match_info().get("otherUserId").unwrap_or("");
    let Ok(other) = ObjectId::parse_str(other_user_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nieprawidłowy identyfikator użytkownika." }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nieprawidłowy identyfikator użytkownika." }));
    };

    let db = get_db();

    match User::find_by_id(&db, other).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::Ok().json(json!({ "isFriend": false, "pendingRequest": null }));
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    let is_friend = match try_are_friends(&db, &user_id, other_user_id).await {
        Ok(v) => v,
        Err(()) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    let mut is_blocked_by_me = false;
    let mut is_blocked_by_other = false;
    if is_friend {
        match crate::utils::friends::try_dm_block_flags(&db, &user_id, other_user_id).await {
            Ok((a, b)) => {
                is_blocked_by_me = a;
                is_blocked_by_other = b;
            }
            Err(()) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        }
    }

    let mut pending_request = serde_json::Value::Null;

    if !is_friend {
        let col = FriendRequest::collection(&db);
        match col
            .find_one(doc! { "from": other, "to": uid, "status": "pending" })
            .await
        {
            Ok(Some(incoming)) => {
                pending_request = json!({
                    "direction": "incoming",
                    "requestId": incoming.id.map(|o| o.to_hex()),
                });
            }
            Ok(None) => match col
                .find_one(doc! { "from": uid, "to": other, "status": "pending" })
                .await
            {
                Ok(Some(outgoing)) => {
                    pending_request = json!({
                        "direction": "outgoing",
                        "requestId": outgoing.id.map(|o| o.to_hex()),
                    });
                }
                Ok(None) => {}
                Err(_) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "error": "Temporarily unavailable",
                        "retryable": true,
                    }));
                }
            },
            Err(_) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        }
    }

    HttpResponse::Ok().json(json!({
        "isFriend": is_friend,
        "isBlockedByMe": is_blocked_by_me,
        "isBlockedByOther": is_blocked_by_other,
        "isDmBlocked": is_blocked_by_me || is_blocked_by_other,
        "pendingRequest": pending_request
    }))
}

pub async fn remove_friend(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let friend_user_id = req.match_info().get("friendUserId").unwrap_or("");
    let Ok(friend_oid) = ObjectId::parse_str(friend_user_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nieprawidłowy identyfikator użytkownika." }));
    };
    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nieprawidłowy identyfikator użytkownika." }));
    };

    if friend_user_id == user_id {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nie możesz usunąć siebie z kontaktów." }));
    }

    let db = get_db();
    let col = FriendRequest::collection(&db);
    let friendship = match col
        .find_one(doc! {
            "status": "accepted",
            "$or": [
                { "from": user_oid, "to": friend_oid },
                { "from": friend_oid, "to": user_oid },
            ]
        })
        .await
    {
        Ok(v) => v,
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    let Some(friendship) = friendship else {
        return HttpResponse::NotFound()
            .json(json!({ "error": "Ten użytkownik nie jest w Twoich kontaktach." }));
    };

    match col.delete_one(doc! { "_id": friendship.id.unwrap_or_default() }).await {
        Ok(r) if r.deleted_count > 0 => {}
        Ok(_) => {
            return HttpResponse::NotFound()
                .json(json!({ "error": "Ten użytkownik nie jest w Twoich kontaktach." }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Failed to remove friend",
                "retryable": true,
            }));
        }
    }

    invalidate_friend_ids_pair(&user_id, friend_user_id);
    typing::invalidate_pair(&user_id, friend_user_id);

    if let Some(session) =
        crate::utils::voice::calls::take_session_for_pair(&user_id, friend_user_id)
    {
        let end_payload = json!({ "from": user_id, "reason": "UNFRIENDED" });
        match session.phase {
            crate::utils::voice::calls::CallPhase::Ringing => {
                crate::ws::registry::emit_to_user(
                    &session.callee_id,
                    "call:cancelled",
                    end_payload.clone(),
                );
                crate::ws::registry::emit_to_user(
                    &session.caller_id,
                    "call:cancelled",
                    end_payload,
                );
            }
            crate::utils::voice::calls::CallPhase::Accepted => {
                crate::ws::registry::emit_to_user(
                    &session.callee_id,
                    "call:ended",
                    end_payload.clone(),
                );
                crate::ws::registry::emit_to_user(
                    &session.caller_id,
                    "call:ended",
                    end_payload,
                );
            }
        }
    }

    use crate::model::messages::Message;
    use crate::utils::messages::access::cleanup_attachment_if_unreferenced;

    let wipe_at = DateTime::now();

    crate::ws::registry::emit_to_user(
        &user_id,
        "friendship-removed",
        json!({ "userId": friend_user_id }),
    );
    crate::ws::registry::emit_to_user(
        friend_user_id,
        "friendship-removed",
        json!({ "userId": user_id }),
    );

    let dm_filter = doc! {
        "$or": [
            { "sender": user_oid, "recipient": friend_oid },
            { "sender": friend_oid, "recipient": user_oid },
        ],
        "deleted": { "$ne": true },
    };
    let wipe_ok = match crate::utils::messages::search::wipe_live_messages(&db, dm_filter).await {
        Ok(urls) => {
            let cleanups: Vec<_> = urls
                .iter()
                .map(|url| cleanup_attachment_if_unreferenced(&db, Some(url)))
                .collect();
            futures_util::future::join_all(cleanups).await;
            crate::utils::tips::clear_dm_tip_at_most(
                &db, user_oid, friend_oid, wipe_at,
            )
            .await;
            true
        }
        Err(e) => {
            log::error!(
                "remove_friend: failed to wipe DM messages for {} / {}: {e}",
                user_id,
                friend_user_id
            );
            false
        }
    };

    if wipe_ok {
        match Message::collection(&db)
            .count_documents(doc! {
                "$or": [
                    { "sender": user_oid, "recipient": friend_oid },
                    { "sender": friend_oid, "recipient": user_oid },
                ],
                "deleted": { "$ne": true },
            })
            .await
        {
            Ok(remaining) if remaining > 0 => {
                if let Ok(mut cursor) = Message::collection(&db)
                    .find(doc! {
                        "$or": [
                            { "sender": user_oid, "recipient": friend_oid },
                            { "sender": friend_oid, "recipient": user_oid },
                        ],
                        "deleted": { "$ne": true },
                    })
                    .sort(doc! { "timestamp": -1, "_id": -1 })
                    .limit(1)
                    .await
                {
                    if let Ok(Some(msg)) = cursor.try_next().await {
                        crate::utils::tips::upsert_dm_tip(&db, &msg).await;
                    }
                }

                let synced_viewer = crate::utils::tips::try_sync_dm_tip_unread(
                    &db, user_oid, friend_oid,
                )
                .await;
                let synced_peer = crate::utils::tips::try_sync_dm_tip_unread(
                    &db, friend_oid, user_oid,
                )
                .await;
                match (synced_viewer, synced_peer) {
                    (Some(nv), Some(np)) => {
                        crate::utils::unread::emit_unread_absolute(
                            &user_id, "dm", friend_user_id, nv,
                        );
                        crate::utils::unread::emit_unread_absolute(
                            friend_user_id, "dm", &user_id, np,
                        );
                    }
                    _ => {
                        crate::utils::unread::invalidate_unread_generation(
                            &user_id, "dm", friend_user_id,
                        );
                        crate::utils::unread::invalidate_unread_generation(
                            friend_user_id, "dm", &user_id,
                        );
                    }
                }
            }
            Ok(_) => {

                match Message::collection(&db)
                    .count_documents(doc! {
                        "$or": [
                            { "sender": user_oid, "recipient": friend_oid },
                            { "sender": friend_oid, "recipient": user_oid },
                        ],
                        "deleted": { "$ne": true },
                    })
                    .await
                {
                    Ok(0) => {

                        let still_empty = Message::collection(&db)
                            .count_documents(doc! {
                                "$or": [
                                    { "sender": user_oid, "recipient": friend_oid },
                                    { "sender": friend_oid, "recipient": user_oid },
                                ],
                                "deleted": { "$ne": true },
                            })
                            .await
                            .ok()
                            == Some(0);
                        if still_empty {
                            let synced_viewer =
                                crate::utils::tips::try_sync_dm_tip_unread(
                                    &db, user_oid, friend_oid,
                                )
                                .await;
                            let synced_peer =
                                crate::utils::tips::try_sync_dm_tip_unread(
                                    &db, friend_oid, user_oid,
                                )
                                .await;
                            match (synced_viewer, synced_peer) {
                                (Some(nv), Some(np)) => {
                                    crate::utils::unread::emit_unread_absolute(
                                        &user_id, "dm", friend_user_id, nv,
                                    );
                                    crate::utils::unread::emit_unread_absolute(
                                        friend_user_id, "dm", &user_id, np,
                                    );
                                }
                                _ => {
                                    crate::utils::unread::invalidate_unread_generation(
                                        &user_id, "dm", friend_user_id,
                                    );
                                    crate::utils::unread::invalidate_unread_generation(
                                        friend_user_id, "dm", &user_id,
                                    );
                                }
                            }
                            crate::ws::registry::emit_to_user(
                                &user_id,
                                "conversation-deleted",
                                json!({ "contactId": friend_user_id }),
                            );
                            crate::ws::registry::emit_to_user(
                                friend_user_id,
                                "conversation-deleted",
                                json!({ "contactId": user_id }),
                            );
                        } else {
                            let synced_viewer =
                                crate::utils::tips::try_sync_dm_tip_unread(
                                    &db, user_oid, friend_oid,
                                )
                                .await;
                            let synced_peer =
                                crate::utils::tips::try_sync_dm_tip_unread(
                                    &db, friend_oid, user_oid,
                                )
                                .await;
                            match (synced_viewer, synced_peer) {
                                (Some(nv), Some(np)) => {
                                    crate::utils::unread::emit_unread_absolute(
                                        &user_id, "dm", friend_user_id, nv,
                                    );
                                    crate::utils::unread::emit_unread_absolute(
                                        friend_user_id, "dm", &user_id, np,
                                    );
                                }
                                _ => {
                                    crate::utils::unread::invalidate_unread_generation(
                                        &user_id, "dm", friend_user_id,
                                    );
                                    crate::utils::unread::invalidate_unread_generation(
                                        friend_user_id, "dm", &user_id,
                                    );
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        let synced_viewer =
                            crate::utils::tips::try_sync_dm_tip_unread(
                                &db, user_oid, friend_oid,
                            )
                            .await;
                        let synced_peer =
                            crate::utils::tips::try_sync_dm_tip_unread(
                                &db, friend_oid, user_oid,
                            )
                            .await;
                        match (synced_viewer, synced_peer) {
                            (Some(nv), Some(np)) => {
                                crate::utils::unread::emit_unread_absolute(
                                    &user_id, "dm", friend_user_id, nv,
                                );
                                crate::utils::unread::emit_unread_absolute(
                                    friend_user_id, "dm", &user_id, np,
                                );
                            }
                            _ => {
                                crate::utils::unread::invalidate_unread_generation(
                                    &user_id, "dm", friend_user_id,
                                );
                                crate::utils::unread::invalidate_unread_generation(
                                    friend_user_id, "dm", &user_id,
                                );
                            }
                        }
                    }
                    Err(_) => {
                        crate::utils::unread::invalidate_unread_generation(
                            &user_id, "dm", friend_user_id,
                        );
                        crate::utils::unread::invalidate_unread_generation(
                            friend_user_id, "dm", &user_id,
                        );
                    }
                }
            }
            Err(_) => {

                crate::utils::unread::invalidate_unread_generation(
                    &user_id, "dm", friend_user_id,
                );
                crate::utils::unread::invalidate_unread_generation(
                    friend_user_id, "dm", &user_id,
                );
            }
        }
    }

    HttpResponse::Ok().json(json!({ "message": "Kontakt został usunięty." }))
}
