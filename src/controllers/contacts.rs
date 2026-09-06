// contacts.rs
// Lista DM, mute, wipe historii, tip/unread fill.
// Zakres:
//  - nie zwracaj częściowego tip przy Err streamu
//  - lista DM, mute, wipe; fill tip/unread przed zaufaniem 0
// Wipe bez absolute: FE musi fence'ować stale WS (wipedKeys).
// Przy zmianach: utils/tips.rs, unread/mod.rs, contacts.ts.

use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;

use crate::middlewares::auth::request_user_id;
use crate::model::friend_requests::FriendRequest;
use crate::model::messages::Message;
use crate::model::users::User;
use crate::utils::db::get_db;
use crate::utils::friends::{try_are_friends, invalidate_friend_ids_pair};
use crate::ws::typing;
use crate::utils::messages::{
    access::cleanup_attachment_if_unreferenced,
    dm_only_or_clause,
};
use crate::utils::messages::escape_regex;
use crate::utils::user::json::resolve_display_name;

const MIN_SEARCH_LENGTH: usize = 3;
const MAX_SEARCH_LENGTH: usize = 64;
const SEARCH_RESULT_LIMIT: i64 = 10;

async fn require_friends_or_503(
    db: &mongodb::Database,
    user_id: &str,
    contact_id: &str,
    not_friends: HttpResponse,
) -> Result<(), HttpResponse> {
    match try_are_friends(db, user_id, contact_id).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(not_friends),
        Err(()) => Err(HttpResponse::ServiceUnavailable().json(json!({
            "message": "Temporarily unavailable",
            "retryable": true,
        }))),
    }
}

fn normalize_text(s: &str) -> String {
    let mapped: String = s
        .chars()
        .map(|c| match c {
            'ą' | 'Ą' => 'a',
            'ć' | 'Ć' => 'c',
            'ę' | 'Ę' => 'e',
            'ł' | 'Ł' => 'l',
            'ń' | 'Ń' => 'n',
            'ó' | 'Ó' => 'o',
            'ś' | 'Ś' => 's',
            'ź' | 'Ź' | 'ż' | 'Ż' => 'z',
            other => other,
        })
        .collect();
    mapped.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ")
}

async fn search_users_by_term(
    db: &mongodb::Database,
    exclude: ObjectId,
    term: &str,
) -> Option<Vec<User>> {
    let escaped = escape_regex(term);

    let filter = doc! {
        "_id": { "$ne": exclude },
        "isActive": { "$ne": false },
        "isBlocked": { "$ne": true },
        "isBanned": { "$ne": true },
        "isDisabled": { "$ne": true },
        "deletionScheduledAt": { "$exists": false },
        "$or": [
            { "username": { "$regex": format!("^{escaped}") } },
            { "displayName": { "$regex": format!("^{escaped}"), "$options": "i" } },
        ],
    };

    match User::collection(db)
        .find(filter)
        .limit(SEARCH_RESULT_LIMIT)
        .await
    {
        Ok(cursor) => match cursor.try_collect().await {
            Ok(u) => Some(u),
            Err(e) => {
                log::error!("search_users_by_term collect: {e}");
                None
            }
        },
        Err(e) => {
            log::error!("search_users_by_term: {e}");
            None
        }
    }
}

#[derive(Deserialize)]
pub struct SearchBody {
    #[serde(rename = "searchTerm")]
    pub search_term: Option<String>,
}

fn friend_profile_json(friend: &User) -> serde_json::Value {
    json!({
        "_id": friend.id.map(|o| o.to_hex()).unwrap_or_default(),
        "username": friend.username,
        "displayName": resolve_display_name(friend),
        "bio": friend.bio,
        "image": friend.image,
        "banner": friend.banner,
        "color": friend.color,
        "isOnline": friend.is_online,
        "lastSeen": friend.last_seen.as_ref().and_then(|d| d.try_to_rfc3339_string().ok()),
        "availabilityStatus": crate::utils::user::json::availability_status_str(&friend.availability_status),
        "createdAt": friend.created_at.try_to_rfc3339_string().ok(),
    })
}

pub async fn get_contact_profile(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Brak autoryzacji" }));
    };
    let contact_id = req.match_info().get("contactId").unwrap_or("");
    let Ok(contact_oid) = ObjectId::parse_str(contact_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nieprawidłowy identyfikator kontaktu" }));
    };

    let db = get_db();
    if let Err(resp) = require_friends_or_503(
        &db,
        &user_id,
        contact_id,
        HttpResponse::NotFound()
            .json(json!({ "message": "Kontakt nie znaleziony lub brak relacji znajomości" })),
    )
    .await
    {
        return resp;
    }

    let friend = match User::find_by_id(&db, contact_oid).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" }));
        }
        Err(e) => {
            log::error!("get_contact_profile: user lookup: {e}");
            return HttpResponse::InternalServerError().json(json!({
                "message": "Nie udało się wczytać profilu",
            }));
        }
    };

    HttpResponse::Ok().json(json!({
        "contact": friend_profile_json(&friend),
    }))
}

pub async fn search_contacts(req: HttpRequest, body: web::Json<SearchBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::InternalServerError().body("Internal Server Error.");
    };

    let Some(search_term) = body.search_term.clone() else {
        return HttpResponse::BadRequest().body("Search Term is required.");
    };

    let normalized = normalize_text(&search_term);
    if normalized.chars().count() < MIN_SEARCH_LENGTH {
        return HttpResponse::BadRequest().body(format!(
            "Search term must be at least {MIN_SEARCH_LENGTH} characters."
        ));
    }
    if normalized.chars().count() > MAX_SEARCH_LENGTH {
        return HttpResponse::BadRequest().body(format!(
            "Search term must be at most {MAX_SEARCH_LENGTH} characters."
        ));
    }

    let db = get_db();
    let Some(matches) = search_users_by_term(&db, uid, &normalized).await else {
        return HttpResponse::ServiceUnavailable().json(json!({
            "message": "Temporarily unavailable",
            "retryable": true,
        }));
    };
    let friend_set: HashSet<String> = match crate::utils::friends::try_friend_ids(&db, &user_id).await
    {
        Ok(ids) => ids.into_iter().collect(),
        Err(()) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    let mut results = Vec::with_capacity(matches.len());
    for c in &matches {
        let Some(candidate_id) = c.id.map(|o| o.to_hex()) else {
            continue;
        };
        if friend_set.contains(&candidate_id) {
            results.push(json!({
                "_id": candidate_id,
                "username": c.username,
                "displayName": resolve_display_name(c),
                "bio": c.bio,
                "image": c.image,
                "banner": c.banner,
                "color": c.color,
                "createdAt": c.created_at.try_to_rfc3339_string().ok(),
            }));
        } else {
            results.push(json!({
                "_id": candidate_id,
                "username": c.username,
                "displayName": resolve_display_name(c),
                "color": c.color,
            }));
        }
    }

    HttpResponse::Ok().json(json!({ "contacts": results }))
}

async fn dm_unread_counts_batch(
    db: &mongodb::Database,
    uid: ObjectId,
    friend_ids: &[ObjectId],
) -> Option<std::collections::HashMap<ObjectId, u64>> {
    let mut out = std::collections::HashMap::new();
    if friend_ids.is_empty() {
        return Some(out);
    }

    let pipeline = vec![
        doc! {
            "$match": {
                "recipient": uid,
                "sender": { "$in": friend_ids },
                "read": false,
                "deleted": { "$ne": true },
                "$and": [
                    { "$or": dm_only_or_clause() },
                    {
                        "$nor": [{
                            "messageType": "CALL",
                            "durationMs": { "$gt": 0 },
                        }]
                    },
                ],
            }
        },
        doc! {
            "$group": {
                "_id": "$sender",
                "count": { "$sum": 1 },
            }
        },
    ];
    let mut cursor = match Message::collection(db).aggregate(pipeline).await {
        Ok(c) => c,
        Err(_) => return None,
    };
    loop {
        match cursor.try_next().await {
            Ok(Some(doc)) => {
                let Ok(fid) = doc.get_object_id("_id") else { continue };
                let count = match doc.get("count") {
                    Some(mongodb::bson::Bson::Int64(n)) => (*n).max(0) as u64,
                    Some(mongodb::bson::Bson::Int32(n)) => (*n).max(0) as u64,
                    _ => 0,
                };
                out.insert(fid, count);
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    Some(out)
}

async fn dm_last_messages_batch(
    db: &mongodb::Database,
    uid: ObjectId,
    friend_ids: &[ObjectId],
) -> Option<std::collections::HashMap<ObjectId, (DateTime, String, ObjectId, Option<u64>)>> {
    let mut out =
        crate::utils::tips::load_dm_tips_for_friends(db, uid, friend_ids).await?;
    let missing: Vec<ObjectId> = friend_ids
        .iter()
        .copied()
        .filter(|id| {
            out.get(id)
                .map(|(ts, preview, _, _)| {
                    preview.is_empty() && ts.timestamp_millis() == 0
                })
                .unwrap_or(true)
        })
        .collect();
    if missing.is_empty() {
        return Some(out);
    }
    let pipeline = vec![
        doc! {
            "$match": {
                "deleted": { "$ne": true },
                "$and": [
                    { "$or": dm_only_or_clause() },
                    { "$or": [
                        { "sender": uid, "recipient": { "$in": &missing } },
                        { "recipient": uid, "sender": { "$in": &missing } },
                    ]},
                ],
            }
        },
        doc! { "$sort": { "timestamp": -1, "_id": -1 } },
        doc! {
            "$group": {
                "_id": {
                    "$cond": [
                        { "$eq": ["$sender", uid] },
                        "$recipient",
                        "$sender",
                    ]
                },
                "timestamp": { "$first": "$timestamp" },
                "content": { "$first": "$content" },
                "messageId": { "$first": "$_id" },
            }
        },
    ];
    let mut cursor = match Message::collection(db).aggregate(pipeline).await {
        Ok(c) => c,
        Err(_) => return None,
    };
    let mut filled: std::collections::HashMap<
        ObjectId,
        (DateTime, String, ObjectId, Option<u64>),
    > = std::collections::HashMap::new();
    loop {
        match cursor.try_next().await {
            Ok(Some(doc)) => {
                let Ok(fid) = doc.get_object_id("_id") else { continue };
                let Some(ts) = doc.get_datetime("timestamp").ok().copied() else { continue };
                let Some(raw) = doc.get_str("content").ok() else { continue };
                let Ok(mid) = doc.get_object_id("messageId") else { continue };
                let unread = out.get(&fid).and_then(|e| e.3);
                filled.insert(
                    fid,
                    (
                        ts,
                        crate::utils::messages::storage::content_for_api(raw),
                        mid,
                        unread,
                    ),
                );
            }
            Ok(None) => break,

            Err(_) => return None,
        }
    }
    for (fid, entry) in filled {
        out.insert(fid, entry);
    }
    Some(out)
}

pub async fn get_contacts_for_list(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    if user_id.is_empty() {
        return HttpResponse::BadRequest().body("User ID is required.");
    }
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().body("User ID is required.");
    };

    let db = get_db();

    let friendships: Vec<FriendRequest> = match FriendRequest::collection(&db)
        .find(doc! { "status": "accepted", "$or": [ { "from": uid }, { "to": uid } ] })
        .await
    {
        Ok(c) => match c.try_collect().await {
            Ok(f) => f,
            Err(_) => {
                return HttpResponse::ServiceUnavailable()
                    .body("Contacts temporarily unavailable. Please retry.");
            }
        },
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    let current_user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::Unauthorized().body("Unauthorized");
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable()
                .body("Contacts temporarily unavailable. Please retry.");
        }
    };
    let muted: Vec<String> = current_user
        .muted_contacts
        .iter()
        .map(|o| o.to_hex())
        .collect();
    let blocked: Vec<String> = current_user
        .blocked_contacts
        .iter()
        .map(|o| o.to_hex())
        .collect();

    let other_ids: Vec<ObjectId> = friendships
        .iter()
        .map(|f| if f.from == uid { f.to } else { f.from })
        .collect();
    let mut friend_map: std::collections::HashMap<ObjectId, User> =
        std::collections::HashMap::new();
    if !other_ids.is_empty() {
        let cursor = match User::collection(&db)
            .find(doc! { "_id": { "$in": &other_ids } })
            .await
        {
            Ok(c) => c,
            Err(_) => {
                return HttpResponse::ServiceUnavailable()
                    .body("Contacts temporarily unavailable. Please retry.");
            }
        };
        let users: Vec<User> = match cursor.try_collect().await {
            Ok(u) => u,
            Err(_) => {
                return HttpResponse::ServiceUnavailable()
                    .body("Contacts temporarily unavailable. Please retry.");
            }
        };
        for u in users {
            if let Some(id) = u.id {
                friend_map.insert(id, u);
            }
        }
    }

    let blocked_set: HashSet<String> = blocked.into_iter().collect();
    let muted_set: HashSet<String> = muted.into_iter().collect();

    let active_friend_ids: Vec<ObjectId> = friendships
        .iter()
        .map(|f| if f.from == uid { f.to } else { f.from })
        .filter(|fid| !blocked_set.contains(&fid.to_hex()))
        .collect();

    let Some(last_map) = dm_last_messages_batch(&db, uid, &active_friend_ids).await else {
        return HttpResponse::ServiceUnavailable()
            .body("Contacts temporarily unavailable. Please retry.");
    };
    let need_unread: Vec<ObjectId> = active_friend_ids
        .iter()
        .copied()
        .filter(|id| match last_map.get(id) {

            None => true,
            Some((_, _, _, None)) => true,

            Some((ts, preview, _, Some(0))) => {
                !(preview.is_empty() && ts.timestamp_millis() == 0)
            }

            Some((_, _, _, Some(n))) if *n > 0 => true,
            Some((_, _, _, Some(_))) => false,
        })
        .collect();
    let unread_map = if need_unread.is_empty() {
        Some(std::collections::HashMap::new())
    } else {
        dm_unread_counts_batch(&db, uid, &need_unread).await
    };
    let Some(unread_map) = unread_map else {
        return HttpResponse::ServiceUnavailable()
            .body("Contacts temporarily unavailable. Please retry.");
    };

    let mut contacts: Vec<(i64, serde_json::Value)> = Vec::with_capacity(friendships.len());
    for f in &friendships {
        let other_id = if f.from == uid { f.to } else { f.from };
        let Some(friend) = friend_map.get(&other_id) else {
            continue;
        };
        let fid_hex = other_id.to_hex();
        let (last, unread) = if blocked_set.contains(&fid_hex) {
            (None, 0)
        } else {
            let tip = last_map.get(&other_id);

            let unread = if need_unread.iter().any(|id| *id == other_id) {
                unread_map.get(&other_id).copied().unwrap_or(0)
            } else {
                tip.and_then(|t| t.3)
                    .unwrap_or_else(|| unread_map.get(&other_id).copied().unwrap_or(0))
            };
            let last = tip.and_then(|(ts, c, id, _)| {
                if c.is_empty() && ts.timestamp_millis() == 0 {
                    None
                } else {
                    Some((*ts, c.clone(), *id))
                }
            });
            (last, unread)
        };

        let last_time_ms = last.as_ref().map(|(t, _, _)| t.timestamp_millis()).unwrap_or(0);
        let mut profile = friend_profile_json(friend);
        if let Some(obj) = profile.as_object_mut() {
            obj.insert(
                "lastMessageTime".to_string(),
                json!(last.as_ref().and_then(|(t, _, _)| t.try_to_rfc3339_string().ok())),
            );
            obj.insert(
                "lastMessage".to_string(),
                json!(last.as_ref().map(|(_, c, _)| c.clone())),
            );
            obj.insert(
                "lastMessageId".to_string(),
                json!(last.as_ref().map(|(_, _, id)| id.to_hex())),
            );
            obj.insert("unreadCount".to_string(), json!(unread));
            obj.insert("isMuted".to_string(), json!(muted_set.contains(&fid_hex)));
            obj.insert(
                "isBlockedByMe".to_string(),
                json!(blocked_set.contains(&fid_hex)),
            );
        }
        contacts.push((last_time_ms, profile));
    }

    contacts.sort_by(|a, b| b.0.cmp(&a.0));
    let contacts: Vec<_> = contacts.into_iter().map(|(_, c)| c).collect();

    HttpResponse::Ok().json(json!({ "contacts": contacts }))
}

pub async fn toggle_contact_mute(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Brak autoryzacji" }));
    };
    let contact_id = req.match_info().get("contactId").unwrap_or("");
    let Ok(contact_oid) = ObjectId::parse_str(contact_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nieprawidłowy identyfikator kontaktu" }));
    };

    let db = get_db();
    if let Err(resp) = require_friends_or_503(
        &db,
        &user_id,
        contact_id,
        HttpResponse::NotFound()
            .json(json!({ "message": "Kontakt nie znaleziony lub brak relacji znajomości" })),
    )
    .await
    {
        return resp;
    }

    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" }));
    };
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    let mut muted = user.muted_contacts.clone();
    let is_muted;
    if let Some(pos) = muted.iter().position(|o| *o == contact_oid) {
        muted.remove(pos);
        is_muted = false;
    } else {
        muted.push(contact_oid);
        is_muted = true;
    }

    let muted_bson = match mongodb::bson::to_bson(&muted) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Internal Server Error" }));
        }
    };
    if User::set_fields(&db, uid, doc! { "mutedContacts": muted_bson }).await.is_err() {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    }

    HttpResponse::Ok().json(json!({
        "isMuted": is_muted,
        "message": if is_muted { "Konwersacja wyciszona" } else { "Wyciszenie wyłączone" },
    }))
}

pub async fn get_blocked_contacts(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Brak autoryzacji" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Nieprawidłowy użytkownik" }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable()
                .json(json!({ "message": "Contacts temporarily unavailable. Please retry." }));
        }
    };

    let mut blocked_map: std::collections::HashMap<ObjectId, User> =
        std::collections::HashMap::new();
    if !user.blocked_contacts.is_empty() {
        let cursor = match User::collection(&db)
            .find(doc! { "_id": { "$in": &user.blocked_contacts } })
            .await
        {
            Ok(c) => c,
            Err(_) => {
                return HttpResponse::ServiceUnavailable()
                    .json(json!({ "message": "Contacts temporarily unavailable. Please retry." }));
            }
        };
        let users: Vec<User> = match cursor.try_collect().await {
            Ok(u) => u,
            Err(_) => {
                return HttpResponse::ServiceUnavailable()
                    .json(json!({ "message": "Contacts temporarily unavailable. Please retry." }));
            }
        };
        for u in users {
            if let Some(id) = u.id {
                blocked_map.insert(id, u);
            }
        }
    }

    let mut blocked = Vec::new();
    for contact_oid in &user.blocked_contacts {
        let Some(friend) = blocked_map.get(contact_oid) else {
            continue;
        };
        blocked.push(json!({
            "_id": contact_oid.to_hex(),
            "username": friend.username,
            "displayName": resolve_display_name(friend),
            "image": friend.image,
            "color": friend.color,
        }));
    }

    HttpResponse::Ok().json(json!({ "contacts": blocked }))
}

pub async fn toggle_contact_block(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Brak autoryzacji" }));
    };
    let contact_id = req.match_info().get("contactId").unwrap_or("");
    let Ok(contact_oid) = ObjectId::parse_str(contact_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nieprawidłowy identyfikator kontaktu" }));
    };

    let db = get_db();
    if let Err(resp) = require_friends_or_503(
        &db,
        &user_id,
        contact_id,
        HttpResponse::NotFound()
            .json(json!({ "message": "Kontakt nie znaleziony lub brak relacji znajomości" })),
    )
    .await
    {
        return resp;
    }

    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" }));
    };
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    let mut blocked = user.blocked_contacts.clone();
    let is_blocked;
    if let Some(pos) = blocked.iter().position(|o| *o == contact_oid) {
        blocked.remove(pos);
        is_blocked = false;
    } else {
        blocked.push(contact_oid);
        is_blocked = true;
    }

    let blocked_bson = match mongodb::bson::to_bson(&blocked) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Internal Server Error" }));
        }
    };
    if User::set_fields(&db, uid, doc! { "blockedContacts": blocked_bson }).await.is_err() {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    }

    invalidate_friend_ids_pair(&user_id, contact_id);
    crate::utils::friends::invalidate_block_pair(&user_id, contact_id);
    typing::invalidate_pair(&user_id, contact_id);

    if is_blocked {
        if let Some(session) =
            crate::utils::voice::calls::take_session_for_pair(&user_id, contact_id)
        {
            let end_payload = json!({ "from": user_id, "reason": "BLOCKED" });
            let event = match session.phase {
                crate::utils::voice::calls::CallPhase::Ringing => "call:cancelled",
                crate::utils::voice::calls::CallPhase::Accepted => "call:ended",
            };
            crate::ws::registry::emit_to_user(&session.callee_id, event, end_payload.clone());
            crate::ws::registry::emit_to_user(&session.caller_id, event, end_payload);
        }
    }

    crate::ws::registry::emit_to_user(
        &user_id,
        "contact-block-updated",
        json!({ "contactId": contact_id, "isBlockedByMe": is_blocked }),
    );
    crate::ws::registry::emit_to_user(
        contact_id,
        "contact-block-updated",
        json!({ "contactId": user_id, "isBlockedByOther": is_blocked }),
    );

    HttpResponse::Ok().json(json!({
        "isBlocked": is_blocked,
        "message": if is_blocked { "Użytkownik zablokowany" } else { "Użytkownik odblokowany" },
    }))
}

pub async fn delete_conversation(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let contact_id = req.match_info().get("contactId").unwrap_or("");

    if user_id.is_empty() || contact_id.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "message": "Missing user or contact id" }));
    }

    let (Ok(uid), Ok(cid)) = (ObjectId::parse_str(&user_id), ObjectId::parse_str(contact_id)) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Missing user or contact id" }));
    };

    let db = get_db();
    if let Err(resp) = require_friends_or_503(
        &db,
        &user_id,
        contact_id,
        HttpResponse::Forbidden()
            .json(json!({ "message": "You can only delete conversations with friends" })),
    )
    .await
    {
        return resp;
    }

    let wipe_at = DateTime::now();

    let live_filter = doc! {
        "$or": [
            { "sender": uid, "recipient": cid },
            { "sender": cid, "recipient": uid },
        ],
        "deleted": { "$ne": true },
    };
    let file_urls = match crate::utils::messages::search::wipe_live_messages(&db, live_filter).await {
        Ok(urls) => urls,
        Err(e) => {
            log::error!(
                "delete_conversation: failed to wipe DM messages for {} / {}: {e}",
                user_id,
                contact_id
            );
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Failed to delete conversation",
                "retryable": true,
            }));
        }
    };

    let cleanups: Vec<_> = file_urls
        .iter()
        .map(|url| cleanup_attachment_if_unreferenced(&db, Some(url)))
        .collect();
    futures_util::future::join_all(cleanups).await;

    if let Some(session) =
        crate::utils::voice::calls::take_session_for_pair(&user_id, contact_id)
    {
        let end_payload = json!({ "from": user_id, "reason": "CONVERSATION_DELETED" });
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

    crate::utils::tips::clear_dm_tip_at_most(&db, uid, cid, wipe_at).await;

    match Message::collection(&db)
        .count_documents(doc! {
            "$or": [
                { "sender": uid, "recipient": cid },
                { "sender": cid, "recipient": uid },
            ],
            "deleted": { "$ne": true },
        })
        .await
    {
        Ok(remaining) if remaining > 0 => {

            if let Ok(mut cursor) = Message::collection(&db)
                .find(doc! {
                    "$or": [
                        { "sender": uid, "recipient": cid },
                        { "sender": cid, "recipient": uid },
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
            let synced_viewer =
                crate::utils::tips::try_sync_dm_tip_unread(&db, uid, cid).await;
            let synced_peer =
                crate::utils::tips::try_sync_dm_tip_unread(&db, cid, uid).await;
            match (synced_viewer, synced_peer) {
                (Some(nv), Some(np)) => {
                    crate::utils::unread::emit_unread_absolute(&user_id, "dm", contact_id, nv);
                    crate::utils::unread::emit_unread_absolute(contact_id, "dm", &user_id, np);
                }
                _ => {
                    crate::utils::unread::invalidate_unread_generation(&user_id, "dm", contact_id);
                    crate::utils::unread::invalidate_unread_generation(contact_id, "dm", &user_id);
                }
            }
        }
        Ok(_) => {

            match Message::collection(&db)
                .count_documents(doc! {
                    "$or": [
                        { "sender": uid, "recipient": cid },
                        { "sender": cid, "recipient": uid },
                    ],
                    "deleted": { "$ne": true },
                })
                .await
            {
                Ok(0) => {

                    let still_empty = Message::collection(&db)
                        .count_documents(doc! {
                            "$or": [
                                { "sender": uid, "recipient": cid },
                                { "sender": cid, "recipient": uid },
                            ],
                            "deleted": { "$ne": true },
                        })
                        .await
                        .ok()
                        == Some(0);
                    if still_empty {
                        let synced_viewer =
                            crate::utils::tips::try_sync_dm_tip_unread(&db, uid, cid)
                                .await;
                        let synced_peer =
                            crate::utils::tips::try_sync_dm_tip_unread(&db, cid, uid)
                                .await;
                        match (synced_viewer, synced_peer) {
                            (Some(nv), Some(np)) => {
                                crate::utils::unread::emit_unread_absolute(
                                    &user_id, "dm", contact_id, nv,
                                );
                                crate::utils::unread::emit_unread_absolute(
                                    contact_id, "dm", &user_id, np,
                                );
                            }
                            _ => {
                                crate::utils::unread::invalidate_unread_generation(
                                    &user_id, "dm", contact_id,
                                );
                                crate::utils::unread::invalidate_unread_generation(
                                    contact_id, "dm", &user_id,
                                );
                            }
                        }
                        crate::ws::registry::emit_to_user(
                            &user_id,
                            "conversation-deleted",
                            json!({ "contactId": contact_id }),
                        );
                        crate::ws::registry::emit_to_user(
                            contact_id,
                            "conversation-deleted",
                            json!({ "contactId": user_id }),
                        );
                    } else {
                        let synced_viewer =
                            crate::utils::tips::try_sync_dm_tip_unread(&db, uid, cid)
                                .await;
                        let synced_peer =
                            crate::utils::tips::try_sync_dm_tip_unread(&db, cid, uid)
                                .await;
                        match (synced_viewer, synced_peer) {
                            (Some(nv), Some(np)) => {
                                crate::utils::unread::emit_unread_absolute(
                                    &user_id, "dm", contact_id, nv,
                                );
                                crate::utils::unread::emit_unread_absolute(
                                    contact_id, "dm", &user_id, np,
                                );
                            }
                            _ => {
                                crate::utils::unread::invalidate_unread_generation(
                                    &user_id, "dm", contact_id,
                                );
                                crate::utils::unread::invalidate_unread_generation(
                                    contact_id, "dm", &user_id,
                                );
                            }
                        }
                    }
                }
                Ok(_) => {
                    let synced_viewer =
                        crate::utils::tips::try_sync_dm_tip_unread(&db, uid, cid)
                            .await;
                    let synced_peer =
                        crate::utils::tips::try_sync_dm_tip_unread(&db, cid, uid)
                            .await;
                    match (synced_viewer, synced_peer) {
                        (Some(nv), Some(np)) => {
                            crate::utils::unread::emit_unread_absolute(
                                &user_id, "dm", contact_id, nv,
                            );
                            crate::utils::unread::emit_unread_absolute(
                                contact_id, "dm", &user_id, np,
                            );
                        }
                        _ => {
                            crate::utils::unread::invalidate_unread_generation(
                                &user_id, "dm", contact_id,
                            );
                            crate::utils::unread::invalidate_unread_generation(
                                contact_id, "dm", &user_id,
                            );
                        }
                    }
                }
                Err(_) => {

                    crate::utils::unread::invalidate_unread_generation(
                        &user_id, "dm", contact_id,
                    );
                    crate::utils::unread::invalidate_unread_generation(
                        contact_id, "dm", &user_id,
                    );
                }
            }
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "message": "Failed to delete conversation",
                "retryable": true,
            }));
        }
    }

    HttpResponse::Ok().json(json!({ "message": "Conversation deleted" }))
}
