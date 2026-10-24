// channels.rs
// CRUD kanału, członkowie, kick/ban/mute, avatar.
// Zakres:
//  - $pull membership, ban-before-kick
//  - CRUD, członkowie, kick/ban/mute, avatar; $pull membership
// Po kick fan-out WS i unread — nie zostawiaj ghost rosteru.
// Przy zmianach: model/channels.rs, utils/channel/*, ws/handlers.rs.

use actix_multipart::form::{tempfile::TempFile, MultipartForm};
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::middlewares::auth::request_user_id;
use crate::model::channels::{Channel, CreateChannelInput};
use crate::model::messages::Message;
use crate::model::reports::{ChannelReport, CreateChannelReportInput};
use crate::model::storage_cleanup::{PendingStorageDeletion, StorageObjectKind};
use crate::model::users::User;
use crate::utils::access::members::{require_channel_access, AccessDeniedReason};
use crate::utils::channel::{
    can_access_channel, channel_member_count, enrich_channel_unread, enrich_channels_batch,
    fetch_users_by_refs, fetch_users_map_slim, get_channel_ban_mute_lists, is_channel_admin,
    is_channel_member, is_channel_muted_member, moderation, populate_channel_user,
    serialize_channel_list_item,
};
use crate::utils::db::get_db;
use crate::utils::friends::try_are_friends;
use crate::utils::images::{reencode_error_message, reencode_upload_to_webp_async};
use crate::utils::messages::serialize_messages_batch;
use crate::utils::storage::{avatar_channel_key, avatar_key_owned_by_channel, storage};
use crate::utils::upload::{file_bytes_within_limit, local_file_size, MAX_AVATAR_BYTES};
use crate::utils::validators::file_type::validate_file_magic_async;
use crate::utils::validators::unicode::sanitize_channel_name;
use crate::ws::registry::{channel_recipient_ids, emit_to_user, emit_to_users};
use crate::ws::typing;

const REPORT_REASONS: &[&str] = &[
    "Spam lub reklamy",
    "Treści obraźliwe",
    "Nękanie lub bullying",
    "Nielegalne treści",
    "Podszywanie się",
    "Inne",
];

const DEFAULT_CHANNEL_MESSAGE_LIMIT: i64 = 30;
const MAX_CHANNEL_MESSAGE_LIMIT: i64 = 50;

fn param<'a>(req: &'a HttpRequest, name: &str) -> &'a str {
    req.match_info().get(name).unwrap_or("")
}

fn iso(dt: &DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

async fn serialize_channel_for_client(
    db: &mongodb::Database,
    c: &Channel,
    viewer_id: ObjectId,
) -> Value {
    let viewer_id_string = viewer_id.to_hex();
    let unread_fut = enrich_channel_unread(db, viewer_id, c);
    let admin_fut = populate_channel_user(db, c.admin, &viewer_id_string);
    let members_fut = fetch_users_by_refs(db, &c.members, &viewer_id_string);
    let mute_fut = User::find_by_id(db, viewer_id);
    let (unread_tip, admin, members, mute_user) =
        tokio::join!(unread_fut, admin_fut, members_fut, mute_fut);
    let (unread, last) = unread_tip.unwrap_or_else(|| {
        log::warn!(
            "Using initial unread state while serializing newly created channel {}",
            c.id.map(|id| id.to_hex()).unwrap_or_default()
        );
        (0, None)
    });
    let ch_id = c.id.map(|o| o.to_hex()).unwrap_or_default();
    let is_muted = match mute_user {
        Ok(Some(u)) => u.muted_channels.iter().any(|id| Some(*id) == c.id),
        Ok(None) => {
            log::warn!(
                "Viewer {} disappeared while serializing newly created channel {}",
                viewer_id.to_hex(),
                ch_id
            );
            false
        }
        Err(error) => {
            log::warn!(
                "Using initial mute state while serializing newly created channel {}: {error}",
                ch_id
            );
            false
        }
    };

    json!({
        "_id": ch_id,
        "name": c.name,
        "description": c.description,
        "image": c.image,
        "admin": admin,
        "members": members,
        "bannedMembers": moderation::active_moderation_user_ids(&c.banned_members),
        "mutedMembers": moderation::active_moderation_user_ids(&c.muted_members),
        "isMutedHere": is_channel_muted_member(c, Some(&viewer_id.to_hex())),
        "mutedHereExpiresAt": moderation::viewer_mute_expires_at(c, &viewer_id.to_hex()),

        "messages": Vec::<String>::new(),
        "isPrivate": c.is_private,
        "rateLimitPerUser": c.rate_limit_per_user,
        "chatLocked": c.chat_locked,
        "createdAt": iso(&c.created_at),
        "updatedAt": iso(&c.updated_at),
        "unreadCount": unread,
        "lastMessage": last.as_ref().map(|(_, c, _)| c.clone()),
        "lastMessageTime": last.as_ref().and_then(|(t, _, _)| iso(t)),
        "lastMessageId": last.as_ref().map(|(_, _, id)| id.to_hex()),
        "isMuted": is_muted,
    })
}

#[derive(Deserialize)]
pub struct CreateChannelBody {
    pub name: Option<String>,
    pub members: Option<Vec<String>>,
}

pub async fn create_channel(req: HttpRequest, body: web::Json<CreateChannelBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Admin user not found." }));
    };

    let db = get_db();
    match User::find_by_id(&db, uid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::BadRequest().json(json!({ "message": "Admin user not found." }));
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    }

    let mut valid_member_ids: Vec<ObjectId> = Vec::new();
    if let Some(members) = body.members.as_ref().filter(|m| !m.is_empty()) {
        let oids: Vec<ObjectId> = members
            .iter()
            .filter_map(|m| ObjectId::parse_str(m).ok())
            .collect();
        let found: Vec<User> = match User::collection(&db)
            .find(doc! { "_id": { "$in": &oids } })
            .await
        {
            Ok(c) => match c.try_collect().await {
                Ok(u) => u,
                Err(_) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "message": "Temporarily unavailable",
                        "retryable": true,
                    }));
                }
            },
            Err(_) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "message": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        };
        if found.len() != members.len() {
            return HttpResponse::BadRequest()
                .json(json!({ "message": "Some members are not valid users." }));
        }
        valid_member_ids = found.into_iter().filter_map(|u| u.id).collect();
    }

    if !valid_member_ids.is_empty() {
        let friend_set: std::collections::HashSet<String> =
            match crate::utils::friends::try_friend_ids(&db, &user_id).await {
                Ok(ids) => ids.into_iter().collect(),
                Err(()) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "message": "Temporarily unavailable",
                        "retryable": true,
                    }));
                }
            };
        for member_oid in &valid_member_ids {
            let member_hex = member_oid.to_hex();
            if member_hex != user_id && !friend_set.contains(&member_hex) {
                return HttpResponse::Forbidden().json(json!({
                    "message": "Możesz dodawać do kanału tylko swoich znajomych."
                }));
            }
        }
    }

    let input = CreateChannelInput {
        name: body.name.clone().unwrap_or_default(),
        description: None,
        admin: uid,
        members: Some(valid_member_ids),
        is_private: None,
        image: None,
    };

    match Channel::create(&db, input).await {
        Ok(channel) => {
            let serialized = serialize_channel_for_client(&db, &channel, uid).await;
            if let Some(ch_id) = channel.id {
                let ch_hex = ch_id.to_hex();
                let mut seed_ids = channel.members.clone();
                if !seed_ids.iter().any(|m| *m == uid) {
                    seed_ids.push(uid);
                }
                seed_ids.push(channel.admin);
                let mut seen = std::collections::HashSet::new();
                let seed_futs: Vec<_> = seed_ids
                    .into_iter()
                    .filter(|oid| seen.insert(*oid))
                    .map(|member_oid| {
                        let db = db.clone();
                        async move {
                            let result =
                                crate::model::read_state::ChannelReadState::seed_if_missing(
                                    &db, member_oid, ch_id,
                                )
                                .await;
                            (member_oid, result)
                        }
                    })
                    .collect();
                for (member_id, result) in futures_util::future::join_all(seed_futs).await {
                    if let Err(error) = result {
                        log::error!(
                            "Failed to seed read state for user {} in newly created channel {}: {error}",
                            member_id.to_hex(),
                            ch_hex
                        );
                    }
                }

                let notify_futs: Vec<_> = channel
                    .members
                    .iter()
                    .filter(|member_id| member_id.to_hex() != user_id)
                    .map(|member_id| {
                        let db = db.clone();
                        let channel = channel.clone();
                        let mid = member_id.to_hex();
                        let ch_hex = ch_hex.clone();
                        async move {
                            match serialize_channel_list_item(&db, &channel, *member_id).await {
                                Some(slim) => {
                                    emit_to_user(
                                        &mid,
                                        "channel-added",
                                        json!({ "channelId": ch_hex, "channel": slim }),
                                    );
                                }

                                None => {
                                    emit_to_user(
                                        &mid,
                                        "channel-added",
                                        json!({ "channelId": ch_hex }),
                                    );
                                }
                            }
                        }
                    })
                    .collect();
                futures_util::future::join_all(notify_futs).await;
            }
            HttpResponse::Created().json(json!({ "channel": serialized }))
        }
        Err(_) => {
            HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }))
        }
    }
}

pub async fn get_user_channels(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Internal Server Error" }));
    };

    let db = get_db();
    let channels: Vec<Channel> = match Channel::collection(&db)
        .find(doc! {
            "$or": [ { "admin": uid }, { "members": uid } ],
            "isDeleting": { "$ne": true },
        })
        .sort(doc! { "updatedAt": -1 })
        .await
    {
        Ok(c) => match c.try_collect().await {
            Ok(chs) => chs,
            Err(_) => {
                return HttpResponse::ServiceUnavailable()
                    .json(json!({ "message": "Channels temporarily unavailable. Please retry." }));
            }
        },
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Internal Server Error" }));
        }
    };

    let muted_set: std::collections::HashSet<String> = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u.muted_channels.iter().map(|o| o.to_hex()).collect(),
        Ok(None) => {
            return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable()
                .json(json!({ "message": "Channels temporarily unavailable. Please retry." }));
        }
    };

    let mut all_user_ids: Vec<ObjectId> = Vec::new();
    let mut seen_users = std::collections::HashSet::new();
    for ch in &channels {
        if seen_users.insert(ch.admin) {
            all_user_ids.push(ch.admin);
        }
    }
    let users_map = fetch_users_map_slim(&db, &all_user_ids).await;
    let Some(enrich_map) = enrich_channels_batch(&db, uid, &channels).await else {
        return HttpResponse::ServiceUnavailable()
            .json(json!({ "message": "Channels temporarily unavailable. Please retry." }));
    };

    let mut enriched: Vec<(i64, Value)> = channels
        .into_iter()
        .map(|ch| {
            let ch_oid = ch.id.unwrap_or_default();
            let (unread, last) = enrich_map.get(&ch_oid).cloned().unwrap_or((0, None));
            let admin = users_map
                .get(&ch.admin)
                .cloned()
                .unwrap_or_else(|| json!({ "_id": ch.admin.to_hex() }));
            let ch_id = ch.id.map(|o| o.to_hex()).unwrap_or_default();
            let is_muted = muted_set.contains(&ch_id);
            let member_count = channel_member_count(&ch);

            let sort_key = last
                .as_ref()
                .map(|(t, _, _)| t.timestamp_millis())
                .unwrap_or_else(|| ch.updated_at.timestamp_millis());

            (
                sort_key,
                json!({
                    "_id": ch_id,
                    "name": ch.name,
                    "description": ch.description,
                    "image": ch.image,
                    "admin": admin,
                    "members": Vec::<Value>::new(),
                    "memberCount": member_count,
                    "messages": Vec::<String>::new(),
                    "isPrivate": ch.is_private,
                    "createdAt": iso(&ch.created_at),
                    "updatedAt": iso(&ch.updated_at),
                    "unreadCount": unread,
                    "lastMessage": last.as_ref().map(|(_, c, _)| c.clone()),
                    "lastMessageTime": last.as_ref().and_then(|(t, _, _)| iso(t)),
                    "lastMessageId": last.as_ref().map(|(_, _, id)| id.to_hex()),
                    "isMuted": is_muted,
                    "isMutedHere": is_channel_muted_member(&ch, Some(&user_id)),
                    "mutedHereExpiresAt": moderation::viewer_mute_expires_at(&ch, &user_id),
                    "rateLimitPerUser": ch.rate_limit_per_user,
                    "chatLocked": ch.chat_locked,
                }),
            )
        })
        .collect();

    enriched.sort_by(|a, b| b.0.cmp(&a.0));
    let channels: Vec<Value> = enriched.into_iter().map(|(_, c)| c).collect();

    HttpResponse::Ok().json(json!({ "channels": channels }))
}

pub async fn get_channel_messages(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let channel_id = param(&req, "channelId");

    let db = get_db();
    if let Err(reason) = require_channel_access(&db, channel_id, &user_id).await {
        if reason == AccessDeniedReason::Unavailable {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": reason.as_str(),
                "retryable": true,
            }));
        }
        return HttpResponse::NotFound().json(json!({
            "message": reason.as_str(),
        }));
    }

    let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid channel id" }));
    };

    let query =
        web::Query::<std::collections::HashMap<String, String>>::from_query(req.query_string())
            .map(|q| q.into_inner())
            .unwrap_or_default();
    let limit = query
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(DEFAULT_CHANNEL_MESSAGE_LIMIT)
        .clamp(1, MAX_CHANNEL_MESSAGE_LIMIT);

    let mut and_clauses = vec![
        doc! { "channel": channel_oid },
        doc! { "deleted": { "$ne": true } },
    ];
    if let Some(before_id) = query
        .get("before")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let Ok(before_oid) = ObjectId::parse_str(before_id) else {
            return HttpResponse::BadRequest().json(json!({ "message": "Invalid cursor" }));
        };
        and_clauses.push(doc! { "_id": { "$lt": before_oid } });
    }

    let mut messages: Vec<Message> = match Message::collection(&db)
        .find(doc! { "$and": and_clauses })
        .sort(doc! { "_id": -1 })
        .limit(limit + 1)
        .await
    {
        Ok(c) => match c.try_collect().await {
            Ok(m) => m,
            Err(e) => {
                log::error!("get_channel_messages: {e}");
                return HttpResponse::InternalServerError()
                    .json(json!({ "message": "Internal Server Error" }));
            }
        },
        Err(e) => {
            log::error!("get_channel_messages: {e}");
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Internal Server Error" }));
        }
    };

    let has_more = messages.len() as i64 > limit;
    if has_more {
        messages.truncate(limit as usize);
    }
    messages.reverse();

    let out = serialize_messages_batch(&db, &messages).await;
    HttpResponse::Ok().json(json!({ "messages": out, "hasMore": has_more }))
}

pub async fn get_channel_details(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound()
            .json(json!({ "message": "Kanał nie znaleziony lub brak dostępu" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) if can_access_channel(&c, Some(&user_id)) => {
            moderation::maybe_prune_channel_moderation(&db, &c).await
        }
        Ok(Some(_)) | Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({ "message": "Kanał nie znaleziony lub brak dostępu" }));
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    let Ok(viewer_oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound()
            .json(json!({ "message": "Kanał nie znaleziony lub brak dostępu" }));
    };
    let is_muted = match User::find_by_id(&db, viewer_oid).await {
        Ok(Some(u)) => u.muted_channels.iter().any(|id| *id == cid),
        Ok(None) => {
            return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Channels temporarily unavailable. Please retry.",
                "retryable": true,
            }));
        }
    };

    let admin = populate_channel_user(&db, channel.admin, &user_id).await;
    let members = fetch_users_by_refs(&db, &channel.members, &user_id).await;
    let Some((banned_members, muted_members)) =
        get_channel_ban_mute_lists(&db, cid, &user_id).await
    else {
        return HttpResponse::ServiceUnavailable().json(json!({
            "message": "Channels temporarily unavailable. Please retry.",
            "retryable": true,
        }));
    };

    HttpResponse::Ok().json(json!({
        "channel": {
            "_id": cid.to_hex(),
            "name": channel.name,
            "description": channel.description,
            "image": if channel.image.is_empty() { Value::Null } else { json!(channel.image) },
            "admin": admin,
            "members": members,
            "bannedMembers": banned_members,
            "mutedMembers": muted_members,
            "memberCount": channel_member_count(&channel),
            "isAdmin": is_channel_admin(&channel, Some(&user_id)),
            "isMuted": is_muted,
            "isMutedHere": is_channel_muted_member(&channel, Some(&user_id)),
            "mutedHereExpiresAt": moderation::viewer_mute_expires_at(&channel, &user_id),
            "rateLimitPerUser": channel.rate_limit_per_user,
            "chatLocked": channel.chat_locked,
        }
    }))
}

#[derive(Deserialize)]
pub struct RenameBody {
    pub name: Option<String>,
}

pub async fn rename_channel(req: HttpRequest, body: web::Json<RenameBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let name = body.name.clone().unwrap_or_default();
    let new_name = sanitize_channel_name(&name);
    if new_name.chars().count() < 3 || new_name.chars().count() > 50 {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nazwa kanału musi mieć od 3 do 50 znaków" }));
    }

    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" })),
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "error": "Tylko administrator może zmienić nazwę kanału" }));
    }

    match Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! { "$set": { "name": &new_name, "updatedAt": DateTime::now() } },
        )
        .await
    {
        Ok(_) => {}
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Failed to rename channel",
                "retryable": true,
            }));
        }
    }

    emit_to_users(
        &channel_recipient_ids(&channel),
        "channel-name-updated",
        json!({ "channelId": cid.to_hex(), "name": new_name }),
    );
    HttpResponse::Ok().json(json!({ "name": new_name }))
}

#[derive(Deserialize)]
pub struct SlowmodeBody {
    #[serde(rename = "rateLimitPerUser")]
    pub rate_limit_per_user: Option<u32>,
}

pub async fn update_channel_slowmode(
    req: HttpRequest,
    body: web::Json<SlowmodeBody>,
) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let rate_limit = body.rate_limit_per_user.unwrap_or(0);
    if rate_limit > 21_600 {
        return HttpResponse::BadRequest().json(json!({
            "error": "Slowmode nie może przekraczać 21600 sekund (6 godzin)."
        }));
    }

    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" })),
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({
            "error": "Tylko administrator może zmienić slowmode kanału."
        }));
    }

    match Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! {
                "$set": {
                    "rateLimitPerUser": rate_limit,
                    "updatedAt": DateTime::now(),
                }
            },
        )
        .await
    {
        Ok(_) => {}
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Failed to update slowmode",
                "retryable": true,
            }));
        }
    }

    emit_to_users(
        &channel_recipient_ids(&channel),
        "channel-slowmode-updated",
        json!({ "channelId": cid.to_hex(), "rateLimitPerUser": rate_limit }),
    );
    typing::invalidate_channel(&cid.to_hex());

    HttpResponse::Ok().json(json!({ "rateLimitPerUser": rate_limit }))
}

#[derive(Deserialize)]
pub struct ChatLockBody {
    #[serde(rename = "chatLocked")]
    pub chat_locked: Option<bool>,
}

pub async fn update_channel_chat_lock(
    req: HttpRequest,
    body: web::Json<ChatLockBody>,
) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let chat_locked = body.chat_locked.unwrap_or(false);

    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" })),
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({
            "error": "Tylko administrator może zablokować lub odblokować czat kanału."
        }));
    }

    match Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! {
                "$set": {
                    "chatLocked": chat_locked,
                    "updatedAt": DateTime::now(),
                }
            },
        )
        .await
    {
        Ok(_) => {}
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Failed to update chat lock",
                "retryable": true,
            }));
        }
    }

    emit_to_users(
        &channel_recipient_ids(&channel),
        "channel-chat-locked-updated",
        json!({ "channelId": cid.to_hex(), "chatLocked": chat_locked }),
    );
    typing::invalidate_channel(&cid.to_hex());

    HttpResponse::Ok().json(json!({ "chatLocked": chat_locked }))
}

pub async fn delete_channel_avatar(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Only admin can delete channel avatar" }));
    }

    if !channel.image.is_empty() {
        let channel_id = cid.to_hex();
        match Channel::collection(&db)
            .update_one(
                doc! { "_id": cid, "image": &channel.image },
                doc! { "$set": { "image": "", "updatedAt": DateTime::now() } },
            )
            .await
        {
            Ok(result) if result.modified_count == 1 => {}
            Ok(_) => {
                return HttpResponse::Conflict().json(json!({
                    "message": "Channel avatar changed before deletion completed. Please retry.",
                    "retryable": true,
                }));
            }
            Err(error) => {
                log::error!(
                    "Failed to detach avatar {} from channel {}: {error}",
                    channel.image,
                    channel_id
                );
                return HttpResponse::InternalServerError().json(json!({
                    "message": "Failed to delete channel avatar",
                    "retryable": true,
                }));
            }
        };

        if avatar_key_owned_by_channel(&channel.image, &channel_id) {
            if let Err(error) = PendingStorageDeletion::delete_or_defer(
                &db,
                &channel.image,
                StorageObjectKind::Avatar,
            )
            .await
            {
                log::error!(
                    "Failed to schedule cleanup for detached channel avatar {}: {error}",
                    channel.image
                );
                match Channel::collection(&db)
                    .update_one(
                        doc! { "_id": cid, "image": "" },
                        doc! { "$set": { "image": &channel.image, "updatedAt": DateTime::now() } },
                    )
                    .await
                {
                    Ok(result) if result.modified_count == 1 => {}
                    Ok(_) => log::error!(
                        "Could not restore channel avatar {} after cleanup scheduling failed; channel {} changed concurrently",
                        channel.image,
                        channel_id
                    ),
                    Err(restore_error) => log::error!(
                        "Could not restore channel avatar {} after cleanup scheduling failed: {restore_error}",
                        channel.image
                    ),
                }
                return HttpResponse::ServiceUnavailable().json(json!({
                    "message": "Channel avatar cleanup is pending.",
                    "retryable": true,
                }));
            }
        }
        emit_to_users(
            &channel_recipient_ids(&channel),
            "channel-avatar-updated",
            json!({ "channelId": channel_id, "image": "" }),
        );
    }

    HttpResponse::Ok().json(json!({ "message": "Channel avatar deleted" }))
}

#[derive(MultipartForm)]
pub struct ChannelAvatarForm {
    #[multipart(rename = "avatar", limit = "6 MiB")]
    pub file: TempFile,
}

pub async fn upload_channel_avatar(
    req: HttpRequest,
    form: MultipartForm<ChannelAvatarForm>,
) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Only admin can change channel avatar" }));
    }

    let ext = form
        .file
        .file_name
        .as_deref()
        .and_then(|n| n.rsplit('.').next())
        .map(|e| e.to_lowercase())
        .filter(|e| ["jpg", "jpeg", "png", "webp"].contains(&e.as_str()))
        .unwrap_or_else(|| "png".to_string());

    let upload_path = form.file.file.path().to_path_buf();
    if !validate_file_magic_async(upload_path.clone(), ext.clone()).await {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid file content" }));
    }
    if local_file_size(&upload_path)
        .map(|size| !file_bytes_within_limit(size, MAX_AVATAR_BYTES))
        .unwrap_or(true)
    {
        return HttpResponse::PayloadTooLarge()
            .json(json!({ "message": "File too large. Maximum size is 6 MB." }));
    }

    let previous_image = channel.image.clone();
    let channel_id = cid.to_hex();
    let key = avatar_channel_key(&channel_id);
    let webp = match reencode_upload_to_webp_async(upload_path).await {
        Ok(bytes) => bytes,
        Err(err) => {
            return HttpResponse::BadRequest().json(json!({
                "message": reencode_error_message(&err),
            }));
        }
    };
    if storage()
        .put_public(&key, webp, "image/webp")
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Internal Server Error" }));
    }

    match Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! { "$set": { "image": &key, "updatedAt": DateTime::now() } },
        )
        .await
    {
        Ok(_) => {}
        Err(_) => {
            if let Err(cleanup_error) =
                PendingStorageDeletion::delete_or_defer(&db, &key, StorageObjectKind::Avatar).await
            {
                log::error!("Failed to schedule cleanup for unreferenced channel avatar {key}: {cleanup_error}");
            }
            return HttpResponse::InternalServerError().json(json!({
                "message": "Failed to update channel avatar",
                "retryable": true,
            }));
        }
    }

    let mut cleanup_pending = false;
    if !previous_image.is_empty()
        && previous_image != key
        && avatar_key_owned_by_channel(&previous_image, &channel_id)
    {
        if let Err(error) =
            PendingStorageDeletion::delete_or_defer(&db, &previous_image, StorageObjectKind::Avatar)
                .await
        {
            log::error!(
                "Failed to schedule cleanup for previous channel avatar {previous_image}: {error}"
            );
            cleanup_pending = true;
        }
    }

    emit_to_users(
        &channel_recipient_ids(&channel),
        "channel-avatar-updated",
        json!({ "channelId": channel_id, "image": key }),
    );
    HttpResponse::Ok().json(json!({
        "message": "Avatar updated",
        "image": key,
        "cleanupPending": cleanup_pending,
    }))
}

pub async fn leave_channel(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if channel.admin.to_hex() == user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Admin cannot leave channel. Delete instead." }));
    }

    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid user" }));
    };
    match Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! { "$pull": { "members": uid }, "$set": { "updatedAt": DateTime::now() } },
        )
        .await
    {
        Ok(r) if r.modified_count > 0 || r.matched_count > 0 => {}
        Ok(_) => {
            return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "message": "Failed to leave channel",
                "retryable": true,
            }));
        }
    }

    typing::invalidate_user_channel(&user_id, &cid.to_hex());

    typing::invalidate_channel(&cid.to_hex());

    let read_state_cleanup_failed =
        match crate::model::read_state::ChannelReadState::collection(&db)
            .delete_many(doc! { "userId": uid, "channelId": cid })
            .await
        {
            Ok(_) => false,
            Err(error) => {
                log::error!("Failed to clear channel read state on leave: {error}");
                true
            }
        };

    let channel_id = cid.to_hex();

    crate::utils::unread::invalidate_unread_generation(&user_id, "channel", &channel_id);
    crate::utils::unread::emit_unread_absolute(&user_id, "channel", &channel_id, 0);
    let participants = crate::utils::voice::channels::leave_channel_voice(&channel_id, &user_id);
    let mut remaining = channel_recipient_ids(&channel);
    remaining.retain(|r| r != &user_id);
    let member_count = remaining.len();
    crate::ws::registry::emit_to_users(
        &crate::ws::registry::channel_recipient_ids(&channel),
        "channel-voice:state",
        json!({
            "channelId": channel_id,
            "participants": participants,
        }),
    );
    emit_to_users(
        &remaining,
        "channel-member-left",
        json!({
            "channelId": channel_id,
            "userId": user_id,
            "memberCount": member_count,
        }),
    );

    emit_to_user(
        &user_id,
        "channel-left",
        json!({ "channelId": cid.to_hex() }),
    );
    if read_state_cleanup_failed {
        return HttpResponse::Ok().json(json!({
            "message": "Left channel",
            "cleanupPending": true,
        }));
    }
    HttpResponse::Ok().json(json!({
        "message": "Left channel",
        "cleanupPending": false,
    }))
}

#[derive(Deserialize)]
pub struct AddUserBody {
    #[serde(rename = "userIdToAdd")]
    pub user_id_to_add: Option<String>,
}

pub async fn add_user_to_channel(req: HttpRequest, body: web::Json<AddUserBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };
    let target = body.user_id_to_add.clone().unwrap_or_default();

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({ "message": "Only admin can add users" }));
    }

    if channel.members.iter().any(|m| m.to_hex() == target) {
        return HttpResponse::BadRequest().json(json!({ "message": "User is already a member" }));
    }

    if crate::utils::channel::is_channel_banned(&channel, Some(&target)) {
        return HttpResponse::Forbidden().json(json!({
            "message": "User is banned from this channel. Unban them before adding again."
        }));
    }

    if target != user_id {
        match try_are_friends(&db, &user_id, &target).await {
            Ok(true) => {}
            Ok(false) => {
                return HttpResponse::Forbidden().json(json!({
                    "message": "Możesz dodawać do kanału tylko swoich znajomych."
                }));
            }
            Err(()) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "message": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        }
    }

    let Ok(target_oid) = ObjectId::parse_str(&target) else {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Internal Server Error" }));
    };

    let already_member = channel.admin == target_oid || channel.members.contains(&target_oid);
    if !already_member {
        if let Err(error) =
            crate::model::read_state::ChannelReadState::reset_for_rejoin(&db, target_oid, cid).await
        {
            log::error!("Failed to reset channel read state before adding member: {error}");
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    }

    match Channel::collection(&db)
        .update_one(
            doc! { "_id": cid, "isDeleting": { "$ne": true } },
            doc! { "$addToSet": { "members": target_oid }, "$set": { "updatedAt": DateTime::now() } },
        )
        .await
    {
        Ok(result) if result.matched_count == 1 => {}
        Ok(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Channel deletion is in progress.",
                "retryable": true,
            }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "message": "Failed to add member",
                "retryable": true,
            }));
        }
    }

    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(ch)) => ch,
        Ok(None) | Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };
    match serialize_channel_list_item(&db, &channel, target_oid).await {
        Some(slim) => {
            emit_to_user(
                &target,
                "channel-added",
                json!({ "channelId": cid.to_hex(), "channel": slim }),
            );
        }
        None => {
            emit_to_user(
                &target,
                "channel-added",
                json!({ "channelId": cid.to_hex() }),
            );
        }
    }
    let mut peers = channel_recipient_ids(&channel);
    peers.retain(|r| r != &target);
    emit_to_users(
        &peers,
        "channel-member-joined",
        json!({
            "channelId": cid.to_hex(),
            "userId": target,
            "memberCount": channel_recipient_ids(&channel).len(),
        }),
    );
    typing::invalidate_channel(&cid.to_hex());
    HttpResponse::Ok().json(json!({ "message": "User added to channel" }))
}

pub async fn delete_channel(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Only admin can delete channel" }));
    }

    let channel_id = cid.to_hex();
    match Channel::collection(&db)
        .update_one(
            doc! { "_id": cid, "admin": channel.admin },
            doc! {
                "$set": {
                    "isDeleting": true,
                    "updatedAt": DateTime::now(),
                },
            },
        )
        .await
    {
        Ok(result) if result.matched_count == 1 => {}
        Ok(_) => {
            return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
        }
        Err(error) => {
            log::error!(
                "delete_channel: failed to mark channel {channel_id} for deletion: {error}"
            );
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Failed to begin channel deletion",
                "retryable": true,
            }));
        }
    }
    crate::utils::access::cache::invalidate_channel(&channel_id);
    typing::invalidate_channel(&channel_id);

    match crate::utils::channel::deletion::delete_channel(&db, cid).await {
        Ok(crate::utils::channel::deletion::ChannelDeletionOutcome::Deleted) => {
            HttpResponse::Ok().json(json!({ "message": "Channel deleted" }))
        }
        Ok(crate::utils::channel::deletion::ChannelDeletionOutcome::Busy) => {
            HttpResponse::ServiceUnavailable().json(json!({
                "message": "Channel deletion is already in progress.",
                "retryable": true,
            }))
        }
        Ok(crate::utils::channel::deletion::ChannelDeletionOutcome::Missing) => {
            HttpResponse::Ok().json(json!({ "message": "Channel deleted" }))
        }
        Err(error) => {
            log::error!("delete_channel: failed to delete channel {channel_id}: {error}");
            HttpResponse::ServiceUnavailable().json(json!({
                "message": "Channel deletion is pending and will be retried automatically.",
                "retryable": true,
            }))
        }
    }
}

pub async fn toggle_channel_mute(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound()
            .json(json!({ "message": "Kanał nie znaleziony lub brak dostępu" }));
    };

    let db = get_db();
    match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) if can_access_channel(&c, Some(&user_id)) => {}
        Ok(Some(_)) | Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({ "message": "Kanał nie znaleziony lub brak dostępu" }));
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

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

    let mut muted = user.muted_channels.clone();
    let is_muted;
    if let Some(pos) = muted.iter().position(|o| *o == cid) {
        muted.remove(pos);
        is_muted = false;
    } else {
        muted.push(cid);
        is_muted = true;
    }

    let muted_bson = match mongodb::bson::to_bson(&muted) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Internal Server Error" }));
        }
    };
    if User::set_fields(&db, uid, doc! { "mutedChannels": muted_bson })
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Internal Server Error" }));
    }

    HttpResponse::Ok().json(json!({
        "isMuted": is_muted,
        "message": if is_muted { "Kanał wyciszony" } else { "Wyciszenie wyłączone" },
    }))
}

#[derive(Deserialize)]
pub struct TargetUserBody {
    #[serde(rename = "userId")]
    pub user_id: Option<String>,

    #[serde(rename = "durationSeconds")]
    pub duration_seconds: Option<u64>,
}

pub async fn kick_channel_member(
    req: HttpRequest,
    body: web::Json<TargetUserBody>,
) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let target = body.user_id.clone().unwrap_or_default();
    if target.is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Brak identyfikatora użytkownika" }));
    }
    let Ok(target_oid) = ObjectId::parse_str(&target) else {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nieprawidłowy identyfikator użytkownika" }));
    };
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if !is_channel_admin(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Tylko twórca kanału może wyrzucać członków" }));
    }
    if channel.admin.to_hex() == target {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nie można wyrzucić twórcy kanału" }));
    }

    match Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! {
                "$pull": { "members": target_oid },
                "$set": { "updatedAt": DateTime::now() },
            },
        )
        .await
    {
        Ok(_) => {}
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "message": "Failed to kick member",
                "retryable": true,
            }));
        }
    }

    let moderation_cleanup_failed = match moderation::pull_muted_member(&db, cid, target_oid).await
    {
        Ok(()) => false,
        Err(error) => {
            log::error!("Failed to clear channel mute after kick: {error}");
            true
        }
    };

    emit_to_user(
        &target,
        "channel-left",
        json!({ "channelId": cid.to_hex() }),
    );
    typing::invalidate_channel(&cid.to_hex());
    crate::utils::access::cache::invalidate_channel(&cid.to_hex());

    let read_state_cleanup_failed =
        match crate::model::read_state::ChannelReadState::collection(&db)
            .delete_many(doc! { "userId": target_oid, "channelId": cid })
            .await
        {
            Ok(_) => false,
            Err(error) => {
                log::error!("Failed to clear channel read state after member kick: {error}");
                true
            }
        };

    let channel_id = cid.to_hex();
    crate::utils::unread::invalidate_unread_generation(&target, "channel", &channel_id);
    crate::utils::unread::emit_unread_absolute(&target, "channel", &channel_id, 0);
    let participants = crate::utils::voice::channels::leave_channel_voice(&channel_id, &target);

    let mut recipients = channel_recipient_ids(&channel);
    if !recipients.iter().any(|r| r == &target) {
        recipients.push(target.clone());
    }
    emit_to_users(
        &recipients,
        "channel-voice:state",
        json!({
            "channelId": channel_id,
            "participants": participants,
        }),
    );
    let mut remaining = channel_recipient_ids(&channel);
    remaining.retain(|r| r != &target);
    emit_to_users(
        &remaining,
        "channel-member-left",
        json!({
            "channelId": channel_id,
            "userId": target,
            "memberCount": remaining.len(),
        }),
    );

    HttpResponse::Ok().json(json!({
        "message": "Użytkownik wyrzucony z kanału",
        "cleanupPending": read_state_cleanup_failed || moderation_cleanup_failed,
    }))
}

pub async fn ban_channel_member(req: HttpRequest, body: web::Json<TargetUserBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let target = body.user_id.clone().unwrap_or_default();
    if target.is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Brak identyfikatora użytkownika" }));
    }
    let Ok(target_oid) = ObjectId::parse_str(&target) else {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nieprawidłowy identyfikator użytkownika" }));
    };
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if !is_channel_admin(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Tylko twórca kanału może banować" }));
    }
    if channel.admin.to_hex() == target {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nie można zbanować twórcy kanału" }));
    }

    let entry = moderation::build_moderation_entry(target_oid, body.duration_seconds);

    if moderation::upsert_banned_member(&db, cid, entry)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({
            "message": "Failed to ban member",
            "retryable": true,
        }));
    }
    match Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! {
                "$pull": { "members": target_oid },
                "$set": { "updatedAt": DateTime::now() },
            },
        )
        .await
    {
        Ok(_) => {}
        Err(_) => {
            let mut compensated = false;
            for _ in 0..3 {
                if moderation::pull_banned_member(&db, cid, target_oid)
                    .await
                    .is_ok()
                {
                    compensated = true;
                    break;
                }
            }
            if !compensated {
                log::error!(
                    "ban compensate failed channel={} target={}",
                    cid.to_hex(),
                    target_oid.to_hex()
                );
            }
            return HttpResponse::InternalServerError().json(json!({
                "message": "Failed to ban member",
                "retryable": true,
            }));
        }
    }

    let moderation_cleanup_failed = match moderation::pull_muted_member(&db, cid, target_oid).await
    {
        Ok(()) => false,
        Err(error) => {
            log::error!("Failed to clear channel mute after ban: {error}");
            true
        }
    };

    emit_to_user(
        &target,
        "channel-left",
        json!({ "channelId": cid.to_hex() }),
    );
    typing::invalidate_channel(&cid.to_hex());
    crate::utils::access::cache::invalidate_channel(&cid.to_hex());
    let read_state_cleanup_failed =
        match crate::model::read_state::ChannelReadState::collection(&db)
            .delete_many(doc! { "userId": target_oid, "channelId": cid })
            .await
        {
            Ok(_) => false,
            Err(error) => {
                log::error!("Failed to clear channel read state after member ban: {error}");
                true
            }
        };
    let channel_id = cid.to_hex();
    crate::utils::unread::invalidate_unread_generation(&target, "channel", &channel_id);
    crate::utils::unread::emit_unread_absolute(&target, "channel", &channel_id, 0);
    let participants = crate::utils::voice::channels::leave_channel_voice(&channel_id, &target);
    let mut recipients = channel_recipient_ids(&channel);
    if !recipients.iter().any(|r| r == &target) {
        recipients.push(target.clone());
    }
    emit_to_users(
        &recipients,
        "channel-voice:state",
        json!({
            "channelId": channel_id,
            "participants": participants,
        }),
    );
    let mut remaining = channel_recipient_ids(&channel);
    remaining.retain(|r| r != &target);
    emit_to_users(
        &remaining,
        "channel-member-left",
        json!({
            "channelId": channel_id,
            "userId": target,
            "memberCount": remaining.len(),
        }),
    );
    let lists = get_channel_ban_mute_lists(&db, cid, &user_id).await;
    HttpResponse::Ok().json(json!({
        "message": "Użytkownik zbanowany na kanale",
        "bannedMembers": lists.as_ref().map(|(banned, _)| banned),
        "mutedMembers": lists.as_ref().map(|(_, muted)| muted),
        "cleanupPending": read_state_cleanup_failed
            || moderation_cleanup_failed
            || lists.is_none(),
    }))
}

pub async fn unban_channel_member(
    req: HttpRequest,
    body: web::Json<TargetUserBody>,
) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let target = body.user_id.clone().unwrap_or_default();
    if target.is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Brak identyfikatora użytkownika" }));
    }
    let Ok(target_oid) = ObjectId::parse_str(&target) else {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nieprawidłowy identyfikator użytkownika" }));
    };
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if !is_channel_admin(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Tylko twórca kanału może odbanować" }));
    }

    if moderation::pull_banned_member(&db, cid, target_oid)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({
            "message": "Failed to unban member",
            "retryable": true,
        }));
    }

    typing::invalidate_channel(&cid.to_hex());
    crate::utils::access::cache::invalidate_channel(&cid.to_hex());

    let lists = get_channel_ban_mute_lists(&db, cid, &user_id).await;
    HttpResponse::Ok().json(json!({
        "message": "Ban użytkownika cofnięty",
        "bannedMembers": lists.as_ref().map(|(banned, _)| banned),
        "mutedMembers": lists.as_ref().map(|(_, muted)| muted),
        "cleanupPending": lists.is_none(),
    }))
}

pub async fn mute_channel_member(
    req: HttpRequest,
    body: web::Json<TargetUserBody>,
) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let target = body.user_id.clone().unwrap_or_default();
    if target.is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Brak identyfikatora użytkownika" }));
    }
    let Ok(target_oid) = ObjectId::parse_str(&target) else {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nieprawidłowy identyfikator użytkownika" }));
    };
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if !is_channel_admin(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Tylko twórca kanału może wyciszać członków" }));
    }
    if channel.admin.to_hex() == target {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nie można wyciszyć twórcy kanału" }));
    }
    if !is_channel_member(&channel, Some(&target)) {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Użytkownik nie jest na kanale" }));
    }

    let entry = moderation::build_moderation_entry(target_oid, body.duration_seconds);
    if moderation::upsert_muted_member(&db, cid, entry.clone())
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({
            "message": "Failed to mute member",
            "retryable": true,
        }));
    }

    let moderation_cleanup_failed = match moderation::pull_banned_member(&db, cid, target_oid).await
    {
        Ok(()) => false,
        Err(error) => {
            log::error!("Failed to clear channel ban after mute: {error}");
            true
        }
    };

    let muted_here_expires_at = entry
        .expires_at
        .as_ref()
        .and_then(|dt| dt.try_to_rfc3339_string().ok());

    emit_to_user(
        &target,
        "channel-moderation-updated",
        json!({
            "channelId": cid.to_hex(),
            "isMutedHere": true,
            "mutedHereExpiresAt": muted_here_expires_at,
        }),
    );
    typing::invalidate_channel(&cid.to_hex());
    crate::utils::access::cache::invalidate_channel(&cid.to_hex());

    let lists = get_channel_ban_mute_lists(&db, cid, &user_id).await;
    HttpResponse::Ok().json(json!({
        "message": "Użytkownik wyciszony na kanale",
        "bannedMembers": lists.as_ref().map(|(banned, _)| banned),
        "mutedMembers": lists.as_ref().map(|(_, muted)| muted),
        "cleanupPending": moderation_cleanup_failed || lists.is_none(),
    }))
}

pub async fn unmute_channel_member(
    req: HttpRequest,
    body: web::Json<TargetUserBody>,
) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let target = body.user_id.clone().unwrap_or_default();
    if target.is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Brak identyfikatora użytkownika" }));
    }
    let Ok(target_oid) = ObjectId::parse_str(&target) else {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nieprawidłowy identyfikator użytkownika" }));
    };
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if !is_channel_admin(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Tylko twórca kanału może cofnąć wyciszenie" }));
    }

    if moderation::pull_muted_member(&db, cid, target_oid)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({
            "message": "Failed to unmute member",
            "retryable": true,
        }));
    }

    emit_to_user(
        &target,
        "channel-moderation-updated",
        json!({
            "channelId": cid.to_hex(),
            "isMutedHere": false,
            "mutedHereExpiresAt": Value::Null,
        }),
    );
    typing::invalidate_channel(&cid.to_hex());
    crate::utils::access::cache::invalidate_channel(&cid.to_hex());

    let lists = get_channel_ban_mute_lists(&db, cid, &user_id).await;
    HttpResponse::Ok().json(json!({
        "message": "Wyciszenie użytkownika cofnięte",
        "bannedMembers": lists.as_ref().map(|(banned, _)| banned),
        "mutedMembers": lists.as_ref().map(|(_, muted)| muted),
        "cleanupPending": lists.is_none(),
    }))
}

#[derive(Deserialize)]
pub struct ReportBody {
    pub reason: Option<String>,
    pub details: Option<String>,
}

pub async fn report_channel(req: HttpRequest, body: web::Json<ReportBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let reason = body.reason.clone().unwrap_or_default();
    let reason_trimmed = reason.trim();
    if reason_trimmed.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "message": "Podaj powód zgłoszenia" }));
    }
    if !REPORT_REASONS.contains(&reason_trimmed) {
        return HttpResponse::BadRequest().json(json!({
            "message": "Nieprawidłowy powód zgłoszenia",
            "reasons": REPORT_REASONS,
        }));
    }
    let details = body
        .details
        .as_deref()
        .unwrap_or("")
        .trim()
        .chars()
        .take(1000)
        .collect::<String>();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    if !is_channel_member(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Musisz być na kanale, aby go zgłosić" }));
    }

    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" }));
    };
    let reporter = match User::find_by_id(&db, uid).await {
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

    let input = CreateChannelReportInput {
        channel_id: cid,
        channel_name: channel.name.clone(),
        reported_by: uid,
        reporter_username: reporter.username.clone(),
        reason: reason_trimmed.to_string(),
        details: if details.is_empty() {
            None
        } else {
            Some(details)
        },
    };

    match ChannelReport::create(&db, input).await {
        Ok(_) => HttpResponse::Created().json(json!({
            "message": "Zgłoszenie zostało wysłane do panelu administratora",
            "reasons": REPORT_REASONS,
        })),
        Err(_) => {
            HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }))
        }
    }
}
