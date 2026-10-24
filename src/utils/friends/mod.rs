// mod.rs
// Czy para może DM (friend vs block).
// Zakres:
//  - brak dokumentu = not blocked
//  - czy para może DM; brak dokumentu = not blocked
// Wołane z WS send — cache'uj w friends/cache.rs.
// Przy zmianach: access/members.rs, handlers send.

use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::Database;
use serde_json::{json, Value};
use std::collections::HashSet;

use crate::model::friend_requests::FriendRequest;
use crate::model::users::User;
use crate::utils::friends::cache::{
    get_cached_block_pair, get_cached_friend_ids, get_cached_friend_set, put_cached_friend_ids,
};
use crate::utils::user::json::resolve_display_name;

pub mod cache;

pub use cache::{
    invalidate_block_pair, invalidate_block_pair_for_user, invalidate_friend_ids_cache,
    invalidate_friend_ids_pair,
};

pub async fn try_dm_block_flags(
    db: &Database,
    viewer: &str,
    peer: &str,
) -> Result<(bool, bool), ()> {
    if viewer.is_empty() || peer.is_empty() || viewer == peer {
        return Ok((false, false));
    }
    if let Some(flags) = crate::utils::friends::cache::get_cached_block_flags(viewer, peer) {
        return Ok(flags);
    }
    let (Ok(u1), Ok(u2)) = (ObjectId::parse_str(viewer), ObjectId::parse_str(peer)) else {
        return Ok((false, false));
    };

    use mongodb::bson::Document;

    let coll = db.collection::<Document>("users");
    let cursor = coll
        .find(doc! { "_id": { "$in": [u1, u2] } })
        .projection(doc! { "_id": 1, "blockedContacts": 1 })
        .await
        .map_err(|_| ())?;
    let docs: Vec<Document> = cursor.try_collect().await.map_err(|_| ())?;
    if docs.len() < 2 {
        crate::utils::friends::cache::put_cached_block_flags(viewer, peer, false, false);
        return Ok((false, false));
    }

    let blocks = |doc: &Document, other: ObjectId| -> bool {
        doc.get_array("blockedContacts")
            .ok()
            .map(|arr| {
                arr.iter()
                    .any(|b| b.as_object_id().map(|id| id == other).unwrap_or(false))
            })
            .unwrap_or(false)
    };

    let mut viewer_blocks = false;
    let mut peer_blocks = false;
    for doc in &docs {
        let Ok(id) = doc.get_object_id("_id") else {
            continue;
        };
        if id == u1 {
            viewer_blocks = blocks(doc, u2);
        } else if id == u2 {
            peer_blocks = blocks(doc, u1);
        }
    }
    crate::utils::friends::cache::put_cached_block_flags(viewer, peer, viewer_blocks, peer_blocks);
    Ok((viewer_blocks, peer_blocks))
}

pub async fn try_is_dm_blocked(db: &Database, user_id1: &str, user_id2: &str) -> Result<bool, ()> {
    if let Some(blocked) = get_cached_block_pair(user_id1, user_id2) {
        return Ok(blocked);
    }
    let (a, b) = try_dm_block_flags(db, user_id1, user_id2).await?;
    Ok(a || b)
}

pub async fn are_friends(db: &Database, user_id1: &str, user_id2: &str) -> bool {
    matches!(try_are_friends(db, user_id1, user_id2).await, Ok(true))
}

pub async fn try_are_friends(db: &Database, user_id1: &str, user_id2: &str) -> Result<bool, ()> {
    if user_id1.is_empty() || user_id2.is_empty() || user_id1 == user_id2 {
        return Ok(false);
    }
    if let Some(set) = get_cached_friend_set(user_id1) {
        return Ok(set.contains(user_id2));
    }
    match load_friend_ids_uncached(db, user_id1).await {
        Ok(ids) => {
            put_cached_friend_ids(user_id1, ids.clone());
            Ok(ids.iter().any(|id| id == user_id2))
        }
        Err(_) => match load_friend_ids_uncached(db, user_id1).await {
            Ok(ids) => {
                put_cached_friend_ids(user_id1, ids.clone());
                Ok(ids.iter().any(|id| id == user_id2))
            }
            Err(_) => Err(()),
        },
    }
}

pub async fn try_friend_ids(db: &Database, user_id: &str) -> Result<Vec<String>, ()> {
    if let Some(cached) = get_cached_friend_ids(user_id) {
        return Ok(cached);
    }

    match load_friend_ids_uncached(db, user_id).await {
        Ok(ids) => {
            put_cached_friend_ids(user_id, ids.clone());
            Ok(ids)
        }
        Err(_) => match load_friend_ids_uncached(db, user_id).await {
            Ok(ids) => {
                put_cached_friend_ids(user_id, ids.clone());
                Ok(ids)
            }
            Err(_) => Err(()),
        },
    }
}

async fn load_friend_ids_uncached(db: &Database, user_id: &str) -> Result<Vec<String>, ()> {
    let Ok(uid) = ObjectId::parse_str(user_id) else {
        return Ok(Vec::new());
    };

    let filter = doc! {
        "status": "accepted",
        "$or": [ { "from": uid }, { "to": uid } ],
    };

    let cursor = match FriendRequest::collection(db).find(filter).await {
        Ok(c) => c,
        Err(_) => return Err(()),
    };

    let requests: Vec<FriendRequest> = match cursor.try_collect().await {
        Ok(r) => r,
        Err(_) => return Err(()),
    };

    Ok(requests
        .into_iter()
        .filter_map(|r| {
            let other = if r.from == uid { r.to } else { r.from };
            if other == uid {
                None
            } else {
                Some(other.to_hex())
            }
        })
        .collect())
}

pub async fn emit_to_friends(db: &Database, user_id: &str, event: &str, data: Value) {
    if let Some(cached) = get_cached_friend_ids(user_id) {
        if !cached.is_empty() {
            crate::ws::registry::emit_to_users(&cached, event, data);
        }
        return;
    }
    match load_friend_ids_uncached(db, user_id).await {
        Ok(ids) => {
            put_cached_friend_ids(user_id, ids.clone());
            if !ids.is_empty() {
                crate::ws::registry::emit_to_users(&ids, event, data);
            }
        }
        Err(_) => match load_friend_ids_uncached(db, user_id).await {
            Ok(ids) => {
                put_cached_friend_ids(user_id, ids.clone());
                if !ids.is_empty() {
                    crate::ws::registry::emit_to_users(&ids, event, data);
                }
            }
            Err(_) => {
                log::warn!("emit_to_friends: friend list unavailable for {user_id}");
            }
        },
    }
}

pub async fn emit_profile_event(db: &Database, user_id: &str, event: &str, data: Value) {
    crate::ws::registry::emit_to_user(user_id, event, data.clone());
    emit_to_friends(db, user_id, event, data).await;
}

pub async fn emit_status_event(db: &Database, user_id: &str, data: Value) {
    let Ok(user_oid) = ObjectId::parse_str(user_id) else {
        log::warn!("emit_status_event received invalid user id");
        return;
    };
    let user = match User::find_by_id(db, user_oid).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            log::warn!("emit_status_event could not find user {user_id}");
            return;
        }
        Err(error) => {
            log::error!("emit_status_event user lookup failed for {user_id}: {error}");
            crate::ws::registry::emit_to_user(user_id, "user-status-changed", data);
            return;
        }
    };

    let own_status = crate::utils::user::presence::presence_payload(&user, user_id, true);
    crate::ws::registry::emit_to_user(
        user_id,
        "user-status-changed",
        json!({ "userId": user_id, "status": own_status }),
    );

    let friend_ids: HashSet<String> = match try_friend_ids(db, user_id).await {
        Ok(ids) => ids.into_iter().collect(),
        Err(()) => {
            log::warn!("emit_status_event could not load friends for {user_id}");
            HashSet::new()
        }
    };
    let mut visible_recipients = Vec::new();
    let mut hidden_recipients = Vec::new();
    let connected_ids = crate::ws::registry::connected_user_ids().await;
    for viewer_id in connected_ids {
        if viewer_id == user_id {
            continue;
        }
        let is_friend = friend_ids.contains(&viewer_id);
        if crate::utils::user::presence::can_view_presence(&user, &viewer_id, is_friend) {
            visible_recipients.push(viewer_id);
        } else {
            hidden_recipients.push(viewer_id);
        }
    }
    if let Some(viewer_id) = visible_recipients.first() {
        let status = crate::utils::user::presence::presence_payload(
            &user,
            viewer_id,
            friend_ids.contains(viewer_id),
        );
        crate::ws::registry::emit_to_users(
            &visible_recipients,
            "user-status-changed",
            json!({ "userId": user_id, "status": status }),
        );
    }
    if let Some(viewer_id) = hidden_recipients.first() {
        let status = crate::utils::user::presence::presence_payload(
            &user,
            viewer_id,
            friend_ids.contains(viewer_id),
        );
        crate::ws::registry::emit_to_users(
            &hidden_recipients,
            "user-status-changed",
            json!({ "userId": user_id, "status": status }),
        );
    }
}

pub fn map_friend_user(user: &User) -> Value {
    json!({
        "_id": user.id.map(|o| o.to_hex()).unwrap_or_default(),
        "username": user.username,
        "displayName": resolve_display_name(user),
        "bio": user.bio,
        "image": user.image,
        "banner": user.banner,
        "color": user.color,
        "createdAt": user.created_at.try_to_rfc3339_string().ok(),
    })
}
