// mod.rs
// Tip/unread denorm kanału, fill przed zaufaniem unread 0.
// Zakres:
//  - roster helpers
//  - tip/unread denorm; fill zanim zaufasz unread 0
// Nie ufaj unread 0 gdy tip jest dziurawy — najpierw fill.
// Przy zmianach: controllers/channels.rs, tips.rs, unread/mod.rs.

use std::collections::{HashMap, HashSet};

use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::Database;
use serde_json::{json, Value};

use crate::model::channel_moderation::has_active_entry;
use crate::model::channels::Channel;
use crate::model::messages::Message;
use crate::model::read_state::ChannelReadState;
use crate::model::users::User;
use crate::utils::user::json::resolve_display_name;

pub mod deletion;
pub mod moderation;

pub fn channel_member_count(channel: &Channel) -> usize {
    let mut ids = HashSet::with_capacity(channel.members.len() + 1);
    ids.insert(channel.admin);
    for m in &channel.members {
        ids.insert(*m);
    }
    ids.len()
}

pub fn is_channel_admin(channel: &Channel, user_id: Option<&str>) -> bool {
    if channel.is_deleting {
        return false;
    }
    match user_id {
        Some(uid) if !uid.is_empty() => channel.admin.to_hex() == uid,
        _ => false,
    }
}

pub fn is_channel_member(channel: &Channel, user_id: Option<&str>) -> bool {
    if channel.is_deleting {
        return false;
    }
    let Some(uid) = user_id.filter(|u| !u.is_empty()) else {
        return false;
    };
    if is_channel_admin(channel, Some(uid)) {
        return true;
    }
    channel.members.iter().any(|m| m.to_hex() == uid)
}

pub fn is_channel_banned(channel: &Channel, user_id: Option<&str>) -> bool {
    let Some(uid) = user_id.filter(|u| !u.is_empty()) else {
        return false;
    };
    has_active_entry(&channel.banned_members, uid)
}

pub fn is_channel_muted_member(channel: &Channel, user_id: Option<&str>) -> bool {
    let Some(uid) = user_id.filter(|u| !u.is_empty()) else {
        return false;
    };
    has_active_entry(&channel.muted_members, uid)
}

pub fn can_access_channel(channel: &Channel, user_id: Option<&str>) -> bool {
    !channel.is_deleting
        && is_channel_member(channel, user_id)
        && !is_channel_banned(channel, user_id)
}

pub async fn channel_read_state_user_ids(
    db: &Database,
    channel_id: ObjectId,
) -> mongodb::error::Result<Vec<String>> {
    let states: Vec<ChannelReadState> = ChannelReadState::collection(db)
        .find(doc! { "channelId": channel_id })
        .await?
        .try_collect()
        .await?;
    Ok(states
        .into_iter()
        .map(|state| state.user_id.to_hex())
        .collect())
}

pub fn is_channel_chat_locked_for_sender(channel: &Channel, sender_id: &str) -> bool {
    channel.chat_locked && channel.admin.to_hex() != sender_id
}

fn user_to_list_admin(db_value: Option<&Value>, admin_id: ObjectId) -> Value {
    db_value
        .cloned()
        .unwrap_or_else(|| json!({ "_id": admin_id.to_hex() }))
}

pub async fn serialize_channel_list_item(
    db: &Database,
    channel: &Channel,
    viewer_id: ObjectId,
) -> Option<Value> {
    let admin_map = fetch_users_map_slim(db, &[channel.admin]).await;
    let admin = user_to_list_admin(admin_map.get(&channel.admin), channel.admin);
    let ch_id = channel.id.map(|o| o.to_hex()).unwrap_or_default();
    let is_muted = match User::find_by_id(db, viewer_id).await {
        Ok(Some(u)) => u.muted_channels.iter().any(|id| Some(*id) == channel.id),
        Ok(None) => return None,
        Err(error) => {
            log::error!(
                "Failed to load viewer {} while serializing channel {}: {error}",
                viewer_id.to_hex(),
                channel.id.map(|id| id.to_hex()).unwrap_or_default()
            );
            return None;
        }
    };
    let (unread, last) = enrich_channel_unread(db, viewer_id, channel).await?;

    Some(json!({
        "_id": ch_id,
        "name": channel.name,
        "description": channel.description,
        "image": channel.image,
        "admin": admin,
        "members": Vec::<Value>::new(),
        "memberCount": channel_member_count(channel),
        "messages": Vec::<String>::new(),
        "isPrivate": channel.is_private,
        "createdAt": channel.created_at.try_to_rfc3339_string().ok(),
        "updatedAt": channel.updated_at.try_to_rfc3339_string().ok(),
        "unreadCount": unread,
        "lastMessage": last.as_ref().map(|(_, c, _)| c.clone()),
        "lastMessageTime": last.as_ref().and_then(|(t, _, _)| t.try_to_rfc3339_string().ok()),
        "lastMessageId": last.as_ref().map(|(_, _, id)| id.to_hex()),
        "isMuted": is_muted,
        "isMutedHere": is_channel_muted_member(channel, Some(&viewer_id.to_hex())),
        "mutedHereExpiresAt": crate::utils::channel::moderation::viewer_mute_expires_at(
            channel,
            &viewer_id.to_hex(),
        ),
        "rateLimitPerUser": channel.rate_limit_per_user,
        "chatLocked": channel.chat_locked,
    }))
}

fn user_to_channel_json(user: &User) -> Value {
    json!({
        "_id": user.id.map(|o| o.to_hex()),
        "username": user.username,
        "displayName": resolve_display_name(user),
        "bio": user.bio,
        "image": user.image,
        "banner": user.banner,
        "color": user.color,
        "isOnline": user.is_online,
        "lastSeen": user.last_seen.as_ref().and_then(|d| d.try_to_rfc3339_string().ok()),
    })
}

fn user_to_channel_json_slim(user: &User) -> Value {
    json!({
        "_id": user.id.map(|o| o.to_hex()),
        "username": user.username,
        "displayName": resolve_display_name(user),
        "image": user.image,
        "color": user.color,
    })
}

pub async fn fetch_users_map_slim(db: &Database, ids: &[ObjectId]) -> HashMap<ObjectId, Value> {
    let mut seen = HashSet::new();
    let unique: Vec<ObjectId> = ids.iter().copied().filter(|id| seen.insert(*id)).collect();
    let mut out = HashMap::with_capacity(unique.len());
    if unique.is_empty() {
        return out;
    }

    let users_result = match User::collection(db)
        .find(doc! { "_id": { "$in": &unique } })
        .await
    {
        Ok(cursor) => match cursor.try_collect::<Vec<User>>().await {
            Ok(users) => Ok(users),
            Err(error) => Err(format!("decode channel list users: {error}")),
        },
        Err(error) => Err(format!("query channel list users: {error}")),
    };
    let users = match users_result {
        Ok(users) => users,
        Err(error) => {
            log::error!("{error}");
            for id in unique {
                out.insert(id, json!({ "_id": id.to_hex(), "unavailable": true }));
            }
            return out;
        }
    };

    let mut found = HashSet::new();
    for user in &users {
        let Some(id) = user.id else { continue };
        found.insert(id);
        out.insert(id, user_to_channel_json_slim(user));
    }
    for id in unique {
        if !found.contains(&id) {
            out.insert(id, json!({ "_id": id.to_hex() }));
        }
    }
    out
}

pub async fn populate_channel_user(db: &Database, id: ObjectId) -> Value {
    match User::find_by_id(db, id).await {
        Ok(Some(u)) => user_to_channel_json(&u),
        Ok(None) => json!({ "_id": id.to_hex() }),
        Err(error) => {
            log::error!("Failed to load channel user {}: {error}", id.to_hex());
            json!({ "_id": id.to_hex(), "unavailable": true })
        }
    }
}

pub async fn fetch_users_map(db: &Database, ids: &[ObjectId]) -> HashMap<ObjectId, Value> {
    let mut seen = HashSet::new();
    let unique: Vec<ObjectId> = ids.iter().copied().filter(|id| seen.insert(*id)).collect();
    let mut out = HashMap::with_capacity(unique.len());
    if unique.is_empty() {
        return out;
    }

    let users_result = match User::collection(db)
        .find(doc! { "_id": { "$in": &unique } })
        .await
    {
        Ok(cursor) => match cursor.try_collect::<Vec<User>>().await {
            Ok(users) => Ok(users),
            Err(error) => Err(format!("decode channel users: {error}")),
        },
        Err(error) => Err(format!("query channel users: {error}")),
    };
    let users = match users_result {
        Ok(users) => users,
        Err(error) => {
            log::error!("{error}");
            for id in unique {
                out.insert(id, json!({ "_id": id.to_hex(), "unavailable": true }));
            }
            return out;
        }
    };

    let mut found = HashSet::new();
    for user in &users {
        let Some(id) = user.id else { continue };
        found.insert(id);
        out.insert(id, user_to_channel_json(user));
    }
    for id in unique {
        if !found.contains(&id) {
            out.insert(id, json!({ "_id": id.to_hex() }));
        }
    }
    out
}

pub async fn fetch_users_by_refs(db: &Database, ids: &[ObjectId]) -> Vec<Value> {
    let mut seen = HashSet::new();
    let unique: Vec<ObjectId> = ids.iter().copied().filter(|id| seen.insert(*id)).collect();
    if unique.is_empty() {
        return Vec::new();
    }
    let map = fetch_users_map(db, &unique).await;
    unique
        .into_iter()
        .map(|id| {
            map.get(&id)
                .cloned()
                .unwrap_or_else(|| json!({ "_id": id.to_hex() }))
        })
        .collect()
}

pub async fn get_channel_ban_mute_lists(
    db: &Database,
    channel_id: ObjectId,
) -> Option<(Vec<Value>, Vec<Value>)> {
    moderation::get_channel_ban_mute_lists(db, channel_id).await
}

pub async fn enrich_channel_unread(
    db: &Database,
    user_id: ObjectId,
    channel: &Channel,
) -> Option<(u64, Option<(DateTime, String, ObjectId)>)> {
    let Some(channel_id) = channel.id else {
        return Some((0, None));
    };

    let tip = match (
        channel.last_message_at,
        channel.last_message.as_ref(),
        channel.last_message_id,
    ) {
        (Some(ts), Some(preview), Some(mid)) => Some((ts, preview.clone(), mid)),
        _ => {
            match Message::collection(db)
                .find(doc! { "channel": channel_id, "deleted": { "$ne": true } })
                .sort(doc! { "timestamp": -1, "_id": -1 })
                .limit(1)
                .await
            {
                Ok(mut cursor) => match cursor.try_next().await {
                    Ok(Some(m)) => {
                        let content = crate::utils::messages::storage::content_for_api_async(
                            m.content.clone(),
                        )
                        .await;
                        m.id.map(|id| (m.timestamp, content, id))
                    }
                    Ok(None) => None,
                    Err(error) => {
                        log::error!(
                            "Failed to read latest message for channel {}: {error}",
                            channel_id.to_hex()
                        );
                        return None;
                    }
                },
                Err(error) => {
                    log::error!(
                        "Failed to query latest message for channel {}: {error}",
                        channel_id.to_hex()
                    );
                    return None;
                }
            }
        }
    };

    let state = match ChannelReadState::find(db, user_id, channel_id).await {
        Ok(s) => s,
        Err(error) => {
            log::error!(
                "Failed to load read state for user {} in channel {}: {error}",
                user_id.to_hex(),
                channel_id.to_hex()
            );
            return None;
        }
    };

    let unread = if let Some(ref s) = state {
        let effective = if s.last_read_at.timestamp_millis() <= 0 {
            s.created_at
        } else {
            s.last_read_at
        };
        let tip_ts = tip.as_ref().map(|(ts, _, _)| *ts);
        let behind_tip =
            tip_ts.is_some_and(|ts| effective.timestamp_millis() < ts.timestamp_millis());
        let stale_high = s.unread_count > 0
            && tip_ts.is_some_and(|ts| effective.timestamp_millis() >= ts.timestamp_millis());

        if s.unread_count > 0 && !stale_high && !behind_tip {
            s.unread_count
        } else if s.unread_count == 0 && !behind_tip && tip.is_none() {
            0
        } else {
            match crate::utils::unread::try_count_channel_unread(db, user_id, channel_id).await {
                Some(n) => n,
                None if s.unread_count > 0 => s.unread_count,
                None => {
                    log::error!(
                        "Failed to calculate unread count for user {} in channel {}",
                        user_id.to_hex(),
                        channel_id.to_hex()
                    );
                    return None;
                }
            }
        }
    } else if tip.is_some() {
        match crate::utils::unread::try_count_channel_unread(db, user_id, channel_id).await {
            Some(count) => count,
            None => {
                log::error!(
                    "Failed to calculate unread count for user {} in channel {} without a read state",
                    user_id.to_hex(),
                    channel_id.to_hex()
                );
                return None;
            }
        }
    } else {
        0
    };

    Some((unread, tip))
}

pub async fn enrich_channels_batch(
    db: &Database,
    user_id: ObjectId,
    channels: &[Channel],
) -> Option<HashMap<ObjectId, (u64, Option<(DateTime, String, ObjectId)>)>> {
    let channel_ids: Vec<ObjectId> = channels.iter().filter_map(|c| c.id).collect();
    let mut out: HashMap<ObjectId, (u64, Option<(DateTime, String, ObjectId)>)> = HashMap::new();
    for id in &channel_ids {
        out.insert(*id, (0, None));
    }
    if channel_ids.is_empty() {
        return Some(out);
    }

    let mut missing_tip: Vec<ObjectId> = Vec::new();
    for ch in channels {
        let Some(id) = ch.id else { continue };
        match (
            ch.last_message_at,
            ch.last_message.as_ref(),
            ch.last_message_id,
        ) {
            (Some(ts), Some(preview), Some(mid)) => {
                if let Some(entry) = out.get_mut(&id) {
                    entry.1 = Some((ts, preview.clone(), mid));
                }
            }
            _ => missing_tip.push(id),
        }
    }

    if !missing_tip.is_empty() {
        let last_pipeline = vec![
            doc! {
                "$match": {
                    "channel": { "$in": &missing_tip },
                    "deleted": { "$ne": true },
                }
            },
            doc! { "$sort": { "timestamp": -1, "_id": -1 } },
            doc! {
                "$group": {
                    "_id": "$channel",
                    "timestamp": { "$first": "$timestamp" },
                    "content": { "$first": "$content" },
                    "messageId": { "$first": "$_id" },
                }
            },
        ];
        match Message::collection(db).aggregate(last_pipeline).await {
            Ok(mut cursor) => {
                let mut filled: HashMap<ObjectId, (DateTime, String, ObjectId)> = HashMap::new();
                loop {
                    match cursor.try_next().await {
                        Ok(Some(doc)) => {
                            let Ok(cid) = doc.get_object_id("_id") else {
                                continue;
                            };
                            let ts = doc.get_datetime("timestamp").ok().copied();
                            let content = doc
                                .get_str("content")
                                .ok()
                                .map(crate::utils::messages::storage::content_for_api);
                            let mid = doc.get_object_id("messageId").ok();
                            if let (Some(ts), Some(content), Some(mid)) = (ts, content, mid) {
                                filled.insert(cid, (ts, content, mid));
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            log::error!("Failed to read latest channel messages: {error}");
                            return None;
                        }
                    }
                }
                for (cid, tip) in filled {
                    if let Some(entry) = out.get_mut(&cid) {
                        entry.1 = Some(tip);
                    }
                }
            }
            Err(error) => {
                log::error!("Failed to query latest channel messages: {error}");
                return None;
            }
        }
    }

    let mut last_reads: HashMap<ObjectId, DateTime> = HashMap::new();
    let mut missing_unread: Vec<ObjectId> = Vec::new();
    match ChannelReadState::collection(db)
        .find(doc! { "userId": user_id, "channelId": { "$in": &channel_ids } })
        .await
    {
        Ok(cursor) => {
            let states: Vec<ChannelReadState> = match cursor.try_collect().await {
                Ok(s) => s,
                Err(error) => {
                    log::error!("Failed to decode channel read states: {error}");
                    return None;
                }
            };
            for s in states {
                let effective = if s.last_read_at.timestamp_millis() <= 0 {
                    s.created_at
                } else {
                    s.last_read_at
                };
                last_reads.insert(s.channel_id, effective);
                let tip_ts = out
                    .get(&s.channel_id)
                    .and_then(|e| e.1.as_ref().map(|t| t.0));
                let behind_tip =
                    tip_ts.is_some_and(|ts| effective.timestamp_millis() < ts.timestamp_millis());

                if s.unread_count > 0 {
                    let stale_high = tip_ts
                        .is_some_and(|ts| effective.timestamp_millis() >= ts.timestamp_millis());
                    if stale_high || behind_tip {
                        missing_unread.push(s.channel_id);
                    } else if let Some(entry) = out.get_mut(&s.channel_id) {
                        entry.0 = s.unread_count;
                    }
                } else if behind_tip || tip_ts.is_some() {
                    missing_unread.push(s.channel_id);
                }
            }
            for cid in &channel_ids {
                if last_reads.contains_key(cid) {
                    continue;
                }
                if out.get(cid).and_then(|e| e.1.as_ref()).is_some() {
                    missing_unread.push(*cid);
                }
            }
        }
        Err(error) => {
            log::error!("Failed to query channel read states: {error}");
            return None;
        }
    }

    if !missing_unread.is_empty() {
        let mut or_clauses = Vec::with_capacity(missing_unread.len());
        for cid in &missing_unread {
            let last_read = last_reads
                .get(cid)
                .copied()
                .unwrap_or_else(|| DateTime::from_millis(0));
            or_clauses.push(doc! {
                "channel": cid,
                "timestamp": { "$gt": last_read },
            });
        }
        let unread_pipeline = vec![
            doc! {
                "$match": {
                    "deleted": { "$ne": true },
                    "sender": { "$ne": user_id },
                    "$or": or_clauses,
                }
            },
            doc! {
                "$group": {
                    "_id": "$channel",
                    "count": { "$sum": 1 },
                }
            },
        ];
        match Message::collection(db).aggregate(unread_pipeline).await {
            Ok(mut cursor) => loop {
                match cursor.try_next().await {
                    Ok(Some(doc)) => {
                        let Ok(cid) = doc.get_object_id("_id") else {
                            continue;
                        };
                        let count = match doc.get("count") {
                            Some(mongodb::bson::Bson::Int64(n)) => (*n).max(0) as u64,
                            Some(mongodb::bson::Bson::Int32(n)) => (*n).max(0) as u64,
                            _ => 0,
                        };
                        if let Some(entry) = out.get_mut(&cid) {
                            entry.0 = count;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        log::error!("Failed to read channel unread aggregation: {error}");
                        return None;
                    }
                }
            },
            Err(error) => {
                log::error!("Failed to aggregate channel unread counts: {error}");
                return None;
            }
        }
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use mongodb::bson::{doc, oid::ObjectId, DateTime};

    use crate::model::channels::Channel;

    use super::{can_access_channel, is_channel_member};

    fn channel_document(is_deleting: Option<bool>) -> Channel {
        let admin = ObjectId::new();
        let mut document = doc! {
            "name": "test",
            "admin": admin,
            "members": [],
            "createdAt": DateTime::now(),
            "updatedAt": DateTime::now(),
        };
        if let Some(is_deleting) = is_deleting {
            document.insert("isDeleting", is_deleting);
        }
        mongodb::bson::from_document(document).unwrap()
    }

    #[test]
    fn deleting_channel_is_not_accessible() {
        let channel = channel_document(Some(true));
        let admin_id = channel.admin.to_hex();

        assert!(!is_channel_member(&channel, Some(&admin_id)));
        assert!(!can_access_channel(&channel, Some(&admin_id)));
    }

    #[test]
    fn channels_without_deletion_flag_remain_accessible() {
        let channel = channel_document(None);
        let admin_id = channel.admin.to_hex();

        assert!(is_channel_member(&channel, Some(&admin_id)));
        assert!(can_access_channel(&channel, Some(&admin_id)));
    }
}
