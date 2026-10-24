// moderation.rs
// Atomowy $pull mute/ban, prune wygasłych timed.
// Zakres:
//  - bez rewrite tablicy ze snapshotu
//  - atomowy $pull mute/ban, prune timed; nie rewrite tablicy
// Kick/ban kolejność: ban upsert, potem pull member (komentarze w channels.rs).
// Przy zmianach: controllers/channels.rs, model/channels.rs.

use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::Database;
use serde_json::{json, Value};

use crate::model::channel_moderation::{active_moderation_entries, ChannelModerationEntry};
use crate::model::channels::Channel;

pub async fn pull_muted_member(
    db: &Database,
    channel_id: ObjectId,
    user_id: ObjectId,
) -> mongodb::error::Result<()> {
    Channel::collection(db)
        .update_one(
            doc! { "_id": channel_id },
            doc! {
                "$pull": { "mutedMembers": { "userId": user_id } },
                "$set": { "updatedAt": DateTime::now() },
            },
        )
        .await?;
    Ok(())
}

pub async fn pull_banned_member(
    db: &Database,
    channel_id: ObjectId,
    user_id: ObjectId,
) -> mongodb::error::Result<()> {
    Channel::collection(db)
        .update_one(
            doc! { "_id": channel_id },
            doc! {
                "$pull": { "bannedMembers": { "userId": user_id } },
                "$set": { "updatedAt": DateTime::now() },
            },
        )
        .await?;
    Ok(())
}

pub async fn upsert_banned_member(
    db: &Database,
    channel_id: ObjectId,
    entry: ChannelModerationEntry,
) -> mongodb::error::Result<()> {
    let entry_bson = mongodb::bson::to_bson(&entry).map_err(|e| {
        mongodb::error::Error::custom(format!("failed to serialize ban entry: {e}"))
    })?;
    let uid = entry.user_id;
    Channel::collection(db)
        .update_one(
            doc! { "_id": channel_id },
            vec![doc! {
                "$set": {
                    "bannedMembers": {
                        "$concatArrays": [
                            {
                                "$filter": {
                                    "input": { "$ifNull": ["$bannedMembers", []] },
                                    "as": "e",
                                    "cond": { "$ne": ["$$e.userId", uid] },
                                }
                            },
                            [entry_bson],
                        ]
                    },
                    "updatedAt": DateTime::now(),
                }
            }],
        )
        .await?;
    Ok(())
}

pub async fn upsert_muted_member(
    db: &Database,
    channel_id: ObjectId,
    entry: ChannelModerationEntry,
) -> mongodb::error::Result<()> {
    let entry_bson = mongodb::bson::to_bson(&entry).map_err(|e| {
        mongodb::error::Error::custom(format!("failed to serialize mute entry: {e}"))
    })?;
    let uid = entry.user_id;
    Channel::collection(db)
        .update_one(
            doc! { "_id": channel_id },
            vec![doc! {
                "$set": {
                    "mutedMembers": {
                        "$concatArrays": [
                            {
                                "$filter": {
                                    "input": { "$ifNull": ["$mutedMembers", []] },
                                    "as": "e",
                                    "cond": { "$ne": ["$$e.userId", uid] },
                                }
                            },
                            [entry_bson],
                        ]
                    },
                    "updatedAt": DateTime::now(),
                }
            }],
        )
        .await?;
    Ok(())
}

pub async fn populate_moderation_user_list(
    db: &Database,
    entries: &[ChannelModerationEntry],
    viewer_id: &str,
) -> Vec<Value> {
    use super::fetch_users_map;

    let active = active_moderation_entries(entries);
    if active.is_empty() {
        return Vec::new();
    }
    let ids: Vec<ObjectId> = active.iter().map(|e| e.user_id).collect();
    let map = fetch_users_map(db, &ids, viewer_id).await;
    let mut out = Vec::with_capacity(active.len());
    for entry in active {
        let mut user = map
            .get(&entry.user_id)
            .cloned()
            .unwrap_or_else(|| json!({ "_id": entry.user_id.to_hex() }));
        if let Some(obj) = user.as_object_mut() {
            obj.insert(
                "moderationExpiresAt".to_string(),
                json!(entry
                    .expires_at
                    .as_ref()
                    .and_then(|dt| dt.try_to_rfc3339_string().ok())),
            );
            obj.insert(
                "moderationCreatedAt".to_string(),
                json!(entry.created_at.try_to_rfc3339_string().ok()),
            );
            obj.insert(
                "moderationPermanent".to_string(),
                json!(entry.expires_at.is_none()),
            );
        }
        out.push(user);
    }
    out
}

pub async fn get_channel_ban_mute_lists(
    db: &Database,
    channel_id: ObjectId,
    viewer_id: &str,
) -> Option<(Vec<Value>, Vec<Value>)> {
    let channel = match Channel::find_by_id(db, channel_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return Some((vec![], vec![])),
        Err(_) => return None,
    };
    let banned = populate_moderation_user_list(db, &channel.banned_members, viewer_id).await;
    let muted = populate_moderation_user_list(db, &channel.muted_members, viewer_id).await;
    Some((banned, muted))
}

pub fn build_moderation_entry(
    user_id: ObjectId,
    duration_seconds: Option<u64>,
) -> ChannelModerationEntry {
    match duration_seconds {
        Some(0) | None => ChannelModerationEntry::permanent(user_id),
        Some(seconds) => ChannelModerationEntry::timed(user_id, seconds),
    }
}

pub fn active_moderation_user_ids(entries: &[ChannelModerationEntry]) -> Vec<String> {
    active_moderation_entries(entries)
        .into_iter()
        .map(|entry| entry.user_id.to_hex())
        .collect()
}

pub fn viewer_mute_expires_at(channel: &Channel, viewer_id: &str) -> Option<String> {
    channel
        .muted_members
        .iter()
        .find(|entry| entry.is_active() && entry.user_id.to_hex() == viewer_id)
        .and_then(|entry| entry.expires_at.as_ref())
        .and_then(|dt| dt.try_to_rfc3339_string().ok())
}

pub async fn maybe_prune_channel_moderation(db: &Database, channel: &Channel) -> Channel {
    let banned = active_moderation_entries(&channel.banned_members);
    let muted = active_moderation_entries(&channel.muted_members);
    if banned.len() == channel.banned_members.len() && muted.len() == channel.muted_members.len() {
        return channel.clone();
    }

    let active_muted: std::collections::HashSet<ObjectId> =
        muted.iter().map(|e| e.user_id).collect();
    let expired_mute_users: Vec<String> = channel
        .muted_members
        .iter()
        .filter(|entry| !active_muted.contains(&entry.user_id))
        .map(|entry| entry.user_id.to_hex())
        .collect();

    if let Some(channel_id) = channel.id {
        let now = DateTime::now();
        if let Err(error) = Channel::collection(db)
            .update_one(
                doc! { "_id": channel_id },
                doc! {
                    "$pull": {
                        "bannedMembers": { "expiresAt": { "$lte": now } },
                        "mutedMembers": { "expiresAt": { "$lte": now } },
                    },
                    "$set": { "updatedAt": now },
                },
            )
            .await
        {
            log::error!(
                "Failed to prune expired channel moderation entries for channel {}: {error}",
                channel_id.to_hex()
            );
        }
        let channel_id_hex = channel_id.to_hex();
        crate::ws::typing::invalidate_channel(&channel_id_hex);
        crate::utils::access::cache::invalidate_channel(&channel_id_hex);
        for user_id in expired_mute_users {
            crate::ws::registry::emit_to_user(
                &user_id,
                "channel-moderation-updated",
                json!({
                    "channelId": channel_id_hex,
                    "isMutedHere": false,
                    "mutedHereExpiresAt": Value::Null,
                }),
            );
        }
    }
    Channel {
        banned_members: banned,
        muted_members: muted,
        ..channel.clone()
    }
}
