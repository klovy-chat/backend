// mod.rs
// Cięższe operacje (wipe tipów, sprzątanie po userze).
// Zakres:
//  - audyt poboczny
//  - wipe tipów, sprzątanie po userze; nie z publicznego API
// Nie wołaj z publicznego API bez osobnej autoryzacji admina.
// Przy zmianach: model/audit.rs.

use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::Database;
use serde_json::json;

use crate::model::channels::Channel;
use crate::model::read_state::ChannelReadState;
use crate::model::reports::ChannelReport;
use crate::model::friend_requests::FriendRequest;
use crate::model::invites::Invite;
use crate::model::messages::Message;
use crate::model::uploads::PendingUpload;
use crate::model::refresh_tokens::RefreshToken;
use crate::model::users::User;
use crate::model::warnings::Warning;
use crate::utils::storage::{avatar_key_owned_by_channel, storage};
use crate::ws::registry::disconnect_user;

pub const DELETION_GRACE_DAYS: i64 = 7;

pub async fn repair_broken_account_status_fields(db: &Database) -> Result<u64, mongodb::error::Error> {
    let result = User::collection(db)
        .update_many(
            doc! { "isDisabled": mongodb::bson::Bson::Null },
            doc! {
                "$set": { "isDisabled": false },
                "$unset": { "disabledAt": "" },
            },
        )
        .await?;
    Ok(result.modified_count)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PurgeRemovedSchemaReport {
    pub users_modified: u64,
    pub messages_modified: u64,
    pub e2e_keys_dropped: bool,
}

pub async fn purge_removed_schema_fields(
    db: &Database,
) -> Result<PurgeRemovedSchemaReport, mongodb::error::Error> {
    let mut report = PurgeRemovedSchemaReport::default();

    let users = User::collection(db)
        .update_many(
            doc! {
                "$or": [
                    { "e2eEnabled": { "$exists": true } },
                    { "role": { "$exists": true } },
                    { "isAdmin": { "$exists": true } },
                    { "listeningActivity": { "$exists": true } },
                    { "shareListening": { "$exists": true } },
                    { "connectedAccounts": { "$exists": true } },
                    { "badges": { "$exists": true } },
                    { "featuredBadgeIds": { "$exists": true } },
                ]
            },
            doc! {
                "$unset": {
                    "e2eEnabled": "",
                    "role": "",
                    "isAdmin": "",
                    "listeningActivity": "",
                    "shareListening": "",
                    "connectedAccounts": "",
                    "badges": "",
                    "featuredBadgeIds": "",
                }
            },
        )
        .await?;
    report.users_modified = users.modified_count;

    let messages = Message::collection(db)
        .update_many(
            doc! {
                "$or": [
                    { "e2eEncrypted": { "$exists": true } },
                    { "e2eVersion": { "$exists": true } },
                ]
            },
            doc! {
                "$unset": {
                    "e2eEncrypted": "",
                    "e2eVersion": "",
                }
            },
        )
        .await?;
    report.messages_modified = messages.modified_count;

    for collection_name in ["e2e_keys", "oauth_tokens", "push_tokens", "badges"] {
        let collection = db.collection::<mongodb::bson::Document>(collection_name);
        match collection.drop().await {
            Ok(()) => {
                if collection_name == "e2e_keys" {
                    report.e2e_keys_dropped = true;
                }
            }
            Err(e) => {

                let msg = e.to_string();
                if !msg.contains("NamespaceNotFound") && !msg.contains("ns not found") {
                    return Err(e);
                }
            }
        }
    }

    Ok(report)
}

async fn delete_message_attachment(storage: &crate::utils::storage::R2Storage, path: &str) {
    let _ = storage.delete_attachment_key(path).await;
    if path.starts_with('/') {
        let _ = storage.delete_attachment_key(&path[1..]).await;
    }
}

async fn delete_user_storage_files(user: &User, user_id: ObjectId, db: &Database) {
    let storage = storage();

    if let Some(image) = user.image.as_deref() {
        let _ = storage.delete_avatar_key(image).await;
    }
    if let Some(banner) = user.banner.as_deref() {
        let _ = storage.delete_public_media_key(banner).await;
    }

    let owned_channels: Vec<Channel> = match Channel::collection(db)
        .find(doc! { "admin": user_id })
        .await
    {
        Ok(cursor) => cursor.try_collect().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let owned_channel_ids: Vec<ObjectId> = owned_channels
        .iter()
        .filter_map(|channel| channel.id)
        .collect();

    for channel in &owned_channels {
        if channel.image.is_empty() {
            continue;
        }
        let channel_id = channel.id.map(|id| id.to_hex()).unwrap_or_default();
        if avatar_key_owned_by_channel(&channel.image, &channel_id) {
            let _ = storage.delete_avatar_key(&channel.image).await;
        }
    }

    if let Ok(cursor) = PendingUpload::collection(db)
        .find(doc! { "userId": user_id })
        .await
    {
        if let Ok(entries) = cursor.try_collect::<Vec<PendingUpload>>().await {
            for entry in entries {
                let _ = storage.delete_attachment_key(&entry.file_path).await;
            }
        }
    }

    let mut attachment_filter = vec![
        doc! { "sender": user_id },
        doc! { "recipient": user_id },
    ];
    if !owned_channel_ids.is_empty() {
        attachment_filter.push(doc! { "channel": { "$in": &owned_channel_ids } });
    }

    if let Ok(cursor) = Message::collection(db)
        .find(doc! {
            "$or": attachment_filter,
            "fileUrl": { "$exists": true, "$ne": null },
        })
        .await
    {
        if let Ok(messages) = cursor.try_collect::<Vec<Message>>().await {
            for message in messages {
                if let Some(path) = message.file_url.as_deref() {
                    delete_message_attachment(&storage, path).await;
                }
            }
        }
    }
}

async fn purge_user_related_records(db: &Database, user_id: ObjectId) {
    let _ = RefreshToken::revoke_all_for_user(db, user_id).await;
    let _ = Warning::collection(db)
        .delete_many(doc! { "userId": user_id })
        .await;
    let _ = PendingUpload::collection(db)
        .delete_many(doc! { "userId": user_id })
        .await;
    let _ = db
        .collection::<mongodb::bson::Document>("user_storage_usage")
        .delete_many(doc! { "userId": user_id })
        .await;
    let _ = ChannelReadState::collection(db)
        .delete_many(doc! { "userId": user_id })
        .await;
    let _ = ChannelReport::collection(db)
        .delete_many(doc! { "reportedBy": user_id })
        .await;
}

pub async fn purge_user_data(
    db: &Database,
    user_id: ObjectId,
) -> Result<u64, mongodb::error::Error> {
    use crate::utils::tips::DmConversationTip;
    use crate::ws::registry::{channel_recipient_ids, emit_to_users};

    let user_hex = user_id.to_hex();

    let friendships: Vec<FriendRequest> = FriendRequest::collection(db)
        .find(doc! {
            "status": "accepted",
            "$or": [{ "from": user_id }, { "to": user_id }],
        })
        .await?
        .try_collect()
        .await
        .unwrap_or_default();
    for f in &friendships {
        let peer = if f.from == user_id { f.to } else { f.from };
        let peer_hex = peer.to_hex();
        crate::utils::friends::invalidate_friend_ids_pair(&user_hex, &peer_hex);
        crate::ws::typing::invalidate_pair(&user_hex, &peer_hex);
        crate::utils::tips::clear_dm_tip(db, user_id, peer).await;

        if let Some(session) =
            crate::utils::voice::calls::take_session_for_pair(&user_hex, &peer_hex)
        {
            let end_payload = json!({ "from": user_hex, "reason": "ACCOUNT_DELETED" });
            let event = match session.phase {
                crate::utils::voice::calls::CallPhase::Ringing => "call:cancelled",
                crate::utils::voice::calls::CallPhase::Accepted => "call:ended",
            };
            crate::ws::registry::emit_to_user(&session.callee_id, event, end_payload.clone());
            crate::ws::registry::emit_to_user(&session.caller_id, event, end_payload);
        }
    }

    for session in crate::utils::voice::calls::take_sessions_for_user(&user_hex) {
        let end_payload = json!({ "from": user_hex, "reason": "ACCOUNT_DELETED" });
        let event = match session.phase {
            crate::utils::voice::calls::CallPhase::Ringing => "call:cancelled",
            crate::utils::voice::calls::CallPhase::Accepted => "call:ended",
        };
        crate::ws::registry::emit_to_user(&session.callee_id, event, end_payload.clone());
        crate::ws::registry::emit_to_user(&session.caller_id, event, end_payload);
    }

    for channel_id in crate::utils::voice::channels::clear_user_from_all_channels(&user_hex) {
        let participants =
            crate::utils::voice::channels::participants_in_channel(&channel_id);
        if let Ok(oid) = ObjectId::parse_str(&channel_id) {
            if let Ok(Some(ch)) = Channel::find_by_id(db, oid).await {
                let recipients = channel_recipient_ids(&ch);
                emit_to_users(
                    &recipients,
                    "channel-voice:state",
                    json!({ "channelId": channel_id, "participants": participants }),
                );
            }
        }
    }
    let _ = DmConversationTip::collection(db)
        .delete_many(doc! {
            "$or": [{ "userA": user_id }, { "userB": user_id }],
        })
        .await;

    let tip_channel_oids: Vec<ObjectId> = Message::collection(db)
        .distinct("channel", doc! {
            "sender": user_id,
            "channel": { "$type": "objectId" },
        })
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|b| match b {
            mongodb::bson::Bson::ObjectId(oid) => Some(oid),
            _ => None,
        })
        .collect();

    Message::collection(db)
        .delete_many(doc! {
            "$or": [
                { "sender": user_id },
                { "recipient": user_id },
            ],
        })
        .await?;

    FriendRequest::collection(db)
        .delete_many(doc! {
            "$or": [
                { "from": user_id },
                { "to": user_id },
            ],
        })
        .await?;

    Invite::collection(db)
        .delete_many(doc! { "createdBy": user_id })
        .await?;

    let member_channels: Vec<Channel> = Channel::find_by_member(db, user_id)
        .await
        .unwrap_or_default();

    Channel::collection(db)
        .update_many(
            doc! { "members": user_id },
            doc! { "$pull": { "members": user_id } },
        )
        .await?;

    for ch in &member_channels {
        let Some(cid) = ch.id else { continue };
        let channel_id = cid.to_hex();
        crate::ws::typing::invalidate_channel(&channel_id);
        let mut remaining = channel_recipient_ids(ch);
        remaining.retain(|r| r != &user_hex);
        let participants =
            crate::utils::voice::channels::leave_channel_voice(&channel_id, &user_hex);
        emit_to_users(
            &remaining,
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
                "userId": user_hex,
                "memberCount": remaining.len(),
            }),
        );
    }

    let owned: Vec<Channel> = Channel::collection(db)
        .find(doc! { "admin": user_id })
        .await?
        .try_collect()
        .await
        .unwrap_or_default();

    let owned_ids: Vec<ObjectId> = owned.iter().filter_map(|c| c.id).collect();
    let owned_set: std::collections::HashSet<ObjectId> = owned_ids.iter().copied().collect();

    for cid in tip_channel_oids {
        if owned_set.contains(&cid) {
            continue;
        }
        crate::utils::tips::recompute_channel_tip(db, cid).await;
    }

    let channels_deleted = owned_ids.len() as u64;
    if !owned_ids.is_empty() {
        for ch in &owned {
            let Some(cid) = ch.id else { continue };
            let channel_id = cid.to_hex();
            crate::ws::typing::invalidate_channel(&channel_id);
            crate::utils::voice::channels::clear_channel_voice(&channel_id);
            let recipients = channel_recipient_ids(ch);
            emit_to_users(
                &recipients,
                "channel-voice:state",
                json!({
                    "channelId": channel_id,
                    "participants": Vec::<String>::new(),
                }),
            );
            emit_to_users(
                &recipients,
                "channel-deleted",
                json!({ "channelId": channel_id }),
            );
        }
        Message::collection(db)
            .delete_many(doc! { "channel": { "$in": &owned_ids } })
            .await?;
        Invite::collection(db)
            .delete_many(doc! { "channelId": { "$in": &owned_ids } })
            .await?;
        let _ = ChannelReadState::collection(db)
            .delete_many(doc! { "channelId": { "$in": &owned_ids } })
            .await;
        Channel::collection(db)
            .delete_many(doc! { "_id": { "$in": &owned_ids } })
            .await?;
    }

    User::collection(db)
        .delete_one(doc! { "_id": user_id })
        .await?;

    Ok(channels_deleted)
}

pub async fn purge_user_completely(
    db: &Database,
    user_id: ObjectId,
) -> Result<u64, mongodb::error::Error> {
    let user = User::find_by_id(db, user_id).await?.ok_or_else(|| {
        mongodb::error::Error::custom("User not found for purge")
    })?;

    delete_user_storage_files(&user, user_id, db).await;
    purge_user_related_records(db, user_id).await;
    disconnect_user(&user_id.to_hex());
    purge_user_data(db, user_id).await
}

pub async fn process_scheduled_deletions(db: &Database) -> Result<u64, mongodb::error::Error> {
    let now = DateTime::now();
    let users: Vec<User> = User::collection(db)
        .find(doc! {
            "deletionScheduledAt": { "$lte": now },
        })
        .await?
        .try_collect()
        .await?;

    let mut deleted = 0u64;
    for user in users {
        let Some(user_id) = user.id else { continue };
        match purge_user_completely(db, user_id).await {
            Ok(_) => {
                deleted += 1;
                log::info!("Auto-deleted user account {}", user_id.to_hex());
            }
            Err(e) => {
                log::error!(
                    "Failed to auto-delete user {}: {e}",
                    user_id.to_hex()
                );
            }
        }
    }

    Ok(deleted)
}
