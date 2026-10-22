use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::Database;

use crate::model::channels::Channel;

const DELETION_LEASE_MS: i64 = 2 * 60 * 1000;

pub enum ChannelDeletionOutcome {
    Busy,
    Missing,
    Deleted,
}

pub async fn resume_pending_channel_deletions(db: &Database) -> Result<u64, String> {
    let now = DateTime::now();
    let cursor = Channel::collection(db)
        .find(doc! {
            "isDeleting": true,
            "$and": [
                {
                    "$or": [
                        { "deleteClaimUntil": { "$exists": false } },
                        { "deleteClaimUntil": { "$lt": now } },
                    ],
                },
                {
                    "$nor": [{
                        "activeMessageWrites": {
                            "$elemMatch": { "expiresAt": { "$gt": now } },
                        },
                    }],
                },
            ],
        })
        .limit(100)
        .await
        .map_err(|error| format!("find channels pending deletion: {error}"))?;
    let channels: Vec<Channel> = cursor
        .try_collect()
        .await
        .map_err(|error| format!("read channels pending deletion: {error}"))?;

    let mut deleted = 0;
    for channel in channels {
        let Some(channel_id) = channel.id else {
            log::error!("Skipping channel marked for deletion without an id");
            continue;
        };
        match delete_channel(db, channel_id).await {
            Ok(ChannelDeletionOutcome::Deleted) => deleted += 1,
            Ok(ChannelDeletionOutcome::Busy | ChannelDeletionOutcome::Missing) => {}
            Err(error) => log::warn!(
                "Automatic deletion retry failed for channel {}: {error}",
                channel_id.to_hex()
            ),
        }
    }
    Ok(deleted)
}

pub async fn delete_channel(
    db: &Database,
    channel_id: ObjectId,
) -> Result<ChannelDeletionOutcome, String> {
    let channel = Channel::find_by_id(db, channel_id)
        .await
        .map_err(|error| format!("load channel: {error}"))?;
    let Some(channel) = channel else {
        return Ok(ChannelDeletionOutcome::Missing);
    };
    if !channel.is_deleting {
        return Ok(ChannelDeletionOutcome::Missing);
    }

    let claim_token = uuid::Uuid::new_v4().to_string();
    let now = DateTime::now();
    let claim_until =
        DateTime::from_millis(now.timestamp_millis().saturating_add(DELETION_LEASE_MS));
    let no_active_writes_after = DateTime::now();
    let claim = Channel::collection(db)
        .update_one(
            doc! {
                "_id": channel_id,
                "isDeleting": true,
                "$and": [
                    {
                        "$or": [
                            { "deleteClaimUntil": { "$exists": false } },
                            { "deleteClaimUntil": { "$lt": now } },
                        ],
                    },
                    {
                        "$nor": [{
                            "activeMessageWrites": {
                                "$elemMatch": { "expiresAt": { "$gt": no_active_writes_after } },
                            },
                        }],
                    },
                ],
            },
            doc! {
                "$set": {
                    "deleteClaimToken": &claim_token,
                    "deleteClaimUntil": claim_until,
                },
            },
        )
        .await
        .map_err(|error| format!("claim channel deletion: {error}"))?;
    if claim.matched_count == 0 {
        return Ok(ChannelDeletionOutcome::Busy);
    }

    let channel_id_hex = channel_id.to_hex();
    let recipients = crate::ws::registry::channel_recipient_ids(&channel);
    let heartbeat_db = db.clone();
    let heartbeat_token = claim_token.clone();
    let (heartbeat_failed_tx, mut heartbeat_failed_rx) = tokio::sync::oneshot::channel();
    let heartbeat = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let now = DateTime::now();
            let until =
                DateTime::from_millis(now.timestamp_millis().saturating_add(DELETION_LEASE_MS));
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                Channel::collection(&heartbeat_db).update_one(
                    doc! {
                        "_id": channel_id,
                        "isDeleting": true,
                        "deleteClaimToken": &heartbeat_token,
                    },
                    doc! { "$set": { "deleteClaimUntil": until } },
                ),
            )
            .await
            {
                Ok(Ok(result)) if result.matched_count == 1 => {}
                Ok(Ok(_)) => {
                    let _ = heartbeat_failed_tx.send(());
                    break;
                }
                Ok(Err(error)) => {
                    log::error!(
                        "Failed to renew deletion claim for channel {}: {error}",
                        channel_id.to_hex()
                    );
                    let _ = heartbeat_failed_tx.send(());
                    break;
                }
                Err(_) => {
                    log::error!(
                        "Timed out renewing deletion claim for channel {}",
                        channel_id.to_hex()
                    );
                    let _ = heartbeat_failed_tx.send(());
                    break;
                }
            }
        }
    });
    let (result, heartbeat_failed) = tokio::select! {
        result = finish_channel_deletion(db, channel_id, &channel_id_hex, &claim_token) => {
            (result, false)
        },
        _ = &mut heartbeat_failed_rx => (
            Err(format!("channel {channel_id_hex} deletion claim heartbeat failed")),
            true,
        ),
    };
    heartbeat.abort();
    match result {
        Ok(()) => {
            crate::utils::access::cache::invalidate_channel(&channel_id_hex);
            crate::ws::typing::invalidate_channel(&channel_id_hex);
            crate::utils::voice::channels::clear_channel_voice(&channel_id_hex);

            for recipient in &recipients {
                crate::utils::unread::invalidate_unread_generation(
                    recipient,
                    "channel",
                    &channel_id_hex,
                );
                crate::utils::unread::emit_unread_absolute(
                    recipient,
                    "channel",
                    &channel_id_hex,
                    0,
                );
            }
            crate::ws::registry::emit_to_users(
                &recipients,
                "channel-voice:state",
                serde_json::json!({
                    "channelId": channel_id_hex,
                    "participants": Vec::<String>::new(),
                }),
            );
            crate::ws::registry::emit_to_users(
                &recipients,
                "channel-deleted",
                serde_json::json!({ "channelId": channel_id_hex }),
            );
            Ok(ChannelDeletionOutcome::Deleted)
        }
        Err(error) => {
            if heartbeat_failed {
                log::warn!(
                    "Keeping deletion claim for channel {channel_id_hex} until expiry after heartbeat failure"
                );
            } else if let Err(release_error) = Channel::collection(db)
                .update_one(
                    doc! { "_id": channel_id, "deleteClaimToken": &claim_token },
                    doc! {
                        "$unset": {
                            "deleteClaimToken": "",
                            "deleteClaimUntil": "",
                        },
                    },
                )
                .await
            {
                log::error!(
                    "Failed to release deletion claim for channel {channel_id_hex}: {release_error}"
                );
            }
            Err(error)
        }
    }
}

async fn finish_channel_deletion(
    db: &Database,
    channel_id: ObjectId,
    channel_id_hex: &str,
    claim_token: &str,
) -> Result<(), String> {
    let all_channel_files_filter = doc! {
        "channel": channel_id,
        "fileUrl": { "$exists": true, "$ne": null },
    };
    let mut file_urls =
        crate::utils::messages::search::message_file_urls(db, all_channel_files_filter)
            .await
            .map_err(|error| format!("read channel attachment URLs: {error}"))?;

    let live_filter = doc! {
        "channel": channel_id,
        "deleted": { "$ne": true },
    };
    let wipe_result = crate::utils::messages::search::wipe_live_messages(db, live_filter)
        .await
        .map_err(|error| format!("wipe channel messages: {error}"))?;
    if wipe_result.wipe_pending {
        return Err("channel messages were wiped, but late message cleanup is incomplete".into());
    }
    file_urls.extend(wipe_result.file_urls);
    file_urls.sort();
    file_urls.dedup();

    let cleanups: Vec<_> = file_urls
        .iter()
        .map(|url| {
            crate::utils::messages::access::cleanup_attachment_if_unreferenced(db, Some(url))
        })
        .collect();
    for result in futures_util::future::join_all(cleanups).await {
        result.map_err(|error| format!("clean up channel attachment: {error}"))?;
    }

    crate::model::invites::Invite::collection(db)
        .delete_many(doc! { "channelId": channel_id })
        .await
        .map_err(|error| format!("delete channel invites: {error}"))?;
    crate::model::read_state::ChannelReadState::collection(db)
        .delete_many(doc! { "channelId": channel_id })
        .await
        .map_err(|error| format!("delete channel read states: {error}"))?;

    let result = Channel::collection(db)
        .delete_one(doc! {
            "_id": channel_id,
            "isDeleting": true,
            "deleteClaimToken": claim_token,
        })
        .await
        .map_err(|error| format!("delete channel {channel_id_hex}: {error}"))?;
    if result.deleted_count == 0 {
        return Err(format!(
            "channel {channel_id_hex} deletion claim was lost before final delete"
        ));
    }
    Ok(())
}
