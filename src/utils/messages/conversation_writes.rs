use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::Database;

const WRITE_LEASE_MS: i64 = 5 * 60 * 1000;
const DELETION_LEASE_MS: i64 = 15 * 60 * 1000;

pub struct DmConversationGuard {
    db: Database,
    key: String,
    token: String,
    deletion: bool,
    released: bool,
    heartbeat: tokio::task::JoinHandle<()>,
}

impl DmConversationGuard {
    pub async fn release(mut self) -> Result<(), String> {
        self.heartbeat.abort();
        let result = release_guard(&self.db, &self.key, &self.token, self.deletion).await;
        self.released = result.is_ok();
        result
    }
}

impl Drop for DmConversationGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.heartbeat.abort();
        let db = self.db.clone();
        let key = self.key.clone();
        let token = self.token.clone();
        let deletion = self.deletion;
        tokio::spawn(async move {
            if let Err(error) = release_guard(&db, &key, &token, deletion).await {
                log::error!("Failed to release DM conversation guard for {key}: {error}");
            }
        });
    }
}

fn start_heartbeat(
    db: Database,
    key: String,
    token: String,
    deletion: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let now = DateTime::now();
            let lease_ms = if deletion {
                DELETION_LEASE_MS
            } else {
                WRITE_LEASE_MS
            };
            let expires_at = DateTime::from_millis(now.timestamp_millis() + lease_ms);
            let collection = db.collection::<mongodb::bson::Document>("dm_conversation_writes");
            let update = async {
                if deletion {
                    collection
                        .update_one(
                            doc! { "_id": &key, "deleteClaimToken": &token },
                            doc! { "$set": { "deleteClaimUntil": expires_at } },
                        )
                        .await
                } else {
                    collection
                        .update_one(
                            doc! {
                                "_id": &key,
                                "activeMessageWrites": {
                                    "$elemMatch": { "token": &token, "expiresAt": { "$gt": now } },
                                },
                            },
                            vec![doc! {
                                "$set": {
                                    "activeMessageWrites": {
                                        "$map": {
                                            "input": { "$ifNull": ["$activeMessageWrites", []] },
                                            "as": "write",
                                            "in": {
                                                "$cond": [
                                                    { "$eq": ["$$write.token", &token] },
                                                    { "$mergeObjects": ["$$write", { "expiresAt": expires_at }] },
                                                    "$$write",
                                                ],
                                            },
                                        },
                                    },
                                },
                            }],
                        )
                        .await
                }
            };
            match tokio::time::timeout(std::time::Duration::from_secs(10), update).await {
                Ok(Ok(result)) if result.matched_count == 1 => {}
                Ok(Ok(_)) => {
                    log::error!("DM conversation guard was lost for {key}");
                    break;
                }
                Ok(Err(error)) => {
                    log::error!("Failed to renew DM conversation guard for {key}: {error}");
                }
                Err(_) => {
                    log::error!("Timed out renewing DM conversation guard for {key}");
                }
            }
        }
    })
}

fn pair_key(first: ObjectId, second: ObjectId) -> String {
    let first = first.to_hex();
    let second = second.to_hex();
    if first <= second {
        format!("{first}:{second}")
    } else {
        format!("{second}:{first}")
    }
}

async fn ensure_guard_document(db: &Database, key: &str) -> mongodb::error::Result<()> {
    let collection = db.collection::<mongodb::bson::Document>("dm_conversation_writes");
    match collection
        .update_one(
            doc! { "_id": key },
            doc! { "$setOnInsert": { "createdAt": DateTime::now() } },
        )
        .upsert(true)
        .await
    {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.kind.as_ref(),
                mongodb::error::ErrorKind::Write(
                    mongodb::error::WriteFailure::WriteError(write_error)
                ) if write_error.code == 11000
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub async fn reserve_message_write(
    db: &Database,
    sender: ObjectId,
    recipient: ObjectId,
) -> Result<Option<DmConversationGuard>, String> {
    let key = pair_key(sender, recipient);
    ensure_guard_document(db, &key)
        .await
        .map_err(|error| format!("initialize DM conversation guard {key}: {error}"))?;

    let now = DateTime::now();
    let expires_at = DateTime::from_millis(now.timestamp_millis() + WRITE_LEASE_MS);
    let token = uuid::Uuid::new_v4().to_string();
    let result = db
        .collection::<mongodb::bson::Document>("dm_conversation_writes")
        .update_one(
            doc! {
                "_id": &key,
                "$or": [
                    { "deleteClaimUntil": { "$exists": false } },
                    { "deleteClaimUntil": { "$lte": now } },
                ],
            },
            vec![doc! {
                "$set": {
                    "activeMessageWrites": {
                        "$concatArrays": [
                            {
                                "$filter": {
                                    "input": { "$ifNull": ["$activeMessageWrites", []] },
                                    "as": "write",
                                    "cond": { "$gt": ["$$write.expiresAt", now] },
                                }
                            },
                            [{ "token": &token, "expiresAt": expires_at }],
                        ]
                    }
                }
            }],
        )
        .await
        .map_err(|error| format!("reserve DM conversation write for {key}: {error}"))?;
    if result.matched_count != 1 {
        return Ok(None);
    }
    let heartbeat = start_heartbeat(db.clone(), key.clone(), token.clone(), false);
    Ok(Some(DmConversationGuard {
        db: db.clone(),
        key,
        token,
        deletion: false,
        released: false,
        heartbeat,
    }))
}

pub async fn claim_deletion(
    db: &Database,
    first: ObjectId,
    second: ObjectId,
) -> Result<Option<DmConversationGuard>, String> {
    let key = pair_key(first, second);
    ensure_guard_document(db, &key)
        .await
        .map_err(|error| format!("initialize DM conversation guard {key}: {error}"))?;

    let now = DateTime::now();
    let lease_until = DateTime::from_millis(now.timestamp_millis() + DELETION_LEASE_MS);
    let token = uuid::Uuid::new_v4().to_string();
    let result = db
        .collection::<mongodb::bson::Document>("dm_conversation_writes")
        .update_one(
            doc! {
                "_id": &key,
                "$and": [
                    {
                        "$or": [
                            { "deleteClaimUntil": { "$exists": false } },
                            { "deleteClaimUntil": { "$lte": now } },
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
            },
            doc! {
                "$set": {
                    "deleteClaimToken": &token,
                    "deleteClaimUntil": lease_until,
                },
            },
        )
        .await
        .map_err(|error| format!("claim DM conversation deletion for {key}: {error}"))?;
    if result.matched_count != 1 {
        return Ok(None);
    }
    let heartbeat = start_heartbeat(db.clone(), key.clone(), token.clone(), true);
    Ok(Some(DmConversationGuard {
        db: db.clone(),
        key,
        token,
        deletion: true,
        released: false,
        heartbeat,
    }))
}

async fn release_guard(
    db: &Database,
    key: &str,
    token: &str,
    deletion: bool,
) -> Result<(), String> {
    let collection = db.collection::<mongodb::bson::Document>("dm_conversation_writes");
    let result = if deletion {
        collection
            .update_one(
                doc! { "_id": key, "deleteClaimToken": token },
                doc! {
                    "$unset": {
                        "deleteClaimToken": "",
                        "deleteClaimUntil": "",
                    },
                },
            )
            .await
    } else {
        collection
            .update_one(
                doc! { "_id": key },
                doc! { "$pull": { "activeMessageWrites": { "token": token } } },
            )
            .await
    }
    .map_err(|error| format!("release DM conversation guard {key}: {error}"))?;
    if result.matched_count != 1 {
        return Err(format!("DM conversation guard was lost for {key}"));
    }
    Ok(())
}
