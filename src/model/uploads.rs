// uploads.rs
// Pending upload: klucz R2, size, hash, owner, kontekst.
// Zakres:
//  - zanim powstanie Message
//  - pending R2 zanim powstanie Message; TTL + reconcile
// Reconcile kasuje osierocone; nie zostawiaj pending bez TTL.
// Przy zmianach: utils/storage/reconcile.rs, messages/access.rs.

use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::options::IndexOptions;
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};

use crate::model::messages::Message;
use crate::model::scan::{default_pending_scan_status, ScanStatus};
use crate::utils::storage::{attachment_stored_url_aliases, cdn_public_base_url};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUpload {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    #[serde(rename = "userId")]
    pub user_id: ObjectId,
    #[serde(rename = "filePath")]
    pub file_path: String,
    #[serde(rename = "contextType")]
    pub context_type: String,
    #[serde(rename = "contextId")]
    pub context_id: String,
    #[serde(rename = "fileSize", default)]
    pub file_size: u64,
    #[serde(rename = "fileHash", default)]
    pub file_hash: String,
    #[serde(rename = "contentType", default)]
    pub content_type: String,
    #[serde(rename = "scanStatus", default = "default_pending_scan_status")]
    pub scan_status: ScanStatus,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime,
    #[serde(rename = "pendingSlot", skip_serializing_if = "Option::is_none")]
    pub pending_slot: Option<i32>,
    #[serde(rename = "sendClaimedAt", skip_serializing_if = "Option::is_none")]
    pub send_claimed_at: Option<DateTime>,
    #[serde(rename = "cleanupClaimedAt", skip_serializing_if = "Option::is_none")]
    pub cleanup_claimed_at: Option<DateTime>,
    #[serde(rename = "quotaReserved", default)]
    pub quota_reserved: bool,
    #[serde(rename = "quotaAccountingVersion", default)]
    pub quota_accounting_version: i32,
}

impl PendingUpload {
    const CLAIM_LEASE_MS: i64 = 60 * 60 * 1000;

    pub fn collection(db: &Database) -> Collection<Self> {
        db.collection("pending_uploads")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "createdAt": 1 })
                    .options(
                        IndexOptions::builder()
                            .expire_after(std::time::Duration::from_secs(24 * 60 * 60))
                            .build(),
                    )
                    .build(),
            )
            .await?;
        Self::collection(db)
            .create_index(IndexModel::builder().keys(doc! { "filePath": 1 }).build())
            .await?;
        Self::collection(db)
            .create_index(IndexModel::builder().keys(doc! { "fileHash": 1 }).build())
            .await?;
        Self::collection(db)
            .create_index(IndexModel::builder().keys(doc! { "scanStatus": 1 }).build())
            .await?;
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "userId": 1, "pendingSlot": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("userId_pendingSlot_unique".to_string())
                            .unique(true)
                            .partial_filter_expression(doc! {
                                "pendingSlot": { "$exists": true }
                            })
                            .build(),
                    )
                    .build(),
            )
            .await?;
        Ok(())
    }

    async fn commit_quota_reservation(
        db: &Database,
        entry: &PendingUpload,
    ) -> mongodb::error::Result<()> {
        if entry.quota_accounting_version >= 2 {
            if let Some(id) = entry.id {
                crate::model::storage_usage::UserStorageUsage::commit_upload_reservation(
                    db,
                    entry.user_id,
                    id,
                )
                .await?;
            }
        }
        Ok(())
    }

    pub async fn count_for_user(db: &Database, user_id: ObjectId) -> mongodb::error::Result<u64> {
        Self::collection(db)
            .count_documents(doc! { "userId": user_id })
            .await
    }

    pub async fn register(
        db: &Database,
        user_id: ObjectId,
        file_path: &str,
        context_type: &str,
        context_id: &str,
        file_size: u64,
        file_hash: &str,
        content_type: &str,
        scan_status: ScanStatus,
    ) -> mongodb::error::Result<ObjectId> {
        let legacy_pending = Self::collection(db)
            .count_documents(doc! {
                "userId": user_id,
                "pendingSlot": { "$exists": false },
            })
            .await?;
        let max_slots = crate::utils::upload::MAX_PENDING_UPLOADS_PER_USER;
        if legacy_pending >= max_slots {
            return Err(mongodb::error::Error::custom("too many pending uploads"));
        }

        for slot in 0..(max_slots - legacy_pending) {
            let pending = PendingUpload {
                id: None,
                user_id,
                file_path: file_path.to_string(),
                context_type: context_type.to_string(),
                context_id: context_id.to_string(),
                file_size,
                file_hash: file_hash.to_string(),
                content_type: content_type.to_string(),
                scan_status,
                created_at: DateTime::now(),
                pending_slot: Some(slot as i32),
                send_claimed_at: None,
                cleanup_claimed_at: None,
                quota_reserved: false,
                quota_accounting_version: 2,
            };
            match Self::collection(db).insert_one(pending).await {
                Ok(result) => {
                    return result.inserted_id.as_object_id().ok_or_else(|| {
                        mongodb::error::Error::custom(
                            "pending upload insert did not return an ObjectId",
                        )
                    })
                }
                Err(error) if Self::is_duplicate_key_error(&error) => continue,
                Err(error) => return Err(error),
            }
        }

        Err(mongodb::error::Error::custom("too many pending uploads"))
    }

    fn is_duplicate_key_error(error: &mongodb::error::Error) -> bool {
        matches!(
            error.kind.as_ref(),
            mongodb::error::ErrorKind::Write(
                mongodb::error::WriteFailure::WriteError(write_error)
            ) if write_error.code == 11000
        )
    }

    pub async fn find_for_user_and_path(
        db: &Database,
        user_id: ObjectId,
        file_path: &str,
    ) -> mongodb::error::Result<Option<Self>> {
        Self::collection(db)
            .find_one(doc! { "filePath": file_path, "userId": user_id })
            .await
    }

    pub async fn set_scan_status(
        db: &Database,
        file_path: &str,
        scan_status: ScanStatus,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_many(
                doc! { "filePath": file_path },
                doc! { "$set": { "scanStatus": scan_status.as_str() } },
            )
            .await?;
        Ok(())
    }

    pub async fn find_pending_scans(db: &Database) -> mongodb::error::Result<Vec<Self>> {
        use futures_util::TryStreamExt;
        let cursor = Self::collection(db)
            .find(doc! { "scanStatus": ScanStatus::Pending.as_str() })
            .await?;
        cursor.try_collect().await
    }

    pub async fn find_by_path(
        db: &Database,
        file_path: &str,
    ) -> mongodb::error::Result<Option<Self>> {
        Self::collection(db)
            .find_one(doc! { "filePath": file_path })
            .await
    }

    pub async fn claim_by_path(
        db: &Database,
        user_id: ObjectId,
        file_path: &str,
    ) -> mongodb::error::Result<()> {
        if let Some(entry) = Self::find_for_user_and_path(db, user_id, file_path).await? {
            Self::release_quota_for_entry(db, &entry).await?;
        }
        Self::collection(db)
            .delete_one(doc! { "filePath": file_path, "userId": user_id })
            .await?;
        Ok(())
    }

    pub async fn finalize_send_claim(
        db: &Database,
        user_id: ObjectId,
        file_path: &str,
    ) -> mongodb::error::Result<()> {
        if let Some(entry) = Self::find_for_user_and_path(db, user_id, file_path).await? {
            if entry.quota_accounting_version >= 2 {
                if let Some(id) = entry.id {
                    crate::model::storage_usage::UserStorageUsage::commit_upload_reservation(
                        db, user_id, id,
                    )
                    .await?;
                }
            }
        }
        Self::collection(db)
            .delete_one(doc! {
                "filePath": file_path,
                "userId": user_id,
                "sendClaimedAt": { "$exists": true },
            })
            .await?;
        Ok(())
    }

    async fn release_quota_for_entry(
        db: &Database,
        entry: &PendingUpload,
    ) -> mongodb::error::Result<()> {
        let Some(id) = entry.id else {
            return Ok(());
        };
        let legacy_bytes =
            (entry.quota_accounting_version < 2 && entry.quota_reserved).then_some(entry.file_size);
        crate::model::storage_usage::UserStorageUsage::release_upload_reservation(
            db,
            entry.user_id,
            id,
            legacy_bytes,
        )
        .await?;
        Ok(())
    }

    pub async fn reserve_for_send(
        db: &Database,
        user_id: ObjectId,
        file_path: &str,
    ) -> mongodb::error::Result<bool> {
        let now = DateTime::now();
        let lease_expired =
            DateTime::from_millis(now.timestamp_millis().saturating_sub(Self::CLAIM_LEASE_MS));
        let result = Self::collection(db)
            .update_one(
                doc! {
                    "userId": user_id,
                    "filePath": file_path,
                    "$and": [
                        { "$or": [
                            { "sendClaimedAt": { "$exists": false } },
                            { "sendClaimedAt": { "$lt": lease_expired } },
                        ] },
                        { "$or": [
                            { "cleanupClaimedAt": { "$exists": false } },
                            { "cleanupClaimedAt": { "$lt": lease_expired } },
                        ] },
                    ],
                },
                doc! {
                    "$set": { "sendClaimedAt": now },
                    "$unset": { "cleanupClaimedAt": "" },
                },
            )
            .await?;
        Ok(result.matched_count > 0)
    }

    pub async fn release_send_claim(
        db: &Database,
        user_id: ObjectId,
        file_path: &str,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_one(
                doc! {
                    "userId": user_id,
                    "filePath": file_path,
                    "sendClaimedAt": { "$exists": true },
                },
                doc! { "$unset": { "sendClaimedAt": "" } },
            )
            .await?;
        Ok(())
    }

    pub async fn mark_quota_reserved(
        db: &Database,
        user_id: ObjectId,
        file_path: &str,
    ) -> mongodb::error::Result<bool> {
        let result = Self::collection(db)
            .update_one(
                doc! { "userId": user_id, "filePath": file_path },
                doc! { "$set": { "quotaReserved": true } },
            )
            .await?;
        Ok(result.matched_count > 0)
    }

    async fn claim_for_cleanup(
        db: &Database,
        id: ObjectId,
        cutoff: DateTime,
        now: DateTime,
    ) -> mongodb::error::Result<bool> {
        let lease_expired =
            DateTime::from_millis(now.timestamp_millis().saturating_sub(Self::CLAIM_LEASE_MS));
        let result = Self::collection(db)
            .update_one(
                doc! {
                    "_id": id,
                    "createdAt": { "$lt": cutoff },
                    "$and": [
                        { "$or": [
                            { "sendClaimedAt": { "$exists": false } },
                            { "sendClaimedAt": { "$lt": lease_expired } },
                        ] },
                        { "$or": [
                            { "cleanupClaimedAt": { "$exists": false } },
                            { "cleanupClaimedAt": { "$lt": lease_expired } },
                        ] },
                    ],
                },
                doc! {
                    "$set": { "cleanupClaimedAt": now },
                    "$unset": { "sendClaimedAt": "" },
                },
            )
            .await?;
        Ok(result.matched_count > 0)
    }

    pub async fn cleanup_orphans(db: &Database) -> mongodb::error::Result<u64> {
        use futures_util::TryStreamExt;

        let now = DateTime::now();
        let cutoff_ms = now.timestamp_millis().saturating_sub(3_600_000);
        let cutoff = DateTime::from_millis(cutoff_ms);

        let cursor = Self::collection(db)
            .find(doc! { "createdAt": { "$lt": cutoff } })
            .await?;
        let entries: Vec<PendingUpload> = cursor.try_collect().await?;

        let mut removed = 0u64;
        for entry in entries {
            let Some(id) = entry.id else {
                continue;
            };
            let claim_time = DateTime::now();
            if !Self::claim_for_cleanup(db, id, cutoff, claim_time).await? {
                continue;
            }

            let aliases = attachment_stored_url_aliases(&entry.file_path, &cdn_public_base_url());
            let referenced = Message::collection(db)
                .count_documents(doc! {
                    "deleted": { "$ne": true },
                    "fileUrl": { "$in": aliases },
                })
                .await?;
            if referenced > 0 {
                if entry.quota_accounting_version >= 2 {
                    Self::commit_quota_reservation(db, &entry).await?;
                }
                Self::collection(db)
                    .delete_one(doc! { "_id": id, "cleanupClaimedAt": claim_time })
                    .await?;
                removed += 1;
                log::warn!(
                    "Removed stale pending-upload record for active message attachment {} without deleting the object",
                    entry.file_path
                );
                continue;
            }

            let object_size = crate::utils::storage::storage()
                .head_attachment_content_length(&entry.file_path)
                .await
                .map_err(|error| {
                    mongodb::error::Error::custom(format!(
                        "inspect orphaned upload {}: {error}",
                        entry.file_path
                    ))
                })?;
            let thumb_size = match crate::utils::storage::attachment_thumb_key(&entry.file_path) {
                Some(thumb) => crate::utils::storage::storage()
                    .head_attachment_content_length(&thumb)
                    .await
                    .map_err(|error| {
                        mongodb::error::Error::custom(format!(
                            "inspect orphaned upload thumbnail {thumb}: {error}"
                        ))
                    })?,
                None => None,
            };

            crate::utils::storage::storage()
                .delete_attachment_key(&entry.file_path)
                .await
                .map_err(|error| {
                    mongodb::error::Error::custom(format!(
                        "delete orphaned upload {}: {error}",
                        entry.file_path
                    ))
                })?;

            let measured_size = object_size
                .unwrap_or_default()
                .saturating_add(thumb_size.unwrap_or_default());
            let legacy_bytes = (entry.quota_accounting_version < 2 && entry.quota_reserved)
                .then_some(if entry.file_size > 0 {
                    entry.file_size
                } else {
                    measured_size
                });
            crate::model::storage_usage::UserStorageUsage::release_upload_reservation(
                db,
                entry.user_id,
                id,
                legacy_bytes,
            )
            .await
            .map_err(|error| {
                mongodb::error::Error::custom(format!(
                    "release storage quota for orphaned upload {}: {error}",
                    entry.file_path
                ))
            })?;

            Self::collection(db)
                .delete_one(doc! { "_id": id, "cleanupClaimedAt": claim_time })
                .await?;
            removed += 1;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use mongodb::bson::{doc, oid::ObjectId, DateTime};

    use super::PendingUpload;

    #[test]
    fn legacy_pending_upload_defaults_to_unreserved_quota() {
        let document = doc! {
            "userId": ObjectId::new(),
            "filePath": "attachments/test/file.bin",
            "contextType": "dm",
            "contextId": "conversation",
            "createdAt": DateTime::now(),
        };

        let upload: PendingUpload = mongodb::bson::from_document(document).unwrap();

        assert!(!upload.quota_reserved);
        assert_eq!(upload.quota_accounting_version, 0);
    }
}
