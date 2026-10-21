// uploads.rs
// Pending upload: klucz R2, size, hash, owner, kontekst.
// Zakres:
//  - zanim powstanie Message
//  - pending R2 zanim powstanie Message; TTL + reconcile
// Reconcile kasuje osierocone; nie zostawiaj pending bez TTL.
// Przy zmianach: utils/storage/reconcile.rs, messages/access.rs.

use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};

use crate::model::scan::{default_pending_scan_status, ScanStatus};

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
}

impl PendingUpload {
    pub fn collection(db: &Database) -> Collection<Self> {
        db.collection("pending_uploads")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        use mongodb::options::IndexOptions;

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
    ) -> mongodb::error::Result<()> {
        let pending = Self::count_for_user(db, user_id).await?;
        if pending >= crate::utils::upload::MAX_PENDING_UPLOADS_PER_USER {
            return Err(mongodb::error::Error::custom("too many pending uploads"));
        }

        let doc = PendingUpload {
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
        };
        Self::collection(db).insert_one(doc).await?;
        Ok(())
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

    pub async fn find_by_path(db: &Database, file_path: &str) -> mongodb::error::Result<Option<Self>> {
        Self::collection(db)
            .find_one(doc! { "filePath": file_path })
            .await
    }

    pub async fn claim_by_path(
        db: &Database,
        user_id: ObjectId,
        file_path: &str,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .delete_one(doc! { "filePath": file_path, "userId": user_id })
            .await?;
        Ok(())
    }

    pub async fn cleanup_orphans(db: &Database) -> mongodb::error::Result<u64> {
        use futures_util::TryStreamExt;

        let cutoff_ms = DateTime::now().timestamp_millis().saturating_sub(3_600_000);
        let cutoff = DateTime::from_millis(cutoff_ms);

        let cursor = Self::collection(db)
            .find(doc! { "createdAt": { "$lt": cutoff } })
            .await?;
        let entries: Vec<PendingUpload> = cursor.try_collect().await?;

        let mut removed = 0u64;
        for entry in entries {
            let object_size = crate::utils::storage::storage()
                .head_attachment_content_length(&entry.file_path)
                .await
                .map_err(|error| {
                    mongodb::error::Error::custom(format!(
                        "inspect orphaned upload {}: {error}",
                        entry.file_path
                    ))
                })?;

            crate::utils::storage::storage()
                .delete_attachment_key(&entry.file_path)
                .await
                .map_err(|error| {
                    mongodb::error::Error::custom(format!(
                        "delete orphaned upload {}: {error}",
                        entry.file_path
                    ))
                })?;

            // Do not decrement usage for an object already deleted by an earlier attempt.
            if let Some(object_size) = object_size {
                let size = if entry.file_size > 0 {
                    entry.file_size
                } else {
                    object_size
                };
                if size > 0 {
                    crate::model::storage_usage::UserStorageUsage::adjust(
                        db,
                        entry.user_id,
                        -(size as i64),
                    )
                    .await
                    .map_err(|error| {
                        mongodb::error::Error::custom(format!(
                            "adjust storage usage for orphaned upload {}: {error}",
                            entry.file_path
                        ))
                    })?;
                }
            }

            if let Some(id) = entry.id {
                Self::collection(db).delete_one(doc! { "_id": id }).await?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}
