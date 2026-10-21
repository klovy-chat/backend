use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageObjectKind {
    Avatar,
    PublicMedia,
}

impl StorageObjectKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Avatar => "avatar",
            Self::PublicMedia => "public_media",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingStorageDeletion {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    key: String,
    kind: String,
    #[serde(rename = "createdAt")]
    created_at: DateTime,
}

impl PendingStorageDeletion {
    fn collection(db: &Database) -> Collection<Self> {
        db.collection("pending_storage_deletions")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "key": 1, "kind": 1 })
                    .options(
                        mongodb::options::IndexOptions::builder()
                            .unique(true)
                            .build(),
                    )
                    .build(),
            )
            .await?;
        Ok(())
    }

    pub async fn delete_or_defer(
        db: &Database,
        key: &str,
        kind: StorageObjectKind,
    ) -> mongodb::error::Result<()> {
        let deletion = match kind {
            StorageObjectKind::Avatar => {
                crate::utils::storage::storage()
                    .delete_avatar_key(key)
                    .await
            }
            StorageObjectKind::PublicMedia => {
                crate::utils::storage::storage()
                    .delete_public_media_key(key)
                    .await
            }
        };

        if let Err(error) = deletion {
            log::warn!("Storage deletion failed for {key}; scheduling retry: {error}");
            Self::collection(db)
                .update_one(
                    doc! { "key": key, "kind": kind.as_str() },
                    doc! { "$setOnInsert": {
                        "key": key,
                        "kind": kind.as_str(),
                        "createdAt": DateTime::now(),
                    } },
                )
                .upsert(true)
                .await
                .map_err(|db_error| {
                    mongodb::error::Error::custom(format!(
                        "schedule storage deletion for {key} after {error}: {db_error}"
                    ))
                })?;
        }
        Ok(())
    }

    pub async fn process_pending(db: &Database) -> mongodb::error::Result<u64> {
        let mut cursor = Self::collection(db).find(doc! {}).await?;
        let mut deleted = 0;

        while let Some(pending) = cursor.try_next().await? {
            let result = match pending.kind.as_str() {
                "avatar" => {
                    crate::utils::storage::storage()
                        .delete_avatar_key(&pending.key)
                        .await
                }
                "public_media" => {
                    crate::utils::storage::storage()
                        .delete_public_media_key(&pending.key)
                        .await
                }
                kind => {
                    log::error!(
                        "Unknown pending storage deletion kind {kind} for {}",
                        pending.key
                    );
                    continue;
                }
            };

            if let Err(error) = result {
                log::warn!(
                    "Pending storage deletion failed for {}: {error}",
                    pending.key
                );
                continue;
            }

            if let Some(id) = pending.id {
                Self::collection(db).delete_one(doc! { "_id": id }).await?;
                deleted += 1;
            }
        }
        Ok(deleted)
    }
}
