// storage_usage.rs
// Suma bajtów usera (avatar/banner/załączniki).
// Zakres:
//  - limit quota
//  - suma bajtów; inc/dec przy upload/delete
// Inkrementuj/dekrementuj przy upload/delete, nie przeliczaj zawsze full scan.
// Przy zmianach: controllers upload, storage/r2.rs.

use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime};
use mongodb::options::IndexOptions;
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStorageUsage {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    #[serde(rename = "userId")]
    pub user_id: ObjectId,
    #[serde(rename = "bytesUsed", default)]
    pub bytes_used: i64,
    #[serde(default)]
    pub revision: i64,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateUsageMigrationReport {
    pub users_merged: u64,
    pub records_merged: u64,
}

impl UserStorageUsage {
    pub fn collection(db: &Database) -> Collection<Self> {
        db.collection("user_storage_usage")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        Self::merge_duplicate_user_records(db, false).await?;

        let collection = Self::collection(db);
        if let Err(error) = collection.drop_index("userId_1".to_string()).await {
            if !matches!(
                error.kind.as_ref(),
                mongodb::error::ErrorKind::Command(command) if command.code == 27
            ) {
                return Err(error);
            }
        }

        collection
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "userId": 1 })
                    .options(
                        IndexOptions::builder()
                            .name("userId_unique".to_string())
                            .unique(true)
                            .build(),
                    )
                    .build(),
            )
            .await?;
        Ok(())
    }

    pub async fn merge_duplicate_user_records(
        db: &Database,
        dry_run: bool,
    ) -> mongodb::error::Result<DuplicateUsageMigrationReport> {
        let pipeline = vec![
            doc! { "$sort": { "_id": 1 } },
            doc! {
                "$group": {
                    "_id": "$userId",
                    "ids": { "$push": "$_id" },
                    "totalBytes": {
                        "$sum": {
                            "$max": [
                                {
                                    "$convert": {
                                        "input": "$bytesUsed",
                                        "to": "long",
                                        "onError": 0,
                                        "onNull": 0,
                                    }
                                },
                                0,
                            ]
                        }
                    },
                }
            },
            doc! {
                "$match": {
                    "$expr": { "$gt": [{ "$size": "$ids" }, 1] }
                }
            },
        ];

        let mut cursor = Self::collection(db)
            .aggregate(pipeline)
            .allow_disk_use(true)
            .await?;
        let mut report = DuplicateUsageMigrationReport::default();
        while let Some(group) = cursor.try_next().await? {
            let user_id = group.get_object_id("_id").map_err(|_| {
                mongodb::error::Error::custom(
                    "Cannot merge duplicate storage usage records with missing or invalid userId",
                )
            })?;
            let ids = group
                .get_array("ids")
                .map_err(|error| mongodb::error::Error::custom(error.to_string()))?
                .iter()
                .map(|value| match value {
                    Bson::ObjectId(id) => Ok(*id),
                    _ => Err(mongodb::error::Error::custom(
                        "Storage usage record has an invalid _id",
                    )),
                })
                .collect::<mongodb::error::Result<Vec<_>>>()?;
            let Some((&keep_id, duplicate_ids)) = ids.split_first() else {
                continue;
            };
            let total_bytes = group
                .get("totalBytes")
                .and_then(Self::bson_i64_saturating)
                .unwrap_or(0);

            if !dry_run {
                let collection = Self::collection(db);
                collection
                    .update_one(
                        doc! { "_id": keep_id },
                        doc! {
                            "$set": {
                                "bytesUsed": total_bytes,
                                "updatedAt": DateTime::now(),
                            }
                        },
                    )
                    .await?;
                collection
                    .delete_many(doc! { "_id": { "$in": duplicate_ids } })
                    .await?;
            }

            report.users_merged += 1;
            report.records_merged += duplicate_ids.len() as u64;
            log::warn!(
                "{} duplicate storage usage record(s) for user {}; {} bytes after merge{}",
                duplicate_ids.len(),
                user_id.to_hex(),
                total_bytes,
                if dry_run { " (dry run)" } else { "" }
            );
        }
        Ok(report)
    }

    pub async fn bytes_used(db: &Database, user_id: ObjectId) -> mongodb::error::Result<i64> {
        Ok(Self::collection(db)
            .find_one(doc! { "userId": user_id })
            .await?
            .map(|entry| entry.bytes_used.max(0))
            .unwrap_or(0))
    }

    fn bson_i64_saturating(value: &Bson) -> Option<i64> {
        match value {
            Bson::Int32(value) => Some(i64::from(*value)),
            Bson::Int64(value) => Some(*value),
            Bson::Double(value) if value.is_finite() && *value >= i64::MAX as f64 => Some(i64::MAX),
            Bson::Double(value) if value.is_finite() && *value <= i64::MIN as f64 => Some(i64::MIN),
            Bson::Double(value) if value.is_finite() => Some(*value as i64),
            _ => None,
        }
    }

    pub async fn would_exceed(
        db: &Database,
        user_id: ObjectId,
        additional: u64,
    ) -> mongodb::error::Result<bool> {
        let max = crate::utils::upload::max_user_storage_bytes();
        let current = Self::bytes_used(db, user_id).await?;
        Ok(quota_would_exceed(current, additional, max))
    }

    pub async fn reserve(
        db: &Database,
        user_id: ObjectId,
        additional: u64,
    ) -> mongodb::error::Result<bool> {
        let max = crate::utils::upload::max_user_storage_bytes();
        let Ok(additional) = i64::try_from(additional) else {
            return Ok(false);
        };
        let max = i64::try_from(max).unwrap_or(i64::MAX);
        if additional > max {
            return Ok(false);
        }

        let collection = Self::collection(db);
        if let Err(error) = collection
            .update_one(
                doc! { "userId": user_id },
                doc! {
                    "$setOnInsert": {
                        "userId": user_id,
                        "bytesUsed": 0,
                        "revision": 0,
                        "updatedAt": DateTime::now(),
                    },
                },
            )
            .upsert(true)
            .await
        {
            let duplicate_key = matches!(
                error.kind.as_ref(),
                mongodb::error::ErrorKind::Write(
                    mongodb::error::WriteFailure::WriteError(write_error)
                ) if write_error.code == 11000
            );
            if !duplicate_key {
                return Err(error);
            }
        }

        let current_with_additional = doc! {
            "$add": [
                { "$max": [{ "$ifNull": ["$bytesUsed", 0] }, 0] },
                additional,
            ],
        };
        let result = collection
            .update_one(
                doc! {
                    "userId": user_id,
                    "$expr": { "$lte": [current_with_additional.clone(), max] },
                },
                vec![doc! {
                    "$set": {
                        "bytesUsed": current_with_additional,
                        "revision": { "$add": [{ "$ifNull": ["$revision", 0] }, 1] },
                        "updatedAt": DateTime::now(),
                    },
                }],
            )
            .await?;
        Ok(result.matched_count > 0)
    }

    pub async fn reserve_for_upload(
        db: &Database,
        user_id: ObjectId,
        additional: u64,
        reservation_id: ObjectId,
    ) -> mongodb::error::Result<bool> {
        let max = crate::utils::upload::max_user_storage_bytes();
        let Ok(additional) = i64::try_from(additional) else {
            return Ok(false);
        };
        let max = i64::try_from(max).unwrap_or(i64::MAX);
        if additional > max {
            return Ok(false);
        }

        let collection = Self::collection(db);
        if let Err(error) = collection
            .update_one(
                doc! { "userId": user_id },
                doc! {
                    "$setOnInsert": {
                        "userId": user_id,
                        "bytesUsed": 0,
                        "revision": 0,
                        "updatedAt": DateTime::now(),
                    },
                },
            )
            .upsert(true)
            .await
        {
            let duplicate_key = matches!(
                error.kind.as_ref(),
                mongodb::error::ErrorKind::Write(
                    mongodb::error::WriteFailure::WriteError(write_error)
                ) if write_error.code == 11000
            );
            if !duplicate_key {
                return Err(error);
            }
        }
        let token = reservation_id.to_hex();
        let reservations = doc! { "$ifNull": ["$quotaReservations", []] };
        let token_exists = doc! {
            "$in": [
                { "$literal": &token },
                {
                    "$map": {
                        "input": reservations.clone(),
                        "as": "reservation",
                        "in": "$$reservation.token",
                    }
                },
            ],
        };
        let current_with_additional = doc! {
            "$add": [
                { "$max": [{ "$ifNull": ["$bytesUsed", 0] }, 0] },
                additional,
            ],
        };
        let result = collection
            .update_one(
                doc! {
                    "userId": user_id,
                    "$expr": {
                        "$or": [
                            token_exists.clone(),
                            { "$lte": [current_with_additional.clone(), max] },
                        ],
                    },
                },
                vec![doc! {
                    "$set": {
                        "bytesUsed": {
                            "$cond": [
                                token_exists.clone(),
                                { "$ifNull": ["$bytesUsed", 0] },
                                current_with_additional,
                            ],
                        },
                        "quotaReservations": {
                            "$cond": [
                                token_exists,
                                reservations.clone(),
                                {
                                    "$concatArrays": [
                                        reservations,
                                        [{ "token": &token, "bytes": additional }],
                                    ],
                                },
                            ],
                        },
                        "revision": {
                            "$add": [{ "$ifNull": ["$revision", 0] }, 1],
                        },
                        "updatedAt": DateTime::now(),
                    },
                }],
            )
            .await?;
        Ok(result.matched_count > 0)
    }

    pub async fn release_upload_reservation(
        db: &Database,
        user_id: ObjectId,
        reservation_id: ObjectId,
        legacy_bytes: Option<u64>,
    ) -> mongodb::error::Result<bool> {
        let token = reservation_id.to_hex();
        let reservations = doc! { "$ifNull": ["$quotaReservations", []] };
        let token_exists = doc! {
            "$in": [
                { "$literal": &token },
                {
                    "$map": {
                        "input": reservations.clone(),
                        "as": "reservation",
                        "in": "$$reservation.token",
                    }
                },
            ],
        };
        let already_released = doc! {
            "$in": [
                { "$literal": &token },
                { "$ifNull": ["$releasedQuotaUploads", []] },
            ],
        };
        let legacy_bytes = i64::try_from(legacy_bytes.unwrap_or_default()).unwrap_or(i64::MAX);
        let result = Self::collection(db)
            .update_one(
                doc! {
                    "userId": user_id,
                    "$expr": {
                        "$or": [
                            token_exists.clone(),
                            { "$and": [{ "$gt": [legacy_bytes, 0] }, { "$not": [already_released.clone()] }] },
                        ],
                    },
                },
                vec![doc! {
                    "$set": {
                        "bytesUsed": {
                            "$max": [
                                0,
                                {
                                    "$subtract": [
                                        { "$ifNull": ["$bytesUsed", 0] },
                                        {
                                            "$cond": [
                                                token_exists.clone(),
                                                {
                                                    "$reduce": {
                                                        "input": reservations.clone(),
                                                        "initialValue": 0,
                                                        "in": {
                                                            "$cond": [
                                                                { "$eq": ["$$this.token", &token] },
                                                                { "$add": ["$$value", "$$this.bytes"] },
                                                                "$$value",
                                                            ],
                                                        },
                                                    },
                                                },
                                                legacy_bytes,
                                            ],
                                        },
                                    ],
                                },
                            ],
                        },
                        "quotaReservations": {
                            "$filter": {
                                "input": reservations,
                                "as": "reservation",
                                "cond": { "$ne": ["$$reservation.token", &token] },
                            },
                        },
                        "releasedQuotaUploads": {
                            "$cond": [
                                token_exists,
                                { "$ifNull": ["$releasedQuotaUploads", []] },
                                {
                                    "$concatArrays": [
                                        { "$ifNull": ["$releasedQuotaUploads", []] },
                                        [{ "$literal": &token }],
                                    ],
                                },
                            ],
                        },
                        "revision": {
                            "$add": [{ "$ifNull": ["$revision", 0] }, 1],
                        },
                        "updatedAt": DateTime::now(),
                    },
                }],
            )
            .await?;
        Ok(result.matched_count > 0)
    }

    pub async fn commit_upload_reservation(
        db: &Database,
        user_id: ObjectId,
        reservation_id: ObjectId,
    ) -> mongodb::error::Result<()> {
        let token = reservation_id.to_hex();
        Self::collection(db)
            .update_one(
                doc! {
                    "userId": user_id,
                    "quotaReservations.token": &token,
                },
                vec![doc! {
                    "$set": {
                        "quotaReservations": {
                            "$filter": {
                                "input": { "$ifNull": ["$quotaReservations", []] },
                                "as": "reservation",
                                "cond": { "$ne": ["$$reservation.token", &token] },
                            },
                        },
                        "revision": {
                            "$add": [{ "$ifNull": ["$revision", 0] }, 1],
                        },
                        "updatedAt": DateTime::now(),
                    },
                }],
            )
            .await?;
        Ok(())
    }

    pub async fn adjust(
        db: &Database,
        user_id: ObjectId,
        delta: i64,
    ) -> mongodb::error::Result<()> {
        if delta == 0 {
            return Ok(());
        }
        Self::collection(db)
            .update_one(
                doc! { "userId": user_id },
                doc! {
                    "$inc": { "bytesUsed": delta, "revision": 1 },
                    "$set": { "updatedAt": DateTime::now() },
                    "$setOnInsert": { "userId": user_id },
                },
            )
            .upsert(true)
            .await?;
        Ok(())
    }

    pub async fn debit_attachment_cleanup_once(
        db: &Database,
        user_id: ObjectId,
        key: &str,
        bytes: i64,
    ) -> mongodb::error::Result<bool> {
        if bytes <= 0 {
            return Ok(false);
        }
        let collection = Self::collection(db);
        match collection
            .update_one(
                doc! {
                    "userId": user_id,
                    "attachmentCleanupKeys": { "$ne": key },
                },
                doc! {
                    "$inc": { "bytesUsed": -bytes, "revision": 1 },
                    "$addToSet": { "attachmentCleanupKeys": key },
                    "$set": { "updatedAt": DateTime::now() },
                    "$setOnInsert": { "userId": user_id },
                },
            )
            .upsert(true)
            .await
        {
            Ok(result) => Ok(result.matched_count > 0 || result.upserted_id.is_some()),
            Err(error)
                if matches!(
                    error.kind.as_ref(),
                    mongodb::error::ErrorKind::Write(
                        mongodb::error::WriteFailure::WriteError(write_error)
                    ) if write_error.code == 11000
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    pub async fn restore_attachment_cleanup(
        db: &Database,
        user_id: ObjectId,
        key: &str,
        bytes: i64,
    ) -> mongodb::error::Result<bool> {
        let result = Self::collection(db)
            .update_one(
                doc! {
                    "userId": user_id,
                    "attachmentCleanupKeys": key,
                },
                doc! {
                    "$inc": { "bytesUsed": bytes.max(0), "revision": 1 },
                    "$pull": { "attachmentCleanupKeys": key },
                    "$set": { "updatedAt": DateTime::now() },
                },
            )
            .await?;
        Ok(result.matched_count > 0)
    }

    pub async fn clear_attachment_cleanup_marker(
        db: &Database,
        user_id: ObjectId,
        key: &str,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_one(
                doc! { "userId": user_id },
                doc! {
                    "$pull": { "attachmentCleanupKeys": key },
                    "$set": { "updatedAt": DateTime::now() },
                },
            )
            .await?;
        Ok(())
    }

    pub async fn set_bytes(
        db: &Database,
        user_id: ObjectId,
        bytes: i64,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_one(
                doc! { "userId": user_id },
                doc! {
                    "$set": {
                        "bytesUsed": bytes.max(0),
                        "updatedAt": DateTime::now(),
                    },
                    "$inc": { "revision": 1 },
                    "$setOnInsert": { "userId": user_id },
                },
            )
            .upsert(true)
            .await?;
        Ok(())
    }

    pub async fn set_bytes_if_unchanged(
        db: &Database,
        user_id: ObjectId,
        expected_revision: Option<i64>,
        bytes: i64,
    ) -> mongodb::error::Result<bool> {
        let collection = Self::collection(db);
        let bytes = bytes.max(0);
        let Some(expected_revision) = expected_revision else {
            let row = Self {
                id: None,
                user_id,
                bytes_used: bytes,
                revision: 1,
                updated_at: DateTime::now(),
            };
            return match collection.insert_one(row).await {
                Ok(_) => Ok(true),
                Err(error)
                    if matches!(
                        error.kind.as_ref(),
                        mongodb::error::ErrorKind::Write(
                            mongodb::error::WriteFailure::WriteError(write_error)
                        ) if write_error.code == 11000
                    ) =>
                {
                    Ok(false)
                }
                Err(error) => Err(error),
            };
        };

        let filter = if expected_revision == 0 {
            doc! {
                "userId": user_id,
                "$or": [
                    { "revision": 0 },
                    { "revision": { "$exists": false } },
                ],
            }
        } else {
            doc! { "userId": user_id, "revision": expected_revision }
        };
        let result = collection
            .update_one(
                filter,
                doc! {
                    "$set": {
                        "bytesUsed": bytes,
                        "updatedAt": DateTime::now(),
                    },
                    "$inc": { "revision": 1 },
                },
            )
            .await?;
        Ok(result.matched_count == 1)
    }
}

fn quota_would_exceed(current: i64, additional: u64, max: u64) -> bool {
    let Ok(additional) = i64::try_from(additional) else {
        return true;
    };
    let max = i64::try_from(max).unwrap_or(i64::MAX);
    current.max(0).saturating_add(additional) > max
}

#[cfg(test)]
mod tests {
    use super::quota_would_exceed;

    #[test]
    fn quota_check_allows_exact_limit_and_rejects_overflow() {
        assert!(!quota_would_exceed(90, 10, 100));
        assert!(quota_would_exceed(90, 11, 100));
        assert!(!quota_would_exceed(-1, 100, 100));
        assert!(quota_would_exceed(0, u64::MAX, 100));
    }
}
