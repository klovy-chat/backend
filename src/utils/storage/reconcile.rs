// reconcile.rs
// Sprzątanie pending vs obiekty w R2.
// Zakres:
//  - start / job
//  - kasuj pending bez message; nie ruszaj żywego klucza
// Nie kasuj obiektu jeśli message wciąż wskazuje klucz.
// Przy zmianach: uploads.rs, main.rs.

use std::collections::{HashMap, HashSet};

use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::Database;

use crate::model::messages::Message;
use crate::model::storage_usage::UserStorageUsage;
use crate::model::uploads::PendingUpload;
use crate::utils::storage::{is_attachment_key, storage, StorageError};

#[derive(Debug, Default)]
pub struct ReconcileReport {
    pub orphan_objects_deleted: u64,
    pub missing_objects: u64,
    pub usage_users_updated: u64,
}

pub async fn reconcile_attachments(db: &Database) -> Result<ReconcileReport, StorageError> {
    let mut report = ReconcileReport::default();

    let referenced = collect_referenced_paths(db).await.map_err(|e| {
        StorageError::DatabaseFailed(format!("attachment reference scan failed: {e}"))
    })?;
    let public_objects = storage().list_public_attachments().await?;
    let quarantine_objects = storage().list_quarantine_attachments().await?;

    let mut r2_keys: HashSet<String> = HashSet::new();
    for (key, _) in public_objects.iter().chain(quarantine_objects.iter()) {
        r2_keys.insert(key.clone());
    }

    for key in r2_keys.iter() {
        if referenced.contains(key) {
            continue;
        }
        if storage().delete_attachment_key(key).await.is_ok() {
            report.orphan_objects_deleted += 1;
        }
    }

    for path in &referenced {
        if !r2_keys.contains(path) {
            report.missing_objects += 1;
            log::warn!("Attachment referenced in MongoDB but missing in R2: {path}");
        }
    }

    match rebuild_user_storage_usage(db).await {
        Ok(updated) => report.usage_users_updated = updated,
        Err(e) => log::warn!("Storage usage rebuild failed: {e}"),
    }

    Ok(report)
}

async fn collect_referenced_paths(db: &Database) -> mongodb::error::Result<HashSet<String>> {
    let mut paths = HashSet::new();

    let mut pending_cursor = PendingUpload::collection(db).find(doc! {}).await?;
    while let Some(entry) = pending_cursor.try_next().await? {
        paths.insert(entry.file_path);
    }

    let mut message_cursor = Message::collection(db)
        .find(doc! {
            "deleted": { "$ne": true },
            "fileUrl": { "$exists": true, "$ne": null },
        })
        .await?;
    while let Some(msg) = message_cursor.try_next().await? {
        if let Some(url) = msg.file_url {
            let normalized = url
                .trim()
                .replace('\\', "/")
                .trim_start_matches('/')
                .to_string();
            if is_attachment_key(&normalized) {
                paths.insert(normalized);
            }
        }
    }

    Ok(paths)
}

async fn rebuild_user_storage_usage(db: &Database) -> mongodb::error::Result<u64> {
    let mut usage: HashMap<ObjectId, i64> = HashMap::new();

    let pending_cursor = PendingUpload::collection(db).find(doc! {}).await?;
    let pending: Vec<PendingUpload> = pending_cursor.try_collect().await?;
    for entry in pending {
        *usage.entry(entry.user_id).or_insert(0) += entry.file_size as i64;
    }

    let msg_cursor = Message::collection(db)
        .find(doc! {
            "deleted": { "$ne": true },
            "fileUrl": { "$regex": "^attachments/" },
        })
        .await?;
    let messages: Vec<Message> = msg_cursor.try_collect().await?;
    for msg in messages {
        let Some(size) = msg.file_size else {
            continue;
        };
        *usage.entry(msg.sender).or_insert(0) += size as i64;
    }

    let mut updated = 0u64;
    for (user_id, bytes) in &usage {
        UserStorageUsage::set_bytes(db, *user_id, *bytes).await?;
        updated += 1;
    }

    let existing = UserStorageUsage::collection(db).find(doc! {}).await?;
    let rows: Vec<UserStorageUsage> = existing.try_collect().await?;
    for row in rows {
        if usage.contains_key(&row.user_id) {
            continue;
        }
        if row.bytes_used <= 0 {
            continue;
        }
        UserStorageUsage::set_bytes(db, row.user_id, 0).await?;
        updated += 1;
    }

    Ok(updated)
}
