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
use crate::utils::messages::access::canonicalize_message_file_url;
use crate::utils::storage::{cdn_public_base_url, is_attachment_key, storage, StorageError};

#[derive(Debug, Default)]
pub struct ReconcileReport {
    pub orphan_objects_deleted: u64,
    pub missing_objects: u64,
    pub usage_users_updated: u64,
    pub usage_users_skipped_concurrent: u64,
}

pub async fn reconcile_attachments(db: &Database) -> Result<ReconcileReport, StorageError> {
    let mut report = ReconcileReport::default();
    let usage_snapshot = collect_usage_snapshot(db).await.map_err(|error| {
        StorageError::DatabaseFailed(format!("storage usage snapshot failed: {error}"))
    })?;

    let referenced = collect_referenced_paths(db).await.map_err(|e| {
        StorageError::DatabaseFailed(format!("attachment reference scan failed: {e}"))
    })?;
    let public_objects = storage().list_public_attachments().await?;
    let quarantine_objects = storage().list_quarantine_attachments().await?;

    let mut r2_keys: HashSet<String> = HashSet::new();
    for (key, _) in public_objects.iter().chain(quarantine_objects.iter()) {
        r2_keys.insert(key.clone());
    }

    let referenced_before_deletion = collect_referenced_paths(db).await.map_err(|error| {
        StorageError::DatabaseFailed(format!(
            "attachment reference recheck failed before orphan cleanup: {error}"
        ))
    })?;

    for key in r2_keys.iter() {
        if referenced.contains(key) || referenced_before_deletion.contains(key) {
            continue;
        }
        storage().delete_attachment_key(key).await?;
        report.orphan_objects_deleted += 1;
    }

    for path in &referenced {
        if !r2_keys.contains(path) {
            report.missing_objects += 1;
            log::warn!("Attachment referenced in MongoDB but missing in R2: {path}");
        }
    }

    report.usage_users_updated = rebuild_user_storage_usage(
        db,
        &public_objects,
        &quarantine_objects,
        &usage_snapshot,
        &mut report.usage_users_skipped_concurrent,
    )
    .await
    .map_err(|e| StorageError::DatabaseFailed(format!("storage usage rebuild failed: {e}")))?;

    Ok(report)
}

async fn collect_usage_snapshot(
    db: &Database,
) -> mongodb::error::Result<HashMap<ObjectId, (i64, i64)>> {
    let mut cursor = UserStorageUsage::collection(db).find(doc! {}).await?;
    let mut snapshot = HashMap::new();
    while let Some(row) = cursor.try_next().await? {
        snapshot.insert(row.user_id, (row.revision, row.bytes_used));
    }
    Ok(snapshot)
}

async fn collect_referenced_paths(db: &Database) -> mongodb::error::Result<HashSet<String>> {
    let mut paths = HashSet::new();

    let mut pending_cursor = PendingUpload::collection(db).find(doc! {}).await?;
    while let Some(entry) = pending_cursor.try_next().await? {
        insert_attachment_reference(&mut paths, entry.file_path);
    }

    let mut message_cursor = Message::collection(db)
        .find(doc! {
            "deleted": { "$ne": true },
            "fileUrl": { "$exists": true, "$ne": null },
        })
        .await?;
    while let Some(msg) = message_cursor.try_next().await? {
        if let Some(url) = msg.file_url {
            if let Some(path) = canonicalize_message_file_url(&url, &cdn_public_base_url()) {
                if is_attachment_key(&path) {
                    insert_attachment_reference(&mut paths, path);
                }
            }
        }
    }

    Ok(paths)
}

fn insert_attachment_reference(paths: &mut HashSet<String>, path: String) {
    if let Some(thumb) = crate::utils::storage::attachment_thumb_key(&path) {
        paths.insert(thumb);
    }
    paths.insert(path);
}

async fn rebuild_user_storage_usage(
    db: &Database,
    public_objects: &[(String, u64)],
    quarantine_objects: &[(String, u64)],
    snapshot: &HashMap<ObjectId, (i64, i64)>,
    skipped_concurrent: &mut u64,
) -> mongodb::error::Result<u64> {
    let object_sizes = merge_object_sizes(public_objects, quarantine_objects);

    let mut attachments: HashMap<String, (ObjectId, u64)> = HashMap::new();
    let mut msg_cursor = Message::collection(db)
        .find(doc! {
            "deleted": { "$ne": true },
            "fileUrl": { "$exists": true, "$ne": null },
        })
        .await?;
    while let Some(message) = msg_cursor.try_next().await? {
        let Some(url) = message.file_url else {
            continue;
        };
        let Some(path) = canonicalize_message_file_url(&url, &cdn_public_base_url()) else {
            continue;
        };
        if is_attachment_key(&path) {
            let fallback_size = message.file_size.unwrap_or_default();
            attachments
                .entry(path)
                .and_modify(|(_, size)| *size = (*size).max(fallback_size))
                .or_insert((message.sender, fallback_size));
        }
    }

    let mut pending_cursor = PendingUpload::collection(db).find(doc! {}).await?;
    while let Some(entry) = pending_cursor.try_next().await? {
        attachments
            .entry(entry.file_path)
            .and_modify(|(_, size)| *size = (*size).max(entry.file_size))
            .or_insert((entry.user_id, entry.file_size));
    }

    let mut usage: HashMap<ObjectId, i64> = HashMap::new();
    for (path, (user_id, fallback_size)) in attachments {
        let size = attachment_usage_bytes(&path, &object_sizes, fallback_size);
        if size > 0 {
            *usage.entry(user_id).or_insert(0) += size.min(i64::MAX as u64) as i64;
        }
    }

    let mut updated = 0u64;
    for (user_id, bytes) in &usage {
        let revision = snapshot.get(user_id).map(|(revision, _)| *revision);
        if UserStorageUsage::set_bytes_if_unchanged(db, *user_id, revision, *bytes).await? {
            updated += 1;
        } else {
            *skipped_concurrent += 1;
            log::warn!(
                "Skipped storage usage rebuild for user {} because usage changed during reconciliation",
                user_id.to_hex()
            );
        }
    }

    for (user_id, (_, bytes_used)) in snapshot {
        if usage.contains_key(user_id) {
            continue;
        }
        if *bytes_used <= 0 {
            continue;
        }
        if UserStorageUsage::set_bytes_if_unchanged(db, *user_id, Some(snapshot[user_id].0), 0)
            .await?
        {
            updated += 1;
        } else {
            *skipped_concurrent += 1;
            log::warn!(
                "Skipped clearing storage usage for user {} because usage changed during reconciliation",
                user_id.to_hex()
            );
        }
    }

    Ok(updated)
}

fn attachment_usage_bytes(path: &str, object_sizes: &HashMap<String, u64>, fallback: u64) -> u64 {
    let full_size = object_sizes.get(path).copied().unwrap_or_default();
    let thumb_size = crate::utils::storage::attachment_thumb_key(path)
        .and_then(|thumb| object_sizes.get(&thumb).copied())
        .unwrap_or_default();
    full_size.saturating_add(thumb_size).max(fallback)
}

fn merge_object_sizes(
    public_objects: &[(String, u64)],
    quarantine_objects: &[(String, u64)],
) -> HashMap<String, u64> {
    let mut object_sizes = HashMap::new();
    for (path, size) in public_objects.iter().chain(quarantine_objects) {
        object_sizes
            .entry(path.clone())
            .and_modify(|current: &mut u64| *current = (*current).max(*size))
            .or_insert(*size);
    }
    object_sizes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referenced_webp_attachment_keeps_its_thumbnail_during_reconcile() {
        let path = "attachments/groups/group_0123456789abcdef01234567/550e8400-e29b-41d4-a716-446655440000.webp";
        let mut paths = HashSet::new();

        insert_attachment_reference(&mut paths, path.to_string());

        assert!(paths.contains(path));
        assert!(paths.contains(
            "attachments/groups/group_0123456789abcdef01234567/550e8400-e29b-41d4-a716-446655440000.thumb.webp"
        ));
    }

    #[test]
    fn referenced_non_image_attachment_has_no_thumbnail_reference() {
        let path = "attachments/groups/group_0123456789abcdef01234567/550e8400-e29b-41d4-a716-446655440000.pdf";
        let mut paths = HashSet::new();

        insert_attachment_reference(&mut paths, path.to_string());

        assert_eq!(paths, HashSet::from([path.to_string()]));
    }

    #[test]
    fn image_usage_includes_thumbnail_and_fallback_size() {
        let path = "attachments/groups/group_0123456789abcdef01234567/550e8400-e29b-41d4-a716-446655440000.webp";
        let thumb = format!("{}.thumb.webp", path.trim_end_matches(".webp"));
        let object_sizes = HashMap::from([(path.to_string(), 900), (thumb, 100)]);

        assert_eq!(attachment_usage_bytes(path, &object_sizes, 950), 1000);
    }

    #[test]
    fn object_size_merge_does_not_count_public_and_quarantine_copies_twice() {
        let path = "attachments/groups/group_0123456789abcdef01234567/550e8400-e29b-41d4-a716-446655440000.webp";
        let public = vec![(path.to_string(), 900)];
        let quarantine = vec![(path.to_string(), 900)];

        assert_eq!(
            merge_object_sizes(&public, &quarantine).get(path),
            Some(&900)
        );
    }
}
