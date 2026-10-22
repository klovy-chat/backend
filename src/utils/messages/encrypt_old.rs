// encrypt_old.rs
// Migracja legacy plaintext/opaque → sealed.
// Zakres:
//  - warunkowy update, dry-run
//  - legacy plaintext/opaque → sealed; dry-run przed --apply
// Nie odpalaj --apply bez backupu i bez FE które umie czytać sealed.
// Przy zmianach: bin/encrypt_old_messages.rs, crypto/encrypt.rs.

use futures_util::TryStreamExt;
use mongodb::bson::{doc, DateTime};
use mongodb::Database;

use crate::model::messages::Message;
use crate::utils::messages::storage::{
    inbound_plaintext_for_processing, is_client_opaque, is_content_server_sealed,
    prepare_content_for_storage, reveal_content_internal,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct MigrateContentSealReport {
    pub scanned: u64,
    pub skipped_already_sealed: u64,
    pub skipped_not_needed: u64,
    pub skipped_empty: u64,
    pub skipped_unchanged: u64,
    pub skipped_concurrent_update: u64,
    pub migrated: u64,
    pub errors: u64,
}

#[derive(Debug, Clone)]
pub struct MigrateContentSealOptions {
    pub dry_run: bool,
    pub batch_size: u32,
    pub limit: Option<u64>,
}

impl Default for MigrateContentSealOptions {
    fn default() -> Self {
        Self {
            dry_run: true,
            batch_size: 200,
            limit: None,
        }
    }
}

pub fn message_content_needs_seal_migration(stored: &str) -> bool {
    if stored.trim().is_empty() {
        return false;
    }
    if is_content_server_sealed(stored) {
        return false;
    }
    if is_client_opaque(stored) {
        return true;
    }
    true
}

pub fn seal_legacy_message_content(stored: &str) -> Result<Option<String>, String> {
    if !message_content_needs_seal_migration(stored) {
        return Ok(None);
    }

    let before = inbound_plaintext_for_processing(stored, false);
    let sealed = prepare_content_for_storage(stored)?;
    let after = reveal_content_internal(&sealed);
    if before != after {
        return Err("content roundtrip mismatch after seal".to_string());
    }
    if sealed == stored {
        return Ok(None);
    }
    Ok(Some(sealed))
}

pub async fn migrate_message_content_seal(
    db: &Database,
    options: MigrateContentSealOptions,
) -> Result<MigrateContentSealReport, mongodb::error::Error> {
    let mut report = MigrateContentSealReport::default();
    let filter = doc! {
        "content": { "$exists": true, "$type": "string", "$ne": "" },
    };

    let batch_size = options.batch_size.max(1) as u64;
    let mut cursor = Message::collection(db)
        .find(filter)
        .batch_size(options.batch_size)
        .await?;

    while let Some(result) = cursor.try_next().await? {
        if options.limit.is_some_and(|limit| report.scanned >= limit) {
            break;
        }

        let msg = result;
        report.scanned += 1;

        let Some(id) = msg.id else {
            report.errors += 1;
            log::warn!("message without _id skipped");
            continue;
        };

        if msg.content.trim().is_empty() {
            report.skipped_empty += 1;
            continue;
        }

        if is_content_server_sealed(&msg.content) {
            report.skipped_already_sealed += 1;
            continue;
        }

        if !message_content_needs_seal_migration(&msg.content) {
            report.skipped_not_needed += 1;
            continue;
        }

        let original = msg.content.clone();
        let sealed = match seal_legacy_message_content(&original) {
            Ok(Some(value)) => value,
            Ok(None) => {
                report.skipped_unchanged += 1;
                continue;
            }
            Err(e) => {
                report.errors += 1;
                log::error!("message {id}: seal failed: {e}");
                continue;
            }
        };

        if options.dry_run {
            report.migrated += 1;
            if report.migrated <= 5 {
                log::info!(
                    "[dry-run] would seal message {id} (len {} -> {})",
                    original.len(),
                    sealed.len()
                );
            }
            continue;
        }

        let update = Message::collection(db)
            .update_one(
                doc! { "_id": id, "content": &original },
                doc! {
                    "$set": {
                        "content": &sealed,
                        "updatedAt": DateTime::now(),
                    }
                },
            )
            .await?;

        if update.modified_count == 0 {
            report.skipped_concurrent_update += 1;
            log::warn!("message {id}: content changed during migration, skipped");
            continue;
        }

        report.migrated += 1;
        if report.migrated % batch_size == 0 {
            log::info!("sealed {} messages so far...", report.migrated);
        }
    }

    Ok(report)
}
