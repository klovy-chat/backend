// worker.rs
// Kolejka skanu: kwarantanna → clamd → publiczny R2 albo blocked.
// Zakres:
//  - upload nie czeka; WS message-edited po werdykcie
//  - SHA obiektu vs pending; cache tylko po realnym clamd
//  - publiczny obiekt ≠ automatycznie clean
// Bez CLAMAV_HOST plik zostaje w kwarantannie (fail-closed).
// Przy zmianach: clamd.rs, messages.rs, r2.rs.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use mongodb::Database;
use once_cell::sync::OnceCell;
use serde_json::json;
use tokio::sync::mpsc;

use crate::model::channels::Channel;
use crate::model::messages::Message;
use crate::model::scan::ScanStatus;
use crate::model::scan_cache::ScanVerdict;
use crate::model::uploads::PendingUpload;
use crate::utils::db::get_db;
use crate::utils::hash::sha256_hex;
use crate::utils::messages::access::canonicalize_message_file_url;
use crate::utils::messages::serialize_message;
use crate::utils::storage::{cdn_public_base_url, is_attachment_key, storage};
use crate::ws::registry;

use super::clamd::{clamd_addr, scan_bytes, ClamVerdict};

const MAX_SCAN_ATTEMPTS: u8 = 8;
const SCAN_RECOVERY_RETRY_DELAY: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone)]
pub struct ScanJob {
    pub file_path: String,
    pub file_hash: String,
    pub content_type: String,
    pub attempts: u8,
}

static SCAN_TX: OnceCell<mpsc::UnboundedSender<ScanJob>> = OnceCell::new();
static IN_FLIGHT: OnceCell<Mutex<HashSet<String>>> = OnceCell::new();

fn in_flight() -> &'static Mutex<HashSet<String>> {
    IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()))
}

fn try_begin(path: &str) -> bool {
    let Ok(mut set) = in_flight().lock() else {
        return false;
    };
    set.insert(path.to_string())
}

fn finish(path: &str) {
    if let Ok(mut set) = in_flight().lock() {
        set.remove(path);
    }
}

struct InFlightGuard(String);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        finish(&self.0);
    }
}

pub fn spawn_worker() {
    let (tx, mut rx) = mpsc::unbounded_channel::<ScanJob>();
    if SCAN_TX.set(tx).is_err() {
        return;
    }
    match clamd_addr() {
        Some(addr) => log::info!("attachment scanner ready (clamd={addr})"),
        None => log::error!(
            "attachment scanner fail-closed: CLAMAV_HOST is not set — uploads stay in quarantine"
        ),
    }
    tokio::spawn(async move {
        match super::clamd::ping_clamd().await {
            Ok(()) => log::info!("clamd ping ok"),
            Err(err) => log::error!("clamd ping failed: {err}"),
        }
        while let Some(job) = rx.recv().await {
            if !try_begin(&job.file_path) {
                continue;
            }
            let _guard = InFlightGuard(job.file_path.clone());
            log::info!("attachment scan started for {}", job.file_path);
            let result = process_job(job.clone()).await;
            drop(_guard);
            if let Err(err) = result {
                log::warn!("attachment scan failed for {}: {err}", job.file_path);
                schedule_retry(job);
            }
        }
    });
}

fn schedule_retry(mut job: ScanJob) {
    if clamd_addr().is_none() {
        return;
    }
    if job.attempts >= MAX_SCAN_ATTEMPTS {
        log::error!(
            "attachment scan exhausted {MAX_SCAN_ATTEMPTS} short retries; retrying after recovery delay: {}",
            job.file_path
        );
        job.attempts = 0;
        tokio::spawn(async move {
            tokio::time::sleep(SCAN_RECOVERY_RETRY_DELAY).await;
            enqueue(job);
        });
        return;
    }
    job.attempts = job.attempts.saturating_add(1);
    let delay = Duration::from_secs(2u64.saturating_pow(job.attempts.min(6).into()).min(60));
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        enqueue(job);
    });
}

pub fn enqueue(job: ScanJob) {
    if let Some(tx) = SCAN_TX.get() {
        log::info!("attachment scan queued for {}", job.file_path);
        if tx.send(job).is_err() {
            log::warn!("attachment scan queue closed");
        }
    } else {
        log::error!(
            "attachment scan worker not started; dropping job {}",
            job.file_path
        );
    }
}

pub async fn requeue_pending() {
    let db = get_db();
    match PendingUpload::find_pending_scans(&db).await {
        Ok(pending) => {
            for entry in pending {
                enqueue(ScanJob {
                    file_path: entry.file_path,
                    file_hash: entry.file_hash,
                    content_type: entry.content_type,
                    attempts: 0,
                });
            }
        }
        Err(err) => log::warn!("requeue pending uploads failed: {err}"),
    }
    match Message::find_pending_scans(&db).await {
        Ok(messages) => {
            for message in messages {
                let Some(raw) = message.file_url.as_deref() else {
                    continue;
                };
                let Some(path) = canonicalize_message_file_url(raw, &cdn_public_base_url()) else {
                    continue;
                };
                if path.is_empty() || path.starts_with("https://") || !is_attachment_key(&path) {
                    continue;
                }
                let content_type = message.file_type.clone().unwrap_or_default();
                enqueue(ScanJob {
                    file_path: path,
                    file_hash: String::new(),
                    content_type,
                    attempts: 0,
                });
            }
        }
        Err(err) => log::warn!("requeue pending messages failed: {err}"),
    }
}

async fn load_scan_bytes(path: &str) -> Result<Option<Vec<u8>>, String> {
    if let Some(bytes) = storage()
        .get_quarantine(path)
        .await
        .map_err(|e| e.to_string())?
    {
        return Ok(Some(bytes));
    }
    storage().get_public(path).await.map_err(|e| e.to_string())
}

async fn process_job(job: ScanJob) -> Result<(), String> {
    let db = get_db();
    let content_type = if job.content_type.trim().is_empty() {
        PendingUpload::find_by_path(&db, &job.file_path)
            .await
            .ok()
            .flatten()
            .map(|pending| pending.content_type)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "application/octet-stream".to_string())
    } else {
        job.content_type.clone()
    };

    let declared_hash = if job.file_hash.is_empty() {
        PendingUpload::find_by_path(&db, &job.file_path)
            .await
            .ok()
            .flatten()
            .map(|pending| pending.file_hash)
            .unwrap_or_default()
    } else {
        job.file_hash.clone()
    };

    let Some(bytes) = load_scan_bytes(&job.file_path).await? else {
        return Err("attachment object missing".into());
    };

    let actual_hash = sha256_hex(&bytes);
    if !declared_hash.is_empty() && actual_hash != declared_hash {
        log::warn!(
            "attachment hash mismatch for {}, treating as blocked",
            job.file_path
        );
        if let Err(error) = ScanVerdict::put(&db, &actual_hash, ScanStatus::Blocked, false).await {
            log::warn!(
                "Failed to cache blocked attachment verdict for {}: {error}",
                job.file_path
            );
        }
        return apply_verdict(
            &db,
            &job.file_path,
            &content_type,
            ScanStatus::Blocked,
            &bytes,
        )
        .await;
    }

    let clamd_configured = clamd_addr().is_some();

    match ScanVerdict::get(&db, &actual_hash).await {
        Ok(Some(cached)) => {
            return apply_verdict(&db, &job.file_path, &content_type, cached, &bytes).await;
        }
        Ok(None) => {}
        Err(error) => {
            log::warn!(
                "Failed to read cached attachment scan verdict for {}: {error}",
                job.file_path
            );
        }
    }

    if !clamd_configured {
        log::error!(
            "CLAMAV_HOST is not set; leaving {} in quarantine",
            job.file_path
        );
        return Ok(());
    }

    let verdict = match scan_bytes(&bytes).await {
        Ok(ClamVerdict::Clean) => ScanStatus::Clean,
        Ok(ClamVerdict::Infected) => ScanStatus::Blocked,
        Err(err) => return Err(err.to_string()),
    };

    if !actual_hash.is_empty() {
        if let Err(error) = ScanVerdict::put(&db, &actual_hash, verdict, true).await {
            log::warn!(
                "Failed to cache attachment scan verdict for {}: {error}",
                job.file_path
            );
        }
    }
    apply_verdict(&db, &job.file_path, &content_type, verdict, &bytes).await
}

async fn apply_verdict(
    db: &Database,
    file_path: &str,
    content_type: &str,
    verdict: ScanStatus,
    bytes: &[u8],
) -> Result<(), String> {
    match verdict {
        ScanStatus::Clean => {
            log::info!("attachment scan clean, publishing {file_path}");
            storage()
                .publish_scanned(file_path, bytes.to_vec(), content_type)
                .await
                .map_err(|e| e.to_string())?;
            PendingUpload::set_scan_status(db, file_path, ScanStatus::Clean)
                .await
                .map_err(|e| format!("update pending upload scan status for {file_path}: {e}"))?;
            let messages = Message::apply_scan_verdict(db, file_path, ScanStatus::Clean, false)
                .await
                .map_err(|e| e.to_string())?;
            emit_scan_updates(db, &messages).await;
        }
        ScanStatus::Blocked => {
            log::warn!("attachment scan blocked {file_path}");
            PendingUpload::set_scan_status(db, file_path, ScanStatus::Blocked)
                .await
                .map_err(|e| format!("update blocked upload scan status for {file_path}: {e}"))?;
            let messages = Message::apply_scan_verdict(db, file_path, ScanStatus::Blocked, true)
                .await
                .map_err(|e| e.to_string())?;
            emit_scan_updates(db, &messages).await;
            storage()
                .delete_attachment_key(file_path)
                .await
                .map_err(|e| format!("delete blocked attachment {file_path}: {e}"))?;
        }
        ScanStatus::Pending => {}
    }
    Ok(())
}

async fn emit_scan_updates(db: &Database, messages: &[Message]) {
    for message in messages {
        let populated = serialize_message(db, message).await;
        if let Some(channel_id) = message.channel {
            if let Ok(Some(channel)) = Channel::find_by_id(db, channel_id).await {
                let recipients = registry::channel_recipient_ids(&channel);
                let mut payload = populated;
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert("channelId".into(), json!(channel_id.to_hex()));
                }
                registry::emit_to_users(&recipients, "message-edited", payload);
            }
        } else if let Some(recipient) = message.recipient {
            registry::emit_to_user(&recipient.to_hex(), "message-edited", populated.clone());
            registry::emit_to_user(&message.sender.to_hex(), "message-edited", populated);
        }
    }
}
