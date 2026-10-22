// search.rs
// Indeks searchText (encrypted) + HMAC tokens; wipe wiadomości bez pełnego Message.
// Zakres:
//  - API nie zwraca tych pól
//  - encrypted searchText + HMAC; substring = tokeny, nie regex
//  - wipe_live_messages: projection fileUrl, nie hydratacja Message
// Substring search = tokeny, nie regex na sealed content.
// Przy zmianach: hmac.rs, controllers/messages.rs, channels.rs.

use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use mongodb::Database;
use std::sync::OnceLock;

use crate::model::messages::Message;
use crate::utils::crypto::encrypt::{decrypt_field, encrypt_field};
use crate::utils::crypto::hmac::{derive_subkey, hmac_sha256_hex};
use crate::utils::messages::storage::{inbound_plaintext_for_processing, reveal_content_internal};

const SEARCH_NGRAM_LEN: usize = 2;
const SEARCH_TOKEN_CONTEXT: &str = "search-token-v1";

#[derive(Debug, Clone)]
pub struct SearchIndex {
    pub encrypted_text: String,
    pub tokens: Vec<String>,
}

impl SearchIndex {
    pub fn empty() -> Self {
        Self {
            encrypted_text: String::new(),
            tokens: Vec::new(),
        }
    }
}

fn search_token_key() -> Result<[u8; 32], String> {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    if let Some(key) = KEY.get() {
        return Ok(*key);
    }
    let raw = std::env::var("FIELD_ENCRYPTION_KEY")
        .or_else(|_| std::env::var("JWT_KEY"))
        .map_err(|_| "FIELD_ENCRYPTION_KEY or JWT_KEY is required".to_string())?;
    let trimmed = raw.trim();
    if trimmed.len() < 32 {
        return Err("Encryption key must be at least 32 characters".to_string());
    }
    Ok(*KEY.get_or_init(|| derive_subkey(trimmed, SEARCH_TOKEN_CONTEXT)))
}

pub fn normalize_search_text(plain: &str) -> String {
    plain.trim().to_lowercase()
}

fn search_token_hex(gram: &str) -> String {
    match search_token_key() {
        Ok(key) => hmac_sha256_hex(&key, gram),
        Err(_) => String::new(),
    }
}

pub fn search_tokens_from_normalized(normalized: &str) -> Vec<String> {
    let normalized = normalized.trim();
    if normalized.is_empty() {
        return Vec::new();
    }

    let chars: Vec<char> = normalized.chars().collect();
    let n = SEARCH_NGRAM_LEN.min(chars.len());
    let mut tokens = Vec::new();
    if chars.len() <= n {
        let token = search_token_hex(normalized);
        if !token.is_empty() {
            tokens.push(token);
        }
        return tokens;
    }

    for window in chars.windows(n) {
        let gram: String = window.iter().collect();
        let token = search_token_hex(&gram);
        if token.is_empty() {
            return Vec::new();
        }
        if tokens.last().is_none_or(|last| last != &token) {
            tokens.push(token);
        }
    }
    tokens
}

pub fn search_tokens_for_query(query: &str) -> Vec<String> {
    search_tokens_from_normalized(&query.trim().to_lowercase())
}

pub fn is_search_text_sealed(stored: &str) -> bool {
    let trimmed = stored.trim();
    !trimmed.is_empty() && decrypt_field(trimmed).is_ok()
}

pub fn build_search_index_from_normalized(normalized: &str) -> Result<SearchIndex, String> {
    let normalized = normalized.trim();
    if normalized.is_empty() {
        return Ok(SearchIndex::empty());
    }
    Ok(SearchIndex {
        encrypted_text: encrypt_field(normalized)?,
        tokens: search_tokens_from_normalized(normalized),
    })
}

pub fn build_search_index_from_incoming(incoming: &str) -> Result<SearchIndex, String> {
    let plain = inbound_plaintext_for_processing(incoming.trim(), false);
    build_search_index_from_normalized(&normalize_search_text(&plain))
}

pub fn search_text_from_incoming(incoming: &str) -> String {
    build_search_index_from_incoming(incoming)
        .map(|idx| idx.encrypted_text)
        .unwrap_or_default()
}

pub fn search_text_from_stored(stored: &str) -> String {
    normalize_search_text(&reveal_content_internal(stored))
}

fn normalized_from_legacy_search_field(search_text: &str, content: &str) -> String {
    let trimmed = search_text.trim();
    if is_search_text_sealed(trimmed) {
        return decrypt_field(trimmed).unwrap_or_default();
    }
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }
    search_text_from_stored(content)
}

pub async fn backfill_message_search_text(db: &Database) -> mongodb::error::Result<u64> {
    const BATCH: i64 = 200;
    const MAX_BATCHES: u32 = 50;

    let mut updated = 0u64;
    for _ in 0..MAX_BATCHES {
        let cursor = Message::collection(db)
            .find(doc! {
                "messageType": "TEXT",
                "deleted": { "$ne": true },
                "$or": [
                    { "searchTokens": { "$exists": false } },
                    { "searchTokens": { "$size": 0 } },
                    {
                        "$and": [
                            { "searchText": { "$type": "string", "$ne": "" } },
                            { "searchText": { "$not": { "$regex": "^[A-Z2-7]+$" } } },
                        ]
                    },
                ],
            })
            .limit(BATCH)
            .await?;

        let batch: Vec<Message> = cursor.try_collect().await?;
        if batch.is_empty() {
            break;
        }

        let mut batch_updated = 0u64;
        for msg in batch {
            let Some(id) = msg.id else { continue };
            let normalized = normalized_from_legacy_search_field(&msg.search_text, &msg.content);
            let index = match build_search_index_from_normalized(&normalized) {
                Ok(index) => index,
                Err(e) => {
                    log::warn!("searchText backfill encrypt failed for {id}: {e}");
                    continue;
                }
            };
            let _ = Message::collection(db)
                .update_one(
                    doc! { "_id": id },
                    doc! {
                        "$set": {
                            "searchText": &index.encrypted_text,
                            "searchTokens": &index.tokens,
                        }
                    },
                )
                .await?;
            batch_updated += 1;
        }
        updated += batch_updated;
        if batch_updated == 0 {
            break;
        }
    }

    Ok(updated)
}

pub async fn collect_message_ids(
    db: &Database,
    filter: Document,
) -> mongodb::error::Result<Vec<ObjectId>> {
    collect_message_ids_limited(db, filter, None).await
}

pub async fn collect_message_ids_limited(
    db: &Database,
    filter: Document,
    limit: Option<i64>,
) -> mongodb::error::Result<Vec<ObjectId>> {
    let coll = db.collection::<Document>("messages");
    let mut find = coll.find(filter).projection(doc! { "_id": 1 });
    if let Some(limit) = limit {
        find = find.limit(limit);
    }
    let mut cursor = find.await?;

    let mut ids = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        if let Ok(id) = doc.get_object_id("_id") {
            ids.push(id);
        }
    }
    Ok(ids)
}

async fn collect_message_file_urls(
    db: &Database,
    filter: Document,
) -> mongodb::error::Result<Vec<String>> {
    let coll = db.collection::<Document>("messages");
    let mut cursor = coll.find(filter).projection(doc! { "fileUrl": 1 }).await?;

    let mut urls = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        match doc.get("fileUrl") {
            None | Some(Bson::Null) => continue,
            Some(Bson::String(url)) if !url.is_empty() => urls.push(url.clone()),
            Some(Bson::String(_)) => {}
            Some(value) => {
                return Err(mongodb::error::Error::custom(format!(
                    "Invalid fileUrl on message {}: expected a string, got {value:?}",
                    doc.get_object_id("_id")
                        .map(|id| id.to_hex())
                        .unwrap_or_else(|_| "unknown".to_string())
                )));
            }
        }
    }
    Ok(urls)
}

pub async fn message_file_urls(
    db: &Database,
    filter: Document,
) -> mongodb::error::Result<Vec<String>> {
    collect_message_file_urls(db, filter).await
}

fn soft_delete_set() -> Document {
    let now = DateTime::now();
    doc! {
        "$set": {
            "deleted": true,
            "deletedAt": now,
            "updatedAt": now,
            "searchText": "",
            "searchTokens": [],
        }
    }
}

/// Soft-delete matching live messages and return attachment URLs for cleanup.
///
/// Must not hydrate full [`Message`]: wipe paths project `{_id, fileUrl}` only,
/// and `Message` requires `sender` / `content` / `timestamp`.
pub async fn wipe_live_messages(
    db: &Database,
    filter: Document,
) -> mongodb::error::Result<WipeLiveMessagesResult> {
    let coll = db.collection::<Document>("messages");
    let mut urls = collect_message_file_urls(db, filter.clone()).await?;
    if let Err(error) = coll.update_many(filter.clone(), soft_delete_set()).await {
        log::error!("Initial message wipe returned an error; retrying idempotently: {error}");
        if let Err(retry_error) = coll.update_many(filter.clone(), soft_delete_set()).await {
            log::error!("Message wipe retry failed; completion is uncertain: {retry_error}");
            return Ok(WipeLiveMessagesResult {
                file_urls: urls,
                wipe_pending: true,
            });
        }
    }

    for _ in 0..3 {
        let late = match collect_message_file_urls(db, filter.clone()).await {
            Ok(urls) => urls,
            Err(error) => {
                log::error!(
                    "Messages were wiped, but late attachment URLs could not be collected: {error}"
                );
                return Ok(WipeLiveMessagesResult {
                    file_urls: urls,
                    wipe_pending: true,
                });
            }
        };
        if late.is_empty() {
            return Ok(WipeLiveMessagesResult {
                file_urls: urls,
                wipe_pending: false,
            });
        }
        urls.extend(late);
        if let Err(error) = coll.update_many(filter.clone(), soft_delete_set()).await {
            log::error!("Late message wipe failed; retrying idempotently: {error}");
            if let Err(retry_error) = coll.update_many(filter.clone(), soft_delete_set()).await {
                log::error!("Late message wipe retry failed: {retry_error}");
                return Ok(WipeLiveMessagesResult {
                    file_urls: urls,
                    wipe_pending: true,
                });
            }
        }
    }
    Ok(WipeLiveMessagesResult {
        file_urls: urls,
        wipe_pending: true,
    })
}

pub struct WipeLiveMessagesResult {
    pub file_urls: Vec<String>,
    pub wipe_pending: bool,
}
