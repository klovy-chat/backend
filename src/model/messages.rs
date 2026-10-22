// messages.rs
// Dokument wiadomości: sealed content, załączniki, reakcje, typ, nonce, pin, soft-delete.
// Zakres:
//  - idempotencja send po sender+nonce
//  - claim unread delete vs mark-read
// Nowe pole widoczne w API: serde + frontend types/index.ts.
// Przy zmianach: ws/handlers.rs, utils/crypto/encrypt.rs, messages/search.rs.

use crate::model::scan::ScanStatus;
use crate::utils::storage::{attachment_stored_url_aliases, cdn_public_base_url};
use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    options::IndexOptions,
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType {
    Text,
    File,
    Image,
    Video,
    Audio,
    Sticker,

    Call,
}

impl Default for MessageType {
    fn default() -> Self {
        Self::Text
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub emoji: String,
    #[serde(default)]
    pub users: Vec<ObjectId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadBy {
    pub user: ObjectId,
    #[serde(rename = "readAt")]
    pub read_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub sender: ObjectId,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<ObjectId>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<ObjectId>,

    pub content: String,

    #[serde(
        rename = "searchText",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub search_text: String,

    #[serde(
        rename = "searchTokens",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub search_tokens: Vec<String>,

    #[serde(rename = "messageType", default)]
    pub message_type: MessageType,

    #[serde(rename = "fileUrl", skip_serializing_if = "Option::is_none")]
    pub file_url: Option<String>,

    #[serde(rename = "fileType", skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,

    #[serde(rename = "fileSize", skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,

    #[serde(rename = "fileName", skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,

    #[serde(rename = "scanStatus", default)]
    pub scan_status: ScanStatus,

    #[serde(rename = "durationMs", skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u32>,

    #[serde(rename = "clientNonce", skip_serializing_if = "Option::is_none")]
    pub client_nonce: Option<String>,

    pub timestamp: DateTime,

    #[serde(default)]
    pub read: bool,

    #[serde(rename = "readBy", default)]
    pub read_by: Vec<ReadBy>,

    #[serde(default)]
    pub reactions: HashMap<String, Reaction>,

    #[serde(rename = "quotedMessage", skip_serializing_if = "Option::is_none")]
    pub quoted_message: Option<ObjectId>,

    #[serde(default)]
    pub mentions: Vec<ObjectId>,

    #[serde(rename = "mentionsEveryone", default)]
    pub mentions_everyone: bool,

    #[serde(default)]
    pub edited: bool,

    #[serde(rename = "editedAt", skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<DateTime>,

    #[serde(default)]
    pub deleted: bool,

    #[serde(rename = "deletedAt", skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime>,

    #[serde(default)]
    pub pinned: bool,

    #[serde(rename = "pinnedAt", skip_serializing_if = "Option::is_none")]
    pub pinned_at: Option<DateTime>,

    #[serde(rename = "pinnedBy", skip_serializing_if = "Option::is_none")]
    pub pinned_by: Option<ObjectId>,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

#[derive(Debug)]
pub enum MessageValidationError {
    ContentRequired,
    ContentTooLong,
    FileUrlRequired,
}

impl std::fmt::Display for MessageValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::ContentRequired => "Treść wiadomości jest wymagana",
            Self::ContentTooLong => "Wiadomość nie może przekraczać 2000 znaków",
            Self::FileUrlRequired => {
                "URL pliku jest wymagany dla wiadomości typu FILE, IMAGE, VIDEO lub AUDIO"
            }
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for MessageValidationError {}

pub struct CreateMessageInput {
    pub sender: ObjectId,
    pub recipient: Option<ObjectId>,
    pub channel: Option<ObjectId>,
    pub content: String,
    pub message_type: Option<MessageType>,
    pub file_url: Option<String>,
    pub file_type: Option<String>,
    pub file_size: Option<u64>,
    pub file_name: Option<String>,
    pub scan_status: ScanStatus,
    pub duration_ms: Option<u32>,
    pub quoted_message: Option<ObjectId>,
    pub mentions: Option<Vec<ObjectId>>,
    pub mentions_everyone: Option<bool>,

    pub client_nonce: Option<String>,

    pub read: Option<bool>,
}

#[derive(Debug)]
pub enum CreateMessageOutcome {
    Created(Message),

    IdempotentReplay(Message),
}

#[derive(Debug)]
pub enum CreateMessageError {
    Validation(MessageValidationError),

    NonceConflict,
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for CreateMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(e) => write!(f, "{e}"),
            Self::NonceConflict => write!(f, "clientNonce conflict"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CreateMessageError {}

fn same_message_scope(existing: &Message, input: &CreateMessageInput) -> bool {
    existing.recipient == input.recipient && existing.channel == input.channel
}

pub const MAX_MESSAGE_CONTENT_LEN: usize = 2000;

pub fn is_message_content_within_limit(content: &str) -> bool {
    content.trim().chars().count() <= MAX_MESSAGE_CONTENT_LEN
}

pub fn validate_message(input: &CreateMessageInput) -> Result<(), MessageValidationError> {
    let msg_type = input.message_type.as_ref().unwrap_or(&MessageType::Text);

    if *msg_type == MessageType::Call {
        if !is_message_content_within_limit(&input.content) {
            return Err(MessageValidationError::ContentTooLong);
        }
        return Ok(());
    }

    if *msg_type != MessageType::Text && input.file_url.is_none() {
        return Err(MessageValidationError::FileUrlRequired);
    }

    if *msg_type == MessageType::Audio {
        if !is_message_content_within_limit(&input.content) {
            return Err(MessageValidationError::ContentTooLong);
        }
        return Ok(());
    }

    if input.content.trim().is_empty() {
        return Err(MessageValidationError::ContentRequired);
    }
    let plain = crate::utils::messages::storage::inbound_plaintext_for_processing(
        input.content.trim(),
        false,
    );
    if plain.trim().is_empty() {
        return Err(MessageValidationError::ContentRequired);
    }
    if !is_message_content_within_limit(&plain) {
        return Err(MessageValidationError::ContentTooLong);
    }
    Ok(())
}

impl Message {
    pub fn collection(db: &Database) -> Collection<Message> {
        db.collection("messages")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let col = Self::collection(db);

        let indexes = vec![
            IndexModel::builder()
                .keys(doc! { "sender": 1, "recipient": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "sender": 1, "recipient": 1, "_id": -1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "recipient": 1, "sender": 1, "_id": -1 })
                .build(),
            IndexModel::builder().keys(doc! { "channel": 1 }).build(),
            IndexModel::builder()
                .keys(doc! { "channel": 1, "_id": -1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "channel": 1, "pinned": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "sender": 1, "recipient": 1, "pinned": 1 })
                .build(),
            IndexModel::builder().keys(doc! { "timestamp": -1 }).build(),
            IndexModel::builder()
                .keys(doc! { "recipient": 1, "read": 1, "channel": 1, "deleted": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "channel": 1, "timestamp": -1, "sender": 1, "deleted": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "mentions": 1, "read": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "channel": 1, "messageType": 1, "searchTokens": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "sender": 1, "recipient": 1, "messageType": 1, "searchTokens": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "sender": 1, "clientNonce": 1 })
                .options(
                    IndexOptions::builder()
                        .unique(true)
                        .partial_filter_expression(doc! {
                            "clientNonce": { "$type": "string" }
                        })
                        .build(),
                )
                .build(),
        ];

        col.create_indexes(indexes).await?;
        Ok(())
    }

    pub async fn create(
        db: &Database,
        input: CreateMessageInput,
    ) -> Result<CreateMessageOutcome, CreateMessageError> {
        validate_message(&input).map_err(CreateMessageError::Validation)?;

        let client_nonce = input
            .client_nonce
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 64)
            .map(|s| s.to_string());

        if let Some(ref nonce) = client_nonce {
            if let Ok(Some(existing)) = Self::collection(db)
                .find_one(doc! {
                    "sender": input.sender,
                    "clientNonce": nonce,
                })
                .await
            {
                if existing.deleted || !same_message_scope(&existing, &input) {
                    return Err(CreateMessageError::NonceConflict);
                }
                return Ok(CreateMessageOutcome::IdempotentReplay(existing));
            }
        }

        let trimmed = input.content.trim();
        let stored_content =
            crate::utils::messages::storage::prepare_content_for_storage_async(trimmed.to_string())
                .await
                .map_err(|e| CreateMessageError::Other(e.into()))?;
        let msg_type = input.message_type.clone().unwrap_or_default();
        let search_index = if msg_type == MessageType::Text {
            crate::utils::messages::search::build_search_index_from_incoming(trimmed)
                .map_err(|e| CreateMessageError::Other(e.into()))?
        } else {
            crate::utils::messages::search::SearchIndex::empty()
        };

        let now = DateTime::now();
        let scope_recipient = input.recipient;
        let scope_channel = input.channel;
        let scope_sender = input.sender;
        let msg = Message {
            id: None,
            sender: input.sender,
            recipient: input.recipient,
            channel: input.channel,
            content: stored_content,
            search_text: search_index.encrypted_text,
            search_tokens: search_index.tokens,
            message_type: msg_type,
            file_url: input.file_url,
            file_type: input.file_type,
            file_size: input.file_size,
            file_name: input.file_name,
            scan_status: input.scan_status,
            duration_ms: input.duration_ms,
            client_nonce: client_nonce.clone(),
            timestamp: now,
            read: input.read.unwrap_or(false),
            read_by: vec![],
            reactions: HashMap::new(),
            quoted_message: input.quoted_message,
            mentions: input.mentions.unwrap_or_default(),
            mentions_everyone: input.mentions_everyone.unwrap_or(false),
            edited: false,
            edited_at: None,
            deleted: false,
            deleted_at: None,
            pinned: false,
            pinned_at: None,
            pinned_by: None,
            created_at: now,
            updated_at: now,
        };

        match Self::collection(db).insert_one(&msg).await {
            Ok(result) => {
                let id = result.inserted_id.as_object_id();
                Ok(CreateMessageOutcome::Created(Message { id, ..msg }))
            }
            Err(e) => {
                if let Some(ref nonce) = client_nonce {
                    if let Ok(Some(existing)) = Self::collection(db)
                        .find_one(doc! {
                            "sender": scope_sender,
                            "clientNonce": nonce,
                        })
                        .await
                    {
                        let scope_ok = existing.recipient == scope_recipient
                            && existing.channel == scope_channel;
                        if existing.deleted || !scope_ok {
                            return Err(CreateMessageError::NonceConflict);
                        }
                        return Ok(CreateMessageOutcome::IdempotentReplay(existing));
                    }
                }
                Err(CreateMessageError::Other(e.into()))
            }
        }
    }

    pub async fn find_by_id(
        db: &Database,
        id: ObjectId,
    ) -> mongodb::error::Result<Option<Message>> {
        Self::collection(db).find_one(doc! { "_id": id }).await
    }

    pub async fn refreshed(self, db: &Database) -> Self {
        let Some(id) = self.id else {
            return self;
        };
        Self::find_by_id(db, id)
            .await
            .ok()
            .flatten()
            .unwrap_or(self)
    }

    pub async fn soft_delete_active(
        db: &Database,
        id: ObjectId,
    ) -> mongodb::error::Result<SoftDeleteOutcome> {
        let set = doc! {
            "deleted": true,
            "deletedAt": DateTime::now(),
            "updatedAt": DateTime::now(),
            "searchText": "",
            "searchTokens": [],
        };

        let unread = Self::collection(db)
            .update_one(
                doc! { "_id": id, "deleted": { "$ne": true }, "read": false },
                doc! { "$set": set.clone() },
            )
            .await?;
        if unread.modified_count > 0 {
            return Ok(SoftDeleteOutcome::Deleted { was_unread: true });
        }
        let any = Self::collection(db)
            .update_one(
                doc! { "_id": id, "deleted": { "$ne": true } },
                doc! { "$set": set },
            )
            .await?;
        if any.modified_count > 0 {
            return Ok(SoftDeleteOutcome::Deleted { was_unread: false });
        }
        Ok(SoftDeleteOutcome::AlreadyDeleted)
    }

    pub async fn apply_scan_verdict(
        db: &Database,
        file_path: &str,
        scan_status: ScanStatus,
        clear_file_url: bool,
    ) -> mongodb::error::Result<Vec<Message>> {
        use futures_util::TryStreamExt;

        let aliases = attachment_stored_url_aliases(file_path, &cdn_public_base_url());
        let filter = doc! {
            "fileUrl": { "$in": aliases },
            "deleted": { "$ne": true },
        };
        let cursor = Self::collection(db).find(filter.clone()).await?;
        let mut messages: Vec<Message> = cursor.try_collect().await?;
        if messages.is_empty() {
            return Ok(messages);
        }

        let mut set = doc! {
            "scanStatus": scan_status.as_str(),
            "updatedAt": DateTime::now(),
        };
        if clear_file_url {
            set.insert("fileUrl", mongodb::bson::Bson::Null);
        }
        Self::collection(db)
            .update_many(filter, doc! { "$set": set })
            .await?;
        for message in &mut messages {
            message.scan_status = scan_status;
            if clear_file_url {
                message.file_url = None;
            }
        }
        Ok(messages)
    }

    pub async fn find_pending_scans(db: &Database) -> mongodb::error::Result<Vec<Message>> {
        use futures_util::TryStreamExt;
        let cursor = Self::collection(db)
            .find(doc! {
                "scanStatus": ScanStatus::Pending.as_str(),
                "deleted": { "$ne": true },
                "fileUrl": { "$exists": true, "$ne": null },
            })
            .await?;
        cursor.try_collect().await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftDeleteOutcome {
    AlreadyDeleted,
    Deleted { was_unread: bool },
}
