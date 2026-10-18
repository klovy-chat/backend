// messages.rs
// HTTP historii, pin, search, delete, upload załączników.
// Zakres:
//  - send realtime jest na WS, nie tutaj (poza wyjątkami HTTP)
//  - historia, pin, search, delete, upload; send live na WS
// Search idzie w searchTokens, nie w plaintext content.
// Przy zmianach: model/messages.rs, messages/search.rs, ws/handlers.rs.

use actix_multipart::form::{tempfile::TempFile, text::Text, MultipartForm};
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth::request_user_id;
use crate::model::channels::Channel;
use crate::model::messages::{is_message_content_within_limit, Message};
use crate::model::uploads::PendingUpload;
use crate::utils::messages::mentions::{has_everyone_mention, resolve_mentions};
use crate::model::storage_usage::UserStorageUsage;
use crate::utils::hash::sha256_hex;
use crate::model::users::User;
use crate::utils::attachments::log_attachment_upload;
use crate::utils::access::members::{
    authorize_dm_history_read, require_channel_access, require_dm_access, require_message_participant,
    AccessDeniedReason,
};
use crate::utils::db::get_db;
use crate::utils::images::{
    reencode_error_message, reencode_upload_to_webp_variants_async,
};
use crate::utils::messages::{
    access::cleanup_attachment_if_unreferenced,
    can_pin_message, try_can_pin_message, dm_conversation_base_clauses,
    serialize_message, serialize_messages_batch, validate_dm_history_before_cursor,
    message_belongs_to_dm_conversation,
};
use crate::utils::channel::is_channel_admin;
use crate::utils::friends::are_friends;
use crate::utils::messages::storage::inbound_plaintext_for_processing;
use crate::utils::messages::search::{build_search_index_from_incoming, search_tokens_for_query};
use crate::utils::storage::{
    attachment_dm_key, attachment_group_key, attachment_thumb_key, storage,
};
use crate::utils::scan::{enqueue, ScanJob};
use crate::model::scan::ScanStatus;
use crate::utils::ratelimit::{
    chat_attachment_retry_after_secs, try_consume_chat_attachment_quota,
};
use crate::utils::upload::{
    file_bytes_within_limit, is_image_extension, local_file_size, MAX_ATTACHMENT_BYTES,
    MAX_CHAT_ATTACHMENTS_PER_WINDOW, MAX_IMAGE_ATTACHMENT_BYTES, CHAT_ATTACHMENT_WINDOW_SECS,
};
use crate::utils::validators::zip::validate_upload_document_async;
use crate::utils::validators::file_type::{
    resolve_upload_content_type, validate_file_magic_async,
};
use crate::utils::link_preview::{fetch_link_preview, is_safe_preview_target};
use crate::utils::ratelimit::Store;
use once_cell::sync::Lazy;
use std::time::Duration;

static LINK_PREVIEW_LIMIT: Lazy<Store> = Lazy::new(|| Store::new(40, Duration::from_secs(60)));

const SEARCH_LIMIT: i64 = 50;
const MIN_QUERY_LENGTH: usize = 2;
const MAX_QUERY_LENGTH: usize = 200;

const DEFAULT_MESSAGE_LIMIT: i64 = 30;
const MAX_MESSAGE_LIMIT: i64 = 50;
const MAX_PINNED_MESSAGES: i64 = 50;

const ALLOWED_EXTENSIONS: &[&str] = &[
    "pdf", "jpg", "jpeg", "png", "webp", "docx", "xlsx", "pptx", "txt", "csv", "webm", "ogg",
    "wav", "mp3", "aac", "mp4", "m4a", "mov", "heic", "heif",
];

async fn serialize_all(db: &mongodb::Database, msgs: &[Message]) -> Vec<serde_json::Value> {
    serialize_messages_batch(db, msgs).await
}

#[derive(Deserialize)]
pub struct GetMessagesBody {
    pub id: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,

    #[serde(default)]
    pub before: Option<String>,
}

pub async fn get_messages(req: HttpRequest, body: web::Json<GetMessagesBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({
            "error": "UNAUTHORIZED",
            "message": "Authentication required.",
        }));
    };
    let contact_id = body.id.clone().unwrap_or_default();

    if contact_id.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "error": "INVALID_REQUEST",
            "message": "Contact id is required.",
        }));
    }

    let db = get_db();
    let (user_oid, contact_oid) = match authorize_dm_history_read(&db, &user_id, &contact_id).await {
        Ok(pair) => pair,
        Err(AccessDeniedReason::Unavailable) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
        Err(reason) => {
            return HttpResponse::Forbidden().json(json!({
                "error": "ACCESS_DENIED",
                "message": reason.as_str(),
            }));
        }
    };

    let limit = body
        .limit
        .unwrap_or(DEFAULT_MESSAGE_LIMIT)
        .clamp(1, MAX_MESSAGE_LIMIT);

    let mut and_clauses = dm_conversation_base_clauses(user_oid, contact_oid);

    if let Some(before_id) = body.before.as_deref().filter(|s| !s.is_empty()) {
        let before_oid = match validate_dm_history_before_cursor(
            &db,
            user_oid,
            contact_oid,
            before_id,
        )
        .await
        {
            Ok(oid) => oid,
            Err(crate::utils::messages::CursorValidateError::Unavailable) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "UNAVAILABLE",
                    "message": "Temporarily unavailable. Retry.",
                    "retryable": true,
                }));
            }
            Err(crate::utils::messages::CursorValidateError::Invalid) => {
                return HttpResponse::BadRequest().json(json!({
                    "error": "INVALID_CURSOR",
                    "message": "Invalid pagination cursor.",
                }));
            }
        };
        and_clauses.push(doc! { "_id": { "$lt": before_oid } });
    }

    let filter = doc! { "$and": and_clauses };

    let mut messages: Vec<Message> = match Message::collection(&db)
        .find(filter)
        .sort(doc! { "_id": -1 })
        .limit(limit + 1)
        .await
    {
        Ok(c) => match c.try_collect().await {
            Ok(m) => m,
            Err(e) => {
                log::error!("get_messages try_collect: {e}");
                return HttpResponse::InternalServerError().body("Internal Server Error");
            }
        },
        Err(e) => {
            log::error!("get_messages find: {e}");
            return HttpResponse::InternalServerError().body("Internal Server Error");
        }
    };

    let has_more = messages.len() as i64 > limit;
    if has_more {
        messages.truncate(limit as usize);
    }

    messages.retain(|m| message_belongs_to_dm_conversation(m, user_oid, contact_oid));
    messages.reverse();

    let out = serialize_all(&db, &messages).await;
    HttpResponse::Ok().json(json!({ "messages": out, "hasMore": has_more }))
}

#[derive(MultipartForm)]
pub struct UploadFileForm {
    #[multipart(rename = "file", limit = "10 MiB")]
    pub file: TempFile,
    #[multipart(rename = "contextType")]
    pub context_type: Text<String>,
    #[multipart(rename = "contextId")]
    pub context_id: Text<String>,
    #[multipart(rename = "contentType")]
    pub content_type: Option<Text<String>>,
}

pub async fn upload_file(req: HttpRequest, form: MultipartForm<UploadFileForm>) -> HttpResponse {
    let original_name = form
        .file
        .file_name
        .as_deref()
        .map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n).to_string())
        .unwrap_or_default();

    if original_name.is_empty() {
        return HttpResponse::BadRequest().body("File is required.");
    }

    let user_id = request_user_id(&req).unwrap_or_default();
    if user_id.is_empty() {
        return HttpResponse::Unauthorized().body("Authentication required.");
    }
    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().body("Invalid user.");
    };

    let ext = original_name
        .rsplit('.')
        .next()
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    if !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
        return HttpResponse::BadRequest().body("Invalid file type.");
    }
    let upload_path = form.file.file.path().to_path_buf();
    if !validate_file_magic_async(upload_path.clone(), ext.clone()).await {
        return HttpResponse::BadRequest().body("Invalid file content.");
    }
    if matches!(ext.as_str(), "pdf" | "docx" | "xlsx" | "pptx" | "csv")
        && !validate_upload_document_async(upload_path.clone(), ext.clone()).await
    {
        return HttpResponse::BadRequest().body("Invalid file content.");
    }

    let is_image = is_image_extension(&ext);
    let max_upload_bytes = if is_image {
        MAX_IMAGE_ATTACHMENT_BYTES
    } else {
        MAX_ATTACHMENT_BYTES
    };
    if local_file_size(form.file.file.path())
        .map(|size| !file_bytes_within_limit(size, max_upload_bytes))
        .unwrap_or(true)
    {
        let limit_mb = max_upload_bytes / (1024 * 1024);
        return HttpResponse::PayloadTooLarge()
            .body(format!("File too large. Maximum size is {limit_mb} MB."));
    }

    if original_name.contains("..") || original_name.contains('/') || original_name.contains('\\') {
        return HttpResponse::BadRequest().body("Invalid file name.");
    }

    let context_type = form.context_type.0.trim().to_ascii_lowercase();
    let context_id = form.context_id.0.trim().to_string();
    if context_id.is_empty() {
        return HttpResponse::BadRequest().body("Upload context is required.");
    }

    let db = get_db();

    if matches!(context_type.as_str(), "dm" | "channel") {
        if let Err(mut retry_after) = try_consume_chat_attachment_quota(&user_id) {
            if retry_after == 0 {
                retry_after = chat_attachment_retry_after_secs(&user_id);
            }
            let window_minutes = CHAT_ATTACHMENT_WINDOW_SECS / 60;
            return HttpResponse::TooManyRequests().json(json!({
                "error": "CHAT_ATTACHMENT_LIMIT",
                "message": format!(
                    "Osiągnięto limit {} załączników na {} minut. Spróbuj ponownie później.",
                    MAX_CHAT_ATTACHMENTS_PER_WINDOW,
                    window_minutes,
                ),
                "retryAfter": retry_after,
            }));
        }
    }

    let stored_ext = if is_image { "webp" } else { ext.as_str() };

    let logical_path = match context_type.as_str() {
        "dm" => {
            if ObjectId::parse_str(&context_id).is_err() {
                return HttpResponse::BadRequest().body("Invalid contact ID.");
            }
            match require_dm_access(&db, &user_id, &context_id).await {
                Ok(()) => {}
                Err(AccessDeniedReason::Unavailable) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "error": "Temporarily unavailable",
                        "retryable": true,
                    }));
                }
                Err(_) => {
                    return HttpResponse::Forbidden().body("You cannot upload to this conversation.");
                }
            }
            let filename = format!("{}.{}", uuid::Uuid::new_v4(), stored_ext);
            attachment_dm_key(&user_id, &context_id, &filename)
        }
        "channel" => {
            if ObjectId::parse_str(&context_id).is_err() {
                return HttpResponse::BadRequest().body("Invalid channel ID.");
            }
            match require_channel_access(&db, &context_id, &user_id).await {
                Ok(_) => {}
                Err(AccessDeniedReason::Unavailable) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "error": "Temporarily unavailable",
                        "retryable": true,
                    }));
                }
                Err(_) => {
                    return HttpResponse::Forbidden().body("You cannot upload to this channel.");
                }
            }
            let filename = format!("{}.{}", uuid::Uuid::new_v4(), stored_ext);
            attachment_group_key(&context_id, &filename)
        }
        _ => return HttpResponse::BadRequest().body("Invalid upload context."),
    };

    let (body, thumb_body) = if is_image {
        match reencode_upload_to_webp_variants_async(upload_path).await {
            Ok(variants) => (variants.full, Some(variants.thumb)),
            Err(err) => return HttpResponse::BadRequest().body(reencode_error_message(&err)),
        }
    } else {
        match tokio::task::spawn_blocking(move || std::fs::read(&upload_path)).await {
            Ok(Ok(bytes)) => (bytes, None),
            _ => return HttpResponse::InternalServerError().body("Internal Server Error."),
        }
    };

    let thumb_size = thumb_body.as_ref().map(|b| b.len() as u64).unwrap_or(0);
    let file_size = body.len() as u64;
    let total_stored = file_size.saturating_add(thumb_size);

    if !file_bytes_within_limit(file_size, max_upload_bytes) {
        let limit_mb = max_upload_bytes / (1024 * 1024);
        return HttpResponse::PayloadTooLarge()
            .body(format!("File too large. Maximum size is {limit_mb} MB."));
    }

    if UserStorageUsage::would_exceed(&db, user_oid, total_stored)
        .await
        .unwrap_or(true)
    {
        return HttpResponse::PayloadTooLarge().body(
            "Storage quota exceeded. Delete old attachments or wait for cleanup.",
        );
    }

    let file_hash = sha256_hex(&body);
    let client_mime = form.content_type.as_ref().map(|value| value.0.as_str());
    let content_type = resolve_upload_content_type(stored_ext, client_mime, &body);
    if let Err(err) = storage()
        .put_quarantine(&logical_path, body, &content_type)
        .await
    {
        log::error!("put_quarantine {logical_path} failed: {err}");
        return HttpResponse::InternalServerError().body("Internal Server Error.");
    }

    let thumb_path = attachment_thumb_key(&logical_path);
    if let (Some(thumb_bytes), Some(thumb_key)) = (thumb_body, thumb_path.as_ref()) {
        if let Err(err) = storage()
            .put_quarantine(thumb_key, thumb_bytes, "image/webp")
            .await
        {
            log::error!("put_quarantine thumb {thumb_key} failed: {err}");
            let _ = storage().delete_attachment_key(&logical_path).await;
            return HttpResponse::InternalServerError().body("Internal Server Error.");
        }
    }

    if PendingUpload::register(
        &db,
        user_oid,
        &logical_path,
        &context_type,
        &context_id,
        total_stored,
        &file_hash,
        &content_type,
        ScanStatus::Pending,
    )
    .await
    .is_err()
    {
        let _ = storage().delete_attachment_key(&logical_path).await;
        if PendingUpload::count_for_user(&db, user_oid)
            .await
            .map(|count| count >= crate::utils::upload::MAX_PENDING_UPLOADS_PER_USER)
            .unwrap_or(false)
        {
            return HttpResponse::TooManyRequests()
                .body("Too many pending uploads. Send or wait before uploading more.");
        }
        return HttpResponse::InternalServerError().body("Internal Server Error.");
    }

    if UserStorageUsage::adjust(&db, user_oid, total_stored as i64)
        .await
        .is_err()
    {
        let _ = storage().delete_attachment_key(&logical_path).await;
        let _ = PendingUpload::claim_by_path(&db, user_oid, &logical_path).await;
        return HttpResponse::InternalServerError().body("Internal Server Error.");
    }

    enqueue(ScanJob {
        file_path: logical_path.clone(),
        file_hash: file_hash.clone(),
        content_type: content_type.clone(),
        attempts: 0,
    });

    log_attachment_upload(
        &req,
        &user_id,
        &logical_path,
        &context_type,
        &context_id,
        file_size,
    )
    .await;

    HttpResponse::Ok().json(json!({
        "filePath": logical_path,
        "scanStatus": ScanStatus::Pending.as_str(),
    }))
}

#[derive(Deserialize)]
pub struct EditMessageBody {
    pub content: Option<String>,
}

pub async fn edit_message(req: HttpRequest, body: web::Json<EditMessageBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let message_id = req.match_info().get("messageId").unwrap_or("");
    let Ok(mid) = ObjectId::parse_str(message_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "Message not found" }));
    };

    let db = get_db();

    if let Ok(uid) = ObjectId::parse_str(&user_id) {
        match User::find_by_id(&db, uid).await {
            Ok(Some(u)) if u.is_login_allowed() => {}
            Ok(Some(_)) => {
                return HttpResponse::Forbidden()
                    .json(json!({ "error": "Account is inactive or blocked" }))
            }
            Ok(None) => {
                return HttpResponse::Unauthorized().json(json!({ "error": "User not found" }))
            }
            Err(_) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        }
    }

    let message = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) => m,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Message not found" })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal server error", "retryable": true })),
    };

    if message.sender.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "error": "Not authorized to edit this message" }));
    }

    if message.message_type != crate::model::messages::MessageType::Text {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Only text messages can be edited" }));
    }

    if let Err(reason) = require_message_participant(&db, &user_id, &message).await {
        if reason == AccessDeniedReason::Unavailable {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": reason.as_str(),
                "retryable": true,
            }));
        }
        return HttpResponse::Forbidden().json(json!({ "error": reason.as_str() }));
    }

    let content = crate::utils::validators::sanitize::sanitize_message_content(
        body.content.as_deref().unwrap_or(""),
    );
    let content = inbound_plaintext_for_processing(&content, false);

    if content.trim().is_empty() {
        return HttpResponse::BadRequest().json(json!({ "error": "Treść wiadomości jest wymagana" }));
    }
    if !is_message_content_within_limit(&content) {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Wiadomość nie może przekraczać 2000 znaków" }));
    }

    let (mentions, mentions_everyone) = if let Some(channel_id) = message.channel {
        let channel = match Channel::find_by_id(&db, channel_id).await {
            Ok(Some(ch)) => ch,
            Ok(None) => {
                return HttpResponse::NotFound().json(json!({ "error": "Channel not found" }));
            }
            Err(_) => match Channel::find_by_id(&db, channel_id).await {
                Ok(Some(ch)) => ch,
                Ok(None) => {
                    return HttpResponse::NotFound().json(json!({ "error": "Channel not found" }));
                }
                Err(_) => {
                    return HttpResponse::InternalServerError().json(json!({
                        "error": "Internal server error",
                        "retryable": true,
                    }));
                }
            },
        };
        let mut ids: Vec<String> = channel.members.iter().map(|m| m.to_hex()).collect();
        ids.push(channel.admin.to_hex());
        let mentions = match resolve_mentions(&db, &content, &ids).await {
            Ok(m) => m,
            Err(()) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        };
        (
            mentions,
            is_channel_admin(&channel, Some(&user_id)) && has_everyone_mention(&content),
        )
    } else if let Some(recipient) = message.recipient {
        let mentions = match resolve_mentions(
            &db,
            &content,
            &[message.sender.to_hex(), recipient.to_hex()],
        )
        .await
        {
            Ok(m) => m,
            Err(()) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        };
        (mentions, false)
    } else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid message" }));
    };

    let mentions_bson = match mongodb::bson::to_bson(&mentions) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Internal server error",
                "retryable": true,
            }));
        }
    };
    let stored_content = match crate::utils::messages::storage::prepare_content_for_storage_async(
        content.trim().to_string(),
    )
    .await
    {
        Ok(c) => c,
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal server error", "retryable": true })),
    };
    let search_index = match build_search_index_from_incoming(content.trim()) {
        Ok(index) => index,
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal server error", "retryable": true })),
    };
    let set_doc = doc! {
        "content": stored_content,
        "searchText": search_index.encrypted_text,
        "searchTokens": search_index.tokens,
        "mentions": mentions_bson,
        "mentionsEveryone": mentions_everyone,
        "edited": true,
        "editedAt": DateTime::now(),
        "updatedAt": DateTime::now(),
    };
    let edit_ok = match Message::collection(&db)
        .update_one(
            doc! { "_id": mid, "deleted": { "$ne": true } },
            doc! { "$set": set_doc },
        )
        .await
    {
        Ok(r) => r.modified_count > 0,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Internal server error", "retryable": true }));
        }
    };
    if !edit_ok {
        return HttpResponse::NotFound().json(json!({ "error": "Message not found" }));
    }

    let updated = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) => m,
        Ok(None) | Err(_) => match Message::find_by_id(&db, mid).await {
            Ok(Some(m)) => m,
            _ => {
                return HttpResponse::InternalServerError().json(json!({
                    "error": "Internal server error",
                    "retryable": true,
                }));
            }
        },
    };

    {
        let tip_msg = updated.clone();
        if let Some(cid) = tip_msg.channel {
            crate::utils::tips::upsert_channel_tip(&db, cid, &tip_msg).await;
        } else {
            crate::utils::tips::upsert_dm_tip(&db, &tip_msg).await;
        }
    }
            let populated = serialize_message(&db, &updated).await;
            let previous_mentions: std::collections::HashSet<String> =
                message.mentions.iter().map(|id| id.to_hex()).collect();
            let previous_everyone = message.mentions_everyone;
            let sender_id = updated.sender.to_hex();
            let from_user = populated
                .get("sender")
                .cloned()
                .unwrap_or(json!({ "_id": sender_id }));
            let preview_content = content.trim().to_string();
            let message_id_hex = mid.to_hex();

            let muted_lookup: Option<std::collections::HashSet<String>> =
                if let Some(channel_oid) = updated.channel {
                    if let Ok(Some(channel)) = Channel::find_by_id(&db, channel_oid).await {
                        use mongodb::bson::Document;
                        let coll = db.collection::<Document>("users");
                        let mut member_oids = channel.members.clone();
                        if !member_oids.iter().any(|id| *id == channel.admin) {
                            member_oids.push(channel.admin);
                        }
                        match coll
                            .find(doc! {
                                "_id": { "$in": &member_oids },
                                "mutedChannels": channel_oid,
                            })
                            .projection(doc! { "_id": 1 })
                            .await
                        {
                            Ok(mut cursor) => {
                                let mut set = std::collections::HashSet::new();
                                let mut ok = true;
                                loop {
                                    match cursor.try_next().await {
                                        Ok(Some(d)) => {
                                            if let Ok(id) = d.get_object_id("_id") {
                                                set.insert(id.to_hex());
                                            }
                                        }
                                        Ok(None) => break,
                                        Err(_) => {
                                            ok = false;
                                            break;
                                        }
                                    }
                                }
                                if ok {
                                    Some(set)
                                } else {
                                    None
                                }
                            }
                            Err(_) => None,
                        }
                    } else {
                        None
                    }
                } else if let Some(recipient) = updated.recipient {
                    use mongodb::bson::Document;
                    let coll = db.collection::<Document>("users");
                    match coll
                        .find_one(doc! { "_id": recipient })
                        .projection(doc! { "mutedContacts": 1 })
                        .await
                    {
                        Ok(Some(doc)) => {
                            let muted = doc
                                .get_array("mutedContacts")
                                .ok()
                                .map(|arr| {
                                    arr.iter().any(|b| {
                                        b.as_object_id()
                                            .map(|id| id.to_hex() == sender_id)
                                            .unwrap_or(false)
                                    })
                                })
                                .unwrap_or(false);
                            if muted {
                                Some(std::collections::HashSet::from([recipient.to_hex()]))
                            } else {
                                Some(std::collections::HashSet::new())
                            }
                        }
                        Ok(None) => None,
                        Err(_) => None,
                    }
                } else {
                    Some(std::collections::HashSet::new())
                };
            let mentions_ok = muted_lookup.is_some();
            let muted_ids = muted_lookup.unwrap_or_default();

            let emit_new_mention = |member_id: &str, scope: &str, source_id: &str, source_name: Option<&str>| {
                if !mentions_ok || member_id == sender_id || muted_ids.contains(member_id) {
                    return;
                }
                let newly = (mentions.iter().any(|id| id.to_hex() == member_id)
                    && !previous_mentions.contains(member_id))
                    || (mentions_everyone && !previous_everyone);
                if !newly {
                    return;
                }
                let preview = if preview_content.chars().count() > 140 {
                    format!("{}…", preview_content.chars().take(140).collect::<String>())
                } else {
                    preview_content.clone()
                };
                crate::ws::registry::emit_to_user(
                    member_id,
                    "message-mention",
                    json!({
                        "scope": scope,
                        "sourceId": source_id,
                        "sourceName": source_name,
                        "messageId": message_id_hex,
                        "from": from_user,
                        "preview": preview,
                    }),
                );
            };

            if let Some(channel_id) = updated.channel {
                let channel = match Channel::find_by_id(&db, channel_id).await {
                    Ok(Some(ch)) => Some(ch),

                    Ok(None) | Err(_) => None,
                };
                if let Some(channel) = channel {
                    let recipients = crate::ws::registry::channel_recipient_ids(&channel);
                    crate::ws::registry::emit_to_users(
                        &recipients,
                        "message-edited",
                        populated.clone(),
                    );
                    let channel_id_hex = channel_id.to_hex();
                    for r in &recipients {
                        emit_new_mention(r, "channel", &channel_id_hex, Some(&channel.name));
                    }
                } else {

                    use crate::model::read_state::ChannelReadState;
                    use futures_util::TryStreamExt;
                    let mut recipients = vec![sender_id.clone()];
                    if let Ok(cursor) = ChannelReadState::collection(&db)
                        .find(doc! { "channelId": channel_id })
                        .await
                    {
                        let states: Vec<ChannelReadState> =
                            cursor.try_collect().await.unwrap_or_default();
                        for s in states {
                            let id = s.user_id.to_hex();
                            if !recipients.iter().any(|r| r == &id) {
                                recipients.push(id);
                            }
                        }
                    }
                    crate::ws::registry::emit_to_users(
                        &recipients,
                        "message-edited",
                        populated.clone(),
                    );
                }
            } else if let Some(recipient) = updated.recipient {
                crate::ws::registry::emit_to_user(
                    &recipient.to_hex(),
                    "message-edited",
                    populated.clone(),
                );
                crate::ws::registry::emit_to_user(
                    &updated.sender.to_hex(),
                    "message-edited",
                    populated.clone(),
                );
                emit_new_mention(&recipient.to_hex(), "dm", &sender_id, None);
            }
            HttpResponse::Ok().json(json!({ "message": populated }))
}

pub async fn delete_message(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "User not authenticated" }));
    };
    let message_id = req.match_info().get("messageId").unwrap_or("");
    let Ok(mid) = ObjectId::parse_str(message_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "Message not found" }));
    };

    let db = get_db();
    let message = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) => m,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Message not found" })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal server error", "retryable": true })),
    };

    if message.sender.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "error": "Not authorized to delete this message" }));
    }

    if let Err(reason) = require_message_participant(&db, &user_id, &message).await {
        if reason == AccessDeniedReason::Unavailable {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": reason.as_str(),
                "retryable": true,
            }));
        }
        return HttpResponse::Forbidden().json(json!({ "error": reason.as_str() }));
    }

    let outcome = match Message::soft_delete_active(&db, mid).await {
        Ok(o) => o,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Failed to delete message",
                "retryable": true,
            }));
        }
    };
    let crate::model::messages::SoftDeleteOutcome::Deleted { was_unread } = outcome else {
        return HttpResponse::Ok().json(json!({ "success": true }));
    };
    cleanup_attachment_if_unreferenced(&db, message.file_url.as_deref()).await;
    if let Some(channel_id) = message.channel {
        crate::utils::tips::refresh_channel_tip_after_delete(&db, channel_id, mid)
            .await;
        let body = json!({ "_id": message_id });

        let channel = match crate::model::channels::Channel::find_by_id(&db, channel_id).await {
            Ok(Some(ch)) => Some(ch),
            Ok(None) => None,
            Err(_) => crate::model::channels::Channel::find_by_id(&db, channel_id)
                .await
                .ok()
                .flatten(),
        };
        if let Some(channel) = channel {
            let recipients = crate::ws::registry::channel_recipient_ids(&channel);
            crate::ws::registry::emit_to_users(&recipients, "message-deleted", body);
            let sender_hex = message.sender.to_hex();
            let msg_ts = message.timestamp;
            let channel_id_hex = channel_id.to_hex();
            use crate::model::read_state::ChannelReadState;
            use futures_util::TryStreamExt;
            let mut targets: Vec<String> =
                channel.members.iter().map(|m| m.to_hex()).collect();
            targets.push(channel.admin.to_hex());
            let member_oids: Vec<ObjectId> = targets
                .iter()
                .filter_map(|id| ObjectId::parse_str(id).ok())
                .collect();
            let mut last_reads: std::collections::HashMap<String, (DateTime, DateTime)> =
                std::collections::HashMap::new();
            let mut read_state_ok = false;
            if let Ok(cursor) = ChannelReadState::collection(&db)
                .find(doc! {
                    "channelId": channel_id,
                    "userId": { "$in": &member_oids },
                })
                .await
            {
                match cursor.try_collect::<Vec<ChannelReadState>>().await {
                    Ok(states) => {
                        read_state_ok = true;
                        for s in states {
                            last_reads
                                .insert(s.user_id.to_hex(), (s.last_read_at, s.created_at));
                        }
                    }
                    Err(_) => {
                        read_state_ok = false;
                    }
                }
            }
            let mut seen = std::collections::HashSet::new();
            let mut affected: Vec<(String, ObjectId)> = Vec::new();
            for member_id in targets {
                if member_id == sender_hex || !seen.insert(member_id.clone()) {
                    continue;
                }
                let Ok(oid) = ObjectId::parse_str(&member_id) else {
                    continue;
                };

                if !read_state_ok {
                    affected.push((member_id, oid));
                    continue;
                }
                let Some(&(last, created)) = last_reads.get(&member_id) else {

                    affected.push((member_id, oid));
                    continue;
                };
                let effective = if last.timestamp_millis() <= 0 {
                    created
                } else {
                    last
                };
                if effective.timestamp_millis() <= 0 || msg_ts <= effective {
                    continue;
                }
                affected.push((member_id, oid));
            }
            let sync_futs: Vec<_> = affected
                .into_iter()
                .map(|(member_id, oid)| {
                    let db = db.clone();
                    let channel_id_hex = channel_id_hex.clone();
                    async move {
                        if let Some(n) = crate::utils::unread::try_sync_channel_unread(
                            &db, oid, channel_id,
                        )
                        .await
                        {
                            crate::utils::unread::emit_unread_absolute(
                                &member_id,
                                "channel",
                                &channel_id_hex,
                                n,
                            );
                        }
                    }
                })
                .collect();
            futures_util::future::join_all(sync_futs).await;
        } else {

            crate::ws::registry::emit_to_user(&message.sender.to_hex(), "message-deleted", body.clone());
            crate::ws::registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "DELETE_FANOUT_DEGRADED",
                    "message": "Wiadomość usunięta, ale synchronizacja z kanałem może być niepełna. Odśwież czat.",
                    "retryable": true,
                    "messageId": message_id,
                }),
            );
            use crate::model::read_state::ChannelReadState;
            use futures_util::TryStreamExt;
            if let Ok(cursor) = ChannelReadState::collection(&db)
                .find(doc! { "channelId": channel_id })
                .await
            {
                let states: Vec<ChannelReadState> = match cursor.try_collect().await {
                    Ok(s) => s,
                    Err(e) => {

                        log::error!("delete_message channel fanout try_collect: {e}");
                        crate::ws::registry::emit_to_user(
                            &user_id,
                            "error",
                            json!({
                                "code": "DELETE_FANOUT_DEGRADED",
                                "message": "Wiadomość usunięta, ale synchronizacja z kanałem może być niepełna. Odśwież czat.",
                                "retryable": true,
                                "messageId": message_id,
                            }),
                        );
                        return HttpResponse::Ok().json(json!({
                            "ok": true,
                            "degraded": true,
                        }));
                    }
                };
                let mut seen = std::collections::HashSet::new();
                seen.insert(message.sender.to_hex());
                let channel_id_hex = channel_id.to_hex();
                for s in states {
                    let member_id = s.user_id.to_hex();
                    if !seen.insert(member_id.clone()) {
                        continue;
                    }
                    crate::ws::registry::emit_to_user(&member_id, "message-deleted", body.clone());
                    if was_unread {
                        if let Some(n) = crate::utils::unread::try_sync_channel_unread(
                            &db, s.user_id, channel_id,
                        )
                        .await
                        {
                            crate::utils::unread::emit_unread_absolute(
                                &member_id,
                                "channel",
                                &channel_id_hex,
                                n,
                            );
                        }
                    }
                }
            }
        }
    } else if let Some(recipient) = message.recipient {
        crate::utils::tips::refresh_dm_tip_after_delete(
            &db,
            message.sender,
            recipient,
            mid,
        )
        .await;
        let body = json!({ "_id": message_id });
        crate::ws::registry::emit_to_user(&recipient.to_hex(), "message-deleted", body.clone());
        crate::ws::registry::emit_to_user(&message.sender.to_hex(), "message-deleted", body);
        if was_unread {
            let recipient_hex = recipient.to_hex();
            let sender_oid = message.sender;

            if let Some(n) = crate::utils::tips::try_sync_dm_tip_unread(
                &db,
                recipient,
                sender_oid,
            )
            .await
            {
                crate::utils::unread::emit_unread_absolute(
                    &recipient_hex,
                    "dm",
                    &sender_oid.to_hex(),
                    n,
                );
            }
        }
    }
    HttpResponse::Ok().json(json!({ "success": true }))
}

pub async fn pin_message(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let message_id = req.match_info().get("messageId").unwrap_or("");
    let Ok(mid) = ObjectId::parse_str(message_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "Message not found" }));
    };

    let db = get_db();
    let message = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) if !m.deleted => m,
        Ok(Some(_)) | Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "error": "Message not found" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    match try_can_pin_message(&db, &user_id, &message).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Forbidden().json(json!({
                "error": "FORBIDDEN",
                "message": "Nie masz uprawnień do przypinania tej wiadomości.",
            }));
        }
        Err(AccessDeniedReason::Unavailable) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
        Err(_) => {
            return HttpResponse::Forbidden().json(json!({
                "error": "FORBIDDEN",
                "message": "Nie masz uprawnień do przypinania tej wiadomości.",
            }));
        }
    }

    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id" }));
    };
    match Message::collection(&db)
        .update_one(
            doc! { "_id": mid },
            doc! { "$set": {
                "pinned": true,
                "pinnedAt": DateTime::now(),
                "pinnedBy": user_oid,
                "updatedAt": DateTime::now(),
            }},
        )
        .await
    {
        Ok(_) => {}
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Failed to pin message",
                "retryable": true,
            }));
        }
    }

    match Message::find_by_id(&db, mid).await {
        Ok(Some(updated)) => {
            let populated = serialize_message(&db, &updated).await;
            emit_message_pin_fanout(&db, &updated, &populated, &user_id).await;
            HttpResponse::Ok().json(json!({ "message": populated }))
        }
        Ok(None) | Err(_) => match Message::find_by_id(&db, mid).await {
            Ok(Some(updated)) => {
                let populated = serialize_message(&db, &updated).await;
                emit_message_pin_fanout(&db, &updated, &populated, &user_id).await;
                HttpResponse::Ok().json(json!({ "message": populated }))
            }
            _ => {
                let mut patched = message.clone();
                patched.pinned = true;
                patched.pinned_at = Some(DateTime::now());
                patched.pinned_by = Some(user_oid);
                let populated = serialize_message(&db, &patched).await;
                emit_message_pin_fanout(&db, &patched, &populated, &user_id).await;
                HttpResponse::Ok().json(json!({ "message": populated }))
            }
        },
    }
}

pub async fn unpin_message(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let message_id = req.match_info().get("messageId").unwrap_or("");
    let Ok(mid) = ObjectId::parse_str(message_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "Message not found" }));
    };

    let db = get_db();
    let message = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) if !m.deleted => m,
        Ok(Some(_)) | Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "error": "Message not found" }))
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };

    match try_can_pin_message(&db, &user_id, &message).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Forbidden().json(json!({
                "error": "FORBIDDEN",
                "message": "Nie masz uprawnień do odpięcia tej wiadomości.",
            }));
        }
        Err(AccessDeniedReason::Unavailable) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
        Err(_) => {
            return HttpResponse::Forbidden().json(json!({
                "error": "FORBIDDEN",
                "message": "Nie masz uprawnień do odpięcia tej wiadomości.",
            }));
        }
    }

    match Message::collection(&db)
        .update_one(
            doc! { "_id": mid },
            doc! {
                "$set": { "pinned": false, "updatedAt": DateTime::now() },
                "$unset": { "pinnedAt": "", "pinnedBy": "" },
            },
        )
        .await
    {
        Ok(_) => {}
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Failed to unpin message",
                "retryable": true,
            }));
        }
    }

    match Message::find_by_id(&db, mid).await {
        Ok(Some(updated)) => {
            let populated = serialize_message(&db, &updated).await;
            emit_message_pin_fanout(&db, &updated, &populated, &user_id).await;
            HttpResponse::Ok().json(json!({ "message": populated }))
        }
        Ok(None) | Err(_) => match Message::find_by_id(&db, mid).await {
            Ok(Some(updated)) => {
                let populated = serialize_message(&db, &updated).await;
                emit_message_pin_fanout(&db, &updated, &populated, &user_id).await;
                HttpResponse::Ok().json(json!({ "message": populated }))
            }
            _ => {
                let mut patched = message.clone();
                patched.pinned = false;
                patched.pinned_at = None;
                patched.pinned_by = None;
                let populated = serialize_message(&db, &patched).await;
                emit_message_pin_fanout(&db, &patched, &populated, &user_id).await;
                HttpResponse::Ok().json(json!({ "message": populated }))
            }
        },
    }
}

async fn emit_message_pin_fanout(
    db: &mongodb::Database,
    updated: &Message,
    populated: &serde_json::Value,
    actor_id: &str,
) {
    if let Some(channel_id) = updated.channel {
        let channel = match Channel::find_by_id(db, channel_id).await {
            Ok(Some(ch)) => Some(ch),

            Ok(None) | Err(_) => None,
        };
        if let Some(channel) = channel {
            let recipients = crate::ws::registry::channel_recipient_ids(&channel);
            crate::ws::registry::emit_to_users(&recipients, "message-edited", populated.clone());
        } else {
            use crate::model::read_state::ChannelReadState;
            use futures_util::TryStreamExt;
            let mut recipients = vec![actor_id.to_string(), updated.sender.to_hex()];
            recipients.dedup();
            if let Ok(cursor) = ChannelReadState::collection(db)
                .find(doc! { "channelId": channel_id })
                .await
            {
                let states: Vec<ChannelReadState> =
                    cursor.try_collect().await.unwrap_or_default();
                for s in states {
                    let id = s.user_id.to_hex();
                    if !recipients.iter().any(|r| r == &id) {
                        recipients.push(id);
                    }
                }
            }
            crate::ws::registry::emit_to_users(&recipients, "message-edited", populated.clone());
        }
    } else if let Some(recipient) = updated.recipient {
        crate::ws::registry::emit_to_user(&recipient.to_hex(), "message-edited", populated.clone());
        crate::ws::registry::emit_to_user(&updated.sender.to_hex(), "message-edited", populated.clone());
        if actor_id != updated.sender.to_hex() && actor_id != recipient.to_hex() {
            crate::ws::registry::emit_to_user(actor_id, "message-edited", populated.clone());
        }
    }
}

#[derive(Deserialize)]
pub struct PinnedBody {
    #[serde(rename = "contactId")]
    pub contact_id: Option<String>,
    #[serde(rename = "channelId")]
    pub channel_id: Option<String>,
}

pub async fn get_pinned_messages(req: HttpRequest, body: web::Json<PinnedBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let db = get_db();

    if let Some(channel_id) = body.channel_id.as_deref().filter(|s| !s.is_empty()) {
        let channel = match require_channel_access(&db, channel_id, &user_id).await {
            Ok(ch) => ch,
            Err(AccessDeniedReason::Unavailable) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
            Err(_) => {
                return HttpResponse::Forbidden().json(json!({ "error": "Access denied" }));
            }
        };
        let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {
            return HttpResponse::BadRequest().json(json!({ "error": "Invalid channel id" }));
        };
        let messages: Vec<Message> = match Message::collection(&db)
            .find(doc! { "channel": channel_oid, "pinned": true, "deleted": { "$ne": true } })
            .sort(doc! { "pinnedAt": -1 })
            .limit(MAX_PINNED_MESSAGES)
            .await
        {
            Ok(c) => match c.try_collect().await {
                Ok(m) => m,
                Err(_) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "error": "Temporarily unavailable",
                        "retryable": true,
                    }));
                }
            },
            Err(_) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        };
        let can_pin = if let Some(m) = messages.first() {
            can_pin_message(&db, &user_id, m).await
        } else {
            is_channel_admin(&channel, Some(&user_id))
        };
        let out = serialize_all(&db, &messages).await;
        return HttpResponse::Ok().json(json!({ "messages": out, "canPin": can_pin }));
    }

    if let Some(contact_id) = body.contact_id.as_deref().filter(|s| !s.is_empty()) {
        let (uid, cid) = match authorize_dm_history_read(&db, &user_id, contact_id).await {
            Ok(pair) => pair,
            Err(AccessDeniedReason::Unavailable) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
            Err(_) => {
                return HttpResponse::Forbidden().json(json!({ "error": "Access denied" }));
            }
        };
        let filter = doc! {
            "$and": [
                { "$or": [
                    { "sender": uid, "recipient": cid },
                    { "sender": cid, "recipient": uid },
                ]},
                { "pinned": true },
                { "deleted": { "$ne": true } },
            ]
        };
        let messages: Vec<Message> = match Message::collection(&db)
            .find(filter)
            .sort(doc! { "pinnedAt": -1 })
            .limit(MAX_PINNED_MESSAGES)
            .await
        {
            Ok(c) => match c.try_collect().await {
                Ok(m) => m,
                Err(_) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "error": "Temporarily unavailable",
                        "retryable": true,
                    }));
                }
            },
            Err(_) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        };
        let mut messages = messages;
        messages.retain(|m| message_belongs_to_dm_conversation(m, uid, cid));
        let can_pin = if let Some(m) = messages.first() {
            can_pin_message(&db, &user_id, m).await
        } else {
            are_friends(&db, &user_id, contact_id).await
        };
        let out = serialize_all(&db, &messages).await;
        return HttpResponse::Ok().json(json!({ "messages": out, "canPin": can_pin }));
    }

    HttpResponse::BadRequest().json(json!({ "error": "contactId or channelId required" }))
}

#[derive(Deserialize)]
pub struct SearchMessagesBody {
    pub query: Option<String>,
    #[serde(rename = "contactId")]
    pub contact_id: Option<String>,
    #[serde(rename = "channelId")]
    pub channel_id: Option<String>,
}

pub async fn search_messages(req: HttpRequest, body: web::Json<SearchMessagesBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let trimmed = body.query.clone().unwrap_or_default().trim().to_string();
    if trimmed.chars().count() < MIN_QUERY_LENGTH {
        return HttpResponse::BadRequest().json(json!({
            "error": "QUERY_TOO_SHORT",
            "message": format!("Wpisz co najmniej {} znaki.", MIN_QUERY_LENGTH),
        }));
    }
    if trimmed.chars().count() > MAX_QUERY_LENGTH {
        return HttpResponse::BadRequest().json(json!({
            "error": "QUERY_TOO_LONG",
            "message": format!("Zapytanie może mieć co najwyżej {} znaków.", MAX_QUERY_LENGTH),
        }));
    }

    let tokens = search_tokens_for_query(&trimmed);
    if tokens.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "error": "QUERY_TOO_SHORT",
            "message": format!("Wpisz co najmniej {} znaki.", MIN_QUERY_LENGTH),
        }));
    }
    let db = get_db();

    if let Some(channel_id) = body.channel_id.as_deref().filter(|s| !s.is_empty()) {
        match require_channel_access(&db, channel_id, &user_id).await {
            Ok(_) => {}
            Err(AccessDeniedReason::Unavailable) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
            Err(_) => {
                return HttpResponse::Forbidden().json(json!({ "error": "Access denied" }));
            }
        }
        let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {
            return HttpResponse::BadRequest().json(json!({ "error": "Invalid channel id" }));
        };
        let filter = doc! {
            "channel": channel_oid,
            "deleted": { "$ne": true },
            "messageType": "TEXT",
            "searchTokens": { "$all": &tokens },
        };
        let messages: Vec<Message> = match Message::collection(&db)
            .find(filter)
            .sort(doc! { "timestamp": -1 })
            .limit(SEARCH_LIMIT)
            .await
        {
            Ok(c) => match c.try_collect().await {
                Ok(m) => m,
                Err(_) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "error": "Temporarily unavailable",
                        "retryable": true,
                    }));
                }
            },
            Err(_) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        };
        let out = serialize_all(&db, &messages).await;
        return HttpResponse::Ok().json(json!({ "messages": out }));
    }

    if let Some(contact_id) = body.contact_id.as_deref().filter(|s| !s.is_empty()) {
        let (uid, cid) = match authorize_dm_history_read(&db, &user_id, contact_id).await {
            Ok(pair) => pair,
            Err(AccessDeniedReason::Unavailable) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
            Err(_) => {
                return HttpResponse::Forbidden().json(json!({ "error": "Access denied" }));
            }
        };
        let filter = doc! {
            "$and": [
                { "$or": [
                    { "sender": uid, "recipient": cid },
                    { "sender": cid, "recipient": uid },
                ]},
                { "deleted": { "$ne": true } },
                { "messageType": "TEXT" },
                { "searchTokens": { "$all": &tokens } },
            ]
        };
        let mut messages: Vec<Message> = match Message::collection(&db)
            .find(filter)
            .sort(doc! { "timestamp": -1 })
            .limit(SEARCH_LIMIT)
            .await
        {
            Ok(c) => match c.try_collect().await {
                Ok(m) => m,
                Err(_) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "error": "Temporarily unavailable",
                        "retryable": true,
                    }));
                }
            },
            Err(_) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Temporarily unavailable",
                    "retryable": true,
                }));
            }
        };
        messages.retain(|m| message_belongs_to_dm_conversation(m, uid, cid));
        let out = serialize_all(&db, &messages).await;
        return HttpResponse::Ok().json(json!({ "messages": out }));
    }

    HttpResponse::BadRequest().json(json!({ "error": "contactId or channelId required" }))
}

#[derive(Deserialize)]
pub struct LinkPreviewBody {
    pub url: Option<String>,
}

pub async fn link_preview(req: HttpRequest, body: web::Json<LinkPreviewBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    if user_id.is_empty() {
        return HttpResponse::Unauthorized().json(json!({
            "error": "UNAUTHORIZED",
            "message": "Authentication required.",
        }));
    }

    let rate_key = format!("link-preview:{user_id}");
    if !LINK_PREVIEW_LIMIT.check_and_increment_with_window(&rate_key, 40, Duration::from_secs(60)) {
        return HttpResponse::TooManyRequests().json(json!({
            "error": "TOO_MANY_REQUESTS",
            "message": "Too many preview requests.",
        }));
    }

    let url = body.url.clone().unwrap_or_default().trim().to_string();
    if url.is_empty() || !is_safe_preview_target(&url) {
        return HttpResponse::BadRequest().json(json!({
            "error": "INVALID_URL",
            "message": "Invalid preview URL.",
        }));
    }

    match fetch_link_preview(&url).await {
        Ok(preview) => HttpResponse::Ok().json(preview),
        Err(message) => HttpResponse::BadGateway().json(json!({
            "error": "PREVIEW_UNAVAILABLE",
            "message": message,
        })),
    }
}
