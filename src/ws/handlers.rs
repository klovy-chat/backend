// handlers.rs
// Obsługa ramek: send/edit/react/typing/call/presence/mark-read.
// Zakres:
//  - auth per ramka
//  - Mongo + fan-out
//  - unread absolute vs delta
// Nowy type: match tutaj + FE protocol.ts. Idempotencja send = nonce w messages.rs.
// Przy zmianach: ws/state.rs, model/messages.rs, utils/unread/mod.rs, api/ws.ts.

use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::Database;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::model::channels::Channel;
use crate::model::messages::{
    CreateMessageError, CreateMessageInput, CreateMessageOutcome, Message, MessageType,
};
use crate::model::scan::ScanStatus;
use crate::model::users::{AvailabilityStatus, User};
use crate::ws::registry;
use crate::ws::state::{is_valid_object_id, now_ms, SocketState};
use crate::ws::typing::{self, TypingAccess};
use crate::utils::access::members::{
    channel_admin_bypasses_slowmode, require_channel_access, require_channel_message_access,
    require_dm_access, require_message_participant, AccessDeniedReason,
};
use crate::utils::ratelimit::slowmode::{check_channel_slowmode, record_channel_slowmode};
use crate::utils::db::get_db;
use crate::utils::friends::try_is_dm_blocked;
use crate::utils::channel::can_access_channel;
use crate::utils::voice::calls::{
    accept_session, cancel_session, create_ringing_session, drain_expired_sessions,
    end_session, reject_session, restore_sessions, ringing_sessions_for_callee,
    take_sessions_for_user, CallPhase, CallSession, CallSessionError,
};
use crate::utils::voice::channels::{
    clear_user_from_all_channels, join_channel_voice, leave_channel_voice, participants_in_channel,
};
use crate::utils::messages::access::{
    claim_pending_upload, try_can_mark_message_as_read,
    cleanup_attachment_if_unreferenced, scan_status_for_attachment, validate_message_attachment,
    AttachmentSendContext, QuoteContext, validate_quote_target_with_access,
};
use crate::utils::scan::{enqueue, ScanJob};
use crate::utils::messages::mentions::{has_everyone_mention, resolve_mentions};
use crate::utils::messages::{dm_only_or_clause, serialize_message};
use crate::utils::messages::storage::inbound_plaintext_for_processing;
use crate::utils::unread::{
    emit_unread_absolute,
    emit_unread_delta_at, peek_unread_generation,
    mark_channel_as_read_for_user,
};

async fn message_still_active(db: &Database, id: ObjectId) -> Option<bool> {
    match Message::collection(db)
        .find_one(doc! { "_id": id, "deleted": { "$ne": true } })
        .projection(doc! { "_id": 1 })
        .await
    {
        Ok(Some(_)) => Some(true),
        Ok(None) => Some(false),
        Err(_) => None,
    }
}
use crate::utils::user::json::resolve_display_name;

fn parse_message_type(s: &str) -> MessageType {
    match s.to_uppercase().as_str() {
        "FILE" => MessageType::File,
        "IMAGE" => MessageType::Image,
        "VIDEO" => MessageType::Video,
        "AUDIO" => MessageType::Audio,
        "STICKER" => MessageType::Sticker,
        _ => MessageType::Text,
    }
}

fn is_connected_user(connected: &str, claimed: &str) -> bool {
    !claimed.is_empty() && connected == claimed
}

fn reactions_json(msg: &Message) -> Value {
    let mut map = serde_json::Map::new();
    for (emoji, reaction) in &msg.reactions {
        map.insert(
            emoji.clone(),
            json!(reaction.users.iter().map(|u| u.to_hex()).collect::<Vec<_>>()),
        );
    }
    Value::Object(map)
}

async fn set_user_online(user_id: &str) -> bool {
    if !is_valid_object_id(user_id) {
        return false;
    }
    let Ok(oid) = ObjectId::parse_str(user_id) else {
        return false;
    };
    matches!(
        User::set_fields(&get_db(), oid, doc! { "isOnline": true }).await,
        Ok(Some(_))
    )
}

async fn set_user_offline(user_id: &str) -> bool {
    if !is_valid_object_id(user_id) {
        return false;
    }
    let Ok(oid) = ObjectId::parse_str(user_id) else {
        return false;
    };
    let now = DateTime::now();
    matches!(
        User::set_fields(
            &get_db(),
            oid,
            doc! { "isOnline": false, "lastSeen": now },
        )
        .await,
        Ok(Some(_))
    )
}

fn normalize_availability_status(status: &str) -> &'static str {
    match status.to_lowercase().as_str() {
        "away" => "away",
        "brb" => "brb",
        "dnd" => "dnd",
        _ => "online",
    }
}

async fn set_availability(user_id: &str, status: &str) -> Option<&'static str> {
    let normalized = normalize_availability_status(status);
    if !is_valid_object_id(user_id) {
        return None;
    }
    let Ok(oid) = ObjectId::parse_str(user_id) else {
        return None;
    };

    match User::set_fields(
        &get_db(),
        oid,
        doc! { "availabilityStatus": normalized },
    )
    .await
    {
        Ok(Some(_)) => {
            crate::utils::user::online::put(user_id, normalized);
            Some(normalized)
        }
        Ok(None) | Err(_) => None,
    }
}

async fn availability_status_for_user(user_id: &str) -> Option<&'static str> {
    if let Some(cached) = crate::utils::user::online::get(user_id) {
        return Some(normalize_availability_status(&cached));
    }
    let Ok(oid) = ObjectId::parse_str(user_id) else {
        return None;
    };
    match User::find_by_id(&get_db(), oid).await {
        Ok(Some(user)) => {
            let status = match user.availability_status {
                AvailabilityStatus::Away => "away",
                AvailabilityStatus::Brb => "brb",
                AvailabilityStatus::Dnd => "dnd",
                AvailabilityStatus::Online => "online",
            };
            crate::utils::user::online::put(user_id, status);
            Some(status)
        }
        Ok(None) => None,
        Err(_) => None,
    }
}

async fn broadcast_user_status(user_id: &str, status: Value) {
    crate::utils::friends::emit_status_event(
        &get_db(),
        user_id,
        json!({ "userId": user_id, "status": status }),
    )
    .await;
}

fn emit_mention(
    target_user_id: &str,
    scope: &str,
    source_id: &str,
    source_name: Option<&str>,
    message_id: &str,
    from_user: &Value,
    content: &str,
) {
    let preview = content.trim();
    let preview = if preview.chars().count() > 140 {
        format!("{}…", preview.chars().take(140).collect::<String>())
    } else {
        preview.to_string()
    };
    registry::emit_to_user(
        target_user_id,
        "message-mention",
        json!({
            "scope": scope,
            "sourceId": source_id,
            "sourceName": source_name,
            "messageId": message_id,
            "from": from_user,
            "preview": preview,
        }),
    );
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendMessagePayload {
    sender: String,
    recipient: String,
    content: Option<String>,
    message_type: Option<String>,
    file_url: Option<String>,
    file_type: Option<String>,
    file_size: Option<u64>,
    file_name: Option<String>,
    duration_ms: Option<u32>,
    quoted_message: Option<String>,
    client_nonce: Option<String>,
}

async fn handle_send_message(connected: &str, payload: SendMessagePayload) {
    let db = get_db();
    if !is_connected_user(connected, &payload.sender) || payload.recipient.is_empty() {
        return;
    }
    let (friends, blocks) = tokio::join!(
        crate::utils::friends::try_are_friends(&db, &payload.sender, &payload.recipient),
        crate::utils::friends::try_dm_block_flags(&db, &payload.sender, &payload.recipient),
    );
    match friends {
        Ok(true) => {}
        Ok(false) => {
            registry::emit_to_user(
                &payload.sender,
                "dm-error",
                json!({
                    "code": "NOT_FRIENDS",
                    "message": "Możesz pisać tylko do znajomych. Wyślij zaproszenie, aby dodać kontakt.",
                    "clientNonce": payload.client_nonce,
                }),
            );
            return;
        }
        Err(()) => {
            emit_send_error(
                connected,
                "SEND_FAILED",
                "Nie udało się wysłać wiadomości. Spróbuj ponownie.",
                payload.client_nonce.as_deref(),
            );
            return;
        }
    }
    let (blocked_by_me, blocked_by_other) = match blocks {
        Ok(flags) => flags,
        Err(()) => {
            emit_send_error(
                connected,
                "SEND_FAILED",
                "Nie udało się wysłać wiadomości. Spróbuj ponownie.",
                payload.client_nonce.as_deref(),
            );
            return;
        }
    };
    if blocked_by_me || blocked_by_other {
        registry::emit_to_user(
            &payload.sender,
            "dm-error",
            json!({
                "code": "USER_BLOCKED",
                "message": "Nie możesz wysłać wiadomości — użytkownik jest zablokowany lub zablokował Cię.",
                "clientNonce": payload.client_nonce,
                "blockedByMe": blocked_by_me,
                "blockedByOther": blocked_by_other,
            }),
        );
        return;
    }
    let file_url = match validate_message_attachment(
        &db,
        &payload.sender,
        &payload.file_url,
        payload.file_size,
        Some(AttachmentSendContext::Dm {
            recipient_id: payload.recipient.clone(),
        }),
    )
    .await
    {
        Ok(url) => url,
        Err(()) => {
        log::warn!(
            "sendMessage rejected INVALID_FILE sender={} file={:?}",
            payload.sender,
            payload.file_url
        );
        registry::emit_to_user(
            &payload.sender,
            "dm-error",
            json!({
                "code": "INVALID_FILE",
                "message": "Nie można dołączyć tego pliku do wiadomości.",
                "clientNonce": payload.client_nonce,
            }),
        );
        return;
        }
    };

    let quoted = if let Some(ref q) = payload.quoted_message {
        match validate_quote_target_with_access(
            &db,
            &payload.sender,
            q,
            QuoteContext::Dm {
                contact_id: payload.recipient.clone(),
            },
            true,
        )
        .await
        {
            Ok(m) => m.and_then(|m| m.id),
            Err(()) => {
                emit_send_error(
                    connected,
                    "SEND_FAILED",
                    "Nie udało się wysłać wiadomości. Spróbuj ponownie.",
                    payload.client_nonce.as_deref(),
                );
                return;
            }
        }
    } else {
        None
    };

    let (Ok(sender), Ok(recipient)) = (
        ObjectId::parse_str(&payload.sender),
        ObjectId::parse_str(&payload.recipient),
    ) else {
        return;
    };

    let msg_type = parse_message_type(payload.message_type.as_deref().unwrap_or("TEXT"));
    let content = crate::utils::validators::sanitize::sanitize_message_content(
        payload.content.as_deref().unwrap_or(""),
    );
    let content = inbound_plaintext_for_processing(&content, false);
    let mention_plain = content.clone();

    let mentions = match resolve_mentions(
        &db,
        &content,
        &[payload.sender.clone(), payload.recipient.clone()],
    )
    .await
    {
        Ok(m) => m,
        Err(()) => {
            emit_send_error(
                connected,
                "SEND_FAILED",
                "Failed to send message.",
                payload.client_nonce.as_deref(),
            );
            return;
        }
    };

    let scan_status = scan_status_for_attachment(&db, &payload.sender, &file_url).await;
    let input = CreateMessageInput {
        sender,
        recipient: Some(recipient),
        channel: None,
        content,
        message_type: Some(msg_type),
        file_url: file_url.clone(),
        file_type: payload.file_type,
        file_size: payload.file_size,
        file_name: payload.file_name,
        scan_status,
        duration_ms: payload.duration_ms,
        quoted_message: quoted,
        mentions: Some(mentions.clone()),
        mentions_everyone: Some(false),
        client_nonce: payload.client_nonce.clone(),
        read: None,
    };

    let unread_gen = peek_unread_generation(&payload.recipient, "dm", &payload.sender);

    let (created, is_replay) = match Message::create(&db, input).await {
        Ok(CreateMessageOutcome::Created(m)) => (m, false),
        Ok(CreateMessageOutcome::IdempotentReplay(m)) => (m, true),
        Err(CreateMessageError::NonceConflict) => {
            emit_send_error(
                connected,
                "NONCE_CONFLICT",
                "Message nonce conflict. Retry with a new nonce.",
                payload.client_nonce.as_deref(),
            );
            return;
        }
        Err(e) => {
            log::error!("sendMessage create error: {}", e);
            emit_send_error(
                connected,
                "SEND_FAILED",
                "Failed to send message.",
                payload.client_nonce.as_deref(),
            );
            return;
        }
    };

    claim_pending_upload(&payload.sender, &file_url).await;

    if created.scan_status == ScanStatus::Pending {
        if let Some(path) = created.file_url.clone() {
            enqueue(ScanJob {
                file_path: path,
                file_hash: String::new(),
                content_type: created.file_type.clone().unwrap_or_default(),
                attempts: 0,
            });
        }
    }

    let created = created.refreshed(&db).await;

    if is_replay {
        let populated = serialize_message(&db, &created).await;
        registry::emit_to_user(&payload.recipient, "receiveMessage", populated.clone());
        registry::emit_to_user(&payload.sender, "receiveMessage", populated);
        let db_tip = db.clone();
        let tip_msg = created.clone();
        let sender_oid = sender;
        let recipient_oid = recipient;
        let recipient_id = payload.recipient.clone();
        let sender_id = payload.sender.clone();
        let bump = payload.sender != payload.recipient;
        tokio::spawn(async move {
            crate::utils::tips::upsert_dm_tip(&db_tip, &tip_msg).await;
            if bump {
                if let Some(n) = crate::utils::tips::try_sync_dm_tip_unread(
                    &db_tip, recipient_oid, sender_oid,
                )
                .await
                {
                    emit_unread_absolute(&recipient_id, "dm", &sender_id, n);
                }
            }
        });
        return;
    }

    let (populated, muted_lookup) = tokio::join!(
        serialize_message(&db, &created),
        async {
            use mongodb::bson::Document;
            let coll = db.collection::<Document>("users");
            match coll
                .find_one(doc! { "_id": recipient })
                .projection(doc! { "mutedContacts": 1 })
                .await
            {
                Ok(Some(doc)) => Ok(doc
                    .get_array("mutedContacts")
                    .ok()
                    .map(|arr| {
                        arr.iter().any(|b| {
                            b.as_object_id()
                                .map(|id| id == sender)
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)),
                Ok(None) => Err(()),
                Err(_) => Err(()),
            }
        },
    );
    let muted_lookup_ok = muted_lookup.is_ok();
    let recipient_muted = muted_lookup.unwrap_or(true);

    registry::emit_to_user(&payload.recipient, "receiveMessage", populated.clone());
    registry::emit_to_user(&payload.sender, "receiveMessage", populated.clone());

    {
        let db_tip = db.clone();
        let tip_msg = created.clone();
        let tip_mid = tip_msg.id;
        let sender_oid = sender;
        let recipient_oid = recipient;
        let bump = payload.sender != payload.recipient;
        let unread_gen_tip = unread_gen;
        let recipient_id_tip = payload.recipient.clone();
        let sender_id_tip = payload.sender.clone();
        let message_id = created.id.map(|o| o.to_hex()).unwrap_or_default();
        let sender_json = populated.get("sender").cloned().unwrap_or(Value::Null);
        let content_for_mention = mention_plain;
        let mention_recipient = mentions.iter().any(|m| m.to_hex() == payload.recipient);
        let notify = muted_lookup_ok && !recipient_muted && bump;
        tokio::spawn(async move {
            crate::utils::tips::upsert_dm_tip(&db_tip, &tip_msg).await;
            if bump {

                let still_active = match tip_mid {
                    Some(id) => message_still_active(&db_tip, id).await,
                    None => Some(false),
                };
                if still_active == Some(false) {
                    if let Some(n) = crate::utils::tips::try_sync_dm_tip_unread(
                        &db_tip, recipient_oid, sender_oid,
                    )
                    .await
                    {
                        crate::utils::unread::emit_unread_absolute(
                            &recipient_id_tip,
                            "dm",
                            &sender_id_tip,
                            n,
                        );
                    }
                } else if peek_unread_generation(&recipient_id_tip, "dm", &sender_id_tip)
                    == unread_gen_tip
                {
                    let bumped = crate::utils::tips::bump_dm_unread(
                        &db_tip,
                        sender_oid,
                        recipient_oid,
                    )
                    .await;
                    let still_active = match tip_mid {
                        Some(id) => message_still_active(&db_tip, id).await,
                        None => Some(false),
                    };
                    if bumped
                        && still_active != Some(false)
                        && peek_unread_generation(&recipient_id_tip, "dm", &sender_id_tip)
                            == unread_gen_tip
                    {
                        emit_unread_delta_at(
                            &recipient_id_tip,
                            "dm",
                            &sender_id_tip,
                            1,
                            unread_gen_tip,
                        );
                    } else if let Some(n) = crate::utils::tips::try_sync_dm_tip_unread(
                        &db_tip, recipient_oid, sender_oid,
                    )
                    .await
                    {
                        crate::utils::unread::emit_unread_absolute(
                            &recipient_id_tip,
                            "dm",
                            &sender_id_tip,
                            n,
                        );
                    }
                } else if let Some(n) = crate::utils::tips::try_sync_dm_tip_unread(
                    &db_tip, recipient_oid, sender_oid,
                )
                .await
                {
                    crate::utils::unread::emit_unread_absolute(
                        &recipient_id_tip,
                        "dm",
                        &sender_id_tip,
                        n,
                    );
                }
            }
            if notify && mention_recipient {
                emit_mention(
                    &recipient_id_tip,
                    "dm",
                    &sender_id_tip,
                    None,
                    &message_id,
                    &sender_json,
                    content_for_mention.as_str(),
                );
            }
        });
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChannelMessagePayload {
    channel_id: String,
    sender: String,
    content: Option<String>,
    message_type: Option<String>,
    file_url: Option<String>,
    file_type: Option<String>,
    file_size: Option<u64>,
    file_name: Option<String>,
    duration_ms: Option<u32>,
    quoted_message: Option<String>,
    client_nonce: Option<String>,
}

async fn handle_send_channel_message(connected: &str, payload: ChannelMessagePayload) {
    let db = get_db();
    if !is_connected_user(connected, &payload.sender) || payload.channel_id.is_empty() {
        return;
    }

    let channel = match require_channel_message_access(&db, &payload.channel_id, &payload.sender).await
    {
        Ok(channel) => channel,
        Err(reason) => {
            emit_send_error(
                connected,
                "FORBIDDEN",
                reason.as_str(),
                payload.client_nonce.as_deref(),
            );
            return;
        }
    };

    let bypass = channel_admin_bypasses_slowmode(&channel, &payload.sender);
    if crate::utils::channel::is_channel_chat_locked_for_sender(&channel, &payload.sender) {
        emit_send_error(
            connected,
            "CHAT_LOCKED",
            "Czat na tym kanale jest zablokowany.",
            payload.client_nonce.as_deref(),
        );
        return;
    }
    if let Err(retry_after) = check_channel_slowmode(
        &payload.sender,
        &payload.channel_id,
        channel.rate_limit_per_user,
        bypass,
    )
    .await
    {
        let mut body = json!({
            "message": "Slowmode is enabled for this channel.",
            "code": "SLOWMODE",
            "retryAfter": retry_after,
        });
        if let Some(nonce) = payload
            .client_nonce
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 64)
        {
            if let Some(obj) = body.as_object_mut() {
                obj.insert("clientNonce".into(), json!(nonce));
            }
        }
        registry::emit_to_user(connected, "error", body);
        return;
    }

    let file_url = match validate_message_attachment(
        &db,
        &payload.sender,
        &payload.file_url,
        payload.file_size,
        Some(AttachmentSendContext::Channel {
            channel_id: payload.channel_id.clone(),
        }),
    )
    .await
    {
        Ok(url) => url,
        Err(()) => {
        log::warn!(
            "channel message rejected INVALID_FILE sender={} file={:?}",
            payload.sender,
            payload.file_url
        );
        emit_send_error(
            connected,
            "INVALID_FILE",
            "Nie udało się wysłać załącznika. Spróbuj ponownie.",
            payload.client_nonce.as_deref(),
        );
        return;
        }
    };

    let Ok(channel_oid) = ObjectId::parse_str(&payload.channel_id) else {
        return;
    };

    let quoted = if let Some(ref q) = payload.quoted_message {
        match validate_quote_target_with_access(
            &db,
            &payload.sender,
            q,
            QuoteContext::Channel {
                channel_id: payload.channel_id.clone(),
            },
            true,
        )
        .await
        {
            Ok(m) => m.and_then(|m| m.id),
            Err(()) => {
                emit_send_error(
                    connected,
                    "SEND_FAILED",
                    "Nie udało się wysłać wiadomości. Spróbuj ponownie.",
                    payload.client_nonce.as_deref(),
                );
                return;
            }
        }
    } else {
        None
    };

    let Ok(sender) = ObjectId::parse_str(&payload.sender) else {
        return;
    };

    let client_nonce = payload.client_nonce.clone();
    let rate_limit = channel.rate_limit_per_user;
    let bypass_sm = bypass;
    match create_and_broadcast_channel_message(
        &db,
        ChannelBroadcastInput {
            channel,
            channel_oid,
            sender,
            content: payload.content.clone().unwrap_or_default(),
            message_type: parse_message_type(payload.message_type.as_deref().unwrap_or("TEXT")),
            file_url,
            file_type: payload.file_type,
            file_size: payload.file_size,
            file_name: payload.file_name,
            duration_ms: payload.duration_ms,
            quoted_message: quoted,
            client_nonce: payload.client_nonce,
        },
    )
    .await
    {
        Ok(ChannelBroadcastOutcome::Created(_)) => {
            record_channel_slowmode(
                &payload.sender,
                &payload.channel_id,
                rate_limit,
                bypass_sm,
            );
        }
        Ok(ChannelBroadcastOutcome::IdempotentReplay(_)) => {}
        Err(CreateMessageError::NonceConflict) => {
            emit_send_error(
                connected,
                "NONCE_CONFLICT",
                "Message nonce conflict. Retry with a new nonce.",
                client_nonce.as_deref(),
            );
        }
        Err(_) => {
            emit_send_error(
                connected,
                "SEND_FAILED",
                "Failed to send message.",
                client_nonce.as_deref(),
            );
        }
    }
}

pub struct ChannelBroadcastInput {
    pub channel: Channel,
    pub channel_oid: ObjectId,
    pub sender: ObjectId,

    pub content: String,
    pub message_type: MessageType,
    pub file_url: Option<String>,
    pub file_type: Option<String>,
    pub file_size: Option<u64>,
    pub file_name: Option<String>,
    pub duration_ms: Option<u32>,
    pub quoted_message: Option<ObjectId>,
    pub client_nonce: Option<String>,
}

pub enum ChannelBroadcastOutcome {
    Created(Value),
    IdempotentReplay(Value),
}

pub async fn create_and_broadcast_channel_message(
    db: &Database,
    input: ChannelBroadcastInput,
) -> Result<ChannelBroadcastOutcome, CreateMessageError> {
    let ChannelBroadcastInput {
        channel,
        channel_oid,
        sender,
        content,
        message_type,
        file_url,
        file_type,
        file_size,
        file_name,
        duration_ms,
        quoted_message,
        client_nonce,
    } = input;

    let channel_id_str = channel_oid.to_hex();
    let sender_hex = sender.to_hex();

    let mut member_ids: Vec<String> = channel.members.iter().map(|m| m.to_hex()).collect();
    member_ids.push(channel.admin.to_hex());

    let sanitized = crate::utils::validators::sanitize::sanitize_message_content(&content);
    let prepared_content = inbound_plaintext_for_processing(&sanitized, false);
    let mention_plain = prepared_content.clone();

    let mentions = match resolve_mentions(db, &prepared_content, &member_ids).await {
        Ok(m) => m,
        Err(()) => {
            return Err(CreateMessageError::Other(
                "failed to resolve mentions".into(),
            ));
        }
    };
    let mentions_everyone = has_everyone_mention(&prepared_content);

    let scan_status = scan_status_for_attachment(db, &sender_hex, &file_url).await;
    let create_input = CreateMessageInput {
        sender,
        recipient: None,
        channel: Some(channel_oid),
        content: prepared_content,
        message_type: Some(message_type),
        file_url,
        file_type,
        file_size,
        file_name,
        scan_status,
        duration_ms,
        quoted_message,
        mentions: Some(mentions.clone()),
        mentions_everyone: Some(mentions_everyone),
        client_nonce: client_nonce.clone(),
        read: None,
    };

    let unread_gens: std::collections::HashMap<String, u64> = member_ids
        .iter()
        .filter(|id| **id != sender_hex)
        .map(|id| {
            (
                id.clone(),
                peek_unread_generation(id, "channel", &channel_id_str),
            )
        })
        .collect();

    let (created, is_replay) = match Message::create(db, create_input).await {
        Ok(CreateMessageOutcome::Created(m)) => (m, false),
        Ok(CreateMessageOutcome::IdempotentReplay(m)) => (m, true),
        Err(e) => {
            log::error!("create_and_broadcast_channel_message error: {}", e);
            return Err(e);
        }
    };

    claim_pending_upload(&sender_hex, &created.file_url).await;

    if created.scan_status == ScanStatus::Pending {
        if let Some(path) = created.file_url.clone() {
            enqueue(ScanJob {
                file_path: path,
                file_hash: String::new(),
                content_type: created.file_type.clone().unwrap_or_default(),
                attempts: 0,
            });
        }
    }

    let created = created.refreshed(db).await;

    let mut member_oids = channel.members.clone();
    if !member_oids.iter().any(|id| *id == channel.admin) {
        member_oids.push(channel.admin);
    }

    let mut notified = std::collections::HashSet::new();
    let mut recipients: Vec<String> = Vec::new();
    let mut unread_targets: Vec<String> = Vec::new();
    for member_id in &member_ids {
        if !notified.insert(member_id.clone()) {
            continue;
        }
        recipients.push(member_id.clone());
        if member_id != &sender_hex {
            unread_targets.push(member_id.clone());
        }
    }

    if is_replay {
        let mut populated = serialize_message(db, &created).await;
        if let Some(obj) = populated.as_object_mut() {
            obj.insert("channelId".into(), json!(channel_id_str));
        }
        registry::emit_to_users(&recipients, "receive-channel-message", populated.clone());
        let db_tip = db.clone();
        let tip_msg = created.clone();
        let channel_id_heal = channel_id_str.clone();
        let unread_targets_heal = unread_targets.clone();
        tokio::spawn(async move {
            crate::utils::tips::upsert_channel_tip(
                &db_tip, channel_oid, &tip_msg,
            )
            .await;
            let futs: Vec<_> = unread_targets_heal
                .into_iter()
                .filter_map(|mid| ObjectId::parse_str(&mid).ok().map(|oid| (mid, oid)))
                .map(|(mid, oid)| {
                    let db = db_tip.clone();
                    let channel_id_heal = channel_id_heal.clone();
                    async move {
                        if let Some(n) =
                            crate::utils::unread::try_sync_channel_unread(&db, oid, channel_oid)
                                .await
                        {
                            emit_unread_absolute(&mid, "channel", &channel_id_heal, n);
                        }
                    }
                })
                .collect();
            futures_util::future::join_all(futs).await;
        });
        return Ok(ChannelBroadcastOutcome::IdempotentReplay(populated));
    }

    let (mut populated, muted_lookup) = tokio::join!(
        serialize_message(db, &created),
        async {
            use mongodb::bson::Document;
            let coll = db.collection::<Document>("users");
            match coll
                .find(doc! {
                    "_id": { "$in": &member_oids },
                    "mutedChannels": channel_oid,
                })
                .projection(doc! { "_id": 1 })
                .await
            {
                Ok(cursor) => match cursor.try_collect::<Vec<Document>>().await {
                    Ok(docs) => Ok(docs
                        .into_iter()
                        .filter_map(|d| d.get_object_id("_id").ok().map(|id| id.to_hex()))
                        .collect::<std::collections::HashSet<String>>()),
                    Err(_) => Err(()),
                },
                Err(_) => Err(()),
            }
        }
    );
    let muted_lookup_ok = muted_lookup.is_ok();
    let muted_ids = muted_lookup.unwrap_or_default();

    if let Some(obj) = populated.as_object_mut() {
        obj.insert("channelId".into(), json!(channel_id_str));
    }

    let mentioned: std::collections::HashSet<String> =
        mentions.iter().map(|m| m.to_hex()).collect();

    registry::emit_to_users(&recipients, "receive-channel-message", populated.clone());

    let channel_id_for_unread = channel_id_str.clone();
    let channel_name = channel.name.clone();
    let message_id = created.id.map(|o| o.to_hex()).unwrap_or_default();
    let message_ts = created.timestamp;
    let sender_json = populated.get("sender").cloned().unwrap_or(Value::Null);
    let content_for_mention = mention_plain;
    let tip_msg = created.clone();
    tokio::spawn(async move {
        let db = get_db();
        crate::utils::tips::upsert_channel_tip(&db, channel_oid, &tip_msg).await;
        use crate::model::read_state::ChannelReadState;
        let msg_oid = ObjectId::parse_str(&message_id).ok();
        let still_active = match msg_oid {
            Some(id) => message_still_active(&db, id).await,
            None => Some(false),
        };
        if still_active == Some(false) {

            let futs: Vec<_> = unread_targets
                .iter()
                .filter_map(|member_id| ObjectId::parse_str(member_id).ok().map(|oid| (member_id.clone(), oid)))
                .map(|(member_id, oid)| {
                    let db = db.clone();
                    let channel_id_for_unread = channel_id_for_unread.clone();
                    async move {
                        if let Some(n) =
                            crate::utils::unread::try_sync_channel_unread(&db, oid, channel_oid)
                                .await
                        {
                            emit_unread_absolute(
                                &member_id,
                                "channel",
                                &channel_id_for_unread,
                                n,
                            );
                        }
                    }
                })
                .collect();
            futures_util::future::join_all(futs).await;
            return;
        }
        let mut bump_oids: Vec<ObjectId> = Vec::new();
        let mut mismatch: Vec<(String, ObjectId)> = Vec::new();
        for member_id in &unread_targets {
            let gen = unread_gens.get(member_id).copied().unwrap_or(0);
            if peek_unread_generation(member_id, "channel", &channel_id_for_unread) != gen {
                if let Ok(oid) = ObjectId::parse_str(member_id) {
                    mismatch.push((member_id.clone(), oid));
                }
            } else if let Ok(oid) = ObjectId::parse_str(member_id) {

                bump_oids.push(oid);
            }
            let muted = muted_ids.contains(member_id);
            if muted_lookup_ok && !muted && (mentioned.contains(member_id) || mentions_everyone) {
                emit_mention(
                    member_id,
                    "channel",
                    &channel_id_for_unread,
                    Some(&channel_name),
                    &message_id,
                    &sender_json,
                    &content_for_mention,
                );
            }
        }
        if !mismatch.is_empty() {
            let recount_futs: Vec<_> = mismatch
                .iter()
                .map(|(member_id, oid)| {
                    let db = db.clone();
                    let member_id = member_id.clone();
                    let oid = *oid;
                    async move {
                        let n = crate::utils::unread::try_sync_channel_unread(
                            &db, oid, channel_oid,
                        )
                        .await;
                        (member_id, n)
                    }
                })
                .collect();
            for (member_id, n) in futures_util::future::join_all(recount_futs).await {
                if let Some(n) = n {
                    emit_unread_absolute(&member_id, "channel", &channel_id_for_unread, n);
                }
            }
        }
        if !bump_oids.is_empty() {

            let mut still_ok = Vec::new();
            let mut late_mismatch: Vec<ObjectId> = Vec::new();
            for oid in bump_oids {
                let mid = oid.to_hex();
                let gen = unread_gens.get(&mid).copied().unwrap_or(0);
                if peek_unread_generation(&mid, "channel", &channel_id_for_unread) == gen {
                    still_ok.push(oid);
                } else {
                    late_mismatch.push(oid);
                }
            }
            if !late_mismatch.is_empty() {
                let futs: Vec<_> = late_mismatch
                    .into_iter()
                    .map(|oid| {
                        let db = db.clone();
                        async move {
                            let n = crate::utils::unread::try_sync_channel_unread(
                                &db, oid, channel_oid,
                            )
                            .await;
                            (oid, n)
                        }
                    })
                    .collect();
                for (oid, n) in futures_util::future::join_all(futs).await {
                    if let Some(n) = n {
                        let mid = oid.to_hex();
                        emit_unread_absolute(&mid, "channel", &channel_id_for_unread, n);
                    }
                }
            }
            if !still_ok.is_empty() {
                let msg_oid = ObjectId::parse_str(&message_id).ok();
                let still_active = match msg_oid {
                    Some(id) => message_still_active(&db, id).await,
                    None => Some(false),
                };
                if still_active == Some(false) {
                    let futs: Vec<_> = still_ok
                        .into_iter()
                        .map(|oid| {
                            let db = db.clone();
                            async move {
                                let n = crate::utils::unread::try_sync_channel_unread(
                                    &db, oid, channel_oid,
                                )
                                .await;
                                (oid, n)
                            }
                        })
                        .collect();
                    for (oid, n) in futures_util::future::join_all(futs).await {
                        if let Some(n) = n {
                            let mid = oid.to_hex();
                            emit_unread_absolute(&mid, "channel", &channel_id_for_unread, n);
                        }
                    }
                } else {
                let failed = ChannelReadState::bump_unread_many(
                    &db,
                    &still_ok,
                    channel_oid,
                    message_ts,
                )
                .await;

                let still_active = match msg_oid {
                    Some(id) => message_still_active(&db, id).await,
                    None => Some(false),
                };
                let mut post_mismatch: Vec<ObjectId> = failed;
                let mut bumped_ok: Vec<ObjectId> = Vec::new();
                for oid in &still_ok {
                    if post_mismatch.contains(oid) {
                        continue;
                    }
                    let mid = oid.to_hex();
                    let gen = unread_gens.get(&mid).copied().unwrap_or(0);
                    if still_active == Some(false)
                        || peek_unread_generation(&mid, "channel", &channel_id_for_unread) != gen
                    {
                        post_mismatch.push(*oid);
                    } else {
                        bumped_ok.push(*oid);
                    }
                }

                for oid in &bumped_ok {
                    let mid = oid.to_hex();
                    let gen = unread_gens.get(&mid).copied().unwrap_or(0);
                    emit_unread_delta_at(&mid, "channel", &channel_id_for_unread, 1, gen);
                }
                if !post_mismatch.is_empty() {
                    let futs: Vec<_> = post_mismatch
                        .into_iter()
                        .map(|oid| {
                            let db = db.clone();
                            async move {
                                let n = crate::utils::unread::try_sync_channel_unread(
                                    &db, oid, channel_oid,
                                )
                                .await;
                                (oid, n)
                            }
                        })
                        .collect();
                    let mut still_none: Vec<ObjectId> = Vec::new();
                    for (oid, n) in futures_util::future::join_all(futs).await {
                        if let Some(n) = n {
                            let mid = oid.to_hex();
                            emit_unread_absolute(&mid, "channel", &channel_id_for_unread, n);
                        } else {
                            still_none.push(oid);
                        }
                    }

                    if !still_none.is_empty() {
                        let db_retry = db.clone();
                        let channel_id_retry = channel_id_for_unread.clone();
                        tokio::spawn(async move {
                            for oid in still_none {
                                for _ in 0..3 {
                                    if let Some(n) = crate::utils::unread::try_sync_channel_unread(
                                        &db_retry, oid, channel_oid,
                                    )
                                    .await
                                    {
                                        let mid = oid.to_hex();
                                        emit_unread_absolute(
                                            &mid,
                                            "channel",
                                            &channel_id_retry,
                                            n,
                                        );
                                        break;
                                    }
                                }
                            }
                        });
                    }
                }
                }
            }
        }
    });

    Ok(ChannelBroadcastOutcome::Created(populated))
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TypingPayload {
    chat_id: Option<String>,
    is_typing: Option<bool>,
}

async fn handle_typing(state: SocketState, connected: &str, payload: TypingPayload) {
    let Some(chat_id) = payload.chat_id.filter(|s| !s.is_empty()) else {
        return;
    };
    let user_id = connected;
    let is_typing = payload.is_typing.unwrap_or(false);

    let cached = typing::get(user_id, &chat_id);
    let channel_recipients: Option<Vec<String>> = match cached {
        Some(TypingAccess::Denied { .. }) => return,
        Some(TypingAccess::Dm { .. }) => None,
        Some(TypingAccess::Channel { recipients, .. }) => Some(recipients),
        None => {
            if chat_id.starts_with("channel_") {
                let channel_id = chat_id.trim_start_matches("channel_");
                match require_channel_message_access(&get_db(), channel_id, user_id).await {
                    Ok(channel) => {
                        let recipients = registry::channel_recipient_ids(&channel);
                        typing::put(
                            user_id,
                            &chat_id,
                            TypingAccess::Channel {
                                checked_at_ms: typing::now_access_ms(),
                                recipients: recipients.clone(),
                            },
                        );
                        Some(recipients)
                    }
                    Err(AccessDeniedReason::Unavailable) => {

                        if !is_typing {
                            state.touch_typing(&chat_id, user_id, false);
                            let db = get_db();
                            if let Ok(oid) = ObjectId::parse_str(channel_id) {
                                if let Ok(Some(channel)) = Channel::find_by_id(&db, oid).await {
                                    let others: Vec<String> = registry::channel_recipient_ids(&channel)
                                        .into_iter()
                                        .filter(|r| r != user_id)
                                        .collect();
                                    registry::emit_to_users(
                                        &others,
                                        "typing",
                                        json!({ "chatId": chat_id, "userId": user_id, "isTyping": false }),
                                    );
                                }
                            }
                        }
                        return;
                    }
                    Err(_) => {
                        typing::put(
                            user_id,
                            &chat_id,
                            TypingAccess::Denied {
                                checked_at_ms: typing::now_access_ms(),
                            },
                        );
                        return;
                    }
                }
            } else {
                match require_dm_access(&get_db(), user_id, &chat_id).await {
                    Ok(()) => {
                        typing::put(
                            user_id,
                            &chat_id,
                            TypingAccess::Dm {
                                checked_at_ms: typing::now_access_ms(),
                            },
                        );
                        None
                    }
                    Err(AccessDeniedReason::Unavailable) => {

                        if !is_typing {
                            state.touch_typing(&chat_id, user_id, false);
                            registry::emit_to_user(
                                &chat_id,
                                "typing",
                                json!({ "chatId": chat_id, "userId": user_id, "isTyping": false }),
                            );
                        }
                        return;
                    }
                    Err(_) => {
                        typing::put(
                            user_id,
                            &chat_id,
                            TypingAccess::Denied {
                                checked_at_ms: typing::now_access_ms(),
                            },
                        );
                        return;
                    }
                }
            }
        }
    };

    state.touch_typing(&chat_id, user_id, is_typing);

    let event = json!({ "chatId": chat_id, "userId": user_id, "isTyping": is_typing });

    if let Some(recipients) = channel_recipients {
        let others: Vec<String> = recipients
            .into_iter()
            .filter(|r| r != user_id)
            .collect();
        registry::emit_to_users(&others, "typing", event);
    } else {
        registry::emit_to_user(&chat_id, "typing", event);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReactionPayload {
    message_id: Option<String>,
    emoji: Option<String>,
}

async fn handle_reaction(connected: &str, payload: ReactionPayload) {
    let Some(message_id) = payload.message_id else { return };
    let Some(emoji) = payload.emoji else { return };
    let user_id = connected.to_string();
    let emoji = emoji.trim().to_string();
    if emoji.is_empty() || emoji.len() > 32 {
        return;
    }

    if emoji.contains('.') || emoji.contains('$') {
        return;
    }
    let Ok(mid) = ObjectId::parse_str(&message_id) else { return };
    let Ok(uid) = ObjectId::parse_str(&user_id) else { return };
    let db = get_db();
    let msg = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) => m,
        Ok(None) => return,
        Err(_) => match Message::find_by_id(&db, mid).await {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(_) => {
                registry::emit_to_user(
                    &user_id,
                    "error",
                    json!({
                        "code": "REACTION_SYNC_FAILED",
                        "message": "Nie udało się zaktualizować reakcji. Spróbuj ponownie.",
                        "retryable": true,
                    }),
                );
                return;
            }
        },
    };
    if let Err(reason) = require_message_participant(&db, &user_id, &msg).await {
        if reason == AccessDeniedReason::Unavailable {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "REACTION_SYNC_FAILED",
                    "message": "Nie udało się zaktualizować reakcji. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }

        let payload_json = json!({
            "messageId": message_id,
            "reactions": reactions_json(&msg),
            "channelId": msg.channel.map(|c| c.to_hex()),
        });
        registry::emit_to_user(&user_id, "message-reaction", payload_json);
        return;
    }

    let users_path = format!("reactions.{emoji}.users");
    let emoji_path = format!("reactions.{emoji}.emoji");
    let now = DateTime::now();
    let pull = Message::collection(&db)
        .update_one(
            doc! { "_id": mid, &users_path: uid },
            doc! {
                "$pull": { &users_path: uid },
                "$set": { "updatedAt": now },
            },
        )
        .await;
    let pulled = match pull {
        Ok(r) => r.modified_count > 0,
        Err(_) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "REACTION_SYNC_FAILED",
                    "message": "Nie udało się zaktualizować reakcji. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    };
    if pulled {
        let _ = Message::collection(&db)
            .update_one(
                doc! { "_id": mid, &users_path: { "$size": 0 } },
                doc! { "$unset": { format!("reactions.{emoji}"): "" } },
            )
            .await;
    } else {
        match Message::collection(&db)
            .update_one(
                doc! { "_id": mid, &users_path: { "$ne": uid } },
                doc! {
                    "$addToSet": { &users_path: uid },
                    "$set": { &emoji_path: &emoji, "updatedAt": now },
                },
            )
            .await
        {
            Ok(_) => {}
            Err(_) => {
                registry::emit_to_user(
                    &user_id,
                    "error",
                    json!({
                        "code": "REACTION_SYNC_FAILED",
                        "message": "Nie udało się zaktualizować reakcji. Spróbuj ponownie.",
                        "retryable": true,
                    }),
                );
                return;
            }
        }
    }

    let fresh = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) => m,
        Ok(None) | Err(_) => match Message::find_by_id(&db, mid).await {
            Ok(Some(m)) => m,
            _ => {

                let payload_json = json!({
                    "messageId": message_id,
                    "reactions": reactions_json(&msg),
                    "channelId": msg.channel.map(|c| c.to_hex()),
                    "degraded": true,
                });
                if let Some(channel_id) = msg.channel {
                    if let Ok(Some(channel)) = Channel::find_by_id(&db, channel_id).await {
                        let recipients = registry::channel_recipient_ids(&channel);
                        registry::emit_to_users(&recipients, "message-reaction", payload_json);
                    } else if let Some(recipient) = msg.recipient {
                        registry::emit_to_user(&msg.sender.to_hex(), "message-reaction", payload_json.clone());
                        registry::emit_to_user(&recipient.to_hex(), "message-reaction", payload_json);
                    } else {
                        registry::emit_to_user(&user_id, "message-reaction", payload_json);
                    }
                } else if let Some(recipient) = msg.recipient {
                    registry::emit_to_user(&msg.sender.to_hex(), "message-reaction", payload_json.clone());
                    registry::emit_to_user(&recipient.to_hex(), "message-reaction", payload_json);
                }
                registry::emit_to_user(
                    &user_id,
                    "error",
                    json!({
                        "code": "REACTION_SYNC_DEGRADED",
                        "message": "Reakcja zapisana — odśwież czat, jeśli lista się nie zgadza.",
                        "retryable": true,
                        "messageId": message_id,
                    }),
                );
                return;
            }
        },
    };

    let payload_json = json!({
        "messageId": message_id,
        "reactions": reactions_json(&fresh),
        "channelId": fresh.channel.map(|c| c.to_hex()),
    });

    if let Some(channel_id) = fresh.channel {
        let channel = match Channel::find_by_id(&db, channel_id).await {
            Ok(Some(ch)) => Some(ch),

            Ok(None) | Err(_) => None,
        };
        if let Some(channel) = channel {
            let recipients = registry::channel_recipient_ids(&channel);
            registry::emit_to_users(&recipients, "message-reaction", payload_json);
        } else {
            use crate::model::read_state::ChannelReadState;
            let mut recipients = vec![user_id.clone()];
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
            registry::emit_to_users(&recipients, "message-reaction", payload_json);
        }
    } else if let Some(recipient) = fresh.recipient {
        registry::emit_to_user(&fresh.sender.to_hex(), "message-reaction", payload_json.clone());
        registry::emit_to_user(&recipient.to_hex(), "message-reaction", payload_json);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarkMessageReadPayload {
    message_id: Option<String>,
    user_id: Option<String>,
}

async fn handle_mark_message_read(connected: &str, payload: MarkMessageReadPayload) {
    let Some(message_id) = payload.message_id else { return };
    let Some(user_id) = payload.user_id else { return };
    if !is_connected_user(connected, &user_id) {
        return;
    }
    let Ok(mid) = ObjectId::parse_str(&message_id) else { return };
    let db = get_db();
    let msg = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) => m,
        Ok(None) => return,
        Err(_) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "MARK_READ_FAILED",
                    "message": "Nie udało się oznaczyć wiadomości jako przeczytanej. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    };
    match try_can_mark_message_as_read(&db, &user_id, &msg).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(()) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "MARK_READ_FAILED",
                    "message": "Nie udało się oznaczyć wiadomości jako przeczytanej. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    }
    let peer = msg.sender.to_hex();
    let now = DateTime::now();
    let update = Message::collection(&db)
        .update_one(
            doc! { "_id": mid, "read": false },
            doc! {
                "$set": { "read": true, "updatedAt": now },
            },
        )
        .await;
    let flipped = match update {
        Ok(r) => r.modified_count > 0,
        Err(_) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "MARK_READ_FAILED",
                    "message": "Nie udało się oznaczyć wiadomości jako przeczytanej. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    };
    if !flipped {
        return;
    }
    registry::emit_to_user(
        &msg.sender.to_hex(),
        "message-read",
        json!({ "messageId": message_id, "read": true }),
    );
    if let (Ok(viewer), Ok(peer_oid)) = (
        ObjectId::parse_str(&user_id),
        ObjectId::parse_str(&peer),
    ) {
        heal_dm_unread_after_mark(&db, &user_id, &peer, viewer, peer_oid).await;
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarkConversationReadPayload {
    user_id: Option<String>,
    contact_id: Option<String>,
}

async fn handle_mark_conversation_read(connected: &str, payload: MarkConversationReadPayload) {
    let Some(user_id) = payload.user_id else { return };
    let Some(contact_id) = payload.contact_id else { return };
    if !is_connected_user(connected, &user_id) {
        return;
    }
    let db = get_db();

    let (Ok(uid), Ok(cid)) = (ObjectId::parse_str(&user_id), ObjectId::parse_str(&contact_id)) else {
        return;
    };

    const MAX_EMIT_IDS: usize = 500;
    let filter = doc! {
        "sender": cid,
        "recipient": uid,
        "read": false,
        "deleted": { "$ne": true },
        "$or": dm_only_or_clause(),
    };
    let ids = match crate::utils::messages::search::collect_message_ids_limited(
        &db,
        filter.clone(),
        Some((MAX_EMIT_IDS as i64) + 1),
    )
    .await
    {
        Ok(ids) => ids,
        Err(_) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "MARK_READ_FAILED",
                    "message": "Nie udało się oznaczyć rozmowy jako przeczytanej. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    };
    if ids.is_empty() {

        heal_dm_unread_after_mark(&db, &user_id, &contact_id, uid, cid).await;
        return;
    }

    let conversation_read = ids.len() > MAX_EMIT_IDS;
    let now = DateTime::now();

    let mark_filter = if conversation_read {
        filter
    } else {
        doc! { "_id": { "$in": &ids } }
    };

    if Message::collection(&db)
        .update_many(
            mark_filter,
            doc! {
                "$set": { "read": true, "updatedAt": now },
            },
        )
        .await
        .is_err()
    {
        registry::emit_to_user(
            &user_id,
            "error",
            json!({
                "code": "MARK_READ_FAILED",
                "message": "Nie udało się oznaczyć rozmowy jako przeczytanej. Spróbuj ponownie.",
                "retryable": true,
            }),
        );
        return;
    }

    let message_ids: Vec<String> = if conversation_read {
        Vec::new()
    } else {
        ids.iter().map(|i| i.to_hex()).collect()
    };

    registry::emit_to_user(
        &contact_id,
        "messages-read",
        json!({
            "messageIds": message_ids,
            "read": true,
            "readerId": user_id,
            "conversationRead": conversation_read,
        }),
    );
    heal_dm_unread_after_mark(&db, &user_id, &contact_id, uid, cid).await;
}

async fn heal_dm_unread_after_mark(
    db: &Database,
    user_id: &str,
    peer: &str,
    viewer: ObjectId,
    peer_oid: ObjectId,
) {

    match crate::utils::tips::try_sync_dm_tip_unread(db, viewer, peer_oid).await {
        Some(tip_n) => {
            emit_unread_absolute(user_id, "dm", peer, tip_n);
            let db_tip = db.clone();
            let user_id = user_id.to_string();
            let peer = peer.to_string();
            let n_prev = tip_n;
            tokio::spawn(async move {
                let mut n_prev = n_prev;
                for _ in 0..3 {
                    let Some(n) = crate::utils::tips::try_sync_dm_tip_unread(
                        &db_tip, viewer, peer_oid,
                    )
                    .await
                    else {
                        break;
                    };
                    if n == n_prev {
                        break;
                    }
                    emit_unread_absolute(&user_id, "dm", &peer, n);
                    n_prev = n;
                }
            });
        }
        None => {

            crate::utils::unread::invalidate_unread_generation(user_id, "dm", peer);
            let db_tip = db.clone();
            let user_id = user_id.to_string();
            let peer = peer.to_string();
            tokio::spawn(async move {
                for _ in 0..3 {
                    if let Some(n) = crate::utils::tips::try_sync_dm_tip_unread(
                        &db_tip, viewer, peer_oid,
                    )
                    .await
                    {
                        emit_unread_absolute(&user_id, "dm", &peer, n);
                        if n == 0 {
                            break;
                        }
                    }
                }
            });
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarkChannelReadPayload {
    user_id: Option<String>,
    channel_id: Option<String>,
}

async fn handle_mark_channel_read(connected: &str, payload: MarkChannelReadPayload) {
    let Some(user_id) = payload.user_id else { return };
    let Some(channel_id) = payload.channel_id else { return };
    if !is_connected_user(connected, &user_id) {
        return;
    }
    let db = get_db();
    match require_channel_access(&db, &channel_id, &user_id).await {
        Ok(_) => {}
        Err(AccessDeniedReason::Unavailable) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "MARK_READ_FAILED",
                    "message": "Nie udało się oznaczyć kanału jako przeczytanego. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
        Err(_) => return,
    }
    if mark_channel_as_read_for_user(&db, &user_id, &channel_id)
        .await
        .is_err()
    {
        registry::emit_to_user(
            &user_id,
            "error",
            json!({
                "code": "MARK_READ_FAILED",
                "message": "Nie udało się oznaczyć kanału jako przeczytanego. Spróbuj ponownie.",
                "retryable": true,
            }),
        );
        return;
    }

    if let (Ok(uid), Ok(cid)) = (
        ObjectId::parse_str(&user_id),
        ObjectId::parse_str(&channel_id),
    ) {
        match crate::utils::unread::try_sync_channel_unread(&db, uid, cid).await {
            Some(tip_n) => {
                emit_unread_absolute(&user_id, "channel", &channel_id, tip_n);
                let db_tip = db.clone();
                let user_id = user_id.clone();
                let channel_id = channel_id.clone();
                let n_prev = tip_n;
                tokio::spawn(async move {
                    let mut n_prev = n_prev;
                    for _ in 0..3 {
                        let Some(n2) =
                            crate::utils::unread::try_sync_channel_unread(&db_tip, uid, cid).await
                        else {
                            break;
                        };
                        if n2 == n_prev {
                            break;
                        }
                        emit_unread_absolute(&user_id, "channel", &channel_id, n2);
                        n_prev = n2;
                    }
                });
            }
            None => {

                crate::utils::unread::invalidate_unread_generation(
                    &user_id, "channel", &channel_id,
                );
                let db_tip = db.clone();
                let user_id = user_id.clone();
                let channel_id = channel_id.clone();
                tokio::spawn(async move {
                    for _ in 0..3 {
                        if let Some(n) =
                            crate::utils::unread::try_sync_channel_unread(&db_tip, uid, cid).await
                        {
                            emit_unread_absolute(&user_id, "channel", &channel_id, n);
                            if n == 0 {
                                break;
                            }
                        }
                    }
                });
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EditMessagePayload {
    message_id: Option<String>,
    content: Option<String>,
    user_id: Option<String>,
}

async fn handle_edit_message(connected: &str, payload: EditMessagePayload) {
    let Some(message_id) = payload.message_id else { return };
    let Some(content_raw) = payload.content else { return };
    let Some(user_id) = payload.user_id else { return };
    if !is_connected_user(connected, &user_id) {
        return;
    }
    let Ok(mid) = ObjectId::parse_str(&message_id) else { return };
    let db = get_db();
    let msg = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) => m,
        Ok(None) => return,
        Err(_) => match Message::find_by_id(&db, mid).await {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(_) => {
                registry::emit_to_user(
                    &user_id,
                    "error",
                    json!({
                        "code": "EDIT_FAILED",
                        "message": "Nie udało się edytować wiadomości. Spróbuj ponownie.",
                        "retryable": true,
                    }),
                );
                return;
            }
        },
    };
    if msg.sender.to_hex() != user_id {
        return;
    }
    if msg.message_type != MessageType::Text {
        registry::emit_to_user(
            &user_id,
            "error",
            json!({
                "code": "EDIT_FORBIDDEN",
                "message": "Only text messages can be edited.",
            }),
        );
        return;
    }
    if let Err(reason) = require_message_participant(&db, &user_id, &msg).await {
        if reason == AccessDeniedReason::Unavailable {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "EDIT_FAILED",
                    "message": "Nie udało się edytować wiadomości. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
        }
        return;
    }

    let sanitized = crate::utils::validators::sanitize::sanitize_message_content(&content_raw);
    let prepared_content = inbound_plaintext_for_processing(&sanitized, false);
    if prepared_content.is_empty() {
        return;
    }
    if !crate::model::messages::is_message_content_within_limit(&prepared_content)
    {
        registry::emit_to_user(
            connected,
            "error",
            json!({ "message": "Wiadomość nie może przekraczać 2000 znaków", "code": "CONTENT_TOO_LONG" }),
        );
        return;
    }

    let previous_mentions: std::collections::HashSet<String> =
        msg.mentions.iter().map(|id| id.to_hex()).collect();
    let previous_everyone = msg.mentions_everyone;
    let sender_id = msg.sender.to_hex();

    let mentions;
    let mentions_everyone;
    let channel_doc;
    if let Some(channel_id) = msg.channel {
        channel_doc = match Channel::find_by_id(&db, channel_id).await {
            Ok(Some(ch)) => Some(ch),

            Ok(None) | Err(_) => None,
        };
        if let Some(ref channel) = channel_doc {
            let mut ids: Vec<String> = channel.members.iter().map(|m| m.to_hex()).collect();
            ids.push(channel.admin.to_hex());
            mentions = match resolve_mentions(&db, &prepared_content, &ids).await {
                Ok(m) => m,
                Err(()) => {
                    registry::emit_to_user(
                        &user_id,
                        "error",
                        json!({
                            "code": "EDIT_FAILED",
                            "message": "Nie udało się edytować wiadomości. Spróbuj ponownie.",
                            "retryable": true,
                        }),
                    );
                    return;
                }
            };
            mentions_everyone = has_everyone_mention(&prepared_content);
        } else {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "EDIT_FAILED",
                    "message": "Nie udało się edytować wiadomości. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    } else if msg.recipient.is_some() {
        channel_doc = None;
        mentions = match resolve_mentions(
            &db,
            &prepared_content,
            &[msg.sender.to_hex(), msg.recipient.unwrap().to_hex()],
        )
        .await
        {
            Ok(m) => m,
            Err(()) => {
                registry::emit_to_user(
                    &user_id,
                    "error",
                    json!({
                        "code": "EDIT_FAILED",
                        "message": "Nie udało się edytować wiadomości. Spróbuj ponownie.",
                        "retryable": true,
                    }),
                );
                return;
            }
        };
        mentions_everyone = false;
    } else {
        return;
    };

    let mentions_bson = match mongodb::bson::to_bson(&mentions) {
        Ok(b) => b,
        Err(_) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "EDIT_FAILED",
                    "message": "Nie udało się edytować wiadomości. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    };
    let stored_content = match crate::utils::messages::storage::prepare_content_for_storage_async(
        prepared_content.trim().to_string(),
    )
    .await
    {
        Ok(c) => c,
        Err(_) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "EDIT_FAILED",
                    "message": "Nie udało się edytować wiadomości. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    };
    let search_index = match crate::utils::messages::search::build_search_index_from_incoming(
        prepared_content.trim(),
    ) {
        Ok(index) => index,
        Err(_) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "EDIT_FAILED",
                    "message": "Nie udało się edytować wiadomości. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    };
    let edit_result = Message::collection(&db)
        .update_one(
            doc! { "_id": mid, "deleted": { "$ne": true } },
            doc! { "$set": {
                "content": stored_content,
                "searchText": search_index.encrypted_text,
                "searchTokens": search_index.tokens,
                "mentions": mentions_bson,
                "mentionsEveryone": mentions_everyone,
                "edited": true,
                "editedAt": DateTime::now(),
                "updatedAt": DateTime::now(),
            }},
        )
        .await;
    let flipped = match edit_result {
        Ok(r) => r.modified_count > 0,
        Err(_) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "EDIT_FAILED",
                    "message": "Nie udało się edytować wiadomości. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    };
    if !flipped {
        return;
    }

    let updated = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) => m,
        Ok(None) | Err(_) => match Message::find_by_id(&db, mid).await {
            Ok(Some(m)) => m,
            _ => {
                registry::emit_to_user(
                    &user_id,
                    "error",
                    json!({
                        "code": "EDIT_FAILED",
                        "message": "Nie udało się odświeżyć edycji. Spróbuj ponownie.",
                        "retryable": true,
                    }),
                );
                return;
            }
        },
    };
    {
        if let Some(cid) = updated.channel {
            crate::utils::tips::upsert_channel_tip(&db, cid, &updated).await;
        } else {
            crate::utils::tips::upsert_dm_tip(&db, &updated).await;
        }
        let populated = serialize_message(&db, &updated).await;
        let from_user = populated
            .get("sender")
            .cloned()
            .unwrap_or(json!({ "_id": sender_id }));
        let preview_content = prepared_content.clone();

        let muted_lookup: Option<std::collections::HashSet<String>> =
            if let (Some(channel_oid), Some(ref channel)) =
                (updated.channel, channel_doc.as_ref())
            {
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

        let ping_if_new = |member_id: &str, source_id: &str, source_name: Option<&str>| {
            if !mentions_ok || member_id == sender_id || muted_ids.contains(member_id) {
                return;
            }
            let newly_mentioned = (mentions.iter().any(|id| id.to_hex() == member_id)
                && !previous_mentions.contains(member_id))
                || (mentions_everyone && !previous_everyone);
            if !newly_mentioned {
                return;
            }
            emit_mention(
                member_id,
                if updated.channel.is_some() {
                    "channel"
                } else {
                    "dm"
                },
                source_id,
                source_name,
                &message_id,
                &from_user,
                &preview_content,
            );
        };

        if let Some(channel_id) = updated.channel {
            if let Some(ref channel) = channel_doc {
                let channel_id_hex = channel_id.to_hex();
                let recipients = registry::channel_recipient_ids(channel);
                registry::emit_to_users(&recipients, "message-edited", populated.clone());
                for r in &recipients {
                    ping_if_new(r, &channel_id_hex, Some(&channel.name));
                }
            }
        } else if let Some(recipient) = updated.recipient {
            let recipient_hex = recipient.to_hex();
            registry::emit_to_user(&recipient_hex, "message-edited", populated.clone());
            registry::emit_to_user(&updated.sender.to_hex(), "message-edited", populated.clone());
            ping_if_new(&recipient_hex, &sender_id, None);
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteMessagePayload {
    message_id: Option<String>,
    user_id: Option<String>,
}

async fn handle_delete_message(connected: &str, payload: DeleteMessagePayload) {
    let Some(message_id) = payload.message_id else { return };
    let Some(user_id) = payload.user_id else { return };
    if !is_connected_user(connected, &user_id) {
        return;
    }
    let Ok(mid) = ObjectId::parse_str(&message_id) else { return };
    let db = get_db();
    let msg = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) => m,
        Ok(None) => return,
        Err(_) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "DELETE_FAILED",
                    "message": "Nie udało się usunąć wiadomości. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    };
    if msg.sender.to_hex() != user_id {
        return;
    }
    if let Err(reason) = require_message_participant(&db, &user_id, &msg).await {
        if reason == AccessDeniedReason::Unavailable {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "DELETE_FAILED",
                    "message": "Nie udało się usunąć wiadomości. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
        }
        return;
    }

    let outcome = match Message::soft_delete_active(&db, mid).await {
        Ok(o) => o,
        Err(_) => {
            registry::emit_to_user(
                &user_id,
                "error",
                json!({
                    "code": "DELETE_FAILED",
                    "message": "Nie udało się usunąć wiadomości. Spróbuj ponownie.",
                    "retryable": true,
                }),
            );
            return;
        }
    };
    let crate::model::messages::SoftDeleteOutcome::Deleted { was_unread } = outcome else {
        return;
    };
    cleanup_attachment_if_unreferenced(&db, msg.file_url.as_deref()).await;
    let body = json!({ "_id": message_id });
    if let Some(channel_id) = msg.channel {
        let channel_id_hex = channel_id.to_hex();
        let channel = match Channel::find_by_id(&db, channel_id).await {
            Ok(Some(ch)) => Some(ch),
            Ok(None) | Err(_) => None,
        };
        if let Some(channel) = channel {
            let recipients = registry::channel_recipient_ids(&channel);
            registry::emit_to_users(&recipients, "message-deleted", body);
            let sender_hex = msg.sender.to_hex();
            let msg_ts = msg.timestamp;
            let mut targets: Vec<String> = channel.members.iter().map(|m| m.to_hex()).collect();
            targets.push(channel.admin.to_hex());

            crate::utils::tips::refresh_channel_tip_after_delete(
                &db, channel_id, mid,
            )
            .await;
            {
                use crate::model::read_state::ChannelReadState;
                use futures_util::TryStreamExt;
                let mut seen = std::collections::HashSet::new();
                let member_oids: Vec<ObjectId> = targets
                    .iter()
                    .filter_map(|id| ObjectId::parse_str(id).ok())
                    .collect();
                let mut last_reads: std::collections::HashMap<
                    String,
                    (DateTime, DateTime),
                > = std::collections::HashMap::new();
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
                let affected: Vec<(String, ObjectId)> = targets
                    .into_iter()
                    .filter_map(|member_id| {
                        if member_id == sender_hex || !seen.insert(member_id.clone()) {
                            return None;
                        }
                        let oid = ObjectId::parse_str(&member_id).ok()?;

                        if !read_state_ok {
                            return Some((member_id, oid));
                        }
                        let Some(&(last, created)) = last_reads.get(&member_id) else {

                            return Some((member_id, oid));
                        };

                        let effective = if last.timestamp_millis() <= 0 {
                            created
                        } else {
                            last
                        };
                        if effective.timestamp_millis() <= 0 || msg_ts <= effective {
                            return None;
                        }
                        Some((member_id, oid))
                    })
                    .collect();
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
                                emit_unread_absolute(
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
            }
        } else {
            crate::utils::tips::refresh_channel_tip_after_delete(
                &db, channel_id, mid,
            )
            .await;
            registry::emit_to_user(&msg.sender.to_hex(), "message-deleted", body.clone());

            registry::emit_to_user(
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
                match cursor.try_collect::<Vec<ChannelReadState>>().await {
                    Ok(states) => {
                        let mut seen = std::collections::HashSet::new();
                        seen.insert(msg.sender.to_hex());
                        for s in states {
                            let member_id = s.user_id.to_hex();
                            if !seen.insert(member_id.clone()) {
                                continue;
                            }
                            registry::emit_to_user(&member_id, "message-deleted", body.clone());
                            if was_unread {
                                if let Some(n) = crate::utils::unread::try_sync_channel_unread(
                                    &db, s.user_id, channel_id,
                                )
                                .await
                                {
                                    emit_unread_absolute(
                                        &member_id,
                                        "channel",
                                        &channel_id_hex,
                                        n,
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "message-deleted fanout read-state collect failed channel={}: {e}",
                            channel_id_hex
                        );
                        registry::emit_to_user(
                            &user_id,
                            "error",
                            json!({
                                "code": "DELETE_FANOUT_DEGRADED",
                                "message": "Wiadomość usunięta, ale synchronizacja z kanałem może być niepełna. Odśwież czat.",
                                "retryable": true,
                                "messageId": message_id,
                            }),
                        );
                    }
                }
            }
        }
    } else if let Some(recipient) = msg.recipient {
        let recipient_hex = recipient.to_hex();

        registry::emit_to_user(&recipient_hex, "message-deleted", body.clone());
        registry::emit_to_user(&msg.sender.to_hex(), "message-deleted", body);
        let sender_oid = msg.sender;
        crate::utils::tips::refresh_dm_tip_after_delete(
            &db,
            sender_oid,
            recipient,
            mid,
        )
        .await;
        if was_unread {

            if crate::utils::unread::try_count_dm_unread(&db, recipient, sender_oid)
                .await
                .is_some()
            {
                if let Some(n) = crate::utils::tips::try_sync_dm_tip_unread(
                    &db, recipient, sender_oid,
                )
                .await
                {
                    emit_unread_absolute(&recipient_hex, "dm", &sender_oid.to_hex(), n);
                }
            }
        }
    } else {
        registry::emit_to_user(&msg.sender.to_hex(), "message-deleted", body);
    }
}

#[derive(Debug, Deserialize)]
struct CallPayload {
    from: Option<String>,
    to: Option<String>,
    mode: Option<String>,
}

async fn finalize_expired_ringing_session(db: &Database, session: CallSession) {
    registry::emit_to_user(
        &session.callee_id,
        "call:cancelled",
        json!({ "from": session.caller_id }),
    );

    registry::emit_to_user(
        &session.caller_id,
        "call:cancelled",
        json!({ "from": session.caller_id, "reason": "TIMEOUT" }),
    );
    create_missed_call_log_message(db, &session.caller_id, &session.callee_id).await;
}

async fn finalize_stale_accepted_session(db: &Database, session: CallSession) {
    let payload = json!({ "from": session.caller_id, "reason": "TIMEOUT" });
    registry::emit_to_user(&session.caller_id, "call:ended", payload.clone());
    registry::emit_to_user(&session.callee_id, "call:ended", payload);
    if let Some(accepted_at) = session.accepted_at {
        let secs = accepted_at.elapsed().as_secs();
        create_call_log_message(db, &session.caller_id, &session.callee_id, secs).await;
    }
}

async fn finalize_expired_ringing_sessions() {
    let expired = drain_expired_sessions();
    if expired.is_empty() {
        return;
    }
    let db = get_db();
    for session in expired {
        match session.phase {
            CallPhase::Ringing => finalize_expired_ringing_session(&db, session).await,
            CallPhase::Accepted => finalize_stale_accepted_session(&db, session).await,
        }
    }
}

pub async fn sweep_expired_call_sessions() {
    finalize_expired_ringing_sessions().await;
}

async fn handle_call_invite(
    connected: &str,
    payload: CallPayload,
    state: &SocketState,
    conn_id: u64,
) {
    finalize_expired_ringing_sessions().await;
    let Some(from) = payload.from else { return };
    let Some(to) = payload.to else { return };
    if !is_connected_user(connected, &from) || from == to {
        return;
    }
    let db = get_db();
    match crate::utils::friends::try_are_friends(&db, &from, &to).await {
        Ok(true) => {}
        Ok(false) => {
            registry::emit_to_user(
                &from,
                "call:unavailable",
                json!({ "to": to, "reason": "NOT_FRIENDS" }),
            );
            return;
        }
        Err(()) => {
            registry::emit_to_user(
                &from,
                "call:unavailable",
                json!({ "to": to, "reason": "TEMP_UNAVAILABLE", "retryable": true }),
            );
            return;
        }
    }
    match try_is_dm_blocked(&db, &from, &to).await {
        Ok(true) => {
            registry::emit_to_user(&from, "call:unavailable", json!({ "to": to, "reason": "BLOCKED" }));
            return;
        }
        Ok(false) => {}
        Err(()) => {
            registry::emit_to_user(
                &from,
                "call:unavailable",
                json!({ "to": to, "reason": "TEMP_UNAVAILABLE", "retryable": true }),
            );
            return;
        }
    }

    let mode = if payload.mode.as_deref() == Some("video") {
        "video"
    } else {
        "audio"
    };

    let (session_id, replaced_expired) =
        match create_ringing_session(&from, &to, mode, conn_id) {
        Ok(result) => result,
        Err(CallSessionError::InProgress) => {
            registry::emit_to_user(
                &from,
                "call:unavailable",
                json!({ "to": to, "reason": "BUSY" }),
            );
            return;
        }
        Err(_) => return,
    };
    if let Some(expired) = replaced_expired {
        match expired.phase {
            CallPhase::Ringing => finalize_expired_ringing_session(&db, expired).await,
            CallPhase::Accepted => finalize_stale_accepted_session(&db, expired).await,
        }
    }

    let caller = User::find_by_id(&db, ObjectId::parse_str(&from).unwrap_or_default())
        .await
        .ok()
        .flatten();
    let caller_json = caller.map(|u| {
        json!({
            "_id": from,
            "username": u.username,
            "displayName": resolve_display_name(&u),
            "image": u.image,
            "color": u.color,
        })
    }).unwrap_or(json!({ "_id": from }));

    if state.is_user_connected(&to) {
        registry::emit_to_user(
            &to,
            "call:incoming",
            json!({
                "from": from,
                "mode": mode,
                "caller": caller_json,
                "callSessionId": session_id,
            }),
        );
    }
}

async fn handle_call_simple(
    connected: &str,
    incoming_event: &str,
    payload: CallPayload,
    conn_id: u64,
) {
    let outgoing = match incoming_event {
        "call:accept" => "call:accepted",
        "call:reject" => "call:rejected",
        "call:cancel" => "call:cancelled",
        "call:end" => "call:ended",
        _ => return,
    };
    let Some(from) = payload.from else { return };
    let Some(to) = payload.to else { return };
    if !is_connected_user(connected, &from) || from == to {
        return;
    }

    let db = get_db();

    let teardown_only = matches!(
        incoming_event,
        "call:reject" | "call:cancel" | "call:end"
    );
    if !teardown_only {
        match crate::utils::friends::try_are_friends(&db, &from, &to).await {
            Ok(true) => {}
            Ok(false) => {
                registry::emit_to_user(
                    &from,
                    "call:unavailable",
                    json!({ "to": to, "reason": "NOT_FRIENDS" }),
                );
                return;
            }
            Err(()) => {
                registry::emit_to_user(
                    &from,
                    "call:unavailable",
                    json!({ "to": to, "reason": "TEMP_UNAVAILABLE", "retryable": true }),
                );
                return;
            }
        }
        match try_is_dm_blocked(&db, &from, &to).await {
            Ok(true) => {
                registry::emit_to_user(
                    &from,
                    "call:unavailable",
                    json!({ "to": to, "reason": "BLOCKED" }),
                );
                return;
            }
            Ok(false) => {}
            Err(()) => {
                registry::emit_to_user(
                    &from,
                    "call:unavailable",
                    json!({ "to": to, "reason": "TEMP_UNAVAILABLE", "retryable": true }),
                );
                return;
            }
        }
    }

    match incoming_event {
        "call:accept" => {
            match accept_session(&from, &to, conn_id) {
                Ok(_) => {
                    registry::emit_to_user(&to, outgoing, json!({ "from": from }));
                    registry::emit_to_user(&from, outgoing, json!({ "from": from }));
                }
                Err(CallSessionError::Expired(expired)) => {
                    finalize_expired_ringing_session(&db, expired).await;
                }
                Err(err) => {
                    let reason = match err {
                        CallSessionError::NotFound => "NOT_FOUND",
                        CallSessionError::WrongRole => "WRONG_ROLE",
                        CallSessionError::InvalidPhase => "INVALID_PHASE",
                        CallSessionError::InProgress => "BUSY",
                        CallSessionError::Expired(_) => "EXPIRED",
                    };
                    registry::emit_to_user(
                        &from,
                        "call:unavailable",
                        json!({ "to": to, "reason": reason }),
                    );
                }
            }
        }
        "call:reject" => {
            match reject_session(&from, &to) {
                Ok(()) => {

                    create_missed_call_log_message(&db, &to, &from).await;
                    registry::emit_to_user(&to, outgoing, json!({ "from": from }));

                    registry::emit_to_user(&from, outgoing, json!({ "from": from }));
                }
                Err(CallSessionError::Expired(expired)) => {
                    finalize_expired_ringing_session(&db, expired).await;
                }
                Err(err) => {
                    let reason = match err {
                        CallSessionError::NotFound => "NOT_FOUND",
                        CallSessionError::WrongRole => "WRONG_ROLE",
                        CallSessionError::InvalidPhase => "INVALID_PHASE",
                        CallSessionError::InProgress => "BUSY",
                        CallSessionError::Expired(_) => "EXPIRED",
                    };
                    registry::emit_to_user(
                        &from,
                        "call:unavailable",
                        json!({ "to": to, "reason": reason }),
                    );
                }
            }
        }
        "call:cancel" => {

            match cancel_session(&from, &to) {
                Ok(()) => {
                    registry::emit_to_user(&to, outgoing, json!({ "from": from }));

                    registry::emit_to_user(&from, outgoing, json!({ "from": from }));
                }
                Err(CallSessionError::Expired(expired)) => {
                    finalize_expired_ringing_session(&db, expired).await;
                }
                Err(err) => {
                    let reason = match err {
                        CallSessionError::NotFound => "NOT_FOUND",
                        CallSessionError::WrongRole => "WRONG_ROLE",
                        CallSessionError::InvalidPhase => "INVALID_PHASE",
                        CallSessionError::InProgress => "BUSY",
                        CallSessionError::Expired(_) => "EXPIRED",
                    };
                    registry::emit_to_user(
                        &from,
                        "call:unavailable",
                        json!({ "to": to, "reason": reason }),
                    );
                }
            }
        }
        "call:end" => {
            match end_session(&from, &to) {
                Ok(session) => {
                    registry::emit_to_user(&to, outgoing, json!({ "from": from }));

                    registry::emit_to_user(&from, outgoing, json!({ "from": from }));
                    match session.phase {
                        CallPhase::Accepted => {
                            if let Some(accepted_at) = session.accepted_at {
                                let secs = accepted_at.elapsed().as_secs();
                                create_call_log_message(
                                    &db,
                                    &session.caller_id,
                                    &session.callee_id,
                                    secs,
                                )
                                .await;
                            }
                        }

                        CallPhase::Ringing => {
                            if from == session.callee_id {
                                create_missed_call_log_message(
                                    &db,
                                    &session.caller_id,
                                    &session.callee_id,
                                )
                                .await;
                            }
                        }
                    }
                }
                Err(err) => {
                    let reason = match err {
                        CallSessionError::NotFound => "NOT_FOUND",
                        CallSessionError::WrongRole => "WRONG_ROLE",
                        CallSessionError::InvalidPhase => "INVALID_PHASE",
                        CallSessionError::InProgress => "BUSY",
                        CallSessionError::Expired(_) => "EXPIRED",
                    };
                    registry::emit_to_user(
                        &from,
                        "call:unavailable",
                        json!({ "to": to, "reason": reason }),
                    );
                }
            }
        }
        _ => {}
    }
}

async fn handle_call_timeout(connected: &str, payload: CallPayload) {
    finalize_expired_ringing_sessions().await;
    let Some(from) = payload.from else { return };
    let Some(to) = payload.to else { return };
    if !is_connected_user(connected, &from) || from == to {
        return;
    }
    let db = get_db();

    match cancel_session(&from, &to) {
        Ok(()) => {
            registry::emit_to_user(&to, "call:cancelled", json!({ "from": from }));

            registry::emit_to_user(&from, "call:cancelled", json!({ "from": from }));
            create_missed_call_log_message(&db, &from, &to).await;
        }
        Err(CallSessionError::Expired(expired)) => {
            finalize_expired_ringing_session(&db, expired).await;
        }
        Err(err) => {
            let reason = match err {
                CallSessionError::NotFound => "NOT_FOUND",
                CallSessionError::WrongRole => "WRONG_ROLE",
                CallSessionError::InvalidPhase => "INVALID_PHASE",
                CallSessionError::InProgress => "BUSY",
                CallSessionError::Expired(_) => "EXPIRED",
            };
            registry::emit_to_user(
                &from,
                "call:unavailable",
                json!({ "to": to, "reason": reason }),
            );
        }
    }
}

#[derive(Debug, Deserialize)]
struct ChannelVoicePayload {
    #[serde(rename = "channelId")]
    channel_id: Option<String>,
}

async fn emit_channel_voice_state(channel_id: &str, participants: &[String]) {
    let body = json!({
        "channelId": channel_id,
        "participants": participants,
    });
    let db = get_db();
    let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {

        let recipients: Vec<String> = participants.to_vec();
        if !recipients.is_empty() {
            registry::emit_to_users(&recipients, "channel-voice:state", body);
        }
        return;
    };
    let channel = match Channel::find_by_id(&db, channel_oid).await {
        Ok(Some(ch)) => Some(ch),

        Ok(None) | Err(_) => None,
    };
    if let Some(channel) = channel {
        let mut recipients = registry::channel_recipient_ids(&channel);
        for p in participants {
            if !recipients.iter().any(|r| r == p) {
                recipients.push(p.clone());
            }
        }
        registry::emit_to_users(&recipients, "channel-voice:state", body);
    } else {
        let recipients: Vec<String> = participants.to_vec();
        if !recipients.is_empty() {
            registry::emit_to_users(&recipients, "channel-voice:state", body);
        }
    }
}

async fn handle_channel_voice_join(connected: &str, payload: ChannelVoicePayload, conn_id: u64) {
    let Some(channel_id) = payload.channel_id.as_deref().map(str::trim).filter(|s| !s.is_empty())
    else {
        return;
    };
    if !is_valid_object_id(channel_id) {
        return;
    }
    let db = get_db();
    let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {
        return;
    };
    let channel = match Channel::find_by_id(&db, channel_oid).await {
        Ok(Some(ch)) => ch,
        Ok(None) => return,
        Err(_) => match Channel::find_by_id(&db, channel_oid).await {
            Ok(Some(ch)) => ch,
            Ok(None) => return,
            Err(_) => {
                registry::emit_to_user(
                    connected,
                    "error",
                    json!({
                        "code": "VOICE_JOIN_FAILED",
                        "message": "Nie udało się dołączyć do voice. Spróbuj ponownie.",
                        "retryable": true,
                    }),
                );
                return;
            }
        },
    };
    if !can_access_channel(&channel, Some(connected)) {
        return;
    }
    let (participants, left_channels) = join_channel_voice(channel_id, connected, conn_id);
    for left_id in left_channels {
        let remaining = participants_in_channel(&left_id);
        emit_channel_voice_state(&left_id, &remaining).await;
    }
    emit_channel_voice_state(channel_id, &participants).await;
}

async fn handle_channel_voice_leave(connected: &str, payload: ChannelVoicePayload) {
    let Some(channel_id) = payload.channel_id.as_deref().map(str::trim).filter(|s| !s.is_empty())
    else {
        return;
    };
    if !is_valid_object_id(channel_id) {
        return;
    }
    let already_in = participants_in_channel(channel_id)
        .iter()
        .any(|id| id == connected);
    if !already_in {
        let db = get_db();
        let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {
            return;
        };
        let Ok(Some(channel)) = Channel::find_by_id(&db, channel_oid).await else {
            return;
        };

        if !can_access_channel(&channel, Some(connected)) {
            return;
        }
    }
    let participants = leave_channel_voice(channel_id, connected);
    emit_channel_voice_state(channel_id, &participants).await;
}

async fn handle_channel_voice_state_request(connected: &str, payload: ChannelVoicePayload) {
    let Some(channel_id) = payload.channel_id.as_deref().map(str::trim).filter(|s| !s.is_empty())
    else {
        return;
    };
    if !is_valid_object_id(channel_id) {
        return;
    }
    let db = get_db();
    let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {
        return;
    };
    let channel = match Channel::find_by_id(&db, channel_oid).await {
        Ok(Some(ch)) => ch,
        Ok(None) => return,
        Err(_) => match Channel::find_by_id(&db, channel_oid).await {
            Ok(Some(ch)) => ch,
            Ok(None) => return,
            Err(_) => {
                registry::emit_to_user(
                    connected,
                    "error",
                    json!({
                        "code": "VOICE_STATE_FAILED",
                        "message": "Nie udało się pobrać stanu voice. Spróbuj ponownie.",
                        "retryable": true,
                    }),
                );
                return;
            }
        },
    };
    if !can_access_channel(&channel, Some(connected)) {
        return;
    }
    let participants = participants_in_channel(channel_id);
    registry::emit_to_user(
        connected,
        "channel-voice:state",
        json!({
            "channelId": channel_id,
            "participants": participants,
        }),
    );
}

fn format_call_duration(total_secs: u64) -> String {
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    if hours > 0 {
        format!("{}:{:02}:{:02}", hours, minutes, seconds)
    } else {
        format!("{}:{:02}", minutes, seconds)
    }
}

async fn create_call_log_message(db: &Database, caller_id: &str, callee_id: &str, duration_secs: u64) {
    persist_call_log(
        db,
        caller_id,
        callee_id,
        format!("Voice call · {}", format_call_duration(duration_secs)),
        duration_secs.saturating_mul(1000).min(u32::MAX as u64) as u32,
        false,
    )
    .await;
}

async fn create_missed_call_log_message(db: &Database, caller_id: &str, callee_id: &str) {
    persist_call_log(db, caller_id, callee_id, "Missed call".to_string(), 0, true).await;
}

async fn persist_call_log(
    db: &Database,
    caller_id: &str,
    callee_id: &str,
    content: String,
    duration_ms: u32,
    missed: bool,
) {
    let (Ok(caller), Ok(callee)) = (
        ObjectId::parse_str(caller_id),
        ObjectId::parse_str(callee_id),
    ) else {
        return;
    };

    let input = CreateMessageInput {
        sender: caller,
        recipient: Some(callee),
        channel: None,
        content,
        message_type: Some(MessageType::Call),
        file_url: None,
        file_type: None,
        file_size: None,
        file_name: None,
        scan_status: ScanStatus::Clean,
        duration_ms: Some(duration_ms),
        quoted_message: None,
        mentions: None,
        mentions_everyone: Some(false),
        client_nonce: None,

        read: Some(!missed),
    };

    let unread_gen = peek_unread_generation(callee_id, "dm", caller_id);

    let created = match Message::create(db, input).await {
        Ok(CreateMessageOutcome::Created(m) | CreateMessageOutcome::IdempotentReplay(m)) => m,
        Err(e) => {
            log::error!("call log create error: {}", e);
            return;
        }
    };

    let populated = serialize_message(db, &created).await;

    let bump_unread = missed;
    {
        let db_tip = db.clone();
        let tip_msg = created.clone();
        let caller_oid = caller;
        let callee_oid = callee;
        let caller_id = caller_id.to_string();
        let callee_id = callee_id.to_string();
        tokio::spawn(async move {
            crate::utils::tips::upsert_dm_tip(&db_tip, &tip_msg).await;

            if !bump_unread {
                return;
            }
            let tip_mid = tip_msg.id;
            let still_active = match tip_mid {
                Some(id) => message_still_active(&db_tip, id).await,
                None => Some(false),
            };
            if still_active == Some(false) {
                if let Some(n) = crate::utils::tips::try_sync_dm_tip_unread(
                    &db_tip, callee_oid, caller_oid,
                )
                .await
                {
                    crate::utils::unread::emit_unread_absolute(&callee_id, "dm", &caller_id, n);
                }
            } else if peek_unread_generation(&callee_id, "dm", &caller_id) == unread_gen {
                let bumped = crate::utils::tips::bump_dm_unread(
                    &db_tip, caller_oid, callee_oid,
                )
                .await;
                let still_active = match tip_mid {
                    Some(id) => message_still_active(&db_tip, id).await,
                    None => Some(false),
                };
                if bumped
                    && still_active != Some(false)
                    && peek_unread_generation(&callee_id, "dm", &caller_id) == unread_gen
                {
                    emit_unread_delta_at(&callee_id, "dm", &caller_id, 1, unread_gen);
                } else if let Some(n) = crate::utils::tips::try_sync_dm_tip_unread(
                    &db_tip, callee_oid, caller_oid,
                )
                .await
                {
                    crate::utils::unread::emit_unread_absolute(&callee_id, "dm", &caller_id, n);
                }
            } else if let Some(n) = crate::utils::tips::try_sync_dm_tip_unread(
                &db_tip, callee_oid, caller_oid,
            )
            .await
            {
                crate::utils::unread::emit_unread_absolute(&callee_id, "dm", &caller_id, n);
            }
        });
    }
    registry::emit_to_user(caller_id, "receiveMessage", populated.clone());
    registry::emit_to_user(callee_id, "receiveMessage", populated);
}

fn emit_queue_full_error(user_id: &str, client_nonce: Option<&str>) {
    let mut body = json!({
        "code": "QUEUE_FULL",
        "message": "Zbyt wiele operacji naraz. Spróbuj ponownie.",
    });
    if let Some(nonce) = client_nonce
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 64)
    {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("clientNonce".into(), json!(nonce));
        }
    }
    registry::emit_to_user(user_id, "error", body);
}

fn emit_rate_limit_error(user_id: &str, client_nonce: Option<&str>) {
    let mut body = json!({
        "code": "RATE_LIMITED",
        "message": "Rate limit exceeded",
    });
    if let Some(nonce) = client_nonce
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 64)
    {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("clientNonce".into(), json!(nonce));
        }
    }
    registry::emit_to_user(user_id, "error", body);
}

fn payload_client_nonce(payload: &Value) -> Option<&str> {
    payload
        .get("clientNonce")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 64)
}

fn emit_send_error(
    user_id: &str,
    code: &str,
    message: &str,
    client_nonce: Option<&str>,
) {
    let mut body = json!({
        "code": code,
        "message": message,
    });
    if let Some(nonce) = client_nonce
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 64)
    {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("clientNonce".into(), json!(nonce));
        }
    }
    registry::emit_to_user(user_id, "error", body);
}

pub async fn on_user_connected(user_id: &str, socket_state: &SocketState) {
    finalize_expired_ringing_sessions().await;
    if !socket_state.is_user_connected(user_id) || socket_state.connection_count(user_id) == 0 {
        return;
    }
    if !set_user_online(user_id).await {
        return;
    }
    // The connection may have disappeared while the database update was in flight.
    // Do not publish an online event for a socket that is already gone.
    if !socket_state.is_user_connected(user_id) || socket_state.connection_count(user_id) == 0 {
        let _ = set_user_offline(user_id).await;
        return;
    }

    if let Some(availability) = availability_status_for_user(user_id).await {
        if !socket_state.is_user_connected(user_id) || socket_state.connection_count(user_id) == 0 {
            let _ = set_user_offline(user_id).await;
            return;
        }
        broadcast_user_status(
            user_id,
            json!({
                "isOnline": true,
                "availabilityStatus": availability,
                "lastSeen": Value::Null,
            }),
        )
        .await;
    }

    let ringing = ringing_sessions_for_callee(user_id);
    if ringing.is_empty() {
        return;
    }
    let db = get_db();
    for session in ringing {
        let caller = User::find_by_id(
            &db,
            ObjectId::parse_str(&session.caller_id).unwrap_or_default(),
        )
        .await
        .ok()
        .flatten();
        let caller_json = caller
            .map(|u| {
                json!({
                    "_id": session.caller_id,
                    "username": u.username,
                    "displayName": resolve_display_name(&u),
                    "image": u.image,
                    "color": u.color,
                })
            })
            .unwrap_or(json!({ "_id": session.caller_id }));
        registry::emit_to_user(
            user_id,
            "call:incoming",
            json!({
                "from": session.caller_id,
                "mode": session.mode,
                "caller": caller_json,
                "callSessionId": session.session_id,
            }),
        );
    }
}

pub async fn finalize_taken_call_sessions(user_id: &str, call_sessions: Vec<CallSession>) {
    if call_sessions.is_empty() {
        return;
    }
    let db = get_db();
    for session in call_sessions {
        let peer = if session.caller_id == user_id {
            session.callee_id.clone()
        } else {
            session.caller_id.clone()
        };
        match session.phase {
            CallPhase::Ringing => {
                if session.caller_id == user_id {
                    registry::emit_to_user(
                        &peer,
                        "call:cancelled",
                        json!({ "from": user_id }),
                    );

                    registry::emit_to_user(
                        user_id,
                        "call:cancelled",
                        json!({ "from": user_id, "reason": "TAB_CLOSED" }),
                    );
                } else {

                    registry::emit_to_user(
                        &peer,
                        "call:rejected",
                        json!({ "from": user_id }),
                    );
                    create_missed_call_log_message(&db, &session.caller_id, &session.callee_id)
                        .await;
                }
            }
            CallPhase::Accepted => {
                registry::emit_to_user(&peer, "call:ended", json!({ "from": user_id }));
                registry::emit_to_user(user_id, "call:ended", json!({ "from": user_id }));
                if let Some(accepted_at) = session.accepted_at {
                    let secs = accepted_at.elapsed().as_secs();
                    create_call_log_message(
                        &db,
                        &session.caller_id,
                        &session.callee_id,
                        secs,
                    )
                    .await;
                }
            }
        }
    }
}

pub async fn on_user_disconnected(user_id: &str, socket_state: &SocketState) {

    if socket_state.is_user_connected(user_id) || socket_state.connection_count(user_id) > 0 {
        return;
    }

    let call_sessions = take_sessions_for_user(user_id);
    if socket_state.is_user_connected(user_id) || socket_state.connection_count(user_id) > 0 {

        restore_sessions(call_sessions);
        return;
    }
    finalize_taken_call_sessions(user_id, call_sessions).await;

    if socket_state.is_user_connected(user_id) || socket_state.connection_count(user_id) > 0 {
        return;
    }

    let cleared_channels = clear_user_from_all_channels(user_id);
    for channel_id in cleared_channels {
        let participants = participants_in_channel(&channel_id);
        emit_channel_voice_state(&channel_id, &participants).await;
    }

    if socket_state.is_user_connected(user_id) || socket_state.connection_count(user_id) > 0 {
        return;
    }

    let Some(availability) = availability_status_for_user(user_id).await else {
        return;
    };
    if socket_state.is_user_connected(user_id) || socket_state.connection_count(user_id) > 0 {
        return;
    }
    if !set_user_offline(user_id).await {
        return;
    }

    if socket_state.is_user_connected(user_id) || socket_state.connection_count(user_id) > 0 {
        let _ = set_user_online(user_id).await;
        return;
    }
    broadcast_user_status(
        user_id,
        json!({
            "isOnline": false,
            "availabilityStatus": availability,
            "lastSeen": now_ms(),
        }),
    )
    .await;
}

pub async fn dispatch_message(
    connected: &str,
    msg_type: &str,
    payload: Value,
    state: &SocketState,
    conn_id: u64,
) {
    match msg_type {
        "sendMessage" => {
            if !state.check_rate_limit(connected, "sendMessage", 60, 60_000) {
                emit_rate_limit_error(connected, payload_client_nonce(&payload));
                return;
            }
            if let Ok(p) = serde_json::from_value::<SendMessagePayload>(payload) {
                let user_id = connected.to_string();
                let nonce = p.client_nonce.clone();
                if !state.spawn_user_ordered(user_id.clone(), async move {
                    handle_send_message(&user_id, p).await;
                }) {
                    emit_queue_full_error(connected, nonce.as_deref());
                }
            }
        }
        "send-channel-message" => {
            if !state
                .check_rate_limit(connected, "send-channel-message", 60, 60_000)
            {
                emit_rate_limit_error(connected, payload_client_nonce(&payload));
                return;
            }
            if let Ok(p) = serde_json::from_value::<ChannelMessagePayload>(payload) {
                let user_id = connected.to_string();
                let nonce = p.client_nonce.clone();
                if !state.spawn_user_ordered(user_id.clone(), async move {
                    handle_send_channel_message(&user_id, p).await;
                }) {
                    emit_queue_full_error(connected, nonce.as_deref());
                }
            }
        }
        "typing" => {
            if let Ok(p) = serde_json::from_value::<TypingPayload>(payload) {

                if p.is_typing.unwrap_or(false) {
                    let chat_key = p
                        .chat_id
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .unwrap_or("unknown");
                    let action = format!("typing:{chat_key}");
                    if !state.check_rate_limit(connected, &action, 20, 60_000) {
                        return;
                    }
                }

                let state = state.clone();
                let connected = connected.to_string();
                let state_job = state.clone();
                let connected_job = connected.clone();
                let chat_id = p
                    .chat_id
                    .clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "unknown".to_string());
                let is_typing = p.is_typing;
                let p = p.clone();
                state.spawn_user_ordered_eventually(connected, chat_id, is_typing, async move {
                    handle_typing(state_job, &connected_job, p).await;
                });
            }
        }
        "message-reaction" => {
            if !state
                .check_rate_limit(connected, "message-reaction", 120, 60_000)
            {
                emit_rate_limit_error(connected, None);
                return;
            }
            if let Ok(p) = serde_json::from_value::<ReactionPayload>(payload) {
                let user_id = connected.to_string();
                if !state.spawn_user_ordered(user_id.clone(), async move {
                    handle_reaction(&user_id, p).await;
                }) {
                    emit_queue_full_error(connected, None);
                }
            }
        }
        "mark-message-read" => {
            if !state
                .check_rate_limit(connected, "mark-message-read", 300, 60_000)
            {
                emit_rate_limit_error(connected, None);
                return;
            }
            if let Ok(p) = serde_json::from_value::<MarkMessageReadPayload>(payload) {
                let user_id = connected.to_string();
                if !state.spawn_user_ack(user_id.clone(), async move {
                    handle_mark_message_read(&user_id, p).await;
                }) {
                    emit_queue_full_error(connected, None);
                }
            }
        }
        "mark-conversation-read" => {
            if !state
                .check_rate_limit(connected, "mark-conversation-read", 60, 60_000)
            {
                emit_rate_limit_error(connected, None);
                return;
            }
            if let Ok(p) = serde_json::from_value::<MarkConversationReadPayload>(payload) {
                let user_id = connected.to_string();
                if !state.spawn_user_ack(user_id.clone(), async move {
                    handle_mark_conversation_read(&user_id, p).await;
                }) {
                    emit_queue_full_error(connected, None);
                }
            }
        }
        "mark-channel-read" => {
            if !state
                .check_rate_limit(connected, "mark-channel-read", 300, 60_000)
            {
                emit_rate_limit_error(connected, None);
                return;
            }
            if let Ok(p) = serde_json::from_value::<MarkChannelReadPayload>(payload) {
                let user_id = connected.to_string();
                if !state.spawn_user_ack(user_id.clone(), async move {
                    handle_mark_channel_read(&user_id, p).await;
                }) {
                    emit_queue_full_error(connected, None);
                }
            }
        }
        "editMessage" => {
            if !state.check_rate_limit(connected, "editMessage", 60, 60_000) {
                emit_rate_limit_error(connected, None);
                return;
            }
            if let Ok(p) = serde_json::from_value::<EditMessagePayload>(payload) {
                let user_id = connected.to_string();
                if !state.spawn_user_ordered(user_id.clone(), async move {
                    handle_edit_message(&user_id, p).await;
                }) {
                    emit_queue_full_error(connected, None);
                }
            }
        }
        "deleteMessage" => {
            if !state.check_rate_limit(connected, "deleteMessage", 60, 60_000) {
                emit_rate_limit_error(connected, None);
                return;
            }
            if let Ok(p) = serde_json::from_value::<DeleteMessagePayload>(payload) {
                let user_id = connected.to_string();
                if !state.spawn_user_ordered(user_id.clone(), async move {
                    handle_delete_message(&user_id, p).await;
                }) {
                    emit_queue_full_error(connected, None);
                }
            }
        }
        "set-online" => {
            if !state.check_rate_limit(connected, "set-online", 30, 60_000) {
                return;
            }
            let connected = connected.to_string();
            let state = state.clone();
            tokio::spawn(async move {
                if state.connection_count(&connected) == 0 {
                    return;
                }
                if !set_user_online(&connected).await {
                    return;
                }
                if state.connection_count(&connected) == 0 {
                    let _ = set_user_offline(&connected).await;
                    return;
                }
                let Some(availability) = availability_status_for_user(&connected).await else {
                    return;
                };
                if state.connection_count(&connected) == 0 {
                    let _ = set_user_offline(&connected).await;
                    return;
                }
                broadcast_user_status(
                    &connected,
                    json!({
                        "isOnline": true,
                        "availabilityStatus": availability,
                        "lastSeen": Value::Null,
                    }),
                )
                .await;
            });
        }
        "set-offline" => {
            if !state.check_rate_limit(connected, "set-offline", 30, 60_000) {
                return;
            }

            let connected = connected.to_string();
            let state = state.clone();
            tokio::spawn(async move {
                if state.connection_count(&connected) > 1 {
                    return;
                }
                let Some(availability) = availability_status_for_user(&connected).await else {
                    return;
                };
                if state.connection_count(&connected) > 1 {
                    return;
                }
                if !set_user_offline(&connected).await {
                    return;
                }

                if state.connection_count(&connected) > 1 {
                    let _ = set_user_online(&connected).await;
                    return;
                }
                broadcast_user_status(
                    &connected,
                    json!({
                        "isOnline": false,
                        "availabilityStatus": availability,
                        "lastSeen": now_ms(),
                    }),
                )
                .await;
            });
        }
        "set-status" => {
            if !state.check_rate_limit(connected, "set-status", 30, 60_000) {
                return;
            }

            let status = payload
                .get("availabilityStatus")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if let Some(st) = status {
                let connected = connected.to_string();
                tokio::spawn(async move {
                    let Some(normalized) = set_availability(&connected, &st).await else {
                        return;
                    };

                    let Ok(oid) = ObjectId::parse_str(&connected) else {
                        return;
                    };
                    let user = match User::find_by_id(&get_db(), oid).await {
                        Ok(Some(u)) => u,
                        Ok(None) | Err(_) => return,
                    };
                    let last_seen = user
                        .last_seen
                        .map(|ts| json!(ts.timestamp_millis()))
                        .unwrap_or(Value::Null);
                    broadcast_user_status(
                        &connected,
                        json!({
                            "isOnline": user.is_online,
                            "availabilityStatus": normalized,
                            "lastSeen": if user.is_online { Value::Null } else { last_seen },
                        }),
                    )
                    .await;
                });
            }
        }
        "call:invite" => {
            if !state.check_rate_limit(connected, "call:invite", 20, 60_000) {
                emit_rate_limit_error(connected, None);
                return;
            }
            if let Ok(p) = serde_json::from_value::<CallPayload>(payload) {
                let user_id = connected.to_string();
                let state = state.clone();
                if !state.clone().spawn_user_realtime(user_id.clone(), async move {
                    handle_call_invite(&user_id, p, &state, conn_id).await;
                }) {
                    emit_queue_full_error(connected, None);
                }
            }
        }
        "call:accept" | "call:reject" | "call:cancel" | "call:end" => {
            if !state.check_rate_limit(connected, msg_type, 30, 60_000) {
                emit_rate_limit_error(connected, None);
                return;
            }
            if let Ok(p) = serde_json::from_value::<CallPayload>(payload) {
                let user_id = connected.to_string();
                let msg_type = msg_type.to_string();
                if !state.spawn_user_realtime(user_id.clone(), async move {
                    handle_call_simple(&user_id, &msg_type, p, conn_id).await;
                }) {
                    emit_queue_full_error(connected, None);
                }
            }
        }
        "call:timeout" => {
            if !state.check_rate_limit(connected, "call:timeout", 20, 60_000) {
                emit_rate_limit_error(connected, None);
                return;
            }
            if let Ok(p) = serde_json::from_value::<CallPayload>(payload) {
                let user_id = connected.to_string();
                if !state.spawn_user_realtime(user_id.clone(), async move {
                    handle_call_timeout(&user_id, p).await;
                }) {
                    emit_queue_full_error(connected, None);
                }
            }
        }
        "channel-voice:join" | "channel-voice:leave" | "channel-voice:state" => {
            if !state.check_rate_limit(connected, msg_type, 40, 60_000) {
                emit_rate_limit_error(connected, None);
                return;
            }
            if let Ok(p) = serde_json::from_value::<ChannelVoicePayload>(payload) {
                let user_id = connected.to_string();
                let msg_type = msg_type.to_string();
                if !state.spawn_user_realtime(user_id.clone(), async move {
                    match msg_type.as_str() {
                        "channel-voice:join" => {
                            handle_channel_voice_join(&user_id, p, conn_id).await
                        }
                        "channel-voice:leave" => handle_channel_voice_leave(&user_id, p).await,
                        _ => handle_channel_voice_state_request(&user_id, p).await,
                    }
                }) {
                    emit_queue_full_error(connected, None);
                }
            }
        }
        _ => {}
    }
}
