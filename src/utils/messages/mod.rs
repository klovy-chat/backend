// mod.rs
// Reeksport access/search/mentions/storage.
// Zakres:
//  - ścieżka send
//  - access, search, mentions, storage — nowy aspekt = podplik
// Nowy aspekt wiadomości: podplik tutaj.
// Przy zmianach: handlers.rs.

pub mod access;
pub mod conversation_writes;
pub mod encrypt_old;
pub mod mentions;
pub mod search;
pub mod storage;

use futures::stream::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime};
use mongodb::Database;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

use crate::model::channels::Channel;
use crate::model::messages::Message;
use crate::model::users::User;
use crate::utils::access::members::require_dm_access;
use crate::utils::channel::{can_access_channel, is_channel_admin};
use crate::utils::user::json::resolve_display_name;

pub fn dm_only_or_clause() -> Bson {
    Bson::Array(vec![
        doc! { "channel": Bson::Null }.into(),
        doc! { "channel": { "$exists": false } }.into(),
    ])
}

pub fn escape_regex(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '.' | '*' | '+' | '?' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' | '\\'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn file_url_for_api(msg: &Message) -> serde_json::Value {
    if msg.scan_status.exposes_file_url() {
        json!(msg.file_url)
    } else {
        Value::Null
    }
}

fn scan_status_for_api(msg: &Message) -> &'static str {
    msg.scan_status.as_str()
}

fn iso(dt: &DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

pub async fn populate_user(db: &Database, id: ObjectId) -> Value {
    match User::find_by_id(db, id).await {
        Ok(Some(u)) => json!({
            "_id": u.id.map(|o| o.to_hex()),
            "username": u.username,
            "displayName": resolve_display_name(&u),
            "bio": u.bio,
            "image": u.image,
            "color": u.color,
        }),
        _ => Value::Null,
    }
}

fn reactions_to_json(msg: &Message) -> Value {
    let mut map = serde_json::Map::new();
    for (key, reaction) in &msg.reactions {
        let users: Vec<String> = reaction.users.iter().map(|o| o.to_hex()).collect();
        map.insert(key.clone(), json!(users));
    }
    Value::Object(map)
}

fn message_content_for_api(msg: &Message, content_cache: &HashMap<ObjectId, String>) -> String {
    msg.id
        .and_then(|id| content_cache.get(&id).cloned())
        .unwrap_or_else(|| crate::utils::messages::storage::content_for_api(&msg.content))
}

async fn build_content_cache(
    msgs: &[Message],
    quoted: &HashMap<ObjectId, Message>,
) -> HashMap<ObjectId, String> {
    let mut pairs: Vec<(ObjectId, String)> = Vec::new();
    for m in msgs {
        if let Some(id) = m.id {
            pairs.push((id, m.content.clone()));
        }
    }
    for m in quoted.values() {
        if let Some(id) = m.id {
            pairs.push((id, m.content.clone()));
        }
    }
    let contents: Vec<String> = pairs.iter().map(|(_, c)| c.clone()).collect();
    let decrypted = crate::utils::messages::storage::contents_for_api_batch_async(contents).await;
    pairs
        .into_iter()
        .zip(decrypted)
        .map(|((id, _), plain)| (id, plain))
        .collect()
}

async fn serialize_message_inner(db: &Database, msg: &Message, include_quote: bool) -> Value {
    let content_cache = build_content_cache(std::slice::from_ref(msg), &HashMap::new()).await;
    let sender = populate_user(db, msg.sender).await;

    let recipient = match msg.recipient {
        Some(r) => populate_user(db, r).await,
        None => Value::Null,
    };

    let pinned_by = match msg.pinned_by {
        Some(p) => populate_user(db, p).await,
        None => Value::Null,
    };

    let mut mentions = Vec::new();
    for m in &msg.mentions {
        mentions.push(populate_user(db, *m).await);
    }

    let quoted = if include_quote {
        match msg.quoted_message {
            Some(q) => match Message::find_by_id(db, q).await {
                Ok(Some(qm)) => Box::pin(serialize_message_inner(db, &qm, false)).await,
                Ok(None) => Value::Null,
                Err(_) => json!({ "_id": q.to_hex(), "unavailable": true }),
            },
            None => Value::Null,
        }
    } else {
        Value::Null
    };

    json!({
        "_id": msg.id.map(|o| o.to_hex()),
        "sender": sender,
        "recipient": recipient,
        "channel": msg.channel.map(|o| o.to_hex()),
        "content": message_content_for_api(msg, &content_cache),
        "messageType": serde_json::to_value(&msg.message_type).unwrap_or(Value::Null),
        "fileUrl": file_url_for_api(msg),
        "fileType": msg.file_type,
        "fileSize": msg.file_size,
        "fileName": msg.file_name,
        "scanStatus": scan_status_for_api(msg),
        "durationMs": msg.duration_ms,
        "clientNonce": msg.client_nonce,
        "timestamp": iso(&msg.timestamp),
        "read": msg.read,
        "reactions": reactions_to_json(msg),
        "quotedMessage": quoted,
        "mentions": mentions,
        "mentionsEveryone": msg.mentions_everyone,
        "edited": msg.edited,
        "editedAt": msg.edited_at.as_ref().and_then(iso),
        "deleted": msg.deleted,
        "deletedAt": msg.deleted_at.as_ref().and_then(iso),
        "pinned": msg.pinned,
        "pinnedAt": msg.pinned_at.as_ref().and_then(iso),
        "pinnedBy": pinned_by,
        "createdAt": iso(&msg.created_at),
        "updatedAt": iso(&msg.updated_at),
    })
}

pub async fn serialize_message(db: &Database, msg: &Message) -> Value {
    let mut batch = serialize_messages_batch(db, std::slice::from_ref(msg)).await;
    if let Some(value) = batch.pop() {
        return value;
    }
    serialize_message_inner(db, msg, true).await
}

fn user_to_json(u: &User) -> Value {
    json!({
        "_id": u.id.map(|o| o.to_hex()),
        "username": u.username,
        "displayName": resolve_display_name(u),
        "bio": u.bio,
        "image": u.image,
        "color": u.color,
    })
}

fn collect_message_user_ids(msg: &Message, set: &mut HashSet<ObjectId>) {
    set.insert(msg.sender);
    if let Some(r) = msg.recipient {
        set.insert(r);
    }
    if let Some(p) = msg.pinned_by {
        set.insert(p);
    }
    for m in &msg.mentions {
        set.insert(*m);
    }
}

fn cached_user(users: &HashMap<ObjectId, Value>, id: ObjectId) -> Value {
    users.get(&id).cloned().unwrap_or(Value::Null)
}

fn mark_users_unavailable(user_map: &mut HashMap<ObjectId, Value>, ids: &[ObjectId]) {
    for id in ids {
        user_map.insert(*id, json!({ "_id": id.to_hex(), "unavailable": true }));
    }
}

enum QuotedSer<'a> {
    None,
    Present(&'a Message),
    Unavailable(ObjectId),
}

fn serialize_message_cached(
    msg: &Message,
    users: &HashMap<ObjectId, Value>,
    quoted: QuotedSer<'_>,
    content_cache: &HashMap<ObjectId, String>,
) -> Value {
    let sender = cached_user(users, msg.sender);
    let recipient = msg
        .recipient
        .map(|r| cached_user(users, r))
        .unwrap_or(Value::Null);
    let pinned_by = msg
        .pinned_by
        .map(|p| cached_user(users, p))
        .unwrap_or(Value::Null);
    let mentions: Vec<Value> = msg
        .mentions
        .iter()
        .map(|m| cached_user(users, *m))
        .collect();

    let quoted = match quoted {
        QuotedSer::Present(qm) => {
            serialize_message_cached(qm, users, QuotedSer::None, content_cache)
        }
        QuotedSer::None => Value::Null,
        QuotedSer::Unavailable(id) => json!({ "_id": id.to_hex(), "unavailable": true }),
    };

    json!({
        "_id": msg.id.map(|o| o.to_hex()),
        "sender": sender,
        "recipient": recipient,
        "channel": msg.channel.map(|o| o.to_hex()),
        "content": message_content_for_api(msg, &content_cache),
        "messageType": serde_json::to_value(&msg.message_type).unwrap_or(Value::Null),
        "fileUrl": file_url_for_api(msg),
        "fileType": msg.file_type,
        "fileSize": msg.file_size,
        "fileName": msg.file_name,
        "scanStatus": scan_status_for_api(msg),
        "durationMs": msg.duration_ms,
        "clientNonce": msg.client_nonce,
        "timestamp": iso(&msg.timestamp),
        "read": msg.read,
        "reactions": reactions_to_json(msg),
        "quotedMessage": quoted,
        "mentions": mentions,
        "mentionsEveryone": msg.mentions_everyone,
        "edited": msg.edited,
        "editedAt": msg.edited_at.as_ref().and_then(iso),
        "deleted": msg.deleted,
        "deletedAt": msg.deleted_at.as_ref().and_then(iso),
        "pinned": msg.pinned,
        "pinnedAt": msg.pinned_at.as_ref().and_then(iso),
        "pinnedBy": pinned_by,
        "createdAt": iso(&msg.created_at),
        "updatedAt": iso(&msg.updated_at),
    })
}

pub async fn serialize_messages_batch(db: &Database, msgs: &[Message]) -> Vec<Value> {
    if msgs.is_empty() {
        return Vec::new();
    }

    let quoted_ids: Vec<ObjectId> = msgs.iter().filter_map(|m| m.quoted_message).collect();
    let mut quoted_map: HashMap<ObjectId, Message> = HashMap::new();
    let mut quotes_unavailable = false;
    if !quoted_ids.is_empty() {
        match Message::collection(db)
            .find(doc! { "_id": { "$in": &quoted_ids } })
            .await
        {
            Ok(cursor) => match cursor.try_collect::<Vec<Message>>().await {
                Ok(list) => {
                    for m in list {
                        if let Some(id) = m.id {
                            quoted_map.insert(id, m);
                        }
                    }
                }
                Err(error) => {
                    log::error!("Failed to decode quoted messages during serialization: {error}");
                    quotes_unavailable = true;
                }
            },
            Err(error) => {
                log::error!("Failed to query quoted messages during serialization: {error}");
                quotes_unavailable = true;
            }
        }
    }

    let mut user_ids: HashSet<ObjectId> = HashSet::new();
    for m in msgs {
        collect_message_user_ids(m, &mut user_ids);
    }
    for m in quoted_map.values() {
        collect_message_user_ids(m, &mut user_ids);
    }

    let mut user_map: HashMap<ObjectId, Value> = HashMap::new();
    if !user_ids.is_empty() {
        let ids: Vec<ObjectId> = user_ids.into_iter().collect();
        match User::collection(db)
            .find(doc! { "_id": { "$in": &ids } })
            .await
        {
            Ok(cursor) => match cursor.try_collect::<Vec<User>>().await {
                Ok(users) => {
                    for user in users {
                        if let Some(id) = user.id {
                            user_map.insert(id, user_to_json(&user));
                        }
                    }
                }
                Err(error) => {
                    log::error!("Failed to decode message authors during serialization: {error}");
                    mark_users_unavailable(&mut user_map, &ids);
                }
            },
            Err(error) => {
                log::error!("Failed to query message authors during serialization: {error}");
                mark_users_unavailable(&mut user_map, &ids);
            }
        }
    }

    let content_cache = build_content_cache(msgs, &quoted_map).await;

    msgs.iter()
        .map(|m| {
            let quoted = match m.quoted_message {
                Some(q) => match quoted_map.get(&q) {
                    Some(qm) => QuotedSer::Present(qm),
                    None if quotes_unavailable => QuotedSer::Unavailable(q),
                    None => QuotedSer::None,
                },
                None => QuotedSer::None,
            };
            serialize_message_cached(m, &user_map, quoted, &content_cache)
        })
        .collect()
}

pub async fn can_pin_message(db: &Database, user_id: &str, msg: &Message) -> bool {
    matches!(try_can_pin_message(db, user_id, msg).await, Ok(true))
}

pub async fn try_can_pin_message(
    db: &Database,
    user_id: &str,
    msg: &Message,
) -> Result<bool, crate::utils::access::members::AccessDeniedReason> {
    use crate::utils::access::members::AccessDeniedReason;
    if msg.deleted {
        return Ok(false);
    }

    if let Some(channel_id) = msg.channel {
        let channel = match Channel::find_by_id(db, channel_id).await {
            Ok(Some(ch)) => ch,
            Ok(None) => return Ok(false),
            Err(_) => return Err(AccessDeniedReason::Unavailable),
        };
        if !can_access_channel(&channel, Some(user_id)) {
            return Ok(false);
        }
        return Ok(is_channel_admin(&channel, Some(user_id)));
    }

    if let Some(recipient) = msg.recipient {
        let sender_id = msg.sender.to_hex();
        let recipient_id = recipient.to_hex();
        let is_participant = user_id == sender_id || user_id == recipient_id;
        if !is_participant {
            return Ok(false);
        }
        let other_id = if user_id == sender_id {
            recipient_id
        } else {
            sender_id
        };
        match require_dm_access(db, user_id, &other_id).await {
            Ok(()) => return Ok(true),
            Err(AccessDeniedReason::Unavailable) => return Err(AccessDeniedReason::Unavailable),
            Err(_) => return Ok(false),
        }
    }

    Ok(false)
}

pub fn dm_conversation_base_clauses(
    user: ObjectId,
    contact: ObjectId,
) -> Vec<mongodb::bson::Document> {
    vec![
        doc! { "$or": [
            { "sender": user, "recipient": contact },
            { "sender": contact, "recipient": user },
        ]},
        doc! { "deleted": { "$ne": true } },
        doc! { "$or": dm_only_or_clause() },
    ]
}

pub fn message_belongs_to_dm_conversation(
    msg: &Message,
    user: ObjectId,
    contact: ObjectId,
) -> bool {
    msg.recipient.is_some()
        && msg.channel.is_none()
        && !msg.deleted
        && ((msg.sender == user && msg.recipient == Some(contact))
            || (msg.sender == contact && msg.recipient == Some(user)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorValidateError {
    Invalid,
    Unavailable,
}

pub async fn validate_dm_history_before_cursor(
    db: &Database,
    user: ObjectId,
    contact: ObjectId,
    before_id: &str,
) -> Result<ObjectId, CursorValidateError> {
    let Ok(before_oid) = ObjectId::parse_str(before_id) else {
        return Err(CursorValidateError::Invalid);
    };
    let msg = match Message::find_by_id(db, before_oid).await {
        Ok(Some(m)) => m,
        Ok(None) => return Err(CursorValidateError::Invalid),
        Err(_) => return Err(CursorValidateError::Unavailable),
    };
    if message_belongs_to_dm_conversation(&msg, user, contact) {
        Ok(before_oid)
    } else {
        Err(CursorValidateError::Invalid)
    }
}
