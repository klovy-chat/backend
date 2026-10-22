// mod.rs
// Denorm unread, fence delta vs absolute, recovery po poison mutex.
// Zakres:
//  - mark-read vs +1 z send
//  - delta z send vs absolute z mark-read; poison mutex recovery
// Absolute 0 bez potwierdzenia recount = sticky-high albo false-zero na FE.
// Przy zmianach: handlers.rs, read_state.rs, UnreadSync.tsx.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::Database;
use once_cell::sync::Lazy;
use serde::Serialize;

use crate::model::messages::Message;
use crate::model::read_state::ChannelReadState;
use crate::ws::registry;

static UNREAD_REVISION: AtomicU64 = AtomicU64::new(1);

struct GenerationEntry {
    value: u64,
    touched_at_ms: i64,
}

static UNREAD_GENERATIONS: Lazy<Mutex<HashMap<String, GenerationEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static GENERATION_FLOOR: Lazy<Mutex<HashMap<String, u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static USER_GENERATION_WATERMARK: Lazy<Mutex<HashMap<String, u64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const GENERATION_GC_IDLE_MS: i64 = 3_600_000;
const GENERATION_GC_EVERY: u64 = 64;
const GENERATION_FLOOR_MAX: usize = 50_000;
const USER_WATERMARK_MAX: usize = 50_000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn user_id_from_conv_key(key: &str) -> &str {
    key.split(':').next().unwrap_or(key)
}

fn bump_user_watermark(user_id: &str, value: u64) {
    if value == 0 {
        return;
    }
    let Ok(mut wm) = USER_GENERATION_WATERMARK.lock() else {
        return;
    };
    let entry = wm.entry(user_id.to_string()).or_insert(0);
    *entry = (*entry).max(value);
    if wm.len() > USER_WATERMARK_MAX {
        let overflow = wm.len() - USER_WATERMARK_MAX;
        let mut entries: Vec<(String, u64)> = wm.iter().map(|(k, v)| (k.clone(), *v)).collect();
        entries.sort_by_key(|(_, v)| *v);
        for (k, _) in entries.into_iter().take(overflow) {
            wm.remove(&k);
        }
    }
}

fn user_watermark(user_id: &str) -> u64 {
    USER_GENERATION_WATERMARK
        .lock()
        .ok()
        .and_then(|g| g.get(user_id).copied())
        .unwrap_or(0)
}

fn maybe_gc_generations(guard: &mut HashMap<String, GenerationEntry>) {
    static GC_COUNTER: AtomicU64 = AtomicU64::new(0);
    if GC_COUNTER.fetch_add(1, Ordering::Relaxed) % GENERATION_GC_EVERY != 0 {
        return;
    }
    let cutoff = now_ms().saturating_sub(GENERATION_GC_IDLE_MS);
    let mut to_floor: Vec<(String, u64)> = Vec::new();
    guard.retain(|key, e| {
        if e.touched_at_ms >= cutoff {
            true
        } else {
            to_floor.push((key.clone(), e.value));
            false
        }
    });
    if to_floor.is_empty() {
        return;
    }
    if let Ok(mut floor) = GENERATION_FLOOR.lock() {
        for (key, value) in to_floor {
            bump_user_watermark(user_id_from_conv_key(&key), value);
            let entry = floor.entry(key).or_insert(0);
            *entry = (*entry).max(value);
        }
        if floor.len() > GENERATION_FLOOR_MAX {
            let overflow = floor.len() - GENERATION_FLOOR_MAX;
            let mut entries: Vec<(String, u64)> =
                floor.iter().map(|(k, v)| (k.clone(), *v)).collect();
            entries.sort_by_key(|(_, v)| *v);
            for (k, v) in entries.into_iter().take(overflow) {
                bump_user_watermark(user_id_from_conv_key(&k), v);
                floor.remove(&k);
            }
        }
    }
}

fn floor_value(key: &str) -> u64 {
    let floor = GENERATION_FLOOR
        .lock()
        .ok()
        .and_then(|g| g.get(key).copied())
        .unwrap_or(0);
    let wm = user_watermark(user_id_from_conv_key(key));
    floor.max(wm)
}

fn next_revision() -> u64 {
    UNREAD_REVISION.fetch_add(1, Ordering::Relaxed)
}

fn conv_key(user_id: &str, kind: &str, id: &str) -> String {
    format!("{user_id}:{kind}:{id}")
}

fn current_generation(user_id: &str, kind: &str, id: &str) -> u64 {
    let key = conv_key(user_id, kind, id);
    let wm = user_watermark(user_id);
    let Ok(mut guard) = UNREAD_GENERATIONS.lock() else {
        return floor_value(&key).max(wm);
    };
    maybe_gc_generations(&mut guard);
    if let Some(entry) = guard.get_mut(&key) {
        entry.touched_at_ms = now_ms();
        return entry.value.max(wm);
    }
    floor_value(&key).max(wm)
}

fn bump_generation(user_id: &str, kind: &str, id: &str) -> u64 {
    let key = conv_key(user_id, kind, id);
    let mut guard = match UNREAD_GENERATIONS.lock() {
        Ok(g) => g,

        Err(e) => e.into_inner(),
    };
    maybe_gc_generations(&mut guard);
    let now = now_ms();
    let base = guard
        .get(&key)
        .map(|e| e.value)
        .unwrap_or_else(|| floor_value(&key));
    let next = base.saturating_add(1);
    guard.insert(
        key.clone(),
        GenerationEntry {
            value: next,
            touched_at_ms: now,
        },
    );
    drop(guard);
    if let Ok(mut floor) = GENERATION_FLOOR.lock() {
        floor.remove(&key);
    } else if let Err(e) = GENERATION_FLOOR.lock() {
        e.into_inner().remove(&key);
    }
    bump_user_watermark(user_id, next);
    next
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnreadUpdatedEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<i64>,
    pub revision: u64,

    pub generation: u64,
}

fn dm_only() -> mongodb::bson::Document {
    doc! { "$or": [ { "channel": mongodb::bson::Bson::Null }, { "channel": { "$exists": false } } ] }
}

pub async fn try_count_dm_unread(
    db: &Database,
    user_id: ObjectId,
    contact_id: ObjectId,
) -> Option<u64> {
    let filter = doc! {
        "sender": contact_id,
        "recipient": user_id,
        "read": false,
        "deleted": { "$ne": true },
        "$and": [
            dm_only(),
            {
                "$nor": [{
                    "messageType": "CALL",
                    "durationMs": { "$gt": 0 },
                }]
            },
        ],
    };
    match Message::collection(db)
        .count_documents(filter.clone())
        .await
    {
        Ok(n) => Some(n),
        Err(_) => Message::collection(db).count_documents(filter).await.ok(),
    }
}

pub async fn try_count_channel_unread(
    db: &Database,
    user_id: ObjectId,
    channel_id: ObjectId,
) -> Option<u64> {
    for _ in 0..3 {
        let state = match ChannelReadState::find(db, user_id, channel_id).await {
            Ok(s) => s,
            Err(_) => return None,
        };
        let last_read = match state.as_ref() {
            Some(s) if s.last_read_at.timestamp_millis() <= 0 => s.created_at,
            Some(s) => s.last_read_at,
            None => return None,
        };

        let filter = doc! {
            "channel": channel_id,
            "timestamp": { "$gt": last_read },
            "sender": { "$ne": user_id },
            "deleted": { "$ne": true },
        };
        let n = match Message::collection(db)
            .count_documents(filter.clone())
            .await
        {
            Ok(n) => n,
            Err(_) => match Message::collection(db).count_documents(filter).await {
                Ok(n) => n,
                Err(_) => return None,
            },
        };

        let state2 = match ChannelReadState::find(db, user_id, channel_id).await {
            Ok(s) => s,
            Err(_) => return None,
        };
        let last_read2 = match state2.as_ref() {
            Some(s) if s.last_read_at.timestamp_millis() <= 0 => Some(s.created_at),
            Some(s) => Some(s.last_read_at),
            None => return None,
        };
        if Some(last_read) == last_read2 {
            return Some(n);
        }
    }
    None
}

async fn channel_unread_denorm(
    db: &Database,
    user_id: ObjectId,
    channel_id: ObjectId,
) -> Result<Option<u64>, ()> {
    match ChannelReadState::find(db, user_id, channel_id).await {
        Ok(Some(s)) => Ok(Some(s.unread_count)),
        Ok(None) => Ok(None),
        Err(_) => Err(()),
    }
}

pub async fn set_channel_unread_denorm(
    db: &Database,
    user_id: ObjectId,
    channel_id: ObjectId,
    unread: u64,
) -> bool {
    use mongodb::options::UpdateOptions;
    let now = DateTime::now();

    let last_read = DateTime::from_millis(now.timestamp_millis().saturating_sub(1));

    ChannelReadState::collection(db)
        .update_one(
            doc! { "userId": user_id, "channelId": channel_id },
            doc! {
                "$set": {
                    "unreadCount": unread as i64,
                    "updatedAt": now,
                },
                "$setOnInsert": {
                    "createdAt": now,

                    "lastReadAt": last_read,
                },
            },
        )
        .with_options(UpdateOptions::builder().upsert(true).build())
        .await
        .is_ok()
}

pub async fn try_sync_channel_unread(
    db: &Database,
    user_id: ObjectId,
    channel_id: ObjectId,
) -> Option<u64> {
    let Some(mut n) = try_count_channel_unread(db, user_id, channel_id).await else {
        return None;
    };
    for _ in 0..3 {
        if !set_channel_unread_denorm(db, user_id, channel_id, n).await {
            return None;
        }
        let denorm = match channel_unread_denorm(db, user_id, channel_id).await {
            Ok(Some(v)) => v,
            Ok(None) | Err(()) => return None,
        };
        let Some(n2) = try_count_channel_unread(db, user_id, channel_id).await else {
            return None;
        };
        if n2 == n && denorm == n {
            return Some(n);
        }
        n = n2;
    }
    if !set_channel_unread_denorm(db, user_id, channel_id, n).await {
        return None;
    }
    match channel_unread_denorm(db, user_id, channel_id).await {
        Ok(Some(v)) if v == n => {}
        _ => return None,
    }
    match try_count_channel_unread(db, user_id, channel_id).await {
        Some(n2) if n2 == n => Some(n),
        _ => None,
    }
}

pub fn emit_unread_updated(user_id: &str, event: UnreadUpdatedEvent) {
    registry::emit_to_user(user_id, "unread-updated", event);
}

pub fn emit_unread_delta(user_id: &str, kind: &str, id: &str, delta: i64) {
    let generation = current_generation(user_id, kind, id);
    emit_unread_delta_at(user_id, kind, id, delta, generation);
}

pub fn emit_unread_delta_at(user_id: &str, kind: &str, id: &str, delta: i64, generation: u64) {
    emit_unread_updated(
        user_id,
        UnreadUpdatedEvent {
            kind: kind.into(),
            id: id.to_string(),
            unread_count: None,
            delta: Some(delta),
            revision: next_revision(),
            generation,
        },
    );
}

pub fn peek_unread_generation(user_id: &str, kind: &str, id: &str) -> u64 {
    current_generation(user_id, kind, id)
}

pub fn invalidate_unread_generation(user_id: &str, kind: &str, id: &str) -> u64 {
    bump_generation(user_id, kind, id)
}

pub fn emit_unread_absolute(user_id: &str, kind: &str, id: &str, unread_count: u64) {
    let generation = bump_generation(user_id, kind, id);
    emit_unread_updated(
        user_id,
        UnreadUpdatedEvent {
            kind: kind.into(),
            id: id.to_string(),
            unread_count: Some(unread_count),
            delta: None,
            revision: next_revision(),
            generation,
        },
    );
}

pub async fn emit_dm_unread_updated(db: &Database, user_id: &str, contact_id: &str) -> Option<u64> {
    let (Ok(uid), Ok(cid)) = (
        ObjectId::parse_str(user_id),
        ObjectId::parse_str(contact_id),
    ) else {
        return None;
    };
    let Some(unread) = try_count_dm_unread(db, uid, cid).await else {
        return None;
    };
    emit_unread_absolute(user_id, "dm", contact_id, unread);
    Some(unread)
}

pub async fn emit_channel_unread_updated(
    db: &Database,
    user_id: &str,
    channel_id: &str,
) -> Option<u64> {
    let (Ok(uid), Ok(cid)) = (
        ObjectId::parse_str(user_id),
        ObjectId::parse_str(channel_id),
    ) else {
        return None;
    };
    let Some(unread) = try_count_channel_unread(db, uid, cid).await else {
        return None;
    };
    emit_unread_absolute(user_id, "channel", channel_id, unread);
    Some(unread)
}

pub async fn mark_channel_as_read_for_user(
    db: &Database,
    user_id: &str,
    channel_id: &str,
) -> Result<(), ()> {
    let (Ok(uid), Ok(cid)) = (
        ObjectId::parse_str(user_id),
        ObjectId::parse_str(channel_id),
    ) else {
        return Err(());
    };
    ChannelReadState::upsert(db, uid, cid).await.map_err(|_| ())
}
