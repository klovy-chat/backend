// cache.rs
// TTL cache allow/deny członkostwa.
// Zakres:
//  - inwalidacja z typing cache przy moderacji
//  - TTL allow/deny; za długi = pisanie po kick
// Za długi TTL = pisanie po kick. Za krótki = Mongo na każdy send.
// Przy zmianach: members.rs, ws/typing.rs, channels.rs.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;

use crate::model::channels::Channel;
use crate::utils::access::members::AccessDeniedReason;

const ALLOW_TTL_MS: i64 = 30_000;
const DENY_TTL_MS: i64 = 3_000;
const CACHE_MAX: usize = 8_000;

#[derive(Clone)]
enum Cached {
    Allow {
        at_ms: i64,
        channel: Channel,
    },
    Deny {
        at_ms: i64,
        reason: AccessDeniedReason,
    },
}

static CACHE: Lazy<Mutex<HashMap<String, Cached>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn key(channel_id: &str, user_id: &str) -> String {
    format!("{channel_id}:{user_id}")
}

pub fn get(channel_id: &str, user_id: &str) -> Option<Result<Channel, AccessDeniedReason>> {
    let guard = CACHE.lock().ok()?;
    let entry = guard.get(&key(channel_id, user_id))?;
    match entry {
        Cached::Allow { at_ms, channel } => {
            if now_ms().saturating_sub(*at_ms) > ALLOW_TTL_MS {
                return None;
            }
            Some(Ok(channel.clone()))
        }
        Cached::Deny { at_ms, reason } => {
            if now_ms().saturating_sub(*at_ms) > DENY_TTL_MS {
                return None;
            }
            Some(Err(reason.clone()))
        }
    }
}

fn trim(map: &mut HashMap<String, Cached>) {
    if map.len() <= CACHE_MAX {
        return;
    }
    let overflow = map.len() - CACHE_MAX;
    let keys: Vec<String> = map.keys().take(overflow).cloned().collect();
    for key in keys {
        map.remove(&key);
    }
}

pub fn put_ok(channel_id: &str, user_id: &str, channel: Channel) {
    if let Ok(mut guard) = CACHE.lock() {
        guard.insert(
            key(channel_id, user_id),
            Cached::Allow {
                at_ms: now_ms(),
                channel,
            },
        );
        trim(&mut guard);
    }
}

pub fn put_err(channel_id: &str, user_id: &str, reason: AccessDeniedReason) {
    if let Ok(mut guard) = CACHE.lock() {
        guard.insert(
            key(channel_id, user_id),
            Cached::Deny {
                at_ms: now_ms(),
                reason,
            },
        );
        trim(&mut guard);
    }
}

pub fn invalidate_channel(channel_id: &str) {
    if let Ok(mut guard) = CACHE.lock() {
        let prefix = format!("{channel_id}:");
        guard.retain(|k, _| !k.starts_with(&prefix));
    }
}

pub fn invalidate_user(user_id: &str) {
    if let Ok(mut guard) = CACHE.lock() {
        let suffix = format!(":{user_id}");
        guard.retain(|k, _| !k.ends_with(&suffix));
    }
}

pub fn clear_user(user_id: &str) {
    invalidate_user(user_id);
}
