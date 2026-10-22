// cache.rs
// TTL id znajomych i par blokad.
// Zakres:
//  - fan-out presence
//  - TTL znajomych i blokad; inwaliduj przy każdej mutacji
// Inwaliduj przy każdej mutacji FriendRequest.
// Przy zmianach: friends.rs, user/online.rs.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;

const FRIEND_IDS_TTL_MS: i64 = 30_000;
const BLOCK_PAIR_TTL_MS: i64 = 15_000;
const FRIEND_CACHE_MAX: usize = 20_000;
const BLOCK_CACHE_MAX: usize = 40_000;

struct CacheEntry {
    ids: HashSet<String>,
    cached_at_ms: i64,
}

struct BlockEntry {
    low_blocks_high: bool,
    high_blocks_low: bool,
    cached_at_ms: i64,
}

static FRIEND_IDS_CACHE: Lazy<Mutex<HashMap<String, CacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static BLOCK_PAIR_CACHE: Lazy<Mutex<HashMap<String, BlockEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn block_pair_key(user_a: &str, user_b: &str) -> String {
    if user_a <= user_b {
        format!("{user_a}:{user_b}")
    } else {
        format!("{user_b}:{user_a}")
    }
}

fn trim_map<K, V>(map: &mut HashMap<K, V>, max: usize)
where
    K: Clone + Eq + std::hash::Hash,
{
    if map.len() <= max {
        return;
    }
    let overflow = map.len() - max;
    let keys: Vec<K> = map.keys().take(overflow).cloned().collect();
    for k in keys {
        map.remove(&k);
    }
}

pub fn get_cached_friend_ids(user_id: &str) -> Option<Vec<String>> {
    let guard = FRIEND_IDS_CACHE.lock().ok()?;
    let entry = guard.get(user_id)?;
    if now_ms().saturating_sub(entry.cached_at_ms) > FRIEND_IDS_TTL_MS {
        return None;
    }
    Some(entry.ids.iter().cloned().collect())
}

pub fn get_cached_friend_set(user_id: &str) -> Option<HashSet<String>> {
    let guard = FRIEND_IDS_CACHE.lock().ok()?;
    let entry = guard.get(user_id)?;
    if now_ms().saturating_sub(entry.cached_at_ms) > FRIEND_IDS_TTL_MS {
        return None;
    }
    Some(entry.ids.clone())
}

pub fn put_cached_friend_ids(user_id: &str, ids: Vec<String>) {
    if let Ok(mut guard) = FRIEND_IDS_CACHE.lock() {
        guard.insert(
            user_id.to_string(),
            CacheEntry {
                ids: ids.into_iter().collect(),
                cached_at_ms: now_ms(),
            },
        );
        trim_map(&mut guard, FRIEND_CACHE_MAX);
    }
}

pub fn invalidate_friend_ids_cache(user_id: &str) {
    if let Ok(mut guard) = FRIEND_IDS_CACHE.lock() {
        guard.remove(user_id);
    }
}

pub fn invalidate_friend_ids_pair(user_a: &str, user_b: &str) {
    if let Ok(mut guard) = FRIEND_IDS_CACHE.lock() {
        guard.remove(user_a);
        guard.remove(user_b);
    }
}

pub fn get_cached_block_flags(viewer: &str, peer: &str) -> Option<(bool, bool)> {
    let key = block_pair_key(viewer, peer);
    let guard = BLOCK_PAIR_CACHE.lock().ok()?;
    let entry = guard.get(&key)?;
    if now_ms().saturating_sub(entry.cached_at_ms) > BLOCK_PAIR_TTL_MS {
        return None;
    }
    let (low, high) = if viewer <= peer {
        (viewer, peer)
    } else {
        (peer, viewer)
    };
    if viewer == low && peer == high {
        Some((entry.low_blocks_high, entry.high_blocks_low))
    } else {
        Some((entry.high_blocks_low, entry.low_blocks_high))
    }
}

pub fn put_cached_block_flags(viewer: &str, peer: &str, viewer_blocks: bool, peer_blocks: bool) {
    let key = block_pair_key(viewer, peer);
    let (low_blocks_high, high_blocks_low) = if viewer <= peer {
        (viewer_blocks, peer_blocks)
    } else {
        (peer_blocks, viewer_blocks)
    };
    if let Ok(mut guard) = BLOCK_PAIR_CACHE.lock() {
        guard.insert(
            key,
            BlockEntry {
                low_blocks_high,
                high_blocks_low,
                cached_at_ms: now_ms(),
            },
        );
        trim_map(&mut guard, BLOCK_CACHE_MAX);
    }
}

pub fn get_cached_block_pair(user_a: &str, user_b: &str) -> Option<bool> {
    get_cached_block_flags(user_a, user_b).map(|(a, b)| a || b)
}

pub fn invalidate_block_pair(user_a: &str, user_b: &str) {
    let key = block_pair_key(user_a, user_b);
    if let Ok(mut guard) = BLOCK_PAIR_CACHE.lock() {
        guard.remove(&key);
    }
}

pub fn invalidate_block_pair_for_user(user_id: &str) {
    if let Ok(mut guard) = BLOCK_PAIR_CACHE.lock() {
        guard.retain(|key, _| {
            let mut parts = key.splitn(2, ':');
            let a = parts.next().unwrap_or("");
            let b = parts.next().unwrap_or("");
            a != user_id && b != user_id
        });
    }
}
