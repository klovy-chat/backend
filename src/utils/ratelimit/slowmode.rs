// slowmode.rs
// Odstęp wiadomości na kanale; admin omija.
// Zakres:
//  - record po udanym send
//  - odstęp na kanale; admin omija; UI ten sam interval
// UI musi pokazać ten sam interval co tu.
// Przy zmianach: handlers.rs, ChannelSettings.

use std::time::Duration;

use super::Store;

static SLOWMODE: once_cell::sync::Lazy<Store> =
    once_cell::sync::Lazy::new(|| Store::new(1, Duration::from_secs(1)));

fn slowmode_key(user_id: &str, channel_id: &str) -> String {
    format!("slowmode:{user_id}:{channel_id}")
}

pub async fn check_channel_slowmode(
    user_id: &str,
    channel_id: &str,
    rate_limit_secs: u32,
    bypass: bool,
) -> Result<(), u64> {
    if bypass || rate_limit_secs == 0 {
        return Ok(());
    }

    let window = Duration::from_secs(rate_limit_secs as u64);
    let key = slowmode_key(user_id, channel_id);

    if SLOWMODE.would_block_with_window(&key, 1, window) {
        Err(rate_limit_secs as u64)
    } else {
        Ok(())
    }
}

pub fn record_channel_slowmode(
    user_id: &str,
    channel_id: &str,
    rate_limit_secs: u32,
    bypass: bool,
) {
    if bypass || rate_limit_secs == 0 {
        return;
    }
    let window = Duration::from_secs(rate_limit_secs as u64);
    let key = slowmode_key(user_id, channel_id);
    SLOWMODE.increment_with_window(&key, window);
}
