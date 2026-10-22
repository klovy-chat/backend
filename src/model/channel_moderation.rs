// channel_moderation.rs
// Wpis mute/ban (opcjonalne wygaśnięcie) + deserializer starych kształtów.
// Zakres:
//  - osadzone w Channel
//  - mute/ban + expiry; deserializer starych kształtów
// Nie zmieniaj kształtu bez migracji starych dokumentów.
// Przy zmianach: model/channels.rs, utils/channel/moderation.rs.

use mongodb::bson::{oid::ObjectId, DateTime};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelModerationEntry {
    #[serde(rename = "userId")]
    pub user_id: ObjectId,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ModerationEntryCompat {
    Legacy(ObjectId),
    Full(ChannelModerationEntry),
}

impl ChannelModerationEntry {
    pub fn permanent(user_id: ObjectId) -> Self {
        Self {
            user_id,
            expires_at: None,
            created_at: DateTime::now(),
        }
    }

    pub fn timed(user_id: ObjectId, duration_seconds: u64) -> Self {
        let created_at = DateTime::now();
        Self {
            user_id,
            expires_at: Some(DateTime::from_millis(
                created_at.timestamp_millis() + duration_seconds as i64 * 1000,
            )),
            created_at,
        }
    }

    pub fn is_active(&self) -> bool {
        match self.expires_at {
            Some(expires_at) => expires_at.timestamp_millis() > DateTime::now().timestamp_millis(),
            None => true,
        }
    }
}

pub fn active_moderation_entries(
    entries: &[ChannelModerationEntry],
) -> Vec<ChannelModerationEntry> {
    entries
        .iter()
        .filter(|entry| entry.is_active())
        .cloned()
        .collect()
}

pub fn deserialize_moderation_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<ChannelModerationEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Vec::<ModerationEntryCompat>::deserialize(deserializer)?;
    let now = DateTime::now();
    Ok(raw
        .into_iter()
        .filter_map(|item| match item {
            ModerationEntryCompat::Legacy(user_id) => Some(ChannelModerationEntry {
                user_id,
                expires_at: None,
                created_at: now,
            }),

            ModerationEntryCompat::Full(entry) => Some(entry),
        })
        .collect())
}

pub fn has_active_entry(entries: &[ChannelModerationEntry], user_id: &str) -> bool {
    entries
        .iter()
        .any(|entry| entry.is_active() && entry.user_id.to_hex() == user_id)
}
