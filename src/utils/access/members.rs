// members.rs
// Czy wolno pisać/czytać (admin, ban, mute, friend, block).
// Zakres:
//  - AccessDeniedReason
//  - admin, ban, mute, friend, block → AccessDeniedReason
// Nowa reguła (np. slowmode) — tu i slowmode.rs, nie tylko w handlerze.
// Przy zmianach: ws/handlers.rs, cache.rs, friends/mod.rs.

use mongodb::bson::oid::ObjectId;
use mongodb::Database;

use crate::model::channels::Channel;
use crate::utils::channel::{can_access_channel, is_channel_admin, is_channel_muted_member};
use crate::utils::friends::try_is_dm_blocked;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDeniedReason {
    InvalidId,
    NotFound,
    Unavailable,
    NotMember,
    Banned,
    Muted,
    NotFriends,
    Blocked,
}

impl AccessDeniedReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidId => "Invalid ID",
            Self::NotFound => "Resource not found",
            Self::Unavailable => "Temporarily unavailable",
            Self::NotMember => "Access denied",
            Self::Banned => "You are banned from this channel",
            Self::Muted => "You are muted in this channel",
            Self::NotFriends => "Not friends with this user",
            Self::Blocked => "This conversation is not available",
        }
    }
}

pub async fn require_channel_access(
    db: &Database,
    channel_id: &str,
    user_id: &str,
) -> Result<Channel, AccessDeniedReason> {
    if let Some(cached) = crate::utils::access::cache::get(channel_id, user_id) {
        return cached;
    }

    let channel_oid = ObjectId::parse_str(channel_id).map_err(|_| AccessDeniedReason::InvalidId)?;
    let result = async {
        let channel = Channel::find_by_id(db, channel_oid)
            .await
            .map_err(|_| AccessDeniedReason::Unavailable)?
            .ok_or(AccessDeniedReason::NotFound)?;
        let channel =
            crate::utils::channel::moderation::maybe_prune_channel_moderation(db, &channel).await;

        if !can_access_channel(&channel, Some(user_id)) {
            if crate::utils::channel::is_channel_banned(&channel, Some(user_id)) {
                return Err(AccessDeniedReason::Banned);
            }
            return Err(AccessDeniedReason::NotMember);
        }

        Ok(channel)
    }
    .await;

    match &result {
        Ok(channel) => {
            crate::utils::access::cache::put_ok(channel_id, user_id, channel.clone());
        }
        Err(reason)
            if *reason != AccessDeniedReason::InvalidId
                && *reason != AccessDeniedReason::Unavailable =>
        {
            crate::utils::access::cache::put_err(channel_id, user_id, reason.clone());
        }
        Err(_) => {}
    }

    result
}

pub async fn require_channel_message_access(
    db: &Database,
    channel_id: &str,
    user_id: &str,
) -> Result<Channel, AccessDeniedReason> {
    let channel = require_channel_access(db, channel_id, user_id).await?;
    if is_channel_muted_member(&channel, Some(user_id)) {
        return Err(AccessDeniedReason::Muted);
    }
    Ok(channel)
}

pub fn channel_admin_bypasses_slowmode(channel: &Channel, user_id: &str) -> bool {
    is_channel_admin(channel, Some(user_id))
}

pub async fn require_dm_access(
    db: &Database,
    user_id: &str,
    contact_id: &str,
) -> Result<(), AccessDeniedReason> {
    if ObjectId::parse_str(user_id).is_err() || ObjectId::parse_str(contact_id).is_err() {
        return Err(AccessDeniedReason::InvalidId);
    }
    if user_id == contact_id {
        return Err(AccessDeniedReason::InvalidId);
    }
    let friends = match crate::utils::friends::try_are_friends(db, user_id, contact_id).await {
        Ok(v) => v,
        Err(()) => return Err(AccessDeniedReason::Unavailable),
    };
    let blocked = match try_is_dm_blocked(db, user_id, contact_id).await {
        Ok(v) => v,
        Err(()) => return Err(AccessDeniedReason::Unavailable),
    };
    if !friends {
        return Err(AccessDeniedReason::NotFriends);
    }
    if blocked {
        return Err(AccessDeniedReason::Blocked);
    }
    Ok(())
}

pub async fn authorize_dm_history_read(
    db: &Database,
    user_id: &str,
    contact_id: &str,
) -> Result<(ObjectId, ObjectId), AccessDeniedReason> {
    let user_oid = ObjectId::parse_str(user_id).map_err(|_| AccessDeniedReason::InvalidId)?;
    let contact_oid = ObjectId::parse_str(contact_id).map_err(|_| AccessDeniedReason::InvalidId)?;
    require_dm_access(db, user_id, contact_id).await?;
    Ok((user_oid, contact_oid))
}

pub async fn require_message_participant(
    db: &Database,
    user_id: &str,
    msg: &crate::model::messages::Message,
) -> Result<(), AccessDeniedReason> {
    if msg.deleted {
        return Err(AccessDeniedReason::NotFound);
    }
    if let Some(channel_id) = msg.channel {
        require_channel_access(db, &channel_id.to_hex(), user_id).await?;
        return Ok(());
    }
    if let Some(recipient) = msg.recipient {
        let sender_id = msg.sender.to_hex();
        let recipient_id = recipient.to_hex();
        let is_participant = user_id == sender_id || user_id == recipient_id;
        if !is_participant {
            return Err(AccessDeniedReason::NotMember);
        }
        let other = if user_id == sender_id {
            recipient_id
        } else {
            sender_id
        };
        let (friends, blocked) = tokio::join!(
            crate::utils::friends::try_are_friends(db, user_id, &other),
            try_is_dm_blocked(db, user_id, &other),
        );
        let friends = match friends {
            Ok(v) => v,
            Err(()) => return Err(AccessDeniedReason::Unavailable),
        };
        let blocked = match blocked {
            Ok(v) => v,
            Err(()) => return Err(AccessDeniedReason::Unavailable),
        };
        if !friends {
            return Err(AccessDeniedReason::NotFriends);
        }
        if blocked {
            return Err(AccessDeniedReason::Blocked);
        }
        return Ok(());
    }
    Err(AccessDeniedReason::NotFound)
}
