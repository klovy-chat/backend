use mongodb::bson::DateTime;
use serde_json::{json, Value};

use crate::model::users::{PresenceVisibility, User};

const THIRTY_DAYS_MS: i64 = 30 * 24 * 60 * 60 * 1000;

pub fn can_view_presence(user: &User, viewer_id: &str, are_friends: bool) -> bool {
    if user.id.is_some_and(|id| id.to_hex() == viewer_id) {
        return true;
    }
    if user
        .presence_hidden_until
        .is_some_and(|until| until > DateTime::now())
    {
        return false;
    }
    if let Ok(viewer_oid) = mongodb::bson::oid::ObjectId::parse_str(viewer_id) {
        if user.presence_visible_to.contains(&viewer_oid) {
            return true;
        }
    }
    match user.presence_visibility {
        PresenceVisibility::Everyone => true,
        PresenceVisibility::Friends => are_friends,
        PresenceVisibility::Nobody => false,
    }
}

pub fn presence_payload(user: &User, viewer_id: &str, are_friends: bool) -> Value {
    let visible = can_view_presence(user, viewer_id, are_friends);
    let long_ago = !user.is_online
        && user.last_seen.is_some_and(|last_seen| {
            DateTime::now().timestamp_millis() - last_seen.timestamp_millis() >= THIRTY_DAYS_MS
        });

    json!({
        "isOnline": visible && user.is_online,
        "lastSeen": if visible && !long_ago {
            user.last_seen.as_ref().and_then(|date| date.try_to_rfc3339_string().ok())
        } else {
            None
        },
        "isPresenceHidden": !visible,
        "isLastSeenLongAgo": long_ago,
    })
}
