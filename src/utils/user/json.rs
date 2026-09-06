// json.rs
// JSON użytkownika bez hash/sekretów (own vs public).
// Zakres:
//  - API responses
//  - own vs public; wrażliwe pola default skip
// Nowe pole wrażliwe: default skip.
// Przy zmianach: controllers/users.rs, types/index.ts.

use serde_json::{json, Value};

use crate::model::users::{AvailabilityStatus, User};

pub const BIO_MAX_LENGTH: usize = 500;
pub const DISPLAY_NAME_MAX_LENGTH: usize = 32;

pub fn availability_status_str(status: &AvailabilityStatus) -> &'static str {
    match status {
        AvailabilityStatus::Online => "online",
        AvailabilityStatus::Away => "away",
        AvailabilityStatus::Brb => "brb",
        AvailabilityStatus::Dnd => "dnd",
    }
}

pub fn resolve_display_name(user: &User) -> Option<String> {
    user.display_name
        .as_ref()
        .map(|dn| dn.trim())
        .filter(|dn| !dn.is_empty())
        .map(|dn| dn.to_string())
}

fn iso(dt: &mongodb::bson::DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

pub fn serialize_user(user: &User) -> Value {
    serialize_user_for_viewer(user, true)
}

pub fn serialize_user_for_viewer(
    user: &User,
    is_self: bool,
) -> Value {
    let bio = user
        .bio
        .as_ref()
        .map(|b| b.trim().to_string())
        .filter(|b| !b.is_empty());

    let mut payload = json!({
        "id": user.id.map(|o| o.to_hex()),
        "username": user.username,
        "displayName": resolve_display_name(user),
        "bio": bio,
        "image": user.image,
        "banner": user.banner,
        "profileSetup": user.profile_setup,
        "color": user.color,
        "isOnline": user.is_online,
        "lastSeen": user.last_seen.as_ref().and_then(iso),
        "availabilityStatus": availability_status_str(&user.availability_status),
        "createdAt": iso(&user.created_at),
        "twoFactorEnabled": user.two_factor_enabled,
    });

    if is_self {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("language".to_string(), json!(user.language));
            obj.insert("isDisabled".to_string(), json!(user.is_disabled));
            obj.insert(
                "deletionScheduledAt".to_string(),
                json!(user.deletion_scheduled_at.as_ref().and_then(iso)),
            );
        }
    }

    payload
}
