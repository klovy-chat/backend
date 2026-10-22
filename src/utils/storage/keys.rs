// keys.rs
// Konwencja kluczy obiektów (user/…, chat/…).
// Zakres:
//  - deterministyczne path
//  - user/…, chat/… — zmiana layoutu = 404 starych URL
//  - allowlista rozszerzeń załącznika (w tym mp3/aac/mov/heic/pptx/csv)
// Zmiana layoutu = stare URL 404. Migruj albo alias.
// Przy zmianach: r2.rs, cdn.ts, file_type.rs.

const ALLOWED_ATTACHMENT_EXTENSIONS: &[&str] = &[
    "pdf", "jpg", "jpeg", "png", "webp", "docx", "xlsx", "pptx", "txt", "csv", "webm", "ogg",
    "wav", "mp3", "aac", "mp4", "m4a", "mov", "heic", "heif",
];

pub fn normalize_storage_key(path: &str) -> String {
    path.trim()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string()
}

pub fn is_safe_key(path: &str) -> bool {
    let normalized = normalize_storage_key(path);
    !normalized.is_empty() && !normalized.contains("..")
}

pub fn dm_conversation_id(user_a: &str, user_b: &str) -> String {
    let (first, second) = if user_a <= user_b {
        (user_a, user_b)
    } else {
        (user_b, user_a)
    };
    format!("conv_{first}_{second}")
}

fn new_media_version() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn is_media_version(value: &str) -> bool {
    value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_owned_media_id<'a>(rest: &'a str) -> Option<&'a str> {
    let rest = rest.strip_suffix(".webp")?;
    if let Some((id, version)) = rest.split_once('/') {
        if !is_media_version(version) {
            return None;
        }
        return Some(id);
    }
    Some(rest)
}

pub fn avatar_user_key(user_id: &str) -> String {
    format!("avatars/users/{user_id}/{}.webp", new_media_version())
}

pub fn avatar_channel_key(channel_id: &str) -> String {
    format!("avatars/channels/{channel_id}/{}.webp", new_media_version())
}

pub fn banner_user_key(user_id: &str) -> String {
    format!("banners/users/{user_id}/{}.webp", new_media_version())
}

pub fn attachment_dm_key(user_id: &str, recipient_id: &str, filename: &str) -> String {
    let conv = dm_conversation_id(user_id, recipient_id);
    format!("attachments/dm/{conv}/{filename}")
}

pub fn attachment_group_key(channel_id: &str, filename: &str) -> String {
    format!("attachments/groups/group_{channel_id}/{filename}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvatarKind {
    User { user_id: String },
    Channel { channel_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicMediaKind {
    UserBanner { user_id: String },
}

pub fn avatar_key_parts(path: &str) -> Option<AvatarKind> {
    let normalized = normalize_storage_key(path);
    if let Some(rest) = normalized.strip_prefix("avatars/users/") {
        let id = parse_owned_media_id(rest)?;
        if !is_object_id_hex(id) {
            return None;
        }
        return Some(AvatarKind::User {
            user_id: id.to_string(),
        });
    }
    if let Some(rest) = normalized.strip_prefix("avatars/channels/") {
        let id = parse_owned_media_id(rest)?;
        if !is_object_id_hex(id) {
            return None;
        }
        return Some(AvatarKind::Channel {
            channel_id: id.to_string(),
        });
    }
    None
}

pub fn is_avatar_key(path: &str) -> bool {
    avatar_key_parts(path).is_some()
}

pub fn avatar_key_owned_by_user(path: &str, user_id: &str) -> bool {
    matches!(
        avatar_key_parts(path),
        Some(AvatarKind::User { user_id: id }) if id == user_id
    )
}

pub fn avatar_key_owned_by_channel(path: &str, channel_id: &str) -> bool {
    matches!(
        avatar_key_parts(path),
        Some(AvatarKind::Channel { channel_id: id }) if id == channel_id
    )
}

pub fn public_media_key_parts(path: &str) -> Option<PublicMediaKind> {
    let normalized = normalize_storage_key(path);
    if let Some(rest) = normalized.strip_prefix("banners/users/") {
        let id = parse_owned_media_id(rest)?;
        if !is_object_id_hex(id) {
            return None;
        }
        return Some(PublicMediaKind::UserBanner {
            user_id: id.to_string(),
        });
    }
    None
}

pub fn is_public_media_key(path: &str) -> bool {
    public_media_key_parts(path).is_some()
}

pub fn public_media_key_owned_by_user(path: &str, user_id: &str) -> bool {
    matches!(
        public_media_key_parts(path),
        Some(PublicMediaKind::UserBanner { user_id: id }) if id == user_id
    )
}

pub fn is_attachment_key(path: &str) -> bool {
    attachment_key_parts(path).is_some()
}

fn is_object_id_hex(value: &str) -> bool {
    value.len() == 24 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn attachment_filename_is_valid(filename: &str) -> bool {
    if let Some(stem) = filename.strip_suffix(".thumb.webp") {
        return uuid::Uuid::parse_str(stem).is_ok();
    }
    let Some((name, ext)) = filename.rsplit_once('.') else {
        return false;
    };
    if ext.is_empty() || ext.len() > 8 || ext.contains('/') || ext.contains("..") {
        return false;
    }
    if !ALLOWED_ATTACHMENT_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()) {
        return false;
    }
    uuid::Uuid::parse_str(name).is_ok()
}

pub fn attachment_thumb_key(full_key: &str) -> Option<String> {
    let normalized = normalize_storage_key(full_key);
    if normalized.ends_with(".thumb.webp") {
        return None;
    }
    if !normalized.ends_with(".webp") {
        return None;
    }
    let stem = normalized.trim_end_matches(".webp");
    Some(format!("{stem}.thumb.webp"))
}

pub fn attachment_key_parts(path: &str) -> Option<(String, String)> {
    let normalized = normalize_storage_key(path);
    if normalized.starts_with("attachments/dm/") {
        let rest = normalized.strip_prefix("attachments/dm/")?;
        let (conv, filename) = rest.split_once('/')?;
        if !conv.starts_with("conv_") {
            return None;
        }
        let ids = conv.strip_prefix("conv_")?;
        let (a, b) = ids.split_once('_')?;
        if !is_object_id_hex(a) || !is_object_id_hex(b) || !attachment_filename_is_valid(filename) {
            return None;
        }
        return Some(("dm".to_string(), conv.to_string()));
    }

    if normalized.starts_with("attachments/groups/group_") {
        let rest = normalized.strip_prefix("attachments/groups/group_")?;
        let (channel_id, filename) = rest.split_once('/')?;
        if !is_object_id_hex(channel_id) || !attachment_filename_is_valid(filename) {
            return None;
        }
        return Some(("channel".to_string(), channel_id.to_string()));
    }

    None
}

pub fn attachment_path_matches_dm(path: &str, user_id: &str, contact_id: &str) -> bool {
    let Some((kind, conv)) = attachment_key_parts(path) else {
        return false;
    };
    kind == "dm" && conv == dm_conversation_id(user_id, contact_id)
}

pub fn attachment_path_matches_channel(path: &str, channel_id: &str) -> bool {
    let Some((kind, id)) = attachment_key_parts(path) else {
        return false;
    };
    kind == "channel" && id == channel_id
}

pub fn is_logical_message_path(path: &str) -> bool {
    is_attachment_key(path)
}

/// Keys Mongo may store for the same object: logical path, slash-prefixed, or CDN-wrapped.
pub fn attachment_stored_url_aliases(path: &str, cdn_base: &str) -> Vec<String> {
    let path = normalize_storage_key(path);
    if path.is_empty() {
        return Vec::new();
    }
    let mut aliases = vec![path.clone(), format!("/{path}")];
    let base = cdn_base.trim().trim_end_matches('/');
    if base.starts_with("https://") || base.starts_with("http://") {
        aliases.push(format!("{base}/{path}"));
    }
    aliases
}

fn attachment_is_inline_media(ext: &str) -> bool {
    matches!(
        ext,
        "webp"
            | "jpg"
            | "jpeg"
            | "png"
            | "webm"
            | "ogg"
            | "wav"
            | "mp3"
            | "aac"
            | "mp4"
            | "m4a"
            | "mov"
    )
}

pub fn attachment_prefers_download(path: &str) -> bool {
    let normalized = normalize_storage_key(path);
    if normalized.ends_with(".thumb.webp") {
        return false;
    }
    let Some(ext) = normalized.rsplit('.').next() else {
        return true;
    };
    !attachment_is_inline_media(&ext.to_ascii_lowercase())
}

pub fn content_type_for_ext(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "webp" => "image/webp",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "webm" => "audio/webm",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "mp3" => "audio/mpeg",
        "aac" => "audio/aac",
        "mp4" => "video/mp4",
        "m4a" => "audio/mp4",
        "mov" => "video/quicktime",
        "heic" => "image/heic",
        "heif" => "image/heif",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_pref_is_non_media() {
        assert!(attachment_prefers_download("attachments/dm/conv_a/x.pdf"));
        assert!(attachment_prefers_download("attachments/dm/conv_a/x.csv"));
        assert!(attachment_prefers_download("attachments/dm/conv_a/x.heic"));
        assert!(!attachment_prefers_download("attachments/dm/conv_a/x.webp"));
        assert!(!attachment_prefers_download("attachments/dm/conv_a/x.mp3"));
        assert!(!attachment_prefers_download("attachments/dm/conv_a/x.mp4"));
        assert!(!attachment_prefers_download(
            "attachments/dm/conv_a/x.thumb.webp"
        ));
    }
}
