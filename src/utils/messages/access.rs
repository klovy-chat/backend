// access.rs
// Czy ten user może wysłać ten plik/treść (size, SHA pending, membership).
// Zakres:
//  - skip R2 HEAD na non-image gdy size już sprawdzony
//  - size, SHA pending, membership przed send/upload
// Nowe ograniczenie załącznika: tu + attachments.rs + FE.
// Przy zmianach: ws send, upload.rs.

use mongodb::bson::oid::ObjectId;
use mongodb::Database;

use crate::model::uploads::PendingUpload;
use crate::model::messages::Message;
use crate::model::scan::ScanStatus;
use crate::utils::access::members::{
    require_channel_message_access, require_dm_access,
};
use crate::utils::friends::try_are_friends;
use crate::utils::storage::{
    attachment_path_matches_channel, attachment_path_matches_dm, attachment_stored_url_aliases,
    cdn_public_base_url, is_attachment_key, is_logical_message_path, is_safe_key, storage,
};
use crate::utils::validators::url::is_allowed_external_media_url;

#[derive(Debug, Clone)]
pub enum QuoteContext {
    Dm { contact_id: String },
    Channel { channel_id: String },
}

#[derive(Debug, Clone)]
pub enum AttachmentSendContext {
    Dm { recipient_id: String },
    Channel { channel_id: String },
}

pub async fn validate_quote_target(
    db: &Database,
    user_id: &str,
    quoted_message_id: &str,
    context: QuoteContext,
) -> Result<Option<Message>, ()> {
    validate_quote_target_with_access(db, user_id, quoted_message_id, context, false).await
}

pub async fn validate_quote_target_with_access(
    db: &Database,
    user_id: &str,
    quoted_message_id: &str,
    context: QuoteContext,
    access_already_checked: bool,
) -> Result<Option<Message>, ()> {
    let Ok(qid) = ObjectId::parse_str(quoted_message_id) else {
        return Ok(None);
    };

    let quoted = match Message::find_by_id(db, qid).await {
        Ok(Some(m)) => m,
        Ok(None) => return Ok(None),
        Err(_) => return Err(()),
    };
    if quoted.deleted {
        return Ok(None);
    }

    match context {
        QuoteContext::Dm { contact_id } => {
            let sender = quoted.sender.to_hex();
            let recipient = quoted.recipient.map(|r| r.to_hex()).unwrap_or_default();
            let in_conv = (sender == user_id && recipient == contact_id)
                || (sender == contact_id && recipient == user_id);
            if !in_conv || quoted.recipient.is_none() {
                return Ok(None);
            }
            if !access_already_checked {
                match require_dm_access(db, user_id, &contact_id).await {
                    Ok(()) => {}
                    Err(crate::utils::access::members::AccessDeniedReason::Unavailable) => {
                        return Err(());
                    }
                    Err(_) => return Ok(None),
                }
            }
            Ok(Some(quoted))
        }
        QuoteContext::Channel { channel_id } => {
            if quoted.channel.map(|c| c.to_hex()) != Some(channel_id.clone()) {
                return Ok(None);
            }
            if !access_already_checked {
                match require_channel_message_access(db, &channel_id, user_id).await {
                    Ok(_) => {}
                    Err(crate::utils::access::members::AccessDeniedReason::Unavailable) => {
                        return Err(());
                    }
                    Err(_) => return Ok(None),
                }
            }
            Ok(Some(quoted))
        }
    }
}

pub async fn try_can_mark_message_as_read(
    db: &Database,
    user_id: &str,
    msg: &Message,
) -> Result<bool, ()> {
    if msg.deleted || msg.read || msg.channel.is_some() {
        return Ok(false);
    }
    let Some(recipient) = msg.recipient else {
        return Ok(false);
    };
    if recipient.to_hex() != user_id {
        return Ok(false);
    }
    try_are_friends(db, user_id, &msg.sender.to_hex()).await
}

fn attachment_matches_send_context(
    path: &str,
    user_id: &str,
    context: &AttachmentSendContext,
) -> bool {
    match context {
        AttachmentSendContext::Dm { recipient_id } => {
            attachment_path_matches_dm(path, user_id, recipient_id)
        }
        AttachmentSendContext::Channel { channel_id } => {
            attachment_path_matches_channel(path, channel_id)
        }
    }
}

fn normalize_cdn_host(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.strip_prefix("www.")
        .unwrap_or(&host)
        .trim_end_matches('.')
        .to_string()
}

fn our_cdn_hosts(cdn_base: &str) -> Vec<String> {
    let mut hosts = vec!["cdn.klovy.chat".to_string()];
    if let Ok(parsed) = reqwest::Url::parse(cdn_base.trim()) {
        if let Some(host) = parsed.host_str() {
            let host = normalize_cdn_host(host);
            if !host.is_empty() && !hosts.iter().any(|h| h == &host) {
                hosts.push(host);
            }
        }
    }
    hosts
}

/// Strip CDN wrapper / quarantine prefix. Own-CDN attachment URLs become logical keys
/// so they cannot skip the pending+ClamAV path by posing as external https.
pub fn canonicalize_message_file_url(raw: &str, cdn_base: &str) -> Option<String> {
    let normalized = raw.trim().replace('\\', "/");
    if normalized.is_empty() {
        return Some(String::new());
    }
    if normalized.contains("..") || normalized.contains('@') {
        return None;
    }
    let without_slash = normalized.trim_start_matches('/');
    if without_slash.starts_with("quarantine/") {
        return None;
    }

    if normalized.len() >= 8 && normalized[..8].eq_ignore_ascii_case("https://") {
        let parsed = reqwest::Url::parse(&normalized).ok()?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return None;
        }
        let host = normalize_cdn_host(parsed.host_str()?);
        let path = parsed.path().trim_start_matches('/');
        if path.starts_with("quarantine/") || path.contains("..") {
            return None;
        }
        if our_cdn_hosts(cdn_base).iter().any(|h| h == &host) {
            if is_attachment_key(path) {
                return Some(path.to_string());
            }
            return None;
        }
        if is_allowed_external_media_url(&normalized) {
            return Some(normalized);
        }
        return None;
    }

    if (normalized.len() >= 7 && normalized[..7].eq_ignore_ascii_case("http://"))
        || normalized.starts_with("//")
    {
        return None;
    }

    if is_safe_key(without_slash) && is_attachment_key(without_slash) {
        return Some(without_slash.to_string());
    }
    None
}

pub fn user_owns_message_file_url(user_id: &str, file_url: &str) -> bool {
    if file_url.trim().is_empty() {
        return true;
    }
    if user_id.is_empty() {
        return false;
    }
    canonicalize_message_file_url(file_url, &cdn_public_base_url()).is_some()
}

pub fn validate_message_file_url(user_id: &str, file_url: &Option<String>) -> bool {
    match file_url {
        None => true,
        Some(url) if url.trim().is_empty() => true,
        Some(url) => user_owns_message_file_url(user_id, url),
    }
}

pub async fn cleanup_attachment_if_unreferenced(
    db: &Database,
    file_url: Option<&str>,
) -> Result<(), String> {
    let Some(url) = file_url else {
        return Ok(());
    };
    let Some(path) = canonicalize_message_file_url(url, &cdn_public_base_url()) else {
        return Ok(());
    };
    if path.is_empty() || path.starts_with("https://") || !is_attachment_key(&path) {
        return Ok(());
    }

    let aliases = attachment_stored_url_aliases(&path, &cdn_public_base_url());
    let count = Message::collection(db)
        .count_documents(mongodb::bson::doc! {
            "deleted": { "$ne": true },
            "fileUrl": { "$in": aliases },
        })
        .await
        .map_err(|e| format!("count attachment references for {path}: {e}"))?;

    if count == 0 {
        let owner = find_attachment_uploader(db, &path).await?;
        let size = storage()
            .head_attachment_content_length(&path)
            .await
            .map_err(|e| format!("read attachment size for {path}: {e}"))?
            .unwrap_or(0);
        let thumb_bytes = if let Some(thumb) = crate::utils::storage::attachment_thumb_key(&path)
        {
            storage()
                .head_attachment_content_length(&thumb)
                .await
                .map_err(|e| format!("read thumbnail size for {thumb}: {e}"))?
                .unwrap_or(0)
        } else {
            0
        };

        storage()
            .delete_attachment_key(&path)
            .await
            .map_err(|e| format!("delete attachment {path}: {e}"))?;

        if let Some(user_id) = owner {
            let measured = size.saturating_add(thumb_bytes);
            if measured > 0 {
                crate::model::storage_usage::UserStorageUsage::adjust(
                    db,
                    user_id,
                    -(measured as i64),
                )
                .await
                .map_err(|e| format!("update storage usage for {user_id}: {e}"))?;
            }
        }
    }
    Ok(())
}

async fn find_attachment_uploader(
    db: &Database,
    path: &str,
) -> Result<Option<ObjectId>, String> {
    if let Some(pending) = PendingUpload::collection(db)
        .find_one(mongodb::bson::doc! { "filePath": path })
        .await
        .map_err(|e| format!("find pending upload for {path}: {e}"))?
    {
        return Ok(Some(pending.user_id));
    }

    let aliases = attachment_stored_url_aliases(path, &cdn_public_base_url());
    let message = Message::collection(db)
        .find_one(mongodb::bson::doc! {
            "fileUrl": { "$in": aliases },
        })
        .await
        .map_err(|e| format!("find message uploader for {path}: {e}"))?;

    Ok(message.map(|message| message.sender))
}

async fn attachment_stored_size_is_valid(
    path: &str,
    claimed_size: Option<u64>,
    pending_size: Option<u64>,
) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("");
    let is_image = matches!(
        ext.to_ascii_lowercase().as_str(),
        "jpg" | "jpeg" | "png" | "webp"
    );

    if !is_image {
        if let (Some(claimed), Some(expected)) = (claimed_size, pending_size) {
            if expected > 0
                && claimed == expected
                && expected <= crate::utils::upload::MAX_ATTACHMENT_BYTES
            {
                return true;
            }
        }
    }

    let actual = match storage().head_attachment_content_length(path).await {
        Ok(Some(len)) => len,
        Ok(None) => {
            log::warn!("attachment size check: object missing path={path}");
            return false;
        }
        Err(err) => {
            log::warn!("attachment size check: HEAD failed path={path}: {err}");
            return false;
        }
    };

    let max_bytes = if is_image {
        crate::utils::upload::MAX_IMAGE_ATTACHMENT_BYTES
    } else {
        crate::utils::upload::MAX_ATTACHMENT_BYTES
    };
    if actual > max_bytes {
        return false;
    }

    if let Some(expected) = pending_size {
        if expected > 0 {

            if is_image {
                if expected < actual {
                    return false;
                }
            } else if actual != expected {
                return false;
            }
        }
    }

    let Some(claimed) = claimed_size else {
        return true;
    };

    if is_image {
        return true;
    }

    if actual > claimed {
        return false;
    }

    actual == claimed
}

pub async fn claim_pending_upload(user_id: &str, file_url: &Option<String>) {
    let Some(url) = file_url else {
        return;
    };
    let Some(path) = canonicalize_message_file_url(url, &cdn_public_base_url()) else {
        return;
    };
    if path.is_empty() || path.starts_with("https://") {
        return;
    }
    if !is_logical_message_path(&path) {
        return;
    }
    let Ok(user_oid) = ObjectId::parse_str(user_id) else {
        return;
    };
    let db = crate::utils::db::get_db();
    let _ = PendingUpload::claim_by_path(&db, user_oid, &path).await;
}

pub async fn validate_message_attachment(
    db: &Database,
    user_id: &str,
    file_url: &Option<String>,
    file_size: Option<u64>,
    send_context: Option<AttachmentSendContext>,
) -> Result<Option<String>, ()> {
    let canonical = match file_url {
        None => return Ok(None),
        Some(url) if url.trim().is_empty() => return Ok(None),
        Some(url) => canonicalize_message_file_url(url, &cdn_public_base_url()).ok_or_else(|| {
            log::warn!(
                "attachment rejected INVALID_FILE reason=canonical user={user_id} file={file_url:?}"
            );
        })?,
    };
    if canonical.is_empty() {
        return Ok(None);
    }

    if canonical.starts_with("https://") {
        if !is_allowed_external_media_url(&canonical) {
            log::warn!("attachment rejected INVALID_FILE reason=external user={user_id}");
            return Err(());
        }
        return Ok(Some(canonical));
    }

    if file_size
        .map(|size| size > crate::utils::upload::MAX_ATTACHMENT_BYTES)
        .unwrap_or(false)
    {
        let ext = canonical.rsplit('.').next().unwrap_or("");
        let is_image = matches!(
            ext.to_ascii_lowercase().as_str(),
            "jpg" | "jpeg" | "png" | "webp"
        );
        if !is_image {
            return Err(());
        }
    }

    let path = canonical;
    if !is_attachment_key(&path) {
        log::warn!("attachment rejected INVALID_FILE reason=not_attachment_key path={path}");
        return Err(());
    }

    let Some(send_context) = send_context else {
        log::warn!("attachment rejected INVALID_FILE reason=no_send_context path={path}");
        return Err(());
    };
    if !attachment_matches_send_context(&path, user_id, &send_context) {
        log::warn!("attachment rejected INVALID_FILE reason=context_mismatch path={path}");
        return Err(());
    }

    let Ok(user_oid) = ObjectId::parse_str(user_id) else {
        return Err(());
    };

    let pending = match PendingUpload::find_for_user_and_path(db, user_oid, &path).await {
        Ok(Some(entry)) => entry,
        _ => {
            log::warn!("attachment rejected INVALID_FILE reason=no_pending path={path}");
            return Err(());
        }
    };

    let context_ok = match send_context {
        AttachmentSendContext::Dm { recipient_id } => {
            pending.context_type == "dm" && pending.context_id == recipient_id
        }
        AttachmentSendContext::Channel { channel_id } => {
            pending.context_type == "channel" && pending.context_id == channel_id
        }
    };
    if !context_ok {
        log::warn!("attachment rejected INVALID_FILE reason=pending_context path={path}");
        return Err(());
    }

    if pending.file_hash.is_empty() {
        log::warn!("attachment rejected INVALID_FILE reason=empty_hash path={path}");
        return Err(());
    }

    if !pending.scan_status.allows_send() {
        log::warn!("attachment rejected INVALID_FILE reason=scan_blocked path={path}");
        return Err(());
    }

    if !attachment_stored_size_is_valid(&path, file_size, Some(pending.file_size)).await {
        log::warn!(
            "attachment rejected INVALID_FILE reason=size path={path} claimed={file_size:?} pending={}",
            pending.file_size
        );
        return Err(());
    }

    Ok(Some(path))
}

pub async fn scan_status_for_attachment(
    db: &Database,
    user_id: &str,
    file_url: &Option<String>,
) -> ScanStatus {
    let Some(url) = file_url else {
        return ScanStatus::Clean;
    };
    let Some(canonical) = canonicalize_message_file_url(url, &cdn_public_base_url()) else {
        return ScanStatus::Pending;
    };
    if canonical.is_empty() {
        return ScanStatus::Clean;
    }
    if canonical.starts_with("https://") {
        return ScanStatus::Clean;
    }
    if !is_attachment_key(&canonical) {
        return ScanStatus::Pending;
    }
    let Ok(user_oid) = ObjectId::parse_str(user_id) else {
        return ScanStatus::Pending;
    };
    match PendingUpload::find_for_user_and_path(db, user_oid, &canonical).await {
        Ok(Some(pending)) => pending.scan_status,
        _ => ScanStatus::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "attachments/dm/conv_aaaaaaaaaaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbb/550e8400-e29b-41d4-a716-446655440000.webp";

    #[test]
    fn cdn_url_becomes_logical_key() {
        let cdn = "https://cdn.klovy.chat";
        let wrapped = format!("{cdn}/{KEY}");
        assert_eq!(
            canonicalize_message_file_url(&wrapped, cdn).as_deref(),
            Some(KEY)
        );
    }

    #[test]
    fn quarantine_prefix_is_rejected() {
        let cdn = "https://cdn.klovy.chat";
        assert!(canonicalize_message_file_url(&format!("quarantine/{KEY}"), cdn).is_none());
        assert!(
            canonicalize_message_file_url(&format!("{cdn}/quarantine/{KEY}"), cdn).is_none()
        );
    }

    #[test]
    fn random_https_png_is_rejected() {
        assert!(canonicalize_message_file_url(
            "https://evil.example/payload.png",
            "https://cdn.klovy.chat"
        )
        .is_none());
    }

    #[test]
    fn giphy_stays_external() {
        let url = "https://media.giphy.com/media/abc/giphy.gif";
        assert_eq!(
            canonicalize_message_file_url(url, "https://cdn.klovy.chat").as_deref(),
            Some(url)
        );
    }

    #[test]
    fn www_cdn_host_becomes_logical_key() {
        let cdn = "https://cdn.klovy.chat";
        let wrapped = format!("https://www.cdn.klovy.chat/{KEY}");
        assert_eq!(
            canonicalize_message_file_url(&wrapped, cdn).as_deref(),
            Some(KEY)
        );
    }

    #[test]
    fn own_cdn_is_not_external_skip_scan() {
        let cdn = "https://cdn.klovy.chat";
        assert_eq!(
            canonicalize_message_file_url(&format!("{cdn}/{KEY}"), cdn).as_deref(),
            Some(KEY)
        );
        assert!(crate::utils::validators::url::is_allowed_external_media_url(
            &format!("{cdn}/{KEY}")
        ) == false);
    }
}
