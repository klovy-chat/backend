// attachments.rs
// Reguły załączników czatu (rozmiar, liczba, typy).
// Zakres:
//  - kontrakt z FE constants/upload.ts
//  - rozmiar, liczba, typy — kontrakt z constants/upload.ts
// Zmiana bez frontu = UX 413.
// Przy zmianach: messages/access.rs, upload.rs.

use actix_web::HttpRequest;
use serde_json::json;

use crate::model::audit::AuditLog;
use crate::utils::db::get_db;
use crate::utils::ip::client_ip_from_http_request;

pub async fn log_attachment_upload(
    req: &HttpRequest,
    user_id: &str,
    path: &str,
    context_type: &str,
    context_id: &str,
    file_size: u64,
) {
    let client_ip = client_ip_from_http_request(req);
    let db = get_db();
    if let Err(e) = AuditLog::insert(
        &db,
        "attachment.upload",
        Some("attachment"),
        Some(path),
        json!({
            "userId": user_id,
            "contextType": context_type,
            "contextId": context_id,
            "fileSize": file_size,
        }),
        Some(&client_ip),
        Some(user_id),
    )
    .await
    {
        log::warn!("Failed to write attachment upload audit log ({path}): {e}");
    }
}
