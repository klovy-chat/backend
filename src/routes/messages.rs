// messages.rs
// Routing wiadomości i uploadu.
// Zakres:
//  - page, pin, search, files
//  - page, pin, search, files — upload ma inny limit body
// Upload ma inny limit body niż JSON.
// Przy zmianach: controllers/messages.rs, upload.rs.

use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::messages::{
    delete_message, edit_message, get_messages, get_pinned_messages, link_preview, pin_message,
    search_messages, unpin_message, upload_file,
};
use crate::middlewares::auth::{log_suspicious_activity, require_active_account, verify_token};
use crate::utils::ratelimit::{discovery_limiter, pin_message_limiter, upload_limiter};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .wrap(from_fn(log_suspicious_activity("get-messages")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(get_messages)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(log_suspicious_activity("get-messages")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(get_messages)),
    );
    cfg.service(
        web::resource("/list")
            .wrap(from_fn(log_suspicious_activity("get-messages")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(get_messages)),
    );
    cfg.service(
        web::resource("/get-messages")
            .wrap(from_fn(log_suspicious_activity("get-messages")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(get_messages)),
    );
    cfg.service(
        web::resource("/pinned")
            .wrap(from_fn(log_suspicious_activity("get-pinned-messages")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(get_pinned_messages)),
    );
    cfg.service(
        web::resource("/search")
            .wrap(from_fn(log_suspicious_activity("search-messages")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(discovery_limiter))
            .route(web::post().to(search_messages)),
    );
    cfg.service(
        web::resource("/upload-file")
            .wrap(from_fn(log_suspicious_activity("file-upload")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(upload_limiter))
            .route(web::post().to(upload_file)),
    );
    cfg.service(
        web::resource("/upload")
            .wrap(from_fn(log_suspicious_activity("file-upload")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(upload_limiter))
            .route(web::post().to(upload_file)),
    );
    cfg.service(
        web::resource("/file")
            .wrap(from_fn(log_suspicious_activity("file-upload")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(upload_limiter))
            .route(web::post().to(upload_file)),
    );
    cfg.service(
        web::resource("/link-preview")
            .wrap(from_fn(log_suspicious_activity("link-preview")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(link_preview)),
    );
    cfg.service(
        web::resource("/{messageId}/pin")
            .wrap(from_fn(log_suspicious_activity("pin-message")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(pin_message_limiter))
            .route(web::post().to(pin_message))
            .route(web::delete().to(unpin_message)),
    );
    cfg.service(
        web::resource("/{messageId}")
            .wrap(from_fn(log_suspicious_activity("edit-delete-message")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::put().to(edit_message))
            .route(web::delete().to(delete_message)),
    );
}
