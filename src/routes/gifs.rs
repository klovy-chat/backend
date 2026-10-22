// gifs.rs
// Routing GIF proxy.
// Zakres:
//  - search query
//  - search query; nie loguj pełnego query jeśli PII
// Nie loguj pełnego query jeśli PII.
// Przy zmianach: controllers/gifs.rs.

use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::gifs::{search_gifs, trending_gifs};
use crate::middlewares::auth::{log_suspicious_activity, require_active_account, verify_token};
use crate::utils::ratelimit::discovery_limiter;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .wrap(from_fn(log_suspicious_activity("gif-trending")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(trending_gifs)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(log_suspicious_activity("gif-trending")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(trending_gifs)),
    );
    cfg.service(
        web::resource("/trending")
            .wrap(from_fn(log_suspicious_activity("gif-trending")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(trending_gifs)),
    );
    cfg.service(
        web::resource("/trends")
            .wrap(from_fn(log_suspicious_activity("gif-trending")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(trending_gifs)),
    );
    cfg.service(
        web::resource("/search")
            .wrap(from_fn(log_suspicious_activity("gif-search")))
            .wrap(from_fn(discovery_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(search_gifs)),
    );
}
