// users.rs
// Routing użytkowników.
// Zakres:
//  - status użytkownika i ustawienia prywatności obecności
//  - wrap JWT jak inne prywatne ścieżki
// Logika w controllers/users.rs, tu tylko routing.
// Przy zmianach: controllers/users.rs.

use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::users::{get_presence_settings, get_user_status, update_presence_settings};
use crate::middlewares::auth::{require_active_account, verify_token};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/presence-settings")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_presence_settings))
            .route(web::put().to(update_presence_settings)),
    );
    cfg.service(
        web::resource("/status/{userId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_status)),
    );
    cfg.service(
        web::resource("/{userId}/status")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_status)),
    );
}
