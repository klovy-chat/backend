use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::admin::get_admin_access;
use crate::middlewares::admin::require_admin;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/me")
            .wrap(from_fn(require_admin))
            .route(web::get().to(get_admin_access)),
    );
}