// friends.rs
// Routing znajomych.
// Zakres:
//  - invite/accept/block
//  - invite/accept/block — idempotencja accept w kontrolerze
// Idempotentne accept: kontroler.
// Przy zmianach: controllers/friends.rs.

use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::friends::{
    accept_friend_request, cancel_friend_request, check_friendship, get_friends,
    get_received_requests, get_sent_requests, reject_friend_request, remove_friend,
    send_friend_request,
};
use crate::middlewares::auth::{require_active_account, verify_token};
use crate::utils::ratelimit::{discovery_limiter, friend_action_limiter, friend_request_limiter};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .wrap(from_fn(friend_request_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_friends))
            .route(web::post().to(send_friend_request)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(friend_request_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_friends))
            .route(web::post().to(send_friend_request)),
    );
    cfg.service(
        web::resource("/send")
            .wrap(from_fn(friend_request_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(send_friend_request)),
    );
    cfg.service(
        web::resource("/request")
            .wrap(from_fn(friend_request_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(send_friend_request)),
    );
    cfg.service(
        web::resource("/requests")
            .wrap(from_fn(friend_request_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(send_friend_request)),
    );
    cfg.service(
        web::resource("/received")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_received_requests)),
    );
    cfg.service(
        web::resource("/sent")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_sent_requests)),
    );
    cfg.service(
        web::resource("/list")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_friends)),
    );
    cfg.service(
        web::resource("/requests/received")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_received_requests)),
    );
    cfg.service(
        web::resource("/requests/sent")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_sent_requests)),
    );
    cfg.service(
        web::resource("/status/{otherUserId}")
            .wrap(from_fn(discovery_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(check_friendship)),
    );
    cfg.service(
        web::resource("/{requestId}/accept")
            .wrap(from_fn(friend_action_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(accept_friend_request)),
    );
    cfg.service(
        web::resource("/{requestId}/reject")
            .wrap(from_fn(friend_action_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(reject_friend_request)),
    );
    cfg.service(
        web::resource("/{requestId}/cancel")
            .wrap(from_fn(friend_action_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(cancel_friend_request)),
    );
    cfg.service(
        web::resource("/{friendUserId}")
            .wrap(from_fn(friend_action_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::delete().to(remove_friend)),
    );
}
