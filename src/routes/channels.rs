// channels.rs
// Routing kanałów i moderacji.
// Zakres:
//  - CRUD, members
//  - CRUD i moderacja; admin sprawdzany w kontrolerze
// Część akcji tylko admin — sprawdzane w kontrolerze.
// Przy zmianach: controllers/channels.rs.

use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::channels::{
    add_user_to_channel, ban_channel_member, create_channel, delete_channel, delete_channel_avatar,
    get_channel_details, get_channel_messages, get_user_channels, kick_channel_member,
    leave_channel, mute_channel_member, rename_channel, report_channel, toggle_channel_mute,
    unban_channel_member, unmute_channel_member, update_channel_chat_lock, update_channel_slowmode,
    upload_channel_avatar,
};
use crate::controllers::invites::{create_invite, delete_invite, list_invites};
use crate::middlewares::auth::{require_active_account, verify_token};
use crate::utils::ratelimit::{channel_report_limiter, upload_limiter};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/{channelId}/invite-link")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(create_invite)),
    );
    cfg.service(
        web::resource("/{channelId}/invite")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(create_invite)),
    );
    cfg.service(
        web::resource("/{channelId}/invites")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(list_invites))
            .route(web::post().to(create_invite)),
    );
    cfg.service(
        web::resource("/{channelId}/invites/{inviteId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::delete().to(delete_invite)),
    );
    cfg.service(
        web::resource("/{channelId}/details")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_channel_details)),
    );
    cfg.service(
        web::resource("/{channelId}/mute")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(toggle_channel_mute)),
    );
    cfg.service(
        web::resource("/{channelId}/report")
            .wrap(from_fn(channel_report_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(report_channel)),
    );
    cfg.service(
        web::resource("/{channelId}/kick")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(kick_channel_member)),
    );
    cfg.service(
        web::resource("/{channelId}/ban")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(ban_channel_member)),
    );
    cfg.service(
        web::resource("/{channelId}/unban")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(unban_channel_member)),
    );
    cfg.service(
        web::resource("/{channelId}/mute-member")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(mute_channel_member)),
    );
    cfg.service(
        web::resource("/{channelId}/unmute-member")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(unmute_channel_member)),
    );
    cfg.service(
        web::resource("/{channelId}/slowmode")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::patch().to(update_channel_slowmode)),
    );
    cfg.service(
        web::resource("/{channelId}/chat-lock")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::patch().to(update_channel_chat_lock)),
    );
    cfg.service(
        web::resource("/{channelId}/name")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::patch().to(rename_channel)),
    );
    cfg.service(
        web::resource("/{channelId}/avatar")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(upload_limiter))
            .route(web::post().to(upload_channel_avatar))
            .route(web::delete().to(delete_channel_avatar)),
    );
    cfg.service(
        web::resource("")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_channels))
            .route(web::post().to(create_channel)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_channels))
            .route(web::post().to(create_channel)),
    );
    cfg.service(
        web::resource("/list")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_channels)),
    );
    cfg.service(
        web::resource("/create")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(create_channel)),
    );
    cfg.service(
        web::resource("/create-channel")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(create_channel)),
    );
    cfg.service(
        web::resource("/get-user-channels")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_channels)),
    );
    cfg.service(
        web::resource("/user-channels")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_channels)),
    );
    cfg.service(
        web::resource("/get-channel-messages/{channelId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_channel_messages)),
    );
    cfg.service(
        web::resource("/messages/{channelId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_channel_messages)),
    );
    cfg.service(
        web::resource("/{channelId}/messages")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_channel_messages)),
    );
    cfg.service(
        web::resource("/leave/{channelId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(leave_channel)),
    );
    cfg.service(
        web::resource("/{channelId}/leave")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(leave_channel)),
    );
    cfg.service(
        web::resource("/add-user/{channelId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(add_user_to_channel)),
    );
    cfg.service(
        web::resource("/delete/{channelId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::delete().to(delete_channel)),
    );
    cfg.service(
        web::resource("/{channelId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::delete().to(delete_channel)),
    );
}
