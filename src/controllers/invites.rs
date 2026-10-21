// invites.rs
// Tworzenie i konsumowanie kodów zaproszeń.
// Zakres:
//  - already-member refund use
//  - member write landed = nie release_use
// FRONTEND_URL do linku w odpowiedzi.
// Przy zmianach: model/invites.rs, pages/Invite.tsx.

use actix_web::{web, HttpRequest, HttpResponse};
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth::request_user_id;
use crate::model::channels::Channel;
use crate::model::invites::{Invite, MAX_INVITE_USE_LIMIT};
use crate::model::users::User;
use crate::utils::channel::{is_channel_banned, is_channel_member, serialize_channel_list_item};
use crate::utils::db::get_db;
use crate::utils::user::json::resolve_display_name;
use crate::ws::registry::{channel_recipient_ids, emit_to_user, emit_to_users};

#[derive(Debug, Deserialize, Default)]
struct CreateInviteBody {

    #[serde(rename = "maxUses", default)]
    max_uses: Option<u32>,
}

fn db_error(context: &str, e: impl std::fmt::Display) -> HttpResponse {
    log::error!("{context}: {e}");
    HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" }))
}

fn db_error_retryable(context: &str, e: impl std::fmt::Display) -> HttpResponse {
    log::error!("{context}: {e}");
    HttpResponse::InternalServerError().json(json!({
        "error": "Internal Server Error",
        "retryable": true,
    }))
}

async fn refund_invite_use(
    db: &mongodb::Database,
    invite_id: &str,
    reservation_id: &str,
) -> Result<(), HttpResponse> {
    for attempt in 0..2 {
        match Invite::release_use(db, invite_id, reservation_id).await {
            Ok(()) => return Ok(()),
            Err(error) if attempt == 0 => {
                log::warn!("Invite-use refund attempt failed for {invite_id}: {error}");
            }
            Err(error) => {
                log::error!("Failed to refund invite use for {invite_id}: {error}");
                return Err(HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Invite use could not be refunded",
                    "retryable": true,
                })));
            }
        }
    }
    unreachable!()
}

fn frontend_origin(req: &HttpRequest) -> String {
    let origin = if crate::utils::env::is_production() {
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://127.0.0.1:5173".to_string())
    } else {
        req.headers()
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://127.0.0.1:5173".to_string())
            })
    };
    origin.trim_end_matches('/').to_string()
}

async fn require_channel_owner(
    req: &HttpRequest,
) -> Result<(ObjectId, ObjectId), HttpResponse> {
    let user_id = request_user_id(req).unwrap_or_default();
    let channel_id = req.match_info().get("channelId").unwrap_or("");
    let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {
        return Err(HttpResponse::NotFound().json(json!({ "error": "Channel not found" })));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, channel_oid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Err(HttpResponse::NotFound().json(json!({ "error": "Channel not found" })))
        }
        Err(e) => return Err(db_error("invite: channel lookup", e)),
    };

    if channel.admin.to_hex() != user_id {
        return Err(HttpResponse::Forbidden()
            .json(json!({ "error": "Only the channel owner can manage invites" })));
    }

    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        return Err(HttpResponse::InternalServerError().json(json!({ "error": "Invalid user" })));
    };

    Ok((channel_oid, user_oid))
}

fn invite_view(invite: &Invite, origin: &str) -> serde_json::Value {
    json!({
        "inviteId": invite.invite_id,
        "url": format!("{}/invite/{}", origin, invite.invite_id),
        "useCount": invite.use_count,
        "maxUses": invite.max_uses,
        "revoked": invite.revoked || invite.used,
        "createdAt": invite.created_at.try_to_rfc3339_string().ok(),
        "expiresAt": invite
            .expires_at
            .as_ref()
            .and_then(|d| d.try_to_rfc3339_string().ok()),
    })
}

pub async fn create_invite(req: HttpRequest, body: web::Bytes) -> HttpResponse {
    let (channel_oid, user_oid) = match require_channel_owner(&req).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let parsed: CreateInviteBody = if body.is_empty() {
        CreateInviteBody::default()
    } else {
        serde_json::from_slice(&body).unwrap_or_default()
    };

    let max_uses = match parsed.max_uses {
        None => None,
        Some(0) => None,
        Some(n) if n > MAX_INVITE_USE_LIMIT => {
            return HttpResponse::BadRequest().json(json!({
                "error": format!("Join limit must be at most {MAX_INVITE_USE_LIMIT}")
            }))
        }
        Some(n) => Some(n),
    };

    let db = get_db();
    let invite = match Invite::create(&db, channel_oid, user_oid, max_uses, None).await {
        Ok(i) => i,
        Err(e) => return db_error("create_invite: invite creation", e),
    };

    let origin = frontend_origin(&req);
    let mut view = invite_view(&invite, &origin);

    view["url"] = json!(format!("{}/invite/{}", origin, invite.invite_id));
    HttpResponse::Ok().json(view)
}

pub async fn list_invites(req: HttpRequest) -> HttpResponse {
    let (channel_oid, _user_oid) = match require_channel_owner(&req).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let db = get_db();
    let invites = match Invite::list_for_channel(&db, channel_oid).await {
        Ok(list) => list,
        Err(e) => return db_error("list_invites: lookup", e),
    };

    let origin = frontend_origin(&req);
    let items: Vec<serde_json::Value> = invites
        .iter()
        .map(|inv| invite_view(inv, &origin))
        .collect();

    HttpResponse::Ok().json(json!({ "invites": items }))
}

pub async fn delete_invite(req: HttpRequest) -> HttpResponse {
    let (channel_oid, _user_oid) = match require_channel_owner(&req).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let invite_id = req.match_info().get("inviteId").unwrap_or("");

    let db = get_db();
    match Invite::delete_for_channel(&db, invite_id, channel_oid).await {
        Ok(true) => HttpResponse::Ok().json(json!({ "success": true })),
        Ok(false) => HttpResponse::NotFound().json(json!({ "error": "Invite not found" })),
        Err(e) => db_error("delete_invite: delete", e),
    }
}

pub async fn get_invite(req: HttpRequest) -> HttpResponse {
    let invite_id = req.match_info().get("inviteId").unwrap_or("");

    let db = get_db();
    let invite = match Invite::find_by_invite_id(&db, invite_id).await {
        Ok(Some(i)) => i,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Invite not found" })),
        Err(e) => return db_error("get_invite: lookup", e),
    };

    let channel = match Channel::find_by_id(&db, invite.channel_id).await {
        Ok(c) => c,
        Err(e) => return db_error("get_invite: channel", e),
    };
    let channel_json = channel.map(|c| {
        let member_count = crate::utils::channel::channel_member_count(&c);
        json!({
            "_id": c.id.map(|o| o.to_hex()),
            "name": c.name,
            "image": c.image,
            "description": c.description,
            "memberCount": member_count,
            "createdAt": c.created_at.try_to_rfc3339_string().ok(),
        })
    });

    let inviter_json = match User::find_by_id(&db, invite.created_by).await {
        Ok(Some(user)) => Some(json!({
            "displayName": resolve_display_name(&user),
            "username": user.username,
            "image": user.image,
            "color": user.color,
        })),
        Ok(None) => None,
        Err(e) => return db_error("get_invite: inviter", e),
    };

    let expired = invite
        .expires_at
        .map(|exp| exp < DateTime::now())
        .unwrap_or(false);
    let limit_reached = invite
        .max_uses
        .map(|max| invite.use_count >= max)
        .unwrap_or(false);
    let joinable = !invite.revoked && !invite.used && !expired && !limit_reached;

    HttpResponse::Ok().json(json!({
        "invite": {
            "inviteId": invite.invite_id,
            "channelId": channel_json,
            "inviter": inviter_json,
            "useCount": invite.use_count,
            "maxUses": invite.max_uses,
            "revoked": invite.revoked || invite.used,
            "expired": expired,
            "limitReached": limit_reached,
            "joinable": joinable,
            "expiresAt": invite.expires_at.as_ref().and_then(|d| d.try_to_rfc3339_string().ok()),
        }
    }))
}

pub async fn accept_invite(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let invite_id = req.match_info().get("inviteId").unwrap_or("");

    let db = get_db();
    let invite = match Invite::find_by_invite_id(&db, invite_id).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "error": "Zaproszenie nie znalezione" }))
        }
        Err(e) => return db_error("accept_invite: invite lookup", e),
    };

    if invite.revoked || invite.used {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Zaproszenie zostało wyłączone przez właściciela kanału" }));
    }

    if let Some(exp) = invite.expires_at {
        if exp < DateTime::now() {
            return HttpResponse::BadRequest().json(json!({ "error": "Zaproszenie wygasło" }));
        }
    }

    if let Some(max) = invite.max_uses {
        if invite.use_count >= max {
            return HttpResponse::BadRequest()
                .json(json!({ "error": "Limit dołączeń dla tego zaproszenia został osiągnięty" }));
        }
    }

    let channel = match Channel::find_by_id(&db, invite.channel_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" })),
        Err(e) => return db_error("accept_invite: channel lookup", e),
    };

    if is_channel_banned(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden()
            .json(json!({ "error": "Nie masz dostępu do tego kanału" }));
    }

    let channel_id_hex = channel.id.map(|o| o.to_hex());

    if is_channel_member(&channel, Some(&user_id)) {
        return HttpResponse::Ok().json(json!({
            "success": true,
            "channelId": channel_id_hex,
            "alreadyMember": true,
        }));
    }

    let reservation_id = uuid::Uuid::new_v4().to_string();
    let consumed = match Invite::try_register_use(&db, invite_id, &reservation_id).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return HttpResponse::BadRequest().json(
                json!({ "error": "Zaproszenie zostało wyłączone, wygasło lub osiągnęło limit" }),
            )
        }
        Err(e) => {
            if let Err(response) = refund_invite_use(&db, invite_id, &reservation_id).await {
                return response;
            }
            return db_error("accept_invite: register use", e);
        }
    };

    let channel = match Channel::find_by_id(&db, consumed.channel_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            if let Err(response) = refund_invite_use(&db, invite_id, &reservation_id).await {
                return response;
            }
            return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" }));
        }
        Err(e) => {
            if let Err(response) = refund_invite_use(&db, invite_id, &reservation_id).await {
                return response;
            }
            return db_error_retryable("accept_invite: channel reload", e);
        }
    };

    if is_channel_banned(&channel, Some(&user_id)) {
        if let Err(response) = refund_invite_use(&db, invite_id, &reservation_id).await {
            return response;
        }
        return HttpResponse::Forbidden()
            .json(json!({ "error": "Nie masz dostępu do tego kanału" }));
    }

    let channel_id_hex = channel.id.map(|o| o.to_hex());

    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        if let Err(response) = refund_invite_use(&db, invite_id, &reservation_id).await {
            return response;
        }
        return HttpResponse::BadRequest().json(json!({ "error": "Użytkownik nie istnieje" }));
    };
    match User::find_by_id(&db, user_oid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            if let Err(response) = refund_invite_use(&db, invite_id, &reservation_id).await {
                return response;
            }
            return HttpResponse::BadRequest().json(json!({ "error": "Użytkownik nie istnieje" }));
        }
        Err(_) => {
            if let Err(response) = refund_invite_use(&db, invite_id, &reservation_id).await {
                return response;
            }
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    }

    let Some(channel_oid) = channel.id else {
        if let Err(response) = refund_invite_use(&db, invite_id, &reservation_id).await {
            return response;
        }
        return HttpResponse::InternalServerError().json(json!({
            "error": "Kanał nie istnieje",
            "retryable": true,
        }));
    };

    if let Err(error) = crate::model::read_state::ChannelReadState::seed_if_missing(
        &db,
        user_oid,
        channel_oid,
    )
    .await
    {
        log::error!("Failed to seed channel read state during invite acceptance: {error}");
        if let Err(response) = refund_invite_use(&db, invite_id, &reservation_id).await {
            return response;
        }
        return HttpResponse::ServiceUnavailable().json(json!({
            "error": "Temporarily unavailable",
            "retryable": true,
        }));
    }

    let res = Channel::collection(&db)
        .update_one(
            doc! { "_id": channel_oid },
            doc! { "$addToSet": { "members": user_oid }, "$set": { "updatedAt": DateTime::now() } },
        )
        .await;
    let modified = match res {
        Ok(r) => r.modified_count,
        Err(error) => {
            log::error!("Failed to add invitee to channel: {error}");
            if let Err(response) = refund_invite_use(&db, invite_id, &reservation_id).await {
                return response;
            }
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Internal Server Error", "retryable": true }));
        }
    };

    if modified == 0 {
        if let Err(response) = refund_invite_use(&db, invite_id, &reservation_id).await {
            return response;
        }
        return HttpResponse::Ok().json(json!({
            "success": true,
            "channelId": channel_id_hex,
            "alreadyMember": true,
        }));
    }

    if let Err(error) = Invite::commit_use(&db, invite_id, &reservation_id).await {
        log::error!("Failed to commit invite-use reservation for {invite_id}: {error}");
        return HttpResponse::ServiceUnavailable().json(json!({
            "error": "Membership was added, but invite usage finalization is pending",
            "retryable": true,
        }));
    }

    let channel = match Channel::find_by_id(&db, channel_oid).await {
        Ok(Some(ch)) => ch,
        Ok(None) | Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Temporarily unavailable",
                "retryable": true,
            }));
        }
    };
    match serialize_channel_list_item(&db, &channel, user_oid).await {
        Some(slim) => {
            emit_to_user(
                &user_id,
                "channel-added",
                json!({ "channelId": channel_oid.to_hex(), "channel": slim }),
            );
        }
        None => {
            emit_to_user(
                &user_id,
                "channel-added",
                json!({ "channelId": channel_oid.to_hex() }),
            );
        }
    }
    let mut peers = channel_recipient_ids(&channel);
    peers.retain(|r| r != &user_id);
    emit_to_users(
        &peers,
        "channel-member-joined",
        json!({
            "channelId": channel_oid.to_hex(),
            "userId": user_id,
            "memberCount": channel_recipient_ids(&channel).len(),
        }),
    );
    crate::ws::typing::invalidate_channel(&channel_oid.to_hex());
    HttpResponse::Ok().json(json!({ "success": true, "channelId": channel_id_hex }))
}
