// mod.rs
// Handshake WS: origin, TLS, IP, klient, JWT, crypto token.
// Zakres:
//  - pętla gniazda, heartbeat, cap połączeń
//  - handshake: origin, TLS, IP, klient, JWT, crypto
// Nowy warunek odrzucenia: log + ten sam powód co HTTP gdy się da.
// Przy zmianach: ws/handlers.rs, ws/registry.rs, middlewares/client.rs.

pub mod keys;
pub mod encrypt;
pub mod handlers;
pub mod registry;
pub mod state;
pub mod typing;

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{
        ws::{rejection::WebSocketUpgradeRejection, Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, RawQuery, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::decode;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use tokio::sync::{mpsc, watch};

use crate::middlewares::ip_block::IPBlockerArc;
use crate::utils::ip::client_ip_from_headers;
use crate::utils::security::id::{query_client_valid, query_param, WS_CRYPTO_QUERY_PARAM};
use crate::utils::security::origin::is_origin_header_allowed;
use crate::utils::security::transport::is_secure_client_connection;
use crate::ws::keys::{consume_ws_crypto_key, ws_frame_encryption_required};
use crate::ws::encrypt::{decrypt_frame_async, encrypt_frame_async, FrameCipher};
use crate::ws::handlers::{
    dispatch_message, finalize_taken_call_sessions, on_user_connected, on_user_disconnected,
};
use crate::utils::voice::calls::take_sessions_for_connection;
use crate::ws::registry::ConnectionRegistry;
use crate::ws::state::{is_valid_object_id, SocketState};
use crate::middlewares::auth::TokenPayload;
use crate::utils::auth::jwt::{
    jwt_decoding_key, parse_jwt_from_cookie_header, parse_refresh_from_cookie_header,
    resolve_session_family_id, user_from_jwt_with_refresh, JwtUserError,
};
use crate::utils::auth::validation::hs256_validation;

#[derive(Clone)]
pub struct WsAppState {
    pub socket_state: SocketState,
    pub registry: ConnectionRegistry,
    pub ip_block: Arc<IPBlockerArc>,
}

pub fn init(registry: ConnectionRegistry) {
    registry::set_registry(registry);
}

#[derive(Debug, Deserialize)]
struct IncomingFrame {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    payload: serde_json::Value,
}

const PING_INTERVAL: Duration = Duration::from_secs(45);
const PONG_TIMEOUT: Duration = Duration::from_secs(90);
const AUTH_RECHECK_INTERVAL: Duration = Duration::from_secs(30);
const MAX_PAYLOAD: usize = 64 * 1024;
const MAX_PING_PAYLOAD: usize = 1024;

pub async fn ws_handler(
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(app_state): State<WsAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let ws = match ws {
        Ok(ws) => ws,
        Err(_) => {
            return (StatusCode::UPGRADE_REQUIRED, "WebSocket required").into_response();
        }
    };

    if raw_query.as_deref().is_some_and(|q| q.len() > crate::utils::upload::MAX_PROXY_URI_BYTES)
    {
        return (StatusCode::URI_TOO_LONG, "URI too long").into_response();
    }

    if !is_origin_header_allowed(&headers) {
        log::warn!("WebSocket rejected — invalid origin");
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    if !is_secure_client_connection(&headers) {
        log::warn!("WebSocket rejected — insecure transport (require HTTPS/WSS in production)");
        return (StatusCode::FORBIDDEN, "Secure connection required").into_response();
    }

    let client_ip = client_ip_from_headers(&headers, Some(peer));

    if app_state.ip_block.is_blocked(&client_ip) {
        log::warn!("WebSocket rejected — blocked IP {}", client_ip);
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    if !query_client_valid(raw_query.as_deref()) {
        app_state.ip_block.add_suspicious_activity(&client_ip);
        log::warn!("WebSocket rejected — missing client identifier for IP {}", client_ip);
        return (StatusCode::BAD_REQUEST, "Unsupported client").into_response();
    }

    if let Err(retry_after) = crate::utils::ratelimit::ws_handshake_allowed(&client_ip) {
        log::warn!("WebSocket rejected — handshake rate limit for IP {}", client_ip);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after.to_string())],
            "Too many requests",
        )
            .into_response();
    }

    if !app_state.socket_state.can_accept_ip_connection(&client_ip) {
        log::warn!("WebSocket rejected — too many connections from IP {}", client_ip);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            "Too many connections",
        )
            .into_response();
    }

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok());

    let refresh_token = cookie_header.and_then(parse_refresh_from_cookie_header);
    let refresh_ref = refresh_token.as_deref();

    let (user_id, jwt_token) =
        if let Some(token) = cookie_header.and_then(|h| parse_jwt_from_cookie_header(h)) {
            match user_from_jwt_with_refresh(&token, refresh_ref).await {
                Ok(user) => (
                    user.id.map(|id| id.to_hex()).unwrap_or_default(),
                    token,
                ),
                Err(JwtUserError::Unavailable) => {
                    log::warn!("WebSocket rejected — JWT user lookup unavailable");
                    return (StatusCode::SERVICE_UNAVAILABLE, "Temporarily unavailable").into_response();
                }
                Err(JwtUserError::Denied) => (String::new(), String::new()),
            }
        } else {
            (String::new(), String::new())
        };

    if user_id.is_empty() || jwt_token.is_empty() || !is_valid_object_id(&user_id) {
        log::warn!("WebSocket rejected — missing or invalid JWT cookie");
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let session_family_id = if let Ok(key) = jwt_decoding_key() {
        decode::<TokenPayload>(&jwt_token, &key, &hs256_validation())
            .ok()
            .map(|data| data.claims)
    } else {
        None
    };

    let session_family_id = if let Some(payload) = session_family_id {
        match resolve_session_family_id(&payload, refresh_ref).await {
            Ok(v) => v,
            Err(JwtUserError::Unavailable) => {
                log::warn!("WebSocket rejected — session family lookup unavailable");
                return (StatusCode::SERVICE_UNAVAILABLE, "Temporarily unavailable")
                    .into_response();
            }
            Err(JwtUserError::Denied) => None,
        }
    } else {
        None
    };

    let encryption_required = ws_frame_encryption_required();
    let crypto_token = query_param(raw_query.as_deref(), WS_CRYPTO_QUERY_PARAM);
    let frame_key = if encryption_required {
        let Some(token) = crypto_token.as_deref() else {
            log::warn!("WebSocket rejected — missing frame encryption token for user {}", user_id);
            return (StatusCode::FORBIDDEN, "Encryption required").into_response();
        };
        match consume_ws_crypto_key(token, &user_id) {
            Some(key) => Some(key),
            None => {
                log::warn!("WebSocket rejected — invalid frame encryption token for user {}", user_id);
                return (StatusCode::FORBIDDEN, "Invalid encryption token").into_response();
            }
        }
    } else {
        crypto_token
            .as_deref()
            .and_then(|token| consume_ws_crypto_key(token, &user_id))
    };

    ws.on_upgrade(move |socket| {
        handle_socket(
            socket,
            user_id,
            jwt_token,
            refresh_token,
            session_family_id,
            client_ip,
            frame_key,
            app_state,
        )
    })
}

async fn process_incoming_text(
    text: &str,
    connected: &str,
    state: &SocketState,
    tx: &mpsc::Sender<String>,
    last_pong_at: &mut std::time::Instant,
    conn_id: u64,
) -> bool {

    if let Ok(parsed) = serde_json::from_str::<IncomingFrame>(text) {
        if parsed.msg_type == "pong" {
            *last_pong_at = std::time::Instant::now();
            return true;
        }
        if parsed.msg_type == "ping" {
            *last_pong_at = std::time::Instant::now();
            let _ = tx.try_send(json!({"type":"pong","payload":{}}).to_string());
            return true;
        }
        dispatch_message(connected, &parsed.msg_type, parsed.payload, state, conn_id).await;
    }

    true
}

async fn handle_socket(
    socket: WebSocket,
    user_id: String,
    jwt_token: String,
    refresh_token: Option<String>,
    session_family_id: Option<String>,
    client_ip: String,
    frame_key: Option<[u8; 32]>,
    app_state: WsAppState,
) {
    if !app_state.socket_state.register_ip_connection(&client_ip) {
        log::warn!("WebSocket dropped after upgrade — connection cap for {}", client_ip);
        return;
    }

    let Some(is_first_connection) = app_state.socket_state.register_connection(&user_id)
    else {
        log::warn!("Too many connections for user {}", user_id);
        app_state
            .socket_state
            .unregister_ip_connection(&client_ip);
        return;
    };

    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<String>(registry::WS_SEND_BUFFER);
    let (revoke_tx, mut revoke_rx) = watch::channel(false);
    let conn_id = app_state
        .registry
        .register(&user_id, tx.clone(), revoke_tx, session_family_id)
        .await;

    if is_first_connection {
        let user_id_for_presence = user_id.clone();
        let socket_state_for_presence = app_state.socket_state.clone();
        tokio::spawn(async move {
            on_user_connected(&user_id_for_presence, &socket_state_for_presence).await;
        });
    }
    log::info!("User connected: {}", user_id);

    let state = app_state.socket_state.clone();
    let connected = user_id.clone();
    let mut auth_interval = tokio::time::interval(AUTH_RECHECK_INTERVAL);
    auth_interval.tick().await;
    let mut ping_interval = tokio::time::interval(PING_INTERVAL);
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    ping_interval.tick().await;
    let mut last_pong_at = std::time::Instant::now();

    let ws_frame_key = frame_key;
    if let Some(key) = ws_frame_key {
        if FrameCipher::new(&key).is_err() {
            log::error!("WebSocket frame cipher init failed for {}", user_id);
            app_state.registry.unregister(&user_id, conn_id).await;
            app_state.socket_state.unregister_connection(&user_id);
            app_state
                .socket_state
                .unregister_ip_connection(&client_ip);
            return;
        }
    }
    let encryption_required = ws_frame_key.is_some();

    loop {
        tokio::select! {
            _ = revoke_rx.changed() => {
                if *revoke_rx.borrow_and_update() {
                    log::info!("WebSocket session revoked for user {}", user_id);
                    let _ = ws_sender.send(Message::Close(None)).await;
                    break;
                }
            }
            _ = ping_interval.tick() => {
                if last_pong_at.elapsed() > PONG_TIMEOUT {
                    log::info!("WebSocket pong timeout for user {}", user_id);
                    let _ = ws_sender.send(Message::Close(None)).await;
                    break;
                }
                if ws_sender
                    .send(Message::Ping(Default::default()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            _ = auth_interval.tick() => {
                if !state.try_begin_auth_recheck(
                    &user_id,
                    AUTH_RECHECK_INTERVAL.as_millis() as i64,
                ) {
                    continue;
                }
                let jwt_token = jwt_token.clone();
                let refresh_token = refresh_token.clone();
                let user_id = user_id.clone();
                let registry = app_state.registry.clone();
                tokio::spawn(async move {
                    match user_from_jwt_with_refresh(
                        &jwt_token,
                        refresh_token.as_deref(),
                    )
                    .await
                    {
                        Ok(_) => {}

                        Err(JwtUserError::Unavailable) => return,
                        Err(JwtUserError::Denied) => {
                            registry.disconnect_user(&user_id).await;
                            return;
                        }
                    }
                });
            }
            msg = rx.recv() => {
                match msg {
                    Some(text) => {
                        let outbound = if let Some(key) = ws_frame_key {
                            match encrypt_frame_async(key, text).await {
                                Ok(bytes) => Message::Binary(bytes.into()),
                                Err(e) => {
                                    log::warn!("WebSocket encrypt failed for user {}: {e}", user_id);
                                    continue;
                                }
                            }
                        } else {
                            Message::Text(text.into())
                        };
                        if ws_sender.send(outbound).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            result = ws_receiver.next() => {
                match result {
                    Some(Ok(Message::Binary(data))) => {
                        if data.len() > MAX_PAYLOAD {
                            continue;
                        }
                        let text = if let Some(key) = ws_frame_key {
                            match decrypt_frame_async(key, data.to_vec()).await {
                                Ok(value) => value,
                                Err(e) => {
                                    log::warn!("WebSocket decrypt failed for user {}: {e}", user_id);
                                    continue;
                                }
                            }
                        } else {
                            continue;
                        };
                        if !process_incoming_text(
                            &text,
                            &connected,
                            &state,
                            &tx,
                            &mut last_pong_at,
                            conn_id,
                        )
                        .await
                        {
                            let _ = ws_sender.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if encryption_required {
                            log::warn!("WebSocket rejected plaintext frame for user {}", user_id);
                            continue;
                        }
                        if text.len() > MAX_PAYLOAD {
                            continue;
                        }
                        if !process_incoming_text(
                            &text,
                            &connected,
                            &state,
                            &tx,
                            &mut last_pong_at,
                            conn_id,
                        )
                        .await
                        {
                            let _ = ws_sender.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if data.len() > MAX_PING_PAYLOAD {
                            continue;
                        }
                        if ws_sender.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        last_pong_at = std::time::Instant::now();
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                }
            }
        }
    }
    app_state.registry.unregister(&user_id, conn_id).await;
    app_state.socket_state.unregister_connection(&user_id);
    app_state
        .socket_state
        .unregister_ip_connection(&client_ip);

    let last_connection = !app_state.socket_state.is_user_connected(&user_id);

    if !last_connection {
        let voice_left =
            crate::utils::voice::channels::clear_connection(&user_id, conn_id);
        if !voice_left.is_empty() {
            let user_id_voice = user_id.clone();
            tokio::spawn(async move {
                use crate::model::channels::Channel;
                use crate::utils::db::get_db;
                use crate::ws::registry::{channel_recipient_ids, emit_to_users};
                use mongodb::bson::oid::ObjectId;
                use serde_json::json;
                let db = get_db();
                for channel_id in voice_left {
                    let participants =
                        crate::utils::voice::channels::participants_in_channel(&channel_id);
                    let body = json!({ "channelId": channel_id, "participants": participants });
                    let Ok(oid) = ObjectId::parse_str(&channel_id) else {
                        let mut recipients = participants.clone();
                        if !recipients.iter().any(|r| r == &user_id_voice) {
                            recipients.push(user_id_voice.clone());
                        }
                        if !recipients.is_empty() {
                            emit_to_users(&recipients, "channel-voice:state", body);
                        }
                        continue;
                    };
                    let channel = match Channel::find_by_id(&db, oid).await {
                        Ok(Some(ch)) => Some(ch),

                        Ok(None) | Err(_) => None,
                    };
                    if let Some(ch) = channel {
                        let mut recipients = channel_recipient_ids(&ch);
                        if !recipients.iter().any(|r| r == &user_id_voice) {
                            recipients.push(user_id_voice.clone());
                        }
                        for p in &participants {
                            if !recipients.iter().any(|r| r == p) {
                                recipients.push(p.clone());
                            }
                        }
                        emit_to_users(&recipients, "channel-voice:state", body);
                    } else {
                        let mut recipients = participants.clone();
                        if !recipients.iter().any(|r| r == &user_id_voice) {
                            recipients.push(user_id_voice.clone());
                        }
                        if !recipients.is_empty() {
                            emit_to_users(&recipients, "channel-voice:state", body);
                        }
                    }
                }
            });
        }
    }

    if !last_connection {
        let call_left = take_sessions_for_connection(&user_id, conn_id);
        if !call_left.is_empty() {
            let user_id_call = user_id.clone();
            tokio::spawn(async move {
                finalize_taken_call_sessions(&user_id_call, call_left).await;
            });
        }
    }

    if last_connection {
        let user_id_for_presence = user_id.clone();
        let socket_state = app_state.socket_state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            if socket_state.is_user_connected(&user_id_for_presence)
                || socket_state.connection_count(&user_id_for_presence) > 0
            {
                return;
            }
            socket_state.clear_user_state(&user_id_for_presence);
            on_user_disconnected(&user_id_for_presence, &socket_state).await;
        });
    }
    log::info!("User disconnected: {}", user_id);
}
