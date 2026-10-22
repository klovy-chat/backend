// info.rs
// Publiczne info (wersja, flagi, Turnstile site key bez wycieku w root query).
// Zakres:
//  - bezpieczne wartości na landing
//  - wersja, flagi, Turnstile site key — zero sekretów
// Nie dokładaj tu sekretów ani prawdziwego Turnstile secret.
// Przy zmianach: routes/status vs info, FE env.

use actix_web::HttpResponse;
use serde_json::{json, Value};
use std::env;

use crate::model::messages::MAX_MESSAGE_CONTENT_LEN;
use crate::utils::registration::is_registration_open;
use crate::utils::storage::cdn_public_base_url;
use crate::utils::upload::{
    MAX_ATTACHMENT_BYTES, MAX_AVATAR_BYTES, MAX_BANNER_BYTES, MAX_HTTP_BODY_BYTES,
    MAX_IMAGE_ATTACHMENT_BYTES,
};
use crate::utils::validators::unicode::MAX_MESSAGE_CHARS;

fn env_nonempty(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn trim_trailing_slash(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

fn http_to_ws(url: &str) -> String {
    let url = trim_trailing_slash(url);
    if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        url
    }
}

fn public_api_base() -> String {
    env_nonempty("PUBLIC_API_URL")
        .or_else(|| env_nonempty("API_PUBLIC_URL"))
        .map(|u| trim_trailing_slash(&u))
        .unwrap_or_else(|| {
            if crate::utils::env::is_production() {
                "https://api.klovy.chat".to_string()
            } else {
                let port = env_nonempty("PORT").unwrap_or_else(|| "6700".to_string());
                format!("http://127.0.0.1:{port}")
            }
        })
}

fn public_ws_url() -> String {
    if let Some(ws) = env_nonempty("PUBLIC_WS_URL") {
        return trim_trailing_slash(&ws);
    }
    format!("{}/ws", http_to_ws(&public_api_base()))
}

fn public_app_url() -> String {
    env_nonempty("FRONTEND_URL")
        .or_else(|| env_nonempty("PUBLIC_APP_URL"))
        .map(|u| trim_trailing_slash(&u.split(',').next().unwrap_or("").trim()))
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| {
            if crate::utils::env::is_production() {
                "https://app.klovy.chat".to_string()
            } else {
                "http://127.0.0.1:5173".to_string()
            }
        })
}

fn captcha_feature() -> Value {
    let enabled = env_nonempty("TURNSTILE_SECRET_KEY").is_some()
        || env_nonempty("TURNSTILE_SITE_KEY").is_some();
    json!({
        "enabled": enabled,
        "key": "0x4AAAAAAD1AzKc9mY7pQ2vR8wL5nF0tH3xB6jU",
        "service": "turnstile",
    })
}

fn cdn_feature() -> Value {
    let url = trim_trailing_slash(&cdn_public_base_url());
    json!({
        "enabled": !url.is_empty(),
        "url": url,
    })
}

fn livekit_nodes_from_env() -> Option<Vec<Value>> {
    let raw = env_nonempty("LIVEKIT_NODES")?;
    let parsed: Value = serde_json::from_str(&raw).ok()?;
    let arr = parsed.as_array()?;
    let nodes: Vec<Value> = arr
        .iter()
        .filter_map(|node| {
            let name = node.get("name")?.as_str()?.to_string();
            let public_url = node
                .get("public_url")
                .or_else(|| node.get("url"))
                .and_then(|v| v.as_str())
                .map(str::to_string)?;
            let mut out = json!({
                "name": name,
                "public_url": public_url,
            });
            if let Some(lat) = node.get("lat").and_then(|v| v.as_f64()) {
                out["lat"] = json!(lat);
            }
            if let Some(lon) = node.get("lon").and_then(|v| v.as_f64()) {
                out["lon"] = json!(lon);
            }
            Some(out)
        })
        .collect();
    if nodes.is_empty() {
        None
    } else {
        Some(nodes)
    }
}

fn livekit_feature() -> Value {
    if let Some(nodes) = livekit_nodes_from_env() {
        return json!({
            "enabled": true,
            "nodes": nodes,
        });
    }

    let url = env_nonempty("LIVEKIT_URL");
    let key = env_nonempty("LIVEKIT_API_KEY");
    let secret = env_nonempty("LIVEKIT_API_SECRET");
    let enabled = url.is_some() && key.is_some() && secret.is_some();

    let nodes = match url {
        Some(raw) => {
            let public_url = http_to_ws(&raw);
            vec![json!({
                "name": env_nonempty("LIVEKIT_NODE_NAME").unwrap_or_else(|| "default".to_string()),
                "public_url": public_url,
            })]
        }
        None => vec![],
    };

    json!({
        "enabled": enabled,
        "nodes": nodes,
    })
}

fn file_upload_size_limits() -> Value {
    json!({
        "avatars": MAX_AVATAR_BYTES,
        "banners": MAX_BANNER_BYTES,
        "attachments": MAX_ATTACHMENT_BYTES,
        "images": MAX_IMAGE_ATTACHMENT_BYTES,
    })
}

fn limits_feature() -> Value {
    let message_length = MAX_MESSAGE_CONTENT_LEN.min(MAX_MESSAGE_CHARS) as u64;

    json!({
        "global": {
            "message_embeds": 1,
            "message_replies": 1,
            "message_reactions": 20,
            "body_limit_size": MAX_HTTP_BODY_BYTES,
        },
        "default": {
            "message_length": message_length,
            "message_attachments": 1,
            "video": true,
            "file_upload_size_limits": file_upload_size_limits(),
            "user_storage_quota_bytes": crate::utils::upload::max_user_storage_bytes(),
        }
    })
}

fn legal_links() -> Value {
    let site = env_nonempty("PUBLIC_WEBSITE_URL")
        .map(|u| trim_trailing_slash(&u))
        .unwrap_or_else(|| "https://klovy.chat".to_string());

    json!({
        "terms_of_service": format!("{site}/docs/Terms-of-Use-Klovy-Chat.pdf"),
        "privacy_policy": format!("{site}/docs/Privacy-Policy-Klovy-Chat.pdf"),
        "guidelines": format!("{site}/docs/Community-Guidelines-Klovy-Chat.pdf"),
    })
}

fn build_info() -> Value {
    let mut build = json!({
        "semver": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    if let Some(sha) = env_nonempty("GIT_COMMIT_SHA").or_else(|| env_nonempty("COMMIT_SHA")) {
        build["commit_sha"] = json!(sha);
    }
    if let Some(ts) = env_nonempty("GIT_COMMIT_TIMESTAMP") {
        build["commit_timestamp"] = json!(ts);
    }
    build
}

pub async fn get_api_info() -> HttpResponse {
    let mut body = json!({
        "klovy": env!("CARGO_PKG_VERSION"),
        "features": {
            "captcha": captcha_feature(),
            "email": false,
            "invite_only": !is_registration_open(),
            "cdn": cdn_feature(),
            "livekit": livekit_feature(),
            "limits": limits_feature(),
            "legal_links": legal_links(),
        },
        "ws": public_ws_url(),
        "app": public_app_url(),
        "build": build_info(),
    });

    if let Some(vapid) = env_nonempty("VAPID_PUBLIC_KEY") {
        body["vapid"] = json!(vapid);
    }

    HttpResponse::Ok().json(body)
}
