// config.rs
// Walidacja ENV przy starcie (R2, JWT, porty, LiveKit, sekrety).
// Zakres:
//  - panic/log zanim wejdzie ruch
//  - wymagane ENV przy starcie; nowa zmienna = tu, inaczej prod wstanie na pół
// Nowa wymagana zmienna: tu, inaczej prod wstanie „na pół”.
// Przy zmianach: main.rs, .env.example.

use std::env;

use crate::utils::env::{is_production, node_env};
use crate::utils::auth::jwt::jwt_secret;
use crate::utils::registration::{
    is_registration_disabled, signup_max_global_per_day, signup_max_global_per_hour,
    signup_max_per_ip_hour,
};

fn origin_looks_like_production(origin: &str) -> bool {
    let lower = origin.to_ascii_lowercase();
    !lower.contains("127.0.0.1") && !lower.contains("::1")
}

fn validate_r2_env() {
    for var in [
        "R2_ACCOUNT_ID",
        "R2_ACCESS_KEY_ID",
        "R2_SECRET_ACCESS_KEY",
        "R2_PUBLIC_BUCKET",
        "CDN_PUBLIC_BASE_URL",
    ] {
        if env::var(var).map(|v| v.trim().is_empty()).unwrap_or(true) {
            panic!(
                "{var} must be set — uploads use Cloudflare R2 (see backend/docs/R2_SETUP.md)"
            );
        }
    }

    let public = env::var("R2_PUBLIC_BUCKET").unwrap_or_default();
    let public = public.trim();
    let quarantine = env::var("R2_QUARANTINE_BUCKET").unwrap_or_default();
    let quarantine = quarantine.trim();
    if quarantine.is_empty() || quarantine == public {
        if is_production() {
            panic!(
                "R2_QUARANTINE_BUCKET must be a separate private bucket in production \
                 (not the same as R2_PUBLIC_BUCKET) — otherwise pending files are on the CDN"
            );
        }
        log::error!(
            "R2_QUARANTINE_BUCKET is missing or equals R2_PUBLIC_BUCKET — \
             pending attachments may be reachable on the public CDN"
        );
    }
}

fn validate_clamav_env(require: bool) {
    let host = env::var("CLAMAV_HOST").unwrap_or_default();
    if !host.trim().is_empty() {
        return;
    }
    if require {
        panic!(
            "CLAMAV_HOST must be set in production (e.g. 127.0.0.1:3310) — \
             attachments stay in quarantine until clamd scans them"
        );
    }
    log::error!(
        "CLAMAV_HOST is not set — uploaded attachments will stay in quarantine until clamd is configured"
    );
}

fn validate_livekit_env() {
    let url = env::var("LIVEKIT_URL").unwrap_or_default();
    let key = env::var("LIVEKIT_API_KEY").unwrap_or_default();
    let secret = env::var("LIVEKIT_API_SECRET").unwrap_or_default();

    let any_set = !url.trim().is_empty() || !key.trim().is_empty() || !secret.trim().is_empty();
    if !any_set {
        return;
    }

    if url.trim().is_empty() || key.trim().is_empty() || secret.trim().is_empty() {
        panic!(
            "LIVEKIT_URL, LIVEKIT_API_KEY, and LIVEKIT_API_SECRET must all be set when voice is enabled"
        );
    }

    if !crate::utils::security::urls::is_allowed_livekit_url(&url) {
        panic!("LIVEKIT_URL is not allowed: must be wss:// or https:// with a public host");
    }
}

pub fn validate_startup_config() {
    let origin = env::var("ORIGIN").unwrap_or_default();
    if origin_looks_like_production(&origin) && !is_production() {
        panic!(
            "NODE_ENV must be \"production\" when ORIGIN is set to a public URL ({origin})"
        );
    }

    if is_production() {
        jwt_secret().expect("Invalid JWT_KEY for production");
        let token_hash_key = env::var("TOKEN_HASH_KEY").unwrap_or_default();
        if token_hash_key.trim().len() < 32 {
            panic!("TOKEN_HASH_KEY must be at least 32 characters in production");
        }
        if origin.trim().is_empty() {
            panic!("ORIGIN must be set in production");
        }
        for part in origin.split(',') {
            let part = part.trim().trim_end_matches('/');
            if part.is_empty() {
                continue;
            }
            if !part.starts_with("https://") {
                panic!("ORIGIN entries must use HTTPS in production (got {part})");
            }
        }
        let turnstile = env::var("TURNSTILE_SECRET_KEY").unwrap_or_default();
        if turnstile.trim().is_empty() {
            panic!("TURNSTILE_SECRET_KEY must be set in production");
        }
        let report_secret = env::var("SECURITY_REPORT_SECRET").unwrap_or_default();
        if report_secret.trim().len() < 16 {
            log::warn!(
                "SECURITY_REPORT_SECRET is not set or too short (min 16 chars) — \
                 the /api/security/report endpoint will be disabled"
            );
        }

        let field_key = env::var("FIELD_ENCRYPTION_KEY").unwrap_or_default();
        if field_key.trim().len() < 32 {
            panic!("FIELD_ENCRYPTION_KEY must be at least 32 characters in production");
        }

        let mongo_uri = crate::utils::db_url::database_url().unwrap_or_default();
        if mongo_uri.trim().is_empty() {
            panic!("Database URL must be set in production (DATABASE_URL, MONGODB_URI, or MONGO_URI)");
        }

        if !env::var("TRUST_PROXY")
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false)
        {
            panic!("TRUST_PROXY must be enabled (true) in production when behind a reverse proxy");
        }

        let internal_http_port = env::var("INTERNAL_HTTP_PORT").unwrap_or_default();
        if internal_http_port.trim().is_empty() {
            panic!("INTERNAL_HTTP_PORT must be set in production");
        }
        let internal_port: u16 = internal_http_port
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("INTERNAL_HTTP_PORT must be a valid port number (1-65535)"));
        if internal_port == 0 {
            panic!("INTERNAL_HTTP_PORT must be a valid port number (1-65535)");
        }
        let public_port: u16 = env::var("PORT")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(|v| {
                v.parse()
                    .unwrap_or_else(|_| panic!("PORT must be a valid port number (1-65535)"))
            })
            .unwrap_or(6700);
        if internal_port == public_port {
            panic!(
                "INTERNAL_HTTP_PORT ({internal_port}) must differ from PORT ({public_port}) — \
                 the public server and the internal actix server cannot share a port"
            );
        }

        if internal_port == 6701 {
            panic!(
                "INTERNAL_HTTP_PORT=6701 conflicts with Caddy on :6701 \
                 (tunnel → Caddy:6701 → Axum:{public_port}). Set INTERNAL_HTTP_PORT=6702"
            );
        }

        let internal_proxy_secret = env::var("INTERNAL_PROXY_SECRET").unwrap_or_default();
        if internal_proxy_secret.trim().len() < 32 {
            panic!(
                "INTERNAL_PROXY_SECRET must be at least 32 characters in production"
            );
        }

        let frontend_url = env::var("FRONTEND_URL").unwrap_or_default();
        if frontend_url.trim().is_empty() {
            panic!("FRONTEND_URL must be set in production");
        }
        if !frontend_url.trim().starts_with("https://") {
            panic!("FRONTEND_URL must use HTTPS in production");
        }

        validate_r2_env();
        validate_livekit_env();
        validate_clamav_env(true);

        if is_registration_disabled() {
            log::warn!("Registration is DISABLED — new signups are rejected");
        } else {
            log::info!(
                "Signup limits: {} per IP/hour, {} global/hour, {} global/day",
                signup_max_per_ip_hour(),
                signup_max_global_per_hour(),
                signup_max_global_per_day()
            );
        }

        log::info!("WebSocket frame encryption is required in production");

        log::info!(
            "Production security configuration validated (NODE_ENV={})",
            node_env()
        );
        return;
    }

    validate_r2_env();
    validate_clamav_env(false);

    if jwt_secret().is_err() {
        log::warn!(
            "JWT_KEY is missing or empty — authentication will not work until it is configured"
        );
    }
}
