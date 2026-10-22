// auth_fallback.rs
// Gdy Turnstile bypass: honeypot, timing, twardszy IP.
// Zakres:
//  - Verified Turnstile = prawie passthrough
//  - gdy Turnstile bypass: honeypot, timing, twardszy IP
// Nie wyłączaj tego w prod gdy siteverify pada.
// Przy zmianach: captcha.rs, security/bots.rs, timing.rs.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpMessage, HttpResponse,
};
use actix_web_lab::middleware::Next;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::middlewares::captcha::TurnstileOutcome;
use crate::middlewares::ip_block::IPBlockerArc;
use crate::utils::env::is_development;
use crate::utils::ip::client_ip_from_service_request;
use crate::utils::ratelimit::Store;
use crate::utils::security::bots::is_known_bot_user_agent;
use crate::utils::security::user_agent::CLIENT_USER_AGENT_HEADER;

static FALLBACK_SIGNUP: Lazy<Store> = Lazy::new(|| {
    Store::new(
        crate::utils::registration::signup_max_per_ip_hour().min(2),
        Duration::from_secs(3600),
    )
});
static FALLBACK_LOGIN: Lazy<Store> = Lazy::new(|| Store::new(4, Duration::from_secs(15 * 60)));
static LAST_AUTH_ATTEMPT: Lazy<Mutex<HashMap<String, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const MIN_AUTH_INTERVAL: Duration = Duration::from_secs(3);
const FALLBACK_DELAY_BASE_MS: u64 = 1500;
const LAST_AUTH_ATTEMPT_MAX: usize = 20_000;

const HONEYPOT_FIELDS: &[&str] = &[
    "website",
    "url",
    "company",
    "fax",
    "phone2",
    "address_line2",
    "email_confirm",
    "confirm_email",
    "middle_name",
    "honeypot",
    "_gotcha",
    "botcheck",
];

fn honeypot_triggered(body: &serde_json::Value) -> bool {
    let Some(obj) = body.as_object() else {
        return false;
    };
    HONEYPOT_FIELDS.iter().any(|field| {
        obj.get(*field)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty())
    })
}

fn client_user_agent(req: &ServiceRequest) -> String {
    req.headers()
        .get(CLIENT_USER_AGENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string()
}

fn has_trusted_client_fingerprint(req: &ServiceRequest) -> bool {
    let klovy_ua = client_user_agent(req);
    if klovy_ua.len() >= 8 && !is_known_bot_user_agent(&klovy_ua) {
        return true;
    }

    req.headers()
        .get(actix_web::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ua| {
            let ua = ua.trim();
            ua.len() >= 8 && !is_known_bot_user_agent(ua)
        })
}

fn too_soon_since_last_attempt(ip: &str) -> bool {
    let now = Instant::now();
    let mut map = LAST_AUTH_ATTEMPT.lock().unwrap_or_else(|e| e.into_inner());
    map.retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(3600));
    if map.len() > LAST_AUTH_ATTEMPT_MAX {
        let overflow = map.len() - LAST_AUTH_ATTEMPT_MAX;
        let keys: Vec<String> = map.keys().take(overflow).cloned().collect();
        for key in keys {
            map.remove(&key);
        }
    }

    if let Some(last) = map.get(ip) {
        if now.duration_since(*last) < MIN_AUTH_INTERVAL {
            return true;
        }
    }

    map.insert(ip.to_string(), now);
    false
}

fn fallback_delay_ms() -> u64 {
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 % 1000)
        .unwrap_or(0);
    FALLBACK_DELAY_BASE_MS + jitter
}

async fn run_auth_fallback_guard(
    action: &'static str,
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if is_development() {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let outcome = req
        .extensions()
        .get::<TurnstileOutcome>()
        .copied()
        .unwrap_or(TurnstileOutcome::Bypassed);

    let ip = client_ip_from_service_request(&req);
    let trusted_client = has_trusted_client_fingerprint(&req);
    let blocker = req
        .app_data::<actix_web::web::Data<IPBlockerArc>>()
        .cloned();

    let (http_req, payload) = req.into_parts();
    let body_bytes = crate::middlewares::read_body_bytes(payload).await?;

    if let Ok(body) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
        if honeypot_triggered(&body) {
            if let Some(blocker) = &blocker {
                blocker.add_suspicious_activity(&ip);
            }
            let res =
                HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid request" }));
            return Ok(ServiceResponse::new(http_req, res));
        }
    }

    if outcome == TurnstileOutcome::Verified {
        let payload = actix_web::dev::Payload::from(body_bytes);
        let req = ServiceRequest::from_parts(http_req, payload);
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    if !trusted_client {
        if let Some(blocker) = &blocker {
            blocker.add_suspicious_activity(&ip);
        }
        let res =
            HttpResponse::BadRequest().json(serde_json::json!({ "error": "Unsupported client" }));
        return Ok(ServiceResponse::new(http_req, res));
    }

    let rate_key = format!("{action}:{ip}");
    let allowed = match action {
        "signup" => FALLBACK_SIGNUP.check_and_increment(&rate_key),
        _ => FALLBACK_LOGIN.check_and_increment(&rate_key),
    };
    if !allowed {
        if let Some(blocker) = &blocker {
            blocker.add_suspicious_activity(&ip);
        }
        let res = HttpResponse::TooManyRequests().json(serde_json::json!({
            "error": "Too many attempts. Try again later.",
            "retryAfter": if action == "signup" { 3600 } else { 900 }
        }));
        return Ok(ServiceResponse::new(http_req, res));
    }

    if too_soon_since_last_attempt(&ip) {
        let res = HttpResponse::TooManyRequests().json(serde_json::json!({
            "error": "Too many attempts. Try again later.",
            "retryAfter": MIN_AUTH_INTERVAL.as_secs()
        }));
        return Ok(ServiceResponse::new(http_req, res));
    }

    sleep(Duration::from_millis(fallback_delay_ms())).await;

    let payload = actix_web::dev::Payload::from(body_bytes);
    let req = ServiceRequest::from_parts(http_req, payload);
    Ok(next.call(req).await?.map_into_boxed_body())
}

pub async fn auth_fallback_guard_signup(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    run_auth_fallback_guard("signup", req, next).await
}

pub async fn auth_fallback_guard_login(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    run_auth_fallback_guard("login", req, next).await
}
