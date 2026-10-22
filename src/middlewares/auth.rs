// auth.rs
// Weryfikacja JWT cookie → user w extensions.
// Zakres:
//  - brak tokenu = 401
//  - JWT cookie → user w extensions; brak = 401
// Publiczne ścieżki nie owijaj tym wrapem.
// Przy zmianach: utils/auth/jwt.rs, routes/*.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpMessage, HttpRequest, HttpResponse,
};
use actix_web_lab::middleware::Next;
use jsonwebtoken::decode;
use lazy_static::lazy_static;
use mongodb::bson::oid::ObjectId;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::model::users::User;
use crate::utils::auth::jwt::{
    jwt_decoding_key, user_from_jwt, user_from_jwt_with_refresh, user_from_token_payload,
    JwtUserError,
};
use crate::utils::auth::refresh::REFRESH_COOKIE;
use crate::utils::auth::validation::hs256_validation;
use crate::utils::db::get_db;

#[derive(Debug, Clone)]
pub struct RequestUserId(pub String);

pub fn request_user_id(req: &HttpRequest) -> Option<String> {
    req.extensions().get::<RequestUserId>().map(|u| u.0.clone())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPayload {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "tokenVersion")]
    pub token_version: i32,
    #[serde(
        rename = "sessionFamilyId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_family_id: Option<String>,
    pub exp: usize,
    #[serde(default = "default_jwt_issuer")]
    pub iss: String,
    #[serde(default = "default_jwt_audience")]
    pub aud: String,
}

fn default_jwt_issuer() -> String {
    crate::utils::auth::validation::JWT_ISSUER.to_string()
}

fn default_jwt_audience() -> String {
    crate::utils::auth::validation::JWT_AUDIENCE.to_string()
}

pub async fn verify_token(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let token = match req.cookie("jwt") {
        Some(c) => c.value().to_string(),
        None => {
            let (req, _) = req.into_parts();
            let res = HttpResponse::Unauthorized()
                .json(serde_json::json!({ "message": "Authentication token missing." }));
            return Ok(ServiceResponse::new(req, res));
        }
    };

    if token.len() > 1000 {
        let (req, _) = req.into_parts();
        let res = HttpResponse::Unauthorized()
            .json(serde_json::json!({ "message": "Invalid token format." }));
        return Ok(ServiceResponse::new(req, res));
    }

    let jwt_key = match jwt_decoding_key() {
        Ok(key) => key,
        Err(_) => {
            let (req, _) = req.into_parts();
            let res = HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Authentication is not configured." }));
            return Ok(ServiceResponse::new(req, res));
        }
    };

    let payload = match decode::<TokenPayload>(&token, &jwt_key, &hs256_validation()) {
        Ok(data) => data.claims,
        Err(err) => {
            let (req, _) = req.into_parts();
            use jsonwebtoken::errors::ErrorKind;
            let res = match err.kind() {
                ErrorKind::ExpiredSignature => HttpResponse::Unauthorized()
                    .json(serde_json::json!({ "message": "Token expired." })),
                _ => HttpResponse::Forbidden()
                    .json(serde_json::json!({ "message": "Invalid token." })),
            };
            return Ok(ServiceResponse::new(req, res));
        }
    };

    if payload.user_id.is_empty() {
        let (req, _) = req.into_parts();
        let res = HttpResponse::Forbidden()
            .json(serde_json::json!({ "message": "Invalid token payload." }));
        return Ok(ServiceResponse::new(req, res));
    }

    let refresh_token = req.cookie(REFRESH_COOKIE).map(|c| c.value().to_string());

    match user_from_token_payload(&payload, refresh_token.as_deref()).await {
        Ok(_) => {}
        Err(JwtUserError::Unavailable) => {
            let (req, _) = req.into_parts();
            let res = HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "message": "Temporarily unavailable. Retry."
            }));
            return Ok(ServiceResponse::new(req, res));
        }
        Err(JwtUserError::Denied) => {
            let (req, _) = req.into_parts();
            let res = HttpResponse::Forbidden()
                .json(serde_json::json!({ "message": "User not found or inactive." }));
            return Ok(ServiceResponse::new(req, res));
        }
    }

    req.extensions_mut()
        .insert(RequestUserId(payload.user_id.clone()));

    Ok(next.call(req).await?.map_into_boxed_body())
}

pub async fn verify_token_for_logout(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if let Some(token) = req.cookie("jwt").map(|c| c.value().to_string()) {
        if !token.is_empty() && token.len() <= 1000 {
            if let Ok(key) = jwt_decoding_key() {
                if let Ok(data) = decode::<TokenPayload>(&token, &key, &hs256_validation()) {
                    let user_id = data.claims.user_id;
                    if !user_id.is_empty() && ObjectId::parse_str(&user_id).is_ok() {
                        req.extensions_mut().insert(RequestUserId(user_id));
                    }
                }
            }
        }
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}

pub async fn resolve_authenticated_user(req: &ServiceRequest) -> Result<User, JwtUserError> {
    if let Some(uid) = req.extensions().get::<RequestUserId>() {
        if let Ok(oid) = ObjectId::parse_str(&uid.0) {
            match User::find_by_id(&get_db(), oid).await {
                Ok(Some(user)) if user.is_login_allowed() => return Ok(user),
                Ok(Some(_)) | Ok(None) => return Err(JwtUserError::Denied),
                Err(_) => return Err(JwtUserError::Unavailable),
            }
        }
        return Err(JwtUserError::Denied);
    }

    let token = req
        .cookie("jwt")
        .map(|c| c.value().to_string())
        .ok_or(JwtUserError::Denied)?;
    let refresh_token = req.cookie(REFRESH_COOKIE).map(|c| c.value().to_string());
    match refresh_token.as_deref() {
        Some(refresh) => user_from_jwt_with_refresh(&token, Some(refresh)).await,
        None => user_from_jwt(&token).await,
    }
}

pub async fn require_active_account(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let user_id = {
        let ext = req.extensions();
        ext.get::<RequestUserId>().map(|u| u.0.clone())
    };

    let user_id = match user_id.and_then(|id| ObjectId::parse_str(&id).ok()) {
        Some(id) => id,
        None => {
            let (req, _) = req.into_parts();
            let res =
                HttpResponse::Unauthorized().json(serde_json::json!({ "error": "User not found" }));
            return Ok(ServiceResponse::new(req, res));
        }
    };

    let db = get_db();
    let user = match User::find_by_id(&db, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            let (req, _) = req.into_parts();
            let res =
                HttpResponse::Unauthorized().json(serde_json::json!({ "error": "User not found" }));
            return Ok(ServiceResponse::new(req, res));
        }
        Err(_) => {
            let (req, _) = req.into_parts();
            let res = HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "Temporarily unavailable. Retry."
            }));
            return Ok(ServiceResponse::new(req, res));
        }
    };

    if !user.is_login_allowed() {
        let (req, _) = req.into_parts();
        let res = HttpResponse::Forbidden()
            .json(serde_json::json!({ "error": "Account is inactive or blocked" }));
        return Ok(ServiceResponse::new(req, res));
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}

pub fn log_suspicious_activity(
    action: &'static str,
) -> impl Fn(
    ServiceRequest,
    Next<actix_web::body::BoxBody>,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
            Output = Result<ServiceResponse<actix_web::body::BoxBody>, actix_web::Error>,
        >,
    >,
> + Clone {
    move |req: ServiceRequest, next: Next<actix_web::body::BoxBody>| {
        Box::pin(async move {
            if crate::utils::env::is_development() {
                return next.call(req).await;
            }

            lazy_static! {
                static ref SUSPICIOUS_PATTERNS: Vec<Regex> = vec![
                    Regex::new(r"\.\.").unwrap(),
                    Regex::new(r"(?:\.\.[/\\]|[/\\]\.\.[/\\])").unwrap(),
                    Regex::new(r"(?i)%2e%2e").unwrap(),
                    Regex::new(r"(?i)%252e%252e").unwrap(),
                    Regex::new(r"(?i)<script").unwrap(),
                    Regex::new(r"(?i)<iframe").unwrap(),
                    Regex::new(r"(?i)<object").unwrap(),
                    Regex::new(r"(?i)<embed").unwrap(),
                    Regex::new(r"(?i)<form").unwrap(),
                    Regex::new(r"(?i)javascript:").unwrap(),
                    Regex::new(r"(?i)vbscript:").unwrap(),
                    Regex::new(r"(?i)data:text/html").unwrap(),
                    Regex::new(r"(?i)on\w+\s*=").unwrap(),
                    Regex::new(r"(?i)style\s*=.*expression").unwrap(),
                    Regex::new(r"(?i)@import").unwrap(),
                    Regex::new(r"(?i)union.*select").unwrap(),
                    Regex::new(r"(?i)insert.*into").unwrap(),
                    Regex::new(r"(?i)update.*set").unwrap(),
                    Regex::new(r"(?i)delete.*from").unwrap(),
                    Regex::new(r"(?i)drop.*table").unwrap(),
                    Regex::new(r"(?i)create.*table").unwrap(),
                    Regex::new(r"(?i)alter.*table").unwrap(),
                    Regex::new(r"(?i)exec.*\(").unwrap(),
                    Regex::new(r"(?i)execute.*\(").unwrap(),
                    Regex::new(r"(?i)sp_").unwrap(),
                    Regex::new(r"(?i)xp_").unwrap(),
                    Regex::new(r"(?i);.*select").unwrap(),
                    Regex::new(r"(?i);\s*drop").unwrap(),
                    Regex::new(r#"(?i)'\s*or\s*'1'\s*=\s*'1"#).unwrap(),
                    Regex::new(r#"(?i)"\s*or\s*"1"\s*=\s*"1"#).unwrap(),
                    Regex::new(r"(?i)'\s*or\s*1\s*=\s*1").unwrap(),
                    Regex::new(r#"(?i)"\s*or\s*1\s*=\s*1"#).unwrap(),
                    Regex::new(r"\$\(.*\)").unwrap(),
                    Regex::new(r"`.*`").unwrap(),
                    Regex::new(r"(?i)system\(").unwrap(),
                    Regex::new(r"(?i)exec\(").unwrap(),
                    Regex::new(r"(?i)eval\(").unwrap(),
                    Regex::new(r"(?i)passthru\(").unwrap(),
                    Regex::new(r"(?i)shell_exec\(").unwrap(),
                    Regex::new(r"(?i)cmd\.exe").unwrap(),
                    Regex::new(r"(?i)powershell").unwrap(),
                    Regex::new(r"(?i)bash").unwrap(),
                    Regex::new(r"(?i)/bin/").unwrap(),
                    Regex::new(r"\(\|\(").unwrap(),
                    Regex::new(r"\)\|\)").unwrap(),
                    Regex::new(r"\*\)\(").unwrap(),
                    Regex::new(r"(?i)<!ENTITY").unwrap(),
                    Regex::new(r"(?i)<!DOCTYPE.*ENTITY").unwrap(),
                    Regex::new(r"(?i)SYSTEM.*file:").unwrap(),
                    Regex::new(r"<%.*%>").unwrap(),
                    Regex::new(r"(?i)\$where").unwrap(),
                    Regex::new(r"(?i)php://").unwrap(),
                    Regex::new(r"(?i)file://").unwrap(),
                    Regex::new(r"(?i)data://").unwrap(),
                    Regex::new(r"(?i)expect://").unwrap(),
                    Regex::new(r"(?i)\.php\?").unwrap(),
                    Regex::new(r"(?i)\.asp\?").unwrap(),
                    Regex::new(r"(?i)\.tsp\?").unwrap(),
                    Regex::new(r"(?i)content-type:").unwrap(),
                    Regex::new(r"(?i)set-cookie:").unwrap(),
                    Regex::new(r"(?i)sqlmap").unwrap(),
                    Regex::new(r"(?i)nmap").unwrap(),
                    Regex::new(r"(?i)nikto").unwrap(),
                    Regex::new(r"(?i)burp").unwrap(),
                    Regex::new(r"(?i)\bzap\b").unwrap(),
                    Regex::new(r"(?i)masscan").unwrap(),
                    Regex::new(r"(?i)dirb").unwrap(),
                    Regex::new(r"(?i)gobuster").unwrap(),
                    Regex::new(r"(?i)&#x").unwrap(),
                    Regex::new(r"&#\d+").unwrap(),
                    Regex::new(r"(?i)__proto__").unwrap(),
                    Regex::new(r"(?i)constructor.*prototype").unwrap(),
                    Regex::new(r"(?i)none.*algorithm").unwrap(),
                ];
                static ref SUSPICIOUS_HEADERS: Vec<&'static str> = vec![
                    "x-forwarded-for",
                    "x-real-ip",
                    "x-originating-ip",
                    "x-remote-ip",
                    "x-cluster-client-ip",
                ];
            }

            let ip = req
                .connection_info()
                .realip_remote_addr()
                .unwrap_or("unknown")
                .to_string();
            let user_agent = req
                .headers()
                .get(actix_web::http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();
            let uri = req.uri().to_string();
            let query = req.query_string().to_string();
            let user_id_str = {
                let ext = req.extensions();
                ext.get::<RequestUserId>().map(|u| u.0.clone())
            };

            let request_data = format!("{uri} {query}");

            let mut is_suspicious = SUSPICIOUS_PATTERNS
                .iter()
                .any(|p| p.is_match(&request_data));

            if !is_suspicious {
                let suspicious_header_count = SUSPICIOUS_HEADERS
                    .iter()
                    .filter(|h| req.headers().contains_key(**h))
                    .count();
                if suspicious_header_count > 2 {
                    is_suspicious = true;
                }
            }

            if !is_suspicious {
                let total_params = req.query_string().split('&').count();
                if total_params > 50 {
                    is_suspicious = true;
                }
            }

            if is_suspicious {
                let suspicious_headers_found: Vec<&str> = SUSPICIOUS_HEADERS
                    .iter()
                    .copied()
                    .filter(|h| req.headers().contains_key(*h))
                    .collect();

                log::warn!(
                    "Suspicious activity detected: {} | ip={} | url={} | user_agent={} | user_id={:?} | ts={} | headers={:?}",
                    action,
                    ip,
                    uri,
                    user_agent,
                    user_id_str,
                    chrono::Utc::now().to_rfc3339(),
                    suspicious_headers_found,
                );

                let (req, _) = req.into_parts();
                let res = HttpResponse::BadRequest().json(serde_json::json!({
                    "message": "Invalid request"
                }));
                return Ok(ServiceResponse::new(req, res));
            }

            next.call(req).await
        })
    }
}
