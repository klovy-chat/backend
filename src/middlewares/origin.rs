// origin.rs
// Sprawdza Origin względem FRONTEND_URL / localhost.
// Zakres:
//  - mutacje i WS
//  - Origin vs FRONTEND_URL / localhost; mutacje i WS
// Nowy origin deployu: ENV, nie hardcoded (poza DEV).
// Przy zmianach: utils/security/origin.rs, ws/mod.rs.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::Method,
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::utils::security::origin::{
    allowed_origins, requires_origin_guard, validate_browser_origin_values, OriginGuardMode,
};

pub async fn origin_guard_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let method = req.method().clone();
    let path = req.path().to_string();

    if !requires_origin_guard(&method, &path) {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let mode = if matches!(method, Method::GET | Method::HEAD) {
        OriginGuardMode::RejectKnownBad
    } else {
        OriginGuardMode::Strict
    };

    let allowed = allowed_origins();
    let origin = req.headers().get("origin").and_then(|v| v.to_str().ok());
    let referer = req.headers().get("referer").and_then(|v| v.to_str().ok());

    if !validate_browser_origin_values(origin, referer, &allowed, mode) {
        let (req, _) = req.into_parts();
        let res = HttpResponse::Forbidden().json(serde_json::json!({ "error": "Invalid origin" }));
        return Ok(ServiceResponse::new(req, res).map_into_boxed_body());
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}
