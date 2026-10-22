// client.rs
// Wymaga X-Klovy-Client; tani 403 + trop na IP block.
// Zakres:
//  - preflight CORS bez nagłówka = przepuść
//  - wymaga X-Klovy-Client; to nie auth — JWT i tak musi być
// To nie jest auth — JWT i tak musi być.
// Przy zmianach: utils/security/id.rs, ip_block.rs, clientId.ts.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::middlewares::ip_block::IPBlockerArc;
use crate::utils::ip::client_ip_from_service_request;
use crate::utils::security::id::{official_client_presented, CLIENT_HEADER_NAME};

pub async fn client_guard_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let path = req.path().to_string();
    let method = req.method().as_str().to_string();
    let query = req.query_string();
    let query = (!query.is_empty()).then_some(query);
    let header_value = req
        .headers()
        .get(CLIENT_HEADER_NAME)
        .and_then(|v| v.to_str().ok());

    if official_client_presented(&method, &path, query, header_value) {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    if let Some(blocker) = req
        .app_data::<actix_web::web::Data<IPBlockerArc>>()
        .cloned()
    {
        let ip = client_ip_from_service_request(&req);
        blocker.add_suspicious_activity(&ip);
    }

    let (req, _) = req.into_parts();
    let res = HttpResponse::BadRequest().json(serde_json::json!({
        "error": "Unsupported client",
    }));
    Ok(ServiceResponse::new(req, res).map_into_boxed_body())
}
