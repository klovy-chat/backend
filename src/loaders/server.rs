// server.rs
// Składanie Axum (edge: CORS, proxy, limity) i Actix (API + WS upgrade).
// Zakres:
//  - łańcuch middleware
//  - bind PORT vs INTERNAL_HTTP_PORT
// Nowe middleware: wrap tutaj w dobrej kolejności (klient/IP przed auth).
// Przy zmianach: middlewares/*, routes/mod.rs, utils/security/cors.rs.

use actix_web::{
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    http::header,
    middleware::Compress,
    web, App, HttpRequest, HttpResponse, HttpServer,
};
use actix_web_lab::middleware::from_fn;
use std::env;

use crate::routes::{
    auth, channels, contacts, emojis,
    friends, gifs, invites, messages, status,
    stickers, users, voice,
};

use crate::middlewares::{
    client::client_guard_middleware,
    csrf::csrf_middleware,
    proxy::{proxy, internal_proxy_secret, INTERNAL_PROXY_HEADER},
    ip_block::{ip_blocker_middleware, track_suspicious_activity, IPBlockerArc},
    origin::origin_guard_middleware,
};

use crate::utils::ratelimit::{
    auth_rate_limiter, edge_http_allowed, global_limiter, send_limiter, try_acquire_http_slot,
    HTTP_EDGE_TIMEOUT,
};
use actix_multipart::form::MultipartFormConfig;
use crate::utils::upload::{
    max_proxy_body_bytes, MAX_HTTP_BODY_BYTES, MAX_JSON_PAYLOAD_BYTES, MAX_PROXY_URI_BYTES,
};

use crate::utils::validators::{
    sanitize::sanitize_input_middleware,
    json::validate_json_payload_middleware,
};

use crate::controllers::info::get_api_info;
use crate::utils::security::timing::constant_time_eq_str;
use crate::utils::security::origin::{allowed_origins, is_cors_response_header};
use crate::utils::security::monitor::{SecurityEventType, SecurityMonitor};

pub async fn security_headers_middleware(
    req: ServiceRequest,
    next: actix_web_lab::middleware::Next<impl actix_web::body::MessageBody>,
) -> Result<ServiceResponse<impl actix_web::body::MessageBody>, actix_web::Error> {
    let mut res = next.call(req).await?;

    let headers = res.headers_mut();

    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::HeaderName::from_static("x-xss-protection"),
        header::HeaderValue::from_static("0"),
    );
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        header::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        header::HeaderValue::from_static(
            "geolocation=(), microphone=(self), camera=(self), payment=(), usb=(), \
             magnetometer=(), gyroscope=()",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("x-download-options"),
        header::HeaderValue::from_static("noopen"),
    );
    headers.insert(
        header::HeaderName::from_static("x-permitted-cross-domain-policies"),
        header::HeaderValue::from_static("none"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        header::HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-embedder-policy"),
        header::HeaderValue::from_static("credentialless"),
    );

    if crate::utils::env::is_production() {
        headers.insert(
            header::HeaderName::from_static("strict-transport-security"),
            header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }

    let csp = crate::utils::security::csp::content_security_policy(
        crate::utils::env::is_production(),
    );
    if let Ok(value) = header::HeaderValue::from_str(&csp) {
        headers.insert(
            header::HeaderName::from_static("content-security-policy"),
            value,
        );
    }

    headers.remove("x-powered-by");
    headers.remove("server");

    Ok(res)
}

pub async fn suspicious_request_middleware(
    req: ServiceRequest,
    next: actix_web_lab::middleware::Next<impl actix_web::body::MessageBody + 'static>,
) -> Result<ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    use regex::Regex;

    lazy_static::lazy_static! {
        static ref SUSPICIOUS_PATTERNS: Vec<Regex> = vec![
            Regex::new(r"\.\.").unwrap(),
            Regex::new(r"(?i)<script").unwrap(),
            Regex::new(r"(?i)javascript:").unwrap(),
            Regex::new(r"(?i)on\w+\s*=").unwrap(),
            Regex::new(r"(?i)union.*select").unwrap(),
            Regex::new(r"(?i)drop\s+table").unwrap(),
            Regex::new(r"(?i)exec\s*\(").unwrap(),
        ];
    }

    let uri = req.uri().to_string();
    let query = req.query_string().to_string();
    let ip = crate::utils::ip::client_ip_from_service_request(&req);
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let request_string = format!("{} {}", uri, query);

    let is_suspicious = SUSPICIOUS_PATTERNS
        .iter()
        .any(|pattern| pattern.is_match(&request_string));

    if is_suspicious {
        if let Some(monitor) = req.app_data::<web::Data<SecurityMonitor>>() {
            monitor.log_event(
                SecurityEventType::SuspiciousRequests,
                serde_json::json!({
                    "ip": ip,
                    "url": uri,
                    "userAgent": user_agent,
                }),
            );
        }

        log::warn!(
            "Suspicious request detected: ip={}, url={}, user_agent={}, timestamp={}",
            ip,
            uri,
            user_agent,
            chrono::Utc::now().to_rfc3339()
        );

        let (req, _payload) = req.into_parts();
        let res = HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "Invalid request" }));
        return Ok(ServiceResponse::new(req, res).map_into_boxed_body());
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}

pub async fn security_report_handler(
    req: HttpRequest,
    security_monitor: web::Data<SecurityMonitor>,
) -> HttpResponse {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let secret = env::var("SECURITY_REPORT_SECRET").unwrap_or_default();
    if secret.trim().is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Not found" }));
    }
    let expected = format!("Bearer {}", secret);

    match auth_header {
        Some(h) if constant_time_eq_str(h, &expected) => {
            let report = security_monitor.get_security_report();
            HttpResponse::Ok().json(report)
        }
        _ => HttpResponse::Unauthorized().json(serde_json::json!({ "error": "Unauthorized" })),
    }
}

pub async fn not_found_handler(_req: HttpRequest) -> HttpResponse {
    HttpResponse::NotFound().json(serde_json::json!({
        "error": "Route not found",
    }))
}

pub fn create_app(
    security_monitor: web::Data<SecurityMonitor>,
    ip_block: web::Data<IPBlockerArc>,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    App::new()
        .app_data(security_monitor.clone())
        .app_data(ip_block.clone())
        .app_data(
            web::JsonConfig::default()
                .limit(MAX_JSON_PAYLOAD_BYTES as usize)
                .error_handler(|err, _req| {
                    log::warn!("JSON payload error: {err}");
                    let response = HttpResponse::BadRequest()
                        .json(serde_json::json!({ "error": "Invalid request payload" }));
                    actix_web::error::InternalError::from_response(err, response).into()
                }),
        )
        .app_data(
            web::FormConfig::default()
                .limit(MAX_JSON_PAYLOAD_BYTES as usize),
        )
        .app_data(
            MultipartFormConfig::default()
                .total_limit(MAX_HTTP_BODY_BYTES)
                .memory_limit(1024 * 1024),
        )
        .wrap(Compress::default())
        .wrap(from_fn(security_headers_middleware))
        .wrap(from_fn(suspicious_request_middleware))
        .wrap(from_fn(ip_blocker_middleware))
        .wrap(from_fn(track_suspicious_activity))
        .wrap(from_fn(global_limiter))
        .wrap(from_fn(client_guard_middleware))
        .wrap(from_fn(origin_guard_middleware))
        .wrap(from_fn(csrf_middleware))
        .wrap(from_fn(sanitize_input_middleware))
        .wrap(from_fn(validate_json_payload_middleware))
        .wrap(from_fn(proxy))
        .service(web::resource("/").route(web::get().to(get_api_info)))
        .service(web::resource("/api").route(web::get().to(get_api_info)))
        .service(web::resource("/api/").route(web::get().to(get_api_info)))
        .service(
            web::scope("/api/auth")
                .configure(auth::configure),
        )
        .service(
            web::scope("/api/channel")
                .wrap(from_fn(send_limiter))
                .configure(channels::configure),
        )
        .service(
            web::scope("/api/channels")
                .wrap(from_fn(send_limiter))
                .configure(channels::configure),
        )
        .service(
            web::scope("/api/contacts")
                .configure(contacts::configure),
        )
        .service(
            web::scope("/api/contact")
                .configure(contacts::configure),
        )
        .service(
            web::scope("/api/messages")
                .wrap(from_fn(send_limiter))
                .configure(messages::configure),
        )
        .service(
            web::scope("/api/message")
                .wrap(from_fn(send_limiter))
                .configure(messages::configure),
        )
        .service(
            web::scope("/api/friends")
                .configure(friends::configure),
        )
        .service(
            web::scope("/api/friend")
                .configure(friends::configure),
        )
        .service(
            web::scope("/api/gifs")
                .wrap(from_fn(send_limiter))
                .configure(gifs::configure),
        )
        .service(
            web::scope("/api/gif")
                .wrap(from_fn(send_limiter))
                .configure(gifs::configure),
        )
        .service(
            web::scope("/api/stickers")
                .wrap(from_fn(send_limiter))
                .configure(stickers::configure),
        )
        .service(
            web::scope("/api/emojis")
                .configure(emojis::configure),
        )
        .service(
            web::scope("/api/emoji")
                .configure(emojis::configure),
        )
        .service(
            web::scope("/api/voice")
                .wrap(from_fn(send_limiter))
                .configure(voice::configure),
        )
        .service(
            web::scope("/api/voices")
                .wrap(from_fn(send_limiter))
                .configure(voice::configure),
        )
        .service(
            web::scope("/api/user")
                .configure(users::configure),
        )
        .service(
            web::scope("/api/users")
                .configure(users::configure),
        )
        .service(
            web::scope("/api/user/status")
                .configure(status::configure),
        )
        .service(
            web::scope("/api/status")
                .configure(status::configure),
        )
        .service(
            web::scope("/api/security")
                .wrap(from_fn(auth_rate_limiter))
                .service(web::resource("").route(web::get().to(security_report_handler)))
                .service(web::resource("/").route(web::get().to(security_report_handler)))
                .route("/report", web::get().to(security_report_handler)),
        )
        .service(
            web::scope("/api/invite")
                .configure(invites::configure),
        )
        .service(
            web::scope("/api/invites")
                .configure(invites::configure),
        )
        .default_service(web::to(not_found_handler))
}

pub async fn run_server() -> std::io::Result<()> {
    use axum::{body::Body, extract::ConnectInfo, middleware, response::Response, Router};
    use http::Request;
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use tower::ServiceBuilder;

    let port = match env::var("PORT") {
        Ok(raw) => match raw.trim().parse::<u16>() {
            Ok(p) if p != 0 => p,
            _ => {
                log::warn!("PORT ('{raw}') is not a valid port number — falling back to 6700");
                6700
            }
        },
        Err(_) => 6700,
    };

    let internal_port_env = env::var("INTERNAL_HTTP_PORT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let internal_port = internal_port_env
        .as_ref()
        .and_then(|p| p.parse::<u16>().ok())
        .filter(|p| *p != 0)
        .unwrap_or_else(|| port.saturating_add(1));

    let security_monitor = web::Data::new(SecurityMonitor::new());
    let ip_block = std::sync::Arc::new(IPBlockerArc::new());
    let ip_blocker_data = web::Data::from(ip_block.clone());

    let sm = security_monitor.clone();
    let ib = ip_blocker_data.clone();

    let internal_listener = if crate::utils::env::is_production() {
        std::net::TcpListener::bind(("127.0.0.1", internal_port))
            .expect("Failed to bind internal actix server — set INTERNAL_HTTP_PORT")
    } else if internal_port_env.is_some() {
        std::net::TcpListener::bind(("127.0.0.1", internal_port))
            .expect("Failed to bind internal actix server")
    } else {
        std::net::TcpListener::bind(("127.0.0.1", internal_port)).unwrap_or_else(|_| {
            std::net::TcpListener::bind(("127.0.0.1", 0))
                .expect("Failed to bind internal actix server on fallback port")
        })
    };
    let actual_internal_port = internal_listener
        .local_addr()
        .expect("Failed to determine internal listener port")
        .port();

    tokio::spawn(async move {
        if let Err(e) = HttpServer::new(move || create_app(sm.clone(), ib.clone()))
            .listen(internal_listener)
            .expect("Failed to bind internal actix server")
            .run()
            .await
        {
            log::error!("Internal actix server error: {e}");
        }
    });

    async fn public_security_headers(req: Request<Body>, next: middleware::Next) -> Response {
        let mut res = next.run(req).await;
        let headers = res.headers_mut();
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
        headers.insert(
            "referrer-policy",
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
        headers.insert(
            "cross-origin-opener-policy",
            HeaderValue::from_static("same-origin"),
        );
        if crate::utils::env::is_production() {
            headers.insert(
                "strict-transport-security",
                HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            );
            let csp = crate::utils::security::csp::content_security_policy(true);
            if let Ok(value) = HeaderValue::from_str(&csp) {
                headers.insert("content-security-policy", value);
            }
        }
        headers.insert(
            "permissions-policy",
            HeaderValue::from_static(
                "geolocation=(), microphone=(self), camera=(self), payment=(), usb=()",
            ),
        );
        res
    }

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .expect("Failed to build HTTP proxy client");
    let internal_base = format!("http://127.0.0.1:{actual_internal_port}");
    let health_url = format!("{internal_base}/");

    for attempt in 0..50 {
        let mut health_req = client.get(&health_url);
        if let Some(secret) = internal_proxy_secret() {
            health_req = health_req.header(INTERNAL_PROXY_HEADER, secret);
        }
        match health_req.send().await {
            Ok(resp) if resp.status().is_success() => break,
            _ if attempt == 49 => {
                log::warn!(
                    "Internal actix server did not become ready on {internal_base}; continuing anyway"
                );
            }
            _ => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
        }
    }

    let socket_state = crate::ws::state::SocketState::new();
    let registry = crate::ws::registry::ConnectionRegistry::new();
    crate::ws::init(registry.clone());
    let ip_blocker_http = ip_block.clone();
    let ws_state = crate::ws::WsAppState {
        socket_state,
        registry,
        ip_block,
    };

    let allowed_origins = allowed_origins();
    use http::header::{self, HeaderValue};
    use http::Method;
    use tower_http::cors::AllowOrigin;

    use crate::utils::security::cors::CORS_ALLOWED_REQUEST_HEADERS;

    let origin_headers: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|origin| origin.parse().ok())
        .collect();

    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(if origin_headers.is_empty() {
            AllowOrigin::exact(
                "http://127.0.0.1:5173"
                    .parse()
                    .unwrap_or_else(|_| HeaderValue::from_static("http://127.0.0.1:5173")),
            )
        } else {
            AllowOrigin::list(origin_headers)
        })
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])

        .allow_headers(CORS_ALLOWED_REQUEST_HEADERS)
        .expose_headers([
            header::CONTENT_DISPOSITION,
            header::HeaderName::from_static("x-total-count"),
            header::HeaderName::from_static("x-rate-limit-remaining"),
            header::HeaderName::from_static("x-rate-limit-reset"),
        ])
        .max_age(std::time::Duration::from_secs(86400))
        .allow_credentials(true);

    log::info!(
        "CORS allow-headers: {}",
        crate::utils::security::cors::cors_allowed_request_header_names().join(", ")
    );

    let client2 = client.clone();
    let base2 = internal_base.clone();

    fn proxy_json(status: http::StatusCode, body: String) -> Response<Body> {
        Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }

    async fn proxy_to_actix(
        req: Request<Body>,
        client: reqwest::Client,
        internal_base: String,
        ip_block: std::sync::Arc<IPBlockerArc>,
    ) -> Result<Response<Body>, Infallible> {
        let method = req.method().clone();
        let path = req
            .uri()
            .path_and_query()
            .map(|x| x.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        if path.len() > MAX_PROXY_URI_BYTES {
            return Ok(proxy_json(
                http::StatusCode::URI_TOO_LONG,
                r#"{"error":"URI too long"}"#.to_string(),
            ));
        }

        let url = format!("{internal_base}{path}");

        let (parts, body) = req.into_parts();
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0);
        let client_ip = crate::utils::ip::client_ip_from_headers(&parts.headers, peer);

        if !crate::utils::security::transport::is_secure_client_connection(&parts.headers) {
            log::warn!(
                "HTTP request rejected — insecure transport (require HTTPS in production) path={path} ip={client_ip}"
            );
            return Ok(proxy_json(
                http::StatusCode::FORBIDDEN,
                r#"{"error":"Secure connection required"}"#.to_string(),
            ));
        }

        if ip_block.is_blocked(&client_ip) {
            return Ok(proxy_json(
                http::StatusCode::FORBIDDEN,
                r#"{"error":"Access denied"}"#.to_string(),
            ));
        }

        if let Err(retry_after) = edge_http_allowed(&client_ip) {
            let mut response = proxy_json(
                http::StatusCode::TOO_MANY_REQUESTS,
                format!(
                    r#"{{"error":"Too many requests from this IP, please try again later.","retryAfter":{retry_after}}}"#
                ),
            );
            if let Ok(value) = http::HeaderValue::from_str(&retry_after.to_string()) {
                response.headers_mut().insert(http::header::RETRY_AFTER, value);
            }
            return Ok(response);
        }

        let path_only = parts.uri.path();
        let client_header = parts
            .headers
            .get(crate::utils::security::id::CLIENT_HEADER_NAME)
            .and_then(|value| value.to_str().ok());
        if !crate::utils::security::id::official_client_presented(
            method.as_str(),
            path_only,
            parts.uri.query(),
            client_header,
        ) {
            ip_block.add_suspicious_activity(&client_ip);
            return Ok(proxy_json(
                http::StatusCode::BAD_REQUEST,
                r#"{"error":"Unsupported client"}"#.to_string(),
            ));
        }

        let content_type = parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        let max_body = max_proxy_body_bytes(method.as_str(), content_type);
        if let Some(declared) = parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
        {
            if declared > max_body {
                return Ok(proxy_json(
                    http::StatusCode::PAYLOAD_TOO_LARGE,
                    r#"{"error":"Payload too large"}"#.to_string(),
                ));
            }
        }

        let Some(_http_slot) = try_acquire_http_slot() else {
            return Ok(proxy_json(
                http::StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"Server busy"}"#.to_string(),
            ));
        };

        let proxy_work = async {
        let body_bytes = match axum::body::to_bytes(body, max_body).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(Response::builder()
                    .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"Payload too large"}"#))
                    .unwrap_or_else(|_| Response::new(Body::empty())));
            }
        };
        let body_len = body_bytes.len();

        fn should_strip_request_header(name: &str) -> bool {
            matches!(
                name,
                "host"
                    | "content-length"
                    | "transfer-encoding"
                    | "content-encoding"
                    | "connection"
                    | "keep-alive"
                    | "te"
                    | "trailer"
                    | "upgrade"
                    | "x-real-ip"
                    | "x-forwarded-for"
                    | "x-forwarded-proto"
                    | "cf-connecting-ip"
                    | "true-client-ip"
            )
        }

        let mut rb = client.request(method, &url).body(body_bytes);
        for (name, value) in parts.headers.iter() {
            let name_str = name.as_str();
            if should_strip_request_header(name_str) {
                continue;
            }
            rb = rb.header(name, value);
        }

        rb = rb.header("X-Real-IP", &client_ip);
        rb = rb.header("X-Forwarded-For", &client_ip);
        if crate::utils::security::transport::proxy_headers_indicate_https(&parts.headers) {
            rb = rb.header("X-Forwarded-Proto", "https");
        } else if let Some(proto) = parts
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            rb = rb.header("X-Forwarded-Proto", proto);
        }
        if let Some(secret) = internal_proxy_secret() {
            rb = rb.header(INTERNAL_PROXY_HEADER, secret);
        }

        match rb.send().await {
            Ok(resp) => {
                let status = resp.status();
                let headers = resp.headers().clone();
                let bytes = match crate::utils::http::read_response_limited(
                    resp,
                    crate::utils::http::MAX_PROXY_RESPONSE_BYTES,
                )
                .await
                {
                    Ok(bytes) => bytes,
                    Err(crate::utils::http::LimitedBodyError::TooLarge) => {
                        log::error!(
                            "HTTP proxy response too large path={path} body_bytes={body_len}"
                        );
                        return Ok(Response::builder()
                            .status(http::StatusCode::BAD_GATEWAY)
                            .header(http::header::CONTENT_TYPE, "application/json")
                            .body(Body::from(
                                r#"{"error":"Bad Gateway","detail":"internal proxy"}"#,
                            ))
                            .unwrap_or_else(|_| Response::new(Body::empty())));
                    }
                    Err(_) => Vec::new(),
                };
                let mut builder = Response::builder().status(status);
                for (k, v) in headers.iter() {
                    if k == http::header::TRANSFER_ENCODING {
                        continue;
                    }

                    if is_cors_response_header(k.as_str()) {
                        continue;
                    }
                    builder = builder.header(k, v);
                }
                Ok(builder
                    .body(Body::from(bytes))
                    .unwrap_or_else(|_| Response::new(Body::empty())))
            }
            Err(e) => {
                log::error!(
                    "HTTP proxy to actix failed path={path} body_bytes={body_len}: {e}"
                );
                Ok(Response::builder()
                    .status(http::StatusCode::BAD_GATEWAY)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"Bad Gateway","detail":"internal proxy"}"#))
                    .unwrap_or_else(|_| Response::new(Body::empty())))
            }
        }
        };

        match tokio::time::timeout(HTTP_EDGE_TIMEOUT, proxy_work).await {
            Ok(response) => response,
            Err(_) => {
                log::warn!("HTTP proxy timed out path={path}");
                Ok(proxy_json(
                    http::StatusCode::REQUEST_TIMEOUT,
                    r#"{"error":"Request timeout"}"#.to_string(),
                ))
            }
        }
    }

    let app = Router::new()

        .route("/ws", axum::routing::any(crate::ws::ws_handler))
        .fallback(move |req: Request<Body>| {
            let c = client2.clone();
            let b = base2.clone();
            let blocker = ip_blocker_http.clone();
            async move { proxy_to_actix(req, c, b, blocker).await }
        })
        .layer(middleware::from_fn(public_security_headers))
        .with_state(ws_state);

    let app = app.layer(ServiceBuilder::new().layer(cors));

    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(listener) => listener,
        Err(err) if env::var("PORT").is_err() => {
            log::warn!(
                "Port {port} unavailable, falling back to an ephemeral port: {err}"
            );
            tokio::net::TcpListener::bind(("0.0.0.0", 0)).await?
        }
        Err(err) => return Err(err),
    };
    let actual_port = listener.local_addr()?.port();

    log::info!(
        "Klovy Chat listening on 0.0.0.0:{actual_port} (HTTP→actix 127.0.0.1:{actual_internal_port}, WebSocket /ws)"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("Shutdown signal received, stopping server...");
    })
    .await?;
    Ok(())
}
