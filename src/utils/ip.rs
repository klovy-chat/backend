// ip.rs
// IP z Forwarded / CF-Connecting-IP.
// Zakres:
//  - rate limit, ban, sesje
//  - Forwarded / CF-Connecting-IP do limitu, bana, sesji
// Za złym proxy wszyscy wyglądają na 1 IP — strojenie zaufanych hopów.
// Przy zmianach: ip_block.rs, ratelimit, ws/mod.rs.

use std::net::{IpAddr, SocketAddr};

use actix_web::{dev::ServiceRequest, HttpRequest};
use http::HeaderMap;

fn trust_proxy_headers() -> bool {
    std::env::var("TRUST_PROXY")
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

fn normalize_client_ip_candidate(raw: &str) -> Option<String> {
    let mut ip = raw.trim().trim_matches('"');
    if ip.is_empty() {
        return None;
    }

    if ip.starts_with('[') {
        if let Some(end) = ip.find(']') {
            ip = &ip[1..end];
        }
    } else if ip.contains(':') && ip.contains('.') {
        if let Some(host) = ip.rsplit_once(':').map(|(host, _)| host) {
            ip = host;
        }
    }

    let parsed = ip.parse::<IpAddr>().ok()?;
    Some(parsed.to_string())
}

fn forwarded_header_ip(raw: &str) -> Option<String> {
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("for=") {
            if let Some(ip) = normalize_client_ip_candidate(value) {
                return Some(ip);
            }
        }
    }
    None
}

fn x_forwarded_for_client_ip(raw: &str) -> Option<String> {
    raw.split(',')
        .find_map(|part| normalize_client_ip_candidate(part))
}

fn client_ip_from_header_values(
    cf_connecting_ip: Option<&str>,
    true_client_ip: Option<&str>,
    x_forwarded_for: Option<&str>,
    forwarded: Option<&str>,
    x_real_ip: Option<&str>,
) -> Option<String> {
    if let Some(raw) = cf_connecting_ip {
        if let Some(ip) = normalize_client_ip_candidate(raw) {
            return Some(ip);
        }
    }

    if let Some(raw) = true_client_ip {
        if let Some(ip) = normalize_client_ip_candidate(raw) {
            return Some(ip);
        }
    }

    if let Some(raw) = x_forwarded_for {
        if let Some(ip) = x_forwarded_for_client_ip(raw) {
            return Some(ip);
        }
    }

    if let Some(raw) = forwarded {
        if let Some(ip) = forwarded_header_ip(raw) {
            return Some(ip);
        }
    }

    if let Some(raw) = x_real_ip {
        if let Some(ip) = normalize_client_ip_candidate(raw) {
            return Some(ip);
        }
    }

    None
}

fn ip_from_http_headers(headers: &HeaderMap) -> Option<String> {
    client_ip_from_header_values(
        headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok()),
        headers.get("true-client-ip").and_then(|v| v.to_str().ok()),
        headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
        headers.get("forwarded").and_then(|v| v.to_str().ok()),
        headers.get("x-real-ip").and_then(|v| v.to_str().ok()),
    )
}

fn ip_from_actix_headers(headers: &actix_web::http::header::HeaderMap) -> Option<String> {
    client_ip_from_header_values(
        headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok()),
        headers.get("true-client-ip").and_then(|v| v.to_str().ok()),
        headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
        headers.get("forwarded").and_then(|v| v.to_str().ok()),
        headers.get("x-real-ip").and_then(|v| v.to_str().ok()),
    )
}

pub fn client_ip_from_headers(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if trust_proxy_headers() {
        if let Some(ip) = ip_from_http_headers(headers) {
            return ip;
        }
    }

    peer.map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn client_ip_from_http_request(req: &HttpRequest) -> String {
    if trust_proxy_headers() {
        if let Some(ip) = ip_from_actix_headers(req.headers()) {
            return ip;
        }
    }

    req.connection_info()
        .realip_remote_addr()
        .map(str::to_string)
        .or_else(|| req.connection_info().peer_addr().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn client_ip_from_service_request(req: &ServiceRequest) -> String {
    if trust_proxy_headers() {
        if let Some(ip) = ip_from_actix_headers(req.headers()) {
            return ip;
        }
    }

    req.connection_info()
        .peer_addr()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
