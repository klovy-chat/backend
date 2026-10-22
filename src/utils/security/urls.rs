// urls.rs
// Allowlista URL (CDN, Giphy, LiveKit, emoji JSON).
// Zakres:
//  - embed i proxy
//  - CDN, Giphy, LiveKit, emoji JSON — nowy host też na FE
// Nowy host mediów: tu + FE allowedMedia.ts.
// Przy zmianach: gifs.rs, livekit, ExternalMedia.

const DEFAULT_EMOJI_API_URL: &str =
    "https://cdn.jsdelivr.net/npm/unicode-emoji-json@0.9.0/data-by-group.json";

fn host_blocked(hostname: &str) -> bool {
    let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return true;
    }
    if host == "127.0.0.1" || host == "::1" || host == "[::1]" || host.ends_with(".local") {
        return true;
    }
    if host == "::1" || host == "[::1]" {
        return true;
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip_is_blocked(ip);
    }

    if let Some(stripped) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        if let Ok(ip) = stripped.parse::<std::net::IpAddr>() {
            return ip_is_blocked(ip);
        }
    }

    false
}

fn ip_is_blocked(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.octets()[0] == 10
                || (v4.octets()[0] == 172 && (16..=31).contains(&v4.octets()[1]))
                || (v4.octets()[0] == 192 && v4.octets()[1] == 168)
                || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
                || v4.octets()[0] == 0
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || v6.is_unique_local()
        }
    }
}

fn parse_https_host(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let without_scheme = trimmed.strip_prefix("https://")?;
    let host = without_scheme.split('/').next()?.split(':').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn parse_wss_or_https_host(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let without_scheme = trimmed
        .strip_prefix("wss://")
        .or_else(|| trimmed.strip_prefix("https://"))?;
    let host = without_scheme.split('/').next()?.split(':').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

pub fn is_allowed_outbound_https_url(url: &str) -> bool {
    let trimmed = url.trim();
    if !trimmed.starts_with("https://") {
        return false;
    }
    if trimmed.contains("..") {
        return false;
    }

    let without_scheme = trimmed.strip_prefix("https://").unwrap_or(trimmed);
    let authority = without_scheme.split('/').next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }

    let Some(host) = parse_https_host(trimmed) else {
        return false;
    };

    !host_blocked(&host)
}

pub fn resolve_emoji_api_url() -> String {
    if let Ok(raw) = std::env::var("EMOJI_API_URL") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && is_allowed_outbound_https_url(trimmed) {
            return trimmed.to_string();
        }
        if !trimmed.is_empty() {
            log::warn!("EMOJI_API_URL is not allowed (must be public HTTPS); using default");
        }
    }
    DEFAULT_EMOJI_API_URL.to_string()
}

pub fn resolve_security_webhook_url() -> Option<String> {
    let raw = std::env::var("SECURITY_WEBHOOK_URL").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_allowed_outbound_https_url(trimmed) {
        Some(trimmed.to_string())
    } else {
        log::warn!("SECURITY_WEBHOOK_URL blocked (must be public HTTPS)");
        None
    }
}

pub fn is_allowed_livekit_url(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.contains("..") || trimmed.contains('@') {
        return false;
    }
    if !(trimmed.starts_with("wss://") || trimmed.starts_with("https://")) {
        return false;
    }

    let Some(host) = parse_wss_or_https_host(trimmed) else {
        return false;
    };

    !host_blocked(&host)
}
