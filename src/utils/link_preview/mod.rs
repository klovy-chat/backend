// mod.rs
// OG preview tylko https, limity rozmiaru.
// Zakres:
//  - SSR F karta
//  - OG tylko https; SSRF — nie fetchuj RFC1918
// SSRF: nie fetchuj RFC1918. Allowlista hostów w urls.rs.
// Przy zmianach: controllers/messages.rs, embeds.ts.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use regex::Regex;
use reqwest::redirect::Policy;
use serde::Serialize;

const MAX_HTML_BYTES: usize = 512 * 1024;
const MAX_PREVIEW_REDIRECTS: usize = 3;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkPreview {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,
}

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        other => other,
    }
}

fn ip_is_disallowed(ip: IpAddr) -> bool {
    match canonicalize_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 198 && matches!(o[1], 18 | 19))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

fn host_is_blocked(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return true;
    }
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return true;
    }
    if host == "metadata.google.internal" {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip_is_disallowed(ip);
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return ip_is_disallowed(IpAddr::V4(v4));
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return ip_is_disallowed(IpAddr::V6(v6));
    }
    false
}

async fn host_resolves_public(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    if host_is_blocked(host) {
        return None;
    }
    let Ok(addrs) = tokio::net::lookup_host((host, port)).await else {
        return None;
    };
    let mut public_addrs = Vec::new();
    for addr in addrs {
        if ip_is_disallowed(addr.ip()) {
            return None;
        }
        public_addrs.push(addr);
    }
    (!public_addrs.is_empty()).then_some(public_addrs)
}

fn client_for_resolved_host(
    host: &str,
    addrs: &[SocketAddr],
) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(6))
        .user_agent("KlovyChatLinkPreview/1.0")
        .no_proxy()
        .resolve_to_addrs(host, addrs)
        .build()
}

pub fn is_safe_preview_target(url: &str) -> bool {
    let trimmed = url.trim();
    if !trimmed.starts_with("https://") {
        return false;
    }
    if trimmed.contains("..") || trimmed.contains('\\') || trimmed.contains('@') {
        return false;
    }

    let parsed = match reqwest::Url::parse(trimmed) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };

    if parsed.username() != "" || parsed.password().is_some() {
        return false;
    }

    let Some(host) = parsed.host_str() else {
        return false;
    };

    !host_is_blocked(host)
}

fn meta_content(html: &str, property: &str) -> Option<String> {
    let escaped = regex::escape(property);
    let patterns = [
        format!(r#"(?is)<meta[^>]+property=["']{escaped}["'][^>]+content=["']([^"']+)["']"#),
        format!(r#"(?is)<meta[^>]+content=["']([^"']+)["'][^>]+property=["']{escaped}["']"#),
        format!(r#"(?is)<meta[^>]+name=["']{escaped}["'][^>]+content=["']([^"']+)["']"#),
        format!(r#"(?is)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']{escaped}["']"#),
    ];

    for pattern in patterns {
        let Ok(re) = Regex::new(&pattern) else {
            continue;
        };
        if let Some(caps) = re.captures(html) {
            let value = caps.get(1)?.as_str().trim();
            if !value.is_empty() {
                return Some(decode_basic_entities(value));
            }
        }
    }

    None
}

fn decode_basic_entities(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn normalize_preview_image(base: &reqwest::Url, raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let resolved = if trimmed.starts_with("//") {
        reqwest::Url::parse(&format!("https:{trimmed}")).ok()
    } else if trimmed.starts_with("https://") {
        reqwest::Url::parse(trimmed).ok()
    } else if trimmed.starts_with('/') {
        base.join(trimmed).ok()
    } else {
        base.join(trimmed).ok()
    }?;

    if resolved.scheme() != "https" {
        return None;
    }

    let host = resolved.host_str()?;
    if host_is_blocked(host) {
        return None;
    }

    Some(resolved.to_string())
}

fn extract_title(html: &str) -> Option<String> {
    meta_content(html, "og:title")
        .or_else(|| meta_content(html, "twitter:title"))
        .or_else(|| {
            let re = Regex::new(r"(?is)<title[^>]*>([^<]+)</title>").ok()?;
            let caps = re.captures(html)?;
            let value = caps.get(1)?.as_str().trim();
            if value.is_empty() {
                None
            } else {
                Some(decode_basic_entities(value))
            }
        })
}

pub async fn fetch_link_preview(url: &str) -> Result<LinkPreview, &'static str> {
    let mut current = reqwest::Url::parse(url.trim()).map_err(|_| "Invalid preview URL.")?;
    let mut hops = 0usize;

    loop {
        if !is_safe_preview_target(current.as_str()) {
            return Err("Invalid preview URL.");
        }
        let Some(host) = current.host_str().map(str::to_string) else {
            return Err("Invalid preview URL.");
        };
        let port = current
            .port_or_known_default()
            .ok_or("Invalid preview URL.")?;
        let addrs = host_resolves_public(&host, port)
            .await
            .ok_or("Invalid preview URL.")?;
        let client =
            client_for_resolved_host(&host, &addrs).map_err(|_| "Failed to fetch preview.")?;

        let response = client
            .get(current.clone())
            .header(reqwest::header::ACCEPT, "text/html,application/xhtml+xml")
            .send()
            .await
            .map_err(|_| "Failed to fetch preview.")?;

        if response.status().is_redirection() {
            if hops >= MAX_PREVIEW_REDIRECTS {
                return Err("Preview unavailable.");
            }
            hops += 1;
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or("Preview unavailable.")?;
            current = current
                .join(location)
                .or_else(|_| reqwest::Url::parse(location))
                .map_err(|_| "Invalid preview URL.")?;
            continue;
        }

        if !response.status().is_success() {
            return Err("Preview unavailable.");
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();

        if !content_type.contains("text/html") && !content_type.contains("application/xhtml") {
            return Err("Preview unavailable.");
        }

        let bytes = crate::utils::http::read_response_limited(response, MAX_HTML_BYTES)
            .await
            .map_err(|err| match err {
                crate::utils::http::LimitedBodyError::TooLarge => "Preview too large.",
                crate::utils::http::LimitedBodyError::ReadFailed => "Failed to read preview.",
            })?;

        let html = String::from_utf8_lossy(&bytes);
        let title = extract_title(&html);
        let description = meta_content(&html, "og:description")
            .or_else(|| meta_content(&html, "twitter:description"))
            .or_else(|| meta_content(&html, "description"));
        let site_name = meta_content(&html, "og:site_name");
        let image = meta_content(&html, "og:image")
            .or_else(|| meta_content(&html, "twitter:image"))
            .or_else(|| meta_content(&html, "twitter:image:src"))
            .and_then(|raw| normalize_preview_image(&current, &raw));

        if title.is_none() && description.is_none() && image.is_none() {
            return Err("Preview unavailable.");
        }

        return Ok(LinkPreview {
            url: current.to_string(),
            title,
            description,
            image,
            site_name,
        });
    }
}
