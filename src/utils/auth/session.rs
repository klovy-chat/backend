// session.rs
// Lista/revoke sesji, wiązanie UA.
// Zakres:
//  - wiersze w ustawieniach
//  - lista/revoke; logout all kasuje family refresh
// Revoke family refresh przy logout all.
// Przy zmianach: refresh.rs, Panel.tsx.

use crate::utils::security::client::ClientEnvironmentHints;

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub browser: String,
    pub os: String,
    pub label: String,
    pub is_known: bool,
}

const MAX_LABEL_LEN: usize = 160;

fn sanitize_client_label(value: Option<&String>) -> Option<String> {
    let raw = value?.trim();
    if raw.is_empty() || raw.len() > MAX_LABEL_LEN {
        return None;
    }
    if raw.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(raw.to_string())
}

fn short_version(version: &str, parts: usize) -> String {
    let chunks: Vec<&str> = version.split('.').filter(|part| !part.is_empty()).collect();
    if chunks.len() <= parts {
        return version.to_string();
    }
    chunks[..parts].join(".")
}

fn extract_platform_primary_segment(ua: &str) -> Option<String> {
    let start = ua.find('(')?;
    let rest = &ua[start + 1..];
    let end = rest.find(')')?;
    let inner = rest[..end].trim();
    if inner.is_empty() {
        return None;
    }

    let noise = [
        "X11",
        "WOW64",
        "Win64",
        "U",
        "Mobile",
        "Tablet",
        "compatible",
    ];

    inner
        .split(';')
        .map(|part| part.trim())
        .find(|part| {
            !part.is_empty()
                && !noise.iter().any(|n| part.eq_ignore_ascii_case(n))
                && !part.starts_with("rv:")
        })
        .map(str::to_string)
}

fn is_version_token(token: &str) -> bool {
    if token.is_empty() {
        return true;
    }
    token
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == '_')
}

fn is_arch_token(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "x86"
            | "x86_64"
            | "x64"
            | "amd64"
            | "i686"
            | "arm64"
            | "aarch64"
            | "wow64"
            | "64-bit"
            | "32-bit"
    )
}

pub fn simplify_os_label(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let primary = trimmed.split('·').next().unwrap_or(trimmed).trim();
    let mut result = Vec::new();
    let mut skip_next = false;

    for word in primary.split_whitespace() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if word.eq_ignore_ascii_case("nt") {
            skip_next = true;
            continue;
        }
        if !is_version_token(word) && !is_arch_token(word) {
            result.push(word);
        }
    }

    result.join(" ").trim().to_string()
}

fn extract_platform_from_user_agent(ua: &str) -> Option<String> {
    extract_platform_primary_segment(ua)
}

fn extract_browser_from_user_agent(ua: &str) -> Option<String> {
    let rules: &[(&str, &str)] = &[
        ("Edg/", "Edge"),
        ("EdgA/", "Edge"),
        ("EdgiOS/", "Edge"),
        ("OPR/", "Opera"),
        ("Vivaldi/", "Vivaldi"),
        ("Firefox/", "Firefox"),
        ("CriOS/", "Chrome"),
        ("Chrome/", "Chrome"),
    ];

    for (needle, name) in rules {
        if let Some(idx) = ua.find(needle) {
            let version_start = idx + needle.len();
            let version: String = ua[version_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !version.is_empty() {
                return Some(format!("{name} {}", short_version(&version, 2)));
            }
            return Some(name.to_string());
        }
    }

    if let Some(idx) = ua.find("Version/") {
        let version_start = idx + "Version/".len();
        let version: String = ua[version_start..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if ua.contains("Safari") {
            if version.is_empty() {
                return Some("Safari".to_string());
            }
            return Some(format!("Safari {}", short_version(&version, 2)));
        }
    }

    None
}

fn fallback_from_user_agent(ua: &str) -> ClientInfo {
    let trimmed = ua.trim();
    if trimmed.is_empty() {
        return ClientInfo {
            browser: "Unknown browser".to_string(),
            os: "Unknown OS".to_string(),
            label: "Unknown session".to_string(),
            is_known: false,
        };
    }

    let browser =
        extract_browser_from_user_agent(trimmed).unwrap_or_else(|| "Unknown browser".to_string());
    let os = simplify_os_label(&extract_platform_from_user_agent(trimmed).unwrap_or_default());
    let os = if os.is_empty() {
        "Unknown OS".to_string()
    } else {
        os
    };
    let is_known = browser != "Unknown browser";
    let label = os.clone();

    ClientInfo {
        browser,
        os,
        label,
        is_known,
    }
}

pub fn normalize_browser_name(browser: &str) -> String {
    match browser.trim().to_ascii_lowercase().as_str() {
        "opera gx" | "opera neon" => "Opera".to_string(),
        other if other.starts_with("opera ") => "Opera".to_string(),
        _ => browser.trim().to_string(),
    }
}

fn detect_browser_family(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("edg") {
        Some("edge")
    } else if lower.contains("opr") || lower.contains("opera") {
        Some("opera")
    } else if lower.contains("vivaldi") {
        Some("vivaldi")
    } else if lower.contains("firefox") || lower.contains("fxios") {
        Some("firefox")
    } else if lower.contains("brave") {
        Some("brave")
    } else if lower.contains("crios") || lower.contains("chrome") || lower.contains("chromium") {
        Some("chrome")
    } else if lower.contains("safari") {
        Some("safari")
    } else {
        None
    }
}

fn detect_os_family(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("android") {
        Some("android")
    } else if lower.contains("iphone")
        || lower.contains("ipad")
        || lower.contains("ipod")
        || lower.contains("ios")
    {
        Some("ios")
    } else if lower.contains("cros") || lower.contains("chrome os") {
        Some("chromeos")
    } else if lower.contains("windows") || lower.contains("win32") || lower.contains("win64") {
        Some("windows")
    } else if lower.contains("mac") || lower.contains("darwin") {
        Some("macos")
    } else if lower.contains("linux") || lower.contains("ubuntu") || lower.contains("x11") {
        Some("linux")
    } else {
        None
    }
}

pub fn resolved_os_label(reported_os: &str, ua: &str) -> String {
    let simplified = simplify_os_label(reported_os);
    if !simplified.is_empty() {
        return simplified;
    }

    let from_ua = simplify_os_label(&extract_platform_from_user_agent(ua).unwrap_or_default());
    if from_ua.is_empty() {
        "Unknown OS".to_string()
    } else {
        from_ua
    }
}

fn client_environment_matches_user_agent(
    reported_browser: &str,
    reported_os: &str,
    ua: &str,
) -> bool {
    let ua_info = fallback_from_user_agent(ua);
    let ua_browser_family = detect_browser_family(&ua_info.browser);
    let reported_browser_family = detect_browser_family(reported_browser);
    let ua_os_family = detect_os_family(&ua_info.os);
    let reported_os_family = detect_os_family(reported_os);

    let browser_ok = match (ua_browser_family, reported_browser_family) {
        (Some(expected), Some(reported)) => expected == reported,
        (None, _) => true,
        (Some(_), None) => false,
    };
    let os_ok = match (ua_os_family, reported_os_family) {
        (Some(expected), Some(reported)) => expected == reported,
        (None, _) => true,
        (Some(_), None) => false,
    };

    browser_ok && os_ok
}

pub fn resolve_client_info(ua: &str, env: &ClientEnvironmentHints) -> ClientInfo {
    if let (Some(browser), Some(os)) = (
        sanitize_client_label(env.browser.as_ref()),
        sanitize_client_label(env.os.as_ref()),
    ) {
        let browser = normalize_browser_name(&browser);
        if client_environment_matches_user_agent(&browser, &os, ua) {
            let os = resolved_os_label(&os, ua);
            let label = os.clone();
            return ClientInfo {
                browser,
                os,
                label,
                is_known: true,
            };
        }
    }

    fallback_from_user_agent(ua)
}
