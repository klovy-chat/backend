// url.rs
// Tylko poprawne https URL.
// Zakres:
//  - invite, embed, zewnętrzne media w wiadomości
//  - https; http tylko świadomie w DEV
//  - fileUrl https = allowlista hostów (nie dowolny .png)
// http tylko świadomie (DEV).
// Przy zmianach: embeds.ts, invites, FE allowedMedia.ts.

fn normalize_host(host: &str) -> String {
    let lower = host.trim_end_matches('.').to_ascii_lowercase();
    lower
        .strip_prefix("www.")
        .unwrap_or(lower.as_str())
        .trim_end_matches('.')
        .to_string()
}

fn is_trusted_external_media_host(host: &str) -> bool {
    let host = normalize_host(host);
    if host.is_empty() {
        return false;
    }
    if host == "media.giphy.com"
        || host == "i.giphy.com"
        || host.ends_with(".giphy.com")
        || host == "cdn.discordapp.com"
        || host == "media.discordapp.net"
        || host == "i.imgur.com"
        || host == "media.tenor.com"
        || host == "images.unsplash.com"
        || host == "raw.githubusercontent.com"
    {
        return true;
    }
    false
}

pub fn is_allowed_external_media_url(url: &str) -> bool {
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

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }

    let Some(host) = parsed.host_str() else {
        return false;
    };

    if !is_trusted_external_media_host(host) {
        return false;
    }

    parsed.path().split('/').any(|part| !part.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_arbitrary_image_hosts() {
        assert!(!is_allowed_external_media_url(
            "https://evil.example/payload.png"
        ));
        assert!(!is_allowed_external_media_url("https://127.0.0.1/x.png"));
    }

    #[test]
    fn allows_known_cdn_hosts_with_path() {
        assert!(is_allowed_external_media_url(
            "https://media.giphy.com/media/abc/giphy.gif"
        ));
        assert!(is_allowed_external_media_url("https://i.imgur.com/abc.png"));
        assert!(!is_allowed_external_media_url("https://i.imgur.com/"));
        assert!(
            !is_allowed_external_media_url("https://cdn.klovy.chat/attachments/dm/x/y.webp"),
            "own CDN must not skip the attachment scan path"
        );
    }
}
