use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::StatusCode,
    HttpResponse,
};
use actix_web_lab::middleware::Next;
use once_cell::sync::Lazy;
use semver::Version;
use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const DESKTOP_HEADER: &str = "x-klovy-desktop";
const DESKTOP_VERSION_HEADER: &str = "x-klovy-desktop-version";
const RELEASES_URL: &str =
    "https://api.github.com/repos/klovy-chat/application/releases/latest";
const CACHE_TTL: Duration = Duration::from_secs(300);

static LATEST_RELEASE: Lazy<Mutex<Option<(Version, Instant)>>> = Lazy::new(|| Mutex::new(None));

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
}

fn parse_release_version(tag: &str) -> Option<Version> {
    let tag = tag.trim();
    let tag = tag
        .strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .unwrap_or(tag);
    Version::parse(tag).ok()
}

fn is_current_version(client: &Version, latest: &Version) -> bool {
    client >= latest
}

async fn latest_release_version() -> Result<Version, String> {
    let mut cached = LATEST_RELEASE.lock().await;
    if let Some((version, fetched_at)) = cached.as_ref() {
        if fetched_at.elapsed() < CACHE_TTL {
            return Ok(version.clone());
        }
    }

    let release = reqwest::Client::builder()
        .user_agent("KlovyChatBackend")
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| format!("Could not create GitHub client: {error}"))?
        .get(RELEASES_URL)
        .send()
        .await
        .map_err(|error| format!("Could not fetch latest desktop release: {error}"))?
        .error_for_status()
        .map_err(|error| format!("GitHub latest release request failed: {error}"))?
        .json::<GitHubRelease>()
        .await
        .map_err(|error| format!("Could not parse latest desktop release: {error}"))?;

    let version = parse_release_version(&release.tag_name)
        .ok_or_else(|| format!("Invalid desktop release tag: {}", release.tag_name))?;
    *cached = Some((version.clone(), Instant::now()));
    Ok(version)
}

pub async fn desktop_version_guard(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if !req.headers().contains_key(DESKTOP_HEADER) {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let client_version = req
        .headers()
        .get(DESKTOP_VERSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_release_version);

    let latest_version = match latest_release_version().await {
        Ok(version) => version,
        Err(error) => {
            log::error!("{error}");
            let (req, _) = req.into_parts();
            let res = HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "code": "DESKTOP_VERSION_CHECK_UNAVAILABLE",
                "message": "Could not verify the latest desktop version. Try again later.",
            }));
            return Ok(ServiceResponse::new(req, res).map_into_boxed_body());
        }
    };

    if client_version.is_some_and(|version| is_current_version(&version, &latest_version)) {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let (req, _) = req.into_parts();
    let res = HttpResponse::build(StatusCode::UPGRADE_REQUIRED).json(serde_json::json!({
        "code": "DESKTOP_UPDATE_REQUIRED",
        "message": "A newer desktop version is required.",
        "latestVersion": latest_version.to_string(),
    }));
    Ok(ServiceResponse::new(req, res).map_into_boxed_body())
}

#[cfg(test)]
mod tests {
    use super::{is_current_version, parse_release_version};

    #[test]
    fn parses_release_tags_with_or_without_v_prefix() {
        assert_eq!(
            parse_release_version("v1.2.3").unwrap().to_string(),
            "1.2.3"
        );
        assert_eq!(parse_release_version("1.2.3").unwrap().to_string(), "1.2.3");
        assert!(parse_release_version("latest").is_none());
    }

    #[test]
    fn rejects_versions_older_than_latest_release() {
        let current = parse_release_version("1.2.3").unwrap();
        let latest = parse_release_version("v1.2.4").unwrap();
        assert!(!is_current_version(&current, &latest));
        assert!(is_current_version(&latest, &latest));
    }
}
