// fingerprint.rs
// Odcisk sesji oparty na User-Agent.
// Zakres:
//  - anomalia cookie
//  - stabilna weryfikacja sesji niezależna od zmiennego IP
// Przy zmianach: ip.rs, session.rs.

use actix_web::HttpRequest;

use crate::utils::auth::user_agent::user_agent_from_request;
use crate::utils::crypto::hmac::hmac_sha256_hex;
use crate::utils::crypto::token_hash::refresh_token_hmac_key;

const FINGERPRINT_PREFIX: &str = "refresh-fingerprint-v2|";
const FINGERPRINT_VERSION: &str = "v2:";

pub fn session_fingerprint_from_request(req: &HttpRequest) -> Option<String> {
    let ua = user_agent_from_request(req);

    if ua.trim().is_empty() {
        return None;
    }

    let key = refresh_token_hmac_key().ok()?;
    Some(format!(
        "{FINGERPRINT_VERSION}{}",
        hmac_sha256_hex(&key, &format!("{FINGERPRINT_PREFIX}{ua}"))
    ))
}

pub fn fingerprints_match(stored: &str, current: &str) -> bool {
    stored.len() == current.len()
        && crate::utils::security::timing::constant_time_eq(stored.as_bytes(), current.as_bytes())
}

pub fn fingerprint_matches_session(
    stored_fingerprint: &str,
    stored_user_agent: Option<&str>,
    current_fingerprint: &str,
    current_user_agent: &str,
) -> bool {
    if fingerprints_match(stored_fingerprint, current_fingerprint) {
        return true;
    }

    let is_legacy_fingerprint = stored_fingerprint.len() == 64
        && stored_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit());
    is_legacy_fingerprint
        && current_fingerprint.starts_with(FINGERPRINT_VERSION)
        && !current_user_agent.trim().is_empty()
        && stored_user_agent == Some(current_user_agent)
}

#[cfg(test)]
mod tests {
    use super::fingerprint_matches_session;

    #[test]
    fn matches_current_fingerprint() {
        assert!(fingerprint_matches_session(
            "v2:current",
            Some("Browser"),
            "v2:current",
            "Browser"
        ));
    }

    #[test]
    fn migrates_legacy_fingerprint_when_user_agent_matches() {
        assert!(fingerprint_matches_session(
            &"a".repeat(64),
            Some("Browser"),
            "v2:current",
            "Browser"
        ));
    }

    #[test]
    fn rejects_legacy_fingerprint_when_user_agent_differs() {
        assert!(!fingerprint_matches_session(
            &"a".repeat(64),
            Some("Browser"),
            "v2:current",
            "Different Browser"
        ));
    }
}
