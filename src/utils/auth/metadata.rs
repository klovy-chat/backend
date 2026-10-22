// metadata.rs
// IP/miejsce/urządzenie przy loginie.
// Zakres:
//  - wiersz sesji
//  - IP/urządzenie do wiersza sesji; geo opcjonalne
// Geo opcjonalne — nie blokuj loginu gdy lookup padnie.
// Przy zmianach: session.rs.

use actix_web::HttpRequest;

use super::client::client_environment_from_request;
use super::fingerprint::session_fingerprint_from_request;
use super::session::resolve_client_info;
use super::user_agent::user_agent_from_request;

#[derive(Debug, Clone)]
pub struct SessionClientMetadata {
    pub fingerprint: Option<String>,
    pub user_agent: String,
    pub browser: String,
    pub os: String,
    pub label: String,
}

pub fn session_metadata_from_request(req: &HttpRequest) -> SessionClientMetadata {
    let user_agent = user_agent_from_request(req);
    let environment = client_environment_from_request(req);

    let client = resolve_client_info(&user_agent, &environment);
    SessionClientMetadata {
        fingerprint: session_fingerprint_from_request(req),
        user_agent,
        browser: client.browser,
        os: client.os,
        label: client.label,
    }
}
