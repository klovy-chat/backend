// cors.rs
// Allowlist nagłówków (X-Klovy-*, CSRF) zsynchronizowana z FE.
// Zakres:
//  - preflight
//  - X-Klovy-* i CSRF na allowliście; nowy header = tu + FE
// Nowy custom header bez wpisu tutaj = cichy fail przeglądarki.
// Przy zmianach: clientId.ts, clientInfo.ts, api/client.ts.

use http::header::HeaderName;

use super::csrf::CSRF_HEADER_NAME;
use super::id::CLIENT_HEADER_NAME;
use super::user_agent::CLIENT_USER_AGENT_HEADER;

pub const CORS_ALLOWED_REQUEST_HEADERS: [HeaderName; 10] = [
    HeaderName::from_static("content-type"),
    HeaderName::from_static("authorization"),
    HeaderName::from_static("accept"),
    HeaderName::from_static("accept-language"),
    HeaderName::from_static("accept-encoding"),
    HeaderName::from_static("x-requested-with"),
    HeaderName::from_static(CSRF_HEADER_NAME),
    HeaderName::from_static("x-client-version"),
    HeaderName::from_static(CLIENT_HEADER_NAME),
    HeaderName::from_static(CLIENT_USER_AGENT_HEADER),
];

pub fn cors_allowed_request_header_names() -> &'static [&'static str] {
    &[
        "content-type",
        "authorization",
        "accept",
        "accept-language",
        "accept-encoding",
        "x-requested-with",
        CSRF_HEADER_NAME,
        "x-client-version",
        CLIENT_HEADER_NAME,
        CLIENT_USER_AGENT_HEADER,
    ]
}
