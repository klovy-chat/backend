// gifs.rs
// Proxy wyszukiwania Giphy GIF.
// Zakres:
//  - allowlista URL w odpowiedzi
//  - proxy Giphy; allowlista URL w odpowiedzi
// Quota i klucz tylko w ENV serwera.
// Przy zmianach: api/gifs.ts, controllers/stickers.rs.

use actix_web::{web, HttpResponse};
use serde::Deserialize;
use serde_json::{json, Value};

const GIPHY_BASE_URL: &str = "https://api.giphy.com/v1/gifs";
const DEFAULT_LIMIT: u32 = 24;
const MAX_LIMIT: u32 = 50;
const RATING: &str = "pg-13";

use crate::model::users::normalize_language;

#[derive(Deserialize)]
pub struct GifQuery {
    pub q: Option<String>,
    pub limit: Option<String>,
    pub lang: Option<String>,
}

fn parse_limit(raw: &Option<String>) -> u32 {
    match raw {
        Some(s) => match s.parse::<i64>() {
            Ok(n) if n > 0 => (n as u32).min(MAX_LIMIT),
            _ => DEFAULT_LIMIT,
        },
        None => DEFAULT_LIMIT,
    }
}

fn get_str(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn normalize(gifs: &[Value]) -> Vec<Value> {
    gifs.iter()
        .filter_map(|gif| {
            let id = get_str(gif, "id")?;
            let images = gif.get("images")?;
            let original = images.get("original")?;
            let original_url = get_str(original, "url")?;

            let preview = images
                .get("fixed_height_small")
                .and_then(|x| get_str(x, "url"))
                .or_else(|| images.get("fixed_height").and_then(|x| get_str(x, "url")))
                .or_else(|| images.get("fixed_width").and_then(|x| get_str(x, "url")))
                .unwrap_or_else(|| original_url.clone());

            let title = get_str(gif, "title")
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| "GIF".to_string());

            let width = get_str(original, "width")
                .and_then(|w| w.parse::<i64>().ok())
                .unwrap_or(0);
            let height = get_str(original, "height")
                .and_then(|h| h.parse::<i64>().ok())
                .unwrap_or(0);

            Some(json!({
                "id": id,
                "title": title,
                "url": original_url,
                "preview": preview,
                "width": width,
                "height": height,
            }))
        })
        .collect()
}

async fn fetch_from_giphy(
    path: &str,
    params: &[(&str, String)],
) -> Result<Vec<Value>, HttpResponse> {
    let url = format!("{}{}", GIPHY_BASE_URL, path);
    let resp = match crate::utils::http::outbound_http_client()
        .get(&url)
        .query(params)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::error!("Error fetching from Giphy: {}", e);
            return Err(HttpResponse::BadGateway()
                .json(json!({ "error": "Nie udało się połączyć z Giphy." })));
        }
    };

    if !resp.status().is_success() {
        log::error!("Giphy API error: {}", resp.status());
        return Err(HttpResponse::BadGateway()
            .json(json!({ "error": "Nie udało się pobrać GIF-ów z Giphy." })));
    }

    let bytes = match crate::utils::http::read_response_limited(
        resp,
        crate::utils::http::MAX_GIPHY_JSON_BYTES,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(HttpResponse::BadGateway()
                .json(json!({ "error": "Nie udało się pobrać GIF-ów z Giphy." })))
        }
    };
    let body: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return Err(HttpResponse::BadGateway()
                .json(json!({ "error": "Nie udało się pobrać GIF-ów z Giphy." })))
        }
    };

    let data = body
        .get("data")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(normalize(&data))
}

fn api_key() -> Result<String, HttpResponse> {
    match std::env::var("GIPHY_API_KEY") {
        Ok(k) if !k.is_empty() => Ok(k),
        _ => {
            log::error!("GIPHY_API_KEY is not configured");
            Err(HttpResponse::ServiceUnavailable().json(
                json!({ "error": "Wyszukiwarka GIF-ów jest niedostępna (brak konfiguracji)." }),
            ))
        }
    }
}

pub async fn search_gifs(query: web::Query<GifQuery>) -> HttpResponse {
    let key = match api_key() {
        Ok(k) => k,
        Err(resp) => return resp,
    };

    let q = query.q.clone().unwrap_or_default().trim().to_string();
    if q.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "error": "Brak frazy wyszukiwania." }));
    }
    if q.len() > 100 {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Fraza wyszukiwania jest zbyt długa." }));
    }

    let limit = parse_limit(&query.limit);
    let lang = normalize_language(query.lang.as_deref().unwrap_or("en"));
    let params = vec![
        ("api_key", key),
        ("q", q),
        ("limit", limit.to_string()),
        ("rating", RATING.to_string()),
        ("lang", lang),
        ("bundle", "messaging_non_clips".to_string()),
    ];

    match fetch_from_giphy("/search", &params).await {
        Ok(gifs) => HttpResponse::Ok().json(json!({ "gifs": gifs })),
        Err(resp) => resp,
    }
}

pub async fn trending_gifs(query: web::Query<GifQuery>) -> HttpResponse {
    let key = match api_key() {
        Ok(k) => k,
        Err(resp) => return resp,
    };

    let limit = parse_limit(&query.limit);
    let params = vec![
        ("api_key", key),
        ("limit", limit.to_string()),
        ("rating", RATING.to_string()),
        ("bundle", "messaging_non_clips".to_string()),
    ];

    match fetch_from_giphy("/trending", &params).await {
        Ok(gifs) => HttpResponse::Ok().json(json!({ "gifs": gifs })),
        Err(resp) => resp,
    }
}
