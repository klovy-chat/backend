// mod.rs
// Reeksport middleware + helper odczytu body z limitem bajtów.
// Zakres:
//  - ochrona RAM na wewnętrznym Actix
//  - reeksport + limit bajtów body na wewnętrznym Actix
// Limit musi być ≥ max uploadu, inaczej 413 przed kontrolerem.
// Przy zmianach: utils/upload.rs, loaders/server.rs.

pub mod auth_fallback;
pub mod auth;
pub mod client;
pub mod csrf;
pub mod proxy;
pub mod ip_block;
pub mod origin;
pub mod signup;
pub mod captcha;
pub mod validation;

use actix_web::dev::Payload;
use actix_web::web::{Bytes, BytesMut};

use crate::utils::upload::MAX_HTTP_BODY_BYTES;

pub(crate) async fn read_body_bytes(mut payload: Payload) -> Result<Bytes, actix_web::Error> {
    use futures_util::StreamExt;
    let mut buf = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(actix_web::error::ErrorBadRequest)?;

        if buf.len() + chunk.len() > MAX_HTTP_BODY_BYTES {
            return Err(actix_web::error::ErrorPayloadTooLarge("Payload too large"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}
