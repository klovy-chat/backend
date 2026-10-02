use std::{collections::HashSet, env};

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpResponse,
};
use actix_web_lab::middleware::Next;
use mongodb::bson::oid::ObjectId;

use crate::middlewares::auth::{resolve_authenticated_user, JwtUserError};

fn parse_admin_user_ids(value: &str) -> Result<HashSet<ObjectId>, ()> {
    let mut user_ids = HashSet::new();

    for value in value.split(',').map(str::trim).filter(|value| !value.is_empty()) {
        user_ids.insert(ObjectId::parse_str(value).map_err(|_| ())?);
    }

    if user_ids.is_empty() {
        return Err(());
    }

    Ok(user_ids)
}

fn configured_admin_user_ids() -> Result<HashSet<ObjectId>, ()> {
    let value = env::var("ADMIN_USER_IDS").map_err(|_| ())?;
    parse_admin_user_ids(&value)
}

pub async fn require_admin(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let user = match resolve_authenticated_user(req.request()).await {
        Ok(user) => user,
        Err(JwtUserError::Denied) => {
            let (req, _) = req.into_parts();
            let res = HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": "Authentication required" }));
            return Ok(ServiceResponse::new(req, res));
        }
        Err(JwtUserError::Unavailable) => {
            let (req, _) = req.into_parts();
            let res = HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({ "error": "Authentication temporarily unavailable" }));
            return Ok(ServiceResponse::new(req, res));
        }
    };

    let user_id = match user.id {
        Some(user_id) => user_id,
        None => {
            let (req, _) = req.into_parts();
            let res = HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": "Authentication required" }));
            return Ok(ServiceResponse::new(req, res));
        }
    };

    let admin_user_ids = match configured_admin_user_ids() {
        Ok(user_ids) => user_ids,
        Err(()) => {
            log::error!("ADMIN_USER_IDS is missing or invalid; admin API access is disabled");
            let (req, _) = req.into_parts();
            let res = HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({ "error": "Admin access is not configured" }));
            return Ok(ServiceResponse::new(req, res));
        }
    };

    if !admin_user_ids.contains(&user_id) {
        let (req, _) = req.into_parts();
        let res = HttpResponse::Forbidden()
            .json(serde_json::json!({ "error": "Admin access required" }));
        return Ok(ServiceResponse::new(req, res));
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}

#[cfg(test)]
mod tests {
    use super::parse_admin_user_ids;
    use mongodb::bson::oid::ObjectId;

    #[test]
    fn parses_comma_separated_admin_user_ids() {
        let first_id = "507f1f77bcf86cd799439011";
        let second_id = "507f1f77bcf86cd799439012";
        let user_ids = parse_admin_user_ids(&format!(" {first_id}, {second_id} ")).unwrap();

        assert_eq!(user_ids.len(), 2);
        assert!(user_ids.contains(&ObjectId::parse_str(first_id).unwrap()));
        assert!(user_ids.contains(&ObjectId::parse_str(second_id).unwrap()));
    }

    #[test]
    fn rejects_empty_or_invalid_admin_user_ids() {
        assert!(parse_admin_user_ids(" , ").is_err());
        assert!(parse_admin_user_ids("not-an-object-id").is_err());
    }
}