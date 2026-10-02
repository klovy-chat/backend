use actix_web::HttpResponse;

pub async fn get_admin_access() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "isAdmin": true }))
}