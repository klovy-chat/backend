// auth.rs
// HTTP auth: signup/login/2FA/sesje/profil/hasło/ostrzeżenia.
// Zakres:
//  - ciasteczka JWT+refresh
//  - step-up przy wrażliwych zmianach
// Nowy flow logowania: middleware captcha/csrf + ten plik + FE api/auth.ts.
// Przy zmianach: routes/auth.rs, utils/auth/*, middlewares/captcha.rs.

use actix_multipart::form::MultipartForm;
use actix_web::cookie::{time::Duration as CookieDuration, Cookie, SameSite};
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime};
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth::RequestUserId;
use crate::model::refresh_tokens::RefreshToken;
use crate::model::users::{CreateUserInput, User, normalize_language};
use crate::model::warnings::{severity_str, Warning};
use crate::routes::auth::{ProfileBannerForm, ProfileImageForm};
use crate::utils::auth::tokens::{create_access_token, ACCESS_MAX_AGE_MS, REFRESH_MAX_AGE_MS};
use crate::utils::auth::refresh::{
    family_id_from_refresh_token, issue_refresh_token, list_user_sessions,
    revoke_other_sessions_for_user, revoke_refresh_token_family, revoke_session_for_user,
    revoke_user_refresh_tokens, rotate_refresh_token, RefreshAuthError, REFRESH_COOKIE,
};
use crate::utils::auth::metadata::session_metadata_from_request;
use crate::utils::auth::step_up::{
    backup_codes_bson_after_consumption, verify_step_up_auth, StepUpResult,
};
use crate::utils::auth::totp::{
    build_otpauth_url, decrypt_totp_secret, encrypt_totp_secret, generate_backup_codes,
    generate_totp_secret, hash_backup_codes, is_totp_code, verify_and_consume_backup_code,
    verify_totp_code,
};
use crate::utils::auth::two_factor::{
    create_two_factor_challenge_token, decode_two_factor_challenge_token,
};
use crate::utils::crypto::passwords::verify_user_password;
use crate::ws::registry::{disconnect_user, revoke_session_remotely};
use crate::utils::friends::{emit_profile_event, emit_status_event};
use crate::utils::db::get_db;
use crate::utils::user::json::{resolve_display_name, serialize_user, BIO_MAX_LENGTH, DISPLAY_NAME_MAX_LENGTH};
use crate::utils::upload::{
    file_bytes_within_limit, local_file_size, MAX_AVATAR_BYTES, MAX_BANNER_BYTES,
    MAX_BANNER_EDGE,
};
use crate::utils::validators::file_type::validate_file_magic_async;
use crate::utils::validators::username::{is_valid_username, looks_like_email, normalize_username};
use crate::utils::validators::leaked_password::{check_password_breach, PasswordBreachCheck};
use crate::utils::security::csrf::{build_csrf_cookie, clear_csrf_cookie, csrf_token_for_response, generate_csrf_token};
use crate::utils::security::monitor::{SecurityEventType, SecurityMonitor};
use crate::utils::registration::{is_registration_open, try_consume_global_signup_slot};

use crate::utils::env::is_production;
use crate::utils::admin::DELETION_GRACE_DAYS;
use crate::utils::images::{
    reencode_error_message, reencode_upload_to_webp_async, reencode_upload_to_webp_max_edge_async,
};
use crate::utils::storage::{
    avatar_user_key, avatar_key_owned_by_user, banner_user_key, public_media_key_owned_by_user,
    storage,
};

const ALLOWED_IMAGE_EXT: &[&str] = &["jpg", "jpeg", "png", "webp"];

fn req_user_id(req: &HttpRequest) -> Option<String> {
    req.extensions().get::<RequestUserId>().map(|u| u.0.clone())
}

async fn password_matches(plain: &str, hash: &str) -> Result<bool, HttpResponse> {
    match verify_user_password(plain, hash).await {
        Ok(v) => Ok(v),
        Err(()) => Err(HttpResponse::ServiceUnavailable().json(json!({
            "message": "Temporarily unavailable. Retry."
        }))),
    }
}

fn step_up_err_response(message: &str) -> HttpResponse {
    if message.starts_with("Temporarily unavailable") {
        HttpResponse::ServiceUnavailable().json(json!({ "message": message }))
    } else {
        HttpResponse::BadRequest().json(json!({ "message": message }))
    }
}

fn jwt_cookie(value: &str, max_age_ms: i64) -> Cookie<'static> {
    Cookie::build("jwt", value.to_string())
        .http_only(true)
        .secure(is_production())
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(CookieDuration::milliseconds(max_age_ms))
        .finish()
}

fn refresh_cookie(value: &str, max_age_ms: i64) -> Cookie<'static> {
    Cookie::build(REFRESH_COOKIE, value.to_string())
        .http_only(true)
        .secure(is_production())
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(CookieDuration::milliseconds(max_age_ms))
        .finish()
}

fn clear_legacy_refresh_cookie() -> Cookie<'static> {
    Cookie::build(REFRESH_COOKIE, "")
        .http_only(true)
        .secure(is_production())
        .same_site(SameSite::Strict)
        .path("/api/auth/refresh")
        .max_age(CookieDuration::seconds(0))
        .finish()
}

fn clear_refresh_cookie() -> Cookie<'static> {
    refresh_cookie("", 0)
}

async fn invalidate_user_session(user_id: ObjectId) {
    let db = get_db();
    if let Err(e) = User::invalidate_tokens(&db, user_id).await {
        log::error!("Failed to invalidate tokens: {e}");
    }
    if let Err(e) = revoke_user_refresh_tokens(user_id).await {
        log::error!("Failed to revoke refresh tokens: {e}");
    }
    disconnect_user(&user_id.to_hex());
}

async fn revoke_other_devices(req: &HttpRequest, user_id: ObjectId) {
    let Some(raw) = req.cookie(REFRESH_COOKIE).map(|c| c.value().to_string()) else {
        return;
    };
    let current_family = match family_id_from_refresh_token(&raw).await {
        Ok(Some(fid)) => fid,
        _ => return,
    };
    let db = get_db();
    let other_families =
        match RefreshToken::active_family_ids_for_user_except(&db, user_id, &current_family).await {
            Ok(families) => families,
            Err(_) => return,
        };
    if revoke_other_sessions_for_user(user_id, &current_family)
        .await
        .is_err()
    {
        return;
    }
    let hex = user_id.to_hex();
    for family in other_families {
        revoke_session_remotely(&hex, &family);
    }
}

async fn add_login_delay() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let delay = 100 + (nanos % 400) as u64;
    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
}

fn file_ext(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((_, ext)) => ext.to_lowercase(),
        None => name.to_lowercase(),
    }
}

#[derive(Deserialize)]
pub struct CredentialsBody {
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub language: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateLanguageBody {
    pub language: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateProfileBody {
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub color: Option<i32>,
}

#[derive(Deserialize)]
pub struct AvailabilityBody {
    #[serde(rename = "availabilityStatus")]
    pub availability_status: Option<String>,
}

#[derive(Deserialize)]
pub struct TwoFactorLoginBody {
    #[serde(rename = "twoFactorToken")]
    pub two_factor: Option<String>,
    pub code: Option<String>,
}

#[derive(Deserialize)]
pub struct SetupTwoFactorBody {
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct TwoFactorCodeBody {
    pub password: Option<String>,
    pub code: Option<String>,
}

#[derive(Deserialize)]
pub struct TwoFactorDisableBody {
    pub password: Option<String>,
    pub code: Option<String>,
}

#[derive(Deserialize)]
pub struct ChangePasswordBody {
    #[serde(rename = "currentPassword")]
    pub current_password: Option<String>,
    #[serde(rename = "newPassword")]
    pub new_password: Option<String>,
    pub code: Option<String>,
}

#[derive(Deserialize)]
pub struct ChangeUsernameBody {
    pub username: Option<String>,
    pub password: Option<String>,
    pub code: Option<String>,
}

#[derive(Deserialize)]
pub struct AccountActionBody {
    pub password: Option<String>,
    pub code: Option<String>,
}

async fn verify_account_action_credentials(
    user: &User,
    password: &str,
    code: Option<&str>,
    db: &mongodb::Database,
    user_id: ObjectId,
) -> Result<(), HttpResponse> {
    if password.is_empty() {
        return Err(HttpResponse::BadRequest().json(json!({
            "message": "Hasło jest wymagane."
        })));
    }

    match password_matches(password, &user.password).await {
        Ok(true) => {}
        Ok(false) => {
            add_login_delay().await;
            return Err(HttpResponse::BadRequest().json(json!({
                "message": "Hasło jest nieprawidłowe."
            })));
        }
        Err(res) => return Err(res),
    }

    match verify_step_up_auth(user, code).await {
        Err(message) => {
            add_login_delay().await;
            Err(step_up_err_response(message))
        }
        Ok(StepUpResult::BackupConsumed { index }) => {
            let codes_bson = backup_codes_bson_after_consumption(user, index);
            if let Err(e) = User::set_fields(db, user_id, doc! { "backupCodes": codes_bson }).await {
                log::error!("Failed to update backup codes after step-up: {e}");
                Err(HttpResponse::InternalServerError().body("Internal Server Error"))
            } else {
                Ok(())
            }
        }
        Ok(StepUpResult::NotRequired) | Ok(StepUpResult::Verified) => Ok(()),
    }
}

async fn login_response(req: &HttpRequest, user: User) -> HttpResponse {
    let Some(oid) = user.id else {
        return HttpResponse::InternalServerError().body("Internal Server Error");
    };
    let user_id = oid.to_hex();
    let db = get_db();
    let metadata = session_metadata_from_request(req);
    let refresh = match issue_refresh_token(oid, metadata).await {
        Ok(r) => r,
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };
    let token = match create_access_token(
        &db,
        &user.username,
        &user_id,
        Some(&refresh.family_id),
    )
    .await
    {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    let csrf = generate_csrf_token();
    HttpResponse::Ok()
        .cookie(jwt_cookie(&token, ACCESS_MAX_AGE_MS))
        .cookie(refresh_cookie(&refresh.raw_token, REFRESH_MAX_AGE_MS))
        .cookie(clear_legacy_refresh_cookie())
        .cookie(build_csrf_cookie(&csrf))
        .json(json!({
            "user": serialize_user(&user),
            "csrfToken": csrf,
        }))
}

fn account_status_response(user: &User) -> Option<HttpResponse> {
    if user.is_disabled {
        return Some(HttpResponse::Forbidden().json(json!({
            "message": "Konto zostało wyłączone. Skontaktuj się z administracją, aby je przywrócić.",
            "code": "ACCOUNT_DISABLED",
        })));
    }

    if !user.is_active {
        return Some(HttpResponse::Forbidden().json(json!({
            "message": "Konto jest nieaktywne. Skontaktuj się z administracją."
        })));
    }

    if user.is_banned {
        let message = user
            .block_reason
            .as_deref()
            .map(|r| r.trim())
            .filter(|r| !r.is_empty())
            .unwrap_or("Konto zostało zbanowane za naruszenie regulaminu.");
        return Some(
            HttpResponse::Forbidden()
                .json(json!({ "message": message, "code": "ACCOUNT_BANNED" })),
        );
    }

    if user.is_blocked {
        let message = user
            .block_reason
            .as_deref()
            .map(|r| r.trim())
            .filter(|r| !r.is_empty())
            .unwrap_or("Konto jest zablokowane.");
        return Some(
            HttpResponse::Forbidden()
                .json(json!({ "message": message, "code": "ACCOUNT_BLOCKED" })),
        );
    }

    None
}

pub async fn registration_status() -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "open": is_registration_open(),
        "message": if is_registration_open() {
            "Rejestracja jest otwarta."
        } else {
            "Rejestracja nowych kont jest obecnie wyłączona."
        }
    }))
}

pub async fn issue_ws_crypto_key(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({
            "message": "User not authenticated."
        }));
    };

    let (token, key) = crate::ws::keys::issue_ws_crypto_key(&user_id);
    HttpResponse::Ok().json(json!({
        "token": token,
        "key": key,
        "expiresIn": 30
    }))
}

pub async fn signup(
    body: web::Json<CredentialsBody>,
    monitor: web::Data<SecurityMonitor>,
) -> HttpResponse {
    let db = get_db();

    if !is_registration_open() {
        return HttpResponse::Forbidden().json(json!({
            "message": "Rejestracja nowych kont jest obecnie wyłączona.",
            "code": "REGISTRATION_DISABLED"
        }));
    }

    let raw_username = body.username.as_deref().unwrap_or("").trim();
    let raw_email = body.email.as_deref().unwrap_or("").trim();

    if raw_username.is_empty() && !raw_email.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Rejestracja odbywa się przez nazwę użytkownika, nie adres e-mail."
        }));
    }

    if looks_like_email(raw_username) {
        return HttpResponse::BadRequest().json(json!({
            "message": "Rejestracja odbywa się przez nazwę użytkownika, nie adres e-mail."
        }));
    }

    let normalized = normalize_username(raw_username);
    let password = body.password.clone().unwrap_or_default();

    if normalized.is_empty() || password.is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Username and password are required" }));
    }

    if !is_valid_username(&normalized) {
        return HttpResponse::BadRequest().json(json!({
            "message": "Nie można utworzyć konta. Sprawdź dane lub wybierz inną nazwę użytkownika."
        }));
    }

    match User::username_exists(&db, &normalized).await {
        Ok(true) => {
            monitor.log_event(
                SecurityEventType::AuthFailure,
                json!({ "username": normalized, "reason": "username_taken" }),
            );
            add_login_delay().await;
            return HttpResponse::BadRequest().json(json!({
                "message": "Nie można utworzyć konta. Sprawdź dane lub wybierz inną nazwę użytkownika."
            }));
        }
        Ok(false) => {}
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Internal Server Error" }))
        }
    }

    match check_password_breach(&password).await {
        PasswordBreachCheck::Breached => {
            return HttpResponse::BadRequest().json(json!({
                "message": "To hasło pojawiło się w wycieku danych. Wybierz inne, bezpieczniejsze hasło.",
                "code": "PASSWORD_BREACHED"
            }));
        }
        PasswordBreachCheck::Unavailable => {
            log::error!("Failed to verify password against breach database");
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Nie można teraz zweryfikować hasła. Spróbuj ponownie za chwilę."
            }));
        }
        PasswordBreachCheck::Safe => {}
    }

    match try_consume_global_signup_slot(&db).await {
        Ok(()) => {}
        Err(err) => {
            monitor.log_event(
                SecurityEventType::AuthFailure,
                json!({ "reason": err.code(), "action": "signup" }),
            );
            use crate::utils::registration::SignupQuotaError;
            if err == SignupQuotaError::Unavailable {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "message": err.user_message(),
                    "code": err.code(),
                    "retryable": true,
                }));
            }
            return HttpResponse::TooManyRequests().json(json!({
                "message": err.user_message(),
                "code": err.code()
            }));
        }
    }

    match User::create(
        &db,
        CreateUserInput {
            username: normalized.clone(),
            password,
            language: body.language.clone(),
        },
    )
    .await
    {
        Ok(user) => {
            HttpResponse::Created().json(json!({
                "message": "Konto utworzone. Możesz się zalogować.",
                "user": serialize_user(&user),
            }))
        }
        Err(e) => {
            match User::username_exists(&db, &normalized).await {
                Ok(_) => {

                    add_login_delay().await;
                    HttpResponse::BadRequest().json(json!({
                        "message": "Nie można utworzyć konta. Sprawdź dane lub wybierz inną nazwę użytkownika."
                    }))
                }
                Err(_) => {
                    log::error!("signup failed (username lookup unavailable): {e}");
                    HttpResponse::ServiceUnavailable().json(json!({
                        "message": "Temporarily unavailable. Retry."
                    }))
                }
            }
        }
    }
}

pub async fn login(
    req: HttpRequest,
    body: web::Json<CredentialsBody>,
    monitor: web::Data<SecurityMonitor>,
) -> HttpResponse {
    let db = get_db();
    let raw_username = body.username.as_deref().unwrap_or("").trim();
    let raw_email = body.email.as_deref().unwrap_or("").trim();

    if raw_username.is_empty() && !raw_email.is_empty() {
        add_login_delay().await;
        return HttpResponse::BadRequest().json(json!({
            "message": "Logowanie odbywa się przez nazwę użytkownika, nie adres e-mail."
        }));
    }

    if looks_like_email(raw_username) {
        add_login_delay().await;
        return HttpResponse::BadRequest().json(json!({
            "message": "Logowanie odbywa się przez nazwę użytkownika, nie adres e-mail."
        }));
    }

    let normalized = normalize_username(raw_username);
    let password = body.password.clone().unwrap_or_default();

    if normalized.is_empty() || password.is_empty() {
        add_login_delay().await;
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Username and password are required" }));
    }

    if !is_valid_username(&normalized) {
        add_login_delay().await;
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid credentials" }));
    }

    let user = match User::find_by_username(&db, &normalized).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            monitor.log_event(
                SecurityEventType::LoginFailures,
                json!({ "username": normalized, "reason": "user_not_found" }),
            );
            add_login_delay().await;
            return HttpResponse::BadRequest().json(json!({ "message": "Invalid credentials" }));
        }
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    match password_matches(&password, &user.password).await {
        Ok(true) => {}
        Ok(false) => {
            monitor.log_event(
                SecurityEventType::LoginFailures,
                json!({ "username": normalized, "reason": "invalid_password" }),
            );
            add_login_delay().await;
            return HttpResponse::BadRequest().json(json!({ "message": "Invalid credentials" }));
        }
        Err(res) => return res,
    }

    if let Some(response) = account_status_response(&user) {
        add_login_delay().await;
        return response;
    }

    if user.two_factor_enabled {
        let user_id = user.id.map(|o| o.to_hex()).unwrap_or_default();
        let challenge = match create_two_factor_challenge_token(&user_id) {
            Ok(token) => token,
            Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
        };
        return HttpResponse::Ok().json(json!({
            "requiresTwoFactor": true,
            "twoFactorToken": challenge,
        }));
    }

    login_response(&req, user).await
}

pub async fn verify_two_factor_login(req: HttpRequest, body: web::Json<TwoFactorLoginBody>) -> HttpResponse {
    let token = body.two_factor.as_deref().unwrap_or("").trim();
    let code = body.code.as_deref().unwrap_or("").trim();

    if token.is_empty() || code.is_empty() {
        add_login_delay().await;
        return HttpResponse::BadRequest().json(json!({ "message": "Two-factor token and code are required." }));
    }

    let payload = match decode_two_factor_challenge_token(token) {
        Ok(p) => p,
        Err(message) => {
            add_login_delay().await;
            return HttpResponse::BadRequest().json(json!({ "message": message }));
        }
    };

    let Ok(user_oid) = ObjectId::parse_str(&payload.user_id) else {
        add_login_delay().await;
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid two-factor token." }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, user_oid).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            add_login_delay().await;
            return HttpResponse::BadRequest().json(json!({ "message": "Invalid two-factor token." }));
        }
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    if !user.two_factor_enabled {
        add_login_delay().await;
        return HttpResponse::BadRequest().json(json!({ "message": "Two-factor authentication is not enabled." }));
    }

    if let Some(response) = account_status_response(&user) {
        add_login_delay().await;
        return response;
    }

    let mut verified = false;
    let mut updated_backup_codes = user.backup_codes.clone();

    if is_totp_code(code) {
        if let Some(encrypted) = user.totp_secret.as_deref() {
            match decrypt_totp_secret(encrypted) {
                Ok(secret) => {
                    match verify_totp_code(&user.username, &secret, code) {
                        Ok(v) => verified = v,
                        Err(()) => {
                            return HttpResponse::ServiceUnavailable().json(json!({
                                "message": "Temporarily unavailable. Retry."
                            }));
                        }
                    }
                }
                Err(_) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "message": "Temporarily unavailable. Retry."
                    }));
                }
            }
        }
    } else if let Some(hashes) = user.backup_codes.as_ref() {
        match verify_and_consume_backup_code(code, hashes).await {
            Ok(Some(index)) => {
                verified = true;
                if let Some(codes) = updated_backup_codes.as_mut() {
                    codes.remove(index);
                }
            }
            Ok(None) => {}
            Err(()) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "message": "Temporarily unavailable. Retry."
                }));
            }
        }
    }

    if !verified {
        add_login_delay().await;
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid authentication code." }));
    }

    if updated_backup_codes != user.backup_codes {
        let backup_val = match updated_backup_codes {
            Some(codes) if !codes.is_empty() => {
                Bson::Array(codes.into_iter().map(Bson::String).collect())
            }
            _ => Bson::Null,
        };

        match User::set_fields(&db, user_oid, doc! { "backupCodes": backup_val }).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return HttpResponse::NotFound()
                    .json(json!({ "message": "User not found." }));
            }
            Err(_) => {

                return HttpResponse::ServiceUnavailable().json(json!({
                    "message": "Temporarily unavailable. Retry."
                }));
            }
        }
    }

    login_response(&req, user).await
}

pub async fn setup_two_factor(
    req: HttpRequest,
    body: web::Json<SetupTwoFactorBody>,
) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let password = body.password.as_deref().unwrap_or("").trim();
    if password.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Password is required to start two-factor setup."
        }));
    }

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found."),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    match password_matches(password, &user.password).await {
        Ok(true) => {}
        Ok(false) => {
            add_login_delay().await;
            return HttpResponse::BadRequest().json(json!({ "message": "Invalid password." }));
        }
        Err(res) => return res,
    }

    if user.two_factor_enabled {
        return HttpResponse::BadRequest().json(json!({
            "message": "Two-factor authentication is already enabled."
        }));
    }

    let secret = generate_totp_secret();
    let encrypted = match encrypt_totp_secret(&secret) {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    match User::set_fields(&db, oid, doc! { "totpPendingSecret": encrypted }).await {
        Ok(Some(_)) => HttpResponse::Ok().json(json!({
            "secret": secret,
            "otpauthUrl": build_otpauth_url(&user.username, &secret),
        })),
        Ok(None) => HttpResponse::NotFound().body("User not found."),
        Err(_) => HttpResponse::InternalServerError().body("Internal Server Error"),
    }
}

pub async fn enable_two_factor(
    req: HttpRequest,
    body: web::Json<TwoFactorCodeBody>,
) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let code = body.code.as_deref().unwrap_or("").trim();
    let password = body.password.as_deref().unwrap_or("").trim();
    if code.is_empty() || password.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Password and authentication code are required."
        }));
    }

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found."),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    match password_matches(password, &user.password).await {
        Ok(true) => {}
        Ok(false) => {
            add_login_delay().await;
            return HttpResponse::BadRequest().json(json!({ "message": "Invalid password." }));
        }
        Err(res) => return res,
    }

    if user.two_factor_enabled {
        return HttpResponse::BadRequest().json(json!({
            "message": "Two-factor authentication is already enabled."
        }));
    }

    let Some(pending_encrypted) = user.totp_pending_secret.as_deref() else {
        return HttpResponse::BadRequest().json(json!({
            "message": "Two-factor setup has not been started."
        }));
    };

    let secret = match decrypt_totp_secret(pending_encrypted) {
        Ok(value) => value,
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable. Retry."
            }));
        }
    };

    match verify_totp_code(&user.username, &secret, code) {
        Ok(true) => {}
        Ok(false) => {
            add_login_delay().await;
            return HttpResponse::BadRequest().json(json!({ "message": "Invalid authentication code." }));
        }
        Err(()) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable. Retry."
            }));
        }
    }

    let plain_codes = generate_backup_codes();
    let hashed_codes = match hash_backup_codes(&plain_codes).await {
        Ok(codes) => codes,
        Err(_) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable. Retry."
            }));
        }
    };

    let backup_bson: Vec<Bson> = hashed_codes.into_iter().map(Bson::String).collect();

    match User::set_fields(
        &db,
        oid,
        doc! {
            "twoFactorEnabled": true,
            "totpSecret": pending_encrypted,
            "totpPendingSecret": Bson::Null,
            "backupCodes": backup_bson,
        },
    )
    .await
    {
        Ok(Some(updated)) => {
            revoke_other_devices(&req, oid).await;
            HttpResponse::Ok().json(json!({
            "message": "Two-factor authentication enabled.",
            "twoFactorEnabled": updated.two_factor_enabled,
            "backupCodes": plain_codes,
        }))},
        Ok(None) => HttpResponse::NotFound().body("User not found."),
        Err(_) => HttpResponse::InternalServerError().body("Internal Server Error"),
    }
}

pub async fn disable_two_factor(
    req: HttpRequest,
    body: web::Json<TwoFactorDisableBody>,
) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let password = body.password.as_deref().unwrap_or("");
    let code = body.code.as_deref().unwrap_or("").trim();

    if password.is_empty() || code.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Password and authentication code are required."
        }));
    }

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found."),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    if !user.two_factor_enabled {
        return HttpResponse::BadRequest().json(json!({
            "message": "Two-factor authentication is not enabled."
        }));
    }

    match password_matches(password, &user.password).await {
        Ok(true) => {}
        Ok(false) => {
            add_login_delay().await;
            return HttpResponse::BadRequest().json(json!({ "message": "Invalid password." }));
        }
        Err(res) => return res,
    }

    let mut verified = false;
    if is_totp_code(code) {
        if let Some(encrypted) = user.totp_secret.as_deref() {
            match decrypt_totp_secret(encrypted) {
                Ok(secret) => {
                    match verify_totp_code(&user.username, &secret, code) {
                        Ok(v) => verified = v,
                        Err(()) => {
                            return HttpResponse::ServiceUnavailable().json(json!({
                                "message": "Temporarily unavailable. Retry."
                            }));
                        }
                    }
                }
                Err(_) => {
                    return HttpResponse::ServiceUnavailable().json(json!({
                        "message": "Temporarily unavailable. Retry."
                    }));
                }
            }
        }
    } else if let Some(hashes) = user.backup_codes.as_ref() {
        match verify_and_consume_backup_code(code, hashes).await {
            Ok(Some(_)) => verified = true,
            Ok(None) => {}
            Err(()) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "message": "Temporarily unavailable. Retry."
                }));
            }
        }
    }

    if !verified {
        add_login_delay().await;
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid authentication code." }));
    }

    match User::set_fields(
        &db,
        oid,
        doc! {
            "twoFactorEnabled": false,
            "totpSecret": Bson::Null,
            "totpPendingSecret": Bson::Null,
            "backupCodes": Bson::Null,
        },
    )
    .await
    {
        Ok(Some(updated)) => {
            revoke_other_devices(&req, oid).await;
            HttpResponse::Ok().json(json!({
            "message": "Two-factor authentication disabled.",
            "twoFactorEnabled": updated.two_factor_enabled,
        }))},
        Ok(None) => HttpResponse::NotFound().body("User not found."),
        Err(_) => HttpResponse::InternalServerError().body("Internal Server Error"),
    }
}

pub async fn change_password(
    req: HttpRequest,
    body: web::Json<ChangePasswordBody>,
) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let current = body.current_password.as_deref().unwrap_or("").trim();
    let new_password = body.new_password.as_deref().unwrap_or("").trim();

    if current.is_empty() || new_password.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Current password and new password are required."
        }));
    }

    if current == new_password {
        return HttpResponse::BadRequest().json(json!({
            "message": "New password must be different from the current password."
        }));
    }

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found."),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    match password_matches(current, &user.password).await {
        Ok(true) => {}
        Ok(false) => {
            add_login_delay().await;
            return HttpResponse::BadRequest().json(json!({
                "message": "Current password is incorrect."
            }));
        }
        Err(res) => return res,
    }

    match verify_step_up_auth(&user, body.code.as_deref()).await {
        Err(message) => {
            add_login_delay().await;
            return step_up_err_response(message);
        }
        Ok(StepUpResult::BackupConsumed { index }) => {
            let codes_bson = backup_codes_bson_after_consumption(&user, index);
            if let Err(e) = User::set_fields(&db, oid, doc! { "backupCodes": codes_bson }).await {
                log::error!("Failed to update backup codes after step-up: {e}");
                return HttpResponse::InternalServerError().body("Internal Server Error");
            }
        }
        Ok(StepUpResult::NotRequired) | Ok(StepUpResult::Verified) => {}
    }

    match check_password_breach(new_password).await {
        PasswordBreachCheck::Breached => {
            return HttpResponse::BadRequest().json(json!({
                "message": "To hasło pojawiło się w wycieku danych. Wybierz inne, bezpieczniejsze hasło.",
                "code": "PASSWORD_BREACHED"
            }));
        }
        PasswordBreachCheck::Unavailable => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Nie można teraz zweryfikować hasła. Spróbuj ponownie za chwilę."
            }));
        }
        PasswordBreachCheck::Safe => {}
    }

    if let Err(e) = User::update_password(&db, oid, new_password).await {
        log::error!("Failed to update password: {e}");
        return HttpResponse::InternalServerError().body("Internal Server Error");
    }

    invalidate_user_session(oid).await;

    let updated = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        _ => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    login_response(&req, updated).await
}

pub async fn change_username(
    req: HttpRequest,
    body: web::Json<ChangeUsernameBody>,
) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let normalized = normalize_username(body.username.as_deref().unwrap_or(""));
    let password = body.password.as_deref().unwrap_or("");

    if password.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Podaj aktualne hasło, aby zmienić nazwę użytkownika."
        }));
    }

    if !is_valid_username(&normalized) {
        return HttpResponse::BadRequest().json(json!({
            "message": "Nazwa użytkownika: 3–32 znaków, tylko małe litery, cyfry i _."
        }));
    }

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found."),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    match password_matches(password, &user.password).await {
        Ok(true) => {}
        Ok(false) => {
            add_login_delay().await;
            return HttpResponse::BadRequest().json(json!({ "message": "Nieprawidłowe hasło." }));
        }
        Err(res) => return res,
    }

    if normalized == user.username {
        return HttpResponse::BadRequest().json(json!({
            "message": "To jest już Twoja obecna nazwa użytkownika."
        }));
    }

    match verify_step_up_auth(&user, body.code.as_deref()).await {
        Err(message) => {
            add_login_delay().await;
            return step_up_err_response(message);
        }
        Ok(StepUpResult::BackupConsumed { index }) => {
            let codes_bson = backup_codes_bson_after_consumption(&user, index);
            if let Err(e) = User::set_fields(&db, oid, doc! { "backupCodes": codes_bson }).await {
                log::error!("Failed to update backup codes after step-up: {e}");
                return HttpResponse::InternalServerError().body("Internal Server Error");
            }
        }
        Ok(StepUpResult::NotRequired) | Ok(StepUpResult::Verified) => {}
    }

    match User::username_taken_by_other(&db, &normalized, oid).await {
        Ok(true) => {
            return HttpResponse::Conflict().json(json!({
                "message": "Ta nazwa użytkownika jest już zajęta. Wybierz inną."
            }));
        }
        Ok(false) => {}
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    }

    match User::set_fields(&db, oid, doc! { "username": &normalized }).await {
        Ok(Some(user)) => {
            emit_profile_event(
                &db,
                &user_id,
                "profile-updated",
                json!({
                    "userId": user_id,
                    "username": user.username,
                    "displayName": resolve_display_name(&user),
                    "bio": user.bio.as_ref().map(|b| b.trim()).filter(|b| !b.is_empty()),
                    "color": user.color,
                }),
            )
            .await;
            HttpResponse::Ok().json(serialize_user(&user))
        }
        Ok(None) => HttpResponse::NotFound().body("User not found."),
        Err(_) => {

            match User::username_taken_by_other(&db, &normalized, oid).await {
                Ok(true) => HttpResponse::Conflict().json(json!({
                    "message": "Ta nazwa użytkownika jest już zajęta. Wybierz inną."
                })),
                Ok(false) => HttpResponse::InternalServerError().body("Internal Server Error."),
                Err(_) => HttpResponse::ServiceUnavailable().json(json!({
                    "message": "Temporarily unavailable. Retry."
                })),
            }
        }
    }
}

pub async fn refresh_session(req: HttpRequest) -> HttpResponse {
    let refresh_token = req
        .cookie(REFRESH_COOKIE)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    match rotate_refresh_token(&refresh_token, session_metadata_from_request(&req)).await {
        Ok(session) => {
            let user_id = session.user.id.map(|o| o.to_hex()).unwrap_or_default();
            let db = get_db();
            let access = match create_access_token(
                &db,
                &session.user.username,
                &user_id,
                Some(&session.family_id),
            )
            .await
            {
                Ok(t) => t,
                Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
            };

            let csrf = generate_csrf_token();
            HttpResponse::Ok()
                .cookie(jwt_cookie(&access, ACCESS_MAX_AGE_MS))
                .cookie(refresh_cookie(
                    &session.new_refresh_token,
                    REFRESH_MAX_AGE_MS,
                ))
                .cookie(clear_legacy_refresh_cookie())
                .cookie(build_csrf_cookie(&csrf))
                .json(json!({
                    "user": serialize_user(&session.user),
                    "csrfToken": csrf,
                }))
        }

        Err(RefreshAuthError::Unavailable) => HttpResponse::ServiceUnavailable().json(json!({
            "message": "Temporarily unavailable. Retry."
        })),
        Err(RefreshAuthError::Denied) => HttpResponse::Unauthorized()
            .cookie(jwt_cookie("", 0))
            .cookie(clear_refresh_cookie())
            .cookie(clear_legacy_refresh_cookie())
            .json(json!({ "message": "Session expired. Please log in again." })),
    }
}

pub async fn logout(req: HttpRequest) -> HttpResponse {
    if let Some(cookie) = req.cookie(REFRESH_COOKIE) {
        let raw = cookie.value();
        let family_id = match family_id_from_refresh_token(raw).await {
            Ok(v) => v,
            Err(RefreshAuthError::Unavailable) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "message": "Temporarily unavailable. Retry."
                }));
            }
            Err(RefreshAuthError::Denied) => None,
        };
        match revoke_refresh_token_family(raw).await {
            Ok(Some(user_id)) => {
                let uid = user_id.to_hex();
                if let Some(fid) = family_id {
                    revoke_session_remotely(&uid, &fid);
                } else {
                    disconnect_user(&uid);
                }
            }
            Ok(None) => {}
            Err(RefreshAuthError::Unavailable) | Err(RefreshAuthError::Denied) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "message": "Temporarily unavailable. Retry."
                }));
            }
        }
    } else if let Some(user_id) = req_user_id(&req) {
        if let Ok(oid) = ObjectId::parse_str(&user_id) {
            disconnect_user(&oid.to_hex());
        }
    }

    HttpResponse::Ok()
        .cookie(jwt_cookie("", 0))
        .cookie(clear_refresh_cookie())
        .cookie(clear_legacy_refresh_cookie())
        .cookie(clear_csrf_cookie())
        .body("Logout successful")
}

pub async fn list_sessions(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let mut current_family_id = if let Some(cookie) = req.cookie(REFRESH_COOKIE) {
        match family_id_from_refresh_token(cookie.value()).await {
            Ok(v) => v,
            Err(RefreshAuthError::Unavailable) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "message": "Temporarily unavailable. Retry."
                }));
            }
            Err(RefreshAuthError::Denied) => None,
        }
    } else {
        None
    };

    // Fall back to the access token's family claim when the refresh cookie is
    // absent or not scoped to this path (e.g. a legacy cookie), so the current
    // device is still flagged correctly in the list.
    if current_family_id.is_none() {
        if let Some(jwt) = req.cookie("jwt") {
            current_family_id =
                crate::utils::auth::jwt::session_family_from_jwt(jwt.value());
        }
    }

    match list_user_sessions(oid, current_family_id.as_deref()).await {
        Ok(sessions) => HttpResponse::Ok().json(json!({ "sessions": sessions })),
        Err(_) => HttpResponse::InternalServerError().json(json!({
            "message": "Nie udało się pobrać listy sesji."
        })),
    }
}

pub async fn revoke_session(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let family_id = req.match_info().get("sessionId").unwrap_or("").trim();
    if family_id.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Brak identyfikatora sesji."
        }));
    }

    let current_family_id = req
        .cookie(REFRESH_COOKIE)
        .map(|cookie| cookie.value().to_string());

    let current_family = if let Some(raw) = current_family_id {
        match family_id_from_refresh_token(&raw).await {
            Ok(v) => v,
            Err(RefreshAuthError::Unavailable) => {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "message": "Temporarily unavailable. Retry."
                }));
            }
            Err(RefreshAuthError::Denied) => None,
        }
    } else {
        None
    };
    let revoking_current = current_family.as_deref() == Some(family_id);

    match revoke_session_for_user(oid, family_id).await {
        Ok(_) => {
            revoke_session_remotely(&oid.to_hex(), family_id);
            if revoking_current {
                HttpResponse::Ok()
                    .cookie(jwt_cookie("", 0))
                    .cookie(clear_refresh_cookie())
                    .cookie(clear_legacy_refresh_cookie())
                    .cookie(clear_csrf_cookie())
                    .json(json!({
                        "message": "Sesja została wylogowana.",
                        "currentSessionRevoked": true,
                    }))
            } else {
                HttpResponse::Ok().json(json!({
                    "message": "Sesja została wylogowana.",
                    "currentSessionRevoked": false,
                }))
            }
        }
        Err(message) if message == "Session not found" => {
            HttpResponse::NotFound().json(json!({ "message": "Sesja nie istnieje." }))
        }
        Err(_) => HttpResponse::InternalServerError().json(json!({
            "message": "Nie udało się wylogować sesji."
        })),
    }
}

pub async fn revoke_other_sessions(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let Some(raw_token) = req.cookie(REFRESH_COOKIE).map(|c| c.value().to_string()) else {
        return HttpResponse::BadRequest().json(json!({
            "message": "Nie można określić bieżącej sesji."
        }));
    };

    let current_family = match family_id_from_refresh_token(&raw_token).await {
        Ok(Some(fid)) => fid,
        Ok(None) => {
            return HttpResponse::BadRequest().json(json!({
                "message": "Bieżąca sesja jest nieprawidłowa."
            }));
        }
        Err(RefreshAuthError::Unavailable) | Err(RefreshAuthError::Denied) => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "message": "Temporarily unavailable. Retry."
            }));
        }
    };

    let db = get_db();
    let other_families = match RefreshToken::active_family_ids_for_user_except(&db, oid, &current_family)
        .await
    {
        Ok(families) => families,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "message": "Nie udało się wylogować innych sesji."
            }));
        }
    };

    match revoke_other_sessions_for_user(oid, &current_family).await {
        Ok(revoked) => {
            let user_hex = oid.to_hex();
            for family in other_families {
                revoke_session_remotely(&user_hex, &family);
            }
            HttpResponse::Ok().json(json!({
                "message": if revoked > 0 {
                    format!("Wylogowano {revoked} innych sesji.")
                } else {
                    "Brak innych aktywnych sesji.".to_string()
                },
                "revokedCount": revoked,
            }))
        }
        Err(_) => HttpResponse::InternalServerError().json(json!({
            "message": "Nie udało się wylogować innych sesji."
        })),
    }
}

pub async fn get_user_info(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User with the given id not found.");
    };

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User with the given id not found."),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    let mut payload = serialize_user(&user);

    let (csrf, csrf_cookie) = csrf_token_for_response(&req);
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("csrfToken".to_string(), json!(csrf));
        let session_needs_refresh = req
            .cookie("jwt")
            .map(|c| {
                crate::utils::auth::jwt::session_family_from_jwt(c.value()).is_none()
            })
            .unwrap_or(false);
        obj.insert(
            "sessionNeedsRefresh".to_string(),
            json!(session_needs_refresh),
        );
    }

    let mut builder = HttpResponse::Ok();
    if let Some(cookie) = csrf_cookie {
        builder.cookie(cookie);
    }
    builder.json(payload)
}

fn serialize_own_warning(w: &Warning) -> serde_json::Value {
    json!({
        "id": w.id.map(|o| o.to_hex()),
        "reason": w.reason,
        "severity": severity_str(&w.severity),
        "acknowledged": w.acknowledged,
        "acknowledgedAt": w.acknowledged_at.and_then(|dt| dt.try_to_rfc3339_string().ok()),
        "createdAt": w.created_at.try_to_rfc3339_string().ok(),
    })
}

pub async fn get_my_warnings(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User with the given id not found.");
    };

    let db = get_db();
    let warnings = match Warning::list_for_user(&db, oid).await {
        Ok(w) => w,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się pobrać ostrzeżeń." }));
        }
    };

    let unacknowledged = warnings.iter().filter(|w| !w.acknowledged).count();
    let items: Vec<serde_json::Value> = warnings.iter().map(serialize_own_warning).collect();

    HttpResponse::Ok().json(json!({
        "warnings": items,
        "total": items.len(),
        "unacknowledged": unacknowledged,
    }))
}

pub async fn acknowledge_my_warnings(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User with the given id not found.");
    };

    let db = get_db();
    match Warning::acknowledge_all_for_user(&db, oid).await {
        Ok(count) => HttpResponse::Ok().json(json!({
            "message": "Ostrzeżenia zostały potwierdzone.",
            "acknowledged": count,
        })),
        Err(_) => HttpResponse::InternalServerError()
            .json(json!({ "error": "Nie udało się potwierdzić ostrzeżeń." })),
    }
}

pub async fn update_profile(req: HttpRequest, body: web::Json<UpdateProfileBody>) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::BadRequest().body("User ID is required.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let trimmed_name = crate::utils::validators::unicode::sanitize_display_name(
        body.display_name.as_deref().unwrap_or(""),
    );
    if trimmed_name.is_empty() {
        return HttpResponse::BadRequest().body("Display name is required.");
    }
    if trimmed_name.chars().count() > DISPLAY_NAME_MAX_LENGTH {
        return HttpResponse::BadRequest()
            .body(format!("Display name must be at most {DISPLAY_NAME_MAX_LENGTH} characters."));
    }

    let trimmed_bio = crate::utils::validators::unicode::sanitize_bio(
        body.bio.as_deref().unwrap_or(""),
    );
    if trimmed_bio.chars().count() > BIO_MAX_LENGTH {
        return HttpResponse::BadRequest()
            .body(format!("Bio must be at most {BIO_MAX_LENGTH} characters."));
    }

    let bio_val: Bson = if trimmed_bio.is_empty() {
        Bson::Null
    } else {
        Bson::String(trimmed_bio)
    };
    let color_val: Bson = body.color.map(Bson::from).unwrap_or(Bson::Null);

    let set = doc! {
        "displayName": &trimmed_name,
        "bio": bio_val,
        "color": color_val,
        "profileSetup": true,
    };

    let db = get_db();
    match User::set_fields(&db, oid, set).await {
        Ok(Some(user)) => {
            emit_profile_event(
                &db,
                &user_id,
                "profile-updated",
                json!({
                    "userId": user_id,
                    "displayName": resolve_display_name(&user),
                    "bio": user.bio.as_ref().map(|b| b.trim()).filter(|b| !b.is_empty()),
                    "color": user.color,
                }),
            )
            .await;
            HttpResponse::Ok().json(serialize_user(&user))
        }
        Ok(None) => HttpResponse::NotFound().body("User not found."),
        Err(_) => HttpResponse::InternalServerError().body("Internal Server Error."),
    }
}

pub async fn update_language(req: HttpRequest, body: web::Json<UpdateLanguageBody>) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::BadRequest().body("User ID is required.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let language = normalize_language(body.language.as_deref().unwrap_or("en"));
    let set = doc! { "language": &language };

    let db = get_db();
    match User::set_fields(&db, oid, set).await {
        Ok(Some(user)) => HttpResponse::Ok().json(serialize_user(&user)),
        Ok(None) => HttpResponse::NotFound().body("User not found."),
        Err(_) => HttpResponse::InternalServerError().body("Internal Server Error."),
    }
}

pub async fn update_availability_status(
    req: HttpRequest,
    body: web::Json<AvailabilityBody>,
) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::BadRequest().body("User ID is required.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let status = body.availability_status.as_deref().unwrap_or("");
    if !matches!(status, "online" | "away" | "brb" | "dnd") {
        return HttpResponse::BadRequest().body("Invalid availability status.");
    }

    let db = get_db();

    match User::set_fields(
        &db,
        oid,
        doc! {
            "availabilityStatus": status,
            "isOnline": true,
        },
    )
    .await
    {
        Ok(Some(user)) => {
            crate::utils::user::online::put(&user_id, status);
            emit_status_event(
                &db,
                &user_id,
                json!({
                    "userId": user_id,
                    "status": {
                        "isOnline": true,
                        "availabilityStatus": status,
                        "lastSeen": serde_json::Value::Null,
                    },
                }),
            )
            .await;
            HttpResponse::Ok().json(serialize_user(&user))
        }
        Ok(None) => HttpResponse::NotFound().body("User not found."),
        Err(_) => HttpResponse::InternalServerError().body("Internal Server Error."),
    }
}

pub async fn add_profile_image(
    req: HttpRequest,
    MultipartForm(form): MultipartForm<ProfileImageForm>,
) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let original = form.file.file_name.clone().unwrap_or_default();
    let ext = file_ext(&original);
    if !ALLOWED_IMAGE_EXT.contains(&ext.as_str()) {
        return HttpResponse::BadRequest().body("Invalid file type.");
    }
    let upload_path = form.file.file.path().to_path_buf();
    if !validate_file_magic_async(upload_path.clone(), ext.clone()).await {
        return HttpResponse::BadRequest().body("Invalid file content.");
    }
    if local_file_size(&upload_path)
        .map(|size| !file_bytes_within_limit(size, MAX_AVATAR_BYTES))
        .unwrap_or(true)
    {
        return HttpResponse::PayloadTooLarge().body("File too large. Maximum size is 6 MB.");
    }

    let db = get_db();
    let existing = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found."),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error."),
    };
    let previous_image = existing.image.clone();

    let key = avatar_user_key(&user_id);
    let webp = match reencode_upload_to_webp_async(upload_path).await {
        Ok(bytes) => bytes,
        Err(err) => return HttpResponse::BadRequest().body(reencode_error_message(&err)),
    };
    if storage()
        .put_public(&key, webp, "image/webp")
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().body("Internal Server Error.");
    }

    match User::set_fields(&db, oid, doc! { "image": &key }).await {
        Ok(Some(user)) => {
            if let Some(image) = previous_image {
                if image != key && avatar_key_owned_by_user(&image, &user_id) {
                    let _ = storage().delete_avatar_key(&image).await;
                }
            }
            emit_profile_event(
                &db,
                &user_id,
                "profile-image-updated",
                json!({
                    "userId": user_id,
                    "image": user.image,
                }),
            )
            .await;
            HttpResponse::Ok().json(json!({ "image": user.image }))
        }
        Ok(None) => HttpResponse::NotFound().body("User not found."),
        Err(_) => HttpResponse::InternalServerError().body("Internal Server Error."),
    }
}

pub async fn remove_profile_image(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "User not found" }));
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "User not found" }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "User not found" })),
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Internal server error" }))
        }
    };

    if let Some(image) = &user.image {
        match User::set_fields(&db, oid, doc! { "image": Bson::Null }).await {
            Ok(Some(_)) => {
                if avatar_key_owned_by_user(image, &user_id) {
                    let _ = storage().delete_avatar_key(image).await;
                }
                emit_profile_event(
                    &db,
                    &user_id,
                    "profile-image-updated",
                    json!({
                        "userId": user_id,
                        "image": null,
                    }),
                )
                .await;
            }
            Ok(None) => {
                return HttpResponse::NotFound().json(json!({ "error": "User not found" }));
            }
            Err(_) => {
                return HttpResponse::InternalServerError()
                    .json(json!({ "error": "Internal server error" }));
            }
        }
    }

    HttpResponse::Ok().json(json!({ "message": "Profile image removed successfully" }))
}

pub async fn add_profile_banner(
    req: HttpRequest,
    MultipartForm(form): MultipartForm<ProfileBannerForm>,
) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let original = form.file.file_name.clone().unwrap_or_default();
    let ext = file_ext(&original);
    if !ALLOWED_IMAGE_EXT.contains(&ext.as_str()) {
        return HttpResponse::BadRequest().body("Invalid file type.");
    }
    let upload_path = form.file.file.path().to_path_buf();
    if !validate_file_magic_async(upload_path.clone(), ext.clone()).await {
        return HttpResponse::BadRequest().body("Invalid file content.");
    }
    if local_file_size(&upload_path)
        .map(|size| !file_bytes_within_limit(size, MAX_BANNER_BYTES))
        .unwrap_or(true)
    {
        return HttpResponse::PayloadTooLarge().body("File too large. Maximum size is 7 MB.");
    }

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found."),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error."),
    };
    let previous_banner = user.banner.clone();

    let key = banner_user_key(&user_id);
    let webp = match reencode_upload_to_webp_max_edge_async(upload_path, MAX_BANNER_EDGE).await {
        Ok(bytes) => bytes,
        Err(err) => return HttpResponse::BadRequest().body(reencode_error_message(&err)),
    };
    if storage()
        .put_public(&key, webp, "image/webp")
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().body("Internal Server Error.");
    }

    match User::set_fields(&db, oid, doc! { "banner": &key }).await {
        Ok(Some(user)) => {
            if let Some(banner) = previous_banner {
                if banner != key && public_media_key_owned_by_user(&banner, &user_id) {
                    let _ = storage().delete_public_media_key(&banner).await;
                }
            }
            emit_profile_event(
                &db,
                &user_id,
                "profile-banner-updated",
                json!({
                    "userId": user_id,
                    "banner": user.banner,
                }),
            )
            .await;
            HttpResponse::Ok().json(json!({ "banner": user.banner }))
        }
        Ok(None) => HttpResponse::NotFound().body("User not found."),
        Err(_) => HttpResponse::InternalServerError().body("Internal Server Error."),
    }
}

pub async fn remove_profile_banner(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "User not found" }));
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "User not found" }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "User not found" })),
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Internal server error" }))
        }
    };

    if let Some(banner) = &user.banner {
        match User::set_fields(&db, oid, doc! { "banner": Bson::Null }).await {
            Ok(Some(_)) => {
                if public_media_key_owned_by_user(banner, &user_id) {
                    let _ = storage().delete_public_media_key(banner).await;
                }
                emit_profile_event(
                    &db,
                    &user_id,
                    "profile-banner-updated",
                    json!({
                        "userId": user_id,
                        "banner": null,
                    }),
                )
                .await;
            }
            Ok(None) => {
                return HttpResponse::NotFound().json(json!({ "error": "User not found" }));
            }
            Err(_) => {
                return HttpResponse::InternalServerError()
                    .json(json!({ "error": "Internal server error" }));
            }
        }
    }

    HttpResponse::Ok().json(json!({ "message": "Profile banner removed successfully" }))
}

pub async fn disable_account(
    req: HttpRequest,
    body: web::Json<AccountActionBody>,
) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found."),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    if user.is_disabled {
        return HttpResponse::BadRequest().json(json!({
            "message": "Konto jest już wyłączone.",
            "code": "ACCOUNT_ALREADY_DISABLED",
        }));
    }

    if user.is_pending_deletion() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Konto jest oznaczone do usunięcia.",
            "code": "ACCOUNT_PENDING_DELETION",
        }));
    }

    let password = body.password.as_deref().unwrap_or("").trim();
    if let Err(response) =
        verify_account_action_credentials(&user, password, body.code.as_deref(), &db, oid).await
    {
        return response;
    }

    let now = DateTime::now();
    if User::collection(&db)
        .update_one(
            doc! { "_id": oid },
            doc! {
                "$set": {
                    "isDisabled": true,
                    "disabledAt": now,
                    "updatedAt": now,
                },
            },
        )
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({
            "message": "Nie udało się wyłączyć konta."
        }));
    }

    invalidate_user_session(oid).await;

    HttpResponse::Ok().json(json!({
        "message": "Konto zostało wyłączone. Aby je przywrócić, skontaktuj się z administracją.",
        "code": "ACCOUNT_DISABLED",
    }))
}

pub async fn request_account_deletion(
    req: HttpRequest,
    body: web::Json<AccountActionBody>,
) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found."),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    if user.is_pending_deletion() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Konto jest już oznaczone do usunięcia.",
            "code": "ACCOUNT_PENDING_DELETION",
        }));
    }

    let password = body.password.as_deref().unwrap_or("").trim();
    if let Err(response) =
        verify_account_action_credentials(&user, password, body.code.as_deref(), &db, oid).await
    {
        return response;
    }

    let now = DateTime::now();
    let grace_ms = DELETION_GRACE_DAYS * 24 * 60 * 60 * 1000;
    let scheduled = DateTime::from_millis(now.timestamp_millis() + grace_ms);
    let scheduled_iso = scheduled.try_to_rfc3339_string().ok();

    if User::collection(&db)
        .update_one(
            doc! { "_id": oid },
            doc! {
                "$set": {
                    "deletionRequestedAt": now,
                    "deletionScheduledAt": scheduled,
                    "isDisabled": false,
                    "updatedAt": now,
                },
                "$unset": {
                    "disabledAt": "",
                },
            },
        )
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({
            "message": "Nie udało się oznaczyć konta do usunięcia."
        }));
    }

    HttpResponse::Ok().json(json!({
        "message": format!(
            "Konto zostało oznaczone do usunięcia. Możesz nadal korzystać z konta przez {} dni. Po tym czasie zostanie trwale usunięte, chyba że sam anulujesz tę operację w ustawieniach.",
            DELETION_GRACE_DAYS
        ),
        "code": "ACCOUNT_PENDING_DELETION",
        "deletionScheduledAt": scheduled_iso,
        "graceDays": DELETION_GRACE_DAYS,
    }))
}

pub async fn cancel_account_deletion(
    req: HttpRequest,
    body: web::Json<AccountActionBody>,
) -> HttpResponse {
    let Some(user_id) = req_user_id(&req) else {
        return HttpResponse::Unauthorized().body("User not authenticated.");
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().body("User not found.");
    };

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found."),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    if !user.is_pending_deletion() {
        return HttpResponse::BadRequest().json(json!({
            "message": "Konto nie jest oznaczone do usunięcia.",
            "code": "ACCOUNT_NOT_PENDING_DELETION",
        }));
    }

    let password = body.password.as_deref().unwrap_or("").trim();
    if let Err(response) =
        verify_account_action_credentials(&user, password, body.code.as_deref(), &db, oid).await
    {
        return response;
    }

    let now = DateTime::now();
    if User::collection(&db)
        .update_one(
            doc! { "_id": oid },
            doc! {
                "$set": {
                    "updatedAt": now,
                },
                "$unset": {
                    "deletionRequestedAt": "",
                    "deletionScheduledAt": "",
                },
            },
        )
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({
            "message": "Nie udało się anulować usunięcia konta."
        }));
    }

    HttpResponse::Ok().json(json!({
        "message": "Oznaczenie konta do usunięcia zostało anulowane.",
        "code": "ACCOUNT_DELETION_CANCELLED",
    }))
}
