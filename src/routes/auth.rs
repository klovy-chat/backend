// auth.rs
// Ścieżki /api/auth/* + które middleware (captcha, csrf, signup).
// Zakres:
//  - mapowanie na controllers/auth
//  - które /api/auth/* i które middleware (captcha, csrf, signup)
// Nowy endpoint: najpierw tu (auth vs public), potem kontroler.
// Przy zmianach: controllers/auth.rs, middlewares/*.

use actix_multipart::form::{tempfile::TempFile, MultipartForm};
use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::auth::{
    acknowledge_my_warnings, add_profile_banner, add_profile_image, change_password,
    change_username, disable_account, disable_two_factor, enable_two_factor, get_my_warnings, get_user_info, list_sessions, login,
    logout, refresh_session, registration_status, issue_ws_crypto_key, remove_profile_banner, remove_profile_image, request_account_deletion, cancel_account_deletion, revoke_all_sessions, revoke_other_sessions, revoke_session, setup_two_factor, signup,
    update_availability_status, update_language, update_profile, verify_two_factor_login,
};
use crate::middlewares::signup::registration_closed;
use crate::controllers::announcements::{dismiss_announcements, get_my_announcements};
use crate::middlewares::auth_fallback::{auth_fallback_guard_login, auth_fallback_guard_signup};
use crate::middlewares::auth::{
    log_suspicious_activity, require_active_account, verify_token, verify_token_for_logout,
};
use crate::middlewares::captcha::verify_turnstile_token;
use crate::middlewares::validation::validate_password;
use crate::utils::ratelimit::{change_password_limiter, change_username_limiter, login_limiter, refresh_limiter, signup_limiter, status_update_limiter, two_factor_login_limiter, two_factor_mutation_limiter, upload_limiter};

#[derive(MultipartForm)]
pub struct ProfileImageForm {
    #[multipart(rename = "profile-image", limit = "6 MiB")]
    pub file: TempFile,
}

#[derive(MultipartForm)]
pub struct ProfileBannerForm {
    #[multipart(rename = "profile-banner", limit = "7 MiB")]
    pub file: TempFile,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_info)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_info)),
    );

    cfg.service(
        web::resource("/login")
            .wrap(from_fn(login_limiter))
            .wrap(from_fn(verify_turnstile_token))
            .wrap(from_fn(auth_fallback_guard_login))
            .wrap(from_fn(log_suspicious_activity("login")))
            .route(web::post().to(login)),
    );
    cfg.service(
        web::resource("/sign-in")
            .wrap(from_fn(login_limiter))
            .wrap(from_fn(verify_turnstile_token))
            .wrap(from_fn(auth_fallback_guard_login))
            .wrap(from_fn(log_suspicious_activity("login")))
            .route(web::post().to(login)),
    );
    cfg.service(
        web::resource("/signin")
            .wrap(from_fn(login_limiter))
            .wrap(from_fn(verify_turnstile_token))
            .wrap(from_fn(auth_fallback_guard_login))
            .wrap(from_fn(log_suspicious_activity("login")))
            .route(web::post().to(login)),
    );

    cfg.service(
        web::resource("/login/2fa")
            .wrap(from_fn(two_factor_login_limiter))
            .wrap(from_fn(verify_turnstile_token))
            .wrap(from_fn(auth_fallback_guard_login))
            .route(web::post().to(verify_two_factor_login)),
    );

    cfg.service(
        web::resource("/2fa/setup")
            .wrap(from_fn(two_factor_mutation_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(setup_two_factor)),
    );
    cfg.service(
        web::resource("/2fa/enable")
            .wrap(from_fn(two_factor_mutation_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(enable_two_factor)),
    );
    cfg.service(
        web::resource("/2fa/disable")
            .wrap(from_fn(two_factor_mutation_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(disable_two_factor)),
    );

    cfg.service(
        web::resource("/registration-status")
            .route(web::get().to(registration_status)),
    );

    cfg.service(
        web::resource("/ws-crypto")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(issue_ws_crypto_key)),
    );

    cfg.service(
        web::resource("/signup")
            .wrap(from_fn(registration_closed))
            .wrap(from_fn(signup_limiter))
            .wrap(from_fn(validate_password))
            .wrap(from_fn(verify_turnstile_token))
            .wrap(from_fn(auth_fallback_guard_signup))
            .wrap(from_fn(log_suspicious_activity("signup")))
            .route(web::post().to(signup)),
    );
    cfg.service(
        web::resource("/register")
            .wrap(from_fn(registration_closed))
            .wrap(from_fn(signup_limiter))
            .wrap(from_fn(validate_password))
            .wrap(from_fn(verify_turnstile_token))
            .wrap(from_fn(auth_fallback_guard_signup))
            .wrap(from_fn(log_suspicious_activity("signup")))
            .route(web::post().to(signup)),
    );

    cfg.service(
        web::resource("/refresh")
            .wrap(from_fn(refresh_limiter))
            .route(web::post().to(refresh_session)),
    );

    cfg.service(
        web::resource("/change-password")
            .wrap(from_fn(validate_password))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(log_suspicious_activity("change-password")))
            .wrap(from_fn(change_password_limiter))
            .route(web::post().to(change_password)),
    );

    cfg.service(
        web::resource("/change-username")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(log_suspicious_activity("change-username")))
            .wrap(from_fn(change_username_limiter))
            .route(web::post().to(change_username)),
    );

    cfg.service(
        web::resource("/logout")
            .wrap(from_fn(verify_token_for_logout))
            .route(web::post().to(logout)),
    );

    cfg.service(
        web::resource("/userinfo")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_info)),
    );
    cfg.service(
        web::resource("/me")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_info)),
    );
    cfg.service(
        web::resource("/user")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_user_info)),
    );
    cfg.service(
        web::resource("/update-profile")
            .wrap(from_fn(log_suspicious_activity("profile-update")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(update_profile)),
    );
    cfg.service(
        web::resource("/profile")
            .wrap(from_fn(log_suspicious_activity("profile-update")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(update_profile)),
    );
    cfg.service(
        web::resource("/language")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::patch().to(update_language)),
    );
    cfg.service(
        web::resource("/availability-status")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(status_update_limiter))
            .route(web::post().to(update_availability_status)),
    );
    cfg.service(
        web::resource("/status")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(status_update_limiter))
            .route(web::post().to(update_availability_status)),
    );

    cfg.service(
        web::resource("/add-profile-image")
            .wrap(from_fn(log_suspicious_activity("profile-image-upload")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(upload_limiter))
            .route(web::post().to(add_profile_image)),
    );
    cfg.service(
        web::resource("/profile-image")
            .wrap(from_fn(log_suspicious_activity("profile-image-upload")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(upload_limiter))
            .route(web::post().to(add_profile_image)),
    );
    cfg.service(
        web::resource("/avatar")
            .wrap(from_fn(log_suspicious_activity("profile-image-upload")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(upload_limiter))
            .route(web::post().to(add_profile_image)),
    );

    cfg.service(
        web::resource("/remove-profile-image")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::delete().to(remove_profile_image)),
    );

    cfg.service(
        web::resource("/add-profile-banner")
            .wrap(from_fn(log_suspicious_activity("profile-banner-upload")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(upload_limiter))
            .route(web::post().to(add_profile_banner)),
    );
    cfg.service(
        web::resource("/profile-banner")
            .wrap(from_fn(log_suspicious_activity("profile-banner-upload")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(upload_limiter))
            .route(web::post().to(add_profile_banner)),
    );
    cfg.service(
        web::resource("/banner")
            .wrap(from_fn(log_suspicious_activity("profile-banner-upload")))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(upload_limiter))
            .route(web::post().to(add_profile_banner)),
    );

    cfg.service(
        web::resource("/remove-profile-banner")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::delete().to(remove_profile_banner)),
    );

    cfg.service(
        web::resource("/warnings")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_my_warnings)),
    );
    cfg.service(
        web::resource("/warnings/acknowledge")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(acknowledge_my_warnings)),
    );

    cfg.service(
        web::resource("/announcements")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_my_announcements)),
    );
    cfg.service(
        web::resource("/announcements/dismiss")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(dismiss_announcements)),
    );

    cfg.service(
        web::resource("/account/disable")
            .wrap(from_fn(two_factor_mutation_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(log_suspicious_activity("account-disable")))
            .route(web::post().to(disable_account)),
    );

    cfg.service(
        web::resource("/account/request-deletion")
            .wrap(from_fn(two_factor_mutation_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(log_suspicious_activity("account-request-deletion")))
            .route(web::post().to(request_account_deletion)),
    );

    cfg.service(
        web::resource("/account/cancel-deletion")
            .wrap(from_fn(two_factor_mutation_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(log_suspicious_activity("account-cancel-deletion")))
            .route(web::post().to(cancel_account_deletion)),
    );

    cfg.service(
        web::resource("/sessions")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(list_sessions)),
    );

    cfg.service(
        web::resource("/sessions/revoke-others")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(revoke_other_sessions)),
    );

    cfg.service(
        web::resource("/sessions/revoke-all")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(revoke_all_sessions)),
    );

    cfg.service(
        web::resource("/sessions/{sessionId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::delete().to(revoke_session)),
    );
}
