// step_up.rs
// Ponowne hasło przy zmianie email/hasła/2FA off.
// Zakres:
//  - krótki challenge
//  - hasło ponownie przy zmianie email/hasła/2FA off
// Bez tego CSRF+skradziona sesja zmienia konto.
// Przy zmianach: controllers/auth.rs.

use mongodb::bson::{doc, oid::ObjectId, Bson, Document};
use mongodb::Database;

use crate::model::users::User;
use crate::utils::auth::totp::{
    decrypt_totp_secret, is_totp_code, verify_and_consume_backup_code, verify_totp_code,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepUpResult {
    NotRequired,
    Verified,
    BackupConsumed,
}

pub async fn verify_step_up_auth(
    db: &Database,
    user: &User,
    code: Option<&str>,
) -> Result<StepUpResult, &'static str> {
    if !user.two_factor_enabled {
        return Ok(StepUpResult::NotRequired);
    }

    let Some(code) = code.map(str::trim).filter(|c| !c.is_empty()) else {
        return Err("Authentication code is required when two-factor is enabled.");
    };

    if is_totp_code(code) {
        if let Some(encrypted) = user.totp_secret.as_deref() {
            match decrypt_totp_secret(encrypted) {
                Ok(secret) => match verify_totp_code(&user.username, &secret, code) {
                    Ok(true) => return Ok(StepUpResult::Verified),
                    Ok(false) => {}
                    Err(()) => return Err("Temporarily unavailable. Retry."),
                },
                Err(_) => return Err("Temporarily unavailable. Retry."),
            }
        }
        return Err("Invalid authentication code.");
    }

    if let Some(hashes) = user.backup_codes.as_ref() {
        match verify_and_consume_backup_code(code, hashes).await {
            Ok(Some(index)) => match consume_backup_code(db, user, index).await {
                Ok(true) => return Ok(StepUpResult::BackupConsumed),
                Ok(false) => return Err("Invalid authentication code."),
                Err(error) => {
                    log::error!("Failed to atomically consume backup code: {error}");
                    return Err("Temporarily unavailable. Retry.");
                }
            },
            Ok(None) => {}
            Err(()) => return Err("Temporarily unavailable. Retry."),
        }
    }

    Err("Invalid authentication code.")
}

pub async fn consume_backup_code(
    db: &Database,
    user: &User,
    index: usize,
) -> mongodb::error::Result<bool> {
    let Some(stored_codes) = user.backup_codes.as_ref() else {
        return Ok(false);
    };
    if index >= stored_codes.len() {
        return Ok(false);
    }
    let mut codes = stored_codes.clone();
    codes.remove(index);
    let expected_codes = Bson::Array(stored_codes.iter().cloned().map(Bson::String).collect());
    let replacement = if codes.is_empty() {
        Bson::Null
    } else {
        Bson::Array(codes.into_iter().map(Bson::String).collect())
    };
    let user_id: ObjectId = user
        .id
        .ok_or_else(|| mongodb::error::Error::custom("User has no database id"))?;
    let result = db
        .collection::<Document>("users")
        .update_one(
            doc! { "_id": user_id, "backupCodes": expected_codes },
            doc! { "$set": { "backupCodes": replacement } },
        )
        .await?;
    Ok(result.matched_count == 1)
}
