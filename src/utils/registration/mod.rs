// mod.rs
// Czy signup otwarty / disabled + limity rejestracji.
// Zakres:
//  - czytane przez middleware
//  - signup open / disabled — czyta middleware
// Zmiana bez FE = 403 z komunikatem API.
// Przy zmianach: signup.rs, controllers/auth.rs.

use std::env;

use mongodb::{
    bson::{doc, DateTime},
    options::{FindOneAndUpdateOptions, ReturnDocument},
    Collection, Database,
};

use crate::utils::env::is_production;

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|v| {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

fn env_u32(name: &str, default: u32) -> u32 {
    env_u64(name, default as u64) as u32
}

pub fn is_registration_disabled() -> bool {
    env_flag("REGISTRATION_DISABLED")
}

pub fn signup_max_per_ip_hour() -> u32 {
    // A single public IP is routinely shared by many legitimate users (home NAT,
    // schools, offices, mobile CGNAT). A prod cap of 3/hour — which also counts
    // failed attempts such as "username taken" — meant a couple of typos from one
    // person could lock out everyone else behind that IP, so some people could
    // sign up while others couldn't. Keep an anti-abuse ceiling but make it far
    // less likely to catch real users. Override with SIGNUP_MAX_PER_IP_HOUR.
    env_u32("SIGNUP_MAX_PER_IP_HOUR", if is_production() { 8 } else { 20 })
}

pub fn signup_max_global_per_hour() -> u64 {
    env_u64("SIGNUP_MAX_GLOBAL_PER_HOUR", if is_production() { 25 } else { 200 })
}

pub fn signup_max_global_per_day() -> u64 {
    env_u64("SIGNUP_MAX_GLOBAL_PER_DAY", if is_production() { 100 } else { 1000 })
}

pub fn is_registration_open() -> bool {
    !is_registration_disabled()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupQuotaError {
    HourlyLimit,
    DailyLimit,
    Unavailable,
}

impl SignupQuotaError {
    pub fn user_message(self) -> &'static str {
        match self {
            Self::HourlyLimit | Self::DailyLimit => {
                "Rejestracja jest tymczasowo niedostępna z powodu dużego obciążenia. Spróbuj ponownie później."
            }
            Self::Unavailable => "Temporarily unavailable. Retry.",
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::HourlyLimit => "SIGNUP_HOURLY_LIMIT",
            Self::DailyLimit => "SIGNUP_DAILY_LIMIT",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SignupQuotaDoc {
    #[serde(rename = "_id")]
    id: String,
    count: i64,
    #[serde(rename = "updatedAt")]
    updated_at: DateTime,
}

fn quota_collection(db: &Database) -> Collection<SignupQuotaDoc> {
    db.collection("signup_quotas")
}

fn utc_window_keys(now: DateTime) -> (String, String) {
    let millis = now.timestamp_millis();
    let secs = millis / 1000;
    let hour = secs / 3600;
    let day = secs / 86_400;
    (format!("hour:{hour}"), format!("day:{day}"))
}

async fn try_consume_window(
    db: &Database,
    key: &str,
    max: u64,
) -> mongodb::error::Result<bool> {
    let now = DateTime::now();

    // Increment unconditionally with a plain `_id` filter (which always matches an
    // existing bucket, so `upsert` only ever inserts a brand-new window). This
    // avoids the previous conditional-upsert filter, which — once the bucket was
    // full — matched nothing and made MongoDB attempt a duplicate-`_id` insert,
    // surfacing a write error that callers mistranslated into a misleading
    // "temporarily unavailable" 503 instead of a proper rate-limit response.
    let update = doc! {
        "$inc": { "count": 1 },
        "$set": { "updatedAt": now },
    };
    let options = FindOneAndUpdateOptions::builder()
        .upsert(true)
        .return_document(ReturnDocument::After)
        .build();

    let updated = quota_collection(db)
        .find_one_and_update(doc! { "_id": key }, update)
        .with_options(options)
        .await?;

    let count = updated.map(|doc| doc.count).unwrap_or(0);
    if count <= max as i64 {
        return Ok(true);
    }

    // Over the limit: undo our speculative increment so the bucket settles at
    // `max` and later windows aren't inflated. Best-effort — a lost decrement
    // only makes the limiter marginally stricter, never looser.
    let _ = quota_collection(db)
        .update_one(
            doc! { "_id": key, "count": { "$gt": 0_i64 } },
            doc! { "$inc": { "count": -1 } },
        )
        .await;

    Ok(false)
}

pub async fn try_consume_global_signup_slot(
    db: &Database,
) -> Result<(), SignupQuotaError> {
    let now = DateTime::now();
    let (hour_key, day_key) = utc_window_keys(now);

    let hour_ok = match try_consume_window(db, &hour_key, signup_max_global_per_hour()).await {
        Ok(v) => v,
        Err(_) => return Err(SignupQuotaError::Unavailable),
    };
    if !hour_ok {
        return Err(SignupQuotaError::HourlyLimit);
    }

    let day_ok = match try_consume_window(db, &day_key, signup_max_global_per_day()).await {
        Ok(v) => v,
        Err(_) => return Err(SignupQuotaError::Unavailable),
    };
    if !day_ok {

        let _ = quota_collection(db)
            .update_one(
                doc! { "_id": &hour_key, "count": { "$gt": 0 } },
                doc! { "$inc": { "count": -1 } },
            )
            .await;
        return Err(SignupQuotaError::DailyLimit);
    }

    Ok(())
}

pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
    quota_collection(db)
        .create_index(
            mongodb::IndexModel::builder()
                .keys(doc! { "updatedAt": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .expire_after(std::time::Duration::from_secs(8 * 24 * 3600))
                        .build(),
                )
                .build(),
        )
        .await?;

    Ok(())
}
