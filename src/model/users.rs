// users.rs
// Dokument użytkownika: credentials, profil, 2FA, status, język.
// Zakres:
//  - hash hasła, flagi usunięcia/disable
//  - credentials, profil, 2FA, status; hash nie w JSON
// Nigdy nie serializuj hash/sekretów w JSON publicznym (user/json.rs).
// Przy zmianach: controllers/auth.rs, utils/user/json.rs.

use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    Collection, Database, IndexModel,
};
use mongodb::options::IndexOptions;
use serde::{Deserialize, Serialize};

use crate::utils::crypto::passwords::{
    hash_user_password, is_stored_password_hash, verify_user_password,
};
use crate::utils::validators::username::{is_valid_username, normalize_username};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AvailabilityStatus {
    Online,
    Away,
    Brb,
    Dnd,
}

impl Default for AvailabilityStatus {
    fn default() -> Self {
        Self::Online
    }
}

fn default_language() -> String {
    "en".to_string()
}

pub fn normalize_language(lang: &str) -> String {
    match lang.trim().to_lowercase().as_str() {
        "pl" => "pl".to_string(),
        _ => "en".to_string(),
    }
}

pub fn deserialize_bool_default_false<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Boolish {
        Bool(bool),
        Null,
    }

    Ok(match Boolish::deserialize(deserializer)? {
        Boolish::Bool(value) => value,
        Boolish::Null => false,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub username: String,

    pub password: String,

    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,

    #[serde(rename = "profileSetup", default)]
    pub profile_setup: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<i32>,

    #[serde(rename = "isActive")]
    pub is_active: bool,

    #[serde(rename = "isBlocked", default)]
    pub is_blocked: bool,

    #[serde(rename = "isBanned", default)]
    pub is_banned: bool,

    #[serde(rename = "blockReason", skip_serializing_if = "Option::is_none")]
    pub block_reason: Option<String>,

    #[serde(rename = "blockedAt", skip_serializing_if = "Option::is_none")]
    pub blocked_at: Option<DateTime>,

    #[serde(
        rename = "isDisabled",
        default,
        deserialize_with = "deserialize_bool_default_false"
    )]
    pub is_disabled: bool,

    #[serde(rename = "disabledAt", skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<DateTime>,

    #[serde(rename = "deletionRequestedAt", skip_serializing_if = "Option::is_none")]
    pub deletion_requested_at: Option<DateTime>,

    #[serde(rename = "deletionScheduledAt", skip_serializing_if = "Option::is_none")]
    pub deletion_scheduled_at: Option<DateTime>,

    #[serde(rename = "isOnline", default)]
    pub is_online: bool,

    #[serde(rename = "availabilityStatus", default)]
    pub availability_status: AvailabilityStatus,

    #[serde(rename = "lastSeen", skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime>,

    #[serde(default = "default_language")]
    pub language: String,

    #[serde(rename = "mutedChannels", default)]
    pub muted_channels: Vec<ObjectId>,

    #[serde(rename = "mutedContacts", default)]
    pub muted_contacts: Vec<ObjectId>,

    #[serde(rename = "blockedContacts", default)]
    pub blocked_contacts: Vec<ObjectId>,

    #[serde(rename = "tokenVersion", default)]
    pub token_version: i32,

    #[serde(rename = "twoFactorEnabled", default)]
    pub two_factor_enabled: bool,

    #[serde(rename = "totpSecret", skip_serializing_if = "Option::is_none", default)]
    pub totp_secret: Option<String>,

    #[serde(rename = "totpPendingSecret", skip_serializing_if = "Option::is_none", default)]
    pub totp_pending_secret: Option<String>,

    #[serde(rename = "backupCodes", skip_serializing_if = "Option::is_none", default)]
    pub backup_codes: Option<Vec<String>>,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

pub struct CreateUserInput {
    pub username: String,
    pub password: String,
    pub language: Option<String>,
}

#[derive(Debug)]
pub enum UserValidationError {
    UsernameRequired,
    UsernameTooShort,
    UsernameTooLong,
    UsernameInvalidChars,
    PasswordRequired,
    PasswordTooShort,
}

impl std::fmt::Display for UserValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::UsernameRequired     => "Username is required",
            Self::UsernameTooShort     => "Username must be at least 3 characters",
            Self::UsernameTooLong      => "Username must be at most 32 characters",
            Self::UsernameInvalidChars => "Username may only contain lowercase letters, numbers and underscores",
            Self::PasswordRequired     => "Password is required",
            Self::PasswordTooShort     => "Password must be at least 8 characters",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for UserValidationError {}

pub fn validate_user(input: &CreateUserInput) -> Result<(), UserValidationError> {
    let username = input.username.trim();

    if username.is_empty() {
        return Err(UserValidationError::UsernameRequired);
    }
    if username.len() < 3 {
        return Err(UserValidationError::UsernameTooShort);
    }
    if username.len() > 32 {
        return Err(UserValidationError::UsernameTooLong);
    }
    if !is_valid_username(username) {
        return Err(UserValidationError::UsernameInvalidChars);
    }
    if input.password.trim().is_empty() {
        return Err(UserValidationError::PasswordRequired);
    }
    if input.password.len() < 8 {
        return Err(UserValidationError::PasswordTooShort);
    }

    Ok(())
}

impl User {
    pub fn collection(db: &Database) -> Collection<User> {
        db.collection("users")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "username": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "displayName": 1 })
                    .build(),
            )
            .await?;
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "createdAt": -1 })
                    .build(),
            )
            .await?;

        Ok(())
    }

    pub async fn create(
        db: &Database,
        input: CreateUserInput,
    ) -> Result<User, Box<dyn std::error::Error>> {
        validate_user(&input)?;

        let username = normalize_username(input.username.trim());

        let password = if is_stored_password_hash(&input.password) {
            input.password.clone()
        } else {
            hash_user_password(&input.password).await?
        };

        let now = DateTime::now();
        let user = User {
            id: None,
            username,
            password,
            display_name: None,
            bio: None,
            image: None,
            banner: None,
            profile_setup: false,
            color: None,
            is_active: true,
            is_blocked: false,
            is_banned: false,
            block_reason: None,
            blocked_at: None,
            is_disabled: false,
            disabled_at: None,
            deletion_requested_at: None,
            deletion_scheduled_at: None,
            is_online: false,
            availability_status: AvailabilityStatus::Online,
            last_seen: None,
            language: input
                .language
                .as_deref()
                .map(normalize_language)
                .unwrap_or_else(default_language),
            muted_channels: vec![],
            muted_contacts: vec![],
            blocked_contacts: vec![],
            token_version: 0,
            two_factor_enabled: false,
            totp_secret: None,
            totp_pending_secret: None,
            backup_codes: None,
            created_at: now,
            updated_at: now,
        };

        let result = Self::collection(db).insert_one(&user).await?;
        let id = result.inserted_id.as_object_id();

        Ok(User { id, ..user })
    }

    pub fn is_login_allowed(&self) -> bool {
        self.is_active
            && !self.is_disabled
            && !self.is_blocked
            && !self.is_banned
    }

    pub fn is_pending_deletion(&self) -> bool {
        self.deletion_scheduled_at.is_some()
    }

    pub async fn find_by_id(
        db: &Database,
        id: ObjectId,
    ) -> mongodb::error::Result<Option<User>> {
        Self::collection(db).find_one(doc! { "_id": id }).await
    }

    pub async fn find_by_username(
        db: &Database,
        username: &str,
    ) -> mongodb::error::Result<Option<User>> {
        Self::collection(db)
            .find_one(doc! {
                "username": normalize_username(username),
            })
            .await
    }

    pub async fn login(
        db: &Database,
        username: &str,
        password: &str,
    ) -> Result<User, Box<dyn std::error::Error>> {
        let user = Self::find_by_username(db, username)
            .await?
            .ok_or("Incorrect username or user not found")?;

        match verify_user_password(password, &user.password).await {
            Ok(true) => Ok(user),
            Ok(false) => Err("Incorrect password".into()),
            Err(()) => Err("Temporarily unavailable".into()),
        }
    }

    pub async fn update_password(
        db: &Database,
        id: ObjectId,
        new_password: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let hashed = hash_user_password(new_password).await?;

        Self::collection(db)
            .update_one(
                doc! { "_id": id },
                doc! {
                    "$set": {
                        "password": hashed,
                        "updatedAt": DateTime::now(),
                    },
                    "$inc": { "tokenVersion": 1 },
                },
            )
            .await?;

        Ok(())
    }

    pub async fn set_fields(
        db: &Database,
        id: ObjectId,
        set: mongodb::bson::Document,
    ) -> mongodb::error::Result<Option<User>> {
        let mut set = set;
        set.insert("updatedAt", DateTime::now());
        Self::collection(db)
            .update_one(doc! { "_id": id }, doc! { "$set": set })
            .await?;
        Self::find_by_id(db, id).await
    }

    pub async fn username_exists(
        db: &Database,
        username: &str,
    ) -> mongodb::error::Result<bool> {
        let count = Self::collection(db)
            .count_documents(doc! { "username": normalize_username(username) })
            .await?;
        Ok(count > 0)
    }

    pub async fn username_taken_by_other(
        db: &Database,
        username: &str,
        exclude_id: ObjectId,
    ) -> mongodb::error::Result<bool> {
        let count = Self::collection(db)
            .count_documents(doc! {
                "username": normalize_username(username),
                "_id": { "$ne": exclude_id },
            })
            .await?;
        Ok(count > 0)
    }

    pub async fn invalidate_tokens(
        db: &Database,
        id: ObjectId,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_one(
                doc! { "_id": id },
                doc! { "$inc": { "tokenVersion": 1 }, "$set": { "updatedAt": DateTime::now() } },
            )
            .await?;

        Ok(())
    }
}
