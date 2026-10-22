// announcements.rs
// Ogłoszenie serwera (treść, okno czasowe).
// Zakres:
//  - lista dla klienta
//  - treść + okno czasowe; nie mylić z warnings
// Nie mieszaj z warnings (to nie jest kara na konto).
// Przy zmianach: controllers/announcements.rs.

use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    options::IndexOptions,
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const ANNOUNCEMENT_TITLE_MAX: usize = 120;
pub const ANNOUNCEMENT_BODY_MAX: usize = 8000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announcement {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub title: String,

    pub body: String,

    #[serde(default = "default_active")]
    pub active: bool,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

fn default_active() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct CreateAnnouncementInput {
    pub title: String,
    pub body: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnouncementDismissal {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "userId")]
    pub user_id: ObjectId,

    #[serde(rename = "announcementId")]
    pub announcement_id: ObjectId,

    #[serde(rename = "dismissedAt")]
    pub dismissed_at: DateTime,
}

fn iso(dt: &DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

impl Announcement {
    pub fn collection(db: &Database) -> Collection<Announcement> {
        db.collection("announcements")
    }

    pub fn to_api_json(&self) -> Value {
        json!({
            "id": self.id.map(|o| o.to_hex()),
            "title": self.title,
            "body": self.body,
            "active": self.active,
            "createdAt": iso(&self.created_at),
            "updatedAt": iso(&self.updated_at),
        })
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "active": 1, "createdAt": -1 })
                    .build(),
            )
            .await?;

        AnnouncementDismissal::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "userId": 1, "announcementId": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;

        Ok(())
    }

    pub async fn create(
        db: &Database,
        input: CreateAnnouncementInput,
    ) -> mongodb::error::Result<Announcement> {
        validate_announcement(&input.title, &input.body).map_err(mongodb::error::Error::custom)?;

        let now = DateTime::now();
        let announcement = Announcement {
            id: None,
            title: input.title.trim().to_string(),
            body: input.body.trim().to_string(),
            active: input.active,
            created_at: now,
            updated_at: now,
        };

        let result = Self::collection(db).insert_one(&announcement).await?;
        let created = Announcement {
            id: result.inserted_id.as_object_id(),
            ..announcement
        };
        if created.active {
            crate::ws::registry::emit_to_all_connected(
                "announcement:published",
                json!({ "announcement": created.to_api_json() }),
            );
        }
        Ok(created)
    }

    pub async fn find_by_id(
        db: &Database,
        id: ObjectId,
    ) -> mongodb::error::Result<Option<Announcement>> {
        Self::collection(db).find_one(doc! { "_id": id }).await
    }

    pub async fn list_all(db: &Database) -> mongodb::error::Result<Vec<Announcement>> {
        Self::collection(db)
            .find(doc! {})
            .sort(doc! { "createdAt": -1 })
            .limit(200)
            .await?
            .try_collect()
            .await
    }

    pub async fn list_active(db: &Database) -> mongodb::error::Result<Vec<Announcement>> {
        Self::collection(db)
            .find(doc! { "active": true })
            .sort(doc! { "createdAt": -1 })
            .limit(50)
            .await?
            .try_collect()
            .await
    }

    pub async fn update_fields(
        db: &Database,
        id: ObjectId,
        set: mongodb::bson::Document,
    ) -> mongodb::error::Result<Option<Announcement>> {
        use mongodb::options::FindOneAndUpdateOptions;
        use mongodb::options::ReturnDocument;

        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        Self::collection(db)
            .find_one_and_update(doc! { "_id": id }, doc! { "$set": set })
            .with_options(options)
            .await
    }

    pub async fn delete_by_id(db: &Database, id: ObjectId) -> mongodb::error::Result<bool> {
        let result = Self::collection(db).delete_one(doc! { "_id": id }).await?;
        AnnouncementDismissal::collection(db)
            .delete_many(doc! { "announcementId": id })
            .await?;
        Ok(result.deleted_count > 0)
    }
}

impl AnnouncementDismissal {
    pub fn collection(db: &Database) -> Collection<AnnouncementDismissal> {
        db.collection("announcement_dismissals")
    }

    pub async fn dismissed_ids_for_user(
        db: &Database,
        user_id: ObjectId,
    ) -> mongodb::error::Result<Vec<ObjectId>> {
        let rows: Vec<AnnouncementDismissal> = Self::collection(db)
            .find(doc! { "userId": user_id })
            .limit(500)
            .await?
            .try_collect()
            .await?;
        Ok(rows.into_iter().map(|r| r.announcement_id).collect())
    }

    pub async fn dismiss(
        db: &Database,
        user_id: ObjectId,
        announcement_id: ObjectId,
    ) -> mongodb::error::Result<bool> {
        let dismissal = AnnouncementDismissal {
            id: None,
            user_id,
            announcement_id,
            dismissed_at: DateTime::now(),
        };
        match Self::collection(db).insert_one(&dismissal).await {
            Ok(_) => Ok(true),
            Err(e) if e.to_string().contains("duplicate key") => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn dismiss_all(
        db: &Database,
        user_id: ObjectId,
        announcement_ids: &[ObjectId],
    ) -> mongodb::error::Result<u64> {
        let mut count = 0u64;
        for aid in announcement_ids {
            if Self::dismiss(db, user_id, *aid).await? {
                count += 1;
            }
        }
        Ok(count)
    }
}

pub fn validate_announcement(title: &str, body: &str) -> Result<(), &'static str> {
    let title = title.trim();
    let body = body.trim();
    if title.is_empty() {
        return Err("Title is required.");
    }
    if title.chars().count() > ANNOUNCEMENT_TITLE_MAX {
        return Err("Title is too long.");
    }
    if body.is_empty() {
        return Err("Body is required.");
    }
    if body.chars().count() > ANNOUNCEMENT_BODY_MAX {
        return Err("Body is too long.");
    }
    Ok(())
}
