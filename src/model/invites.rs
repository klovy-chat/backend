// invites.rs
// Kod zaproszenia: kanał, twórca, uses, expiry.
// Zakres:
//  - atomowe consume
//  - kod, uses, expiry; consume atomowe
// Race already-member: refund use w kontrolerze.
// Przy zmianach: controllers/invites.rs.

use mongodb::{
    bson::{doc, oid::ObjectId, Bson, DateTime},
    options::{FindOneAndUpdateOptions, IndexOptions, ReturnDocument},
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_INVITE_USE_LIMIT: u32 = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "inviteId")]
    pub invite_id: String,

    #[serde(rename = "channelId")]
    pub channel_id: ObjectId,

    #[serde(rename = "createdBy")]
    pub created_by: ObjectId,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime>,

    #[serde(default)]
    pub used: bool,

    #[serde(rename = "useCount", default)]
    pub use_count: u32,

    #[serde(rename = "pendingUseIds", default)]
    pub pending_use_ids: Vec<String>,

    #[serde(rename = "maxUses", skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,

    #[serde(default)]
    pub revoked: bool,
}

impl Invite {
    pub fn collection(db: &Database) -> Collection<Invite> {
        db.collection("invites")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "inviteId": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;

        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "channelId": 1, "createdAt": -1 })
                    .build(),
            )
            .await?;

        Ok(())
    }

    pub async fn create(
        db: &Database,
        channel_id: ObjectId,
        created_by: ObjectId,
        max_uses: Option<u32>,
        expires_at: Option<DateTime>,
    ) -> mongodb::error::Result<Invite> {
        let invite = Invite {
            id: None,
            invite_id: Uuid::new_v4().to_string(),
            channel_id,
            created_by,
            created_at: DateTime::now(),
            expires_at,
            used: false,
            use_count: 0,
            pending_use_ids: Vec::new(),
            max_uses,
            revoked: false,
        };

        let result = Self::collection(db).insert_one(&invite).await?;
        let id = result.inserted_id.as_object_id();

        Ok(Invite { id, ..invite })
    }

    pub async fn find_by_invite_id(
        db: &Database,
        invite_id: &str,
    ) -> mongodb::error::Result<Option<Invite>> {
        Self::collection(db)
            .find_one(doc! { "inviteId": invite_id })
            .await
    }

    pub async fn list_for_channel(
        db: &Database,
        channel_id: ObjectId,
    ) -> mongodb::error::Result<Vec<Invite>> {
        use futures_util::stream::TryStreamExt;
        let cursor = Self::collection(db)
            .find(doc! { "channelId": channel_id })
            .sort(doc! { "createdAt": -1 })
            .await?;
        cursor.try_collect().await
    }

    pub async fn delete_for_channel(
        db: &Database,
        invite_id: &str,
        channel_id: ObjectId,
    ) -> mongodb::error::Result<bool> {
        let res = Self::collection(db)
            .delete_one(doc! { "inviteId": invite_id, "channelId": channel_id })
            .await?;
        Ok(res.deleted_count > 0)
    }

    pub async fn try_register_use(
        db: &Database,
        invite_id: &str,
        reservation_id: &str,
    ) -> mongodb::error::Result<Option<Invite>> {
        let now = DateTime::now();
        let filter = doc! {
            "inviteId": invite_id,
            "used": { "$ne": true },
            "revoked": { "$ne": true },
            "$and": [
                { "$or": [
                    { "expiresAt": { "$exists": false } },
                    { "expiresAt": Bson::Null },
                    { "expiresAt": { "$gt": now } },
                ]},
                { "$or": [
                    { "maxUses": { "$exists": false } },
                    { "maxUses": Bson::Null },
                    { "$expr": { "$lt": ["$useCount", "$maxUses"] } },
                ]},
            ],
        };
        let update = doc! {
            "$inc": { "useCount": 1 },
            "$addToSet": { "pendingUseIds": reservation_id },
        };
        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        Self::collection(db)
            .find_one_and_update(filter, update)
            .with_options(options)
            .await
    }

    pub async fn release_use(
        db: &Database,
        invite_id: &str,
        reservation_id: &str,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_one(
                doc! {
                    "inviteId": invite_id,
                    "pendingUseIds": reservation_id,
                },
                doc! {
                    "$inc": { "useCount": -1 },
                    "$pull": { "pendingUseIds": reservation_id },
                },
            )
            .await?;
        Ok(())
    }

    pub async fn commit_use(
        db: &Database,
        invite_id: &str,
        reservation_id: &str,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_one(
                doc! {
                    "inviteId": invite_id,
                    "pendingUseIds": reservation_id,
                },
                doc! { "$pull": { "pendingUseIds": reservation_id } },
            )
            .await?;
        Ok(())
    }
}
