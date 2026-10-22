// read_state.rs
// lastRead + unreadCount per user × rozmowa.
// Zakres:
//  - denorm do listy
//  - lastRead + unreadCount per user × rozmowa
// Absolute unread emituj dopiero po zweryfikowanym sync (handlers).
// Przy zmianach: utils/unread/mod.rs, ws mark-read.

use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    options::IndexOptions,
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelReadState {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "userId")]
    pub user_id: ObjectId,

    #[serde(rename = "channelId")]
    pub channel_id: ObjectId,

    #[serde(rename = "lastReadAt")]
    pub last_read_at: DateTime,

    #[serde(rename = "unreadCount", default)]
    pub unread_count: u64,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

impl ChannelReadState {
    pub fn collection(db: &Database) -> Collection<ChannelReadState> {
        db.collection("channelreadstates")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let col = Self::collection(db);

        col.create_index(
            IndexModel::builder()
                .keys(doc! { "userId": 1, "channelId": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
        )
        .await?;

        col.create_index(IndexModel::builder().keys(doc! { "channelId": 1 }).build())
            .await?;

        Ok(())
    }

    pub async fn find(
        db: &Database,
        user_id: ObjectId,
        channel_id: ObjectId,
    ) -> mongodb::error::Result<Option<ChannelReadState>> {
        Self::collection(db)
            .find_one(doc! { "userId": user_id, "channelId": channel_id })
            .await
    }

    pub async fn upsert(
        db: &Database,
        user_id: ObjectId,
        channel_id: ObjectId,
    ) -> mongodb::error::Result<()> {
        use mongodb::options::UpdateOptions;

        let now = DateTime::now();

        let last_read = DateTime::from_millis(now.timestamp_millis().saturating_sub(1));
        Self::collection(db)
            .update_one(
                doc! { "userId": user_id, "channelId": channel_id },
                doc! {
                    "$set": {
                        "lastReadAt": last_read,
                        "updatedAt": now,
                        "unreadCount": 0i64,
                    },
                    "$setOnInsert": { "createdAt": now },
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await?;

        Ok(())
    }

    pub async fn bump_unread(
        db: &Database,
        user_id: ObjectId,
        channel_id: ObjectId,

        message_ts: DateTime,
    ) -> mongodb::error::Result<()> {
        use mongodb::options::UpdateOptions;
        let now = DateTime::now();
        let watermark = DateTime::from_millis(message_ts.timestamp_millis().saturating_sub(1));
        Self::collection(db)
            .update_one(
                doc! { "userId": user_id, "channelId": channel_id },
                doc! {
                    "$inc": { "unreadCount": 1i64 },
                    "$set": { "updatedAt": now },
                    "$setOnInsert": {
                        "createdAt": now,

                        "lastReadAt": watermark,
                    },
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await?;
        Ok(())
    }

    pub async fn bump_unread_many(
        db: &Database,
        user_ids: &[ObjectId],
        channel_id: ObjectId,
        message_ts: DateTime,
    ) -> Vec<ObjectId> {
        let mut failed = Vec::new();
        if user_ids.is_empty() {
            return failed;
        }
        const CHUNK: usize = 32;
        let mut i = 0;
        while i < user_ids.len() {
            let end = (i + CHUNK).min(user_ids.len());
            let batch = user_ids[i..end].iter().copied().map(|uid| async move {
                (
                    uid,
                    Self::bump_unread(db, uid, channel_id, message_ts).await,
                )
            });
            for (uid, res) in futures_util::future::join_all(batch).await {
                if res.is_err() {
                    failed.push(uid);
                }
            }
            i = end;
        }
        failed
    }

    pub async fn seed_if_missing(
        db: &Database,
        user_id: ObjectId,
        channel_id: ObjectId,
    ) -> mongodb::error::Result<()> {
        use mongodb::options::UpdateOptions;
        let now = DateTime::now();

        let last_read = DateTime::from_millis(now.timestamp_millis().saturating_sub(1));
        Self::collection(db)
            .update_one(
                doc! { "userId": user_id, "channelId": channel_id },
                doc! {
                    "$setOnInsert": {
                        "createdAt": now,
                        "lastReadAt": last_read,
                        "unreadCount": 0i64,
                        "updatedAt": now,
                    },
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await?;
        Ok(())
    }

    pub async fn reset_for_rejoin(
        db: &Database,
        user_id: ObjectId,
        channel_id: ObjectId,
    ) -> mongodb::error::Result<()> {
        use mongodb::options::UpdateOptions;

        let now = DateTime::now();
        let last_read = now;
        Self::collection(db)
            .update_one(
                doc! { "userId": user_id, "channelId": channel_id },
                doc! {
                    "$set": {
                        "lastReadAt": last_read,
                        "unreadCount": 0i64,
                        "updatedAt": now,
                    },
                    "$setOnInsert": {
                        "createdAt": now,
                    },
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await?;
        Ok(())
    }
}
