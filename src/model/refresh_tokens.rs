// refresh_tokens.rs
// Rodzina refresh: hash, expiry, revoke.
// Zakres:
//  - reuse detection
//  - hash, family, expiry; plaintext tylko w cookie
// Plaintext token tylko w cookie odpowiedzi, w Mongo hash.
// Przy zmianach: utils/auth/refresh.rs, token_hash.rs.

use chrono::{DateTime, Utc};
use mongodb::bson::{doc, oid::ObjectId, DateTime as BsonDateTime};
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    #[serde(rename = "userId")]
    pub user_id: ObjectId,
    #[serde(rename = "tokenHash")]
    pub token_hash: String,
    #[serde(rename = "familyId")]
    pub family_id: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: BsonDateTime,
    #[serde(rename = "createdAt")]
    pub created_at: BsonDateTime,
    pub revoked: bool,
    #[serde(rename = "clientFingerprint", skip_serializing_if = "Option::is_none")]
    pub client_fingerprint: Option<String>,
    #[serde(rename = "clientUserAgent", skip_serializing_if = "Option::is_none")]
    pub client_user_agent: Option<String>,
    #[serde(rename = "clientBrowser", skip_serializing_if = "Option::is_none")]
    pub client_browser: Option<String>,
    #[serde(rename = "clientOs", skip_serializing_if = "Option::is_none")]
    pub client_os: Option<String>,
    #[serde(rename = "clientLabel", skip_serializing_if = "Option::is_none")]
    pub client_label: Option<String>,
    #[serde(rename = "lastUsedAt", skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<BsonDateTime>,
}

impl RefreshToken {
    fn collection(db: &Database) -> Collection<Self> {
        db.collection("refresh_tokens")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        use mongodb::options::IndexOptions;

        let collection = Self::collection(db);
        collection
            .create_index(IndexModel::builder().keys(doc! { "userId": 1 }).build())
            .await?;
        collection
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "tokenHash": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        collection
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "expiresAt": 1 })
                    .options(
                        IndexOptions::builder()
                            .expire_after(std::time::Duration::from_secs(0))
                            .build(),
                    )
                    .build(),
            )
            .await?;
        Ok(())
    }

    pub async fn insert(db: &Database, token: &RefreshToken) -> mongodb::error::Result<()> {
        Self::collection(db).insert_one(token).await?;
        Ok(())
    }

    pub async fn find_by_hash(
        db: &Database,
        token_hash: &str,
    ) -> mongodb::error::Result<Option<Self>> {
        Self::collection(db)
            .find_one(doc! { "tokenHash": token_hash })
            .await
    }

    pub async fn revoke_by_id(db: &Database, id: ObjectId) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_one(
                doc! { "_id": id },
                doc! { "$set": { "revoked": true } },
            )
            .await?;
        Ok(())
    }

    pub async fn revoke_family(db: &Database, family_id: &str) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_many(
                doc! { "familyId": family_id },
                doc! { "$set": { "revoked": true } },
            )
            .await?;
        Ok(())
    }

    pub async fn revoke_all_for_user(
        db: &Database,
        user_id: ObjectId,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_many(
                doc! { "userId": user_id },
                doc! { "$set": { "revoked": true } },
            )
            .await?;
        Ok(())
    }

    pub async fn revoke_all_except_family(
        db: &Database,
        user_id: ObjectId,
        except_family_id: &str,
    ) -> mongodb::error::Result<u64> {
        let result = Self::collection(db)
            .update_many(
                doc! {
                    "userId": user_id,
                    "familyId": { "$ne": except_family_id },
                    "revoked": false,
                },
                doc! { "$set": { "revoked": true } },
            )
            .await?;
        Ok(result.modified_count)
    }

    pub async fn find_active_for_user(
        db: &Database,
        user_id: ObjectId,
    ) -> mongodb::error::Result<Vec<Self>> {
        use futures_util::TryStreamExt;

        let now = BsonDateTime::now();
        Self::collection(db)
            .find(doc! {
                "userId": user_id,
                "revoked": false,
                "expiresAt": { "$gt": now },
            })
            .sort(doc! { "lastUsedAt": -1, "createdAt": -1 })
            .await?
            .try_collect()
            .await
    }

    pub async fn family_belongs_to_user(
        db: &Database,
        user_id: ObjectId,
        family_id: &str,
    ) -> mongodb::error::Result<bool> {
        let count = Self::collection(db)
            .count_documents(doc! {
                "userId": user_id,
                "familyId": family_id,
            })
            .await?;
        Ok(count > 0)
    }

    pub async fn family_is_active(
        db: &Database,
        family_id: &str,
    ) -> mongodb::error::Result<bool> {
        let now = BsonDateTime::now();
        let count = Self::collection(db)
            .count_documents(doc! {
                "familyId": family_id,
                "revoked": false,
                "expiresAt": { "$gt": now },
            })
            .await?;
        Ok(count > 0)
    }

    pub async fn active_family_ids_for_user(
        db: &Database,
        user_id: ObjectId,
    ) -> mongodb::error::Result<Vec<String>> {
        use futures_util::TryStreamExt;

        let now = BsonDateTime::now();
        let tokens: Vec<Self> = Self::collection(db)
            .find(doc! {
                "userId": user_id,
                "revoked": false,
                "expiresAt": { "$gt": now },
            })
            .await?
            .try_collect()
            .await?;

        let mut families = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for token in tokens {
            if seen.insert(token.family_id.clone()) {
                families.push(token.family_id);
            }
        }
        Ok(families)
    }

    pub async fn active_family_ids_for_user_except(
        db: &Database,
        user_id: ObjectId,
        except_family_id: &str,
    ) -> mongodb::error::Result<Vec<String>> {
        use futures_util::TryStreamExt;

        let now = BsonDateTime::now();
        let tokens: Vec<Self> = Self::collection(db)
            .find(doc! {
                "userId": user_id,
                "familyId": { "$ne": except_family_id },
                "revoked": false,
                "expiresAt": { "$gt": now },
            })
            .await?
            .try_collect()
            .await?;

        let mut families = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for token in tokens {
            if seen.insert(token.family_id.clone()) {
                families.push(token.family_id);
            }
        }
        Ok(families)
    }

    pub fn bson_expiry(dt: DateTime<Utc>) -> BsonDateTime {
        BsonDateTime::from_millis(dt.timestamp_millis())
    }
}
