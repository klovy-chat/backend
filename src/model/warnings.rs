// warnings.rs
// Ostrzeżenie na konto (treść, przeczytane).
// Zakres:
//  - baner FE
//  - ostrzeżenie na konto; acknowledge = wszystkie nieprzeczytane
// Acknowledge = wszystkie nieprzeczytane, nie pojedyncze id (tak działa Panel).
// Przy zmianach: controllers/auth.rs, Warning.tsx.

use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WarningSeverity {
    Low,
    Medium,
    High,
}

impl Default for WarningSeverity {
    fn default() -> Self {
        parse_severity(None)
    }
}

pub fn severity_str(severity: &WarningSeverity) -> &'static str {
    match severity {
        WarningSeverity::Low => "low",
        WarningSeverity::Medium => "medium",
        WarningSeverity::High => "high",
    }
}

pub fn parse_severity(value: Option<&str>) -> WarningSeverity {
    match value.map(|s| s.trim().to_lowercase()).as_deref() {
        Some("low") => WarningSeverity::Low,
        Some("high") => WarningSeverity::High,
        _ => WarningSeverity::Medium,
    }
}

pub const WARNING_REASON_MAX_LENGTH: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warning {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "userId")]
    pub user_id: ObjectId,

    pub reason: String,

    #[serde(default)]
    pub severity: WarningSeverity,

    #[serde(rename = "issuedBy", default = "default_issued_by")]
    pub issued_by: String,

    #[serde(default)]
    pub acknowledged: bool,

    #[serde(rename = "acknowledgedAt", skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<DateTime>,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,
}

fn default_issued_by() -> String {
    "admin".to_string()
}

pub struct CreateWarningInput {
    pub user_id: ObjectId,
    pub reason: String,
    pub severity: WarningSeverity,
}

impl Warning {
    pub fn collection(db: &Database) -> Collection<Warning> {
        db.collection("warnings")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let col = Self::collection(db);

        col.create_index(
            IndexModel::builder()
                .keys(doc! { "userId": 1, "createdAt": -1 })
                .build(),
        )
        .await?;

        col.create_index(
            IndexModel::builder()
                .keys(doc! { "userId": 1, "acknowledged": 1 })
                .build(),
        )
        .await?;

        Ok(())
    }

    pub async fn create(
        db: &Database,
        input: CreateWarningInput,
    ) -> mongodb::error::Result<Warning> {
        let reason = input
            .reason
            .trim()
            .chars()
            .take(WARNING_REASON_MAX_LENGTH)
            .collect::<String>();

        let warning = Warning {
            id: None,
            user_id: input.user_id,
            reason,
            severity: parse_severity(Some(severity_str(&input.severity))),
            issued_by: default_issued_by(),
            acknowledged: false,
            acknowledged_at: None,
            created_at: DateTime::now(),
        };

        let result = Self::collection(db).insert_one(&warning).await?;
        let id = result.inserted_id.as_object_id();

        Ok(Warning { id, ..warning })
    }

    pub async fn find_by_id(
        db: &Database,
        id: ObjectId,
    ) -> mongodb::error::Result<Option<Warning>> {
        Self::collection(db).find_one(doc! { "_id": id }).await
    }

    pub async fn list_for_user(
        db: &Database,
        user_id: ObjectId,
    ) -> mongodb::error::Result<Vec<Warning>> {
        use futures_util::TryStreamExt;
        Self::collection(db)
            .find(doc! { "userId": user_id })
            .sort(doc! { "createdAt": -1 })
            .limit(200)
            .await?
            .try_collect()
            .await
    }

    pub async fn count_for_user(db: &Database, user_id: ObjectId) -> mongodb::error::Result<u64> {
        Self::collection(db)
            .count_documents(doc! { "userId": user_id })
            .await
    }

    pub async fn acknowledge_all_for_user(
        db: &Database,
        user_id: ObjectId,
    ) -> mongodb::error::Result<u64> {
        let result = Self::collection(db)
            .update_many(
                doc! { "userId": user_id, "acknowledged": false },
                doc! { "$set": { "acknowledged": true, "acknowledgedAt": DateTime::now() } },
            )
            .await?;
        Ok(result.modified_count)
    }

    pub async fn delete_one(
        db: &Database,
        id: ObjectId,
        user_id: ObjectId,
    ) -> mongodb::error::Result<bool> {
        let result = Self::collection(db)
            .delete_one(doc! { "_id": id, "userId": user_id })
            .await?;
        Ok(result.deleted_count > 0)
    }
}
