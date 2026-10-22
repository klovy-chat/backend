// audit.rs
// Wpis audytu (aktor, akcja, cel).
// Zakres:
//  - ślady wrażliwych operacji
//  - aktor, akcja, cel — pisz po udanej mutacji
// Pisz po udanej mutacji, nie przed (inaczej fałszywy ślad).
// Przy zmianach: utils/admin/mod.rs.

use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub action: String,
    #[serde(rename = "targetType", skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    #[serde(rename = "targetId", skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default)]
    pub details: Value,
    #[serde(rename = "clientIp", skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(rename = "actorUserId", skip_serializing_if = "Option::is_none")]
    pub actor_user_id: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime,
}

impl AuditLog {
    fn collection(db: &Database) -> Collection<Self> {
        db.collection("audit_logs")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        Self::collection(db)
            .create_index(IndexModel::builder().keys(doc! { "createdAt": -1 }).build())
            .await?;
        Self::collection(db)
            .create_index(IndexModel::builder().keys(doc! { "action": 1 }).build())
            .await?;
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "actorUserId": 1 })
                    .build(),
            )
            .await?;
        Ok(())
    }

    pub async fn insert(
        db: &Database,
        action: &str,
        target_type: Option<&str>,
        target_id: Option<&str>,
        details: Value,
        client_ip: Option<&str>,
        actor_user_id: Option<&str>,
    ) -> mongodb::error::Result<()> {
        let entry = AuditLog {
            id: None,
            action: action.to_string(),
            target_type: target_type.map(str::to_string),
            target_id: target_id.map(str::to_string),
            details,
            client_ip: client_ip.map(str::to_string),
            actor_user_id: actor_user_id.map(str::to_string),
            created_at: DateTime::now(),
        };
        Self::collection(db).insert_one(entry).await?;
        Ok(())
    }
}
