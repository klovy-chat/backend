// reports.rs
// Zgłoszenie treści/kanału.
// Zakres:
//  - reporter, powód, target
//  - zgłoszenie treści/kanału; reporter nie wychodzi publicznym API
// Nie zwracaj reportera innym userom w publicznym API.
// Przy zmianach: controllers/channels.rs.

use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelReportStatus {
    Pending,
    Reviewed,
    Dismissed,
}

impl Default for ChannelReportStatus {
    fn default() -> Self {
        Self::Pending
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelReport {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "channelId")]
    pub channel_id: ObjectId,

    #[serde(rename = "channelName")]
    pub channel_name: String,

    #[serde(rename = "reportedBy")]
    pub reported_by: ObjectId,

    #[serde(rename = "reporterUsername")]
    pub reporter_username: String,

    pub reason: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    #[serde(default)]
    pub status: ChannelReportStatus,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "reviewedAt", skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<DateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateChannelReportInput {
    pub channel_id: ObjectId,
    pub channel_name: String,
    pub reported_by: ObjectId,
    pub reporter_username: String,
    pub reason: String,
    pub details: Option<String>,
}

#[derive(Debug)]
pub enum ChannelReportValidationError {
    ReasonRequired,
    ReasonTooLong,
    DetailsTooLong,
}

impl std::fmt::Display for ChannelReportValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::ReasonRequired => "Powód jest wymagany",
            Self::ReasonTooLong => "Powód nie może przekraczać 200 znaków",
            Self::DetailsTooLong => "Opis nie może przekraczać 2000 znaków",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for ChannelReportValidationError {}

pub fn validate_channel_report(
    input: &CreateChannelReportInput,
) -> Result<(), ChannelReportValidationError> {
    if input.reason.trim().is_empty() {
        return Err(ChannelReportValidationError::ReasonRequired);
    }
    if input.reason.trim().len() > 200 {
        return Err(ChannelReportValidationError::ReasonTooLong);
    }
    if let Some(d) = &input.details {
        if d.trim().len() > 2000 {
            return Err(ChannelReportValidationError::DetailsTooLong);
        }
    }
    Ok(())
}

impl ChannelReport {
    pub fn collection(db: &Database) -> Collection<ChannelReport> {
        db.collection("channelreports")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let col = Self::collection(db);

        col.create_index(IndexModel::builder().keys(doc! { "channelId": 1 }).build())
            .await?;

        col.create_index(IndexModel::builder().keys(doc! { "status": 1 }).build())
            .await?;

        col.create_index(
            IndexModel::builder()
                .keys(doc! { "status": 1, "createdAt": -1 })
                .build(),
        )
        .await?;

        Ok(())
    }

    pub async fn create(
        db: &Database,
        input: CreateChannelReportInput,
    ) -> Result<ChannelReport, Box<dyn std::error::Error>> {
        validate_channel_report(&input)?;

        let report = ChannelReport {
            id: None,
            channel_id: input.channel_id,
            channel_name: input.channel_name.trim().to_string(),
            reported_by: input.reported_by,
            reporter_username: input.reporter_username.trim().to_string(),
            reason: input.reason.trim().to_string(),
            details: input
                .details
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty()),
            status: ChannelReportStatus::Pending,
            created_at: DateTime::now(),
            reviewed_at: None,
        };

        let result = Self::collection(db).insert_one(&report).await?;
        let id = result.inserted_id.as_object_id();

        Ok(ChannelReport { id, ..report })
    }
}
