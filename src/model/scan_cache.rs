// scan_cache.rs
// Werdykt ClamAV po SHA-256 pliku (clean/blocked).
// Zakres:
//  - ten sam hash = bez ponownego skanu
//  - nie cache'uj pending, błędów sieci ani clean bez clamd
// TTL 30 dni. Przy zmianach: utils/scan/, uploads.rs.

use mongodb::bson::{doc, DateTime};
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};

use super::scan::ScanStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanVerdict {
    #[serde(rename = "_id")]
    pub hash: String,
    pub verdict: ScanStatus,
    #[serde(rename = "scannedAt")]
    pub scanned_at: DateTime,
    #[serde(rename = "viaClamd", default)]
    pub via_clamd: bool,
}

impl ScanVerdict {
    pub fn collection(db: &Database) -> Collection<Self> {
        db.collection("attachment_scan_cache")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        use mongodb::options::IndexOptions;

        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "scannedAt": 1 })
                    .options(
                        IndexOptions::builder()
                            .expire_after(std::time::Duration::from_secs(30 * 24 * 60 * 60))
                            .build(),
                    )
                    .build(),
            )
            .await?;
        Ok(())
    }

    pub async fn get(db: &Database, hash: &str) -> mongodb::error::Result<Option<ScanStatus>> {
        if hash.is_empty() {
            return Ok(None);
        }
        let doc = Self::collection(db).find_one(doc! { "_id": hash }).await?;
        Ok(doc.and_then(|row| match row.verdict {
            ScanStatus::Blocked => Some(ScanStatus::Blocked),
            ScanStatus::Clean if row.via_clamd => Some(ScanStatus::Clean),
            _ => None,
        }))
    }

    pub async fn put(
        db: &Database,
        hash: &str,
        verdict: ScanStatus,
        via_clamd: bool,
    ) -> mongodb::error::Result<()> {
        if hash.is_empty() || matches!(verdict, ScanStatus::Pending) {
            return Ok(());
        }
        if matches!(verdict, ScanStatus::Clean) && !via_clamd {
            return Ok(());
        }
        Self::collection(db)
            .update_one(
                doc! { "_id": hash },
                doc! {
                    "$set": {
                        "verdict": verdict.as_str(),
                        "scannedAt": DateTime::now(),
                        "viaClamd": via_clamd,
                    }
                },
            )
            .upsert(true)
            .await?;
        Ok(())
    }
}
