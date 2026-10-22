use std::collections::HashMap;

use futures_util::TryStreamExt;
use klovy_chat_server::model::friend_requests::FriendRequest;
use klovy_chat_server::utils::db;
use klovy_chat_server::utils::db_url::database_url;
use mongodb::bson::{doc, oid::ObjectId};

#[derive(Default)]
struct MigrationReport {
    updated: usize,
    already_current: usize,
    conflicts: Vec<(String, Vec<ObjectId>)>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv_override().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut dry_run = true;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--apply" => dry_run = false,
            "--help" | "-h" => {
                print_help();
                return;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                print_help();
                std::process::exit(1);
            }
        }
    }

    let database_url = database_url().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });
    db::init_db(&database_url).await.unwrap_or_else(|error| {
        eprintln!("Failed to connect to MongoDB: {error}");
        std::process::exit(1);
    });

    let database = db::get_db();
    let report = migrate(&database, dry_run).await.unwrap_or_else(|error| {
        eprintln!("Friend request pair migration failed: {error}");
        std::process::exit(1);
    });

    log::info!(
        "Friend request pair migration preview ({}):",
        if dry_run { "dry-run" } else { "apply" }
    );
    log::info!("  records requiring updates: {}", report.updated);
    log::info!("  records already current: {}", report.already_current);
    log::info!(
        "  ambiguous pairs left unchanged: {}",
        report.conflicts.len()
    );
    for (pair_key, ids) in &report.conflicts {
        log::error!(
            "  resolve duplicate pair {pair_key} manually; request IDs: {}",
            ids.iter()
                .map(|id| id.to_hex())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if !dry_run && !report.conflicts.is_empty() {
        eprintln!(
            "Migration aborted without writes because duplicate pairs need manual resolution."
        );
        std::process::exit(2);
    }

    if !dry_run {
        FriendRequest::create_pair_key_index(&database)
            .await
            .unwrap_or_else(|error| {
                eprintln!("Failed to create friend request pair index: {error}");
                std::process::exit(1);
            });
    }

    log::info!("Friend request pair migration finished.");
}

async fn migrate(
    database: &mongodb::Database,
    dry_run: bool,
) -> mongodb::error::Result<MigrationReport> {
    let collection = FriendRequest::collection(database);
    let cursor = collection.find(doc! {}).await?;
    let requests: Vec<FriendRequest> = cursor.try_collect().await?;
    let mut groups: HashMap<String, Vec<FriendRequest>> = HashMap::new();

    for request in requests {
        groups
            .entry(FriendRequest::pair_key(request.from, request.to))
            .or_default()
            .push(request);
    }

    let mut report = MigrationReport::default();
    let mut updates = Vec::new();
    for (pair_key, requests) in groups {
        if requests.len() > 1 {
            let ids = requests.iter().filter_map(|request| request.id).collect();
            report.conflicts.push((pair_key, ids));
            continue;
        }

        let request = &requests[0];
        if request.pair_key.as_deref() == Some(pair_key.as_str()) {
            report.already_current += 1;
            continue;
        }

        let id = request.id.ok_or_else(|| {
            mongodb::error::Error::custom("friend request document is missing its _id")
        })?;
        report.updated += 1;
        updates.push((id, pair_key));
    }

    if !dry_run && report.conflicts.is_empty() {
        for (id, pair_key) in updates {
            collection
                .update_one(doc! { "_id": id }, doc! { "$set": { "pairKey": pair_key } })
                .await?;
        }
    }

    Ok(report)
}

fn print_help() {
    eprintln!(
        "migrate-friend-request-pairs — backfill direction-independent pair keys\n\
         \n\
         Options:\n\
           --dry-run          Preview only; this is the default\n\
           --apply            Backfill unambiguous pairs and create the unique index\n\
           -h, --help         Show this help\n\
         \n\
         Ambiguous duplicate pairs are reported and left unchanged. Resolve them manually.\n\
         Run --apply while backend instances are stopped, before deploying the new version."
    );
}
