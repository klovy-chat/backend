use klovy_chat_server::model::storage_usage::UserStorageUsage;
use klovy_chat_server::utils::db;
use klovy_chat_server::utils::db_url::database_url;

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

    if dry_run {
        log::info!(
            "DRY RUN — no writes. Pass --apply to merge duplicates and create the unique index."
        );
    } else {
        log::warn!("APPLY mode — duplicate storage usage records will be merged and indexed.");
    }

    let database = db::get_db();
    let report = UserStorageUsage::merge_duplicate_user_records(&database, dry_run)
        .await
        .unwrap_or_else(|error| {
            eprintln!("Storage usage migration failed: {error}");
            std::process::exit(1);
        });

    if !dry_run {
        UserStorageUsage::create_indexes(&database)
            .await
            .unwrap_or_else(|error| {
                eprintln!("Failed to create storage usage index: {error}");
                std::process::exit(1);
            });
    }

    log::info!("Storage usage migration finished:");
    log::info!("  users with duplicates: {}", report.users_merged);
    log::info!("  duplicate records merged: {}", report.records_merged);
}

fn print_help() {
    eprintln!(
        "migrate-storage-usage — merge duplicate per-user storage usage records\n\
         \n\
         Options:\n\
           --dry-run          Preview only; this is the default\n\
           --apply            Merge records and create the unique userId index\n\
           -h, --help         Show this help\n\
         \n\
         Run --apply while backend instances are stopped, before deploying the new version."
    );
}
