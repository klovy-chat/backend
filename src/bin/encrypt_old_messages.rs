// encrypt_old_messages.rs
// CLI migracji: pieczętuje starą treść wiadomości w Mongo (--dry-run/--apply).
// Zakres:
//  - ten sam DATABASE_URL i klucz pola co serwer
//  - CLI --dry-run/--apply; ten sam DATABASE_URL i klucz pola
// Odpalaj po deploymencie kodu, który serwuje już sealed content.
// Przy zmianach: utils/messages/encrypt_old.rs, model/messages.rs.

use klovy_chat_server::utils::db;
use klovy_chat_server::utils::db_url::database_url;
use klovy_chat_server::utils::messages::encrypt_old::{
    migrate_message_content_seal, MigrateContentSealOptions,
};

#[tokio::main]
async fn main() {
    dotenvy::dotenv_override().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut dry_run = true;
    let mut batch_size = 200u32;
    let mut limit = None;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--apply" => dry_run = false,
            "--dry-run" => dry_run = true,
            "--help" | "-h" => {
                print_help();
                return;
            }
            _ if arg.starts_with("--batch-size=") => {
                batch_size = arg
                    .trim_start_matches("--batch-size=")
                    .parse()
                    .unwrap_or_else(|_| {
                        eprintln!("Invalid --batch-size value");
                        std::process::exit(1);
                    });
            }
            _ if arg.starts_with("--limit=") => {
                limit = Some(
                    arg.trim_start_matches("--limit=")
                        .parse()
                        .unwrap_or_else(|_| {
                            eprintln!("Invalid --limit value");
                            std::process::exit(1);
                        }),
                );
            }
            other => {
                eprintln!("Unknown argument: {other}");
                print_help();
                std::process::exit(1);
            }
        }
    }

    let database_url = database_url().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    db::init_db(&database_url).await.unwrap_or_else(|e| {
        eprintln!("Failed to connect to MongoDB: {e}");
        std::process::exit(1);
    });

    if dry_run {
        log::info!("DRY RUN — no writes. Pass --apply to update MongoDB.");
    } else {
        log::warn!("APPLY mode — message content will be sealed in MongoDB.");
    }

    let report = migrate_message_content_seal(
        &db::get_db(),
        MigrateContentSealOptions {
            dry_run,
            batch_size,
            limit,
        },
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("Migration failed: {e}");
        std::process::exit(1);
    });

    log::info!("Migration finished:");
    log::info!("  scanned: {}", report.scanned);
    log::info!("  migrated: {}", report.migrated);
    log::info!(
        "  skipped (already sealed): {}",
        report.skipped_already_sealed
    );
    log::info!("  skipped (not needed): {}", report.skipped_not_needed);
    log::info!("  skipped (empty): {}", report.skipped_empty);
    log::info!("  skipped (unchanged): {}", report.skipped_unchanged);
    log::info!(
        "  skipped (concurrent update): {}",
        report.skipped_concurrent_update
    );
    log::info!("  errors: {}", report.errors);

    if report.errors > 0 {
        std::process::exit(1);
    }
}

fn print_help() {
    eprintln!(
        "encrypt-old-messages — seal legacy message content in MongoDB\n\
         \n\
         Options:\n\
           --dry-run          Preview only (default)\n\
           --apply            Write sealed content to MongoDB\n\
           --batch-size=N     Cursor batch size (default 200)\n\
           --limit=N          Stop after scanning N candidates\n\
           -h, --help         Show this help\n\
         \n\
         Deploy the new backend first, then run with --apply once, then remove this binary."
    );
}
