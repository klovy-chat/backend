// main.rs
// Proces serwera: dotenv, logi, Mongo, R2, indeksy, bind HTTP.
// Zakres:
//  - Axum publiczny + Actix wewnętrzny z loaders/server.rs
//  - dotenv, logi, Mongo, R2, indeksy, bind; nowy model = indeks tutaj albo w db::
// Nowy model Mongo: dopisz sync/index tutaj albo w db::, inaczej unikaty nie wstaną.
// Przy zmianach: loaders/server.rs, utils/config.rs, utils/db/mod.rs.

use klovy_chat_server::loaders::server;
use klovy_chat_server::utils::env::is_production;
use klovy_chat_server::model::{
    announcements::Announcement, audit::AuditLog, channels::Channel,
    read_state::ChannelReadState, reports::ChannelReport,
    friend_requests::FriendRequest, invites::Invite,
    messages::Message, uploads::PendingUpload, scan_cache::ScanVerdict,
    refresh_tokens::RefreshToken, users::User, storage_usage::UserStorageUsage,
    warnings::Warning,
};
use klovy_chat_server::utils::db_url::database_url;
use klovy_chat_server::utils::db;
use klovy_chat_server::utils::storage::reconcile_attachments;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv_override().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let database_url = database_url().expect("Database URL is not configured");

    db::init_db(&database_url)
        .await
        .expect("Failed to connect to MongoDB");

    db::sync_user_indexes().await.ok();

    klovy_chat_server::utils::config::validate_startup_config();

    klovy_chat_server::utils::storage::init_storage().unwrap_or_else(|e| {
        panic!(
            "Failed to initialize R2 storage: {e}\n\
             Configure R2_* variables in backend/.env — see backend/docs/R2_SETUP.md"
        )
    });
    klovy_chat_server::utils::scan::spawn_worker();

    let mongodb_db = db::get_db();
    ensure_indexes(&mongodb_db).await;
    klovy_chat_server::utils::scan::requeue_pending().await;

    {
        let db = mongodb_db.clone();
        tokio::spawn(async move {
            match klovy_chat_server::utils::messages::search::backfill_message_search_text(&db)
                .await
            {
                Ok(n) if n > 0 => log::info!("Startup: backfilled searchText on {n} message(s)"),
                Err(e) => log::warn!("Startup searchText backfill failed: {e}"),
                _ => {}
            }
        });
    }

    match PendingUpload::cleanup_orphans(&mongodb_db).await {
        Ok(removed) if removed > 0 => {
            log::info!("Cleaned up {removed} orphaned pending uploads at startup");
        }
        Err(e) => log::warn!("Pending upload cleanup failed: {e}"),
        _ => {}
    }

    match klovy_chat_server::utils::admin::repair_broken_account_status_fields(&mongodb_db).await {
        Ok(repaired) if repaired > 0 => {
            log::info!("Startup: repaired {repaired} user account(s) with invalid isDisabled=null");
        }
        Err(e) => log::warn!("Startup account status repair failed: {e}"),
        _ => {}
    }

    match klovy_chat_server::utils::admin::purge_removed_schema_fields(&mongodb_db).await {
        Ok(report)
            if report.users_modified > 0
                || report.messages_modified > 0
                || report.e2e_keys_dropped =>
        {
            log::info!(
                "Startup schema purge: unset fields on {} user(s), {} message(s); e2e_keys dropped={}",
                report.users_modified,
                report.messages_modified,
                report.e2e_keys_dropped
            );
        }
        Err(e) => log::warn!("Startup schema purge failed: {e}"),
        _ => {}
    }

    match klovy_chat_server::utils::admin::process_scheduled_deletions(&mongodb_db).await {
        Ok(deleted) if deleted > 0 => {
            log::info!("Startup: auto-deleted {deleted} scheduled user account(s)");
        }
        Err(e) => log::warn!("Startup scheduled account deletion failed: {e}"),
        _ => {}
    }

    tokio::spawn(async {
        let interval = std::time::Duration::from_secs(6 * 60 * 60);
        loop {
            tokio::time::sleep(interval).await;
            let db = klovy_chat_server::utils::db::get_db();
            match PendingUpload::cleanup_orphans(&db).await {
                Ok(removed) if removed > 0 => {
                    log::info!("Periodic cleanup removed {removed} orphaned pending uploads");
                }
                Err(e) => log::warn!("Periodic pending upload cleanup failed: {e}"),
                _ => {}
            }
        }
    });

    tokio::spawn(async {
        let interval = std::time::Duration::from_secs(60 * 60);
        loop {
            tokio::time::sleep(interval).await;
            let db = klovy_chat_server::utils::db::get_db();
            match klovy_chat_server::utils::admin::process_scheduled_deletions(&db).await {
                Ok(deleted) if deleted > 0 => {
                    log::info!("Auto-deleted {deleted} scheduled user account(s)");
                }
                Err(e) => log::warn!("Scheduled account deletion job failed: {e}"),
                _ => {}
            }
        }
    });

    tokio::spawn(async {
        let interval = std::time::Duration::from_secs(15);
        loop {
            tokio::time::sleep(interval).await;
            klovy_chat_server::ws::handlers::sweep_expired_call_sessions().await;
        }
    });

    tokio::spawn(async {
        let interval = std::time::Duration::from_secs(24 * 60 * 60);
        loop {
            tokio::time::sleep(interval).await;
            let db = klovy_chat_server::utils::db::get_db();
            match reconcile_attachments(&db).await {
                Ok(report) if report.orphan_objects_deleted > 0 || report.missing_objects > 0 => {
                    log::info!(
                        "Attachment reconcile: deleted {} orphan R2 objects, {} missing in R2, {} usage records updated",
                        report.orphan_objects_deleted,
                        report.missing_objects,
                        report.usage_users_updated
                    );
                }
                Ok(report) if report.usage_users_updated > 0 => {
                    log::info!(
                        "Attachment reconcile: rebuilt storage usage for {} users",
                        report.usage_users_updated
                    );
                }
                Err(e) => log::warn!("Attachment reconcile failed: {e}"),
                _ => {}
            }
        }
    });

    match reconcile_attachments(&mongodb_db).await {
        Ok(report) => log::info!(
            "Startup attachment reconcile: deleted {} orphan R2 objects, {} missing in R2, {} usage records updated",
            report.orphan_objects_deleted,
            report.missing_objects,
            report.usage_users_updated
        ),
        Err(e) => log::warn!("Startup attachment reconcile failed: {e}"),
    }

    log::info!("Klovy Chat server startup");
    server::run_server().await
}

async fn ensure_indexes(db: &mongodb::Database) {
    let tasks: [(&str, mongodb::error::Result<()>); 16] = [
        ("users", User::create_indexes(db).await),
        ("signup_quotas", klovy_chat_server::utils::registration::create_indexes(db).await),
        ("channels", Channel::create_indexes(db).await),
        ("messages", Message::create_indexes(db).await),
        ("friend_requests", FriendRequest::create_indexes(db).await),
        ("invites", Invite::create_indexes(db).await),
        ("channel_read_states", ChannelReadState::create_indexes(db).await),
        ("dm_conversation_tips", klovy_chat_server::utils::tips::DmConversationTip::create_indexes(db).await),
        ("channel_reports", ChannelReport::create_indexes(db).await),
        ("refresh_tokens", RefreshToken::create_indexes(db).await),
        ("pending_uploads", PendingUpload::create_indexes(db).await),
        ("attachment_scan_cache", ScanVerdict::create_indexes(db).await),
        ("user_storage_usage", UserStorageUsage::create_indexes(db).await),
        ("audit_logs", AuditLog::create_indexes(db).await),
        ("warnings", Warning::create_indexes(db).await),
        ("announcements", Announcement::create_indexes(db).await),
    ];

    for (name, result) in tasks {
        if let Err(error) = result {
            log::error!("Failed to create MongoDB indexes for {name}: {error}");
            if is_production() {
                panic!("MongoDB index creation failed for {name}: {error}");
            }
        }
    }
}
