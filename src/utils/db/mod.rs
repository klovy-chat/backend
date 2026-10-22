// mod.rs
// Klient Mongo, init, indeksy userów, get_db().
// Zakres:
//  - jedna Database na proces
//  - klient Mongo, get_db(), indeksy userów przy init
// Nowy unikalny indeks: sync przy starcie, nie „przy okazji requestu”.
// Przy zmianach: main.rs, model/*.

use mongodb::{Client, Database};
use once_cell::sync::OnceCell;

static DB: OnceCell<Database> = OnceCell::new();

pub async fn init_db(uri: &str) -> mongodb::error::Result<()> {
    let mut options = mongodb::options::ClientOptions::parse(uri).await?;

    let max_pool = std::env::var("MONGO_MAX_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(50);
    options.max_pool_size = Some(max_pool);
    options.min_pool_size = Some(5);
    options.max_idle_time = Some(std::time::Duration::from_secs(300));
    options.server_selection_timeout = Some(std::time::Duration::from_secs(10));
    options.connect_timeout = Some(std::time::Duration::from_secs(45));

    let client = Client::with_options(options)?;

    let db = match client.default_database() {
        Some(db) => db,
        None => {
            let name = std::env::var("DB_NAME").unwrap_or_else(|_| "klovy".to_string());
            client.database(&name)
        }
    };

    db.run_command(mongodb::bson::doc! { "ping": 1 }).await?;

    let _ = DB.set(db);
    Ok(())
}

pub fn get_db() -> Database {
    DB.get()
        .expect("Database not initialized — call init_db() first")
        .clone()
}

async fn drop_stale_indexes(collection_name: &str, stale: &[&str]) -> mongodb::error::Result<()> {
    let db = get_db();
    let collection = db.collection::<mongodb::bson::Document>(collection_name);

    let mut cursor = match collection.list_indexes().await {
        Ok(c) => c,
        Err(_) => {
            log::info!("{collection_name} collection does not exist yet — skipping index cleanup");
            return Ok(());
        }
    };

    use futures::stream::StreamExt;
    let mut existing: Vec<String> = Vec::new();
    while let Some(item) = cursor.next().await {
        if let Ok(model) = item {
            if let Some(name) = model.options.and_then(|o| o.name) {
                existing.push(name);
            }
        }
    }

    for name in stale {
        if existing.iter().any(|n| n == name) {
            if let Err(e) = collection.drop_index((*name).to_string()).await {
                log::error!("Error dropping stale {collection_name} index {name}: {e}");
            } else {
                log::info!("Dropped stale {collection_name} index: {name}");
            }
        }
    }

    Ok(())
}

pub async fn sync_user_indexes() -> mongodb::error::Result<()> {
    drop_stale_indexes("users", &["email_1", "role_1", "e2eEnabled_1"]).await?;
    drop_stale_indexes(
        "messages",
        &[
            "e2eEncrypted_1",
            "e2eVersion_1",
            "e2eEncrypted_1_e2eVersion_1",
        ],
    )
    .await?;
    Ok(())
}
