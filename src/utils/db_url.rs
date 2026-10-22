// db_url.rs
// Odczyt DATABASE_URL.
// Zakres:
//  - Mongo connection string
//  - DATABASE_URL — też binarki migracji
// Bin migracji też tego używa.
// Przy zmianach: main.rs, encrypt_old_messages.rs.

use std::env;

pub fn database_url() -> Result<String, String> {
    for key in ["DATABASE_URL", "MONGODB_URI", "MONGO_URI"] {
        if let Ok(value) = env::var(key) {
            let value = value.trim().to_string();
            if !value.is_empty() {
                return Ok(value);
            }
        }
    }
    Err("Database URL is not configured (set DATABASE_URL, MONGODB_URI, or MONGO_URI)".to_string())
}
