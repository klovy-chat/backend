// mod.rs
// Składanie scope /api z plików tematycznych.
// Zakres:
//  - auth, channels, messages, ws nie tutaj tylko upgrade
//  - składanie /api; WS upgrade nie tutaj
// Nowa ścieżka publiczna vs z auth: patrz wrap w danym routes/*.rs.
// Przy zmianach: loaders/server.rs, middlewares/auth.rs.

pub mod auth;
pub mod channels;
pub mod contacts;
pub mod emojis;
pub mod friends;
pub mod gifs;
pub mod invites;
pub mod messages;
pub mod status;
pub mod stickers;
pub mod users;
pub mod voice;
