// registry.rs
// Mapa user → gniazda, fan-out, limit połączeń / IP.
// Zakres:
//  - cap pamięci przy wolnym kliencie
//  - user → gniazda, fan-out, cap / IP; broadcast best-effort
// Broadcast musi być best-effort — błąd jednego peera nie rollbackuje zapisu.
// Przy zmianach: ws/mod.rs, handlers.rs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::OnceCell;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::sync::mpsc::error::TrySendError;

use crate::model::channels::Channel;

pub type WsSender = mpsc::Sender<String>;

pub const WS_SEND_BUFFER: usize = 512;

static REGISTRY: OnceCell<ConnectionRegistry> = OnceCell::new();
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

struct Connection {
    id: u64,
    tx: WsSender,
    revoke: watch::Sender<bool>,
    session_family_id: Option<String>,
}

#[derive(Clone, Default)]
pub struct ConnectionRegistry {
    connections: Arc<Mutex<HashMap<String, Vec<Connection>>>>,
}

fn is_critical_event(msg_type: &str) -> bool {
    matches!(
        msg_type,
        "unread-updated"
            | "message-read"
            | "messages-read"
            | "message-deleted"
            | "message-edited"
            | "message-reaction"
            | "message-mention"
            | "receiveMessage"
            | "receive-channel-message"
            | "error"
            | "dm-error"
            | "friendship-removed"
            | "friendship-added"
            | "contact-block-updated"
            | "channel-added"
            | "channel-left"
            | "channel-deleted"
            | "channel-member-joined"
            | "channel-member-left"
            | "channel-avatar-updated"
            | "channel-name-updated"
            | "channel-slowmode-updated"
            | "channel-chat-locked-updated"
            | "channel-moderation-updated"
            | "conversation-deleted"
            | "session:revoked"
            | "user-status-changed"
            | "announcement:published"
    ) || msg_type.starts_with("call:")
        || msg_type.starts_with("channel-voice:")
}

async fn enqueue_frame(tx: &WsSender, msg: String, critical: bool) {
    match tx.try_send(msg) {
        Ok(()) => {}
        Err(TrySendError::Full(msg)) if critical => {
            let _ = tokio::time::timeout(Duration::from_millis(50), tx.send(msg)).await;
        }
        Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {}
    }
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(
        &self,
        user_id: &str,
        tx: WsSender,
        revoke: watch::Sender<bool>,
        session_family_id: Option<String>,
    ) -> u64 {
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        self.connections
            .lock()
            .await
            .entry(user_id.to_string())
            .or_default()
            .push(Connection {
                id,
                tx,
                revoke,
                session_family_id,
            });
        id
    }

    pub async fn unregister(&self, user_id: &str, conn_id: u64) {
        let mut map = self.connections.lock().await;
        if let Some(senders) = map.get_mut(user_id) {
            senders.retain(|c| c.id != conn_id);
            if senders.is_empty() {
                map.remove(user_id);
            }
        }
    }

    async fn send_to_family(&self, user_id: &str, family_id: &str, msg_type: &str, payload: Value) {
        let msg = match serde_json::to_string(&json!({ "type": msg_type, "payload": payload })) {
            Ok(s) => s,
            Err(_) => return,
        };
        let critical = is_critical_event(msg_type);
        let senders: Vec<WsSender> = self
            .connections
            .lock()
            .await
            .get(user_id)
            .map(|conns| {
                conns
                    .iter()
                    .filter(|c| c.session_family_id.as_deref() == Some(family_id))
                    .map(|c| c.tx.clone())
                    .collect()
            })
            .unwrap_or_default();
        for tx in senders {
            enqueue_frame(&tx, msg.clone(), critical).await;
        }
    }

    async fn send_prebuilt_to_user(&self, user_id: &str, msg: &str, critical: bool) {
        let senders: Vec<WsSender> = self
            .connections
            .lock()
            .await
            .get(user_id)
            .map(|conns| conns.iter().map(|c| c.tx.clone()).collect())
            .unwrap_or_default();
        for tx in senders {
            enqueue_frame(&tx, msg.to_string(), critical).await;
        }
    }

    async fn send_prebuilt_to_users(&self, user_ids: &[String], msg: Arc<String>, critical: bool) {
        let senders: Vec<WsSender> = {
            let map = self.connections.lock().await;
            let mut out = Vec::new();
            for uid in user_ids {
                if let Some(conns) = map.get(uid) {
                    out.extend(conns.iter().map(|c| c.tx.clone()));
                }
            }
            out
        };
        for tx in senders {
            enqueue_frame(&tx, (*msg).clone(), critical).await;
        }
    }

    pub async fn disconnect_family(&self, user_id: &str, family_id: &str) {
        let connections = {
            let mut map = self.connections.lock().await;
            let Some(conns) = map.get_mut(user_id) else {
                return;
            };
            let (to_revoke, remaining): (Vec<_>, Vec<_>) = conns
                .drain(..)
                .partition(|c| c.session_family_id.as_deref() == Some(family_id));
            *conns = remaining;
            if conns.is_empty() {
                map.remove(user_id);
            }
            to_revoke
        };
        for conn in connections {
            let _ = conn.revoke.send(true);
            drop(conn.tx);
        }
    }

    pub async fn disconnect_user(&self, user_id: &str) {
        let connections = {
            let mut map = self.connections.lock().await;
            map.remove(user_id).unwrap_or_default()
        };
        for conn in connections {
            let _ = conn.revoke.send(true);
            drop(conn.tx);
        }
    }

    pub async fn broadcast_to_all(&self, msg_type: &str, payload: Value) {
        let Ok(msg) = serde_json::to_string(&json!({ "type": msg_type, "payload": payload })) else {
            return;
        };
        let user_ids: Vec<String> = self.connections.lock().await.keys().cloned().collect();
        self.send_prebuilt_to_users(&user_ids, Arc::new(msg), is_critical_event(msg_type))
            .await;
    }
}

pub fn revoke_session_remotely(user_id: &str, family_id: &str) {
    let Some(reg) = registry() else {
        return;
    };
    let uid = user_id.to_string();
    let fid = family_id.to_string();
    let reg = reg.clone();
    tokio::spawn(async move {
        reg.send_to_family(&uid, &fid, "session:revoked", json!({}))
            .await;
        reg.disconnect_family(&uid, &fid).await;
    });
}

pub fn disconnect_user(user_id: &str) {
    let Some(reg) = registry() else {
        return;
    };
    let uid = user_id.to_string();
    let reg = reg.clone();
    tokio::spawn(async move {
        reg.disconnect_user(&uid).await;
    });
}

pub fn set_registry(registry: ConnectionRegistry) {
    let _ = REGISTRY.set(registry);
}

fn registry() -> Option<&'static ConnectionRegistry> {
    REGISTRY.get()
}

pub fn emit_to_user(user_id: &str, event: &str, data: impl Serialize + Send + Sync + 'static) {
    let Some(reg) = registry() else {
        return;
    };
    let uid = user_id.to_string();
    let Ok(msg) = serde_json::to_string(&json!({ "type": event, "payload": data })) else {
        return;
    };
    let critical = is_critical_event(event);
    let reg = reg.clone();
    tokio::spawn(async move {
        reg.send_prebuilt_to_user(&uid, &msg, critical).await;
    });
}

pub fn emit_to_users(user_ids: &[String], event: &str, data: Value) {
    if user_ids.is_empty() {
        return;
    }
    let Some(reg) = registry() else {
        return;
    };
    let Ok(msg) = serde_json::to_string(&json!({ "type": event, "payload": data })) else {
        return;
    };
    let msg = Arc::new(msg);
    let critical = is_critical_event(event);
    let ids = user_ids.to_vec();
    let reg = reg.clone();
    tokio::spawn(async move {
        reg.send_prebuilt_to_users(&ids, msg, critical).await;
    });
}

pub fn emit_to_all_connected(event: &str, data: impl Serialize + Send + Sync + 'static) {
    let Some(reg) = registry() else {
        return;
    };
    let Ok(payload) = serde_json::to_value(&data) else {
        return;
    };
    let event = event.to_string();
    let reg = reg.clone();
    tokio::spawn(async move {
        reg.broadcast_to_all(&event, payload).await;
    });
}

pub fn channel_recipient_ids(channel: &Channel) -> Vec<String> {
    let mut ids: Vec<String> = channel.members.iter().map(|m| m.to_hex()).collect();
    let admin = channel.admin.to_hex();
    if !ids.iter().any(|id| id == &admin) {
        ids.push(admin);
    }
    ids
}
