// state.rs
// Kolejki FIFO per gniazdo: chat, mark-read, typing, call (bez HOL-block).
// Zakres:
//  - jeden worker, nie dropuj sendera mid-job
//  - FIFO chat / mark-read / typing / call — bez HOL-block
// Nowy rodzaj ramki o innym SLA: nowa kolejka, nie wrzucaj typing na send FIFO.
// Przy zmianach: ws/handlers.rs, ws/registry.rs.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

#[derive(Clone, Default)]
pub struct RateLimitEntry {
    pub count: u32,
    pub reset_at_ms: i64,
}

type UserJob = Pin<Box<dyn Future<Output = ()> + Send>>;

struct FifoSlot {
    tx: mpsc::Sender<UserJob>,

    alive: Arc<AtomicBool>,

    busy: Arc<AtomicBool>,
    last_used_ms: i64,
}

#[derive(Clone, Default)]
pub struct SocketState {
    pub typing_users: Arc<StdMutex<HashMap<String, HashMap<String, i64>>>>,

    pub rate_limits: Arc<StdMutex<HashMap<String, HashMap<String, RateLimitEntry>>>>,
    pub connections: Arc<StdMutex<HashMap<String, u32>>>,
    pub ip_connections: Arc<StdMutex<HashMap<String, u32>>>,

    chat_fifo: Arc<StdMutex<HashMap<String, FifoSlot>>>,

    ack_fifo: Arc<StdMutex<HashMap<String, FifoSlot>>>,

    typing_fifo: Arc<StdMutex<HashMap<String, TypingSlot>>>,

    call_fifo: Arc<StdMutex<HashMap<String, FifoSlot>>>,

    auth_recheck_started: Arc<StdMutex<HashMap<String, i64>>>,
    typing_gc_counter: Arc<AtomicU32>,

    ws_total: Arc<AtomicU32>,
}

struct TypingJob {
    chat_id: String,
    is_typing: Option<bool>,
    job: UserJob,
}

struct TypingSlot {
    queue: std::collections::VecDeque<TypingJob>,

    running: bool,
    last_used_ms: i64,
}

const MAX_CONNECTIONS_PER_USER: u32 = 6;
const MAX_CONNECTIONS_PER_IP: u32 = 24;
const MAX_GLOBAL_WS_CONNECTIONS: u32 = 2048;
const CHAT_FIFO_CAP: usize = 128;
const ACK_FIFO_CAP: usize = 128;
const CALL_FIFO_CAP: usize = 64;
const TYPING_QUEUE_MAX: usize = 512;
const FIFO_IDLE_GC_MS: i64 = 60_000;

impl SocketState {
    pub fn new() -> Self {
        Self::default()
    }

    fn gc_fifo_map(
        map: &mut HashMap<String, FifoSlot>,
        connections: &StdMutex<HashMap<String, u32>>,
        now: i64,
    ) {
        let conn = connections.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|uid, slot| {
            if !slot.alive.load(Ordering::Acquire) {
                return false;
            }

            if slot.busy.load(Ordering::Acquire) {
                return true;
            }
            let connected = conn.get(uid).copied().unwrap_or(0) > 0;
            if connected {
                return true;
            }
            now.saturating_sub(slot.last_used_ms) < FIFO_IDLE_GC_MS
        });
    }

    fn fifo_enqueue(
        map: &StdMutex<HashMap<String, FifoSlot>>,
        connections: &StdMutex<HashMap<String, u32>>,
        user_id: &str,
        job: UserJob,
        cap: usize,
        label: &'static str,
    ) -> bool {
        let now = now_ms();
        let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
        Self::gc_fifo_map(&mut guard, connections, now);

        if let Some(slot) = guard.get_mut(user_id) {
            if slot.alive.load(Ordering::Acquire) {
                slot.last_used_ms = now;
                return match slot.tx.try_send(job) {
                    Ok(()) => true,
                    Err(mpsc::error::TrySendError::Full(_)) => false,
                    Err(mpsc::error::TrySendError::Closed(retry_job)) => {
                        guard.remove(user_id);
                        Self::fifo_spawn_locked(&mut guard, user_id, retry_job, cap, label, now)
                    }
                };
            }
            guard.remove(user_id);
        }

        Self::fifo_spawn_locked(&mut guard, user_id, job, cap, label, now)
    }

    fn fifo_spawn_locked(
        map: &mut HashMap<String, FifoSlot>,
        user_id: &str,
        job: UserJob,
        cap: usize,
        label: &'static str,
        now: i64,
    ) -> bool {
        let (tx, mut rx) = mpsc::channel::<UserJob>(cap);
        let alive = Arc::new(AtomicBool::new(true));
        let busy = Arc::new(AtomicBool::new(false));
        let alive_worker = alive.clone();
        let busy_worker = busy.clone();
        if tx.try_send(job).is_err() {
            return false;
        }
        map.insert(
            user_id.to_string(),
            FifoSlot {
                tx,
                alive,
                busy,
                last_used_ms: now,
            },
        );
        let uid = user_id.to_string();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                busy_worker.store(true, Ordering::Release);
                job.await;
                busy_worker.store(false, Ordering::Release);
            }
            alive_worker.store(false, Ordering::Release);
            log::warn!("{label} FIFO worker exited for {uid}");
        });
        true
    }

    pub fn spawn_user_ordered<F>(&self, user_id: impl Into<String>, fut: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let user_id = user_id.into();
        let job: UserJob = Box::pin(fut);
        Self::fifo_enqueue(
            &self.chat_fifo,
            &self.connections,
            &user_id,
            job,
            CHAT_FIFO_CAP,
            "chat",
        )
    }

    pub fn spawn_user_ack<F>(&self, user_id: impl Into<String>, fut: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let user_id = user_id.into();
        let job: UserJob = Box::pin(fut);
        Self::fifo_enqueue(
            &self.ack_fifo,
            &self.connections,
            &user_id,
            job,
            ACK_FIFO_CAP,
            "ack",
        )
    }

    pub fn spawn_user_realtime<F>(&self, user_id: impl Into<String>, fut: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let user_id = user_id.into();
        let job: UserJob = Box::pin(fut);
        Self::fifo_enqueue(
            &self.call_fifo,
            &self.connections,
            &user_id,
            job,
            CALL_FIFO_CAP,
            "call",
        )
    }

    pub fn spawn_user_ordered_eventually<F>(
        &self,
        user_id: impl Into<String>,
        chat_id: impl Into<String>,
        is_typing: Option<bool>,
        fut: F,
    ) where
        F: Future<Output = ()> + Send + 'static,
    {
        let user_id = user_id.into();
        let chat_id = chat_id.into();
        let job: UserJob = Box::pin(fut);
        let now = now_ms();
        let mut guard = self.typing_fifo.lock().unwrap_or_else(|e| e.into_inner());

        {
            let conn = self.connections.lock().unwrap_or_else(|e| e.into_inner());
            guard.retain(|uid, slot| {
                if slot.running || !slot.queue.is_empty() {
                    return true;
                }
                let connected = conn.get(uid).copied().unwrap_or(0) > 0;
                connected || now.saturating_sub(slot.last_used_ms) < FIFO_IDLE_GC_MS
            });
        }

        let slot = guard.entry(user_id.clone()).or_insert_with(|| TypingSlot {
            queue: std::collections::VecDeque::new(),
            running: false,
            last_used_ms: now,
        });
        slot.last_used_ms = now;

        if let Some(existing) = slot
            .queue
            .iter_mut()
            .find(|j| j.chat_id == chat_id && j.is_typing == is_typing)
        {
            existing.job = job;
        } else {
            slot.queue.retain(|j| j.chat_id != chat_id);
            if slot.queue.len() >= TYPING_QUEUE_MAX {
                slot.queue.pop_front();
            }
            slot.queue.push_back(TypingJob {
                chat_id,
                is_typing,
                job,
            });
        }
        if slot.running {
            return;
        }
        slot.running = true;
        let map = self.typing_fifo.clone();
        let uid = user_id;
        tokio::spawn(async move {
            loop {
                let next = {
                    let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
                    let Some(slot) = guard.get_mut(&uid) else {
                        return;
                    };
                    match slot.queue.pop_front() {
                        Some(entry) => entry.job,
                        None => {
                            slot.running = false;
                            return;
                        }
                    }
                };
                next.await;
            }
        });
    }

    pub fn check_rate_limit(
        &self,
        user_id: &str,
        action: &str,
        max_requests: u32,
        window_ms: i64,
    ) -> bool {
        let now = now_ms();
        let mut limits = self.rate_limits.lock().unwrap_or_else(|e| e.into_inner());
        static RL_GC: AtomicU32 = AtomicU32::new(0);
        if RL_GC.fetch_add(1, Ordering::Relaxed) % 64 == 0 {
            for user_map in limits.values_mut() {
                user_map.retain(|_, e| now <= e.reset_at_ms);
            }
            limits.retain(|_, user_map| !user_map.is_empty());
        }
        let user_limits = limits.entry(user_id.to_string()).or_default();
        let entry = user_limits
            .entry(action.to_string())
            .or_insert(RateLimitEntry {
                count: 0,
                reset_at_ms: now + window_ms,
            });

        if now > entry.reset_at_ms {
            entry.count = 0;
            entry.reset_at_ms = now + window_ms;
        }
        if entry.count >= max_requests {
            return false;
        }
        entry.count += 1;
        true
    }

    pub fn register_connection(&self, user_id: &str) -> Option<bool> {
        let mut map = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        let count = map.entry(user_id.to_string()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_USER {
            return None;
        }
        let first = *count == 0;
        *count += 1;
        Some(first)
    }

    pub fn can_accept_ip_connection(&self, ip: &str) -> bool {
        if self.ws_total.load(Ordering::Relaxed) >= MAX_GLOBAL_WS_CONNECTIONS {
            return false;
        }
        let map = self
            .ip_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.get(ip).copied().unwrap_or(0) < MAX_CONNECTIONS_PER_IP
    }

    pub fn register_ip_connection(&self, ip: &str) -> bool {
        loop {
            let current = self.ws_total.load(Ordering::Relaxed);
            if current >= MAX_GLOBAL_WS_CONNECTIONS {
                return false;
            }
            if self
                .ws_total
                .compare_exchange_weak(current, current + 1, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        let mut map = self
            .ip_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let count = map.entry(ip.to_string()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_IP {
            self.ws_total.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        *count += 1;
        true
    }

    pub fn unregister_ip_connection(&self, ip: &str) {
        let mut map = self
            .ip_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let removed = match map.get_mut(ip) {
            Some(count) if *count <= 1 => {
                map.remove(ip);
                true
            }
            Some(count) => {
                *count -= 1;
                true
            }
            None => false,
        };
        if removed {
            self.ws_total.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub fn unregister_connection(&self, user_id: &str) {
        let mut map = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(user_id) {
            if *count <= 1 {
                map.remove(user_id);
            } else {
                *count -= 1;
            }
        }
    }

    pub fn is_user_connected(&self, user_id: &str) -> bool {
        self.connection_count(user_id) > 0
    }

    pub fn connection_count(&self, user_id: &str) -> u32 {
        self.connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(user_id)
            .copied()
            .unwrap_or(0)
    }

    pub fn touch_typing(&self, chat_id: &str, user_id: &str, is_typing: bool) {
        let now = now_ms();
        let mut typing = self.typing_users.lock().unwrap_or_else(|e| e.into_inner());

        let should_gc = self.typing_gc_counter.fetch_add(1, Ordering::Relaxed) % 32 == 0;
        if should_gc {
            typing.retain(|_, users| {
                users.retain(|_, last_ms| now.saturating_sub(*last_ms) < 8_000);
                !users.is_empty()
            });
        } else if let Some(users) = typing.get_mut(chat_id) {
            users.retain(|_, last_ms| now.saturating_sub(*last_ms) < 8_000);
        }

        let chat = typing.entry(chat_id.to_string()).or_default();
        if is_typing {
            chat.insert(user_id.to_string(), now);
        } else {
            chat.remove(user_id);
            if chat.is_empty() {
                typing.remove(chat_id);
            }
        }
    }

    pub fn try_begin_auth_recheck(&self, user_id: &str, interval_ms: i64) -> bool {
        let now = now_ms();
        let mut map = self
            .auth_recheck_started
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(last) = map.get(user_id) {
            if now.saturating_sub(*last) < interval_ms {
                return false;
            }
        }
        map.insert(user_id.to_string(), now);
        true
    }

    pub fn clear_user_state(&self, user_id: &str) {
        self.auth_recheck_started
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(user_id);
        self.rate_limits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(user_id);

        crate::ws::typing::clear_user(user_id);
        crate::utils::access::cache::clear_user(user_id);
        crate::utils::friends::cache::invalidate_block_pair_for_user(user_id);
        let mut typing = self.typing_users.lock().unwrap_or_else(|e| e.into_inner());
        for users in typing.values_mut() {
            users.remove(user_id);
        }
        typing.retain(|_, users| !users.is_empty());
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn is_valid_object_id(s: &str) -> bool {
    s.len() == 24 && s.chars().all(|c| c.is_ascii_hexdigit())
}
