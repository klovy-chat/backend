// ip_block.rs
// Tymczasowe bany IP po floodzie / failed auth.
// Zakres:
//  - track_suspicious_activity
//  - tymczasowe bany po floodzie / failed auth
// Nie banuj całych NAT bez progu — strojenie w tym pliku.
// Przy zmianach: utils/security/monitor.rs, loaders/server.rs.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpResponse,
};
use actix_web_lab::middleware::Next;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::time::sleep;

use crate::utils::ip::client_ip_from_service_request;
use crate::utils::security::monitor::{SecurityEventType, SecurityMonitor};

#[derive(Debug, Clone)]
struct SuspiciousActivity {
    count: u32,
    last_activity: Instant,
}

pub struct IPBlockerArc {
    blocked_ips: Arc<Mutex<HashSet<String>>>,
    suspicious_activity: Mutex<HashMap<String, SuspiciousActivity>>,
    max_suspicious_activity: u32,
    block_duration: Duration,
}

impl IPBlockerArc {
    pub fn new() -> Self {
        Self {
            blocked_ips: Arc::new(Mutex::new(HashSet::new())),
            suspicious_activity: Mutex::new(HashMap::new()),
            max_suspicious_activity: 30,
            block_duration: Duration::from_secs(30 * 60),
        }
    }

    pub fn is_blocked(&self, ip: &str) -> bool {
        self.blocked_ips
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(ip)
    }

    pub fn add_suspicious_activity(&self, ip: &str) {
        let now = Instant::now();
        let block_duration = self.block_duration;

        let should_block = {
            let mut map = self
                .suspicious_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if map.len() >= 20_000 {
                map.retain(|_, entry| now.duration_since(entry.last_activity) <= block_duration);
            }
            let entry = map.entry(ip.to_string()).or_insert(SuspiciousActivity {
                count: 0,
                last_activity: now,
            });

            if now.duration_since(entry.last_activity) > block_duration {
                entry.count = 0;
            }

            entry.count += 1;
            entry.last_activity = now;
            entry.count >= self.max_suspicious_activity
        };

        if should_block {
            if !self.is_blocked(ip) {
                self.block_ip_arc(ip, None);
                log::warn!("IP {} blocked due to suspicious activity", ip);
            }
        }
    }

    pub fn block_ip_arc(&self, ip: &str, duration: Option<Duration>) {
        let duration = duration.unwrap_or(self.block_duration);
        let ip_owned = ip.to_string();
        let blocked_arc = Arc::clone(&self.blocked_ips);

        {
            let mut set = self.blocked_ips.lock().unwrap_or_else(|e| e.into_inner());
            if set.len() >= 10_000 && !set.contains(&ip_owned) {
                return;
            }
            set.insert(ip_owned.clone());
        }

        tokio::spawn(async move {
            sleep(duration).await;
            blocked_arc
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&ip_owned);
            log::info!("IP {} unblocked (timer expired)", ip_owned);
        });
    }
}

pub async fn ip_blocker_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let ip = client_ip_from_service_request(&req);

    let blocker = req
        .app_data::<actix_web::web::Data<IPBlockerArc>>()
        .cloned();

    if let Some(blocker) = blocker {
        if blocker.is_blocked(&ip) {
            if let Some(monitor) = req.app_data::<actix_web::web::Data<SecurityMonitor>>() {
                monitor.log_event(
                    SecurityEventType::BlockedRequests,
                    serde_json::json!({ "ip": ip }),
                );
            }
            log::warn!("Blocked IP {} attempted access", ip);
            let (req, _) = req.into_parts();
            let res = HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied",
                "message": "Your IP has been temporarily blocked due to suspicious activity",
            }));
            return Ok(ServiceResponse::new(req, res));
        }
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}

pub async fn track_suspicious_activity(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let ip = client_ip_from_service_request(&req);
    let url = req.uri().path().to_string();
    let user_agent = req
        .headers()
        .get(actix_web::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let query_count = req
        .query_string()
        .split('&')
        .filter(|s| !s.is_empty())
        .count();

    let is_suspicious = url.contains("..")
        || url.contains("<script")
        || crate::utils::security::bots::is_known_bot_user_agent(&user_agent)
        || query_count > 50;

    if is_suspicious {
        let blocker = req
            .app_data::<actix_web::web::Data<IPBlockerArc>>()
            .cloned();
        let monitor = req
            .app_data::<actix_web::web::Data<SecurityMonitor>>()
            .cloned();

        if let Some(monitor) = monitor {
            monitor.log_event(
                SecurityEventType::SuspiciousRequests,
                serde_json::json!({
                    "ip": ip,
                    "url": url,
                    "userAgent": user_agent,
                }),
            );
        }

        if let Some(blocker) = blocker {
            blocker.add_suspicious_activity(&ip);
        }
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}
