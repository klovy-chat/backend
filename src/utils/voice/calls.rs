// calls.rs
// Sesja DM: ringing TTL, accept, missed log duration 0.
// Zakres:
//  - CALL_* fan-out
//  - DM ringing TTL, accept, missed duration 0, CALL_* fan-out
// Timeout = hangup nawet gdy Mongo friendship miss.
// Przy zmianach: handlers.rs call, CallContext.tsx, hangup.ts.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use uuid::Uuid;

const RINGING_TTL: Duration = Duration::from_secs(60);

const ACCEPTED_TTL: Duration = Duration::from_secs(4 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPhase {
    Ringing,
    Accepted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSession {
    pub session_id: String,
    pub caller_id: String,
    pub callee_id: String,
    pub mode: String,
    pub phase: CallPhase,
    pub created_at: Instant,
    pub accepted_at: Option<Instant>,

    pub caller_conn_id: Option<u64>,

    pub callee_conn_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallSessionError {
    NotFound,
    WrongRole,
    InvalidPhase,
    InProgress,

    Expired(CallSession),
}

fn pair_key(a: &str, b: &str) -> String {
    let mut ids = [a, b];
    ids.sort();
    format!("{}:{}", ids[0], ids[1])
}

static SESSIONS: LazyLock<Mutex<HashMap<String, CallSession>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn is_accepted_stale(session: &CallSession) -> bool {
    let started = session.accepted_at.unwrap_or(session.created_at);
    started.elapsed() >= ACCEPTED_TTL
}

fn take_stale_locked(sessions: &mut HashMap<String, CallSession>) -> Vec<CallSession> {
    let mut stale = Vec::new();
    sessions.retain(|_, session| match session.phase {
        CallPhase::Ringing if session.created_at.elapsed() >= RINGING_TTL => {
            stale.push(session.clone());
            false
        }
        CallPhase::Accepted if is_accepted_stale(session) => {
            stale.push(session.clone());
            false
        }
        _ => true,
    });
    stale
}

pub fn drain_expired_sessions() -> Vec<CallSession> {
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    take_stale_locked(&mut sessions)
}

pub fn create_ringing_session(
    caller_id: &str,
    callee_id: &str,
    mode: &str,
    caller_conn_id: u64,
) -> Result<(String, Option<CallSession>), CallSessionError> {
    let key = pair_key(caller_id, callee_id);
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());

    let mut replaced_expired = None;
    if let Some(existing) = sessions.get(&key) {
        let active = match existing.phase {
            CallPhase::Ringing => existing.created_at.elapsed() < RINGING_TTL,
            CallPhase::Accepted => !is_accepted_stale(existing),
        };
        if active {
            return Err(CallSessionError::InProgress);
        }
        replaced_expired = sessions.remove(&key);
    }

    if user_has_active_session_locked(&sessions, caller_id)
        || user_has_active_session_locked(&sessions, callee_id)
    {
        return Err(CallSessionError::InProgress);
    }

    let session_id = Uuid::new_v4().to_string();
    sessions.insert(
        key,
        CallSession {
            session_id: session_id.clone(),
            caller_id: caller_id.to_string(),
            callee_id: callee_id.to_string(),
            mode: mode.to_string(),
            phase: CallPhase::Ringing,
            created_at: Instant::now(),
            accepted_at: None,
            caller_conn_id: Some(caller_conn_id),
            callee_conn_id: None,
        },
    );
    Ok((session_id, replaced_expired))
}

fn user_has_active_session_locked(sessions: &HashMap<String, CallSession>, user_id: &str) -> bool {
    sessions.values().any(|session| {
        if session.caller_id != user_id && session.callee_id != user_id {
            return false;
        }
        match session.phase {
            CallPhase::Ringing => session.created_at.elapsed() < RINGING_TTL,
            CallPhase::Accepted => !is_accepted_stale(session),
        }
    })
}

pub fn accept_session(
    callee_id: &str,
    caller_id: &str,
    callee_conn_id: u64,
) -> Result<CallSession, CallSessionError> {
    let key = pair_key(caller_id, callee_id);
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(session) = sessions.get_mut(&key) else {
        return Err(CallSessionError::NotFound);
    };
    if session.callee_id != callee_id || session.caller_id != caller_id {
        return Err(CallSessionError::WrongRole);
    }
    if session.phase != CallPhase::Ringing {
        return Err(CallSessionError::InvalidPhase);
    }
    if session.created_at.elapsed() >= RINGING_TTL {
        let expired = sessions.remove(&key).ok_or(CallSessionError::NotFound)?;
        return Err(CallSessionError::Expired(expired));
    }
    session.phase = CallPhase::Accepted;
    session.accepted_at = Some(Instant::now());
    session.callee_conn_id = Some(callee_conn_id);
    Ok(session.clone())
}

pub fn reject_session(callee_id: &str, caller_id: &str) -> Result<(), CallSessionError> {
    let key = pair_key(caller_id, callee_id);
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(session) = sessions.get(&key) else {
        return Err(CallSessionError::NotFound);
    };
    if session.callee_id != callee_id || session.caller_id != caller_id {
        return Err(CallSessionError::WrongRole);
    }
    if session.phase != CallPhase::Ringing {
        return Err(CallSessionError::InvalidPhase);
    }
    sessions.remove(&key);
    Ok(())
}

pub fn cancel_session(caller_id: &str, callee_id: &str) -> Result<(), CallSessionError> {
    let key = pair_key(caller_id, callee_id);
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(session) = sessions.get(&key) else {
        return Err(CallSessionError::NotFound);
    };
    if session.caller_id != caller_id || session.callee_id != callee_id {
        return Err(CallSessionError::WrongRole);
    }
    if session.phase != CallPhase::Ringing {
        return Err(CallSessionError::InvalidPhase);
    }
    sessions.remove(&key);
    Ok(())
}

pub fn end_session(user_id: &str, peer_id: &str) -> Result<CallSession, CallSessionError> {
    let key = pair_key(user_id, peer_id);
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(session) = sessions.get(&key) else {
        return Err(CallSessionError::NotFound);
    };
    let is_participant = (session.caller_id == user_id && session.callee_id == peer_id)
        || (session.callee_id == user_id && session.caller_id == peer_id);
    if !is_participant {
        return Err(CallSessionError::WrongRole);
    }
    let session = sessions.remove(&key);
    session.ok_or(CallSessionError::NotFound)
}

pub fn token_allowed(user_id: &str, peer_id: &str) -> Result<CallSession, CallSessionError> {
    let key = pair_key(user_id, peer_id);
    let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(session) = sessions.get(&key) else {
        return Err(CallSessionError::NotFound);
    };
    let is_participant = (session.caller_id == user_id && session.callee_id == peer_id)
        || (session.callee_id == user_id && session.caller_id == peer_id);
    if !is_participant {
        return Err(CallSessionError::WrongRole);
    }
    if session.phase != CallPhase::Accepted || is_accepted_stale(session) {
        return Err(CallSessionError::InvalidPhase);
    }
    Ok(session.clone())
}

pub fn active_session_for_user(user_id: &str) -> Option<CallSession> {
    let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    sessions
        .values()
        .find(|session| {
            session.phase == CallPhase::Accepted
                && !is_accepted_stale(session)
                && (session.caller_id == user_id || session.callee_id == user_id)
        })
        .cloned()
}

pub fn clear_ringing_sessions_for_user(user_id: &str) {
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    sessions.retain(|_, session| {
        if session.caller_id != user_id && session.callee_id != user_id {
            return true;
        }
        session.phase != CallPhase::Ringing
    });
}

fn connection_owns_side(session: &CallSession, user_id: &str, conn_id: u64) -> bool {
    if session.caller_id == user_id {
        return session.caller_conn_id == Some(conn_id);
    }
    if session.callee_id == user_id {
        return session.phase == CallPhase::Accepted && session.callee_conn_id == Some(conn_id);
    }
    false
}

pub fn take_sessions_for_connection(user_id: &str, conn_id: u64) -> Vec<CallSession> {
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let mut taken = Vec::new();
    sessions.retain(|_, session| {
        if connection_owns_side(session, user_id, conn_id) {
            taken.push(session.clone());
            false
        } else {
            true
        }
    });
    taken
}

pub fn take_sessions_for_user(user_id: &str) -> Vec<CallSession> {
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let mut taken = Vec::new();
    sessions.retain(|_, session| {
        if session.caller_id == user_id || session.callee_id == user_id {
            taken.push(session.clone());
            false
        } else {
            true
        }
    });
    taken
}

pub fn restore_sessions(sessions: Vec<CallSession>) {
    if sessions.is_empty() {
        return;
    }
    let mut map = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    for session in sessions {
        let key = pair_key(&session.caller_id, &session.callee_id);
        if map.contains_key(&key) {
            continue;
        }

        let still_valid = match session.phase {
            CallPhase::Ringing => session.created_at.elapsed() < RINGING_TTL,
            CallPhase::Accepted => !is_accepted_stale(&session),
        };
        if still_valid {
            map.insert(key, session);
        }
    }
}

pub fn ringing_sessions_for_callee(user_id: &str) -> Vec<CallSession> {
    let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    sessions
        .values()
        .filter(|session| {
            session.callee_id == user_id
                && session.phase == CallPhase::Ringing
                && session.created_at.elapsed() < RINGING_TTL
        })
        .cloned()
        .collect()
}

pub fn take_session_for_pair(a: &str, b: &str) -> Option<CallSession> {
    let key = pair_key(a, b);
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    sessions.remove(&key)
}

pub fn clear_sessions_for_user(user_id: &str) {
    let _ = take_sessions_for_user(user_id);
}
