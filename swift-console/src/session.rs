//! In-memory server-side sessions keyed by the `sc_session` cookie.

use crate::util;
use std::collections::HashMap;
use std::time::Instant;

pub const COOKIE: &str = "sc_session";

#[derive(Clone)]
pub struct Session {
    pub token: String,
    pub storage_url: String,
    pub tenant: String,
    pub user: String,
    pub key: String,
    pub last_seen: Instant,
    pub tempurl_default_secs: u64,
}

pub struct SessionStore {
    map: std::sync::Mutex<HashMap<String, Session>>,
    idle: std::time::Duration,
}

impl SessionStore {
    pub fn new(idle_hours: u64) -> Self {
        SessionStore {
            map: std::sync::Mutex::new(HashMap::new()),
            idle: std::time::Duration::from_secs(idle_hours * 3600),
        }
    }

    pub fn create(&self, s: Session) -> String {
        let sid = util::rand_hex(16);
        let mut m = self.map.lock().unwrap();
        // Opportunistic cleanup of idle sessions.
        let idle = self.idle;
        m.retain(|_, v| v.last_seen.elapsed() < idle);
        m.insert(sid.clone(), s);
        sid
    }

    /// Fetch a live session snapshot, refreshing its idle timer.
    pub fn get(&self, sid: &str) -> Option<Session> {
        let mut m = self.map.lock().unwrap();
        let s = m.get_mut(sid)?;
        if s.last_seen.elapsed() >= self.idle {
            m.remove(sid);
            return None;
        }
        s.last_seen = Instant::now();
        Some(s.clone())
    }

    pub fn update_token(&self, sid: &str, token: &str, storage_url: &str) {
        if let Some(s) = self.map.lock().unwrap().get_mut(sid) {
            s.token = token.to_string();
            s.storage_url = storage_url.to_string();
        }
    }

    pub fn set_tempurl_default(&self, sid: &str, secs: u64) {
        if let Some(s) = self.map.lock().unwrap().get_mut(sid) {
            s.tempurl_default_secs = secs;
        }
    }

    pub fn remove(&self, sid: &str) {
        self.map.lock().unwrap().remove(sid);
    }
}

/// Extract the session id + snapshot from request headers.
pub fn from_headers(
    store: &SessionStore,
    headers: &axum::http::HeaderMap,
) -> Option<(String, Session)> {
    let sid = util::cookie_value(headers, COOKIE)?;
    let s = store.get(&sid)?;
    Some((sid, s))
}
