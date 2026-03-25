use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Session {
    pub last_activity: Instant,
}

pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    timeout: Duration,
}

impl SessionStore {
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            timeout,
        }
    }

    pub fn create_session(&self) -> String {
        use rand::Rng;
        let token: String = (0..32)
            .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
            .collect();
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(
            token.clone(),
            Session {
                last_activity: Instant::now(),
            },
        );
        token
    }

    pub fn validate(&self, token: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(token) {
            if session.last_activity.elapsed() < self.timeout {
                session.last_activity = Instant::now();
                return true;
            }
            sessions.remove(token);
        }
        false
    }

    pub fn remove(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }

    pub fn cleanup_expired(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.last_activity.elapsed() < self.timeout);
    }
}

/// Extract session token from Cookie header value.
pub fn extract_session_cookie(cookie_header: &str) -> Option<&str> {
    cookie_header
        .split(';')
        .map(|s| s.trim())
        .find_map(|part| {
            let (key, value) = part.split_once('=')?;
            if key.trim() == "session" {
                Some(value.trim())
            } else {
                None
            }
        })
}

/// Build Set-Cookie header value for a session.
pub fn session_cookie(token: &str) -> String {
    format!("session={token}; HttpOnly; Secure; SameSite=Strict; Path=/")
}

/// Build Set-Cookie header that clears the session.
pub fn clear_session_cookie() -> String {
    "session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_validate_session() {
        let store = SessionStore::new(Duration::from_secs(1800));
        let token = store.create_session();
        assert!(store.validate(&token));
    }

    #[test]
    fn test_invalid_token_rejected() {
        let store = SessionStore::new(Duration::from_secs(1800));
        assert!(!store.validate("nonexistent"));
    }

    #[test]
    fn test_remove_session() {
        let store = SessionStore::new(Duration::from_secs(1800));
        let token = store.create_session();
        store.remove(&token);
        assert!(!store.validate(&token));
    }

    #[test]
    fn test_expired_session_rejected() {
        let store = SessionStore::new(Duration::from_millis(1));
        let token = store.create_session();
        std::thread::sleep(Duration::from_millis(10));
        assert!(!store.validate(&token));
    }

    #[test]
    fn test_cleanup_expired() {
        let store = SessionStore::new(Duration::from_millis(1));
        store.create_session();
        store.create_session();
        std::thread::sleep(Duration::from_millis(10));
        store.cleanup_expired();
    }

    #[test]
    fn test_extract_session_cookie() {
        assert_eq!(
            extract_session_cookie("session=abc123; other=value"),
            Some("abc123")
        );
        assert_eq!(extract_session_cookie("other=value"), None);
        assert_eq!(extract_session_cookie("session=token"), Some("token"));
    }

    #[test]
    fn test_session_cookie_format() {
        let cookie = session_cookie("abc");
        assert!(cookie.contains("session=abc"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
    }
}
