use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use rustls::sign::CertifiedKey;

use crate::tls::cert::load_certified_key;

pub fn file_mtime(path: &PathBuf) -> Option<SystemTime> {
    fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

pub fn try_reload_if_changed(
    cert_path: &PathBuf,
    key_path: &PathBuf,
    last_cert_mtime: &mut Option<SystemTime>,
    last_key_mtime: &mut Option<SystemTime>,
    certified_key: &Arc<RwLock<Arc<CertifiedKey>>>,
) -> bool {
    let cert_mtime = file_mtime(cert_path);
    let key_mtime = file_mtime(key_path);

    if cert_mtime == *last_cert_mtime && key_mtime == *last_key_mtime {
        return false;
    }

    match load_certified_key(cert_path, key_path) {
        Ok(new_key) => {
            *certified_key.write().unwrap() = Arc::new(new_key);
            eprintln!("TLS certificate reloaded successfully");
            *last_cert_mtime = cert_mtime;
            *last_key_mtime = key_mtime;
            true
        }
        Err(e) => {
            eprintln!("Failed to reload TLS certificate (keeping current): {}", e);
            false
        }
    }
}

pub async fn watch_certs(
    cert_path: PathBuf,
    key_path: PathBuf,
    certified_key: Arc<RwLock<Arc<CertifiedKey>>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.tick().await; // consume the initial immediate tick

    let mut last_cert_mtime = file_mtime(&cert_path);
    let mut last_key_mtime = file_mtime(&key_path);

    loop {
        interval.tick().await;
        try_reload_if_changed(
            &cert_path,
            &key_path,
            &mut last_cert_mtime,
            &mut last_key_mtime,
            &certified_key,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::cert::load_certified_key;
    use crate::tls::test_helpers::write_test_cert_files;
    use tempfile::NamedTempFile;

    #[test]
    fn test_file_mtime_existing_file() {
        let f = NamedTempFile::new().unwrap();
        assert!(file_mtime(&f.path().to_path_buf()).is_some());
    }

    #[test]
    fn test_file_mtime_nonexistent_file() {
        assert!(file_mtime(&PathBuf::from("/nonexistent/path/cert.pem")).is_none());
    }

    #[test]
    fn test_try_reload_no_change_returns_false() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let key = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&key)));

        let mut last_cert = file_mtime(&cert_path);
        let mut last_key = file_mtime(&key_path);

        let reloaded =
            try_reload_if_changed(&cert_path, &key_path, &mut last_cert, &mut last_key, &shared);

        assert!(!reloaded);
        assert!(Arc::ptr_eq(&shared.read().unwrap(), &key));
    }

    #[test]
    fn test_try_reload_detects_mtime_change_and_reloads() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let key = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&key)));

        let mut last_cert: Option<SystemTime> = None;
        let mut last_key: Option<SystemTime> = None;

        let reloaded =
            try_reload_if_changed(&cert_path, &key_path, &mut last_cert, &mut last_key, &shared);

        assert!(reloaded);
        assert!(last_cert.is_some());
        assert!(last_key.is_some());
    }

    #[test]
    fn test_try_reload_keeps_old_key_on_invalid_cert() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let original_key = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&original_key)));

        std::fs::write(&cert_path, b"not a valid certificate").unwrap();

        let mut last_cert: Option<SystemTime> = None;
        let mut last_key: Option<SystemTime> = None;

        let reloaded =
            try_reload_if_changed(&cert_path, &key_path, &mut last_cert, &mut last_key, &shared);

        assert!(!reloaded);
        assert!(Arc::ptr_eq(&shared.read().unwrap(), &original_key));
        assert!(last_cert.is_none());
    }

    #[test]
    fn test_try_reload_updates_mtimes_only_on_success() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let key = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&key)));

        let actual_cert_mtime = file_mtime(&cert_path);
        let actual_key_mtime = file_mtime(&key_path);

        let mut last_cert: Option<SystemTime> = None;
        let mut last_key: Option<SystemTime> = None;

        let reloaded =
            try_reload_if_changed(&cert_path, &key_path, &mut last_cert, &mut last_key, &shared);

        assert!(reloaded);
        assert_eq!(last_cert, actual_cert_mtime);
        assert_eq!(last_key, actual_key_mtime);
    }
}
