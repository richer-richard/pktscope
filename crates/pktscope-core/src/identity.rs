//! Binary-identity tracking for the "program modification" alert (signal 5).
//!
//! On macOS the identity is the code signature (cdhash + signing id + team id,
//! via `codesign`); elsewhere it is the SHA-256 of the executable's contents.
//! Results are cached by `(path, mtime, size)` so `codesign`/hashing runs only
//! when a binary first appears or changes.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use lru::LruCache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityKind {
    MacCodesign,
    Sha256,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
    Valid,
    Unsigned,
    AdHoc,
    Invalid,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryIdentity {
    pub path: PathBuf,
    pub kind: IdentityKind,
    /// cdhash (macOS) or sha256 hex (elsewhere); empty if unreadable.
    pub value: String,
    pub signing_id: Option<String>,
    pub team_id: Option<String>,
    pub authority: Option<String>,
    pub status: IdentityStatus,
}

static CACHE: Mutex<Option<LruCache<String, BinaryIdentity>>> = Mutex::new(None);

impl BinaryIdentity {
    /// Resolve the identity of the executable at `path`, using a process-wide
    /// cache keyed by `(path, mtime, size)`.
    pub fn identify(path: &Path) -> BinaryIdentity {
        let key = std::fs::metadata(path).ok().map(|m| cache_key(path, &m));
        if let Some(k) = &key {
            if let Some(hit) = cache_get(k) {
                return hit;
            }
        }
        let id = compute_identity(path);
        if let Some(k) = key {
            cache_put(k, id.clone());
        }
        id
    }

    /// True if `current` is a meaningful change from `self` (the baseline).
    /// A changed cdhash with the same team + signing id is treated as a normal
    /// app update and only flagged when `flag_signed_updates` is set; a changed
    /// team/signing id or a Valid→non-Valid regression always flags.
    pub fn changed_since(&self, current: &BinaryIdentity, flag_signed_updates: bool) -> bool {
        if self.status == IdentityStatus::Unreadable || current.status == IdentityStatus::Unreadable
        {
            return false;
        }
        let regressed =
            self.status == IdentityStatus::Valid && current.status != IdentityStatus::Valid;
        match (&self.kind, &current.kind) {
            (IdentityKind::MacCodesign, IdentityKind::MacCodesign) => {
                if self.team_id != current.team_id || self.signing_id != current.signing_id {
                    return true;
                }
                if regressed {
                    return true;
                }
                if self.value != current.value {
                    return flag_signed_updates;
                }
                false
            }
            _ => self.value != current.value || regressed,
        }
    }
}

fn cache_key(path: &Path, meta: &std::fs::Metadata) -> String {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}|{}|{}", path.display(), mtime, meta.len())
}

fn cache_get(key: &str) -> Option<BinaryIdentity> {
    let mut guard = CACHE.lock().ok()?;
    guard
        .get_or_insert_with(|| LruCache::new(NonZeroUsize::new(1024).unwrap()))
        .get(key)
        .cloned()
}

fn cache_put(key: String, value: BinaryIdentity) {
    if let Ok(mut guard) = CACHE.lock() {
        guard
            .get_or_insert_with(|| LruCache::new(NonZeroUsize::new(1024).unwrap()))
            .put(key, value);
    }
}

fn sha256_file(path: &Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let mut h = Sha256::new();
    h.update(&data);
    let out = h.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    Some(s)
}

fn unreadable(path: &Path, kind: IdentityKind) -> BinaryIdentity {
    BinaryIdentity {
        path: path.to_path_buf(),
        kind,
        value: String::new(),
        signing_id: None,
        team_id: None,
        authority: None,
        status: IdentityStatus::Unreadable,
    }
}

#[cfg(target_os = "macos")]
fn compute_identity(path: &Path) -> BinaryIdentity {
    if std::fs::metadata(path).is_err() {
        return unreadable(path, IdentityKind::MacCodesign);
    }
    let mut signing_id = None;
    let mut team_id = None;
    let mut authority = None;
    let mut cdhash = None;
    let mut status = IdentityStatus::Unsigned;

    if let Ok(out) = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(path)
        .output()
    {
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        if out.status.success() {
            status = IdentityStatus::Valid;
        }
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("Identifier=") {
                signing_id = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("TeamIdentifier=") {
                let v = v.trim();
                if v != "not set" {
                    team_id = Some(v.to_string());
                }
            } else if let Some(v) = line.strip_prefix("CDHash=") {
                cdhash = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Authority=") {
                if authority.is_none() {
                    authority = Some(v.trim().to_string());
                }
            }
            if line.contains("adhoc") {
                status = IdentityStatus::AdHoc;
            }
        }
    }

    let value = cdhash.or_else(|| sha256_file(path)).unwrap_or_default();
    BinaryIdentity {
        path: path.to_path_buf(),
        kind: IdentityKind::MacCodesign,
        value,
        signing_id,
        team_id,
        authority,
        status,
    }
}

#[cfg(not(target_os = "macos"))]
fn compute_identity(path: &Path) -> BinaryIdentity {
    match sha256_file(path) {
        Some(value) => BinaryIdentity {
            path: path.to_path_buf(),
            kind: IdentityKind::Sha256,
            value,
            signing_id: None,
            team_id: None,
            authority: None,
            status: IdentityStatus::Valid,
        },
        None => unreadable(path, IdentityKind::Sha256),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn id(
        kind: IdentityKind,
        value: &str,
        signing: Option<&str>,
        team: Option<&str>,
        status: IdentityStatus,
    ) -> BinaryIdentity {
        BinaryIdentity {
            path: PathBuf::from("/x"),
            kind,
            value: value.to_string(),
            signing_id: signing.map(|s| s.to_string()),
            team_id: team.map(|s| s.to_string()),
            authority: None,
            status,
        }
    }

    #[test]
    fn test_changed_since_truth_table() {
        let base = id(
            IdentityKind::MacCodesign,
            "h1",
            Some("com.x"),
            Some("TEAM"),
            IdentityStatus::Valid,
        );

        // identical
        assert!(!base.changed_since(&base, false));
        // team change
        let team = id(
            IdentityKind::MacCodesign,
            "h1",
            Some("com.x"),
            Some("OTHER"),
            IdentityStatus::Valid,
        );
        assert!(base.changed_since(&team, false));
        // signing id change
        let sign = id(
            IdentityKind::MacCodesign,
            "h1",
            Some("com.y"),
            Some("TEAM"),
            IdentityStatus::Valid,
        );
        assert!(base.changed_since(&sign, false));
        // cdhash change, same team+signing: not flagged unless flag set
        let upd = id(
            IdentityKind::MacCodesign,
            "h2",
            Some("com.x"),
            Some("TEAM"),
            IdentityStatus::Valid,
        );
        assert!(!base.changed_since(&upd, false));
        assert!(base.changed_since(&upd, true));
        // Valid -> Unsigned regression always flags
        let unsig = id(
            IdentityKind::MacCodesign,
            "h1",
            Some("com.x"),
            Some("TEAM"),
            IdentityStatus::Unsigned,
        );
        assert!(base.changed_since(&unsig, false));
        // unreadable never flags
        let unread = id(
            IdentityKind::MacCodesign,
            "",
            None,
            None,
            IdentityStatus::Unreadable,
        );
        assert!(!base.changed_since(&unread, true));
    }

    #[test]
    fn test_sha256_changes_on_modify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin");
        std::fs::write(&path, b"hello").unwrap();
        let i1 = BinaryIdentity::identify(&path);
        assert!(!i1.value.is_empty());

        // Modify (different size => different cache key, recomputed).
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b" world").unwrap();
        drop(f);
        let i2 = BinaryIdentity::identify(&path);
        assert_ne!(i1.value, i2.value);
        // Sha256 identities compare by value.
        if i1.kind == IdentityKind::Sha256 {
            assert!(i1.changed_since(&i2, false));
        }
    }
}
