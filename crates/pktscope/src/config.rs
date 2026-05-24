//! Optional `config.toml` (capture defaults, display, and saved named filters).
//! CLI arguments take precedence over config values.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub capture: CaptureConfig,
    pub display: DisplayConfig,
    /// Saved named filters, recalled in the filter bar as `:name`.
    pub filters: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    pub default_interface: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DisplayConfig {
    pub color_scheme: String,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            color_scheme: "dark".into(),
        }
    }
}

impl Config {
    pub fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("pktscope").join("config.toml"))
    }

    /// Load `config.toml`, falling back to defaults (and warning) on any error.
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
                eprintln!("pktscope: ignoring invalid {}: {e}", path.display());
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }
}
