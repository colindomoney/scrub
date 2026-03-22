use crate::cli::{Cli, Sensitivity};
use regex::Regex;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Default)]
pub struct FileConfig {
    pub sensitivity: Option<String>,
    pub extra_patterns: Option<Vec<String>>,
    pub allowlist: Option<Vec<String>>,
}

pub struct ResolvedConfig {
    pub sensitivity: Sensitivity,
    pub extra_patterns: Vec<Regex>,
    pub allowlist: Vec<String>,
    pub entropy_threshold: f64,
    pub min_token_length: usize,
}

impl ResolvedConfig {
    pub fn from(cli: &Cli, file: FileConfig) -> Result<Self, String> {
        // CLI sensitivity takes priority over file config
        let sensitivity = if cli.sensitivity != Sensitivity::Medium {
            cli.sensitivity.clone()
        } else if let Some(ref s) = file.sensitivity {
            match s.as_str() {
                "low" => Sensitivity::Low,
                "medium" => Sensitivity::Medium,
                "high" => Sensitivity::High,
                other => return Err(format!("invalid sensitivity in config: {other}")),
            }
        } else {
            cli.sensitivity.clone()
        };

        let (entropy_threshold, min_token_length) = match sensitivity {
            Sensitivity::Low => (f64::INFINITY, usize::MAX),
            Sensitivity::Medium => (4.5, 20),
            Sensitivity::High => (3.8, 16),
        };

        let extra_patterns = file
            .extra_patterns
            .unwrap_or_default()
            .into_iter()
            .map(|p| {
                Regex::new(&p)
                    .map_err(|e| format!("[scrub] error: invalid extra pattern {p:?}: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let allowlist = file.allowlist.unwrap_or_default();

        Ok(ResolvedConfig {
            sensitivity,
            extra_patterns,
            allowlist,
            entropy_threshold,
            min_token_length,
        })
    }
}

pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("scrub").join("config.toml"))
}

pub fn load_config(path: &Path) -> Result<FileConfig, String> {
    if !path.exists() {
        return Ok(FileConfig::default());
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("[scrub] error reading config {}: {e}", path.display()))?;
    toml::from_str(&text)
        .map_err(|e| format!("[scrub] error parsing config {}: {e}", path.display()))
}
