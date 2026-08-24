use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// ----------------------------------------------------------------------------
// Configuration (TOML)
// ----------------------------------------------------------------------------

/// Top-level application configuration structure containing general settings,
/// threshold limits for adaptive escalation, LiteLLM connection parameters,
/// and extractive token compression settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub thresholds: ThresholdsConfig,
    #[serde(default)]
    pub litellm: LiteLlmConfig,
    #[serde(default)]
    pub lingua: LinguaConfig,
}

/// General operating mode and line budget limits.
/// Controls whether auto-tiering, fast regex clustering, token pruning, or AI summary runs,
/// as well as the maximum output line count for compressed logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_max_lines")]
    pub max_lines: usize,
}

fn default_mode() -> String {
    "auto".to_string()
}
fn default_max_lines() -> usize {
    200
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            max_lines: default_max_lines(),
        }
    }
}

/// Threshold limits determining when log-squeeze escalates from Tier 1 to Tier 2 (Lingua)
/// or Tier 3 (AI semantic summary) in automatic mode based on line counts and error density.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdsConfig {
    #[serde(default = "default_min_lines_ai")]
    pub min_lines_for_ai: usize,
    #[serde(default = "default_min_lines_lingua")]
    pub min_lines_for_lingua: usize,
}

fn default_min_lines_ai() -> usize {
    100
}
fn default_min_lines_lingua() -> usize {
    30
}

impl Default for ThresholdsConfig {
    fn default() -> Self {
        Self {
            min_lines_for_ai: default_min_lines_ai(),
            min_lines_for_lingua: default_min_lines_lingua(),
        }
    }
}

/// Connection parameters for Tier 3 semantic analysis via LiteLLM, Ollama, or OpenAI.
/// Stores endpoint URL, API key environment variable, target model, request timeouts,
/// token limits, and sampling temperature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiteLlmConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_litellm_endpoint")]
    pub endpoint: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_litellm_key_env")]
    pub api_key_env: String,
    #[serde(default = "default_litellm_model")]
    pub model: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_temp")]
    pub temperature: f32,
}

fn default_true() -> bool {
    true
}
fn default_litellm_endpoint() -> String {
    "http://localhost:11434/v1".to_string()
}
fn default_litellm_key_env() -> String {
    "OPENAI_API_KEY".to_string()
}
fn default_litellm_model() -> String {
    "llama3.2".to_string()
}
fn default_timeout() -> u64 {
    15
}
fn default_max_tokens() -> u32 {
    500
}
fn default_temp() -> f32 {
    0.2
}

impl Default for LiteLlmConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            endpoint: default_litellm_endpoint(),
            api_key: None,
            api_key_env: default_litellm_key_env(),
            model: default_litellm_model(),
            timeout_secs: default_timeout(),
            max_tokens: default_max_tokens(),
            temperature: default_temp(),
        }
    }
}

/// Settings for Tier 2 extractive token-level compression (LLMLingua-2 / token pruner).
/// Configures whether extractive compression is enabled, which algorithm is preferred,
/// and the target retention rate (e.g. 0.5 retains approximately 50% of tokens).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinguaConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_lingua_method")]
    pub method: String,
    #[serde(default = "default_lingua_rate")]
    pub rate: f32,
}

fn default_lingua_method() -> String {
    "auto".to_string()
}
fn default_lingua_rate() -> f32 {
    0.5
}

impl Default for LinguaConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            method: default_lingua_method(),
            rate: default_lingua_rate(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            thresholds: ThresholdsConfig::default(),
            litellm: LiteLlmConfig::default(),
            lingua: LinguaConfig::default(),
        }
    }
}

impl AppConfig {
    /// Loads an existing configuration from a custom path or the default user config directory.
    /// If no configuration file exists at the destination, this method creates parent folders,
    /// writes a well-commented default configuration file, and returns the default configuration.
    pub fn load_or_create(custom_path: Option<&Path>) -> Self {
        let path = match custom_path {
            Some(p) => p.to_path_buf(),
            None => {
                if let Ok(home) = std::env::var("HOME") {
                    PathBuf::from(home).join(".config/log-squeeze/config.toml")
                } else {
                    PathBuf::from("config.toml")
                }
            }
        };

        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(cfg) = toml::from_str::<AppConfig>(&content) {
                    return cfg;
                }
            }
        } else {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let default_cfg = AppConfig::default();
            if let Ok(content) = toml::to_string_pretty(&default_cfg) {
                let header = "# log-squeeze configuration file\n# Squeezing pipeline: Fast (regex/dedup) -> Lingua (token prune) -> AI (LiteLLM)\n\n";
                let _ = fs::write(&path, format!("{}{}", header, content));
            }
            return default_cfg;
        }

        AppConfig::default()
    }

    /// Resolves the API key to use for semantic AI analysis requests.
    /// It checks if a literal API key was provided directly in the configuration file,
    /// and if not, retrieves the key from the environment variable named in `api_key_env`.
    pub fn get_litellm_api_key(&self) -> Option<String> {
        if let Some(ref k) = self.litellm.api_key {
            if !k.trim().is_empty() {
                return Some(k.clone());
            }
        }
        if let Ok(k) = std::env::var(&self.litellm.api_key_env) {
            if !k.trim().is_empty() {
                return Some(k);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_roundtrip() {
        let default_cfg = AppConfig::default();
        let toml_str = toml::to_string(&default_cfg).expect("Should serialize config");
        let parsed_cfg: AppConfig = toml::from_str(&toml_str).expect("Should parse serialized config");

        assert_eq!(parsed_cfg.general.mode, "auto");
        assert_eq!(parsed_cfg.general.max_lines, 200);
        assert_eq!(parsed_cfg.litellm.model, "llama3.2");
        assert_eq!(parsed_cfg.thresholds.min_lines_for_ai, 100);
        assert_eq!(parsed_cfg.lingua.rate, 0.5);
    }

    #[test]
    fn test_partial_toml_uses_defaults() {
        let partial_toml = r#"
        [general]
        max_lines = 50
        "#;
        let parsed_cfg: AppConfig = toml::from_str(partial_toml).expect("Should parse partial config");

        assert_eq!(parsed_cfg.general.max_lines, 50);
        assert_eq!(parsed_cfg.general.mode, "auto");
        assert_eq!(parsed_cfg.litellm.model, "llama3.2");
        assert_eq!(parsed_cfg.litellm.timeout_secs, 15);
    }
}
