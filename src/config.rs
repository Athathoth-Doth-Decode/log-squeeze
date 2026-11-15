use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// ----------------------------------------------------------------------------
// Configuration (TOML)
// ----------------------------------------------------------------------------

/// Top-level application configuration structure containing general settings,
/// threshold limits for adaptive escalation, LiteLLM connection parameters,
/// and extractive token compression settings.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Legacy escalation thresholds retained for configuration compatibility.
/// Auto now stays in Tier 1 regardless of these values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct LiteLlmConfig {
    #[serde(default)]
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

fn default_litellm_endpoint() -> String {
    "http://localhost:11434/v1".to_string()
}
fn default_litellm_key_env() -> String {
    "LOG_SQUEEZE_API_KEY".to_string()
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
            enabled: false,
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
#[serde(deny_unknown_fields)]
pub struct LinguaConfig {
    #[serde(default)]
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
            enabled: false,
            method: default_lingua_method(),
            rate: default_lingua_rate(),
        }
    }
}

impl AppConfig {
    /// Read configuration without creating or changing files.
    /// Only an absent standard path permits defaults; other read failures stop processing.
    /// Parser diagnostics deliberately omit source text because TOML can contain credentials.
    pub fn load(custom_path: Option<&Path>) -> Result<Self, String> {
        let path = custom_path.map(Path::to_path_buf).unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(".config/log-squeeze/config.toml")
        });
        let display = crate::redact::redact(&path.display().to_string());
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && custom_path.is_none()
                    && fs::symlink_metadata(&path).is_err() =>
            {
                return Ok(Self::default());
            }
            Err(e) => return Err(format!("Cannot read config '{}': {}", display, e.kind())),
        };
        let cfg: Self = toml::from_str(&content).map_err(|e: toml::de::Error| {
            let line = e
                .span()
                .map(|span| {
                    content[..span.start]
                        .bytes()
                        .filter(|b| *b == b'\n')
                        .count()
                        + 1
                })
                .unwrap_or(1);
            format!(
                "Invalid config '{}' at line {}: invalid TOML, field, or value type",
                display, line
            )
        })?;
        cfg.validate()
            .map_err(|e| format!("Invalid config '{}': {}", display, e))?;
        Ok(cfg)
    }

    /// Validate values that select execution paths or control requests.
    /// Legacy thresholds remain accepted for compatibility but cannot enable escalation.
    /// Report field names without echoing possibly sensitive values.
    pub fn validate(&self) -> Result<(), String> {
        if self.general.max_lines == 0 {
            return Err("general.max_lines must be positive".into());
        }
        if !matches!(
            self.general.mode.as_str(),
            "auto" | "fast" | "lingua" | "ai"
        ) {
            return Err("general.mode must be auto, fast, lingua, or ai".into());
        }
        if !matches!(self.lingua.method.as_str(), "auto" | "builtin" | "uv") {
            return Err("lingua.method must be auto, builtin, or uv".into());
        }
        if !self.lingua.rate.is_finite() || self.lingua.rate <= 0.0 || self.lingua.rate > 1.0 {
            return Err("lingua.rate must be finite and in (0, 1]".into());
        }
        if self.litellm.timeout_secs == 0
            || self.litellm.max_tokens == 0
            || !self.litellm.temperature.is_finite()
        {
            return Err(
                "litellm requires positive timeout_secs/max_tokens and finite temperature".into(),
            );
        }
        crate::ai::validate_endpoint(&self.litellm.endpoint, false)?;
        Ok(())
    }

    /// Resolves the API key to use for semantic AI analysis requests.
    /// It checks if a literal API key was provided directly in the configuration file,
    /// and if not, retrieves the key from the environment variable named in `api_key_env`.
    pub fn get_litellm_api_key(&self) -> Option<String> {
        if let Some(ref k) = self.litellm.api_key
            && !k.trim().is_empty()
        {
            return Some(k.clone());
        }
        if let Ok(k) = std::env::var(&self.litellm.api_key_env)
            && !k.trim().is_empty()
        {
            return Some(k);
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
        let parsed_cfg: AppConfig =
            toml::from_str(&toml_str).expect("Should parse serialized config");

        assert!(!parsed_cfg.litellm.enabled);
        assert!(!parsed_cfg.lingua.enabled);
        assert_eq!(parsed_cfg.litellm.api_key_env, "LOG_SQUEEZE_API_KEY");
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
        let parsed_cfg: AppConfig =
            toml::from_str(partial_toml).expect("Should parse partial config");

        assert_eq!(parsed_cfg.general.max_lines, 50);
        assert!(!parsed_cfg.litellm.enabled);
        assert!(!parsed_cfg.lingua.enabled);
        assert_eq!(parsed_cfg.litellm.api_key_env, "LOG_SQUEEZE_API_KEY");
        assert_eq!(parsed_cfg.general.mode, "auto");
        assert_eq!(parsed_cfg.litellm.model, "llama3.2");
        assert_eq!(parsed_cfg.litellm.timeout_secs, 15);
    }
}
