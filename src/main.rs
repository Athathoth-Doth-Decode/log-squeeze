use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum LogLevel {
    Panic,
    Fatal,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
    Unknown,
}

impl LogLevel {
    fn is_error_or_warn(&self) -> bool {
        matches!(
            self,
            LogLevel::Panic | LogLevel::Fatal | LogLevel::Error | LogLevel::Warn
        )
    }

    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Panic => "PANIC",
            LogLevel::Fatal => "FATAL",
            LogLevel::Error => "ERROR",
            LogLevel::Warn => "WARN",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
            LogLevel::Trace => "TRACE",
            LogLevel::Unknown => "LOG",
        }
    }
}

// ----------------------------------------------------------------------------
// Configuration (TOML)
// ----------------------------------------------------------------------------

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
    "https://litellm.homenet.trak.spb.ru/v1".to_string()
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

// ----------------------------------------------------------------------------
// Tier 1: Fast Deterministic Masker & Deduplicator
// ----------------------------------------------------------------------------

struct Masker {
    re_iso_time: Regex,
    re_syslog_time: Regex,
    re_time_only: Regex,
    re_ipv4: Regex,
    re_ipv6: Regex,
    re_uuid: Regex,
    re_hex: Regex,
    re_hash: Regex,
    re_duration_bytes: Regex,
    re_num: Regex,
}

impl Masker {
    fn new() -> Self {
        Self {
            re_iso_time: Regex::new(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b").unwrap(),
            re_syslog_time: Regex::new(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b").unwrap(),
            re_time_only: Regex::new(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b").unwrap(),
            re_uuid: Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b").unwrap(),
            re_ipv4: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{1,5})?\b").unwrap(),
            re_ipv6: Regex::new(r"\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){4,7}\b").unwrap(),
            re_hex: Regex::new(r"\b0x[0-9a-fA-F]+\b").unwrap(),
            re_hash: Regex::new(r"\b[0-9a-fA-F]{32,64}\b").unwrap(),
            re_duration_bytes: Regex::new(r"\b\d+(?:\.\d+)?\s*(?:ms|µs|ns|s|m|MB|GB|KB|B|MiB|GiB|KiB)\b").unwrap(),
            re_num: Regex::new(r"\b\d+\b").unwrap(),
        }
    }

    fn mask(&self, line: &str) -> String {
        let s = self.re_iso_time.replace_all(line, "<TIME>");
        let s = self.re_syslog_time.replace_all(&s, "<TIME>");
        let s = self.re_time_only.replace_all(&s, "<TIME>");
        let s = self.re_uuid.replace_all(&s, "<UUID>");
        let s = self.re_ipv4.replace_all(&s, "<IP>");
        let s = self.re_ipv6.replace_all(&s, "<IPV6>");
        let s = self.re_hex.replace_all(&s, "<HEX>");
        let s = self.re_hash.replace_all(&s, "<HASH>");
        let s = self.re_duration_bytes.replace_all(&s, "<VAL>");
        let s = self.re_num.replace_all(&s, "<N>");
        s.into_owned()
    }
}

fn detect_level(line: &str) -> LogLevel {
    let lower = line.to_ascii_lowercase();
    if lower.contains("panic") {
        LogLevel::Panic
    } else if lower.contains("fatal") || lower.contains("critical") {
        LogLevel::Fatal
    } else if lower.contains("error") || lower.contains("exception") || lower.contains("fail") {
        LogLevel::Error
    } else if lower.contains("warn") {
        LogLevel::Warn
    } else if lower.contains("info") {
        LogLevel::Info
    } else if lower.contains("debug") {
        LogLevel::Debug
    } else if lower.contains("trace") {
        LogLevel::Trace
    } else {
        LogLevel::Unknown
    }
}

fn is_stack_trace_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("at ")
        || trimmed.starts_with("Caused by:")
        || trimmed.starts_with("File ")
        || trimmed.starts_with("Traceback (most recent call last):")
        || trimmed.starts_with("goroutine ")
        || trimmed.starts_with("... ")
        || (trimmed.contains(".rs:") && trimmed.contains(":"))
        || (trimmed.contains(".go:") && trimmed.contains(":"))
        || (trimmed.contains(".py\", line "))
        || (trimmed.contains(".java:"))
}

#[derive(Debug, Clone, Serialize)]
struct EventCluster {
    template: String,
    level: LogLevel,
    count: usize,
    first_example: String,
    last_example: String,
    stack_trace: Vec<String>,
}

#[derive(Debug, Default, Serialize, Clone)]
struct SqueezeStats {
    total_lines: usize,
    output_lines: usize,
    panics: usize,
    fatals: usize,
    errors: usize,
    warnings: usize,
    infos: usize,
    debugs: usize,
    traces: usize,
    unknowns: usize,
}

impl SqueezeStats {
    fn record_level(&mut self, level: LogLevel) {
        match level {
            LogLevel::Panic => self.panics += 1,
            LogLevel::Fatal => self.fatals += 1,
            LogLevel::Error => self.errors += 1,
            LogLevel::Warn => self.warnings += 1,
            LogLevel::Info => self.infos += 1,
            LogLevel::Debug => self.debugs += 1,
            LogLevel::Trace => self.traces += 1,
            LogLevel::Unknown => self.unknowns += 1,
        }
    }

    fn total_errors_and_warns(&self) -> usize {
        self.panics + self.fatals + self.errors + self.warnings
    }
}

struct FastSqueezeResult {
    stats: SqueezeStats,
    clusters: Vec<EventCluster>,
    rendered_output: String,
    is_structured_code_heuristic: bool,
}

fn run_fast_squeeze<R: BufRead>(reader: R, max_lines: usize, errors_only: bool, summary_only: bool) -> io::Result<FastSqueezeResult> {
    let masker = Masker::new();
    let mut stats = SqueezeStats::default();

    let mut clusters: Vec<EventCluster> = Vec::new();
    let mut current_cluster: Option<EventCluster> = None;
    let mut global_templates: HashMap<String, usize> = HashMap::new();

    let mut unknown_level_lines = 0;

    for line_res in reader.lines() {
        let raw_line = line_res?;
        stats.total_lines += 1;

        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let is_st = is_stack_trace_line(trimmed);

        if is_st {
            if let Some(ref mut cur) = current_cluster {
                if cur.level.is_error_or_warn() && cur.stack_trace.len() < 30 {
                    cur.stack_trace.push(raw_line.clone());
                    continue;
                }
            }
        }

        let level = detect_level(trimmed);
        if level == LogLevel::Unknown {
            unknown_level_lines += 1;
        }
        stats.record_level(level);

        let template = masker.mask(trimmed);
        *global_templates.entry(template.clone()).or_insert(0) += 1;

        if let Some(mut cur) = current_cluster.take() {
            if cur.template == template && !cur.level.is_error_or_warn() {
                cur.count += 1;
                cur.last_example = raw_line;
                current_cluster = Some(cur);
            } else if cur.template == template && cur.level.is_error_or_warn() && cur.stack_trace.is_empty() {
                cur.count += 1;
                cur.last_example = raw_line;
                current_cluster = Some(cur);
            } else {
                clusters.push(cur);
                current_cluster = Some(EventCluster {
                    template,
                    level,
                    count: 1,
                    first_example: raw_line.clone(),
                    last_example: raw_line,
                    stack_trace: Vec::new(),
                });
            }
        } else {
            current_cluster = Some(EventCluster {
                template,
                level,
                count: 1,
                first_example: raw_line.clone(),
                last_example: raw_line,
                stack_trace: Vec::new(),
            });
        }
    }

    if let Some(cur) = current_cluster {
        clusters.push(cur);
    }

    let filtered_clusters: Vec<EventCluster> = if errors_only {
        clusters
            .into_iter()
            .filter(|c| c.level.is_error_or_warn())
            .collect()
    } else {
        clusters
    };

    let total_errors = stats.panics + stats.fatals + stats.errors;
    let reduction_pct = if stats.total_lines > 0 {
        let cl_count = filtered_clusters.len();
        if stats.total_lines >= cl_count {
            ((stats.total_lines - cl_count) as f64 / stats.total_lines as f64) * 100.0
        } else {
            0.0
        }
    } else {
        0.0
    };

    let mut out_buf = Vec::new();

    writeln!(
        out_buf,
        "=== [log-squeeze] Total: {} lines | Compressed to: {} events ({:.1}% reduction) | Errors: {} | Warnings: {} ===",
        stats.total_lines,
        filtered_clusters.len(),
        reduction_pct,
        total_errors,
        stats.warnings
    )?;

    if summary_only {
        writeln!(out_buf, "\n--- Top Repeating Templates ---")?;
        let mut top_templates: Vec<(&String, &usize)> = global_templates.iter().collect();
        top_templates.sort_by(|a, b| b.1.cmp(a.1));

        for (tmpl, count) in top_templates.iter().take(25) {
            writeln!(out_buf, "[x{:>5}] {}", count, tmpl)?;
        }
        let rendered = String::from_utf8_lossy(&out_buf).into_owned();
        return Ok(FastSqueezeResult {
            stats,
            clusters: filtered_clusters,
            rendered_output: rendered,
            is_structured_code_heuristic: false,
        });
    }

    let total_events = filtered_clusters.len();
    let display_events = if total_events > max_lines && !errors_only {
        let (errs_warns, others): (Vec<_>, Vec<_>) = filtered_clusters
            .clone()
            .into_iter()
            .partition(|c| c.level.is_error_or_warn());

        let remaining_budget = max_lines.saturating_sub(errs_warns.len()).max(20);
        let sample_step = if others.len() > remaining_budget {
            others.len() / remaining_budget
        } else {
            1
        };

        let mut combined = errs_warns;
        if sample_step > 1 {
            writeln!(
                out_buf,
                "[log-squeeze notice: sampled non-error events 1-in-{} to fit {} line budget]",
                sample_step, max_lines
            )?;
        }
        for (i, item) in others.into_iter().enumerate() {
            if i % sample_step == 0 {
                combined.push(item);
            }
        }
        combined
    } else {
        filtered_clusters.clone()
    };

    for ev in display_events {
        if ev.count == 1 {
            writeln!(out_buf, "{}", ev.first_example)?;
        } else {
            writeln!(
                out_buf,
                "[x{}] [{}] {} ... [last: {}]",
                ev.count,
                ev.level.as_str(),
                ev.first_example,
                ev.last_example
            )?;
        }

        if !ev.stack_trace.is_empty() {
            writeln!(out_buf, "  +--- Stack Trace ({} lines):", ev.stack_trace.len())?;
            for st_line in &ev.stack_trace {
                writeln!(out_buf, "  | {}", st_line)?;
            }
            writeln!(out_buf, "  +---")?;
        }
    }

    let is_code = stats.total_lines > 20 && (unknown_level_lines as f64 / stats.total_lines as f64) > 0.85;

    Ok(FastSqueezeResult {
        stats,
        clusters: filtered_clusters,
        rendered_output: String::from_utf8_lossy(&out_buf).into_owned(),
        is_structured_code_heuristic: is_code,
    })
}

// ----------------------------------------------------------------------------
// Tier 2: Lingua Token Compressor
// ----------------------------------------------------------------------------

fn run_lingua_compress(input: &str, rate: f32) -> Result<String, String> {
    let uv_bin = which_bin("uv");
    if let Some(uv) = uv_bin {
        let py_script = r#"
import sys
from llmlingua import PromptCompressor
text = sys.stdin.read()
if not text.strip():
    sys.exit(0)
rate = float(sys.argv[1]) if len(sys.argv) > 1 else 0.5
compressor = PromptCompressor(
    model_name="microsoft/llmlingua-2-bert-base-multilingual-meetingbank",
    use_llmlingua2=True,
    device_map="cpu"
)
res = compressor.compress_prompt(
    context=[text],
    rate=rate,
    force_tokens=['\n', '?', '!', ':', '-', '{', '}', '[', ']']
)
print(res['compressed_prompt'])
"#;

        let mut child = Command::new(uv)
            .args(&[
                "run",
                "--with",
                "llmlingua>=0.2.2",
                "--with",
                "torch",
                "--with",
                "transformers",
                "python3",
                "-c",
                py_script,
                &rate.to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn uv: {}", e))?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input.as_bytes());
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("Failed waiting for uv process: {}", e))?;

        if output.status.success() {
            let result = String::from_utf8_lossy(&output.stdout).into_owned();
            if !result.trim().is_empty() {
                return Ok(result);
            }
        }
    }

    Ok(run_builtin_token_pruner(input, rate))
}

fn run_builtin_token_pruner(input: &str, target_rate: f32) -> String {
    let mut out = String::new();
    let stopwords: HashMap<&str, ()> = [
        "the", "a", "an", "is", "are", "was", "were", "to", "of", "and", "in", "that", "it",
        "for", "on", "with", "as", "this", "by", "at", "from", "be", "or", "which",
        "и", "в", "на", "с", "по", "для", "к", "о", "из", "что", "это", "как",
    ]
    .iter()
    .cloned()
    .map(|s| (s, ()))
    .collect();

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            out.push('\n');
            continue;
        }

        let indent_len = line.len() - line.trim_start().len();
        let indent = &line[..indent_len];
        out.push_str(indent);

        let words: Vec<&str> = trimmed.split_whitespace().collect();
        if words.len() <= 3 {
            out.push_str(trimmed);
            out.push('\n');
            continue;
        }

        let mut kept_words = Vec::new();
        for (idx, w) in words.iter().enumerate() {
            let lower = w.to_lowercase();
            let clean = lower.trim_matches(|c: char| !c.is_alphanumeric());
            if stopwords.contains_key(clean) && (idx % 2 == 0) && target_rate < 0.8 {
                continue;
            }
            kept_words.push(*w);
        }

        if kept_words.is_empty() {
            out.push_str(trimmed);
        } else {
            out.push_str(&kept_words.join(" "));
        }
        out.push('\n');
    }

    out
}

fn which_bin(name: &str) -> Option<PathBuf> {
    if let Ok(path_var) = std::env::var("PATH") {
        for p in std::env::split_paths(&path_var) {
            let full = p.join(name);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let full = PathBuf::from(home).join(".local/bin").join(name);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

// ----------------------------------------------------------------------------
// Tier 3: LiteLLM Semantic Analyzer
// ----------------------------------------------------------------------------

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct ChatCompletionRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessageResponse,
}

#[derive(Deserialize)]
struct ChatMessageResponse {
    content: String,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
}

fn run_litellm_summary(squeezed_text: &str, cfg: &AppConfig) -> Result<String, String> {
    let api_key = cfg.get_litellm_api_key().unwrap_or_default();
    let url = format!("{}/chat/completions", cfg.litellm.endpoint.trim_end_matches('/'));

    let system_prompt = "You are an expert SRE, cloud infrastructure and systems diagnostic agent. \
Analyze the provided squeezed logs and produce a concise, structured markdown report with the following sections:
1. **Root Cause & Summary**: What failed and why.
2. **Key Events & Timeline**: Concise sequence of critical events.
3. **Critical Verbatim Lines**: 2-4 exact log error lines in quotes.
4. **Actionable Recommendations**: Clear troubleshooting steps.
Be direct, highly technical, and avoid fluff or conversational filler.";

    let payload = ChatCompletionRequest {
        model: &cfg.litellm.model,
        messages: vec![
            ChatMessage {
                role: "system",
                content: system_prompt,
            },
            ChatMessage {
                role: "user",
                content: squeezed_text,
            },
        ],
        max_tokens: cfg.litellm.max_tokens,
        temperature: cfg.litellm.temperature,
    };

    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(cfg.litellm.timeout_secs)))
        .build()
        .new_agent();

    let mut req = agent.post(&url);
    if !api_key.is_empty() {
        req = req.header("Authorization", &format!("Bearer {}", api_key));
    }
    req = req.header("Content-Type", "application/json");

    let resp = req
        .send_json(&payload)
        .map_err(|e| format!("LiteLLM request error ({}): {}", url, e))?;

    let mut body_str = String::new();
    resp.into_body()
        .into_reader()
        .read_to_string(&mut body_str)
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    let parsed: ChatCompletionResponse = serde_json::from_str(&body_str)
        .map_err(|e| format!("Failed to parse JSON response: {}. Raw: {}", e, body_str))?;

    if let Some(choice) = parsed.choices.into_iter().next() {
        Ok(choice.message.content)
    } else {
        Err("Empty choices in LiteLLM response".to_string())
    }
}

// ----------------------------------------------------------------------------
// CLI Args & Orchestration
// ----------------------------------------------------------------------------

#[derive(Debug)]
struct CliOptions {
    input_file: Option<PathBuf>,
    config_file: Option<PathBuf>,
    mode_override: Option<String>,
    errors_only: bool,
    summary_only: bool,
    json_output: bool,
    max_lines: Option<usize>,
    lingua_rate: Option<f32>,
    model_override: Option<String>,
    endpoint_override: Option<String>,
    api_key_override: Option<String>,
}

impl Default for CliOptions {
    fn default() -> Self {
        Self {
            input_file: None,
            config_file: None,
            mode_override: None,
            errors_only: false,
            summary_only: false,
            json_output: false,
            max_lines: None,
            lingua_rate: None,
            model_override: None,
            endpoint_override: None,
            api_key_override: None,
        }
    }
}

fn parse_args() -> Result<CliOptions, String> {
    let mut opts = CliOptions::default();
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-1" | "--fast" => opts.mode_override = Some("fast".to_string()),
            "-2" | "--lingua" => opts.mode_override = Some("lingua".to_string()),
            "-3" | "--ai" | "--semantic" => opts.mode_override = Some("ai".to_string()),
            "-a" | "--auto" => opts.mode_override = Some("auto".to_string()),
            "-e" | "--errors-only" => opts.errors_only = true,
            "-s" | "--summary" => opts.summary_only = true,
            "-j" | "--json" => opts.json_output = true,
            "-m" | "--max-lines" => {
                let val = args.next().ok_or("Missing value for --max-lines")?;
                opts.max_lines = Some(val.parse().map_err(|_| "Invalid number for --max-lines")?);
            }
            "-r" | "--rate" => {
                let val = args.next().ok_or("Missing value for --rate")?;
                opts.lingua_rate = Some(val.parse().map_err(|_| "Invalid float for --rate")?);
            }
            "--model" => {
                let val = args.next().ok_or("Missing value for --model")?;
                opts.model_override = Some(val);
            }
            "--endpoint" => {
                let val = args.next().ok_or("Missing value for --endpoint")?;
                opts.endpoint_override = Some(val);
            }
            "--key" => {
                let val = args.next().ok_or("Missing value for --key")?;
                opts.api_key_override = Some(val);
            }
            "--config" => {
                let val = args.next().ok_or("Missing value for --config")?;
                opts.config_file = Some(PathBuf::from(val));
            }
            "-h" | "--help" => {
                println!(
                    "log-squeeze v0.2.0 — Adaptive 3-Tier Log & Context Squeezer for LLM Agents\n\n\
                    USAGE:\n    log-squeeze [OPTIONS] [FILE]\n    <stdout> | log-squeeze [OPTIONS]\n\n\
                    PIPELINE MODES:\n    -a, --auto            Auto-detect best pipeline tier (default)\n    -1, --fast            Tier 1: Deterministic regex mask, dedup & cluster (<5ms)\n    -2, --lingua          Tier 2: Token-level extractive compression (LLMLingua-2)\n    -3, --ai              Tier 3: Semantic root-cause analysis via LiteLLM/Ollama\n\n\
                    OPTIONS:\n    -e, --errors-only     Filter to ERRORs, WARNs, PANICs and stack traces\n    -s, --summary         Show frequency template clusters summary\n    -j, --json            Output structured JSON (Tier 1)\n    -m, --max-lines <N>   Output line budget limit (default: 200)\n    -r, --rate <float>    Target token retention rate for Lingua (default: 0.5)\n    --model <name>        LiteLLM model override (e.g. llama3.2, qwen3:8b)\n    --endpoint <url>      LiteLLM API endpoint URL\n    --key <key>           LiteLLM API key\n    --config <file>       Custom config path (default: ~/.config/log-squeeze/config.toml)\n    -h, --help            Show this help message\n\n\
                    EXAMPLES:\n    kubectl logs deploy/traefik -n traefik | log-squeeze\n    journalctl -u rke2-server -n 1000 | log-squeeze --ai\n    cat huge-manifest.yaml | log-squeeze --lingua -r 0.4\n    log-squeeze /var/log/syslog -1 -e"
                );
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("Unknown option: {}", other));
            }
            file => {
                opts.input_file = Some(PathBuf::from(file));
            }
        }
    }

    Ok(opts)
}

fn main() -> io::Result<()> {
    let cli_opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Run 'log-squeeze --help' for usage.");
            std::process::exit(1);
        }
    };

    let mut config = AppConfig::load_or_create(cli_opts.config_file.as_deref());

    if let Some(ref m) = cli_opts.mode_override {
        config.general.mode = m.clone();
    }
    if let Some(m) = cli_opts.max_lines {
        config.general.max_lines = m;
    }
    if let Some(r) = cli_opts.lingua_rate {
        config.lingua.rate = r;
    }
    if let Some(ref model) = cli_opts.model_override {
        config.litellm.model = model.clone();
    }
    if let Some(ref ep) = cli_opts.endpoint_override {
        config.litellm.endpoint = ep.clone();
    }
    if let Some(ref k) = cli_opts.api_key_override {
        config.litellm.api_key = Some(k.clone());
    }

    let mut raw_input = String::new();
    if let Some(ref path) = cli_opts.input_file {
        let mut file = File::open(path)?;
        file.read_to_string(&mut raw_input)?;
    } else {
        io::stdin().read_to_string(&mut raw_input)?;
    }

    if raw_input.trim().is_empty() {
        return Ok(());
    }

    let effective_mode = config.general.mode.to_ascii_lowercase();

    if effective_mode == "lingua" {
        match run_lingua_compress(&raw_input, config.lingua.rate) {
            Ok(compressed) => {
                println!("{}", compressed);
                return Ok(());
            }
            Err(e) => {
                eprintln!("[log-squeeze: Lingua pass warning: {}]", e);
            }
        }
    }

    let reader = io::Cursor::new(raw_input.as_bytes());
    let fast_res = run_fast_squeeze(
        reader,
        config.general.max_lines,
        cli_opts.errors_only,
        cli_opts.summary_only,
    )?;

    if cli_opts.json_output {
        #[derive(Serialize)]
        struct OutputJson<'a> {
            stats: &'a SqueezeStats,
            clusters_count: usize,
            clusters: &'a [EventCluster],
        }
        let out = OutputJson {
            stats: &fast_res.stats,
            clusters_count: fast_res.clusters.len(),
            clusters: &fast_res.clusters,
        };
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }

    if effective_mode == "fast" || cli_opts.summary_only {
        print!("{}", fast_res.rendered_output);
        return Ok(());
    }

    if effective_mode == "ai" {
        eprintln!("[log-squeeze: Generating semantic summary via LiteLLM ({})]...", config.litellm.model);
        match run_litellm_summary(&fast_res.rendered_output, &config) {
            Ok(summary) => {
                println!("=== [log-squeeze: AI Semantic Summary (model: {})] ===\n", config.litellm.model);
                println!("{}", summary.trim());
                return Ok(());
            }
            Err(e) => {
                eprintln!("[log-squeeze: LiteLLM fallback to tier-1 output: {}]\n", e);
                print!("{}", fast_res.rendered_output);
                return Ok(());
            }
        }
    }

    if fast_res.is_structured_code_heuristic && fast_res.stats.total_lines >= config.thresholds.min_lines_for_lingua && config.lingua.enabled {
        if let Ok(compressed) = run_lingua_compress(&raw_input, config.lingua.rate) {
            println!("{}", compressed);
            return Ok(());
        }
    }

    let should_ai = config.litellm.enabled
        && fast_res.stats.total_lines >= config.thresholds.min_lines_for_ai
        && fast_res.stats.total_errors_and_warns() > 0;

    if should_ai {
        match run_litellm_summary(&fast_res.rendered_output, &config) {
            Ok(summary) => {
                println!("=== [log-squeeze: AI Semantic Summary (model: {})] ===\n", config.litellm.model);
                println!("{}", summary.trim());
                return Ok(());
            }
            Err(e) => {
                eprintln!("[log-squeeze: LiteLLM auto-pass error: {}, showing tier-1 output]\n", e);
            }
        }
    }

    print!("{}", fast_res.rendered_output);
    Ok(())
}
