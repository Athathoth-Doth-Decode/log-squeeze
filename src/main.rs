mod ai;
mod config;
mod lingua;
mod masker;

use ai::run_litellm_summary;
use config::AppConfig;
use lingua::run_lingua_compress;
use masker::{run_fast_squeeze, EventCluster, SqueezeStats};
use serde::Serialize;
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

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

/// Parses command line arguments and flags into a structured `CliOptions` instance.
/// Supports short flags (-a, -1, -2, -3, -e, -s, -j, -m, -r, -h) as well as long options
/// for endpoint, model, api key, and custom configuration file path.
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

/// Main application entry point orchestrating the 3-tier log compression pipeline.
/// Reads log stream from stdin or file, applies configuration and command line overrides,
/// and delegates to Tier 1 (fast clustering), Tier 2 (Lingua token pruning), or Tier 3 (AI summary).
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
