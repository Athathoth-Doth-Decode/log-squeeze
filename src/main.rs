use log_squeeze::ai::run_litellm_summary;
use log_squeeze::config::AppConfig;
use log_squeeze::lingua::{run_builtin_token_pruner, run_lingua_compress};
use log_squeeze::masker::{EventCluster, SqueezeStats, run_fast_squeeze};
use log_squeeze::redact::redact;
use serde::Serialize;
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

// ----------------------------------------------------------------------------
// CLI Args & Orchestration
// ----------------------------------------------------------------------------

#[derive(Default)]
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

/// Parses command line arguments and flags into a structured `CliOptions` instance.
/// Supports short flags (-a, -1, -2, -3, -e, -s, -j, -m, -r, -h) as well as long options
/// for endpoint, model, api key, and custom configuration file path.
fn parse_args() -> Result<CliOptions, String> {
    let mut opts = CliOptions::default();
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-1" | "--fast" => set_mode(&mut opts, "fast")?,
            "-2" | "--lingua" => set_mode(&mut opts, "lingua")?,
            "-3" | "--ai" => set_mode(&mut opts, "ai")?,
            "-a" | "--auto" => set_mode(&mut opts, "auto")?,
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
                    PIPELINE MODES:\n    -a, --auto            Local Tier 1 only (default; no network or subprocesses)\n    -1, --fast            Tier 1: Deterministic regex mask, dedup & cluster (<5ms)\n    -2, --lingua          Tier 2: Token-level extractive compression (LLMLingua-2)\n    -3, --ai              Tier 3: Semantic root-cause analysis via LiteLLM/Ollama\n\n\
                    OPTIONS:\n    -e, --errors-only     Filter to ERRORs, WARNs, PANICs and stack traces\n    -s, --summary         Show frequency template clusters summary\n    -j, --json            Compact JSON with the same Tier 1 selection\n    -m, --max-lines <N>   Hard Tier 1 line cap, including header (positive; default: 200)\n    -r, --rate <float>    Target token retention rate for Lingua (default: 0.5)\n    --model <name>        LiteLLM model override (e.g. qwen3-coder:30b)\n    --endpoint <url>      LiteLLM API endpoint URL\n    --key <key>           LiteLLM API key\n    --config <file>       Custom config path (default: ~/.config/log-squeeze/config.toml)\n    -h, --help            Show this help message\n\n\
                    EXAMPLES:\n    kubectl logs deploy/traefik -n traefik | log-squeeze\n    journalctl -u rke2-server -n 1000 | log-squeeze --ai\n    cat huge-manifest.yaml | log-squeeze --lingua -r 0.4\n    log-squeeze /var/log/syslog -1 -e"
                );
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                return Err("Unknown option; run --help for supported flags".into());
            }
            file => {
                opts.input_file = Some(PathBuf::from(file));
            }
        }
    }

    let external = matches!(opts.mode_override.as_deref(), Some("ai" | "lingua"));
    if external && (opts.errors_only || opts.json_output || opts.summary_only) {
        return Err(
            "--ai/--lingua cannot be combined with --errors-only, --json, or --summary".into(),
        );
    }
    if opts.errors_only && opts.summary_only {
        return Err("--errors-only cannot be combined with --summary".into());
    }
    if opts.json_output && opts.summary_only {
        return Err("--json cannot be combined with --summary".into());
    }
    Ok(opts)
}

// Select exactly one pipeline for this invocation.
// Conflicting flags are rejected instead of silently using the last flag.
// Only an explicit external mode authorizes subprocess or network execution.
fn set_mode(opts: &mut CliOptions, mode: &str) -> Result<(), String> {
    if opts
        .mode_override
        .as_deref()
        .is_some_and(|previous| previous != mode)
    {
        return Err(
            "Conflicting pipeline modes; choose one of --auto, --fast, --lingua, --ai".into(),
        );
    }
    opts.mode_override = Some(mode.into());
    Ok(())
}

/// Main application entry point orchestrating the 3-tier log compression pipeline.
/// Reads log stream from stdin or file, applies configuration and command line overrides,
/// and delegates to Tier 1 (fast clustering), Tier 2 (Lingua token pruning), or Tier 3 (AI summary).
fn run() -> Result<(), String> {
    let cli_opts = parse_args()?;
    let mut config = AppConfig::load(cli_opts.config_file.as_deref())?;

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

    config.validate()?;
    // Configuration preferences never authorize external execution.
    let effective_mode = cli_opts.mode_override.as_deref().unwrap_or("fast");
    if effective_mode == "ai" {
        log_squeeze::ai::validate_endpoint(
            &config.litellm.endpoint,
            config.get_litellm_api_key().is_some(),
        )?;
    }
    // Logs routinely contain stray non-UTF-8 bytes; replace them instead of rejecting the input.
    let mut raw_bytes = Vec::new();
    if let Some(ref path) = cli_opts.input_file {
        let mut file = File::open(path).map_err(|_| "Cannot open input file")?;
        file.read_to_end(&mut raw_bytes)
            .map_err(|_| "Cannot read input file")?;
    } else {
        io::stdin()
            .read_to_end(&mut raw_bytes)
            .map_err(|_| "Cannot read stdin")?;
    }
    let raw_input = String::from_utf8_lossy(&raw_bytes).into_owned();

    if raw_input.trim().is_empty() {
        return Ok(());
    }

    let raw_input = redact(&raw_input);

    if effective_mode == "lingua" {
        let builtin = config.lingua.method == "builtin";
        if !builtin && !config.lingua.enabled {
            eprintln!(
                "[log-squeeze: lingua.enabled = false; using the built-in pruner without subprocesses]"
            );
        }
        let compressed = if builtin || !config.lingua.enabled {
            run_builtin_token_pruner(&raw_input, config.lingua.rate)
        } else {
            run_lingua_compress(&raw_input, config.lingua.rate)?
        };
        println!("{}", compressed);
        return Ok(());
    }

    let reader = io::Cursor::new(raw_input.as_bytes());
    let mut fast_res = run_fast_squeeze(
        reader,
        config.general.max_lines,
        cli_opts.errors_only,
        cli_opts.summary_only,
    )
    .map_err(|_| "Tier 1 input processing failed")?;

    if cli_opts.json_output {
        // WHY: Borrow already redacted clusters to serialize without copying log content.
        #[derive(Serialize)]
        struct OutputJson<'a> {
            stats: &'a SqueezeStats,
            clusters_count: usize,
            clusters: &'a [EventCluster],
            #[serde(skip_serializing_if = "Option::is_none")]
            budget: Option<&'a log_squeeze::BudgetStats>,
        }
        // Compact JSON stays within even a one-line cap; its data uses the text selection budget.
        fast_res.stats.output_lines = 1;
        let out = OutputJson {
            stats: &fast_res.stats,
            clusters_count: fast_res.clusters.len(),
            clusters: &fast_res.clusters,
            budget: (!fast_res.budget.is_empty()).then_some(&fast_res.budget),
        };
        println!("{}", serde_json::to_string(&out).unwrap());
        return Ok(());
    }

    if effective_mode == "fast" || cli_opts.summary_only {
        print!("{}", fast_res.rendered_output);
        return Ok(());
    }

    // Tier 3 is opt-in twice: the -3 flag and litellm.enabled. Any failure falls back to the
    // already rendered Tier 1 output so a pipeline never loses the log it was given.
    if effective_mode == "ai" {
        if !config.litellm.enabled {
            eprintln!("[log-squeeze: litellm.enabled = false; showing Tier 1 output]");
        } else {
            eprintln!("[log-squeeze: Generating semantic summary via LiteLLM]...");
            match run_litellm_summary(&fast_res.rendered_output, &config) {
                Ok(summary) => {
                    println!("=== [log-squeeze: AI Semantic Summary] ===\n");
                    println!("{}", summary.trim());
                    return Ok(());
                }
                Err(error) => eprintln!("[log-squeeze: {error}; showing Tier 1 output]"),
            }
        }
    }

    print!("{}", fast_res.rendered_output);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {}", error);
        std::process::exit(1);
    }
}
