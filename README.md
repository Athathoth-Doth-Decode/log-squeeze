# log-squeeze 🍋⚡

[![Rust](https://img.shields.io/badge/rust-2024_edition-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/version-v0.2.0-green.svg)]()

> **Adaptive 3-Tier Log & Context Compression Engine for AI Coding Agents, SREs, and DevOps.**  
> Squeeze 10,000+ line logs and massive manifests by **80–95%** without losing critical errors, stack traces, or root causes.

---

## 🎯 Why `log-squeeze`?

When AI coding assistants (such as Antigravity, Claude Code, Cursor, Aider) or human engineers inspect massive command outputs (`kubectl logs`, `journalctl`, CI/CD build logs, massive Kubernetes manifests):
- **Context Windows Blow Up:** Thousands of repetitive log lines saturate the token budget.
- **Lost In The Noise:** Critical stack traces and panic messages get buried under millions of repeated debug/info lines.
- **High Latency & Costs:** Sending raw logs to LLMs is slow, expensive, and degrades reasoning accuracy.

`log-squeeze` solves this with an **adaptive, 3-tier pipelined compression strategy** written in pure, high-performance Rust.

```
                  ┌──────────────────────────────────────────────┐
                  │                 Raw Log Stream               │
                  │        (stdin / file / kubectl / logs)       │
                  └──────────────────────┬───────────────────────┘
                                         │
                   ▼ Mode: --auto / Heuristics / Flags ▼
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │ ⚡ Tier 1: Fast Clustering & Deduplication (<5ms, Zero API cost)             │
   │    • Regex entity masking (IPs, UUIDs, Timestamps, Hashes, Hex, Durations)  │
   │    • Consecutive & global template deduplication ([x42] occurrences)        │
   │    • Preserves full error context & multi-line stack traces (Go, Java, Py)  │
   └────────────────────────┬────────────────────────────┬───────────────────────┘
                            │                            │
   (Structured Docs/Code)   │                            │ (Massive Errors / >100 lines)
                            ▼                            ▼
   ┌──────────────────────────────────┐        ┌──────────────────────────────────┐
   │ 🧠 Tier 2: Token-Level Pruning   │        │ 🤖 Tier 3: AI Semantic Summary   │
   │    • LLMLingua-2 BERT compression│        │    • LiteLLM / OpenAI / Ollama   │
   │    • Built-in token pruner       │        │    • Root Cause & Timeline       │
   │    • Configs, JSON, YAML, Docs   │        │    • Actionable Recommendations  │
   └──────────────────────────────────┘        └──────────────────────────────────┘
```

---

## 🚀 Features

* **⚡ Ultra-fast Tier 1 Deterministic Squeezing:** Processes tens of thousands of lines in milliseconds. Masks high-cardinality values (IPv4/IPv6, UUIDs, timestamps, memory addresses) to cluster repetitive log templates.
* **🛡️ Stack Trace & Error Awareness:** Automatically identifies and protects multi-line exceptions across Python, Java, Go, Rust, and Node.js.
* **🧠 Tier 2 Token Compression (LLMLingua-2 + Rust Fallback):**
  * **Neural Model:** Uses `microsoft/llmlingua-2-bert-base-multilingual-meetingbank` via `uv` (~500 MB weights downloaded once from Hugging Face and cached locally in `~/.cache/huggingface/`).
  * **Zero-Python / Offline Fallback:** If `uv`/Python or internet access is not available, automatically falls back to an internal **pure Rust token pruner** with zero external dependencies.
* **🤖 Tier 3 Semantic Root-Cause Analysis:** Seamlessly integrates with any OpenAI-compatible API endpoint (LiteLLM, Ollama, vLLM, OpenAI, Groq) to generate an immediate, structured diagnostic report.
* **🔄 Adaptive Auto-tiering:** Automatically chooses between Tier 1, Tier 2, or Tier 3 depending on input size, error density, and content type.
* **📦 Zero Runtime Dependencies:** Standalone native binary with minimal memory footprint; runs seamlessly in air-gapped / minimal Linux environments without Python.

---

## 📦 Installation

### From Source (Rust Cargo)

```bash
git clone https://github.com/<your-username>/log-squeeze.git
cd log-squeeze
cargo build --release

# Copy or link binary to your PATH
cp target/release/log-squeeze ~/.local/bin/
```

### One-Liner Cargo Install

```bash
cargo install --path .
```

---

## 💡 Quick Start & Cheatsheet

### 1. Basic Piped Usage (Auto-Tiering)
```bash
# Squeeze Kubernetes pod logs
kubectl logs deployment/ingress-controller -n ingress | log-squeeze

# Squeeze systemd journal output
journalctl -u rke2-server -n 2000 | log-squeeze
```

### 2. Squeeze Local Log Files
```bash
log-squeeze /var/log/syslog
```

### 3. Filter Only Errors, Warnings & Stack Traces
```bash
# Keep only errors, warnings, panics and their stack traces
kubectl logs deploy/api-service | log-squeeze -e
```

### 4. Frequency Cluster Summary
```bash
# See top repeating log templates and occurrence frequencies
cat app-access.log | log-squeeze -s
```

### 5. Structured JSON Output
```bash
# Export parsed clusters and error statistics to JSON
cat error.log | log-squeeze -j | jq .
```

### 6. Force Tier 2 (LLMLingua / Manifest Squeezing)
```bash
# Compress a huge Kubernetes manifest or documentation file to 40% size
cat massive-crds.yaml | log-squeeze -2 -r 0.4
```
> **ℹ️ Note on Tier 2 Execution & Offline Environments:**
> * **With `uv` / Python:** Uses `microsoft/llmlingua-2-bert-base-multilingual-meetingbank`. On its very first run, `uv` downloads model weights (~500 MB) from Hugging Face into `~/.cache/huggingface/hub/`. Subsequent runs are local and offline.
> * **Without Python / Air-gapped:** If Python or `uv` is not present, `log-squeeze` automatically uses its built-in **native Rust token pruner** with zero external downloads and sub-millisecond execution.

### 7. Force Tier 3 (AI Semantic Diagnostic Summary)
```bash
# Direct semantic diagnosis using your configured LLM
kubectl logs pod/failing-pod | log-squeeze -3 --model llama3.2
```

---

## ⚙️ Configuration (`config.toml`)

`log-squeeze` automatically generates a configuration file on its first run at `~/.config/log-squeeze/config.toml`:

```toml
[general]
mode = "auto"          # "auto", "fast", "lingua", or "ai"
max_lines = 200        # Output line budget

[thresholds]
min_lines_for_ai = 100
min_lines_for_lingua = 30

[litellm]
enabled = true
endpoint = "http://localhost:11434/v1"   # LiteLLM, Ollama, or OpenAI endpoint
api_key_env = "OPENAI_API_KEY"           # Environment variable for API key
model = "llama3.2"                       # Model name (e.g., llama3.2, qwen2.5-coder, gpt-4o-mini)
timeout_secs = 15
max_tokens = 500
temperature = 0.2

[lingua]
enabled = true
method = "auto"
rate = 0.5
```

---

## 🤖 Integrating with AI Agents (Cursor, Claude Code, Aider, Antigravity)

Add a rule to your `AGENTS.md`, `.cursorrules`, or `CLAUDE.md`:

```markdown
### Log Inspection Rule
When reading large logs, crash dumps, or manifests (`kubectl logs`, `journalctl`, `/var/log/*`, large YAML/JSON files), ALWAYS pipe output through `log-squeeze`:
- Default: `kubectl logs <pod> | log-squeeze`
- Only errors/traces: `journalctl -xe | log-squeeze -e`
- Semantic root-cause: `kubectl logs <pod> | log-squeeze -3`
```

---

## 📊 Example Output

### Tier 1 Output:
```text
=== [log-squeeze] Total: 4120 lines | Compressed to: 12 events (99.7% reduction) | Errors: 2 | Warnings: 1 ===
[x3890] [INFO] <TIME> [http-pool-worker-<N>] Handling request GET /api/v1/health ... [last: 2026-08-24T12:00:00Z [http-pool-worker-8] Handling request GET /api/v1/health]
[x228]  [WARN] <TIME> Slow query detected on db-<IP>: query duration <VAL>
[x2]    [ERROR] <TIME> Database connection timeout to 10.254.3.99:5432 after 30000ms
  +--- Stack Trace (4 lines):
  | Caused by: java.net.SocketTimeoutException: connect timed out
  |   at java.base/sun.nio.ch.NioSocketImpl.connect(NioSocketImpl.java:567)
  |   at org.postgresql.core.v3.ConnectionFactoryImpl.openConnectionImpl(ConnectionFactoryImpl.java:236)
  |   at org.postgresql.Driver.connect(Driver.java:260)
  +---
```

### Tier 3 AI Summary Output:
```markdown
=== [log-squeeze: AI Semantic Summary (model: llama3.2)] ===

1. **Root Cause & Summary**: PostgreSQL pool exhaustion caused by a network partition to `10.254.3.99:5432`.
2. **Key Events & Timeline**:
   - High frequency of slow health queries (>500ms).
   - At 12:00:00Z, connection timeout triggered connection pool drain.
3. **Critical Verbatim Lines**:
   > "Database connection timeout to 10.254.3.99:5432 after 30000ms"
   > "Caused by: java.net.SocketTimeoutException: connect timed out"
4. **Actionable Recommendations**:
   - Check network routing / firewall between worker and `10.254.3.99`.
   - Verify PostgreSQL service status on `10.254.3.99`.
```

---

## 🛠️ CLI Options Reference

| Flag | Description |
|---|---|
| `-a, --auto` | Auto-detect best pipeline tier (default) |
| `-1, --fast` | Force Tier 1: Deterministic regex mask, dedup & cluster (<5ms) |
| `-2, --lingua` | Force Tier 2: Token-level extractive compression (LLMLingua-2) |
| `-3, --ai, --semantic` | Force Tier 3: Semantic root-cause analysis via LiteLLM/OpenAI/Ollama |
| `-e, --errors-only` | Filter out non-error logs; keep only ERRORs, WARNs, PANICs, and traces |
| `-s, --summary` | Show top repeating template frequency clusters |
| `-j, --json` | Output clusters and statistics as structured JSON |
| `-m, --max-lines <N>` | Output line budget limit (default: 200) |
| `-r, --rate <float>` | Target token retention rate for Lingua (default: 0.5) |
| `--model <name>` | LiteLLM/OpenAI model override (e.g., `llama3.2`, `gpt-4o-mini`) |
| `--endpoint <url>` | LiteLLM/OpenAI API endpoint URL |
| `--key <key>` | API key for semantic LLM requests |
| `--config <path>` | Custom configuration file path |
| `-h, --help` | Display help message |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
