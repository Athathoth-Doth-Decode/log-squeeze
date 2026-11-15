# log-squeeze 🍋⚡

A Rust CLI for reducing log output before inspecting it or passing it to an AI agent.
Default execution is local: secret redaction followed by Tier 1 clustering.
External execution requires an explicit `-2` or `-3` flag.

## Execution and security

All tiers redact recognized secrets **before** processing logs. JSON clusters,
examples, templates, stack lines and outbound log text receive the same redaction.
There is no flag to disable it. Recognized forms include:

- Bearer and Basic Authorization headers; JWTs.
- URL credentials, including `postgres://`, `mongodb+srv://`, `redis://` and HTTPS,
  also with JSON-escaped slashes such as `postgres:\/\/`.
- AWS access keys and named secret/session keys.
- `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `api-key`,
  `access_key` and related key fields in logs, query parameters and single-line JSON/YAML values.

Values become `<REDACTED>`; surrounding keys, quotes and useful text remain.
Redacting an already redacted log produces the same result. Query separators are
handled separately: `password: first&second` is entirely redacted, while
`?password=first&ok=yes` retains `&ok=yes`. Value boundaries depend on the context:

- Block YAML plain scalars are redacted through the end of the value, preserving
  a following comment; spaces, `&`, commas and semicolons remain part of the secret.
- In a single-line YAML flow mapping, a plain scalar continues through spaces to
  the separating comma or closing container. Neighboring mapping entries remain.
  Nesting and punctuation inside quoted strings are tracked separately.
- In unquoted log fields, a comma followed by `key=value` starts the next field,
  with optional spaces around the key and `=`. Other commas, `&` and semicolons
  remain part of the secret. Quote a log value containing a literal `,key=value`
  sequence so it is distinguishable from neighboring diagnostic fields.
- Quoted secrets retain their quotes. An unterminated quoted secret is redacted
  through the end of its line; the next event remains.

For example:

```text
credentials: {password: FAKE_FIRST FAKE_SECOND, user: app}
→ credentials: {password: <REDACTED>, user: app}

ERROR password=FAKE_PASSWORD,code=500,path=/checkout user=app
→ ERROR password=<REDACTED>,code=500,path=/checkout user=app
```

C1 remains partially addressed in [REVIEW.md](REVIEW.md). This is pattern-based
redaction: arbitrary unlabeled secrets, encoded field names and multiline YAML
values are not comprehensively detected.

| Invocation | Execution |
|---|---|
| Default, `-a` / `--auto`, `-1` / `--fast` | Local Tier 1 only; no LLM, uv, Python, dependency or model downloads |
| `-e` / `--errors-only` | Local error/warning lines and currently recognized attached stacks |
| `-2` / `--lingua` | Explicit Tier 2; may run uv/Python and download dependencies/models |
| `-2` with `[lingua] method = "builtin"` | Builtin Rust token pruner only |
| `-3` / `--ai` | Explicit request to the configured OpenAI-compatible API |

`general.mode = "ai"` or `"lingua"` never authorizes external execution.
Legacy `enabled` and threshold settings cannot escalate auto, regardless of input
size, errors or content. They remain accepted for config compatibility; explicit
`-2`/`-3` select their tier even when the corresponding `enabled` is false.
The former `--semantic` alias is no longer accepted; use `--ai`.

Tier 3 redacts again at the transport boundary. Its log message is limited to
**32 KiB of UTF-8 bytes**, including `\n[log-squeeze: logs truncated]` when needed.
Characters are never split. The system prompt and JSON framing are outside this
log-text budget. The model sees the Tier 1 output, which may already be sampled.

API key precedence: `--key`, nonempty `litellm.api_key`, then the environment
variable named by `litellm.api_key_env` (default **`LOG_SQUEEZE_API_KEY`**).
`OPENAI_API_KEY` is read only if explicitly named by `api_key_env`.
Prefer environment variables to `--key`, whose argument is visible in process listings.

Sending a key over HTTP is rejected except for parsed loopback IPs (`127.0.0.0/8`,
`::1`) and exact `localhost`/`localhost.` names, pinned to `127.0.0.1` for HTTP.
`localhost.evil.example` is rejected. HTTPS remains available for remote services.
Endpoint userinfo, query strings and fragments are rejected. Redirects and
proxy environment variables are disabled so they cannot bypass this policy.
Request failures exit nonzero with a safe diagnostic: no keys, raw logs, endpoint
text or response body are printed to stderr. There is no AI-error fallback output.

## Installation

```bash
set -euo pipefail
git clone https://github.com/Athathoth-Doth-Decode/log-squeeze.git
cd log-squeeze
cargo build --release
# Optional installation, performed by you:
cp target/release/log-squeeze ~/.local/bin/
```

## Usage

```bash
set -euo pipefail
kubectl logs deploy/api | log-squeeze
journalctl -u my-service | log-squeeze -e
log-squeeze -1 /var/log/syslog
log-squeeze -j application.log
log-squeeze -s application.log
# Explicit network request:
log-squeeze -3 --model llama3.2 application.log
# Explicit Tier 2; see its limitations below:
log-squeeze -2 -r 0.4 manifest.yaml
```

| Flag | Description |
|---|---|
| `-a, --auto` | Local Tier 1 (default) |
| `-1, --fast` | Local templates, global deduplication and ordered selection |
| `-2, --lingua` | Explicit token compression |
| `-3, --ai` | Explicit semantic summary via the configured API |
| `-e, --errors-only` | Error/warning events and recognized stacks |
| `-s, --summary` | Repeating template frequencies |
| `-j, --json` | Compact JSON with the same selected Tier 1 events and stacks |
| `-m, --max-lines <N>` | Hard Tier 1 text-line cap including metadata; positive, default 200 |
| `-r, --rate <float>` | Tier 2 rate, finite and in `(0, 1]` |
| `--model <name>` | Model override |
| `--endpoint <url>` | API endpoint override |
| `--key <key>` | Explicit API key override |
| `--config <path>` | Required existing custom config |
| `-h, --help` | Usage |

Conflicting pipeline flags are errors. `-2`/`-3` cannot be combined with `-e`,
`-j` or `-s`; `-e -s` and `-j -s` are also errors. `-e -j` returns filtered
clusters, including attached stack lines, as JSON.

## Configuration

The standard path is `~/.config/log-squeeze/config.toml`. If absent, safe defaults
are used in memory; the program does **not** create or rewrite config files.
An explicitly supplied missing `--config` is an error. Existing unreadable files,
invalid TOML, unknown fields, invalid types and invalid setting values stop the
program before reading input, with a path and safe diagnostic. TOML parse errors
include a line number but never echo source text.

```toml
[general]
mode = "auto"          # External modes still require a CLI flag
max_lines = 200

[thresholds]           # Legacy compatibility; no automatic escalation
min_lines_for_ai = 100
min_lines_for_lingua = 30

[litellm]
enabled = false        # Does not authorize auto or prevent explicit -3
endpoint = "http://localhost:11434/v1"
api_key_env = "LOG_SQUEEZE_API_KEY"
# api_key = "..."      # Optional literal; prefer the environment
model = "llama3.2"
timeout_secs = 15
max_tokens = 500
temperature = 0.2

[lingua]
enabled = false        # Does not authorize auto or prevent explicit -2
method = "auto"        # "builtin" skips uv; "auto"/"uv" try existing neural path
rate = 0.5
```

Create a custom config yourself if needed and protect files containing API keys
with permissions such as `0600`. Existing permissions are not changed or audited.

## Levels and stack traces

Explicit severity takes precedence over message words. Supported headers include
JSON `level`/`severity`/`log.level`, klog `I/W/E/F`, leading `INFO`/`[INFO]`-style
labels (also after timestamps, thread labels or syslog prefixes), and logfmt
`level=`/`severity=`/`log.level=` outside quoted values. JSON and logfmt accept Pino
numeric levels: 10 trace, 20 debug, 30 info, 40 warn, 50 error, 60 fatal.
An unknown explicit value remains `Unknown`. Separators `-`, `|` and `:` between
timestamp and level are supported: `2026-11-08 10:00:00,123 - INFO - no panic detected`
stays INFO.

For example, `INFO no panic detected`, `[INFO] ERROR counter=0` and
`level=info msg="warning"` stay INFO. Without an explicit level, whole-word
failure and crash signatures are used; `failover`, `error_count` and `/api/errors`
do not match `fail` or `error`. OOM-kill and segfault diagnostics are recognized.

The parser assembles complete events before clustering:

- Go panic blocks retain signals, goroutine headers, function/file frames, internal
  blank lines and `exit status`.
- Python tracebacks retain source lines, error pointers, terminal exceptions and
  chained tracebacks, including source such as `INFO = 1 / 0` after a `File` frame.
- Rust panic blocks retain the separate panic message, numbered frames, source
  locations and backtrace notes.
- Java retains frames, `Caused by`, `Suppressed` and `... N more` lines. Standalone
  exception class names such as `java.lang.NullPointerException` are errors even
  without a colon or message.
- Node retains frames and diagnostic object tails such as `errno`, `code` and `port`;
  properties named `error`, `info` or `fatal` do not end the object.

New klog, timestamped and syslog records end the active stack, even when indented.
Bare severity words are interpreted in context: one more-indented source line
after a Python `File` frame and indented properties inside a Node object remain
part of the stack. Other explicit headers begin new events. A `.go:` or `.rs:`
mention alone is not a frame. Stack frames inherit the parent severity and are
not counted as independent errors. Counts describe input events before global
deduplication; `total_lines` includes frames and blank lines.

`-e` keeps error/warning events with these attached stacks, and `-e -j` includes
the same selected blocks in JSON. The former silent 30-line stack limit is removed;
the explicit output budget below applies to all local modes.

## Deduplication, order and output budget

Tier 1 merges repeated complete events across the input and emits clusters in
**first-occurrence order**. Repeats show `[xN]`, the first and last redacted head,
and the first representative stack. This is an aggregate view: it does not replay
every repeated occurrence in chronological order.

For ERROR/WARN/PANIC/FATAL, identity preserves diagnostic numbers, addresses and
other message values; only a recognized leading timestamp is normalized. Thus
`ERROR code=13` and `ERROR code=14` remain separate. Other severities use masked
templates. Standalone numbers from 100 through 599 remain in templates, so HTTP
200/500/502 cannot collapse into one outcome. Recognized location frames compare
with dynamic values masked, including three-digit source line numbers; source
snippets, exception causes and Node object properties compare without masking.
All comparisons happen after redaction.

`-m N` / `general.max_lines` is a **hard physical line cap for Tier 1 text**,
including the summary header, stack frames, blank lines and decoration. It also
applies with `-e` and `-s`. Zero is an error; `-m 1` emits only the header with
omission counts. Terminal wrapping and byte length are not bounded by this option.

Selection reserves one header row, then retains event heads by priority
PANIC, FATAL, ERROR, WARN, other, with first occurrence breaking ties. Selected
heads print in source order. Remaining rows go to stacks in the same priority
order; decoration is omitted when needed to retain more frames. Gaps appear as
`[... N events skipped]`; truncated stacks say `[... N stack lines omitted]`.
Markers share existing rows so they cannot exceed the cap. A skipped cluster
counts all its occurrences; gap positions refer to cluster first-occurrence order.
The header's cluster count is before budget selection, and severity counters cover
all input events. `-s` sorts frequencies descending, breaks ties lexically and
reports omitted templates.

`-j` uses the same event/frame selection as text and writes one compact JSON line.
`clusters_count` counts selected clusters. On omission, the `budget` object gives
`skipped_events`, `skipped_clusters`, `skipped_after`, `omitted_stack_lines` and
`omitted_templates`. Affected clusters have `skipped_before` or
`omitted_stack_lines`; zero-valued cluster fields and an empty `budget` are omitted.
Stack omission counts describe representative stack rows, not every repeated copy.
`stats.output_lines` is the actual output row count (one for nonempty JSON output).

This cap controls Tier 1, including the log text prepared for explicit Tier 3.
It does not limit Tier 2 output or the model's response; Tier 3 retains its separate
32 KiB request limit. Error identities are intentionally conservative: timestamps
inside JSON/logfmt fields and varying request IDs can prevent merging.

## Known limitations and verification

The security, level/trace and deduplication/budget stages are recorded in
[REVIEW.md](REVIEW.md), including the remaining redaction limitations. C3, C4 and
I5 reproductions now have regression coverage. Remaining limits include:

- Arbitrary trace formats, Python ExceptionGroup trees, and streams that prepend
  a fresh timestamp/logger header to every frame are not fully supported. Header
  precedence treats each such prefixed line as a new event. Unstructured severity
  detection remains heuristic.
- Template-based clustering of lower-severity messages remains lossy. Error
  clustering does not merge differing diagnostic values just to increase compression.
  Memory use on large inputs and non-UTF-8 input handling remain unchanged.
- Tier 2's builtin pruner can damage JSON or alter YAML values. The existing
  neural model path is known to fail, lacks a subprocess timeout and has unpinned
  dependencies. Only explicit `-2` can attempt it; no real neural run was used to
  validate this stage.
- Output handling on a broken pipe remains an open issue.

Regression tests use fake secrets, isolated temporary HOME/config directories,
loopback HTTP stubs and fake uv executables in both discovery locations. Reviewed
bypasses involving ampersands, unterminated quotes and JSON-escaped URLs, plus YAML
flow scalar boundaries and comma-separated diagnostic fields, have exact stdout,
idempotence and outbound-request regression coverage. The tests
check exact output, outbound authorization/redaction, UTF-8 byte limits, no auto
connections/processes, safe errors, redirects and strict configuration loading.
Level and trace tests also compare handwritten text/JSON goldens, klog event
counts, chained exceptions, new-record boundaries and stacks longer than 30 lines.
Deduplication/budget tests cover HTTP outcomes, nonadjacent repeated stacks, source
order in a 1000-event stream, dense errors, 250-frame stacks, tiny budgets,
deterministic summaries and identical text/JSON selection.

```bash
set -euo pipefail
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

License: MIT OR Apache-2.0; see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
