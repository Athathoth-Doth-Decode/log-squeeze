use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

// ----------------------------------------------------------------------------
// Log Level
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LogLevel {
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
    /// Determines whether the log level represents an error, panic, or warning condition.
    /// This is used by the pipeline to decide whether to attach stack traces and retain
    /// events during budget filtering when non-error logs are downsampled.
    pub fn is_error_or_warn(&self) -> bool {
        matches!(
            self,
            LogLevel::Panic | LogLevel::Fatal | LogLevel::Error | LogLevel::Warn
        )
    }

    /// Returns a static string representation of the log level for rendering and CLI display.
    /// This function returns a borrowed static literal without allocating heap memory,
    /// ensuring zero runtime memory overhead during rapid stream processing.
    pub fn as_str(&self) -> &'static str {
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
// Tier 1: Multi-Locale Masker & Deduplicator
// ----------------------------------------------------------------------------

pub struct Masker {
    re_full_date_time: Regex,
    re_syslog_time: Regex,
    re_time_only: Regex,
    re_date_only: Regex,
    re_uuid: Regex,
    re_ipv4: Regex,
    re_ipv6: Regex,
    re_hex: Regex,
    re_hash: Regex,
    re_duration_bytes: Regex,
    re_num: Regex,
}

impl Masker {
    /// Compiles all regular expression patterns used for masking dynamic log entities.
    /// Supports internationalized date/time formats (ISO 8601, European DD.MM.YYYY, Russian months in syslog),
    /// decimal commas in floating-point numbers, and localized unit measurements (ms, sec, мс, МБ).
    pub fn new() -> Self {
        Self {
            // Full Date + Time (ISO 8601: 2026-08-24T13:25:53, RU/EU: 24.08.2026 13:25:53 or 24/08/2026 13:25:53)
            re_full_date_time: Regex::new(
                r"\b(?:\d{4}[-/.]\d{2}[-/.]\d{2}|\d{2}[-/.]\d{2}[-/.]\d{4})[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
            ).unwrap(),
            // Syslog timestamp with English and Russian month abbreviations (e.g. Aug 24 13:25:53, Авг 24 13:25:53)
            re_syslog_time: Regex::new(
                r"(?i)\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|Янв|Фев|Мар|Апр|Май|Июн|Июл|Авг|Сен|Окт|Ноя|Дек)[a-яa-z.]*\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"
            ).unwrap(),
            // Time only (13:25:53 or 13:25:53.123456)
            re_time_only: Regex::new(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b").unwrap(),
            // Date only (2026-08-24 or 24.08.2026)
            re_date_only: Regex::new(r"\b(?:\d{4}-\d{2}-\d{2}|\d{2}\.\d{2}\.\d{4})\b").unwrap(),
            // UUID (8-4-4-4-12)
            re_uuid: Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b").unwrap(),
            // IPv4 address with optional port
            re_ipv4: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{1,5})?\b").unwrap(),
            // IPv6 address
            re_ipv6: Regex::new(r"\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){4,7}\b").unwrap(),
            // Hex memory address
            re_hex: Regex::new(r"\b0x[0-9a-fA-F]+\b").unwrap(),
            // SHA/MD5 hashes (32 to 64 hex characters)
            re_hash: Regex::new(r"\b[0-9a-fA-F]{32,64}\b").unwrap(),
            // Durations, latencies, memory and disk sizes (supporting dot and comma, plus Latin and Cyrillic units)
            re_duration_bytes: Regex::new(
                r"(?i)\b\d+(?:[.,]\d+)?\s*(?:ms|µs|ns|s|sec|m|min|h|MB|GB|KB|TB|B|MiB|GiB|KiB|мс|мкс|нс|сек|с|мин|ч|МБ|ГБ|КБ|ТБ|Б|байт)\b"
            ).unwrap(),
            // Generic numbers
            re_num: Regex::new(r"\b\d+\b").unwrap(),
        }
    }

    /// Replaces high-cardinality dynamic entities in a raw log line with standardized tokens.
    /// Transforms dynamic timestamps, network addresses, identifiers, and measurements into
    /// uniform cluster templates (e.g. `<TIME>`, `<IP>`, `<UUID>`, `<VAL>`, `<N>`).
    pub fn mask(&self, line: &str) -> String {
        let s = self.re_full_date_time.replace_all(line, "<TIME>");
        let s = self.re_syslog_time.replace_all(&s, "<TIME>");
        let s = self.re_time_only.replace_all(&s, "<TIME>");
        let s = self.re_date_only.replace_all(&s, "<DATE>");
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

impl Default for Masker {
    fn default() -> Self {
        Self::new()
    }
}

/// Detects the semantic log level of a single log line using case-insensitive keyword inspection.
/// Categorizes lines into Panic, Fatal, Error, Warn, Info, Debug, Trace, or Unknown.
pub fn detect_level(line: &str) -> LogLevel {
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

/// Checks if a log line is part of a multi-line language exception stack trace.
/// Supports standard stack trace formats for Python tracebacks, Go goroutines,
/// Java caused-by exceptions, Rust source backtraces, and Node.js call stacks.
pub fn is_stack_trace_line(line: &str) -> bool {
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
pub struct EventCluster {
    pub template: String,
    pub level: LogLevel,
    pub count: usize,
    pub first_example: String,
    pub last_example: String,
    pub stack_trace: Vec<String>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct SqueezeStats {
    pub total_lines: usize,
    pub output_lines: usize,
    pub panics: usize,
    pub fatals: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub debugs: usize,
    pub traces: usize,
    pub unknowns: usize,
}

impl SqueezeStats {
    pub fn record_level(&mut self, level: LogLevel) {
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

    pub fn total_errors_and_warns(&self) -> usize {
        self.panics + self.fatals + self.errors + self.warnings
    }
}

pub struct FastSqueezeResult {
    pub stats: SqueezeStats,
    pub clusters: Vec<EventCluster>,
    pub rendered_output: String,
    pub is_structured_code_heuristic: bool,
}

/// Executes Tier 1 fast deterministic stream compression on any buffered reader.
/// Masks dynamic tokens, deduplicates consecutive events into occurrences count `[xN]`,
/// attaches and preserves stack traces, and renders compressed output within budget limits.
pub fn run_fast_squeeze<R: BufRead>(
    reader: R,
    max_lines: usize,
    errors_only: bool,
    summary_only: bool,
) -> io::Result<FastSqueezeResult> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masker_russian_syslog_and_metrics() {
        let masker = Masker::new();

        // Russian syslog timestamp
        let line1 = "Авг 24 13:25:53 app-00 systemd[1]: Started Service.";
        let masked1 = masker.mask(line1);
        assert_eq!(masked1, "<TIME> app-<N> systemd[<N>]: Started Service.");

        // Russian duration and bytes with comma
        let line2 = "Запрос выполнен за 14,5 мс, передано 2,4 МБ данных на 10.254.3.99:5432";
        let masked2 = masker.mask(line2);
        assert_eq!(masked2, "Запрос выполнен за <VAL>, передано <VAL> данных на <IP>");

        // European date format DD.MM.YYYY
        let line3 = "24.08.2026 13:25:53.123 [main] ERROR - Failed to connect";
        let masked3 = masker.mask(line3);
        assert_eq!(masked3, "<TIME> [main] ERROR - Failed to connect");
    }

    #[test]
    fn test_stack_trace_detection() {
        assert!(is_stack_trace_line("  at java.base/sun.nio.ch.NioSocketImpl.connect(NioSocketImpl.java:567)"));
        assert!(is_stack_trace_line("Caused by: java.net.SocketTimeoutException: connect timed out"));
        assert!(is_stack_trace_line("Traceback (most recent call last):"));
        assert!(is_stack_trace_line("  File \"server.py\", line 42, in handle_req"));
        assert!(is_stack_trace_line("goroutine 1 [running]:"));
        assert!(!is_stack_trace_line("2026-08-24T12:00:00Z INFO Server started on port 8080"));
    }

    #[test]
    fn test_fast_squeeze_deduplication() {
        let input = "\
2026-08-24T12:00:01Z [INFO] GET /api/v1/health 200 2.5ms
2026-08-24T12:00:02Z [INFO] GET /api/v1/health 200 3.1ms
2026-08-24T12:00:03Z [INFO] GET /api/v1/health 200 1.9ms
2026-08-24T12:00:04Z [ERROR] Failed to connect to database
  at org.postgresql.Driver.connect(Driver.java:260)
";
        let reader = io::Cursor::new(input.as_bytes());
        let res = run_fast_squeeze(reader, 200, false, false).unwrap();

        assert_eq!(res.stats.total_lines, 5);
        assert_eq!(res.stats.infos, 3);
        assert_eq!(res.stats.errors, 1);
        assert!(res.rendered_output.contains("[x3] [INFO]"));
        assert!(res.rendered_output.contains("Stack Trace (1 lines)"));
    }
}
