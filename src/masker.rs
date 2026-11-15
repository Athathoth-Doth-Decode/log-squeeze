use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{self, BufRead};

// ----------------------------------------------------------------------------
// Log Level
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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

    /// Redact secrets before replacing dynamic entities with standardized template tokens.
    /// Timestamps, addresses, identifiers and measurements use their existing placeholders.
    /// Standalone numbers in the HTTP status range remain visible instead of becoming `<N>`.
    pub fn mask(&self, line: &str) -> String {
        let redacted = crate::redact::redact(line);
        let s = self.re_full_date_time.replace_all(&redacted, "<TIME>");
        let s = self.re_syslog_time.replace_all(&s, "<TIME>");
        let s = self.re_time_only.replace_all(&s, "<TIME>");
        let s = self.re_date_only.replace_all(&s, "<DATE>");
        let s = self.re_uuid.replace_all(&s, "<UUID>");
        let s = self.re_ipv4.replace_all(&s, "<IP>");
        let s = self.re_ipv6.replace_all(&s, "<IPV6>");
        let s = self.re_hex.replace_all(&s, "<HEX>");
        let s = self.re_hash.replace_all(&s, "<HASH>");
        let s = self.re_duration_bytes.replace_all(&s, "<VAL>");
        // WHY: Borrow regex captures only while deciding whether this number is an HTTP code.
        let s = self.re_num.replace_all(&s, |caps: &regex::Captures<'_>| {
            let number = &caps[0];
            if number.len() == 3 && matches!(number.parse::<u16>(), Ok(100..=599)) {
                number.to_owned()
            } else {
                "<N>".to_owned()
            }
        });
        s.into_owned()
    }

    /// Error identities normalize volatile values that never distinguish one failure from another:
    /// timestamps anywhere in the line (JSON `ts`, logfmt `time=`), UUIDs, hex addresses, hashes,
    /// durations and sizes. Plain numbers, error codes and IP addresses stay distinct.
    fn diagnostic_identity(&self, line: &str) -> String {
        let identity = self.leading_identity(line);
        let s = self.re_full_date_time.replace_all(&identity, "<TIME>");
        let s = self.re_syslog_time.replace_all(&s, "<TIME>");
        let s = self.re_time_only.replace_all(&s, "<TIME>");
        let s = self.re_uuid.replace_all(&s, "<UUID>");
        let s = self.re_hex.replace_all(&s, "<HEX>");
        let s = self.re_hash.replace_all(&s, "<HASH>");
        self.re_duration_bytes.replace_all(&s, "<VAL>").into_owned()
    }

    /// Klog's date/time prefix is volatile while its severity, source and message are retained.
    fn leading_identity(&self, line: &str) -> String {
        let line = line.trim();
        let klog = line.len() > 5
            && matches!(line.as_bytes()[0], b'I' | b'W' | b'E' | b'F')
            && line.as_bytes()[1..5].iter().all(u8::is_ascii_digit)
            && line.as_bytes()[5].is_ascii_whitespace();
        let message = if klog { line[5..].trim_start() } else { line };
        for pattern in [
            &self.re_full_date_time,
            &self.re_syslog_time,
            &self.re_time_only,
        ] {
            if let Some(timestamp) = pattern.find(message).filter(|found| found.start() == 0) {
                let prefix = if klog { &line[..1] } else { "" };
                return format!("{prefix}<TIME>{}", &message[timestamp.end()..]);
            }
        }
        line.to_owned()
    }

    fn stack_identity(&self, line: &str) -> String {
        if crate::trace::is_location_frame(line) {
            self.re_num
                .replace_all(&self.mask(line), "<N>")
                .into_owned()
        } else {
            line.to_owned()
        }
    }
}

impl Default for Masker {
    fn default() -> Self {
        Self::new()
    }
}

pub use crate::levels::detect_level;
pub use crate::trace::is_stack_trace_line;
use crate::trace::{EventParser, ParsedEvent};

#[derive(Debug, Clone, Serialize)]
pub struct EventCluster {
    pub template: String,
    pub level: LogLevel,
    pub count: usize,
    pub first_example: String,
    pub last_example: String,
    pub stack_trace: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub skipped_before: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub omitted_stack_lines: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
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
    pub budget: crate::output::BudgetStats,
}

#[derive(PartialEq, Eq, Hash)]
struct ClusterKey {
    level: LogLevel,
    head: String,
    stack: Vec<String>,
}

/// Complete events are globally indexed by severity, diagnostic identity and stack shape.
/// The vector retains first-occurrence order while repeat counts and last examples update in place.
/// Error summaries keep semantic values even when a generic display template masks those values.
fn collect_event(
    event: ParsedEvent,
    masker: &Masker,
    stats: &mut SqueezeStats,
    templates: &mut HashMap<String, usize>,
    index: &mut HashMap<ClusterKey, usize>,
    clusters: &mut Vec<EventCluster>,
) {
    stats.record_level(event.level);
    let template = masker.mask(event.head.trim());
    let head = if event.level.is_error_or_warn() {
        masker.diagnostic_identity(&event.head)
    } else {
        template.clone()
    };
    *templates.entry(head.clone()).or_default() += 1;
    let key = ClusterKey {
        level: event.level,
        head,
        stack: event
            .stack
            .iter()
            .map(|line| masker.stack_identity(line))
            .collect(),
    };
    if let Some(&position) = index.get(&key) {
        clusters[position].count += 1;
        clusters[position].last_example = event.head;
        return;
    }
    index.insert(key, clusters.len());
    clusters.push(EventCluster {
        template,
        level: event.level,
        count: 1,
        first_example: event.head.clone(),
        last_example: event.head,
        stack_trace: event.stack,
        skipped_before: 0,
        omitted_stack_lines: 0,
    });
}

/// Redact and assemble complete events before globally clustering their repetitions.
/// Filter requested severities before selecting output in first-occurrence order.
/// Rendering enforces a physical line budget and reports all omitted events and stack lines.
pub fn run_fast_squeeze<R: BufRead>(
    reader: R,
    max_lines: usize,
    errors_only: bool,
    summary_only: bool,
) -> io::Result<FastSqueezeResult> {
    if max_lines == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "max_lines must be positive",
        ));
    }
    let masker = Masker::new();
    let mut stats = SqueezeStats::default();
    let mut clusters = Vec::new();
    let mut index = HashMap::new();
    let mut templates = HashMap::new();
    let mut parser = EventParser::default();
    for line in reader.lines() {
        let line = crate::redact::redact(&line?);
        stats.total_lines += 1;
        if let Some(event) = parser.push(line) {
            collect_event(
                event,
                &masker,
                &mut stats,
                &mut templates,
                &mut index,
                &mut clusters,
            );
        }
    }
    if let Some(event) = parser.finish() {
        collect_event(
            event,
            &masker,
            &mut stats,
            &mut templates,
            &mut index,
            &mut clusters,
        );
    }
    let clusters: Vec<_> = clusters
        .into_iter()
        .filter(|cluster| !errors_only || cluster.level.is_error_or_warn())
        .collect();
    let is_code = stats.total_lines > 20 && stats.unknowns as f64 / stats.total_lines as f64 > 0.85;
    let (clusters, rendered_output, budget) = if summary_only {
        let (rendered, budget) =
            crate::output::render_summary(clusters.len(), templates, &mut stats, max_lines);
        (clusters, rendered, budget)
    } else {
        crate::output::render_events(clusters, &mut stats, max_lines)
    };
    Ok(FastSqueezeResult {
        stats,
        clusters,
        rendered_output,
        is_structured_code_heuristic: is_code,
        budget,
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
        assert_eq!(
            masked2,
            "Запрос выполнен за <VAL>, передано <VAL> данных на <IP>"
        );

        // European date format DD.MM.YYYY
        let line3 = "24.08.2026 13:25:53.123 [main] ERROR - Failed to connect";
        let masked3 = masker.mask(line3);
        assert_eq!(masked3, "<TIME> [main] ERROR - Failed to connect");
    }

    #[test]
    fn test_stack_trace_detection() {
        assert!(is_stack_trace_line(
            "  at java.base/sun.nio.ch.NioSocketImpl.connect(NioSocketImpl.java:567)"
        ));
        assert!(is_stack_trace_line(
            "Caused by: java.net.SocketTimeoutException: connect timed out"
        ));
        assert!(is_stack_trace_line("Traceback (most recent call last):"));
        assert!(is_stack_trace_line(
            "  File \"server.py\", line 42, in handle_req"
        ));
        assert!(is_stack_trace_line("goroutine 1 [running]:"));
        assert!(!is_stack_trace_line(
            "2026-08-24T12:00:00Z INFO Server started on port 8080"
        ));
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
