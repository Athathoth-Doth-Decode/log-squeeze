//! Event severity and record boundaries, independent of stack continuation lines.
use crate::masker::LogLevel;
use regex::Regex;
use std::sync::LazyLock;

static KLOG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([IWEF])\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\d+\s+[^\s]+:\d+\]").unwrap()
});
static TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:(?:\d{4}[-/.]\d{2}[-/.]\d{2}[T ]|\d{2}[./]\d{2}[./]\d{4} )?\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(?:\s+|[-|:]|$)").unwrap()
});
static SYSLOG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|Янв|Фев|Мар|Апр|Май|Июн|Июл|Авг|Сен|Окт|Ноя|Дек)[a-zа-яё.]*\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:\s*").unwrap()
});
static TEXT_LEVEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(PANIC|FATAL|CRITICAL|ERROR|ERR|WARNING|WARN|INFO|DEBUG|TRACE)\b(?:\s|[:|-]|$)",
    )
    .unwrap()
});
static PANIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:panic|panicked)\b").unwrap());
static FATAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:fatal|critical)\b").unwrap());
static ERROR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:error|exception|failed|failure|fail|oomkilled|segfault|segmentation fault|out of memory|killed process|KeyboardInterrupt|SystemExit)\b|\b[A-Za-z_][\w.]*(?:Error|Exception):").unwrap()
});
static EXCEPTION_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*(?:Error|Exception)$").unwrap()
});
static WARN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:warn|warning)\b").unwrap());

fn named_level(value: &str) -> Option<LogLevel> {
    match value.to_ascii_lowercase().as_str() {
        "panic" => Some(LogLevel::Panic),
        "fatal" | "critical" | "60" => Some(LogLevel::Fatal),
        "error" | "err" | "50" => Some(LogLevel::Error),
        "warn" | "warning" | "40" => Some(LogLevel::Warn),
        "info" | "information" | "notice" | "30" => Some(LogLevel::Info),
        "debug" | "20" => Some(LogLevel::Debug),
        "trace" | "10" => Some(LogLevel::Trace),
        _ => None,
    }
}

/// Prefer top-level JSON severity over words contained in a message or nested object.
/// Pino numeric values use their documented ten-through-sixty severity scale.
/// An unrecognized explicit value remains Unknown instead of promoting message text.
fn json_level(line: &str) -> Option<LogLevel> {
    if !line.starts_with('{') {
        return None;
    }
    let object: serde_json::Value = serde_json::from_str(line).ok()?;
    for key in ["level", "severity", "log.level"] {
        if let Some(value) = object.get(key) {
            return Some(
                match value {
                    serde_json::Value::String(text) => named_level(text),
                    serde_json::Value::Number(number) => named_level(&number.to_string()),
                    _ => None,
                }
                .unwrap_or(LogLevel::Unknown),
            );
        }
    }
    None
}

/// Scan logfmt tokens while respecting quoted message values and their escapes.
/// Only actual level/severity assignments can select a level, never text inside msg.
/// Other tokens remain uninterpreted so the original log text stays intact.
fn logfmt_level(line: &str) -> Option<LogLevel> {
    let mut quote = None;
    let mut escaped = false;
    let mut start = 0;
    for (i, c) in line
        .char_indices()
        .chain(std::iter::once((line.len(), ' ')))
    {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == delimiter {
                quote = None;
            }
        } else if matches!(c, '"' | '\'') {
            quote = Some(c);
        } else if c.is_whitespace() {
            if let Some((key, value)) = line[start..i].split_once('=')
                && matches!(
                    key.to_ascii_lowercase().as_str(),
                    "level" | "severity" | "log.level"
                )
            {
                return Some(
                    named_level(value.trim_matches(['"', '\''])).unwrap_or(LogLevel::Unknown),
                );
            }
            start = i + c.len_utf8();
        }
    }
    None
}

/// Examine bracketed header tokens in order instead of skipping a recognized level.
/// Thread labels may precede the level, but words after that level are only message text.
/// Numeric bracket contents are treated as labels, not as Pino severity codes.
fn text_level(mut message: &str) -> Option<LogLevel> {
    for _ in 0..4 {
        if let Some(rest) = message.strip_prefix('[') {
            let end = rest.find(']')?;
            let label = &rest[..end];
            if label.bytes().any(|byte| byte.is_ascii_alphabetic())
                && let Some(level) = named_level(label)
            {
                return Some(level);
            }
            message = skip_header_separators(&rest[end + 1..]);
        } else {
            return TEXT_LEVEL
                .captures(message)
                .and_then(|caps| named_level(&caps[1]));
        }
    }
    None
}

fn skip_header_separators(text: &str) -> &str {
    text.trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '-' | '|' | ':'))
}

/// Recognize severity in structured fields or at the beginning of a log header.
/// Timestamp and thread prefixes are removed only for examining that header.
/// The rest of the message cannot override a recognized explicit level.
pub(crate) fn explicit_level(line: &str) -> Option<LogLevel> {
    let line = line.trim_start();
    if let Some(level) = json_level(line) {
        return Some(level);
    }
    if let Some(caps) = KLOG.captures(line) {
        return Some(match &caps[1] {
            "I" => LogLevel::Info,
            "W" => LogLevel::Warn,
            "E" => LogLevel::Error,
            _ => LogLevel::Fatal,
        });
    }
    let message = TIMESTAMP
        .find(line)
        .or_else(|| SYSLOG.find(line))
        .map_or(line, |prefix| skip_header_separators(&line[prefix.end()..]));
    text_level(message).or_else(|| logfmt_level(line))
}

pub(crate) fn has_record_prefix(line: &str) -> bool {
    let trimmed = line.trim_start();
    KLOG.is_match(trimmed) || TIMESTAMP.is_match(trimmed) || SYSLOG.is_match(trimmed)
}

pub(crate) fn has_event_header(line: &str) -> bool {
    has_record_prefix(line)
        || explicit_level(line).is_some()
        || (line.starts_with('{') && serde_json::from_str::<serde_json::Value>(line).is_ok())
}

/// Use explicit severity before applying conservative unstructured-message heuristics.
/// Whole-word diagnostics recognize failures and kernel crashes without matching failover or paths like /errors.
/// Stack collectors call this only for event heads so frame names cannot inflate error counts.
pub fn detect_level(line: &str) -> LogLevel {
    if let Some(level) = explicit_level(line) {
        return level;
    }
    if PANIC.is_match(line) {
        LogLevel::Panic
    } else if FATAL.is_match(line) {
        LogLevel::Fatal
    } else if ERROR.is_match(line)
        || EXCEPTION_NAME.is_match(line.trim())
        || line
            .trim_start()
            .starts_with("Traceback (most recent call last):")
    {
        LogLevel::Error
    } else if WARN.is_match(line) {
        LogLevel::Warn
    } else {
        LogLevel::Unknown
    }
}
