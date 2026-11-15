//! Assemble redacted event heads and their language-specific continuation blocks.
use crate::levels::{detect_level, has_event_header, has_record_prefix};
use crate::masker::LogLevel;
use regex::Regex;
use std::sync::LazyLock;

const PYTHON_HEAD: &str = "Traceback (most recent call last):";
static AT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[ \t]+at[ \t]+\S").unwrap());
static PY_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^[ \t]+File "[^"]+", line \d+(?:, in .*)?$"#).unwrap());
static GO_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[ \t]+\S+\.go:\d+(?:\s|$)").unwrap());
static GO_ROUTINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^goroutine \d+ \[[^\]]+\]:$").unwrap());
static GO_FUNCTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[\w./*()\[\]-]+\([^)]*\)(?:\s+.*)?$").unwrap());
static RUST_FRAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*\d+:\s+\S").unwrap());
static JAVA_CAUSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:Caused by|Suppressed):\s+\S").unwrap());
static JAVA_MORE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s+\.\.\. \d+ (?:more|common frames omitted)$").unwrap());
static PY_EXCEPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][\w.]*(?::.*)?$").unwrap());
static NODE_PROPERTY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^[ \t]+(?:[A-Za-z_$][\w$.-]*|"[^"]+"|'[^']+')[ \t]*:"#).unwrap()
});

pub(crate) fn is_location_frame(line: &str) -> bool {
    AT.is_match(line)
        || PY_FILE.is_match(line)
        || GO_FILE.is_match(line)
        || GO_ROUTINE.is_match(line.trim())
        || RUST_FRAME.is_match(line)
}

pub fn is_stack_trace_line(line: &str) -> bool {
    !has_event_header(line)
        && (AT.is_match(line)
            || PY_FILE.is_match(line)
            || GO_FILE.is_match(line)
            || GO_ROUTINE.is_match(line.trim())
            || RUST_FRAME.is_match(line)
            || JAVA_CAUSE.is_match(line)
            || JAVA_MORE.is_match(line)
            || line.trim() == PYTHON_HEAD)
}

pub(crate) struct ParsedEvent {
    pub head: String,
    pub level: LogLevel,
    pub stack: Vec<String>,
}

#[derive(Default, Clone, Copy)]
enum TraceKind {
    #[default]
    None,
    Java,
    Python {
        source_after_indent: Option<usize>,
    },
    PythonDone,
    PythonChain,
    Go,
    Rust {
        message_pending: bool,
    },
    NodeObject {
        depth: usize,
    },
    Closed,
}

#[derive(Default)]
pub(crate) struct EventParser {
    current: Option<ParsedEvent>,
    kind: TraceKind,
    blanks: Vec<String>,
}

impl EventParser {
    /// Delay each event until its continuation block has been recognized completely.
    /// Blank separators are retained only when another frame or chained exception follows.
    /// New headers and unrelated text flush the event without consuming any of the next record.
    pub fn push(&mut self, line: String) -> Option<ParsedEvent> {
        if line.trim().is_empty() {
            if self
                .current
                .as_ref()
                .is_some_and(|event| event.level.is_error_or_warn())
            {
                self.blanks.push(line);
            }
            return None;
        }
        if self.continues(&line) {
            let event = self.current.as_mut().unwrap();
            event.stack.append(&mut self.blanks);
            event.stack.push(line);
            return None;
        }
        self.blanks.clear();
        let level = detect_level(&line);
        self.kind = initial_kind(&line, level);
        self.current.replace(ParsedEvent {
            head: line,
            level,
            stack: Vec::new(),
        })
    }

    pub fn finish(self) -> Option<ParsedEvent> {
        self.current
    }

    /// Apply the active language's continuation grammar before classifying any frame text.
    /// Record prefixes always end a stack, while source slots and object properties may contain severity words.
    /// Terminal exceptions and closing object braces prevent an unrelated later trace from merging.
    fn continues(&mut self, line: &str) -> bool {
        if !self
            .current
            .as_ref()
            .is_some_and(|event| event.level.is_error_or_warn())
            || has_record_prefix(line)
        {
            return false;
        }
        let python_source = matches!(self.kind, TraceKind::Python { source_after_indent: Some(indent) }
            if indentation(line) > indent && !PY_FILE.is_match(line));
        let node_property =
            matches!(self.kind, TraceKind::NodeObject { .. }) && NODE_PROPERTY.is_match(line);
        if has_event_header(line) && !python_source && !node_property {
            return false;
        }
        let trimmed = line.trim();
        match self.kind {
            TraceKind::None => self.start_trace(line),
            TraceKind::Java => {
                if AT.is_match(line) || JAVA_CAUSE.is_match(line) || JAVA_MORE.is_match(line) {
                    if trimmed.ends_with('{') {
                        self.kind = TraceKind::NodeObject { depth: 1 };
                    }
                    true
                } else if trimmed == "{" {
                    self.kind = TraceKind::NodeObject { depth: 1 };
                    true
                } else {
                    false
                }
            }
            TraceKind::Python { .. } => {
                if PY_FILE.is_match(line) {
                    self.kind = TraceKind::Python {
                        source_after_indent: Some(indentation(line)),
                    };
                    true
                } else if line.starts_with([' ', '\t']) {
                    // A File frame licenses one source line, then only normal continuation rules apply.
                    self.kind = TraceKind::Python {
                        source_after_indent: None,
                    };
                    true
                } else if PY_EXCEPTION.is_match(line) {
                    self.kind = TraceKind::PythonDone;
                    true
                } else {
                    false
                }
            }
            TraceKind::PythonDone => {
                if matches!(
                    trimmed,
                    "During handling of the above exception, another exception occurred:"
                        | "The above exception was the direct cause of the following exception:"
                ) {
                    self.kind = TraceKind::PythonChain;
                    true
                } else {
                    false
                }
            }
            TraceKind::PythonChain => {
                if trimmed == PYTHON_HEAD {
                    self.kind = TraceKind::Python {
                        source_after_indent: None,
                    };
                    true
                } else {
                    false
                }
            }
            TraceKind::Go => {
                if trimmed.starts_with("exit status ") {
                    self.kind = TraceKind::Closed;
                    true
                } else {
                    GO_ROUTINE.is_match(trimmed)
                        || GO_FUNCTION.is_match(trimmed)
                        || GO_FILE.is_match(line)
                        || trimmed.starts_with("[signal ")
                        || trimmed.starts_with("created by ")
                        || trimmed == "runtime stack:"
                }
            }
            TraceKind::Rust { message_pending } => {
                let known = trimmed == "stack backtrace:"
                    || RUST_FRAME.is_match(line)
                    || AT.is_match(line)
                    || trimmed.starts_with("note: ");
                if message_pending || known {
                    self.kind = TraceKind::Rust {
                        message_pending: false,
                    };
                    true
                } else {
                    false
                }
            }
            TraceKind::NodeObject { depth } => {
                if !line.starts_with([' ', '\t']) && !trimmed.starts_with('}') {
                    return false;
                }
                let (opened, closed) = object_braces(line);
                let depth = (depth + opened).saturating_sub(closed);
                self.kind = if depth == 0 {
                    TraceKind::Closed
                } else {
                    TraceKind::NodeObject { depth }
                };
                true
            }
            TraceKind::Closed => false,
        }
    }

    /// An error head can be followed by a recognizable language-specific trace opener.
    /// Openers determine which continuation grammar is used for subsequent lines.
    /// Ordinary file mentions and unindented prose cannot start a trace.
    fn start_trace(&mut self, line: &str) -> bool {
        let trimmed = line.trim();
        self.kind = if trimmed == PYTHON_HEAD {
            TraceKind::Python {
                source_after_indent: None,
            }
        } else if GO_ROUTINE.is_match(trimmed) {
            TraceKind::Go
        } else if trimmed == "stack backtrace:" {
            TraceKind::Rust {
                message_pending: false,
            }
        } else if AT.is_match(line) || JAVA_CAUSE.is_match(line) || JAVA_MORE.is_match(line) {
            if trimmed.ends_with('{') {
                TraceKind::NodeObject { depth: 1 }
            } else {
                TraceKind::Java
            }
        } else {
            return false;
        };
        true
    }
}

/// Set a trace grammar when an event starts with a crash or traceback header.
/// The parent severity is determined once and inherited by every attached frame.
/// Rust's separate panic-message line is accepted only when the header ends in a colon.
fn initial_kind(line: &str, level: LogLevel) -> TraceKind {
    let trimmed = line.trim();
    if !level.is_error_or_warn() {
        return TraceKind::None;
    }
    if trimmed == PYTHON_HEAD {
        TraceKind::Python {
            source_after_indent: None,
        }
    } else if trimmed.starts_with("panic:")
        || trimmed.starts_with("fatal error:")
        || GO_ROUTINE.is_match(trimmed)
    {
        TraceKind::Go
    } else if trimmed.starts_with("thread ") && trimmed.contains("panicked at") {
        TraceKind::Rust {
            message_pending: trimmed.ends_with(':'),
        }
    } else if trimmed.starts_with("Error:") && trimmed.ends_with('{') {
        TraceKind::NodeObject { depth: 1 }
    } else {
        TraceKind::None
    }
}

fn indentation(line: &str) -> usize {
    line.bytes()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count()
}

/// Count only structural braces in Node diagnostic object lines.
/// Quotes and escapes prevent braces inside a property value from ending the block.
/// The caller retains all object lines until the matching closing brace arrives.
fn object_braces(line: &str) -> (usize, usize) {
    let (mut opened, mut closed) = (0, 0);
    let mut quote = None;
    let mut escaped = false;
    for c in line.chars() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == delimiter {
                quote = None;
            }
        } else {
            match c {
                '\'' | '"' => quote = Some(c),
                '{' => opened += 1,
                '}' => closed += 1,
                _ => {}
            }
        }
    }
    (opened, closed)
}
