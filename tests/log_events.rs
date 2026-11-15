use log_squeeze::masker::{LogLevel, detect_level, is_stack_trace_line, run_fast_squeeze};
use std::io::Cursor;

// Explicit levels describe the event even when its message mentions a more severe word.
// Structured fields, Pino numeric levels and klog prefixes take precedence over heuristics.
// Unstructured diagnostics use whole tokens and known crash signatures instead of substrings.
#[test]
fn explicit_levels_win_over_message_text() {
    for (line, expected) in [
        ("INFO no panic detected", LogLevel::Info),
        ("[INFO] ERROR counter=0", LogLevel::Info),
        ("[INFO][worker] fatal counter=0", LogLevel::Info),
        ("INFO sample payload level=error", LogLevel::Info),
        ("INFO failover test completed, 0 errors", LogLevel::Info),
        ("[WARN] recovered from previous fatal error", LogLevel::Warn),
        (
            "2026-11-07T10:00:00Z [worker] DEBUG error counter=0",
            LogLevel::Debug,
        ),
        ("level=info msg=\"warning panic error\"", LogLevel::Info),
        ("msg=\"level=error\" level=debug", LogLevel::Debug),
        (r#"{"level":30,"msg":"panic: failure"}"#, LogLevel::Info),
        (r#"{"level":"warning","msg":"fatal error"}"#, LogLevel::Warn),
        (
            r#"{"severity":"debug","message":"warning"}"#,
            LogLevel::Debug,
        ),
        (
            "W1107 10:00:00.123456 123 worker.go:42] failed request",
            LogLevel::Warn,
        ),
        (
            "F1107 10:00:00.123456 123 worker.go:42] stopping",
            LogLevel::Fatal,
        ),
        ("GET /api/errors 200", LogLevel::Unknown),
        ("failover completed; error_count=0", LogLevel::Unknown),
        ("informational tracing enabled", LogLevel::Unknown),
        (
            "kernel: Out of memory: Killed process 42 (worker)",
            LogLevel::Error,
        ),
        ("kernel: worker[42]: segfault at 0 ip abc", LogLevel::Error),
        ("pod terminated: OOMKilled", LogLevel::Error),
        ("request failed", LogLevel::Error),
        (
            "thread 'main' panicked at src/main.rs:8:5:",
            LogLevel::Panic,
        ),
    ] {
        assert_eq!(detect_level(line), expected, "{line}");
    }
}

// Source file mentions in an ordinary event do not make it a stack frame.
// Frame matching requires the appropriate position, indentation and language syntax.
// Explicit new-event headers always end the current trace even after an error.
#[test]
fn stack_syntax_does_not_match_ordinary_messages() {
    for line in [
        "I1107 10:00:00.123456 123 worker.go:42] starting",
        "2026-11-07T10:00:00Z ERROR src/main.rs:42: failed",
        "INFO worker.go:42 finished",
        "File not found",
        "at least one worker remains",
        "worker.go:42 is the configured source",
    ] {
        assert!(!is_stack_trace_line(line), "{line}");
    }
    for line in [
        "    at java.base.Socket.connect(Socket.java:42)",
        "\t/work/main.go:12 +0x20",
        "  File \"app.py\", line 7, in <module>",
        "   1: core::result::unwrap_failed",
        "goroutine 1 [running]:",
    ] {
        assert!(is_stack_trace_line(line), "{line}");
    }
}

// Every klog header is a separate event regardless of the source filename it contains.
// Counters must reflect all eight records and never treat records as continuation frames.
// Filtering keeps exactly the three errors and one warning in source order.
#[test]
fn klog_headers_are_independent_events() {
    let input = include_str!("fixtures/events/klog.log");
    let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
    assert_eq!(result.stats.total_lines, 8);
    assert_eq!(
        (
            result.stats.infos,
            result.stats.warnings,
            result.stats.errors
        ),
        (4, 1, 3)
    );
    assert_eq!(
        result
            .clusters
            .iter()
            .map(|event| (
                event.first_example.as_str(),
                event.level,
                event.stack_trace.len()
            ))
            .collect::<Vec<_>>(),
        input
            .lines()
            .zip([
                LogLevel::Info,
                LogLevel::Warn,
                LogLevel::Error,
                LogLevel::Info,
                LogLevel::Error,
                LogLevel::Info,
                LogLevel::Error,
                LogLevel::Info
            ])
            .map(|(line, level)| (line, level, 0))
            .collect::<Vec<_>>()
    );
}

// Stack blocks preserve language frames, internal separators and the terminal exception.
// Completed blocks are counted as single events and keep their original parent severity.
// Following INFO events must remain separate and disappear only when errors-only filters them.
#[test]
fn language_traces_are_complete_error_events() {
    let input = include_str!("fixtures/events/traces.log");
    let result = run_fast_squeeze(Cursor::new(input), 200, true, false).unwrap();
    let expected_heads = [
        "panic: runtime error: invalid memory address or nil pointer dereference",
        "Traceback (most recent call last):",
        "thread 'main' panicked at src/main.rs:8:5:",
        "ERROR database request failed",
        "Error: connect ECONNREFUSED 127.0.0.1:5432",
    ];
    assert_eq!(
        result
            .clusters
            .iter()
            .map(|event| event.first_example.as_str())
            .collect::<Vec<_>>(),
        expected_heads
    );
    assert_eq!(
        result
            .clusters
            .iter()
            .map(|event| event.level)
            .collect::<Vec<_>>(),
        [
            LogLevel::Panic,
            LogLevel::Error,
            LogLevel::Panic,
            LogLevel::Error,
            LogLevel::Error
        ]
    );
    assert_eq!(
        (result.stats.infos, result.stats.panics, result.stats.errors),
        (6, 2, 3)
    );
    let expected_stacks = [
        "[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x123]\n\ngoroutine 1 [running]:\nmain.main()\n\t/work/main.go:12 +0x20\n\ngoroutine 2 [chan receive]:\nmain.worker()\n\t/work/worker.go:8 +0x10\nexit status 2",
        "  File \"app.py\", line 7, in <module>\n    connect(password=\"<REDACTED>\")\n  File \"client.py\", line 3, in connect\n    raise ValueError(\"bad input\")\nValueError: bad input\n\nDuring handling of the above exception, another exception occurred:\n\nTraceback (most recent call last):\n  File \"app.py\", line 9, in <module>\n    raise RuntimeError(\"request failed\")\nRuntimeError: request failed",
        "called `Result::unwrap()` on an `Err` value: password=<REDACTED>\nstack backtrace:\n   0: rust_begin_unwind\n             at /rustc/library/std/src/panicking.rs:692:5\n   1: core::result::unwrap_failed\n             at /rustc/library/core/src/result.rs:1761:5\n   2: app::main\n             at ./src/main.rs:8:5\nnote: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.",
        "    at org.example.Client.open(Client.java:17)\nCaused by: java.net.SocketTimeoutException: timeout\n    at org.example.Socket.read(Socket.java:22)\n    Suppressed: java.io.IOException: cleanup\n        at org.example.Client.close(Client.java:30)\n    ... 2 more",
        "    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1637:16) {\n  errno: -111,\n  code: 'ECONNREFUSED',\n  syscall: 'connect',\n  password: '<REDACTED>',\n  port: 5432\n}",
    ];
    for (event, expected) in result.clusters.iter().zip(expected_stacks) {
        assert_eq!(event.stack_trace.join("\n"), expected);
        assert_eq!(event.count, 1);
        assert_eq!(event.first_example, event.last_example);
    }
}

// Stack length must not silently discard the thirty-first and later frames.
// A subsequent timestamped record terminates the stack even without an explicit level.
// The next warning is counted separately and cannot be absorbed into the previous error.
#[test]
fn long_stack_ends_at_new_header() {
    let frames: Vec<_> = (0..45)
        .map(|i| format!("    at example.Frame.run(Frame.java:{i})"))
        .collect();
    let input = format!(
        "ERROR failed\n{}\n2026-11-07T10:00:00Z worker.go:42 heartbeat\nWARN retrying\n",
        frames.join("\n")
    );
    let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
    assert_eq!(result.clusters.len(), 3);
    assert_eq!(result.clusters[0].stack_trace, frames);
    assert_eq!(
        result.clusters[1].first_example,
        "2026-11-07T10:00:00Z worker.go:42 heartbeat"
    );
    assert_eq!(result.clusters[2].level, LogLevel::Warn);
}

// A finished traceback cannot absorb a later independent exception block.
// A logged error may own the following traceback, and stack text never increments severity counters.
// Compare complete event heads and frames across both attachment and termination boundaries.
#[test]
fn traceback_boundaries_and_parent_levels() {
    let input = "WARN request rejected\nTraceback (most recent call last):\n  File \"a.py\", line 1, in run\n    raise CustomProblem()\nCustomProblem: unavailable\nTraceback (most recent call last):\n  File \"b.py\", line 2, in run\n    raise ValueError()\nValueError: bad input\nINFO recovered\n";
    let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
    assert_eq!(
        result
            .clusters
            .iter()
            .map(|event| (event.first_example.as_str(), event.level))
            .collect::<Vec<_>>(),
        [
            ("WARN request rejected", LogLevel::Warn),
            ("Traceback (most recent call last):", LogLevel::Error),
            ("INFO recovered", LogLevel::Info)
        ]
    );
    assert_eq!(
        result.clusters[0].stack_trace,
        [
            "Traceback (most recent call last):",
            "  File \"a.py\", line 1, in run",
            "    raise CustomProblem()",
            "CustomProblem: unavailable"
        ]
    );
    assert_eq!(
        result.clusters[1].stack_trace,
        [
            "  File \"b.py\", line 2, in run",
            "    raise ValueError()",
            "ValueError: bad input"
        ]
    );
    assert_eq!(
        (
            result.stats.warnings,
            result.stats.errors,
            result.stats.infos
        ),
        (1, 1, 1)
    );
}

// A new explicit header terminates every supported active stack grammar.
// Timestamped records and structured levels are boundaries even when filenames resemble frames.
// Unindented ordinary prose must not be swallowed after Java or Node frames either.
#[test]
fn each_trace_stops_before_a_new_record() {
    for prefix in [
        "ERROR request failed\n    at example.Foo.run(Foo.java:1)\n",
        "panic: unavailable\ngoroutine 1 [running]:\nmain.main()\n",
        "Traceback (most recent call last):\n  File \"a.py\", line 1, in run\n",
        "thread 'main' panicked at src/main.rs:1:1:\n",
        "Error: connect failed\n    at fake.connect (node:net:1:1) {\n",
    ] {
        for header in [
            "I1107 10:00:00.123456 1 worker.go:42] ready",
            "2026-11-07T10:00:00Z heartbeat",
            "level=info msg=\"no panic\"",
            "{\"level\":30,\"msg\":\"ready\"}",
        ] {
            let input = format!("{prefix}{header}\n");
            let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
            assert_eq!(result.clusters.len(), 2);
            assert_eq!(result.clusters[1].first_example, header);
            assert_eq!(result.clusters[1].stack_trace, Vec::<String>::new());
        }
    }
    let input = "ERROR failed\n    at example.Frame.run(Frame.java:1)\nFile not found\nat least one worker remains\n";
    let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
    assert_eq!(
        result
            .clusters
            .iter()
            .map(|event| event.first_example.as_str())
            .collect::<Vec<_>>(),
        [
            "ERROR failed",
            "File not found",
            "at least one worker remains"
        ]
    );
}

// Same-looking error heads with different stacks are still independent complete events.
// Event assembly happens before the global deduplication step.
// Neither the first nor the later stack can be lost by merging an unfinished header.
#[test]
fn repeated_heads_do_not_lose_their_stacks() {
    let input = "ERROR failed\nERROR failed\n    at example.One.run(One.java:1)\nERROR failed\n    at example.Two.run(Two.java:2)\n";
    let result = run_fast_squeeze(Cursor::new(input), 200, true, false).unwrap();
    assert_eq!(
        result
            .clusters
            .iter()
            .map(|event| event.count)
            .collect::<Vec<_>>(),
        [1, 1, 1]
    );
    assert_eq!(result.clusters[0].stack_trace, Vec::<String>::new());
    assert_eq!(
        result.clusters[1].stack_trace,
        ["    at example.One.run(One.java:1)"]
    );
    assert_eq!(
        result.clusters[2].stack_trace,
        ["    at example.Two.run(Two.java:2)"]
    );
}

// Only top-level structured fields select severity; unknown explicit values stay Unknown.
// Pino numeric levels and syslog-prefixed text levels retain their exact mappings.
// Message keywords, quoted logfmt content and nested JSON objects cannot override them.
#[test]
fn structured_levels_and_syslog_prefixes() {
    for (line, level) in [
        (r#"{"level":10,"msg":"error"}"#, LogLevel::Trace),
        (r#"{"level":20,"msg":"error"}"#, LogLevel::Debug),
        (r#"{"level":40,"msg":"error"}"#, LogLevel::Warn),
        (r#"{"level":50,"msg":"panic"}"#, LogLevel::Error),
        (r#"{"level":60,"msg":"info"}"#, LogLevel::Fatal),
        (r#"{"level":99,"msg":"panic"}"#, LogLevel::Unknown),
        (
            r#"{"level":"info","nested":{"level":"error"},"msg":"panic"}"#,
            LogLevel::Info,
        ),
        ("msg='level=panic warning' level=info", LogLevel::Info),
        (
            "Nov  8 12:00:00 host app[42]: INFO no panic detected",
            LogLevel::Info,
        ),
        (
            "ноя 08 12:00:00 host app[42]: WARN failure recovered",
            LogLevel::Warn,
        ),
        ("[42] worker running", LogLevel::Unknown),
    ] {
        assert_eq!(detect_level(line), level, "{line}");
    }
}

// Java exception classes can be printed alone when the exception has no message.
// Their frames must remain attached and visible through errors-only filtering.
// Ordinary identifiers and source filenames must not acquire an error level accidentally.
#[test]
fn java_exceptions_without_messages_are_errors() {
    for head in [
        "java.lang.NullPointerException",
        "NullPointerException",
        "com.example.Outer$InnerException",
        "java.lang.AssertionError",
    ] {
        assert_eq!(detect_level(head), LogLevel::Error);
        let input = format!("{head}\n    at com.example.Main.run(Main.java:10)\n");
        let result = run_fast_squeeze(Cursor::new(input), 200, true, false).unwrap();
        assert_eq!(result.clusters.len(), 1);
        assert_eq!(result.stats.errors, 1);
        assert_eq!(result.clusters[0].first_example, head);
        assert_eq!(
            result.clusters[0].stack_trace,
            ["    at com.example.Main.run(Main.java:10)"]
        );
    }
    for line in [
        "NullPointerException.java",
        "exception_count=0",
        "INFO java.lang.NullPointerException",
    ] {
        assert_eq!(
            detect_level(line),
            if line.starts_with("INFO ") {
                LogLevel::Info
            } else {
                LogLevel::Unknown
            }
        );
    }
}

// Source code shown after a Python File frame may begin with a severity-looking identifier.
// Only that source slot and its error pointer belong to the active exception block.
// A subsequent unindented INFO event remains a distinct event with its own level.
#[test]
fn python_source_is_not_a_new_log_header() {
    for source in [
        "    INFO = 1 / 0",
        "    ERROR = 1 / 0",
        "    level=info",
        "    {\"level\":30}",
    ] {
        let input = format!(
            "Traceback (most recent call last):\n  File \"<string>\", line 1, in <module>\n{source}\n           ~~^~~\nZeroDivisionError: division by zero\nINFO ready\n"
        );
        let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
        assert_eq!(result.clusters.len(), 2);
        assert_eq!((result.stats.errors, result.stats.infos), (1, 1));
        assert_eq!(
            result.clusters[0].stack_trace,
            [
                "  File \"<string>\", line 1, in <module>",
                source,
                "           ~~^~~",
                "ZeroDivisionError: division by zero"
            ]
        );
        assert_eq!(result.clusters[1].first_example, "INFO ready");
    }
}

// Node diagnostic object properties can have names such as error, info or fatal.
// Property syntax inside the active object takes precedence over bare severity words.
// The closing brace and later independent event must survive without inflating error counts.
#[test]
fn node_properties_are_not_new_log_headers() {
    let input = "Error: request failed\n    at connect (node:net:1:1) {\n  error: \"inner\",\n  info: \"detail\",\n  fatal: false,\n  code: 'EFAIL',\n  cause: { error: \"nested\" },\n}\nINFO ready\n";
    let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
    assert_eq!(result.clusters.len(), 2);
    assert_eq!(
        (result.stats.errors, result.stats.fatals, result.stats.infos),
        (1, 0, 1)
    );
    assert_eq!(
        result.clusters[0].stack_trace,
        [
            "    at connect (node:net:1:1) {",
            "  error: \"inner\",",
            "  info: \"detail\",",
            "  fatal: false,",
            "  code: 'EFAIL',",
            "  cause: { error: \"nested\" },",
            "}"
        ]
    );
    assert_eq!(result.clusters[1].first_example, "INFO ready");
}

// Python logging and similar layouts place punctuation between timestamp and level.
// Only the header's separators are skipped; message words cannot override its level.
// Include adjacent separators, thread labels and different severities as controls.
#[test]
fn timestamp_level_separators_preserve_explicit_severity() {
    for (line, level) in [
        (
            "2026-11-08 10:00:00,123 - INFO - no panic detected",
            LogLevel::Info,
        ),
        ("2026-11-08 10:00:00,123 - INFO - ready", LogLevel::Info),
        (
            "2026-11-08 10:00:00,123 | WARN | previous fatal recovered",
            LogLevel::Warn,
        ),
        (
            "2026-11-08T10:00:00Z|INFO|no panic detected",
            LogLevel::Info,
        ),
        (
            "2026-11-08T10:00:00+03:00 - [worker] - DEBUG - error counter=0",
            LogLevel::Debug,
        ),
        (
            "2026-11-08 10:00:00,123 : ERROR : request failed",
            LogLevel::Error,
        ),
    ] {
        assert_eq!(detect_level(line), level, "{line}");
    }
}

// Strong record signatures still end a stack even at the indentation of a source snippet.
// Also keep real text/logfmt headers distinct when they are not in a source or property slot.
// Test both unfinished Python and Node blocks so the new exceptions cannot swallow klog records.
#[test]
fn real_headers_still_end_python_and_node_blocks() {
    for prefix in [
        "Traceback (most recent call last):\n  File \"app.py\", line 1, in run\n",
        "Error: request failed\n    at connect (node:net:1:1) {\n",
    ] {
        for header in [
            "I1108 10:00:00.123456 1 worker.go:42] ready",
            "    W1108 10:00:00.123456 1 worker.go:42] retry",
            "    2026-11-08 10:00:00,123 - INFO - ready",
            "    Nov  8 10:00:00 host app[42]: INFO ready",
            "INFO ready",
            "level=info msg=\"ready\"",
        ] {
            let result = run_fast_squeeze(
                Cursor::new(format!("{prefix}{header}\n")),
                200,
                false,
                false,
            )
            .unwrap();
            assert_eq!(result.clusters.len(), 2, "{prefix}{header}");
            assert_eq!(result.clusters[1].first_example, header);
            assert_eq!(result.clusters[1].stack_trace, Vec::<String>::new());
        }
    }
    let input = "Traceback (most recent call last):\n  File \"app.py\", line 1, in run\n    INFO = 1 / 0\n    INFO next record\n";
    let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
    assert_eq!(result.clusters.len(), 2);
    assert_eq!(
        result.clusters[0].stack_trace,
        ["  File \"app.py\", line 1, in run", "    INFO = 1 / 0"]
    );
    assert_eq!(result.clusters[1].first_example, "    INFO next record");
}
