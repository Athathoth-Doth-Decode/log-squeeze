use log_squeeze::masker::{Masker, run_fast_squeeze};
use std::io::Cursor;

// HTTP outcomes must survive masking and remain separate even in informational logs.
// Repeated outcomes may merge globally, with their first occurrence defining order.
// Error and warning identities additionally preserve all numeric diagnostic values.
#[test]
fn semantic_values_survive_global_clustering() {
    let input = "INFO response status=200\nINFO response status=500\nINFO response status=502\nINFO response status=200\nERROR code=13\nERROR code=14\nERROR code=13\nWARN attempts=7\nWARN attempts=8\n";
    let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
    assert_eq!(
        result
            .clusters
            .iter()
            .map(|c| (c.first_example.as_str(), c.count))
            .collect::<Vec<_>>(),
        [
            ("INFO response status=200", 2),
            ("INFO response status=500", 1),
            ("INFO response status=502", 1),
            ("ERROR code=13", 2),
            ("ERROR code=14", 1),
            ("WARN attempts=7", 1),
            ("WARN attempts=8", 1)
        ]
    );
    assert_eq!(
        Masker::new().mask("HTTP 200 401 500 502 599 count=42"),
        "HTTP 200 401 500 502 599 count=<N>"
    );
}

// Timestamps are volatile in an error or warning message identity.
// Nonadjacent repeats retain the first and last examples without moving other clusters.
// Different numeric values inside the message must not be normalized away.
#[test]
fn timestamped_errors_merge_without_losing_diagnostics() {
    let input = "2026-11-08 10:00:00 ERROR code=13\nINFO ready\n2026-11-08 10:01:00 ERROR code=13\n2026-11-08 10:02:00 ERROR code=14\n";
    let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
    assert_eq!(result.clusters.len(), 3);
    assert_eq!(result.clusters[0].count, 2);
    assert_eq!(
        result.clusters[0].first_example,
        "2026-11-08 10:00:00 ERROR code=13"
    );
    assert_eq!(
        result.clusters[0].last_example,
        "2026-11-08 10:01:00 ERROR code=13"
    );
    assert_eq!(result.clusters[1].first_example, "INFO ready");
    assert_eq!(
        result.clusters[2].first_example,
        "2026-11-08 10:02:00 ERROR code=14"
    );
    assert_eq!(result.stats.errors, 3);
}

// Complete repeated stacks merge even when unrelated events separate their occurrences.
// Source locations can vary, but cause messages and object properties remain diagnostic data.
// Keep one representative stack and never merge different exception causes.
#[test]
fn repeated_stacks_merge_globally_but_causes_stay_distinct() {
    let mut input = String::new();
    for line in 90..130 {
        input.push_str(&format!("java.lang.NullPointerException\n    at app.Main.run(Main.java:{line})\nINFO heartbeat\n"));
    }
    input.push_str("ERROR failed\n    at app.Main.run(Main.java:1)\nCaused by: Error code=13\nERROR failed\n    at app.Main.run(Main.java:2)\nCaused by: Error code=14\n");
    let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
    assert_eq!(
        result.clusters.iter().map(|c| c.count).collect::<Vec<_>>(),
        [40, 40, 1, 1]
    );
    assert_eq!(
        result.clusters[0].stack_trace,
        ["    at app.Main.run(Main.java:90)"]
    );
    assert_eq!(
        result.clusters[2].stack_trace[1],
        "Caused by: Error code=13"
    );
    assert_eq!(
        result.clusters[3].stack_trace[1],
        "Caused by: Error code=14"
    );
}

// Selection prefers diagnostic events but renders all selected clusters in source order.
// Gap markers count omitted input events and consume no additional physical output lines.
// The header and all notices are included in the hard line cap.
#[test]
fn budget_selection_keeps_order_and_marks_gaps() {
    let input = "INFO alpha\nDEBUG beta\nERROR gamma\nINFO delta\nWARN epsilon\nINFO zeta\n";
    let result = run_fast_squeeze(Cursor::new(input), 4, false, false).unwrap();
    assert_eq!(
        result.rendered_output,
        "=== [log-squeeze] Total: 6 lines | Compressed to: 6 events (0.0% reduction) | Errors: 1 | Warnings: 1 ===\nINFO alpha\n[... 1 events skipped] ERROR gamma\n[... 1 events skipped] WARN epsilon [... 1 events skipped]\n"
    );
    assert_eq!(result.stats.output_lines, 4);
    assert_eq!(
        result
            .clusters
            .iter()
            .map(|c| c.first_example.as_str())
            .collect::<Vec<_>>(),
        ["INFO alpha", "ERROR gamma", "WARN epsilon"]
    );
}

// Errors-only uses the same hard budget and reports every omitted stack line explicitly.
// Tiny budgets preserve as many frames as fit without adding uncounted decoration rows.
// Larger budgets retain the complete original stack with its usual formatting.
#[test]
fn stack_budget_is_hard_including_header_and_notices() {
    let input = "ERROR failed\n    at app.One.run(One.java:1)\n    at app.Two.run(Two.java:2)\n    at app.Three.run(Three.java:3)\n    at app.Four.run(Four.java:4)\n";
    let result = run_fast_squeeze(Cursor::new(input), 4, true, false).unwrap();
    assert_eq!(
        result.rendered_output,
        "=== [log-squeeze] Total: 5 lines | Compressed to: 1 events (80.0% reduction) | Errors: 1 | Warnings: 0 ===\nERROR failed [... 2 stack lines omitted]\n  |     at app.One.run(One.java:1)\n  |     at app.Two.run(Two.java:2)\n"
    );
    assert_eq!(
        result.clusters[0].stack_trace,
        [
            "    at app.One.run(One.java:1)",
            "    at app.Two.run(Two.java:2)"
        ]
    );
    for cap in 1..=9 {
        let result = run_fast_squeeze(Cursor::new(input), cap, true, false).unwrap();
        assert!(result.rendered_output.lines().count() <= cap, "cap={cap}");
        assert_eq!(
            result.stats.output_lines,
            result.rendered_output.lines().count()
        );
    }
    assert_eq!(
        run_fast_squeeze(Cursor::new(input), 0, false, false)
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
}

// Frequency ties must have a stable lexical order rather than hash iteration order.
// The summary budget includes its header, spacing, title and omission notice.
// Numeric error diagnostics remain visible even when their generic templates match.
#[test]
fn summary_is_deterministic_and_obeys_budget() {
    let input = "ERROR code=14\nINFO zebra\nERROR code=13\nINFO alpha\n";
    let result = run_fast_squeeze(Cursor::new(input), 5, false, true).unwrap();
    assert_eq!(
        result.rendered_output,
        "=== [log-squeeze] Total: 4 lines | Compressed to: 4 events (0.0% reduction) | Errors: 2 | Warnings: 0 ===\n\n--- Top Repeating Templates ---\n[x    1] ERROR code=13\n[x    1] ERROR code=14 [... 2 templates omitted]\n"
    );
    assert_eq!(result.stats.output_lines, 5);
    for cap in 1..=8 {
        let result = run_fast_squeeze(Cursor::new(input), cap, false, true).unwrap();
        assert_eq!(result.rendered_output.lines().count(), cap.min(7));
        assert_eq!(result.stats.output_lines, cap.min(7));
        assert_eq!(
            result.budget.omitted_templates,
            4usize.saturating_sub(cap.saturating_sub(3))
        );
    }
}

// Reproduce the original large-stream chronology failure with an error in the middle.
// Selection must keep the error after all retained earlier records, never move it to the front.
// Exact gap counts cover all omitted clusters both before and after that error.
#[test]
fn thousand_event_selection_keeps_middle_error_in_position() {
    let input: String = (0..1000)
        .map(|i| {
            if i == 500 {
                "ERROR middle failure\n".to_owned()
            } else {
                format!("INFO item_{i}\n")
            }
        })
        .collect();
    let result = run_fast_squeeze(Cursor::new(input), 10, false, false).unwrap();
    let mut expected: Vec<String> = (0..8).map(|i| format!("INFO item_{i}")).collect();
    expected.push("ERROR middle failure".into());
    assert_eq!(
        result
            .clusters
            .iter()
            .map(|c| c.first_example.clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        result.rendered_output.lines().last().unwrap(),
        "[... 492 events skipped] ERROR middle failure [... 499 events skipped]"
    );
    assert_eq!(result.stats.output_lines, 10);
    assert_eq!(result.budget.skipped_events, 991);
    assert_eq!(result.budget.skipped_clusters, 991);
}

// Many distinct errors cannot bypass the hard cap through errors-only mode.
// A long single stack must also honor the default-sized budget instead of emitting every frame.
// Keep exact diagnostic counters even when most output events or frames are omitted.
#[test]
fn dense_errors_and_long_stacks_stay_within_budget() {
    let input: String = (0..1000)
        .map(|code| format!("ERROR code={code}\n"))
        .collect();
    let result = run_fast_squeeze(Cursor::new(input), 5, true, false).unwrap();
    assert_eq!(result.stats.errors, 1000);
    assert_eq!(result.stats.output_lines, 5);
    assert_eq!(
        result
            .clusters
            .iter()
            .map(|c| c.first_example.as_str())
            .collect::<Vec<_>>(),
        [
            "ERROR code=0",
            "ERROR code=1",
            "ERROR code=2",
            "ERROR code=3"
        ]
    );
    assert_eq!(result.budget.skipped_events, 996);
    assert_eq!(
        result.rendered_output.lines().last().unwrap(),
        "ERROR code=3 [... 996 events skipped]"
    );
    let input = "ERROR failed\n".to_owned()
        + &(0..250)
            .map(|n| format!("    at app.Main.run(Main.java:{n})\n"))
            .collect::<String>();
    let result = run_fast_squeeze(Cursor::new(input), 200, true, false).unwrap();
    assert_eq!(result.stats.output_lines, 200);
    assert_eq!(result.clusters[0].stack_trace.len(), 198);
    assert_eq!(result.clusters[0].omitted_stack_lines, 52);
    assert_eq!(
        result.rendered_output.lines().nth(1).unwrap(),
        "ERROR failed [... 52 stack lines omitted]"
    );
}

// Numeric object properties and exception text are not source locations.
// Different diagnostics keep separate clusters even when normalized frame locations match.
// Identical diagnostics with varying source line numbers still merge globally.
#[test]
fn node_diagnostics_are_part_of_stack_identity() {
    let input = "Error: failed\n    at app.run(app.js:90:1) {\n  code: 13\n}\nError: failed\n    at app.run(app.js:100:2) {\n  code: 14\n}\nError: failed\n    at app.run(app.js:101:3) {\n  code: 13\n}\n";
    let result = run_fast_squeeze(Cursor::new(input), 200, true, false).unwrap();
    assert_eq!(
        result.clusters.iter().map(|c| c.count).collect::<Vec<_>>(),
        [2, 1]
    );
    assert_eq!(
        result.clusters[0].stack_trace,
        ["    at app.run(app.js:90:1) {", "  code: 13", "}"]
    );
    assert_eq!(
        result.clusters[1].stack_trace,
        ["    at app.run(app.js:100:2) {", "  code: 14", "}"]
    );
}

// Structured controller logs carry their timestamp inside the record, not at its start.
// Timestamps, UUIDs and durations are volatile; codes, IPs and plain numbers stay diagnostic.
// Forty identical JSON errors and repeated slow-query warnings must each collapse to one cluster.
#[test]
fn embedded_timestamps_uuids_and_durations_do_not_split_errors() {
    let mut input = String::new();
    for minute in 10..50 {
        input.push_str(&format!(
            "{{\"level\":\"error\",\"ts\":\"2026-11-13T22:{minute}:00Z\",\"msg\":\"Reconciler error\",\"name\":\"litellm\"}}\n"
        ));
    }
    input.push_str("WARN slow query took 17ms request=6f1c2a9e-0b7d-4c3e-9a51-2f8e7d6c5b4a\n");
    input.push_str("WARN slow query took 2,5 s request=0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d\n");
    input.push_str("ERROR connect 10.0.0.1:5432 refused\nERROR connect 10.0.0.2:5432 refused\n");
    let result = run_fast_squeeze(Cursor::new(input), 200, false, false).unwrap();
    assert_eq!(
        result
            .clusters
            .iter()
            .map(|c| (c.level.as_str(), c.count))
            .collect::<Vec<_>>(),
        [("ERROR", 40), ("WARN", 2), ("ERROR", 1), ("ERROR", 1)]
    );
    assert_eq!(
        result.clusters[0].last_example,
        "{\"level\":\"error\",\"ts\":\"2026-11-13T22:49:00Z\",\"msg\":\"Reconciler error\",\"name\":\"litellm\"}"
    );
    assert_eq!(
        result.clusters[2].first_example,
        "ERROR connect 10.0.0.1:5432 refused"
    );
}
