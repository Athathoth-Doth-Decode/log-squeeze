//! Deterministic selection and rendering under a physical text-line budget.
use crate::masker::{EventCluster, LogLevel, SqueezeStats};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Default, Serialize)]
pub struct BudgetStats {
    pub skipped_events: usize,
    pub skipped_clusters: usize,
    pub skipped_after: usize,
    pub omitted_stack_lines: usize,
    pub omitted_templates: usize,
}

impl BudgetStats {
    pub fn is_empty(&self) -> bool {
        self.skipped_clusters == 0 && self.omitted_stack_lines == 0 && self.omitted_templates == 0
    }
}

fn priority(level: LogLevel) -> u8 {
    match level {
        LogLevel::Panic => 0,
        LogLevel::Fatal => 1,
        LogLevel::Error => 2,
        LogLevel::Warn => 3,
        _ => 4,
    }
}

/// Describe the complete filtered cluster set before any budget omissions.
/// Severity counters still cover input events rather than sampled output rows.
/// Gap markers elsewhere in the output distinguish budget selection from deduplication.
fn header(stats: &SqueezeStats, clusters: usize) -> String {
    let reduction = if stats.total_lines == 0 {
        0.0
    } else {
        100.0 * stats.total_lines.saturating_sub(clusters) as f64 / stats.total_lines as f64
    };
    format!(
        "=== [log-squeeze] Total: {} lines | Compressed to: {} events ({:.1}% reduction) | Errors: {} | Warnings: {} ===",
        stats.total_lines,
        clusters,
        reduction,
        stats.panics + stats.fatals + stats.errors,
        stats.warnings
    )
}

/// Reserve the header and select event heads by severity with stable ties.
/// Re-sort selected indices into first-occurrence order and record gaps by occurrence count.
/// Spend the remaining rows on stacks, retaining complete decoration only when it fits.
pub(crate) fn render_events(
    clusters: Vec<EventCluster>,
    stats: &mut SqueezeStats,
    max_lines: usize,
) -> (Vec<EventCluster>, String, BudgetStats) {
    let title = header(stats, clusters.len());
    let mut indices: Vec<_> = (0..clusters.len()).collect();
    indices.sort_by_key(|&index| (priority(clusters[index].level), index));
    indices.truncate(max_lines.saturating_sub(1));
    indices.sort_unstable();
    let mut selected = Vec::with_capacity(indices.len());
    let mut indices = indices.into_iter().peekable();
    let mut budget = BudgetStats::default();
    let mut gap = 0;
    for (index, mut cluster) in clusters.into_iter().enumerate() {
        if indices.peek() == Some(&index) {
            indices.next();
            cluster.skipped_before = gap;
            gap = 0;
            selected.push(cluster);
        } else {
            gap += cluster.count;
            budget.skipped_events += cluster.count;
            budget.skipped_clusters += 1;
            budget.omitted_stack_lines += cluster.stack_trace.len();
        }
    }
    budget.skipped_after = gap;
    let mut remaining = max_lines - 1 - selected.len();
    let mut order: Vec<_> = (0..selected.len()).collect();
    order.sort_by_key(|&index| (priority(selected[index].level), index));
    let mut decorated = vec![false; selected.len()];
    for index in order {
        let cluster = &mut selected[index];
        let frames = cluster.stack_trace.len();
        if frames == 0 {
            continue;
        }
        if frames.saturating_add(2) <= remaining {
            decorated[index] = true;
            remaining -= frames + 2;
        } else {
            let keep = frames.min(remaining);
            cluster.omitted_stack_lines = frames - keep;
            budget.omitted_stack_lines += frames - keep;
            cluster.stack_trace.truncate(keep);
            remaining -= keep;
        }
    }
    let mut rows = vec![title];
    for (cluster, decorated) in selected.iter().zip(decorated) {
        render_cluster(cluster, decorated, &mut rows);
    }
    if budget.skipped_after > 0 {
        rows.last_mut()
            .unwrap()
            .push_str(&format!(" [... {} events skipped]", budget.skipped_after));
    }
    if selected.is_empty() && budget.omitted_stack_lines > 0 {
        rows[0].push_str(&format!(
            " [... {} stack lines omitted]",
            budget.omitted_stack_lines
        ));
    }
    stats.output_lines = rows.len();
    (selected, rows.join("\n") + "\n", budget)
}

/// Each selected cluster prints its first and last example without changing event order.
/// Omission markers share existing rows so they never exceed the requested budget.
/// A compact stack still preserves each retained frame verbatim after redaction.
fn render_cluster(cluster: &EventCluster, decorated: bool, rows: &mut Vec<String>) {
    let mut head = if cluster.count == 1 {
        cluster.first_example.clone()
    } else {
        format!(
            "[x{}] [{}] {} ... [last: {}]",
            cluster.count,
            cluster.level.as_str(),
            cluster.first_example,
            cluster.last_example
        )
    };
    if cluster.skipped_before > 0 {
        head = format!("[... {} events skipped] {head}", cluster.skipped_before);
    }
    if cluster.omitted_stack_lines > 0 {
        head.push_str(&format!(
            " [... {} stack lines omitted]",
            cluster.omitted_stack_lines
        ));
    }
    rows.push(head);
    if decorated {
        rows.push(format!(
            "  +--- Stack Trace ({} lines):",
            cluster.stack_trace.len()
        ));
    }
    for frame in &cluster.stack_trace {
        rows.push(if frame.is_empty() {
            "  |".into()
        } else {
            format!("  | {frame}")
        });
    }
    if decorated {
        rows.push("  +---".into());
    }
}

/// Summary frequencies sort by descending count and then lexical template text.
/// Header, spacing and title consume the same physical-row budget as template entries.
/// Any excluded templates are counted on the final emitted row, including tiny budgets.
pub(crate) fn render_summary(
    clusters: usize,
    templates: HashMap<String, usize>,
    stats: &mut SqueezeStats,
    max_lines: usize,
) -> (String, BudgetStats) {
    let mut templates: Vec<_> = templates.into_iter().collect();
    templates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let shown = templates.len().min(max_lines.saturating_sub(3));
    let mut rows = vec![
        header(stats, clusters),
        String::new(),
        "--- Top Repeating Templates ---".into(),
    ];
    rows.truncate(max_lines);
    for (template, count) in templates.iter().take(shown) {
        rows.push(format!("[x{count:>5}] {template}"));
    }
    let budget = BudgetStats {
        omitted_templates: templates.len() - shown,
        ..BudgetStats::default()
    };
    if budget.omitted_templates > 0 {
        rows.last_mut().unwrap().push_str(&format!(
            " [... {} templates omitted]",
            budget.omitted_templates
        ));
    }
    stats.output_lines = rows.len();
    (rows.join("\n") + "\n", budget)
}
