//! Terminal output (the `--show` mode), approximating the original Rich layout.

use crate::models::{Finding, ScanResult, Severity};
use serde_json::Value;
use std::fmt::Write as _;

const CYAN: &str = "36";
const GREEN: &str = "32";
const YELLOW: &str = "33";
const RED: &str = "31";

fn c(code: &str, text: &str) -> String {
    format!("\x1b[{code}m{text}\x1b[0m")
}

fn bold(text: &str) -> String {
    format!("\x1b[1m{text}\x1b[0m")
}

fn dim(text: &str) -> String {
    format!("\x1b[2m{text}\x1b[0m")
}

/// Display width of a string, ignoring ANSI escapes and counting wide
/// (e.g. CJK) characters as two columns.
fn visible_len(s: &str) -> usize {
    use unicode_width::UnicodeWidthChar;
    let mut len = 0;
    let mut in_esc = false;
    for ch in s.chars() {
        if in_esc {
            if ch == 'm' {
                in_esc = false;
            }
        } else if ch == '\x1b' {
            in_esc = true;
        } else {
            len += ch.width().unwrap_or(0);
        }
    }
    len
}

pub fn print_header(file_path: &str, app_type: &str) {
    let title = format!("{} {}", bold(&c(CYAN, "APEX —")), bold(&c(CYAN, "Static Analysis")));
    let line1 = format!("{} {}", bold("File :"), file_path);
    let line2 = format!("{} {}", bold("Type :"), app_type.to_uppercase());

    let inner = [line1, line2];
    let title_w = visible_len(&title);
    let box_w = inner
        .iter()
        .map(|l| visible_len(l))
        .chain(std::iter::once(title_w))
        .max()
        .unwrap_or(20);

    // Interior width (between the vertical borders) is box_w + 2.
    let top_dashes = box_w.saturating_sub(title_w + 1);
    println!();
    println!(
        "{}",
        c(CYAN, &format!("╭─ {} {}╮", title, "─".repeat(top_dashes)))
    );
    for l in &inner {
        let pad = box_w.saturating_sub(visible_len(l));
        println!("{} {}{} {}", c(CYAN, "│"), l, " ".repeat(pad), c(CYAN, "│"));
    }
    println!("{}", c(CYAN, &format!("╰{}╯", "─".repeat(box_w + 2))));
    println!();
}

pub fn print_finding(finding: &Finding, detail: bool) {
    let sev = finding.severity;
    let mut loc = String::new();
    if let Some(fp) = &finding.file_path {
        loc = format!(" @ {fp}");
        if let Some(line) = finding.line {
            let _ = write!(loc, ":{line}");
        }
    }
    let head = c(
        sev.ansi(),
        &format!("{} {}", sev.icon(), finding.title),
    );
    let tail = dim(&format!("{}{}", finding.category, loc));
    println!("  {head}  {tail}");

    if detail {
        // Description (the human-readable proof).
        println!("      {}", dim(&finding.description));

        // Classification tags.
        let mut tags = Vec::new();
        if let Some(cwe) = &finding.cwe {
            tags.push(cwe.clone());
        }
        if let Some(masvs) = &finding.masvs {
            tags.push(masvs.clone());
        }
        if let Some(mitre) = &finding.mitre {
            tags.push(format!("ATT&CK {mitre}"));
        }
        if !tags.is_empty() {
            println!("      {}", dim(&format!("[{}]", tags.join(" · "))));
        }

        // Metadata (raw proof / values).
        for (k, v) in &finding.metadata {
            println!("      {} {}", dim(&format!("{k}:")), dim(&render_value(v)));
        }
        println!();
    }
}

/// Render a JSON metadata value compactly, capping long arrays/objects.
fn render_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(a) => {
            let cap = 8;
            let mut parts: Vec<String> = a.iter().take(cap).map(render_value).collect();
            if a.len() > cap {
                parts.push(format!("… (+{} more)", a.len() - cap));
            }
            format!("[{}]", parts.join(", "))
        }
        Value::Object(o) => {
            let cap = 6;
            let mut parts: Vec<String> = o
                .iter()
                .take(cap)
                .map(|(k, val)| format!("{k}={}", render_value(val)))
                .collect();
            if o.len() > cap {
                parts.push(format!("… (+{} more)", o.len() - cap));
            }
            format!("{{{}}}", parts.join(", "))
        }
    }
}

pub fn print_summary(result: &ScanResult) {
    println!();
    let summary = result.summary();

    println!("{}", bold("Summary"));
    println!("  {:<10} {:>6}", bold("Severity"), bold("Count"));
    for sev in Severity::ALL {
        let count = summary
            .get(sev.value())
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let label = sev.value().to_uppercase();
        if count > 0 {
            println!(
                "  {:<10} {:>6}",
                c(sev.ansi(), &label),
                c(sev.ansi(), &count.to_string())
            );
        } else {
            println!("  {} {}", dim(&format!("{label:<10}")), dim(&format!("{count:>6}")));
        }
    }
    let total = summary.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    println!("  {:<10} {:>6}", bold("TOTAL"), bold(&total.to_string()));

    let score = result.security_score();
    let score_color = if score >= 80 {
        GREEN
    } else if score >= 50 {
        YELLOW
    } else {
        RED
    };
    println!(
        "\n{} {}",
        bold("Security Score:"),
        bold(&c(score_color, &format!("{score}/100")))
    );

    println!("\n{}", dim(&format!("SHA256   : {}", result.file_hash)));
    println!(
        "{}\n",
        dim(&format!("Duration : {:.2}s", round2(result.scan_duration)))
    );
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}
