use crate::analyze::{Report, Severity};
use std::fmt::Write;

fn sev(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    }
}

pub fn markdown(report: &Report, min_score: u32) -> String {
    let mut s = String::new();
    let count = |sv| report.severity_counts.get(&sv).copied().unwrap_or(0);
    let _ = writeln!(s, "# IAM Risk Report\n");
    let _ = writeln!(
        s,
        "Principals analyzed: **{}** | Critical: **{}** | High: **{}** | Medium: **{}** | Low: **{}**\n",
        report.principals_analyzed,
        count(Severity::Critical),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low)
    );
    let shown: Vec<_> = report
        .principals
        .iter()
        .filter(|p| p.risk_score >= min_score.max(1))
        .collect();
    if shown.is_empty() {
        let _ = writeln!(s, "No findings at or above the selected risk score.");
    } else {
        let _ = writeln!(
            s,
            "| Risk | Principal | Type | Findings |\n|---|---|---|---|"
        );
        for p in &shown {
            let rules: Vec<&str> = p.findings.iter().map(|f| f.rule).collect();
            let _ = writeln!(
                s,
                "| {} | `{}` | {:?} | {} |",
                p.risk_score,
                p.arn,
                p.kind,
                rules.join(", ")
            );
        }
        for p in &shown {
            let _ = writeln!(s, "\n## {} (risk {})\n", p.name, p.risk_score);
            for f in &p.findings {
                let _ = writeln!(s, "- **[{}]** {}", sev(f.severity), f.title);
                for e in &f.evidence {
                    let _ = writeln!(s, "  - `{e}`");
                }
                let _ = writeln!(s, "  - Fix: {}", f.remediation);
            }
        }
    }
    if !report.warnings.is_empty() {
        let _ = writeln!(s, "\n## Warnings\n");
        for w in &report.warnings {
            let _ = writeln!(s, "- {w}");
        }
    }
    s
}
