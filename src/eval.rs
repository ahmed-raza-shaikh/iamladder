//! Detection accuracy against labeled policy cases.

use crate::analyze::{Options, analyze_principal};
use crate::model::{Grant, Principal, PrincipalKind};
use crate::policy::Statement;
use anyhow::Context;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

#[derive(Deserialize)]
struct Case {
    name: String,
    statements: Vec<Statement>,
    expected: BTreeSet<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Metrics {
    pub tp: usize,
    pub fp: usize,
    pub fn_: usize,
}

impl Metrics {
    pub fn precision(&self) -> f64 {
        if self.tp + self.fp == 0 {
            1.0
        } else {
            self.tp as f64 / (self.tp + self.fp) as f64
        }
    }
    pub fn recall(&self) -> f64 {
        if self.tp + self.fn_ == 0 {
            1.0
        } else {
            self.tp as f64 / (self.tp + self.fn_) as f64
        }
    }
    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub cases: usize,
    pub exact_matches: usize,
    pub overall: Metrics,
    pub per_rule: BTreeMap<String, Metrics>,
    pub errors: Vec<String>,
}

pub fn run(path: &Path) -> anyhow::Result<Report> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let cases: Vec<Case> = serde_json::from_str(&raw).context("parsing eval cases")?;
    let opts = Options {
        now_days: 0,
        dormant_days: i64::MAX,
    };
    let mut report = Report {
        cases: cases.len(),
        ..Report::default()
    };
    for case in cases {
        let principal = Principal {
            kind: PrincipalKind::User,
            name: case.name.clone(),
            arn: format!("arn:aws:iam::000000000000:user/{}", case.name),
            grants: case
                .statements
                .into_iter()
                .map(|statement| Grant {
                    source: "inline:case".into(),
                    statement,
                })
                .collect(),
            last_used: None,
            created: None,
        };
        let predicted: BTreeSet<String> = analyze_principal(&principal, None, opts)
            .findings
            .iter()
            .map(|f| f.rule.to_string())
            .collect();
        for rule in predicted.union(&case.expected) {
            let m = report.per_rule.entry(rule.clone()).or_default();
            match (predicted.contains(rule), case.expected.contains(rule)) {
                (true, true) => m.tp += 1,
                (true, false) => m.fp += 1,
                _ => m.fn_ += 1,
            }
        }
        if predicted == case.expected {
            report.exact_matches += 1;
        } else {
            report.errors.push(format!(
                "{}: expected {:?}, got {:?}",
                case.name, case.expected, predicted
            ));
        }
    }
    for m in report.per_rule.values() {
        report.overall.tp += m.tp;
        report.overall.fp += m.fp;
        report.overall.fn_ += m.fn_;
    }
    Ok(report)
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "| Rule | Support | Precision | Recall | F1 |\n|---|---|---|---|---|"
        )?;
        let o = &self.overall;
        writeln!(
            f,
            "| **All rules (micro)** | {} | {:.4} | {:.4} | {:.4} |",
            o.tp + o.fn_,
            o.precision(),
            o.recall(),
            o.f1()
        )?;
        for (rule, m) in &self.per_rule {
            writeln!(
                f,
                "| {rule} | {} | {:.4} | {:.4} | {:.4} |",
                m.tp + m.fn_,
                m.precision(),
                m.recall(),
                m.f1()
            )?;
        }
        writeln!(
            f,
            "\nExact-match cases: {}/{}",
            self.exact_matches, self.cases
        )?;
        for e in &self.errors {
            writeln!(f, "- {e}")?;
        }
        Ok(())
    }
}
