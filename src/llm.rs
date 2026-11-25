//! Optional executive summary through any OpenAI-compatible chat completions API.
//! Only finding metadata (ARNs, rule ids, titles, scores) is sent, never raw policies.

use crate::analyze::Report;
use anyhow::Context;
use serde_json::{Value, json};
use std::time::Duration;

pub struct LlmConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

const SYSTEM_PROMPT: &str = "You are a senior cloud security analyst writing for a CISO. \
Using ONLY the findings provided, write: (1) a three-sentence executive summary, \
(2) the five highest-impact remediation actions in priority order, each naming the affected principals, \
(3) quick wins that can be completed in a day. Do not invent principals, permissions or numbers.";

pub fn summarize(cfg: &LlmConfig, report: &Report, top: usize) -> anyhow::Result<String> {
    let principals: Vec<Value> = report
        .principals
        .iter()
        .filter(|p| p.risk_score > 0)
        .take(top)
        .map(|p| {
            json!({
                "arn": p.arn,
                "risk_score": p.risk_score,
                "findings": p.findings.iter().map(|f| json!({
                    "rule": f.rule, "severity": f.severity, "title": f.title
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let facts = json!({
        "principals_analyzed": report.principals_analyzed,
        "severity_counts": report.severity_counts,
        "top_principals": principals,
    });
    let url = format!("{}/chat/completions", cfg.base_url.trim_end_matches('/'));
    let resp: Value = ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", cfg.api_key))
        .timeout(Duration::from_secs(90))
        .send_json(json!({
            "model": cfg.model,
            "temperature": 0,
            "messages": [
                { "role": "system", "content": SYSTEM_PROMPT },
                { "role": "user", "content": facts.to_string() }
            ]
        }))
        .context("calling LLM endpoint")?
        .into_json()
        .context("decoding LLM response")?;
    resp["choices"][0]["message"]["content"]
        .as_str()
        .map(str::to_owned)
        .context("LLM response had no message content")
}
