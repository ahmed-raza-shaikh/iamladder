//! AWS IAM risk analysis: privilege escalation, over-permission and least-privilege generation.

pub mod analyze;
pub mod cloudtrail;
pub mod eval;
pub mod leastpriv;
pub mod llm;
pub mod model;
pub mod policy;
pub mod report;

use std::path::Path;

/// Loads authorization details and optional CloudTrail files and runs the full analysis.
pub fn run(
    auth: &Path,
    trails: &[impl AsRef<Path>],
    opts: analyze::Options,
) -> anyhow::Result<(analyze::Report, Option<cloudtrail::Usage>)> {
    use anyhow::Context;
    let raw =
        std::fs::read_to_string(auth).with_context(|| format!("reading {}", auth.display()))?;
    let details: model::AuthorizationDetails =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", auth.display()))?;
    let (principals, warnings) = details.principals();
    let usage = load_usage(trails)?;
    Ok((
        analyze::analyze(&principals, warnings, usage.as_ref(), opts),
        usage,
    ))
}

pub fn load_usage(trails: &[impl AsRef<Path>]) -> anyhow::Result<Option<cloudtrail::Usage>> {
    use anyhow::Context;
    if trails.is_empty() {
        return Ok(None);
    }
    let mut usage = cloudtrail::Usage::default();
    for t in trails {
        let t = t.as_ref();
        let raw = std::fs::read_to_string(t).with_context(|| format!("reading {}", t.display()))?;
        usage
            .ingest_json(&raw)
            .with_context(|| format!("parsing CloudTrail file {}", t.display()))?;
    }
    Ok(Some(usage))
}
