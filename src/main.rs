use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use iam_risk_intel::analyze::{Options, Severity, days_from_iso};
use iam_risk_intel::{eval, leastpriv, llm, report};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    version,
    about = "AWS IAM risk intelligence and least-privilege generator"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Markdown,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analyze `aws iam get-account-authorization-details` output (plus optional CloudTrail).
    Analyze {
        #[arg(long)]
        auth: PathBuf,
        /// CloudTrail JSON file(s) used for unused-permission and activity analysis.
        #[arg(long = "cloudtrail")]
        cloudtrail: Vec<PathBuf>,
        #[arg(long, value_enum, default_value = "markdown")]
        format: Format,
        #[arg(long, default_value_t = 90)]
        dormant_days: i64,
        /// Reference date (YYYY-MM-DD); defaults to today.
        #[arg(long)]
        now: Option<String>,
        /// Hide principals below this risk score in Markdown output.
        #[arg(long, default_value_t = 1)]
        min_score: u32,
        /// Exit with code 2 if any finding is at or above this severity (CI gating).
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
        /// Append an LLM-written executive summary (OpenAI-compatible API).
        #[arg(long)]
        explain: bool,
        #[arg(
            long,
            env = "OPENAI_BASE_URL",
            default_value = "https://api.openai.com/v1"
        )]
        llm_base_url: String,
        #[arg(long, env = "LLM_MODEL", default_value = "gpt-4o-mini")]
        llm_model: String,
    },
    /// Generate a least-privilege policy for one principal from CloudTrail activity.
    LeastPrivilege {
        #[arg(long = "cloudtrail", required = true)]
        cloudtrail: Vec<PathBuf>,
        /// IAM user or role ARN.
        #[arg(long)]
        principal: String,
    },
    /// Measure detection accuracy on labeled cases.
    Eval {
        #[arg(default_value = "datasets/privesc_cases.json")]
        path: PathBuf,
        #[arg(long, default_value_t = 0.99)]
        min_f1: f64,
    },
}

fn today() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64 / 86_400)
}

fn main() -> anyhow::Result<ExitCode> {
    match Cli::parse().cmd {
        Cmd::Analyze {
            auth,
            cloudtrail,
            format,
            dormant_days,
            now,
            min_score,
            fail_on,
            explain,
            llm_base_url,
            llm_model,
        } => {
            let now_days = match now {
                Some(d) => days_from_iso(&d).context("--now must be YYYY-MM-DD")?,
                None => today(),
            };
            let opts = Options {
                now_days,
                dormant_days,
            };
            let (report, _) = iam_risk_intel::run(&auth, &cloudtrail, opts)?;
            match format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&report)?),
                Format::Markdown => print!("{}", report::markdown(&report, min_score)),
            }
            if explain {
                let cfg = llm::LlmConfig {
                    base_url: llm_base_url,
                    api_key: std::env::var("OPENAI_API_KEY")
                        .context("--explain requires OPENAI_API_KEY")?,
                    model: llm_model,
                };
                println!(
                    "\n## Executive summary\n\n{}",
                    llm::summarize(&cfg, &report, 25)?
                );
            }
            if let Some(level) = fail_on {
                let threshold = match level {
                    FailOn::Low => Severity::Low,
                    FailOn::Medium => Severity::Medium,
                    FailOn::High => Severity::High,
                    FailOn::Critical => Severity::Critical,
                };
                if report.severity_counts.keys().any(|s| *s >= threshold) {
                    return Ok(ExitCode::from(2));
                }
            }
        }
        Cmd::LeastPrivilege {
            cloudtrail,
            principal,
        } => {
            let usage = iam_risk_intel::load_usage(&cloudtrail)?.unwrap_or_default();
            let used = usage.by_principal.get(&principal).with_context(|| {
                format!("no successful activity for {principal} in the supplied CloudTrail")
            })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&leastpriv::generate(used))?
            );
        }
        Cmd::Eval { path, min_f1 } => {
            let r = eval::run(&path)?;
            println!("{r}");
            anyhow::ensure!(
                r.overall.f1() >= min_f1,
                "F1 {:.4} below {min_f1}",
                r.overall.f1()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}
