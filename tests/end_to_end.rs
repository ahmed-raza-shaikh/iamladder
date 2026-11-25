use iam_risk_intel::analyze::{Options, days_from_iso};
use iam_risk_intel::{eval, leastpriv};
use std::path::Path;

fn opts() -> Options {
    Options {
        now_days: days_from_iso("2026-11-25").unwrap(),
        dormant_days: 90,
    }
}

#[test]
fn example_account_is_ranked_correctly() {
    let (report, _) = iam_risk_intel::run(
        Path::new("examples/authorization-details.json"),
        &["examples/cloudtrail.json"],
        opts(),
    )
    .unwrap();
    let order: Vec<&str> = report.principals.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        order,
        [
            "legacy-etl",
            "alice-admin",
            "build-bot",
            "app-backend",
            "analyst"
        ]
    );
    let analyst = report.principals.last().unwrap();
    assert_eq!(
        analyst.risk_score, 0,
        "fully used read-only access is not a risk"
    );
    assert!(report.warnings.is_empty());
}

#[test]
fn least_privilege_drops_denied_and_unused_actions() {
    let usage = iam_risk_intel::load_usage(&["examples/cloudtrail.json"])
        .unwrap()
        .unwrap();
    assert_eq!(usage.denied, 1);
    let policy =
        leastpriv::generate(&usage.by_principal["arn:aws:iam::111122223333:user/build-bot"]);
    let text = policy.to_string();
    assert!(text.contains("s3:PutObject") && text.contains("ec2:DescribeInstances"));
    assert!(!text.contains("DeleteObject") && !text.contains("PassRole"));
}

#[test]
fn detection_accuracy_gate() {
    let r = eval::run(Path::new("datasets/privesc_cases.json")).unwrap();
    assert!(r.overall.precision() >= 0.99, "{r}");
    assert!(r.overall.recall() >= 0.99, "{r}");
}
