use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use iam_risk_intel::analyze::{Options, analyze};
use iam_risk_intel::cloudtrail::Usage;
use iam_risk_intel::model::{Grant, Principal, PrincipalKind};
use iam_risk_intel::policy::Statement;
use std::hint::black_box;

const STATEMENTS: [&str; 6] = [
    r#"{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:ListBucket"],"Resource":"*"}"#,
    r#"{"Effect":"Allow","Action":["ec2:Describe*","ec2:RunInstances"],"Resource":"*"}"#,
    r#"{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::1:role/app"}"#,
    r#"{"Effect":"Allow","Action":"dynamodb:*","Resource":"*"}"#,
    r#"{"Effect":"Allow","Action":["sqs:SendMessage","sqs:ReceiveMessage"],"Resource":"*"}"#,
    r#"{"Effect":"Deny","Action":"iam:CreateAccessKey","Resource":"*"}"#,
];

fn principals(n: usize) -> Vec<Principal> {
    let statements: Vec<Statement> = STATEMENTS
        .iter()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    (0..n)
        .map(|i| Principal {
            kind: if i % 2 == 0 {
                PrincipalKind::User
            } else {
                PrincipalKind::Role
            },
            name: format!("p{i}"),
            arn: format!("arn:aws:iam::1:user/p{i}"),
            grants: statements
                .iter()
                .map(|s| Grant {
                    source: "inline:bench".into(),
                    statement: s.clone(),
                })
                .collect(),
            last_used: Some("2026-11-01T00:00:00Z".into()),
            created: Some("2024-01-01T00:00:00Z".into()),
        })
        .collect()
}

fn trail(events: usize, principals: usize) -> String {
    let records: Vec<String> = (0..events)
        .map(|i| {
            format!(
                r#"{{"eventSource":"s3.amazonaws.com","eventName":"{}","userIdentity":{{"type":"IAMUser","arn":"arn:aws:iam::1:user/p{}"}},"resources":[{{"ARN":"arn:aws:s3:::bucket/k{}"}}]}}"#,
                ["GetObject", "PutObject", "ListBucket"][i % 3],
                i % principals,
                i % 50
            )
        })
        .collect();
    format!(r#"{{"Records":[{}]}}"#, records.join(","))
}

fn bench(c: &mut Criterion) {
    let opts = Options {
        now_days: 20_782,
        dormant_days: 90,
    };
    let ps = principals(10_000);
    let raw = trail(100_000, 10_000);
    let mut usage = Usage::default();
    usage.ingest_json(&raw).unwrap();

    let mut g = c.benchmark_group("iam");
    g.sample_size(20);
    g.throughput(Throughput::Elements(ps.len() as u64));
    g.bench_function("analyze_10k_principals", |b| {
        b.iter(|| analyze(black_box(&ps), Vec::new(), None, opts))
    });
    g.bench_function("analyze_10k_principals_with_usage", |b| {
        b.iter(|| analyze(black_box(&ps), Vec::new(), Some(&usage), opts))
    });
    g.throughput(Throughput::Elements(100_000));
    g.bench_function("ingest_100k_cloudtrail_events", |b| {
        b.iter(|| {
            let mut u = Usage::default();
            u.ingest_json(black_box(&raw)).unwrap();
            u
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
