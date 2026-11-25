# iam-risk-intel

Find the AWS identities that can take over your account, and replace their permissions with the ones they actually use.

`iam-risk-intel` reads the standard `aws iam get-account-authorization-details` export and, optionally, CloudTrail logs. It reports:

- **Full admin**: `Action "*"` on `Resource "*"`, including admin inherited through groups.
- **Privilege-escalation paths**: 24 known IAM escalation primitives, for example `iam:PassRole` + `ec2:RunInstances`, `iam:CreatePolicyVersion` and `lambda:UpdateFunctionCode`. Wildcards (`iam:*`, `iam:Put*Policy`) and explicit denies are evaluated.
- **Over-broad grants**: service wildcards (`s3:*`, with `iam:*`/`kms:*` treated as high severity) and `Allow` + `NotAction`.
- **Dormant identities**: roles unused for more than N days, and identities with no activity in the supplied CloudTrail window.
- **Unused permissions**: explicitly granted actions that were never successfully called.
- **Least-privilege policies**: generated from observed CloudTrail activity, scoped to resource ARNs when CloudTrail recorded them. Failed (`AccessDenied`) calls are excluded.
- **Executive summary (optional)**: written by any OpenAI-compatible LLM. Only finding metadata is sent, never policy documents.

Each principal gets a 0–100 risk score, and principals are ranked by it. `--fail-on high` turns the tool into a CI/CD gate.

## Quick start

```bash
cargo build --release

# 1. Export IAM state (read-only; requires iam:GetAccountAuthorizationDetails)
aws iam get-account-authorization-details --output json > auth.json

# 2. Analyze (CloudTrail is optional but enables unused-permission and activity checks)
./target/release/iam-risk-intel analyze --auth auth.json --cloudtrail trail-*.json

# Try it on the bundled example account
./target/release/iam-risk-intel analyze \
  --auth examples/authorization-details.json \
  --cloudtrail examples/cloudtrail.json --now 2026-11-25
```

Example output (abridged):

```
| Risk | Principal                                   | Type | Findings |
|------|---------------------------------------------|------|----------|
| 70   | arn:aws:iam::111122223333:role/legacy-etl   | Role | privesc_passrole_glue, privesc_update_glue_endpoint, dormant_principal, service_wildcard |
| 53   | arn:aws:iam::111122223333:user/alice-admin  | User | full_admin, no_observed_activity |
| 35   | arn:aws:iam::111122223333:user/build-bot    | User | privesc_passrole_ec2, unused_permissions |
```

### Generate a least-privilege policy

```bash
iam-risk-intel least-privilege --cloudtrail trail.json \
  --principal arn:aws:iam::111122223333:user/build-bot
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "Observed1", "Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": "*" },
    { "Sid": "Observed2", "Effect": "Allow", "Action": ["s3:PutObject"],
      "Resource": ["arn:aws:s3:::artifacts-prod/builds/app.sha256", "arn:aws:s3:::artifacts-prod/builds/app.tar.gz"] }
  ]
}
```

### Other options

| Flag | Purpose |
|---|---|
| `--format json` | Machine-readable report for SIEM/ticketing |
| `--fail-on high` | Exit code `2` when any finding is at or above the severity, for pipelines |
| `--dormant-days 90` | Inactivity threshold |
| `--now YYYY-MM-DD` | Reproducible reports |
| `--explain` | Add an LLM executive summary. Uses `OPENAI_API_KEY`, `OPENAI_BASE_URL` (Azure OpenAI, vLLM, Ollama and similar work) and `LLM_MODEL` |

## Accuracy and performance

Measured on an Apple Silicon laptop with `cargo bench` and `iam-risk-intel eval`:

| Metric | Result |
|---|---|
| Escalation/over-permission detection, 45 labeled cases, 55 expected findings | **Precision 1.00, recall 1.00, F1 1.00** (45/45 exact matches) |
| Analyze 10,000 principals (6 statements each) | **49 ms** (~200k principals/s) |
| Analyze 10,000 principals + CloudTrail usage | **65 ms** |
| Ingest 100,000 CloudTrail events | **98 ms** (~1M events/s) |

`datasets/privesc_cases.json` covers every escalation path, plus wildcard and glob grants, `NotAction`, explicit and resource-scoped denies, case-insensitivity and incomplete paths that must *not* fire. The labels come from AWS IAM semantics. Like any curated suite, it measures correctness against the rules the tool implements; it does not measure coverage of escalation techniques the tool doesn't know about.

```bash
cargo test                              # unit + end-to-end + accuracy gate
cargo run --release -- eval             # accuracy table
cargo bench                             # performance
```

To run the bundled GitHub Actions workflow (fmt, clippy, tests, accuracy gate, coverage), copy `ci/github-actions.yml` to `.github/workflows/ci.yml`.

## Limitations

- Evaluates identity-based policies only. SCPs, permission boundaries, session policies and resource-based policies are not yet considered, so results are a conservative upper bound on effective access.
- `Condition` blocks are not evaluated. A conditional `Allow` still counts toward escalation paths, and a conditional `Deny` does not block them.
- AWS-managed policies other than `AdministratorAccess` must be present in the export, which is the default for `get-account-authorization-details`. Missing ones are listed under warnings.
- Least-privilege output reflects only the CloudTrail window you supply. Use 30–90 days to capture periodic jobs.

## License

MIT
