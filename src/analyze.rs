//! Risk rules: full admin, privilege-escalation paths, wildcards, dormancy and unused access.

use crate::cloudtrail::{ActionUse, Usage};
use crate::model::{Grant, Principal, PrincipalKind};
use crate::policy::{Effect, is_wildcard};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn weight(self) -> u32 {
        match self {
            Severity::Low => 3,
            Severity::Medium => 10,
            Severity::High => 25,
            Severity::Critical => 50,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub title: String,
    pub evidence: Vec<String>,
    pub remediation: &'static str,
}

pub struct EscalationPath {
    pub id: &'static str,
    pub actions: &'static [&'static str],
    pub impact: &'static str,
}

/// Known IAM privilege-escalation primitives (after Rhino Security Labs / Bishop Fox research).
pub const ESCALATION_PATHS: &[EscalationPath] = &[
    EscalationPath {
        id: "privesc_create_policy_version",
        actions: &["iam:CreatePolicyVersion"],
        impact: "can publish an admin version of any customer-managed policy",
    },
    EscalationPath {
        id: "privesc_set_default_policy_version",
        actions: &["iam:SetDefaultPolicyVersion"],
        impact: "can roll a managed policy back to a more permissive version",
    },
    EscalationPath {
        id: "privesc_passrole_ec2",
        actions: &["iam:PassRole", "ec2:RunInstances"],
        impact: "can launch an instance with a privileged role and read its credentials",
    },
    EscalationPath {
        id: "privesc_create_access_key",
        actions: &["iam:CreateAccessKey"],
        impact: "can mint access keys for other users",
    },
    EscalationPath {
        id: "privesc_create_login_profile",
        actions: &["iam:CreateLoginProfile"],
        impact: "can set a console password on users that have none",
    },
    EscalationPath {
        id: "privesc_update_login_profile",
        actions: &["iam:UpdateLoginProfile"],
        impact: "can reset other users' console passwords",
    },
    EscalationPath {
        id: "privesc_attach_user_policy",
        actions: &["iam:AttachUserPolicy"],
        impact: "can attach AdministratorAccess to itself",
    },
    EscalationPath {
        id: "privesc_attach_group_policy",
        actions: &["iam:AttachGroupPolicy"],
        impact: "can attach admin policies to its own group",
    },
    EscalationPath {
        id: "privesc_attach_role_policy",
        actions: &["iam:AttachRolePolicy", "sts:AssumeRole"],
        impact: "can attach admin policies to a role it can assume",
    },
    EscalationPath {
        id: "privesc_put_user_policy",
        actions: &["iam:PutUserPolicy"],
        impact: "can write an inline admin policy on itself",
    },
    EscalationPath {
        id: "privesc_put_group_policy",
        actions: &["iam:PutGroupPolicy"],
        impact: "can write an inline admin policy on its group",
    },
    EscalationPath {
        id: "privesc_put_role_policy",
        actions: &["iam:PutRolePolicy", "sts:AssumeRole"],
        impact: "can write an inline admin policy on a role it can assume",
    },
    EscalationPath {
        id: "privesc_add_user_to_group",
        actions: &["iam:AddUserToGroup"],
        impact: "can add itself to an admin group",
    },
    EscalationPath {
        id: "privesc_update_assume_role_policy",
        actions: &["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
        impact: "can rewrite a privileged role's trust policy and assume it",
    },
    EscalationPath {
        id: "privesc_passrole_lambda_invoke",
        actions: &[
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
        ],
        impact: "can run code as any passable role via Lambda",
    },
    EscalationPath {
        id: "privesc_passrole_lambda_event_source",
        actions: &[
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:CreateEventSourceMapping",
        ],
        impact: "can run code as any passable role via a triggered Lambda",
    },
    EscalationPath {
        id: "privesc_update_lambda_code",
        actions: &["lambda:UpdateFunctionCode"],
        impact: "can replace code of Lambdas that run with privileged roles",
    },
    EscalationPath {
        id: "privesc_passrole_glue",
        actions: &["iam:PassRole", "glue:CreateDevEndpoint"],
        impact: "can create a Glue endpoint with a privileged role and SSH into it",
    },
    EscalationPath {
        id: "privesc_update_glue_endpoint",
        actions: &["glue:UpdateDevEndpoint"],
        impact: "can add its SSH key to existing privileged Glue endpoints",
    },
    EscalationPath {
        id: "privesc_passrole_cloudformation",
        actions: &["iam:PassRole", "cloudformation:CreateStack"],
        impact: "can deploy stacks that create resources as a privileged role",
    },
    EscalationPath {
        id: "privesc_passrole_datapipeline",
        actions: &[
            "iam:PassRole",
            "datapipeline:CreatePipeline",
            "datapipeline:PutPipelineDefinition",
        ],
        impact: "can run commands as a privileged role via Data Pipeline",
    },
    EscalationPath {
        id: "privesc_passrole_ecs",
        actions: &["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"],
        impact: "can run containers as a privileged task role",
    },
    EscalationPath {
        id: "privesc_passrole_sagemaker",
        actions: &[
            "iam:PassRole",
            "sagemaker:CreateNotebookInstance",
            "sagemaker:CreatePresignedNotebookInstanceUrl",
        ],
        impact: "can open a notebook running as a privileged role",
    },
    EscalationPath {
        id: "privesc_ssm_send_command",
        actions: &["ssm:SendCommand"],
        impact: "can execute commands on instances and use their roles",
    },
];

const SENSITIVE_SERVICES: [&str; 5] = ["iam", "sts", "kms", "organizations", "secretsmanager"];

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Days since Unix epoch representing "today".
    pub now_days: i64,
    pub dormant_days: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageSummary {
    pub observed_actions: usize,
    pub granted_explicit_actions: usize,
    pub unused_explicit_actions: Vec<String>,
    pub wildcard_grants: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrincipalReport {
    pub arn: String,
    pub name: String,
    pub kind: PrincipalKind,
    pub risk_score: u32,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub principals_analyzed: usize,
    pub severity_counts: BTreeMap<Severity, usize>,
    pub principals: Vec<PrincipalReport>,
    pub warnings: Vec<String>,
}

fn is_denied(grants: &[Grant], action: &str) -> bool {
    grants.iter().any(|g| {
        g.statement.effect == Effect::Deny
            && g.statement.is_unscoped()
            && g.statement.matches_action(action)
    })
}

/// Sources of Allow statements granting `action` (on any resource), unless explicitly denied.
fn allow_sources<'a>(grants: &'a [Grant], action: &str) -> Vec<&'a str> {
    if is_denied(grants, action) {
        return Vec::new();
    }
    grants
        .iter()
        .filter(|g| g.statement.effect == Effect::Allow && g.statement.matches_action(action))
        .map(|g| g.source.as_str())
        .collect()
}

/// Parses the `YYYY-MM-DD` prefix of an ISO-8601 timestamp into days since the Unix epoch.
pub fn days_from_iso(s: &str) -> Option<i64> {
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let m: i64 = s.get(5..7)?.parse().ok()?;
    let d: i64 = s.get(8..10)?.parse().ok()?;
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn privilege_findings(p: &Principal, out: &mut Vec<Finding>) {
    let admin: Vec<String> = p
        .grants
        .iter()
        .filter(|g| {
            g.statement.effect == Effect::Allow
                && g.statement.is_unscoped()
                && g.statement.actions().iter().any(|a| a == "*")
        })
        .map(|g| g.source.clone())
        .collect();
    if !admin.is_empty() {
        out.push(Finding {
            rule: "full_admin",
            severity: Severity::Critical,
            title: "Unrestricted administrator access (Action \"*\" on Resource \"*\")".into(),
            evidence: admin,
            remediation: "Replace with a scoped role; reserve admin for break-glass identities protected by MFA and alerts.",
        });
        return;
    }

    let not_action: Vec<String> = p
        .grants
        .iter()
        .filter(|g| g.statement.effect == Effect::Allow && g.statement.not_action.is_some())
        .map(|g| g.source.clone())
        .collect();
    if !not_action.is_empty() {
        out.push(Finding {
            rule: "allow_not_action",
            severity: Severity::High,
            title: "Allow + NotAction grants every action except the listed ones, including future services".into(),
            evidence: not_action,
            remediation: "Rewrite as an explicit Action allow-list.",
        });
    }

    for path in ESCALATION_PATHS {
        let mut evidence = Vec::with_capacity(path.actions.len());
        for action in path.actions {
            let sources = allow_sources(&p.grants, action);
            if sources.is_empty() {
                break;
            }
            evidence.push(format!("{action} via {}", sources.join(", ")));
        }
        if evidence.len() == path.actions.len() {
            out.push(Finding {
                rule: path.id,
                severity: Severity::High,
                title: format!("Privilege escalation: {}", path.impact),
                evidence,
                remediation: "Remove or tightly scope these actions (resource ARNs, iam:PassedToService, permission boundaries).",
            });
        }
    }

    let mut wildcards: Vec<(String, bool)> = Vec::new();
    for g in &p.grants {
        if g.statement.effect != Effect::Allow {
            continue;
        }
        for a in g.statement.actions() {
            if let Some(service) = a.strip_suffix(":*") {
                let sensitive = SENSITIVE_SERVICES.contains(&service.to_ascii_lowercase().as_str());
                wildcards.push((format!("{a} via {}", g.source), sensitive));
            } else if a == "*" {
                wildcards.push((format!("* (scoped) via {}", g.source), true));
            }
        }
    }
    if !wildcards.is_empty() {
        let sensitive = wildcards.iter().any(|w| w.1);
        out.push(Finding {
            rule: "service_wildcard",
            severity: if sensitive { Severity::High } else { Severity::Medium },
            title: "Service-wide wildcard actions".into(),
            evidence: wildcards.into_iter().map(|w| w.0).collect(),
            remediation: "Replace wildcards with the specific actions in use (see `least-privilege`).",
        });
    }
}

fn activity_findings(
    p: &Principal,
    used: Option<&BTreeMap<String, ActionUse>>,
    has_trail: bool,
    opts: Options,
    out: &mut Vec<Finding>,
) -> Option<UsageSummary> {
    let age = |d: &Option<String>| {
        d.as_deref()
            .and_then(days_from_iso)
            .map(|d| opts.now_days - d)
    };
    let dormant = match (p.kind, age(&p.last_used), age(&p.created)) {
        (PrincipalKind::Role, Some(idle), _) if idle > opts.dormant_days => {
            Some(format!("role last used {idle} days ago"))
        }
        (PrincipalKind::Role, None, Some(created)) if created > opts.dormant_days => {
            Some(format!("role never used; created {created} days ago"))
        }
        _ => None,
    };
    if let Some(e) = dormant {
        out.push(Finding {
            rule: "dormant_principal",
            severity: Severity::Medium,
            title: format!("Inactive for more than {} days", opts.dormant_days),
            evidence: vec![e],
            remediation: "Delete the role or remove its policies; unused privileged identities are prime takeover targets.",
        });
    } else if has_trail && used.is_none() {
        out.push(Finding {
            rule: "no_observed_activity",
            severity: Severity::Low,
            title: "No successful API calls in the supplied CloudTrail window".into(),
            evidence: vec![],
            remediation: "Confirm the identity is still needed; disable keys or delete it if not.",
        });
    }

    let used = used?;
    let explicit: BTreeSet<String> = p
        .grants
        .iter()
        .filter(|g| g.statement.effect == Effect::Allow)
        .flat_map(|g| g.statement.actions())
        .filter(|a| !is_wildcard(a))
        .map(|a| a.to_ascii_lowercase())
        .collect();
    let unused: Vec<String> = explicit
        .iter()
        .filter(|a| !used.contains_key(*a))
        .cloned()
        .collect();
    let wildcard_grants: BTreeSet<String> = p
        .grants
        .iter()
        .filter(|g| g.statement.effect == Effect::Allow)
        .flat_map(|g| g.statement.actions())
        .filter(|a| is_wildcard(a))
        .cloned()
        .collect();
    if !unused.is_empty() {
        let ratio = unused.len() as f64 / explicit.len() as f64;
        out.push(Finding {
            rule: "unused_permissions",
            severity: if ratio >= 0.5 {
                Severity::Medium
            } else {
                Severity::Low
            },
            title: format!(
                "{} of {} explicitly granted actions were never used ({:.0}%)",
                unused.len(),
                explicit.len(),
                ratio * 100.0
            ),
            evidence: unused.iter().take(25).cloned().collect(),
            remediation: "Apply the generated least-privilege policy after a review period.",
        });
    }
    Some(UsageSummary {
        observed_actions: used.len(),
        granted_explicit_actions: explicit.len(),
        unused_explicit_actions: unused,
        wildcard_grants: wildcard_grants.into_iter().collect(),
    })
}

pub fn analyze_principal(p: &Principal, usage: Option<&Usage>, opts: Options) -> PrincipalReport {
    let mut findings = Vec::new();
    privilege_findings(p, &mut findings);
    let used = usage.and_then(|u| u.by_principal.get(&p.arn));
    let usage_summary = activity_findings(p, used, usage.is_some(), opts, &mut findings);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.rule.cmp(b.rule)));
    PrincipalReport {
        arn: p.arn.clone(),
        name: p.name.clone(),
        kind: p.kind,
        risk_score: findings
            .iter()
            .map(|f| f.severity.weight())
            .sum::<u32>()
            .min(100),
        findings,
        usage: usage_summary,
    }
}

pub fn analyze(
    principals: &[Principal],
    warnings: Vec<String>,
    usage: Option<&Usage>,
    opts: Options,
) -> Report {
    let mut reports: Vec<PrincipalReport> = principals
        .iter()
        .map(|p| analyze_principal(p, usage, opts))
        .collect();
    reports.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| a.arn.cmp(&b.arn))
    });
    let mut severity_counts = BTreeMap::new();
    for f in reports.iter().flat_map(|r| &r.findings) {
        *severity_counts.entry(f.severity).or_default() += 1;
    }
    Report {
        principals_analyzed: principals.len(),
        severity_counts,
        principals: reports,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Statement;

    fn principal(kind: PrincipalKind, statements: &[&str]) -> Principal {
        Principal {
            kind,
            name: "p".into(),
            arn: "arn:aws:iam::1:user/p".into(),
            grants: statements
                .iter()
                .map(|s| Grant {
                    source: "inline:test".into(),
                    statement: serde_json::from_str::<Statement>(s).unwrap(),
                })
                .collect(),
            last_used: None,
            created: None,
        }
    }

    fn rules(p: &Principal) -> Vec<&'static str> {
        let opts = Options {
            now_days: 20_000,
            dormant_days: 90,
        };
        analyze_principal(p, None, opts)
            .findings
            .iter()
            .map(|f| f.rule)
            .collect()
    }

    #[test]
    fn admin_suppresses_redundant_findings() {
        let p = principal(
            PrincipalKind::User,
            &[r#"{"Effect":"Allow","Action":"*","Resource":"*"}"#],
        );
        assert_eq!(rules(&p), ["full_admin"]);
    }

    #[test]
    fn detects_multi_action_escalation() {
        let p = principal(
            PrincipalKind::User,
            &[r#"{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"}"#],
        );
        assert_eq!(rules(&p), ["privesc_passrole_ec2"]);
    }

    #[test]
    fn explicit_deny_breaks_path() {
        let p = principal(
            PrincipalKind::User,
            &[
                r#"{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"}"#,
                r#"{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}"#,
            ],
        );
        assert!(rules(&p).is_empty());
    }

    #[test]
    fn dormant_roles() {
        let mut p = principal(PrincipalKind::Role, &[]);
        p.last_used = Some("2024-01-01T00:00:00Z".into());
        let opts = Options {
            now_days: days_from_iso("2026-11-25").unwrap(),
            dormant_days: 90,
        };
        let r = analyze_principal(&p, None, opts);
        assert_eq!(r.findings[0].rule, "dormant_principal");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(days_from_iso("1970-01-01"), Some(0));
        assert_eq!(days_from_iso("2000-03-01"), Some(11_017));
        assert_eq!(days_from_iso("bad"), None);
    }

    #[test]
    fn unused_permissions_from_usage() {
        let p = principal(
            PrincipalKind::User,
            &[
                r#"{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],"Resource":"*"}"#,
            ],
        );
        let mut usage = Usage::default();
        usage.by_principal.insert(
            p.arn.clone(),
            BTreeMap::from([("s3:getobject".into(), ActionUse::default())]),
        );
        let opts = Options {
            now_days: 0,
            dormant_days: 90,
        };
        let r = analyze_principal(&p, Some(&usage), opts);
        assert_eq!(r.findings[0].rule, "unused_permissions");
        assert_eq!(r.findings[0].severity, Severity::Medium);
        assert_eq!(
            r.usage.unwrap().unused_explicit_actions,
            ["s3:deleteobject", "s3:putobject"]
        );
    }
}
