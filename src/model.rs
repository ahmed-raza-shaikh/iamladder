//! Loads the output of `aws iam get-account-authorization-details` into resolved principals.

use crate::policy::{Effect, OneOrMany, PolicyDocument, Statement};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthorizationDetails {
    #[serde(default)]
    pub user_detail_list: Vec<UserDetail>,
    #[serde(default)]
    pub group_detail_list: Vec<GroupDetail>,
    #[serde(default)]
    pub role_detail_list: Vec<RoleDetail>,
    #[serde(default)]
    pub policies: Vec<ManagedPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InlinePolicy {
    pub policy_name: String,
    pub policy_document: PolicyDocument,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AttachedPolicy {
    pub policy_name: String,
    pub policy_arn: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserDetail {
    pub user_name: String,
    pub arn: String,
    #[serde(default)]
    pub user_policy_list: Vec<InlinePolicy>,
    #[serde(default)]
    pub attached_managed_policies: Vec<AttachedPolicy>,
    #[serde(default)]
    pub group_list: Vec<String>,
    pub create_date: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GroupDetail {
    pub group_name: String,
    #[serde(default)]
    pub group_policy_list: Vec<InlinePolicy>,
    #[serde(default)]
    pub attached_managed_policies: Vec<AttachedPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RoleLastUsed {
    pub last_used_date: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RoleDetail {
    pub role_name: String,
    pub arn: String,
    #[serde(default)]
    pub role_policy_list: Vec<InlinePolicy>,
    #[serde(default)]
    pub attached_managed_policies: Vec<AttachedPolicy>,
    pub role_last_used: Option<RoleLastUsed>,
    pub create_date: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyVersion {
    pub document: PolicyDocument,
    #[serde(default)]
    pub is_default_version: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ManagedPolicy {
    pub arn: String,
    #[serde(default)]
    pub policy_version_list: Vec<PolicyVersion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    User,
    Role,
}

/// A statement together with where it came from (for evidence in findings).
#[derive(Debug, Clone)]
pub struct Grant {
    pub source: String,
    pub statement: Statement,
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub kind: PrincipalKind,
    pub name: String,
    pub arn: String,
    pub grants: Vec<Grant>,
    pub last_used: Option<String>,
    pub created: Option<String>,
}

const ADMINISTRATOR_ACCESS: &str = "arn:aws:iam::aws:policy/AdministratorAccess";

fn admin_statement() -> Statement {
    Statement {
        sid: None,
        effect: Effect::Allow,
        action: Some(OneOrMany::One("*".into())),
        not_action: None,
        resource: Some(OneOrMany::One("*".into())),
        not_resource: None,
        condition: None,
    }
}

struct Resolver<'a> {
    managed: HashMap<&'a str, &'a PolicyDocument>,
    warnings: Vec<String>,
}

impl Resolver<'_> {
    fn push_inline(&self, out: &mut Vec<Grant>, prefix: &str, list: &[InlinePolicy]) {
        for p in list {
            for s in p.policy_document.statement.as_slice() {
                out.push(Grant {
                    source: format!("{prefix}inline:{}", p.policy_name),
                    statement: s.clone(),
                });
            }
        }
    }

    fn push_attached(&mut self, out: &mut Vec<Grant>, prefix: &str, list: &[AttachedPolicy]) {
        for a in list {
            let source = format!("{prefix}managed:{}", a.policy_name);
            match self.managed.get(a.policy_arn.as_str()) {
                Some(doc) => out.extend(doc.statement.as_slice().iter().map(|s| Grant {
                    source: source.clone(),
                    statement: s.clone(),
                })),
                None if a.policy_arn == ADMINISTRATOR_ACCESS => out.push(Grant {
                    source,
                    statement: admin_statement(),
                }),
                None => self.warnings.push(format!(
                    "managed policy {} not present in input; its permissions were not analyzed",
                    a.policy_arn
                )),
            }
        }
    }
}

impl AuthorizationDetails {
    /// Flattens users (including group memberships) and roles into principals.
    pub fn principals(&self) -> (Vec<Principal>, Vec<String>) {
        let mut r = Resolver {
            managed: self
                .policies
                .iter()
                .filter_map(|p| {
                    p.policy_version_list
                        .iter()
                        .find(|v| v.is_default_version)
                        .map(|v| (p.arn.as_str(), &v.document))
                })
                .collect(),
            warnings: Vec::new(),
        };
        let groups: HashMap<&str, &GroupDetail> = self
            .group_detail_list
            .iter()
            .map(|g| (g.group_name.as_str(), g))
            .collect();

        let mut out = Vec::with_capacity(self.user_detail_list.len() + self.role_detail_list.len());
        for u in &self.user_detail_list {
            let mut grants = Vec::new();
            r.push_inline(&mut grants, "", &u.user_policy_list);
            r.push_attached(&mut grants, "", &u.attached_managed_policies);
            for g in &u.group_list {
                let prefix = format!("group:{g}/");
                match groups.get(g.as_str()) {
                    Some(gd) => {
                        r.push_inline(&mut grants, &prefix, &gd.group_policy_list);
                        r.push_attached(&mut grants, &prefix, &gd.attached_managed_policies);
                    }
                    None => r
                        .warnings
                        .push(format!("group {g} of user {} not found", u.user_name)),
                }
            }
            out.push(Principal {
                kind: PrincipalKind::User,
                name: u.user_name.clone(),
                arn: u.arn.clone(),
                grants,
                last_used: None,
                created: u.create_date.clone(),
            });
        }
        for role in &self.role_detail_list {
            let mut grants = Vec::new();
            r.push_inline(&mut grants, "", &role.role_policy_list);
            r.push_attached(&mut grants, "", &role.attached_managed_policies);
            out.push(Principal {
                kind: PrincipalKind::Role,
                name: role.role_name.clone(),
                arn: role.arn.clone(),
                grants,
                last_used: role
                    .role_last_used
                    .as_ref()
                    .and_then(|l| l.last_used_date.clone()),
                created: role.create_date.clone(),
            });
        }
        r.warnings.sort();
        r.warnings.dedup();
        (out, r.warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_groups_and_managed_policies() {
        let details: AuthorizationDetails = serde_json::from_str(
            r#"{
              "UserDetailList": [{"UserName":"alice","Arn":"arn:aws:iam::1:user/alice","GroupList":["devs"],
                 "AttachedManagedPolicies":[{"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"},
                                            {"PolicyName":"Missing","PolicyArn":"arn:aws:iam::1:policy/Missing"}]}],
              "GroupDetailList": [{"GroupName":"devs","AttachedManagedPolicies":[{"PolicyName":"S3","PolicyArn":"arn:aws:iam::1:policy/S3"}]}],
              "RoleDetailList": [{"RoleName":"ci","Arn":"arn:aws:iam::1:role/ci","RoleLastUsed":{"LastUsedDate":"2026-01-01T00:00:00Z"},
                 "RolePolicyList":[{"PolicyName":"pass","PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}}]}],
              "Policies": [{"Arn":"arn:aws:iam::1:policy/S3","PolicyVersionList":[
                 {"IsDefaultVersion":false,"Document":{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}},
                 {"IsDefaultVersion":true,"Document":{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}}]}]
            }"#,
        )
        .unwrap();
        let (principals, warnings) = details.principals();
        assert_eq!(principals.len(), 2);
        let alice = &principals[0];
        assert_eq!(alice.grants.len(), 2);
        assert_eq!(alice.grants[1].source, "group:devs/managed:S3");
        assert!(alice.grants[1].statement.matches_action("s3:GetObject"));
        assert!(!alice.grants[1].statement.matches_action("s3:PutObject"));
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            principals[1].last_used.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
    }
}
