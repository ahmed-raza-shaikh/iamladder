//! Aggregates CloudTrail events into per-principal action usage.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    event_source: String,
    event_name: String,
    user_identity: Identity,
    error_code: Option<String>,
    #[serde(default)]
    resources: Vec<EventResource>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Identity {
    #[serde(rename = "type")]
    kind: Option<String>,
    arn: Option<String>,
    session_context: Option<SessionContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionContext {
    session_issuer: Option<SessionIssuer>,
}

#[derive(Deserialize)]
struct SessionIssuer {
    arn: Option<String>,
}

#[derive(Deserialize)]
struct EventResource {
    #[serde(rename = "ARN")]
    arn: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TrailFile {
    Records {
        #[serde(rename = "Records")]
        records: Vec<Event>,
    },
    List(Vec<Event>),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ActionUse {
    /// Action as it appears in policies, e.g. `s3:GetObject`.
    pub name: String,
    pub count: u64,
    pub resources: BTreeSet<String>,
    /// At least one call did not report a resource ARN, so resource scoping is unknown.
    pub unscoped_calls: bool,
}

#[derive(Debug, Default)]
pub struct Usage {
    /// principal ARN -> lowercase action -> usage
    pub by_principal: HashMap<String, BTreeMap<String, ActionUse>>,
    pub events: u64,
    pub denied: u64,
    pub unattributed: u64,
}

/// CloudTrail event sources whose IAM action prefix differs from the hostname.
fn service_prefix(event_source: &str) -> &str {
    let host = event_source
        .strip_suffix(".amazonaws.com")
        .unwrap_or(event_source);
    match host {
        "monitoring" => "cloudwatch",
        "email" => "ses",
        "elasticmapreduce" => "elasticmapreduce",
        "streams.dynamodb" => "dynamodb",
        h => h,
    }
}

/// Strips API version suffixes such as `UpdateFunctionCode20150331v2`.
fn canonical_event_name(name: &str) -> &str {
    let b = name.as_bytes();
    let mut end = b.len();
    if let Some(v) = name.rfind('v')
        && v + 1 < b.len()
        && b[v + 1..].iter().all(u8::is_ascii_digit)
    {
        end = v;
    }
    if end >= 8 && b[end - 8..end].iter().all(u8::is_ascii_digit) {
        &name[..end - 8]
    } else {
        name
    }
}

fn principal_arn(id: &Identity) -> Option<&str> {
    match id.kind.as_deref() {
        Some("AssumedRole") => id
            .session_context
            .as_ref()
            .and_then(|s| s.session_issuer.as_ref())
            .and_then(|i| i.arn.as_deref()),
        _ => id.arn.as_deref(),
    }
}

impl Usage {
    pub fn ingest_json(&mut self, raw: &str) -> serde_json::Result<()> {
        let events = match serde_json::from_str(raw)? {
            TrailFile::Records { records } => records,
            TrailFile::List(list) => list,
        };
        for e in events {
            self.events += 1;
            if e.error_code
                .as_deref()
                .is_some_and(|c| c.contains("AccessDenied") || c.contains("Unauthorized"))
            {
                self.denied += 1;
                continue;
            }
            let Some(arn) = principal_arn(&e.user_identity) else {
                self.unattributed += 1;
                continue;
            };
            let name = format!(
                "{}:{}",
                service_prefix(&e.event_source),
                canonical_event_name(&e.event_name)
            );
            let entry = self
                .by_principal
                .entry(arn.to_string())
                .or_default()
                .entry(name.to_ascii_lowercase())
                .or_insert_with(|| ActionUse {
                    name,
                    ..ActionUse::default()
                });
            entry.count += 1;
            let arns: Vec<String> = e.resources.into_iter().filter_map(|r| r.arn).collect();
            if arns.is_empty() {
                entry.unscoped_calls = true;
            }
            entry.resources.extend(arns);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_roles_users_and_skips_denied() {
        let mut u = Usage::default();
        u.ingest_json(
            r#"{"Records":[
              {"eventSource":"s3.amazonaws.com","eventName":"GetObject","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::1:assumed-role/app/i-1","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::1:role/app"}}},"resources":[{"ARN":"arn:aws:s3:::bucket/key"}]},
              {"eventSource":"monitoring.amazonaws.com","eventName":"PutMetricData","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::1:user/bob"}},
              {"eventSource":"lambda.amazonaws.com","eventName":"UpdateFunctionCode20150331v2","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::1:user/bob"}},
              {"eventSource":"iam.amazonaws.com","eventName":"CreateUser","errorCode":"AccessDenied","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::1:user/bob"}}
            ]}"#,
        )
        .unwrap();
        assert_eq!((u.events, u.denied), (4, 1));
        let app = &u.by_principal["arn:aws:iam::1:role/app"]["s3:getobject"];
        assert!(app.resources.contains("arn:aws:s3:::bucket/key") && !app.unscoped_calls);
        let bob = &u.by_principal["arn:aws:iam::1:user/bob"];
        assert!(bob.contains_key("cloudwatch:putmetricdata"));
        assert!(bob.contains_key("lambda:updatefunctioncode"));
        assert!(!bob.contains_key("iam:createuser"));
    }
}
