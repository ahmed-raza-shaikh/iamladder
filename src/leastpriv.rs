//! Generates a least-privilege policy from observed CloudTrail usage.

use crate::cloudtrail::ActionUse;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Actions sharing the same resource set are merged into one statement. Resources fall back
/// to `*` when any call lacked a resource ARN, because CloudTrail cannot prove a narrower scope.
pub fn generate(usage: &BTreeMap<String, ActionUse>) -> Value {
    let mut groups: BTreeMap<Vec<&str>, Vec<&str>> = BTreeMap::new();
    for u in usage.values() {
        let resources = if u.unscoped_calls || u.resources.is_empty() {
            vec!["*"]
        } else {
            u.resources.iter().map(String::as_str).collect()
        };
        groups.entry(resources).or_default().push(&u.name);
    }
    let statements: Vec<Value> = groups
        .into_iter()
        .enumerate()
        .map(|(i, (resources, mut actions))| {
            actions.sort_unstable();
            json!({
                "Sid": format!("Observed{}", i + 1),
                "Effect": "Allow",
                "Action": actions,
                "Resource": if resources.len() == 1 { json!(resources[0]) } else { json!(resources) },
            })
        })
        .collect();
    json!({ "Version": "2012-10-17", "Statement": statements })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn use_of(name: &str, resources: &[&str], unscoped: bool) -> ActionUse {
        ActionUse {
            name: name.into(),
            count: 1,
            resources: resources.iter().map(|s| s.to_string()).collect(),
            unscoped_calls: unscoped,
        }
    }

    #[test]
    fn groups_actions_by_resource() {
        let usage = BTreeMap::from([
            (
                "s3:getobject".into(),
                use_of("s3:GetObject", &["arn:aws:s3:::b/*"], false),
            ),
            (
                "s3:putobject".into(),
                use_of("s3:PutObject", &["arn:aws:s3:::b/*"], false),
            ),
            (
                "sts:getcalleridentity".into(),
                use_of("sts:GetCallerIdentity", &[], true),
            ),
        ]);
        let p = generate(&usage);
        let s = p["Statement"].as_array().unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0]["Resource"], "*");
        assert_eq!(s[0]["Action"], json!(["sts:GetCallerIdentity"]));
        assert_eq!(s[1]["Action"], json!(["s3:GetObject", "s3:PutObject"]));
        assert_eq!(s[1]["Resource"], "arn:aws:s3:::b/*");
    }
}
