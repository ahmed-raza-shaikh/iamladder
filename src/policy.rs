//! IAM policy document model and action matching.

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl<T> OneOrMany<T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::One(v) => std::slice::from_ref(v),
            Self::Many(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Statement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub effect: Effect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<OneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_action: Option<OneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<OneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_resource: Option<OneOrMany<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<serde_json::Value>,
}

impl Statement {
    pub fn actions(&self) -> &[String] {
        self.action.as_ref().map_or(&[], OneOrMany::as_slice)
    }

    pub fn matches_action(&self, action: &str) -> bool {
        match (&self.action, &self.not_action) {
            (Some(a), _) => a.as_slice().iter().any(|p| glob_match(p, action)),
            (None, Some(na)) => !na.as_slice().iter().any(|p| glob_match(p, action)),
            (None, None) => false,
        }
    }

    /// True when the statement applies to every resource without conditions.
    pub fn is_unscoped(&self) -> bool {
        self.condition.is_none()
            && self.not_resource.is_none()
            && self
                .resource
                .as_ref()
                .is_some_and(|r| r.as_slice().iter().any(|r| r == "*"))
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyDocument {
    #[serde(default)]
    pub statement: OneOrMany<Statement>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawDocument {
    #[serde(default)]
    statement: OneOrMany<Statement>,
}

impl<'de> Deserialize<'de> for PolicyDocument {
    /// Accepts a JSON object or the URL-encoded string the raw IAM API returns.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            Object(RawDocument),
            Encoded(String),
        }
        let raw = match Either::deserialize(d)? {
            Either::Object(o) => o,
            Either::Encoded(s) => {
                serde_json::from_str(&percent_decode(&s)).map_err(serde::de::Error::custom)?
            }
        };
        Ok(Self {
            statement: raw.statement,
        })
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16).map(|v| v as u8);
        match (
            b[i],
            b.get(i + 1).and_then(|&c| hex(c)),
            b.get(i + 2).and_then(|&c| hex(c)),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push(h << 4 | l);
                i += 3;
            }
            (b'+', _, _) => {
                out.push(b' ');
                i += 1;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Case-insensitive IAM wildcard match supporting `*` and `?`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

pub fn is_wildcard(action: &str) -> bool {
    action.contains(['*', '?'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matching() {
        assert!(glob_match("*", "s3:GetObject"));
        assert!(glob_match("s3:*", "S3:getobject"));
        assert!(glob_match("iam:Create*Key", "iam:CreateAccessKey"));
        assert!(glob_match("ec2:?unInstances", "ec2:RunInstances"));
        assert!(!glob_match("s3:Get*", "s3:PutObject"));
        assert!(!glob_match("iam:PassRole", "iam:PassRoles"));
    }

    #[test]
    fn parses_single_statement_and_strings() {
        let doc: PolicyDocument = serde_json::from_str(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}"#,
        )
        .unwrap();
        let s = &doc.statement.as_slice()[0];
        assert!(s.matches_action("s3:GetObject"));
        assert!(s.is_unscoped());
    }

    #[test]
    fn parses_url_encoded_documents() {
        let doc: PolicyDocument = serde_json::from_str(
            r#""%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22iam%3APassRole%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D""#,
        )
        .unwrap();
        assert!(doc.statement.as_slice()[0].matches_action("iam:PassRole"));
    }

    #[test]
    fn not_action_inverts_match() {
        let s: Statement =
            serde_json::from_str(r#"{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}"#)
                .unwrap();
        assert!(s.matches_action("ec2:RunInstances"));
        assert!(!s.matches_action("iam:PassRole"));
    }

    #[test]
    fn conditions_make_statement_scoped() {
        let s: Statement = serde_json::from_str(
            r#"{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}"#,
        )
        .unwrap();
        assert!(!s.is_unscoped());
    }
}
