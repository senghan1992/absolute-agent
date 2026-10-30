//! 시크릿 마스킹 — 리포트·로그·LLM 전달 전에 자격증명을 가린다.
//!
//! 발견 증거에는 요청 헤더나 본문 전체가 붙기 때문에, 그대로 저장하면
//! 리포트가 곧 자격증명 유출물이 된다. 이 모듈은 저장 직전에 시크릿을 가린다.
//!
//! 원칙:
//!   - 값은 **삭제하지 않고 형태만 남긴다** (`AKIA…MPLE`) — 근거는 유지
//!   - 탐지 규칙은 보수적으로 — 일반 텍스트를 시크릿으로 오인하지 않는다
//!   - 마스킹 결과는 원본과 다른 문자열을 쓴다 (치환 후 재탐지 루프 방지)

use regex::Regex;
use std::sync::OnceLock;

/// 마스킹 대체 문자열.
const MASK: &str = "***REDACTED***";

/// 헤더 이름이 민감한지.
pub fn is_sensitive_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "authorization"
        || n == "proxy-authorization"
        || n == "cookie"
        || n == "set-cookie"
        || n == "x-api-key"
        || n == "api-key"
        || n == "x-auth-token"
        || n == "x-access-token"
        || n == "x-csrf-token"
        || n == "x-xsrf-token"
        || n == "authentication"
}

/// 헤더 목록 마스킹.
pub fn redact_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            if is_sensitive_header(k) {
                (k.clone(), MASK.to_string())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

/// URL 쿼리에서 민감한 파라미터 값을 가린다.
pub fn redact_url(url: &str) -> String {
    let Ok(mut u) = url::Url::parse(url) else { return url.to_string() };
    let pairs: Vec<(String, String)> = u
        .query_pairs()
        .map(|(k, v)| {
            if is_sensitive_param(&k) {
                (k.into_owned(), MASK.to_string())
            } else {
                (k.into_owned(), v.into_owned())
            }
        })
        .collect();
    if pairs.is_empty() {
        return url.to_string();
    }
    u.query_pairs_mut().clear();
    for (k, v) in pairs {
        u.query_pairs_mut().append_pair(&k, &v);
    }
    u.to_string()
}

/// 민감한 쿼리 파라미터 이름.
pub fn is_sensitive_param(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "token", "access_token", "refresh_token", "id_token", "password", "passwd", "pwd", "secret",
        "api_key", "apikey", "key", "auth", "authorization", "session", "sessionid", "sid", "jwt",
        "signature", "sig", "code", "otp", "mfa", "remember_token", "csrf", "xsrf",
    ]
    .iter()
    .any(|needle| n == *needle || n.ends_with(&format!("_{needle}")) || n.starts_with(&format!("{needle}_")))
}

struct Rules {
    patterns: Vec<(&'static str, Regex)>,
}

fn rules() -> &'static Rules {
    static CELL: OnceLock<Rules> = OnceLock::new();
    CELL.get_or_init(|| {
        let patterns: Vec<(&'static str, Regex)> = vec![
            ("private_key", Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----").unwrap()),
            ("jwt", Regex::new(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}").unwrap()),
            ("aws_key", Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap()),
            ("github_token", Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b").unwrap()),
            ("slack_token", Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b").unwrap()),
            ("google_key", Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap()),
            ("bearer", Regex::new(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}").unwrap()),
            // JSON/INI/YAML 스타일의 키-값 (접두/접미 변형까지 커버)
            ("kv_secret", Regex::new(r#"(?i)(["']?(?:[a-z0-9_.-]*(?:api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|pass|auth[_-]?token|access[_-]?token|refresh[_-]?token|private[_-]?key|session[_-]?id|credential|secret|token|key))["']?\s*[:=]\s*["']?)([A-Za-z0-9._~+/=-]{8,})(["']?)"#).unwrap()),
            // connection string
            ("conn_str", Regex::new(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@)[^\s]+").unwrap()),
        ];
        Rules { patterns }
    })
}

/// 텍스트에서 시크릿을 마스킹한다.
pub fn redact_text(text: &str) -> String {
    let mut out = text.to_string();
    for rule in rules().patterns.iter() {
        out = match rule.0 {
            "private_key" => rule.1.replace_all(&out, "-----BEGIN PRIVATE KEY----- [REDACTED] -----END PRIVATE KEY-----").to_string(),
            "kv_secret" => {
                rule.1.replace_all(&out, |c: &regex::Captures| {
                    format!("{}{}{}", &c[1], MASK, &c[3])
                }).to_string()
            }
            "conn_str" => rule.1.replace_all(&out, |c: &regex::Captures| {
                format!("{}{}", &c[1], MASK)
            }).to_string(),
            "bearer" => rule.1.replace_all(&out, |c: &regex::Captures| {
                let scheme = c[1].to_uppercase();
                format!("{scheme} {MASK}")
            }).to_string(),
            _ => rule.1.replace_all(&out, MASK).to_string(),
        };
    }
    out
}

/// 시크릿이 포함되었는지 빠르게 확인 (마스킹이 필요한지 판단).
pub fn contains_secret(text: &str) -> bool {
    rules().patterns.iter().any(|(_, re)| re.is_match(text))
}

/// 증거 문자열을 안전하게 만든다 — 본문 + 헤더 + URL 을 함께 마스킹.
pub fn redact_evidence(body: &str, headers: &[(String, String)], url: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("URL: {}\n", redact_url(url)));
    if !headers.is_empty() {
        out.push_str("헤더:\n");
        for (k, v) in redact_headers(headers) {
            out.push_str(&format!("  {k}: {v}\n"));
        }
    }
    out.push_str("본문:\n");
    out.push_str(&redact_text(body));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_aws_key() {
        let out = redact_text("key=AKIAIOSFODNN7EXAMPLE here");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "{out}");
        assert!(out.contains("here"), "{out}");
    }

    #[test]
    fn masks_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefgh";
        let out = redact_text(&format!("token: {jwt}"));
        assert!(!out.contains(jwt), "{out}");
    }

    #[test]
    fn masks_bearer_header_value() {
        let out = redact_text("Authorization: Bearer abcdefghijklmnop");
        assert!(!out.contains("abcdefghijklmnop"), "{out}");
    }

    #[test]
    fn masks_password_kv() {
        let out = redact_text(r#"{"password": "sup3rS3cretValue"}"#);
        assert!(!out.contains("sup3rS3cretValue"), "{out}");
        assert!(out.contains("password"), "{out}");
    }

    #[test]
    fn masks_prefixed_env_style_secrets() {
        let out = redact_text("API_KEY=sk_live_abcdef1234567890abcd\nDB_PASS=sup3rs3cret\nSECRET_TOKEN=abcdefgh12345678");
        assert!(!out.contains("sk_live_abcdef1234567890abcd"), "{out}");
        assert!(!out.contains("sup3rs3cret"), "{out}");
        assert!(!out.contains("abcdefgh12345678"), "{out}");
    }

    #[test]
    fn keeps_normal_text() {
        let text = "사용자 로그인 성공 (user=alice, role=admin)";
        assert_eq!(redact_text(text), text);
    }

    #[test]
    fn masks_headers() {
        let h = vec![
            ("Cookie".to_string(), "session=abc123".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let out = redact_headers(&h);
        assert_eq!(out[0].1, MASK);
        assert_eq!(out[1].1, "application/json");
    }

    #[test]
    fn masks_url_params() {
        let out = redact_url("http://h/api?token=abc123def&page=2");
        assert!(!out.contains("abc123def"), "{out}");
        assert!(out.contains("page=2"), "{out}");
    }
}
