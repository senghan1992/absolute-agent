//! 논리 취약점 탐지 모듈 — 스톰(비양자식 변이)과 다른 축의 점검.
//!
//! 스톰은 "값을 바꿔 응답이 어떻게 달라지는가"를 본다. 이 모듈은 그와 달리
//! **의미론적 상태**를 다룬다.
//!   - idor   : 이 리소스 외의 다른 리소스가 접근되는가 (인가 검증 누락)
//!   - tamper : 금액/수량이 서버에서 재검증되지 않고 그대로 반영되는가
//!
//! 두 모듈 모두 인가 게이트·RPS 상한을 지키고, 근거를 남긴 Finding 을 만든다.

pub mod idor;
pub mod tamper;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use serde_json::Value;

use crate::scope::Authorization;
use crate::storm::Gate;

/// 프로브 응답.
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub status: u16,
    pub body: String,
    pub len: usize,
    pub elapsed_ms: u64,
    pub headers: Vec<(String, String)>,
}

impl ProbeResponse {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// 프로브용 HTTP 클라이언트 — 인가 검사 + RPS 상한을 반드시 거친다.
pub struct ProbeClient {
    client: reqwest::Client,
    auth: Arc<Authorization>,
    gate: Arc<Gate>,
}

impl ProbeClient {
    pub fn new(auth: Arc<Authorization>) -> Result<Self, String> {
        let insecure = std::env::var("FORGE_INSECURE").ok().as_deref() == Some("1");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(insecure)
            .user_agent("REDFORGE/0.1 (+authorized-security-testing)")
            .build()
            .map_err(|e| e.to_string())?;
        let gate = Arc::new(Gate::new(auth.rps_limit()));
        Ok(Self { client, auth, gate })
    }

    /// 인가 대상인지 확인 (호스트·포트).
    pub fn check_scope(&self, url: &str) -> Result<(String, Option<u16>), String> {
        let (host, port, _) = crate::scope::split_authority(url).map_err(|e| e.to_string())?;
        self.auth.check(&host, port).map_err(|e| e.to_string())?;
        Ok((host, port))
    }

    /// 요청 1회 — 인가 게이트와 RPS 상한을 적용한다.
    pub async fn request(
        &self,
        method: &str,
        url: &str,
        query: &[(String, String)],
        body: Option<&str>,
    ) -> Result<ProbeResponse, String> {
        self.check_scope(url)?;
        self.gate.acquire().await;

        let mut full = url.to_string();
        for (k, v) in query {
            full = crate::storm::inject_query(&full, k, v);
        }
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut req = self.client.request(m, &full);
        for (k, v) in self.auth.credentials.merge_headers() {
            req = req.header(k, v);
        }
        if let Some(b) = body {
            req = req.body(b.to_string());
        }
        let started = std::time::Instant::now();
        let resp = req.send().await.map_err(|e| format!("요청 실패: {e}"))?;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp.text().await.unwrap_or_default();
        Ok(ProbeResponse { status, len: body.len(), body, elapsed_ms, headers })
    }
}

/// 금액/수량 관련 필드명.
pub fn is_money_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    [
        "price", "amount", "total", "subtotal", "grand_total", "qty", "quantity", "cost", "fee",
        "balance", "credit", "discount", "tax", "payment", "charge", "unit_price", "shipping",
        "net", "gross", "value",
    ]
    .iter()
    .any(|needle| k.contains(needle))
}

/// 응답에서 금액/수량 숫자 필드를 추출한다 (JSON + 텍스트/HTML).
pub fn extract_numeric_fields(body: &str) -> BTreeMap<String, f64> {
    let mut out: BTreeMap<String, f64> = BTreeMap::new();

    // 1) JSON — 중첩 객체까지 순회.
    if let Ok(json) = serde_json::from_str::<Value>(body) {
        walk_json(&json, &mut Vec::new(), &mut out);
    }

    // 2) 텍스트/HTML — "total: 123.45", "Total = $1,299.00" 등.
    let re = Regex::new(
        r#"(?i)(total|price|amount|subtotal|qty|quantity|cost|fee|balance|discount|tax|unit_price|shipping|grand_total)\s*[:=]\s*['"]?(?:[$€£¥]\s*)?([0-9][0-9,._]*)"#,
    )
    .unwrap();
    for cap in re.captures_iter(body) {
        let key = cap.get(1).map(|m| m.as_str().to_ascii_lowercase()).unwrap_or_default();
        if let Some(raw) = cap.get(2).map(|m| m.as_str()) {
            if let Some(v) = parse_number(raw) {
                out.entry(key).or_insert(v);
            }
        }
    }
    out
}

fn walk_json(value: &Value, path: &mut Vec<String>, out: &mut BTreeMap<String, f64>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                path.push(k.clone());
                walk_json(v, path, out);
                path.pop();
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_json(item, path, out);
            }
        }
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                let key = if path.is_empty() { "value".to_string() } else { path.join(".") };
                if is_money_key(&key) {
                    out.entry(key).or_insert(f);
                } else if path.len() == 1 {
                    // 최상위 숫자 필드도 후보 (예: {"total": 10})
                    out.entry(key).or_insert(f);
                }
            }
        }
        _ => {}
    }
}

/// "1,299.00" → 1299.0
pub fn parse_number(raw: &str) -> Option<f64> {
    let cleaned: String = raw.chars().filter(|c| c.is_ascii_digit() || *c == '.').collect();
    cleaned.parse::<f64>().ok()
}

/// 응답에서 식별자(PII) 를 뽑는다 — 서로 다른 리소스인지 판별하는 근거.
pub fn extract_identifiers(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    // 이메일
    let email_re = Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap();
    for cap in email_re.captures_iter(body) {
        out.push(cap.get(0).map(|m| m.as_str().to_lowercase()).unwrap_or_default());
    }

    // JSON 의 식별자 성격 필드
    if let Ok(json) = serde_json::from_str::<Value>(body) {
        let mut found: Vec<(String, String)> = Vec::new();
        collect_identity_fields(&json, &mut Vec::new(), &mut found);
        for (k, v) in found {
            out.push(format!("{k}={v}"));
        }
    }

    out.sort();
    out.dedup();
    out
}

fn collect_identity_fields(value: &Value, path: &mut Vec<String>, out: &mut Vec<(String, String)>) {
    if let Value::Object(map) = value {
        for (k, v) in map {
            let key_l = k.to_ascii_lowercase();
            let is_identity = ["name", "username", "user", "email", "owner", "account", "login", "nick", "nickname", "full_name"]
                .iter()
                .any(|x| key_l == *x || key_l.ends_with(&format!("_{x}")) || key_l.starts_with(&format!("{x}_")));
            if is_identity {
                if let Value::String(s) = v {
                    let full = if path.is_empty() { k.clone() } else { format!("{}.{}", path.join("."), k) };
                    out.push((full, s.clone()));
                }
            }
            path.push(k.clone());
            collect_identity_fields(v, path, out);
            path.pop();
        }
    } else if let Value::Array(items) = value {
        for item in items {
            collect_identity_fields(item, path, out);
        }
    }
}

/// 응답 본문에서 특정 값(예: id) 을 제거한 정규화 해시 — "다른 리소스인가" 판별용.
pub fn resource_signature(body: &str, exclude: &str) -> String {
    let mut text = body.to_string();
    if !exclude.is_empty() {
        text = text.replace(exclude, "0");
    }
    crate::storm::short_hash(&crate::storm::normalize_body(&text))
}

/// 쿼리/폼/JSON 바디에서 파라미터 값을 교체한다.
pub fn replace_param(url: &str, body: Option<&str>, param: &str, value: &str) -> (String, Option<String>) {
    // 1) 바디가 JSON 이면 구조적으로 교체.
    if let Some(b) = body {
        if let Ok(mut json) = serde_json::from_str::<Value>(b) {
            if let Some(v) = json.get_mut(param) {
                // 원래 값이 숫자였으면 숫자로 넣는다 (서버가 타입을 구분하는 경우 대비).
                let was_number = v.is_number();
                *v = match (was_number, value.parse::<f64>()) {
                    (true, Ok(num)) => serde_json::Number::from_f64(num)
                        .map(Value::Number)
                        .unwrap_or_else(|| Value::String(value.to_string())),
                    _ => Value::String(value.to_string()),
                };
                return (url.to_string(), Some(json.to_string()));
            }
        }
        // 2) form-urlencoded.
        if b.contains('=') && !b.trim_start().starts_with('{') && !b.contains('\n') {
            let mut pairs: Vec<String> = Vec::new();
            let mut replaced = false;
            for part in b.split('&') {
                if let Some((k, _)) = part.split_once('=') {
                    if k == param {
                        pairs.push(format!("{k}={value}"));
                        replaced = true;
                        continue;
                    }
                }
                pairs.push(part.to_string());
            }
            if replaced {
                return (url.to_string(), Some(pairs.join("&")));
            }
        }
    }
    // 3) 쿼리스트링.
    (crate::storm::inject_query(url, param, value), body.map(str::to_string))
}

/// URL 의 해당 파라미터 값을 읽는다 (없으면 빈 문자열).
pub fn read_param(url: &str, param: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => u
            .query_pairs()
            .find(|(k, _)| k == param)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// findings 요약 문자열 (TUI/CLI 출력용).
pub fn summarize_findings(findings: &[crate::report::Finding]) -> String {
    if findings.is_empty() {
        return "확정된 취약점 없음.".to_string();
    }
    let mut out = String::new();
    for (i, f) in findings.iter().enumerate() {
        out.push_str(&format!("{}. [{}] {} — {}\n", i + 1, f.severity, f.title, f.target));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_money_fields_from_json() {
        let body = r#"{"id":7,"price":19.99,"qty":3,"total":59.97,"user":{"name":"alice","email":"a@x.io"}}"#;
        let nums = extract_numeric_fields(body);
        assert_eq!(nums.get("price"), Some(&19.99));
        assert_eq!(nums.get("qty"), Some(&3.0));
        assert_eq!(nums.get("total"), Some(&59.97));
    }

    #[test]
    fn extracts_money_fields_from_html() {
        let body = "<div>Total: $1,299.00</div><span>Qty = 2</span>";
        let nums = extract_numeric_fields(body);
        assert_eq!(nums.get("total"), Some(&1299.0));
        assert_eq!(nums.get("qty"), Some(&2.0));
    }

    #[test]
    fn extracts_identifiers() {
        let body = r#"{"name":"bob","email":"bob@lab.local","id":2}"#;
        let ids = extract_identifiers(body);
        assert!(ids.iter().any(|x| x.contains("bob@lab.local")), "{ids:?}");
        assert!(ids.iter().any(|x| x.contains("name=bob")), "{ids:?}");
    }

    #[test]
    fn signature_ignores_identifier_value() {
        let a = resource_signature(r#"{"id":1,"name":"alice"}"#, "1");
        let b = resource_signature(r#"{"id":1,"name":"bob"}"#, "1");
        assert_ne!(a, b, "이름이 다르면 서명이 달라야 함");
        let c = resource_signature(r#"{"id":2,"name":"alice"}"#, "2");
        assert_eq!(a, c, "id 값만 다르면 같은 리소스");
    }

    #[test]
    fn replaces_param_in_json_body_keeps_number_type() {
        // 숫자였던 값은 숫자로 유지한다 (서버가 타입을 구분하는 경우 대비).
        let (u, b) = replace_param("http://x/checkout", Some(r#"{"price":10,"qty":2}"#), "price", "0");
        assert_eq!(u, "http://x/checkout");
        let out = b.unwrap();
        assert!(out.contains(r#""price":0"#), "{out}");
        assert!(out.contains(r#""qty":2"#), "{out}");
    }

    #[test]
    fn replaces_param_in_json_body_keeps_string_type() {
        // 문자열이었던 값은 문자열로 유지한다.
        let (_, b) = replace_param("http://x/checkout", Some(r#"{"sku":"A1","price":"10"}"#), "price", "0");
        let out = b.unwrap();
        assert!(out.contains(r#""price":"0""#), "{out}");
    }

    #[test]
    fn replaces_param_in_form_body() {
        let (u, b) = replace_param("http://x/checkout", Some("sku=1&price=10"), "price", "0");
        assert_eq!(b.unwrap(), "sku=1&price=0");
        assert_eq!(u, "http://x/checkout");
    }

    #[test]
    fn reads_query_param() {
        assert_eq!(read_param("http://x/api/user?id=42", "id"), "42");
        assert_eq!(read_param("http://x/api/user", "id"), "");
    }
}
