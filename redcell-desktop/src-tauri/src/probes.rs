//! P0 결정적 스윕 — LLM 분석 전에 실행하는 읽기 전용 대량 프로브.
//!
//! 시니어 해커가 손으로는 엄두도 못 내는 "수백 개 경로·수십 종 페이로드 변형·
//! 헤더/쿠키/CORS/TLS 전수 점검"을 수십 초 안에 확정한다. 결과는 증거 ID(`[P-###]`)
//! 와 함께 저장되고, LLM 워커·collector 는 이 증거 위에서 분석가 역할을 한다.
//!
//! 안전 규칙: GET/HEAD/OPTIONS + 무해 쿼리 마커만 사용, 단일 호스트(외부 추적 금지),
//! RPS 상한·요청 타임아웃·본문 크기 상한·전체 타임아웃.

use std::collections::VecDeque;
use std::io::Read;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const PROBE_THREADS: usize = 24;
pub const PROBE_RPS: u32 = 30;
pub const REQ_TIMEOUT: Duration = Duration::from_secs(8);
pub const SWEEP_TIMEOUT: Duration = Duration::from_secs(180);
pub const BODY_CAP: u64 = 262_144;
pub const JS_BODY_CAP: u64 = 1_048_576;
pub const JS_FETCH_CAP: usize = 10;
pub const PARAM_CAP: usize = 20;
pub const REDIRECT_JOB_CAP: usize = 16;

const UA: &str = "Mozilla/5.0 (RedCell authorized-agent; read-only sweep)";
const EVIL_ORIGIN: &str = "https://evil-probe.test";
const EVIL_URL: &str = "https://evil-probe.test/r";
const EVIL_PROTOREL: &str = "//evil-probe.test/r";

/// 민감 경로 워드리스트 — 존재+내용 시그니처로 판정한다 (404는 버림).
const PATH_WORDLIST: &[&str] = &[
    "/robots.txt", "/.well-known/security.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml", "/swagger",
    "/swagger-ui", "/swagger-ui.html", "/api/docs", "/docs", "/redoc", "/api/openapi.json",
    "/api/swagger.json", "/graphql", "/graphiql", "/graphql/console", "/playground",
    "/.env", "/.env.bak", "/.env.local", "/.env.production", "/.env.development",
    "/.env.old", "/.env.save", "/.env~", "/env", "/config/.env",
    "/.git/HEAD", "/.git/config", "/.git/index", "/.svn/entries", "/.hg/requires",
    "/.bzr/branch.conf", "/CVS/Entries",
    "/backup.sql", "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/site.zip", "/site.tar.gz", "/www.zip", "/web.zip", "/app.zip",
    "/index.php.bak", "/index.php~", "/index.php.old", "/index.html.bak",
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old", "/wp-config.php.save",
    "/config.php.bak", "/config.php~", "/settings.php.bak", "/.htaccess.bak",
    "/admin", "/admin/", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/phpMyAdmin", "/manager/html", "/manager/status", "/console",
    "/login", "/signin", "/admin/login", "/admin.php", "/administrator/index.php",
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env", "/actuator/configprops",
    "/actuator/beans", "/actuator/mappings", "/actuator/heapdump", "/actuator/threaddump",
    "/health", "/healthz", "/readyz", "/livez", "/status", "/metrics", "/info",
    "/server-status", "/server-info", "/nginx_status", "/.nginx_status",
    "/debug", "/_debug", "/phpinfo.php", "/info.php", "/test.php", "/test", "/dev",
    "/package.json", "/package-lock.json", "/composer.json", "/composer.lock",
    "/Gemfile", "/Gemfile.lock", "/requirements.txt", "/Pipfile", "/go.mod",
    "/web.config", "/.htaccess", "/.htpasswd", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.DS_Store", "/Thumbs.db", "/desktop.ini",
    "/.well-known/openid-configuration", "/.well-known/change-password",
    "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
    "/.aws/credentials", "/.aws/config", "/id_rsa", "/id_rsa.pub", "/.npmrc",
    "/.yarnrc", "/.gitlab-ci.yml", "/.github/workflows/ci.yml", "/Dockerfile",
    "/docker-compose.yml", "/.dockerenv",
    "/api", "/api/v1", "/api/v2", "/api/users", "/v1", "/v2",
    "/script", "/api/json", "/api/python", "/config.xml",
    "/elmah.axd", "/trace.axd", "/server-error",
    "/%2e%2e/%2e%2e/etc/passwd", "/..;/", "/.\\./.\\./windows/win.ini",
    "/favicon.ico",
];

const REDIRECT_PARAMS: &[&str] = &[
    "url", "redirect", "redirect_uri", "redirect_url", "return", "returnUrl", "return_to",
    "next", "continue", "dest", "destination", "target", "goto", "r", "u", "link",
];

const SQL_FINGERPRINTS: &[&str] = &[
    "you have an error in your sql syntax", "warning: mysql", "mysqli_", "mysql_fetch",
    "pg_query", "pgerror", "unterminated quoted string", "postgresql",
    "sqlite3::", "sqlite error", "ora-", "oracle error", "pl/sql",
    "sqlserver", "microsoft ole db", "odbc sql server driver", "jdbc",
    "syntax error at or near", "quoted string not properly terminated",
];

const SECRET_WORDS: &[&str] = &["api_key", "apikey", "api-key", "secret", "passwd", "password", "token"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeHit {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub target: String,
    pub title: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub request: String,
    #[serde(default)]
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReport {
    pub target: String,
    pub started_at: String,
    pub duration_ms: u64,
    pub probes_run: usize,
    pub hits: Vec<ProbeHit>,
    #[serde(default)]
    pub authenticated: bool,
    #[serde(default)]
    pub verified: usize,
    /// 파괴적 프로브 실행 여부 (동의 기반).
    #[serde(default)]
    pub danger: bool,
}

#[derive(Debug, Clone)]
pub struct SweepConfig {
    pub threads: usize,
    pub rps: u32,
    pub req_timeout: Duration,
    pub sweep_timeout: Duration,
    /// 세션 쿠키 (사용자가 붙여넣은 Cookie 헤더 값) — 전 요청에 첨부.
    pub cookie: Option<String>,
    /// 파괴적 진단 동의 — 모달 명시 동의 시에만 true. 기본 false (fail-closed).
    /// true 일 때만 기본자격·IDOR 인접·쓰기검증 프로브가 동작한다.
    pub danger: bool,
    /// 진행 피드백 — TUI 폴링용 (None 이면 미사용).
    pub feedback: Option<std::sync::Arc<SweepFeedback>>,
}

/// 스윕 피드백 — 중단 요청 + 진행률 + 현재 단계.
#[derive(Debug, Default)]
pub struct SweepFeedback {
    pub cancel: AtomicBool,
    pub done: AtomicUsize,
    pub total: AtomicUsize,
    pub phase: Mutex<String>,
}

impl SweepFeedback {
    // 진행률 폴링용 접근자 — 현재 호출자는 테스트뿐이라 일반 빌드 경고를 끈다.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn phase_label(&self) -> String {
        self.phase.lock().map(|p| p.clone()).unwrap_or_default()
    }
}

fn cancelled(cfg: &SweepConfig) -> bool {
    cfg.feedback.as_ref().map(|f| f.cancel.load(Ordering::Relaxed)).unwrap_or(false)
}

fn set_phase(cfg: &SweepConfig, phase: &str) {
    if let Some(f) = &cfg.feedback {
        *f.phase.lock().unwrap() = phase.to_string();
    }
}

fn bump_done(cfg: &SweepConfig, counter: &AtomicUsize) {
    if let Some(f) = &cfg.feedback {
        f.done.store(counter.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

impl SweepConfig {
    pub fn with_defaults() -> Self {
        SweepConfig {
            threads: PROBE_THREADS,
            rps: PROBE_RPS,
            req_timeout: REQ_TIMEOUT,
            sweep_timeout: SWEEP_TIMEOUT,
            cookie: None,
            danger: false,
            feedback: None,
        }
    }
    fn cookie_headers(&self) -> Vec<(&str, &str)> {
        match &self.cookie {
            Some(c) if !c.trim().is_empty() => vec![("Cookie", c.as_str())],
            _ => vec![],
        }
    }
}

impl Default for SweepConfig {
    fn default() -> Self {
        SweepConfig::with_defaults()
    }
}

/// 대상 base URL 조합 — 포트 관례(http/https) + 반대 스킴 1회 대조용.
fn bases_for(host: &str, port: Option<u16>) -> (String, String) {
    let (primary, alt) = match port {
        Some(p) if p == 443 || p == 8443 => {
            (format!("https://{host}/"), format!("http://{host}/"))
        }
        Some(p) => (
            format!("http://{host}:{p}/"),
            format!("https://{host}:{p}/"),
        ),
        None => (format!("http://{host}/"), format!("https://{host}/")),
    };
    (primary, alt.trim_end_matches('/').to_string() + "/")
}

fn agent_for(cfg: &SweepConfig) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(cfg.req_timeout)
        .timeout_read(cfg.req_timeout)
        .timeout_write(cfg.req_timeout)
        .redirects(0)
        .user_agent(UA)
        .build()
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

fn fetch(
    agent: &ureq::Agent,
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    cap: u64,
) -> Result<Resp, String> {
    let mut req = agent.request(method, url);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(e.to_string()),
    };
    let status = resp.status();
    let mut hs = Vec::new();
    for name in resp.headers_names() {
        for v in resp.all(&name) {
            hs.push((name.clone(), v.to_string()));
        }
    }
    let mut buf = Vec::new();
    resp.into_reader()
        .take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(Resp {
        status,
        headers: hs,
        body: String::from_utf8_lossy(&buf).into_owned(),
    })
}

fn header<'a>(hs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    hs.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn header_all<'a>(hs: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    hs.iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

// ── 분류기 (순수 함수 — 단위 테스트 대상) ─────────────────────────────────────

/// 보안 헤더 감사 — (헤더명, 심각도, 메시지).
pub fn audit_security_headers(hs: &[(String, String)], is_https: bool) -> Vec<(String, Severity, String)> {
    let mut out = Vec::new();
    let need = [
        ("content-security-policy", "CSP 미설정 — XSS/인젝션 피해 확대", Severity::Medium),
        ("x-frame-options", "X-Frame-Options 미설정 — 클릭재킹 가능", Severity::Low),
        ("x-content-type-options", "X-Content-Type-Options 미설정 — MIME 스니핑", Severity::Low),
        ("referrer-policy", "Referrer-Policy 미설정 — 리퍼러 과다 노출", Severity::Info),
    ];
    for (name, msg, sev) in need {
        if header(hs, name).is_none() {
            out.push((name.to_string(), sev, msg.to_string()));
        }
    }
    match header(hs, "strict-transport-security") {
        None => out.push((
            "strict-transport-security".to_string(),
            if is_https { Severity::Medium } else { Severity::Info },
            "HSTS 미설정 — HTTPS 강제 없음".to_string(),
        )),
        Some(v) if !v.to_lowercase().contains("includesubdomains") => out.push((
            "strict-transport-security".to_string(),
            Severity::Info,
            "HSTS 에 includeSubDomains 없음".to_string(),
        )),
        _ => {}
    }
    for (name, label) in [("server", "Server 배너"), ("x-powered-by", "X-Powered-By 배너")] {
        if let Some(v) = header(hs, name) {
            out.push((name.to_string(), Severity::Info, format!("{label} 노출: {v}")));
        }
    }
    out
}

/// 쿠키 플래그 감사 — (쿠키명, 심각도, 메시지).
pub fn audit_cookies(set_cookies: &[&str], is_https: bool) -> Vec<(String, Severity, String)> {
    let mut out = Vec::new();
    for sc in set_cookies {
        let name = sc.split(';').next().unwrap_or("").split('=').next().unwrap_or("?").trim();
        let lower = sc.to_lowercase();
        let sensitive = ["sess", "sid", "token", "auth", "session", "jwt", "login", "id"]
            .iter()
            .any(|k| name.to_lowercase().contains(k));
        if !lower.contains("httponly") {
            out.push((
                name.to_string(),
                if sensitive { Severity::Medium } else { Severity::Low },
                format!("쿠키 '{name}' HttpOnly 없음 — XSS 로 탈취 가능"),
            ));
        }
        if is_https && !lower.contains("secure") {
            out.push((
                name.to_string(),
                if sensitive { Severity::Medium } else { Severity::Low },
                format!("쿠키 '{name}' Secure 없음 — 평문 전송 가능"),
            ));
        }
        if !lower.contains("samesite") {
            out.push((
                name.to_string(),
                Severity::Low,
                format!("쿠키 '{name}' SameSite 없음 — CSRF 위험 증가"),
            ));
        }
    }
    out
}

/// 바이트 구간을 문자 경계에 맞춰 잘라 반환한다 — 어떤 오프셋이 와도 패닉 없음.
/// 웹 본문 파싱은 신뢰할 수 없는 입력(한글 등 멀티바이트)을 다루므로 고정 바이트
/// 잘라내기(`&s[a..b]`)를 직접 쓰지 않고 이 헬퍼를 쓴다.
fn safe_slice(s: &str, start: usize, end: usize) -> &str {
    let mut a = start.min(s.len());
    while a < s.len() && !s.is_char_boundary(a) {
        a += 1;
    }
    let mut b = end.min(s.len());
    while b > a && !s.is_char_boundary(b) {
        b -= 1;
    }
    &s[a..b]
}

/// ASCII 바늘의 대소문자 무시 탐색 — 원문 바이트 오프셋 반환.
/// `to_lowercase()` 복사본에서 찾은 오프셋을 원문에 쓰면 안 된다: 소문자 변환이
/// 바이트 길이를 바꿀 수 있어(예: 'İ' → 2문자) 원문의 문자 경계와 어긋나 패닉난다.
/// needle 은 소문자 ASCII 여야 한다.
fn find_ascii_ci(hay: &str, needle: &str, from: usize) -> Option<usize> {
    let h = hay.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || from >= h.len() {
        return None;
    }
    (from..=h.len().saturating_sub(n.len())).find(|&i| {
        h[i..i + n.len()].iter().zip(n.iter()).all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
}

/// 비밀 문자열 스캔 — (종류, 마스킹 발췌). 마스킹: 앞 8자 + … + 뒤 4자.
pub fn find_secrets(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut push = |kind: &str, raw: &str| {
        let m = mask_secret(raw);
        if !out.iter().any(|(_, e)| e == &m) {
            out.push((kind.to_string(), m));
        }
    };
    let b = text.as_bytes();
    // AWS 액세스 키: AKIA + 16자 대문자/숫자.
    for i in 0..b.len().saturating_sub(20) {
        if &b[i..i + 4] == b"AKIA" && b[i + 4..i + 20].iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
            push("AWS 액세스 키", &text[i..i + 20]);
        }
    }
    // JWT: eyJ + base64url + . + eyJ(페이로드).
    for i in 0..b.len().saturating_sub(24) {
        if &b[i..i + 3] == b"eyJ" {
            let mut j = i + 3;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'-' || b[j] == b'_' || b[j] == b'.') {
                j += 1;
            }
            let tok = &text[i..j.min(i + 200)];
            if tok.matches('.').count() >= 2 && tok.len() > 24 {
                push("JWT", tok);
            }
        }
    }
    // PEM 개인키 블록.
    if text.contains("PRIVATE KEY-----") {
        push("PEM 개인키", "-----BEGIN ... PRIVATE KEY-----");
    }
    // 토큰 접두사류.
    for (needle, kind, take) in [
        ("xoxb-", "Slack 토큰", 24usize),
        ("xoxp-", "Slack 토큰", 24),
        ("xoxa-", "Slack 토큰", 24),
        ("xoxs-", "Slack 토큰", 24),
        ("ghp_", "GitHub 토큰", 20),
        ("gho_", "GitHub 토큰", 20),
        ("sk-live-", "API 시크릿 키", 20),
        ("sk-test-", "API 시크릿 키", 20),
    ] {
        let mut rest = text;
        while let Some(pos) = rest.find(needle) {
            push(kind, safe_slice(rest, pos, pos + take));
            rest = &rest[pos + needle.len()..];
        }
    }
    // key=value 대입형 (따옴표 값 12자 이상, 흔한 키 이름).
    // 원문에서 직접 대소문자 무시 탐색한다 — lowercased 복사본 오프셋을 원문에
    // 쓰면 문자 경계가 어긋나 패닉난다 (esdp.lge.com 한글 본문에서 실발생).
    for word in SECRET_WORDS {
        let mut from = 0;
        while let Some(pos) = find_ascii_ci(text, word, from) {
            let seg = safe_slice(text, pos, pos + 80);
            if let Some(v) = assignment_value(seg, word.len()) {
                if v.len() >= 12 {
                    push("하드코딩 비밀 추정", v);
                }
            }
            from = pos + word.len();
        }
    }
    // .env 형 비인용 대입 (KEY=VALUE 한 줄, 값 12자 이상·공백 없음).
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.len() > 160 {
            continue;
        }
        if let Some((k, v)) = t.split_once('=') {
            let k = k.trim().to_lowercase();
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
            if v.len() >= 12
                && !v.contains(char::is_whitespace)
                && SECRET_WORDS.iter().any(|w| k.contains(w))
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                push("하드코딩 비밀 추정(.env)", v);
            }
        }
    }
    out
}

fn mask_secret(raw: &str) -> String {
    let r: String = raw.chars().take(64).collect();
    if r.len() <= 16 {
        return r;
    }
    // 앞 8자 + … + 뒤 4자 — 문자 단위로 잘라 멀티바이트 경계 패닉을 방지한다.
    let head: String = r.chars().take(8).collect();
    let tail: String = r.chars().rev().take(4).collect::<String>().chars().rev().collect();
    format!("{head}…{tail}")
}

/// `key = "value"` / `key: 'value'` 형태에서 따옴표 값을 뽑는다.
fn assignment_value(seg: &str, skip: usize) -> Option<&str> {
    let rest = seg.get(skip..)?.trim_start();
    let rest = rest.strip_prefix(':').or_else(|| rest.strip_prefix('='))?.trim_start();
    let q = rest.chars().next()?;
    if q != '"' && q != '\'' {
        return None;
    }
    let inner = &rest[q.len_utf8()..];
    let end = inner.find(q)?;
    let v = &inner[..end];
    if v.len() < 4 || v.contains(char::is_whitespace) {
        return None;
    }
    Some(v)
}

/// SQL 오류 지문 — (지문, 심각도 힌트).
pub fn find_sql_errors(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    SQL_FINGERPRINTS
        .iter()
        .filter(|fp| lower.contains(**fp))
        .map(|fp| fp.to_string())
        .collect()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReflectCtx {
    pub found: bool,
    pub in_script: bool,
    pub in_attr: bool,
    pub in_comment: bool,
}

/// 반사 컨텍스트 분류 — 마커가 HTML 어디에 박혔는지.
pub fn classify_reflection(body: &str, marker: &str) -> ReflectCtx {
    let mut ctx = ReflectCtx::default();
    let Some(pos) = body.find(marker) else {
        return ctx;
    };
    ctx.found = true;
    let head = &body[..pos];
    let script_open = head.rfind("<script");
    let script_close = head.rfind("</script>");
    ctx.in_script = script_open.map(|o| script_close.map(|c| c < o).unwrap_or(true)).unwrap_or(false);
    let c_open = head.rfind("<!--");
    let c_close = head.rfind("-->");
    ctx.in_comment = c_open.map(|o| c_close.map(|c| c < o).unwrap_or(true)).unwrap_or(false);
    // 태그 내부 + '=' 포함이면 속성 컨텍스트.
    let lt = head.rfind('<');
    let gt = head.rfind('>');
    if let Some(lt) = lt {
        if gt.map(|g| g < lt).unwrap_or(true) && head[lt..].contains('=') {
            ctx.in_attr = true;
        }
    }
    ctx
}

/// 반사 심각도 — raw(특수문자 포함 마커) 여부에 따라 가중.
pub fn reflect_severity(ctx: &ReflectCtx, raw: bool) -> Option<Severity> {
    if !ctx.found {
        return None;
    }
    if ctx.in_comment {
        return Some(Severity::Info);
    }
    if raw {
        if ctx.in_script {
            return Some(Severity::High);
        }
        if ctx.in_attr {
            return Some(Severity::Medium);
        }
        return Some(Severity::Medium);
    }
    if ctx.in_script {
        return Some(Severity::Medium);
    }
    if ctx.in_attr {
        return Some(Severity::Low);
    }
    Some(Severity::Info)
}

/// HTML 에서 쿼리 파라미터명 수집 (?a= & &b= + form input name).
pub fn extract_params(html: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |n: &str| {
        let n = n.trim();
        if !n.is_empty()
            && n.len() <= 32
            && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
            && !out.iter().any(|x| x == n)
        {
            out.push(n.to_string());
        }
    };
    let b = html.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if (b[i] == b'?' || b[i] == b'&') && i + 1 < b.len() {
            let mut j = i + 1;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] == b'-' || b[j] == b'.') {
                j += 1;
            }
            if j < b.len() && b[j] == b'=' && j > i + 1 {
                push(&html[i + 1..j]);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    // <input name="..."> — 원문에서 직접 대소문자 무시 탐색한다.
    // lowercased 복사본 오프셋을 원문에 쓰면 문자 경계가 어긋나 패닉난다.
    let mut from = 0;
    while let Some(found) = find_ascii_ci(html, "name=\"", from) {
        let pos = found + 6;
        if let Some(end) = html[pos..].find('"').map(|e| pos + e) {
            push(&html[pos..end]);
            from = end + 1;
        } else {
            break;
        }
    }
    out.truncate(PARAM_CAP);
    out
}

/// 동일 출처 JS 수집 — src="..." 중 상대경로·동일호스트만.
pub fn extract_scripts(html: &str, host: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut from = 0;
    while let Some(pos) = html[from..].find("src=\"").map(|p| from + p + 5) {
        if let Some(end) = html[pos..].find('"').map(|e| pos + e) {
            let src = html[pos..end].trim();
            let path = if let Some(rest) = src.strip_prefix("https://") {
                rest.split('/').next().filter(|h| h.eq_ignore_ascii_case(host)).map(|_| format!("/{}", rest.split('/').skip(1).collect::<Vec<_>>().join("/")))
            } else if let Some(rest) = src.strip_prefix("http://") {
                rest.split('/').next().filter(|h| h.eq_ignore_ascii_case(host)).map(|_| format!("/{}", rest.split('/').skip(1).collect::<Vec<_>>().join("/")))
            } else if src.starts_with('/') && !src.starts_with("//") {
                Some(src.to_string())
            } else {
                None // 외부 CDN·프로토콜 상대 URL 은 추적 금지
            };
            if let Some(p) = path {
                if !out.contains(&p) && out.len() < JS_FETCH_CAP {
                    out.push(p);
                }
            }
            from = end + 1;
        } else {
            break;
        }
    }
    out
}

/// 경로 분류 — (심각도(200 기준), 설명).
fn classify_path(path: &str, status: u16, body: &str) -> Option<(Severity, String)> {
    let p = path.to_lowercase();
    // 404/400 은 없음으로 간주 (일부 WAF 는 403 으로 막음 — 존재 신호로 기록).
    if status == 404 || status == 400 {
        return None;
    }
    let secret_file = p.contains(".env") || p.ends_with("id_rsa") || p.contains(".aws/credentials")
        || p.ends_with(".htpasswd") || p.contains("credentials");
    let vcs = p.contains("/.git/") || p.contains("/.svn/") || p.contains("/.hg/")
        || p.contains("/cvs/") || p.contains(".bzr/");
    let backup = p.ends_with(".bak") || p.ends_with(".old") || p.ends_with('~')
        || p.ends_with(".save") || p.ends_with(".swp") || p.ends_with(".zip")
        || p.ends_with(".tar.gz") || p.ends_with(".sql");
    let actuator_sensitive = p.contains("/actuator/env") || p.contains("/actuator/heapdump")
        || p.contains("/actuator/configprops") || p.contains("/actuator/threaddump");
    let admin = p.contains("/admin") || p.contains("wp-login") || p.contains("phpmyadmin")
        || p.contains("/manager/") || p.ends_with("/console");
    let docs = p.contains("swagger") || p.contains("openapi") || p.ends_with("/graphql")
        || p.contains("graphiql") || p.contains("/docs") || p.contains("redoc");
    let debug = p.contains("phpinfo") || p.ends_with("/debug") || p.ends_with("/test.php")
        || p.contains("elmah") || p.contains("trace.axd");
    if status == 401 || status == 403 {
        if secret_file || vcs || backup || actuator_sensitive || admin {
            return Some((Severity::Info, format!("민감 경로 존재 추정 ({status})")));
        }
        return None;
    }
    if !(200..300).contains(&status) && !(300..400).contains(&status) {
        return None;
    }
    if secret_file {
        let looks_env = body.contains('=') && body.lines().count() > 2;
        return Some((
            if looks_env { Severity::High } else { Severity::Medium },
            "비밀 파일 노출".to_string(),
        ));
    }
    if vcs {
        return Some((Severity::High, "버전관리 메타데이터 노출".to_string()));
    }
    if actuator_sensitive {
        return Some((Severity::High, "Actuator 민감 엔드포인트 노출".to_string()));
    }
    if backup {
        return Some((Severity::Medium, "백업 파일 노출".to_string()));
    }
    if p.contains("/actuator") || p.contains("/metrics") || p.contains("server-status") || p.contains("server-info") {
        return Some((Severity::Medium, "내부 상태 엔드포인트 노출".to_string()));
    }
    if admin {
        return Some((Severity::Low, "관리 패널 노출".to_string()));
    }
    if docs {
        return Some((Severity::Info, "API 문서 노출".to_string()));
    }
    if debug {
        return Some((Severity::Medium, "디버그 페이지 노출".to_string()));
    }
    if p.contains("package.json") || p.contains("composer.json") || p.contains("gemfile") || p.contains("go.mod") || p.contains("web.config") {
        return Some((Severity::Low, "빌드/설정 파일 노출".to_string()));
    }
    if p.contains("robots.txt") || p.contains("sitemap") || p.contains("security.txt") || p.contains("openid-configuration") || p.contains("crossdomain") {
        return Some((Severity::Info, "공개 정보 파일".to_string()));
    }
    if p.contains("%2e%2e") || p.contains("..;") || p.contains("win.ini") {
        if status == 200 && (body.to_lowercase().contains("root:") || body.to_lowercase().contains("[fonts]")) {
            return Some((Severity::Critical, "경로 조작 성공 (LFI 신호)".to_string()));
        }
        return None;
    }
    // 그 외 200 — 관심 경로 노출.
    Some((Severity::Info, "예상 밖 경로 응답".to_string()))
}

// ── 실행 엔진 ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum ProbeKind {
    Path,
    Js,
    Xss { param: String, raw: bool, marker: String },
    Sqli { param: String, quote: char },
    Redirect { param: String, payload: &'static str },
}

/// 쿼리 값용 최소 인코딩 — RFC3986 비예약 문자以外 전부 %XX.
fn pct_encode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

#[derive(Clone)]
struct Job {
    url: String,
    method: &'static str,
    headers: Vec<(String, String)>,
    kind: ProbeKind,
}

struct Gate {
    rps: u32,
    next: Mutex<Instant>,
}

impl Gate {
    fn wait(&self) {
        if self.rps == 0 {
            return;
        }
        let gap = Duration::from_secs_f64(1.0 / self.rps as f64);
        loop {
            let mut n = self.next.lock().unwrap();
            let now = Instant::now();
            if now >= *n {
                *n = now + gap;
                return;
            }
            let sleep = *n - now;
            drop(n);
            std::thread::sleep(sleep.min(Duration::from_millis(250)));
        }
    }
}

fn hit(
    category: &str,
    severity: Severity,
    target: String,
    title: String,
    detail: String,
    evidence: String,
    request: String,
    status: Option<u16>,
) -> ProbeHit {
    ProbeHit {
        id: String::new(), // 마지막에 심각도순으로 P-### 부여
        category: category.to_string(),
        severity: severity.as_str().to_string(),
        target,
        title,
        detail: detail.chars().take(300).collect(),
        evidence: evidence.chars().take(400).collect(),
        request,
        status,
    }
}

fn one_line(s: &str, cap: usize) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(cap).collect()
}

/// base 정찰 — 루트 GET(리다이렉트 체인 수동 추적) + OPTIONS + CORS + 반대 스킴.
struct BaseInfo {
    base: String,
    is_https: bool,
    root_status: u16,
    root_headers: Vec<(String, String)>,
    root_body: String,
    chain: Vec<String>,
    allow: Option<String>,
    trace_echo: bool,
    cors_reflect: bool,
    cors_cred: bool,
    alt_status: Option<u16>,
}

fn fetch_base(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    primary: &str,
    alt: &str,
    counter: &AtomicUsize,
) -> Result<BaseInfo, String> {
    let is_https = primary.starts_with("https://");
    let ch = cfg.cookie_headers();
    // 루트 + 리다이렉트 체인 (동일 호스트만 3홉).
    let mut url = primary.to_string();
    let mut chain = vec![url.clone()];
    let mut root: Option<Resp> = None;
    for _ in 0..4 {
        counter.fetch_add(1, Ordering::Relaxed);
        let r = fetch(agent, "GET", &url, &ch, BODY_CAP)?;
        let status = r.status;
        if (300..400).contains(&status) {
            if let Some(loc) = header(&r.headers, "location") {
                let next = if loc.starts_with('/') {
                    format!("{}{}", primary.trim_end_matches('/'), loc)
                } else if loc.starts_with(primary.trim_end_matches('/')) {
                    loc.to_string()
                } else {
                    root = Some(r);
                    break; // 외부 리다이렉트 — 추적 중단, 증거로 기록
                };
                chain.push(next.clone());
                url = next;
                continue;
            }
        }
        root = Some(r);
        break;
    }
    let root = root.ok_or_else(|| "루트 응답 없음".to_string())?;
    // OPTIONS.
    counter.fetch_add(1, Ordering::Relaxed);
    let allow = fetch(agent, "OPTIONS", primary, &ch, 4096)
        .ok()
        .and_then(|r| header(&r.headers, "allow").map(|s| s.to_string()))
        .or_else(|| {
            fetch(agent, "OPTIONS", primary, &ch, 4096)
                .ok()
                .and_then(|r| header(&r.headers, "access-control-allow-methods").map(|s| s.to_string()))
        });
    // TRACE 반향 (무해 마커).
    counter.fetch_add(1, Ordering::Relaxed);
    let mut trace_h = ch.clone();
    trace_h.push(("X-RC-Probe", "rc7xtrace"));
    let trace_echo = fetch(agent, "TRACE", primary, &trace_h, 8192)
        .map(|r| r.status == 200 && r.body.contains("rc7xtrace"))
        .unwrap_or(false);
    // CORS 반사.
    counter.fetch_add(1, Ordering::Relaxed);
    let mut cors_h = ch.clone();
    cors_h.push(("Origin", EVIL_ORIGIN));
    let (cors_reflect, cors_cred) = fetch(agent, "GET", primary, &cors_h, 4096)
        .map(|r| {
            let acao = header(&r.headers, "access-control-allow-origin").unwrap_or("");
            let cred = header(&r.headers, "access-control-allow-credentials").unwrap_or("");
            (
                acao == EVIL_ORIGIN || acao == "*",
                cred.eq_ignore_ascii_case("true"),
            )
        })
        .unwrap_or((false, false));
    // 반대 스킴 1회.
    counter.fetch_add(1, Ordering::Relaxed);
    let alt_status = fetch(agent, "GET", alt, &ch, 4096).map(|r| r.status).ok();
    Ok(BaseInfo {
        base: primary.to_string(),
        is_https,
        root_status: root.status,
        root_headers: root.headers,
        root_body: root.body,
        chain,
        allow,
        trace_echo,
        cors_reflect,
        cors_cred,
        alt_status,
    })
}

fn base_hits(base: &BaseInfo) -> Vec<ProbeHit> {
    let mut hits = Vec::new();
    let t = base.base.clone();
    for (name, sev, msg) in audit_security_headers(&base.root_headers, base.is_https) {
        hits.push(hit("headers", sev, t.clone(), msg, format!("응답 헤더에 {name} 없음"), String::new(), format!("GET / → {}", base.root_status), Some(base.root_status)));
    }
    let sc: Vec<&str> = header_all(&base.root_headers, "set-cookie");
    for (name, sev, msg) in audit_cookies(&sc, base.is_https) {
        hits.push(hit("cookies", sev, t.clone(), msg, format!("Set-Cookie: {name}"), String::new(), format!("GET / → {}", base.root_status), Some(base.root_status)));
    }
    if let Some(allow) = &base.allow {
        let up = allow.to_uppercase();
        // 상태 변경 메서드는 Medium — 단, 비파괴 경계상 실제 PUT/DELETE 는 절대 발송하지 않고 설정 점검만 권고.
        if up.contains("PUT") || up.contains("DELETE") {
            hits.push(hit("methods", Severity::Medium, t.clone(), format!("쓰기 메서드 허용: {allow}"), "PUT/DELETE 가 열려 있으면 파일 변조·삭제 가능 — 실제 발송 없이 Allow 설정 제거 권고 (비파괴 탐지만 수행)".into(), String::new(), "OPTIONS /".into(), None));
        } else if up.contains("PATCH") {
            hits.push(hit("methods", Severity::Low, t.clone(), format!("PATCH 허용: {allow}"), "부분 수정 메서드 — 필요 없으면 Allow 에서 제거".into(), String::new(), "OPTIONS /".into(), None));
        }
    }
    if base.trace_echo {
        hits.push(hit("methods", Severity::Low, t.clone(), "TRACE 반향 (XST)".into(), "TRACE 요청이 그대로 반사됨 — 구형 브라우저에서 XSS 우회 가능".into(), "X-RC-Probe: rc7xtrace 반사 확인".into(), "TRACE /".into(), None));
    }
    if base.cors_reflect {
        let sev = if base.cors_cred { Severity::High } else { Severity::Medium };
        hits.push(hit("cors", sev, t.clone(), "CORS Origin 반사".into(), format!("임의 Origin({EVIL_ORIGIN})을 그대로 허용{}", if base.cors_cred { " + 자격증명 허용 — 세션 탈취 가능" } else { "" }), String::new(), format!("GET / (Origin: {EVIL_ORIGIN})"), None));
    }
    if base.chain.len() > 1 {
        let last = base.chain.last().unwrap();
        let external = !last.starts_with(base.base.trim_end_matches('/'));
        hits.push(hit(
            "redirect",
            if external { Severity::Medium } else { Severity::Info },
            t.clone(),
            if external { "루트 외부 리다이렉트".into() } else { format!("리다이렉트 {}홉", base.chain.len() - 1) },
            base.chain.join(" → ").chars().take(300).collect(),
            String::new(),
            "GET /".into(),
            Some(base.root_status),
        ));
    }
    match (base.is_https, base.alt_status) {
        (false, None) => hits.push(hit("tls", Severity::Low, t.clone(), "HTTPS 미사용".into(), "평문 HTTP 단독 — 로그인·개인정보 전송 시 도청 가능".into(), String::new(), "GET https://…/ (연결 실패)".into(), None)),
        (false, Some(s)) => hits.push(hit("tls", Severity::Info, t.clone(), "HTTPS 병행 응답".into(), format!("https도 {s} 응답 — HSTS·강제 여부 확인 필요"), String::new(), "GET https://…/".into(), Some(s))),
        (true, Some(s)) if (300..400).contains(&s) => {}
        (true, _) => hits.push(hit("tls", Severity::Info, t.clone(), "HTTP 강제 전환 미확인".into(), "http→https 강제 리다이렉트가 보이지 않음".into(), String::new(), "GET http://…/".into(), base.alt_status)),
    }
    // 루트 본문 비밀 스캔.
    for (kind, ex) in find_secrets(&base.root_body) {
        hits.push(hit("secret", Severity::High, t.clone(), format!("{kind} (홈페이지 인라인)"), "응답 본문에 하드코딩 비밀".into(), ex, format!("GET / → {}", base.root_status), Some(base.root_status)));
    }
    // 로그인 폼 수동 분석.
    let low = base.root_body.to_lowercase();
    if low.contains("type=\"password\"") || low.contains("type='password'") {
        let mut notes = vec!["비밀번호 입력 폼 존재"];
        if low.contains("autocomplete=\"off\"") || low.contains("autocomplete='off'") {
            notes.push("autocomplete=off");
        }
        let csrf = ["csrf", "_token", "authenticity_token"].iter().any(|k| low.contains(k));
        if !csrf {
            notes.push("CSRF 토큰 미발견");
            hits.push(hit("authform", Severity::Low, t.clone(), "로그인 폼 CSRF 토큰 없음".into(), notes.join(" · "), String::new(), format!("GET / → {}", base.root_status), Some(base.root_status)));
        } else {
            hits.push(hit("authform", Severity::Info, t.clone(), "로그인 폼".into(), notes.join(" · "), String::new(), format!("GET / → {}", base.root_status), Some(base.root_status)));
        }
    }
    hits
}

/// 병렬 잡 실행 — 워커 스레드 + RPS 게이트 + 전체 타임아웃.
fn run_jobs(
    jobs: Vec<Job>,
    cfg: &SweepConfig,
    deadline: Instant,
    counter: &AtomicUsize,
) -> Vec<ProbeHit> {
    if let Some(f) = &cfg.feedback {
        // 병렬 잡 + 후속 순차 구간 추정치 (표시용, 초과분은 clamp).
        f.total.store(jobs.len() + 64, Ordering::Relaxed);
    }
    set_phase(cfg, "병렬 프로브");
    let queue = Arc::new(Mutex::new(VecDeque::from(jobs)));
    let gate = Arc::new(Gate { rps: cfg.rps, next: Mutex::new(Instant::now()) });
    let stop = Arc::new(AtomicBool::new(false));
    let out = Arc::new(Mutex::new(Vec::<ProbeHit>::new()));
    let timeout = cfg.req_timeout;
    let cookie = cfg.cookie.clone();
    std::thread::scope(|scope| {
        for _ in 0..cfg.threads {
            let queue = queue.clone();
            let gate = gate.clone();
            let stop = stop.clone();
            let out = out.clone();
            let cookie = cookie.clone();
            scope.spawn(move || {
                let agent = ureq::AgentBuilder::new()
                    .timeout_connect(timeout)
                    .timeout_read(timeout)
                    .timeout_write(timeout)
                    .redirects(0)
                    .user_agent(UA)
                    .build();
                loop {
                    if stop.load(Ordering::Relaxed) || Instant::now() > deadline {
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                    let job = queue.lock().unwrap().pop_front();
                    let Some(job) = job else { return };
                    gate.wait();
                    if Instant::now() > deadline {
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                    // 취소는 게이트 통과 후에도 확인 (RPS 대기 중 요청 반영).
                    if cancelled(cfg) {
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                    if let Some(f) = &cfg.feedback {
                        f.done.store(counter.load(Ordering::Relaxed), Ordering::Relaxed);
                    }
                    let mut hs: Vec<(&str, &str)> = job.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                    if let Some(c) = cookie.as_ref() {
                        if !c.trim().is_empty() {
                            hs.push(("Cookie", c.as_str()));
                        }
                    }
                    let cap = match job.kind {
                        ProbeKind::Js => JS_BODY_CAP,
                        _ => BODY_CAP,
                    };
                    let resp = fetch(&agent, job.method, &job.url, &hs, cap);
                    let mut local = Vec::new();
                    // 단일 잡 파싱 실패가 스윕 전체를 죽이지 않게 격리한다.
                    // 신뢰할 수 없는 웹 본문을 파싱하므로, 어떤 입력이 와도 워커는
                    // 살아남고 다음 잡으로 넘어간다 (실패한 잡의 부분 결과는 버린다).
                    let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        classify_job(&job, resp, &mut local);
                    }))
                    .is_ok();
                    if ok && !local.is_empty() {
                        out.lock().unwrap().extend(local);
                    }
                }
            });
        }
    });
    Arc::try_unwrap(out).map(|m| m.into_inner().unwrap()).unwrap_or_default()
}

fn classify_job(job: &Job, resp: Result<Resp, String>, out: &mut Vec<ProbeHit>) {
    match &job.kind {
        ProbeKind::Path => {
            let Ok(r) = resp else { return };
            let path = job.url.split('?').next().unwrap_or(&job.url);
            let p = path.split('/').skip(3).collect::<Vec<_>>().join("/");
            let p = format!("/{p}");
            if let Some((sev, title)) = classify_path(&p, r.status, &r.body) {
                let ev = if sev == Severity::High || sev == Severity::Critical {
                    one_line(&r.body, 200)
                } else {
                    String::new()
                };
                out.push(hit("paths", sev, job.url.clone(), format!("{title} — {p}"), String::new(), ev, format!("GET {p} → {}", r.status), Some(r.status)));
            }
            // 패스 응답에서도 비밀 스캔 (200 + 텍스트성).
            if r.status == 200 && r.body.len() > 8 {
                for (kind, ex) in find_secrets(&r.body).into_iter().take(2) {
                    out.push(hit("secret", Severity::High, job.url.clone(), format!("{kind} ({p})"), String::new(), ex, format!("GET {p} → 200"), Some(200)));
                }
            }
        }
        ProbeKind::Js => {
            let Ok(r) = resp else { return };
            if r.status != 200 {
                return;
            }
            for (kind, ex) in find_secrets(&r.body).into_iter().take(3) {
                out.push(hit("secret", Severity::High, job.url.clone(), format!("{kind} (JS 번들)"), String::new(), ex, format!("GET → 200 ({}B)", r.body.len()), Some(200)));
            }
            // 내부 URL 힌트.
            for hint in ["/api/", "/admin", "/graphql", "localhost:", "127.0.0.1", "192.168.", "10."] {
                if r.body.contains(hint) {
                    out.push(hit("js-hint", Severity::Info, job.url.clone(), format!("JS 내부 경로 힌트: {hint}"), String::new(), String::new(), "GET → 200".into(), Some(200)));
                    break;
                }
            }
        }
        ProbeKind::Xss { param, raw, marker } => {
            let Ok(r) = resp else { return };
            let ctx = classify_reflection(&r.body, marker);
            if let Some(sev) = reflect_severity(&ctx, *raw) {
                let where_ = if ctx.in_script { "script 컨텍스트" } else if ctx.in_attr { "속성 컨텍스트" } else if ctx.in_comment { "주석" } else { "텍스트" };
                out.push(hit(
                    "xss-reflect",
                    sev,
                    job.url.clone(),
                    format!("반사 XSS 신호 — 파라미터 '{param}' ({where_}{})", if *raw { ", 특수문자 무필터" } else { "" }),
                    "무해 마커 반사 확인 — 실제 악용은 별도 검증 필요".into(),
                    one_line(&r.body, 160),
                    format!("GET → {}", r.status),
                    Some(r.status),
                ));
            }
        }
        ProbeKind::Sqli { param, quote } => {
            let Ok(r) = resp else { return };
            let fps = find_sql_errors(&r.body);
            if !fps.is_empty() {
                out.push(hit(
                    "sqli-signal",
                    Severity::High,
                    job.url.clone(),
                    format!("SQL 오류 노출 — 파라미터 '{param}'"),
                    format!("지문: {}", fps.join(" / ")),
                    one_line(&r.body, 200),
                    format!("GET → {}", r.status),
                    Some(r.status),
                ));
            } else if r.status >= 500 {
                out.push(hit(
                    "sqli-signal",
                    Severity::Medium,
                    job.url.clone(),
                    format!("따옴표({quote}) 입력에 500 — 파라미터 '{param}'"),
                    "서버 오류 전이 — SQL/서버 예외 가능성에 대한 약한 신호".into(),
                    one_line(&r.body, 160),
                    format!("GET → {}", r.status),
                    Some(r.status),
                ));
            }
        }
        ProbeKind::Redirect { param, payload } => {
            let Ok(r) = resp else { return };
            if (300..400).contains(&r.status) {
                if let Some(loc) = header(&r.headers, "location") {
                    if loc.contains("evil-probe.test") {
                        out.push(hit(
                            "openredirect",
                            Severity::High,
                            job.url.clone(),
                            format!("오픈 리다이렉트 — 파라미터 '{param}'"),
                            format!("페이로드 {payload} → Location: {loc}"),
                            String::new(),
                            format!("GET → {}", r.status),
                            Some(r.status),
                        ));
                    }
                }
            }
        }
    }
}

/// 헤드리스 브라우저 탐색 — REDCELL_CHROME_BIN → PATH → ms-playwright 캐시.
pub fn find_browser() -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("REDCELL_CHROME_BIN") {
        let p = std::path::PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    for bin in ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome", "headless_shell"] {
        if let Some(p) = first_on_path(bin) {
            return Some(p);
        }
    }
    // ms-playwright 캐시 (없는 환경에선 조용히 스킵).
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let cache = std::path::PathBuf::from(home).join(".cache").join("ms-playwright");
        if let Ok(rd) = std::fs::read_dir(&cache) {
            let mut cands: Vec<std::path::PathBuf> = Vec::new();
            for e in rd.flatten() {
                let d = e.path();
                cands.push(d.join("chrome-headless-shell-linux64").join("chrome-headless-shell"));
                cands.push(d.join("chrome-linux").join("chrome"));
                cands.push(d.join("chrome-linux64").join("chrome"));
                cands.push(d.join("chrome-win").join("chrome.exe"));
            }
            cands.sort();
            if let Some(p) = cands.into_iter().find(|p| p.is_file()) {
                return Some(p);
            }
        }
    }
    None
}

fn first_on_path(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    let sep = if cfg!(windows) { ';' } else { ':' };
    for dir in std::env::split_paths(&path) {
        let _ = sep;
        let cands: Vec<std::path::PathBuf> = if cfg!(windows) {
            ["", ".exe", ".cmd", ".bat"].iter().map(|e| dir.join(format!("{bin}{e}"))).collect()
        } else {
            vec![dir.join(bin)]
        };
        for c in cands {
            if c.is_file() {
                return Some(c);
            }
        }
    }
    None
}

/// JS 렌더 DOM 확보 — headless --dump-dom (25초 타임아웃). 실패하면 None.
pub fn render_dom(url: &str, cfg: &SweepConfig) -> Option<String> {
    render_dom_with(url, cfg, find_browser())
}

fn render_dom_with(url: &str, cfg: &SweepConfig, bin: Option<std::path::PathBuf>) -> Option<String> {
    let bin = bin?;
    let mut cmd = std::process::Command::new(bin);
    cmd.args([
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--virtual-time-budget=6000",
        "--timeout=20000",
        "--dump-dom",
        url,
    ]);
    hide_window_probe(&mut cmd);
    let mut child = cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().ok()?;
    let overall = cfg.req_timeout.max(Duration::from_secs(25));
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > overall {
                    let _ = child.kill();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return None,
        }
    }
    let mut out = String::new();
    if let Some(o) = child.stdout.take() {
        use std::io::Read;
        let _ = o.take(2_000_000).read_to_string(&mut out);
    }
    if out.trim().len() < 200 {
        return None;
    }
    Some(out)
}

#[cfg(windows)]
fn hide_window_probe(cmd: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn hide_window_probe(_cmd: &mut std::process::Command) {}

// ── 로그인 폼 injection 시도 (안전 프로브) ────────────────────────────────────

/// 로그인 폼 파싱 — password input 을 포함한 첫 form (action·method·필드명).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginForm {
    pub action: String,
    pub post: bool,
    pub user_field: String,
    pub pass_field: String,
}

pub fn parse_login_form(html: &str, base_url: &str) -> Option<LoginForm> {
    // ASCII 소문자화 — 바이트 길이를 보존해 인덱스가 html 과 일치한다.
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(fpos) = lower[from..].find("<form").map(|p| from + p) {
        let fend = lower[fpos..].find("</form>").map(|p| fpos + p).unwrap_or(html.len());
        let form = &html[fpos..fend.min(html.len())];
        let flow = &lower[fpos..fend.min(lower.len())];
        from = fend + 7;
        if !flow.contains("type=\"password\"") && !flow.contains("type='password'") {
            continue;
        }
        let tag_end = flow.find('>').map(|p| fpos + p).unwrap_or(fpos);
        let tag = &html[fpos..tag_end.min(html.len())];
        let action = attr_value(tag, "action").unwrap_or_else(|| "/".to_string());
        // 동일 호스트만 (외부 action 은 추적 금지).
        let action_url = if action.starts_with('/') && !action.starts_with("//") {
            format!("{base_url}{action}")
        } else if action.starts_with("http") {
            let host_part = base_url.split("://").nth(1).unwrap_or("");
            let a_host = action.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("");
            if a_host.eq_ignore_ascii_case(host_part) {
                action
            } else {
                continue;
            }
        } else if action.is_empty() || action == "#" {
            format!("{base_url}/")
        } else {
            continue;
        };
        let method = attr_value(tag, "method").unwrap_or_default().to_lowercase();
        // 필드명 수집.
        let mut texts: Vec<String> = Vec::new();
        let mut pass: Option<String> = None;
        let mut ifrom = 0;
        while let Some(ipos) = flow[ifrom.min(flow.len())..].find("<input").map(|p| ifrom + p) {
            let iend = flow[ipos..].find('>').map(|p| ipos + p).unwrap_or(flow.len());
            let itag = form.get(ipos..iend.min(form.len())).unwrap_or("");
            ifrom = iend + 1;
            let Some(name) = attr_value(itag, "name") else { continue };
            let typ = attr_value(itag, "type").unwrap_or_default().to_lowercase();
            if typ == "password" {
                pass = Some(name);
            } else if typ.is_empty() || ["text", "email", "username", "login", "id"].contains(&typ.as_str()) {
                texts.push(name);
            }
            if ifrom >= flow.len() {
                break;
            }
        }
        let pass_field = pass?;
        let user_field = texts
            .iter()
            .find(|n| ["user", "id", "email", "login", "name", "account"].iter().any(|k| n.to_lowercase().contains(k)))
            .or_else(|| texts.first())
            .cloned()?;
        return Some(LoginForm { action: action_url, post: method != "get", user_field, pass_field });
    }
    None
}

fn attr_value(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find(name).map(|p| from + p) {
        let after = lower[pos + name.len()..].trim_start();
        if !after.starts_with('=') {
            from = pos + name.len();
            continue;
        }
        let v = after[1..].trim_start();
        let q = v.chars().next()?;
        if q == '"' || q == '\'' {
            let end = v[q.len_utf8()..].find(q)?;
            return Some(v[q.len_utf8()..q.len_utf8() + end].to_string());
        }
        let end = v.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(v.len());
        return Some(v[..end].to_string());
    }
    None
}

struct LoginResp {
    status: u16,
    body: String,
    cookies: Vec<String>,
}

fn submit_login(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    form: &LoginForm,
    user: &str,
    pass: &str,
    counter: &AtomicUsize,
) -> Result<LoginResp, String> {
    counter.fetch_add(1, Ordering::Relaxed);
    let ch = cfg.cookie_headers();
    let resp = if form.post {
        let body = format!("{}={}&{}={}", pct_encode(&form.user_field), pct_encode(user), pct_encode(&form.pass_field), pct_encode(pass));
        let mut req = agent.post(&form.action);
        for (k, v) in &ch {
            req = req.set(k, v);
        }
        match req.set("Content-Type", "application/x-www-form-urlencoded").send_string(&body) {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(e.to_string()),
        }
    } else {
        let url = format!("{}?{}={}&{}={}", form.action, pct_encode(&form.user_field), pct_encode(user), pct_encode(&form.pass_field), pct_encode(pass));
        let mut req = agent.get(&url);
        for (k, v) in &ch {
            req = req.set(k, v);
        }
        match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(e.to_string()),
        }
    };
    let status = resp.status();
    let cookies: Vec<String> = resp.all("set-cookie").iter().map(|s| s.to_string()).collect();
    let mut buf = Vec::new();
    resp.into_reader().take(65_536).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok(LoginResp { status, body: String::from_utf8_lossy(&buf).into_owned(), cookies })
}

fn has_error_kw(body: &str) -> bool {
    let l = body.to_lowercase();
    ["invalid", "incorrect", "wrong", "failed", "failure", "error", "denied", "unauthorized",
     "실패", "오류", "틀렸", "없습니다", "맞지 않", "확인해"].iter().any(|k| l.contains(k))
}

fn has_login_form(body: &str) -> bool {
    let l = body.to_lowercase();
    l.contains("type=\"password\"") || l.contains("type='password'")
}

fn new_session_cookie(baseline: &[String], resp: &[String]) -> bool {
    let names = |cs: &[String]| -> Vec<String> {
        cs.iter()
            .map(|c| c.split(';').next().unwrap_or("").split('=').next().unwrap_or("").trim().to_lowercase())
            .collect()
    };
    let before = names(baseline);
    resp.iter().any(|c| {
        let n = c.split(';').next().unwrap_or("").split('=').next().unwrap_or("").trim().to_lowercase();
        !before.contains(&n) && ["sess", "sid", "token", "auth", "session", "jwt", "login", "remember"].iter().any(|k| n.contains(k))
    })
}

/// 로그인 injection 시도 — baseline(오답) → SQLi 우회 2종 → 레이트리밋 6회.
/// 전부 존재하지 않는 계정 + 고정 페이로드, 쓰기·파괴 없음.
pub fn probe_login(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    form: &LoginForm,
    counter: &AtomicUsize,
) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    let target = form.action.clone();
    // 1) baseline — 오답 기준선.
    let Ok(base) = submit_login(agent, cfg, form, "rc7xnouser1", "rc7xw0ng!", counter) else {
        return out;
    };
    let base_fp = find_sql_errors(&base.body);
    // 상세 오류 차이 (수동 열거 가능 신호).
    {
        let l = base.body.to_lowercase();
        let user_kw = l.contains("not found") || l.contains("존재하지") || l.contains("unknown user") || l.contains("no such user");
        let pass_kw = l.contains("wrong password") || l.contains("비밀번호") && l.contains("틀렸");
        if user_kw != pass_kw && (user_kw || pass_kw) {
            out.push(hit("auth-inject", Severity::Low, target.clone(),
                "로그인 상세 오류 차이 — 사용자 열거 가능".into(),
                "계정 존재 여부에 따라 오류 메시지가 갈릴 수 있음 — 수동 확인 필요".into(),
                one_line(&base.body, 200), format!("POST → {}", base.status), Some(base.status)));
        }
    }
    // 2) SQLi 우회 페이로드 2종.
    for (i, (u, p)) in [("rc7x' OR '1'='1", "rc7x' OR '1'='1"), ("rc7x' OR 1=1-- -", "anything")].iter().enumerate() {
        if cancelled(cfg) {
            return out;
        }
        std::thread::sleep(Duration::from_millis(150));
        let Ok(r) = submit_login(agent, cfg, form, u, p, counter) else { continue };
        let masked_u = u.to_string();
        let req = format!("POST {}=*** (payload #{})", form.user_field, i + 1);
        let fps: Vec<String> = find_sql_errors(&r.body).into_iter().filter(|f| !base_fp.contains(f)).collect();
        if !fps.is_empty() {
            out.push(hit("auth-inject", Severity::High, target.clone(),
                "로그인 SQL 오류 노출".into(),
                format!("지문: {} / 입력: {masked_u}", fps.join(" / ")),
                one_line(&r.body, 200), format!("{} → {}", req, r.status), Some(r.status)));
            continue;
        }
        let success = new_session_cookie(&base.cookies, &r.cookies) && !has_login_form(&r.body) && !has_error_kw(&r.body);
        if success {
            out.push(hit("auth-inject", Severity::High, target.clone(),
                "SQLi 인증 우회 가능".into(),
                format!("입력: {masked_u} / 새 세션 쿠키 발급 + 로그인 폼 소멸"),
                one_line(&r.body, 200), format!("{} → {}", req, r.status), Some(r.status)));
            continue;
        }
        let differs = r.status != base.status
            || (r.body.len() as i64 - base.body.len() as i64).abs() > (base.body.len() as i64 * 40 / 100).max(200)
            || has_error_kw(&r.body) != has_error_kw(&base.body);
        if differs {
            out.push(hit("auth-inject", Severity::Medium, target.clone(),
                "로그인 비정상 반응 — 수동 확인".into(),
                format!("입력: {masked_u} / 기준선과 응답이 다름 ({}→{}, {}B→{}B)", base.status, r.status, base.body.len(), r.body.len()),
                one_line(&r.body, 200), format!("{} → {}", req, r.status), Some(r.status)));
        } else {
            out.push(hit("auth-inject", Severity::Info, target.clone(),
                format!("SQLi 우회 시도 #{i} — 차단됨", i = i + 1),
                format!("입력: {masked_u} / 기준선과 동일하게 거부됨"),
                String::new(), format!("{} → {}", req, r.status), Some(r.status)));
        }
    }
    // 3) 레이트리밋 신호 — 오답 6연타 (존재하지 않는 계정).
    let mut limited = false;
    for i in 0..6 {
        if cancelled(cfg) {
            return out;
        }
        std::thread::sleep(Duration::from_millis(120));
        let Ok(r) = submit_login(agent, cfg, form, &format!("rc7xrl{i}"), "rc7xw0ng!", counter) else { continue };
        let l = r.body.to_lowercase();
        if r.status == 429 || l.contains("too many") || l.contains("rate limit") || l.contains("captcha") || l.contains("잠겼") || l.contains("locked") {
            limited = true;
            break;
        }
    }
    if limited {
        out.push(hit("auth-inject", Severity::Info, target.clone(),
            "로그인 레이트리밋/잠금 감지".into(), "연속 오답에 429·잠금·캡차 반응".into(),
            String::new(), "POST ×6 (오답)".into(), None));
    } else {
        out.push(hit("auth-inject", Severity::Low, target,
            "무차별 대입 방어 미확인".into(), "오답 6연타에도 제지 없음 — 별도 방어(지연·캡차) 확인 필요".into(),
            String::new(), "POST ×6 (오답)".into(), None));
    }
    out
}

// ── 인증우회 퍼징 (읽기 전용 경계 내) ───────────────────────────────────────────
// 규칙: 사용자 본인 세션 쿠키만 변조·재전송 (GET), 타인 ID 순회·기본자격 대입 없음.

fn b64url_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        b'=' => None, // 패딩 — 종료
        _ => None,
    }
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        let v = b64url_val(c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn b64url_encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = *bytes.get(i + 1).unwrap_or(&0) as u32;
        let b2 = *bytes.get(i + 2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        let rem = bytes.len() - i;
        out.push(ALPHA[(n >> 18) as usize & 63] as char);
        out.push(ALPHA[(n >> 12) as usize & 63] as char);
        if rem > 1 {
            out.push(ALPHA[(n >> 6) as usize & 63] as char);
        }
        if rem > 2 {
            out.push(ALPHA[n as usize & 63] as char);
        }
        i += 3;
    }
    out
}

struct JwtParts {
    name: String,
    alg: String,
    has_exp: bool,
    header_b64: String,
    payload_b64: String,
}

fn jwt_segments(value: &str) -> Option<(&str, &str, &str)> {
    let mut it = value.split('.');
    let (h, p, s) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() {
        return None;
    }
    if h.len() < 4 || p.len() < 4 {
        return None;
    }
    let ok = |seg: &str| !seg.is_empty() && seg.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    if !ok(h) || !ok(p) || (!s.is_empty() && !ok(s)) {
        return None;
    }
    Some((h, p, s))
}

/// 쿠키 문자열에서 JWT 형태 값을 찾아 헤더를 오프라인 해석한다.
fn find_jwt_in_cookie(cookie: &str) -> Option<JwtParts> {
    for pair in cookie.split(';') {
        let Some((name, value)) = pair.split_once('=') else { continue };
        let value = value.trim().trim_matches('"');
        let Some((h, p, _)) = jwt_segments(value) else { continue };
        let Some(header) = b64url_decode(h) else { continue };
        let Ok(header_s) = String::from_utf8(header) else { continue };
        if !header_s.contains("\"alg\"") {
            continue;
        }
        let Some(alg) = header_s.split("\"alg\"").nth(1).and_then(|s| s.split('"').nth(1)) else { continue };
        let alg = alg.to_string();
        let payload_has_exp = b64url_decode(p)
            .and_then(|b| String::from_utf8(b).ok())
            .map(|s| s.contains("\"exp\""))
            .unwrap_or(false);
        return Some(JwtParts {
            name: name.trim().to_string(),
            alg,
            has_exp: payload_has_exp,
            header_b64: h.to_string(),
            payload_b64: p.to_string(),
        });
    }
    None
}

fn get_with_cookie(
    agent: &ureq::Agent,
    url: &str,
    cookie: Option<&str>,
    counter: &AtomicUsize,
) -> Option<(u16, String)> {
    counter.fetch_add(1, Ordering::Relaxed);
    let mut req = agent.get(url);
    if let Some(c) = cookie {
        req = req.set("Cookie", c);
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(_) => return None,
    };
    let status = resp.status();
    let mut buf = Vec::new();
    use std::io::Read;
    resp.into_reader().take(65_536).read_to_end(&mut buf).ok()?;
    Some((status, String::from_utf8_lossy(&buf).into_owned()))
}

fn bodies_similar(a: &str, b: &str) -> bool {
    let (la, lb) = (a.len() as i64, b.len() as i64);
    if (la - lb).abs() > (la.max(1) * 5 / 100).max(32) {
        return false;
    }
    a.chars().take(200).collect::<String>() == b.chars().take(200).collect::<String>()
}

fn bodies_differ(a: &str, b: &str) -> bool {
    let (la, lb) = (a.len() as i64, b.len() as i64);
    if (la - lb).abs() > (la.max(1) * 10 / 100).max(64) {
        return true;
    }
    a.chars().take(200).collect::<String>() != b.chars().take(200).collect::<String>()
}

/// JWT confusion — 본인 세션 JWT 를 alg=none·서명 제거로 변조해 재전송 (GET 4회).
/// 위조가 원본과 같은 접근을 얻으면 서명 미검증 확정.
pub fn probe_jwt_confusion(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    counter: &AtomicUsize,
) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    let cookie = match cfg.cookie.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) => c.to_string(),
        None => return out,
    };
    let jwt = match find_jwt_in_cookie(&cookie) {
        Some(j) => j,
        None => return out,
    };
    // 오프라인 1차 판정.
    if jwt.alg.eq_ignore_ascii_case("none") {
        out.push(hit("auth-bypass", Severity::High, base_url.to_string(),
            "무서명 JWT 세션 (alg=none)".into(),
            format!("쿠키 {} 가 서명 없는 JWT — 위조 토큰으로 임의 세션 생성 가능", jwt.name),
            format!("alg=none exp={}", if jwt.has_exp { "있음" } else { "없음" }),
            "Cookie 오프라인 해석".into(), None));
        return out;
    }
    if !jwt.has_exp {
        out.push(hit("auth-bypass", Severity::Info, base_url.to_string(),
            format!("JWT 만료 없음 (alg={})", jwt.alg),
            format!("쿠키 {} 페이로드에 exp 없음 — 탈취 시 장기 유효", jwt.name),
            String::new(), "Cookie 오프라인 해석".into(), None));
    }
    // 기준선: 원본 쿠키 vs 무쿠키.
    let url = format!("{base_url}/");
    let (bs, bb) = match get_with_cookie(agent, &url, Some(&cookie), counter) {
        Some(v) => v,
        None => return out,
    };
    let anon = get_with_cookie(agent, &url, None, counter);
    let authed_differs = match &anon {
        Some((st, bo)) => *st != bs || bodies_differ(&bb, bo),
        None => true,
    };
    if !authed_differs {
        out.push(hit("auth-bypass", Severity::Info, base_url.to_string(),
            "JWT 영향 판정 불가 — 인증 전후 동일 응답".into(),
            "루트 경로가 인증과 무관하게 동일 — confusion 시도 생략".into(),
            String::new(), "GET / ×2".into(), Some(bs)));
        return out;
    }
    // 변조 2종 — 서명 검증 여부 판정.
    let none_h = b64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
    let variants = [
        (format!("{none_h}.{}.", jwt.payload_b64), "alg=none+서명 제거"),
        (format!("{}.{}." , jwt.header_b64, jwt.payload_b64), "서명 제거(원본 헤더)"),
    ];
    for (forged, label) in variants {
        if cancelled(cfg) {
            return out;
        }
        std::thread::sleep(Duration::from_millis(150));
        // 해당 쿠키 값만 교체 (나머지 쿠키는 유지).
        let mut pairs: Vec<String> = cookie.split(';').map(|s| s.to_string()).collect();
        for p in pairs.iter_mut() {
            if let Some((n, _)) = p.split_once('=') {
                if n.trim() == jwt.name {
                    *p = format!("{}={forged}", jwt.name);
                }
            }
        }
        let forged_cookie = pairs.join(";");
        let (fs, fb) = match get_with_cookie(agent, &url, Some(&forged_cookie), counter) {
            Some(v) => v,
            None => continue,
        };
        if fs == bs && bodies_similar(&bb, &fb) {
            out.push(hit("auth-bypass", Severity::High, base_url.to_string(),
                format!("JWT 서명 미검증 — {label} 수락"),
                format!("위조 토큰이 원본 세션과 동일한 접근 획득 (GET / → {fs}, 본문 유사)"),
                one_line(&fb, 200), format!("GET / (Cookie: {}=위조)", jwt.name), Some(fs)));
            return out;
        }
    }
    out.push(hit("auth-bypass", Severity::Info, base_url.to_string(),
        "JWT 서명 검증됨 — 위조 2종 거부".into(),
        "alg=none·서명 제거 변조가 모두 원본과 다른 응답 (서명 강제 확인)".into(),
        String::new(), "GET / ×4 (본인 세션)".into(), Some(bs)));
    out
}

/// 인증 차분 — 인증 필요 후보 경로를 쿠키 유무로 대조 (읽기 GET, SPA 폴백 제외).
pub fn probe_auth_differential(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    counter: &AtomicUsize,
) -> Vec<ProbeHit> {
    const CANDS: &[&str] =
        &["/api/me", "/api/user", "/api/profile", "/api/orders", "/me", "/profile", "/account", "/dashboard", "/admin", "/api/admin"];
    let mut out = Vec::new();
    let cookie = cfg.cookie.as_deref().map(str::trim).filter(|c| !c.is_empty());
    let root = get_with_cookie(agent, &format!("{base_url}/"), cookie, counter).map(|(_, b)| b).unwrap_or_default();
    for path in CANDS {
        if cancelled(cfg) {
            return out;
        }
        std::thread::sleep(Duration::from_millis(80));
        let url = format!("{base_url}{path}");
        let authed = get_with_cookie(agent, &url, cookie, counter);
        let (st, body) = match authed {
            Some(v) => v,
            None => continue,
        };
        if st != 200 || body.trim().is_empty() {
            continue;
        }
        // SPA 폴백 (루트와 동일 본문) 은 제외.
        if !root.is_empty() && bodies_similar(&root, &body) {
            continue;
        }
        match cookie {
            Some(_) => {
                std::thread::sleep(Duration::from_millis(80));
                match get_with_cookie(agent, &url, None, counter) {
                    Some((st2, body2)) if st2 == 200 && bodies_similar(&body, &body2) => {
                        // 양쪽 모두 로그인 폼이면 쿠키 무효일 가능성이 커 확정하지 않는다.
                        if has_login_form(&body) && has_login_form(&body2) {
                            out.push(hit("auth-bypass", Severity::Info, url.clone(),
                                "인증 차분 판정 불가 — 양쪽 모두 로그인 폼".into(),
                                format!("{path} — 세션 쿠키가 무효하거나 만료됐을 수 있음"),
                                String::new(), format!("GET {path} ×2 (차분)"), Some(200)));
                        } else {
                            out.push(hit("auth-bypass", Severity::High, url.clone(),
                                "인증 게이트 누락 — 무인증 동일 응답".into(),
                                format!("{path} 가 쿠키 없이도 인증 시와 동일한 200 응답"),
                                one_line(&body2, 200), format!("GET {path} ×2 (차분)"), Some(200)));
                        }
                    }
                    _ => {}
                }
            }
            None => {
                // 무쿠키 스윕에서도 200 이면 노출 신호 (JSON/개인정보 키워드 가중).
                let l = body.to_lowercase();
                let sensitive = ["email", "phone", "address", "card", "password", "token", "user_id", "order"].iter().any(|k| l.contains(k));
                out.push(hit("auth-bypass", if sensitive { Severity::Medium } else { Severity::Low }, url.clone(),
                    "무인증 접근 가능 경로".into(),
                    format!("{path} 가 쿠키 없이 200 ({}B{})", body.len(), if sensitive { "·민감 키워드 포함" } else { "" }),
                    one_line(&body, 200), format!("GET {path}"), Some(200)));
            }
        }
    }
    out
}

/// 응답 내 JWT 하드코딩·노출 스캔 (오프라인, 값 마스킹).
pub fn scan_jwt_leak(body: &str, target: &str) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    for tok in body.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')) {
        if tok.len() < 24 || tok.matches('.').count() != 2 {
            continue;
        }
        let Some((h, p, _)) = jwt_segments(tok) else { continue };
        let is_jwt = b64url_decode(h)
            .and_then(|b| String::from_utf8(b).ok())
            .map(|s| s.contains("\"alg\""))
            .unwrap_or(false)
            && b64url_decode(p).is_some();
        if is_jwt {
            let masked = format!("{}… ({})", &tok[..tok.len().min(12)], tok.len());
            out.push(hit("auth-bypass", Severity::Medium, target.to_string(),
                "응답 본문 내 JWT 노출".into(),
                format!("HTML/JS 에 JWT 형태 토큰 존재 — {masked}"),
                masked, "본문 오프라인 스캔".into(), None));
            break; // 1건이면 충분 (노이즈 방지)
        }
    }
    out
}

// ── 쓰기계열 탐지형 진단 (무발송 — 오프라인 스캔 + OPTIONS 판독만) ─────────────────
// 규칙: PUT/DELETE/PATCH/업로드 전송은 절대 하지 않는다. 표면 식별 + 설정 권고까지.

/// 업로드 폼·메서드 오버라이드 스캔 — 이미 확보한 DOM 에서 오프라인으로만.
pub fn scan_write_surface(html: &str, base_url: &str) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    let low = html.to_ascii_lowercase(); // 바이트 길이 보존 — 원본 슬라이스 오프셋 유효
    let bytes = html.as_bytes();
    let mut pos = 0usize;
    let mut forms = 0;
    while let Some(start) = low[pos..].find("<form") {
        let fs = pos + start;
        let tag_end = match low[fs..].find('>') {
            Some(e) => fs + e,
            None => break,
        };
        let tag = &low[fs..tag_end.min(fs + 2048)];
        // action 추출 (원본 오프셋 그대로).
        let action = ["action=\"", "action='", "action="].iter().find_map(|pat| {
            let a = tag.find(pat)? + fs;
            let rest = &html[a + pat.len()..];
            let quoted = pat.ends_with('"') || pat.ends_with('\'');
            let end = if quoted {
                let q = pat.as_bytes()[pat.len() - 1] as char;
                rest.find(q)?
            } else {
                rest.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(rest.len())
            };
            Some(rest[..end].to_string())
        }).unwrap_or_default();
        let multipart = tag.contains("multipart/form-data");
        // 폼 본문 (다음 </form> 또는 8KB 캡) — 끝을 문자 경계로 내림한다.
        // (to_ascii_lowercase 는 멀티바이트를 그대로 두므로 +8192 가 문자 한가운데 가능)
        let body_end = low[tag_end..].find("</form>").map(|e| tag_end + e).unwrap_or((tag_end + 8192).min(low.len()));
        let body_end = body_end.min(bytes.len());
        let fbody = safe_slice(&low, tag_end, body_end);
        let has_file = fbody.contains("type=\"file\"") || fbody.contains("type='file'") || fbody.contains("type=file");
        let has_spoof = fbody.contains("_method") || fbody.contains("x-http-method-override");
        if has_file || multipart {
            let url = if action.starts_with("http") {
                action.clone()
            } else if action.starts_with('/') {
                format!("{base_url}{action}")
            } else if action.is_empty() {
                base_url.to_string()
            } else {
                format!("{base_url}/{action}")
            };
            // 파일 필드명 수집 (최대 3개).
            let mut fields: Vec<String> = Vec::new();
            let mut fp = 0;
            while fields.len() < 3 {
                let Some(fi) = fbody[fp..].find("type") else { break };
                let seg = safe_slice(fbody, fp + fi, fp + fi + 300);
                if seg.contains("file") {
                    if let Some(ni) = seg.find("name=") {
                        let nv = seg[ni + 5..].trim_start_matches(['"', '\'']);
                        let end = nv.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '[' || c == ']')).unwrap_or(nv.len());
                        if end > 0 {
                            fields.push(nv[..end].to_string());
                        }
                    }
                }
                fp += fi + 4;
                if fp >= fbody.len() {
                    break;
                }
            }
            out.push(hit("upload-surface", Severity::Info, url.clone(),
                "파일 업로드 폼 존재 — 전송 없이 표면 식별".into(),
                format!("action={} field={} — 확장자·MIME 검증, 실행 차단, 외부 스토리지, 악성코드 스캔 권고 (실제 업로드 미수행)",
                    if action.is_empty() { "(self)" } else { &action },
                    if fields.is_empty() { "-".to_string() } else { fields.join(",") }),
                format!("multipart={multipart} file_input={has_file}"),
                format!("폼 오프라인 스캔 → {url}"), None));
            forms += 1;
            if forms >= 5 {
                break;
            }
        } else if has_spoof {
            out.push(hit("method-override", Severity::Low, base_url.to_string(),
                "메서드 오버라이드 힌트 (_method)".into(),
                format!("폼에서 _method/X-HTTP-Method-Override 사용 — action={} — 실제 우회 전송 없이 백엔드 라우팅 점검 권고",
                    if action.is_empty() { "(self)" } else { &action }),
                String::new(), "폼 오프라인 스캔".into(), None));
        }
        // 다음 폼 탐색 위치 — 문자 경계로 올림한다 (그대로 +7 하면 한글 한가운데 가능).
        pos = body_end + 7;
        while pos < low.len() && !low.is_char_boundary(pos) {
            pos += 1;
        }
        if pos >= low.len() {
            break;
        }
    }
    // 폼 밖 JS 전역 힌트 (1건으로 제한).
    if !out.iter().any(|h| h.category == "method-override")
        && (low.contains("x-http-method-override") || low.contains("\"_method\"") || low.contains("'_method'"))
    {
        out.push(hit("method-override", Severity::Low, base_url.to_string(),
            "메서드 오버라이드 힌트 (JS)".into(),
            "JS 에서 _method/X-HTTP-Method-Override 언급 — 실제 우회 전송 없이 점검 권고".into(),
            String::new(), "본문 오프라인 스캔".into(), None));
    }
    out
}

// ── 파괴적 프로브 (동의 게이트 — cfg.danger 일 때만) ─────────────────────────────
// 규칙: 모달 명시 동의 없이 절대 실행하지 않는다 (각 함수 선두 fail-closed).
// 기본자격 5종 상한·잠금 즉시 중단, IDOR 인접 ±2·증거 마스킹, 쓰기 1회+정리 시도.

/// 기본자격 대입 — 로그인 폼에 흔한 초기 자격 5종 시도, 잠금 신호 즉시 중단.
/// 비밀번호는 증거에 절대 남기지 않는다 (*** 마스킹).
pub fn probe_default_creds(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    form: &LoginForm,
    counter: &AtomicUsize,
) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    if !cfg.danger {
        return out;
    }
    const CREDS: &[(&str, &str)] =
        &[("admin", "admin"), ("admin", "password"), ("admin", "admin1234"), ("root", "root"), ("test", "test")];
    let target = form.action.clone();
    for (u, _p) in CREDS {
        if cancelled(cfg) {
            return out;
        }
        std::thread::sleep(Duration::from_millis(200));
        let r = match submit_login(agent, cfg, form, u, _p, counter) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let l = r.body.to_lowercase();
        // 잠금 신호 — 즉시 중단 (계정 잠금·방어 발동 시 더 건드리지 않음).
        if r.status == 429
            || l.contains("too many")
            || l.contains("rate limit")
            || l.contains("captcha")
            || l.contains("locked")
            || l.contains("잠겼")
        {
            out.push(hit("danger-creds", Severity::Info, target,
                "잠금/레이트리밋 감지 — 기본자격 시도 중단".into(),
                "방어 발동 확인 후 즉시 중단함 (계정 잠금 방지)".into(),
                String::new(), "POST (동의 기반, 중단)".into(), Some(r.status)));
            return out;
        }
        let success = new_session_cookie(&[], &r.cookies) && !has_login_form(&r.body) && !has_error_kw(&r.body);
        if success {
            out.push(hit("danger-creds", Severity::Critical, target,
                format!("기본 자격증명으로 로그인 성공 ({u} / ***)"),
                "초기 자격 그대로 유효 — 즉시 변경 필요 (동의 기반 실측)".into(),
                one_line(&r.body, 200), format!("POST {u} / *** (동의 기반)"), Some(r.status)));
            return out;
        }
    }
    out.push(hit("danger-creds", Severity::Info, target,
        "기본자격 5종 거부됨".into(), "admin/root/test 초기 자격 모두 실패 (동의 기반 실측)".into(),
        String::new(), "POST ×5 (동의 기반)".into(), None));
    out
}

fn redact_pii(s: &str) -> String {
    // 이메일·6자리 이상 숫자런 마스킹 (간이 스캐너, ID 자체는 보존).
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '@' {
            while !out.is_empty()
                && !out.ends_with(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ':' | ',' | '{' | '['))
            {
                out.pop();
            }
            out.push_str("[email]");
            i += 1;
            while i < chars.len() && !chars[i].is_whitespace() && !matches!(chars[i], '"' | '\'' | ',' | '}' | ']') {
                i += 1;
            }
            continue;
        }
        if chars[i].is_ascii_digit() {
            let mut j = i;
            while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '-' || chars[j] == ' ') {
                j += 1;
            }
            let digits: usize = chars[i..j].iter().filter(|c| c.is_ascii_digit()).count();
            if digits >= 6 {
                out.push_str("[digits]");
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    one_line(&out, 200)
}

/// DOM 에서 숫자 ID 엔드포인트 수집 — /api/orders/100 형태 (최대 3개).
fn extract_id_endpoints(dom: &str) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = Vec::new();
    for chunk in dom.split(|c: char| c == '"' || c == '\'' || c == ' ' || c == '(' || c == ')' || c == '<' || c == '>') {
        let t = chunk.trim().split('?').next().unwrap_or("");
        if !t.starts_with('/') || t.len() < 4 || t.len() > 120 || t.contains('.') {
            continue;
        }
        let Some(pos) = t.rfind('/') else { continue };
        let (prefix, id_s) = (&t[..pos], &t[pos + 1..]);
        if prefix.len() < 2 || !prefix.contains('/') {
            continue;
        }
        let Ok(id) = id_s.parse::<u64>() else { continue };
        if id == 0 || id > 1_000_000_000 {
            continue;
        }
        if out.iter().any(|(p, i)| p == prefix && i == &id) {
            continue;
        }
        out.push((prefix.to_string(), id));
        if out.len() >= 3 {
            break;
        }
    }
    out
}

/// IDOR 인접 확인 — 본인 세션으로 인접 숫자 ID ±2 조회, 타 리소스 열람 여부 판정.
/// 응답 증거는 마스킹 저장 (개인정보 원문 보관 금지).
pub fn probe_idor_adjacency(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    dom: &str,
    counter: &AtomicUsize,
) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    let cookie = match cfg.danger {
        true => match cfg.cookie.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            Some(c) => c,
            None => return out, // 본인 세션 없이 타인 리소스 조회 금지
        },
        false => return out,
    };
    let endpoints = extract_id_endpoints(dom);
    if endpoints.is_empty() {
        return out;
    }
    let mut tested = 0;
    for (prefix, id) in endpoints {
        if cancelled(cfg) {
            return out;
        }
        let base_u = format!("{base_url}{prefix}/{id}");
        let (_, b0) = match get_with_cookie(agent, &base_u, Some(cookie), counter) {
            Some((200, b)) if b.contains("\"id\"") || b.contains("'id'") => (200, b),
            _ => continue, // 기준 리소스 자체가 안 보이면 판정 불가
        };
        tested += 1;
        let norm0: String = b0.chars().filter(|c| !c.is_whitespace()).collect();
        for delta in [-2i64, -1, 1, 2] {
            if cancelled(cfg) {
                return out;
            }
            let adj = id as i64 + delta;
            if adj <= 0 {
                continue;
            }
            std::thread::sleep(Duration::from_millis(120));
            let adj_u = format!("{base_url}{prefix}/{adj}");
            let (st, b1) = match get_with_cookie(agent, &adj_u, Some(cookie), counter) {
                Some(v) => v,
                None => continue,
            };
            if st != 200 {
                continue;
            }
            let norm1: String = b1.chars().filter(|c| !c.is_whitespace()).collect();
            let has_adj_id = norm1.contains(&format!("\"id\":{adj}")) || norm1.contains(&format!("'id':{adj}"));
            let len_ok = {
                let (a, b) = (norm0.len().max(1), norm1.len().max(1));
                b * 2 >= a && a * 2 >= b
            };
            if has_adj_id && len_ok && norm1 != norm0 {
                out.push(hit("danger-idor", Severity::High, adj_u.clone(),
                    format!("IDOR 확정 — 인접 ID {adj} 타 리소스 열람"),
                    format!("{prefix}/{{id}} 소유권 검사 없음 — 인접 번호로 타인 리소스 응답 (동의 기반, 증거 마스킹)"),
                    redact_pii(&b1), format!("GET {prefix}/{adj} (동의 기반)"), Some(200)));
                return out; // 1건 확정으로 충분 (추가 순회 금지)
            }
        }
    }
    if tested > 0 && out.is_empty() {
        out.push(hit("danger-idor", Severity::Info, base_url.to_string(),
            format!("IDOR 내성 — {tested}개 엔드포인트 인접 ID 거부"),
            "인접 ±2 조회가 모두 거부·차단됨 (동의 기반 실측)".into(),
            String::new(), "GET ×N (동의 기반)".into(), None));
    }
    out
}

fn rand_hex8() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0x1234) as u64;
    let x = n ^ (n >> 33) ^ 0x9e3779b97f4a7c15;
    format!("{:08x}", (x & 0xffff_ffff) as u32)
}

/// 쓰기 검증 — 무해 마커 파일 1건 PUT → GET 확인 → DELETE 정리 시도.
/// 정리 실패 시 잔여물 경로를 리포트에 명시 (수동 삭제 유도).
pub fn probe_write_verify(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    counter: &AtomicUsize,
) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    if !cfg.danger {
        return out;
    }
    const MARKER: &str = "rc7x-consented-write-probe-ok";
    let path = format!("/rc7x-probe-{}.txt", rand_hex8());
    let url = format!("{base_url}{path}");
    let ch = cfg.cookie_headers();
    // 1) PUT 1회.
    counter.fetch_add(1, Ordering::Relaxed);
    let mut req = agent.put(&url).set("Content-Type", "text/plain");
    for (k, v) in &ch {
        req = req.set(k, v);
    }
    let put_status = match req.send_string(MARKER) {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(_, r)) => r.status(),
        Err(_) => {
            out.push(hit("danger-write", Severity::Info, url, "쓰기 판정 불가 — PUT 전송 실패".into(),
                "네트워크 오류 (동의 기반)".into(), String::new(), format!("PUT {path}"), None));
            return out;
        }
    };
    if !(200..=299).contains(&put_status) {
        out.push(hit("danger-write", Severity::Info, url,
            format!("쓰기 거부됨 (PUT → {put_status})"),
            "서버가 쓰기를 거부 — 설정 양호 (동의 기반 실측)".into(),
            String::new(), format!("PUT {path}"), Some(put_status)));
        return out;
    }
    // 2) GET 반영 확인.
    std::thread::sleep(Duration::from_millis(200));
    let reflected = get_with_cookie(agent, &url, cfg.cookie.as_deref(), counter)
        .map(|(st, b)| st == 200 && b.contains(MARKER))
        .unwrap_or(false);
    // 3) DELETE 정리 시도.
    std::thread::sleep(Duration::from_millis(200));
    counter.fetch_add(1, Ordering::Relaxed);
    let mut del = agent.delete(&url);
    for (k, v) in &ch {
        del = del.set(k, v);
    }
    let del_status = match del.call() {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(_, r)) => r.status(),
        Err(_) => 0,
    };
    let cleaned = (200..=299).contains(&del_status) || del_status == 404;
    out.push(hit(
        "danger-write",
        if reflected { Severity::High } else { Severity::Medium },
        url.clone(),
        if reflected { "쓰기 검증됨 — 파일 생성 확인".into() } else { "PUT 수락이나 미반영".into() },
        if cleaned {
            format!("PUT {put_status} → GET 반영 {} → DELETE {del_status} 정리됨 (동의 기반)", if reflected { "확인" } else { "없음" })
        } else {
            format!("PUT {put_status} → GET 반영 {} → DELETE {del_status} 정리 실패 — 잔여물 수동 삭제 필요: {path} (동의 기반)", if reflected { "확인" } else { "없음" })
        },
        String::new(),
        format!("PUT→GET→DELETE {path}"),
        Some(put_status),
    ));
    out
}

// ── P1 검증 루프 (발견 → 재현 → 확정) ─────────────────────────────────────────

/// P1 검증 — P0 발견 중 재현 가능한 것을 2차 프로브로 확정한다 (수십 건 이내).
pub fn verify_pass(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    hits: &[ProbeHit],
    counter: &AtomicUsize,
    deadline: Instant,
) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    let ch = cfg.cookie_headers();
    let mut budget = 24;
    let take = |n: &mut usize| {
        if *n == 0 || Instant::now() > deadline || cancelled(cfg) {
            return false;
        }
        *n -= 1;
        std::thread::sleep(Duration::from_millis(60));
        true
    };
    // XSS: 서로 다른 2번째 마커로 재반사 확인.
    for h in hits.iter().filter(|h| h.category == "xss-reflect").take(3) {
        if !take(&mut budget) {
            break;
        }
        let Some(param) = xss_param_of(h) else { continue };
        let m = format!("rc7xv2{}", out.len());
        counter.fetch_add(1, Ordering::Relaxed);
        let url = format!("{base_url}/?{param}={m}");
        if let Ok(r) = fetch(agent, "GET", &url, &ch, BODY_CAP) {
            let ctx = classify_reflection(&r.body, &m);
            if ctx.found {
                out.push(hit("verify-xss", Severity::High, url,
                    format!("주입 싱크 확정 — 파라미터 '{param}'"),
                    format!("서로 다른 마커 2종 반사 (원 발견: {} {})", h.id, h.title),
                    one_line(&r.body, 160), format!("GET → {}", r.status), Some(r.status)));
            }
        }
    }
    // SQLi: Boolean 차분 (AND 1=1 vs AND 1=2).
    for h in hits.iter().filter(|h| h.category == "sqli-signal").take(3) {
        if !take(&mut budget) {
            break;
        }
        let Some(param) = sqli_param_of(h) else { continue };
        counter.fetch_add(2, Ordering::Relaxed);
        let vt = pct_encode("rc7x0' AND 1=1");
        let vf = pct_encode("rc7x0' AND 1=2");
        let t = fetch(agent, "GET", &format!("{base_url}/?{param}={vt}"), &ch, 65536);
        let f = fetch(agent, "GET", &format!("{base_url}/?{param}={vf}"), &ch, 65536);
        if let (Ok(t), Ok(f)) = (t, f) {
            let diff = t.status != f.status
                || (t.body.len() as i64 - f.body.len() as i64).abs() > 100
                || find_sql_errors(&t.body) != find_sql_errors(&f.body);
            out.push(hit(
                "verify-sqli",
                if diff { Severity::High } else { Severity::Info },
                format!("{base_url}/?{param}=…"),
                if diff { format!("Boolean 차분 확인 — 파라미터 '{param}'") } else { format!("차분 없음 — 파라미터 '{param}' (지문만)") },
                format!("원 발견: {} {} / 1=1({},{})B vs 1=2({},{})B", h.id, h.title, t.status, t.body.len(), f.status, f.body.len()),
                String::new(),
                "GET ×2".into(),
                None,
            ));
        }
    }
    // 오픈 리다이렉트: 제2 호스트로 재확인.
    for h in hits.iter().filter(|h| h.category == "openredirect").take(3) {
        if !take(&mut budget) {
            break;
        }
        let Some(param) = redirect_param_of(h) else { continue };
        counter.fetch_add(1, Ordering::Relaxed);
        let url = format!("{base_url}/?{param}={}", pct_encode("https://evil2-probe.test/r"));
        if let Ok(r) = fetch(agent, "GET", &url, &ch, 4096) {
            let loc = header(&r.headers, "location").unwrap_or("");
            if (300..400).contains(&r.status) && loc.contains("evil2-probe.test") {
                out.push(hit("verify-redirect", Severity::High, url,
                    format!("오픈 리다이렉트 확정 — 파라미터 '{param}'"),
                    format!("제2 호스트로도 302 (원 발견: {} {})", h.id, h.title),
                    format!("Location: {loc}"), format!("GET → {}", r.status), Some(r.status)));
            }
        }
    }
    // 민감 경로: 재요청 안정성.
    for h in hits.iter().filter(|h| h.category == "paths" && (h.severity == "high" || h.severity == "critical")).take(4) {
        if !take(&mut budget) {
            break;
        }
        counter.fetch_add(1, Ordering::Relaxed);
        if let Ok(r) = fetch(agent, "GET", &h.target, &ch, 65536) {
            if r.status == h.status.unwrap_or(0) {
                out.push(hit("verify-paths", Severity::Info, h.target.clone(),
                    "민감 경로 재확인".into(),
                    format!("2회 연속 동일 응답 (원 발견: {} {})", h.id, h.title),
                    String::new(), format!("GET → {}", r.status), Some(r.status)));
            }
        }
    }
    out
}

fn quoted_param(title: &str) -> Option<String> {
    let s = title.split('\'').nth(1)?;
    if s.is_empty() || s.len() > 32 || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return None;
    }
    Some(s.to_string())
}

fn xss_param_of(h: &ProbeHit) -> Option<String> {
    quoted_param(&h.title)
}

fn sqli_param_of(h: &ProbeHit) -> Option<String> {
    quoted_param(&h.title)
}

fn redirect_param_of(h: &ProbeHit) -> Option<String> {
    quoted_param(&h.title)
}

/// 전체 스윕 — base 정찰 → 병렬 잡 → 로그인 시도 → P1 검증 → P-### 부여.
pub fn run_sweep_with_config(host: &str, port: Option<u16>, cfg: SweepConfig) -> ProbeReport {
    let started = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();
    let counter = AtomicUsize::new(0);
    let deadline = started + cfg.sweep_timeout;
    let (primary, alt) = bases_for(host, port);
    let target = format!("{host}{}", port.map(|p| format!(":{p}")).unwrap_or_default());

    let agent = agent_for(&cfg);
    let mut hits = Vec::new();
    set_phase(&cfg, "대상 확인");
    let base = match fetch_base(&agent, &cfg, &primary, &alt, &counter) {
        Ok(b) => b,
        Err(e) => {
            hits.push(hit(
                "target",
                Severity::High,
                primary.clone(),
                "대상 접속 실패".into(),
                format!("base 정찰 실패 — {e}"),
                String::new(),
                "GET /".into(),
                None,
            ));
            let authenticated = cfg.cookie.as_ref().map(|c| !c.trim().is_empty()).unwrap_or(false);
            return finish_report(target, started_at, started, counter.load(Ordering::Relaxed), authenticated, cfg.danger, hits);
        }
    };
    hits.extend(base_hits(&base));
    bump_done(&cfg, &counter);
    let base_url = primary.trim_end_matches('/').to_string();

    // SPA 렌더 DOM (브라우저가 있을 때만) — 파라미터·스크립트·폼 추가 수집.
    let mut params = extract_params(&base.root_body);
    let mut scripts = extract_scripts(&base.root_body, host);
    let mut rendered: Option<String> = None;
    if Instant::now() < deadline && !cancelled(&cfg) {
        set_phase(&cfg, "렌더 DOM");
        match find_browser() {
            None => hits.push(hit("render", Severity::Info, primary.clone(),
                "렌더러 없음 — 정적 파싱만".into(), "헤드리스 브라우저 미설치 (SPA 커버리지 제한)".into(),
                String::new(), "render 스킵".into(), None)),
            Some(_) => match render_dom(&primary, &cfg) {
                Some(dom) => {
                    let (np, ns) = (params.len(), scripts.len());
                    for p in extract_params(&dom) {
                        if !params.contains(&p) {
                            params.push(p);
                        }
                    }
                    for s in extract_scripts(&dom, host) {
                        if !scripts.contains(&s) {
                            scripts.push(s);
                        }
                    }
                    params.truncate(PARAM_CAP);
                    hits.push(hit("render", Severity::Info, primary.clone(),
                        format!("JS 렌더 DOM 확보 ({}B)", dom.len()),
                        format!("추가 파라미터 {}개·스크립트 {}개", params.len().saturating_sub(np), scripts.len().saturating_sub(ns)),
                        String::new(), "headless --dump-dom".into(), None));
                    rendered = Some(dom);
                }
                None => hits.push(hit("render", Severity::Info, primary.clone(),
                    "렌더 실패 — 정적 파싱으로 진행".into(), String::new(), String::new(),
                    "headless --dump-dom".into(), None)),
            },
        }
    }
    let dom_ref = rendered.as_deref().unwrap_or(&base.root_body);

    // 잡 조립.
    let mut jobs: Vec<Job> = Vec::new();
    for path in PATH_WORDLIST {
        jobs.push(Job {
            url: format!("{base_url}{path}"),
            method: "GET",
            headers: vec![],
            kind: ProbeKind::Path,
        });
    }
    for sp in scripts.into_iter().take(JS_FETCH_CAP) {
        jobs.push(Job {
            url: format!("{base_url}{sp}"),
            method: "GET",
            headers: vec![],
            kind: ProbeKind::Js,
        });
    }
    for (i, param) in params.iter().enumerate().take(PARAM_CAP) {
        let m1 = format!("rc7xp0{i}");
        jobs.push(Job {
            url: format!("{base_url}/?{param}={m1}"),
            method: "GET",
            headers: vec![],
            kind: ProbeKind::Xss { param: param.clone(), raw: false, marker: m1 },
        });
        let m2 = format!("rc7x{i}<>\"'()");
        jobs.push(Job {
            url: format!("{base_url}/?{param}={}", pct_encode(&m2)),
            method: "GET",
            headers: vec![],
            kind: ProbeKind::Xss { param: param.clone(), raw: true, marker: m2 },
        });
        for q in ['\'', '"'] {
            jobs.push(Job {
                url: format!("{base_url}/?{param}=rc7x0{}", pct_encode(&q.to_string())),
                method: "GET",
                headers: vec![],
                kind: ProbeKind::Sqli { param: param.clone(), quote: q },
            });
        }
    }
    // 오픈 리다이렉트 — 발견된 리다이렉트성 파라미터 + 기본 3종.
    let mut rparams: Vec<String> = params.iter().filter(|p| REDIRECT_PARAMS.contains(&p.as_str())).cloned().collect();
    for d in ["url", "next", "redirect"] {
        if !rparams.iter().any(|p| p == d) {
            rparams.push(d.to_string());
        }
    }
    let mut rjobs = 0;
    for param in rparams {
        for payload in [EVIL_URL, EVIL_PROTOREL] {
            if rjobs >= REDIRECT_JOB_CAP {
                break;
            }
            jobs.push(Job {
                url: format!("{base_url}/?{param}={payload}"),
                method: "GET",
                headers: vec![],
                kind: ProbeKind::Redirect { param: param.clone(), payload },
            });
            rjobs += 1;
        }
    }

    hits.extend(run_jobs(jobs, &cfg, deadline, &counter));
    bump_done(&cfg, &counter);
    // 로그인 폼 injection 시도 + P1 검증 루프.
    if Instant::now() < deadline && !cancelled(&cfg) {
        set_phase(&cfg, "로그인 시도");
        let login_form = parse_login_form(dom_ref, &base_url);
        if let Some(form) = &login_form {
            hits.extend(probe_login(&agent, &cfg, form, &counter));
        }
        bump_done(&cfg, &counter);
        // 인증우회 퍼징 — JWT confusion + 인증 차분 + JWT 노출 스캔 (읽기 전용).
        if Instant::now() < deadline && !cancelled(&cfg) {
            set_phase(&cfg, "인증 분석");
            hits.extend(probe_jwt_confusion(&agent, &cfg, &base_url, &counter));
            bump_done(&cfg, &counter);
        }
        if Instant::now() < deadline && !cancelled(&cfg) {
            hits.extend(probe_auth_differential(&agent, &cfg, &base_url, &counter));
            bump_done(&cfg, &counter);
        }
        // 파괴적 프로브 — 동의 게이트 (미동의 시 각 함수 선두에서 빈 반환).
        if cfg.danger && Instant::now() < deadline && !cancelled(&cfg) {
            set_phase(&cfg, "파괴적 프로브");
            if let Some(form) = &login_form {
                hits.extend(probe_default_creds(&agent, &cfg, form, &counter));
            }
            hits.extend(probe_idor_adjacency(&agent, &cfg, &base_url, dom_ref, &counter));
            if Instant::now() < deadline && !cancelled(&cfg) {
                hits.extend(probe_write_verify(&agent, &cfg, &base_url, &counter));
            }
            bump_done(&cfg, &counter);
        }
        hits.extend(scan_jwt_leak(dom_ref, &primary));
        hits.extend(scan_write_surface(dom_ref, &base_url));
        if !cancelled(&cfg) {
            set_phase(&cfg, "P1 검증");
        }
        hits.extend(verify_pass(&agent, &cfg, &base_url, &hits, &counter, deadline));
        bump_done(&cfg, &counter);
    }
    let authenticated = cfg.cookie.as_ref().map(|c| !c.trim().is_empty()).unwrap_or(false);
    bump_done(&cfg, &counter);
    set_phase(&cfg, if cancelled(&cfg) { "중단됨" } else { "완료" });
    finish_report(target, started_at, started, counter.load(Ordering::Relaxed), authenticated, cfg.danger, hits)
}

fn finish_report(
    target: String,
    started_at: String,
    started: Instant,
    probes_run: usize,
    authenticated: bool,
    danger: bool,
    mut hits: Vec<ProbeHit>,
) -> ProbeReport {
    hits.sort_by(|a, b| {
        sev_rank(&a.severity)
            .cmp(&sev_rank(&b.severity))
            .then(a.category.cmp(&b.category))
            .then(a.target.cmp(&b.target))
    });
    for (i, h) in hits.iter_mut().enumerate() {
        h.id = format!("P-{:03}", i + 1);
    }
    let verified = hits.iter().filter(|h| h.category.starts_with("verify-")).count();
    ProbeReport {
        target,
        started_at,
        duration_ms: started.elapsed().as_millis() as u64,
        probes_run,
        hits,
        authenticated,
        verified,
        danger,
    }
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

/// 한 줄 요약 — `[sys] P0 스윕 — 프로브 312개·발견 9건(…·정보 1)·검증 3건·18.2초`.
pub fn sweep_summary_line(rep: &ProbeReport) -> String {
    let mut c = [0usize; 5];
    for h in &rep.hits {
        c[sev_rank(&h.severity) as usize] += 1;
    }
    format!(
        "[sys] P0 스윕{}{} — 프로브 {}개·발견 {}건(치명 {}/높음 {}/중간 {}/낮음 {}/정보 {})·검증 {}건·{:.1}초.",
        if rep.authenticated { "(인증)" } else { "" },
        if rep.danger { "(파괴적 동의)" } else { "" },
        rep.probes_run,
        rep.hits.len(),
        c[0],
        c[1],
        c[2],
        c[3],
        c[4],
        rep.verified,
        rep.duration_ms as f64 / 1000.0
    )
}

/// LLM 주입용 증거 다이제스트 — 심각도순, 글자 상한 (초과는 "외 N건 생략").
/// main 바이너리에서만 쓴다 — sweep 은 같은 모듈을 공유하므로 미사용 경고를 끈다.
#[allow(dead_code)]
pub fn evidence_digest(rep: &ProbeReport, cap_chars: usize) -> String {
    let mut out = format!(
        "P0 자동 스윕 — 대상 {} · 프로브 {}개 · {:.1}초{}{} · P1 검증 {}건\n",
        rep.target,
        rep.probes_run,
        rep.duration_ms as f64 / 1000.0,
        if rep.authenticated {
            " · 인증 스윕(세션 쿠키 적용)"
        } else {
            ""
        },
        if rep.danger {
            " · 파괴적 프로브 포함(사용자 명시 동의 — 기본자격·IDOR 인접·쓰기검증)"
        } else {
            ""
        },
        rep.verified
    );
    if rep.hits.is_empty() {
        out.push_str("(스윕 발견 없음 — LLM 자체 정찰로 보완할 것)\n");
        return out;
    }
    let mut omitted = 0;
    for h in &rep.hits {
        let line = format!(
            "[{}] [{}] {} {} — {} · {} {}\n",
            h.id,
            h.severity,
            h.category,
            h.title,
            h.target,
            h.request,
            if h.evidence.is_empty() { String::new() } else { format!("· 증거: {}", h.evidence.chars().take(160).collect::<String>()) }
        );
        if out.chars().count() + line.chars().count() > cap_chars {
            omitted += 1;
            continue;
        }
        out.push_str(&line);
    }
    if omitted > 0 {
        out.push_str(&format!("(외 {omitted}건 생략 — 심각도 낮은 순)\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn headers_audit_flags_missing() {
        let hs: Vec<(String, String)> = vec![("server".into(), "Test/1.0".into())];
        let out = audit_security_headers(&hs, false);
        let names: Vec<&str> = out.iter().map(|(n, _, _)| n.as_str()).collect();
        for must in ["content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "strict-transport-security", "server"] {
            assert!(names.contains(&must), "누락 판정 필요: {must} / {names:?}");
        }
        // HSTS 는 http 에선 info, https 에선 medium.
        let sev_http = out.iter().find(|(n, _, _)| n == "strict-transport-security").unwrap().1;
        assert_eq!(sev_http, Severity::Info);
        let out2 = audit_security_headers(&hs, true);
        let sev_https = out2.iter().find(|(n, _, _)| n == "strict-transport-security").unwrap().1;
        assert_eq!(sev_https, Severity::Medium);
    }

    #[test]
    fn cookies_audit_flags() {
        let sc = ["sess=abc; Path=/", "theme=dark; Path=/; HttpOnly; Secure; SameSite=Lax"];
        let out = audit_cookies(&sc, true);
        assert!(out.iter().any(|(n, s, _)| n == "sess" && *s == Severity::Medium), "{out:?}");
        assert!(!out.iter().any(|(n, _, _)| n == "theme"), "{out:?}");
    }

    #[test]
    fn secrets_detect_and_mask() {
        let text = "var k=\"AKIAIOSFODNN7EXAMPLE\"; tok='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc'; api_key=\"hunter2-secret-value\"";
        let out = find_secrets(text);
        let kinds: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(kinds.contains(&"AWS 액세스 키"), "{out:?}");
        assert!(kinds.contains(&"JWT"), "{out:?}");
        assert!(kinds.contains(&"하드코딩 비밀 추정"), "{out:?}");
        for (_, ex) in &out {
            assert!(!ex.contains("EXAMPLE") || ex.len() < 24, "마스킹 필요: {ex}");
        }
        assert!(find_secrets("print(40 + 2)").is_empty());
    }

    /// esdp.lge.com 실발생 회귀: lowercased 복사본 오프셋 + 고정 바이트 잘라내기가
    /// 한글 문자 경계에서 패닉나 스윕 워커 전체를 죽였다. 아래 입력들은 전부
    /// 패닉 없이 끝나고, 탐지 결과도 유지되어야 한다.
    /// ('İ' U+0130 은 소문자화하면 2문자(i̇)로 불어나 오프셋을 어긋나게 한다.)
    #[test]
    fn korean_body_never_panics_slicing() {
        let tricky = format!(
            "İ{} password=\"hunter2-hunter2-1234\" <input NAME=\"Q\">ghp_한글토큰값1234567890",
            "기".repeat(300)
        );
        let kinds: Vec<String> = find_secrets(&tricky).iter().map(|(k, _)| k.clone()).collect();
        assert!(kinds.contains(&"하드코딩 비밀 추정".to_string()), "탐지 유지: {kinds:?}");
        assert!(kinds.contains(&"GitHub 토큰".to_string()), "접두사 탐지 유지: {kinds:?}");
        let p = extract_params(&tricky);
        assert!(p.contains(&"Q".to_string()), "대소문자 무시 NAME 탐지 유지: {p:?}");
        // 소문자화가 바이트를 줄이는 문자(U+212A: 3B→1B) 뒤의 매치:
        // 구 코드는 lowercased 오프셋을 원문에 써서 '가' 한가운데에서 패닉났다.
        let shrink = format!("\u{212A}{}password=\"hunter2-hunter2-1234\"", "가".repeat(10));
        let kinds2: Vec<String> = find_secrets(&shrink).iter().map(|(k, _)| k.clone()).collect();
        assert!(kinds2.contains(&"하드코딩 비밀 추정".to_string()), "축소 오프셋 탐지: {kinds2:?}");
        // 마스킹이 한글 한가운데를 자르지 않는다.
        let m = mask_secret(&format!("토큰값-{}-끝", "가".repeat(40)));
        assert!(m.contains('…') && m.starts_with("토큰값-"), "{m}");
        // 폼 본문 8KB/300B 캡 + 다음-폼 탐색(+7)이 한글 한가운데에 걸리는 케이스.
        let long_form = format!(
            "<form action=\"/up\" method=\"post\" enctype=\"multipart/form-data\">{}</form>",
            format!("<input type=\"file\" name=\"f\">{}", "한".repeat(9000))
        );
        let hits = scan_write_surface(&long_form, "http://t:1");
        assert!(hits.iter().any(|h| h.category == "upload-surface"), "{hits:?}");
        let no_close = format!("<form action=\"/up\">{}{}", "기".repeat(9000), "<input type=\"file\" name=\"avatar\">");
        let _ = scan_write_surface(&no_close, "http://t:1");
        let two_forms = format!("<form>{}</form><form>{}</form>", "가".repeat(300), "나".repeat(300));
        let _ = scan_write_surface(&two_forms, "http://t:1");
        // safe_slice 경계 케이스.
        assert_eq!(safe_slice("가나다", 0, 5), "가");
        assert_eq!(safe_slice("가나다", 3, 8), "나");
        assert_eq!(safe_slice("abc", 2, 99), "c");
        assert_eq!(safe_slice("abc", 9, 99), "");
        // ASCII 대소문자 무시 탐색.
        assert_eq!(find_ascii_ci("xxPASSWord=1", "password", 0), Some(2));
        assert_eq!(find_ascii_ci("xxPASSWord=1", "password", 3), None);
        assert_eq!(find_ascii_ci("한글NAME=\"Q\"", "name=\"", 0), Some(6));
    }

    #[test]
    fn sql_fingerprints_match() {
        assert!(!find_sql_errors("hello world").is_empty() == false);
        assert!(!find_sql_errors("You have an error in your SQL syntax near ''").is_empty());
        assert!(!find_sql_errors("PGQUERY failed: unterminated quoted string").is_empty());
    }

    #[test]
    fn reflection_contexts() {
        let c = classify_reflection("<p>hello rc7x</p>", "rc7x");
        assert!(c.found && !c.in_script && !c.in_attr);
        let c = classify_reflection("<script>var a='rc7x';</script>", "rc7x");
        assert!(c.found && c.in_script);
        let c = classify_reflection("<input value=\"rc7x\">", "rc7x");
        assert!(c.found && c.in_attr);
        let c = classify_reflection("<!-- rc7x -->", "rc7x");
        assert!(c.found && c.in_comment);
        let c = classify_reflection("<p>nothing</p>", "rc7x");
        assert!(!c.found);
        assert_eq!(reflect_severity(&classify_reflection("<script>rc7x</script>", "rc7x"), true), Some(Severity::High));
        assert_eq!(reflect_severity(&classify_reflection("<p>rc7x</p>", "rc7x"), false), Some(Severity::Info));
    }

    #[test]
    fn params_and_scripts_extracted() {
        let html = r#"<a href="/s?x=1&uid=2">x</a><form><input name="q"><input name="pw"></form><script src="/a.js"></script><script src="https://cdn.evil/x.js"></script>"#;
        let p = extract_params(html);
        for must in ["x", "uid", "q", "pw"] {
            assert!(p.contains(&must.to_string()), "{p:?}");
        }
        let s = extract_scripts(html, "t.local");
        assert_eq!(s, vec!["/a.js"], "외부 CDN 추적 금지: {s:?}");
    }

    #[test]
    fn path_classifier_shapes() {
        assert!(classify_path("/nope", 404, "").is_none());
        let (s, _) = classify_path("/.env", 200, "A=1\nB=2\nC=3\n").unwrap();
        assert_eq!(s, Severity::High);
        let (s, _) = classify_path("/.git/HEAD", 200, "ref: x").unwrap();
        assert_eq!(s, Severity::High);
        let (s, _) = classify_path("/%2e%2e/%2e%2e/etc/passwd", 200, "root:x:0:0").unwrap();
        assert_eq!(s, Severity::Critical);
        assert!(classify_path("/%2e%2e/%2e%2e/etc/passwd", 200, "<p>nope</p>").is_none());
        let (s, _) = classify_path("/.env", 403, "").unwrap();
        assert_eq!(s, Severity::Info);
    }

    #[test]
    fn wordlist_sane() {
        assert!(PATH_WORDLIST.len() >= 120, "워드리스트 빈약: {}", PATH_WORDLIST.len());
        let mut seen = std::collections::HashSet::new();
        for p in PATH_WORDLIST {
            assert!(p.starts_with('/'), "절대경로 필요: {p}");
            assert!(seen.insert(p), "중복: {p}");
        }
    }

    #[test]
    fn digest_caps_and_orders() {
        let rep = ProbeReport {
            target: "t".into(),
            started_at: "".into(),
            duration_ms: 1000,
            probes_run: 10,
            authenticated: false,
            verified: 0,
            danger: false,
            hits: vec![
                hit("a", Severity::Info, "u".into(), "low-prio".into(), "".into(), "".into(), "".into(), None),
                hit("b", Severity::High, "u".into(), "hi-prio".into(), "".into(), "".into(), "".into(), None),
            ],
        };
        let mut rep = rep;
        rep.hits.sort_by(|a, b| sev_rank(&a.severity).cmp(&sev_rank(&b.severity)));
        for (i, h) in rep.hits.iter_mut().enumerate() {
            h.id = format!("P-{:03}", i + 1);
        }
        let d = evidence_digest(&rep, 200);
        assert!(d.find("hi-prio").unwrap() < d.find("low-prio").unwrap_or(usize::MAX), "{d}");
        assert!(d.contains("외 ") || d.contains("low-prio"), "{d}");
        let line = sweep_summary_line(&rep);
        assert!(line.contains("프로브 10개") && line.contains("높음 1"), "{line}");
    }

    // ── 실전 스윕: 로컬 스텁(HTTP) 대상으로 전체 파이프라인 실행 ──────────────

    fn stub_body(method: &str, path: &str, headers: &[(String, String)], req_body: &str) -> (u16, Vec<(String, String)>, String) {
        let origin = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("origin")).map(|(_, v)| v.clone());
        let cookie = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("cookie")).map(|(_, v)| v.clone()).unwrap_or_default();
        let json = |code: u16, body: &str| {
            let mut h: Vec<(String, String)> = vec![("Content-Type".into(), "text/html".into()), ("Server".into(), "Stub/9.9".into())];
            if let Some(o) = origin.clone() {
                h.push(("Access-Control-Allow-Origin".into(), o));
                h.push(("Access-Control-Allow-Credentials".into(), "true".into()));
            }
            (code, h, body.to_string())
        };
        // 취약 로그인 — SQLi 우회 성공 시 세션 발급.
        if path == "/login" && method == "POST" {
            let b = req_body.to_uppercase();
            if (b.contains("%27") || b.contains('\'')) && b.contains("OR") {
                return (302, vec![("Location".into(), "/dashboard".into()), ("Set-Cookie".into(), "sess=vuln123; Path=/".into())], "welcome".into());
            }
            return json(200, "<html><body><form action=\"/login\" method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pw\"></form><p>Invalid credentials</p></body></html>");
        }
        if path == "/" || path.starts_with("/?") {
            if let Some(q) = path.split('?').nth(1) {
                // 오픈 리다이렉트.
                if q.contains("probe.test") {
                    return (302, vec![("Location".into(), EVIL_URL.into())], String::new());
                }
                // SQL 오류.
                if q.contains("%27") || q.contains("%22") || q.contains('\'') || q.contains('"') {
                    return json(200, "DB failed: You have an error in your SQL syntax near 'rc7x0''");
                }
                // 반사 (디코드 후 그대로 — 마커 매칭용).
                if q.contains("rc7x") {
                    let val = q.split('&').next_back().unwrap_or("").split('=').nth(1).unwrap_or("");
                    let decoded = pct_decode(val);
                    return json(200, &format!("<html><body>hi {decoded}<script>var m='{decoded}';</script></body></html>"));
                }
            }
            return json(200, "<html><body><a href=\"/s?x=1\">s</a><form action=\"/login\" method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pw\"></form><script src=\"/a.js\"></script></body></html>");
        }
        match path.split('?').next().unwrap_or(path) {
            "/a.js" => json(200, "var k=\"AKIAIOSFODNN7EXAMPLE\"; fetch(\"/api/u?uid=1\");"),
            // 쿠키 게이트 — 세션 쿠키가 있어야 200.
            "/.env" => if cookie.contains("SESS=ok") {
                json(200, "APP_KEY=base64:abc\nDB_PASSWORD=hunter2-secret\nDEBUG=true\n")
            } else {
                (403, vec![], "denied".into())
            },
            "/.git/HEAD" => json(200, "ref: refs/heads/main\n"),
            "/admin" => json(200, "<h1>admin</h1>"),
            p if p.starts_with("/s") => json(200, "<p>s</p>"),
            _ => (404, vec![], "nf".into()),
        }
    }

    fn pct_decode(s: &str) -> String {
        let mut o = Vec::new();
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    o.push(v);
                    i += 3;
                    continue;
                }
            }
            o.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&o).into_owned()
    }

    /// 스텁 서버 시작 — 포트 반환. 무한 루프(테스트 종료 시 함께 종료).
    fn start_stub() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut conn = conn;
                    let mut raw: Vec<u8> = Vec::new();
                    let mut buf = [0u8; 8192];
                    // 헤더 + (POST면) 본문까지 수신.
                    loop {
                        let Ok(n) = conn.read(&mut buf) else { return };
                        if n == 0 {
                            break;
                        }
                        raw.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&raw).into_owned();
                        if let Some(hend) = text.find("\r\n\r\n") {
                            let cl = text[..hend]
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        v.trim().parse::<usize>().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            if text.len() >= hend + 4 + cl {
                                break;
                            }
                        }
                        if raw.len() > 65536 {
                            break;
                        }
                    }
                    let req = String::from_utf8_lossy(&raw).into_owned();
                    let (head_part, req_body) = match req.find("\r\n\r\n") {
                        Some(p) => (req[..p].to_string(), req[p + 4..].to_string()),
                        None => (req.clone(), String::new()),
                    };
                    let mut lines = head_part.lines();
                    let head = lines.next().unwrap_or("");
                    let mut parts = head.split_whitespace();
                    let method = parts.next().unwrap_or("GET").to_string();
                    let path = parts.next().unwrap_or("/").to_string();
                    let mut hs: Vec<(String, String)> = vec![];
                    for ln in lines {
                        if ln.trim().is_empty() {
                            break;
                        }
                        if let Some((k, v)) = ln.split_once(':') {
                            hs.push((k.trim().to_string(), v.trim().to_string()));
                        }
                    }
                    let (code, mut extra, body) = stub_body(&method, &path, &hs, &req_body);
                    if method == "OPTIONS" {
                        extra.push(("Allow".into(), "GET, HEAD, OPTIONS, PUT".into()));
                    }
                    if method == "TRACE" {
                        let echo = format!("TRACE {path} {req}");
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{echo}", echo.len());
                        let _ = conn.write_all(resp.as_bytes());
                        return;
                    }
                    let mut resp = format!("HTTP/1.1 {code} {}\r\n", reason(code));
                    for (k, v) in extra {
                        resp.push_str(&format!("{k}: {v}\r\n"));
                    }
                    if path == "/" || path.starts_with("/?") {
                        resp.push_str("Set-Cookie: sess=abc; Path=/\r\n");
                    }
                    resp.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()));
                    let _ = conn.write_all(resp.as_bytes());
                });
            }
        });
        // 바인드 안정화.
        std::thread::sleep(Duration::from_millis(100));
        port
    }

    fn reason(code: u16) -> &'static str {
        match code {
            200 => "OK",
            302 => "Found",
            404 => "Not Found",
            _ => "OK",
        }
    }

    #[test]
    fn login_form_parsed() {
        let html = "<form action=\"/login\" method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pw\"></form>";
        let f = parse_login_form(html, "http://t:1").unwrap();
        assert_eq!(f.action, "http://t:1/login");
        assert!(f.post && f.user_field == "user" && f.pass_field == "pw");
        // 외부 action 은 거부.
        let evil = "<form action=\"https://evil.test/x\" method=\"post\"><input name=\"u\"><input type=\"password\" name=\"p\"></form>";
        assert!(parse_login_form(evil, "http://t:1").is_none());
        // password 없는 폼은 무시.
        assert!(parse_login_form("<form><input name=\"q\"></form>", "http://t:1").is_none());
    }

    #[test]
    fn render_degrades_without_browser() {
        // 브라우저 경로 없음·실행 불가면 조용히 None (우아한 성능 저하, 환경 무관).
        assert!(render_dom_with("http://127.0.0.1:9/", &SweepConfig::default(), None).is_none());
        assert!(render_dom_with(
            "http://127.0.0.1:9/",
            &SweepConfig::default(),
            Some(std::path::PathBuf::from("/nonexistent-chrome-xyz"))
        )
        .is_none());
    }

    /// SPA 스텁 — 정적 HTML 은 빈 껍데기, 로그인 폼은 JS 로만 주입된다.
    fn start_spa_stub() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut conn = conn;
                    let mut buf = [0u8; 8192];
                    let mut raw: Vec<u8> = Vec::new();
                    loop {
                        let Ok(n) = conn.read(&mut buf) else { return };
                        if n == 0 {
                            break;
                        }
                        raw.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&raw).into_owned();
                        if text.contains("\r\n\r\n") {
                            break;
                        }
                        if raw.len() > 65536 {
                            break;
                        }
                    }
                    let req = String::from_utf8_lossy(&raw).into_owned();
                    let head = req.lines().next().unwrap_or("");
                    let mut parts = head.split_whitespace();
                    let method = parts.next().unwrap_or("GET");
                    let path = parts.next().unwrap_or("/").to_string();
                    let (code, ctype, body) = if method == "POST" && path == "/login" {
                        (200u16, "text/html", "<html><body>invalid credentials</body></html>".to_string())
                    } else if path == "/" || path.starts_with("/?") {
                        let page = "<!doctype html><html><head><meta charset=\"utf-8\"><title>spa</title></head><body><div id=\"app\"></div><script>document.getElementById('app').innerHTML='<form action=\"/login\" method=\"post\" id=\"spa-login-marker\"><input name=\"uid\"><input type=\"password\" name=\"pwd\"><button>go</button></form>';</script></body></html>";
                        (200u16, "text/html", page.to_string())
                    } else {
                        (404u16, "text/plain", "nf".to_string())
                    };
                    let resp = format!(
                        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        reason(code),
                        body.len()
                    );
                    let _ = conn.write_all(resp.as_bytes());
                });
            }
        });
        std::thread::sleep(Duration::from_millis(100));
        port
    }

    #[test]
    fn render_dom_captures_js_injected_form() {
        let bin = match find_browser() {
            Some(b) => b,
            None => {
                eprintln!("브라우저 없음 — 렌더 실측 스킵");
                return;
            }
        };
        let port = start_spa_stub();
        let url = format!("http://127.0.0.1:{port}/");
        let cfg = SweepConfig::with_defaults();
        // 1) --dump-dom 원자 검증: JS 주입 폼이 DOM 에 보여야 한다.
        let dom = render_dom_with(&url, &cfg, Some(bin)).expect("렌더 실패 — headless --dump-dom 확인 필요");
        assert!(dom.contains("spa-login-marker"), "JS 주입 폼 미포착 ({}B)", dom.len());
        // 2) 풀 스윕: 렌더 확보 힛 + 렌더된 폼에서 authform 검출.
        let rep = run_sweep_with_config("127.0.0.1", Some(port), SweepConfig::with_defaults());
        assert!(rep.hits.iter().any(|h| h.title.contains("JS 렌더 DOM 확보")), "렌더 힛 없음");
        assert!(rep.hits.iter().any(|h| h.category == "authform"), "렌더된 로그인 폼 미검출");
    }

    /// Auth 스텁 — JWT 수용 + 모드 마커(FIXMODE=1 이면 서명 강제).
    fn start_auth_stub() -> u16 {
        fn tok_valid(cookie: &str, fixed: bool) -> bool {
            let Some(tok) = cookie.split(';').find_map(|p| {
                let (n, v) = p.split_once('=')?;
                if n.trim() == "TOK" { Some(v.trim().to_string()) } else { None }
            }) else { return false };
            let mut segs = tok.split('.');
            let (h, p, s) = match (segs.next(), segs.next(), segs.next()) {
                (Some(h), Some(p), Some(s)) => (h, p, s),
                _ => return false,
            };
            // 페이로드에 jwtuser 가 있어야 유효 토큰.
            let payload_ok = pct_decode_url(p).contains("jwtuser");
            if !payload_ok {
                return false;
            }
            if !fixed {
                return true; // 취약: 서명·alg 무시
            }
            !s.is_empty() && pct_decode_url(h).contains("HS256")
        }
        fn pct_decode_url(s: &str) -> String {
            // 테스트용 간이 base64url 디코드 (ASCII 페이로드 가정).
            let mut out = Vec::new();
            let mut buf: u32 = 0;
            let mut bits = 0;
            for &c in s.as_bytes() {
                let v = match c {
                    b'A'..=b'Z' => c - b'A',
                    b'a'..=b'z' => c - b'a' + 26,
                    b'0'..=b'9' => c - b'0' + 52,
                    b'-' => 62,
                    b'_' => 63,
                    _ => continue,
                } as u32;
                buf = (buf << 6) | v;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((buf >> bits) as u8);
                    buf &= (1 << bits) - 1;
                }
            }
            String::from_utf8_lossy(&out).into_owned()
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut conn = conn;
                    let mut buf = [0u8; 8192];
                    let mut raw: Vec<u8> = Vec::new();
                    loop {
                        let Ok(n) = conn.read(&mut buf) else { return };
                        if n == 0 {
                            break;
                        }
                        raw.extend_from_slice(&buf[..n]);
                        if String::from_utf8_lossy(&raw).contains("\r\n\r\n") {
                            break;
                        }
                        if raw.len() > 65536 {
                            break;
                        }
                    }
                    let req = String::from_utf8_lossy(&raw).into_owned();
                    let head = req.lines().next().unwrap_or("");
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let cookie = req
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("cookie") { Some(v.trim().to_string()) } else { None }
                        })
                        .unwrap_or_default();
                    let fixed = cookie.contains("FIXMODE=1");
                    let authed = tok_valid(&cookie, fixed);
                    let (code, ctype, body) = match path.split('?').next().unwrap_or(&path) {
                        "/" => (
                            200u16,
                            "text/html",
                            if authed {
                                "<html><body><h1>welcome jwtuser dashboard</h1><p>orders: 3, balance: 100</p></body></html>".to_string()
                            } else {
                                "<html><body><h1>login page</h1><form><input name=\"u\"><input type=\"password\" name=\"p\"></form></body></html>".to_string()
                            },
                        ),
                        "/api/me" => if authed {
                            (200u16, "application/json", r#"{"user":"jwtuser","email":"u@example.com"}"#.to_string())
                        } else {
                            (401u16, "application/json", r#"{"error":"unauthorized"}"#.to_string())
                        },
                        "/api/orders" => (200u16, "application/json", r#"[{"id":1,"user_id":7,"total":100}]"#.to_string()),
                        _ => (404u16, "text/plain", "nf".to_string()),
                    };
                    let resp = format!(
                        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        reason(code),
                        body.len()
                    );
                    let _ = conn.write_all(resp.as_bytes());
                });
            }
        });
        std::thread::sleep(Duration::from_millis(100));
        port
    }

    fn test_jwt() -> String {
        let h = b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let p = b64url_encode(br#"{"sub":"u1","name":"jwtuser","exp":9999999999}"#);
        format!("{h}.{p}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    }

    #[test]
    fn b64url_roundtrip() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar", r#"{"alg":"HS256"}"#] {
            let enc = b64url_encode(s.as_bytes());
            assert!(!enc.contains(['+', '/', '=']), "{enc}");
            assert_eq!(b64url_decode(&enc).unwrap(), s.as_bytes());
        }
        assert_eq!(b64url_decode("eyJhbGciOiJIUzI1NiJ9").unwrap(), br#"{"alg":"HS256"}"#);
        assert!(b64url_decode("***").is_none());
    }

    #[test]
    fn jwt_cookie_parsed() {
        let jwt = test_jwt();
        let j = find_jwt_in_cookie(&format!("other=1; TOK={jwt}; Secure")).unwrap();
        assert_eq!(j.name, "TOK");
        assert_eq!(j.alg, "HS256");
        assert!(j.has_exp);
        assert!(find_jwt_in_cookie("SESS=ok; a=b").is_none());
        assert!(find_jwt_in_cookie("TOK=not.a.jwt.at.all.x").is_none());
    }

    #[test]
    fn jwt_leak_scan_masks_value() {
        let jwt = test_jwt();
        let hits = scan_jwt_leak(&format!("<html><script>var t='{jwt}';</script></html>"), "http://t/");
        assert_eq!(hits.len(), 1);
        assert!(!hits[0].evidence.contains(&jwt) && hits[0].evidence.contains('…'));
        assert!(scan_jwt_leak("<html>no tokens here. just. dots.</html>", "http://t/").is_empty());
    }

    #[test]
    fn jwt_confusion_catches_missing_signature() {
        let port = start_auth_stub();
        let cfg = SweepConfig {
            threads: 8, rps: 500, req_timeout: Duration::from_secs(5),
            sweep_timeout: Duration::from_secs(60), cookie: Some(format!("TOK={}", test_jwt())),
            danger: false,
            feedback: None,
        };
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        assert!(
            rep.hits.iter().any(|h| h.category == "auth-bypass" && h.severity == "high" && h.title.contains("서명 미검증")),
            "JWT confusion 미검출: {:?}",
            rep.hits.iter().map(|h| format!("{}:{} {}", h.category, h.severity, h.title)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn jwt_confusion_confirms_signature_enforced() {
        let port = start_auth_stub();
        let cfg = SweepConfig {
            threads: 8, rps: 500, req_timeout: Duration::from_secs(5),
            sweep_timeout: Duration::from_secs(60),
            cookie: Some(format!("FIXMODE=1; TOK={}", test_jwt())),
            danger: false,
            feedback: None,
        };
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        assert!(
            rep.hits.iter().any(|h| h.category == "auth-bypass" && h.title.contains("서명 검증됨")),
            "서명 강제 확인 힛 없음: {:?}",
            rep.hits.iter().map(|h| format!("{}:{} {}", h.category, h.severity, h.title)).collect::<Vec<_>>()
        );
        assert!(!rep.hits.iter().any(|h| h.category == "auth-bypass" && h.severity == "high" && h.title.contains("서명 미검증")));
    }

    #[test]
    fn auth_differential_flags_open_and_silent_gated() {
        let port = start_auth_stub();
        // 인증 스윕: /api/orders 는 무인증 동일 응답(high), /api/me 는 게이트(무음).
        let cfg = SweepConfig {
            threads: 8, rps: 500, req_timeout: Duration::from_secs(5),
            sweep_timeout: Duration::from_secs(60), cookie: Some(format!("TOK={}", test_jwt())),
            danger: false,
            feedback: None,
        };
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        assert!(rep.hits.iter().any(|h| h.category == "auth-bypass" && h.severity == "high" && h.target.contains("/api/orders")),
            "/api/orders 차분 미검출");
        assert!(!rep.hits.iter().any(|h| h.target.contains("/api/me")), "/api/me 는 게이트돼 무음이어야 함");
        // 무쿠키 스윕: /api/orders 200 → 노출 medium (/api/me 401 무음).
        let cfg2 = SweepConfig {
            threads: 8, rps: 500, req_timeout: Duration::from_secs(5),
            sweep_timeout: Duration::from_secs(60), cookie: None,
            danger: false,
            feedback: None,
        };
        let rep2 = run_sweep_with_config("127.0.0.1", Some(port), cfg2);
        assert!(rep2.hits.iter().any(|h| h.category == "auth-bypass" && h.severity == "medium" && h.target.contains("/api/orders")),
            "무인증 노출 미검출");
    }

    #[test]
    fn write_surface_scan_shapes() {
        // 업로드 폼 — action 해결 + 필드명 + 무발송 명시.
        let html = "<form action=\"/upload\" method=\"post\" enctype=\"multipart/form-data\"><input type=\"file\" name=\"avatar\"><input type=\"text\" name=\"nick\"></form>";
        let hits = scan_write_surface(html, "http://t:1");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].category, "upload-surface");
        assert_eq!(hits[0].target, "http://t:1/upload");
        assert!(hits[0].detail.contains("avatar") && hits[0].detail.contains("미수행"));
        // _method 스푸핑 폼.
        let spoof = "<form action=\"/posts/1\" method=\"post\"><input type=\"hidden\" name=\"_method\" value=\"PUT\"></form>";
        let hits2 = scan_write_surface(spoof, "http://t:1");
        assert!(hits2.iter().any(|h| h.category == "method-override" && h.severity == "low"));
        // 일반 로그인 폼은 무음.
        assert!(scan_write_surface("<form action=\"/login\"><input name=\"u\"><input type=\"password\" name=\"p\"></form>", "http://t:1").is_empty());
    }

    /// Danger 스텁 — 기본자격 수용(admin/admin1234) + DLOCK 모드(잠금·5번째 유효) +
    /// IDOR 인접 응답 + PUT/GET/DELETE 라운드트립.
    fn start_danger_stub() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut conn = conn;
                    let mut buf = [0u8; 8192];
                    let mut raw: Vec<u8> = Vec::new();
                    loop {
                        let Ok(n) = conn.read(&mut buf) else { return };
                        if n == 0 {
                            break;
                        }
                        raw.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&raw).into_owned();
                        if let Some(hend) = text.find("\r\n\r\n") {
                            let cl = text[..hend]
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        v.trim().parse::<usize>().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            if text.len() >= hend + 4 + cl {
                                break;
                            }
                        }
                        if raw.len() > 65536 {
                            break;
                        }
                    }
                    let req = String::from_utf8_lossy(&raw).into_owned();
                    let (head_part, req_body) = match req.find("\r\n\r\n") {
                        Some(p) => (req[..p].to_string(), req[p + 4..].to_string()),
                        None => (req.clone(), String::new()),
                    };
                    let head = head_part.lines().next().unwrap_or("");
                    let mut parts = head.split_whitespace();
                    let method = parts.next().unwrap_or("GET");
                    let path = parts.next().unwrap_or("/").to_string();
                    let cookie = head_part
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("cookie") { Some(v.trim().to_string()) } else { None }
                        })
                        .unwrap_or_default();
                    let dlock = cookie.contains("DLOCK=1");
                    let invalid_page = "<html><body><p>Invalid credentials</p><form action=\"/login\" method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pw\"></form></body></html>";
                    let (code, mut extra, body): (u16, Vec<(String, String)>, String) =
                        if method == "POST" && path == "/login" {
                            let admin_ok = req_body.contains("user=admin") && req_body.contains("pw=admin1234");
                            let root_try = req_body.contains("user=root");
                            let test_ok = req_body.contains("user=test") && req_body.contains("pw=test");
                            if admin_ok && !dlock {
                                (302, vec![("Location".into(), "/dashboard".into()), ("Set-Cookie".into(), "sess=danger1; Path=/".into())], "welcome".into())
                            } else if dlock && root_try {
                                (429, vec![], "too many attempts, locked".into())
                            } else if dlock && test_ok {
                                (302, vec![("Location".into(), "/dashboard".into()), ("Set-Cookie".into(), "sess=danger5; Path=/".into())], "welcome".into())
                            } else {
                                (200, vec![], invalid_page.to_string())
                            }
                        } else if method == "PUT" && path.starts_with("/rc7x-probe-") {
                            (201, vec![], "created".into())
                        } else if method == "GET" && path.starts_with("/rc7x-probe-") {
                            (200, vec![], "rc7x-consented-write-probe-ok".into())
                        } else if method == "DELETE" && path.starts_with("/rc7x-probe-") {
                            (200, vec![], "deleted".into())
                        } else if path == "/" || path.starts_with("/?") {
                            let page = "<html><body><a href=\"/api/orders/100\">orders</a><a href=\"/api/me/5\">me</a><form action=\"/login\" method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pw\"></form></body></html>";
                            (200, vec![], page.to_string())
                        } else if path.starts_with("/api/orders/") {
                            let id = path.rsplit('/').next().unwrap_or("");
                            match id {
                                "100" => (200, vec![], r#"{"id":100,"user_id":7,"email":"alice@example.com","total":120}"#.into()),
                                "98" | "99" | "101" | "102" => (200, vec![], format!(r#"{{"id":{id},"user_id":9,"email":"bob{id}@example.com","total":55}}"#)),
                                _ => (404, vec![], "nf".into()),
                            }
                        } else if path.starts_with("/api/me/") {
                            if path == "/api/me/5" {
                                (200, vec![], r#"{"id":5,"self":true}"#.into())
                            } else {
                                (403, vec![], "forbidden".into())
                            }
                        } else {
                            (404, vec![], "nf".into())
                        };
                    if method == "OPTIONS" {
                        extra.push(("Allow".into(), "GET, HEAD, OPTIONS".into()));
                    }
                    let mut resp = format!("HTTP/1.1 {code} {}\r\n", reason(code));
                    for (k, v) in extra {
                        resp.push_str(&format!("{k}: {v}\r\n"));
                    }
                    resp.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()));
                    let _ = conn.write_all(resp.as_bytes());
                });
            }
        });
        std::thread::sleep(Duration::from_millis(100));
        port
    }

    fn danger_cfg(cookie: Option<&str>) -> SweepConfig {
        SweepConfig {
            threads: 8, rps: 500, req_timeout: Duration::from_secs(5),
            sweep_timeout: Duration::from_secs(60),
            cookie: cookie.map(|c| c.to_string()),
            danger: true,
            feedback: None,
        }
    }

    #[test]
    fn redact_pii_masks_email_and_digits() {
        let r = redact_pii(r#"{"id":100,"email":"alice@example.com","phone":"010-1234-5678"}"#);
        assert!(r.contains("[email]") && r.contains("[digits]"), "{r}");
        assert!(!r.contains("alice") && !r.contains("1234"));
        assert!(r.contains("100"), "짧은 ID 는 보존: {r}");
    }

    #[test]
    fn id_endpoints_extracted() {
        let eps = extract_id_endpoints(r#"<a href="/api/orders/100">x</a> fetch('/api/me/5?full=1') <img src="/img/logo.png">"#);
        assert_eq!(eps, vec![("/api/orders".to_string(), 100), ("/api/me".to_string(), 5)]);
        assert!(extract_id_endpoints("<a href=\"/about\">x</a>").is_empty());
    }

    #[test]
    fn danger_creds_catches_default() {
        let port = start_danger_stub();
        let cfg = danger_cfg(None);
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        let h = rep.hits.iter().find(|h| h.category == "danger-creds" && h.severity == "critical");
        assert!(h.is_some(), "기본자격 성공 미검출");
        let h = h.unwrap();
        assert!(h.title.contains("admin / ***") && !h.detail.contains("admin1234") && !h.request.contains("admin1234"),
            "비밀번호 마스킹 실패: {h:?}");
    }

    #[test]
    fn danger_creds_stops_on_lockout() {
        let port = start_danger_stub();
        // DLOCK: root→429, 5번째(test/test)는 유효하지만 도달 금지.
        let cfg = danger_cfg(Some("DLOCK=1"));
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        assert!(rep.hits.iter().any(|h| h.category == "danger-creds" && h.title.contains("잠금")),
            "잠금 중단 힛 없음");
        assert!(!rep.hits.iter().any(|h| h.category == "danger-creds" && h.severity == "critical"),
            "잠금 후에도 계속 시도함 (5번째 유효 자격에 도달했으면 안 됨)");
    }

    #[test]
    fn danger_gated_without_consent() {
        let port = start_danger_stub();
        let cfg = SweepConfig {
            threads: 8, rps: 500, req_timeout: Duration::from_secs(5),
            sweep_timeout: Duration::from_secs(60), cookie: Some("SESS=x".into()), danger: false,
            feedback: None,
        };
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        assert!(!rep.danger);
        assert!(!rep.hits.iter().any(|h| h.category.starts_with("danger-")),
            "미동의 파괴적 프로브 실행됨: {:?}",
            rep.hits.iter().map(|h| h.category.clone()).collect::<Vec<_>>());
    }

    #[test]
    fn danger_idor_confirms_and_masks() {
        let port = start_danger_stub();
        let cfg = danger_cfg(Some("SESS=idortest"));
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        let h = rep.hits.iter().find(|h| h.category == "danger-idor" && h.severity == "high");
        assert!(h.is_some(), "IDOR 미확정");
        let h = h.unwrap();
        assert!(h.target.contains("/api/orders/98"), "첫 인접(100-2) 기대: {}", h.target);
        assert!(h.evidence.contains("[email]") && !h.evidence.contains("bob98@example.com"),
            "증거 마스킹 실패: {}", h.evidence);
        assert!(!rep.hits.iter().any(|h| h.target.contains("/api/me/")), "/api/me 인접은 403 — 무음");
    }

    #[test]
    fn danger_write_roundtrip_cleaned() {
        let port = start_danger_stub();
        let cfg = danger_cfg(None);
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        let h = rep.hits.iter().find(|h| h.category == "danger-write");
        assert!(h.is_some(), "쓰기 검증 힛 없음");
        let h = h.unwrap();
        assert_eq!(h.severity, "high");
        assert!(h.detail.contains("정리됨"), "정리 보고 누락: {}", h.detail);
    }

    #[test]
    fn danger_write_rejected_on_shared_stub() {
        let port = start_stub();
        let cfg = danger_cfg(None);
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        assert!(rep.hits.iter().any(|h| h.category == "danger-write" && h.title.contains("거부")),
            "쓰기 거부 info 없음");
        assert!(rep.hits.iter().any(|h| h.category == "danger-creds" && h.title.contains("5종 거부")),
            "기본자격 거부 info 없음");
    }

    #[test]
    fn feedback_reports_progress_and_phase() {
        use std::sync::Arc;
        let port = start_stub();
        let fb = Arc::new(SweepFeedback::default());
        let mut cfg = SweepConfig::with_defaults();
        cfg.cookie = None;
        cfg.feedback = Some(fb.clone());
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        assert!(fb.total.load(Ordering::Relaxed) > 0, "total 미설정");
        assert_eq!(fb.done.load(Ordering::Relaxed), rep.probes_run, "done 불일치");
        assert_eq!(fb.phase_label(), "완료");
    }

    #[test]
    fn feedback_cancel_aborts_early() {
        use std::sync::Arc;
        let port = start_stub();
        // 시작 전 취소 — base 정찰 후 즉시 중단돼야 함.
        let fb = Arc::new(SweepFeedback::default());
        fb.cancel.store(true, Ordering::Relaxed);
        let mut cfg = SweepConfig::with_defaults();
        cfg.feedback = Some(fb.clone());
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        // base 정찰 + 워커당 1개씩 빠져나간 것만 허용 (정상 수백 대비 1/10 이하).
        assert!(rep.probes_run < 40, "중단 안 됨: {} 프로브", rep.probes_run);
        assert_eq!(fb.phase_label(), "중단됨");
        // 중간 취소 — 별도 스레드에서 0.5초 후 중단.
        let fb2 = Arc::new(SweepFeedback::default());
        let fb2c = fb2.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            fb2c.cancel.store(true, Ordering::Relaxed);
        });
        let mut cfg2 = SweepConfig::with_defaults();
        cfg2.feedback = Some(fb2.clone());
        let rep2 = run_sweep_with_config("127.0.0.1", Some(port), cfg2);
        assert!(rep2.probes_run < 150, "중간 중단 안 됨: {} 프로브", rep2.probes_run);
    }

    #[test]
    fn live_sweep_with_cookie_unlocks() {
        let port = start_stub();
        // 쿠키 없이: /.env 는 403 → high 발견 없음.
        let cfg = SweepConfig { threads: 16, rps: 500, req_timeout: Duration::from_secs(5), sweep_timeout: Duration::from_secs(60), cookie: None, danger: false, feedback: None };
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        assert!(!rep.authenticated);
        assert!(!rep.hits.iter().any(|h| h.category == "paths" && h.severity == "high" && h.target.contains("/.env")), "쿠키 없이 .env high 면 안 됨");
        // 쿠키 첨부: 200 → high 발견 + authenticated.
        let cfg2 = SweepConfig { threads: 16, rps: 500, req_timeout: Duration::from_secs(5), sweep_timeout: Duration::from_secs(60), cookie: Some("SESS=ok".into()), danger: false, feedback: None };
        let rep2 = run_sweep_with_config("127.0.0.1", Some(port), cfg2);
        assert!(rep2.authenticated);
        assert!(rep2.hits.iter().any(|h| h.category == "paths" && h.severity == "high" && h.target.contains("/.env")), "쿠키로 .env high 검출 필요");
    }

    #[test]
    fn live_sweep_against_stub() {
        let port = start_stub();
        let cfg = SweepConfig { threads: 16, rps: 500, req_timeout: Duration::from_secs(5), sweep_timeout: Duration::from_secs(60), cookie: None, danger: false, feedback: None };
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        // 수백 프로브 실행 (초인적 탐색량).
        assert!(rep.probes_run >= 100, "프로브 부족: {}", rep.probes_run);
        let cats: Vec<String> = rep.hits.iter().map(|h| format!("{}:{}", h.category, h.severity)).collect();
        let has = |c: &str| cats.iter().any(|x| x.starts_with(c));
        for must in ["paths:high", "secret:high", "headers:", "cookies:", "methods:", "cors:", "sqli-signal:high", "xss-reflect:", "openredirect:high", "authform:", "auth-inject:high", "auth-bypass:", "verify-"] {
            assert!(has(must), "미검출: {must} / {cats:?}");
        }
        // 로그인 우회 확정 + P1 재확인.
        assert!(rep.hits.iter().any(|h| h.title.contains("SQLi 인증 우회 가능")), "우회 미검출: {cats:?}");
        assert!(rep.verified >= 2, "P1 검증 부족: {}", rep.verified);
        assert!(!rep.authenticated);
        // ID 부여 + 심각도순.
        assert!(rep.hits.iter().all(|h| h.id.starts_with("P-")), "ID 누락");
        let ranks: Vec<u8> = rep.hits.iter().map(|h| sev_rank(&h.severity)).collect();
        let mut sorted = ranks.clone();
        sorted.sort();
        assert_eq!(ranks, sorted, "심각도순 정렬 필요");
        // 다이제스트 자족성.
        let d = evidence_digest(&rep, 6000);
        assert!(d.contains("[P-001]") && d.contains("127.0.0.1"), "{d}");
    }
}



