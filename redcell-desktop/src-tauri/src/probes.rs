//! P0 결정적 스윕 — LLM 분석 전에 실행하는 읽기 전용 대량 프로브.
//!
//! 시니어 해커가 손으로는 엄두도 못 내는 "수백 개 경로·수십 종 페이로드 변형·
//! 헤더/쿠키/CORS/TLS 전수 점검"을 수십 초 안에 확정한다. 결과는 증거 ID(`[P-###]`)
//! 와 함께 저장되고, LLM 워커·collector 는 이 증거 위에서 분석가 역할을 한다.
//!
//! 안전 규칙: 기본은 GET/HEAD/OPTIONS + 무해 쿼리 마커 + 로그인 폼 POST(존재하지
//! 않는 계정·고정 무해 페이로드)만 사용, 단일 호스트(외부 추적 금지), RPS 상한·
//! 요청 타임아웃·본문 크기 상한·전체 타임아웃. PUT/DELETE 정리·기본자격·IDOR 인접
//! 쓰기 3종(danger-*)은 명시 동의 시에만 발송한다.

use std::collections::VecDeque;
use std::io::Read;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const PROBE_THREADS: usize = 24;
pub const PROBE_RPS: u32 = 30;
pub const REQ_TIMEOUT: Duration = Duration::from_secs(8);
pub const SWEEP_TIMEOUT: Duration = Duration::from_secs(180);
pub const BODY_CAP: u64 = 262_144;
pub const JS_BODY_CAP: u64 = 1_048_576;
pub const JS_FETCH_CAP: usize = 10;
pub const PARAM_CAP: usize = 20;
/// OpenAPI取り込み 상한 — 오퍼레이션 파싱·GET 투입·표면 기록·스펙 크기.
const API_OP_CAP: usize = 32;
const API_GET_CAP: usize = 20;
const API_HIT_CAP: usize = 12;
const API_QUERY_CAP: usize = 8;
const API_SPEC_CAP: u64 = 2_097_152;
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
    "/v1/models", "/api/tags", "/api/generate", "/api/chat", "/v1/embeddings",
    "/v1/chat/completions", "/api/show", "/api/ps",
    "/script", "/api/json", "/api/python", "/config.xml",
    "/elmah.axd", "/trace.axd", "/server-error",
    "/%2e%2e/%2e%2e/etc/passwd", "/..;/", "/.\\./.\\./windows/win.ini",
    "/favicon.ico",
    "/saml/metadata", "/saml2/metadata", "/adfs/ls/IdpInitiatedSignOn",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
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

// ── 2차 프로브 상수 (GET-only 이식 벡터) ───────────────────────────────────────
/// SSTI 산술 판정 — 보낸 적 없는 곱셈 결과 출현 = 서버 평가 확정.
const SSTI_A: i64 = 7919;
const SSTI_B: i64 = 7331;
const SSTI_EXPECT: &str = "58054189"; // 7919*7331
/// CMDI in-band 페이로드 — 무해 정보 명령 (`id`·`ver`) 출력만 관찰 (파괴·네트워크·파일변경 없음).
const CMDI_PAYLOADS: &[&str] = &[";id", "&ver"];

/// CMDI 출력 판정 — `id`/`ver` 무해 명령의 출력 시그니처.
/// `uid=숫자(이름) gid=숫자(` (Unix) 또는 Windows 버전 배너. 정규식 없이 수작업 스캔.
fn cmdi_output_kind(body: &str) -> Option<&'static str> {
    if has_unix_id_output(body) {
        return Some("unix `id`");
    }
    let low = body.to_lowercase();
    if low.contains("microsoft windows [version") || low.contains("windows ip configuration") {
        return Some("windows `ver`");
    }
    None
}

fn has_unix_id_output(body: &str) -> bool {
    let b = body.as_bytes();
    let mut i = 0usize;
    while i + 4 <= b.len() {
        if b[i..i + 4] == *b"uid=" {
            let mut j = i + 4;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            // `uid=숫자(` — j는 ASCII 경계라 슬라이스 안전.
            if j > i + 4 && j < b.len() && b[j] == b'(' {
                let win: String = body[j..].chars().take(200).collect();
                if let Some(cp) = win.find(')') {
                    let rest = &win[cp..];
                    if let Some(g) = rest.find("gid=") {
                        let after = &rest[g + 4..];
                        let digits = after.chars().take_while(|c| c.is_ascii_digit()).count();
                        if digits > 0 && after.chars().nth(digits) == Some('(') {
                            return true;
                        }
                    }
                }
            }
        }
        i += 1;
    }
    false
}
/// SSRF 판정 — 요청에 없던 클라우드 메타데이터 시그니처 출현 = 서버측 취득.
const SSRF_URL: &str = "http://169.254.169.254/latest/meta-data/";
const SSRF_SIGS: &[&str] = &["ami-id", "ami-launch-index", "instance-id", "instance-type", "local-hostname", "public-hostname", "iam/security-credentials"];
const SSRF_PARAMS: &[&str] = &[
    "url", "uri", "link", "dest", "destination", "target", "redirect", "redirect_url",
    "return", "returnurl", "next", "continue", "goto", "path", "file", "src", "image",
    "img", "avatar", "logo", "webhook", "callback", "feed", "rss", "proxy",
];
const LDAP_XPATH_FPS: &[&str] = &[
    "invalid dn syntax", "ldap_search", "supplied argument is not a valid ldap",
    "ldap error", "xmlpath", "xpath syntax error", "invalid xpath expression",
    "domxpath", "simplexml", "msxml", "javax.xml.xpath",
];
const NOSQL_FPS: &[&str] = &[
    "mongoerror", "mongodb", "$where", "unknown operator", "badvalue",
    "not authorized on", "mongos", "bson",
];
const CRLF_MARKER: &str = "rc7crlf0";
const HPP_A: &str = "rc7hppA0";
const HPP_B: &str = "rc7hppB0";
/// 2차 프로브 잡 상한 (스윕 팽창 방지).
const CRLF_CAP: usize = 8;
const HPP_CAP: usize = 10;
const NOSQL_CAP: usize = 10;
const SSRF_CAP: usize = 8;
/// 역직렬화 blob 시그니처 (완전 오프라인 관측).
const DESER_SIGS: &[(&str, &str)] = &[
    ("rO0AB", "Java 직렬화 (rO0)"),
    ("O:8:", "PHP serialize (O:)"),
    ("a:3:{", "PHP serialize 배열"),
    ("__VIEWSTATE", "ASP.NET ViewState"),
    ("YTozOntzOj", "base64 PHP serialize"),
];
const TABNAB_REL: &[&str] = &["noopener", "noreferrer"];

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
    /// 위험 검사 동의 — 모달 명시 동의 시에만 true. 기본 false (fail-closed).
    /// true 일 때만 기본자격·IDOR 인접·BOLA 파라미터·쓰기검증 프로브가 동작한다.
    pub danger: bool,
    /// 진행 피드백 — TUI 폴링용 (None 이면 미사용).
    pub feedback: Option<std::sync::Arc<SweepFeedback>>,
    /// 게이트 폼 로그인 — 성공 시 세션 쿠키를 스윕 전체에 적용.
    pub login: Option<LoginConfig>,
    /// 인증 후 크롤 — 동일 호스트 bounded BFS 수집.
    pub crawl: Option<CrawlConfig>,
    /// OOB 콜백 — 블라인드 SSRF 탐지 (명시 지정 시에만 수신기 기동).
    pub oob: Option<OobConfig>,
    /// OpenAPI取り込み — 명시 지정 시에만 스펙을 읽어 GET 표면을 프로브에 투입.
    pub openapi: Option<OpenApiConfig>,
    /// P1 검증 예산 — verify 요청 상한 (0이면 스킵, 기본 96).
    pub p1_budget: usize,
    /// 브라우저 미사용 — true 면 CDP·dump-dom 없이 정적 파싱만 (무크롬 CI·결정적 스캔).
    pub no_browser: bool,
}

/// 게이트 폼 로그인 설정 — CI 시크릿에서 주입 (argv 노출 금지).
#[derive(Debug, Clone)]
pub struct LoginConfig {
    pub username: String,
    pub password: String,
    /// 로그인 폼 URL (None 이면 DOM→/login 폴백 자동 탐색).
    pub login_url: Option<String>,
}

/// 크롤 설정 — GET 전용·동일 호스트·파괴 경로 제외.
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    /// 최대 수집 페이지 (루트 포함).
    pub max_pages: usize,
    /// 최대 깊이 (루트=0).
    pub max_depth: u8,
}

/// OpenAPI取り込み 설정 — JSON·YAML 스펙에서 GET 오퍼레이션을 추출해 프로브 표면으로 쓴다.
#[derive(Debug, Clone)]
pub struct OpenApiConfig {
    /// 스펙 소스 — 동일 호스트 http(s) URL 또는 로컬 스펙 파일 경로.
    pub source: String,
}

/// OOB 콜백 설정 — `bind` 로 수신하고 `base` 를 덫 URL 로 뿌린다.
/// 대상에서 `base` 로 닿아야 하므로, 원격 대상이면 도달 가능한 주소·포트를 지정한다.
#[derive(Debug, Clone)]
pub struct OobConfig {
    /// 수신 바인드 (예: `127.0.0.1:0`, 원격 대상이면 `0.0.0.0:8765`).
    pub bind: String,
    /// 덫 URL 베이스 (예: `http://127.0.0.1:8765/oob/`) — 대상에서 도달 가능해야 한다.
    pub base: String,
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
            login: None,
            crawl: None,
            oob: None,
            openapi: None,
            p1_budget: 96,
            no_browser: false,
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

/// 인코딩 순회(%2e) 원시 전송 — ureq/url 크레이트가 %2e 를 `..` 로 정규화해버려
/// 인코딩 순회 프로브가 무력화되므로, http 대상은 TCP 로 직접 쏜다.
/// https 는 TLS 직접 구현 없이 불가 → Err (호출자가 미검증 info 로 기록).
fn fetch_raw_http(url: &str, headers: &[(&str, &str)], cap: u64, timeout: Duration) -> Result<Resp, String> {
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;
    let rest = url.strip_prefix("http://").ok_or("raw 전송은 http 전용")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if hostport.contains('@') || path.bytes().any(|b| b == b'\r' || b == b'\n') {
        return Err("raw 전송 불가 문자".into());
    }
    let addr = if hostport.contains(':') { hostport.to_string() } else { format!("{hostport}:80") };
    let sock = addr.to_socket_addrs().map_err(|e| format!("DNS 실패: {e}"))?.next().ok_or("주소 없음")?;
    let mut stream = std::net::TcpStream::connect_timeout(&sock, timeout).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nUser-Agent: {UA}\r\nConnection: close\r\n");
    for (k, v) in headers {
        if k.bytes().any(|b| b == b'\r' || b == b'\n') || v.bytes().any(|b| b == b'\r' || b == b'\n') {
            continue;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    stream.take(cap + 65536).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    parse_raw_response(&String::from_utf8_lossy(&buf), cap)
}

/// 원시 응답 파싱 — 상태행 + 헤더 + 본문 (http/TLS 공용).
fn parse_raw_response(text: &str, cap: u64) -> Result<Resp, String> {
    let (head, body) = match text.find("\r\n\r\n") {
        Some(p) => (&text[..p], &text[p + 4..]),
        None => return Err("raw 응답 파싱 실패".into()),
    };
    let status: u16 = head
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .parse()
        .map_err(|_| "raw 상태 파싱 실패".to_string())?;
    let mut hs = Vec::new();
    for l in head.lines().skip(1) {
        if let Some((k, v)) = l.split_once(':') {
            hs.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(Resp { status, headers: hs, body: safe_slice(body, 0, cap as usize).to_string() })
}

/// Mozilla 루트 저장소 (지연 1회 구축).
fn mozilla_roots() -> &'static rustls::RootCertStore {
    static ROOTS: std::sync::OnceLock<rustls::RootCertStore> = std::sync::OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
        }));
        roots
    })
}

/// HTTPS 원시 전송 — rustls 직접 스트림 (ureq %2e 정규화 우회).
/// 인증서 체인은 Mozilla 루트로 검증한다 (검증 생략 없음).
fn fetch_raw_tls(url: &str, headers: &[(&str, &str)], cap: u64, timeout: Duration) -> Result<Resp, String> {
    fetch_raw_tls_with_roots(url, headers, cap, timeout, mozilla_roots())
}

fn fetch_raw_tls_with_roots(
    url: &str,
    headers: &[(&str, &str)],
    cap: u64,
    timeout: Duration,
    roots: &rustls::RootCertStore,
) -> Result<Resp, String> {
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;
    use std::sync::Arc;
    let rest = url.strip_prefix("https://").ok_or("raw TLS 는 https 전용")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if hostport.contains('@') || path.bytes().any(|b| b == b'\r' || b == b'\n') {
        return Err("raw 전송 불가 문자".into());
    }
    let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
        let end = h.find(']').ok_or("IPv6 파싱 실패")?;
        let port = h[end + 1..].strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).unwrap_or(443);
        (&h[..end], port)
    } else {
        match hostport.split_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| "포트 파싱 실패")?),
            None => (hostport, 443),
        }
    };
    if host.is_empty() {
        return Err("호스트 없음".into());
    }
    let dial = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let server_name = rustls::ServerName::try_from(host).map_err(|_| "SNI 이름 불가")?;
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    let sock_addr = dial.to_socket_addrs().map_err(|e| format!("DNS 실패: {e}"))?.next().ok_or("주소 없음")?;
    let mut sock = std::net::TcpStream::connect_timeout(&sock_addr, timeout).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nUser-Agent: {UA}\r\nConnection: close\r\n");
    for (k, v) in headers {
        if k.bytes().any(|b| b == b'\r' || b == b'\n') || v.bytes().any(|b| b == b'\r' || b == b'\n') {
            continue;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    match tls.take(cap + 65536).read_to_end(&mut buf) {
        Ok(_) => {}
        // close_notify 없이 끊는 서버 허용 — 받은 만큼 파싱.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !buf.is_empty() => {}
        Err(e) => return Err(e.to_string()),
    }
    parse_raw_response(&String::from_utf8_lossy(&buf), cap)
}

/// 잡 전송 — %2e 경로 + http 면 원시 전송 (정규화 우회), 그 외는 ureq.
fn fetch_job(agent: &ureq::Agent, job: &Job, headers: &[(&str, &str)], cap: u64, timeout: Duration) -> Result<Resp, String> {
    fetch_url_maybe_raw(agent, &job.url, job.method, headers, cap, timeout, matches!(job.kind, ProbeKind::Path))
}

/// URL 전송 — 경로 프로브의 %2e 는 원시 전송으로 보존한다.
fn fetch_url_maybe_raw(
    agent: &ureq::Agent,
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    cap: u64,
    timeout: Duration,
    is_path: bool,
) -> Result<Resp, String> {
    if is_path && method == "GET" {
        let lower = url.to_lowercase();
        if lower.contains("%2e") && lower.starts_with("http://") {
            return fetch_raw_http(url, headers, cap, timeout);
        }
        if lower.contains("%2e") && lower.starts_with("https://") {
            return fetch_raw_tls(url, headers, cap, timeout);
        }
    }
    fetch(agent, method, url, headers, cap)
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
    if n.is_empty() || from >= h.len() || from + n.len() > h.len() {
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

/// LDAP/XPath 오류 지문 — 따옴표 투입 응답에서 찾는다 (SQLi 잡 응답에 함께 적용, 추가 요청 없음).
pub fn find_ldap_xpath_errors(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    LDAP_XPATH_FPS
        .iter()
        .filter(|fp| lower.contains(**fp))
        .map(|fp| fp.to_string())
        .collect()
}

/// NoSQL 오류 지문 — 연산자 투입 응답에서 찾는다.
pub fn find_nosql_errors(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    NOSQL_FPS
        .iter()
        .filter(|fp| lower.contains(**fp))
        .map(|fp| fp.to_string())
        .collect()
}

/// SSRF 판정 — 보낸 URL 에 없던 메타데이터 시그니처가 응답에 있으면 서버측 취득 신호.
/// 단순 반사(요청 URL 그대로 에코)는 제외한다.
pub fn ssrf_signal(sent_url: &str, body: &str) -> Vec<String> {
    SSRF_SIGS
        .iter()
        .filter(|sig| !sent_url.contains(**sig) && body.contains(**sig))
        .map(|sig| sig.to_string())
        .collect()
}

/// JWT 헤더 위험 클레임 오프라인 판독 — kid/jku/x5u 존재를 보고한다 (무전송).
pub fn jwt_risky_claims(header_b64: &str) -> Vec<String> {
    let mut out = Vec::new();
    let text = b64url_decode(header_b64)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    for claim in ["\"kid\"", "\"jku\"", "\"x5u\"", "\"x5c\""] {
        if text.contains(claim) {
            out.push(claim.trim_matches('"').to_string());
        }
    }
    out
}

/// 탭내빙 표면 — `target=_blank` 인데 rel 에 noopener/noreferrer 가 없는 앵커 수 (오프라인).
pub fn count_tabnabbing(html: &str) -> usize {
    let lower = html.to_lowercase();
    let mut n = 0;
    let mut from = 0;
    while let Some(pos) = lower[from..].find("<a ") {
        let start = from + pos;
        let end = lower[start..].find('>').map(|e| start + e).unwrap_or(lower.len());
        let tag = &lower[start..end.min(start + 500)];
        if tag.contains("target=") && tag.contains("_blank") {
            let has_rel = TABNAB_REL.iter().any(|r| tag.contains(r));
            if !has_rel {
                n += 1;
            }
        }
        from = end + 1;
        if from >= lower.len() {
            break;
        }
    }
    n
}

/// CSP 우회 가능성 분석 — unsafe-inline·와일드카드·http: 허용을 보고한다 (오프라인).
pub fn scan_csp_weakness(csp: &str) -> Vec<String> {
    let mut out = Vec::new();
    let c = csp.to_lowercase();
    if c.contains("'unsafe-inline'") {
        out.push("unsafe-inline 허용 — 인라인 스크립트 차단 불가".to_string());
    }
    if c.contains("'unsafe-eval'") {
        out.push("unsafe-eval 허용".to_string());
    }
    if c.contains(" *;") || c.contains(" * ") || c.ends_with(" *") || c.contains("default-src *") || c.contains("script-src *") {
        out.push("와일드카드(*) 소스 허용".to_string());
    }
    if c.contains("http:") && !c.contains("https:") {
        out.push("평문 http: 소스 허용".to_string());
    }
    if c.contains("data:") && c.contains("script-src") {
        out.push("script-src data: 허용 — XSS 우회 경로".to_string());
    }
    out
}

/// 역직렬화 blob 시그니처 관측 — DOM·쿠키에서 진행, 전송 없음 (오프라인).
/// CVE 오프라인 테이블 — (제품, 브랜치 접두, 최초 수정 버전, 대표 CVE, 심각도, 설명).
/// `fixed_in` 이 비면 해당 브랜치 전 버전 해당(EOL 계열). 수정 버전 미만이면 취약.
/// 수동 큐레이션 스냅샷 — NVD 대조로 주기 갱신할 것 (갱신 시 아래 UPDATED 주석도 갱신).
/// UPDATED: 2026-01 (대표 CVE 기준 — 개별 버전 확정은 NVD 대조 필요).
const CVE_TABLE: &[(&str, &str, &str, &str, Severity, &str)] = &[
    ("jquery", "", "3.5.0", "CVE-2020-11022", Severity::High, "XSS(htmlPrefilter) 등 — 3.5.0 미만"),
    ("lodash", "", "4.17.21", "CVE-2020-8203", Severity::High, "프로토타입 오염 등 — 4.17.21 미만"),
    ("bootstrap", "3.", "3.4.1", "CVE-2019-8331", Severity::High, "XSS(tooltip/popover) — 3.4.1 미만"),
    ("bootstrap", "4.", "4.3.1", "CVE-2019-8331", Severity::High, "XSS(tooltip/popover) — 4.3.1 미만"),
    ("moment", "", "2.29.4", "CVE-2022-24785", Severity::Medium, "경로 순회(locale) — 2.29.4 미만"),
    ("angular", "1.", "1.8.3", "CVE-2022-25869", Severity::High, "표현식 주입 — 1.8.3 미만"),
    ("php", "5.", "", "EOL-2018", Severity::High, "PHP 5.x 지원 종료 — 보안 패치 없음"),
    ("php", "7.", "", "EOL-2022", Severity::High, "PHP 7.x 지원 종료 — 보안 패치 없음"),
    ("php", "8.0.", "", "EOL-2023", Severity::Medium, "PHP 8.0 지원 종료 — 보안 패치 없음"),
    ("apache", "2.2.", "", "EOL", Severity::High, "Apache 2.2.x 지원 종료"),
    ("apache", "2.4.", "2.4.51", "CVE-2021-41773", Severity::High, "구버전 — 패치 누락 다수(CVE-2021-41773 등)"),
    ("nginx", "", "1.20.1", "CVE-2021-23017", Severity::Medium, "리졸버 off-by-one 등 — 1.20.1 미만"),
    ("openssl", "1.0.", "", "EOL", Severity::High, "OpenSSL 1.0.x 지원 종료"),
    ("openssl", "1.1.0", "", "EOL", Severity::High, "OpenSSL 1.1.0 지원 종료"),
    ("openssl", "1.1.1", "", "EOL-2023", Severity::Medium, "OpenSSL 1.1.1 지원 종료(2023-09)"),
    ("iis", "7.", "", "EOL", Severity::Medium, "IIS 7.x — 동봉 OS 지원 주기 확인 필요"),
    ("iis", "8.", "", "EOL", Severity::Medium, "IIS 8.x — 동봉 OS 지원 주기 확인 필요"),
    ("wordpress", "", "6.0.0", "다수", Severity::Medium, "구버전 — 버전별 CVE NVD 대조 필요"),
];

pub fn parse_version_parts(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse::<u64>().ok())
        .collect()
}

/// 수치 버전 비교 — a < b 이면 참 (빈 자리 0).
pub fn version_lt(a: &str, b: &str) -> bool {
    let (x, y) = (parse_version_parts(a), parse_version_parts(b));
    if x.is_empty() || y.is_empty() {
        return false;
    }
    let n = x.len().max(y.len());
    for i in 0..n {
        let (p, q) = (x.get(i).copied().unwrap_or(0), y.get(i).copied().unwrap_or(0));
        if p != q {
            return p < q;
        }
    }
    false
}

/// 테이블 대조 — (심각도, 대표 CVE, 설명) 목록.
pub fn lookup_cves(product: &str, version: &str) -> Vec<(Severity, String, String)> {
    let mut out = Vec::new();
    for (prod, branch, fixed_in, cve, sev, title) in CVE_TABLE {
        if *prod != product {
            continue;
        }
        if !branch.is_empty() && !version.starts_with(branch) {
            continue;
        }
        let vuln = if fixed_in.is_empty() { true } else { version_lt(version, fixed_in) };
        if vuln {
            out.push((*sev, cve.to_string(), title.to_string()));
        }
    }
    out
}

/// 마커 뒤 버전 파싱 — v·/·-·_·공백을 건너뛰고 숫자·점 런을 읽는다.
fn parse_ver_after(s: &str, pos: usize) -> Option<String> {
    let rest = s.get(pos..)?.trim_start_matches(|c: char| matches!(c, 'v' | '/' | '-' | '_' | ' ' | ':'));
    let mut v = String::new();
    for c in rest.chars() {
        if c.is_ascii_digit() || c == '.' {
            v.push(c);
        } else {
            break;
        }
    }
    let v = v.trim_matches('.').to_string();
    if parse_version_parts(&v).is_empty() {
        return None;
    }
    Some(v)
}

/// Server·X-Powered-By 지문 — (제품, 버전, 출처).
pub fn fingerprint_server(headers: &[(String, String)]) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    let mut push = |product: &str, ver: String, src: String| {
        if !out.iter().any(|(p, v, _)| p == product && v == &ver) {
            out.push((product.to_string(), ver, src));
        }
    };
    if let Some(server) = header(headers, "server") {
        for tok in server.split_whitespace() {
            let low = tok.to_lowercase();
            for (prefix, product) in [
                ("nginx/", "nginx"),
                ("apache/", "apache"),
                ("microsoft-iis/", "iis"),
                ("openresty/", "openresty"),
                ("openssl/", "openssl"),
                ("php/", "php"),
            ] {
                if low.starts_with(prefix) {
                    if let Some(v) = parse_ver_after(tok, prefix.len()) {
                        push(product, v, format!("Server: {tok}"));
                    }
                }
            }
            if low == "litespeed" || low.starts_with("litespeed/") {
                if let Some(v) = parse_ver_after(tok, "litespeed".len()) {
                    push("litespeed", v, format!("Server: {tok}"));
                }
            }
        }
    }
    if let Some(xpb) = header(headers, "x-powered-by") {
        let low = xpb.to_lowercase();
        if let Some(pos) = low.find("php/") {
            if let Some(v) = parse_ver_after(xpb, pos + 4) {
                push("php", v, format!("X-Powered-By: {xpb}"));
            }
        }
        if let Some(pos) = low.find("express") {
            let _ = pos;
            // Express 는 버전 미표기 — 지문만 (테이블 항목 없음).
            push("express", "unknown".to_string(), format!("X-Powered-By: {xpb}"));
        }
    }
    out
}

const BUNDLE_LIBS: &[&str] = &["jquery", "lodash", "bootstrap", "react", "vue", "moment", "angular"];

/// 번들·본문 지문 — URL 파일명 + 버전 주석 + WP generator + manifest 의존성.
pub fn fingerprint_body(url: &str, body: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    let mut push = |product: &str, ver: String, src: String| {
        if !out.iter().any(|(p, v, _)| p == product && v == &ver) {
            out.push((product.to_string(), ver, src));
        }
    };
    // URL 파일명: jquery-1.12.4.min.js, lodash.4.17.20.js 등.
    let low_url = url.to_lowercase();
    for name in BUNDLE_LIBS {
        if let Some(pos) = low_url.find(name) {
            if let Some(v) = parse_ver_after(&low_url, pos + name.len()) {
                push(name, v, format!("파일명: {url}"));
            }
        }
    }
    let low = body.to_lowercase();
    // 번들 버전 주석.
    for (marker, product) in [
        ("jquery v", "jquery"),
        ("jquery-", "jquery"),
        ("lodash v", "lodash"),
        ("bootstrap v", "bootstrap"),
        ("vue.js v", "vue"),
        (" vue v", "vue"),
        ("react v", "react"),
        ("moment v", "moment"),
        ("angularjs v", "angular"),
        ("angular v", "angular"),
    ] {
        if let Some(pos) = low.find(marker) {
            if let Some(v) = parse_ver_after(&low, pos + marker.len()) {
                push(product, v, "번들 주석".to_string());
            }
        }
    }
    // WordPress generator.
    if let Some(pos) = low.find("wordpress ") {
        if let Some(v) = parse_ver_after(&low, pos + "wordpress ".len()) {
            push("wordpress", v, "generator 메타".to_string());
        }
    }
    // manifest 의존성: "jquery": "^1.12.4".
    for name in BUNDLE_LIBS {
        let key = format!("\"{name}\"");
        if let Some(kpos) = low.find(&key) {
            let after = &low[kpos + key.len()..];
            if let Some(cpos) = after.find(':') {
                let window: &str = &after[cpos + 1..after.len().min(cpos + 25)];
                let mut v = String::new();
                let mut started = false;
                for c in window.chars() {
                    if c.is_ascii_digit() || (started && c == '.') {
                        started = true;
                        v.push(c);
                    } else if started {
                        break;
                    }
                }
                let v = v.trim_matches('.').to_string();
                if !parse_version_parts(&v).is_empty() {
                    push(name, v, "manifest 의존성".to_string());
                }
            }
        }
    }
    out
}

/// 구성요소 적중 — 테이블 대조 통과분만 (최대 6건).
pub fn scan_component_hits(target: &str, products: &[(String, String, String)]) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    for (product, version, src) in products {
        for (sev, cve, title) in lookup_cves(product, version) {
            if out.len() >= 6 {
                return out;
            }
            out.push(hit(
                "vuln-component",
                sev,
                target.to_string(),
                format!("취약 구성요소 — {product} {version} ({cve})"),
                title,
                one_line(src, 120),
                "오프라인 판정 (CVE 테이블)".into(),
                None,
            ));
        }
    }
    out
}

/// 동일 구성요소 중복 제거 — (카테고리, 제목) 첫 적중만 남기고 "외 N곳" 병기.
pub fn dedup_component_hits(hits: &mut Vec<ProbeHit>) {
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for h in hits.iter() {
        if h.category == "vuln-component" {
            *counts.entry(h.title.clone()).or_insert(0) += 1;
        }
    }
    hits.retain(|h| {
        if h.category != "vuln-component" {
            return true;
        }
        if seen.contains_key(&h.title) {
            return false;
        }
        seen.insert(h.title.clone(), 1);
        true
    });
    for h in hits.iter_mut() {
        if h.category == "vuln-component" {
            if let Some(&n) = counts.get(&h.title) {
                if n > 1 {
                    h.detail = format!("{} (외 {}곳 동일 검출)", h.detail, n - 1);
                }
            }
        }
    }
}

pub fn scan_deserialize(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (sig, label) in DESER_SIGS {
        if text.contains(sig) {
            out.push((sig.to_string(), label.to_string()));
        }
    }
    // pickle 프로토콜 헤더 바이트 (\x80\x04-\x05 + c/m 오프코드 근처) — 텍스트 손실 있어도 탐지.
    if text.contains("c__builtin__") || text.contains("cos\nsystem") || text.contains("(S'") {
        out.push(("pickle".to_string(), "Python pickle (c__builtin__/system)".to_string()));
    }
    out
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
/// OIDC 설정 파싱 — (issuer, auth_endpoint 유무, token_endpoint 유무, implicit 허용).
/// issuer 없으면 None. 수동 JSON-ish 스캔.
pub fn parse_oidc_config(body: &str) -> Option<(String, bool, bool, bool)> {
    let low = body.to_lowercase();
    let ipos = low.find("\"issuer\"")?;
    // low 에서 잘라낸다 (body 직접 슬라이스는 비ASCII 경계 패닉 가능 — issuer 는 소문자 표기).
    let after = &low[ipos + "\"issuer\"".len()..];
    let cpos = after.find(':')?;
    let val = after[cpos + 1..].trim_start().trim_start_matches('"');
    let issuer: String = val.chars().take_while(|c| *c != '"' && *c != ',' && *c != '\n').collect();
    if issuer.trim().is_empty() {
        return None;
    }
    let has_auth = low.contains("\"authorization_endpoint\"");
    let has_token = low.contains("\"token_endpoint\"");
    // implicit: response_types_supported 에 token 계열이 code 없이 있으면 허용.
    let implicit = if let Some(rpos) = low.find("\"response_types_supported\"") {
        let window = &low[rpos..low.len().min(rpos + 400)];
        let end = window.find(']').unwrap_or(window.len());
        let arr = &window[..end];
        (arr.contains("\"token\"") || arr.contains("id_token token") || arr.contains("token id_token"))
            && !arr.contains("\"code\"")
    } else {
        false
    };
    Some((issuer.trim().to_string(), has_auth, has_token, implicit))
}

fn classify_path(path: &str, status: u16, body: &str, location: Option<&str>) -> Option<(Severity, String)> {
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
    // 3xx — Location 기준으로 판정. 로그인 게이트(전 경로 →/login)는 조용히
    // 버린다 (균일 게이트 — 실측 esdp.lge.com 전 경로 307 오탐 회귀 방지).
    // 그 외 리다이렉트는 민감 경로만 Info 추정.
    if (300..400).contains(&status) {
        let loc = location.unwrap_or("").to_lowercase();
        let loc_path = loc.split('?').next().unwrap_or("");
        if ["/login", "signin", "logon", "/auth", "sso"].iter().any(|k| loc_path.contains(k)) {
            return None;
        }
        if secret_file || vcs || backup || actuator_sensitive || admin || docs || debug {
            return Some((Severity::Info, format!("민감 경로 리다이렉트 (존재 추정, {status})")));
        }
        return None;
    }
    if !(200..300).contains(&status) {
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
    // LLM API 표면 (OpenAI 호환·Ollama) — 200 + 모델 목록 JSON 이면 인증 없는 추론 노출.
    if p.starts_with("/v1/models") || p.starts_with("/api/tags") || p.starts_with("/api/ps")
        || p.starts_with("/api/show") || p.starts_with("/v1/embeddings") || p.starts_with("/api/generate") || p.starts_with("/api/chat") {
        let looks_llm = body.contains("\"data\"") || body.contains("\"models\"")
            || body.contains("/v1/") || body.to_lowercase().contains("openai")
            || body.to_lowercase().contains("ollama");
        return Some((
            if looks_llm { Severity::High } else { Severity::Medium },
            "LLM API 표면 노출".to_string(),
        ));
    }
    // OIDC 설정 파싱 — issuer·엔드포인트·implicit 플로우 판정.
    if p.contains("openid-configuration") {
        if status == 200 {
            if let Some((issuer, has_auth, has_token, implicit)) = parse_oidc_config(body) {
                let sev = if implicit { Severity::Medium } else { Severity::Info };
                return Some((sev, format!("OpenID 설정 노출 — {} (auth:{},token:{},implicit:{})",
                    one_line(&issuer, 60),
                    if has_auth { "있음" } else { "없음" },
                    if has_token { "있음" } else { "없음" },
                    if implicit { "허용" } else { "없음" })));
            }
        }
        return Some((Severity::Info, "공개 정보 파일".to_string()));
    }
    // SAML 메타데이터·IdP 진입점 — SAML 흔적 없으면 SPA 폴백으로 보고 무시.
    if p.contains("saml/metadata") || p.contains("saml2/metadata") || p.contains("idpinitiatedsignon") {
        let low = body.to_lowercase();
        if body.contains("EntityDescriptor") || body.contains("IDPSSODescriptor") || low.contains("saml") || low.contains("adfs") {
            return Some((Severity::Info, "SAML 표면 노출".to_string()));
        }
        return None;
    }
    // gRPC reflection — GET 으로 마커 확인 (바이너리 POST 없이).
    if p.contains("grpc.reflection") {
        let low = body.to_lowercase();
        let grpc = body.contains("grpc-status") || body.contains("grpc-message") || low.contains("application/grpc") || low.contains("grpc");
        return Some((
            if grpc { Severity::Medium } else { Severity::Low },
            "gRPC reflection 표면".to_string(),
        ));
    }
    if p.contains("robots.txt") || p.contains("sitemap") || p.contains("security.txt") || p.contains("crossdomain") {
        return Some((Severity::Info, "공개 정보 파일".to_string()));
    }
    if p.contains("%2e%2e") || p.contains("..;") || p.contains("win.ini") {
        if status == 200 && (body.to_lowercase().contains("root:") || body.to_lowercase().contains("[fonts]")) {
            // 읽기 전용 LFI — CVSS 3.1 은 단일 C:H 를 7.5(High)로 상한한다.
            // Critical 은 I/A-High 입증이 필요하므로 과대 표기하지 않는다 (차단 여부는 동일).
            return Some((Severity::High, "경로 조작 성공 (LFI, 임의 파일 읽기)".to_string()));
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
    Cmdi { param: String, payload: String },
    Redirect { param: String, payload: &'static str },
    Ssti { param: String, payload: String },
    Ssrf { param: String },
    OobSsrf { param: String, token: String },
    Graphql,
    HostHeader { header: &'static str },
    Crlf { param: String },
    Hpp { param: String },
    Nosql { param: String },
    CorsNull,
    CorsPreflight,
    Websocket { path: String },
    GraphqlDepth,
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

/// 반사 지점 발췌 — 마커 중심 ±70자 (문자 경계 안전). 마커 없으면 헤드 폴백.
fn reflection_snippet(body: &str, marker: &str) -> String {
    let Some(pos) = body.find(marker) else {
        return one_line(body, 160);
    };
    let start = body[..pos].char_indices().rev().take(70).last().map(|(i, _)| i).unwrap_or(0);
    let rest = &body[pos..];
    let end = rest.char_indices().take(70 + marker.len()).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(rest.len());
    one_line(&body[start..pos + end], 200)
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
                    let resp = fetch_job(&agent, &job, &hs, cap, timeout);
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
            if let Some((sev, title)) = classify_path(&p, r.status, &r.body, header(&r.headers, "location")) {
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
            // manifest 버전 스캔 — 의존성 버전을 CVE 테이블과 대조한다.
            if r.status == 200 && ["package.json", "package-lock.json", "composer.json", "composer.lock", "Gemfile.lock", "requirements.txt", "go.mod"]
                .iter().any(|m| p.ends_with(m)) {
                out.extend(scan_component_hits(&job.url, &fingerprint_body(&job.url, &r.body)));
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
            // 번들 버전 스캔 — 파일명·버전 주석을 CVE 테이블과 대조한다.
            out.extend(scan_component_hits(&job.url, &fingerprint_body(&job.url, &r.body).into_iter().take(4).collect::<Vec<_>>()));
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
            let ldap = find_ldap_xpath_errors(&r.body);
            if !ldap.is_empty() {
                out.push(hit(
                    "ldap-xpath-signal",
                    Severity::High,
                    job.url.clone(),
                    format!("LDAP/XPath 오류 노출 — 파라미터 '{param}'"),
                    format!("지문: {}", ldap.join(" / ")),
                    one_line(&r.body, 200),
                    format!("GET → {}", r.status),
                    Some(r.status),
                ));
            }
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
        ProbeKind::Cmdi { param, .. } => {
            let Ok(r) = resp else { return };
            if let Some(kind) = cmdi_output_kind(&r.body) {
                out.push(hit(
                    "cmdi-exec",
                    Severity::Critical,
                    job.url.clone(),
                    format!("OS 명령 실행 (CMDI) — 파라미터 '{param}'"),
                    format!("{kind} 명령 출력이 응답에 노출 — 원격 코드 실행 확정"),
                    one_line(&r.body, 200),
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
        ProbeKind::Ssti { param, payload } => {
            let Ok(r) = resp else { return };
            if r.body.contains(SSTI_EXPECT) {
                out.push(hit(
                    "ssti-eval",
                    Severity::High,
                    job.url.clone(),
                    format!("서버 템플릿 평가 (SSTI) — 파라미터 '{param}'"),
                    format!("{payload} → {SSTI_EXPECT} 계산됨 — 서버가 템플릿을 실행했다"),
                    one_line(&r.body, 160),
                    format!("GET → {}", r.status),
                    Some(r.status),
                ));
            } else if r.body.contains(payload.as_str()) {
                // 미평가 반사 — 클라이언트 템플릿(CSTI) 후보면 약한 신호로 기록.
                let ctx = classify_reflection(&r.body, payload);
                if ctx.in_script {
                    out.push(hit(
                        "csti-signal",
                        Severity::Low,
                        job.url.clone(),
                        format!("클라이언트 템플릿 잔류 — 파라미터 '{param}'"),
                        "템플릿 구문이 script 컨텍스트에 그대로 남음 — 프론트 프레임워크 평가 가능성에 대한 약한 신호".into(),
                        one_line(&r.body, 160),
                        format!("GET → {}", r.status),
                        Some(r.status),
                    ));
                }
            }
        }
        ProbeKind::Ssrf { param } => {
            let Ok(r) = resp else { return };
            let sigs = ssrf_signal(SSRF_URL, &r.body);
            if !sigs.is_empty() {
                out.push(hit(
                    "ssrf-signal",
                    Severity::High,
                    job.url.clone(),
                    format!("SSRF 신호 — 파라미터 '{param}'"),
                    format!("요청에 없던 메타데이터({})가 응답에 포함 — 서버가 내부 주소를 조회했다", sigs.join("/")),
                    one_line(&r.body, 200),
                    format!("GET → {}", r.status),
                    Some(r.status),
                ));
            }
        }
        ProbeKind::OobSsrf { .. } => {
            // 응답 무시 — 종료 시 콜백 수신분 매칭으로 확정한다.
        }
        ProbeKind::Graphql => {
            let Ok(r) = resp else { return };
            if r.status == 200 && (r.body.contains("__schema") || r.body.contains("queryType")) {
                out.push(hit(
                    "graphql-introspect",
                    Severity::Medium,
                    job.url.clone(),
                    "GraphQL introspection 활성화".into(),
                    "인증 없이 __schema 조회 성공 — 스키마 전체 노출".into(),
                    one_line(&r.body, 200),
                    format!("GET → {}", r.status),
                    Some(r.status),
                ));
                // 뮤테이션 존재 — 쓰기 표면 후속 확인 필요 (읽기만으로 판정).
                if r.body.contains("mutationType") && !r.body.contains("\"mutationType\":null") {
                    out.push(hit(
                        "graphql-mutation",
                        Severity::Info,
                        job.url.clone(),
                        "GraphQL 뮤테이션 존재".into(),
                        "mutationType 비어 있지 않음 — 쓰기 API 남용 가능성에 대한 후속 확인 필요".into(),
                        String::new(),
                        format!("GET → {}", r.status),
                        Some(r.status),
                    ));
                }
            }
        }
        ProbeKind::Websocket { path } => {
            match resp {
                Ok(r) if r.status == 101 => {
                    out.push(hit(
                        "websocket-surface",
                        Severity::Medium,
                        job.url.clone(),
                        format!("WebSocket 엔드포인트 — {path}"),
                        "101 Switching Protocols — CSWSH(Origin 검증)·인증 후속 확인 필요".into(),
                        String::new(),
                        format!("GET → 101 (Upgrade)"),
                        Some(101),
                    ));
                }
                Ok(r) if r.body.to_lowercase().contains("websocket") => {
                    out.push(hit(
                        "websocket-surface",
                        Severity::Low,
                        job.url.clone(),
                        format!("WebSocket 흔적 — {path}"),
                        "Upgrade 응답에 websocket 언급 — 엔드포인트 가능성에 대한 약한 신호".into(),
                        one_line(&r.body, 160),
                        format!("GET → {}", r.status),
                        Some(r.status),
                    ));
                }
                Err(e) if e.contains("101") => {
                    out.push(hit(
                        "websocket-surface",
                        Severity::Medium,
                        job.url.clone(),
                        format!("WebSocket 엔드포인트 — {path}"),
                        "101 응답 (전송 계층 표기) — CSWSH 후속 확인 필요".into(),
                        String::new(),
                        "GET (Upgrade)".into(),
                        Some(101),
                    ));
                }
                _ => {}
            }
        }
        ProbeKind::GraphqlDepth => {
            let Ok(r) = resp else { return };
            if r.status == 200 && r.body.contains("__typename") {
                let low = r.body.to_lowercase();
                // depth·복잡도 제한 언급 없이 중첩 15단계가 통과하면 제한 미확인 신호.
                if !low.contains("depth") && !low.contains("complex") && !low.contains("too many") && !low.contains("limit") {
                    out.push(hit(
                        "graphql-depth",
                        Severity::Low,
                        job.url.clone(),
                        "GraphQL depth 제한 미확인".into(),
                        "15단계 중첩 조회가 제한 언급 없이 통과 — DoS(중첩 쿼리) 가능성에 대한 약한 신호".into(),
                        one_line(&r.body, 160),
                        format!("GET → {}", r.status),
                        Some(r.status),
                    ));
                }
            }
        }
        ProbeKind::HostHeader { header: hh } => {
            let Ok(r) = resp else { return };
            let loc = header(&r.headers, "location").unwrap_or("");
            let reflected = loc.contains("evil-probe.test") || r.body.contains("evil-probe.test");
            if reflected {
                out.push(hit(
                    "host-header",
                    Severity::Medium,
                    job.url.clone(),
                    format!("Host 헤더 오염 반영 ({hh})"),
                    "비밀번호 재설정 링크·캐시 키 오염 가능성에 대한 신호 — Location/본문에 canary 반영".into(),
                    one_line(&format!("{loc} {}", one_line(&r.body, 120)), 200),
                    format!("GET → {}", r.status),
                    Some(r.status),
                ));
            }
        }
        ProbeKind::Crlf { param } => {
            let Ok(r) = resp else { return };
            // 응답 헤더에서만 판정 — 본문 반사는 무시한다 (오탐 방지).
            let hit_header = r.headers.iter().any(|(k, v)| {
                v.contains(CRLF_MARKER) && !k.eq_ignore_ascii_case("content-location")
            });
            if hit_header {
                out.push(hit(
                    "crlf-inject",
                    Severity::High,
                    job.url.clone(),
                    format!("CRLF 헤더 주입 — 파라미터 '{param}'"),
                    "개행 페이로드가 응답 헤더에 반영됨 — 응답 분할/쿠키 고정 가능성에 대한 강한 신호".into(),
                    String::new(),
                    format!("GET → {}", r.status),
                    Some(r.status),
                ));
            }
        }
        ProbeKind::Hpp { param } => {
            let Ok(r) = resp else { return };
            if r.body.contains(HPP_A) && r.body.contains(HPP_B) {
                out.push(hit(
                    "hpp-ambiguity",
                    Severity::Low,
                    job.url.clone(),
                    format!("파라미터 오염 모호성 (HPP) — '{param}'"),
                    "같은 이름의 값이 둘 다 반영됨 — WAF/백엔드 파서 불일치 악용 가능성에 대한 약한 신호".into(),
                    one_line(&r.body, 160),
                    format!("GET → {}", r.status),
                    Some(r.status),
                ));
            }
        }
        ProbeKind::Nosql { param } => {
            let Ok(r) = resp else { return };
            let fps = find_nosql_errors(&r.body);
            if !fps.is_empty() {
                out.push(hit(
                    "nosql-signal",
                    Severity::High,
                    job.url.clone(),
                    format!("NoSQL 오류 노출 — 파라미터 '{param}'"),
                    format!("지문: {}", fps.join(" / ")),
                    one_line(&r.body, 200),
                    format!("GET → {}", r.status),
                    Some(r.status),
                ));
            }
        }
        ProbeKind::CorsNull => {
            let Ok(r) = resp else { return };
            if let Some(acao) = header(&r.headers, "access-control-allow-origin") {
                if acao.trim() == "null" {
                    out.push(hit(
                        "cors",
                        Severity::Medium,
                        job.url.clone(),
                        "CORS null Origin 허용".into(),
                        "Access-Control-Allow-Origin: null — 샌드박스 iframe 경유 탈취 가능성에 대한 신호".into(),
                        String::new(),
                        format!("GET → {}", r.status),
                        Some(r.status),
                    ));
                }
            }
        }
        ProbeKind::CorsPreflight => {
            let Ok(r) = resp else { return };
            let methods = header(&r.headers, "access-control-allow-methods").unwrap_or("");
            let has_write = ["PUT", "DELETE", "PATCH"].iter().any(|m| methods.to_uppercase().contains(m));
            let cred = header(&r.headers, "access-control-allow-credentials").map(|v| v.trim() == "true").unwrap_or(false);
            if has_write && cred {
                out.push(hit(
                    "cors",
                    Severity::Medium,
                    job.url.clone(),
                    "CORS preflight 쓰기 허용 + 자격증명".into(),
                    format!("Allow-Methods: {methods} + Allow-Credentials: true — 교차 출처 쓰기 가능성에 대한 신호"),
                    String::new(),
                    format!("OPTIONS → {}", r.status),
                    Some(r.status),
                ));
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

/// 테스트 전용 브라우저 직렬화 — 병렬 테스트의 크롬 동시 기동은 CPU 경합으로
/// DevTools 기동 타임아웃을 유발한다 (플레이크). 테스트 빌드에서만 렌더 세션 전체를
/// 직렬화하고, 프로덕션 빌드에는 어떤 영향도 없다 (컴파일 아웃).
#[cfg(test)]
static BROWSER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn browser_test_guard() -> std::sync::MutexGuard<'static, ()> {
    BROWSER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn render_dom_with(url: &str, cfg: &SweepConfig, bin: Option<std::path::PathBuf>) -> Option<String> {
    #[cfg(test)]
    let _browser_guard = browser_test_guard();
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

// ── CDP 미니 클라이언트 (std 전용 — WS·SHA-1 직접 구현) ────────────────────────

/// SHA-1 (FIPS 180-4) — WebSocket 핸드셰이크 accept 계산용.
fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut data = msg.to_vec();
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// 표준 base64 (패딩 포함) — WS accept 키용 (b64url 과 별개).
fn b64std_encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
        out.push(if rem > 1 { ALPHA[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if rem > 2 { ALPHA[n as usize & 63] as char } else { '=' });
        i += 3;
    }
    out
}

/// WS 텍스트 송신 — 클라이언트 마스크 필수 (RFC 6455).
fn ws_send_text(stream: &mut std::net::TcpStream, payload: &str) -> std::io::Result<()> {
    use std::io::Write;
    let b = payload.as_bytes();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0x12345678);
    let mask = (nanos ^ (std::process::id().wrapping_mul(0x9E3779B9))).to_be_bytes();
    let mut hdr = vec![0x81u8];
    if b.len() < 126 {
        hdr.push(0x80 | b.len() as u8);
    } else if b.len() < 65536 {
        hdr.push(0x80 | 126);
        hdr.extend_from_slice(&(b.len() as u16).to_be_bytes());
    } else {
        hdr.push(0x80 | 127);
        hdr.extend_from_slice(&(b.len() as u64).to_be_bytes());
    }
    hdr.extend_from_slice(&mask);
    stream.write_all(&hdr)?;
    let masked: Vec<u8> = b.iter().enumerate().map(|(i, x)| x ^ mask[i % 4]).collect();
    stream.write_all(&masked)
}

/// WS 수신 — 텍스트 조립(분할 포함), ping→pong, 4MB 상한. 종료·초과 시 None.
fn ws_recv_text(stream: &mut std::net::TcpStream, timeout: Duration) -> Option<String> {
    use std::io::{Read, Write};
    stream.set_read_timeout(Some(timeout)).ok()?;
    let mut msg: Vec<u8> = Vec::new();
    loop {
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).ok()?;
        let opcode = hdr[0] & 0x0F;
        let mut len = (hdr[1] & 0x7F) as u64;
        if len == 126 {
            let mut e = [0u8; 2];
            stream.read_exact(&mut e).ok()?;
            len = u16::from_be_bytes(e) as u64;
        } else if len == 127 {
            let mut e = [0u8; 8];
            stream.read_exact(&mut e).ok()?;
            len = u64::from_be_bytes(e);
        }
        if len > 4_194_304 {
            return None;
        }
        let mask = if hdr[1] & 0x80 != 0 {
            let mut m = [0u8; 4];
            stream.read_exact(&mut m).ok()?;
            Some(m)
        } else {
            None
        };
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).ok()?;
        if let Some(m) = mask {
            for (i, x) in payload.iter_mut().enumerate() {
                *x ^= m[i % 4];
            }
        }
        match opcode {
            0x8 => return None, // close
            0x9 => {
                let n = payload.len().min(125);
                let mut pong = vec![0x8Au8, 0x80 | n as u8, 0, 0, 0, 0];
                pong.extend_from_slice(&payload[..n]);
                stream.write_all(&pong).ok()?;
            }
            0xA => {}
            0x0 | 0x1 | 0x2 => {
                msg.extend_from_slice(&payload);
                if msg.len() > 4_194_304 {
                    return None;
                }
                if hdr[0] & 0x80 != 0 {
                    return String::from_utf8(msg).ok();
                }
            }
            _ => return None,
        }
    }
}

/// WS 핸드셰이크 — 101 + accept 키 검증.
fn ws_connect(hostport: &str, path: &str, timeout: Duration) -> Option<std::net::TcpStream> {
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;
    let addr = hostport.to_socket_addrs().ok()?.next()?;
    let mut stream = std::net::TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&(now as u64).to_be_bytes());
    nonce[8..12].copy_from_slice(&std::process::id().to_be_bytes());
    nonce[12..].copy_from_slice(&now.wrapping_mul(0x9E3779B97F4A7C15).to_be_bytes()[..4]);
    let key = b64std_encode(&nonce);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if raw.len() > 8192 {
            return None;
        }
    }
    let head = String::from_utf8_lossy(&raw).into_owned();
    if !head.starts_with("HTTP/1.1 101") {
        return None;
    }
    let accept = head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("sec-websocket-accept") {
            Some(v.trim().to_string())
        } else {
            None
        }
    })?;
    let expect = b64std_encode(&sha1(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()));
    if accept != expect {
        return None;
    }
    Some(stream)
}

/// DevTools 리스닝 포트 파싱 — stderr 의 "DevTools listening on ws://127.0.0.1:PORT/…".
fn parse_devtools_port(stderr_text: &str) -> Option<u16> {
    let i = stderr_text.find("DevTools listening on")?;
    let hp = stderr_text[i..].split("://").nth(1)?.split('/').next()?;
    hp.rsplit(':').next()?.parse::<u16>().ok().filter(|p| *p != 0)
}

/// CDP Network.requestWillBeSent 의 http(s) URL 추출.
fn cdp_request_url(msg: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(msg).ok()?;
    if v.get("method")?.as_str()? != "Network.requestWillBeSent" {
        return None;
    }
    let u = v.get("params")?.get("request")?.get("url")?.as_str()?;
    if u.starts_with("http://") || u.starts_with("https://") {
        Some(u.to_string())
    } else {
        None
    }
}

/// 동일 호스트 판정 — 호스트:포트 전체 일치 (프라이버시 경계).
fn cdp_same_host(api_url: &str, page_url: &str) -> bool {
    fn host_of(u: &str) -> Option<String> {
        let hp = u.split_once("://")?.1.split('/').next()?;
        if hp.is_empty() {
            return None;
        }
        Some(hp.to_lowercase())
    }
    match (host_of(api_url), host_of(page_url)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// CDP 명령 송신.
fn cdp_send(ws: &mut std::net::TcpStream, id: u64, method: &str, params: &str) -> Option<()> {
    ws_send_text(ws, &format!(r#"{{"id":{id},"method":"{method}","params":{params}}}"#)).ok()
}

/// Runtime.evaluate 응답의 outerHTML 추출.
fn cdp_eval_html(msg: &str, id: u64) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(msg).ok()?;
    if v.get("id")?.as_u64()? != id {
        return None;
    }
    v.get("result")?.get("result")?.get("value")?.as_str().map(|s| s.to_string())
}

/// CDP 크롬 가드 — 종료 시 프로세스 정리 + 프로필 삭제.
struct CdpGuard {
    child: Option<std::process::Child>,
    profile: std::path::PathBuf,
}

impl Drop for CdpGuard {
    fn drop(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait(); // 좀비 회수 — 헬퍼 고아화 최소화
        }
        // 헬퍼 쓰기와 경합하면 ENOTEMPTY 로 남을 수 있어 존재 확인 후 재시도.
        for _ in 0..4 {
            if !self.profile.exists() {
                break;
            }
            let _ = std::fs::remove_dir_all(&self.profile);
            if !self.profile.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }
}

/// CDP 상태 — 상호작용 후 도달한 URL + DOM.
#[derive(Debug, Clone)]
pub struct CdpState {
    pub url: String,
    pub dom: String,
}

/// CDP 수집 표면 — 렌더 DOM + 동일 호스트 XHR/fetch URL + 탐색 상태.
pub struct CdpSurface {
    pub dom: String,
    pub api_urls: Vec<String>,
    pub states: Vec<CdpState>,
    /// 무한 스크롤 유효 횟수 (높이 증가가 관측된 횟수).
    pub scrolled: usize,
    /// SPA 로그인 성공 여부.
    pub authenticated: bool,
    /// 로그인으로 확보한 세션 쿠키 (Cookie 헤더 값, 스윕 전체에 적용).
    pub session_cookie: Option<String>,
}

/// CDP 발견 후보 — 링크·버튼·폼.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdpCand {
    kind: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    href: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    has_password: bool,
}

/// SPA 후보 발견 — 가시 링크 30·버튼 10·폼 5, JSON 반환.
const CDP_DISCOVER_JS: &str = r#"(() => {
  const vis = (el) => { const r = el.getBoundingClientRect(); if (r.width < 2 || r.height < 2) return false; const s = getComputedStyle(el); return s.visibility !== 'hidden' && s.display !== 'none'; };
  const out = [];
  const links = [...document.querySelectorAll('a[href]')].filter(vis).slice(0, 30);
  for (const a of links) out.push({kind:'link', text:(a.innerText||'').trim().replace(/\s+/g,' ').slice(0,80), href:a.href});
  const inLogin = (e) => { const f = e.closest('form'); return !!(f && f.querySelector('input[type=password]')); };
  const btns = [...document.querySelectorAll('button, input[type=submit], input[type=button]')].filter(e => !e.disabled && vis(e) && !inLogin(e)).slice(0,10);
  for (const b of btns) out.push({kind:'button', text:((b.innerText||b.value||'').trim().replace(/\s+/g,' ').slice(0,80))});
  const forms = [...document.forms].filter(vis).slice(0,5);
  for (const f of forms) {
    const inputs = [...f.querySelectorAll('input[name], textarea[name]')].filter(inp => !['submit','button','reset','image','hidden','password','file'].includes((inp.type||'text').toLowerCase())).map(inp => inp.name).slice(0,8);
    out.push({kind:'form', text:((f.id||f.name||'').slice(0,40)), action:f.action, fields:inputs, hasPassword: !!f.querySelector('input[type=password]')});
  }
  return JSON.stringify(out);
})()"#;

/// 버튼 클릭 — __I__번째 가시 버튼 (발견과 동일 셀렉터·순서·로그인 제외).
const CDP_CLICK_JS: &str = r#"(() => { const vis=(el)=>{const r=el.getBoundingClientRect();if(r.width<2||r.height<2)return false;const s=getComputedStyle(el);return s.visibility!=='hidden'&&s.display!=='none';}; const inLogin=(e)=>{const f=e.closest('form');return !!(f&&f.querySelector('input[type=password]'));}; const els=[...document.querySelectorAll('button, input[type=submit], input[type=button]')].filter(e=>!e.disabled&&vis(e)&&!inLogin(e)); const el=els[__I__]; if(!el) return 'missing'; try{el.scrollIntoView({block:'nearest'});}catch(e){} el.click(); return 'clicked'; })()"#;

/// 폼 작성+제출 — __I__번째 폼, 무해 값 + input/change 이벤트, 제출 버튼 우선.
const CDP_SUBMIT_JS: &str = r#"(() => { const fs=[...document.forms]; const f=fs[__I__]; if(!f) return 'missing'; let n=0; f.querySelectorAll('input[name], textarea[name]').forEach(inp=>{ const t=(inp.type||'text').toLowerCase(); if(['submit','button','reset','image','hidden','password','file'].includes(t)) return; try{inp.value='rc7x'; inp.dispatchEvent(new Event('input',{bubbles:true})); inp.dispatchEvent(new Event('change',{bubbles:true})); n++;}catch(e){} }); const btn=f.querySelector('button[type=submit], input[type=submit], button:not([type])'); if(btn){btn.click();} else if(f.requestSubmit){try{f.requestSubmit();}catch(e){f.submit();}} else {f.submit();} return 'submitted:'+n; })()"#;

/// 문서 높이 조회 — 무한 스크롤 정체 판정용.
const CDP_HEIGHT_JS: &str = r#"(() => String(document.body.scrollHeight))()"#;

/// 바닥 스크롤 — 지연 로딩·무한 스크롤 트리거 (높이 변화는 별도 조회).
const CDP_SCROLL_JS: &str = r#"(() => { window.scrollTo(0, document.body.scrollHeight); return 'ok'; })()"#;

/// 로그인 결과 — 비밀번호 폼 소멸 여부.
const CDP_LOGIN_STATE_JS: &str = r#"(() => document.querySelector('form input[type=password]') ? 'still-login' : 'no-login-form')()"#;

/// SPA 로그인 스크립트 — 비밀번호 폼 탐색·채움·제출. 자격은 JSON 이스케이프 주입.
/// 256자 초과 자격은 호출자가 거부한다 (주입 길이 상한).
fn cdp_login_js(user: &str, pass: &str) -> String {
    let uj = serde_json::to_string(user).unwrap_or_default();
    let pj = serde_json::to_string(pass).unwrap_or_default();
    format!(
        r#"(() => {{ const f=[...document.forms].find(f=>f.querySelector('input[type=password]')); if(!f) return 'noform'; const u=[...f.querySelectorAll('input')].find(i=>!['password','submit','button','hidden','checkbox','radio','file'].includes((i.type||'text').toLowerCase())); const p=f.querySelector('input[type=password]'); if(!u||!p) return 'nofield'; u.value={uj}; p.value={pj}; try{{u.dispatchEvent(new Event('input',{{bubbles:true}}));p.dispatchEvent(new Event('input',{{bubbles:true}}));}}catch(e){{}} const b=f.querySelector('button[type=submit],input[type=submit],button:not([type])'); if(b){{b.click();}} else if(f.requestSubmit){{try{{f.requestSubmit();}}catch(e){{f.submit();}}}} else {{f.submit();}} return 'submitted'; }})()"#
    )
}

/// Cookie 헤더 분해 — CDP Network.setCookie 주입용 (최대 20쌍).
fn parse_cookie_pairs(header: &str) -> Vec<(String, String)> {
    header
        .split(';')
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            let k = k.trim().to_string();
            let v = v.trim().trim_matches('"').to_string();
            if k.is_empty() || v.is_empty() || k.len() > 128 || v.len() > 4096 {
                return None;
            }
            if !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                return None;
            }
            Some((k, v))
        })
        .take(20)
        .collect()
}

/// 상태 URL 정규화 — 끝 슬래시 제거 (방문 판정용).
fn cdp_norm_url(u: &str) -> String {
    u.trim_end_matches('/').to_string()
}

/// CDP 렌더 — DevTools 로 내비게이트 후 DOM·네트워크 표면 + 상호작용 상태 수집.
/// 실패하면 None (호출자가 --dump-dom 으로 폴백). 전체 60초 상한.
/// 동일호스트 링크 탐색은 항상, 버튼·폼은 danger 동의 시에만 수행한다.
pub fn cdp_render(
    url: &str,
    cfg: &SweepConfig,
    bin: &std::path::Path,
    agent: &ureq::Agent,
    deadline: Instant,
) -> Option<CdpSurface> {
    #[cfg(test)]
    let _browser_guard = browser_test_guard();
    let start = Instant::now();
    let budget = Duration::from_secs(60);
    let profile = std::env::temp_dir()
        .join(format!("rc7cdp-{}-{}", std::process::id(), chrono::Utc::now().timestamp_millis()));
    let mut cmd = std::process::Command::new(bin);
    cmd.args([
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--ignore-certificate-errors",
        "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=0",
        &format!("--user-data-dir={}", profile.display()),
        "about:blank",
    ]);
    hide_window_probe(&mut cmd);
    let mut guard = CdpGuard {
        child: Some(cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).spawn().ok()?),
        profile,
    };
    // DevTools 포트 — stderr 리더 스레드로 파싱 (12초).
    let (tx, rx) = std::sync::mpsc::channel();
    if let Some(mut err) = guard.child.as_mut().and_then(|c| c.stderr.take()) {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                match err.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(p) = parse_devtools_port(&String::from_utf8_lossy(&buf)) {
                            let _ = tx.send(p);
                            return;
                        }
                        if buf.len() > 65536 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(0);
        });
    }
    let dev_port = rx.recv_timeout(Duration::from_secs(12)).ok().filter(|p| *p != 0)?;
    if start.elapsed() >= budget {
        return None;
    }
    // 새 탭 + WS 접속 (/json/new 는 PUT — GET 405).
    let r = fetch(agent, "PUT", &format!("http://127.0.0.1:{dev_port}/json/new?about:blank"), &[], 65536).ok()?;
    if r.status != 200 {
        return None;
    }
    let ws_url = serde_json::from_str::<serde_json::Value>(&r.body)
        .ok()?
        .get("webSocketDebuggerUrl")?
        .as_str()?
        .to_string();
    let path = format!("/{}", ws_url.split_once("://")?.1.split_once('/')?.1);
    let mut ws = ws_connect(&format!("127.0.0.1:{dev_port}"), &path, Duration::from_secs(8))?;
    let mut next_id = 1u64;
    cdp_send(&mut ws, cdp_nid(&mut next_id), "Page.enable", "{}")?;
    cdp_send(&mut ws, cdp_nid(&mut next_id), "Network.enable", "{}")?;
    // 세션 쿠키 주입 — 인증 SPA 상태 도달용 (best-effort).
    cdp_inject_cookies(&mut ws, &mut next_id, cfg, url);
    let url_json = serde_json::to_string(url).unwrap_or_default();
    cdp_send(&mut ws, cdp_nid(&mut next_id), "Page.navigate", &format!(r#"{{"url":{url_json}}}"#))?;
    // 로드 대기 + XHR 수집 (10초).
    let mut api_urls: Vec<String> = Vec::new();
    cdp_wait_load(&mut ws, url, Duration::from_secs(10), &mut api_urls, &start, budget);
    std::thread::sleep(Duration::from_millis(1200)); // SPA 정착
    if start.elapsed() >= budget {
        return None;
    }
    let dom = cdp_eval_dom(&mut ws, &mut next_id, &start, budget, url, &mut api_urls).filter(|d| d.trim().len() >= 200)?;
    let mut surface = CdpSurface { dom, api_urls, states: Vec::new(), scrolled: 0, authenticated: false, session_cookie: None };
    // 무한 스크롤 — 지연 로딩 콘텐츠를 끌어낸 뒤 DOM을 갱신한다.
    if start.elapsed() < budget {
        let rounds = cdp_scroll(&mut ws, &mut next_id, &start, budget, url, &mut surface.api_urls);
        surface.scrolled += rounds;
        if rounds > 0 {
            if let Some(d) = cdp_eval_dom(&mut ws, &mut next_id, &start, budget, url, &mut surface.api_urls) {
                if d.trim().len() >= 200 {
                    surface.dom = d;
                }
            }
        }
    }
    // SPA 로그인 — 세션 없이 LoginConfig만 있으면 브라우저에서 직접 로그인한다.
    if start.elapsed() < budget {
        if let Some(sess) = cdp_login(&mut ws, &mut next_id, cfg, &start, budget, url, &mut surface.api_urls) {
            surface.authenticated = true;
            surface.session_cookie = Some(sess);
            if let Some(d) = cdp_eval_dom(&mut ws, &mut next_id, &start, budget, url, &mut surface.api_urls) {
                if d.trim().len() >= 200 {
                    surface.dom = d;
                }
            }
        }
    }
    // 상호작용 탐색 — 동일호스트 링크(항상) + 버튼·폼(danger).
    cdp_explore(&mut ws, &mut next_id, url, cfg, deadline, start, budget, &mut surface);
    // 정리 — 탭 닫기 시도 후 가드가 프로세스·프로필 처리.
    let _ = cdp_send(&mut ws, cdp_nid(&mut next_id), "Page.close", "{}");
    Some(surface)
}

/// CDP 명령 id 발급.
fn cdp_nid(next: &mut u64) -> u64 {
    let v = *next;
    *next = next.wrapping_add(1).max(1);
    v
}

/// CDP 생존 확인 — 예산·기한·취소.
fn cdp_live(start: &Instant, budget: Duration, deadline: Instant, cfg: &SweepConfig) -> bool {
    start.elapsed() < budget && Instant::now() < deadline && !cancelled(cfg)
}

/// XHR 수집 — Network.requestWillBeSent 동일호스트 http(s)만 (최대 200).
fn cdp_collect_xhr(msg: &str, page_url: &str, api_urls: &mut Vec<String>) {
    if let Some(u) = cdp_request_url(msg) {
        if cdp_same_host(&u, page_url) && api_urls.len() < 200 && !api_urls.contains(&u) {
            api_urls.push(u);
        }
    }
}

/// 로드 대기 — loadEventFired 또는 시한, XHR 상시 수집.
fn cdp_wait_load(
    ws: &mut std::net::TcpStream,
    page_url: &str,
    wait: Duration,
    api_urls: &mut Vec<String>,
    start: &Instant,
    budget: Duration,
) {
    let until = Instant::now() + wait;
    while Instant::now() < until && start.elapsed() < budget {
        let msg = match ws_recv_text(ws, Duration::from_secs(2)) {
            Some(m) => m,
            None => break,
        };
        cdp_collect_xhr(&msg, page_url, api_urls);
        if msg.contains("Page.loadEventFired") && api_urls.len() >= 200 {
            break;
        }
    }
}

/// Runtime.evaluate 문자열 결과 대기 — 대기 중 XHR도 수집 (상호작용 직후 이벤트 유실 방지).
#[allow(clippy::too_many_arguments)]
fn cdp_eval_value(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    expr: &str,
    wait: Duration,
    start: &Instant,
    budget: Duration,
    page_url: &str,
    api_urls: &mut Vec<String>,
) -> Option<String> {
    let id = cdp_nid(next_id);
    let ej = serde_json::to_string(expr).unwrap_or_default();
    cdp_send(ws, id, "Runtime.evaluate", &format!(r#"{{"expression":{ej},"returnByValue":true}}"#))?;
    let until = Instant::now() + wait;
    while Instant::now() < until && start.elapsed() < budget {
        let msg = ws_recv_text(ws, Duration::from_secs(2))?;
        cdp_collect_xhr(&msg, page_url, api_urls);
        if let Some(v) = cdp_eval_html(&msg, id) {
            return Some(v);
        }
    }
    None
}

/// 현재 DOM.
fn cdp_eval_dom(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    start: &Instant,
    budget: Duration,
    page_url: &str,
    api_urls: &mut Vec<String>,
) -> Option<String> {
    cdp_eval_value(ws, next_id, "document.documentElement.outerHTML", Duration::from_secs(8), start, budget, page_url, api_urls)
}

/// 현재 location.href.
fn cdp_location(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    start: &Instant,
    budget: Duration,
    page_url: &str,
    api_urls: &mut Vec<String>,
) -> Option<String> {
    cdp_eval_value(ws, next_id, "location.href", Duration::from_secs(6), start, budget, page_url, api_urls)
}

/// 후보 발견 — JSON 파싱 실패 시 빈 목록.
fn cdp_discover(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    start: &Instant,
    budget: Duration,
    page_url: &str,
    api_urls: &mut Vec<String>,
) -> Vec<CdpCand> {
    cdp_eval_value(ws, next_id, CDP_DISCOVER_JS, Duration::from_secs(8), start, budget, page_url, api_urls)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// 세션 쿠키 주입 — best-effort (실패해도 진행).
fn cdp_inject_cookies(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    cfg: &SweepConfig,
    url: &str,
) {
    let Some(cookie) = cfg.cookie.as_deref() else { return };
    let pairs = parse_cookie_pairs(cookie);
    if pairs.is_empty() {
        return;
    }
    let domain = url.split_once("://").and_then(|(_, r)| r.split('/').next()).unwrap_or("");
    let domain = domain.split('@').next_back().unwrap_or("").split(':').next().unwrap_or("");
    if domain.is_empty() {
        return;
    }
    for (k, v) in pairs {
        let kj = serde_json::to_string(&k).unwrap_or_default();
        let vj = serde_json::to_string(&v).unwrap_or_default();
        let dj = serde_json::to_string(domain).unwrap_or_default();
        let _ = cdp_send(ws, cdp_nid(next_id), "Network.setCookie",
            &format!(r#"{{"name":{kj},"value":{vj},"domain":{dj}}}"#));
        // 응답 대기 없음 — best-effort.
    }
}

/// 무한 스크롤 수집 — 바닥 스크롤 후 문서 높이 증가가 멈출 때까지 반복 (최대 5회).
/// 지연 로딩·무한 스크롤 콘텐츠의 XHR·DOM을 끌어낸다. 효과 없으면 0을 반환한다.
fn cdp_scroll(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    start: &Instant,
    budget: Duration,
    page_url: &str,
    api_urls: &mut Vec<String>,
) -> usize {
    let mut rounds = 0usize;
    let mut last_h =
        cdp_eval_value(ws, next_id, CDP_HEIGHT_JS, Duration::from_secs(6), start, budget, page_url, api_urls)
            .unwrap_or_default();
    if last_h.is_empty() {
        return 0;
    }
    for _ in 0..5 {
        if start.elapsed() >= budget {
            break;
        }
        let _ = cdp_eval_value(ws, next_id, CDP_SCROLL_JS, Duration::from_secs(6), start, budget, page_url, api_urls);
        std::thread::sleep(Duration::from_millis(500)); // 지연 로딩 정착
        cdp_wait_load(ws, page_url, Duration::from_secs(1), api_urls, start, budget);
        let h =
            cdp_eval_value(ws, next_id, CDP_HEIGHT_JS, Duration::from_secs(6), start, budget, page_url, api_urls)
                .unwrap_or_default();
        if h.is_empty() || h == last_h {
            break;
        }
        last_h = h;
        rounds += 1;
    }
    rounds
}

/// 브라우저 쿠키 회수 — Network.getCookies → Cookie 헤더 값 (최대 20쌍).
fn cdp_cookies(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    start: &Instant,
    budget: Duration,
    page_url: &str,
    api_urls: &mut Vec<String>,
) -> Option<String> {
    let id = cdp_nid(next_id);
    cdp_send(ws, id, "Network.getCookies", "{}")?;
    let until = Instant::now() + Duration::from_secs(6);
    while Instant::now() < until && start.elapsed() < budget {
        let msg = match ws_recv_text(ws, Duration::from_secs(2)) {
            Some(m) => m,
            None => break,
        };
        cdp_collect_xhr(&msg, page_url, api_urls);
        // 이벤트 메시지(id 없음)는 건너뛰고 우리 응답만 취한다.
        let v: serde_json::Value = match serde_json::from_str(&msg) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("id").and_then(|i| i.as_u64()) != Some(id) {
            continue;
        }
        let arr = match v.get("result").and_then(|r| r.get("cookies")).and_then(|c| c.as_array()) {
            Some(a) => a,
            None => return None,
        };
        let pairs: Vec<String> = arr
            .iter()
            .filter_map(|c| {
                let n = c.get("name")?.as_str()?;
                let val = c.get("value")?.as_str()?;
                if n.is_empty() || n.len() > 128 || val.len() > 4096 {
                    return None;
                }
                Some(format!("{n}={val}"))
            })
            .take(20)
            .collect();
        if pairs.is_empty() {
            return None;
        }
        return Some(pairs.join("; "));
    }
    None
}

/// SPA 로그인 — LoginConfig가 있고 아직 세션이 없을 때 브라우저에서 직접 로그인한다.
/// gate_login(HTTP 폼 제출)이 통하지 않는 SPA(XHR·JS 로그인)를 메운다.
/// 성공 시 세션 쿠키를 반환한다. 자격 256자 초과·폼 없음·폼 잔류 시 None.
fn cdp_login(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    cfg: &SweepConfig,
    start: &Instant,
    budget: Duration,
    page_url: &str,
    api_urls: &mut Vec<String>,
) -> Option<String> {
    let lc = cfg.login.as_ref()?;
    if cfg.cookie.as_ref().map(|c| !c.trim().is_empty()).unwrap_or(false) {
        return None; // 이미 세션 보유 (게이트 로그인 성공)
    }
    if lc.username.len() > 256 || lc.password.len() > 256 || lc.username.is_empty() {
        return None;
    }
    let js = cdp_login_js(&lc.username, &lc.password);
    let r = cdp_eval_value(ws, next_id, &js, Duration::from_secs(8), start, budget, page_url, api_urls)?;
    if r != "submitted" {
        return None;
    }
    std::thread::sleep(Duration::from_millis(1500));
    cdp_wait_load(ws, page_url, Duration::from_secs(3), api_urls, start, budget);
    let st = cdp_eval_value(ws, next_id, CDP_LOGIN_STATE_JS, Duration::from_secs(6), start, budget, page_url, api_urls)?;
    if st != "no-login-form" {
        return None; // 폼 잔류 — 실패/캡차/2단계 가능, 조용히 포기 (차단 표면은 별도 보고)
    }
    cdp_cookies(ws, next_id, start, budget, page_url, api_urls)
}

/// SPA 상호작용 탐색 — 링크 상태 3 + 버튼 2 + 폼 2 (버튼·폼은 danger만).
/// 파괴 의심·로그인 폼·방문 URL은 건너뛴다. 부분 성공 허용.
fn cdp_explore(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    page_url: &str,
    cfg: &SweepConfig,
    deadline: Instant,
    start: Instant,
    budget: Duration,
    surface: &mut CdpSurface,
) {
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    visited.insert(cdp_norm_url(page_url));
    if let Some(loc) = cdp_location(ws, next_id, &start, budget, page_url, &mut surface.api_urls) {
        visited.insert(cdp_norm_url(&loc));
    }
    let mut frontier: Vec<String> = Vec::new();
    let mut clicked: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut submitted: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let (mut link_used, mut btn_used, mut form_used) = (0u8, 0u8, 0u8);
    loop {
        if surface.states.len() >= 6 || !cdp_live(&start, budget, deadline, cfg) {
            break;
        }
        let cands = cdp_discover(ws, next_id, &start, budget, page_url, &mut surface.api_urls);
        if cands.is_empty() && frontier.is_empty() {
            break;
        }
        // 링크 수집 — 동일호스트·비파괴·미방문.
        for c in cands.iter().filter(|c| c.kind == "link") {
            let Some(h) = c.href.as_deref() else { continue };
            if h.len() > 512 || !(h.starts_with("http://") || h.starts_with("https://")) {
                continue;
            }
            if !cdp_same_host(h, page_url) || destructive_text(&format!("{} {h}", c.text)) {
                continue;
            }
            let n = cdp_norm_url(h);
            if !visited.contains(&n) && !frontier.iter().any(|f| cdp_norm_url(f) == n) {
                frontier.push(h.to_string());
            }
        }
        // danger 버튼·폼 — 현재 상태에서 각 최대 1개.
        if cfg.danger {
            if btn_used < 2 {
                let mut bi = 0usize;
                for c in cands.iter().filter(|c| c.kind == "button") {
                    let this = bi;
                    bi += 1;
                    if destructive_text(&c.text) {
                        continue;
                    }
                    let here = cdp_location(ws, next_id, &start, budget, page_url, &mut surface.api_urls).unwrap_or_default();
                    if !clicked.insert((cdp_norm_url(&here), c.text.clone())) {
                        continue;
                    }
                    cdp_click_button(ws, next_id, this, page_url, &start, budget, &mut surface.api_urls);
                    btn_used += 1;
                    cdp_record_state(ws, next_id, &start, budget, &mut visited, surface, page_url);
                    break;
                }
            }
            if form_used < 2 && cdp_live(&start, budget, deadline, cfg) {
                let mut fi = 0usize;
                for c in cands.iter().filter(|c| c.kind == "form") {
                    let this = fi;
                    fi += 1;
                    if c.has_password || c.fields.is_empty() {
                        continue;
                    }
                    let act = c.action.as_deref().unwrap_or("");
                    if destructive_text(&format!("{} {}", c.text, act)) {
                        continue;
                    }
                    let here = cdp_location(ws, next_id, &start, budget, page_url, &mut surface.api_urls).unwrap_or_default();
                    if !submitted.insert((cdp_norm_url(&here), act.to_string())) {
                        continue;
                    }
                    cdp_submit_form(ws, next_id, this, page_url, &start, budget, &mut surface.api_urls);
                    form_used += 1;
                    cdp_record_state(ws, next_id, &start, budget, &mut visited, surface, page_url);
                    break;
                }
            }
        }
        // 다음 링크 상태.
        if link_used >= 3 {
            break;
        }
        let next = frontier
            .iter()
            .position(|f| !visited.contains(&cdp_norm_url(f)))
            .map(|i| frontier.remove(i));
        let Some(next) = next else { break };
        if !cdp_live(&start, budget, deadline, cfg) {
            break;
        }
        let nj = serde_json::to_string(&next).unwrap_or_default();
        if cdp_send(ws, cdp_nid(next_id), "Page.navigate", &format!(r#"{{"url":{nj}}}"#)).is_none() {
            break;
        }
        link_used += 1;
        cdp_wait_load(ws, page_url, Duration::from_secs(4), &mut surface.api_urls, &start, budget);
        std::thread::sleep(Duration::from_millis(800));
        // 링크 상태에서도 무한 스크롤 1회분 수집 (지연 로딩 표면).
        if cdp_live(&start, budget, deadline, cfg) {
            let rounds = cdp_scroll(ws, next_id, &start, budget, page_url, &mut surface.api_urls);
            surface.scrolled += rounds;
        }
        cdp_record_state(ws, next_id, &start, budget, &mut visited, surface, page_url);
    }
}

/// 버튼 클릭 후 정착 — location 폴링 3초 + XHR 드레인.
fn cdp_click_button(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    idx: usize,
    page_url: &str,
    start: &Instant,
    budget: Duration,
    api_urls: &mut Vec<String>,
) {
    let before = cdp_location(ws, next_id, start, budget, page_url, api_urls).unwrap_or_default();
    let js = CDP_CLICK_JS.replace("__I__", &idx.to_string());
    let _ = cdp_eval_value(ws, next_id, &js, Duration::from_secs(6), start, budget, page_url, api_urls);
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until && start.elapsed() < budget {
        std::thread::sleep(Duration::from_millis(300));
        if let Some(loc) = cdp_location(ws, next_id, start, budget, page_url, api_urls) {
            if cdp_norm_url(&loc) != cdp_norm_url(&before) {
                break;
            }
        }
    }
    cdp_wait_load(ws, page_url, Duration::from_secs(1), api_urls, start, budget);
}

/// 폼 제출 후 정착 — 내비게이션 대기 4초 + XHR 드레인.
fn cdp_submit_form(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    idx: usize,
    page_url: &str,
    start: &Instant,
    budget: Duration,
    api_urls: &mut Vec<String>,
) {
    let js = CDP_SUBMIT_JS.replace("__I__", &idx.to_string());
    let _ = cdp_eval_value(ws, next_id, &js, Duration::from_secs(6), start, budget, page_url, api_urls);
    cdp_wait_load(ws, page_url, Duration::from_secs(4), api_urls, start, budget);
    std::thread::sleep(Duration::from_millis(800));
}

/// 현재 상태 기록 — 미방문 URL이면 DOM과 함께 저장.
fn cdp_record_state(
    ws: &mut std::net::TcpStream,
    next_id: &mut u64,
    start: &Instant,
    budget: Duration,
    visited: &mut std::collections::HashSet<String>,
    surface: &mut CdpSurface,
    page_url: &str,
) {
    let Some(loc) = cdp_location(ws, next_id, start, budget, page_url, &mut surface.api_urls) else { return };
    if loc.len() > 512 || !visited.insert(cdp_norm_url(&loc)) {
        return;
    }
    if let Some(dom) = cdp_eval_dom(ws, next_id, start, budget, page_url, &mut surface.api_urls) {
        if dom.trim().len() >= 200 {
            surface.states.push(CdpState { url: loc, dom });
        }
    }
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

/// 게이트 폼 로그인 — 성공 시 `Cookie` 헤더값 반환.
/// 폼 탐색: 지정 login_url → DOM → /login 폴백. 성공 판정은 기본자격 프로브와 동일
/// (신규 세션 쿠키 + 로그인 폼 소멸 + 오류 키워드 없음). 비밀번호는 절대 기록하지 않는다.
fn gate_login(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    dom: &str,
    lc: &LoginConfig,
    counter: &AtomicUsize,
) -> Option<String> {
    if lc.username.trim().is_empty() || lc.password.is_empty() {
        return None;
    }
    let form = if let Some(u) = lc.login_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        let (_, body) = get_with_cookie(agent, u, None, counter)?;
        parse_login_form(&body, base_url)?
    } else {
        parse_login_form(dom, base_url).or_else(|| {
            let (_, b) = get_with_cookie(agent, &format!("{base_url}/login"), None, counter)?;
            parse_login_form(&b, base_url)
        })?
    };
    let r = submit_login(agent, cfg, &form, &lc.username, &lc.password, counter).ok()?;
    if !(200..400).contains(&r.status) {
        return None;
    }
    if !new_session_cookie(&[], &r.cookies) || has_login_form(&r.body) || has_error_kw(&r.body) {
        return None;
    }
    let jar: Vec<String> = r
        .cookies
        .iter()
        .map(|c| c.split(';').next().unwrap_or("").trim().to_string())
        .filter(|nv| nv.contains('=') && nv.len() < 4096)
        .collect();
    if jar.is_empty() {
        return None;
    }
    Some(jar.join("; "))
}

/// 저장형 탐지용 폼 — action 절대 URL + POST 여부 + 입력 필드명.
#[derive(Debug, Clone)]
pub struct StoredForm {
    pub action: String,
    pub post: bool,
    pub fields: Vec<String>,
    /// password 입력 포함 여부 — 로그인 폼은 기본자격 프로브 영역이라 stored 에서 제외 (잠금 방지).
    pub is_login: bool,
}

/// 폼 추출 — 최대 3개. 외부 action·상대경로 제외, password/hidden/제출계열 제외.
/// action 생략 시 페이지 자신을 대상으로 한다.
pub fn extract_forms(html: &str, page_url: &str, base_url: &str) -> Vec<StoredForm> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(fs) = find_ascii_ci(html, "<form", pos) {
        let tag_end = html[fs..].find('>').map(|i| fs + i + 1).unwrap_or(html.len());
        let tag = &html[fs..tag_end.min(html.len())];
        let body_end = find_ascii_ci(html, "</form>", tag_end).unwrap_or(html.len());
        let fbody = &html[tag_end.min(html.len())..body_end];
        pos = body_end + 7;
        let action = match attr_value(tag, "action") {
            None => page_url.to_string(),
            Some(a) if a.is_empty() => page_url.to_string(),
            Some(a) if a.starts_with('/') && !a.starts_with("//") => format!("{base_url}{a}"),
            Some(a) if a == base_url || a.starts_with(&format!("{base_url}/")) || a.starts_with(&format!("{base_url}?")) => a.to_string(),
            Some(_) => continue,
        };
        let method_post = attr_value(tag, "method").map(|m| !m.eq_ignore_ascii_case("get")).unwrap_or(true);
        let mut fields: Vec<String> = Vec::new();
        let mut is_login = false;
        let mut ip = 0;
        while let Some(found) = find_ascii_ci(fbody, "<input", ip) {
            let ie = fbody[found..].find('>').map(|i| found + i + 1).unwrap_or(fbody.len());
            let itag = &fbody[found..ie.min(fbody.len())];
            ip = ie; // ie 는 이미 '>' 다음 — +1 금지 (연속 input 누락 회귀)
            let typ = attr_value(itag, "type").map(|s| s.to_lowercase()).unwrap_or_else(|| "text".into());
            if typ == "password" {
                is_login = true;
            }
            let Some(name) = attr_value(itag, "name") else { continue };
            if name.is_empty() || name.len() > 64 {
                continue;
            }
            if ["password", "hidden", "submit", "button", "file", "image", "reset", "checkbox", "radio"].contains(&typ.as_str()) {
                continue;
            }
            if !fields.contains(&name.to_string()) {
                fields.push(name.to_string());
            }
            if fields.len() >= 8 {
                break;
            }
        }
        let mut tp = 0;
        while let Some(found) = find_ascii_ci(fbody, "<textarea", tp) {
            let te = fbody[found..].find('>').map(|i| found + i + 1).unwrap_or(fbody.len());
            let ttag = &fbody[found..te.min(fbody.len())];
            tp = te; // te 는 이미 '>' 다음 — +1 금지
            if let Some(name) = attr_value(ttag, "name") {
                if !name.is_empty() && name.len() <= 64 && !fields.contains(&name.to_string()) {
                    fields.push(name.to_string());
                }
            }
            if fields.len() >= 8 {
                break;
            }
        }
        if fields.is_empty() {
            continue;
        }
        out.push(StoredForm { action, post: method_post, fields, is_login });
        if out.len() >= 3 {
            break;
        }
    }
    out
}

/// 폼 제출 — 전 필드 채움 (POST form-urlencoded / GET 쿼리).
fn submit_form_values(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    form: &StoredForm,
    values: &[(String, String)],
    counter: &AtomicUsize,
) -> Option<(u16, String)> {
    let enc: Vec<String> = values.iter().map(|(k, v)| format!("{}={}", pct_encode(k), pct_encode(v))).collect();
    if form.post {
        counter.fetch_add(1, Ordering::Relaxed);
        let ch = cfg.cookie_headers();
        let mut req = agent.post(&form.action);
        for (k, v) in &ch {
            req = req.set(k, v);
        }
        let r = match req.set("Content-Type", "application/x-www-form-urlencoded").send_string(&enc.join("&")) {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(_) => return None,
        };
        let st = r.status();
        let body = r.into_string().unwrap_or_default();
        Some((st, body))
    } else {
        let sep = if form.action.contains('?') { '&' } else { '?' };
        get_with_cookie(agent, &format!("{}{sep}{}", form.action, enc.join("&")), cfg.cookie.as_deref(), counter)
    }
}

/// Stored XSS 2-pass — 폼에 서로 다른 마커 2종 저장 후 재방문 반사 확인.
/// 쓰기 행위라 danger 동의 필수. 재방문은 폼 페이지 + action 양쪽.
pub fn probe_stored_xss(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    seed_url: &str,
    seed_html: &str,
    counter: &AtomicUsize,
) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    if !cfg.danger {
        return out;
    }
    // 폼 수집 — 시드 + 링크 페이지에서 비로그인 폼 3개가 찰 때까지 (최대 12페이지).
    let mut forms: Vec<(String, StoredForm)> = Vec::new();
    for f in extract_forms(seed_html, seed_url, base_url) {
        if f.is_login {
            continue;
        }
        forms.push((seed_url.to_string(), f));
        if forms.len() >= 3 {
            break;
        }
    }
    if forms.len() < 3 {
        for link in extract_links(seed_html, base_url).into_iter().take(12) {
            if cancelled(cfg) {
                return out;
            }
            if forms.len() >= 3 {
                break;
            }
            if let Some((200, b)) = get_with_cookie(agent, &link, cfg.cookie.as_deref(), counter) {
                for f in extract_forms(&b, &link, base_url) {
                    if f.is_login {
                        continue;
                    }
                    forms.push((link.clone(), f));
                    if forms.len() >= 3 {
                        break;
                    }
                }
            }
        }
    }
    for (purl, form) in forms {
        if cancelled(cfg) {
            return out;
        }
        if form.is_login {
            continue; // 로그인 폼은 기본자격 프로브 영역 (잠금 방지)
        }
        for field in form.fields.iter().take(2) {
            let base_m = format!("rc7stored{}-{}", std::process::id(), chrono::Utc::now().timestamp_millis());
            let mut found = 0;
            let mut found_at = String::new();
            for tag in ["a", "b"] {
                if cancelled(cfg) {
                    return out;
                }
                let m = format!("{base_m}-{tag}-{field}");
                let values: Vec<(String, String)> = form
                    .fields
                    .iter()
                    .map(|f| (f.clone(), if f == field { m.clone() } else { "rc7x".to_string() }))
                    .collect();
                std::thread::sleep(Duration::from_millis(120));
                submit_form_values(agent, cfg, &form, &values, counter);
                std::thread::sleep(Duration::from_millis(120));
                for rv in [purl.as_str(), form.action.as_str()] {
                    if let Some((200, b)) = get_with_cookie(agent, rv, cfg.cookie.as_deref(), counter) {
                        if b.contains(&m) {
                            found += 1;
                            found_at = rv.to_string();
                            break;
                        }
                    }
                }
            }
            if found == 2 {
                out.push(hit("stored-xss", Severity::High, form.action.clone(),
                    format!("Stored XSS 확정 — 재방문 반사 (폼 '{field}')"),
                    format!("서로 다른 마커 2종 저장 후 {found_at} 재방문에서 반사 — 저장형 XSS 확정 (동의 기반)"),
                    format!("marker={base_m}"), format!("POST {} → GET {found_at}", form.action), None));
                return out; // 1건 확정으로 충분
            } else if found == 1 {
                out.push(hit("stored-xss", Severity::Medium, form.action.clone(),
                    format!("Stored XSS 의심 — 1종 반사 (폼 '{field}')"),
                    "마커 1종만 재방문 반사 — 저장 동작 불완전 (동의 기반)".into(),
                    format!("marker={base_m}"), format!("POST {} → GET", form.action), None));
            }
        }
    }
    out
}

/// 저장형 의심 점수 — POST·비로그인 폼의 지속 힌트 (필드명·액션). 0이면 제외.
fn stored_candidate_score(form: &StoredForm) -> u8 {
    if !form.post || form.is_login {
        return 0;
    }
    let mut score = 0u8;
    for f in &form.fields {
        if ["msg", "message", "comment", "content", "body", "text", "memo", "review", "title",
            "name", "nick", "nickname", "author", "post", "article", "description", "feedback"]
            .contains(&f.to_lowercase().as_str())
        {
            score += 1;
        }
    }
    let al = form.action.to_lowercase();
    if ["comment", "guestbook", "/gb", "post", "review", "board", "forum", "memo", "article", "contact"]
        .iter()
        .any(|k| al.contains(k))
    {
        score += 1;
    }
    score
}

/// Stored-XSS 후보 표면화 (세이프 모드 전용) — 쓰기 없이 저장형 의심 폼만 Info 보고.
/// danger 모드에서는 실제 2-pass가 돌므로 호출하지 않는다. 최대 5건.
pub fn probe_stored_candidates(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    seed_url: &str,
    seed_html: &str,
    extra_pages: &[(&str, &str)],
    counter: &AtomicUsize,
) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    if cfg.danger {
        return out;
    }
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut pages: Vec<(String, String)> = Vec::new();
    seen.insert(seed_url.to_string());
    pages.push((seed_url.to_string(), seed_html.to_string()));
    for (u, b) in extra_pages {
        if seen.insert(u.to_string()) {
            pages.push((u.to_string(), b.to_string()));
        }
    }
    // 시드 링크 페이지 수집 (GET만, 최대 12).
    for link in extract_links(seed_html, base_url).into_iter().take(12) {
        if cancelled(cfg) {
            return out;
        }
        if seen.contains(&link) {
            continue;
        }
        if let Some((200, b)) = get_with_cookie(agent, &link, cfg.cookie.as_deref(), counter) {
            seen.insert(link.clone());
            pages.push((link, b));
        }
    }
    for (purl, html) in &pages {
        for f in extract_forms(html, purl, base_url) {
            if stored_candidate_score(&f) == 0 {
                continue;
            }
            out.push(hit("stored-xss", Severity::Info, f.action.clone(),
                format!("Stored-XSS 후보 — 수동 확인 (폼 '{}')", f.fields.join(",")),
                format!("쓰기 없이 표면만 보고 — danger 모드에서 2-pass 확정 가능 · POST {} ({} 발견)",
                    f.action, purl),
                String::new(), "GET 수집 (미전송)".into(), None));
            if out.len() >= 5 {
                return out;
            }
        }
    }
    out
}

/// 폼 제출 추가 금지 어휘 — 크롤 금지 + 쓰기 파괴 의심.
const FORM_EXTRA_FORBIDDEN: &[&str] =
    &["purge", "drop", "kill", "withdraw", "terminate", "suspend", "ban", "탈퇴", "삭제", "/admin/destructive"];

/// 파괴 의심 텍스트 — 크롤 금지 + 폼 제출 금지 어휘 (SPA 후보·액션 공통, 과차단=안전 방향).
fn destructive_text(s: &str) -> bool {
    let l = s.to_lowercase();
    CRAWL_FORBIDDEN.iter().any(|k| l.contains(k)) || FORM_EXTRA_FORBIDDEN.iter().any(|k| l.contains(k))
}

/// 폼 제출 금지 액션 — 동의 모드에서도 제외, 감사 기록.
fn form_action_forbidden(action: &str) -> bool {
    destructive_text(action)
}

/// danger 동의 기반 폼 크롤 — 비로그인·비파괴 폼에 무해 값(`rc7x`) 제출,
/// 200 응답을 크롤 표면에 편입한다. 제출·제외 모두 감사 기록. 최대 4폼.
pub fn crawl_forms_danger(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    seed_url: &str,
    seed_html: &str,
    counter: &AtomicUsize,
) -> (Vec<CrawledPage>, Vec<ProbeHit>) {
    let mut pages = Vec::new();
    let mut out = Vec::new();
    if !cfg.danger {
        return (pages, out);
    }
    // 폼 수집 — 시드 + 링크 페이지 (최대 12, GET).
    let mut forms: Vec<(String, StoredForm)> = Vec::new();
    for f in extract_forms(seed_html, seed_url, base_url) {
        if !f.is_login {
            forms.push((seed_url.to_string(), f));
        }
    }
    if forms.len() < 4 {
        for link in extract_links(seed_html, base_url).into_iter().take(12) {
            if cancelled(cfg) {
                return (pages, out);
            }
            if forms.len() >= 4 {
                break;
            }
            if let Some((200, b)) = get_with_cookie(agent, &link, cfg.cookie.as_deref(), counter) {
                for f in extract_forms(&b, &link, base_url) {
                    if f.is_login {
                        continue;
                    }
                    forms.push((link.clone(), f));
                    if forms.len() >= 4 {
                        break;
                    }
                }
            }
        }
    }
    for (purl, form) in forms.into_iter().take(4) {
        if cancelled(cfg) {
            return (pages, out);
        }
        if form_action_forbidden(&form.action) {
            out.push(hit("danger-write", Severity::Info, form.action.clone(),
                "파괴 의심 폼 제외 — 미제출".into(),
                format!("액션 금지어 포함 ({} 발견) — 동의 모드에서도 제출하지 않음", purl),
                String::new(), format!("{} {} (제외)", if form.post { "POST" } else { "GET" }, form.action), None));
            continue;
        }
        let values: Vec<(String, String)> =
            form.fields.iter().map(|f| (f.clone(), "rc7x".to_string())).collect();
        std::thread::sleep(Duration::from_millis(150));
        match submit_form_values(agent, cfg, &form, &values, counter) {
            Some((200, body)) => {
                pages.push(CrawledPage { url: form.action.clone(), body, headers: Vec::new() });
                out.push(hit("danger-write", Severity::Info, form.action.clone(),
                    "동의 기반 폼 제출 (무해 값)".into(),
                    format!("전 필드 'rc7x' 제출 → 200 ({} 발견) — 응답을 크롤 표면에 편입", purl),
                    String::new(),
                    format!("{} {} (동의 기반)", if form.post { "POST" } else { "GET" }, form.action),
                    Some(200)));
            }
            Some((st, _)) => {
                out.push(hit("danger-write", Severity::Info, form.action.clone(),
                    format!("동의 기반 폼 제출 → {st} (거부됨)"),
                    format!("무해 값 제출했으나 비정상 응답 ({} 발견) — 표면 미편입", purl),
                    String::new(),
                    format!("{} {} (동의 기반)", if form.post { "POST" } else { "GET" }, form.action),
                    Some(st)));
            }
            None => {
                out.push(hit("danger-write", Severity::Info, form.action.clone(),
                    "동의 기반 폼 제출 실패 (전송 오류)".into(),
                    format!("{} 발견 — 표면 미편입", purl),
                    String::new(),
                    format!("{} {} (동의 기반)", if form.post { "POST" } else { "GET" }, form.action),
                    None));
            }
        }
    }
    (pages, out)
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

// ── 2차 오프라인·순차 프로브 (GET-only, 추가 요청 최소) ────────────────────────────

/// 클라이언트 표면 오프라인 스캔 — 탭내빙 + CSP 우회 분석 (요청 없음).
pub fn scan_client_surface(html: &str, headers: &[(String, String)], target: &str) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    let n = count_tabnabbing(html);
    if n > 0 {
        out.push(hit("tabnabbing", Severity::Low, target.to_string(),
            format!("탭내빙 표면 — {n}개 링크"),
            "target=_blank 인데 rel=noopener/noreferrer 없음 — 새 탭에서 opener 조작 가능성에 대한 신호".into(),
            String::new(), "DOM 오프라인 스캔".into(), None));
    }
    if let Some(csp) = header(headers, "content-security-policy") {
        for w in scan_csp_weakness(csp).into_iter().take(3) {
            out.push(hit("csp-analysis", Severity::Low, target.to_string(),
                "CSP 우회 가능 지점".into(), w, one_line(csp, 200), "헤더 오프라인 분석".into(), None));
        }
    }
    out
}

/// 역직렬화 blob 관측 적중 — DOM·쿠키 텍스트에서 시그니처 보고 (요청 없음).
pub fn scan_deserialize_hits(text: &str, target: &str) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    for (sig, label) in scan_deserialize(text).into_iter().take(3) {
        out.push(hit("deserialize-sig", Severity::Medium, target.to_string(),
            format!("역직렬화 입력 지점 — {label}"),
            "관측만 (전송 없음) — 역직렬화 가젯 투입 가능성에 대한 신호, 실제 평가는 에이전트 후속 담당".into(),
            one_line(&sig, 60), "오프라인 관측".into(), None));
    }
    out
}

/// JWT 심화 오프라인 — kid/jku/x5u/x5c 클레임 존재 보고 (무전송).
pub fn jwt_offline_hits(cookie: &str, target: &str) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    for pair in cookie.split(';') {
        let Some((name, value)) = pair.split_once('=') else { continue };
        let value = value.trim().trim_matches('"');
        let Some((h, _, _)) = jwt_segments(value) else { continue };
        let claims = jwt_risky_claims(h);
        if !claims.is_empty() {
            out.push(hit("jwt-offline", Severity::Medium, target.to_string(),
                format!("JWT 위험 헤더 클레임 — {name} ({})", claims.join("/")),
                "kid SQLi/경로 조작·jku/x5u 외부 키 주입 가능성에 대한 신호 — 오프라인 판독, 전송 없음".into(),
                String::new(), "오프라인 판독".into(), None));
            break; // 쿠키당 1건
        }
    }
    out
}

/// 캐시 오염 안전 2단계 — 고유 cache-buster + unkeyed 헤더 canary, 2차 무헤더 재요청.
/// 오염은 격리 키(buster) 안에서만 확인하므로 타 사용자 캐시를 더럽히지 않는다.
pub fn probe_cache_isolation(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    counter: &AtomicUsize,
) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    let buster = format!("rcb{}", counter.load(Ordering::Relaxed) % 100000 + 1000);
    let canary = format!("rc7cache{buster}");
    let url = format!("{base_url}/?{buster}=1");
    let ch = cfg.cookie_headers();
    // 1차: canary 헤더 포함.
    let mut h1: Vec<(&str, &str)> = ch.iter().map(|(k, v)| (*k, *v)).collect();
    h1.push(("X-Forwarded-Host", canary.as_str()));
    counter.fetch_add(1, Ordering::Relaxed);
    let r1 = fetch(agent, "GET", &url, &h1, BODY_CAP);
    if cancelled(cfg) {
        return out;
    }
    // 2차: 동일 buster, 헤더 없이 — canary 가 남아있으면 캐시 저장 신호.
    counter.fetch_add(1, Ordering::Relaxed);
    let r2 = fetch(agent, "GET", &url, &ch, BODY_CAP);
    if let (Ok(a), Ok(b)) = (r1, r2) {
        if !a.body.contains(&canary) {
            return out; // 1차부터 미반영 — 오염 불가
        }
        if b.body.contains(&canary) {
            out.push(hit("cache-poison", Severity::Medium, url.clone(),
                "캐시 오염 신호 (격리 키)".into(),
                "unkeyed 헤더 canary 가 무헤더 재요청에도 잔류 — 동일 키 응답이 캐시되는 신호".into(),
                one_line(&b.body, 160), "GET×2 (격리)".into(), Some(b.status)));
        }
    }
    out
}

/// 세션 엔트로피 — Set-Cookie 2회 수집해 순차/짧음/평문 판정.
pub fn probe_session_entropy(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    base_headers: &[(String, String)],
    counter: &AtomicUsize,
) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    let first: Vec<&str> = header_all(base_headers, "set-cookie");
    if first.is_empty() {
        return out;
    }
    counter.fetch_add(1, Ordering::Relaxed);
    let ch = cfg.cookie_headers();
    let second: Vec<String> = fetch(agent, "GET", &format!("{base_url}/"), &ch, BODY_CAP)
        .map(|r| r.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).map(|(_, v)| v.clone()).collect())
        .unwrap_or_default();
    if cancelled(cfg) {
        return out;
    }
    let values: Vec<String> = first.into_iter().map(|s| s.to_string()).chain(second).collect();
    // 세션 식별자 후보 값만 추출 (name=value 앞부분).
    let mut ids: Vec<String> = Vec::new();
    for sc in &values {
        let name_end = sc.find(';').unwrap_or(sc.len());
        let pair = &sc[..name_end];
        if let Some((n, v)) = pair.split_once('=') {
            let nl = n.trim().to_lowercase();
            if nl.contains("sess") || nl.contains("sid") || nl.contains("token") || nl.contains("auth") || nl == "id" || nl.contains("jwt") {
                ids.push(v.trim().to_string());
            }
        }
    }
    if ids.is_empty() {
        return out;
    }
    // 짧음 (<16자) · 순차(숫자 증감) · 평문 식별자 판정.
    let short = ids.iter().any(|v| v.len() < 16);
    let mut sequential = false;
    let nums: Vec<u64> = ids.iter().filter_map(|v| v.chars().filter(|c| c.is_ascii_digit()).collect::<String>().parse::<u64>().ok()).collect();
    if nums.len() >= 2 {
        let mut s = nums.clone();
        s.sort_unstable();
        s.dedup();
        if s.len() >= 2 && s.windows(2).any(|w| w[1] > w[0] && w[1] - w[0] < 1000) {
            sequential = ids.iter().any(|v| v.len() < 24);
        }
    }
    if sequential {
        out.push(hit("session-entropy", Severity::Medium, base_url.to_string(),
            "세션 ID 순차 발급 의심".into(),
            "연속 수집 쿠키에서 숫자 증감 패턴 — 세션 예측 가능성에 대한 신호".into(),
            String::new(), "GET×2 수집".into(), None));
    } else if short {
        out.push(hit("session-entropy", Severity::Low, base_url.to_string(),
            "짧은 세션 식별자".into(),
            "16자 미만 세션 값 — 무차별 대입 내성에 대한 약한 신호".into(),
            String::new(), "GET×2 수집".into(), None));
    }
    out
}

// ── 파괴적 프로브 (동의 게이트 — cfg.danger 일 때만) ─────────────────────────────
// 규칙: 모달 명시 동의 없이 절대 실행하지 않는다 (각 함수 선두 fail-closed).
// 기본자격 5종 상한·잠금 즉시 중단, IDOR 인접 ±2·BOLA 파라미터 ±2·증거 마스킹, 쓰기 1회+정리 시도.

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

/// BOLA 후보 ID 파라미터명 (소문자 정확 매칭).
const ID_PARAM_NAMES: &[&str] = &[
    "id", "uid", "user", "user_id", "userid", "order", "order_id", "orderid",
    "account", "account_id", "accountid", "customer_id", "invoice_id",
    "doc_id", "file_id", "post_id", "item_id", "record_id",
];

/// DOM 에서 쿼리 파라미터 ID 엔드포인트 수집 — /api/items?id=42 형태 (최대 3개).
/// 상대 경로만 (절대 URL 은 base 합성 불가). 다른 쿼리 인자는 버린다 (단순 인접 판정용).
fn extract_param_id_endpoints(dom: &str) -> Vec<(String, String, u64)> {
    let mut out: Vec<(String, String, u64)> = Vec::new();
    for chunk in dom.split(|c: char| c == '"' || c == '\'' || c == ' ' || c == '(' || c == ')' || c == '<' || c == '>') {
        let t = chunk.trim().split('#').next().unwrap_or("");
        let Some((path, query)) = t.split_once('?') else { continue };
        if !path.starts_with('/') || path.len() < 2 || path.len() > 120 || path.contains('.') {
            continue;
        }
        for pair in query.split('&') {
            let Some((k, v)) = pair.split_once('=') else { continue };
            if !ID_PARAM_NAMES.contains(&k.trim().to_ascii_lowercase().as_str()) {
                continue;
            }
            let Ok(id) = v.trim().parse::<u64>() else { continue };
            if id == 0 || id > 1_000_000_000 {
                continue;
            }
            if out.iter().any(|(p, q, i)| p == path && q == k && i == &id) {
                continue;
            }
            out.push((path.to_string(), k.to_string(), id));
            if out.len() >= 3 {
                return out;
            }
        }
    }
    out
}

/// BOLA 표면 스캔 — DOM 오프라인 식별 (요청 없음·동의 불필요).
/// 순차 숫자 ID(같은 prefix 2개 이상) + ID 파라미터 엔드포인트를 info 로 보고한다.
pub fn scan_bola_surface(html: &str, base_url: &str) -> Vec<ProbeHit> {
    let mut out = Vec::new();
    // 1) 순차 ID — 같은 prefix 에 숫자 ID 가 2개 이상 보이면 열거 가능 신호.
    let mut by_prefix: std::collections::HashMap<String, Vec<u64>> = std::collections::HashMap::new();
    for (prefix, id) in extract_id_endpoints(html) {
        by_prefix.entry(prefix).or_default().push(id);
    }
    let mut prefixes: Vec<(String, Vec<u64>)> = by_prefix.into_iter().collect();
    prefixes.sort_by(|a, b| a.0.cmp(&b.0));
    for (prefix, mut ids) in prefixes {
        ids.sort_unstable();
        ids.dedup();
        if ids.len() < 2 || out.len() >= 3 {
            continue;
        }
        let sample: Vec<String> = ids.iter().take(4).map(|i| i.to_string()).collect();
        out.push(hit("bola-surface", Severity::Info, format!("{base_url}{prefix}/{{id}}"),
            format!("순차 ID 노출 — {prefix} ({}개 목격)", ids.len()),
            format!("같은 경로에 숫자 ID {} 노출 — 소유권 검사 없으면 BOLA(IDOR)로 이어진다 (전송 없이 표면 식별)", sample.join(",")),
            format!("ids={}", sample.join(",")),
            format!("DOM 오프라인 스캔 → {base_url}{prefix}/{{id}}"), None));
    }
    // 2) ID 파라미터 — ?id=42 형태는 쿼리 교체형 BOLA 후보.
    for (path, param, id) in extract_param_id_endpoints(html) {
        if out.len() >= 3 {
            break;
        }
        out.push(hit("bola-surface", Severity::Info, format!("{base_url}{path}?{param}="),
            format!("ID 파라미터 노출 — {path}?{param}="),
            format!("쿼리 파라미터로 리소스 지정 (목격값 {param}={id}) — 파라미터 교체형 BOLA 후보 (전송 없이 표면 식별)"),
            format!("{param}={id}"),
            format!("DOM 오프라인 스캔 → {base_url}{path}?{param}="), None));
    }
    out
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

/// BOLA 인접 판정 — 경로형·파라미터형 공용.
/// 인접 ID 에코(`"id":{adj}) + 본문 규모 유사(2배 이내) + 기준 응답과 다름.
fn bola_adjacent_confirms(norm0: &str, b1: &str, adj: i64) -> bool {
    let norm1: String = b1.chars().filter(|c| !c.is_whitespace()).collect();
    let has_adj_id = norm1.contains(&format!("\"id\":{adj}")) || norm1.contains(&format!("'id':{adj}"));
    let (a, b) = (norm0.len().max(1), norm1.len().max(1));
    let len_ok = b * 2 >= a && a * 2 >= b;
    has_adj_id && len_ok && norm1 != *norm0
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
            if bola_adjacent_confirms(&norm0, &b1, adj) {
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

/// BOLA 파라미터 교체 확인 — `?id=42` 형 엔드포인트의 인접 값 ±2 조회.
/// 본인 세션 필수·증거 마스킹·1건 확정 시 즉시 중단 — 경로형 IDOR 과 동일 윤리.
pub fn probe_bola_param(
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
    let endpoints = extract_param_id_endpoints(dom);
    if endpoints.is_empty() {
        return out;
    }
    let mut tested = 0;
    for (path, param, id) in endpoints.into_iter().take(2) {
        if cancelled(cfg) {
            return out;
        }
        let base_u = format!("{base_url}{path}?{param}={id}");
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
            let adj_u = format!("{base_url}{path}?{param}={adj}");
            let (st, b1) = match get_with_cookie(agent, &adj_u, Some(cookie), counter) {
                Some(v) => v,
                None => continue,
            };
            if st != 200 {
                continue;
            }
            if bola_adjacent_confirms(&norm0, &b1, adj) {
                out.push(hit("danger-bola", Severity::High, adj_u.clone(),
                    format!("BOLA 확정 — ?{param}={adj} 타 리소스 열람"),
                    format!("{path}?{param}= 소유권 검사 없음 — 파라미터 교체로 타인 리소스 응답 (동의 기반, 증거 마스킹)"),
                    redact_pii(&b1), format!("GET {path}?{param}={adj} (동의 기반)"), Some(200)));
                return out; // 1건 확정으로 충분 (추가 순회 금지)
            }
        }
    }
    if tested > 0 && out.is_empty() {
        out.push(hit("danger-bola", Severity::Info, base_url.to_string(),
            format!("BOLA 내성 — {tested}개 엔드포인트 인접 값 거부"),
            "파라미터 인접 ±2 조회가 모두 거부·차단됨 (동의 기반 실측)".into(),
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
    // P1 예산 — 전 distinct 싱크 검증, 전역 예산이 유일한 상한이다 (기본 96, 0이면 스킵).
    // 최악 20파라미터 × (xss 2 + sqli 1 + redirect 1) + 경로 = 84 takes < 96.
    // 기한·취소도 병행 감시한다. 소진 시 미검증 잔량을 gate info 로 명시한다.
    let mut budget = cfg.p1_budget.min(4096);
    let picked_total: usize = ["xss-reflect", "sqli-signal", "openredirect"]
        .iter()
        .map(|c| p1_pick_order(hits, c, false, usize::MAX).len())
        .sum::<usize>()
        + p1_pick_order(hits, "paths", true, usize::MAX).len();
    let mut verified_total = 0usize;
    let mut take = |n: &mut usize| {
        if *n == 0 || Instant::now() > deadline || cancelled(cfg) {
            return false;
        }
        *n -= 1;
        verified_total += 1;
        std::thread::sleep(Duration::from_millis(60));
        true
    };
    // XSS: 서로 다른 2번째 마커로 재반사 확인 + 브레이크아웃 판정.
    // 단순 반사(JSON 인코딩 등)는 Medium, `</script>` 미가공 반사만 High 확정.
    for idx in p1_pick_order(hits, "xss-reflect", false, usize::MAX) {
        let h = &hits[idx];
        if !take(&mut budget) {
            break;
        }
        let Some(param) = xss_param_of(h) else { continue };
        let m = format!("rc7xv2{}", out.len());
        counter.fetch_add(1, Ordering::Relaxed);
        let page = verify_page_base(&h.target);
        let url = format!("{page}?{param}={m}");
        let r = match fetch(agent, "GET", &url, &ch, BODY_CAP) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let ctx = classify_reflection(&r.body, &m);
        if !ctx.found {
            continue;
        }
        let where_ = if ctx.in_script { "script" } else if ctx.in_attr { "속성" } else if ctx.in_comment { "주석" } else { "텍스트" };
        let mut verdict = (
            Severity::Medium,
            format!("반사 싱크 확인 — 인코딩됨 (익스플로잇 미확인, {where_} 컨텍스트)"),
            reflection_snippet(&r.body, &m),
        );
        if take(&mut budget) {
            counter.fetch_add(1, Ordering::Relaxed);
            let burl = format!("{page}?{param}={}", pct_encode("zrc7xq</script><zrc7xq>"));
            match fetch(agent, "GET", &burl, &ch, BODY_CAP) {
                Ok(br) if br.body.contains("</script><zrc7xq>") => {
                    verdict = (
                        Severity::High,
                        "XSS 확정 — 브레이크아웃 미가공 반사".to_string(),
                        reflection_snippet(&br.body, "zrc7xq"),
                    );
                }
                Ok(br) if matches!(br.status, 403 | 406 | 429) => {
                    verdict = (
                        Severity::Medium,
                        format!("반사 싱크 확인 — 브레이크아웃 차단됨 (HTTP {}, WAF/게이트 추정)", br.status),
                        reflection_snippet(&r.body, &m),
                    );
                }
                _ => {}
            }
        }
        let (sev, title, ev) = verdict;
        out.push(hit("verify-xss", sev, url,
            format!("{title} — 파라미터 '{param}'"),
            format!("서로 다른 마커 2종 반사 (원 발견: {} {})", h.id, h.title),
            ev, format!("GET → {}", r.status), Some(r.status)));
    }
    // SQLi: Boolean 차분 (AND 1=1 vs AND 1=2).
    for idx in p1_pick_order(hits, "sqli-signal", false, usize::MAX) {
        let h = &hits[idx];
        if !take(&mut budget) {
            break;
        }
        let Some(param) = sqli_param_of(h) else { continue };
        counter.fetch_add(2, Ordering::Relaxed);
        let page = verify_page_base(&h.target);
        let vt = pct_encode("rc7x0' AND 1=1");
        let vf = pct_encode("rc7x0' AND 1=2");
        let t = fetch(agent, "GET", &format!("{page}?{param}={vt}"), &ch, 65536);
        let f = fetch(agent, "GET", &format!("{page}?{param}={vf}"), &ch, 65536);
        if let (Ok(t), Ok(f)) = (t, f) {
            let diff = t.status != f.status
                || (t.body.len() as i64 - f.body.len() as i64).abs() > 100
                || find_sql_errors(&t.body) != find_sql_errors(&f.body);
            out.push(hit(
                "verify-sqli",
                if diff { Severity::High } else { Severity::Info },
                format!("{page}?{param}=…"),
                if diff { format!("Boolean 차분 확인 — 파라미터 '{param}'") } else { format!("차분 없음 — 파라미터 '{param}' (지문만)") },
                format!("원 발견: {} {} / 1=1({},{})B vs 1=2({},{})B", h.id, h.title, t.status, t.body.len(), f.status, f.body.len()),
                String::new(),
                "GET ×2".into(),
                None,
            ));
            // Boolean 무차분이면 시간 기반으로 에스컬레이션 (OOB 없어도 되는 블라인드 폴백).
            // SQLi 지연이 없으면 같은 주입점에 CMDI 지연도 시도한다 (주입 가능 지점 한정).
            if !diff {
                if let Some(delayed) =
                    verify_time_sqli(agent, &ch, page, &param, h, counter, &mut take, &mut budget)
                {
                    out.push(delayed);
                } else if let Some(cdelayed) =
                    verify_time_cmdi(agent, &ch, page, &param, h, counter, &mut take, &mut budget)
                {
                    out.push(cdelayed);
                }
            }
        }
    }
    // 오픈 리다이렉트: 제2 호스트로 재확인.
    for idx in p1_pick_order(hits, "openredirect", false, usize::MAX) {
        let h = &hits[idx];
        if !take(&mut budget) {
            break;
        }
        let Some(param) = redirect_param_of(h) else { continue };
        counter.fetch_add(1, Ordering::Relaxed);
        let page = verify_page_base(&h.target);
        let url = format!("{page}?{param}={}", pct_encode("https://evil2-probe.test/r"));
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
    for idx in p1_pick_order(hits, "paths", true, usize::MAX) {
        let h = &hits[idx];
        if !take(&mut budget) {
            break;
        }
        counter.fetch_add(1, Ordering::Relaxed);
        if let Ok(r) = fetch_url_maybe_raw(agent, &h.target, "GET", &ch, 65536, cfg.req_timeout, true) {
            if r.status == h.status.unwrap_or(0) {
                out.push(hit("verify-paths", Severity::Info, h.target.clone(),
                    "민감 경로 재확인".into(),
                    format!("2회 연속 동일 응답 (원 발견: {} {})", h.id, h.title),
                    String::new(), format!("GET → {}", r.status), Some(r.status)));
            }
        }
    }
    drop(take);
    if verified_total < picked_total {
        out.push(hit("gate", Severity::Info, base_url.to_string(),
            format!("P1 예산 소진 — 후보 {}건 중 {}회 시도", picked_total, verified_total),
            format!("--p1-budget 상향(현재 {})으로 잔량 검증 가능", cfg.p1_budget.min(4096)),
            String::new(), "P1 예산".into(), None));
    }
    out
}

/// 시간 기반 블라인드 SQLi — Boolean 무차분 시 지연 페이로드로 확정 시도.
/// 기준선<2초·주입≥4.5초·차이≥3초를 모두 만족해야 확정 (지터 오탐 방지).
/// DB별 1회씩 최대 3회, 예산·기한·취소는 take()로 감시.
fn verify_time_sqli(
    agent: &ureq::Agent,
    ch: &[(&str, &str)],
    page: &str,
    param: &str,
    h: &ProbeHit,
    counter: &AtomicUsize,
    take: &mut dyn FnMut(&mut usize) -> bool,
    budget: &mut usize,
) -> Option<ProbeHit> {
    const SLEEP_SECS: u64 = 5;
    if !take(budget) {
        return None;
    }
    counter.fetch_add(1, Ordering::Relaxed);
    let bl_start = Instant::now();
    let bl = fetch(agent, "GET", &format!("{page}?{param}=rc7x0time"), ch, 65536).ok()?;
    let bl_ms = bl_start.elapsed();
    if bl.status >= 500 || bl_ms > Duration::from_millis(2000) {
        return None; // 기준선 불안정 — 판정 불가 (조용히)
    }
    let payloads = [
        ("MySQL", format!("rc7x0' AND SLEEP({SLEEP_SECS})-- -")),
        ("PostgreSQL", format!("rc7x0';SELECT pg_sleep({SLEEP_SECS})-- -")),
        ("MSSQL", format!("rc7x0';WAITFOR DELAY '0:0:0{SLEEP_SECS}'-- -")),
    ];
    for (db, payload) in payloads {
        if !take(budget) {
            return None;
        }
        counter.fetch_add(1, Ordering::Relaxed);
        let st = Instant::now();
        let r = fetch(agent, "GET", &format!("{page}?{param}={}", pct_encode(&payload)), ch, 65536);
        let el = st.elapsed();
        if r.is_ok() && el >= Duration::from_millis(4500) && el.saturating_sub(bl_ms) >= Duration::from_millis(3000) {
            return Some(hit(
                "verify-sqli",
                Severity::High,
                format!("{page}?{param}=…"),
                format!("시간 기반 블라인드 SQLi 확정 — 파라미터 '{param}' ({db})"),
                format!(
                    "원 발견: {} {} / 기준선 {}ms → 주입 {}ms ({}초 지연 페이로드)",
                    h.id,
                    h.title,
                    bl_ms.as_millis(),
                    el.as_millis(),
                    SLEEP_SECS
                ),
                String::new(),
                format!("GET 지연 페이로드 ({db})").into(),
                None,
            ));
        }
    }
    None
}

/// 시간 기반 블라인드 CMDI — SQLi 지연도 없을 때 같은 주입점에 명령 지연을 시도한다.
/// 기준선<2초·주입≥4.5초·차이≥3초를 모두 만족해야 확정 (지터 오탐 방지).
/// 출력 없이 실행만 되는 블라인드 RCE를 잡는다. 셸 3종 + Windows 1종, 예산·기한·취소는 take()로 감시.
fn verify_time_cmdi(
    agent: &ureq::Agent,
    ch: &[(&str, &str)],
    page: &str,
    param: &str,
    h: &ProbeHit,
    counter: &AtomicUsize,
    take: &mut dyn FnMut(&mut usize) -> bool,
    budget: &mut usize,
) -> Option<ProbeHit> {
    const SLEEP_SECS: u64 = 5;
    if !take(budget) {
        return None;
    }
    counter.fetch_add(1, Ordering::Relaxed);
    let bl_start = Instant::now();
    let bl = fetch(agent, "GET", &format!("{page}?{param}=rc7x0time"), ch, 65536).ok()?;
    let bl_ms = bl_start.elapsed();
    if bl.status >= 500 || bl_ms > Duration::from_millis(2000) {
        return None; // 기준선 불안정 — 판정 불가 (조용히)
    }
    let payloads = [
        ("sh", format!("rc7x0;sleep {SLEEP_SECS}")),
        ("sh-pipe", format!("rc7x0|sleep {SLEEP_SECS}")),
        ("sh-and", format!("rc7x0&&sleep {SLEEP_SECS}")),
        ("cmd", format!("rc7x0& ping -n {} 127.0.0.1", SLEEP_SECS + 1)),
    ];
    for (shell, payload) in payloads {
        if !take(budget) {
            return None;
        }
        counter.fetch_add(1, Ordering::Relaxed);
        let st = Instant::now();
        let r = fetch(agent, "GET", &format!("{page}?{param}={}", pct_encode(&payload)), ch, 65536);
        let el = st.elapsed();
        if r.is_ok() && el >= Duration::from_millis(4500) && el.saturating_sub(bl_ms) >= Duration::from_millis(3000) {
            return Some(hit(
                "verify-cmdi",
                Severity::High,
                format!("{page}?{param}=…"),
                format!("시간 기반 블라인드 CMDI 확정 — 파라미터 '{param}' ({shell})"),
                format!(
                    "원 발견: {} {} / 기준선 {}ms → 주입 {}ms ({}초 지연 페이로드) — 출력 없이 명령 실행",
                    h.id,
                    h.title,
                    bl_ms.as_millis(),
                    el.as_millis(),
                    SLEEP_SECS
                ),
                String::new(),
                format!("GET 지연 페이로드 ({shell})").into(),
                None,
            ));
        }
    }
    None
}

fn quoted_param(title: &str) -> Option<String> {
    let s = title.split('\'').nth(1)?;
    if s.is_empty() || s.len() > 32 || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return None;
    }
    Some(s.to_string())
}

/// P1 재검증 기준 페이지 — 원 발견 target 의 쿼리 이전 부분.
/// 크롤 파라미터 발견도 제자리에서 재검증한다 (루트 고정 금지).
fn verify_page_base(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

/// P1 검증 대상 선정 — 카테고리 일치 → 심각도·target 순 정렬 → (페이지, 파라미터) 중복 제거 → cap.
/// 병렬 잡 완료 순서에 흔들리지 않는 결정적 선택 (게이트 재현성).
/// 동일 파라미터라도 페이지가 다르면 별개 싱크이므로 각각 검증한다 (예: /s?q 와 /api/echo?q).
/// 예산 내에서는 뜨거운 발견부터 검증한다 (심각도 우선).
/// 전역 예산(p1_budget)이 총량을 묶으므로 크롤이 커져도 발산하지 않는다.
fn p1_pick_order(hits: &[ProbeHit], category: &str, hot_only: bool, cap: usize) -> Vec<usize> {
    let mut idx: Vec<usize> = hits
        .iter()
        .enumerate()
        .filter(|(_, h)| {
            h.category == category && (!hot_only || h.severity == "high" || h.severity == "critical")
        })
        .map(|(i, _)| i)
        .collect();
    idx.sort_by(|a, b| {
        sev_rank(&hits[*a].severity)
            .cmp(&sev_rank(&hits[*b].severity))
            .then_with(|| hits[*a].target.cmp(&hits[*b].target))
            .then_with(|| hits[*a].id.cmp(&hits[*b].id))
    });
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for i in idx {
        if out.len() >= cap {
            break;
        }
        let param = quoted_param(&hits[i].title).unwrap_or_else(|| format!("!{i}"));
        let key = format!("{}|{param}", verify_page_base(&hits[i].target));
        if seen.insert(key) {
            out.push(i);
        }
    }
    out
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
/// 크롤 수집 페이지 — 본문 + 헤더 (클라이언트 표면 스캔용).
struct CrawledPage {
    url: String,
    body: String,
    headers: Vec<(String, String)>,
}

/// GET 전용 파괴 금지 경로 — 크롤러가 절대 건드리지 않는다.
const CRAWL_FORBIDDEN: &[&str] = &["logout", "signout", "delete", "remove", "destroy", "deactivate", "unsubscribe", "reset-password"];

/// 링크 추출 — 동일 호스트 절대 URL + `/` 상대경로만 (최대 200개).
/// 파괴 경로·비HTTP 스킴·프래그먼트는 제외한다.
fn extract_links(html: &str, base_url: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = html.as_bytes();
    let mut pos = 0;
    while let Some(found) = find_ascii_ci(html, "href", pos) {
        let mut i = found + 4;
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'=') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let (quote, start) = if bytes[i] == b'"' || bytes[i] == b'\'' {
            (bytes[i], i + 1)
        } else {
            (b' ', i)
        };
        let mut j = start;
        while j < bytes.len() && bytes[j] != quote && (quote != b' ' || (bytes[j] != b' ' && bytes[j] != b'\t' && bytes[j] != b'>')) {
            j += 1;
        }
        pos = j + 1;
        if start >= j {
            continue;
        }
        let raw = html.get(start..j).unwrap_or("").trim();
        let link = raw.split('#').next().unwrap_or("").trim();
        if link.is_empty() || link.len() > 500 {
            continue;
        }
        let ll = link.to_lowercase();
        if ll.starts_with("mailto:") || ll.starts_with("javascript:") || ll.starts_with("tel:") || ll.starts_with("data:") {
            continue;
        }
        if CRAWL_FORBIDDEN.iter().any(|k| ll.contains(k)) {
            continue;
        }
        let full = if link.starts_with('/') && !link.starts_with("//") {
            format!("{base_url}{link}")
        } else if link.starts_with("http://") || link.starts_with("https://") {
            if link == base_url || link.starts_with(&format!("{base_url}/")) || link.starts_with(&format!("{base_url}?")) {
                link.to_string()
            } else {
                continue;
            }
        } else {
            continue; // 상대경로(./, ../) 는 스킵 — 정규화 우회 방지
        };
        if !out.contains(&full) {
            out.push(full);
        }
        if out.len() >= 200 {
            break;
        }
    }
    out
}

/// bounded 크롤 — 동일 호스트 BFS (GET 전용, 파괴 경로 제외).
/// 시드 포함 max_pages·max_depth 상한, 기한·취소 존중.
fn crawl_collect(
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    base_url: &str,
    seed: &str,
    max_pages: usize,
    max_depth: u8,
    counter: &AtomicUsize,
    deadline: Instant,
) -> Vec<CrawledPage> {
    let mut pages = Vec::new();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut queue: VecDeque<(String, u8)> = VecDeque::from([(seed.to_string(), 0)]);
    let ch = cfg.cookie_headers();
    while let Some((url, depth)) = queue.pop_front() {
        if pages.len() >= max_pages || Instant::now() > deadline || cancelled(cfg) {
            break;
        }
        if !visited.insert(url.clone()) {
            continue;
        }
        std::thread::sleep(Duration::from_millis(80));
        counter.fetch_add(1, Ordering::Relaxed);
        let r = match fetch(agent, "GET", &url, &ch, BODY_CAP) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if r.status != 200 {
            continue;
        }
        let ctype = header(&r.headers, "content-type").unwrap_or("").to_lowercase();
        if ["image/", "font/", "audio/", "video/", "octet-stream", "application/zip", "application/pdf"]
            .iter()
            .any(|k| ctype.contains(k))
        {
            continue;
        }
        if depth < max_depth {
            for link in extract_links(&r.body, base_url) {
                if !visited.contains(&link) {
                    queue.push_back((link, depth + 1));
                }
            }
        }
        pages.push(CrawledPage { url, body: r.body, headers: r.headers });
    }
    pages
}

/// SSRF 대상 파라미터 — 발견된 URL성 + (루트 전용) 기본 후보.
fn ssrf_params(params: &[String], with_defaults: bool) -> Vec<String> {
    let mut spar: Vec<String> = params.iter().filter(|p| SSRF_PARAMS.contains(&p.to_lowercase().as_str())).cloned().collect();
    if with_defaults {
        for d in ["url", "next", "dest"] {
            if !spar.iter().any(|p| p == d) {
                spar.push(d.to_string());
            }
        }
    }
    spar
}

/// 파라미터 잡 조립 — 페이지 기준 URL로 XSS/SQLi/리다이렉트/SSTI/CRLF/HPP/NoSQL/SSRF.
/// `with_defaults` 가 true 면 리다이렉트·SSRF 기본 파라미터 추가 (루트 전용 —
/// 크롤 페이지는 발견 파라미터만으로 잡 폭증을 막는다).
fn param_jobs_for(page_base: &str, params: &[String], with_defaults: bool) -> Vec<Job> {
    let b = page_base.trim_end_matches('/');
    let mut jobs = Vec::new();
    for (i, param) in params.iter().enumerate().take(PARAM_CAP) {
        let m1 = format!("rc7xp0{i}");
        jobs.push(Job {
            url: format!("{b}/?{param}={m1}"),
            method: "GET",
            headers: vec![],
            kind: ProbeKind::Xss { param: param.clone(), raw: false, marker: m1 },
        });
        let m2 = format!("rc7x{i}<>\"'()");
        jobs.push(Job {
            url: format!("{b}/?{param}={}", pct_encode(&m2)),
            method: "GET",
            headers: vec![],
            kind: ProbeKind::Xss { param: param.clone(), raw: true, marker: m2 },
        });
        for q in ['\'', '"'] {
            jobs.push(Job {
                url: format!("{b}/?{param}=rc7x0{}", pct_encode(&q.to_string())),
                method: "GET",
                headers: vec![],
                kind: ProbeKind::Sqli { param: param.clone(), quote: q },
            });
        }
    }
    // 오픈 리다이렉트 — 발견된 리다이렉트성 파라미터 (+ 기본 3종).
    let mut rparams: Vec<String> = params.iter().filter(|p| REDIRECT_PARAMS.contains(&p.as_str())).cloned().collect();
    if with_defaults {
        for d in ["url", "next", "redirect"] {
            if !rparams.iter().any(|p| p == d) {
                rparams.push(d.to_string());
            }
        }
    }
    let mut rjobs = 0;
    for param in rparams {
        for payload in [EVIL_URL, EVIL_PROTOREL] {
            if rjobs >= REDIRECT_JOB_CAP {
                break;
            }
            jobs.push(Job {
                url: format!("{b}/?{param}={payload}"),
                method: "GET",
                headers: vec![],
                kind: ProbeKind::Redirect { param: param.clone(), payload },
            });
            rjobs += 1;
        }
    }
    // 2차 벡터 — 파라미터당 SSTI 1종 + CMDI 2종 + 상한 내 CRLF/HPP/NoSQL.
    let ssti_payload = format!("{{{{{SSTI_A}*{SSTI_B}}}}}");
    for (i, param) in params.iter().enumerate().take(PARAM_CAP) {
        jobs.push(Job {
            url: format!("{b}/?{param}={}", pct_encode(&ssti_payload)),
            method: "GET",
            headers: vec![],
            kind: ProbeKind::Ssti { param: param.clone(), payload: ssti_payload.clone() },
        });
        for cp in CMDI_PAYLOADS {
            jobs.push(Job {
                url: format!("{b}/?{param}=rc7x0{}", pct_encode(cp)),
                method: "GET",
                headers: vec![],
                kind: ProbeKind::Cmdi { param: param.clone(), payload: cp.to_string() },
            });
        }
        if i < CRLF_CAP {
            jobs.push(Job {
                url: format!("{b}/?{param}=rcx%0d%0aX-RC-Probe%3a{CRLF_MARKER}"),
                method: "GET",
                headers: vec![],
                kind: ProbeKind::Crlf { param: param.clone() },
            });
        }
        if i < HPP_CAP {
            jobs.push(Job {
                url: format!("{b}/?{param}={HPP_A}&{param}={HPP_B}"),
                method: "GET",
                headers: vec![],
                kind: ProbeKind::Hpp { param: param.clone() },
            });
        }
        if i < NOSQL_CAP {
            jobs.push(Job {
                url: format!("{b}/?{param}[%24ne]=rc7nosql0"),
                method: "GET",
                headers: vec![],
                kind: ProbeKind::Nosql { param: param.clone() },
            });
        }
    }
    // SSRF — URL성 파라미터 (+ 기본 후보, 상한 내).
    for param in ssrf_params(params, with_defaults).into_iter().take(SSRF_CAP) {
        jobs.push(Job {
            url: format!("{b}/?{param}={}", pct_encode(SSRF_URL)),
            method: "GET",
            headers: vec![],
            kind: ProbeKind::Ssrf { param },
        });
    }
    jobs
}

/// 루프백 대상 판정 — OOB 자동 기동 조건 (동일 호스트 = 대상 egress 불필요).
/// 보수적 목록 (localhost·127.0.0.1·::1) — 127/8 전역·사설대역은 자동 기동하지 않는다.
fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_lowercase();
    h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]"
}

/// OOB 콜백 수신기 — 블라인드 SSRF 덫 (표준 라이브러리 미니 HTTP).
/// 수신 스레드는 구조체 drop 시 종료된다 (논블로킹 accept 폴링).
pub struct OobReceiver {
    /// 덫 URL 베이스 (항상 `/` 종결).
    pub base: String,
    port: u16,
    hits: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for OobReceiver {
    fn drop(&mut self) {
        self.alive.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

impl OobReceiver {
    pub fn start(bind: &str, base: &str) -> Result<Self, String> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(bind).map_err(|e| format!("OOB 바인드 실패 ({bind}): {e}"))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let h2 = hits.clone();
        let a2 = alive.clone();
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            loop {
                if !a2.load(Ordering::Relaxed) {
                    break;
                }
                match listener.accept() {
                    Ok((mut s, _)) => {
                        s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                        let mut buf = [0u8; 2048];
                        let n = s.read(&mut buf).unwrap_or(0);
                        if let Some(path) = String::from_utf8_lossy(&buf[..n]).split_whitespace().nth(1) {
                            if path.len() < 500 {
                                if let Ok(mut v) = h2.lock() {
                                    if v.len() < 10_000 {
                                        v.push(path.to_string());
                                    }
                                }
                            }
                        }
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self { base: format!("{}/", base.trim_end_matches('/')), port, hits, alive })
    }

    pub fn local_port(&self) -> u16 {
        self.port
    }

    /// 토큰 덫 URL.
    pub fn url_for(&self, token: &str) -> String {
        format!("{}{token}", self.base)
    }

    /// 수신 경로 배출 (비운다).
    pub fn drain(&self) -> Vec<String> {
        self.hits.lock().map(|mut v| std::mem::take(&mut *v)).unwrap_or_default()
    }
}

/// OOB 토큰 매칭 — 수신 경로에 토큰이 들어있으면 (토큰, 파라미터, 잡 URL).
fn match_oob_hits(paths: &[String], tokens: &[(String, String, String)]) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (token, param, url) in tokens {
        if paths.iter().any(|p| p.contains(token)) {
            out.push((token.clone(), param.clone(), url.clone()));
        }
    }
    out
}

/// API 오퍼레이션 — 스펙 원문 경로 + `{x}` 치환된 프로브 경로 + 쿼리명.
#[derive(Debug, Clone)]
pub struct ApiOp {
    pub method: String,
    pub path: String,
    pub probe_path: String,
    pub query: Vec<String>,
}

/// OpenAPI URL 분해 — (호스트, 포트) + 스킴 기본 포트 정규화.
pub fn openapi_url_target(url: &str) -> Option<(String, Option<u16>)> {
    let (rest, default_port) = url
        .strip_prefix("http://")
        .map(|r| (r, 80))
        .or_else(|| url.strip_prefix("https://").map(|r| (r, 443)))?;
    let hostport = rest.split('/').next().unwrap_or("");
    if hostport.is_empty() || hostport.contains('@') {
        return None;
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() => (h.to_string(), p.parse::<u16>().ok()),
        _ => (hostport.to_string(), None),
    };
    if host.is_empty() {
        return None;
    }
    let port = port.or(Some(default_port));
    Some((host.to_lowercase(), port))
}

/// 스펙 파라미터명 검증 — 쿼리 키로 쓸 수 있는 것만 (프로브 인젝션 방지).
fn api_param_name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

fn collect_query_params(v: Option<&serde_json::Value>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(arr) = v.and_then(|x| x.as_array()) else { return out };
    for p in arr {
        let Some(o) = p.as_object() else { continue }; // $ref 문자열 스킵
        if o.contains_key("$ref") {
            continue;
        }
        let name = o.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let loc = o.get("in").and_then(|x| x.as_str()).unwrap_or("");
        if loc != "query" || !api_param_name_ok(name) {
            continue;
        }
        if !out.contains(&name.to_string()) {
            out.push(name.to_string());
        }
    }
    out
}

/// `{x}` 치환 — 숫자 의미면 `1`, 아니면 무해 문자열. 미닫힘 템플릿이면 None.
fn api_probe_path(path: &str) -> Option<String> {
    let mut out = String::with_capacity(path.len() + 8);
    let mut rest = path;
    while let Some(s) = rest.find('{') {
        out.push_str(&rest[..s]);
        let after = &rest[s + 1..];
        let Some(e) = after.find('}') else { return None };
        let name = after[..e].to_lowercase();
        if name.is_empty() || name.len() > 64 {
            return None;
        }
        let numeric = name == "id"
            || name.ends_with("id")
            || name.ends_with("_no")
            || ["page", "limit", "offset", "size", "num", "count", "index", "year", "month", "day"]
                .contains(&name.as_str());
        out.push_str(if numeric { "1" } else { "rc7x" });
        rest = &after[e + 1..];
    }
    out.push_str(rest);
    if out.contains('{') || out.contains('}') {
        return None;
    }
    Some(out)
}

/// YAML 논리행 — 들여쓰기 + 주석 제거 본문.
struct YamlLine {
    indent: usize,
    text: String,
}

/// 따옴표 밖 `#`(앞이 공백·행두)부터 주석 제거.
fn yaml_strip_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut quote = 0u8;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if quote == 0 {
            if c == b'\'' || c == b'"' {
                quote = c;
            } else if c == b'#' && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
                return s[..i].trim_end();
            }
        } else if c == quote {
            if quote == b'\'' && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                i += 1;
            } else {
                quote = 0;
            }
        } else if quote == b'"' && c == b'\\' {
            i += 1;
        }
        i += 1;
    }
    s.trim_end()
}

/// 스칼라 — 전부 문자열로 유지 (버전 `3.0.3` 숫자 훼손 방지, 추출용).
fn yaml_scalar(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        let mut o = String::new();
        let mut it = t[1..t.len() - 1].chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                match it.next() {
                    Some('n') => o.push('\n'),
                    Some('t') => o.push('\t'),
                    Some('r') => o.push('\r'),
                    Some(x) => o.push(x),
                    None => o.push('\\'),
                }
            } else {
                o.push(c);
            }
        }
        return o;
    }
    if t.len() >= 2 && t.starts_with('\'') && t.ends_with('\'') {
        return t[1..t.len() - 1].replace("''", "'");
    }
    t.to_string()
}

/// `key: value` 분리 — 첫 `:` 뒤가 공백·행끝. 따옴표 키 지원.
fn yaml_split_key(s: &str) -> Option<(String, String)> {
    let t = s.trim();
    let start = if t.starts_with('"') || t.starts_with('\'') {
        let q = t.as_bytes()[0];
        let mut i = 1;
        let bytes = t.as_bytes();
        while i < bytes.len() {
            if bytes[i] == q {
                if q == b'\'' && i + 1 < bytes.len() && bytes[i + 1] == q {
                    i += 1;
                } else {
                    break;
                }
            }
            i += 1;
        }
        i + 1
    } else {
        0
    };
    let rest = t.get(start..)?;
    let ci = rest.find(':')?;
    let after = rest.get(ci + 1..)?;
    if !after.is_empty() && !after.starts_with(' ') && !after.starts_with('\t') {
        return None;
    }
    let key = yaml_scalar(t[..start + ci].trim());
    if key.is_empty() {
        return None;
    }
    Some((key, after.trim().to_string()))
}

/// YAML 서브셋 → JSON. 블록 매핑·시퀀스·리터럴·앵커·별칭 지원.
/// 플로우(`{}`·`[]`)·태그(`!!`)·병합(`<<`) 값은 Null로 관대 처리(추출 무시),
/// 구조 오류(탭·별칭 미정의·깊이 초과)는 None.
fn parse_yaml_subset(text: &str) -> Option<serde_json::Value> {
    let mut lines: Vec<YamlLine> = Vec::new();
    for raw in text.lines().take(50_000) {
        if raw.trim().is_empty() {
            continue;
        }
        if raw.starts_with('\t') {
            return None;
        }
        let indent = raw.len() - raw.trim_start_matches(' ').len();
        let body = yaml_strip_comment(raw[indent..].trim_end_matches([' ', '\t']));
        if body.is_empty() || body == "---" || body == "..." {
            continue;
        }
        lines.push(YamlLine { indent, text: body.to_string() });
    }
    if lines.is_empty() {
        return None;
    }
    let mut anchors: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
    let mut budget = 100_000usize;
    let (v, next) = yaml_parse_node(&lines, 0, lines[0].indent, &mut anchors, &mut budget, 0)?;
    if next != lines.len() {
        return None; // 최상위 잔여 = 들여쓰기 어긋남
    }
    Some(v)
}

fn yaml_budget(budget: &mut usize) -> Option<()> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    Some(())
}

fn yaml_parse_node(
    lines: &[YamlLine],
    pos: usize,
    indent: usize,
    anchors: &mut std::collections::HashMap<String, serde_json::Value>,
    budget: &mut usize,
    depth: usize,
) -> Option<(serde_json::Value, usize)> {
    yaml_budget(budget)?;
    if depth > 64 || pos >= lines.len() || lines[pos].indent != indent {
        return None;
    }
    if lines[pos].text == "-" || lines[pos].text.starts_with("- ") {
        yaml_parse_seq(lines, pos, indent, anchors, budget, depth)
    } else {
        let (m, next) = yaml_parse_map(lines, pos, indent, anchors, budget, depth)?;
        Some((serde_json::Value::Object(m), next))
    }
}

fn yaml_parse_seq(
    lines: &[YamlLine],
    pos: usize,
    indent: usize,
    anchors: &mut std::collections::HashMap<String, serde_json::Value>,
    budget: &mut usize,
    depth: usize,
) -> Option<(serde_json::Value, usize)> {
    let mut arr = Vec::new();
    let mut i = pos;
    while i < lines.len() && lines[i].indent == indent && (lines[i].text == "-" || lines[i].text.starts_with("- ")) {
        yaml_budget(budget)?;
        let rest = if lines[i].text == "-" { String::new() } else { lines[i].text[2..].to_string() };
        i += 1;
        if rest.trim() == "{}" {
            arr.push(serde_json::Value::Object(serde_json::Map::new()));
        } else if rest.trim() == "[]" {
            arr.push(serde_json::Value::Array(Vec::new()));
        } else if rest.trim_start().starts_with('{') || rest.trim_start().starts_with('[') {
            arr.push(serde_json::Value::Null); // 플로우 관대 처리
        } else if let Some((k, v)) = yaml_split_key(&rest) {
            // `- key: value` — 매핑 시작, 형제 키는 indent+2 정렬.
            let (val, ni) = yaml_pair_value(lines, i, indent, &v, anchors, budget, depth)?;
            i = ni;
            let mut map = serde_json::Map::new();
            map.insert(k, val);
            while i < lines.len() && lines[i].indent == indent + 2 {
                let Some((sk, sv)) = yaml_split_key(&lines[i].text) else { break };
                i += 1;
                let (svv, ni) = yaml_pair_value(lines, i, indent + 2, &sv, anchors, budget, depth)?;
                i = ni;
                map.insert(sk, svv);
            }
            arr.push(serde_json::Value::Object(map));
        } else {
            let (v, ni) = yaml_pair_value(lines, i, indent, &rest, anchors, budget, depth)?;
            i = ni;
            arr.push(v);
        }
        if arr.len() > 10_000 {
            return None;
        }
    }
    Some((serde_json::Value::Array(arr), i))
}

fn yaml_parse_map(
    lines: &[YamlLine],
    pos: usize,
    indent: usize,
    anchors: &mut std::collections::HashMap<String, serde_json::Value>,
    budget: &mut usize,
    depth: usize,
) -> Option<(serde_json::Map<String, serde_json::Value>, usize)> {
    let mut map = serde_json::Map::new();
    let mut i = pos;
    while i < lines.len() && lines[i].indent == indent {
        yaml_budget(budget)?;
        let Some((k, v)) = yaml_split_key(&lines[i].text) else { break };
        i += 1;
        let (val, ni) = yaml_pair_value(lines, i, indent, &v, anchors, budget, depth)?;
        i = ni;
        map.insert(k, val);
        if map.len() > 10_000 {
            return None;
        }
    }
    Some((map, i))
}

/// 매핑 값 해석 — 리터럴·앵커·별칭·중첩·스칼라(+접속행).
fn yaml_pair_value(
    lines: &[YamlLine],
    next: usize,
    cur_indent: usize,
    rest: &str,
    anchors: &mut std::collections::HashMap<String, serde_json::Value>,
    budget: &mut usize,
    depth: usize,
) -> Option<(serde_json::Value, usize)> {
    yaml_budget(budget)?;
    let t = rest.trim();
    // 리터럴·접기 (|, >, + chomping 무시 — 추출용).
    if t == "|" || t == ">" || t == "|-" || t == ">-" || t == "|+" || t == ">+" {
        let folded = t.starts_with('>');
        let mut parts: Vec<String> = Vec::new();
        let mut i = next;
        while i < lines.len() && lines[i].indent > cur_indent {
            parts.push(lines[i].text.clone());
            i += 1;
        }
        let joined = if folded { parts.join(" ") } else { parts.join("\n") };
        return Some((serde_json::Value::String(joined), i));
    }
    // 앵커 정의.
    if let Some(after) = t.strip_prefix('&') {
        let name: String = after.split_whitespace().next().unwrap_or("").to_string();
        if name.is_empty() || name.len() > 64 {
            return None;
        }
        let remainder = after[name.len()..].trim();
        let (v, ni) = if remainder.is_empty() {
            if next < lines.len() && lines[next].indent > cur_indent {
                yaml_parse_node(lines, next, lines[next].indent, anchors, budget, depth + 1)?
            } else {
                (serde_json::Value::Null, next)
            }
        } else {
            yaml_inline_value(remainder, anchors)?
                .map_or((serde_json::Value::Null, next), |s| (serde_json::Value::String(s), next))
        };
        anchors.insert(name, v.clone());
        return Some((v, ni));
    }
    // 별칭.
    if let Some(name) = t.strip_prefix('*') {
        if name.is_empty() || name.len() > 64 || name.contains([' ', '\t']) {
            return None;
        }
        return anchors.get(name).cloned().map(|v| (v, next));
    }
    // 빈 플로우는 빈 컨테이너 (JSON `{}` 동등성), 나머지는 Null 관대 처리.
    if t == "{}" {
        return Some((serde_json::Value::Object(serde_json::Map::new()), next));
    }
    if t == "[]" {
        return Some((serde_json::Value::Array(Vec::new()), next));
    }
    if t.starts_with('{') || t.starts_with('[') || t.starts_with("!!") {
        return Some((serde_json::Value::Null, next));
    }
    // 빈 값 — 중첩 블록 또는 Null.
    if t.is_empty() {
        if next < lines.len() && lines[next].indent > cur_indent {
            return yaml_parse_node(lines, next, lines[next].indent, anchors, budget, depth + 1);
        }
        return Some((serde_json::Value::Null, next));
    }
    // 인라인 스칼라 + 접속행 (더 깊은 들여쓰기의 비구조행).
    let mut s = yaml_scalar(t);
    let mut i = next;
    while i < lines.len() && lines[i].indent > cur_indent {
        let lt = lines[i].text.trim();
        if lt == "-" || lt.starts_with("- ") || yaml_split_key(lt).is_some() {
            break; // 구조행 — 접속이 아니라 오류급이지만 관대히 중단
        }
        s.push(' ');
        s.push_str(&yaml_scalar(lt));
        i += 1;
        if s.len() > 100_000 {
            return None;
        }
    }
    Some((serde_json::Value::String(s), i))
}

/// 앵커 뒤 인라인 값 — 스칼라 또는 None(플로우).
fn yaml_inline_value(s: &str, anchors: &std::collections::HashMap<String, serde_json::Value>) -> Option<Option<String>> {
    let t = s.trim();
    if t.is_empty() {
        return Some(None);
    }
    if let Some(name) = t.strip_prefix('*') {
        return anchors.get(name).and_then(|v| v.as_str()).map(|x| Some(x.to_string()));
    }
    if t.starts_with('{') || t.starts_with('[') || t.starts_with("!!") {
        return Some(None);
    }
    Some(Some(yaml_scalar(t)))
}

/// 내부 `$ref: "#/..."` 치환 — JSON 포인터(~0/~1), 순환 차단, 노드 상한.
/// 해석 불가(외부·경로 없음·순환)는 원문 유지(추출기가 스킵).
fn resolve_local_refs(v: &serde_json::Value) -> serde_json::Value {
    fn lookup<'a>(root: &'a serde_json::Value, pointer: &str) -> Option<&'a serde_json::Value> {
        let mut cur = root;
        for seg in pointer.split('/').skip(1) {
            let key = seg.replace("~1", "/").replace("~0", "~");
            cur = match cur {
                serde_json::Value::Object(m) => m.get(&key)?,
                serde_json::Value::Array(a) => a.get(key.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        Some(cur)
    }
    fn resolve(
        node: &serde_json::Value,
        root: &serde_json::Value,
        stack: &mut Vec<String>,
        budget: &mut usize,
    ) -> serde_json::Value {
        if *budget == 0 {
            return serde_json::Value::Null;
        }
        *budget -= 1;
        match node {
            serde_json::Value::Object(m) => {
                if let Some(r) = m.get("$ref").and_then(|r| r.as_str()) {
                    if r.starts_with("#/") && !stack.contains(&r.to_string()) && stack.len() < 8 {
                        if let Some(target) = lookup(root, r) {
                            stack.push(r.to_string());
                            let out = resolve(target, root, stack, budget);
                            stack.pop();
                            return out;
                        }
                    }
                    return node.clone(); // 외부·순환·경로없음 — 원문 유지
                }
                let mut nm = serde_json::Map::with_capacity(m.len());
                for (k, v) in m {
                    nm.insert(k.clone(), resolve(v, root, stack, budget));
                }
                serde_json::Value::Object(nm)
            }
            serde_json::Value::Array(a) => {
                serde_json::Value::Array(a.iter().map(|v| resolve(v, root, stack, budget)).collect())
            }
            _ => node.clone(),
        }
    }
    let mut budget = 100_000usize;
    resolve(v, v, &mut Vec::new(), &mut budget)
}

/// YAML 풀파서 — yaml_serde 경유 JSON 값 변환 (flow·앵커·병합 전부).
/// 실패하면 None (호출자가 서브셋 폴백 시도). 2MB 상한.
fn parse_yaml_full(text: &str) -> Option<serde_json::Value> {
    if text.len() > 2_000_000 {
        return None;
    }
    let v: yaml_serde::Value = yaml_serde::from_str(text).ok()?;
    serde_json::to_value(&v).ok()
}

/// OpenAPI 스펙 파싱 — JSON 우선, 실패 시 YAML 풀파서, 최후 서브셋 폴백. 3.x + Swagger 2.0.
/// `paths` 만 추출 (servers 무시), 내부 `$ref` 는 해석 후 사용.
/// 결정적 순서(경로 정렬) + 상한(API_OP_CAP). 비정상은 빈 목록.
pub fn parse_openapi_paths(text: &str) -> Vec<ApiOp> {
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => match parse_yaml_full(text).or_else(|| parse_yaml_subset(text)) {
            Some(v) => v,
            None => return Vec::new(),
        },
    };
    let v = resolve_local_refs(&v);
    let ver_ok = v
        .get("openapi")
        .and_then(|s| s.as_str())
        .map(|s| s.starts_with("3."))
        .unwrap_or(false)
        || v.get("swagger").and_then(|s| s.as_str()).map(|s| s == "2.0").unwrap_or(false);
    if !ver_ok {
        return Vec::new();
    }
    let Some(paths) = v.get("paths").and_then(|p| p.as_object()) else { return Vec::new() };
    let mut keys: Vec<&String> = paths.keys().collect();
    keys.sort();
    let mut ops = Vec::new();
    for path in keys {
        if !path.starts_with('/') || path.len() > 256 || path.contains(' ') {
            continue;
        }
        let Some(item) = paths.get(path).and_then(|i| i.as_object()) else { continue };
        let Some(probe_path) = api_probe_path(path) else { continue };
        let item_q = collect_query_params(item.get("parameters"));
        for method in ["get", "put", "post", "delete", "options", "head", "patch", "trace"] {
            let Some(op) = item.get(method).and_then(|o| o.as_object()) else { continue };
            let mut query = item_q.clone();
            for q in collect_query_params(op.get("parameters")) {
                if !query.contains(&q) {
                    query.push(q);
                }
            }
            query.truncate(API_QUERY_CAP);
            ops.push(ApiOp { method: method.to_string(), path: path.clone(), probe_path: probe_path.clone(), query });
            if ops.len() >= API_OP_CAP {
                return ops;
            }
        }
    }
    ops
}

/// 스펙 원문 로드 — URL 은 동일 호스트만, 파일은 2MB 상한.
pub fn load_openapi_source(
    source: &str,
    host: &str,
    port: Option<u16>,
    agent: &ureq::Agent,
    cfg: &SweepConfig,
    counter: &AtomicUsize,
) -> Option<String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let (h, p) = openapi_url_target(source)?;
        let want_port = port.or(Some(if source.starts_with("https://") { 443 } else { 80 }));
        if h != host.to_lowercase() || p != want_port {
            return None; // 동일 호스트 경계 (프라이버시)
        }
        counter.fetch_add(1, Ordering::Relaxed);
        let r = fetch(agent, "GET", source, &cfg.cookie_headers(), API_SPEC_CAP).ok()?;
        if r.status != 200 || r.body.len() >= API_SPEC_CAP as usize {
            return None;
        }
        return Some(r.body);
    }
    let meta = std::fs::metadata(source).ok()?;
    if meta.len() > API_SPEC_CAP {
        return None;
    }
    std::fs::read_to_string(source).ok()
}

// ── 차단 표면 (캡차·JS챌린지·WAF차단) 감지 ────────────────────────────────────

/// 차단 표면 종류 — 자동 검사가 닿지 못하는 영역.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedKind {
    /// 캡차 위젯 + 로그인/보호 맥락 — 인증 뒤 표면이 캡차에 막힘.
    CaptchaGated,
    /// 봇방어 중개(챌린지) 페이지 — 실제 표면 대신 중개 화면만 보임.
    Challenge,
    /// WAF 벤더 차단 페이지.
    WafBlock,
}

impl BlockedKind {
    fn title(self) -> &'static str {
        match self {
            BlockedKind::CaptchaGated => "캡차 게이트 뒤 표면 미검사",
            BlockedKind::Challenge => "봇방어 챌린지 뒤 표면 미검사",
            BlockedKind::WafBlock => "WAF 차단 뒤 표면 미검사",
        }
    }
}

/// 차단 표면 감지 — 캡차·JS챌린지·WAF차단 뒤는 자동 검사가 닿지 않는다.
/// 상용 스캐너도 이를 자동 우회하지 않으므로, 감지되면 미검사 표면으로 명시 보고하고
/// 요약에 미검사 건수를 남긴다 (조용한 미검사가 가장 나쁜 결과).
/// 오탐 방지: 캡차 위젯 단독(사이트 전역 포함이 흔함)이 아니라 로그인/보호 맥락과
/// 함께 있을 때만, WAF는 차단 상태코드와 벤더 표식이 함께 있을 때만 판정한다.
pub fn detect_blocked_surface(body: &str, status: u16) -> Option<(BlockedKind, String)> {
    let low = body.to_lowercase();
    // 1) 중개 챌린지 — 벤더 표식 우선, 없으면 도전 문구 + 차단 상태코드.
    let challenge_vendor = [
        "cf-challenge", "cf_chl", "px-captcha", "perimeterx", "datadome", "kasada",
        "captcha-delivery.com", "incapsula", "_px3_", "awswaf", "challenge-platform",
    ]
    .iter()
    .any(|m| low.contains(m));
    let challenge_text = low.contains("just a moment")
        || low.contains("verify you are human")
        || low.contains("attention required")
        || low.contains("unusual traffic")
        || low.contains("checking your browser")
        || low.contains("are you a robot");
    if challenge_vendor || (challenge_text && matches!(status, 403 | 429 | 503)) {
        return Some((
            BlockedKind::Challenge,
            "봇방어 중개(챌린지) 페이지가 실제 표면을 가림 — 자동 우회 없이 미검사로 보고".to_string(),
        ));
    }
    // 2) 캡차 게이트 — 위젯 + 로그인/보호 맥락.
    let widget = [
        "g-recaptcha", "h-captcha", "cf-turnstile", "gstatic.com/recaptcha",
        "hcaptcha.com/captcha", "data-sitekey",
    ]
    .iter()
    .any(|m| low.contains(m));
    if widget {
        let gated = low.contains("type=\"password\"")
            || low.contains("type='password'")
            || low.contains("login")
            || low.contains("sign in")
            || low.contains("register")
            || low.contains("password")
            || matches!(status, 401 | 403 | 429);
        if gated {
            return Some((
                BlockedKind::CaptchaGated,
                "캡차가 로그인/보호 표면을 가림 — 자동 제출 불가, 해당 표면 미검사".to_string(),
            ));
        }
    }
    // 3) WAF 차단 — 차단 상태코드 + 벤더 표식.
    if matches!(status, 403 | 429 | 503) {
        let vendor = [
            "akamai", "incapsula", "imperva", "cloudflare", "sucuri", "big-ip",
            "fortinet", "fortiweb", "barracuda", "mod_security", "wordfence",
            "request blocked", "access denied",
        ]
        .iter()
        .any(|m| low.contains(m));
        if vendor {
            return Some((
                BlockedKind::WafBlock,
                format!("WAF 차단 페이지(HTTP {status}) — 차단 뒤 표면 미검사"),
            ));
        }
    }
    None
}

pub fn run_sweep_with_config(host: &str, port: Option<u16>, mut cfg: SweepConfig) -> ProbeReport {
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
    // 차단 표면 — 정적 루트에서 감지되면 미검사 표면으로 명시 (조용한 미검사 방지).
    if let Some((kind, detail)) = detect_blocked_surface(&base.root_body, base.root_status) {
        hits.push(hit("blocked-surface", Severity::Info, primary.clone(),
            kind.title().to_string(), detail, String::new(),
            format!("GET / → {}", base.root_status), Some(base.root_status)));
    }
    bump_done(&cfg, &counter);
    let base_url = primary.trim_end_matches('/').to_string();

    // 게이트 폼 로그인 — 성공 시 세션 쿠키를 스윕 전체에 적용 (인증 스캔).
    if let Some(lc) = cfg.login.clone() {
        set_phase(&cfg, "게이트 로그인");
        match gate_login(&agent, &cfg, &base_url, &base.root_body, &lc, &counter) {
            Some(cookie) => cfg.cookie = Some(cookie),
            None => hits.push(hit("authform", Severity::Info, primary.clone(),
                "게이트 로그인 실패 — 미인증으로 진행".into(),
                "폼 로그인 실패 (자격·폼 구조 확인 필요) — require_auth 정책이면 게이트 실패".into(),
                String::new(), "POST 로그인".into(), None)),
        }
        bump_done(&cfg, &counter);
    }

    // SPA 렌더 DOM (브라우저가 있을 때만) — 파라미터·스크립트·폼 추가 수집.
    let mut params = extract_params(&base.root_body);
    let mut scripts = extract_scripts(&base.root_body, host);
    let mut rendered: Option<String> = None;
    let mut cdp_api: Vec<String> = Vec::new();
    if Instant::now() < deadline && !cancelled(&cfg) {
        set_phase(&cfg, "렌더 DOM");
        match (cfg.no_browser, find_browser()) {
            (true, _) => hits.push(hit("render", Severity::Info, primary.clone(),
                "--no-browser — 정적 파싱만".into(), "의도적 브라우저 비활성 (SPA 커버리지 제한)".into(),
                String::new(), "render 스킵".into(), None)),
            (false, None) => hits.push(hit("render", Severity::Info, primary.clone(),
                "렌더러 없음 — 정적 파싱만".into(), "헤드리스 브라우저 미설치 (SPA 커버리지 제한)".into(),
                String::new(), "render 스킵".into(), None)),
            (false, Some(bin)) => {
                // CDP 우선 (DOM + XHR + 상호작용 상태), 실패 시 --dump-dom 폴백.
                let cdp = cdp_render(&primary, &cfg, &bin, &agent, deadline);
                let mut cdp_scrolled = 0usize;
                let mut cdp_session: Option<String> = None;
                let mut cdp_authed = false;
                if let Some(surf) = &cdp {
                    cdp_api = surf
                        .api_urls
                        .iter()
                        .filter(|u| u.contains('?'))
                        .take(16)
                        .cloned()
                        .collect();
                    // 탐색 상태 URL(쿼리) 우선 편입.
                    for st in surf.states.iter().rev() {
                        if st.url.contains('?') && !cdp_api.contains(&st.url) {
                            cdp_api.insert(0, st.url.clone());
                        }
                    }
                    cdp_api.truncate(16);
                    cdp_scrolled = surf.scrolled;
                    cdp_session = surf.session_cookie.clone();
                    cdp_authed = surf.authenticated;
                }
                let dom_opt: Option<(String, &str, Vec<CdpState>)> = cdp
                    .map(|s| (s.dom, "cdp", s.states))
                    .or_else(|| render_dom_with(&primary, &cfg, Some(bin)).map(|d| (d, "dump-dom", Vec::new())));
                match dom_opt {
                    Some((dom, via, states)) => {
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
                        for st in &states {
                            for p in extract_params(&st.dom) {
                                if !params.contains(&p) {
                                    params.push(p);
                                }
                            }
                            for s in extract_scripts(&st.dom, host) {
                                if !scripts.contains(&s) {
                                    scripts.push(s);
                                }
                            }
                        }
                        params.truncate(PARAM_CAP);
                        hits.push(hit("render", Severity::Info, primary.clone(),
                            format!("JS 렌더 DOM 확보 ({}B, {via})", dom.len()),
                            format!("추가 파라미터 {}개·스크립트 {}개·XHR 표면 {}개·SPA 상태 {}개·스크롤 {}회{}",
                                params.len().saturating_sub(np), scripts.len().saturating_sub(ns), cdp_api.len(), states.len(),
                                cdp_scrolled, if cdp_authed { "·인증 상태" } else { "" }),
                            String::new(), if via == "cdp" { "cdp render" } else { "headless --dump-dom" }.into(), None));
                        // SPA 로그인 세션을 스윕 전체에 적용 (이후 프로브가 인증 표면을 본다).
                        if cdp_authed {
                            if let Some(sess) = cdp_session {
                                if cfg.cookie.as_ref().map(|c| c.trim().is_empty()).unwrap_or(true) {
                                    cfg.cookie = Some(sess);
                                }
                            }
                            hits.push(hit("authform", Severity::Info, primary.clone(),
                                "SPA 로그인 성공 — 인증 상태로 계속".into(),
                                "브라우저에서 로그인 폼 제출 후 세션 확보, 이후 프로브에 적용".into(),
                                String::new(), "cdp login".into(), None));
                        }
                        rendered = Some(dom);
                    }
                    None => hits.push(hit("render", Severity::Info, primary.clone(),
                        "렌더 실패 — 정적 파싱으로 진행".into(), String::new(), String::new(),
                        "cdp + headless --dump-dom".into(), None)),
                }
            }
        }
    }
    let dom_ref = rendered.as_deref().unwrap_or(&base.root_body);
    // 렌더 DOM 차단 표면 — JS 챌린지는 렌더 후에만 드러난다. 정적 루트와 같은 종류면 중복 보고 금지.
    // 렌더 DOM에는 상태코드가 없으므로 200(보수적: 문구 단독 판정 제외)으로 검사한다.
    if let Some(dom) = rendered.as_deref() {
        if let Some((kind, detail)) = detect_blocked_surface(dom, 200) {
            let dup = hits.iter().any(|h| h.category == "blocked-surface" && h.title == kind.title());
            if !dup {
                hits.push(hit("blocked-surface", Severity::Info, primary.clone(),
                    kind.title().to_string(), detail, String::new(), "render DOM".into(), None));
            }
        }
    }

    // 인증 후 크롤 — 동일 호스트 bounded BFS (GET 전용).
    let mut crawled: Vec<CrawledPage> = Vec::new();
    if let Some(cc) = &cfg.crawl {
        if Instant::now() < deadline && !cancelled(&cfg) {
            set_phase(&cfg, "크롤 수집");
            crawled = crawl_collect(&agent, &cfg, &base_url, &primary, cc.max_pages, cc.max_depth, &counter, deadline);
            bump_done(&cfg, &counter);
        }
    }

    // danger 폼 크롤 — 동의 기반 무해 제출 (비로그인·비파괴만).
    if cfg.danger && Instant::now() < deadline && !cancelled(&cfg) {
        set_phase(&cfg, "폼 크롤");
        let (form_pages, form_hits) = crawl_forms_danger(&agent, &cfg, &base_url, &primary, dom_ref, &counter);
        crawled.extend(form_pages);
        hits.extend(form_hits);
        bump_done(&cfg, &counter);
    }

    // Stored-XSS 후보 표면화 — 세이프 모드에서만 (쓰기 없음).
    if !cfg.danger && Instant::now() < deadline && !cancelled(&cfg) {
        set_phase(&cfg, "저장형 후보");
        let mut extra: Vec<(&str, &str)> =
            crawled.iter().map(|p| (p.url.as_str(), p.body.as_str())).collect();
        if rendered.is_some() {
            extra.push((primary.as_str(), base.root_body.as_str()));
        }
        hits.extend(probe_stored_candidates(&agent, &cfg, &base_url, &primary, dom_ref, &extra, &counter));
        bump_done(&cfg, &counter);
    }

    // OpenAPI取り込み — 명시 지정 시에만 (동일 호스트·JSON/YAML).
    let mut api_ops: Vec<ApiOp> = Vec::new();
    if let Some(oc) = &cfg.openapi {
        if Instant::now() < deadline && !cancelled(&cfg) {
            set_phase(&cfg, "OpenAPI取り込み");
            match load_openapi_source(&oc.source, host, port, &agent, &cfg, &counter) {
                Some(text) => {
                    api_ops = parse_openapi_paths(&text);
                    for op in api_ops.iter().take(API_HIT_CAP) {
                        let is_get = op.method == "get";
                        hits.push(hit("api-surface", Severity::Info,
                            format!("{base_url}{}", op.probe_path),
                            format!("OpenAPI {} {} — {}",
                                op.method.to_uppercase(), op.path,
                                if is_get { "GET 프로브 투입" } else { "변경 오퍼레이션(미전송)" }),
                            if is_get {
                                format!("쿼리: {}", if op.query.is_empty() { "(없음)".to_string() } else { op.query.join(", ") })
                            } else {
                                "쓰기 가능 — 스펙 표면만 기록".to_string()
                            },
                            String::new(), format!("OpenAPI {}", oc.source), None));
                    }
                    if api_ops.is_empty() {
                        hits.push(hit("api-surface", Severity::Info, primary.clone(),
                            "OpenAPI 스펙 파싱 실패 — 무시".into(),
                            "JSON 아님·버전 미지원·paths 없음 중 하나".into(),
                            String::new(), format!("OpenAPI {}", oc.source), None));
                    }
                }
                None => hits.push(hit("api-surface", Severity::Info, primary.clone(),
                    "OpenAPI 소스 거부 — 동일 호스트·크기 제한".into(),
                    "URL 호스트 불일치·수신 실패·2MB 초과 중 하나".into(),
                    String::new(), format!("OpenAPI {}", oc.source), None)),
            }
            bump_done(&cfg, &counter);
        }
    }

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
    let mut all_scripts = scripts;
    for page in &crawled {
        for s in extract_scripts(&page.body, host) {
            if !all_scripts.contains(&s) {
                all_scripts.push(s);
            }
        }
    }
    for sp in all_scripts.into_iter().take(JS_FETCH_CAP) {
        jobs.push(Job {
            url: format!("{base_url}{sp}"),
            method: "GET",
            headers: vec![],
            kind: ProbeKind::Js,
        });
    }
    jobs.extend(param_jobs_for(&base_url, &params, true));
    // OpenAPI GET 오퍼레이션 — 쿼리 파라미터 P1 투입 (GET만, 변경 오퍼레이션 미전송).
    for op in api_ops.iter().filter(|o| o.method == "get").take(API_GET_CAP) {
        if op.query.is_empty() {
            continue;
        }
        jobs.extend(param_jobs_for(&format!("{}{}", base_url, op.probe_path), &op.query, false));
    }
    // CDP XHR 표면 — 쿼리 있는 앞 3 URL 파라미터 투입 (루트 중복 제외).
    let mut api_pages = 0;
    for api in &cdp_api {
        if api_pages >= 3 {
            break;
        }
        let Some(qpos) = api.find('?') else { continue };
        let page_base = &api[..qpos];
        if page_base == base_url || *page_base == format!("{base_url}/") {
            continue;
        }
        let keys: Vec<String> = extract_params(api).into_iter().take(8).collect();
        if keys.is_empty() {
            continue;
        }
        jobs.extend(param_jobs_for(page_base, &keys, false));
        api_pages += 1;
    }
    // OOB 블라인드 SSRF 잡 — 응답 무시, 종료 시 콜백 매칭으로 확정 (루트 전용).
    // 명시 지정 우선, 루프백 대상은 자동 기동 (동일 호스트 = 대상 egress 불필요).
    // 원격 + 미지정이면 블라인드 SSRF 미검사를 명시한다 (조용한 미검사 방지).
    let mut oob_tokens: Vec<(String, String, String)> = Vec::new();
    let mut oob_auto = false;
    let oob_rx: Option<OobReceiver> = match &cfg.oob {
        Some(oc) => match OobReceiver::start(&oc.bind, &oc.base) {
            Ok(rx) => Some(rx),
            Err(e) => {
                hits.push(hit("ssrf-signal", Severity::Info, primary.clone(),
                    "OOB 수신기 기동 실패 — 블라인드 SSRF 미검사".into(),
                    format!("바인드 실패: {e}"),
                    String::new(), "OOB listen".into(), None));
                None
            }
        },
        None if is_loopback_host(host) => {
            match OobReceiver::start("127.0.0.1:0", "http://127.0.0.1:1/oob/") {
                Ok(mut rx) => {
                    // 실제 바인딩 포트로 덫 베이스 확정 (base는 placeholder였음).
                    rx.base = format!("http://127.0.0.1:{}/oob/", rx.local_port());
                    oob_auto = true;
                    Some(rx)
                }
                Err(_) => None, // 자동 기동 실패는 조용히 (명시 약속이 없었음)
            }
        }
        None => {
            hits.push(hit("ssrf-signal", Severity::Info, primary.clone(),
                "OOB 미지정 — 블라인드 SSRF 미검사".into(),
                "원격 대상 + --oob-base 미지정: 콜백 수신기 없이 블라인드 SSRF는 판정 불가 (반사 신호만 검사)".into(),
                String::new(), "OOB 미기동".into(), None));
            None
        }
    };
    if let Some(rx) = &oob_rx {
        for (i, param) in ssrf_params(&params, true).into_iter().take(SSRF_CAP).enumerate() {
            let token = format!("rc7oob{}-{}-{i}", std::process::id(), chrono::Utc::now().timestamp_millis());
            let job_url = format!("{base_url}/?{param}={}", pct_encode(&rx.url_for(&token)));
            oob_tokens.push((token.clone(), param.clone(), job_url.clone()));
            jobs.push(Job { url: job_url, method: "GET", headers: vec![], kind: ProbeKind::OobSsrf { param, token } });
        }
    }
    // 크롤 페이지 파라미터 잡 — 파라미터 있는 앞 3페이지 (루트 제외).
    let mut param_pages = 0;
    for page in &crawled {
        if param_pages >= 3 {
            break;
        }
        if page.url == primary {
            continue;
        }
        let pparams: Vec<String> = extract_params(&page.body).into_iter().take(8).collect();
        if pparams.is_empty() {
            continue;
        }
        let page_base = page.url.split('?').next().unwrap_or(&page.url);
        jobs.extend(param_jobs_for(page_base, &pparams, false));
        param_pages += 1;
    }
    // GraphQL introspection (GET).
    jobs.push(Job {
        url: format!("{base_url}/graphql?query={{__schema{{queryType{{name}}}}}}"),
        method: "GET",
        headers: vec![],
        kind: ProbeKind::Graphql,
    });
    // GraphQL depth — 15단계 중첩이 제한 언급 없이 통과하는지 (읽기 전용).
    let deep = "{a{a{a{a{a{a{a{a{a{a{a{a{a{a{__typename}}}}}}}}}}}}}}}";
    jobs.push(Job {
        url: format!("{base_url}/graphql?query={deep}"),
        method: "GET",
        headers: vec![],
        kind: ProbeKind::GraphqlDepth,
    });
    // WebSocket Upgrade — 101 전환 여부만 확인 (핸드셰이크 미완성).
    for wsp in ["/", "/ws", "/socket", "/socket.io/"] {
        jobs.push(Job {
            url: format!("{base_url}{wsp}"),
            method: "GET",
            headers: vec![
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
                ("Sec-WebSocket-Key".to_string(), "cmVkc2Vjd2Vic29ja2V0".to_string()),
                ("Sec-WebSocket-Version".to_string(), "13".to_string()),
            ],
            kind: ProbeKind::Websocket { path: wsp.to_string() },
        });
    }
    // Host 헤더 오염 — Host + X-Forwarded-Host canary.
    for hh in ["Host", "X-Forwarded-Host"] {
        jobs.push(Job {
            url: format!("{base_url}/"),
            method: "GET",
            headers: vec![(hh.to_string(), "evil-probe.test".to_string())],
            kind: ProbeKind::HostHeader { header: hh },
        });
    }
    // CORS 심화 — null Origin + preflight.
    jobs.push(Job {
        url: format!("{base_url}/"),
        method: "GET",
        headers: vec![("Origin".to_string(), "null".to_string())],
        kind: ProbeKind::CorsNull,
    });
    jobs.push(Job {
        url: format!("{base_url}/"),
        method: "OPTIONS",
        headers: vec![
            ("Origin".to_string(), EVIL_ORIGIN.to_string()),
            ("Access-Control-Request-Method".to_string(), "PUT".to_string()),
        ],
        kind: ProbeKind::CorsPreflight,
    });

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
            // IDOR/BOLA 탐색 말뭉치 — 루트 DOM + 크롤 본문 합본.
            let mut idor_corpus = dom_ref.to_string();
            for page in &crawled {
                if page.url != primary {
                    idor_corpus.push_str(&page.body);
                    idor_corpus.push('\n');
                }
            }
            hits.extend(probe_idor_adjacency(&agent, &cfg, &base_url, &idor_corpus, &counter));
            hits.extend(probe_bola_param(&agent, &cfg, &base_url, &idor_corpus, &counter));
            hits.extend(probe_stored_xss(&agent, &cfg, &base_url, &primary, dom_ref, &counter));
            if Instant::now() < deadline && !cancelled(&cfg) {
                hits.extend(probe_write_verify(&agent, &cfg, &base_url, &counter));
            }
            bump_done(&cfg, &counter);
        }
        hits.extend(scan_jwt_leak(dom_ref, &primary));
        hits.extend(scan_write_surface(dom_ref, &base_url));
        hits.extend(scan_bola_surface(dom_ref, &base_url));
        // 오프라인 2차 스캔 — 추가 요청 없음.
        hits.extend(scan_client_surface(dom_ref, &base.root_headers, &primary));
        // 기본 구성요소 스캔 — Server 배너·X-Powered-By·루트 본문을 CVE 테이블과 대조.
        hits.extend(scan_component_hits(&primary, &fingerprint_server(&base.root_headers)));
        hits.extend(scan_component_hits(&primary, &fingerprint_body(&primary, dom_ref)));
        if let Some(c) = cfg.cookie.as_ref() {
            if !c.trim().is_empty() {
                hits.extend(scan_deserialize_hits(&format!("{dom_ref}\n{c}"), &primary));
                hits.extend(jwt_offline_hits(c, &primary));
            } else {
                hits.extend(scan_deserialize_hits(dom_ref, &primary));
            }
        } else {
            hits.extend(scan_deserialize_hits(dom_ref, &primary));
        }
        // 크롤 페이지 오프라인 스캔 — 루트와 동일 세트 (페이지 기준 target).
        for page in &crawled {
            if page.url == primary {
                continue;
            }
            for (kind, ex) in find_secrets(&page.body).into_iter().take(3) {
                hits.push(hit("secret", Severity::High, page.url.clone(),
                    format!("{kind} (크롤 페이지)"), "수집 페이지 본문에 하드코딩 비밀".into(), ex,
                    format!("GET {}", page.url), None));
            }
            hits.extend(scan_jwt_leak(&page.body, &page.url));
            hits.extend(scan_write_surface(&page.body, &page.url));
            hits.extend(scan_bola_surface(&page.body, &page.url));
            hits.extend(scan_client_surface(&page.body, &page.headers, &page.url));
            hits.extend(scan_deserialize_hits(&page.body, &page.url));
            hits.extend(scan_component_hits(&page.url, &fingerprint_body(&page.url, &page.body)));
        }
        // 순차 2차 프로브 — 캐시 오염(안전 2단계) + 세션 엔트로피.
        if Instant::now() < deadline && !cancelled(&cfg) {
            hits.extend(probe_cache_isolation(&agent, &cfg, &base_url, &counter));
        }
        if Instant::now() < deadline && !cancelled(&cfg) {
            hits.extend(probe_session_entropy(&agent, &cfg, &base_url, &base.root_headers, &counter));
        }
        if !cancelled(&cfg) {
            set_phase(&cfg, "P1 검증");
        }
        hits.extend(verify_pass(&agent, &cfg, &base_url, &hits, &counter, deadline));
        bump_done(&cfg, &counter);
    }
    // OOB 콜백 확정 — 블라인드 SSRF (1초 유예 후 수신분 매칭).
    if let Some(rx) = &oob_rx {
        if !oob_tokens.is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1000));
        }
        let drained = rx.drain();
        let matched = match_oob_hits(&drained, &oob_tokens);
        let any_matched = !matched.is_empty();
        for (token, param, job_url) in matched {
            hits.push(hit("ssrf-signal", Severity::High, job_url,
                format!("SSRF 확정 — 블라인드 콜백 수신 (파라미터 '{param}')"),
                format!("대상이 덫 URL을 가져감 (토큰 {token}) — 서버측 요청 위조 확정"),
                token, "GET → 콜백".into(), None));
        }
        if !oob_tokens.is_empty() && !any_matched {
            hits.push(hit("ssrf-signal", Severity::Info, primary.clone(),
                "OOB 무응답 — 블라인드 SSRF 미확정".into(),
                format!("덫 {}개 살포 후 콜백 없음 ({}대상 egress 차단 가능) — 시간 기반 폴백은 SQLi·CMDI에 적용",
                    oob_tokens.len(), if oob_auto { "자동 수신기·" } else { "" }),
                String::new(), "OOB 대기 1초".into(), None));
        }
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
    dedup_component_hits(&mut hits);
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

/// 한 줄 요약 — `[sys] 기본 점검 — 항목 312개·발견 9건(…·정보 1)·직접 확인 3건·18.2초`.
pub fn sweep_summary_line(rep: &ProbeReport) -> String {
    let mut c = [0usize; 5];
    for h in &rep.hits {
        c[sev_rank(&h.severity) as usize] += 1;
    }
    let blocked = rep.hits.iter().filter(|h| h.category == "blocked-surface").count();
    let blocked_txt = if blocked > 0 { format!("·미검사 표면 {blocked}건") } else { String::new() };
    format!(
        "[sys] 기본 점검{}{} — 항목 {}개·발견 {}건(치명 {}/높음 {}/중간 {}/낮음 {}/정보 {})·직접 확인 {}건{blocked_txt}·{:.1}초.",
        if rep.authenticated { "(로그인 포함)" } else { "" },
        if rep.danger { "(위험 검사 포함)" } else { "" },
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
/// 체인 단서 — 카테고리 쌍이 공격 시나리오로 엮이면 P-ID 인용 힌트 (최대 5개).
/// 양쪽 다 info 면 점화하지 않는다. 세션 한정·동일 대상 계산 (저장 없음).
pub fn chain_hints(hits: &[ProbeHit]) -> Vec<String> {
    const RULES: &[(&[&str], &[&str], &str)] = &[
        (&["openredirect", "verify-redirect"], &["xss-reflect", "verify-xss", "stored-xss"],
            "리다이렉트→반사 체인: 외부 유도 후 스크립트 실행 (피싱 증폭)"),
        (&["auth-bypass", "auth-inject"], &["danger-idor", "danger-bola", "bola-surface"],
            "인증→객체참조 체인: 권한 우회 후 타인 리소스 접근"),
        (&["upload-surface"], &["paths", "secret"],
            "업로드→파일 체인: 업로드 후 설정·소스 탈취"),
        (&["sqli-signal", "verify-sqli"], &["secret", "paths"],
            "SQLi→자격 체인: DB 탈취 후 자격 재사용"),
        (&["cors"], &["auth-bypass"],
            "CORS→인증 체인: 크로스사이트 요청 위조"),
        (&["danger-creds"], &["authform", "auth-bypass"],
            "노출 자격→로그인 체인: 초기 자격으로 인증 후 표면 재탐색"),
        (&["secret"], &["authform"],
            "노출 자격→로그인 체인: 유출 자격으로 인증 시도"),
        (&["danger-write"], &["paths"],
            "쓰기→무결성 체인: 변조 후 지속성 확보"),
    ];
    let hot = |h: &ProbeHit| matches!(h.severity.as_str(), "critical" | "high" | "medium");
    let mut out = Vec::new();
    for (left, right, desc) in RULES {
        if out.len() >= 5 {
            break;
        }
        let a = hits.iter().find(|h| left.contains(&h.category.as_str()));
        let b = hits.iter().find(|h| {
            right.contains(&h.category.as_str()) && a.map(|x| x.id.as_str()) != Some(h.id.as_str())
        });
        if let (Some(a), Some(b)) = (a, b) {
            if hot(a) || hot(b) {
                out.push(format!("- [체인] {desc} ([{}]+[{}])", a.id, b.id));
            }
        }
    }
    out
}

// ── 배포 게이트 (CI 판정·SARIF·CVSS) ─────────────────────────────────────────────
// 게이트 판정은 결정적 스윕 결과에만 의존한다 (LLM 추론 제외 — 재현성 보장).

/// CVSS 3.1 Base 점수 계산 (FIRST 스펙 공식). 파싱 실패 시 None.
/// CVSS 3.1 기본 지표 수치.
struct BaseMetrics {
    av: f64,
    ac: f64,
    pr: f64,
    ui: f64,
    sc: bool,
    c: f64,
    i: f64,
    a: f64,
}

fn parse_base_vector(vector: &str) -> Option<BaseMetrics> {
    let body = vector.strip_prefix("CVSS:3.1/")?;
    let mut av: Option<f64> = None;
    let mut ac: Option<f64> = None;
    let mut pr = None;
    let mut ui: Option<f64> = None;
    let mut s_changed = None;
    let mut c: Option<f64> = None;
    let mut i: Option<f64> = None;
    let mut a: Option<f64> = None;
    for seg in body.split('/') {
        let (k, v) = seg.split_once(':')?;
        match k {
            "AV" => av = Some(match v { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => return None }),
            "AC" => ac = Some(match v { "L" => 0.77, "H" => 0.44, _ => return None }),
            "PR" => pr = Some(v),
            "UI" => ui = Some(match v { "N" => 0.85, "R" => 0.62, _ => return None }),
            "S" => s_changed = Some(match v { "U" => false, "C" => true, _ => return None }),
            "C" => c = Some(match v { "N" => 0.0, "L" => 0.22, "H" => 0.56, _ => return None }),
            "I" => i = Some(match v { "N" => 0.0, "L" => 0.22, "H" => 0.56, _ => return None }),
            "A" => a = Some(match v { "N" => 0.0, "L" => 0.22, "H" => 0.56, _ => return None }),
            _ => return None,
        }
    }
    let (av, ac, ui, sc, c, i, a) = (av?, ac?, ui?, s_changed?, c?, i?, a?);
    let pr = match pr? {
        "N" => 0.85,
        "L" => if sc { 0.68 } else { 0.62 },
        "H" => if sc { 0.5 } else { 0.27 },
        _ => return None,
    };
    Some(BaseMetrics { av, ac, pr, ui, sc, c, i, a })
}

/// Roundup: 소수 첫째, 올림 (부동소수 엡실론 보정).
/// 환경식 이중 반올림은 f64으로 유지한다 — f32 중간값 오차(≈5e-6)가 엡실론을 넘는다.
fn cvss_roundup_f64(x: f64) -> f64 {
    (x * 10.0 - 1e-6).ceil() / 10.0
}

fn cvss_roundup(x: f64) -> f32 {
    cvss_roundup_f64(x) as f32
}

pub fn cvss_base_score(vector: &str) -> Option<f32> {
    let m = parse_base_vector(vector)?;
    let iss = 1.0 - (1.0 - m.c) * (1.0 - m.i) * (1.0 - m.a);
    if iss <= 0.0 {
        return Some(0.0);
    }
    let impact = if m.sc {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };
    if m.sc && impact <= 0.0 {
        return Some(0.0);
    }
    let expl = 8.22 * m.av * m.ac * m.pr * m.ui;
    let raw = if m.sc { (1.08 * (impact + expl)).min(10.0) } else { (impact + expl).min(10.0) };
    Some(cvss_roundup(raw))
}

/// CVSS 요구사항 등급 — L/M/H/X(미정의=1.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReqLevel {
    L,
    M,
    H,
    X,
}

/// 시간 지표 — E (미정의 X=1.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TempE {
    X,
    U,
    P,
    F,
    C,
}

impl Default for TempE {
    fn default() -> Self {
        TempE::X
    }
}

/// 시간 지표 — RL (미정의 X=1.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TempRl {
    X,
    O,
    T,
    W,
    U,
}

impl Default for TempRl {
    fn default() -> Self {
        TempRl::X
    }
}

/// 시간 지표 — RC (미정의 X=1.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TempRc {
    X,
    U,
    R,
    C,
}

impl Default for TempRc {
    fn default() -> Self {
        TempRc::X
    }
}

fn req_m() -> ReqLevel {
    ReqLevel::M
}

/// CVSS 환경·시간 지표 — 게이트 정책에서 자산 가치·위협 맥락 주입.
/// 수정 기본 지표(MAV/MAC/MPR/MUI/MS)는 기본값 승계 (정책은 자산 맥락만 표현).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EnvMetrics {
    #[serde(default = "req_m")]
    pub cr: ReqLevel,
    #[serde(default = "req_m")]
    pub ir: ReqLevel,
    #[serde(default = "req_m")]
    pub ar: ReqLevel,
    #[serde(default)]
    pub e: TempE,
    #[serde(default)]
    pub rl: TempRl,
    #[serde(default)]
    pub rc: TempRc,
}

impl Default for EnvMetrics {
    fn default() -> Self {
        EnvMetrics { cr: ReqLevel::M, ir: ReqLevel::M, ar: ReqLevel::M, e: TempE::X, rl: TempRl::X, rc: TempRc::X }
    }
}

fn req_value(l: ReqLevel) -> f64 {
    match l {
        ReqLevel::L => 0.5,
        ReqLevel::M | ReqLevel::X => 1.0,
        ReqLevel::H => 1.5,
    }
}

/// CVSS 3.1 환경 점수 — FIRST 공식. 중립 지표(M/X)에서는 기본 점수와 일치한다.
pub fn cvss_env_score(vector: &str, env: &EnvMetrics) -> Option<f32> {
    let m = parse_base_vector(vector)?;
    let miss = (1.0
        - (1.0 - req_value(env.cr) * m.c)
            * (1.0 - req_value(env.ir) * m.i)
            * (1.0 - req_value(env.ar) * m.a))
    .min(0.915);
    if miss <= 0.0 {
        return Some(0.0);
    }
    let mi = if m.sc {
        7.52 * (miss - 0.029) - 3.25 * (miss - 0.02).powf(15.0)
    } else {
        6.42 * miss
    };
    if m.sc && mi <= 0.0 {
        return Some(0.0);
    }
    let me = 8.22 * m.av * m.ac * m.pr * m.ui;
    let raw = if m.sc { (1.08 * (mi + me)).min(10.0) } else { (mi + me).min(10.0) };
    let e = match env.e {
        TempE::X | TempE::C => 1.0,
        TempE::U => 0.91,
        TempE::P => 0.94,
        TempE::F => 0.97,
    };
    let rl = match env.rl {
        TempRl::X | TempRl::U => 1.0,
        TempRl::O => 0.95,
        TempRl::T => 0.96,
        TempRl::W => 0.97,
    };
    let rc = match env.rc {
        TempRc::X | TempRc::C => 1.0,
        TempRc::U => 0.92,
        TempRc::R => 0.96,
    };
    Some(cvss_roundup(cvss_roundup_f64(raw) * e * rl * rc))
}

/// 환경 지표 라벨 — SARIF `cvss-env` 속성용.
pub fn env_metrics_label(env: &EnvMetrics) -> String {
    format!("CR:{:?}/IR:{:?}/AR:{:?}/E:{:?}/RL:{:?}/RC:{:?}", env.cr, env.ir, env.ar, env.e, env.rl, env.rc)
}

/// 카테고리 대표 CWE. `render`(도구 상태)는 None.
pub fn category_cwe(category: &str) -> Option<u16> {
    Some(match category {
        "sqli-signal" | "verify-sqli" | "auth-inject" => 89,
        "xss-reflect" | "verify-xss" | "csti-signal" | "stored-xss" => 79,
        "ssti-eval" => 94,
        "cmdi-exec" | "verify-cmdi" => 78,
        "ldap-xpath-signal" => 90,
        "nosql-signal" => 943,
        "openredirect" | "verify-redirect" | "redirect" => 601,
        "ssrf-signal" => 918,
        "crlf-inject" => 113,
        "hpp-ambiguity" => 235,
        "host-header" => 640,
        "cors" => 942,
        "auth-bypass" => 287,
        "danger-creds" => 798,
        "danger-idor" | "danger-bola" | "bola-surface" => 639,
        "danger-write" => 73,
        "secret" => 798,
        "paths" | "verify-paths" => 200,
        "methods" | "method-override" => 650,
        "upload-surface" => 434,
        "headers" | "csp-analysis" => 693,
        "cookies" => 614,
        "tls" => 327,
        "jwt-offline" => 347,
        "deserialize-sig" => 502,
        "graphql-introspect" | "graphql-depth" | "websocket-surface" | "js-hint" | "authform" | "api-surface" => 200,
        "graphql-mutation" => 863,
        "cache-poison" => 444,
        "session-entropy" => 330,
        "tabnabbing" => 1021,
        "vuln-component" => 1395,
        _ => return None,
    })
}

/// 카테고리 대표 CVSS 3.1 벡터 — 환경 지표 미반영, 보안팀이 조율할 출발점.
/// 점수는 `cvss_base_score` 로 계산한다 (손계산 아님).
///
/// 정교화 규칙 (감사 일관성):
/// - 밴드는 해당 카테고리가 실제로 방출하는 최대 확정 심각도와 일치한다.
/// - 벡터는 도구가 *입증한* 영향만 기술한다 (최악 가정 금지 — 예: 읽기 전용 LFI 는 C:H 뿐).
/// - Info 전용 표면 메모(bola-surface·upload-surface·js-hint·verify-paths·graphql-mutation)는
///   취약점이 아니라 정찰 기록이므로 점수를 매기지 않는다 (SARIF security-severity 생략).
pub fn category_cvss_vector(category: &str) -> Option<&'static str> {
    Some(match category {
        // Critical — 기본 자격으로 즉시 침투 입증.
        "danger-creds" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        // High — 확정 인젝션/우회 (읽기+제한적 쓰기 입증).
        "verify-sqli" | "ssti-eval" | "auth-inject" | "auth-bypass" | "verify-cmdi" => {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        }
        // Critical — 명령 출력 노출로 원격 코드 실행 입증.
        "cmdi-exec" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        // High — 오류·노출 기반 신호 (기밀성 영향 입증, 쓰기 미입증).
        "sqli-signal" | "ldap-xpath-signal" | "nosql-signal" | "secret" | "paths"
        | "cors" | "vuln-component" => {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        }
        // High — CRLF 응답 분할·동의 기반 쓰기 입증은 무결성 훼손이 본질 (동점 7.5).
        "crlf-inject" | "danger-write" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        // High — SSRF 내부 도달 입증 (스코프 전환).
        "ssrf-signal" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        // High — 확정 XSS 사다리: 미확인 반사 8.2 < 브레이크아웃 확정 8.8.
        // 저장형은 확정과 동점 — 지속성은 base 지표에 없고(temporal 영역) 기본 영향이 같기 때문.
        "xss-reflect" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
        "verify-xss" | "stored-xss" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L",
        // High — 외부 악성 도메인 완전 유도 (피싱 완결).
        "openredirect" | "verify-redirect" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
        // High — 타인 식별자 읽기 입증 (인증 세션, PR:L).
        "danger-idor" | "danger-bola" => "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        // Medium — 루트 리다이렉트 관측 (외부, 미확인).
        "redirect" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        // Medium — 서명·설정 노출 (읽기, 제한적).
        "deserialize-sig" | "methods" | "graphql-introspect" | "websocket-surface" => {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        }
        // Medium — JWT 오프라인 분석 가능 (위조는 미입증).
        "jwt-offline" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        // Medium — 방어 헤더 부재 (직접 착취 불가).
        "headers" | "host-header" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        // Medium — HttpOnly/Secure 없는 민감 쿠키 (XSS 선행 필요).
        "cookies" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
        // Medium — 세션 추측 가능 (엔트로피 부족).
        "session-entropy" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        // Medium — 캐시 키 조작 가능 (포이즈닝은 미입증).
        "cache-poison" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        // Low — 약한 신호·완화책 부재.
        "hpp-ambiguity" | "method-override" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "graphql-depth" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "csti-signal" | "csp-analysis" | "authform" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "tabnabbing" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "tls" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        _ => return None,
    })
}

fn default_fail_on() -> Vec<String> {
    vec!["critical".to_string(), "high".to_string()]
}

/// 억제 1건 — FP·수용 위험의 명시적 예외 (사유·승인자·만료 필수, 감사 추적).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    pub category: String,
    pub target_contains: String,
    pub reason: String,
    pub approver: String,
    pub until: String, // YYYY-MM-DD — 만료 시 무시(fail-closed)
    #[serde(default)]
    pub note: String,
}

/// 게이트 정책 — 기본은 절대 Zero-High.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatePolicy {
    #[serde(default = "default_fail_on")]
    pub fail_on: Vec<String>,
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
    /// true 면 인증 스캔 필수 — 미인증이면 실패 (로그인 실패의 조용한 통과 방지).
    #[serde(default)]
    pub require_auth: bool,
    /// CVSS 환경·시간 지표 — 지정 시 SARIF 심각도에 환경 점수 반영 (게이트 판정은 라벨 기준 유지).
    #[serde(default)]
    pub cvss_env: Option<EnvMetrics>,
}

impl Default for GatePolicy {
    fn default() -> Self {
        GatePolicy { fail_on: default_fail_on(), suppressions: Vec::new(), require_auth: false, cvss_env: None }
    }
}

/// 게이트 정책 파싱+검증 — 무효 심각도·빈 사유/승인자·무효 날짜는 거부.
pub fn parse_gate_policy(text: &str) -> Result<GatePolicy, String> {
    let p: GatePolicy = serde_json::from_str(text).map_err(|e| format!("정책 파싱 실패: {e}"))?;
    if p.fail_on.is_empty() {
        return Err("fail_on 이 비어 있습니다 — 최소 1개 심각도 필요.".into());
    }
    for s in &p.fail_on {
        if !["critical", "high", "medium", "low", "info"].contains(&s.as_str()) {
            return Err(format!("무효 심각도: '{s}'"));
        }
    }
    for s in &p.suppressions {
        if s.category.trim().is_empty() || s.target_contains.trim().is_empty() {
            return Err("억제는 category·target_contains 필수.".into());
        }
        if s.reason.trim().is_empty() {
            return Err("억제 사유(reason) 필수.".into());
        }
        if s.approver.trim().is_empty() {
            return Err("억제 승인자(approver) 필수.".into());
        }
        if chrono::NaiveDate::parse_from_str(s.until.trim(), "%Y-%m-%d").is_err() {
            return Err(format!("무효 until 날짜: '{}' (YYYY-MM-DD).", s.until));
        }
    }
    Ok(p)
}

/// 억제된 발견 — 원본 + 억제 근거.
#[derive(Debug, Clone, Serialize)]
pub struct SuppressedHit {
    pub hit: ProbeHit,
    pub reason: String,
    pub approver: String,
    pub until: String,
}

/// 게이트 판정 — `pass` 가 배포可否. `today` 는 YYYY-MM-DD.
#[derive(Debug, Clone, Serialize)]
pub struct GateVerdict {
    pub pass: bool,
    pub authenticated: bool,
    pub fail_on: Vec<String>,
    pub blocking: Vec<ProbeHit>,
    pub suppressed: Vec<SuppressedHit>,
    pub expired: Vec<String>,
    pub evaluated_day: String,
}

/// 게이트 평가 — fail_on 심각도 발견 중 유효 억제 없는 것이 1건이라도 있으면 실패.
/// 만료 억제는 무시하고 `expired` 에 기록한다 (fail-closed).
pub fn evaluate_gate(rep: &ProbeReport, policy: &GatePolicy, today: &str) -> GateVerdict {
    let mut blocking = Vec::new();
    let mut suppressed = Vec::new();
    let mut expired: Vec<String> = Vec::new();
    for h in &rep.hits {
        if !policy.fail_on.iter().any(|s| s == &h.severity) {
            continue;
        }
        let hit_sup = policy.suppressions.iter().find(|s| {
            s.category == h.category && h.target.contains(&s.target_contains)
        });
        match hit_sup {
            None => blocking.push(h.clone()),
            Some(s) if s.until.trim() >= today => suppressed.push(SuppressedHit {
                hit: h.clone(),
                reason: s.reason.clone(),
                approver: s.approver.clone(),
                until: s.until.clone(),
            }),
            Some(s) => {
                let desc = format!("{} {} (만료 {})", s.category, s.target_contains, s.until);
                if !expired.contains(&desc) {
                    expired.push(desc);
                }
                blocking.push(h.clone());
            }
        }
    }
    if policy.require_auth && !rep.authenticated {
        blocking.push(ProbeHit {
            id: "P-000".into(),
            category: "gate".into(),
            severity: "high".into(),
            target: rep.target.clone(),
            title: "인증 스캔 요구됨 — 로그인 실패 또는 미인증".into(),
            detail: "정책 require_auth=true 지만 인증 없이 스캔됨 — 로그인 안쪽 미검사".into(),
            evidence: String::new(),
            request: String::new(),
            status: None,
        });
    }
    GateVerdict {
        pass: blocking.is_empty(),
        authenticated: rep.authenticated,
        fail_on: policy.fail_on.clone(),
        blocking,
        suppressed,
        expired,
        evaluated_day: today.to_string(),
    }
}

fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// SARIF 2.1.0 리포트 — CI 코드 스캐닝 연동용 (GitLab·GitHub).
/// 전 발견을 results 로, 억제는 `suppressions` 로 기록한다.
pub fn sarif_report(rep: &ProbeReport, verdict: &GateVerdict, env: Option<&EnvMetrics>) -> Value {
    let mut rules: Vec<Value> = Vec::new();
    let mut seen_cats: Vec<String> = Vec::new();
    for h in &rep.hits {
        if seen_cats.contains(&h.category) {
            continue;
        }
        seen_cats.push(h.category.clone());
        let mut props = serde_json::Map::new();
        if let Some(cwe) = category_cwe(&h.category) {
            props.insert("cwe".into(), json!(format!("CWE-{cwe}")));
        }
        if let Some(v) = category_cvss_vector(&h.category) {
            props.insert("cvss-vector".into(), json!(v));
            let score = match env {
                Some(e) => cvss_env_score(v, e),
                None => cvss_base_score(v),
            };
            if let Some(s) = score {
                props.insert("security-severity".into(), json!(format!("{s:.1}")));
            }
            if let Some(e) = env {
                props.insert("cvss-env".into(), json!(env_metrics_label(e)));
            }
        }
        rules.push(json!({
            "id": h.category,
            "name": h.category,
            "shortDescription": { "text": h.category },
            "fullDescription": { "text": format!("RedCell finding category: {}", h.category) },
            "properties": props,
        }));
    }
    let mut results: Vec<Value> = Vec::new();
    for h in &rep.hits {
        let mut r = json!({
            "ruleId": h.category,
            "level": sarif_level(&h.severity),
            "message": { "text": format!("[{}] [{}] {} — {}", h.id, h.severity, h.title, h.target) },
            "locations": [{ "physicalLocation": { "artifactLocation": { "uri": h.target } } }],
        });
        if let Some(s) = verdict.suppressed.iter().find(|s| s.hit.id == h.id) {
            r["suppressions"] = json!([{
                "kind": "external",
                "justification": format!("{} (승인: {}, 만료: {})", s.reason, s.approver, s.until),
            }]);
        }
        results.push(r);
    }
    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": { "driver": {
                "name": "redcell-sweep",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://redcell.local/docs/gate",
                "rules": rules,
            }},
            "results": results,
        }],
    })
}

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
            " · 파괴적 프로브 포함(사용자 명시 동의 — 기본자격·IDOR 인접·BOLA 파라미터·쓰기검증)"
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
        // 짧은 입력 패닉 회귀 (폼 응답 "saved" 등) — needle 이 안 들어가면 None.
        assert_eq!(find_ascii_ci("saved", "<input", 0), None);
        assert_eq!(find_ascii_ci("saved", "name=\"", 0), None);
        assert_eq!(find_ascii_ci("", "<form", 0), None);
        assert!(extract_params("saved").is_empty());
        assert!(extract_params("").is_empty());
    }

    #[test]
    fn sql_fingerprints_match() {
        assert!(!find_sql_errors("hello world").is_empty() == false);
        assert!(!find_sql_errors("You have an error in your SQL syntax near ''").is_empty());
        assert!(!find_sql_errors("PGQUERY failed: unterminated quoted string").is_empty());
    }

    #[test]
    fn protocol_surface_classifiers() {
        // OIDC 파싱.
        let oidc = r#"{"issuer":"https://idp.t/realms/x","authorization_endpoint":"https://idp.t/a","token_endpoint":"https://idp.t/t","response_types_supported":["code"]}"#;
        let (iss, ha, ht, imp) = parse_oidc_config(oidc).expect("파싱");
        assert_eq!(iss, "https://idp.t/realms/x");
        assert!(ha && ht && !imp);
        let oidc2 = r#"{"issuer":"https://idp.t/","response_types_supported":["token","id_token"]}"#;
        assert!(parse_oidc_config(oidc2).unwrap().3, "implicit 감지");
        assert!(parse_oidc_config("not json").is_none());
        let (sev, title) = classify_path("/.well-known/openid-configuration", 200, oidc2, None).expect("판정");
        assert_eq!(sev, Severity::Medium, "{title}");
        // SAML — 흔적 없으면 무시 (SPA 폴백).
        assert!(classify_path("/saml/metadata", 200, "<html>app</html>", None).is_none());
        let (sev, _) = classify_path("/saml/metadata", 200, "<EntityDescriptor id=\"x\">", None).expect("판정");
        assert_eq!(sev, Severity::Info);
        // gRPC.
        let (sev, _) = classify_path("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", 200, "grpc-status: 12", None).expect("판정");
        assert_eq!(sev, Severity::Medium);
        // WebSocket arm — 101 확정.
        let job = Job { url: "http://t/ws".into(), method: "GET", headers: vec![], kind: ProbeKind::Websocket { path: "/ws".into() } };
        let mut out = Vec::new();
        classify_job(&job, Ok(Resp { status: 101, headers: vec![], body: String::new() }), &mut out);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].category, "websocket-surface");
        // GraphQL depth arm — 제한 언급 없으면 신호.
        let job2 = Job { url: "http://t/graphql".into(), method: "GET", headers: vec![], kind: ProbeKind::GraphqlDepth };
        let mut out2 = Vec::new();
        classify_job(&job2, Ok(Resp { status: 200, headers: vec![], body: r#"{"data":{"a":{"__typename":"Q"}}}"#.into() }), &mut out2);
        assert_eq!(out2.len(), 1, "{out2:?}");
        let mut out3 = Vec::new();
        classify_job(&job2, Ok(Resp { status: 200, headers: vec![], body: r#"{"errors":[{"message":"max depth exceeded"}]}"#.into() }), &mut out3);
        assert!(out3.is_empty(), "제한 있으면 신호 없음: {out3:?}");
        // GraphQL 뮤테이션 플래그.
        let job3 = Job { url: "http://t/graphql".into(), method: "GET", headers: vec![], kind: ProbeKind::Graphql };
        let mut out4 = Vec::new();
        classify_job(&job3, Ok(Resp { status: 200, headers: vec![], body: r#"{"__schema":{"queryType":{"name":"Q"},"mutationType":{"name":"M"}}}"#.into() }), &mut out4);
        assert_eq!(out4.len(), 2, "introspect+mutation: {out4:?}");
    }

    #[test]
    fn component_cve_matching() {
        // 버전 비교.
        assert!(version_lt("1.12.4", "3.5.0"));
        assert!(version_lt("3.4.9", "3.5.0"));
        assert!(!version_lt("3.5.0", "3.5.0"));
        assert!(!version_lt("3.6.0", "3.5.0"));
        assert!(version_lt("2.4.50", "2.4.51"));
        assert!(!version_lt("abc", "3.5.0"));
        // 테이블 대조 — 브랜치·EOL.
        assert_eq!(lookup_cves("jquery", "1.12.4").len(), 1);
        assert!(lookup_cves("jquery", "3.7.1").is_empty());
        assert_eq!(lookup_cves("bootstrap", "3.3.7").len(), 1);
        assert!(lookup_cves("bootstrap", "5.3.0").is_empty(), "5.x 는 테이블에 없음");
        assert_eq!(lookup_cves("php", "5.6.40").len(), 1);
        assert!(lookup_cves("php", "8.2.0").is_empty());
        assert_eq!(lookup_cves("apache", "2.4.49").len(), 1);
        assert!(lookup_cves("apache", "2.4.58").is_empty());
        // Server 지문.
        let hs = vec![("Server".to_string(), "Apache/2.4.49 (Ubuntu) OpenSSL/1.1.1".to_string())];
        let fp = fingerprint_server(&hs);
        assert!(fp.iter().any(|(p, v, _)| p == "apache" && v == "2.4.49"), "{fp:?}");
        assert!(fp.iter().any(|(p, v, _)| p == "openssl" && v == "1.1.1"), "{fp:?}");
        // 번들·manifest 지문.
        let fb = fingerprint_body("http://t/static/jquery-1.12.4.min.js", "/*! jQuery v1.12.4 */");
        assert!(fb.iter().any(|(p, v, _)| p == "jquery" && v == "1.12.4"), "{fb:?}");
        let fm = fingerprint_body("http://t/package.json", r#"{"dependencies":{"lodash":"^4.17.20"}}"#);
        assert!(fm.iter().any(|(p, v, _)| p == "lodash" && v == "4.17.20"), "{fm:?}");
        let fw = fingerprint_body("http://t/", r#"<meta name="generator" content="WordPress 5.8" />"#);
        assert!(fw.iter().any(|(p, v, _)| p == "wordpress" && v == "5.8"), "{fw:?}");
        // 적중 + 중복 제거.
        let mut hits = scan_component_hits("http://t/", &fp);
        hits.extend(scan_component_hits("http://t/x", &fp));
        assert!(hits.iter().any(|h| h.category == "vuln-component" && h.title.contains("CVE-2021-41773")), "{hits:?}");
        dedup_component_hits(&mut hits);
        assert_eq!(hits.iter().filter(|h| h.category == "vuln-component").count(), 2, "apache+openssl 각 1건: {hits:?}");
        assert!(hits.iter().any(|h| h.detail.contains("외 1곳")), "중복 병기: {hits:?}");
    }

    #[test]
    fn second_vector_classifiers() {
        // LDAP/XPath — 복합 지문만 (bare 단어는 오탐 방지).
        assert!(find_ldap_xpath_errors("Invalid DN syntax near *").len() == 1);
        assert!(find_ldap_xpath_errors("javax.xml.xpath.XPathExpressionException").len() == 1);
        assert!(find_ldap_xpath_errors("hello world").is_empty());
        // NoSQL.
        assert!(find_nosql_errors("MongoError: unknown operator: $ne").len() >= 1);
        assert!(find_nosql_errors("hello world").is_empty());
        // SSRF — 보낸 URL 에 없던 시그니처만 신호, 단순 반사는 제외.
        assert!(ssrf_signal(SSRF_URL, "ami-id: ami-123").len() == 1);
        assert!(ssrf_signal(SSRF_URL, &format!("echo {SSRF_URL}")).is_empty());
        assert!(ssrf_signal(SSRF_URL, "hello world").is_empty());
        // SSTI 상수 정합.
        assert_eq!(SSTI_A * SSTI_B, SSTI_EXPECT.parse::<i64>().unwrap());
        // CMDI 출력 판정 — `id` 전체형만 확정, 조각은 무시.
        assert_eq!(cmdi_output_kind("uid=1000(www) gid=1000(www) groups=1"), Some("unix `id`"));
        assert_eq!(cmdi_output_kind("<pre>uid=0(root) gid=0(root)</pre>"), Some("unix `id`"));
        assert_eq!(cmdi_output_kind("Microsoft Windows [Version 10.0.19045]"), Some("windows `ver`"));
        assert!(cmdi_output_kind("uid=abc").is_none());
        assert!(cmdi_output_kind("myuid=1000x").is_none());
        assert!(cmdi_output_kind("uid=1000(www)").is_none()); // gid 절단
        assert!(cmdi_output_kind("hello world").is_none());
        // 탭내빙 — rel 없는 _blank 만 계수.
        let html = r#"<a href="x" target="_blank">a</a><a href="y" target="_blank" rel="noopener">b</a>"#;
        assert_eq!(count_tabnabbing(html), 1);
        assert_eq!(count_tabnabbing("<p>no links</p>"), 0);
        // CSP 분석.
        assert!(!scan_csp_weakness("default-src 'self'; script-src 'unsafe-inline'").is_empty());
        assert!(scan_csp_weakness("default-src 'self'").is_empty());
        // 역직렬화 관측.
        assert!(scan_deserialize("data=rO0ABQAAAA").len() == 1);
        assert!(scan_deserialize("hello world").is_empty());
        // JWT 위험 클레임 — kid 포함 헤더.
        let h = b64url_encode(br#"{"alg":"HS256","kid":"1"}"#);
        assert_eq!(jwt_risky_claims(&h), vec!["kid".to_string()]);
        let h2 = b64url_encode(br#"{"alg":"RS256"}"#);
        assert!(jwt_risky_claims(&h2).is_empty());
        // LLM 경로 분류.
        let (sev, _) = classify_path("/v1/models", 200, r#"{"data":[{"id":"gpt"}]}"#, None).expect("LLM 표면 판정");
        assert_eq!(sev, Severity::High);
        assert!(classify_path("/v1/models", 404, "", None).is_none());
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
        assert!(classify_path("/nope", 404, "", None).is_none());
        let (s, _) = classify_path("/.env", 200, "A=1\nB=2\nC=3\n", None).unwrap();
        assert_eq!(s, Severity::High);
        let (s, _) = classify_path("/.git/HEAD", 200, "ref: x", None).unwrap();
        assert_eq!(s, Severity::High);
        let (s, _) = classify_path("/%2e%2e/%2e%2e/etc/passwd", 200, "root:x:0:0", None).unwrap();
        assert_eq!(s, Severity::High); // 읽기 전용 LFI — CVSS 상한 7.5, Critical 과대 표기 금지
        assert!(classify_path("/%2e%2e/%2e%2e/etc/passwd", 200, "<p>nope</p>", None).is_none());
        let (s, _) = classify_path("/.env", 403, "", None).unwrap();
        assert_eq!(s, Severity::Info);
        // 3xx 로그인 게이트 — 실측(esdp.lge.com 전 경로 307→/login) 오탐 회귀 방지.
        assert!(classify_path("/.git/HEAD", 307, "", Some("/login?redirect=%2F.git%2FHEAD")).is_none());
        assert!(classify_path("/.env", 302, "", Some("http://t/signin?next=%2F.env")).is_none());
        assert!(classify_path("/nope", 307, "", Some("/login")).is_none());
        // 3xx 비로그인 — 민감 경로만 Info 추정.
        let (s, t) = classify_path("/.git/HEAD", 301, "", Some("/.git/HEAD/")).unwrap();
        assert_eq!(s, Severity::Info, "{t}");
        assert!(classify_path("/nope", 301, "", Some("/nope/")).is_none());
    }

    #[test]
    fn reflection_snippet_shapes() {
        let body = format!("<html><body>{}<p>marker-here-rc7x</p>{}</body></html>", "a".repeat(300), "b".repeat(300));
        let sn = reflection_snippet(&body, "rc7x");
        assert!(sn.contains("rc7x"), "{sn}");
        assert!(sn.contains("marker-here"), "{sn}");
        assert!(sn.len() <= 220, "윈도우 상한 초과 ({}B): {sn}", sn.len());
        // 마커 없으면 헤드 폴백.
        assert_eq!(reflection_snippet("<p>short</p>", "zzz"), "<p>short</p>");
    }

    #[test]
    fn verify_xss_breakout_confirms_raw() {
        let port = start_stub();
        let cfg = SweepConfig { threads: 16, rps: 500, req_timeout: Duration::from_secs(5), sweep_timeout: Duration::from_secs(60), cookie: None, danger: false, feedback: None, login: None, crawl: None, oob: None, openapi: None, p1_budget: 96, no_browser: true };
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        let h = rep.hits.iter().find(|h| h.category == "verify-xss");
        assert!(h.is_some(), "verify-xss 없음");
        let h = h.unwrap();
        // 스텁은 미가공 반사 — 브레이크아웃 확정 High 여야 한다.
        assert_eq!(h.severity, "high", "{h:?}");
        assert!(h.title.contains("브레이크아웃"), "{h:?}");
        assert!(h.evidence.contains("zrc7xq"), "반사 지점 발췌 필요: {}", h.evidence);
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
        assert!(line.contains("항목 10개") && line.contains("높음 1"), "{line}");
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
        // 시간 전용 블라인드 경로 — Boolean 무차분 + 지연 실행 (폴백 전용).
        if path == "/tblind" || path.starts_with("/tblind?") {
            let q = path.split('?').nth(1).unwrap_or("");
            if let Some(secs) = stub_sleep_secs(q) {
                std::thread::sleep(Duration::from_secs(secs));
                return json(200, "ok-delayed");
            }
            if q.contains("%27") || q.contains("%22") || q.contains('\'') || q.contains('"') {
                return json(200, "DB failed: You have an error in your SQL syntax near 'rc7x0''");
            }
            return json(200, "tblind ok");
        }
        if path == "/" || path.starts_with("/?") {
            if let Some(q) = path.split('?').nth(1) {
                // 오픈 리다이렉트.
                if q.contains("probe.test") {
                    return (302, vec![("Location".into(), EVIL_URL.into())], String::new());
                }
                // 지연 페이로드 (시간 기반 블라인드) — SQL 오류보다 먼저.
                if let Some(secs) = stub_sleep_secs(q) {
                    std::thread::sleep(Duration::from_secs(secs));
                    return json(200, "ok-delayed");
                }
                // Boolean 분화 — 1=2 무행 vs 오류 (fast path).
                if q.contains("1=2") || q.contains("1%3D2") {
                    return json(200, "no rows");
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
            "/openapi.json" => json(200, r#"{"openapi":"3.0.3","paths":{"/api/echo":{"get":{"parameters":[{"name":"q","in":"query"}]}},"/api/users/{id}":{"get":{"parameters":[{"name":"id","in":"path"}]}},"/api/users":{"post":{}}}}"#),
            p if p == "/api/echo" || p == "/api/echo/" => {
                let q = path.split('?').nth(1).unwrap_or("");
                let val = q.split('&').find_map(|kv| kv.strip_prefix("q=")).unwrap_or("");
                let decoded = pct_decode(val);
                json(200, &format!("<html><body>echo {decoded}<script>var m='{decoded}';</script></body></html>"))
            }
            p if p.starts_with("/api/users") => json(200, r#"{"id":1,"name":"stub"}"#),
            p if p.starts_with("/s") => json(200, "<p>s</p>"),
            _ => (404, vec![], "nf".into()),
        }
    }

    /// 지연 페이로드 판독 — SLEEP(n)·PG_SLEEP(n)·WAITFOR '0:0:n' (최대 5초).
    fn stub_sleep_secs(q: &str) -> Option<u64> {
        let qup = pct_decode(q).to_uppercase();
        if let Some(i) = qup.find("SLEEP(") {
            let n = qup[i + 6..].chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u64>().unwrap_or(5);
            Some(n.min(5).max(1))
        } else if qup.contains("WAITFOR") {
            let n = qup.rsplit(':').next().and_then(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u64>().ok()).unwrap_or(5);
            Some(n.min(5).max(1))
        } else {
            None
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
    fn blocked_surface_shapes() {
        // 챌린지 벤더 표식 → 차단.
        let (k, _) = detect_blocked_surface(r#"<html><body><div id="cf-challenge">...</div></body></html>"#, 200).unwrap();
        assert_eq!(k, BlockedKind::Challenge);
        // 도전 문구 + 차단 상태 → 차단, 200이면 무시 (오탐 방지).
        assert!(detect_blocked_surface("Just a moment... checking your browser", 403).is_some());
        assert!(detect_blocked_surface("Just a moment... checking your browser", 200).is_none());
        // 캡차 위젯 + 로그인 맥락 → 게이트, 위젯 단독은 무시.
        let gated = r#"<form action="/login"><input name="u"><input type="password" name="p"><div class="g-recaptcha"></div></form>"#;
        let (k, _) = detect_blocked_surface(gated, 200).unwrap();
        assert_eq!(k, BlockedKind::CaptchaGated);
        assert!(detect_blocked_surface(r#"<div class="g-recaptcha"></div><p>hello</p>"#, 200).is_none());
        // WAF 차단 — 상태 + 벤더 표식.
        let (k, _) = detect_blocked_surface("<title>Request blocked — Akamai</title>", 403).unwrap();
        assert_eq!(k, BlockedKind::WafBlock);
        assert!(detect_blocked_surface("<title>Request blocked — Akamai</title>", 200).is_none());
        assert!(detect_blocked_surface("<h1>Not Found</h1>", 404).is_none());
        // 요약에 미검사 건수 표기.
        let rep = ProbeReport {
            target: "t".into(), started_at: "".into(), duration_ms: 1000, probes_run: 5,
            authenticated: false, verified: 0, danger: false,
            hits: vec![hit("blocked-surface", Severity::Info, "u".into(), BlockedKind::Challenge.title().into(), "d".into(), "".into(), "".into(), None)],
        };
        assert!(sweep_summary_line(&rep).contains("미검사 표면 1건"));
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
        // 상호작용 감사 — 로그인 제출 수·note2 기록·파괴 이동 수.
        let dbg: std::sync::Arc<std::sync::Mutex<(u32, Vec<String>, u32)>> =
            std::sync::Arc::new(std::sync::Mutex::new((0, Vec::new(), 0)));
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let dbg = dbg.clone();
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
                    let (head, rbody) = match req.find("\r\n\r\n") {
                        Some(p) => (req[..p].to_string(), req[p + 4..].to_string()),
                        None => (req.clone(), String::new()),
                    };
                    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
                    let method = parts.next().unwrap_or("GET").to_string();
                    let path = parts.next().unwrap_or("/").split('?').next().unwrap_or("/").to_string();
                    let pad = "x".repeat(240);
                    let mut extra = String::new();
                    let (code, ctype, body) = if method == "POST" && path == "/login" {
                        dbg.lock().unwrap().0 += 1;
                        // CDP 로그인 실측: 정확히 테스트 자격일 때만 세션 발급 + 환영 화면 (폼 소멸).
                        // probe_login 의 우회 페이로드는 절대 매칭 불가 (오탐 방지).
                        if rbody.contains("uid=cdpuser&pwd=cdp-pass-7") {
                            extra = "Set-Cookie: SPA_SESS=ok7; Path=/\r\n".to_string();
                            (200u16, "text/html", format!("<html><body><h1>welcome-marker</h1><p>{pad}</p><a href=\"/step2\">step2</a></body></html>"))
                        } else {
                            (200u16, "text/html", "<html><body>invalid credentials</body></html>".to_string())
                        }
                    } else if method == "POST" && path == "/note2" {
                        let mval = rbody
                            .split('&')
                            .find_map(|kv| kv.strip_prefix("m="))
                            .unwrap_or("")
                            .to_string();
                        dbg.lock().unwrap().1.push(mval);
                        (200u16, "text/html", format!("<html><body><h1>noted2-ok-marker</h1><p>{pad}</p></body></html>"))
                    } else if path == "/dbg-counters" {
                        let (lp, notes, gone) = dbg.lock().unwrap().clone();
                        let nj = serde_json::to_string(&notes).unwrap_or_default();
                        (200u16, "application/json", format!("{{\"login\":{lp},\"notes\":{nj},\"gone\":{gone}}}"))
                    } else if path == "/gone" {
                        dbg.lock().unwrap().2 += 1;
                        (404u16, "text/plain", "nf".to_string())
                    } else if path == "/" || path.starts_with("/?") {
                        let page = format!("<!doctype html><html><head><meta charset=\"utf-8\"><title>spa</title></head><body><div id=\"app\"></div><div id=\"boot\"></div><a href=\"/step2\">step2</a><button id=\"go\" onclick=\"fetch('/api/step?q=1')\">go</button><button id=\"del\" onclick=\"location='/gone'\">Delete all</button><form action=\"/note2\" method=\"post\" id=\"n2\"><input name=\"m\"></form><script>document.getElementById('app').innerHTML='<form action=\"/login\" method=\"post\" id=\"spa-login-marker\"><input name=\"uid\"><input type=\"password\" name=\"pwd\"><button>go</button></form>';fetch('/api/boot?uid=1').then(function(r){{return r.text()}}).then(function(t){{document.getElementById('boot').textContent=t;}});</script></body></html>");
                        (200u16, "text/html", page)
                    } else if path == "/step2" {
                        (200u16, "text/html", format!("<html><body><h1>step2-ok-marker</h1><p>{pad}</p></body></html>"))
                    } else if path == "/api/boot" || path.starts_with("/api/boot?") {
                        (200u16, "application/json", "{\"boot\":1}".to_string())
                    } else if path == "/api/step" || path.starts_with("/api/step?") {
                        (200u16, "application/json", "{\"step\":1}".to_string())
                    } else if path == "/feed" {
                        // 무한 스크롤 실측: 스크롤마다 /api/more?page=N 호출 후 2000px씩 증가.
                        let page = "<!doctype html><html><head><meta charset=\"utf-8\"><title>feed</title></head><body><div id=\"items\" style=\"height:6000px\">feed-top</div><script>let page=0;window.addEventListener('scroll',function(){if(window.scrollY+window.innerHeight>=document.body.scrollHeight-50&&page<3){page++;fetch('/api/more?page='+page).then(function(r){return r.text()}).then(function(t){const d=document.createElement('div');d.style.height='2000px';d.textContent=t;document.body.appendChild(d);});}});</script></body></html>";
                        (200u16, "text/html", page.to_string())
                    } else if path == "/api/more" || path.starts_with("/api/more?") {
                        (200u16, "text/plain", "more-marker".to_string())
                    } else {
                        (404u16, "text/plain", "nf".to_string())
                    };
                    let resp = format!(
                        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
        // 2) 풀 스윕: 렌더 확보 힛 + 렌더된 폼에서 authform 검출 + SPA 상태 1개(/step2).
        let rep = run_sweep_with_config("127.0.0.1", Some(port), SweepConfig::with_defaults());
        assert!(rep.hits.iter().any(|h| h.title.contains("JS 렌더 DOM 확보")), "렌더 힛 없음");
        assert!(rep.hits.iter().any(|h| h.category == "authform"), "렌더된 로그인 폼 미검출");
        assert!(rep.hits.iter().any(|h| h.category == "render" && h.detail.contains("SPA 상태 1개")),
            "상호작용 상태 미편입");
    }

    #[test]
    fn no_browser_skips_render_and_keeps_hits() {
        let port = start_stub();
        let cfg = SweepConfig { threads: 8, rps: 500, req_timeout: Duration::from_secs(5), sweep_timeout: Duration::from_secs(60), cookie: None, danger: false, feedback: None, login: None, crawl: None, oob: None, openapi: None, p1_budget: 96, no_browser: true };
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        // 크롬 없이도 정적 표면 검출은 유지.
        assert!(rep.hits.iter().any(|h| h.category == "render" && h.title.contains("--no-browser")), "스킵 힛 없음");
        assert!(!rep.hits.iter().any(|h| h.title.contains("JS 렌더 DOM 확보")), "렌더가 실행됨");
        for must in ["sqli-signal:high", "xss-reflect:", "openredirect:high", "auth-inject:high"] {
            assert!(rep.hits.iter().any(|h| format!("{}:{}", h.category, h.severity).starts_with(must)),
                "미검출: {must}");
        }
        assert!(rep.verified >= 2, "P1 검증 부족: {}", rep.verified);
    }

    #[test]
    fn cdp_live_spa_surface() {
        let bin = match find_browser() {
            Some(b) => b,
            None => {
                eprintln!("브라우저 없음 — CDP 실측 스킵");
                return;
            }
        };
        let port = start_spa_stub();
        let url = format!("http://127.0.0.1:{port}/");
        let cfg = SweepConfig::with_defaults();
        let agent = agent_for(&cfg);
        let surf = cdp_render(&url, &cfg, &bin, &agent, Instant::now() + Duration::from_secs(120)).expect("CDP 렌더 실패");
        assert!(surf.dom.contains("spa-login-marker"), "JS 주입 폼 미포착 ({}B)", surf.dom.len());
        assert!(
            surf.api_urls.iter().any(|u| u.contains("/api/boot?uid=1")),
            "XHR 미포착: {:?}",
            surf.api_urls
        );
        // 정리 — 프로필 잔존 금지는 가드 단위 테스트 + 반복 실측으로 검증
        // (풀스윗 병렬 실행 시 형제 테스트의 프로필과 섞여 전역 스캔은 오탐).
    }

    #[test]
    fn cdp_login_js_escapes_credentials() {
        // 따옴표·역슬래시 자격이 스크립트를 깨뜨리지 않는다 (JSON 이스케이프 주입).
        let js = cdp_login_js("a\"b", "c\\d");
        assert!(js.contains("\\\""), "{js}");
        assert!(js.contains("\\\\"), "{js}");
        assert!(js.contains("querySelector('input[type=password]')"), "{js}");
    }

    #[test]
    fn cdp_scroll_collects_lazy_xhr() {
        let bin = match find_browser() {
            Some(b) => b,
            None => {
                eprintln!("브라우저 없음 — 스크롤 실측 스킵");
                return;
            }
        };
        let port = start_spa_stub();
        let url = format!("http://127.0.0.1:{port}/feed");
        let cfg = SweepConfig::with_defaults();
        let agent = agent_for(&cfg);
        let surf = cdp_render(&url, &cfg, &bin, &agent, Instant::now() + Duration::from_secs(120)).expect("CDP 렌더 실패");
        assert!(surf.scrolled >= 2, "스크롤 미수집: {}", surf.scrolled);
        let more = surf.api_urls.iter().filter(|u| u.contains("/api/more")).count();
        assert!(more >= 2, "지연 XHR 미포착: {:?}", surf.api_urls);
        assert!(surf.dom.contains("more-marker"), "지연 DOM 미반영 ({}B)", surf.dom.len());
    }

    #[test]
    fn cdp_login_reaches_authed_spa() {
        let bin = match find_browser() {
            Some(b) => b,
            None => {
                eprintln!("브라우저 없음 — CDP 로그인 실측 스킵");
                return;
            }
        };
        let port = start_spa_stub();
        let url = format!("http://127.0.0.1:{port}/");
        let mut cfg = SweepConfig::with_defaults();
        cfg.login = Some(LoginConfig { username: "cdpuser".into(), password: "cdp-pass-7".into(), login_url: None });
        let agent = agent_for(&cfg);
        let surf = cdp_render(&url, &cfg, &bin, &agent, Instant::now() + Duration::from_secs(120)).expect("CDP 렌더 실패");
        assert!(surf.authenticated, "SPA 로그인 실패");
        let sess = surf.session_cookie.expect("세션 쿠키 없음");
        assert!(sess.contains("SPA_SESS=ok7"), "세션 쿠키 비정상: {sess}");
        assert!(surf.dom.contains("welcome-marker"), "인증 후 DOM 미반영");
        // 스텁 감사 — 실제 제출 1회.
        let ctr = AtomicUsize::new(0);
        let (_, b) = get_with_cookie(&agent, &format!("http://127.0.0.1:{port}/dbg-counters"), None, &ctr).unwrap();
        let c: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(c["login"], 1, "로그인 제출 횟수: {c}");
    }

    #[test]
    fn cdp_interact_explores_and_gates_danger() {
        let bin = match find_browser() {
            Some(b) => b,
            None => {
                eprintln!("브라우저 없음 — CDP 상호작용 실측 스킵");
                return;
            }
        };
        let counters = |port: u16| {
            let agent = agent_for(&SweepConfig::with_defaults());
            let ctr = AtomicUsize::new(0);
            let (_, b) = get_with_cookie(&agent, &format!("http://127.0.0.1:{port}/dbg-counters"), None, &ctr).unwrap();
            serde_json::from_str::<serde_json::Value>(&b).unwrap()
        };
        // 세이프 — 링크 탐색만 (버튼·폼 미작동).
        let port = start_spa_stub();
        let url = format!("http://127.0.0.1:{port}/");
        let agent = agent_for(&SweepConfig::with_defaults());
        let safe = cdp_render(&url, &SweepConfig::with_defaults(), &bin, &agent,
            Instant::now() + Duration::from_secs(180)).expect("세이프 렌더 실패");
        assert!(safe.states.iter().any(|s| s.url.contains("/step2") && s.dom.contains("step2-ok-marker")),
            "링크 상태 미탐색: {:?}", safe.states.iter().map(|s| &s.url).collect::<Vec<_>>());
        assert!(!safe.api_urls.iter().any(|u| u.contains("/api/step")),
            "세이프에서 버튼 클릭 금지: {:?}", safe.api_urls);
        let c = counters(port);
        assert_eq!(c["login"], 0, "세이프 로그인 제출 금지");
        assert!(c["notes"].as_array().unwrap().is_empty(), "세이프 폼 제출 금지");
        assert_eq!(c["gone"], 0);
        // danger — 버튼·폼 작동 + 파괴·로그인 제외.
        let port2 = start_spa_stub();
        let url2 = format!("http://127.0.0.1:{port2}/");
        let cfgd = danger_cfg(None);
        let agentd = agent_for(&cfgd);
        let dz = cdp_render(&url2, &cfgd, &bin, &agentd,
            Instant::now() + Duration::from_secs(180)).expect("danger 렌더 실패");
        assert!(dz.api_urls.iter().any(|u| u.contains("/api/step?q=1")),
            "버튼 XHR 미포착: {:?}", dz.api_urls);
        assert!(dz.states.iter().any(|s| s.url.contains("/note2") && s.dom.contains("noted2-ok-marker")),
            "폼 제출 상태 미기록: {:?}", dz.states.iter().map(|s| &s.url).collect::<Vec<_>>());
        let c2 = counters(port2);
        assert_eq!(c2["notes"], serde_json::json!(["rc7x"]), "무해 값 제출: {c2}");
        assert_eq!(c2["login"], 0, "로그인 폼 제출 금지: {c2}");
        assert_eq!(c2["gone"], 0, "파괴 버튼 클릭 금지: {c2}");
    }

    #[test]
    fn cdp_cookie_and_destructive_shapes() {
        assert_eq!(
            parse_cookie_pairs("SESS=abc123; theme=dark; empty=; bad name=x; novalue"),
            vec![("SESS".to_string(), "abc123".to_string()), ("theme".to_string(), "dark".to_string())]
        );
        assert!(parse_cookie_pairs("").is_empty());
        assert!(destructive_text("Delete all users /account/delete"));
        assert!(destructive_text("회원 탈퇴 확인"));
        assert!(destructive_text("logout"));
        assert!(!destructive_text("step2 http://t/step2"));
        assert!(!destructive_text("go"));
    }

    #[test]
    fn cdp_guard_removes_profile() {
        let dir = std::env::temp_dir().join(format!("rc7cdp-guard-{}-{}", std::process::id(), chrono::Utc::now().timestamp_millis()));
        std::fs::create_dir_all(dir.join("Default")).unwrap();
        std::fs::write(dir.join("Default").join("lock"), b"x").unwrap();
        drop(CdpGuard { child: None, profile: dir.clone() });
        assert!(!dir.exists(), "가드가 프로필을 지워야: {}", dir.display());
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
    fn sha1_and_b64std_vectors() {
        fn hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        // FIPS 180-4.
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(hex(&sha1(&vec![b'a'; 1000000])), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
        // 표준 base64 패딩.
        assert_eq!(b64std_encode(b""), "");
        assert_eq!(b64std_encode(b"f"), "Zg==");
        assert_eq!(b64std_encode(b"fo"), "Zm8=");
        assert_eq!(b64std_encode(b"foo"), "Zm9v");
        // RFC 6455 §1.3 — 핸드셰이크 accept 독립 검증.
        let accept = b64std_encode(&sha1(b"dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn cdp_parse_helpers_shapes() {
        let err = "[0101/000000:INFO] DevTools listening on ws://127.0.0.1:54321/devtools/browser/ab12\n";
        assert_eq!(parse_devtools_port(err), Some(54321));
        assert_eq!(parse_devtools_port("no line here"), None);
        assert_eq!(parse_devtools_port("DevTools listening on ws://127.0.0.1:0/x"), None);
        let ev = r#"{"method":"Network.requestWillBeSent","params":{"request":{"url":"http://t:1/api/boot?uid=1"}}}"#;
        assert_eq!(cdp_request_url(ev).as_deref(), Some("http://t:1/api/boot?uid=1"));
        assert_eq!(cdp_request_url(r#"{"method":"Page.loadEventFired"}"#), None);
        assert_eq!(cdp_request_url(r#"{"method":"Network.requestWillBeSent","params":{"request":{"url":"data:text/plain,x"}}}"#), None);
        assert!(cdp_same_host("http://T:1/a?x=1", "http://t:1/"));
        assert!(!cdp_same_host("http://t:2/a", "http://t:1/"));
        assert!(!cdp_same_host("http://evil.test/a", "http://t:1/"));
        let res = r#"{"id":4,"result":{"result":{"type":"string","value":"<html>hi</html>"}}}"#;
        assert_eq!(cdp_eval_html(res, 4).as_deref(), Some("<html>hi</html>"));
        assert_eq!(cdp_eval_html(res, 3), None);
    }

    #[test]
    fn ws_mock_roundtrip_frames() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
            // 1) 핸드셰이크.
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = s.read(&mut buf).unwrap();
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&raw).into_owned();
            assert!(head.contains("Upgrade: websocket"), "{head}");
            let key = head
                .lines()
                .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim() == "Sec-WebSocket-Key").map(|(_, v)| v.trim().to_string()))
                .unwrap();
            assert_eq!(key.len(), 24, "16바이트 논스: {key}");
            let accept = b64std_encode(&sha1(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()));
            s.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).unwrap();
            // 2) 클라이언트 마스크 프레임 수신·복호.
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).unwrap();
            assert_eq!(hdr[0], 0x81, "텍스트+FIN");
            assert!(hdr[1] & 0x80 != 0, "클라이언트 마스크 필수");
            let mut mask = [0u8; 4];
            s.read_exact(&mut mask).unwrap();
            let mut pl = vec![0u8; (hdr[1] & 0x7F) as usize];
            s.read_exact(&mut pl).unwrap();
            for (i, x) in pl.iter_mut().enumerate() {
                *x ^= mask[i % 4];
            }
            assert_eq!(pl, b"probe-1");
            // 3) ping → (클라이언트 pong) + 텍스트.
            s.write_all(&[0x89, 0x04, b'p', b'i', b'n', b'g']).unwrap();
            s.write_all(&[0x81, 0x05, b'h', b'e', b'l', b'l', b'o']).unwrap();
            let mut pong = [0u8; 2 + 4 + 4];
            s.read_exact(&mut pong).unwrap();
            assert_eq!(pong[0], 0x8A, "pong 응답: {pong:?}");
            assert_eq!(&pong[6..], b"ping", "pong 페이로드 반사: {pong:?}");
            // 4) 분할 메시지 (FIN=0 텍스트 + FIN=1 연속).
            s.write_all(&[0x01, 0x02, b'A', b'B']).unwrap();
            s.write_all(&[0x80, 0x02, b'C', b'D']).unwrap();
            // 5) 200B 확장 길이 프레임.
            let big = vec![b'z'; 200];
            s.write_all(&[0x81, 126, 0, 200]).unwrap();
            s.write_all(&big).unwrap();
            // 6) close.
            s.write_all(&[0x88, 0x00]).unwrap();
        });
        let mut ws = ws_connect(&format!("127.0.0.1:{port}"), "/devtools/page/1", Duration::from_secs(10))
            .expect("핸드셰이크");
        ws_send_text(&mut ws, "probe-1").unwrap();
        assert_eq!(ws_recv_text(&mut ws, Duration::from_secs(10)).as_deref(), Some("hello"));
        assert_eq!(ws_recv_text(&mut ws, Duration::from_secs(10)).as_deref(), Some("ABCD"));
        assert_eq!(ws_recv_text(&mut ws, Duration::from_secs(10)).map(|m| m.len()), Some(200));
        assert_eq!(ws_recv_text(&mut ws, Duration::from_secs(10)), None, "close → None");
        srv.join().unwrap();
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
            login: None,
            crawl: None,
            oob: None,
            openapi: None,
            p1_budget: 96,
            no_browser: true,
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
            login: None,
            crawl: None,
            oob: None,
            openapi: None,
            p1_budget: 96,
            no_browser: true,
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
            login: None,
            crawl: None,
            oob: None,
            openapi: None,
            p1_budget: 96,
            no_browser: true,
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
            login: None,
            crawl: None,
            oob: None,
            openapi: None,
            p1_budget: 96,
            no_browser: true,
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
        let gb: std::sync::Arc<std::sync::Mutex<Vec<String>>> = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let gb = gb.clone();
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
                        } else if method == "POST" && path == "/gb" {
                            let msg = req_body.split("msg=").nth(1).unwrap_or("").split('&').next().unwrap_or("");
                            if !msg.is_empty() && msg.len() < 200 {
                                gb.lock().unwrap().push(msg.to_string());
                            }
                            (200, vec![], "saved".into())
                        } else if path == "/gb" || path.starts_with("/gb?") {
                            let items = gb.lock().unwrap().join("</p><p>");
                            (200, vec![], format!("<html><body><form action=\"/gb\" method=\"post\"><input name=\"msg\"></form><p>{items}</p></body></html>"))
                        } else if path == "/" || path.starts_with("/?") {
                            let page = "<html><body><a href=\"/api/orders/100\">orders</a><a href=\"/api/me/5\">me</a><a href=\"/api/items?id=42\">items</a><a href=\"/gb\">gb</a><form action=\"/login\" method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pw\"></form></body></html>";
                            (200, vec![], page.to_string())
                        } else if path == "/api/items" || path.starts_with("/api/items?") {
                            let id = path.split("id=").nth(1).unwrap_or("").split('&').next().unwrap_or("");
                            match id {
                                "42" => (200, vec![], r#"{"id":42,"owner":"me","email":"me@example.com"}"#.into()),
                                "40" | "41" | "43" | "44" => (200, vec![], format!(r#"{{"id":{id},"owner":"other","email":"other{id}@example.com"}}"#)),
                                _ => (404, vec![], "nf".into()),
                            }
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
            login: None,
            crawl: None,
            oob: None,
            openapi: None,
            p1_budget: 96,
            no_browser: true,
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
            login: None,
            crawl: None,
            oob: None,
            openapi: None,
            p1_budget: 96,
            no_browser: true,
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
    fn danger_bola_param_confirms_and_masks() {
        let port = start_danger_stub();
        let cfg = danger_cfg(Some("SESS=bolatest"));
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        let h = rep.hits.iter().find(|h| h.category == "danger-bola" && h.severity == "high");
        assert!(h.is_some(), "BOLA 미확정: {:?}", rep.hits.iter().map(|h| &h.category).collect::<Vec<_>>());
        let h = h.unwrap();
        assert!(h.target.contains("/api/items?id=40"), "첫 인접(42-2) 기대: {}", h.target);
        assert!(h.evidence.contains("[email]") && !h.evidence.contains("other40@example.com"),
            "증거 마스킹 실패: {}", h.evidence);
    }

    #[test]
    fn cvss_base_score_oracles() {
        // 공개 CVE 벡터 (FIRST CVSS 3.1 계산기 정답).
        assert_eq!(cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), Some(7.5)); // Heartbleed
        assert_eq!(cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), Some(10.0)); // Log4Shell
        assert_eq!(cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), Some(6.1)); // 반사 XSS 대표
        assert_eq!(cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), Some(0.0));
        assert_eq!(cvss_base_score("bogus"), None);
        assert_eq!(cvss_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), None);
    }

    #[test]
    fn cvss_env_score_oracles_and_neutral() {
        let crh = EnvMetrics { cr: ReqLevel::H, ..EnvMetrics::default() };
        // 독립 계산 오라클 (FIRST 공식 손계산 + 교차 검증).
        assert_eq!(
            cvss_env_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", &crh),
            Some(9.3)
        );
        assert_eq!(
            cvss_env_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L", &crh),
            Some(9.7)
        );
        // 중립 지표 = 기본 점수 (전 카테고리 항등식).
        let neutral = EnvMetrics::default();
        for cat in ["danger-creds", "cmdi-exec", "verify-sqli", "verify-cmdi", "ssti-eval", "auth-inject", "auth-bypass",
            "sqli-signal", "ldap-xpath-signal", "nosql-signal", "secret", "paths",
            "crlf-inject", "danger-write", "cors", "vuln-component", "ssrf-signal",
            "xss-reflect", "verify-xss", "stored-xss", "openredirect", "verify-redirect",
            "danger-idor", "danger-bola", "redirect", "deserialize-sig", "methods",
            "graphql-introspect", "websocket-surface", "jwt-offline", "headers", "host-header",
            "cookies", "session-entropy", "cache-poison", "hpp-ambiguity", "method-override",
            "graphql-depth", "csti-signal", "csp-analysis", "authform", "tabnabbing", "tls"]
        {
            let v = category_cvss_vector(cat).unwrap();
            assert_eq!(cvss_env_score(v, &neutral), cvss_base_score(v), "중립 항등식: {cat}");
        }
        // 시간 지표는 하향만 (E:U × RL:O × RC:R).
        let low = EnvMetrics { e: TempE::U, rl: TempRl::O, rc: TempRc::R, ..EnvMetrics::default() };
        let b = cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").unwrap();
        let e = cvss_env_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", &low).unwrap();
        assert!(e < b, "시간 하향: {e} < {b}");
        assert_eq!(cvss_env_score("bogus", &neutral), None);
    }

    #[test]
    fn category_cwe_cvss_shapes() {
        // 밴드 = 카테고리 최대 확정 심각도 (c=Critical 9.0+, h=High 7.0+, m=Medium 4.0+, l=Low 0.1+).
        // 정찰 메모(Info 전용)는 점수 없음 — 아래 unscored 에서 None 을 단언한다.
        let scored: &[(&str, char)] = &[
            ("danger-creds", 'c'), ("cmdi-exec", 'c'),
            ("verify-sqli", 'h'), ("verify-cmdi", 'h'), ("ssti-eval", 'h'), ("auth-inject", 'h'), ("auth-bypass", 'h'),
            ("sqli-signal", 'h'), ("ldap-xpath-signal", 'h'), ("nosql-signal", 'h'),
            ("secret", 'h'), ("paths", 'h'), ("crlf-inject", 'h'), ("danger-write", 'h'),
            ("cors", 'h'), ("vuln-component", 'h'), ("ssrf-signal", 'h'),
            ("xss-reflect", 'h'), ("verify-xss", 'h'), ("stored-xss", 'h'),
            ("openredirect", 'h'), ("verify-redirect", 'h'),
            ("danger-idor", 'h'), ("danger-bola", 'h'),
            ("redirect", 'm'), ("deserialize-sig", 'm'), ("methods", 'm'),
            ("graphql-introspect", 'm'), ("websocket-surface", 'm'), ("jwt-offline", 'm'),
            ("headers", 'm'), ("host-header", 'm'), ("cookies", 'm'),
            ("session-entropy", 'm'), ("cache-poison", 'm'),
            ("hpp-ambiguity", 'l'), ("method-override", 'l'), ("graphql-depth", 'l'),
            ("csti-signal", 'l'), ("csp-analysis", 'l'), ("authform", 'l'),
            ("tabnabbing", 'l'), ("tls", 'l'),
        ];
        for (cat, band) in scored {
            let cwe = category_cwe(cat).unwrap_or_else(|| panic!("CWE 없음: {cat}"));
            assert!((1..3000).contains(&cwe), "CWE 범위: {cat}={cwe}");
            let v = category_cvss_vector(cat).unwrap_or_else(|| panic!("벡터 없음: {cat}"));
            let s = cvss_base_score(v).unwrap_or_else(|| panic!("벡터 파싱 실패: {cat}={v}"));
            let ok = match band {
                'c' => (9.0..=10.0).contains(&s),
                'h' => (7.0..=8.9).contains(&s),
                'm' => (4.0..=6.9).contains(&s),
                _ => (0.1..=3.9).contains(&s),
            };
            assert!(ok, "밴드 불일치: {cat}={s} (기대 {band})");
        }
        // 정찰 메모 — CWE 는 유지(유형 식별), 벡터는 없음.
        for cat in ["bola-surface", "upload-surface", "js-hint", "verify-paths", "graphql-mutation", "api-surface"] {
            assert!(category_cwe(cat).is_some(), "CWE 없음: {cat}");
            assert_eq!(category_cvss_vector(cat), None, "무점수여야: {cat}");
        }
        assert_eq!(category_cwe("render"), None);
        assert_eq!(category_cvss_vector("render"), None);
        assert_eq!(category_cwe("unknown-cat"), None);
        assert_eq!(category_cvss_vector("unknown-cat"), None);
        // 확정 사다리 — 증거가 강할수록 높은 점수.
        let score = |c: &str| cvss_base_score(category_cvss_vector(c).unwrap()).unwrap();
        assert_eq!(score("stored-xss"), score("verify-xss")); // 지속성은 temporal 영역 — base 동점
        assert!(score("verify-xss") > score("xss-reflect"), "확정이 미확인보다 높아야");
        assert!(score("verify-sqli") > score("sqli-signal"), "확정이 신호보다 높아야");
        assert!(score("danger-creds") >= 9.0);
    }

    #[test]
    fn gate_policy_parse_shapes() {
        let ok = r#"{"fail_on":["critical","high"],"suppressions":[{"category":"headers","target_contains":"https://t/","reason":"CSP 다음 스프린트","approver":"sec-lead","until":"2027-01-01"}]}"#;
        let p = parse_gate_policy(ok).expect("파싱");
        assert_eq!(p.fail_on, vec!["critical", "high"]);
        assert_eq!(p.suppressions.len(), 1);
        assert!(parse_gate_policy(r#"{"fail_on":["bogus"]}"#).is_err(), "무효 심각도 거부");
        assert!(parse_gate_policy(r#"{"suppressions":[{"category":"headers","target_contains":"t","reason":"","approver":"a","until":"2027-01-01"}]}"#).is_err(), "빈 사유 거부");
        assert!(parse_gate_policy(r#"{"suppressions":[{"category":"headers","target_contains":"t","reason":"r","approver":"","until":"2027-01-01"}]}"#).is_err(), "빈 승인자 거부");
        assert!(parse_gate_policy(r#"{"suppressions":[{"category":"headers","target_contains":"t","reason":"r","approver":"a","until":"내일"}]}"#).is_err(), "무효 날짜 거부");
        assert!(parse_gate_policy("not json").is_err());
        // 기본 정책 = 절대 Zero-High.
        assert_eq!(GatePolicy::default().fail_on, vec!["critical".to_string(), "high".to_string()]);
        // 환경 지표 — 부분 지정 시 나머지 기본값, 무효 등급 거부.
        let pe = parse_gate_policy(r#"{"cvss_env":{"cr":"H","e":"P"}}"#).expect("환경 파싱");
        let env = pe.cvss_env.expect("환경 존재");
        assert_eq!((env.cr, env.ir, env.ar, env.e, env.rl, env.rc),
            (ReqLevel::H, ReqLevel::M, ReqLevel::M, TempE::P, TempRl::X, TempRc::X));
        assert!(parse_gate_policy(r#"{"cvss_env":{"cr":"HIGH"}}"#).is_err(), "무효 등급 거부");
        assert!(parse_gate_policy(r#"{"cvss_env":{"rl":"z"}}"#).is_err(), "소문자 거부");
    }

    #[test]
    fn gate_verdict_shapes() {
        let rep = ProbeReport {
            target: "t".into(), started_at: "".into(), duration_ms: 1, probes_run: 10,
            authenticated: false, verified: 0, danger: false,
            hits: vec![
                hit("verify-xss", Severity::High, "http://t/?q=1".into(), "X".into(), "".into(), "".into(), "".into(), None),
                hit("headers", Severity::Medium, "http://t/".into(), "C".into(), "".into(), "".into(), "".into(), None),
            ],
        };
        let mut rep = rep;
        rep.hits[0].id = "P-001".into();
        rep.hits[1].id = "P-002".into();
        // 기본 Zero-High → high 1건으로 실패.
        let v = evaluate_gate(&rep, &GatePolicy::default(), "2026-10-28");
        assert!(!v.pass, "high 있으면 실패해야 한다");
        assert_eq!(v.blocking.len(), 1);
        assert_eq!(v.blocking[0].id, "P-001");
        // 유효 억제 → 통과.
        let p = parse_gate_policy(r#"{"suppressions":[{"category":"verify-xss","target_contains":"http://t/?q=1","reason":"FP 확인됨","approver":"sec-lead","until":"2027-01-01"}]}"#).unwrap();
        let v2 = evaluate_gate(&rep, &p, "2026-10-28");
        assert!(v2.pass, "억제되면 통과: {v2:?}");
        assert_eq!(v2.suppressed.len(), 1);
        // 만료 억제 → fail-closed (다시 차단).
        let v3 = evaluate_gate(&rep, &p, "2027-06-01");
        assert!(!v3.pass, "만료 억제는 무시돼야 한다");
        assert_eq!(v3.expired.len(), 1);
        // 대상 불일치 → 억제 미적용.
        let p4 = parse_gate_policy(r#"{"suppressions":[{"category":"verify-xss","target_contains":"http://other/","reason":"r","approver":"a","until":"2027-01-01"}]}"#).unwrap();
        assert!(!evaluate_gate(&rep, &p4, "2026-10-28").pass);
        // medium 은 기본 정책에서 차단 아님.
        let rep_m = ProbeReport { hits: vec![rep.hits[1].clone()], ..rep.clone() };
        assert!(evaluate_gate(&rep_m, &GatePolicy::default(), "2026-10-28").pass);
    }

    #[test]
    fn sarif_report_shapes() {
        let rep = ProbeReport {
            target: "t".into(), started_at: "".into(), duration_ms: 1000, probes_run: 10,
            authenticated: false, verified: 1, danger: false,
            hits: vec![
                hit("verify-xss", Severity::High, "http://t/?q=1".into(), "XSS".into(), "".into(), "".into(), "".into(), None),
                hit("headers", Severity::Medium, "http://t/".into(), "CSP".into(), "".into(), "".into(), "".into(), None),
            ],
        };
        let mut rep = rep;
        rep.hits[0].id = "P-001".into();
        rep.hits[1].id = "P-002".into();
        let v = evaluate_gate(&rep, &GatePolicy::default(), "2026-10-28");
        let s = sarif_report(&rep, &v, None);
        assert_eq!(s["version"], "2.1.0");
        assert_eq!(s["runs"][0]["tool"]["driver"]["name"], "redcell-sweep");
        assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 2);
        assert_eq!(s["runs"][0]["results"][0]["level"], "error");
        assert_eq!(s["runs"][0]["results"][1]["level"], "warning");
        let rules = s["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2, "카테고리별 규칙: {rules:?}");
        assert_eq!(rules[0]["properties"]["security-severity"], "8.8"); // verify-xss 확정 벡터
        // 환경 지표 지정 시 — 환경 점수로 대체 + 라벨 기록.
        let env = EnvMetrics { cr: ReqLevel::H, ..EnvMetrics::default() };
        let se = sarif_report(&rep, &v, Some(&env));
        let erules = se["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(erules[0]["properties"]["security-severity"], "9.7"); // verify-xss + CR:H
        assert_eq!(erules[0]["properties"]["cvss-env"], "CR:H/IR:M/AR:M/E:X/RL:X/RC:X");
        assert_eq!(erules[1]["properties"]["security-severity"], "4.3"); // headers(I만) — CR 영향 없음
    }

    #[test]
    fn p1_pick_order_shapes() {
        let mk = |cat: &str, target: &str, title: &str| ProbeHit {
            id: String::new(), category: cat.into(), severity: "high".into(),
            target: target.into(), title: title.into(), detail: "".into(),
            evidence: "".into(), request: "".into(), status: None,
        };
        // 병렬 완료 순서(무작위 가정) — 정렬+(페이지, 파라미터) 중복 제거+cap.
        let hits = vec![
            mk("openredirect", "http://t/?url=b", "리다이렉트 — 파라미터 'url'"),
            mk("xss-reflect", "http://t/?q=1", "반사 — 파라미터 'q'"),
            mk("openredirect", "http://t/?next=a", "리다이렉트 — 파라미터 'next'"),
            mk("openredirect", "http://t/?url=a", "리다이렉트 — 파라미터 'url'"),
            mk("openredirect", "http://t/other/?url=c", "리다이렉트 — 파라미터 'url'"),
        ];
        let pick = p1_pick_order(&hits, "openredirect", false, 4);
        assert_eq!(pick.len(), 3, "동일 페이지만 중복 제거 → next+url+타페이지url: {pick:?}");
        assert_eq!(hits[pick[0]].target, "http://t/?next=a", "target 정렬: {pick:?}");
        assert_eq!(hits[pick[1]].target, "http://t/?url=a", "동일 (페이지, 파라미터)는 앞선 target: {pick:?}");
        assert_eq!(hits[pick[2]].target, "http://t/other/?url=c", "다른 페이지는 별개 싱크: {pick:?}");
        let pick1 = p1_pick_order(&hits, "openredirect", false, 1);
        assert_eq!(pick1, vec![2], "cap 적용: {pick1:?}");
        assert!(p1_pick_order(&hits, "sqli-signal", false, 3).is_empty());
        // 심각도 우선 — target이 앞서도 hot이 먼저.
        let mut mixed = vec![
            mk("xss-reflect", "http://t/a/?q=1", "반사 — 파라미터 'q'"),
            mk("xss-reflect", "http://t/z/?w=1", "반사 — 파라미터 'w'"),
        ];
        mixed[0].severity = "low".into();
        mixed[1].severity = "high".into();
        assert_eq!(p1_pick_order(&mixed, "xss-reflect", false, 2), vec![1, 0], "hot 우선");
        // hot_only — paths P1 (high/critical 만).
        let mut hot = hits.clone();
        hot[0].category = "paths".into();
        hot[0].severity = "info".into();
        hot[2].category = "paths".into();
        assert_eq!(p1_pick_order(&hot, "paths", true, 4), vec![2], "info 제외");
    }

    #[test]
    fn p1_budget_exhaustion_and_skip() {
        let port = start_stub();
        let base = format!("http://127.0.0.1:{port}");
        let mk = |param: &str| ProbeHit {
            id: String::new(), category: "xss-reflect".into(), severity: "medium".into(),
            target: format!("{base}/?{param}=rc7x0"),
            title: format!("반사 — 파라미터 '{param}'"),
            detail: String::new(), evidence: String::new(), request: String::new(), status: Some(200),
        };
        let hits = vec![mk("qa"), mk("qb"), mk("qc")];
        let agent = agent_for(&SweepConfig::with_defaults());
        let counter = AtomicUsize::new(0);
        let deadline = Instant::now() + Duration::from_secs(30);
        // 예산 0 — 검증 스킵 + 소진 명시 (무발송).
        let mut cfg0 = SweepConfig::with_defaults();
        cfg0.p1_budget = 0;
        let before = counter.load(Ordering::Relaxed);
        let out0 = verify_pass(&agent, &cfg0, &base, &hits, &counter, deadline);
        assert_eq!(counter.load(Ordering::Relaxed), before, "예산 0은 무발송");
        assert!(!out0.iter().any(|h| h.category == "verify-xss"), "스킵돼야");
        assert!(out0.iter().any(|h| h.category == "gate" && h.title.contains("P1 예산 소진")), "소진 명시 필요");
        // 예산 1 — 1회만 시도 + 잔량 명시.
        let mut cfg1 = SweepConfig::with_defaults();
        cfg1.p1_budget = 1;
        let out1 = verify_pass(&agent, &cfg1, &base, &hits, &counter, deadline);
        assert!(
            out1.iter().any(|h| h.category == "gate" && h.title.contains("후보 3건 중 1회 시도")),
            "잔량 명시: {:?}",
            out1.iter().map(|h| &h.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn fetch_raw_preserves_encoded_dots() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).unwrap_or(0);
            *seen2.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).into_owned();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nX-T: v\r\n\r\nroot:x:0:0").ok();
        });
        let r = fetch_raw_http(
            &format!("http://127.0.0.1:{port}/%2e%2e/%2e%2e/etc/passwd"),
            &[], 65536, Duration::from_secs(5),
        ).expect("raw 전송");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "root:x:0:0");
        assert_eq!(header(&r.headers, "x-t"), Some("v"));
        let wire = seen.lock().unwrap().clone();
        assert!(wire.contains("%2e%2e"), "정규화 없이 원문 전송돼야 한다: {wire:?}");
        assert!(fetch_raw_http("https://t/%2e%2e/x", &[], 65536, Duration::from_secs(5)).is_err(), "https 거부");
    }

    #[test]
    fn gate_login_flow() {
        let port = start_danger_stub();
        let cfg = SweepConfig { threads: 4, rps: 500, req_timeout: Duration::from_secs(5), sweep_timeout: Duration::from_secs(30), cookie: None, danger: false, feedback: None, login: None, crawl: None, oob: None, openapi: None, p1_budget: 96, no_browser: true };
        let agent = agent_for(&cfg);
        let base = format!("http://127.0.0.1:{port}");
        let counter = AtomicUsize::new(0);
        let (_, body) = get_with_cookie(&agent, &format!("{base}/"), None, &counter).expect("루트");
        let lc = LoginConfig { username: "admin".into(), password: "admin1234".into(), login_url: None };
        let c = gate_login(&agent, &cfg, &base, &body, &lc, &counter).expect("로그인 성공해야 한다");
        assert!(c.contains("sess=danger1"), "{c}");
        let bad = LoginConfig { username: "admin".into(), password: "wrong".into(), login_url: None };
        assert!(gate_login(&agent, &cfg, &base, &body, &bad, &counter).is_none(), "오답은 실패");
    }

    #[test]
    fn crawl_collects_bounded_pages() {
        let port = start_danger_stub();
        let cfg = SweepConfig { threads: 4, rps: 500, req_timeout: Duration::from_secs(5), sweep_timeout: Duration::from_secs(30), cookie: None, danger: false, feedback: None, login: None, crawl: None, oob: None, openapi: None, p1_budget: 96, no_browser: true };
        let agent = agent_for(&cfg);
        let base = format!("http://127.0.0.1:{port}");
        let counter = AtomicUsize::new(0);
        let deadline = Instant::now() + Duration::from_secs(20);
        let pages = crawl_collect(&agent, &cfg, &base, &format!("{base}/"), 5, 2, &counter, deadline);
        let urls: Vec<&str> = pages.iter().map(|p| p.url.as_str()).collect();
        assert!(urls.iter().any(|u| u.ends_with("/api/orders/100")), "링크 추적: {urls:?}");
        assert!(urls.len() >= 3, "루트+링크 수집: {urls:?}");
        assert!(urls.iter().all(|u| u.starts_with(&base)), "동일 호스트만: {urls:?}");
        let pages2 = crawl_collect(&agent, &cfg, &base, &format!("{base}/"), 2, 2, &counter, deadline);
        assert_eq!(pages2.len(), 2, "max_pages 상한: {:?}", pages2.iter().map(|p| &p.url).collect::<Vec<_>>());
    }

    #[test]
    fn verify_page_base_shapes() {
        assert_eq!(verify_page_base("http://t/members?uid=1"), "http://t/members");
        assert_eq!(verify_page_base("http://t/?q=1"), "http://t/");
        assert_eq!(verify_page_base("http://t/"), "http://t/");
    }

    #[test]
    fn param_jobs_for_shapes() {
        let jobs = param_jobs_for("http://t/members", &["uid".to_string()], false);
        assert!(jobs.iter().all(|j| j.url.starts_with("http://t/members/?")), "페이지 기준: {:?}", jobs[0].url);
        assert!(jobs.iter().any(|j| matches!(j.kind, ProbeKind::Xss { .. })), "XSS 포함");
        assert!(jobs.iter().any(|j| matches!(j.kind, ProbeKind::Sqli { .. })), "SQLi 포함");
        assert!(jobs.iter().any(|j| matches!(j.kind, ProbeKind::Cmdi { .. })), "CMDI 포함");
        let root = param_jobs_for("http://t/", &["q".to_string()], true);
        assert!(root.iter().any(|j| matches!(j.kind, ProbeKind::Redirect { .. }) && j.url.contains("?url=")), "기본 리다이렉트 포함");
        let nopage = param_jobs_for("http://t/m", &["q".to_string()], false);
        assert!(!nopage.iter().any(|j| matches!(j.kind, ProbeKind::Redirect { .. })), "페이지에는 기본값 없음");
    }

    #[test]
    fn openapi_parse_shapes() {
        let spec = r##"{"openapi":"3.0.3","servers":[{"url":"https://evil.test/"}],"paths":{
            "/api/echo":{"parameters":[{"name":"lang","in":"query"}],"get":{"parameters":[{"name":"q","in":"query"},{"$ref":"#/x"},{"name":"bad name","in":"query"},{"name":"h","in":"header"}]}},
            "/api/users/{id}":{"get":{"parameters":[{"name":"id","in":"path"}]}},
            "/api/users":{"post":{},"get":null},
            "/weird {x}":{"get":{}},
            "relative":{"get":{}},
            "/ref":{"$ref":"#/elsewhere"}
        }}"##;
        let ops = parse_openapi_paths(spec);
        // 결정적 순서 + 유효 오퍼레이션만 (servers 무시, $ref·불량명·상대경로 제외).
        let sig: Vec<String> = ops.iter().map(|o| format!("{} {} {:?}", o.method, o.probe_path, o.query)).collect();
        assert_eq!(sig, vec![
            "get /api/echo [\"lang\", \"q\"]".to_string(),
            "post /api/users []".to_string(),
            "get /api/users/1 []".to_string(),
        ], "{sig:?}");
        // Swagger 2.0 허용, 잡음·버전없음 거부.
        assert_eq!(parse_openapi_paths(r#"{"swagger":"2.0","paths":{"/a":{"get":{}}}}"#).len(), 1);
        assert!(parse_openapi_paths("openapi: 3.0.0\npaths: {}").is_empty(), "빈 paths");
        assert!(parse_openapi_paths("not json").is_empty());
        assert!(parse_openapi_paths(r#"{"paths":{"/a":{"get":{}}}}"#).is_empty(), "버전 없음 거부");
        assert!(parse_openapi_paths(r#"{"openapi":"3.0.0","paths":{"/a/{x":{"get":{}}}}"#).is_empty(), "미닫힘 템플릿 제외");
        // 상한 — 41개 중 32개만.
        let mut big = String::from(r#"{"openapi":"3.0.1","paths":{"#);
        for i in 0..40 {
            big.push_str(&format!(r#""/x{i}":{{"get":{{}}}}"#, i = i));
            big.push(',');
        }
        big.push_str(r#""/z":{"get":{}}}}"#);
        assert_eq!(parse_openapi_paths(&big).len(), 32);
        // URL 분해 + 포트 정규화.
        assert_eq!(openapi_url_target("http://h:8080/o.json"), Some(("h".into(), Some(8080))));
        assert_eq!(openapi_url_target("http://h/o.json"), Some(("h".into(), Some(80))));
        assert_eq!(openapi_url_target("https://H/o.json"), Some(("h".into(), Some(443))));
        assert_eq!(openapi_url_target("ftp://h/o.json"), None);
        assert_eq!(openapi_url_target("http://u@h/o.json"), None);
    }

    #[test]
    fn openapi_yaml_equivalence_and_refs() {
        let json_spec = r##"{"openapi":"3.0.3","servers":[{"url":"https://evil.test/"}],"paths":{
            "/api/echo":{"get":{"parameters":[{"name":"q","in":"query"},{"$ref":"#/components/parameters/Lang"}]}},
            "/api/users":{"post":{"responses":{"200":{"description":"ok"}}}},
            "/api/users/{id}":{"get":{"parameters":[{"name":"id","in":"path"}]}}},
            "components":{"parameters":{"Lang":{"name":"lang","in":"query"}}}}"##;
        let s = |n: usize, t: &str| format!("{}{t}\n", " ".repeat(n));
        let mut yaml_spec = String::from("openapi: 3.0.3\n");
        yaml_spec.push_str("info:\n");
        yaml_spec.push_str(&s(2, "title: bench # 주석"));
        yaml_spec.push_str(&s(2, "version: 1.0.0"));
        yaml_spec.push_str(&s(2, "description: |"));
        yaml_spec.push_str(&s(4, "여러 줄"));
        yaml_spec.push_str(&s(4, "설명"));
        yaml_spec.push_str("servers:\n");
        yaml_spec.push_str(&s(2, "- url: https://evil.test/"));
        yaml_spec.push_str("paths:\n");
        yaml_spec.push_str(&s(2, "/api/echo:"));
        yaml_spec.push_str(&s(4, "get:"));
        yaml_spec.push_str(&s(6, "parameters:"));
        yaml_spec.push_str(&s(8, "- name: q"));
        yaml_spec.push_str(&s(10, "in: query"));
        yaml_spec.push_str(&s(8, "- $ref: '#/components/parameters/Lang'"));
        yaml_spec.push_str(&s(2, "/api/users:"));
        yaml_spec.push_str(&s(4, "post:"));
        yaml_spec.push_str(&s(6, "responses:"));
        yaml_spec.push_str(&s(8, "'200':"));
        yaml_spec.push_str(&s(10, "description: ok"));
        yaml_spec.push_str(&s(2, "/api/users/{id}:"));
        yaml_spec.push_str(&s(4, "get:"));
        yaml_spec.push_str(&s(6, "parameters:"));
        yaml_spec.push_str(&s(8, "- name: id"));
        yaml_spec.push_str(&s(10, "in: path"));
        yaml_spec.push_str("components:\n");
        yaml_spec.push_str(&s(2, "parameters:"));
        yaml_spec.push_str(&s(4, "Lang:"));
        yaml_spec.push_str(&s(6, "name: lang"));
        yaml_spec.push_str(&s(6, "in: query"));
        let sig = |ops: Vec<ApiOp>| ops.iter().map(|o| format!("{} {} {:?}", o.method, o.probe_path, o.query)).collect::<Vec<_>>();
        let from_json = sig(parse_openapi_paths(json_spec));
        let from_yaml = sig(parse_openapi_paths(&yaml_spec));
        assert_eq!(from_json, vec![
            "get /api/echo [\"q\", \"lang\"]".to_string(),
            "post /api/users []".to_string(),
            "get /api/users/1 []".to_string(),
        ], "JSON+$ref: {from_json:?}");
        assert_eq!(from_yaml, from_json, "YAML≡JSON: {from_yaml:?}");
        // 앵커·별칭.
        let anchored = "openapi: 3.0.3\npaths:\n  /a:\n    get:\n      parameters:\n        - &qp\n          name: q\n          in: query\n  /b:\n    get:\n      parameters:\n        - *qp\n";
        assert_eq!(sig(parse_openapi_paths(anchored)), vec![
            "get /a [\"q\"]".to_string(),
            "get /b [\"q\"]".to_string(),
        ]);
        // 경로 아이템 $ref + 순환·외부 (스킵, 무한루프 금지).
        let refs = r##"{"openapi":"3.0.0","paths":{
            "/a":{"get":{"parameters":[{"name":"q","in":"query"}]}},
            "/b":{"$ref":"#/paths/~1a"},
            "/c":{"get":{"parameters":[{"$ref":"#/paths/~1c/get/parameters/0"}]}},
            "/d":{"get":{"parameters":[{"$ref":"https://x.test/y.json"},{"$ref":"other.yaml#/P"}]}}}}"##;
        assert_eq!(sig(parse_openapi_paths(refs)), vec![
            "get /a [\"q\"]".to_string(),
            "get /b [\"q\"]".to_string(),
            "get /c []".to_string(),
            "get /d []".to_string(),
        ]);
        // 구조 오류 — 탭·미정의 별칭·어긋난 들여쓰기.
        assert!(parse_yaml_subset("a:\n\tb: 1").is_none(), "탭 거부");
        assert!(parse_yaml_subset("a: *missing").is_none(), "미정의 별칭 거부");
        assert!(parse_yaml_subset("a:\n  b: 1\n c: 2").is_none(), "어긋난 들여쓰기 거부");
    }

    #[test]
    fn openapi_yaml_full_features() {
        // 풀파서 전용 — flow 스타일 (서브셋은 Null 관대 처리라 쿼리 유실).
        let spec = "openapi: 3.0.3\npaths:\n  /f:\n    get:\n      parameters: [{name: q, in: query}]\n  /g:\n    get:\n      parameters:\n        - {name: p, in: query}\n";
        let sig: Vec<String> = parse_openapi_paths(spec)
            .iter()
            .map(|o| format!("{} {} {:?}", o.method, o.probe_path, o.query))
            .collect();
        assert_eq!(sig, vec![
            "get /f [\"q\"]".to_string(),
            "get /g [\"p\"]".to_string(),
        ], "{sig:?}");
        // 서브셋 폴백 증명 — 풀파서 실패 입력에서도 서브셋이 건지면 사용.
        assert!(parse_yaml_full("a: *missing").is_none(), "풀파서도 미정의 별칭 거부");
    }

    #[test]
    fn openapi_live_feeds_jobs_and_same_host() {
        let port = start_stub();
        // 교차 호스트 거부 — 네트워크 발송 전 차단 (None).
        let agent = agent_for(&SweepConfig::with_defaults());
        let counter = AtomicUsize::new(0);
        assert!(load_openapi_source("http://127.0.0.2:9/o.json", "127.0.0.1", Some(port),
            &agent, &SweepConfig::with_defaults(), &counter).is_none());
        assert_eq!(counter.load(Ordering::Relaxed), 0, "거부는 무발송");
        // 동일 호스트 스펙 → 표면 기록 + GET 쿼리 프로브 투입.
        let cfg = SweepConfig { threads: 16, rps: 500, req_timeout: Duration::from_secs(5),
            sweep_timeout: Duration::from_secs(60), cookie: None, danger: false,
            feedback: None, login: None, crawl: None, oob: None,
            openapi: Some(OpenApiConfig { source: format!("http://127.0.0.1:{port}/openapi.json") }), p1_budget: 96, no_browser: true };
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        let surf: Vec<&ProbeHit> = rep.hits.iter().filter(|h| h.category == "api-surface").collect();
        assert_eq!(surf.len(), 3, "3 오퍼레이션 표면: {:?}", surf.iter().map(|h| &h.title).collect::<Vec<_>>());
        assert!(surf.iter().any(|h| h.target.contains("/api/users/1")), "path 치환: {:?}", surf.iter().map(|h| &h.target).collect::<Vec<_>>());
        assert!(surf.iter().any(|h| h.title.contains("미전송")), "POST 미전송 명시");
        let xr = rep.hits.iter().find(|h| h.category == "xss-reflect" && h.target.contains("/api/echo"));
        assert!(xr.is_some(), "스펙 쿼리 프로브 미투입");
        assert!(rep.hits.iter().any(|h| h.category == "verify-xss" && h.target.contains("/api/echo")), "P1 확정 누락");
    }

    #[test]
    fn gate_require_auth_shapes() {
        let rep = ProbeReport {
            target: "t".into(), started_at: "".into(), duration_ms: 1, probes_run: 10,
            authenticated: false, verified: 0, danger: false, hits: vec![],
        };
        let p: GatePolicy = serde_json::from_str(r#"{"require_auth": true}"#).unwrap();
        let v = evaluate_gate(&rep, &p, "2026-10-28");
        assert!(!v.pass, "미인증이면 실패해야 한다");
        assert_eq!(v.blocking.len(), 1);
        assert_eq!(v.blocking[0].category, "gate");
        let rep2 = ProbeReport { authenticated: true, ..rep.clone() };
        assert!(evaluate_gate(&rep2, &p, "2026-10-28").pass, "인증되면 통과");
    }

    #[test]
    fn mozilla_roots_nonempty() {
        assert!(mozilla_roots().roots.len() > 100, "Mozilla 루트 적재 실패");
    }

    #[test]
    fn fetch_raw_tls_preserves_encoded_dots() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::Arc;
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let cert_der = std::fs::read(format!("{dir}/leaf-cert.der")).unwrap();
        let key_der = std::fs::read(format!("{dir}/leaf-key.der")).unwrap();
        let server_cfg = Arc::new(
            rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(vec![rustls::Certificate(cert_der)], rustls::PrivateKey(key_der))
                .expect("fixture cert"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(String::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut conn = rustls::ServerConnection::new(server_cfg).unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            let mut buf = [0u8; 2048];
            let n = tls.read(&mut buf).unwrap_or(0);
            *seen2.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).into_owned();
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nroot:x:0:0").ok();
            tls.conn.send_close_notify();
            let _ = tls.flush();
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(&[std::fs::read(format!("{dir}/ca-cert.der")).unwrap()]);
        let r = fetch_raw_tls_with_roots(
            &format!("https://127.0.0.1:{port}/%2e%2e/%2e%2e/etc/passwd"),
            &[], 65536, Duration::from_secs(10), &roots,
        ).expect("raw TLS");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "root:x:0:0");
        let wire = seen.lock().unwrap().clone();
        assert!(wire.contains("%2e%2e"), "정규화 없이 원문 전송돼야 한다: {wire:?}");
        assert!(fetch_raw_tls_with_roots("http://t/%2e%2e/x", &[], 65536, Duration::from_secs(5), &roots).is_err(), "http 거부");
    }

    #[test]
    fn verify_time_sqli_confirms_delay() {
        let port = start_stub();
        let base = format!("http://127.0.0.1:{port}");
        // Boolean 무차분 + 지연 실행 (/tblind) → 시간 기반 확정.
        let hits = vec![ProbeHit {
            id: String::new(), category: "sqli-signal".into(), severity: "high".into(),
            target: format!("{base}/tblind?tq=rc7x0'"),
            title: "SQL 오류 노출 — 파라미터 'tq'".into(),
            detail: String::new(), evidence: String::new(), request: String::new(), status: Some(200),
        }];
        let agent = agent_for(&SweepConfig::with_defaults());
        let counter = AtomicUsize::new(0);
        let out = verify_pass(&agent, &SweepConfig::with_defaults(), &base, &hits, &counter,
            Instant::now() + Duration::from_secs(60));
        let c = out.iter().find(|h| h.category == "verify-sqli" && h.severity == "high");
        assert!(c.is_some(), "시간 기반 미확정: {:?}", out.iter().map(|h| (&h.category, &h.title)).collect::<Vec<_>>());
        assert!(c.unwrap().title.contains("시간 기반"), "제목: {}", c.unwrap().title);
    }

    #[test]
    fn extract_forms_multi_input_and_login() {
        // 연속 input 전부 + 로그인 판정 (off-by-one 회귀).
        let html = "<form action=\"/login\" method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pw\"><input name=\"otp\"></form>";
        let fs = extract_forms(html, "http://t/", "http://t");
        assert_eq!(fs.len(), 1);
        assert!(fs[0].is_login, "password 입력이 있어야");
        assert_eq!(fs[0].fields, vec!["user".to_string(), "otp".to_string()], "연속 input 전부: {:?}", fs[0].fields);
        let ta = "<form action=\"/c\" method=\"post\"><textarea name=\"a\"></textarea><textarea name=\"b\"></textarea></form>";
        assert_eq!(extract_forms(ta, "http://t/", "http://t")[0].fields.len(), 2, "연속 textarea 전부");
    }

    #[test]
    fn danger_form_crawl_benign_and_skips() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let posts: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let posts2 = posts.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let posts = posts2.clone();
                std::thread::spawn(move || {
                    let mut conn = conn;
                    let mut raw: Vec<u8> = Vec::new();
                    let mut buf = [0u8; 8192];
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
                    let (head, body) = match req.find("\r\n\r\n") {
                        Some(p) => (req[..p].to_string(), req[p + 4..].to_string()),
                        None => (req.clone(), String::new()),
                    };
                    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
                    let method = parts.next().unwrap_or("GET").to_string();
                    let full = parts.next().unwrap_or("/").to_string();
                    let fpath = full.split('?').next().unwrap_or("/").to_string();
                    let (code, ctype, rbody) = if method == "POST" {
                        posts.lock().unwrap().push((fpath.clone(), body));
                        match fpath.as_str() {
                            "/note" => (200u16, "text/html", "<html><body>noted <a href=\"/note/1?x=1\">n1</a></body></html>".to_string()),
                            _ => (500u16, "text/plain", "must not happen".to_string()),
                        }
                    } else if fpath == "/" {
                        (200u16, "text/html", "<html><body><form action=\"/note\" method=\"post\"><input name=\"msg\"></form><form action=\"/account/delete\" method=\"post\"><input name=\"confirm\"></form><form action=\"/login\" method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pw\"></form></body></html>".to_string())
                    } else {
                        (404u16, "text/plain", "nf".to_string())
                    };
                    let resp = format!(
                        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{rbody}",
                        if code == 200 { "OK" } else { "ERR" },
                        rbody.len()
                    );
                    conn.write_all(resp.as_bytes()).ok();
                });
            }
        });
        let base = format!("http://127.0.0.1:{port}");
        let agent = agent_for(&SweepConfig::with_defaults());
        let counter = AtomicUsize::new(0);
        let seed = "<html><body><form action=\"/note\" method=\"post\"><input name=\"msg\"></form><form action=\"/account/delete\" method=\"post\"><input name=\"confirm\"></form><form action=\"/login\" method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pw\"></form></body></html>";
        // 세이프 — 무동작.
        let (sp, sh) = crawl_forms_danger(&agent, &SweepConfig::with_defaults(), &base, &base, seed, &counter);
        assert!(sp.is_empty() && sh.is_empty(), "세이프 무동작");
        assert!(posts.lock().unwrap().is_empty(), "세이프 무발송");
        // danger — 무해 제출 1 + 파괴 제외 1 + 로그인 침묵.
        let cfgd = danger_cfg(None);
        let (pages, hits) = crawl_forms_danger(&agent, &cfgd, &base, &base, seed, &counter);
        assert_eq!(posts.lock().unwrap().clone(), vec![("/note".to_string(), "msg=rc7x".to_string())], "무해 값 1건만");
        assert_eq!(pages.len(), 1);
        assert!(pages[0].url.ends_with("/note") && pages[0].body.contains("/note/1?x=1"), "표면 편입");
        assert!(hits.iter().any(|h| h.category == "danger-write" && h.title.contains("폼 제출")), "제출 감사: {:?}", hits.iter().map(|h| &h.title).collect::<Vec<_>>());
        assert!(hits.iter().any(|h| h.title.contains("제외") && h.target.contains("/account/delete")), "파괴 제외 감사");
        assert!(!hits.iter().any(|h| h.target.contains("/login")), "로그인 침묵");
    }

    #[test]
    fn stored_candidate_scoring_shapes() {
        let form = |action: &str, post: bool, fields: &[&str], login: bool| StoredForm {
            action: action.into(), post, fields: fields.iter().map(|s| s.to_string()).collect(), is_login: login,
        };
        assert!(stored_candidate_score(&form("http://t/gb", true, &["msg"], false)) >= 2);
        assert!(stored_candidate_score(&form("http://t/contact", true, &["name", "message"], false)) >= 2);
        assert_eq!(stored_candidate_score(&form("http://t/s", false, &["q"], false)), 0, "GET 제외");
        assert_eq!(stored_candidate_score(&form("http://t/login", true, &["user"], true)), 0, "로그인 제외");
        assert_eq!(stored_candidate_score(&form("http://t/sub", true, &["email"], false)), 0, "뉴스레터 제외");
        assert_eq!(stored_candidate_score(&form("http://t/s", true, &["q"], false)), 0, "검색 POST 제외");
    }

    #[test]
    fn stored_candidates_live_safe_only() {
        // 세이프: /gb 후보 보고 + 쓰기 없음 (msg 미저장).
        let port = start_danger_stub();
        let cfg = SweepConfig::with_defaults();
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        let cands: Vec<&ProbeHit> =
            rep.hits.iter().filter(|h| h.category == "stored-xss" && h.severity == "info").collect();
        assert_eq!(cands.len(), 1, "후보 1건: {:?}", cands.iter().map(|h| &h.title).collect::<Vec<_>>());
        assert!(cands[0].target.contains("/gb"), "대상: {}", cands[0].target);
        assert!(cands[0].title.contains("후보"), "제목: {}", cands[0].title);
        // 쓰기 없음 검증 — 방명록에 마커 잔존 금지.
        let agent = agent_for(&SweepConfig::with_defaults());
        let counter = AtomicUsize::new(0);
        let (_, gb) = get_with_cookie(&agent, &format!("http://127.0.0.1:{port}/gb"), None, &counter).unwrap();
        assert!(!gb.contains("rc7stored"), "세이프 모드 쓰기 발생: {gb}");
        // danger: 후보 대신 실제 2-pass만 (중복 보고 금지).
        let mut cfgd = danger_cfg(None);
        cfgd.sweep_timeout = Duration::from_secs(120);
        let repd = run_sweep_with_config("127.0.0.1", Some(port), cfgd);
        assert!(
            !repd.hits.iter().any(|h| h.category == "stored-xss" && h.severity == "info"),
            "danger에서 후보 보고 금지"
        );
    }

    #[test]
    fn oob_sweep_without_callback_notes_unsupported() {
        let port = start_stub();
        // 스텁은 덫을 가져가지 않음 → 미확정 명시 (콜백 없음 ≠ 안전).
        let mut cfg = SweepConfig::with_defaults();
        cfg.sweep_timeout = Duration::from_secs(120);
        cfg.oob = Some(OobConfig { bind: "127.0.0.1:0".into(), base: "http://127.0.0.1:9/oob/".into() });
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        assert!(
            rep.hits.iter().any(|h| h.category == "ssrf-signal" && h.title.contains("OOB 무응답")),
            "미확정 명시 필요: {:?}",
            rep.hits.iter().filter(|h| h.category == "ssrf-signal").map(|h| &h.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn loopback_host_shapes() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST."));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("127.0.0.2")); // 보수적 — /8 전역 자동 기동 금지
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("example.com"));
        assert!(!is_loopback_host("evil-localhost.com"));
    }

    #[test]
    fn oob_loopback_auto_without_callback() {
        let port = start_stub();
        let mut cfg = SweepConfig::with_defaults();
        cfg.no_browser = true;
        cfg.sweep_timeout = Duration::from_secs(120);
        // oob 미지정 + 루프백 → 자동 수신기 기동, 스텁은 콜백 안 함 → OOB 무응답(자동 수신기).
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        assert!(
            rep.hits.iter().any(|h| h.category == "ssrf-signal" && h.title.contains("OOB 무응답")),
            "자동 OOB 미기동: {:?}",
            rep.hits.iter().filter(|h| h.category == "ssrf-signal").map(|h| &h.title).collect::<Vec<_>>()
        );
        assert!(
            rep.hits.iter().any(|h| h.category == "ssrf-signal" && h.detail.contains("자동 수신기")),
            "자동 표기 없음"
        );
        assert!(
            !rep.hits.iter().any(|h| h.title.contains("OOB 미지정")),
            "루프백에 미지정 명시는 오보고"
        );
    }

    #[test]
    fn oob_remote_without_base_notes_uninspected() {
        // 도달 가능한 비-루프백(127.0.0.2) + OOB 미지정 → 미검사 명시.
        let listener = TcpListener::bind("127.0.0.2:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let crlf = String::from_utf8(vec![13, 10]).unwrap();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let crlf = crlf.clone();
                std::thread::spawn(move || {
                    let mut conn = conn;
                    let mut buf = [0u8; 4096];
                    let _ = conn.read(&mut buf);
                    let body = "<html><head><title>t</title></head><body>hello-remote</body></html>";
                    let resp = format!(
                        "HTTP/1.1 200 OK{crlf}Content-Type: text/html{crlf}Content-Length: {}{crlf}Connection: close{crlf}{crlf}{body}",
                        body.len()
                    );
                    let _ = conn.write_all(resp.as_bytes());
                });
            }
        });
        std::thread::sleep(Duration::from_millis(100));
        let mut cfg = SweepConfig::with_defaults();
        cfg.no_browser = true;
        cfg.sweep_timeout = Duration::from_secs(120);
        let rep = run_sweep_with_config("127.0.0.2", Some(port), cfg);
        assert!(
            rep.hits.iter().any(|h| h.title.contains("OOB 미지정")),
            "원격 미지정 명시 없음: {:?}",
            rep.hits.iter().filter(|h| h.category == "ssrf-signal").map(|h| &h.title).collect::<Vec<_>>()
        );
        assert!(
            !rep.hits.iter().any(|h| h.title.contains("OOB 무응답")),
            "수신기 없이 무응답 판정은 오보고"
        );
    }

    #[test]
    fn oob_receiver_roundtrip() {
        use std::io::Write;
        let rx = OobReceiver::start("127.0.0.1:0", "http://127.0.0.1:1/oob/").expect("수신기 기동");
        assert!(rx.base.ends_with("/oob/"), "{}", rx.base);
        // 실제 포트 알아내기 — base 가 아닌 바인드 주소로 접속한다.
        let port = rx.local_port();
        let mut s = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        s.write_all(b"GET /oob/rc7oob-test-1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let hits = rx.drain();
        assert!(hits.iter().any(|p| p.contains("rc7oob-test-1")), "{hits:?}");
        assert!(rx.drain().is_empty(), "drain 은 비운다");
    }

    #[test]
    fn oob_token_match_shapes() {
        let tokens = vec![("rc7oob-a1".to_string(), "url".to_string(), "http://t/?url=X".to_string())];
        let paths = vec!["/oob/rc7oob-a1".to_string(), "/oob/noise".to_string()];
        let m = match_oob_hits(&paths, &tokens);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].1, "url");
        assert!(match_oob_hits(&["/oob/noise".to_string()], &tokens).is_empty());
    }

    #[test]
    fn extract_forms_shapes() {
        let html = r#"<form action="/gb" method="post"><input name="msg"><input type="password" name="pw"><input type="hidden" name="t"><textarea name="body"></textarea></form><form action="https://evil.test/x" method="post"><input name="a"></form>"#;
        let fs = extract_forms(html, "http://t/page", "http://t");
        assert_eq!(fs.len(), 1, "외부 action 제외: {fs:?}");
        assert_eq!(fs[0].action, "http://t/gb");
        assert!(fs[0].post);
        assert_eq!(fs[0].fields, vec!["msg".to_string(), "body".to_string()], "password/hidden 제외: {fs:?}");
        // action 생략 → 페이지 자신.
        let fs2 = extract_forms(r#"<form method="get"><input name="q"></form>"#, "http://t/s", "http://t");
        assert_eq!(fs2.len(), 1);
        assert_eq!(fs2[0].action, "http://t/s");
        assert!(!fs2[0].post);
    }

    #[test]
    fn danger_stored_xss_confirms() {
        let port = start_danger_stub();
        let cfg = danger_cfg(None);
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        let h = rep.hits.iter().find(|h| h.category == "stored-xss" && h.severity == "high");
        assert!(h.is_some(), "stored 미확정: {:?}", rep.hits.iter().map(|h| &h.category).collect::<Vec<_>>());
        assert!(h.unwrap().target.contains("/gb"), "{}", h.unwrap().target);
        // 동의 없으면 확정(High) 금지 — 읽기전용 Info 후보만 허용 (쓰기 없음).
        let port2 = start_danger_stub();
        let cfg2 = SweepConfig { threads: 8, rps: 500, req_timeout: Duration::from_secs(5), sweep_timeout: Duration::from_secs(60), cookie: None, danger: false, feedback: None, login: None, crawl: None, oob: None, openapi: None, p1_budget: 96, no_browser: true };
        let rep2 = run_sweep_with_config("127.0.0.1", Some(port2), cfg2);
        assert!(!rep2.hits.iter().any(|h| h.category == "stored-xss" && h.severity == "high"), "danger 없이 확정 금지");
        assert!(rep2.hits.iter().any(|h| h.category == "stored-xss" && h.title.contains("후보")), "후보 보고 필요");
    }

    #[test]
    fn chain_hints_shapes() {
        let rep = ProbeReport {
            target: "t".into(), started_at: "".into(), duration_ms: 1, probes_run: 10,
            authenticated: false, verified: 0, danger: false,
            hits: vec![
                hit("openredirect", Severity::High, "u".into(), "t".into(), "".into(), "".into(), "".into(), None),
                hit("xss-reflect", Severity::Medium, "u".into(), "t".into(), "".into(), "".into(), "".into(), None),
                hit("auth-bypass", Severity::High, "u".into(), "t".into(), "".into(), "".into(), "".into(), None),
                hit("bola-surface", Severity::Info, "u".into(), "t".into(), "".into(), "".into(), "".into(), None),
            ],
        };
        // P-ID 부여 (finish_report 모방).
        let mut rep = rep;
        for (i, h) in rep.hits.iter_mut().enumerate() {
            h.id = format!("P-{:03}", i + 1);
        }
        let chains = chain_hints(&rep.hits);
        assert!(chains.iter().any(|c| c.contains("리다이렉트") && c.contains("P-001") && c.contains("P-002")), "{chains:?}");
        assert!(chains.iter().any(|c| c.contains("객체참조")), "{chains:?}");
        assert!(chains.len() <= 5, "상한 초과: {chains:?}");
        // 둘 다 info 면 점화하지 않는다.
        let mut quiet = rep.hits.clone();
        for h in quiet.iter_mut() {
            h.severity = "info".into();
        }
        assert!(chain_hints(&quiet).is_empty(), "info-only 는 무음: {:?}", chain_hints(&quiet));
        assert!(chain_hints(&[]).is_empty());
    }

    #[test]
    fn bola_surface_scan_shapes() {
        let dom = r#"<a href="/api/orders/100">a</a><a href="/api/orders/101">b</a><a href="/api/items?id=42">c</a>"#;
        let hits = scan_bola_surface(dom, "http://t");
        assert!(hits.iter().any(|h| h.category == "bola-surface" && h.title.contains("순차 ID")), "순차 ID 힛 없음: {hits:?}");
        assert!(hits.iter().any(|h| h.category == "bola-surface" && h.target.contains("?id=")), "파라미터 힛 없음: {hits:?}");
        assert!(hits.iter().all(|h| h.severity == "info"), "표면 스캔은 전부 info: {hits:?}");
        let clean = scan_bola_surface("<html><body>hello</body></html>", "http://t");
        assert!(clean.is_empty(), "ID 없으면 무음: {clean:?}");
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
        let cfg = SweepConfig { threads: 16, rps: 500, req_timeout: Duration::from_secs(5), sweep_timeout: Duration::from_secs(60), cookie: None, danger: false, feedback: None, login: None, crawl: None, oob: None, openapi: None, p1_budget: 96, no_browser: true };
        let rep = run_sweep_with_config("127.0.0.1", Some(port), cfg);
        assert!(!rep.authenticated);
        assert!(!rep.hits.iter().any(|h| h.category == "paths" && h.severity == "high" && h.target.contains("/.env")), "쿠키 없이 .env high 면 안 됨");
        // 쿠키 첨부: 200 → high 발견 + authenticated.
        let cfg2 = SweepConfig { threads: 16, rps: 500, req_timeout: Duration::from_secs(5), sweep_timeout: Duration::from_secs(60), cookie: Some("SESS=ok".into()), danger: false, feedback: None, login: None, crawl: None, oob: None, openapi: None, p1_budget: 96, no_browser: true };
        let rep2 = run_sweep_with_config("127.0.0.1", Some(port), cfg2);
        assert!(rep2.authenticated);
        assert!(rep2.hits.iter().any(|h| h.category == "paths" && h.severity == "high" && h.target.contains("/.env")), "쿠키로 .env high 검출 필요");
    }

    #[test]
    fn live_sweep_against_stub() {
        let port = start_stub();
        let cfg = SweepConfig { threads: 16, rps: 500, req_timeout: Duration::from_secs(5), sweep_timeout: Duration::from_secs(60), cookie: None, danger: false, feedback: None, login: None, crawl: None, oob: None, openapi: None, p1_budget: 96, no_browser: true };
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



