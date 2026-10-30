//! 콘텐츠 디스커버리 — 숨겨진 경로·파일·가상호스트·파라미터를 찾아 "공격 표면"을 넓힌다.
//!
//! ffuf·gobuster·dirsearch 를 대체하는 모듈이다. 세 가지 원칙을 지킨다.
//!
//! 1. **소프트 404 제거가 핵심** — 워드프레스·SPA 라우터는 없는 경로에도 200 을 돌려준다.
//!    그래서 존재하지 않는 무작위 경로로 **기준선**(status + 정규화 해시)을 두 번 수집하고,
//!    후보 응답이 기준선과 같으면 "없음"으로 처리한다. 기준선이 흔들리면(두 번 다름)
//!    두 샘플 모두와 비교해 오탐을 줄인다.
//! 2. **단일 HTTP 계층** — 모든 요청은 `crate::http::HttpClient` 로만 나간다.
//!    인가 검사·RPS 상한·리다이렉트 재검사·본문 상한이 이 계층에서 자동으로 보장된다.
//! 3. **비파괴** — GET 만 사용한다. 파라미터 값도 `""`/`"1"`/`"999999999"` 뿐이고
//!    특수문자를 넣지 않는다. 쓰기·삭제·무한 루프는 없다.
//!
//! **보고 구조** — 일반 경로 hit 은 "공격 표면 목록"(`DiscoveryReport::hits`) 에만 남고
//! `Finding` 으로 승격되지 않는다. `Finding` 은 아래 셋만 만든다.
//!
//!   - `exposed_sensitive_file` — 민감 파일(`.env`, `id_rsa`, `.git/config`, `*.sql` 덤프 …)이 노출됨
//!   - `discovery_signal` — 응답 본문에서 `crate::signals::detect` 가 잡은 신호
//!   - `unvalidated_parameter` — 파라미터 값에 따라 응답이 달라짐(파라미터당 1건)
//!
//! 그 밖에 요청 상한으로 탐색 범위가 잘렸을 때는 `discovery_budget` 로 1건 남긴다.
//!
//! **동시성** — `tokio::sync::Semaphore` 로 동시 요청 수를 제한한다.
//! `JoinSet` 대신 `futures::stream::FuturesUnordered` 를 쓰는 이유는,
//! `HttpClient` 가 `Clone` 이 아니어서 태스크를 `'static` 으로 만들 수 없기 때문이다
//! (`crate::http` 을 수정하지 않고 클라이언트를 복제하지 않으려면 빌려 쓰는 수밖에 없다).
//! 복제하지 않은 덕분에 `HttpClient` 안의 RPS 게이트가 그대로 하나만 살아 있다.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use futures::stream::{FuturesUnordered, StreamExt};
use serde::Serialize;
use tokio::sync::Semaphore;

use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::redact;
use crate::report::{self, Finding};
use crate::signals;
use crate::storm;
use crate::wordlists;

/// 기본 요청 상한.
pub const DEFAULT_MAX_REQUESTS: usize = 3000;

/// 기본 동시성.
pub const DEFAULT_CONCURRENCY: usize = 8;

/// 확장자 조합에 쓰는 기본 목록 (폭발을 막기 위해 짧게 유지한다).
pub const DEFAULT_EXTENSIONS: &[&str] = &["php", "bak", "old", "zip", "sql", "txt", "log", "json"];

/// 파라미터 퍼징에 쓰는 값 — 전부 비파괴 값이다.
pub const PARAM_PROBE_VALUES: &[&str] = &["", "1", "999999999"];

/// 백업 파일로 취급하는 확장자.
pub const BACKUP_EXTENSIONS: &[&str] = &[
    "bak", "old", "orig", "save", "tmp", "log", "sql", "dump", "backup", "zip", "tar", "tar.gz",
    "tgz", "gz", "7z", "rar",
];

/// 한 URL 에서 남기는 신호 Finding 최대 개수 (남발 억제).
pub const MAX_SIGNALS_PER_HIT: usize = 3;

/// 보고서에 남기는 신호 Finding 전체 최대 개수 (남발 억제).
pub const MAX_SIGNAL_FINDINGS: usize = 100;

/// 발견 종류.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HitKind {
    /// 평범한 경로/디렉터리.
    Path,
    /// 존재하지만 차단된 파일(403).
    File,
    /// 백업 파일(원본 경로도 함께 존재).
    Backup,
    /// 민감 파일(설정·시크릿· 덤프).
    Sensitive,
    /// 가상호스트가 다른 응답을 반환.
    Vhost,
    /// 값에 따라 응답이 달라지는 파라미터.
    Param,
}

impl HitKind {
    /// 한국어 라벨.
    pub fn label(&self) -> &'static str {
        match self {
            HitKind::Path => "경로",
            HitKind::File => "파일(차단됨)",
            HitKind::Backup => "백업 파일",
            HitKind::Sensitive => "민감 파일",
            HitKind::Vhost => "가상호스트",
            HitKind::Param => "파라미터",
        }
    }
}

impl std::fmt::Display for HitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// 공격 표면 발견 하나.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryHit {
    /// 실제 요청한 URL (시크릿은 마스킹된 상태).
    pub url: String,
    /// 응답 상태코드.
    pub status: u16,
    /// 응답 본문 길이(바이트).
    pub len: usize,
    /// 발견 종류.
    pub kind: HitKind,
    /// 응답 Content-Type.
    pub content_type: Option<String>,
    /// HTML `<title>`. 3xx 는 리다이렉트 대상(`Location: …`), 가상호스트 hit 은 시험한 Host.
    pub title: Option<String>,
    /// 정규화 본문 해시 (`crate::storm::short_hash`).
    pub signature: String,
}

/// 디스커버리 결과.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryReport {
    /// 공격 표면 목록 (일반 경로 hit 포함).
    pub hits: Vec<DiscoveryHit>,
    /// 실제 전송한 요청 수.
    pub requests: u64,
    /// 기준선 응답의 상태코드 (없는 경로에 대한 응답).
    pub baseline_status: u16,
    /// 전체 소요 시간(밀리초).
    pub duration_ms: u64,
    /// 승격된 발견 (민감 파일·신호·파라미터·예산 초과).
    pub findings: Vec<Finding>,
}

/// 디스커버리 계획.
#[derive(Debug, Clone)]
pub struct DiscoveryPlan {
    /// 대상 베이스 URL (예: `http://127.0.0.1:8080`).
    pub base_url: String,
    /// 사용자가 준 경로 목록 (`/admin` 형태).
    pub paths: Vec<String>,
    /// 경로에 붙일 확장자 목록 (`["php","bak"]`).
    pub extensions: Vec<String>,
    /// `wordlists::SENSITIVE_FILES` 를 포함할지.
    pub include_sensitive: bool,
    /// 가상호스트 퍼징을 할지.
    pub vhost: bool,
    /// 값 교차 시험할 파라미터 이름 목록.
    pub params: Vec<String>,
    /// 요청 상한 (절대 넘지 않는다).
    pub max_requests: usize,
    /// 동시 요청 수.
    pub concurrency: usize,
    /// hit 으로 인정할 상태코드. 비우면 2xx/3xx/401/403.
    pub match_status: Vec<u16>,
}

/// 기본 계획 — 사용자 경로만 넣고 돌려도 쓸 만한 설정.
pub fn default_plan(base_url: &str) -> DiscoveryPlan {
    DiscoveryPlan {
        base_url: base_url.to_string(),
        paths: Vec::new(),
        extensions: DEFAULT_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
        include_sensitive: true,
        vhost: false,
        params: Vec::new(),
        max_requests: DEFAULT_MAX_REQUESTS,
        concurrency: DEFAULT_CONCURRENCY,
        match_status: Vec::new(),
    }
}

/// 단계별 요청 예산.
struct Allocation {
    /// 가상호스트 단계를 실행할지.
    allow_vhost: bool,
    /// 파라미터 단계를 실행할지.
    allow_params: bool,
    /// 경로 탐색에 쓸 수 있는 요청 수.
    paths: usize,
}

/// 요청 예산을 계산한다 — 전체 요청이 `max_requests` 를 넘지 않게 한다.
fn allocation(plan: &DiscoveryPlan) -> Allocation {
    let max = plan.max_requests;
    let baseline = 2usize;
    let vhost_cost = if plan.vhost { 1 + wordlists::SUBDOMAIN_LABELS.len() } else { 0 };
    let param_cost = if plan.params.is_empty() {
        0
    } else {
        1 + plan.params.len() * PARAM_PROBE_VALUES.len()
    };
    let allow_vhost = max >= baseline.saturating_add(vhost_cost);
    let allow_params = max
        >= baseline
            .saturating_add(if allow_vhost { vhost_cost } else { 0 })
            .saturating_add(param_cost);
    let used = baseline
        .saturating_add(if allow_vhost { vhost_cost } else { 0 })
        .saturating_add(if allow_params { param_cost } else { 0 });
    Allocation { allow_vhost, allow_params, paths: max.saturating_sub(used) }
}

/// 경로 탐색에 쓸 수 있는 요청 수.
pub fn path_budget(plan: &DiscoveryPlan) -> usize {
    allocation(plan).paths
}

/// 경로 목록 — 사용자 경로 → 확장자 조합 → 민감 파일 → 기본 코퍼스 → 코퍼스 × 확장자.
///
/// 요청 상한에 걸리면 이 순서대로 앞에서부터 잘린다. 그래서 사용자 경로와 민감 파일이
/// 가장 먼저 시도된다.
pub fn build_paths(plan: &DiscoveryPlan) -> Vec<String> {
    let mut all = assemble_paths(plan);
    let budget = path_budget(plan);
    if all.len() > budget {
        all.truncate(budget);
    }
    all
}

/// 상한을 적용하지 않은 전체 후보 경로.
fn assemble_paths(plan: &DiscoveryPlan) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    // 1) 사용자 지정 경로.
    let user: Vec<String> = plan.paths.iter().filter_map(|p| normalize_path(p)).collect();
    for p in &user {
        push_unique(&mut out, &mut seen, p.clone());
    }

    // 2) 사용자 경로 × 확장자.
    let user_targets: Vec<String> = user.iter().filter(|p| !has_extension(p)).cloned().collect();
    for p in wordlists::with_extensions(&user_targets, &plan.extensions) {
        push_unique(&mut out, &mut seen, p);
    }

    // 3) 민감 파일 (이미 확장자가 붙은 이름이라 확장자 조합 대상이 아니다).
    if plan.include_sensitive {
        for f in wordlists::SENSITIVE_FILES {
            if let Some(p) = normalize_path(f) {
                push_unique(&mut out, &mut seen, p);
            }
        }
    }

    // 4) 기본 코퍼스.
    let mut corpus: Vec<String> = Vec::new();
    let mut corpus_seen: BTreeSet<String> = BTreeSet::new();
    for w in wordlists::COMMON_PATHS.iter().chain(wordlists::HIDDEN_ADMIN_PATHS.iter()) {
        if let Some(p) = normalize_path(w) {
            push_unique(&mut corpus, &mut corpus_seen, p);
        }
    }
    for p in &corpus {
        push_unique(&mut out, &mut seen, p.clone());
    }

    // 5) 코퍼스 × 확장자.
    let targets: Vec<String> = corpus.iter().filter(|p| !has_extension(p)).cloned().collect();
    for p in wordlists::with_extensions(&targets, &plan.extensions) {
        push_unique(&mut out, &mut seen, p);
    }

    out
}

/// 중복 없이 목록에 추가.
fn push_unique(out: &mut Vec<String>, seen: &mut BTreeSet<String>, p: String) {
    if seen.insert(p.clone()) {
        out.push(p);
    }
}

/// `"/admin"` 형태로 정규화한다.
fn normalize_path(raw: &str) -> Option<String> {
    let p = raw.trim().trim_start_matches('/');
    if p.is_empty() {
        None
    } else {
        Some(format!("/{p}"))
    }
}

/// 마지막 세그먼트에 이미 확장자가 붙어 있는가.
fn has_extension(path: &str) -> bool {
    path.rsplit('/').next().map(|s| s.contains('.')).unwrap_or(false)
}

/// 경로가 민감 파일 목록에 있는가.
pub fn is_sensitive_path(path: &str) -> bool {
    let p = path.trim().trim_start_matches('/').to_ascii_lowercase();
    wordlists::SENSITIVE_FILES.iter().any(|f| f.to_ascii_lowercase() == p)
}

/// 백업 확장자로 끝나는가.
pub fn is_backup_path(path: &str) -> bool {
    let seg = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    BACKUP_EXTENSIONS.iter().any(|e| seg.ends_with(&format!(".{e}")))
}

/// 백업 파일의 원본 경로 — `"/admin.bak"` → `Some("/admin")`.
pub fn base_path_of(path: &str) -> Option<String> {
    let (head, seg) = match path.rsplit_once('/') {
        Some((h, s)) => (h, s),
        None => ("", path),
    };
    let lower = seg.to_ascii_lowercase();
    if !BACKUP_EXTENSIONS.iter().any(|e| lower.ends_with(&format!(".{e}"))) {
        return None;
    }
    let dot = seg.rfind('.')?;
    let trimmed = seg.get(..dot)?;
    Some(format!("{head}/{trimmed}"))
}

/// 소프트 404 판정 — 기준선과 다르면 hit 후보.
///
/// 상태코드가 같고 정규화 해시도 같으면 "없는 경로"와 같은 응답 → hit 가 아니다.
/// 상태코드가 다르면 hit 후보, 상태코드가 같아도 해시가 다르면(내용이 다르면) hit 후보.
pub fn classify_hit(baseline_sig: &str, baseline_status: u16, status: u16, sig: &str) -> bool {
    status != baseline_status || sig != baseline_sig
}

/// 상태코드가 hit 조건에 맞는지 — `match_status` 가 비면 2xx/3xx/401/403.
pub fn status_matches(plan: &DiscoveryPlan, status: u16) -> bool {
    if plan.match_status.is_empty() {
        return (200..300).contains(&status)
            || (300..400).contains(&status)
            || status == 401
            || status == 403;
    }
    plan.match_status.contains(&status)
}

/// hit 종류를 분류한다.
///
/// `backup_base_found` 는 확장자를 떼어 만든 원본 경로도 같은 실행에서 발견되었는지다.
/// `true` 이면 백업 파일로, 아니면 평범한 경로로 본다.
pub fn classify_kind(path: &str, status: u16, backup_base_found: bool) -> HitKind {
    if is_sensitive_path(path) {
        return HitKind::Sensitive;
    }
    if backup_base_found && is_backup_path(path) {
        return HitKind::Backup;
    }
    if status == 403 {
        return HitKind::File;
    }
    HitKind::Path
}

/// URL 에서 경로 부분만 뽑는다 — 민감 파일 판정에는 경로가 필요하다.
pub fn path_of(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => {
            let p = u.path();
            if p.is_empty() { "/".to_string() } else { p.to_string() }
        }
        Err(_) => {
            // 스킴이 붙지 않은 상대 경로도 처리한다.
            match url.split_once("://") {
                Some((_, rest)) => match rest.find('/') {
                    Some(idx) => rest[idx..].to_string(),
                    None => "/".to_string(),
                },
                None => url.to_string(),
            }
        }
    }
}

/// 민감 파일의 심각도.
///
/// critical — `.env`, 시크릿 키(`id_rsa`, `private.key`, `credentials*`, `secrets*` …), `.git/config`
/// high — 백업·설정(`*.bak`, `config*`, `web.config`, `*.sql` 덤프 …)
/// medium — 로그·기타
pub fn sensitive_severity(path: &str) -> &'static str {
    let p = path.trim().trim_start_matches('/').to_ascii_lowercase();
    if p.starts_with(".env")
        || p.contains("id_rsa")
        || p.contains("id_dsa")
        || p.contains("id_ecdsa")
        || p.contains("id_ed25519")
        || p.contains("authorized_keys")
        || p.starts_with(".ssh/")
        || p.contains("private.key")
        || p.contains("private.pem")
        || p.contains("server.key")
        || p.contains("server.pem")
        || p.contains("certificate.pem")
        || p.ends_with(".pem")
        || p.ends_with(".key")
        || p.contains("credential")
        || p.contains("secrets")
        || p.contains("secret_key_base")
        || p.contains("master.key")
        || p.contains("kubeconfig")
        || p.contains(".kube/")
        || p.contains("service-account")
        || p == ".git/config"
    {
        return "critical";
    }
    if p.ends_with(".bak")
        || p.ends_with(".old")
        || p.ends_with(".orig")
        || p.ends_with(".save")
        || p.contains("backup")
        || p.contains("dump")
        || p.ends_with(".sql")
        || p.ends_with(".zip")
        || p.ends_with(".tar.gz")
        || p.ends_with(".tgz")
        || p.contains("config")
        || p.contains("web.config")
        || p.contains("appsettings")
        || p.contains("database.yml")
        || p.contains("docker-compose")
        || p.contains(".git/")
        || p == ".gitignore"
        || p == ".gitattributes"
        || p.contains(".htaccess")
        || p.contains(".htpasswd")
        || p.contains("makefile")
        || p.contains("dockerfile")
        || p.contains("requirements.txt")
        || p.contains("package-lock")
        || p.contains("composer.lock")
        || p.contains("vagrantfile")
        || p.contains("jenkinsfile")
        || p.contains("pipeline")
    {
        return "high";
    }
    "medium"
}

/// 본문 해시 — 정규화 후 `storm::short_hash`.
pub fn signature(body: &str) -> String {
    storm::short_hash(&storm::normalize_body(body))
}

/// 본문 앞 800자를 시크릿 마스킹해서 만든 증거 문자열.
pub fn evidence_excerpt(body: &str) -> String {
    let excerpt: String = body.chars().take(800).collect();
    let redacted = redact::redact_text(&excerpt);
    if redacted.trim().is_empty() {
        "(응답 본문 없음)".to_string()
    } else {
        redacted
    }
}

/// 하나의 hit 으로 만들어지는 Finding 목록 — 민감 파일 + 본문 신호.
///
/// 일반 경로 hit 은 여기서 아무 Finding 도 만들지 않는다(공격 표면 목록에 머문다).
pub fn build_findings_for_hit(hit: &DiscoveryHit, body: &str) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    let url = redact::redact_url(&hit.url);

    if hit.kind == HitKind::Sensitive {
        let path = path_of(&hit.url);
        out.push(Finding {
            title: format!("민감 파일 노출: {path}"),
            severity: sensitive_severity(&path).to_string(),
            category: "exposed_sensitive_file".to_string(),
            target: url.clone(),
            evidence: evidence_excerpt(body),
            reproduction: format!("curl -sk {url}"),
            remediation: "노출된 파일을 서버에서 즉시 제거하고, 저장소 히스토리(git filter-repo·BFG)에서 \
                          시크릿을 삭제한 뒤 비밀값을 회전시키세요."
                .to_string(),
        });
    }

    for name in signals::detect(body).iter().take(MAX_SIGNALS_PER_HIT) {
        out.push(Finding {
            title: report::signal_label(name).to_string(),
            severity: signals::severity(name).to_string(),
            category: "discovery_signal".to_string(),
            target: url.clone(),
            evidence: evidence_excerpt(body),
            reproduction: format!("curl -sk {url}"),
            remediation: signals::remediation(name).to_string(),
        });
    }

    out
}

/// 파라미터 값이 응답을 바꾸면 만드는 Finding — 파라미터당 1건.
pub fn build_param_finding(param: &str, url: &str) -> Finding {
    let safe_url = redact::redact_url(url);
    Finding {
        title: format!("파라미터 값 검증 미비: {param}"),
        severity: "low".to_string(),
        category: "unvalidated_parameter".to_string(),
        target: safe_url.clone(),
        evidence: format!(
            "파라미터 `{param}` 의 값을 바꿨을 때 응답 서명이 변경되었습니다. \
             서버가 이 값을 입력으로 읽고 있다는 뜻입니다."
        ),
        reproduction: format!("curl -sk '{safe_url}'"),
        remediation: "서버 측 입력 검증(타입·범위·화이트리스트)을 적용하고, 잘못된 값에 대한 \
                      오류 메시지를 일반화하세요."
            .to_string(),
    }
}

/// 요청 상한으로 탐색 범위가 잘렸을 때 남기는 Finding.
fn build_budget_finding(plan: &DiscoveryPlan, candidates: usize, tried: usize) -> Finding {
    Finding {
        title: "요청 상한으로 탐색 범위가 제한됨".to_string(),
        severity: "low".to_string(),
        category: "discovery_budget".to_string(),
        target: redact::redact_url(&plan.base_url),
        evidence: format!(
            "요청 상한 {limit}건 때문에 후보 경로 {candidates}개 중 {tried}개만 시도했습니다. \
             나머지 경로는 점검되지 않았습니다.",
            limit = plan.max_requests,
            candidates = candidates,
            tried = tried
        ),
        reproduction: format!("curl -sk {}", redact::redact_url(&plan.base_url)),
        remediation: "요청 상한을 높여 다시 실행하거나, 대상별로 계획을 나눠 점검 범위를 \
                      빠짐없이 확인하세요."
            .to_string(),
    }
}

/// 수집 중이던 hit (본문은 Finding 근거로 필요하다).
struct Candidate {
    /// 요청한 경로.
    path: String,
    /// 보고용 hit.
    hit: DiscoveryHit,
    /// 응답 본문.
    body: String,
}

/// 무작위 토큰 — 기준선 경로와 가상호스트 기준선에 쓴다.
fn nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string().chars().take(12).collect()
}

/// GET 1건 — 요청 수를 세고, 실패하면 `None`.
async fn probe(
    client: &HttpClient,
    url: &str,
    headers: &[(&str, &str)],
    counter: &AtomicU64,
) -> Option<HttpResponse> {
    counter.fetch_add(1, Ordering::Relaxed);
    let mut req = HttpRequest::get(url).no_redirect();
    for (k, v) in headers {
        req = req.with_header(k, v);
    }
    client.send(&req).await.ok()
}

/// Content-Type 요약.
fn content_type_of(resp: &HttpResponse) -> Option<String> {
    resp.header("content-type")
        .map(|v| v.split(';').next().unwrap_or(v).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// HTML `<title>` 추출 — 정규식으로 만들지 않고 직접 찾아 UTF-8 경계를 지킨다.
fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let open_end = lower.get(start..)?.find('>')? + start + 1;
    let close = lower.get(open_end..)?.find("</title>")? + open_end;
    let raw = body.get(open_end..close)?.trim();
    let title: String = raw.chars().take(120).collect();
    let title = redact::redact_text(&title);
    if title.is_empty() { None } else { Some(title) }
}

/// 경로 단계를 실행한다.
async fn probe_paths(
    client: &HttpClient,
    plan: &DiscoveryPlan,
    base: &str,
    counter: &AtomicU64,
    baseline: &[(u16, String)],
) -> Vec<Candidate> {
    let paths = build_paths(plan);
    let sem = Arc::new(Semaphore::new(plan.concurrency.clamp(1, 64)));
    let mut futs = FuturesUnordered::new();

    for p in &paths {
        let url = format!("{base}{p}");
        let sem = Arc::clone(&sem);
        futs.push(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return None;
            };
            let resp = probe(client, &url, &[], counter).await?;
            Some((p.clone(), url, resp))
        });
    }

    let mut out: Vec<Candidate> = Vec::new();
    while let Some(item) = futs.next().await {
        let Some((path, url, resp)) = item else { continue };
        if !status_matches(plan, resp.status) {
            continue;
        }
        let sig = signature(&resp.body);
        // 기준선 샘플 중 **어느 하나와도** 같지 않으면 hit — 흔들리는 기준선에도 안전하다.
        let is_hit = baseline
            .iter()
            .all(|(bs, bsig)| classify_hit(bsig, *bs, resp.status, &sig));
        if !is_hit {
            continue;
        }
        let title = if (300..400).contains(&resp.status) {
            resp.header("location").map(|l| format!("Location: {l}"))
        } else {
            extract_title(&resp.body)
        };
        out.push(Candidate {
            path: path.clone(),
            hit: DiscoveryHit {
                url: redact::redact_url(&url),
                status: resp.status,
                len: resp.body.len(),
                kind: HitKind::Path,
                content_type: content_type_of(&resp),
                title,
                signature: sig,
            },
            body: resp.body,
        });
    }
    out
}

/// 가상호스트 단계를 실행한다.
async fn probe_vhosts(
    client: &HttpClient,
    base: &str,
    root: &str,
    counter: &AtomicU64,
) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let Some(host) = url::Url::parse(base).ok().and_then(|u| u.host_str().map(|h| h.to_string())) else {
        return out;
    };

    // 기준선 — 허용되지 않는 임의 Host.
    let bogus = format!("forge-invalid-{}.invalid", nonce());
    let Some(base_resp) = probe(client, root, &[("Host", bogus.as_str())], counter).await else {
        return out;
    };
    let bstatus = base_resp.status;
    let bsig = signature(&base_resp.body);
    let bbody = base_resp.body.clone();

    for label in wordlists::SUBDOMAIN_LABELS {
        let vhost = format!("{label}.{host}");
        let Some(resp) = probe(client, root, &[("Host", vhost.as_str())], counter).await else {
            continue;
        };
        // 응답 본문이 기준선과 완전히 같으면 제외.
        if resp.body == bbody {
            continue;
        }
        let sig = signature(&resp.body);
        if !classify_hit(&bsig, bstatus, resp.status, &sig) {
            continue;
        }
        out.push(Candidate {
            path: format!("/{label}"),
            hit: DiscoveryHit {
                url: redact::redact_url(root),
                status: resp.status,
                len: resp.body.len(),
                kind: HitKind::Vhost,
                content_type: content_type_of(&resp),
                title: Some(format!("Host: {vhost}")),
                signature: sig,
            },
            body: resp.body,
        });
    }
    out
}

/// 파라미터 단계를 실행한다 — 파라미터마다 1건의 hit 만 남긴다.
async fn probe_params(
    client: &HttpClient,
    plan: &DiscoveryPlan,
    root: &str,
    counter: &AtomicU64,
    findings: &mut Vec<Finding>,
) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let Some(base_resp) = probe(client, root, &[], counter).await else {
        return out;
    };
    let bstatus = base_resp.status;
    let bsig = signature(&base_resp.body);

    for param in &plan.params {
        let name = param.trim();
        if name.is_empty() {
            continue;
        }
        let mut recorded = false;
        for value in PARAM_PROBE_VALUES {
            let url = storm::inject_query(root, name, value);
            let Some(resp) = probe(client, &url, &[], counter).await else { continue };
            let sig = signature(&resp.body);
            if !classify_hit(&bsig, bstatus, resp.status, &sig) {
                continue;
            }
            if recorded {
                continue;
            }
            recorded = true;
            findings.push(build_param_finding(name, &url));
            out.push(Candidate {
                path: format!("/{name}"),
                hit: DiscoveryHit {
                    url: redact::redact_url(&url),
                    status: resp.status,
                    len: resp.body.len(),
                    kind: HitKind::Param,
                    content_type: content_type_of(&resp),
                    title: Some(format!("param: {name}")),
                    signature: sig,
                },
                body: resp.body,
            });
        }
    }
    out
}

/// 디스커버리 실행.
///
/// 기준선을 두 번 수집해 소프트 404 를 제거한 뒤, 경로 → 가상호스트 → 파라미터 순서로
/// 후보를 훑는다. 전체 요청 수는 `plan.max_requests` 를 넘지 않는다.
pub async fn run(client: &HttpClient, plan: &DiscoveryPlan) -> Result<DiscoveryReport, String> {
    let started = Instant::now();
    let base = plan.base_url.trim().trim_end_matches('/').to_string();
    if base.is_empty() {
        return Err("기본 URL 이 비어 있습니다.".to_string());
    }
    if url::Url::parse(&base).is_err() {
        return Err(format!("기본 URL 을 해석할 수 없습니다: {}", plan.base_url));
    }
    let root = format!("{base}/");
    let counter = AtomicU64::new(0);
    let alloc = allocation(plan);

    // 1) 기준선 (두 번) — 없는 경로의 응답 모양을 기억한다.
    let mut baseline: Vec<(u16, String)> = Vec::new();
    let mut baseline_status = 0u16;
    for i in 0..2 {
        let probe_url = format!("{root}forge-nonexistent-{}", nonce());
        if let Some(resp) = probe(client, &probe_url, &[], &counter).await {
            let sig = signature(&resp.body);
            if i == 0 {
                baseline_status = resp.status;
            }
            baseline.push((resp.status, sig));
        }
    }
    if baseline.is_empty() {
        return Err("기준선 응답을 수집하지 못했습니다 — 대상 서버에 연결 가능한지 확인하세요.".to_string());
    }

    // 2) 경로 탐색.
    let mut candidates = probe_paths(client, plan, &base, &counter, &baseline).await;

    // 3) 가상호스트 퍼징.
    if alloc.allow_vhost {
        candidates.extend(probe_vhosts(client, &base, &root, &counter).await);
    }

    // 4) 파라미터 퍼징.
    let mut findings: Vec<Finding> = Vec::new();
    if alloc.allow_params {
        candidates.extend(probe_params(client, plan, &root, &counter, &mut findings).await);
    }

    // 5) 백업 판정 — 원본 경로도 발견된 경우에만 Backup.
    let hit_paths: BTreeSet<String> = candidates.iter().map(|c| c.path.clone()).collect();
    for c in &mut candidates {
        let base_found = base_path_of(&c.path).map(|b| hit_paths.contains(&b)).unwrap_or(false);
        c.hit.kind = classify_kind(&c.path, c.hit.status, base_found);
    }

    // 6) Finding 승격 — 민감 파일 + 본문 신호. 일반 경로 hit 은 승격하지 않는다.
    let mut signal_findings = 0usize;
    for c in &candidates {
        for f in build_findings_for_hit(&c.hit, &c.body) {
            if f.category == "discovery_signal" {
                if signal_findings >= MAX_SIGNAL_FINDINGS {
                    continue;
                }
                signal_findings += 1;
            }
            findings.push(f);
        }
    }

    // 7) 요청 상한으로 경로가 잘렸다면 그 사실을 남긴다.
    let total_candidates = assemble_paths(plan).len();
    let tried = build_paths(plan).len();
    if total_candidates > tried {
        findings.push(build_budget_finding(plan, total_candidates, tried));
    }

    // 8) 공격 표면 목록 정리 — 민감한 것부터, 같은 종류끼리는 URL 순.
    let mut hits: Vec<DiscoveryHit> = candidates.into_iter().map(|c| c.hit).collect();
    hits.sort_by(|a, b| {
        kind_rank(a.kind)
            .cmp(&kind_rank(b.kind))
            .then_with(|| a.url.cmp(&b.url))
            .then_with(|| a.status.cmp(&b.status))
    });

    Ok(DiscoveryReport {
        hits,
        requests: counter.load(Ordering::Relaxed),
        baseline_status,
        duration_ms: started.elapsed().as_millis() as u64,
        findings,
    })
}

/// 정렬 우선순위 — 민감 파일이 맨 위.
fn kind_rank(kind: HitKind) -> u8 {
    match kind {
        HitKind::Sensitive => 0,
        HitKind::Backup => 1,
        HitKind::File => 2,
        HitKind::Path => 3,
        HitKind::Vhost => 4,
        HitKind::Param => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_with(paths: &[&str], exts: &[&str], max: usize) -> DiscoveryPlan {
        let mut p = default_plan("http://127.0.0.1:8080");
        p.paths = paths.iter().map(|s| s.to_string()).collect();
        p.extensions = exts.iter().map(|s| s.to_string()).collect();
        p.include_sensitive = false;
        p.max_requests = max;
        p
    }

    #[test]
    fn build_paths_expands_extensions_on_base_path() {
        let plan = plan_with(&["/admin"], &["php", "bak"], 500);
        let paths = build_paths(&plan);
        assert!(paths.contains(&"/admin".to_string()), "{paths:?}");
        assert!(paths.contains(&"/admin.php".to_string()), "{paths:?}");
        assert!(paths.contains(&"/admin.bak".to_string()), "{paths:?}");
        // 확장자 조합은 base 경로에만 붙인다 (중복 조합 없음).
        assert!(!paths.contains(&"/admin.php.bak".to_string()), "{paths:?}");
        assert!(!paths.contains(&"/admin.txt".to_string()), "{paths:?}");
    }

    #[test]
    fn build_paths_includes_sensitive_and_corpus_only_when_asked() {
        let mut plan = plan_with(&[], &[], 5000);
        plan.include_sensitive = true;
        let paths = build_paths(&plan);
        assert!(paths.contains(&"/.env".to_string()), "{paths:?}");
        assert!(paths.contains(&"/.git/config".to_string()), "{paths:?}");
        assert!(paths.contains(&"/login".to_string()), "{paths:?}");
        assert!(paths.contains(&"/phpmyadmin".to_string()), "{paths:?}");

        plan.include_sensitive = false;
        let paths = build_paths(&plan);
        assert!(!paths.contains(&"/.env".to_string()), "{paths:?}");
    }

    #[test]
    fn build_paths_truncates_to_request_budget() {
        let plan = plan_with(&["/a"], &["php", "bak", "old"], 20);
        let paths = build_paths(&plan);
        assert!(paths.len() <= path_budget(&plan), "{} > {}", paths.len(), path_budget(&plan));
        assert!(paths.len() < assemble_paths(&plan).len());
        // 절단되면 앞(사용자 경로)부터 남는다.
        assert!(paths.contains(&"/a".to_string()), "{paths:?}");
    }

    #[test]
    fn soft_404_with_same_signature_is_not_a_hit() {
        // 상태코드도 해시도 같으면 없는 경로와 같은 응답 → hit 아님.
        assert!(!classify_hit("abc123", 404, 404, "abc123"));
        // 상태코드가 다르면 hit.
        assert!(classify_hit("abc123", 404, 200, "abc123"));
        // 상태코드는 같아도 내용이 다르면 hit.
        assert!(classify_hit("abc123", 404, 404, "def456"));
    }

    #[test]
    fn classify_kind_maps_status_and_kind() {
        // 민감 파일이 최우선.
        assert_eq!(classify_kind("/.env", 200, false), HitKind::Sensitive);
        assert_eq!(classify_kind("/.git/config", 200, false), HitKind::Sensitive);
        // 원본 경로도 존재하면 백업.
        assert_eq!(classify_kind("/admin.bak", 200, true), HitKind::Backup);
        assert_eq!(classify_kind("/admin.bak", 200, false), HitKind::Path);
        // 403 은 존재하지만 차단된 파일.
        assert_eq!(classify_kind("/admin", 403, false), HitKind::File);
        // 200 / 3xx 는 경로.
        assert_eq!(classify_kind("/admin", 200, false), HitKind::Path);
        assert_eq!(classify_kind("/admin", 302, false), HitKind::Path);
    }

    #[test]
    fn sensitive_severity_is_grouped_by_file_type() {
        assert_eq!(sensitive_severity("/.env"), "critical");
        assert_eq!(sensitive_severity("/.env.production"), "critical");
        assert_eq!(sensitive_severity("/id_rsa"), "critical");
        assert_eq!(sensitive_severity("/.git/config"), "critical");
        assert_eq!(sensitive_severity("/wp-config.php.bak"), "high");
        assert_eq!(sensitive_severity("/web.config"), "high");
        assert_eq!(sensitive_severity("/backup.sql"), "high");
        assert_eq!(sensitive_severity("/access.log"), "medium");
        assert_eq!(sensitive_severity("/error_log"), "medium");
    }

    #[test]
    fn status_filter_uses_defaults_then_explicit_list() {
        let plan = default_plan("http://127.0.0.1:8080");
        assert!(status_matches(&plan, 200));
        assert!(status_matches(&plan, 302));
        assert!(status_matches(&plan, 401));
        assert!(status_matches(&plan, 403));
        assert!(!status_matches(&plan, 404));
        assert!(!status_matches(&plan, 500));

        let mut strict = plan.clone();
        strict.match_status = vec![200, 500];
        assert!(status_matches(&strict, 500));
        assert!(!status_matches(&strict, 403));
    }

    #[test]
    fn base_path_and_backup_detection() {
        assert_eq!(base_path_of("/admin.bak").as_deref(), Some("/admin"));
        assert_eq!(base_path_of("/wp-admin/index.php.bak").as_deref(), Some("/wp-admin/index.php"));
        assert_eq!(base_path_of("/admin"), None);
        assert!(is_backup_path("/backup.sql"));
        assert!(!is_backup_path("/index.php"));
        assert!(is_sensitive_path("/.env"));
        assert!(!is_sensitive_path("/admin"));
    }

    #[test]
    fn findings_only_promote_sensitive_files_and_signals() {
        let plain = DiscoveryHit {
            url: "http://127.0.0.1:8080/admin".to_string(),
            status: 200,
            len: 10,
            kind: HitKind::Path,
            content_type: None,
            title: None,
            signature: "x".to_string(),
        };
        assert!(build_findings_for_hit(&plain, "<html>ok</html>").is_empty());

        let sensitive = DiscoveryHit {
            kind: HitKind::Sensitive,
            url: "http://127.0.0.1:8080/.env".to_string(),
            ..plain.clone()
        };
        let out = build_findings_for_hit(&sensitive, "SECRET=AKIAIOSFODNN7EXAMPLE\n");
        // 민감 파일 Finding + (본문 신호가 있으면) 신호 Finding.
        let exposed = out.iter().find(|f| f.category == "exposed_sensitive_file").expect("민감 파일 Finding");
        assert_eq!(exposed.severity, "critical");
        assert!(exposed.reproduction.contains("curl -sk"));
        // 시크릿은 마스킹되어야 한다.
        assert!(!exposed.evidence.contains("AKIAIOSFODNN7EXAMPLE"), "{}", exposed.evidence);
    }

    #[test]
    fn signal_findings_use_signal_severity_and_label() {
        let hit = DiscoveryHit {
            url: "http://127.0.0.1:8080/index.php".to_string(),
            status: 200,
            len: 10,
            kind: HitKind::Path,
            content_type: None,
            title: None,
            signature: "x".to_string(),
        };
        let out = build_findings_for_hit(&hit, "You have an error in your SQL syntax near 'x'");
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].category, "discovery_signal");
        assert_eq!(out[0].severity, signals::severity("sql_error"));
        assert_eq!(out[0].title, report::signal_label("sql_error"));
    }

    #[test]
    fn param_finding_is_single_low_severity() {
        let f = build_param_finding("id", "http://127.0.0.1:8080/?id=1");
        assert_eq!(f.category, "unvalidated_parameter");
        assert_eq!(f.severity, "low");
    }

    #[test]
    fn default_plan_is_bounded() {
        let p = default_plan("http://127.0.0.1:8080");
        assert_eq!(p.max_requests, DEFAULT_MAX_REQUESTS);
        assert_eq!(p.concurrency, DEFAULT_CONCURRENCY);
        assert!(!p.extensions.is_empty());
        assert!(p.match_status.is_empty());
    }

    #[test]
    fn title_and_content_type_extraction() {
        assert_eq!(
            extract_title("<html><head><title> Admin </title></head></html>").as_deref(),
            Some("Admin")
        );
        assert_eq!(extract_title("<html>no title</html>"), None);
    }

    #[test]
    fn signature_ignores_dynamic_numbers() {
        let a = signature("<p>id=12345</p>");
        let b = signature("<p>id=99999</p>");
        assert_eq!(a, b);
        assert_ne!(a, signature("<p>other</p>"));
    }

    // ── 모의 대상 서버 (루프백) ────────────────────────────────────────

    /// 소프트 404 서버 — 없는 경로에도 200 을 주되 본문은 항상 같다.
    fn start_lab() -> u16 {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let target = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let path = target.split('?').next().unwrap_or("/").to_string();

                let (status, reason, extra, body) = match path.as_str() {
                    "/.env" => (
                        200,
                        "OK",
                        String::new(),
                        "SECRET_KEY=abcdef1234567890\n".to_string(),
                    ),
                    "/admin" => (403, "Forbidden", String::new(), "forbidden\n".to_string()),
                    "/hidden-panel" => (
                        302,
                        "Found",
                        "Location: /login\r\n".to_string(),
                        String::new(),
                    ),
                    // 나머지는 모두 "부드러운 404" — 200 이지만 본문이 같다.
                    _ => (
                        200,
                        "OK",
                        String::new(),
                        "<html><body>not found</body></html>".to_string(),
                    ),
                };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        port
    }

    fn auth_for(port: u16) -> std::sync::Arc<crate::scope::Authorization> {
        let text = format!(
            "engagement:\n  name: \"discover-test\"\nscope:\n  allow:\n    - host: \"127.0.0.1\"\nports:\n  allow_tcp: [{port}]\nlimits:\n  max_requests_per_second: 500\n"
        );
        std::sync::Arc::new(crate::scope::Authorization::parse(&text).expect("인가 파싱"))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_removes_soft_404_and_reports_sensitive_files() {
        let port = start_lab();
        let client = HttpClient::new(auth_for(port)).expect("클라이언트 생성");
        let mut plan = default_plan(&format!("http://127.0.0.1:{port}"));
        plan.paths = vec![
            "/.env".to_string(),
            "/admin".to_string(),
            "/hidden-panel".to_string(),
            "/nothing-here".to_string(),
        ];
        plan.extensions = Vec::new();
        plan.include_sensitive = false;
        plan.max_requests = 40;
        plan.concurrency = 4;

        let report = run(&client, &plan).await.expect("디스커버리 실패");

        // 소프트 404 서버라 기준선도 200 이다.
        assert_eq!(report.baseline_status, 200);

        let find = |needle: &str| {
            report
                .hits
                .iter()
                .find(|h| h.url.ends_with(needle))
                .unwrap_or_else(|| panic!("{needle} 를 찾지 못함: {:?}", report.hits))
                .clone()
        };

        // 민감 파일 — Sensitive + Finding(critical).
        let env = find("/.env");
        assert_eq!(env.kind, HitKind::Sensitive);
        let exposed = report
            .findings
            .iter()
            .find(|f| f.category == "exposed_sensitive_file")
            .expect("민감 파일 Finding 없음");
        assert_eq!(exposed.severity, "critical");
        assert!(exposed.reproduction.contains("curl -sk"));
        assert!(!exposed.evidence.contains("abcdef1234567890"), "{}", exposed.evidence);

        // 403 — 존재하지만 차단된 파일.
        assert_eq!(find("/admin").kind, HitKind::File);

        // 3xx — 경로 + Location 기록.
        let panel = find("/hidden-panel");
        assert_eq!(panel.kind, HitKind::Path);
        assert!(panel.title.as_deref().unwrap_or("").contains("/login"), "{:?}", panel.title);

        // 소프트 404 — 없는 경로는 hit 이 아니다.
        assert!(
            !report.hits.iter().any(|h| h.url.ends_with("/nothing-here")),
            "소프트 404 가 hit 으로 잡힘: {:?}",
            report.hits
        );
        // 코퍼스 경로도 모두 소프트 404 면 잡히지 않는다.
        assert_eq!(report.hits.len(), 3, "{:?}", report.hits);

        // 일반 경로 hit 은 Finding 이 아니다 (공격 표면 목록에만 남는다).
        // 대신 상한으로 잘렸다는 사실은 남는다.
        let budget = report
            .findings
            .iter()
            .find(|f| f.category == "discovery_budget")
            .expect("요청 상한 안내 없음");
        assert!(budget.evidence.contains("요청 상한"), "{}", budget.evidence);
        assert_eq!(budget.severity, "low");
    }
}
