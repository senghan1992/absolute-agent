//! 공유 HTTP 클라이언트 — 모든 아웃바운드 트래픽의 단일 관문.
//!
//! 신형 모듈(포트스캔·콘텐츠 디스커버리·템플릿 엔진·크롤러)이 흩어지지 않도록
//! 트래픽 계층을 한 곳에 모은다. 이 계층이 보장하는 것:
//!
//!   1. **인가 게이트** — 호스트·포트 검사를 요청마다 수행 (fail-closed)
//!   2. **RPS 상한** — 인가 파일의 `limits.max_requests_per_second` 를 강제
//!   3. **리다이렉트 재검사** — 자동 추종을 끄고 직접 따라가며, 매 홉마다 인가 재확인.
//!      (인가 밖 호스트로의 302 → 차단)
//!   4. **프록시 무시** — `HTTP_PROXY`/`ALL_PROXY` 환경변수로 인가를 우회하지 못하게 한다
//!   5. **응답 상한** — 본문은 최대 `max_body` 바이트까지만 읽는다 (메모리 폭주 방지)
//!
//! 기존 `storm::Gate`(토큰 버킷)를 그대로 재사용하므로 RPS 규칙이 엔진 간 달라지지 않는다.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::scope::{Authorization, ScopeError};
use crate::storm::Gate;

/// 기본 응답 본문 상한 (2 MiB).
pub const DEFAULT_MAX_BODY: usize = 2 * 1024 * 1024;

/// 리다이렉트 최대 홉.
pub const MAX_REDIRECTS: usize = 5;

/// HTTP 오류.
#[derive(Debug)]
pub enum HttpError {
    /// 인가 범위 밖 — fail-closed.
    Scope(ScopeError),
    /// URL 파싱 실패.
    InvalidUrl(String),
    /// 전송 실패.
    Transport(String),
    /// 리다이렉트 제한 초과.
    TooManyRedirects,
    /// 응답 본문 읽기 실패.
    Body(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Scope(e) => write!(f, "{e}"),
            HttpError::InvalidUrl(m) => write!(f, "URL 오류: {m}"),
            HttpError::Transport(m) => write!(f, "전송 오류: {m}"),
            HttpError::TooManyRedirects => write!(f, "리다이렉트 횟수 초과 ({MAX_REDIRECTS})."),
            HttpError::Body(m) => write!(f, "응답 읽기 오류: {m}"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<ScopeError> for HttpError {
    fn from(e: ScopeError) -> Self {
        HttpError::Scope(e)
    }
}

/// 요청 1건.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    /// 리다이렉트 추종 (최대 5홉, 매 홉 인가 재검사).
    pub follow_redirects: bool,
    /// 요청별 타임아웃(초). 0 이면 클라이언트 기본값.
    pub timeout_secs: u64,
}

impl HttpRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: "GET".into(),
            url: url.into(),
            query: vec![],
            headers: vec![],
            body: None,
            follow_redirects: true,
            timeout_secs: 0,
        }
    }

    pub fn new(method: &str, url: impl Into<String>) -> Self {
        Self { method: method.to_ascii_uppercase(), ..Self::get(url) }
    }

    pub fn with_query(mut self, k: &str, v: &str) -> Self {
        self.query.push((k.to_string(), v.to_string()));
        self
    }

    pub fn with_header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }

    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn no_redirect(mut self) -> Self {
        self.follow_redirects = false;
        self
    }
}

/// 응답 1건.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// 최종 URL (리다이렉트 추종 후).
    pub url: String,
    pub elapsed_ms: u64,
    /// 따라간 리다이렉트 경로.
    pub redirects: Vec<String>,
    /// 본문이 잘렸는지.
    pub truncated: bool,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn len(&self) -> usize {
        self.body.len()
    }

    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// 상태코드 + 본문 길이 조합 — 존재 여부 지문으로 쓴다.
    pub fn fingerprint(&self) -> (u16, usize) {
        (self.status, self.body.len())
    }
}

/// 인가·RPS를 적용하는 HTTP 클라이언트.
pub struct HttpClient {
    client: reqwest::Client,
    auth: Arc<Authorization>,
    gate: Arc<Gate>,
    max_body: usize,
}

impl HttpClient {
    /// 클라이언트 생성. `FORGE_INSECURE=1` 이면 자체 서명 인증서를 허용한다(랩 전용).
    pub fn new(auth: Arc<Authorization>) -> Result<Self, String> {
        let insecure = std::env::var("FORGE_INSECURE").ok().as_deref() == Some("1");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            // 자동 리다이렉트를 끈다 — 인가 밖 호스트로의 리다이렉트를 막기 위해 직접 처리한다.
            .redirect(reqwest::redirect::Policy::none())
            // 프록시 환경변수는 인가 우회 경로가 된다. 무시한다.
            .no_proxy()
            .danger_accept_invalid_certs(insecure)
            .user_agent("REDFORGE/0.2 (+authorized-security-testing)")
            .pool_max_idle_per_host(64)
            .build()
            .map_err(|e| e.to_string())?;
        let gate = crate::storm::shared_gate(auth.effective_rps());
        Ok(Self { client, auth, gate, max_body: DEFAULT_MAX_BODY })
    }

    /// 응답 본문 상한 설정.
    pub fn with_max_body(mut self, max: usize) -> Self {
        self.max_body = max;
        self
    }

    /// 인가 참조.
    pub fn auth(&self) -> &Authorization {
        &self.auth
    }

    /// URL 이 인가 대상인지 확인.
    pub fn check_scope(&self, url: &str) -> Result<(String, Option<u16>), ScopeError> {
        let (host, port, _) = crate::scope::split_authority(url).map_err(ScopeError::Invalid)?;
        self.auth.check(&host, port)?;
        Ok((host, port))
    }

    /// 요청 실행 — 인가 검사 → RPS → 전송 → (리다이렉트 추종, 매 홉 재검사).
    pub async fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError> {
        let mut current = req.url.clone();
        let mut query = req.query.clone();
        let mut redirects: Vec<String> = Vec::new();
        let started = Instant::now();
        let mut hop = 0usize;

        loop {
            let full = build_url(&current, &query);
            // 1) 인가 검사 (매 홉).
            self.check_scope(&full)?;

            // 2) RPS 상한.
            self.gate.acquire().await;

            let method = reqwest::Method::from_bytes(req.method.as_bytes())
                .unwrap_or(reqwest::Method::GET);
            let mut builder = self.client.request(method, &full);
            // 인가 파일의 자격증명(쿠키·베어러·추가 헤더)을 주입 — 대상 호스트에만.
            let (req_host, _, _) = crate::scope::split_authority(&full).map_err(HttpError::InvalidUrl)?;
            if self.auth.applies_to_host(&req_host) {
                for (k, v) in self.auth.credentials.merge_headers() {
                    builder = builder.header(k.as_str(), v.as_str());
                }
            }
            for (k, v) in &req.headers {
                builder = builder.header(k.as_str(), v.as_str());
            }
            if let Some(b) = &req.body {
                builder = builder.body(b.clone());
            }

            let resp = builder.send().await.map_err(|e| HttpError::Transport(e.to_string()))?;
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let is_redirect = matches!(status, 301 | 302 | 303 | 307 | 308);
            if is_redirect && req.follow_redirects {
                let Some(loc) = location else {
                    let body = read_body(resp, self.max_body).await?;
                    return Ok(HttpResponse {
                        status,
                        headers,
                        body: body.0,
                        url: full,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                        redirects,
                        truncated: body.1,
                    });
                };
                if hop >= MAX_REDIRECTS {
                    return Err(HttpError::TooManyRedirects);
                }
                // 상대 경로 해석.
                let next = resolve_location(&full, &loc)?;
                // 다음 홉의 인가 검사는 루프 시작에서 수행한다 (fail-closed).
                redirects.push(next.clone());
                current = next;
                query.clear();
                hop += 1;
                continue;
            }

            let body = read_body(resp, self.max_body).await?;
            return Ok(HttpResponse {
                status,
                headers,
                body: body.0,
                url: full,
                elapsed_ms: started.elapsed().as_millis() as u64,
                redirects,
                truncated: body.1,
            });
        }
    }

    /// GET便捷 — 경로·쿼리만 넣고 보낸다.
    pub async fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
        self.send(&HttpRequest::get(url)).await
    }

    /// 요청 취소 플래그 — 장시간 스캔에서 중단하기 위해.
    pub fn cancel_flag(&self) -> Arc<tokio::sync::Notify> {
        Arc::new(tokio::sync::Notify::new())
    }
}

/// 쿼리를 붙인 URL.
pub fn build_url(base: &str, query: &[(String, String)]) -> String {
    if query.is_empty() {
        return base.to_string();
    }
    let mut out = base.to_string();
    for (k, v) in query {
        out = crate::storm::inject_query(&out, k, v);
    }
    out
}

/// Location 헤더를 절대 URL로 만든다.
pub fn resolve_location(base: &str, location: &str) -> Result<String, HttpError> {
    let b = url::Url::parse(base).map_err(|e| HttpError::InvalidUrl(e.to_string()))?;
    b.join(location)
        .map(|u| u.to_string())
        .map_err(|e| HttpError::InvalidUrl(e.to_string()))
}

/// 본문을 읽되 상한을 둔다 — (본문, 잘림 여부).
async fn read_body(resp: reqwest::Response, max: usize) -> Result<(String, bool), HttpError> {
    match resp.text().await {
        Ok(text) => {
            if text.len() <= max {
                Ok((text, false))
            } else {
                let mut cut = max;
                while cut > 0 && !text.is_char_boundary(cut) {
                    cut -= 1;
                }
                Ok((text[..cut].to_string(), true))
            }
        }
        Err(e) => Err(HttpError::Body(e.to_string())),
    }
}

/// 호스트만 뽑는다 (인가 검사용).
pub fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Arc<Authorization> {
        let a = Authorization::parse(
            "engagement:\n  authorized_until: \"2099-12-31\"\nscope:\n  allow:\n    - host: \"127.0.0.1\"\nports:\n  allow_tcp: [80, 8080]\n",
        )
        .unwrap();
        Arc::new(a)
    }

    #[test]
    fn scope_blocks_unauthorized_host() {
        let c = HttpClient::new(auth()).unwrap();
        let err = c.check_scope("http://example.com/").unwrap_err();
        assert!(matches!(err, ScopeError::NotAllowed(_)), "{err:?}");
    }

    #[test]
    fn scope_blocks_unauthorized_port() {
        let c = HttpClient::new(auth()).unwrap();
        let err = c.check_scope("http://127.0.0.1:22/").unwrap_err();
        assert!(matches!(err, ScopeError::PortDenied(_)), "{err:?}");
    }

    #[test]
    fn scope_allows_listed_target() {
        let c = HttpClient::new(auth()).unwrap();
        assert!(c.check_scope("http://127.0.0.1:8080/x").is_ok());
    }

    #[test]
    fn build_url_appends_query() {
        let out = build_url("http://h/p", &[("a".into(), "1".into()), ("b".into(), "2".into())]);
        assert!(out.contains("a=1"), "{out}");
        assert!(out.contains("b=2"), "{out}");
    }

    #[test]
    fn resolves_relative_location() {
        let out = resolve_location("http://h/a/b?q=1", "/c/d").unwrap();
        assert_eq!(out, "http://h/c/d");
        let out2 = resolve_location("http://h/a/b", "c").unwrap();
        assert_eq!(out2, "http://h/a/c");
    }
}
