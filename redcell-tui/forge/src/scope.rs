//! 인가(Authorization) 게이트 — fail-closed.
//!
//! redcell 의 `authorization.yaml` 규약과 같은 형태를 읽고, 모든 아웃바운드
//! 트래픽(스톰 엔진·파이썬 커널·LLM 도구)이 통과해야 하는 단일 관문이다.
//!
//! 규칙:
//!   - 인가 파일이 없으면 **차단** (fail-closed)
//!   - `deny` 는 `allow` 를 이긴다
//!   - `authorized_until` 이 지나면 차단, `authorized_from` 이 지나면 아직 시작 불가
//!   - `ports.allow_tcp` 가 있으면 그 포트만 허용
//!   - `limits.max_requests_per_second` 로 전역 RPS 상한을 건다

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::yaml::{self, Yaml};

/// 인가 대상 규칙.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// 정확히 일치하는 호스트 (IP 포함).
    Host(String),
    /// 와일드카드 도메인 (`*.vulnlab.local` → 하위 도메인 + 루트 도메인).
    Domain(String),
    /// CIDR 대역.
    Cidr(Cidr),
}

/// IPv4/IPv6 CIDR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (addr, bits) = spec
            .split_once('/')
            .ok_or_else(|| format!("CIDR 형식이 아닙니다: {spec}"))?;
        let net: IpAddr = addr
            .parse()
            .map_err(|_| format!("IP 주소를 해석할 수 없습니다: {addr}"))?;
        let bits: u8 = bits
            .parse()
            .map_err(|_| format!("CIDR 비트 수가 올바르지 않습니다: {bits}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(format!("CIDR 비트 수 {bits} 가 {max} 를 넘습니다: {spec}"));
        }
        Ok(Self { net, bits })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(x)) => {
                let mask = if self.bits == 0 { 0 } else { u32::MAX << (32 - self.bits) };
                (u32::from(n) & mask) == (u32::from(*x) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(x)) => {
                let mask = if self.bits == 0 {
                    0u128
                } else {
                    u128::MAX << (128 - self.bits)
                };
                (u128::from(n) & mask) == (u128::from(*x) & mask)
            }
            _ => false,
        }
    }
}

/// 인가 컨텍스트(루트 문서).
#[derive(Debug, Clone, Default)]
pub struct Engagement {
    pub name: String,
    pub authorized_by: String,
    pub contact: String,
    pub authorized_from: Option<String>,
    pub authorized_until: Option<String>,
    pub target_ref: Option<String>,
}

/// 대상 외에 보낼 인증 컨텍스트 (인가된 테스트 계정 전용).
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub cookie: Option<String>,
    pub bearer: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl Credentials {
    /// 모든 요청에 병합할 헤더 목록.
    pub fn merge_headers(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        if let Some(c) = &self.cookie {
            out.push(("Cookie".into(), c.clone()));
        }
        if let Some(b) = &self.bearer {
            out.push(("Authorization".into(), format!("Bearer {b}")));
        }
        for (k, v) in &self.headers {
            out.push((k.clone(), v.clone()));
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.cookie.is_none() && self.bearer.is_none() && self.headers.is_empty()
    }
}

/// 파싱된 인가 파일.
#[derive(Debug, Clone, Default)]
pub struct Authorization {
    pub engagement: Engagement,
    pub allow: Vec<Rule>,
    pub deny: Vec<Rule>,
    pub ports: Vec<u16>,
    pub max_rps: Option<f64>,
    pub disallow_destructive: bool,
    pub disallow_dos: bool,
    pub credentials: Credentials,
    pub optional_probes: Vec<String>,
    pub source: PathBuf,
}

/// 인가 거부 사유.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// 인가 파일이 없다/읽을 수 없다 → fail-closed.
    Missing(String),
    /// 인가 기간이 아니거나 만료.
    Expired(String),
    /// deny 규칙에 걸림.
    Denied(String),
    /// allow 목록에 없음.
    NotAllowed(String),
    /// 포트 제한.
    PortDenied(String),
    /// 파일 파싱 실패.
    Invalid(String),
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeError::Missing(m) => write!(f, "인가 파일이 없습니다 (fail-closed): {m}"),
            ScopeError::Expired(m) => write!(f, "인가 기간이 유효하지 않습니다: {m}"),
            ScopeError::Denied(m) => write!(f, "deny 규칙에 의해 차단: {m}"),
            ScopeError::NotAllowed(m) => write!(f, "인가 대상이 아닙니다: {m}"),
            ScopeError::PortDenied(m) => write!(f, "허용되지 않은 포트입니다: {m}"),
            ScopeError::Invalid(m) => write!(f, "인가 파일 오류: {m}"),
        }
    }
}

impl std::error::Error for ScopeError {}

impl Authorization {
    /// 인가 파일 로드. 실패하면 `ScopeError` — 호출자는 반드시 fail-closed 로 처리한다.
    pub fn load(path: &Path) -> Result<Self, ScopeError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ScopeError::Missing(format!("{} ({e})", path.display())))?;
        let mut auth = Authorization::parse(&text)
            .map_err(|e| ScopeError::Invalid(format!("{}: {e}", path.display())))?;
        auth.source = path.to_path_buf();
        Ok(auth)
    }

    /// 텍스트 파싱 (테스트·내장 인가용).
    pub fn parse(text: &str) -> Result<Self, String> {
        let doc = yaml::parse(text).map_err(|e| e.to_string())?;
        let mut auth = Authorization::default();

        if let Some(eng) = doc.get("engagement") {
            auth.engagement = Engagement {
                name: eng.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                authorized_by: eng.get("authorized_by").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                contact: eng.get("contact").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                authorized_from: eng.get("authorized_from").and_then(|v| v.as_str()).map(str::to_string),
                authorized_until: eng.get("authorized_until").and_then(|v| v.as_str()).map(str::to_string),
                target_ref: eng.get("target_ref").and_then(|v| v.as_str()).map(str::to_string),
            };
        }

        if let Some(scope) = doc.get("scope") {
            auth.allow = parse_rules(scope.get("allow"), "scope.allow")?;
            auth.deny = parse_rules(scope.get("deny"), "scope.deny")?;
        }
        if auth.allow.is_empty() {
            return Err("scope.allow 에 허용 대상이 하나도 없습니다 (fail-closed).".into());
        }

        if let Some(ports) = doc.get("ports").and_then(|p| p.get("allow_tcp")) {
            if let Some(items) = ports.as_seq() {
                for item in items {
                    if let Some(n) = item.as_f64() {
                        if (1.0..=65535.0).contains(&n) {
                            auth.ports.push(n as u16);
                        }
                    }
                }
            }
        }

        if let Some(limits) = doc.get("limits") {
            auth.max_rps = limits.get("max_requests_per_second").and_then(|v| v.as_f64());
            auth.disallow_destructive = limits.get("disallow_destructive").and_then(|v| v.as_bool()).unwrap_or(true);
            auth.disallow_dos = limits.get("disallow_dos").and_then(|v| v.as_bool()).unwrap_or(true);
        } else {
            auth.disallow_destructive = true;
            auth.disallow_dos = true;
        }

        if let Some(cred) = doc.get("credentials") {
            auth.credentials = Credentials {
                cookie: cred.get("cookie").and_then(|v| v.as_str()).map(str::to_string),
                bearer: cred.get("bearer").and_then(|v| v.as_str()).map(str::to_string),
                headers: cred.get("headers").map(|h| h.as_str_map().into_iter().collect()).unwrap_or_default(),
            };
        }

        if let Some(probes) = doc.get("optional_probes") {
            if let Some(items) = probes.as_seq() {
                for item in items {
                    if let Some(s) = item.as_str() {
                        auth.optional_probes.push(s.to_string());
                    }
                }
            }
        }

        Ok(auth)
    }

    /// 호스트가 인가 대상인지 판정 (포트 무관).
    pub fn host_allowed(&self, host: &str) -> Result<(), ScopeError> {
        self.check_period()?;
        let h = host.trim().trim_matches('.').to_ascii_lowercase();
        if h.is_empty() {
            return Err(ScopeError::NotAllowed("호스트가 비어 있습니다.".into()));
        }
        // deny 우선.
        for rule in &self.deny {
            if rule_matches(rule, &h) {
                return Err(ScopeError::Denied(format!("{h} 가 deny 규칙에 포함됩니다.")));
            }
        }
        for rule in &self.allow {
            if rule_matches(rule, &h) {
                return Ok(());
            }
        }
        Err(ScopeError::NotAllowed(format!("{h} 가 인가 목록({})에 없습니다.", self.source.display())))
    }

    /// 호스트 + 포트 인가 판정.
    pub fn check(&self, host: &str, port: Option<u16>) -> Result<(), ScopeError> {
        self.host_allowed(host)?;
        if let Some(p) = port {
            if !self.ports.is_empty() && !self.ports.contains(&p) {
                return Err(ScopeError::PortDenied(format!(
                    "포트 {p} 는 허용 목록({:?})에 없습니다.",
                    self.ports
                )));
            }
        }
        Ok(())
    }

    /// 인가 유효기간 확인.
    pub fn check_period(&self) -> Result<(), ScopeError> {
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        if let Some(from) = &self.engagement.authorized_from {
            if today.as_str() < from.as_str() {
                return Err(ScopeError::Expired(format!("인가 시작일({from}) 전입니다.")));
            }
        }
        if let Some(until) = &self.engagement.authorized_until {
            if today.as_str() > until.as_str() {
                return Err(ScopeError::Expired(format!("인가 만료일({until})이 지났습니다.")));
            }
        }
        Ok(())
    }

    /// RPS 상한 — 없으면 제한 없음(None).
    pub fn rps_limit(&self) -> Option<f64> {
        self.max_rps.filter(|v| *v > 0.0)
    }

    /// 자격증명을 이 호스트에 붙여도 되는지 — 점검 대상 호스트에만 붙인다.
    ///
    /// 인가 대상이 여러 호스트이고 그 중 하나가 남의 서버일 수 있으므로,
    /// 자격증명은 **점검 대상 호스트에만** 붙인다.
    pub fn applies_to_host(&self, host: &str) -> bool {
        let h = host.trim().trim_matches('.').to_ascii_lowercase();
        if h.is_empty() {
            return false;
        }
        // target_ref 에 호스트가 지정되어 있으면 그 호스트(및 그 서브도메인) 에만 붙인다.
        if let Some(reference) = &self.engagement.target_ref {
            let ref_host = reference
                .trim()
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .trim_matches('.')
                .to_ascii_lowercase();
            if !ref_host.is_empty() {
                return h == ref_host || h.ends_with(&format!(".{ref_host}"));
            }
        }
        true
    }

    /// 자격증명을 이 호스트에 붙여도 되는지 — 점검 대상 호스트에만 붙인다.
    pub fn credentials_for(&self, host: &str) -> Vec<(String, String)> {
        if self.applies_to_host(host) {
            self.credentials.merge_headers()
        } else {
            Vec::new()
        }
    }

    /// **실제 적용할** RPS 상한 — 인가 파일에 값이 없으면 보수적 기본값을 쓴다.
    ///
    /// 무제한은 "실수로 대상을 잠재우는" 가장 위험한 상태이므로 기본값을 둔다.
    /// CLI 플래그로 이 값을 *올릴* 수는 없다(더 낮출 수만 있다).
    pub fn effective_rps(&self) -> f64 {
        self.rps_limit().unwrap_or(DEFAULT_MAX_RPS)
    }

    /// 선택적 프로브 허용 여부.
    ///
    /// - `optional_probes` 가 비어 있으면(명시되지 않음) → 기본 프로브만 허용
    /// - 목록이 있으면 → 목록에 있는 것만 허용 (`*`/`all` 이면 전부 허용)
    ///
    /// 파괴적·외부 의존 프로브(oob, osint 등)는 목록이 **반드시** 있어야 한다.
    pub fn probe_allowed(&self, name: &str) -> bool {
        if self.optional_probes.is_empty() {
            return !DESTRUCTIVE_PROBES.contains(&name);
        }
        self.optional_probes.iter().any(|p| {
            let p = p.trim().to_ascii_lowercase();
            p == "*" || p == "all" || p == name.to_ascii_lowercase()
        })
    }

    /// 인가 파일에 명시적으로 적어야만 허용되는 프로브인가.
    pub fn requires_explicit_optin(&self, name: &str) -> bool {
        DESTRUCTIVE_PROBES.contains(&name)
            && !self.optional_probes.iter().any(|p| {
                let p = p.trim().to_ascii_lowercase();
                p == "*" || p == "all" || p == name.to_ascii_lowercase()
            })
    }
}

/// 인가 파일에 미지정 시 적용되는 보수적 RPS 기본값.
pub const DEFAULT_MAX_RPS: f64 = 50.0;

/// 명시적 opt-in 이 필요한 프로브 (파괴적 · 외부 전송 · 로컬 시스템 접근).
pub const DESTRUCTIVE_PROBES: &[&str] = &["oob", "osint", "local", "hostinfo", "exploit", "dos"];

fn parse_rules(node: Option<&Yaml>, label: &str) -> Result<Vec<Rule>, String> {
    let mut out = Vec::new();
    let Some(node) = node else { return Ok(out) };
    let items = node.as_seq().ok_or_else(|| format!("{label} 는 목록이어야 합니다."))?;
    for item in items {
        let map = match item {
            Yaml::Map(entries) => entries,
            Yaml::Str(s) => {
                // 축약형: `- "example.com"` → host 규칙.
                out.push(Rule::Host(s.trim().to_ascii_lowercase()));
                continue;
            }
            _ => return Err(format!("{label} 항목 형식이 올바르지 않습니다.")),
        };
        for (k, v) in map {
            let Some(val) = v.as_str() else { continue };
            let val = val.trim();
            match k.as_str() {
                "host" | "ip" => out.push(Rule::Host(val.to_ascii_lowercase())),
                "domain" => {
                    let d = val.trim_start_matches("*.").to_ascii_lowercase();
                    out.push(Rule::Domain(d));
                }
                "cidr" => out.push(Rule::Cidr(Cidr::parse(val)?)),
                _ => {}
            }
        }
    }
    Ok(out)
}

fn rule_matches(rule: &Rule, host: &str) -> bool {
    match rule {
        Rule::Host(h) => h == host,
        Rule::Domain(d) => host == d || host.ends_with(&format!(".{d}")),
        Rule::Cidr(c) => match normalize_ip(host) {
            Some(ip) => c.contains(&ip),
            None => false,
        },
    }
}

/// IP 문자열 정규화 — IPv4-mapped IPv6(`::ffff:1.2.3.4`) 를 IPv4 로 펼친다.
///
/// Cidr 규칙이 IPv4 대역일 때 `::ffff:10.0.0.1` 로 우회되는 것을 막는다.
pub fn normalize_ip(host: &str) -> Option<IpAddr> {
    let ip: IpAddr = host.parse().ok()?;
    Some(match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    })
}

/// 전역 RPS 제한기 — 토큰 버킷.
pub struct RateLimiter {
    rps: f64,
    inner: parking_lot::Mutex<Bucket>,
}

struct Bucket {
    tokens: f64,
    last: std::time::Instant,
}

impl RateLimiter {
    /// rps 제한 없는 리미터.
    pub fn unlimited() -> Self {
        Self { rps: f64::INFINITY, inner: parking_lot::Mutex::new(Bucket { tokens: f64::INFINITY, last: std::time::Instant::now() }) }
    }

    pub fn new(rps: f64) -> Self {
        let rps = if rps.is_finite() && rps > 0.0 { rps } else { f64::INFINITY };
        Self { rps, inner: parking_lot::Mutex::new(Bucket { tokens: rps.min(5.0), last: std::time::Instant::now() }) }
    }

    pub fn rps(&self) -> f64 {
        self.rps
    }

    /// 토큰 1개를 얻을 때까지 대기 (비동기 아님 — 호출측이 tokio::task::yield_now 로 양보).
    pub fn acquire(&self) {
        if !self.rps.is_finite() {
            return;
        }
        loop {
            let wait = {
                let mut b = self.inner.lock();
                let now = std::time::Instant::now();
                let elapsed = now.duration_since(b.last).as_secs_f64();
                b.tokens = (b.tokens + elapsed * self.rps).min(self.rps.max(1.0));
                b.last = now;
                if b.tokens >= 1.0 {
                    b.tokens -= 1.0;
                    None
                } else {
                    Some(std::time::Duration::from_secs_f64((1.0 - b.tokens) / self.rps))
                }
            };
            match wait {
                None => return,
                Some(d) => std::thread::sleep(d.min(std::time::Duration::from_millis(250))),
            }
        }
    }
}

/// 인가 파일 후보 경로 — `REDCELL_HOME` 우선, 없으면 `~/.redcell`.
pub fn authorization_candidates() -> Vec<PathBuf> {
    let home = std::env::var_os("REDCELL_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".redcell")
        });
    vec![home.join("authorization.yaml"), home.join("authorization.yml")]
}

/// 첫 번째 존재하는 인가 파일.
pub fn find_authorization() -> Option<PathBuf> {
    authorization_candidates().into_iter().find(|p| p.is_file())
}

/// 네트워크 대상에서 host/port 추출.
///
/// **포트는 항상 실제 연결 포트**를 돌려준다 — `http://host/` 는 80, `https://host/` 는 443.
/// (이전에는 `None` 이 돌아와 `ports.allow_tcp` 검사가 통째로 건너뛰어졌다.)
pub fn split_authority(url: &str) -> Result<(String, Option<u16>, String), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("URL 파싱 실패 ({url}): {e}"))?;
    let host = parsed.host_str().ok_or("URL 에 호스트가 없습니다.")?.to_string();
    let scheme = parsed.scheme().to_string();
    let port = parsed
        .port()
        .or_else(|| match scheme.as_str() {
            "https" | "wss" => Some(443),
            "http" | "ws" => Some(80),
            _ => None,
        });
    Ok((host, port, scheme))
}

/// `http://host:port/path` 정규화 — 경로가 없으면 `/`.
pub fn normalize_base(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            if u.path().is_empty() {
                u.set_path("/");
            }
            u.to_string()
        }
        Err(_) => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
engagement:
  name: "unit"
  authorized_until: "2099-12-31"
scope:
  allow:
    - host: "127.0.0.1"
    - domain: "*.vulnlab.local"
    - cidr: "10.13.37.0/24"
  deny:
    - host: "10.13.37.1"
ports:
  allow_tcp: [80, 443, 8080]
limits:
  max_requests_per_second: 20
"#;

    #[test]
    fn allows_listed_targets() {
        let a = Authorization::parse(SAMPLE).unwrap();
        assert!(a.host_allowed("127.0.0.1").is_ok());
        assert!(a.host_allowed("app.vulnlab.local").is_ok());
        assert!(a.host_allowed("vulnlab.local").is_ok());
        assert!(a.host_allowed("10.13.37.9").is_ok());
        assert!(matches!(a.host_allowed("evil.com"), Err(ScopeError::NotAllowed(_))));
    }

    #[test]
    fn deny_beats_allow() {
        let a = Authorization::parse(SAMPLE).unwrap();
        assert!(matches!(a.host_allowed("10.13.37.1"), Err(ScopeError::Denied(_))));
    }

    #[test]
    fn port_and_rps_limits() {
        let a = Authorization::parse(SAMPLE).unwrap();
        assert!(a.check("127.0.0.1", Some(8080)).is_ok());
        assert!(matches!(a.check("127.0.0.1", Some(22)), Err(ScopeError::PortDenied(_))));
        assert_eq!(a.rps_limit(), Some(20.0));
    }

    #[test]
    fn fail_closed_without_allow() {
        assert!(Authorization::parse("scope:\n  deny:\n    - host: \"x\"\n").is_err());
    }

    #[test]
    fn expired_period_blocks() {
        let a = Authorization::parse(
            "engagement:\n  authorized_until: \"2001-01-01\"\nscope:\n  allow:\n    - host: \"127.0.0.1\"\n",
        )
        .unwrap();
        assert!(matches!(a.host_allowed("127.0.0.1"), Err(ScopeError::Expired(_))));
    }

    #[test]
    fn rate_limiter_limits_rate() {
        let rl = RateLimiter::new(50.0);
        let start = std::time::Instant::now();
        for _ in 0..40 {
            rl.acquire();
        }
        let elapsed = start.elapsed().as_millis();
        assert!(elapsed >= 500, "RPS 제한이 적용되지 않음: {elapsed}ms");
    }

    #[test]
    fn cidr_math() {
        let c = Cidr::parse("10.13.37.0/24").unwrap();
        assert!(c.contains(&"10.13.37.255".parse().unwrap()));
        assert!(!c.contains(&"10.13.38.1".parse().unwrap()));
    }

    #[test]
    fn effective_rps_has_conservative_default() {
        let a = Authorization::parse(SAMPLE).unwrap();
        assert_eq!(a.effective_rps(), 20.0);
        let b = Authorization::parse("scope:\n  allow:\n    - host: \"127.0.0.1\"\n").unwrap();
        assert!(b.effective_rps() > 0.0, "RPS 기본값이 있어야 한다");
        assert!(b.effective_rps() <= 100.0, "기본값이 너무 크면 안 된다: {}", b.effective_rps());
    }

    #[test]
    fn probe_opt_in_is_respected() {
        // 목록이 없으면 기본(비파괴) 프로브만 허용한다.
        let a = Authorization::parse(SAMPLE).unwrap();
        assert!(a.probe_allowed("idor"));
        assert!(!a.probe_allowed("oob"));
        // 목록이 있으면 그 항목만 허용한다.
        let b = Authorization::parse(
            "scope:\n  allow:\n    - host: \"127.0.0.1\"\noptional_probes:\n  - idor\n",
        )
        .unwrap();
        assert!(b.probe_allowed("idor"));
        assert!(!b.probe_allowed("tamper"));
        assert!(!b.probe_allowed("oob"));
        // '*' 이면 전부 허용.
        let c = Authorization::parse(
            "scope:\n  allow:\n    - host: \"127.0.0.1\"\noptional_probes:\n  - '*'\n",
        )
        .unwrap();
        assert!(c.probe_allowed("oob"));
    }

    #[test]
    fn default_port_is_effective() {
        let (h, p, s) = split_authority("http://example.com/").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, Some(80));
        assert_eq!(s, "http");
        let (_, p2, _) = split_authority("https://example.com/").unwrap();
        assert_eq!(p2, Some(443));
        let (_, p3, _) = split_authority("http://example.com:8099/x").unwrap();
        assert_eq!(p3, Some(8099));
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_ipv4_cidr() {
        let a = Authorization::parse(SAMPLE).unwrap();
        // ::ffff:10.13.37.9 는 10.13.37.9 와 동일하게 취급된다.
        assert!(a.host_allowed("::ffff:10.13.37.9").is_ok());
    }

    #[test]
    fn credentials_bound_to_engagement_target() {
        let a = Authorization::parse(
            "engagement:\n  target_ref: \"https://app.example.com\"\nscope:\n  allow:\n    - domain: \"example.com\"\n    - host: \"other.test\"\n",
        )
        .unwrap();
        assert!(a.applies_to_host("app.example.com"));
        // target_ref 의 하위 도메인만 허용 — 다른 호스트로는 자격증명이 새지 않는다.
        assert!(a.applies_to_host("api.app.example.com"));
        assert!(!a.applies_to_host("api.example.com"));
        assert!(!a.applies_to_host("other.test"));
    }
}
