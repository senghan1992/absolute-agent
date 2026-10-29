// auth.rs — 간단 IP 목록 인가(authorization.list) 관리.
//
// redcell 엔진의 `src/scope/ip-list.ts` 와 동일한 파일 형식/검증 규칙을 따른다:
//   - 한 줄에 하나: IP / CIDR / 도메인  ·  ! 접두사 = 제외(deny, allow 를 이김)  ·  # 주석
//   - 지시자: until: YYYY-MM-DD  ·  ports: 80,443,8080
// 이 모듈은 데스크톱 UI 의 "인가 대상 관리" 패널 전용이다(표시 + 추가 + 제거).
// 실제 스캔 게이트는 항상 redcell 엔진(ScopeGuard)이 수행하므로, 여기서의 내용이
// 어긋나도 실행 시점에 엔진 쪽 검증이 fail-closed 로 다시 확인한다.

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

#[derive(Serialize, Clone, Default)]
pub struct AuthList {
    pub path: String,
    pub allows: Vec<String>,
    pub denies: Vec<String>,
    /// 정식 YAML 인가 파일이면 true(IP 목록 편집 불가).
    pub yaml: bool,
    pub until: Option<String>,
    pub ports: Option<Vec<u16>>,
    /// 파일이 없거나 비어 있음.
    pub empty: bool,
    pub error: Option<String>,
    pub warn: Option<String>,
    /// 기본 IP 목록 경로(안내용).
    pub default_path: String,
}

const HEADER: &str = "# RedCell 인가 목록 — 아래에 적힌 대상만 인가됩니다.\n# 한 줄에 하나: IP / CIDR / 도메인  ·  ! 접두사 = 제외(allow 를 이김)  ·  # 주석\n# 선택 지시자:  until: YYYY-MM-DD  ·  ports: 80,443,8080\n";

/// CLI 와 동일한 기본 redcell 홈: $REDCELL_HOME (기본 ~/.redcell).
pub fn home_dir() -> PathBuf {
    std::env::var("REDCELL_HOME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(PathBuf::from)
                .or_else(|| std::env::var("USERPROFILE").ok().map(PathBuf::from))
                .map(|h| h.join(".redcell"))
        })
        .unwrap_or_else(|| PathBuf::from("."))
}

/// CLI 와 동일한 기본 경로: $REDCELL_HOME/authorization.list (기본 ~/.redcell/authorization.list)
pub fn default_list_path() -> PathBuf {
    home_dir().join("authorization.list")
}

/// 인가 기한 만료 — until(YYYY-MM-DD)이 오늘보다 이전이면 참.
/// 파싱 실패(loader 검증 통과 후 도달 불가)는 미지정 취급.
pub fn is_expired(auth: &AuthList) -> bool {
    match auth.until.as_deref() {
        Some(d) if d.len() == 10 => {
            let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
            today.as_str() > d
        }
        _ => false,
    }
}

/// 호스트 인가 판정 — prime-agent 반응형 게이트용 (데스크톱 내장 매처).
/// 규칙: 기한 만료 → 차단 / deny 우선 → allow(정확·`*.` 와일드카드·IPv4/IPv6 CIDR) → 그 외 차단.
/// 빈 allows 는 전부 차단(fail-closed). 대소문자 무시.
/// 포트 검사는 `is_host_port_allowed` 가 담당한다 (호출자가 포트 맥락을 함께 넘긴다).
pub fn is_host_allowed(auth: &AuthList, host: &str) -> bool {
    if is_expired(auth) {
        return false;
    }
    let h = host.trim().trim_end_matches('.').to_lowercase();
    if h.is_empty() {
        return false;
    }
    if auth.denies.iter().any(|d| target_matches(d, &h)) {
        return false;
    }
    auth.allows.iter().any(|a| target_matches(a, &h))
}

/// 호스트+포트 인가 판정 — `ports:` 지시자 집행점.
/// 지시자 없음 → 호스트 게이트만. 포트 맥락 없음(None) → 호스트 게이트만
/// 적용한다: 추출 단계가 명시 포트·스킴 기본값·port 키를 채우므로, None 은
/// "알 수 없음"이지 우회가 아니다. 베어 호스트 언급까지 차단하면 정상 정찰이
/// 죽으므로 허용하되, 이 한계는 스킬 지침(전체 URL 사용 강제)으로 좁힌다.
pub fn is_host_port_allowed(auth: &AuthList, host: &str, port: Option<u16>) -> bool {
    if !is_host_allowed(auth, host) {
        return false;
    }
    match (&auth.ports, port) {
        (None, _) => true,
        (_, None) => true,
        (Some(list), Some(p)) => list.contains(&p),
    }
}

fn target_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().trim_start_matches('!').to_lowercase();
    if p.is_empty() {
        return false;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        // 와일드카드는 하위 도메인만 (베어 도메인 제외).
        return host.len() > suffix.len() + 1
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
    }
    if let Some((net, bits)) = p.split_once('/') {
        if let Ok(b) = bits.parse::<u32>() {
            if let (Ok(ip), Ok(addr)) = (net.parse::<Ipv4Addr>(), host.parse::<Ipv4Addr>()) {
                if b <= 32 {
                    let mask = if b == 0 { 0u32 } else { u32::MAX << (32 - b) };
                    return (u32::from(ip) & mask) == (u32::from(addr) & mask);
                }
            }
            if let (Ok(ip), Ok(addr)) = (net.parse::<Ipv6Addr>(), host.parse::<Ipv6Addr>()) {
                if b <= 128 {
                    let mask = if b == 0 { 0u128 } else { u128::MAX << (128 - b) };
                    return (u128::from(ip) & mask) == (u128::from(addr) & mask);
                }
            }
        }
        return false;
    }
    p == host
}

/// 대상 문자열 검증 — ip-list.ts 의 classifyTarget 과 동일 규칙.
pub fn validate_target(value: &str) -> Result<(), String> {
    let v = value.trim();
    if v.is_empty() {
        return Err("빈 대상입니다.".into());
    }
    if v.contains('/') {
        let (ip, bits) = v.split_once('/').unwrap();
        let b: u32 = bits
            .trim()
            .parse()
            .map_err(|_| format!("잘못된 CIDR: '{v}' — IP/CIDR 형식(예: 10.0.0.0/24, 2001:db8::/32)이어야 합니다."))?;
        if ip.parse::<Ipv4Addr>().is_ok() && b <= 32 {
            return Ok(());
        }
        if ip.parse::<Ipv6Addr>().is_ok() && b <= 128 {
            return Ok(());
        }
        return Err(format!("잘못된 CIDR: '{v}' — IP/CIDR 형식(예: 10.0.0.0/24, 2001:db8::/32)이어야 합니다."));
    }
    if v.parse::<IpAddr>().is_ok() {
        return Ok(()); // IPv4 / IPv6
    }
    // 숫자+점만으로 된 문자열이 IP 검증을 통과 못 했다면 호스트명으로 오인하지 않는다.
    if !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(format!("잘못된 IP: '{v}'"));
    }
    let (name, wildcard) = match v.strip_prefix("*.") {
        Some(rest) => (rest, true),
        None => (v, false),
    };
    if wildcard && is_hostname(name) {
        return Ok(());
    }
    if !wildcard && is_hostname(v) {
        return Ok(());
    }
    Err(format!(
        "인식할 수 없는 대상: '{v}' — IP, CIDR(10.0.0.0/24), 또는 도메인(*.example.com)만 허용합니다."
    ))
}

/// 호스트명 규칙: 라벨은 영숫자로 시작·끝, 중간은 영숫자/하이픈, 점으로 구분.
fn is_hostname(v: &str) -> bool {
    if v.is_empty() {
        return false;
    }
    for label in v.split('.') {
        if label.is_empty() {
            return false;
        }
        let b = label.as_bytes();
        if !b[0].is_ascii_alphanumeric() || !b[b.len() - 1].is_ascii_alphanumeric() {
            return false;
        }
        if !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-') {
            return false;
        }
    }
    true
}

/// 정식 YAML 인가 파일인가? (첫 비주석 줄이 engagement:/scope: 로 시작하면 YAML)
pub fn is_yaml_file(text: &str) -> bool {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .next()
        .map(|l| l.starts_with("engagement:") || l.starts_with("scope:"))
        .unwrap_or(false)
}

/// 파일 내용 파싱 (syntax 오류는 Err, 허용 0건은 warn 처리 — UI 표시용으로 관대).
fn parse_list(text: &str) -> Result<(Vec<(bool, String)>, Option<String>, Option<Vec<u16>>, usize), String> {
    let mut entries: Vec<(bool, String)> = Vec::new();
    let mut until: Option<String> = None;
    let mut ports: Option<Vec<u16>> = None;
    let mut allow_count = 0usize;

    for (idx, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("until:") {
            let d = rest.trim();
            let bytes = d.as_bytes();
            let ok = bytes.len() == 10 && bytes[4] == b'-' && bytes[7] == b'-'
                && bytes[..4].iter().all(|c| c.is_ascii_digit())
                && bytes[5..7].iter().all(|c| c.is_ascii_digit())
                && bytes[8..10].iter().all(|c| c.is_ascii_digit());
            if !ok {
                return Err(format!("잘못된 until 날짜: '{d}' (YYYY-MM-DD 형식)."));
            }
            until = Some(d.to_string());
            continue;
        }
        if let Some(rest) = lower.strip_prefix("ports:") {
            let nums: Vec<u16> = rest
                .split(',')
                .map(|s| s.trim().parse::<u16>())
                .collect::<Result<_, _>>()
                .map_err(|_| format!("잘못된 ports 지시자: '{line}' — 숫자 포트 목록(예: ports: 80,443,8080)."))?;
            if nums.is_empty() || nums.iter().any(|n| *n == 0) {
                return Err(format!("잘못된 ports 지시자: '{line}' — 숫자 포트 목록(예: ports: 80,443,8080)."));
            }
            ports = Some(nums);
            continue;
        }

        let mut deny = false;
        let mut v = line;
        if let Some(rest) = v.strip_prefix('!') {
            deny = true;
            v = rest.trim();
        }
        validate_target(v).map_err(|e| format!("{e} ({}번째 줄)", idx + 1))?;
        if !deny {
            allow_count += 1;
        }
        entries.push((deny, v.to_string()));
    }
    Ok((entries, until, ports, allow_count))
}

/// 파일 로드 → UI 표시용 구조체.
pub fn load(path: &PathBuf) -> AuthList {
    let mut out = AuthList {
        path: path.to_string_lossy().to_string(),
        default_path: default_list_path().to_string_lossy().to_string(),
        ..Default::default()
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        out.empty = true;
        return out;
    };
    let text = text.trim();
    if text.is_empty() {
        out.empty = true;
        return out;
    }
    if is_yaml_file(text) {
        out.yaml = true;
        out.error = Some(
            "이 경로는 정식 YAML 인가 파일입니다. IP 목록(add/제거)은 이 파일을 편집하지 않습니다.\n\
             ⚙ 설정에서 auth 경로를 비우면 기본 IP 목록으로 전환됩니다."
                .into(),
        );
        return out;
    }
    match parse_list(text) {
        Ok((entries, until, ports, allow_count)) => {
            for (deny, raw) in entries {
                if deny {
                    out.denies.push(raw);
                } else {
                    out.allows.push(raw);
                }
            }
            out.until = until;
            out.ports = ports;
            if is_expired(&out) {
                out.warn = Some(format!(
                    "인가 기한(until {})이 지났습니다 — 모든 대상이 차단됩니다. 기한을 갱신하세요.",
                    out.until.as_deref().unwrap_or("")
                ));
            } else if allow_count == 0 {
                out.warn = Some("허용 대상이 하나도 없습니다. 아래에서 IP를 추가하세요.".into());
            }
        }
        Err(e) => out.error = Some(e),
    }
    out
}

fn yaml_guard(path: &PathBuf) -> Result<(), String> {
    if let Ok(text) = std::fs::read_to_string(path) {
        if is_yaml_file(&text) {
            return Err("정식 YAML 인가 파일입니다. IP 목록 편집을 위해 ⚙ 설정에서 auth 경로를 비우거나 authorization.list 를 지정하세요.".into());
        }
    }
    Ok(())
}

/// 대상 추가 (중복은 무시). 파일이 없으면 헤더와 함께 생성.
pub fn add(path: &PathBuf, target: &str, deny: bool) -> Result<(), String> {
    validate_target(target)?;
    if target.starts_with('!') {
        return Err("add 에는 ! 접두사를 쓰지 마세요. 제외는 별도 토글로 지정됩니다.".into());
    }
    yaml_guard(path)?;

    let line = if deny { format!("!{target}") } else { target.to_string() };
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let has = existing.lines().any(|l| l.trim() == line || l.trim() == target);
    if has {
        return Ok(()); // 이미 있음
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("목록 디렉터리를 만들 수 없습니다: {e}"))?;
        }
    }
    let mut out = String::new();
    if existing.trim().is_empty() {
        out.push_str(HEADER);
    } else {
        out.push_str(&existing);
        if !existing.ends_with('\n') {
            out.push('\n');
        }
    }
    out.push_str(&line);
    out.push('\n');
    std::fs::write(path, out).map_err(|e| format!("목록을 기록할 수 없습니다: {e}"))
}

/// 대상 제거 (allow/deny 모두, ! 접두사 무관).
pub fn remove(path: &PathBuf, target: &str) -> Result<(), String> {
    yaml_guard(path)?;
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let kept: Vec<&str> = existing
        .lines()
        .filter(|l| {
            let t = l.trim();
            t != target.trim() && t != &format!("!{}", target.trim())
        })
        .collect();
    if kept.len() == existing.lines().count() {
        return Ok(()); // 제거할 항목 없음
    }
    std::fs::write(path, kept.join("\n")).map_err(|e| format!("목록을 기록할 수 없습니다: {e}"))
}

/// 사용자 입력(host 란)을 인가 대상으로 정규화한다.
///   "http://10.0.0.5:8080/path" → "10.0.0.5"
///   "https://demo.vulnlab.local" → "demo.vulnlab.local"
///   "10.13.37.5:8080" → "10.13.37.5"
///   "[::1]:8080" → "::1"
/// 스킴이 없는 순수 IP/도메인/호스트명은 그대로.
pub fn normalize_host(host: &str) -> String {
    let h = host.trim();
    if h.is_empty() {
        return h.into();
    }
    // URL 형식: 스킴 제거 → 권한 정보(authority)만 추출 → 경로/쿼리/포트 제거
    if let Some(rest) = h.split_once("://") {
        let cut = rest
            .1
            .find(['/', '?', '#'])
            .unwrap_or(rest.1.len());
        let authority = &rest.1[..cut];
        if let Some(inner) = authority.strip_prefix('[') {
            // IPv6: [::1]:8080 형태
            if let Some(end) = inner.find(']') {
                return inner[..end].to_string();
            }
        }
        if let Some((h2, _p)) = authority.rsplit_once(':') {
            return h2.to_string();
        }
        return authority.to_string();
    }
    // "host:port" 형태(스킴 없이) — 포트가 숫자이고 IPv6(: 포함)가 아닐 때만 분리
    if let Some((h2, p)) = h.rsplit_once(':') {
        if !h2.contains(':') && !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            return h2.to_string();
        }
    }
    h.into()
}

/// 실행 전 자동 인가: host 입력을 정규화해 허용 목록에 추가한다(중복 시 무시).
/// 파일이 정식 YAML 이면 Err 대신 Ok(false, yaml=true) 로 알리기 위해 caller 가
/// load() 로 먼저 확인하고, 여기는 순수 "추가"만 담당한다.
pub fn ensure_allowed(path: &PathBuf, host: &str) -> Result<(bool, String), String> {
    let target = normalize_host(host);
    if target.is_empty() {
        return Err("대상(host)이 비어 있습니다.".into());
    }
    validate_target(&target)?;
    add(path, &target, false)?; // 중복은 내부에서 무시
    Ok((true, target))
}

/// 호스트 DNS 해석 — 중복 제거된 IP 문자열 목록. 실패 시 빈 목록.
pub fn resolve_ips(host: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let mut seen: Vec<String> = Vec::new();
    if host.is_empty() {
        return seen;
    }
    let Ok(addrs) = (host, 80u16).to_socket_addrs() else {
        return seen;
    };
    for a in addrs {
        let ip = a.ip().to_string();
        if !seen.contains(&ip) {
            seen.push(ip);
        }
    }
    seen
}

/// DNS 드리프트(TOCTOU) 판정 — 지금 해석된 IP 중 인가 목록에 없는 것만 반환.
/// 이름 자체가 인가된 상태에서 새 IP 가 나오면 리바인딩 의심.
/// IP 리터럴 입력·해석 실패(빈 목록)는 빈 결과 (판정 불가 — 조용히 통과).
pub fn dns_drifted(host: &str, allows: &[String], resolved: &[String]) -> Vec<String> {
    use std::net::IpAddr;
    if host.trim().is_empty() || resolved.is_empty() {
        return Vec::new();
    }
    if host.trim().parse::<IpAddr>().is_ok() {
        return Vec::new(); // 리터럴은 리바인딩 불가
    }
    let h = host.trim().to_lowercase();
    let name_allowed = allows.iter().any(|a| {
        let t = a.trim().trim_start_matches('!').to_lowercase();
        t == h || (t.strip_prefix("*.").map(|suf| h.len() > suf.len() + 1 && h.ends_with(suf)).unwrap_or(false))
    });
    if !name_allowed {
        return Vec::new(); // 이름 자체가 인가 안 됐으면 게이트가 별도 차단
    }
    resolved.iter().filter(|ip| !allows.iter().any(|a| a.trim() == ip.as_str())).cloned().collect()
}

/// host 를 DNS 로 해석해 나온 IP 를 인가 목록에 추가한다(중복 제외).
/// 반환: (새로 추가한 IP, 이미 목록에 있던 IP).
///
/// 왜 필요한가: 엔진 ScopeGuard 는 연결시점에 "해석된 IP" 를 다시 검증한다. 사내망
/// 호스트(예: axhack.lge.com → 10.x.x.x)는 이름만 인가돼 있으면 사설 대역 측면이동
/// 방지 기본값에 막혀 "가 인가 IP 로 해석되지 않습니다" 가 난다. "URL 입력 = 그 대상
/// 인가" 계약에 따라 이름이 가리키는 실제 IP 도 함께 허용해 실행이 막히지 않게 한다.
/// 해석 실패(오프라인 등)면 조용히 빈 결과를 돌린다 — 엔진이 실행 시점에 재검증한다.
pub fn resolve_and_allow(path: &PathBuf, host: &str, current_allows: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut added, mut known) = (Vec::new(), Vec::new());
    if host.is_empty() {
        return (added, known);
    }
    for ip in resolve_ips(host) {
        if current_allows.iter().any(|x| x == &ip) {
            known.push(ip);
        } else if add(path, &ip, false).is_ok() {
            added.push(ip);
        }
    }
    (added, known)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_file(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rc-auth-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("authorization.list")
    }

    #[test]
    fn validate_accepts_valid_targets() {
        validate_target("127.0.0.1").unwrap();
        validate_target("10.0.0.0/24").unwrap();
        validate_target("0.0.0.0/0").unwrap();
        validate_target("2001:db8::1").unwrap();
        validate_target("*.lab.local").unwrap();
        validate_target("localhost").unwrap();
        validate_target("example.com").unwrap();
    }

    #[test]
    fn validate_rejects_bad_targets() {
        assert!(validate_target("").is_err());
        assert!(validate_target("999.1.1.1").is_err()); // IP 유사(숫자+점)지만 잘못됨
        assert!(validate_target("256.1.1.1").is_err());
        assert!(validate_target("10.0.0.0/99").is_err()); // CIDR 비트 오버
        assert!(validate_target("10.0.0.0/abc").is_err());
        assert!(validate_target("not an ip!").is_err());
        assert!(validate_target("*.bad..local").is_err());
        assert!(validate_target("-bad.com").is_err());
    }

    #[test]
    fn parse_list_handles_comments_deny_directives() {
        let text = "# 주석\n127.0.0.1\n10.13.37.0/24\n!10.13.37.1\nuntil: 2027-12-31\nports: 80,443,8080\n";
        let (entries, until, ports, allow_count) = parse_list(text).unwrap();
        assert_eq!(entries, vec![(false, "127.0.0.1".into()), (false, "10.13.37.0/24".into()), (true, "10.13.37.1".into())]);
        assert_eq!(until.as_deref(), Some("2027-12-31"));
        assert_eq!(ports, Some(vec![80, 443, 8080]));
        assert_eq!(allow_count, 2);
    }

    #[test]
    fn parse_list_rejects_bad_syntax() {
        assert!(parse_list("999.1.1.1\n").is_err());
        assert!(parse_list("until: someday\n1.2.3.4\n").is_err());
        assert!(parse_list("ports: abc\n1.2.3.4\n").is_err());
        assert!(parse_list("1.2.3.4\nnot valid!!\n").is_err());
    }

    #[test]
    fn yaml_detection() {
        let yaml = "engagement:\n  name: t\nscope:\n  allow: []\n";
        let list = "# 주석\n127.0.0.1\n";
        assert!(is_yaml_file(yaml));
        assert!(!is_yaml_file(list));
    }

    #[test]
    fn resolve_and_allow_adds_resolved_ips_once() {
        let p = tmp_file("resolve");
        let _ = std::fs::remove_file(&p);
        // localhost 는 오프라인에서도 해석된다(127.0.0.1 또는 ::1).
        add(&p, "localhost", false).unwrap();
        let allows = load(&p).allows.clone();
        assert!(allows.contains(&"localhost".to_string()));

        let (added, known) = resolve_and_allow(&p, "localhost", &allows);
        // 해석에 성공했으면 IP 가 목록에 생긴다(첫 호출: added, 두 번째 호출: known).
        if added.is_empty() && known.is_empty() {
            // 해석 실패 환경(이론상 드묾) — 목록은 여전히 유효해야 한다.
            assert!(load(&p).allows.contains(&"localhost".to_string()));
            return;
        }
        let allows2 = load(&p).allows.clone();
        assert!(allows2.iter().any(|x| added.contains(x) || known.contains(x)));
        // 재호출 — 같은 IP 는 known 로 분류되고 중복 추가되지 않는다.
        let (added2, known2) = resolve_and_allow(&p, "localhost", &allows2);
        assert!(added2.is_empty());
        assert_eq!(known.len() + added.len(), known2.len() + added2.len());
    }

    #[test]
    fn resolve_and_allow_empty_host_is_noop() {
        let p = tmp_file("resolve-empty");
        let _ = std::fs::remove_file(&p);
        let (added, known) = resolve_and_allow(&p, "", &[]);
        assert!(added.is_empty() && known.is_empty());
    }

    #[test]
    fn add_remove_roundtrip_and_yaml_guard() {
        let p = tmp_file("roundtrip");
        let _ = std::fs::remove_file(&p);

        // 빈 파일에 추가 → 헤더 + 항목 생성
        add(&p, "127.0.0.1", false).unwrap();
        add(&p, "10.13.37.0/24", false).unwrap();
        add(&p, "10.13.37.1", true).unwrap();
        // 중복은 무시
        add(&p, "127.0.0.1", false).unwrap();

        let out = load(&p);
        assert_eq!(out.allows, vec!["127.0.0.1", "10.13.37.0/24"]);
        assert_eq!(out.denies, vec!["10.13.37.1"]);
        assert!(!out.yaml && !out.empty && out.error.is_none());

        // 제거: 대상을 주면 allow/deny 모두(! 붙은 줄 포함) 지워진다
        remove(&p, "10.13.37.1").unwrap();
        remove(&p, "10.13.37.0/24").unwrap();
        remove(&p, "9.9.9.9").unwrap(); // 존재하지 않아도 에러 아님
        let out = load(&p);
        assert_eq!(out.allows, vec!["127.0.0.1"]);
        assert!(out.denies.is_empty());

        // YAML 파일에는 add 가 거부된다
        std::fs::write(&p, "engagement:\n  name: t\nscope:\n  allow: []\n").unwrap();
        assert!(add(&p, "1.2.3.4", false).is_err());
        assert!(load(&p).yaml);

        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn invalid_add_rejected_without_writing() {
        let p = tmp_file("invalid");
        let _ = std::fs::remove_file(&p);
        assert!(add(&p, "999.1.1.1", false).is_err());
        assert!(std::fs::read_to_string(&p).is_err() || std::fs::read_to_string(&p).unwrap().is_empty());
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn normalize_host_cases() {
        assert_eq!(normalize_host("http://10.0.0.5:8080/path"), "10.0.0.5");
        assert_eq!(normalize_host("https://demo.vulnlab.local"), "demo.vulnlab.local");
        assert_eq!(normalize_host("http://x.com:8080"), "x.com");
        assert_eq!(normalize_host("http://[::1]:8080/"), "::1");
        assert_eq!(normalize_host("10.13.37.5:8080"), "10.13.37.5");
        assert_eq!(normalize_host("10.13.37.5"), "10.13.37.5");
        assert_eq!(normalize_host("::1"), "::1"); // IPv6 는 그대로
        assert_eq!(normalize_host("demo.vulnlab.local"), "demo.vulnlab.local");
        assert_eq!(normalize_host("  http://labx.io/a?b#c  "), "labx.io");
        assert_eq!(normalize_host(""), "");
    }

    #[test]
    fn ensure_allowed_auto_adds_url_and_dedupes() {
        let p = tmp_file("ensure");
        let _ = std::fs::remove_file(&p);

        // URL → IP 로 정규화되어 추가
        let (added, target) = ensure_allowed(&p, "http://10.13.37.5:8080/app").unwrap();
        assert!(added);
        assert_eq!(target, "10.13.37.5");
        let out = load(&p);
        assert_eq!(out.allows, vec!["10.13.37.5"]);

        // 중복 실행 → 이미 있음(추가 무시)
        let (added2, target2) = ensure_allowed(&p, "10.13.37.5").unwrap();
        assert!(added2); // 추가 시도 자체는 성공(중복은 내부에서 무시)
        assert_eq!(target2, "10.13.37.5");
        let out = load(&p);
        assert_eq!(out.allows, vec!["10.13.37.5"]);

        // 도메인 URL
        ensure_allowed(&p, "https://demo.vulnlab.local:8443").unwrap();
        let out = load(&p);
        assert_eq!(out.allows, vec!["10.13.37.5", "demo.vulnlab.local"]);

        // 잘못된 대상은 거부 (파일에 기록 없음)
        assert!(ensure_allowed(&p, "http://999.1.1.1").is_err());
        assert!(ensure_allowed(&p, "not an ip!").is_err());

        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    fn auth_list(allows: &[&str], denies: &[&str]) -> AuthList {
        AuthList {
            allows: allows.iter().map(|s| s.to_string()).collect(),
            denies: denies.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn dns_drift_shapes() {
        let allows = vec!["demo.local".to_string(), "10.0.0.5".to_string()];
        // 새 IP 출현 → 드리프트.
        let d = dns_drifted("demo.local", &allows, &["10.0.0.5".to_string(), "10.9.9.9".to_string()]);
        assert_eq!(d, vec!["10.9.9.9".to_string()]);
        // 전부 목록 내 → 정상.
        assert!(dns_drifted("demo.local", &allows, &["10.0.0.5".to_string()]).is_empty());
        // 리터럴·미인가 이름·해석 실패 → 빈 결과.
        assert!(dns_drifted("10.0.0.5", &allows, &["10.0.0.5".to_string()]).is_empty());
        assert!(dns_drifted("evil.local", &allows, &["10.9.9.9".to_string()]).is_empty());
        assert!(dns_drifted("demo.local", &allows, &[]).is_empty());
        // localhost 는 해석 가능 (hosts 파일 — 네트워크 불필요).
        assert!(!resolve_ips("localhost").is_empty());
    }

    #[test]
    fn host_allowed_ipv6_cidr() {
        let a = auth_list(&["2001:db8::/32", "::1"], &[]);
        assert!(is_host_allowed(&a, "2001:db8::1"));
        assert!(is_host_allowed(&a, "2001:db8:ffff::99"));
        assert!(!is_host_allowed(&a, "2001:db9::1"));
        assert!(is_host_allowed(&a, "::1"));
        assert!(is_host_allowed(&a, "2001:DB8::1"), "대소문자 무시");
        assert!(validate_target("2001:db8::/32").is_ok());
        assert!(validate_target("2001:db8::/129").is_err());
        assert!(validate_target("10.0.0.0/33").is_err());
    }

    #[test]
    fn until_expiry_blocks_all() {
        let mut a = auth_list(&["10.0.0.5"], &[]);
        assert!(!is_expired(&a), "미지정은 만료 아님");
        a.until = Some("2999-01-01".into());
        assert!(!is_expired(&a));
        assert!(is_host_allowed(&a, "10.0.0.5"));
        a.until = Some("2000-01-01".into());
        assert!(is_expired(&a));
        assert!(!is_host_allowed(&a, "10.0.0.5"), "만료 시 전부 차단");
    }

    /// 호스트 인가 판정 — prime-agent 반응형 게이트의 판정 근거.
    /// 정확 일치·와일드카드·CIDR·deny 우선·빈 목록 fail-closed.
    #[test]
    fn host_allowed_exact_and_case() {
        let a = auth_list(&["10.13.37.5", "Demo.VulnLab.local"], &[]);
        assert!(is_host_allowed(&a, "10.13.37.5"));
        assert!(is_host_allowed(&a, "demo.vulnlab.local"));
        assert!(is_host_allowed(&a, "DEMO.VULNLAB.LOCAL"));
        assert!(!is_host_allowed(&a, "10.13.37.6"));
        assert!(!is_host_allowed(&a, "other.local"));
        assert!(!is_host_allowed(&a, ""));
    }

    #[test]
    fn host_allowed_wildcard_and_cidr() {
        let a = auth_list(&["*.vulnlab.local", "10.0.0.0/24"], &[]);
        assert!(is_host_allowed(&a, "demo.vulnlab.local"));
        assert!(is_host_allowed(&a, "a.b.vulnlab.local"));
        assert!(!is_host_allowed(&a, "vulnlab.local")); // 베어 도메인은 매칭 안 함
        assert!(!is_host_allowed(&a, "vulnlab.local.evil.com"));
        assert!(is_host_allowed(&a, "10.0.0.5"));
        assert!(is_host_allowed(&a, "10.0.0.0"));
        assert!(!is_host_allowed(&a, "10.0.1.5"));
        assert!(!is_host_allowed(&a, "evil.com"));
    }

    #[test]
    fn host_allowed_deny_wins_and_empty_closed() {
        let a = auth_list(&["10.0.0.0/24"], &["10.0.0.5"]);
        assert!(is_host_allowed(&a, "10.0.0.6"));
        assert!(!is_host_allowed(&a, "10.0.0.5")); // deny 우선
        let empty = auth_list(&[], &[]);
        assert!(!is_host_allowed(&empty, "10.0.0.1")); // 빈 목록 = 전부 차단
        assert!(!is_host_allowed(&empty, "anything.local"));
    }

    #[test]
    fn host_port_gate_shapes() {
        let mut a = auth_list(&["demo.vulnlab.local"], &[]);
        a.ports = Some(vec![80, 443]);
        assert!(is_host_port_allowed(&a, "demo.vulnlab.local", Some(443)));
        assert!(is_host_port_allowed(&a, "demo.vulnlab.local", Some(80)));
        assert!(!is_host_port_allowed(&a, "demo.vulnlab.local", Some(8080)), "인가 밖 포트 차단");
        assert!(!is_host_port_allowed(&a, "evil.com", Some(443)), "호스트 게이트 유지");
        assert!(is_host_port_allowed(&a, "demo.vulnlab.local", None), "포트 맥락 없음은 호스트 게이트만");
        let b = auth_list(&["demo.vulnlab.local"], &[]);
        assert!(is_host_port_allowed(&b, "demo.vulnlab.local", Some(3306)), "지시자 없으면 포트 무제한");
    }
}