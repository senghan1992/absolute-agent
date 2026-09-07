// auth.rs — 간단 IP 목록 인가(authorization.list) 관리.
//
// redcell 엔진의 `src/scope/ip-list.ts` 와 동일한 파일 형식/검증 규칙을 따른다:
//   - 한 줄에 하나: IP / CIDR / 도메인  ·  ! 접두사 = 제외(deny, allow 를 이김)  ·  # 주석
//   - 지시자: until: YYYY-MM-DD  ·  ports: 80,443,8080
// 이 모듈은 데스크톱 UI 의 "인가 대상 관리" 패널 전용이다(표시 + 추가 + 제거).
// 실제 스캔 게이트는 항상 redcell 엔진(ScopeGuard)이 수행하므로, 여기서의 내용이
// 어긋나도 실행 시점에 엔진 쪽 검증이 fail-closed 로 다시 확인한다.

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};
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
            .map_err(|_| format!("잘못된 CIDR: '{v}' — IPv4/CIDR 형식(예: 10.0.0.0/24)이어야 합니다."))?;
        if ip.parse::<Ipv4Addr>().is_err() || b > 32 {
            return Err(format!("잘못된 CIDR: '{v}' — IPv4/CIDR 형식(예: 10.0.0.0/24)이어야 합니다."));
        }
        return Ok(());
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
            if allow_count == 0 {
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
}