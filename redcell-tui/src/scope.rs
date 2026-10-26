//! 스윕 사전 인가 게이트 — 데스크톱/TS 의 ScopeGuard 를 우회하지 않도록 한다.
//!
//! `redcell run` 자식은 TS ScopeGuard 로 fail-closed 검사하지만, TUI 의 P0 스윕은
//! `engine::probes` 를 직접 호출해 그동안 인가 검사 없이 HTTP 를 쏘았다.
//! 이 모듈은 TS `src/scope/ip-list.ts` 와 동일한 규칙으로 `authorization.list`
//! (간단 IP 목록) 를 미리 검사한다:
//!   - 파일 부재·파싱 실패·allow 0개 → 차단 (fail-closed)
//!   - deny(!) 는 allow 를 이긴다
//!   - until: 유효기간, ports: 허용 포트 지시자 지원
//! 정식 YAML 인가(authorization.yaml) 가 있으면 판정을 TS 에 위임한다(Skip).

use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::providers;

/// 인가 판정 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeDecision {
    /// 인가됨 — 진행.
    Allowed,
    /// 인가 목록 파일 자체가 없음 — fail-closed 차단.
    Missing,
    /// 인가 목록에 없거나(또는 deny·기간·포트 불일치) — 차단.
    Denied(String),
    /// 정식 YAML 인가 존재 — TS ScopeGuard 가 판정하므로 TUI 는 개입하지 않음.
    Skip,
}

#[derive(Debug, PartialEq)]
pub(crate) enum Entry {
    Allow { host: String, domain: bool },
    Deny { host: String, domain: bool },
}

#[derive(Debug, Default)]
struct IpList {
    entries: Vec<Entry>,
    cidr_allow: Vec<(Ipv4Addr, u8)>,
    cidr_deny: Vec<(Ipv4Addr, u8)>,
    until: Option<String>,
    ports: Option<Vec<u16>>,
    has_allow: bool,
}

const UNTIL_PREFIX: &str = "until:";
const PORTS_PREFIX: &str = "ports:";

/// 인가 목록 텍스트 파싱 (TS parseIpList 와 동일 규칙).
/// 허용 항목이 하나도 없으면 Err (fail-closed).
pub(crate) fn parse_ip_list(text: &str) -> Result<IpList, String> {
    let mut list = IpList::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix(UNTIL_PREFIX) {
            let d = rest.trim();
            if d.len() == 10 && d.chars().nth(4) == Some('-') {
                list.until = Some(d.to_string());
            } else {
                return Err(format!("잘못된 until 지시자: '{line}' (YYYY-MM-DD)."));
            }
            continue;
        }
        if let Some(rest) = lower.strip_prefix(PORTS_PREFIX) {
            let ports: Vec<u16> = rest
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .filter(|p| *p > 0)
                .collect();
            if ports.is_empty() {
                return Err(format!("잘못된 ports 지시자: '{line}' (예: ports: 80,443,8080)."));
            }
            list.ports = Some(ports);
            continue;
        }
        let (deny, v) = match line.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, line),
        };
        if v.is_empty() {
            continue;
        }
        if v.contains('/') {
            // CIDR — IPv4 (TS ip-list 와 동일하게 IPv4 CIDR 만).
            let Some((ip, bits)) = parse_cidr_parts(v) else {
                return Err(format!("잘못된 CIDR: '{v}' — IPv4/CIDR 형식(예: 10.0.0.0/24)."));
            };
            if deny {
                list.cidr_deny.push((ip, bits));
            } else {
                list.cidr_allow.push((ip, bits));
                list.has_allow = true;
            }
            continue;
        }
        let domain = v.starts_with("*.");
        let host = v.trim_start_matches("*.").to_ascii_lowercase();
        if host.is_empty() || host.contains(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
            return Err(format!("인식할 수 없는 대상: '{v}' — IP, CIDR, 도메인만 허용."));
        }
        if deny {
            list.entries.push(Entry::Deny { host, domain });
        } else {
            list.entries.push(Entry::Allow { host, domain });
            list.has_allow = true;
        }
    }
    if !list.has_allow {
        return Err("인가 목록에 허용 대상이 하나도 없습니다.".into());
    }
    Ok(list)
}

/// "10.0.0.0/24" → (네트워크 주소, 비트)
fn parse_cidr_parts(v: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, bits) = v.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    let bits: u8 = bits.parse().ok()?;
    if bits > 32 {
        return None;
    }
    Some((ip, bits))
}

impl IpList {
    fn host_allowed(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        let as_ip = h.parse::<Ipv4Addr>().ok();
        // deny 는 allow 를 이긴다 — CIDR deny 를 먼저 본다.
        if let Some(ip) = as_ip {
            if self.cidr_deny.iter().any(|(net, bits)| cidr_contains(*net, *bits, ip)) {
                return false;
            }
        }
        // 문자열 항목 (host 정확일치 / *.도메인 와일드카드).
        let mut allowed = false;
        for e in &self.entries {
            let (ehost, edomain, deny) = match e {
                Entry::Allow { host, domain } => (host, *domain, false),
                Entry::Deny { host, domain } => (host, *domain, true),
            };
            let m = if edomain {
                h == ehost.as_str() || h.ends_with(&format!(".{ehost}"))
            } else {
                h == ehost.as_str()
            };
            if m {
                if deny {
                    return false;
                }
                allowed = true;
            }
        }
        if allowed {
            return true;
        }
        // IP 대상은 CIDR allow 로도 허용된다.
        if let Some(ip) = as_ip {
            return self.cidr_allow.iter().any(|(net, bits)| cidr_contains(*net, *bits, ip));
        }
        false
    }
}

fn cidr_contains(net: Ipv4Addr, bits: u8, ip: Ipv4Addr) -> bool {
    let n = u32::from(net);
    let x = u32::from(ip);
    if bits == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - bits as u32);
    (n & mask) == (x & mask)
}

/// 인가 목록 파일 후보 (TS findAuthPath 와 동일 순서의 ip-list 부분).
pub fn auth_list_candidates() -> Vec<PathBuf> {
    let home = providers::redcell_home();
    vec![home.join("authorization.list"), home.join("authorization.yaml")]
}

/// 대상(host, port) 사전 인가 검사 — 스윕·agent 실행 전에 호출.
pub fn preflight(host: &str, port: Option<u16>) -> ScopeDecision {
    let candidates = auth_list_candidates();
    let list_path = candidates.iter().find(|p| p.is_file());
    let yaml = candidates.iter().find(|p| {
        p.extension().map(|e| e == "yaml").unwrap_or(false) && p.is_file()
    });
    let Some(path) = list_path else {
        // 정식 YAML 인가가 있으면 TS ScopeGuard 가 판정 — 개입하지 않는다.
        if yaml.is_some() {
            return ScopeDecision::Skip;
        }
        return ScopeDecision::Missing;
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return ScopeDecision::Denied(format!("인가 파일을 읽을 수 없습니다({}): {e}", path.display())),
    };
    let list = match parse_ip_list(&text) {
        Ok(l) => l,
        Err(e) => return ScopeDecision::Denied(format!("인가 목록 오류({}): {e}", path.display())),
    };
    // 유효기간 — until 이 지났으면 차단.
    if let Some(until) = &list.until {
        let today = chrono::Utc::now().date_naive().format("%Y-%m-%d").to_string();
        if today.as_str() > until.as_str() {
            return ScopeDecision::Denied(format!("인가 기간이 만료되었습니다 (until: {until})."));
        }
    }
    // 포트 제한.
    if let (Some(ports), Some(p)) = (&list.ports, port) {
        if !ports.contains(&p) {
            return ScopeDecision::Denied(format!("포트 {p} 는 허용 포트 목록에 없습니다 ({}).", ports.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")));
        }
    }
    if !list.host_allowed(host) {
        return ScopeDecision::Denied(format!("대상 {host} 는 인가 목록({})에 없습니다.", path.display()));
    }
    ScopeDecision::Allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(text: &str, host: &str, port: Option<u16>) -> ScopeDecision {
        let list = parse_ip_list(text).unwrap();
        // preflight 의 파일 IO 를 피하고 판정 로직만 검사한다.
        let today = chrono::Utc::now().date_naive().format("%Y-%m-%d").to_string();
        if let Some(until) = &list.until {
            if today.as_str() > until.as_str() {
                return ScopeDecision::Denied("expired".into());
            }
        }
        if let (Some(ports), Some(p)) = (&list.ports, port) {
            if !ports.contains(&p) {
                return ScopeDecision::Denied("port".into());
            }
        }
        if list.host_allowed(host) {
            ScopeDecision::Allowed
        } else {
            ScopeDecision::Denied("host".into())
        }
    }

    #[test]
    fn allows_exact_host_and_wildcard_domain() {
        let list = "127.0.0.1\n*.vulnlab.local\n# 주석\n";
        assert_eq!(dec(list, "127.0.0.1", None), ScopeDecision::Allowed);
        assert_eq!(dec(list, "app.vulnlab.local", None), ScopeDecision::Allowed);
        assert_eq!(dec(list, "vulnlab.local", None), ScopeDecision::Allowed);
        assert!(matches!(dec(list, "evil.com", None), ScopeDecision::Denied(_)));
    }

    #[test]
    fn deny_beats_allow() {
        let list = "10.0.0.0/24\n!10.0.0.5\n";
        assert_eq!(dec(list, "10.0.0.3", None), ScopeDecision::Allowed);
        assert!(matches!(dec(list, "10.0.0.5", None), ScopeDecision::Denied(_)));
    }

    #[test]
    fn cidr_and_port_and_until() {
        let list = "10.13.37.0/24\nports: 80,8080\nuntil: 2099-01-01\n";
        assert_eq!(dec(list, "10.13.37.5", Some(8080)), ScopeDecision::Allowed);
        assert!(matches!(dec(list, "10.13.37.5", Some(443)), ScopeDecision::Denied(_)));
        assert!(matches!(dec(list, "10.13.38.5", Some(80)), ScopeDecision::Denied(_)));
        let expired = "10.0.0.1\nuntil: 2001-01-01\n";
        assert!(matches!(dec(expired, "10.0.0.1", None), ScopeDecision::Denied(_)));
    }

    #[test]
    fn fail_closed_on_no_allow_or_bad_line() {
        assert!(parse_ip_list("# 주석만\n").is_err());
        assert!(parse_ip_list("192.168.1.1\n!!bad\n").is_err());
        assert!(parse_ip_list("ports: xyz\n1.2.3.4\n").is_err());
    }

    #[test]
    fn cidr_math() {
        let net: Ipv4Addr = "10.13.37.0".parse().unwrap();
        assert!(cidr_contains(net, 24, "10.13.37.255".parse().unwrap()));
        assert!(!cidr_contains(net, 24, "10.13.38.1".parse().unwrap()));
        assert!(cidr_contains("0.0.0.0".parse().unwrap(), 0, "1.2.3.4".parse().unwrap()));
    }
}
