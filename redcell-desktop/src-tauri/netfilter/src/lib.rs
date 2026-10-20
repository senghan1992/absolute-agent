//! RedCell egress 선행 차단 — `LD_PRELOAD` 로 자식 프로세스에 주입돼
//! `connect(2)` / `getaddrinfo(3)` 를 인가 목록으로 강제한다.
//!
//! - `REDCELL_NETFILTER_ALLOW`: 쉼표 구분 인가 항목 (호스트명 / IP / IPv4 CIDR).
//! - `REDCELL_NETFILTER_DENY`: 쉼표 구분 제외 항목 (형식 동일, allow 를 이김).
//! - `REDCELL_NETFILTER_LOG`: 차단 감사 로그 경로 (없으면 미기록).
//!
//! 강제 지점은 `connect()` 다 (IP 기반, DNS 리바인딩에도 안전 — 연결 시점에
//! 실제 피어 IP 를 재검사한다). `getaddrinfo()` 훅은 조기 실패 + 감사 목적이다.
//! AF_UNIX 는 항상 허용 (로컬 IPC — 네트워크 스코프 밖).
//! 미설정(두 env 모두 비어 있음)이면 완전 passthrough (비활성).
//!
//! 주의: 이 파일의 unsafe 훅 경로에서는 libc 직접 호출만 사용한다.
//! (`libc::connect` / `libc::getaddrinfo` 를 직접 부르면 자기 자신을 재귀 호출하므로
//! `dlsym(RTLD_NEXT)` 로 다음 심볼을 찾아야 한다.)

use std::collections::HashSet;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowEntry {
    Ip(IpAddr),
    Cidr { base: u32, bits: u8 },
    Host(String),
}

impl AllowEntry {
    pub fn parse(raw: &str) -> Option<AllowEntry> {
        let t = raw.trim().trim_matches(|c| c == '[' || c == ']').trim();
        if t.is_empty() {
            return None;
        }
        if let Ok(ip) = t.parse::<IpAddr>() {
            return Some(AllowEntry::Ip(ip));
        }
        if let Some((base, bits)) = t.split_once('/') {
            if let (Ok(ip), Ok(bits)) = (base.trim().parse::<Ipv4Addr>(), bits.trim().parse::<u8>()) {
                if bits <= 32 {
                    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                    return Some(AllowEntry::Cidr { base: u32::from(ip) & mask, bits });
                }
            }
            return None;
        }
        // 호스트명 후보 — 공백·슬래시·제어문자·URL 스킴 잔재 거부.
        if t.len() > 253
            || t.contains(|c: char| c.is_whitespace() || c == '/' || c == ':' || c == '@' || c.is_control())
        {
            return None;
        }
        Some(AllowEntry::Host(t.to_ascii_lowercase()))
    }

    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        match self {
            AllowEntry::Ip(a) => a == ip,
            AllowEntry::Cidr { base, bits } => match ip {
                IpAddr::V4(v4) => {
                    let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                    (u32::from(*v4) & mask) == *base
                }
                IpAddr::V6(_) => false,
            },
            AllowEntry::Host(_) => false,
        }
    }
}

/// `host`, `host:port`, `http(s)://host[:port]/…` 에서 호스트만 추출.
pub fn extract_host(raw: &str) -> Option<String> {
    let mut t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(rest) = t.split("://").nth(1) {
        t = rest;
    } else if t.contains("://") {
        return None;
    }
    let t = t.split('/').next().unwrap_or("");
    let t = t.split('?').next().unwrap_or("");
    let t = t.split('@').next_back().unwrap_or("");
    if t.is_empty() {
        return None;
    }
    // IPv6 리터럴 [::1]:port
    if let Some(stripped) = t.strip_prefix('[') {
        return stripped.split(']').next().map(|h| h.to_string()).filter(|h| !h.is_empty());
    }
    // host:port — 콜론이 2개 이상이면 베어 IPv6 (그대로) 아니면 포트 제거.
    if t.matches(':').count() == 1 {
        if let Some((h, _)) = t.split_once(':') {
            return if h.is_empty() { None } else { Some(h.to_string()) };
        }
    }
    Some(t.to_string())
}

pub fn parse_list(raw: &str) -> Vec<AllowEntry> {
    raw.split(',').filter_map(AllowEntry::parse).collect()
}

/// 런타임 필터 — 호스트명 항목은 init 시점에 실해석해 IP 집합으로 펼친다.
pub struct Filter {
    allow_ips: HashSet<IpAddr>,
    allow_cidrs: Vec<(u32, u8)>,
    deny_ips: HashSet<IpAddr>,
    deny_cidrs: Vec<(u32, u8)>,
}

impl Filter {
    pub fn ip_allowed(&self, ip: &IpAddr) -> bool {
        if self.deny_ips.contains(ip) {
            return false;
        }
        if let IpAddr::V4(v4) = ip {
            let n = u32::from(*v4);
            for (base, bits) in &self.deny_cidrs {
                let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                if (n & mask) == *base {
                    return false;
                }
            }
        }
        if self.allow_ips.contains(ip) {
            return true;
        }
        if let IpAddr::V4(v4) = ip {
            let n = u32::from(*v4);
            for (base, bits) in &self.allow_cidrs {
                let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                if (n & mask) == *base {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::cell::Cell;

    type ConnectFn = unsafe extern "C" fn(c_int, *const libc::sockaddr, libc::socklen_t) -> c_int;
    type GaiFn = unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *const libc::addrinfo,
        *mut *mut libc::addrinfo,
    ) -> c_int;

    static REAL_CONNECT: OnceLock<ConnectFn> = OnceLock::new();
    static REAL_GAI: OnceLock<GaiFn> = OnceLock::new();
    static FILTER: OnceLock<Option<Filter>> = OnceLock::new();
    static LOG_PATH: OnceLock<Option<String>> = OnceLock::new();

    thread_local! {
        static IN_HOOK: Cell<bool> = const { Cell::new(false) };
    }

    fn real_connect() -> ConnectFn {
        *REAL_CONNECT.get_or_init(|| unsafe {
            let sym = libc::dlsym(libc::RTLD_NEXT, c"connect".as_ptr());
            std::mem::transmute::<*mut c_void, ConnectFn>(sym)
        })
    }

    fn real_gai() -> GaiFn {
        *REAL_GAI.get_or_init(|| unsafe {
            let sym = libc::dlsym(libc::RTLD_NEXT, c"getaddrinfo".as_ptr());
            std::mem::transmute::<*mut c_void, GaiFn>(sym)
        })
    }

    fn log_path() -> Option<&'static str> {
        LOG_PATH
            .get_or_init(|| {
                std::env::var("REDCELL_NETFILTER_LOG").ok().filter(|s| !s.trim().is_empty())
            })
            .as_deref()
    }

    /// 감사 로그 — 재진입 안전하게 raw fd 로만 기록한다.
    fn audit(msg: &str) {
        let Some(path) = log_path() else { return };
        let bytes = msg.as_bytes();
        unsafe {
            let cpath = std::ffi::CString::new(path);
            let Ok(cpath) = cpath else { return };
            let fd = libc::open(cpath.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND, 0o600);
            if fd < 0 {
                return;
            }
            let mut off = 0;
            while off < bytes.len() {
                let n = libc::write(fd, bytes[off..].as_ptr() as *const c_void, bytes.len() - off);
                if n <= 0 {
                    break;
                }
                off += n as usize;
            }
            libc::close(fd);
        }
    }

    /// 허용 IP 집합 구축 — 호스트명 항목은 여기서 실해석한다.
    fn build_filter() -> Option<Filter> {
        let allow_raw = std::env::var("REDCELL_NETFILTER_ALLOW").unwrap_or_default();
        let deny_raw = std::env::var("REDCELL_NETFILTER_DENY").unwrap_or_default();
        if allow_raw.trim().is_empty() && deny_raw.trim().is_empty() {
            return None; // 미설정 = 비활성 passthrough
        }
        let mut f = Filter {
            allow_ips: HashSet::new(),
            allow_cidrs: Vec::new(),
            deny_ips: HashSet::new(),
            deny_cidrs: Vec::new(),
        };
        // 숫자·CIDR 항목은 직접 등록.
        for e in parse_list(&allow_raw) {
            match e {
                AllowEntry::Ip(ip) => {
                    f.allow_ips.insert(ip);
                }
                AllowEntry::Cidr { base, bits } => f.allow_cidrs.push((base, bits)),
                AllowEntry::Host(_) => {}
            }
        }
        for e in parse_list(&deny_raw) {
            match e {
                AllowEntry::Ip(ip) => {
                    f.deny_ips.insert(ip);
                }
                AllowEntry::Cidr { base, bits } => f.deny_cidrs.push((base, bits)),
                AllowEntry::Host(_) => {}
            }
        }
        // 호스트명 항목은 실해석해 IP 로 펼친다 (allow·deny 모두).
        let gai = real_gai();
        for (raw, is_deny) in [(&allow_raw, false), (&deny_raw, true)] {
            for e in parse_list(raw) {
                let AllowEntry::Host(host) = e else { continue };
                let Ok(chost) = std::ffi::CString::new(host.clone()) else { continue };
                let mut res: *mut libc::addrinfo = std::ptr::null_mut();
                let rc = unsafe { gai(chost.as_ptr(), std::ptr::null(), std::ptr::null(), &mut res) };
                if rc != 0 || res.is_null() {
                    continue;
                }
                let mut cur = res;
                unsafe {
                    while !cur.is_null() {
                        if let Some(ip) = sockaddr_to_ip((*cur).ai_addr, (*cur).ai_addrlen) {
                            if is_deny {
                                f.deny_ips.insert(ip);
                            } else {
                                f.allow_ips.insert(ip);
                            }
                        }
                        cur = (*cur).ai_next;
                    }
                    libc::freeaddrinfo(res);
                }
            }
        }
        Some(f)
    }

    fn filter() -> Option<&'static Filter> {
        FILTER.get_or_init(build_filter).as_ref()
    }

    pub(super) fn sockaddr_to_ip(sa: *const libc::sockaddr, len: libc::socklen_t) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        unsafe {
            match (*sa).sa_family as c_int {
                libc::AF_INET => {
                    if len as usize >= std::mem::size_of::<libc::sockaddr_in>() {
                        let sin = &*(sa as *const libc::sockaddr_in);
                        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                        Some(IpAddr::V4(ip))
                    } else {
                        None
                    }
                }
                libc::AF_INET6 => {
                    if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() {
                        let sin6 = &*(sa as *const libc::sockaddr_in6);
                        Some(IpAddr::V6(sin6.sin6_addr.s6_addr.into()))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
    }

    fn sockaddr_port(sa: *const libc::sockaddr) -> u16 {
        if sa.is_null() {
            return 0;
        }
        unsafe {
            match (*sa).sa_family as c_int {
                libc::AF_INET => u16::from_be((*(sa as *const libc::sockaddr_in)).sin_port),
                libc::AF_INET6 => u16::from_be((*(sa as *const libc::sockaddr_in6)).sin6_port),
                _ => 0,
            }
        }
    }

    /// 진입 가드 — 재진입이면 true (passthrough 해야 함).
    fn enter_hook() -> bool {
        IN_HOOK.with(|g| {
            if g.get() {
                true
            } else {
                g.set(true);
                false
            }
        })
    }

    fn exit_hook() {
        IN_HOOK.with(|g| g.set(false));
    }

    #[no_mangle]
    pub unsafe extern "C" fn connect(
        sockfd: c_int,
        addr: *const libc::sockaddr,
        addrlen: libc::socklen_t,
    ) -> c_int {
        let real = real_connect();
        if enter_hook() {
            return real(sockfd, addr, addrlen);
        }
        let rc = (|| {
            let Some(f) = filter() else {
                return real(sockfd, addr, addrlen);
            };
            // AF_UNIX 등 비-IP 는 허용.
            let fam = if addr.is_null() { -1 } else { unsafe { (*addr).sa_family as c_int } };
            if fam != libc::AF_INET && fam != libc::AF_INET6 {
                return real(sockfd, addr, addrlen);
            }
            match sockaddr_to_ip(addr, addrlen) {
                Some(ip) if f.ip_allowed(&ip) => real(sockfd, addr, addrlen),
                Some(ip) => {
                    audit(&format!("[redcell-netfilter] blocked connect {ip}:{}\n", sockaddr_port(addr)));
                    unsafe { *libc::__errno_location() = libc::ECONNREFUSED };
                    -1
                }
                None => real(sockfd, addr, addrlen),
            }
        })();
        exit_hook();
        rc
    }

    #[no_mangle]
    pub unsafe extern "C" fn getaddrinfo(
        node: *const c_char,
        service: *const c_char,
        hints: *const libc::addrinfo,
        res: *mut *mut libc::addrinfo,
    ) -> c_int {
        let gai = real_gai();
        if node.is_null() || enter_hook() {
            return gai(node, service, hints, res);
        }
        let rc = (|| {
            let Some(f) = filter() else {
                return gai(node, service, hints, res);
            };
            let name = unsafe { CStr::from_ptr(node) }.to_string_lossy().into_owned();
            // 숫자 리터럴은 그대로 (connect 에서 강제).
            if name.parse::<IpAddr>().is_ok() {
                return gai(node, service, hints, res);
            }
            let mut raw: *mut libc::addrinfo = std::ptr::null_mut();
            let rc = unsafe { gai(node, service, hints, &mut raw) };
            if rc != 0 || raw.is_null() {
                return rc;
            }
            // 결과 중 허용 IP 가 하나라도 있으면 통과 (connect 가 최종 강제).
            let mut ok = false;
            let mut cur = raw;
            unsafe {
                while !cur.is_null() {
                    if let Some(ip) = sockaddr_to_ip((*cur).ai_addr, (*cur).ai_addrlen) {
                        if f.ip_allowed(&ip) {
                            ok = true;
                            break;
                        }
                    }
                    cur = (*cur).ai_next;
                }
            }
            if ok {
                unsafe { *res = raw };
                rc
            } else {
                unsafe { libc::freeaddrinfo(raw) };
                audit(&format!("[redcell-netfilter] blocked dns {name}\n"));
                libc::EAI_NONAME
            }
        })();
        exit_hook();
        rc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_parse_ip_cidr_host() {
        assert_eq!(AllowEntry::parse("1.2.3.4"), Some(AllowEntry::Ip("1.2.3.4".parse().unwrap())));
        assert_eq!(AllowEntry::parse("::1"), Some(AllowEntry::Ip("::1".parse().unwrap())));
        assert_eq!(
            AllowEntry::parse("10.0.0.0/8"),
            Some(AllowEntry::Cidr { base: 0x0a00_0000, bits: 8 })
        );
        // 베이스 정규화 (호스트 비트 마스크).
        assert_eq!(
            AllowEntry::parse("192.168.1.77/24"),
            Some(AllowEntry::Cidr { base: 0xc0a8_0100, bits: 24 })
        );
        assert_eq!(AllowEntry::parse("Example.COM"), Some(AllowEntry::Host("example.com".into())));
        assert_eq!(AllowEntry::parse(""), None);
        assert_eq!(AllowEntry::parse("10.0.0.0/33"), None);
        assert_eq!(AllowEntry::parse("http://x/"), None);
        assert_eq!(AllowEntry::parse("a b"), None);
    }

    #[test]
    fn cidr_match_v4() {
        let c = AllowEntry::parse("192.168.0.0/16").unwrap();
        assert!(c.matches_ip(&"192.168.1.1".parse().unwrap()));
        assert!(!c.matches_ip(&"192.169.0.1".parse().unwrap()));
        assert!(!c.matches_ip(&"::1".parse().unwrap()));
        let all = AllowEntry::parse("0.0.0.0/0").unwrap();
        assert!(all.matches_ip(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn host_extraction_shapes() {
        assert_eq!(extract_host("https://api.anthropic.com/v1").as_deref(), Some("api.anthropic.com"));
        assert_eq!(extract_host("http://localhost:11434/v1").as_deref(), Some("localhost"));
        assert_eq!(extract_host("example.com:8080").as_deref(), Some("example.com"));
        assert_eq!(extract_host("127.0.0.1").as_deref(), Some("127.0.0.1"));
        assert_eq!(extract_host("[::1]:8080/x").as_deref(), Some("::1"));
        assert_eq!(extract_host("user@example.com").as_deref(), Some("example.com"));
        assert_eq!(extract_host(""), None);
    }

    #[test]
    fn filter_deny_wins() {
        let f = Filter {
            allow_ips: ["10.0.0.1".parse().unwrap()].into_iter().collect(),
            allow_cidrs: vec![(0x0a00_0000, 8)],
            deny_ips: ["10.0.0.1".parse().unwrap()].into_iter().collect(),
            deny_cidrs: vec![(0xc0a8_0000, 16)],
        };
        assert!(!f.ip_allowed(&"10.0.0.1".parse().unwrap())); // deny 우선
        assert!(f.ip_allowed(&"10.1.2.3".parse().unwrap())); // CIDR 허용
        assert!(!f.ip_allowed(&"192.168.1.1".parse().unwrap())); // deny CIDR
        assert!(!f.ip_allowed(&"8.8.8.8".parse().unwrap())); // 미등록
    }
}
