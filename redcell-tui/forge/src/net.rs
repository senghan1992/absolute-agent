//! 포트 스캔 + 서비스 배너 수집 — `nmap -sT -sV` 의 최소 대체.
//!
//! Kali 의 `nmap -sT -sV` 를 대체하는 최소 기능이다. **TCP connect scan 만** 쓴다.
//! (SYN scan 은 raw socket 이 필요해 권한·규제를 추가로 요구하므로 쓰지 않는다)
//!
//! 안전장치:
//!   1. **인가 게이트는 포트마다** — `Authorization::check(host, Some(port))` 를 통과한
//!      포트만 연결한다. 인가 밖 포트는 "스킵"으로 기록하고 스캔은 계속된다.
//!   2. **규모 상한** — CIDR 은 IPv4 /24, IPv6 /120 까지만. `hosts × ports` 가 20 000 을
//!      넘으면 스캔을 시작하지 않고 에러로 알린다.
//!   3. **동시성 클램프** — `Semaphore` 로 동시 연결 수를 제한한다(최대 512).
//!   4. **파괴적 행위 없음** — 연결 후 읽기만 한다. 쓰기는 배너 수집용 프로브 바이트뿐이다.
//!
//! 열린 포트 자체는 Finding 이 아니다(공격 표면 목록일 뿐이다). 다만 `sensitive_port()` 로
//! 걸리는 위험 서비스(평문 텔넷/FTP, 무인증 DB·캐시·Docker API 등)가 열려 있으면
//! `category = "exposed_service"` Finding 을 만든다.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use futures::StreamExt;
use regex::Regex;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::report::Finding;
use crate::scope::Authorization;

// ───────────────────────────── 상수 ─────────────────────────────

/// 기본 연결 타임아웃 (밀리초).
pub const DEFAULT_TIMEOUT_MS: u64 = 1200;

/// 기본 동시 연결 수.
pub const DEFAULT_CONCURRENCY: usize = 128;

/// 동시 연결 수 상한.
pub const MAX_CONCURRENCY: usize = 512;

/// 스캔 규모 상한 — `호스트 수 × 포트 수`.
pub const MAX_SCAN_TARGETS: usize = 20_000;

/// CIDR 1건에서 허용하는 최대 호스트 수.
pub const MAX_CIDR_HOSTS: usize = 4096;

/// 저장·보고하는 배너 최대 길이 (문자).
pub const MAX_BANNER_LEN: usize = 512;

/// HTTP 계열로 프로브를 보내는 포트 목록.
const HTTP_PORTS: &[u16] = &[
    80, 81, 3000, 5000, 5911, 7001, 8000, 8001, 8080, 8081, 8088, 8443, 8888,
];

/// 배너 수집 시 사용하는 읽기 대기 시간.
const BANNER_READ_TIMEOUT: Duration = Duration::from_millis(600);

/// HTTP 응답으로 읽을 최대 바이트.
const HTTP_BANNER_MAX: usize = 4096;

/// 그 밖 프로토콜 배너 최대 바이트.
const TEXT_BANNER_MAX: usize = 1024;

// ───────────────────────────── 공개 타입 ─────────────────────────────

/// 포트 상태.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PortState {
    /// 연결 성공 — 포트가 열려 있다.
    Open,
    /// 연결 거부 (ECONNREFUSED) — 닫혀 있다.
    Closed,
    /// 타임아웃 등 그 밖의 오류 — 방화벽으로 걸린 것으로 본다.
    Filtered,
}

impl PortState {
    /// 사람이 읽는 라벨.
    pub fn label(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
        }
    }
}

/// 식별된 서비스 정보.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceInfo {
    /// 서비스 이름 ("http", "ssh", "mysql" ...).
    pub name: String,
    /// 제품 ("nginx", "OpenSSH").
    pub product: Option<String>,
    /// 버전 ("9.6").
    pub version: Option<String>,
    /// 원본 배너 (최대 512자).
    pub banner: Option<String>,
}

/// 포트 1건의 결과.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
    pub elapsed_ms: u64,
}

/// 호스트 1대의 결과.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HostResult {
    pub host: String,
    /// 열린 포트가 하나라도 있으면 살아 있는 것으로 본다.
    pub alive: bool,
    pub ports: Vec<PortResult>,
    /// 배너에서 얻은 약한 OS 힌트 ("Windows(가능성)" 등).
    pub os_hints: Vec<String>,
}

/// 스캔 리포트.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanReport {
    pub hosts: Vec<HostResult>,
    /// 실제로 연결을 시도한 (호스트 × 포트) 건수.
    pub scanned: u64,
    /// 열린 포트 건수.
    pub open: u64,
    pub duration_ms: u64,
    pub findings: Vec<Finding>,
}

/// 스캔 계획.
#[derive(Debug, Clone)]
pub struct ScanPlan {
    /// 대상 호스트 목록 (CIDR 문자열이 들어가면 자동 확장된다).
    pub hosts: Vec<String>,
    /// 대상 포트 목록.
    pub ports: Vec<u16>,
    /// 연결 타임아웃 (밀리초). 0 이면 기본값.
    pub timeout_ms: u64,
    /// 동시 연결 수. 0 이면 기본값, 512 로 클램프된다.
    pub concurrency: usize,
    /// 열린 포트에서 배너를 수집할지 여부.
    pub grab_banner: bool,
    /// 대상 호스트 수 상한. 0 이면 상한 없음(전체 규모 상한만 적용).
    pub max_hosts: usize,
}

impl Default for ScanPlan {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            ports: default_ports(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            concurrency: DEFAULT_CONCURRENCY,
            grab_banner: true,
            max_hosts: 0,
        }
    }
}

// ───────────────────────────── 위험 포트 ─────────────────────────────

/// (포트, 심각도, 설명, 보완 조언).
///
/// 평문 전송·무인증 접근·관리 콘솔 계열만 등록한다. 80/443 같은 일반 웹 포트는
/// "위험 서비스"가 아니므로 여기 넣지 않는다.
const SENSITIVE_PORTS: &[(u16, &str, &str, &str)] = &[
    (
        21,
        "high",
        "평문 FTP — 계정과 데이터가 암호화 없이 전송됩니다",
        "FTP 를 SFTP/SCP 로 대체하고, FTP 를 listen 하지 않도록 서비스를 중지하세요. \
         불가피하면 FTP 를 내부망으로만 노출하고 방화벽에서 외부 접근을 차단하세요.",
    ),
    (
        23,
        "critical",
        "평문 텔넷 — 원격 셸 계정과 세션이 모두 평문으로 노출됩니다",
        "텔넷을 SSH 로 완전히 대체하고 텔넷 데몬을 중지하세요. 필요하면 연결 전 계층 암호화(TLS 터널링)를 \
         적용하고 방화벽에서 23번 포트의 외부 접근을 차단하세요.",
    ),
    (
        25,
        "medium",
        "평문 SMTP — 메일 내용을 중계(relay) 오용할 수 있습니다",
        "SMTP over TLS(465/587)로 전환하고, ACL 로 발신 도메인을 제한해 오픈 릴레이를 막으세요.",
    ),
    (
        110,
        "medium",
        "평문 POP3 — 메일 계정 인증 정보가 평문으로 전송됩니다",
        "POP3S(995)로 전환하고 계정 인증을 삭제 후 TLS 방식으로 변경하세요.",
    ),
    (
        143,
        "medium",
        "평문 IMAP — 메일 계정 인증 정보가 평문으로 전송됩니다",
        "IMAPS(993)로 전환하고 STARTTLS 를 강제하세요. 메일 계정은 웹메일 경유만 허용하세요.",
    ),
    (
        389,
        "medium",
        "LDAP — 암호화되지 않은 바인(bind)이 가능합니다",
        "LDAPS(636) 또는 StartTLS 를 강제하고, 단순 바인 계정을 제거하세요.",
    ),
    (
        445,
        "high",
        "SMB — 파일 공유가 직접 노출되어 취약점 공격面이 됩니다",
        "SMB 는 내부 구역에서만 노출하고 SMB 서명·방화벽 규칙을 적용하세요. 외부 공유는 VPN 뒤로 옮기세요.",
    ),
    (
        1433,
        "high",
        "Microsoft SQL Server — DB 가 직접 노출됩니다",
        "DB 포트를 사내망으로만 열고, 애플리케이션 계정만 사용하며, 네트워크 ACL 과 방화벽으로 접근을 제한하세요.",
    ),
    (
        1521,
        "high",
        "Oracle DB 리스너 — DB 가 직접 노출됩니다",
        "리스너 포트를 사내망으로만 노출하고 listener.ora 의 ADDRESS 항목을 사내 주소로 제한하세요.",
    ),
    (
        2049,
        "medium",
        "NFS — 파일 시스템이 디렉터리 단위로 공유됩니다",
        "NFS 를 사내망으로만 노출하고 export 옵션에서 no_root_squash 를 끄세요.",
    ),
    (
        2375,
        "critical",
        "Docker Remote API — 비인증 상태로 컨테이너를 제어할 수 있습니다",
        "2375 포트 노출을 즉시 차단하세요. 소켓을 활성화하고 UNIX 소켓 인증 또는 mTLS 로만 접속하게 만들고, \
         방화벽에서 2375/2376 을 외부에 열지 마세요.",
    ),
    (
        3306,
        "high",
        "MySQL/MariaDB — DB 가 직접 노출됩니다",
        "DB 포트를 사내망/프라이빗 서브넷으로만 열고, 전용 애플리케이션 계정과 최소 권한을 사용하며 \
         root 원격 로그인을 차단하세요.",
    ),
    (
        3389,
        "high",
        "RDP — 원격 데스크톱이 직접 노출됩니다",
        "RDP 를 VPN 뒤에만 두고, 계정 잠금 정책(NLA· bruteforce 차단)을 적용하고 인터넷 경유 접근을 차단하세요.",
    ),
    (
        5432,
        "high",
        "PostgreSQL — DB 가 직접 노출됩니다",
        "DB 포트를 사내망으로만 열고 pg_hba.conf 에서 신뢰(trust) 인증을 제거하고 SCRAM/SCRAM-SHA-256 만 사용하세요.",
    ),
    (
        5900,
        "high",
        "VNC — 원격 프레임버퍼가 평문으로 노출됩니다",
        "VNC 를 VPN 뒤에서만 사용하고, 암호화된 변형(x11vnc -ssl / Apple 표준 VNC) 을 사용하세요.",
    ),
    (
        5984,
        "medium",
        "CouchDB — 관리자 API 가 비인증으로 열릴 수 있습니다",
        "admin 파티션 계정을 생성하고 CouchDB 를 내부망에만 노출하세요.",
    ),
    (
        6379,
        "critical",
        "Redis — 비인증 접근 시 데이터 유출·원격 명령·암호화 키 탈취가 가능합니다",
        "Redis 에 requirepass(인증) 와 protected-mode 를 켜고, 바인드 주소를 사내 주소로 제한하세요. \
         6379 포트는 절대 인터넷에 노출하지 마세요.",
    ),
    (
        6443,
        "medium",
        "Kubernetes API 서버 — 클러스터 제어_plane 이 노출됩니다",
        "API 서버를 사내망/VPN 에만 노출하고, 인증서 기반 인증(mTLS) 과 RBAC 를 강제하세요.",
    ),
    (
        9000,
        "high",
        "관리 콘솔/프로시 포트 (FastAPI·PHP-FPM 등) — 관리 인터페이스가 노출될 수 있습니다",
        "해당 포트의 실제 서비스를 확인해 관리 API 를 비활성화하거나 인증을 걸고, 인터넷 노출을 차단하세요.",
    ),
    (
        9090,
        "medium",
        "관리 콘솔/프로파일러 — 내부 지표나 관리 화면이 노출됩니다",
        "프로파일러·관리 화면을 비활성화하거나 인증 뒤에 두고 내부망으로만 노출하세요.",
    ),
    (
        9200,
        "critical",
        "Elasticsearch — 비인증 인덱스 조회·데이터 유출이 가능합니다",
        "인증(기본 계정/X-Pack)과 TLS 를 활성화하고, 9200 포트를 사내망으로만 열며 샘플 데이터 접근을 제한하세요.",
    ),
    (
        11211,
        "critical",
        "Memcached — 비인증 읽기/쓰기와 DDoS 증폭에 악용됩니다",
        "Memcached 를 사내망에만 바인드하고, 네트워크 ACL 과 방화벽으로 외부 접근을 차단하세요. \
         UDP 11211 도 함께 차단하세요.",
    ),
    (
        15672,
        "high",
        "RabbitMQ 관리 콘솔 — 큐·계정 관리가 노출됩니다",
        "관리 콘솔을 내부망에서만 열고 기본 게스트 계정을 삭제하며 TLS 를 적용하세요.",
    ),
    (
        27017,
        "critical",
        "MongoDB — 비인증 접근 시 데이터 유출·삭제가 가능합니다",
        "MongoDB 에 인증을 활성화하고 TLS 를 적용하며, 27017 포트를 사내망으로만 노출하세요.",
    ),
    (
        27018,
        "critical",
        "MongoDB (샤드 구성) — 비인증 접근 시 데이터 유출·삭제가 가능합니다",
        "MongoDB 에 인증을 활성화하고 TLS 를 적용하며, 샤드 포트도 사내망으로만 노출하세요.",
    ),
    (
        4444,
        "critical",
        "리버스 셸/악성코드 기본 포트 — 침해 흔적으로 볼 수 있습니다",
        "해당 포트의 프로세스를 즉시 확인하고 격리하세요. 필요하면 방화벽에서 차단하고 침해 경로(point of entry)를 \
         함께 점검하세요.",
    ),
];

/// 위험 포트 → 설명. 위험 포트가 아니면 `None`.
pub fn sensitive_port(port: u16) -> Option<&'static str> {
    SENSITIVE_PORTS.iter().find(|(p, _, _, _)| *p == port).map(|(_, _, desc, _)| *desc)
}

/// 위험 포트 → 심각도.
fn sensitive_severity(port: u16) -> Option<&'static str> {
    SENSITIVE_PORTS.iter().find(|(p, _, _, _)| *p == port).map(|(_, sev, _, _)| *sev)
}

/// 위험 포트 → 보완 조언(한국어).
fn sensitive_remediation(port: u16) -> Option<&'static str> {
    SENSITIVE_PORTS.iter().find(|(p, _, _, _)| *p == port).map(|(_, _, _, rem)| *rem)
}

// ───────────────────────────── 포트/호스트 파싱 ─────────────────────────────

/// 포트 1개 파싱 (1~65535).
fn parse_single_port(raw: &str) -> Result<u16, String> {
    let v: u16 = raw
        .trim()
        .parse()
        .map_err(|_| format!("포트를 해석할 수 없습니다: {raw}"))?;
    if v == 0 {
        return Err("포트 0 은 사용할 수 없습니다.".into());
    }
    Ok(v)
}

/// 포트 목록 파싱 — `"80,443,8000-8100,22"` → 오름차순 정렬·중복 제거된 목록.
///
/// 범위는 양 끝을 포함한다. 잘못된 항목이 하나라도 있으면 전체가 에러다.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut set: BTreeSet<u16> = BTreeSet::new();
    for raw in spec.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        if let Some((a, b)) = item.split_once('-') {
            let start = parse_single_port(a)?;
            let end = parse_single_port(b)?;
            if start > end {
                return Err(format!("포트 범위의 시작({start})이 끝({end})보다 큽니다: {item}"));
            }
            for p in start..=end {
                set.insert(p);
            }
        } else {
            set.insert(parse_single_port(item)?);
        }
    }
    if set.is_empty() {
        return Err("포트 목록이 비어 있습니다.".into());
    }
    Ok(set.into_iter().collect())
}

/// 자주 쓰이는 상위 포트 목록 (기본 스캔 대상).
pub fn default_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443, 445, 465, 587, 993, 1433, 1521, 1723, 2049,
        2181, 2375, 3000, 3306, 3389, 4444, 5000, 5432, 5900, 5984, 6379, 6443, 8000, 8080, 8081, 8088,
        8443, 8888, 9000, 9090, 9200, 9300, 11211, 15672, 27017, 27018,
    ]
}

/// CIDR 1건을 호스트 목록으로 펼친다.
fn expand_cidr(spec: &str) -> Result<Vec<String>, String> {
    let (addr, bits) = spec
        .split_once('/')
        .ok_or_else(|| format!("CIDR 형식이 아닙니다: {spec}"))?;
    let ip: IpAddr = addr
        .trim()
        .parse()
        .map_err(|_| format!("IP 주소를 해석할 수 없습니다: {addr}"))?;
    let bits: u32 = bits
        .trim()
        .parse()
        .map_err(|_| format!("CIDR 비트 수가 올바르지 않습니다: {bits}"))?;

    match ip {
        IpAddr::V4(v4) => {
            if bits > 32 {
                return Err(format!("CIDR 비트 수 {bits} 가 32 를 넘습니다: {spec}"));
            }
            // 규모 상한 — IPv4 는 /24 까지만 허용한다.
            if bits < 24 {
                return Err(format!(
                    "스캔 규모 상한 초과: IPv4 CIDR 는 /24 이상만 허용합니다 ({spec})."
                ));
            }
            let count: u64 = 1u64 << (32 - bits);
            if count > MAX_CIDR_HOSTS as u64 {
                return Err(format!("스캔 규모 상한 초과: {spec} ({}개).", count));
            }
            let mask = u32::MAX << (32 - bits);
            let start = u32::from(v4) & mask;
            let mut out = Vec::with_capacity(count as usize);
            for i in 0..count {
                let addr = start
                    .checked_add(i as u32)
                    .ok_or_else(|| format!("CIDR 범위 계산이 넘쳤습니다: {spec}"))?;
                out.push(IpAddr::V4(Ipv4Addr::from(addr)).to_string());
            }
            Ok(out)
        }
        IpAddr::V6(v6) => {
            if bits > 128 {
                return Err(format!("CIDR 비트 수 {bits} 가 128 를 넘습니다: {spec}"));
            }
            // 규모 상한 — IPv6 는 /120 까지만 허용한다.
            if bits < 120 {
                return Err(format!(
                    "스캔 규모 상한 초과: IPv6 CIDR 는 /120 이상만 허용합니다 ({spec})."
                ));
            }
            let count: u128 = 1u128 << (128 - bits);
            if count > MAX_CIDR_HOSTS as u128 {
                return Err(format!("스캔 규모 상한 초과: {spec} ({}개).", count));
            }
            let mask = u128::MAX << (128 - bits);
            let start = u128::from(v6) & mask;
            let mut out = Vec::with_capacity(count as usize);
            for i in 0..count {
                let addr = start
                    .checked_add(i)
                    .ok_or_else(|| format!("CIDR 범위 계산이 넘쳤습니다: {spec}"))?;
                out.push(IpAddr::V6(Ipv6Addr::from(addr)).to_string());
            }
            Ok(out)
        }
    }
}

/// 대상 문자열을 호스트 목록으로 확장 — `"10.0.0.0/24"`, `"host"`, `"a,b"` 를 모두 받는다.
///
/// CIDR 은 IPv4 /24, IPv6 /120 까지만 허용하며(그보다 넓으면 에러), 결과는 중복 제거된다.
pub fn expand_hosts(spec: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for raw in spec.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        if item.contains('/') {
            for h in expand_cidr(item)? {
                if seen.insert(h.clone()) {
                    out.push(h);
                }
            }
        } else {
            if item.chars().any(char::is_whitespace) {
                return Err(format!("호스트에 공백이 들어갈 수 없습니다: {item}"));
            }
            if seen.insert(item.to_string()) {
                out.push(item.to_string());
            }
        }
    }
    if out.is_empty() {
        return Err("대상 호스트가 비어 있습니다.".into());
    }
    Ok(out)
}

// ───────────────────────────── 서비스 식별 ─────────────────────────────

/// 배너 패턴 규칙.
struct BannerRule {
    /// 이 규칙이 식별한 서비스 이름.
    service: &'static str,
    /// 매칭 정규식 — 명명 그룹 `product` / `version` 을 쓸 수 있다.
    pattern: &'static str,
    /// `product` 그룹이 없을 때 사용할 고정 제품명.
    product_literal: Option<&'static str>,
}

/// 배너 패턴 표.
///
/// `src/signals.rs` 의 신호 표와 같은 형태다. 정규식에 `product` / `version` 명명 그룹이
/// 있으면 그대로 추출하고, 없으면 `product_literal` 을 쓴다.
const BANNER_RULES: &[BannerRule] = &[
    // ── SSH ──
    BannerRule {
        service: "ssh",
        pattern: r"(?im)^SSH-\d+\.\d+-(?P<product>[A-Za-z][A-Za-z.\-_]*)(?P<version>\d[\w.]*)?",
        product_literal: None,
    },
    // ── FTP ──
    BannerRule {
        service: "ftp",
        pattern: r"(?im)^220[ \t\-][^\r\n]*?\b(?P<product>(?:vsftpd|proftpd|pure-ftpd|filezilla server|msftpd|serv-u|wu-ftpd))\s+(?P<version>\d+(?:\.\d+)*)",
        product_literal: None,
    },
    // ── SMTP ──
    BannerRule {
        service: "smtp",
        pattern: r"(?im)^220[ \t][^\r\n]*?\b(?P<product>(?:postfix|exim|sendmail|microsoft esmtp|qmail|smtpd))(?:\s+(?P<version>[\d.]+))?",
        product_literal: None,
    },
    // ── IMAP ──
    BannerRule {
        service: "imap",
        pattern: r"(?im)^\*\s+OK[^\r\n]*?\b(?P<product>(?:dovecot|courier|zimbra|uw-imap))",
        product_literal: None,
    },
    BannerRule {
        service: "imap",
        pattern: r"(?im)^\*\s+OK\b",
        product_literal: None,
    },
    // ── POP3 ──
    BannerRule {
        service: "pop3",
        pattern: r"(?im)^\+OK[^\r\n]*?\b(?P<product>(?:dovecot|courier))",
        product_literal: None,
    },
    // ── MySQL / MariaDB ──
    BannerRule {
        service: "mysql",
        pattern: r"(?i)(?P<product>mysql)[^0-9\r\n]{0,12}(?P<version>\d+(?:\.\d+){1,3})",
        product_literal: None,
    },
    BannerRule {
        service: "mysql",
        pattern: r"(?s)^\x0a(?P<version>\d+(?:\.\d+){1,3})",
        product_literal: Some("MySQL"),
    },
    BannerRule {
        service: "mysql",
        pattern: r"(?i)mariadb[^0-9\r\n]{0,12}(?P<version>\d+(?:\.\d+){1,3})",
        product_literal: Some("MariaDB"),
    },
    // ── PostgreSQL ──
    BannerRule {
        service: "postgresql",
        pattern: r"(?i)(?P<product>postgresql)[^0-9\r\n]{0,8}(?P<version>\d+(?:\.\d+)*)",
        product_literal: None,
    },
    // ── Redis ──
    BannerRule {
        service: "redis",
        pattern: r"(?im)^redis_version:(?P<version>[\d.]+)",
        product_literal: Some("Redis"),
    },
    BannerRule {
        service: "redis",
        pattern: r"(?im)^(?:[-+](?:PONG|ERR|NOAUTH|WRONGPASS|NOPERM))",
        product_literal: Some("Redis"),
    },
    // ── MongoDB ──
    BannerRule {
        service: "mongodb",
        pattern: r"(?i)mongod(?:b)?[^0-9\r\n]{0,12}(?P<version>\d+(?:\.\d+){1,3})",
        product_literal: Some("MongoDB"),
    },
    BannerRule {
        service: "mongodb",
        pattern: r#"(?i)"version"\s*:\s*"(?P<version>[\d.]+)""#,
        product_literal: Some("MongoDB"),
    },
    // ── Elasticsearch ──
    BannerRule {
        service: "elasticsearch",
        pattern: r#"(?i)"number"\s*:\s*"(?P<version>[\d.]+)""#,
        product_literal: Some("Elasticsearch"),
    },
    BannerRule {
        service: "elasticsearch",
        pattern: r"(?i)elasticsearch[^0-9\r\n]{0,8}(?P<version>\d+(?:\.\d+){1,3})",
        product_literal: Some("Elasticsearch"),
    },
    // ── Docker API ──
    BannerRule {
        service: "docker",
        pattern: r#"(?i)"ApiVersion"\s*:\s*"(?P<version>[\d.]+)""#,
        product_literal: Some("Docker"),
    },
    BannerRule {
        service: "docker",
        pattern: r#"(?i)"Version"\s*:\s*"(?P<version>[\d.]+)""#,
        product_literal: Some("Docker"),
    },
    // ── HTTP ──
    BannerRule {
        service: "http",
        pattern: r"(?im)^HTTP/\d(?:\.\d)?\s+\d{3}",
        product_literal: None,
    },
    BannerRule {
        service: "http",
        pattern: r"(?im)^server:\s*(?P<product>microsoft-iis)(?:/)?(?P<version>[\w.\-]+)?",
        product_literal: None,
    },
    BannerRule {
        service: "http",
        pattern: r"(?im)^x-powered-by:\s*(?P<product>php)(?:/)?(?P<version>[\w.\-]+)?",
        product_literal: None,
    },
    BannerRule {
        service: "http",
        pattern: r"(?im)^server:\s*(?P<product>[A-Za-z][A-Za-z0-9.\-_]*)(?:/)?(?P<version>[\w.\-]+)?",
        product_literal: None,
    },
    // ── Memcached ──
    BannerRule {
        service: "memcached",
        pattern: r"(?im)^VERSION\s+(?P<version>[\d.]+)",
        product_literal: Some("memcached"),
    },
    // ── Microsoft SQL Server ──
    BannerRule {
        service: "mssql",
        pattern: r"(?i)(?P<product>microsoft sql server)[^0-9\r\n]{0,8}(?P<version>[\d.]+)?",
        product_literal: None,
    },
    // ── Oracle ──
    BannerRule {
        service: "oracle",
        pattern: r"(?i)\(VERSION=(?P<version>[\d.]+)\)",
        product_literal: Some("Oracle Database"),
    },
    // ── ZooKeeper ──
    BannerRule {
        service: "zookeeper",
        pattern: r"(?i)zookeeper[^0-9\r\n]{0,12}(?P<version>\d+(?:\.\d+)*)",
        product_literal: Some("ZooKeeper"),
    },
    // ── AMQP (RabbitMQ) ──
    BannerRule {
        service: "amqp",
        pattern: r"(?s)^AMQP",
        product_literal: Some("RabbitMQ"),
    },
    // ── LDAP ──
    BannerRule {
        service: "ldap",
        pattern: r"(?i)openldap[^0-9\r\n]{0,8}(?P<version>[\d.]+)?",
        product_literal: Some("OpenLDAP"),
    },
    // ── SMB ──
    BannerRule {
        service: "smb",
        pattern: r"(?s)^\xfeSMB",
        product_literal: Some("SMB"),
    },
    // ── NFS ──
    BannerRule {
        service: "nfs",
        pattern: r"(?i)nfs\s*v?(?P<version>[\d.]+)",
        product_literal: Some("NFS"),
    },
    // ── RDP (TPKT) ──
    BannerRule {
        service: "rdp",
        pattern: r"(?s)^\x03\x00",
        product_literal: Some("RDP"),
    },
    // ── VNC (RFB) ──
    BannerRule {
        service: "vnc",
        pattern: r"(?im)^RFB\s*(?P<version>\d{3}\.\d{3})",
        product_literal: Some("VNC"),
    },
    // ── Telnet (IAC) ──
    BannerRule {
        service: "telnet",
        pattern: r"(?s)^\xff[\xfb-\xfe]",
        product_literal: Some("Telnet"),
    },
    // ── rsync ──
    BannerRule {
        service: "rsync",
        pattern: r"(?im)^@RSYNCD:\s*(?P<version>[\d.]+)",
        product_literal: Some("rsync"),
    },
    // ── SIP ──
    BannerRule {
        service: "sip",
        pattern: r"(?im)^SIP/2\.0\s+\d{3}",
        product_literal: None,
    },
    // ── IRC ──
    BannerRule {
        service: "irc",
        pattern: r"(?im)^:[A-Za-z0-9_\-]+ (?:001|002|003)\b",
        product_literal: None,
    },
    // ── Git ──
    BannerRule {
        service: "git",
        pattern: r"(?im)^git-(?:upload|receive)-pack",
        product_literal: Some("Git"),
    },
    // ── etcd ──
    BannerRule {
        service: "etcd",
        pattern: r#"(?i)"etcdserver""#,
        product_literal: Some("etcd"),
    },
    // ── CouchDB ──
    BannerRule {
        service: "couchdb",
        pattern: r#"(?i)"couchdb""#,
        product_literal: Some("CouchDB"),
    },
    // ── ActiveMQ ──
    BannerRule {
        service: "activemq",
        pattern: r#"(?i)"activemq""#,
        product_literal: Some("ActiveMQ"),
    },
    // ── Squid ──
    BannerRule {
        service: "squid",
        pattern: r"(?im)^HTTP/\d\.\d\s+\d{3}[^\r\n]*squid",
        product_literal: Some("Squid"),
    },
];

/// 정규식 테이블(컴파일 캐시).
fn compiled_rules() -> &'static Vec<(&'static BannerRule, Regex)> {
    static CELL: OnceLock<Vec<(&'static BannerRule, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        BANNER_RULES
            .iter()
            .filter_map(|rule| Regex::new(rule.pattern).ok().map(|re| (rule, re)))
            .collect()
    })
}

/// 포트만으로 알 수 있는 기본 서비스 이름.
fn port_service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios",
        143 => "imap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        587 => "submission",
        631 => "cups",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        2049 => "nfs",
        2181 => "zookeeper",
        2375 => "docker",
        3000 | 3128 | 5000 | 5911 | 7001 | 8000 | 8001 | 8008 | 8080 | 8081 | 8088 | 8888 => "http",
        3306 => "mysql",
        3389 => "rdp",
        4444 => "unknown",
        5432 => "postgresql",
        5555 => "adb",
        5900 => "vnc",
        5984 => "couchdb",
        6379 => "redis",
        6443 => "kubernetes",
        8443 => "https",
        9000 => "unknown",
        9090 => "unknown",
        9200 | 9300 => "elasticsearch",
        11211 => "memcached",
        15672 => "rabbitmq",
        27017 | 27018 | 28017 => "mongodb",
        _ => "unknown",
    }
}

/// 배너에서 아주 약한 OS 힌트를 뽑는다 (단정하지 않는다).
///
/// 예: IIS 헤더 → "Windows(가능성)", Apache+PHP → "Linux(가능성)".
pub fn os_hints_from_banner(banner: &str) -> Vec<String> {
    let lower = banner.to_ascii_lowercase();
    let mut out: Vec<String> = Vec::new();
    if lower.contains("microsoft-iis")
        || lower.contains("windows nt")
        || lower.contains("x-windows")
        || lower.contains("win32")
    {
        out.push("Windows(가능성)".to_string());
    }
    if lower.contains("ubuntu")
        || lower.contains("debian")
        || lower.contains("centos")
        || lower.contains("freebsd")
        || lower.contains("linux")
        || (lower.contains("apache") && lower.contains("php"))
    {
        out.push("Linux(가능성)".to_string());
    }
    if lower.contains("darwin") || lower.contains("macos") || lower.contains("mac os") {
        out.push("macOS(가능성)".to_string());
    }
    if lower.contains("freebsd") || lower.contains("openbsd") {
        out.push("BSD(가능성)".to_string());
    }
    out
}

/// 포트와 배너로 서비스를 식별한다.
///
/// (a) 포트 기반 기본 매핑 + (b) 배너 패턴 매칭을 함께 쓴다.
/// 배너가 있는데 어떤 패턴에도 걸리지 않으면 이름은 "unknown" 이다.
pub fn identify_service(port: u16, banner: &str) -> ServiceInfo {
    let mut name_rule: Option<&'static BannerRule> = None;
    let mut detail: Option<(&'static BannerRule, Option<String>, Option<String>)> = None;

    for (rule, re) in compiled_rules() {
        let Some(caps) = re.captures(banner) else { continue };
        if name_rule.is_none() {
            name_rule = Some(rule);
        }
        let product = caps
            .name("product")
            .map(|m| m.as_str().trim().trim_end_matches(['_', '.', '-']).to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| rule.product_literal.map(|s| s.to_string()));
        let version = caps
            .name("version")
            .map(|m| m.as_str().trim().to_string())
            .filter(|s| !s.is_empty());
        if product.is_some() || version.is_some() {
            detail = Some((rule, product, version));
            break;
        }
    }

    let (name, product, version) = if let Some((rule, p, v)) = detail {
        (rule.service.to_string(), p, v)
    } else if let Some(rule) = name_rule {
        (rule.service.to_string(), rule.product_literal.map(|s| s.to_string()), None)
    } else if banner.trim().is_empty() {
        (port_service_name(port).to_string(), None, None)
    } else {
        ("unknown".to_string(), None, None)
    };

    let banner_out = if banner.trim().is_empty() {
        None
    } else {
        Some(banner.chars().take(MAX_BANNER_LEN).collect())
    };

    ServiceInfo { name, product, version, banner: banner_out }
}

// ───────────────────────────── 스캔 ─────────────────────────────

/// 포트 1건의 스캔 결과(내부용).
enum ProbeOutcome {
    /// 실제 연결을 시도했다.
    Done(PortResult),
    /// 인가 게이트에 막혀 스킵했다.
    Skipped,
}

/// 스캔 중 수집되는 상태 (호스트별 결과 · 스킵 목록).
#[derive(Default)]
struct ScanState {
    results: Vec<(String, u16, ProbeOutcome)>,
    skipped_hosts: Vec<String>,
}

/// 프로토콜별로 보낼 프로브 바이트.
fn probe_bytes(port: u16, host: &str) -> Option<String> {
    let http_req = format!("GET / HTTP/1.0\r\nHost: {host}\r\n\r\n");
    if HTTP_PORTS.contains(&port) {
        return Some(http_req);
    }
    match port {
        2375 => Some(format!("GET /version HTTP/1.0\r\nHost: {host}\r\n\r\n")),
        9200 | 9300 => Some(http_req),
        6379 => Some("PING\r\n".to_string()),
        27017 => Some("ismaster\r\n".to_string()),
        11211 => Some("version\r\n".to_string()),
        _ => None,
    }
}

/// 프로토콜이 특화되지 않은 포트에도 HTTP 프로브를 한 번 시도한다.
///
/// 표준 포트가 아닌(8080·8099·3000 등) 웹 서비스는 매우 흔하다.
/// 한 번의 `GET /` 는 무해하므로, 응답이 HTTP 로 시작하면 http 로 식별한다.
///
/// 단, 배너를 **먼저 보내는** 프로토콜(SSH·SMTP·IMAP 등) 에는 HTTP 프로브를 보내지 않는다.
const GENERIC_HTTP_PROBE: bool = true;

/// 서버가 배너를 먼저 보내는 프로토콜의 포트.
const TEXT_PROTOCOL_PORTS: &[u16] = &[
    21, 22, 23, 25, 110, 143, 465, 587, 993, 995, // ftp·ssh·telnet·smtp·imap·pop3
    1433, 1521, 2049, 3306, 5432, 6379, 9200, 11211, 27017, // DB·캐시
];

/// 소켓에서 배너를 읽는다 (타임아웃이 나면 지금까지 받은 것을 살려서 반환).
async fn read_banner(stream: &mut tokio::net::TcpStream, max: usize, timeout: Duration) -> Option<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut out: Vec<u8> = Vec::with_capacity(max.min(1024));
    let mut buf = [0u8; 1024];
    while out.len() < max {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&out).to_string())
    }
}

/// 열린 포트에서 배너를 수집한다. 실패하면 `None` (스캔은 계속된다).
async fn grab_banner(stream: &mut tokio::net::TcpStream, port: u16, host: &str) -> Option<String> {
    if let Some(probe) = probe_bytes(port, host) {
        if stream.write_all(probe.as_bytes()).await.is_err() {
            return None;
        }
        let _ = stream.flush().await;
        let max = if HTTP_PORTS.contains(&port) { HTTP_BANNER_MAX } else { TEXT_BANNER_MAX };
        return read_banner(stream, max, BANNER_READ_TIMEOUT).await;
    }
    // 프로토콜 미상 포트 — HTTP 프로브를 한 번 시도한다.
    if GENERIC_HTTP_PROBE && !TEXT_PROTOCOL_PORTS.contains(&port) {
        let probe = format!("GET / HTTP/1.0\r\nHost: {host}\r\n\r\n");
        if stream.write_all(probe.as_bytes()).await.is_ok() {
            let _ = stream.flush().await;
            // 한 번만 읽는다 — 첫 응답이 HTTP 가 아니어도 그것이 배너일 수 있다.
            return read_banner(stream, HTTP_BANNER_MAX, BANNER_READ_TIMEOUT).await;
        }
    }
    // 소켓이 배너를 먼저 보내는 프로토콜(SSH·SMTP·IMAP 등) — 소리 없이 읽는다.
    read_banner(stream, TEXT_BANNER_MAX, BANNER_READ_TIMEOUT).await
}

/// 포트 1건 조사 — 인가 검사 → 연결 → (선택) 배너 수집.
async fn probe_port(
    auth: &Authorization,
    host: &str,
    port: u16,
    timeout: Duration,
    grab: bool,
    sem: &tokio::sync::Semaphore,
) -> ProbeOutcome {
    // 1) 인가 게이트 — 포트마다 검사한다. 막힌 포트는 "스킵"으로 기록한다.
    if auth.check(host, Some(port)).is_err() {
        return ProbeOutcome::Skipped;
    }

    // 2) 동시성 제한.
    let Ok(_permit) = sem.acquire().await else {
        return ProbeOutcome::Skipped;
    };

    let started = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port))).await {
        // 3) 연결 성공 → open.
        Ok(Ok(mut stream)) => {
            let banner = if grab { grab_banner(&mut stream, port, host).await } else { None };
            let service = identify_service(port, banner.as_deref().unwrap_or(""));
            ProbeOutcome::Done(PortResult {
                port,
                state: PortState::Open,
                service: Some(service),
                elapsed_ms: started.elapsed().as_millis() as u64,
            })
        }
        // 4) 연결 거부 → closed, 그 밖 오류 → filtered.
        Ok(Err(e)) => {
            let state = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PortState::Closed
            } else {
                PortState::Filtered
            };
            ProbeOutcome::Done(PortResult {
                port,
                state,
                service: None,
                elapsed_ms: started.elapsed().as_millis() as u64,
            })
        }
        // 5) 타임아웃 → filtered.
        Err(_) => ProbeOutcome::Done(PortResult {
            port,
            state: PortState::Filtered,
            service: None,
            elapsed_ms: started.elapsed().as_millis() as u64,
        }),
    }
}

/// 전체 스캔 시간 상한 계산 (부분 결과를 되돌려주기 위한 예산).
fn overall_budget(timeout: Duration, jobs: usize, concurrency: usize) -> Duration {
    let rounds = jobs.div_ceil(concurrency.max(1)) as u64;
    let per_round = timeout.as_millis() as u64 + 800;
    let ms = per_round.saturating_mul(rounds).saturating_add(5_000);
    Duration::from_millis(ms.min(3_600_000))
}

/// TCP connect scan 실행.
///
/// - 인가 게이트는 포트마다 검사하며, 인가 밖 포트는 스킵 기록만 남긴다.
/// - 시간 초과가 나면 **부분 결과**를 돌려준다(에러로 끝내지 않는다).
/// - 규모 상한(`hosts × ports > 20 000`)을 넘으면 에러로 시작을 막는다.
pub async fn scan(auth: &Authorization, plan: &ScanPlan) -> Result<ScanReport, String> {
    let started = Instant::now();

    // 0) 인가 유효기간 — 만료됐으면 조용히 빈 리포트를 만들지 않고 확실히 실패한다.
    auth.check_period().map_err(|e| format!("인가를 통과하지 못했습니다: {e}"))?;

    // 1) 대상 호스트 정리 (CIDR 문자열은 자동 확장).
    let mut hosts: Vec<String> = Vec::new();
    let mut seen_hosts: BTreeSet<String> = BTreeSet::new();
    for raw in &plan.hosts {
        let expanded = if raw.contains('/') { expand_hosts(raw)? } else { vec![raw.trim().to_string()] };
        for h in expanded {
            if h.is_empty() {
                continue;
            }
            if seen_hosts.insert(h.clone()) {
                hosts.push(h);
            }
        }
    }
    if hosts.is_empty() {
        return Err("스캔 대상 호스트가 없습니다.".into());
    }

    // 2) 호스트 수 상한.
    let mut host_capped = false;
    if plan.max_hosts > 0 && hosts.len() > plan.max_hosts {
        hosts.truncate(plan.max_hosts);
        host_capped = true;
    }

    // 3) 대상 포트.
    let ports: Vec<u16> = if plan.ports.is_empty() {
        default_ports()
    } else {
        let mut set: BTreeSet<u16> = BTreeSet::new();
        for p in &plan.ports {
            if *p > 0 {
                set.insert(*p);
            }
        }
        set.into_iter().collect()
    };
    if ports.is_empty() {
        return Err("스캔 대상 포트가 없습니다.".into());
    }

    // 4) 규모 상한.
    let total = hosts.len().saturating_mul(ports.len());
    if total > MAX_SCAN_TARGETS {
        return Err(format!(
            "스캔 규모 상한 초과: {}대 × {}포트 = {} (최대 {}). \
             호스트·포트 범위를 줄이거나 여러 번 나눠 점검하세요.",
            hosts.len(),
            ports.len(),
            total,
            MAX_SCAN_TARGETS
        ));
    }

    // 5) 호스트 단위 인가 검사 — 막힌 호스트는 스캔하지 않는다(스킵 기록).
    let state = Arc::new(parking_lot::Mutex::new(ScanState::default()));
    let mut scan_hosts: Vec<String> = Vec::new();
    for h in &hosts {
        if auth.check(h, None).is_ok() {
            scan_hosts.push(h.clone());
        } else {
            state.lock().skipped_hosts.push(h.clone());
        }
    }

    // 6) 설정 정규화.
    let concurrency = if plan.concurrency == 0 {
        DEFAULT_CONCURRENCY
    } else {
        plan.concurrency
    }
    .clamp(1, MAX_CONCURRENCY);
    let timeout = Duration::from_millis(if plan.timeout_ms == 0 {
        DEFAULT_TIMEOUT_MS
    } else {
        plan.timeout_ms
    });

    // 7) 작업 목록.
    let mut jobs: Vec<(String, u16)> = Vec::with_capacity(scan_hosts.len() * ports.len());
    for h in &scan_hosts {
        for p in &ports {
            jobs.push((h.clone(), *p));
        }
    }

    // 8) 실행 — 동시성 제한(Semaphore) + 전체 시간 상한. 상한을 넘으면 부분 결과를 낸다.
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let budget = overall_budget(timeout, jobs.len(), concurrency);
    let deadline = tokio::time::Instant::now() + budget;
    let grab = plan.grab_banner;

    let stream = futures::stream::iter(jobs)
        .map(|job| {
            let sem = sem.clone();
            let state = state.clone();
            async move {
                let outcome = probe_port(auth, &job.0, job.1, timeout, grab, &sem).await;
                state.lock().results.push((job.0, job.1, outcome));
            }
        })
        .buffer_unordered(concurrency);

    let mut stream = Box::pin(stream);
    loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(())) => continue,
            Ok(None) => break,
            Err(_) => break, // 전체 시간 초과 → 부분 결과로 마무리
        }
    }

    // 9) 결과 정리.
    let (results, skipped_hosts) = {
        let mut st = state.lock();
        (std::mem::take(&mut st.results), std::mem::take(&mut st.skipped_hosts))
    };

    let mut host_map: BTreeMap<String, HostResult> = BTreeMap::new();
    let mut skipped_ports: BTreeMap<String, Vec<u16>> = BTreeMap::new();
    let mut scanned: u64 = 0;
    let mut open: u64 = 0;

    for (host, port, outcome) in results {
        let entry = host_map.entry(host.clone()).or_insert_with(|| HostResult {
            host: host.clone(),
            alive: false,
            ports: Vec::new(),
            os_hints: Vec::new(),
        });
        match outcome {
            ProbeOutcome::Done(pr) => {
                scanned += 1;
                if pr.state == PortState::Open {
                    open += 1;
                    entry.alive = true;
                    if let Some(ServiceInfo { banner: Some(banner), .. }) = &pr.service {
                        for hint in os_hints_from_banner(banner) {
                            if !entry.os_hints.contains(&hint) {
                                entry.os_hints.push(hint);
                            }
                        }
                    }
                }
                entry.ports.push(pr);
            }
            ProbeOutcome::Skipped => {
                skipped_ports.entry(host).or_default().push(port);
            }
        }
    }

    for entry in host_map.values_mut() {
        entry.ports.sort_by_key(|p| p.port);
    }

    // 10) Findings — 열린 포트 자체는 Finding 이 아니다. 위험 서비스만 만든다.
    let mut findings: Vec<Finding> = Vec::new();
    for entry in host_map.values() {
        for pr in &entry.ports {
            if pr.state != PortState::Open {
                continue;
            }
            let Some(desc) = sensitive_port(pr.port) else { continue };
            let severity = sensitive_severity(pr.port).unwrap_or("medium");
            let remediation = sensitive_remediation(pr.port).unwrap_or(
                "해당 서비스를 외부에 노출하지 말고 사내망·인증·암호화 behind 로 옮기세요.",
            );
            let mut evidence = format!("{}:{} 포트가 열려 있습니다. (위험 서비스: {desc})", entry.host, pr.port);
            if let Some(svc) = &pr.service {
                evidence.push_str(&format!("\n서비스: {}", svc.name));
                if let Some(p) = &svc.product {
                    evidence.push_str(&format!(", 제품: {p}"));
                }
                if let Some(v) = &svc.version {
                    evidence.push_str(&format!(", 버전: {v}"));
                }
                if let Some(b) = &svc.banner {
                    evidence.push_str(&format!("\n배너: {b}"));
                }
            }
            findings.push(Finding {
                title: format!("노출된 위험 서비스 — {desc}"),
                severity: severity.to_string(),
                category: "exposed_service".to_string(),
                target: format!("{}:{}", entry.host, pr.port),
                evidence: evidence.chars().take(1200).collect(),
                reproduction: format!("nc -v {} {}", entry.host, pr.port),
                remediation: remediation.to_string(),
            });
        }
    }

    // 스킵 기록 — 인가 밖 포트/호스트가 있었다면 낮은 심각도로 남긴다.
    if !skipped_ports.is_empty() || !skipped_hosts.is_empty() {
        let mut evidence = String::new();
        for (host, ports) in &skipped_ports {
            let list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
            evidence.push_str(&format!("{host}: {} 포트 스킵\n", list.join(", ")));
        }
        for host in &skipped_hosts {
            evidence.push_str(&format!("{host}: 호스트 자체가 인가 범위 밖이라 스킵\n"));
        }
        if host_capped {
            evidence.push_str(&format!("호스트 수 상한({})에 걸려 대상이 잘렸습니다.\n", plan.max_hosts));
        }
        findings.push(Finding {
            title: "인가 범위 밖 포트/호스트 스킵".to_string(),
            severity: "low".to_string(),
            category: "scan_skipped".to_string(),
            target: "scan".to_string(),
            evidence: evidence.chars().take(1200).collect(),
            reproduction: "nc -v <host> <port>  # 인가 추가 후 재점검".to_string(),
            remediation: "인가 파일의 ports.allow_tcp 에 필요한 포트를 추가하거나, 점검 대상 포트를 줄여 \
                         인가 범위 안에서만 재점검하세요."
                .to_string(),
        });
    }

    crate::report::sort_findings(&mut findings);

    Ok(ScanReport {
        hosts: host_map.into_values().collect(),
        scanned,
        open,
        duration_ms: started.elapsed().as_millis() as u64,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_sorts_and_dedups() {
        let ports = parse_ports("443,80,8000-8010,80,22").unwrap();
        assert_eq!(ports[0], 22);
        assert_eq!(ports[1], 80);
        assert_eq!(ports[2], 443);
        assert_eq!(ports.len(), 3 + 11);
        assert!(ports.windows(2).all(|w| w[0] < w[1]), "{ports:?}");
    }

    #[test]
    fn parse_ports_rejects_invalid_input() {
        assert!(parse_ports("http").is_err());
        assert!(parse_ports("80-").is_err());
        assert!(parse_ports("100-80").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("").is_err());
    }

    #[test]
    fn expand_hosts_handles_single_and_cidr() {
        assert_eq!(expand_hosts("127.0.0.1").unwrap(), vec!["127.0.0.1".to_string()]);
        let four = expand_hosts("10.0.0.0/30").unwrap();
        assert_eq!(four.len(), 4);
        assert_eq!(four[0], "10.0.0.0");
        assert_eq!(four[3], "10.0.0.3");
        let two = expand_hosts("a.example.com, b.example.com ,a.example.com").unwrap();
        assert_eq!(two.len(), 2);
        assert_eq!(expand_hosts("10.0.0.0/24").unwrap().len(), 256);
    }

    #[test]
    fn expand_hosts_rejects_wide_cidr() {
        assert!(expand_hosts("10.0.0.0/16").is_err());
        assert!(expand_hosts("10.0.0.0/8").is_err());
        assert!(expand_hosts("2001:db8::/32").is_err());
        assert!(expand_hosts("2001:db8::/120").is_ok());
    }

    #[test]
    fn identify_service_parses_common_banners() {
        let ssh = identify_service(22, "SSH-2.0-OpenSSH_9.6\r\n");
        assert_eq!(ssh.name, "ssh");
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ssh.version.as_deref(), Some("9.6"));

        let mysql = identify_service(3306, "MySQL 8.0.36");
        assert_eq!(mysql.name, "mysql");
        assert_eq!(mysql.product.as_deref(), Some("MySQL"));
        assert_eq!(mysql.version.as_deref(), Some("8.0.36"));

        let nginx = identify_service(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n");
        assert_eq!(nginx.name, "http");
        assert_eq!(nginx.product.as_deref(), Some("nginx"));
        assert_eq!(nginx.version.as_deref(), Some("1.24.0"));

        let ftp = identify_service(21, "220 (vsFTPd 3.0.5)");
        assert_eq!(ftp.name, "ftp");
        assert_eq!(ftp.product.as_deref(), Some("vsFTPd"));
        assert_eq!(ftp.version.as_deref(), Some("3.0.5"));

        let unknown = identify_service(65000, "뭔가 모르는 배너");
        assert_eq!(unknown.name, "unknown");
        assert!(unknown.product.is_none());
    }

    #[test]
    fn identify_service_falls_back_to_port_mapping() {
        let svc = identify_service(22, "");
        assert_eq!(svc.name, "ssh");
        assert!(svc.banner.is_none());
        assert_eq!(identify_service(8080, "").name, "http");
    }

    #[test]
    fn sensitive_ports_are_classified() {
        assert!(sensitive_port(23).is_some());
        assert!(sensitive_port(6379).is_some());
        assert!(sensitive_port(443).is_none());
        assert!(sensitive_port(80).is_none());
        assert!(sensitive_port(3306).is_some());
        assert!(sensitive_port(9200).is_some());
    }

    #[test]
    fn default_ports_are_sorted_and_sane() {
        let ports = default_ports();
        assert!(ports.len() >= 40, "{}", ports.len());
        assert!(ports.windows(2).all(|w| w[0] < w[1]), "{ports:?}");
        assert!(ports.contains(&22) && ports.contains(&443));
    }

    #[test]
    fn all_banner_rules_compile() {
        assert_eq!(compiled_rules().len(), BANNER_RULES.len());
        let services: BTreeSet<&str> = BANNER_RULES.iter().map(|r| r.service).collect();
        assert!(services.len() >= 25, "서비스 패턴 {} 개뿐", services.len());
    }

    #[test]
    fn banner_is_truncated_to_512_chars() {
        let long = "A".repeat(900);
        let svc = identify_service(80, &long);
        assert_eq!(svc.banner.map(|b| b.len()), Some(MAX_BANNER_LEN));
    }

    #[test]
    fn os_hints_are_weak_claims() {
        assert_eq!(os_hints_from_banner("Server: Microsoft-IIS/10.0"), vec!["Windows(가능성)".to_string()]);
        assert_eq!(os_hints_from_banner("Server: Apache/2.4.41 X-Powered-By: PHP/7.4"), vec!["Linux(가능성)".to_string()]);
        assert!(os_hints_from_banner("HTTP/1.1 200 OK").is_empty());
    }

    /// 로컬 리스너로 TCP connect scan 이 동작하는지 확인한다.
    #[tokio::test]
    async fn scan_finds_open_local_port() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return; // 바인딩을 못 하는 환경에서는 통과시킨다.
        };
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        if port == 0 {
            return;
        }
        let auth = Authorization::parse(&format!(
            "engagement:\n  authorized_until: \"2099-12-31\"\nscope:\n  allow:\n    - host: \"127.0.0.1\"\nports:\n  allow_tcp: [{port}]\n"
        ))
        .unwrap();

        let plan = ScanPlan {
            hosts: vec!["127.0.0.1".into()],
            ports: vec![port],
            timeout_ms: 500,
            concurrency: 4,
            grab_banner: false,
            max_hosts: 0,
        };
        let report = scan(&auth, &plan).await.unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.open, 1);
        assert_eq!(report.hosts.len(), 1);
        assert!(report.hosts[0].alive);
        assert_eq!(report.hosts[0].ports[0].state, PortState::Open);
    }

    /// 열린 포트에서 배너를 수집해 서비스를 식별한다.
    #[tokio::test]
    async fn scan_grabs_banner_from_local_service() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        if port == 0 {
            return;
        }
        // 가짜 SSH 서버 — 접속하면 배너를 보내고 끊는다.
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
                let _ = sock.flush().await;
            }
        });

        let auth = Authorization::parse(&format!(
            "engagement:\n  authorized_until: \"2099-12-31\"\nscope:\n  allow:\n    - host: \"127.0.0.1\"\nports:\n  allow_tcp: [{port}]\n"
        ))
        .unwrap();
        let plan = ScanPlan {
            hosts: vec!["127.0.0.1".into()],
            ports: vec![port],
            timeout_ms: 800,
            concurrency: 2,
            grab_banner: true,
            max_hosts: 0,
        };
        let report = scan(&auth, &plan).await.unwrap();
        assert_eq!(report.open, 1);
        let svc = report.hosts[0].ports[0].service.as_ref().unwrap();
        assert_eq!(svc.name, "ssh");
        assert_eq!(svc.product.as_deref(), Some("OpenSSH"));
        assert_eq!(svc.version.as_deref(), Some("9.6"));
    }

    /// 인가에 없는 포트는 스킵되고, 스캔 자체는 중단되지 않는다.
    #[tokio::test]
    async fn scan_skips_unauthorized_ports() {
        let auth = Authorization::parse(
            "engagement:\n  authorized_until: \"2099-12-31\"\nscope:\n  allow:\n    - host: \"127.0.0.1\"\nports:\n  allow_tcp: [80]\n",
        )
        .unwrap();
        let plan = ScanPlan {
            hosts: vec!["127.0.0.1".into()],
            ports: vec![80, 443],
            timeout_ms: 200,
            concurrency: 2,
            grab_banner: false,
            max_hosts: 0,
        };
        let report = scan(&auth, &plan).await.unwrap();
        assert_eq!(report.scanned, 1, "{report:?}");
        assert!(report.findings.iter().any(|f| f.category == "scan_skipped"));
    }

    /// 규모 상한을 넘으면 스캔을 시작하지 않는다.
    #[tokio::test]
    async fn scan_rejects_oversized_plan() {
        let auth = Authorization::parse(
            "engagement:\n  authorized_until: \"2099-12-31\"\nscope:\n  allow:\n    - host: \"127.0.0.1\"\n",
        )
        .unwrap();
        let plan = ScanPlan {
            hosts: vec!["127.0.0.1".into()],
            ports: (1..=30000u16).collect(),
            timeout_ms: 100,
            concurrency: 8,
            grab_banner: false,
            max_hosts: 0,
        };
        assert!(scan(&auth, &plan).await.is_err());
    }
}
