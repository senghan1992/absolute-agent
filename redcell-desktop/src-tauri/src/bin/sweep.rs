//! P0 스윕 단독 CLI — 데스크톱 없이 터미널에서 바로 실측한다.
//!
//! ```sh
//! cargo run --bin sweep -- <host|URL> [--port N] [--cookie "a=b"] [--danger] [--json] [--timeout S]
//!   [--gate] [--policy policy.json] [--sarif out.sarif]
//!   [--login-user U --login-pass P] [--login-url U] [--crawl N] [--crawl-depth D]
//!   [--oob-base URL] [--oob-bind ADDR] [--openapi URL-OR-FILE] [--p1-budget N] [--no-browser]
//! ```
//! `--danger` 는 파괴적 프로브 동의와 동일 (기본자격·IDOR 인접·쓰기검증).
//! `--gate` 는 배포 게이트 판정 (기본 절대 Zero-High) — 통과 0, 실패 1, 사용법 오류 2.
//! 로그인은 플래그 우선, 환경변수 REDCELL_GATE_USER / REDCELL_GATE_PASS 대체 (argv 노출 주의),
//! 플래그는 그 대체 수단이다. 인가된 대상에만 사용할 것.
//! `--openapi` 는 JSON·YAML 스펙取り込み (동일 호스트 URL 또는 로컬 파일, 내부 $ref 해석).
//! `--oob-base` 미지정 시 루프백 대상은 OOB 수신기를 자동 기동한다 (원격은 명시 필요).
//! 로그인은 HTTP 폼 우선, SPA는 브라우저에서 직접 로그인 후 세션을 스윕 전체에 적용한다.

#[path = "../probes.rs"]
mod probes;

use std::time::Duration;

fn usage() -> ! {
    eprintln!("사용법: sweep <host|URL> [--port N] [--cookie \"..\" ] [--danger] [--json] [--timeout S] [--gate] [--policy F] [--sarif F] [--login-user U --login-pass P] [--login-url U] [--crawl N] [--crawl-depth D] [--oob-base URL] [--oob-bind ADDR] [--openapi URL-OR-FILE] [--p1-budget N] [--no-browser]");
    std::process::exit(2);
}

fn parse_target(raw: &str) -> (String, Option<u16>) {
    let mut t = raw.trim().to_string();
    let mut https = false;
    if let Some(rest) = t.strip_prefix("https://") {
        https = true;
        t = rest.to_string();
    } else if let Some(rest) = t.strip_prefix("http://") {
        t = rest.to_string();
    }
    t = t.split('/').next().unwrap_or("").to_string();
    if t.is_empty() {
        usage();
    }
    // [v6]:port / host:port
    let mut port: Option<u16> = None;
    if let Some(stripped) = t.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            let host = stripped[..end].to_string();
            let rest = &stripped[end + 1..];
            if let Some(p) = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()) {
                port = Some(p);
            }
            return (host, port.or(if https { Some(443) } else { None }));
        }
    }
    if t.matches(':').count() == 1 {
        if let Some((h, p)) = t.split_once(':') {
            port = p.parse::<u16>().ok();
            t = h.to_string();
        }
    }
    if port.is_none() && https {
        port = Some(443);
    }
    (t, port)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        usage();
    }
    let mut host_raw = String::new();
    let mut port: Option<u16> = None;
    let mut cookie: Option<String> = None;
    let mut danger = false;
    let mut json = false;
    let mut timeout: Option<u64> = None;
    let mut gate = false;
    let mut policy_path: Option<String> = None;
    let mut sarif_path: Option<String> = None;
    let mut login_user: Option<String> = None;
    let mut login_pass: Option<String> = None;
    let mut login_url: Option<String> = None;
    let mut crawl: Option<usize> = None;
    let mut crawl_depth: u8 = 3;
    let mut oob_base: Option<String> = None;
    let mut oob_bind: String = "127.0.0.1:0".to_string();
    let mut openapi: Option<String> = None;
    let mut p1_budget: Option<usize> = None;
    let mut no_browser = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                port = args.get(i + 1).and_then(|p| p.parse::<u16>().ok());
                if port.is_none() {
                    usage();
                }
                i += 1;
            }
            "--cookie" => {
                cookie = args.get(i + 1).cloned();
                if cookie.is_none() {
                    usage();
                }
                i += 1;
            }
            "--timeout" => {
                timeout = args.get(i + 1).and_then(|t| t.parse::<u64>().ok());
                if timeout.is_none() {
                    usage();
                }
                i += 1;
            }
            "--danger" => danger = true,
            "--json" => json = true,
            "--gate" => gate = true,
            "--policy" => {
                policy_path = args.get(i + 1).cloned();
                if policy_path.is_none() {
                    usage();
                }
                i += 1;
            }
            "--sarif" => {
                sarif_path = args.get(i + 1).cloned();
                if sarif_path.is_none() {
                    usage();
                }
                i += 1;
            }
            "--login-user" => {
                login_user = args.get(i + 1).cloned();
                if login_user.is_none() {
                    usage();
                }
                i += 1;
            }
            "--login-pass" => {
                login_pass = args.get(i + 1).cloned();
                if login_pass.is_none() {
                    usage();
                }
                i += 1;
            }
            "--login-url" => {
                login_url = args.get(i + 1).cloned();
                if login_url.is_none() {
                    usage();
                }
                i += 1;
            }
            "--crawl" => {
                crawl = args.get(i + 1).and_then(|v| v.parse::<usize>().ok());
                if crawl.is_none() {
                    usage();
                }
                i += 1;
            }
            "--crawl-depth" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse::<u8>().ok()) {
                    crawl_depth = v.min(5);
                    i += 1;
                }
            }
            "--oob-base" => {
                oob_base = args.get(i + 1).cloned();
                if oob_base.is_none() {
                    usage();
                }
                i += 1;
            }
            "--oob-bind" => {
                if let Some(v) = args.get(i + 1).cloned() {
                    oob_bind = v;
                    i += 1;
                } else {
                    usage();
                }
            }
            "--openapi" => {
                openapi = args.get(i + 1).cloned();
                if openapi.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
                    usage();
                }
                i += 1;
            }
            "--p1-budget" => {
                match args.get(i + 1).and_then(|v| v.parse::<usize>().ok()) {
                    Some(n) if n <= 4096 => {
                        p1_budget = Some(n);
                        i += 1;
                    }
                    _ => {
                        eprintln!("[오류] --p1-budget 는 0~4096 이어야 합니다 (0이면 P1 스킵).");
                        std::process::exit(2);
                    }
                }
            }
            "--no-browser" => {
                no_browser = true;
            }
            a if a.starts_with('-') => usage(),
            h => {
                if !host_raw.is_empty() {
                    usage();
                }
                host_raw = h.to_string();
            }
        }
        i += 1;
    }
    if host_raw.is_empty() {
        usage();
    }
    let (host, p2) = parse_target(&host_raw);
    let port = port.or(p2);
    let mut cfg = probes::SweepConfig::default();
    cfg.cookie = cookie.filter(|c| !c.trim().is_empty());
    cfg.danger = danger;
    if let Some(n) = p1_budget {
        cfg.p1_budget = n;
    }
    cfg.no_browser = no_browser;
    if let Some(t) = timeout {
        cfg.sweep_timeout = Duration::from_secs(t.max(5));
    }
    // 로그인 자격 — 플래그 우선, 환경변수 대체 (ps 노출 주의).
    let env_user = std::env::var("REDCELL_GATE_USER").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let env_pass = std::env::var("REDCELL_GATE_PASS").ok().filter(|s| !s.is_empty());
    let user = login_user.or(env_user);
    let pass = login_pass.or(env_pass);
    if login_url.is_some() && (user.is_none() || pass.is_none()) {
        eprintln!("[오류] --login-url 은 로그인과 함께 사용하세요.");
        std::process::exit(2);
    }
    match (user, pass) {
        (Some(u), Some(p)) => {
            cfg.login = Some(probes::LoginConfig { username: u, password: p, login_url });
        }
        (Some(_), None) | (None, Some(_)) => {
            eprintln!("[오류] 로그인은 user 와 pass 모두 필요합니다 (플래그 또는 REDCELL_GATE_USER/PASS).");
            std::process::exit(2);
        }
        (None, None) => {}
    }
    if let Some(n) = crawl {
        if n == 0 {
            eprintln!("[오류] --crawl 은 1 이상이어야 합니다.");
            std::process::exit(2);
        }
        cfg.crawl = Some(probes::CrawlConfig { max_pages: n.min(200), max_depth: crawl_depth });
    }
    if let Some(base) = oob_base {
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            eprintln!("[오류] --oob-base 는 http(s) URL이어야 합니다.");
            std::process::exit(2);
        }
        cfg.oob = Some(probes::OobConfig { bind: oob_bind, base });
    } else if args.iter().any(|a| a == "--oob-bind") {
        eprintln!("[오류] --oob-bind 는 --oob-base 와 함께 사용하세요.");
        std::process::exit(2);
    }
    if let Some(src) = openapi {
        let ok = if src.starts_with("http://") || src.starts_with("https://") {
            // 동일 호스트 강제 — 스펙 URL 이 대상을 벗어나면 거부.
            match probes::openapi_url_target(&src) {
                Some((h, p)) => {
                    let want = port.or(Some(if src.starts_with("https://") { 443 } else { 80 }));
                    h == host.to_lowercase() && p == want
                }
                None => false,
            }
        } else {
            std::path::Path::new(&src).is_file()
        };
        if !ok {
            eprintln!("[오류] --openapi 는 동일 호스트 URL 또는 존재하는 파일이어야 합니다: {src}");
            std::process::exit(2);
        }
        cfg.openapi = Some(probes::OpenApiConfig { source: src });
    }
    if danger {
        eprintln!("[경고] --danger: 파괴적 프로브 실행 (기본자격·IDOR 인접·쓰기검증) — 인가된 대상에만 사용하십시오.");
    }
    let rep = probes::run_sweep_with_config(&host, port, cfg);
    if gate {
        // 대상 무응답의 공허한 통과 방지 — 프로브 0건이면 실패(fail-closed).
        if rep.probes_run == 0 {
            eprintln!("[게이트] 실패 — 대상 무응답 (프로브 0건, 증거 없음).");
            std::process::exit(1);
        }
        let policy = match &policy_path {
            None => probes::GatePolicy::default(),
            Some(p) => {
                let text = std::fs::read_to_string(p).unwrap_or_else(|e| {
                    eprintln!("[오류] 정책 파일 읽기 실패 ({p}): {e}");
                    std::process::exit(2);
                });
                probes::parse_gate_policy(&text).unwrap_or_else(|e| {
                    eprintln!("[오류] {e}");
                    std::process::exit(2);
                })
            }
        };
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let verdict = probes::evaluate_gate(&rep, &policy, &today);
        if let Some(sp) = &sarif_path {
            let sarif = probes::sarif_report(&rep, &verdict, policy.cvss_env.as_ref());
            std::fs::write(sp, serde_json::to_string_pretty(&sarif).unwrap()).unwrap_or_else(|e| {
                eprintln!("[오류] SARIF 기록 실패 ({sp}): {e}");
                std::process::exit(2);
            });
        }
        if verdict.pass {
            eprintln!(
                "[게이트] 통과 — 차단 {}건·억제 {}건 (발견 {}건 중).",
                verdict.blocking.len(),
                verdict.suppressed.len(),
                rep.hits.len()
            );
        } else {
            eprintln!("[게이트] 실패 — 차단 {}건 ({}):", verdict.blocking.len(), verdict.fail_on.join("/"));
            for b in verdict.blocking.iter().take(10) {
                eprintln!("  - [{}] [{}] {} — {}", b.id, b.severity, b.category, b.title);
            }
            if verdict.blocking.len() > 10 {
                eprintln!("  - … 외 {}건", verdict.blocking.len() - 10);
            }
        }
        for e in &verdict.expired {
            eprintln!("[게이트] 만료 억제 무시: {e}");
        }
        if json {
            println!("{}", serde_json::to_string_pretty(&verdict).unwrap());
        }
        std::process::exit(if verdict.pass { 0 } else { 1 });
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&rep).unwrap());
        return;
    }
    println!("{}", probes::sweep_summary_line(&rep));
    println!("---");
    for h in &rep.hits {
        println!("[{}] [{}] {} — {}", h.id, h.severity, h.category, h.title);
        println!("    대상: {}", h.target);
        if !h.evidence.is_empty() {
            println!("    증거: {}", h.evidence.chars().take(200).collect::<String>());
        }
    }
}
