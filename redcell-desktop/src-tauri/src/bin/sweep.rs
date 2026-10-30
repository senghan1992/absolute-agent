//! P0 스윕 단독 CLI — 데스크톱 없이 터미널에서 바로 실측한다.
//!
//! ```sh
//! cargo run --bin sweep -- <host|URL> [--port N] [--cookie "a=b"] [--danger] [--json] [--timeout S]
//!   [--gate] [--policy policy.json] [--sarif out.sarif]
//!   [--login-user U --login-pass P] [--login-url U] [--crawl N] [--crawl-depth D]
//!   [--oob-base URL] [--oob-bind ADDR] [--openapi URL-OR-FILE] [--p1-budget N] [--no-browser]
//!   [--rps N] [--threads N] [--seed-url URL]...
//! ```
//! `--seed-url` 은 반복 지정 가능 (동일 호스트·쿼리 필수, 최대 8개 투입).
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
    eprintln!("사용법: sweep <host|URL> [--port N] [--cookie \"..\" ] [--danger] [--json] [--timeout S] [--gate] [--policy F] [--sarif F] [--login-user U --login-pass P] [--login-url U] [--crawl N] [--crawl-depth D] [--oob-base URL] [--oob-bind ADDR] [--openapi URL-OR-FILE] [--p1-budget N] [--no-browser] [--rps N] [--threads N] [--seed-url URL]... [--batch F] [--out-dir D] [--history-dir D]");
    eprintln!("       sweep diff <old.json> <new.json> [--json]   # 지문 기준 신규·해소·지속 비교");
    eprintln!("       sweep history --history-dir D [--json]      # 스캔 이력 목록");
    std::process::exit(2);
}

/// 리포트 저장 — JSON 파일 + index.jsonl 한 줄 요약 append (이력·diff용).
/// 파일명: <host>_<port>_<started_at>.json (RFC3339의 ':' → '-').
fn save_report(dir: &str, host: &str, port: Option<u16>, rep: &probes::ProbeReport) -> String {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("[오류] 디렉토리 생성 실패 ({dir}): {e}");
        std::process::exit(2);
    }
    let safe_host: String = host.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect();
    let ts: String = rep.started_at.chars().map(|c| if c == ':' { '-' } else { c }).collect();
    let fname = format!("{safe_host}_{}_{ts}.json", port.map(|p| p.to_string()).unwrap_or_else(|| "auto".into()));
    let path = format!("{dir}/{fname}");
    std::fs::write(&path, serde_json::to_string_pretty(&rep).unwrap()).unwrap_or_else(|e| {
        eprintln!("[오류] 리포트 기록 실패 ({path}): {e}");
        std::process::exit(2);
    });
    let (mut c, mut h) = (0usize, 0usize);
    for hit in &rep.hits {
        if hit.severity == "critical" { c += 1; }
        if hit.severity == "high" { h += 1; }
    }
    let idx = serde_json::json!({
        "file": fname, "target": rep.target, "started_at": rep.started_at,
        "hits": rep.hits.len(), "critical": c, "high": h,
        "probes_run": rep.probes_run, "duration_ms": rep.duration_ms,
        "danger": rep.danger, "authenticated": rep.authenticated,
    });
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(format!("{dir}/index.jsonl")).unwrap_or_else(|e| {
        eprintln!("[오류] 이력 인덱스 기록 실패 ({dir}/index.jsonl): {e}");
        std::process::exit(2);
    });
    let _ = writeln!(f, "{}", serde_json::to_string(&idx).unwrap());
    path
}

fn cmd_diff(rest: &[String]) {
    let mut json = false;
    let mut files: Vec<String> = Vec::new();
    for a in rest {
        if a == "--json" { json = true; } else if a.starts_with('-') { usage(); } else { files.push(a.clone()); }
    }
    if files.len() != 2 { usage(); }
    let load = |p: &str| -> probes::ProbeReport {
        let text = std::fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("[오류] 리포트 읽기 실패 ({p}): {e}");
            std::process::exit(2);
        });
        serde_json::from_str(&text).unwrap_or_else(|e| {
            eprintln!("[오류] 리포트 파싱 실패 ({p}): {e} (--json 출력 파일이어야 합니다)");
            std::process::exit(2);
        })
    };
    let d = probes::diff_reports(&load(&files[0]), &load(&files[1]));
    if json {
        println!("{}", serde_json::to_string_pretty(&d).unwrap());
        return;
    }
    println!("{}", probes::diff_summary_line(&d));
    for (label, hits) in [("신규", &d.new), ("해소", &d.fixed), ("지속", &d.persisting)] {
        if hits.is_empty() { continue; }
        println!("--- {label} {}건 ---", hits.len());
        for h in hits.iter().take(30) {
            println!("  [{}] [{}] {} — {}", h.id, h.severity, h.category, h.title);
        }
        if hits.len() > 30 { println!("  … 외 {}건", hits.len() - 30); }
    }
    for sc in &d.severity_changes {
        println!("  [변경] {}: {} → {} — {}", sc.fingerprint.chars().take(12).collect::<String>(), sc.from, sc.to, sc.title);
    }
}

fn cmd_history(rest: &[String]) {
    let mut json = false;
    let mut dir: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--json" => json = true,
            "--history-dir" => {
                dir = rest.get(i + 1).cloned();
                if dir.is_none() { usage(); }
                i += 1;
            }
            _ => usage(),
        }
        i += 1;
    }
    let dir = dir.unwrap_or_else(|| { eprintln!("[오류] history 에는 --history-dir 이 필요합니다."); std::process::exit(2); });
    let text = std::fs::read_to_string(format!("{dir}/index.jsonl")).unwrap_or_else(|e| {
        eprintln!("[오류] 이력 인덱스 읽기 실패 ({dir}/index.jsonl): {e}");
        std::process::exit(2);
    });
    let rows: Vec<serde_json::Value> = text.lines().filter_map(|l| serde_json::from_str(l.trim()).ok()).collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&rows).unwrap());
        return;
    }
    println!("[history] {}건 — {dir}/index.jsonl", rows.len());
    for r in rows {
        println!("  {} {} 발견 {}건(치명 {}/높음 {}) {}",
            r.get("started_at").and_then(|v| v.as_str()).unwrap_or("?"),
            r.get("target").and_then(|v| v.as_str()).unwrap_or("?"),
            r.get("hits").and_then(|v| v.as_u64()).unwrap_or(0),
            r.get("critical").and_then(|v| v.as_u64()).unwrap_or(0),
            r.get("high").and_then(|v| v.as_u64()).unwrap_or(0),
            r.get("file").and_then(|v| v.as_str()).unwrap_or("?"));
    }
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
    if args.first().map(|s| s.as_str()) == Some("diff") {
        cmd_diff(&args[1..]);
        return;
    }
    if args.first().map(|s| s.as_str()) == Some("history") {
        cmd_history(&args[1..]);
        return;
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
    let mut rps: Option<u32> = None;
    let mut threads: Option<usize> = None;
    let mut seeds: Vec<String> = Vec::new();
    let mut batch: Option<String> = None;
    let mut out_dir: Option<String> = None;
    let mut history_dir: Option<String> = None;
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
            "--rps" => {
                rps = args.get(i + 1).and_then(|v| v.parse::<u32>().ok());
                if rps.is_none() {
                    usage();
                }
                i += 1;
            }
            "--threads" => {
                threads = args.get(i + 1).and_then(|v| v.parse::<usize>().ok());
                if threads.is_none() {
                    usage();
                }
                i += 1;
            }
            "--seed-url" => {
                let v = args.get(i + 1).cloned().unwrap_or_default();
                if v.trim().is_empty() {
                    usage();
                }
                seeds.push(v);
                i += 1;
            }
            "--batch" => {
                batch = args.get(i + 1).cloned();
                if batch.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
                    usage();
                }
                i += 1;
            }
            "--out-dir" => {
                out_dir = args.get(i + 1).cloned();
                if out_dir.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
                    usage();
                }
                i += 1;
            }
            "--history-dir" => {
                history_dir = args.get(i + 1).cloned();
                if history_dir.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
                    usage();
                }
                i += 1;
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
    if host_raw.is_empty() && batch.is_none() {
        usage();
    }
    if !host_raw.is_empty() && batch.is_some() {
        eprintln!("[오류] --batch 와 대상 위치 인자는 함께 사용할 수 없습니다.");
        std::process::exit(2);
    }
    let (host, p2) = if host_raw.is_empty() { (String::new(), None) } else { parse_target(&host_raw) };
    let port = port.or(p2);
    let mut cfg = probes::SweepConfig::default();
    cfg.cookie = cookie.filter(|c| !c.trim().is_empty());
    cfg.danger = danger;
    if let Some(n) = p1_budget {
        cfg.p1_budget = n;
    }
    cfg.no_browser = no_browser;
    cfg.seeds = seeds;
    if let Some(t) = timeout {
        cfg.sweep_timeout = Duration::from_secs(t.max(5));
    }
    // 스캔 예절 — 외부·공유 대상에는 낮은 RPS·스레드로 (기본 30rps·24스레드).
    if let Some(n) = rps {
        if n == 0 {
            eprintln!("[오류] --rps 는 1 이상이어야 합니다.");
            std::process::exit(2);
        }
        cfg.rps = n.min(1000);
    }
    if let Some(n) = threads {
        if n == 0 {
            eprintln!("[오류] --threads 는 1 이상이어야 합니다.");
            std::process::exit(2);
        }
        cfg.threads = n.min(64);
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
    // 게이트 정책 — 단일·배치 공통 선행 로드.
    let policy: Option<probes::GatePolicy> = if gate {
        Some(match &policy_path {
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
        })
    } else {
        None
    };
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    // 배치 — 대상 파일 순차 스캔 (최대 64개, 동일 설정·타임아웃 적용).
    if let Some(bf) = batch.as_ref() {
        if sarif_path.is_some() {
            eprintln!("[오류] --sarif 은 배치와 함께 사용할 수 없습니다 (--out-dir JSON을 사용하세요).");
            std::process::exit(2);
        }
        let text = std::fs::read_to_string(bf).unwrap_or_else(|e| {
            eprintln!("[오류] 배치 파일 읽기 실패 ({bf}): {e}");
            std::process::exit(2);
        });
        let targets: Vec<String> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(|s| s.to_string()).collect();
        if targets.is_empty() {
            eprintln!("[오류] 배치 파일에 대상이 없습니다: {bf}");
            std::process::exit(2);
        }
        if targets.len() > 64 {
            eprintln!("[오류] 배치는 최대 64개 대상입니다 ({}개).", targets.len());
            std::process::exit(2);
        }
        let mut fails = 0usize;
        for (n, t) in targets.iter().enumerate() {
            let (h, p) = parse_target(t);
            let tp = port.or(p);
            eprintln!("[배치 {}/{}] {t} 스캔 중…", n + 1, targets.len());
            let rep = probes::run_sweep_with_config(&h, tp, cfg.clone());
            if let Some(d) = out_dir.as_ref() {
                let sp = save_report(d, &h, tp, &rep);
                eprintln!("[배치] 저장: {sp}");
            }
            if let Some(d) = history_dir.as_ref() {
                save_report(d, &h, tp, &rep);
            }
            if gate {
                let pol = policy.as_ref().unwrap();
                if rep.probes_run == 0 {
                    eprintln!("[배치] {t}: 게이트 실패 — 대상 무응답 (프로브 0건).");
                    fails += 1;
                } else {
                    let verdict = probes::evaluate_gate(&rep, pol, &today);
                    eprintln!("[배치] {t}: 게이트 {} — 차단 {}건·억제 {}건.", if verdict.pass { "통과" } else { "실패" }, verdict.blocking.len(), verdict.suppressed.len());
                    if !verdict.pass {
                        fails += 1;
                    }
                }
            } else {
                println!("[{}] {}", t, probes::sweep_summary_line(&rep));
            }
        }
        eprintln!("[배치] 완료 — {}개 중 게이트 실패 {}건.", targets.len(), fails);
        std::process::exit(if fails > 0 { 1 } else { 0 });
    }
    let rep = probes::run_sweep_with_config(&host, port, cfg);
    if let Some(d) = out_dir.as_ref() {
        let sp = save_report(d, &host, port, &rep);
        eprintln!("[저장] {sp}");
    }
    if let Some(d) = history_dir.as_ref() {
        let sp = save_report(d, &host, port, &rep);
        eprintln!("[이력] {sp}");
    }
    if gate {
        // 대상 무응답의 공허한 통과 방지 — 프로브 0건이면 실패(fail-closed).
        if rep.probes_run == 0 {
            eprintln!("[게이트] 실패 — 대상 무응답 (프로브 0건, 증거 없음).");
            std::process::exit(1);
        }
        let policy = policy.as_ref().unwrap();
        let verdict = probes::evaluate_gate(&rep, policy, &today);
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
