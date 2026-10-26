//! P0 스윕 단독 CLI — 데스크톱 없이 터미널에서 바로 실측한다.
//!
//! ```sh
//! cargo run --bin sweep -- <host|URL> [--port N] [--cookie "a=b"] [--danger] [--json] [--timeout S]
//! ```
//! `--danger` 는 파괴적 프로브 동의와 동일 (기본자격·IDOR 인접·쓰기검증).
//! 인가된 대상에만 사용할 것.

#[path = "../probes.rs"]
mod probes;

use std::time::Duration;

fn usage() -> ! {
    eprintln!("사용법: sweep <host|URL> [--port N] [--cookie \"..\" ] [--danger] [--json] [--timeout S]");
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
    if let Some(t) = timeout {
        cfg.sweep_timeout = Duration::from_secs(t.max(5));
    }
    if danger {
        eprintln!("[경고] --danger: 파괴적 프로브 실행 (기본자격·IDOR 인접·쓰기검증) — 인가된 대상에만 사용하십시오.");
    }
    let rep = probes::run_sweep_with_config(&host, port, cfg);
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
