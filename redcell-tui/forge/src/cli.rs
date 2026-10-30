//! CLI — 비대화형 명령 모음. TUI 는 `forge`(인자 없음)로 실행.
//!
//!   forge doctor              환경 점검 (파이썬·인가·프로바이더)
//!   forge scope --host H      인가 판정 (fail-closed 확인)
//!   forge kernel --code "…"   파이썬 커널 1회 실행
//!   forge storm --target URL  스톰 엔진 1회 실행 + 리포트

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::kernel::Kernel;
use crate::scope::{self, Authorization, ScopeError};
use crate::storm::{StormEngine, StormPlan, Template};

/// 파싱된 CLI 인자.
#[derive(Debug, Default, Clone)]
pub struct Args {
    pub command: String,
    pub flags: Vec<(String, String)>,
    pub positional: Vec<String>,
}

impl Args {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.flags.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.flags.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
    }
    pub fn has(&self, name: &str) -> bool {
        self.flags.iter().any(|(k, _)| k == name)
    }
    pub fn num(&self, name: &str, default: f64) -> f64 {
        self.get(name).and_then(|v| v.parse().ok()).unwrap_or(default)
    }
}

/// `key=value` / `--flag` 파싱.
pub fn parse_args() -> Args {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1).peekable();
    let mut command = String::new();
    while let Some(arg) = it.next() {
        if let Some(rest) = arg.strip_prefix("--") {
            if let Some((k, v)) = rest.split_once('=') {
                args.flags.push((k.to_string(), v.to_string()));
            } else if let Some(next) = it.peek() {
                if !next.starts_with("--") {
                    args.flags.push((rest.to_string(), it.next().unwrap()));
                } else {
                    args.flags.push((rest.to_string(), "true".to_string()));
                }
            } else {
                args.flags.push((rest.to_string(), "true".to_string()));
            }
        } else if command.is_empty() {
            command = arg;
        } else {
            args.positional.push(arg);
        }
    }
    args.command = if command.is_empty() { "tui".to_string() } else { command };
    args
}

/// 인가 파일 로드 — 없으면 fail-closed 메시지와 함께 종료.
pub fn load_authorization(explicit: Option<&std::path::Path>) -> Result<Authorization, ScopeError> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => scope::find_authorization().ok_or_else(|| {
            ScopeError::Missing(format!(
                "{} 에 authorization.yaml 이 없습니다. 인가된 대상만 점검할 수 있습니다.",
                scope::authorization_candidates()[0].parent().map(|p| p.display().to_string()).unwrap_or_default()
            ))
        })?,
    };
    Authorization::load(&path)
}

/// 실행 디렉터리 (리포트·아티팩트 보관).
pub fn run_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".local/share")
        });
    let dir = base.join("forge/runs");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 리포트 저장 디렉터리.
pub fn report_dir() -> PathBuf {
    let dir = run_dir().join("reports");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn help_text() -> String {
    r#"REDFORGE — 인가된 대상을 위한 터미널 자율 보안점검 에이전트

사용법:
  forge                     TUI 실행 (기본)
  forge tui [--scope PATH]  TUI 실행
  forge doctor              환경 점검
  forge scope --host H [--port P]
                             인가 판정 (deny/기간/포트 확인)
  forge kernel --code "PY" [--timeout MS] [--base URL]
                             파이썬 커널 1회 실행
  forge storm --target URL [--param k=v ...] [--payload P ...]
                             [--max N] [--rps N] [--concurrency N] [--json]
                             스톰 실행 + 결과 JSON 저장
  forge scan --target HOST|CIDR [--ports 22,80,443] [--json]
                             포트 스캔 + 서비스/버전 탐지 (nmap 대체)
  forge discover --target URL [--ext php,bak] [--vhost] [--max N] [--json]
                             콘텐츠 디스커버리 (ffuf/gobuster 대체)
  forge templates --target URL [--tags exposure,config] [--severity medium] [--json]
                             템플릿 스캔 (nuclei 대체)
  forge tech --target URL [--json]
                             기술 스택 지문 + 보안 헤더/쿠키 감사
  forge report --from <storm.json> [--out FILE] [--html]
                             스톰 결과 → Markdown 리포트 (보완 포인트 포함)
  forge idor --target URL --param id [--id V ...] [--spread N]
                             IDOR 탐지 (다른 주체 리소스 접근)
  forge tamper --target URL --param price [--value V ...] [--method POST] [--body ...]
                             가격/수량 변조 탐지

공통 옵션:
  --scope PATH              인가 파일 경로 (기본 ~/.redcell/authorization.yaml)
  --run-dir PATH            실행 디렉터리 (커널·리포트 보관)

주의: --rps 는 인가 파일의 상한을 *올릴* 수 없습니다(낮출 수만 있습니다).
      파괴적 페이로드는 disallow_destructive 정책에 따라 자동으로 제외됩니다.
"# .to_string()
}

/// 명령 실행. TUI 는 `false` 를 반환해 호출부가 TUI 로 넘어간다.
pub async fn run(args: Args) -> anyhow::Result<bool> {
    // "--help" / "-h" 플래그도 명령으로 취급한다 (플래그 파서가 명령을 집어삼키기 때문).
    if args.has("help") || args.has("h") {
        println!("{}", help_text());
        return Ok(true);
    }
    match args.command.as_str() {
        "help" | "--help" | "-h" => {
            println!("{}", help_text());
            Ok(true)
        }
        "doctor" => {
            doctor(&args).await?;
            Ok(true)
        }
        "scope" => {
            let auth = match load_authorization(args.get("scope").map(std::path::Path::new)) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("✖ {e}");
                    std::process::exit(3);
                }
            };
            let host = args.get("host").unwrap_or("");
            let port = args.get("port").and_then(|p| p.parse().ok());
            match auth.check(host, port) {
                Ok(()) => {
                    println!("✔ {host}{} — 인가됨", port.map(|p| format!(":{p}")).unwrap_or_default());
                    println!("  engagement : {}", auth.engagement.name);
                    println!("  허용 포트   : {:?}", auth.ports);
                    println!("  RPS 상한    : {:?}", auth.rps_limit());
                    Ok(true)
                }
                Err(e) => {
                    eprintln!("✖ {e}");
                    std::process::exit(3);
                }
            }
        }
        "kernel" => {
            let auth = load_authorization(args.get("scope").map(std::path::Path::new)).ok();
            let dir = args.get("run-dir").map(PathBuf::from).unwrap_or_else(run_dir);
            let kernel = Kernel::start(
                auth.as_ref().map(|a| a.source.as_path()),
                args.get("base"),
                &dir,
            )
            .await?;
            let code = args.get("code").unwrap_or("print('hello from forge kernel')");
            let timeout = args.num("timeout", 10_000.0) as u64;
            match kernel.exec(code, timeout).await {
                Ok(out) => {
                    print!("{}", out.combined());
                    if !out.stderr.trim().is_empty() {
                        std::process::exit(1);
                    }
                    Ok(true)
                }
                Err(e) => {
                    eprintln!("✖ {e}");
                    std::process::exit(1);
                }
            }
        }
        "storm" => {
            let auth = match load_authorization(args.get("scope").map(std::path::Path::new)) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("✖ {e}");
                    std::process::exit(3);
                }
            };
            let target = args.get("target").unwrap_or("").to_string();
            if target.is_empty() {
                eprintln!("✖ --target 이 필요합니다.");
                std::process::exit(2);
            }
            let mut template = Template::get(&target);
            // 쿼리스트링 파라미터 자동 추출.
            if let Ok(parsed) = url::Url::parse(&target) {
                for (k, v) in parsed.query_pairs() {
                    template.params.push(crate::storm::Param::new(&k, &v));
                }
                template.url = {
                    let mut u = parsed.clone();
                    u.set_query(None);
                    u.to_string()
                };
            }
            for kv in args.get_all("param") {
                if let Some((k, v)) = kv.split_once('=') {
                    template.params.push(crate::storm::Param::new(k, v));
                }
            }
            if !template.params.is_empty() {
                let (t_method, t_url) = (template.method.clone(), template.url.clone());
                template.name = format!("{} {}", t_method, t_url);
            }

            let mut plan = StormPlan::default();
            plan.templates = vec![template];
            if !args.get_all("payload").is_empty() {
                plan.payloads = args.get_all("payload").iter().map(|s| s.to_string()).collect();
            }
            plan.max_requests = args.num("max", plan.max_requests as f64) as usize;
            plan.concurrency = args.num("concurrency", plan.concurrency as f64) as usize;
            plan.rps = args.get("rps").and_then(|v| v.parse().ok());
            plan.max_duration_secs = args.num("duration", plan.max_duration_secs as f64) as u64;

            let (tx, mut rx) = tokio::sync::broadcast::channel::<crate::storm::StormEvent>(256);
            let engine = StormEngine::new().map_err(|e| anyhow::anyhow!(e))?;
            let printer = tokio::spawn(async move {
                while let Ok(ev) = rx.recv().await {
                    match ev {
                        crate::storm::StormEvent::Started { templates, payloads } => {
                            println!("▶ 스톰 시작 — 템플릿 {templates} · 페이로드 {payloads}");
                        }
                        crate::storm::StormEvent::Progress { done, total, rps } => {
                            println!("  {done}/{total} · {rps:.1} req/s");
                        }
                        crate::storm::StormEvent::Anomaly(a) => {
                            println!("  ⚠ [{}] {} {:?} — {}", a.severity, a.template, a.param, a.payload);
                        }
                        crate::storm::StormEvent::Finished { requests, anomalies } => {
                            println!("■ 완료 — 요청 {requests} · 이상 {anomalies}");
                        }
                    }
                }
            });

            let report = engine.run(&plan, &auth, tx).await;
            drop(printer);
            let report = report?;
            let json_out = serde_json::to_string_pretty(&report)?;
            if args.has("json") {
                println!("{json_out}");
            } else {
                println!("요청 {}건 · {:.1} req/s · 이상 {}건 · 오류 {}", report.requests, report.rps, report.anomalies.len(), report.errors);
                for a in report.anomalies.iter().take(30) {
                    println!(
                        "  [{}] {} {:?} payload={:?} status={} lenΔ={} 신호={:?}",
                        a.severity, a.template, a.param, a.payload, a.status, a.len_delta, a.signals
                    );
                }
            }
            let path = report_dir().join(format!("storm-{}.json", chrono::Local::now().format("%Y%m%d-%H%M%S")));
            let _ = std::fs::write(&path, &json_out);
            println!("\n리포트 저장: {}", path.display());
            Ok(true)
        }
        "report" => {
            // 스톰 JSON → Markdown 리포트 (헤드리스 파이프라인용).
            let Some(input) = args.get("from") else {
                eprintln!("사용법: forge report --from <storm.json> [--out FILE]");
                std::process::exit(2);
            };
            let raw = std::fs::read_to_string(input).map_err(|e| anyhow::anyhow!("읽기 실패: {e}"))?;
            let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("JSON 파싱 실패: {e}"))?;
            // 최상위가 배열이면 templates 결과(매칭 목록) 로 본다.
            let storm: serde_json::Value = if parsed.is_array() {
                serde_json::json!({ "matches": parsed })
            } else {
                parsed
            };

            let mut findings: Vec<crate::report::Finding> = Vec::new();
            // 스톰이 아니라 다른 결과(templates·discover·scan) 도 같은 리포트로 합친다.
            if let Some(list) = storm.get("findings").and_then(|v| v.as_array()) {
                for f in list {
                    let get = |k: &str| f.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    findings.push(crate::report::Finding {
                        title: get("title"),
                        severity: get("severity"),
                        category: get("category"),
                        target: get("target"),
                        evidence: get("evidence"),
                        reproduction: get("reproduction"),
                        remediation: get("remediation"),
                    });
                }
            }
            if let Some(list) = storm.get("matches").and_then(|v| v.as_array()) {
                findings.extend(crate::templates::to_findings(
                    &serde_json::from_value::<Vec<crate::templates::TemplateMatch>>(Value::Array(list.clone()))
                        .unwrap_or_default(),
                ));
            }
            let anomalies = storm.get("anomalies").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            for a in anomalies {
                let signals = a.get("signals").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                let template = a.get("template").and_then(|v| v.as_str()).unwrap_or("-");
                let payload = a.get("payload").and_then(|v| v.as_str()).unwrap_or("");
                let status = a.get("status").and_then(|v| v.as_u64()).unwrap_or(0);
                let evidence = a.get("evidence").and_then(|v| v.as_str()).unwrap_or("");
                let repro = format!("{template} 에 payload={payload:?} 주입 → status {status}");
                if signals.is_empty() {
                    findings.push(crate::report::Finding {
                        title: "응답 이상 (구조 변화)".to_string(),
                        severity: a.get("severity").and_then(|v| v.as_str()).unwrap_or("low").to_string(),
                        category: "behavior_diff".to_string(),
                        target: template.to_string(),
                        evidence: evidence.to_string(),
                        reproduction: repro,
                        remediation: "기준선 응답과 달라진 점을 분석해 실제 취약점인지 확인하세요.".to_string(),
                    });
                } else {
                    for sig in signals {
                        let name = sig.as_str().unwrap_or("");
                        findings.push(crate::report::finding_from_signal(name, template, evidence, &repro));
                    }
                }
            }
            crate::report::sort_findings(&mut findings);

            let scope_list: Vec<String> = match load_authorization(args.get("scope").map(std::path::Path::new)) {
                Ok(a) => a.allow.iter().map(|r| format!("{r:?}")).collect(),
                Err(_) => vec!["(미설정)".to_string()],
            };
            let rep = crate::report::Report {
                generated_at: chrono::Local::now().to_rfc3339(),
                engagement: load_authorization(args.get("scope").map(std::path::Path::new))
                    .map(|a| a.engagement.name)
                    .unwrap_or_else(|_| "(미설정)".to_string()),
                scope: scope_list,
                target: storm.get("templates").and_then(|v| v.get(0)).and_then(|t| t.get("url")).and_then(|v| v.as_str()).map(str::to_string),
                summary: crate::report::ReportSummary::of(&findings),
                findings,
                stats: vec![
                    ("스톰 요청".into(), storm.get("requests").and_then(|v| v.as_u64()).unwrap_or(0).to_string()),
                    ("실행 시간(ms)".into(), storm.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0).to_string()),
                    ("요청률(req/s)".into(), format!("{:.1}", storm.get("rps").and_then(|v| v.as_f64()).unwrap_or(0.0))),
                ],
            };

            let md = crate::report::to_markdown(&rep);
            if args.has("html") {
                let dir = crate::cli::report_dir();
                let html_path = dir.join(format!("report-{}.html", chrono::Local::now().format("%Y%m%d-%H%M%S")));
                let _ = std::fs::write(&html_path, crate::report::to_html(&rep));
                println!("HTML 리포트 저장: {}", html_path.display());
            }
            match args.get("out") {
                Some(path) => {
                    std::fs::write(path, &md).map_err(|e| anyhow::anyhow!("저장 실패: {e}"))?;
                    println!("리포트 저장: {path}");
                }
                None => {
                    let dir = report_dir();
                    let path = dir.join(format!("report-{}.md", chrono::Local::now().format("%Y%m%d-%H%M%S")));
                    std::fs::write(&path, &md).map_err(|e| anyhow::anyhow!("저장 실패: {e}"))?;
                    println!("리포트 저장: {}", path.display());
                    println!("{md}");
                }
            }
            Ok(true)
        }
        "idor" => {
            let auth = match load_authorization(args.get("scope").map(std::path::Path::new)) {
                Ok(a) => Arc::new(a),
                Err(e) => {
                    eprintln!("✖ {e}");
                    std::process::exit(3);
                }
            };
            let target = args.get("target").unwrap_or("").to_string();
            if target.is_empty() {
                eprintln!("✖ --target 이 필요합니다.");
                std::process::exit(2);
            }
            let param = args.get("param").unwrap_or("id").to_string();
            let mut cfg = crate::probes::idor::IdorConfig::new(&target, &param);
            cfg.method = args.get("method").unwrap_or("GET").to_uppercase();
            cfg.candidates = args.get_all("id").iter().map(|s| s.to_string()).collect();
            cfg.spread = args.num("spread", 3.0) as u32;
            let client = crate::probes::ProbeClient::new(auth).map_err(|e| anyhow::anyhow!(e))?;
            let report = crate::probes::idor::run(&client, &cfg).await.map_err(|e| anyhow::anyhow!(e))?;
            println!("IDOR 탐색 — {} (기준 {}) · 요청 {}건 · 판정 {:?}", report.param, report.baseline_value, report.requests, report.verdict);
            for s in report.samples.iter().filter(|s| s.differs).take(20) {
                println!("  {}={} → status {} len {} 식별자 {:?}", report.param, s.value, s.status, s.len, s.identifiers);
            }
            if report.findings.is_empty() {
                println!("확정된 취약점 없음.");
            } else {
                for f in &report.findings {
                    println!("
[{}] {}
  대상: {}
  근거: {}
  보완: {}", f.severity, f.title, f.target, f.evidence, f.remediation);
                }
            }
            let json_out = serde_json::to_string_pretty(&report)?;
            let path = report_dir().join(format!("idor-{}.json", chrono::Local::now().format("%Y%m%d-%H%M%S")));
            let _ = std::fs::write(&path, &json_out);
            println!("
결과 저장: {}", path.display());
            Ok(true)
        }
        "tamper" => {
            let auth = match load_authorization(args.get("scope").map(std::path::Path::new)) {
                Ok(a) => Arc::new(a),
                Err(e) => {
                    eprintln!("✖ {e}");
                    std::process::exit(3);
                }
            };
            let target = args.get("target").unwrap_or("").to_string();
            if target.is_empty() {
                eprintln!("✖ --target 이 필요합니다.");
                std::process::exit(2);
            }
            let param = args.get("param").unwrap_or("price").to_string();
            let mut cfg = crate::probes::tamper::TamperConfig::new(&target, &param);
            cfg.method = args.get("method").unwrap_or("POST").to_uppercase();
            if !args.get_all("value").is_empty() {
                cfg.values = args.get_all("value").iter().map(|s| s.to_string()).collect();
            }
            if let Some(b) = args.get("body") {
                cfg.body = Some(b.to_string());
            }
            let client = crate::probes::ProbeClient::new(auth).map_err(|e| anyhow::anyhow!(e))?;
            let report = crate::probes::tamper::run(&client, &cfg).await.map_err(|e| anyhow::anyhow!(e))?;
            println!("가격 변조 탐색 — {} (기준 {}) · 기준 합계 {:?} · 요청 {}건", report.param, report.baseline_value, report.baseline_total, report.requests);
            for a in report.attempts.iter().take(20) {
                println!("  {}={} → status {} {:?} 합계 {:?} 차이 {:?}", report.param, a.value, a.status, a.verdict, a.observed_total, a.delta);
            }
            if report.findings.is_empty() {
                println!("확정된 취약점 없음 (서버가 값을 재계산하거나 거부함).");
            } else {
                for f in &report.findings {
                    println!("
[{}] {}
  대상: {}
  근거: {}
  보완: {}", f.severity, f.title, f.target, f.evidence, f.remediation);
                }
            }
            let json_out = serde_json::to_string_pretty(&report)?;
            let path = report_dir().join(format!("tamper-{}.json", chrono::Local::now().format("%Y%m%d-%H%M%S")));
            let _ = std::fs::write(&path, &json_out);
            println!("
결과 저장: {}", path.display());
            Ok(true)
        }
        "tech" => {
            let auth = match load_authorization(args.get("scope").map(std::path::Path::new)) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("✖ {e}");
                    std::process::exit(3);
                }
            };
            let target = args.get("target").unwrap_or("").to_string();
            if target.is_empty() {
                eprintln!("✖ --target 이 필요합니다.");
                std::process::exit(2);
            }
            let client = crate::http::HttpClient::new(Arc::new(auth)).map_err(|e| anyhow::anyhow!(e))?;
            let resp = client.get(&target).await.map_err(|e| anyhow::anyhow!("요청 실패: {e}"))?;
            let tech = crate::tech::analyze(&resp.headers, &resp.body, resp.status);
            if args.has("json") {
                println!("{}", serde_json::to_string_pretty(&tech)?);
            } else {
                let fp = &tech.fingerprint;
                println!("■ 기술 스택");
                println!("  서버      : {}", fp.web_server.clone().unwrap_or_else(|| "-".into()));
                println!("  프레임워크: {}", if fp.frameworks.is_empty() { "-".into() } else { fp.frameworks.join(", ") });
                println!("  CDN       : {}   WAF: {}", fp.cdn.clone().unwrap_or_else(|| "-".into()), fp.waf.clone().unwrap_or_else(|| "-".into()));
                println!("  지문      : {}", fp.key);
                println!("\n■ 보안 헤더");
                for h in &tech.security_headers {
                    println!("  {} {:<32} {}", if h.present { "✔" } else { "✖" }, h.name,
                        if h.present { h.value.clone().unwrap_or_default() } else { h.note.to_string() });
                }
                if !tech.cookies.is_empty() {
                    println!("\n■ 쿠키");
                    for c in &tech.cookies {
                        println!("  {} secure={} httponly={} samesite={}", c.name, c.secure, c.httponly,
                            c.samesite.clone().unwrap_or_else(|| "-".into()));
                        for i in &c.issues {
                            println!("      - {i}");
                        }
                    }
                }
                let findings = tech.findings(&target);
                println!("\n■ 발견 {}건", findings.len());
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.title, f.remediation);
                }
            }
            Ok(true)
        }
        "scan" => {
            let auth = match load_authorization(args.get("scope").map(std::path::Path::new)) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("✖ {e}");
                    std::process::exit(3);
                }
            };
            let target = args.get("target").unwrap_or("").to_string();
            if target.is_empty() {
                eprintln!("✖ --target 이 필요합니다 (HOST 또는 CIDR).");
                std::process::exit(2);
            }
            let mut plan = crate::net::ScanPlan {
                hosts: crate::net::expand_hosts(&target).map_err(|e| anyhow::anyhow!("{e}"))?,
                ports: match args.get("ports") {
                    Some(p) => crate::net::parse_ports(p).map_err(|e| anyhow::anyhow!("{e}"))?,
                    None => crate::net::default_ports(),
                },
                timeout_ms: args.num("timeout", 1200.0) as u64,
                concurrency: args.num("concurrency", 128.0) as usize,
                grab_banner: !args.has("no-banner"),
                max_hosts: 4096,
            };
            if let Ok(parsed) = url::Url::parse(&target) {
                if let Some(p) = parsed.port() {
                    plan.ports = vec![p];
                }
            }
            let report = crate::net::scan(&auth, &plan).await.map_err(|e| anyhow::anyhow!("{e}"))?;
            if args.has("json") {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "스캔 완료 — 호스트 {} · 열린 포트 {} · {:.1}초",
                    report.hosts.len(),
                    report.open,
                    report.duration_ms as f64 / 1000.0
                );
                for h in &report.hosts {
                    for p in &h.ports {
                        let svc = p
                            .service
                            .as_ref()
                            .map(|s| format!("{} {}", s.name, s.version.clone().unwrap_or_default()))
                            .unwrap_or_default();
                        println!("  {:<24} {:<6} {:<9} {}", h.host, p.port, p.state.label(), svc);
                    }
                }
                for f in &report.findings {
                    println!("  [{}] {} — {}", f.severity, f.title, f.remediation);
                }
            }
            let path = report_dir().join(format!("scan-{}.json", chrono::Local::now().format("%Y%m%d-%H%M%S")));
            let _ = std::fs::write(&path, serde_json::to_string_pretty(&report)?);
            println!("\n결과 저장: {}", path.display());
            Ok(true)
        }
        "discover" => {
            let auth = match load_authorization(args.get("scope").map(std::path::Path::new)) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("✖ {e}");
                    std::process::exit(3);
                }
            };
            let target = args.get("target").unwrap_or("").to_string();
            if target.is_empty() {
                eprintln!("✖ --target 이 필요합니다.");
                std::process::exit(2);
            }
            let client = crate::http::HttpClient::new(Arc::new(auth)).map_err(|e| anyhow::anyhow!(e))?;
            let mut plan = crate::discover::default_plan(&target);
            if let Some(ext) = args.get("ext") {
                plan.extensions = ext.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            }
            if args.has("vhost") {
                plan.vhost = true;
            }
            if let Some(n) = args.get("max") {
                plan.max_requests = n.parse().unwrap_or(plan.max_requests);
            }
            let report = crate::discover::run(&client, &plan).await.map_err(|e| anyhow::anyhow!("{e}"))?;
            if args.has("json") {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "디스커버리 완료 — 요청 {}건 · 발견 {}건 (기준선 {})",
                    report.requests,
                    report.hits.len(),
                    report.baseline_status
                );
                for h in report.hits.iter().take(60) {
                    println!("  [{}] {} {}", h.kind.label(), h.status, h.url);
                }
                for f in &report.findings {
                    println!("  [{}] {} — {}", f.severity, f.title, f.remediation);
                }
            }
            let path = report_dir().join(format!("discover-{}.json", chrono::Local::now().format("%Y%m%d-%H%M%S")));
            let _ = std::fs::write(&path, serde_json::to_string_pretty(&report)?);
            println!("\n결과 저장: {}", path.display());
            Ok(true)
        }
        "templates" => {
            let auth = match load_authorization(args.get("scope").map(std::path::Path::new)) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("✖ {e}");
                    std::process::exit(3);
                }
            };
            let target = args.get("target").unwrap_or("").to_string();
            if target.is_empty() {
                eprintln!("✖ --target 이 필요합니다.");
                std::process::exit(2);
            }
            let client = crate::http::HttpClient::new(Arc::new(auth)).map_err(|e| anyhow::anyhow!(e))?;
            let tags: Vec<String> = args
                .get_all("tags")
                .iter()
                .flat_map(|s| s.split(',').map(|x| x.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect();
            let tag_filter = if tags.is_empty() { None } else { Some(tags.as_slice()) };
            let min_sev = args.get("severity").unwrap_or("info").to_string();
            let mut matches = Vec::new();
            for t in crate::templates::builtin_templates() {
                match crate::templates::execute(&client, &t, &target, tag_filter, &min_sev).await {
                    Ok(m) => matches.extend(m),
                    Err(e) => eprintln!("  (템플릿 {} 실패: {})", t.id, e),
                }
            }
            let findings = crate::templates::to_findings(&matches);
            if args.has("json") {
                println!("{}", serde_json::to_string_pretty(&matches)?);
            } else {
                println!("템플릿 스캔 완료 — 매칭 {}건", matches.len());
                for m in &matches {
                    println!("  [{}] {} — {}", m.severity, m.name, m.url);
                }
                for f in &findings {
                    println!("  [{}] {} — {}", f.severity, f.title, f.remediation);
                }
            }
            let path = report_dir().join(format!("templates-{}.json", chrono::Local::now().format("%Y%m%d-%H%M%S")));
            let _ = std::fs::write(&path, serde_json::to_string_pretty(&matches)?);
            println!("\n결과 저장: {}", path.display());
            Ok(true)
        }
        "tui" => Ok(false),
        other => {
            eprintln!("알 수 없는 명령: {other}\n\n{}", help_text());
            Ok(true)
        }
    }
}

/// 환경 점검.
async fn doctor(args: &Args) -> anyhow::Result<()> {
    println!("REDFORGE 환경 점검\n");

    // 파이썬
    let python = std::env::var("FORGE_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let ver = std::process::Command::new(&python).arg("--version").output();
    match ver {
        Ok(out) => println!("✔ 파이썬     : {} ({python})", String::from_utf8_lossy(&out.stdout).trim()),
        Err(e) => println!("✖ 파이썬     : 실행 실패 ({python}) — {e}"),
    }

    // 인가
    match load_authorization(args.get("scope").map(std::path::Path::new)) {
        Ok(a) => {
            println!("✔ 인가 파일   : {}", a.source.display());
            println!("  engagement : {} ({} ~ {})", a.engagement.name,
                a.engagement.authorized_from.as_deref().unwrap_or("-"),
                a.engagement.authorized_until.as_deref().unwrap_or("-"));
            println!("  허용 대상   : {}건 / 금지 {}건", a.allow.len(), a.deny.len());
            println!("  RPS 상한    : {:?}", a.rps_limit());
            match a.check_period() {
                Ok(()) => println!("✔ 인가 기간   : 유효"),
                Err(e) => println!("✖ 인가 기간   : {e}"),
            }
        }
        Err(e) => println!("✖ 인가 파일   : {e}"),
    }

    // 프로바이더
    let providers = crate::providers::list();
    if providers.is_empty() {
        println!("⚠ LLM        : 연결된 프로바이더 없음 (TUI 의 /providers 에서 설정)");
    } else {
        for p in providers {
            let state = if p.has_key { "✔" } else { "◐" };
            println!("{state} LLM        : {} ({}) · {}", p.name, p.kind, p.default_model.clone().unwrap_or_default());
        }
    }

    // 커널 기동
    let dir = args.get("run-dir").map(PathBuf::from).unwrap_or_else(run_dir);
    match Kernel::start(None, None, &dir).await {
        Ok(k) => {
            let st = k.status().unwrap_or(json!({}));
            println!("✔ 커널        : 기동됨 · {}", st.get("run_dir").and_then(|v| v.as_str()).unwrap_or(""));
            k.shutdown().await;
        }
        Err(e) => println!("✖ 커널        : {e}"),
    }
    Ok(())
}
