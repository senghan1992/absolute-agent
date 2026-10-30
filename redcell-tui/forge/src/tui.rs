//! 터미널 UI — REDFORGE 대시보드.
//!
//! 탭: 콘솔 · 커널 · 스톰 · 발견 · 리포트
//! 입력창: 일반 입력은 목표(goal)로 에이전트에 전달, "/xxx" 는 내부 명령.
//! 대시보드는 스톰 진행률·요청률·이상 건수를 실시간으로 보여준다.

use std::io::{stdout, Stdout};
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Tabs, Wrap};
use ratatui::Terminal;

use crate::agent::{Agent, AgentConfig, AgentEvent, Shared};
use crate::cli;
use crate::kernel::Kernel;
use crate::providers;
use crate::report::{self, Finding, Report, ReportSummary};
use crate::scope::Authorization;
use crate::storm::{Anomaly, StormEngine, StormEvent, StormPlan, Template};

/// TUI 시작 설정.
pub struct TuiConfig {
    pub scope_path: Option<std::path::PathBuf>,
    pub target: Option<String>,
}

/// 탭.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Console,
    Kernel,
    Storm,
    Findings,
    Report,
}

impl Tab {
    const ALL: [Tab; 5] = [Tab::Console, Tab::Kernel, Tab::Storm, Tab::Findings, Tab::Report];
    fn title(self) -> &'static str {
        match self {
            Tab::Console => "콘솔",
            Tab::Kernel => "커널",
            Tab::Storm => "스톰",
            Tab::Findings => "발견",
            Tab::Report => "리포트",
        }
    }
}

/// 로그 한 줄.
#[derive(Debug, Clone)]
struct LogLine {
    kind: &'static str,
    text: String,
    at: String,
}

/// UI 로 전달되는 메시지.
enum Msg {
    Key(KeyEvent),
    Resize,
    Agent(AgentEvent),
}

/// 앱 상태.
struct App {
    tab: Tab,
    log: Vec<LogLine>,
    input: String,
    cursor: usize,
    findings: Vec<Finding>,
    anomalies: Vec<Anomaly>,
    storm_progress: Option<(u64, u64, f64)>,
    storm_requests: u64,
    kernel_code: String,
    kernel_output: String,
    scope: Option<Authorization>,
    scope_error: Option<String>,
    target: Option<String>,
    providers: Vec<providers::ProviderInfo>,
    shared: Arc<Shared>,
    kernel: Option<Arc<Kernel>>,
    agent_running: bool,
    status: String,
    busy: Option<String>,
    report_path: Option<String>,
    palette_open: bool,
    palette_index: usize,
    palette_filter: String,
    should_quit: bool,
}

impl App {
    fn new(shared: Arc<Shared>) -> Self {
        Self {
            tab: Tab::Console,
            log: Vec::new(),
            input: String::new(),
            cursor: 0,
            findings: Vec::new(),
            anomalies: Vec::new(),
            storm_progress: None,
            storm_requests: 0,
            kernel_code: "# 파이썬 커널 — 직접 실행되는 코드\n".to_string(),
            kernel_output: String::new(),
            scope: None,
            scope_error: None,
            target: None,
            providers: providers::list(),
            shared,
            kernel: None,
            agent_running: false,
            status: "준비됨 — /help 로 명령 목록".into(),
            busy: None,
            report_path: None,
            palette_open: false,
            palette_index: 0,
            palette_filter: String::new(),
            should_quit: false,
        }
    }

    fn push_log(&mut self, kind: &'static str, text: impl Into<String>) {
        let at = chrono::Local::now().format("%H:%M:%S").to_string();
        self.log.push(LogLine { kind, text: text.into(), at });
        if self.log.len() > 500 {
            self.log.drain(0..100);
        }
    }

    fn refresh_providers(&mut self) {
        self.providers = providers::list();
    }
}

/// 명령 팔레트 항목.
const COMMANDS: &[(&str, &str)] = &[
    ("/help", "명령 목록 보기"),
    ("/target", "대상 URL 설정 (예: /target http://127.0.0.1:8080)"),
    ("/scope", "인가 상태 보기"),
    ("/providers", "LLM 연결 상태 보기"),
    ("/recon", "대상 정찰 실행 (엔드포인트·지문 추출)"),
    ("/storm", "대상 스톕 실행 (고속 퍼징)"),
    ("/kernel", "커널 탭으로 이동"),
    ("/findings", "발견 탭으로 이동"),
    ("/report", "리포트 생성 (Markdown 저장)"),
    ("/autopilot", "자율 점검 실행 (예: /autopilot IDOR 를 찾아라)"),
    ("/stop", "진행 중인 작업 중지"),
    ("/clear", "콘솔 지우기"),
    ("/quit", "종료"),
];

/// TUI 실행.
pub async fn run(cfg: TuiConfig) -> anyhow::Result<()> {
    let shared = Shared::new();
    let mut app = App::new(shared.clone());

    // 인가 로드 (fail-closed).
    match cli::load_authorization(cfg.scope_path.as_deref()) {
        Ok(auth) => {
            app.push_log("scope", format!(
                "인가 로드 완료 — engagement '{}' · 허용 {}건 · RPS {:?}",
                auth.engagement.name,
                auth.allow.len(),
                auth.rps_limit()
            ));
            app.scope = Some(auth);
        }
        Err(e) => {
            app.scope_error = Some(e.to_string());
            app.push_log("scope", format!("✖ {e}"));
            app.status = "인가 파일 없음 — 공격성 도구는 차단됩니다 (fail-closed)".into();
        }
    }
    app.target = cfg.target.clone();
    if let Some(t) = &app.target {
        app.push_log("scope", format!("대상: {t}"));
    }

    // 파이썬 커널 기동 — TUI 에서 직접 코드를 실행한다.
    let dir = cli::run_dir();
    let scope_path = app.scope.as_ref().map(|a| a.source.clone());
    match Kernel::start(scope_path.as_deref(), app.target.as_deref(), &dir).await {
        Ok(k) => {
            app.push_log("kernel", format!("커널 기동 — {}", k.script_path().display()));
            app.kernel = Some(k);
        }
        Err(e) => app.push_log("err", format!("커널 기동 실패: {e}")),
    }

    // 터미널 준비.
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = event_loop(&mut terminal, &mut app, shared).await;

    // 복구.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

/// 메인 이벤트 루프.
async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    shared: Arc<Shared>,
) -> anyhow::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Msg>();

    // 입력 스레드.
    {
        let tx = tx.clone();
        std::thread::spawn(move || loop {
            match crossterm::event::read() {
                Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => {
                    if tx.send(Msg::Key(k)).is_err() {
                        break;
                    }
                }
                Ok(Event::Resize(_, _)) => {
                    if tx.send(Msg::Resize).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        });
    }

    // 에이전트 이벤트 구독.
    {
        let tx = tx.clone();
        let mut rx_ev = shared.events.subscribe();
        tokio::spawn(async move {
            while let Ok(ev) = rx_ev.recv().await {
                if tx.send(Msg::Agent(ev)).is_err() {
                    break;
                }
            }
        });
    }

    let mut ticker = tokio::time::interval(Duration::from_millis(120));
    loop {
        terminal.draw(|f| draw(f, app))?;
        tokio::select! {
            msg = rx.recv() => {
                let Some(msg) = msg else { break };
                match msg {
                    Msg::Key(k) => handle_key(app, k, &shared),
                    Msg::Resize => {}
                    Msg::Agent(ev) => handle_agent_event(app, ev),
                }
            }
            _ = ticker.tick() => {}
        }
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

/// 키 입력 처리.
fn handle_key(app: &mut App, key: KeyEvent, shared: &Arc<Shared>) {
    // 팔레트가 열려 있으면 별도 처리.
    if app.palette_open {
        match key.code {
            KeyCode::Esc => {
                app.palette_open = false;
                app.palette_filter.clear();
            }
            KeyCode::Up => app.palette_index = app.palette_index.saturating_sub(1),
            KeyCode::Down => app.palette_index = (app.palette_index + 1).min(filtered_commands(&app.palette_filter).len().saturating_sub(1)),
            KeyCode::Backspace => {
                app.palette_filter.pop();
                app.palette_index = 0;
            }
            KeyCode::Enter => {
                let list = filtered_commands(&app.palette_filter);
                if let Some((cmd, _)) = list.get(app.palette_index) {
                    let cmd = cmd.to_string();
                    app.palette_open = false;
                    app.palette_filter.clear();
                    app.input = cmd;
                    app.cursor = app.input.chars().count();
                    submit(app, shared);
                } else {
                    app.palette_open = false;
                }
            }
            KeyCode::Char(c) => {
                app.palette_filter.push(c);
                app.palette_index = 0;
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if app.agent_running || app.busy.is_some() {
                app.agent_running = false;
                app.busy = None;
                app.status = "작업 중지 요청됨.".into();
                app.push_log("sys", "작업 중지 요청됨.");
            } else {
                app.should_quit = true;
            }
        }
        KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => app.should_quit = true,
        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.palette_open = true;
            app.palette_index = 0;
        }
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // 커널 코드 실행 (터미널에서 Ctrl+Enter 가 구분되지 않는 환경 대비).
            if app.tab == Tab::Kernel {
                run_kernel_code(app);
            } else {
                app.status = "Ctrl+R 은 커널 탭에서 코드를 실행합니다.".into();
            }
        }
        KeyCode::Tab => {
            let idx = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
            app.tab = Tab::ALL[(idx + 1) % Tab::ALL.len()];
        }
        KeyCode::Esc => {
            if !app.input.is_empty() {
                app.input.clear();
                app.cursor = 0;
            } else {
                app.tab = Tab::Console;
            }
        }
        KeyCode::Enter => {
            // 커널 탭 + Ctrl = 코드 즉시 실행.
            if app.tab == Tab::Kernel {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    run_kernel_code(app);
                } else {
                    app.kernel_code.push(char::from(10));
                }
            } else {
                submit(app, shared);
            }
        }
        KeyCode::Backspace => {
            if app.tab == Tab::Kernel {
                app.kernel_code.pop();
                return;
            }
            if app.cursor > 0 {
                let idx = char_index(&app.input, app.cursor - 1);
                app.input.remove(idx);
                app.cursor -= 1;
            }
        }
        KeyCode::Left => app.cursor = app.cursor.saturating_sub(1),
        KeyCode::Right => app.cursor = (app.cursor + 1).min(app.input.chars().count()),
        KeyCode::Home => app.cursor = 0,
        KeyCode::End => app.cursor = app.input.chars().count(),
        KeyCode::Char(c) => {
            // 커널 탭에서는 입력이 코드 편집기로 들어간다.
            if app.tab == Tab::Kernel && !key.modifiers.contains(KeyModifiers::CONTROL) {
                app.kernel_code.push(c);
                return;
            }
            let idx = char_index(&app.input, app.cursor);
            app.input.insert(idx, c);
            app.cursor += 1;
        }
        _ => {}
    }
}

/// 커널 탭의 코드를 실행한다 (Ctrl+Enter).
fn run_kernel_code(app: &mut App) {
    let Some(kernel) = app.kernel.clone() else {
        app.status = "커널이 준비되지 않았습니다.".into();
        return;
    };
    let code = app.kernel_code.clone();
    if code.trim().is_empty() {
        app.status = "실행할 코드가 없습니다.".into();
        return;
    }
    app.status = "커널 실행 중…".into();
    let shared = app.shared.clone();
    tokio::spawn(async move {
        let text = match kernel.exec(&code, 30_000).await {
            Ok(out) => format!("$ {}{}{}", code, char::from(10), out.combined()),
            Err(e) => format!("커널 오류: {}", e),
        };
        shared.emit(AgentEvent::KernelOutput(text));
    });
}

fn char_index(s: &str, char_pos: usize) -> usize {
    s.char_indices().nth(char_pos).map(|(i, _)| i).unwrap_or(s.len())
}

fn filtered_commands(filter: &str) -> Vec<(&'static str, &'static str)> {
    let f = filter.trim_start_matches('/').to_lowercase();
    COMMANDS
        .iter()
        .filter(|(cmd, desc)| f.is_empty() || cmd.to_lowercase().contains(&f) || desc.contains(&f))
        .copied()
        .collect()
}

/// 입력 제출 — 명령 또는 목표.
fn submit(app: &mut App, shared: &Arc<Shared>) {
    let text = app.input.trim().to_string();
    app.input.clear();
    app.cursor = 0;
    if text.is_empty() {
        return;
    }
    app.push_log("you", &text);

    if let Some(cmd) = text.strip_prefix('/') {
        let (name, rest) = cmd.split_once(' ').unwrap_or((cmd, ""));
        let rest = rest.trim();
        run_command(app, name, rest, shared);
        return;
    }

    // 일반 입력 → 자율 에이전트 목표.
    start_agent(app, &text, shared);
}

/// 내부 명령 실행.
fn run_command(app: &mut App, name: &str, rest: &str, shared: &Arc<Shared>) {
    match name {
        "help" => {
            for (cmd, desc) in COMMANDS {
                app.push_log("help", format!("{cmd:<12} {desc}"));
            }
            app.status = "명령 목록을 콘솔에 출력했습니다.".into();
        }
        "target" => {
            if rest.is_empty() {
                app.status = "사용법: /target http://host:port".into();
            } else {
                app.target = Some(rest.to_string());
                app.push_log("scope", format!("대상 설정: {rest}"));
                app.status = "대상이 설정되었습니다.".into();
            }
        }
        "scope" => {
            match &app.scope {
                Some(a) => {
                    app.push_log("scope", format!(
                        "engagement={} · until={} · allow={} · deny={} · rps={:?}",
                        a.engagement.name,
                        a.engagement.authorized_until.clone().unwrap_or_else(|| "-".into()),
                        a.allow.len(),
                        a.deny.len(),
                        a.rps_limit()
                    ));
                }
                None => app.push_log("scope", format!("✖ {}", app.scope_error.clone().unwrap_or_default())),
            }
        }
        "providers" => {
            app.refresh_providers();
            let providers_snapshot = app.providers.clone();
            for p in providers_snapshot {
                app.push_log(
                    "llm",
                    format!(
                        "{} · {} · base={} · model={} · key={}",
                        p.name,
                        p.kind,
                        p.base_url.clone().unwrap_or_else(|| "-".into()),
                        p.default_model.clone().unwrap_or_else(|| "-".into()),
                        if p.has_key { "있음" } else { "없음" }
                    ),
                );
            }
            app.status = "프로바이더 목록을 콘솔에 출력했습니다.".into();
        }
        "recon" => {
            let Some(target) = app.target.clone() else {
                app.status = "먼저 /target 으로 대상을 지정하세요.".into();
                return;
            };
            let Some(auth) = app.scope.clone() else {
                app.status = "인가 파일이 없어 실행할 수 없습니다.".into();
                return;
            };
            let (host, port, _) = match crate::scope::split_authority(&target) {
                Ok(v) => v,
                Err(e) => {
                    app.push_log("err", format!("URL 오류: {e}"));
                    return;
                }
            };
            if let Err(e) = auth.check(&host, port) {
                app.push_log("err", format!("인가 게이트 차단: {e}"));
                app.status = "인가 게이트가 차단했습니다.".into();
                return;
            }
            app.busy = Some("정찰 중".into());
            let shared = shared.clone();
            let target = target.clone();
            tokio::spawn(async move {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .user_agent("REDFORGE/0.1")
                    .build();
                if let Ok(client) = client {
                    if let Ok(resp) = client.get(&target).send().await {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        let r = crate::recon::extract(&body, &target, status);
                        if !r.fingerprint.key.is_empty() {
                            *shared.fingerprint.lock() = r.fingerprint.key.clone();
                        }
                        let mut msg = format!("status={status} · 지문={} · 엔드포인트 {}개", r.fingerprint.key, r.endpoints.len());
                        for ep in r.endpoints.iter().take(30) {
                            msg.push_str(&format!("\n  {} {} [{}]", ep.method, ep.url, ep.source));
                        }
                        shared.emit(AgentEvent::Note(msg));
                    }
                }
                shared.emit(AgentEvent::Error("정찰 완료".into()));
            });
            app.status = "정찰을 시작했습니다.".into();
        }
        "storm" => {
            let Some(target) = app.target.clone() else {
                app.status = "먼저 /target 을 지정하세요.".into();
                return;
            };
            let Some(auth) = app.scope.clone() else {
                app.status = "인가 파일이 없어 실행할 수 없습니다.".into();
                return;
            };
            let (host, port, _) = match crate::scope::split_authority(&target) {
                Ok(v) => v,
                Err(e) => {
                    app.push_log("err", format!("URL 오류: {e}"));
                    return;
                }
            };
            if let Err(e) = auth.check(&host, port) {
                app.push_log("err", format!("인가 게이트 차단: {e}"));
                app.status = "인가 게이트가 차단했습니다.".into();
                return;
            }
            app.tab = Tab::Storm;
            app.busy = Some("정찰 → 스톰 실행 중".into());
            let shared_run = shared.clone();
            let (tx, mut rx) = tokio::sync::broadcast::channel::<StormEvent>(256);
            let target_url = target.clone();
            let mut plan = StormPlan::default();
            plan.rps = auth.rps_limit();
            tokio::spawn(async move {
                let shared = shared_run.clone();
                let engine = match StormEngine::new() {
                    Ok(e) => e,
                    Err(e) => {
                        shared.emit(AgentEvent::Error(format!("스톰 엔진 실패: {e}")));
                        return;
                    }
                };
                // 1) 정찰 — 실제 파라미터가 있는 표면을 먼저 찾는다.
                let mut templates: Vec<Template> = Vec::new();
                if let Ok(client) = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(8))
                    .user_agent("REDFORGE/0.1")
                    .build()
                {
                    if let Ok(resp) = client.get(&target_url).send().await {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        let r = crate::recon::extract(&body, &target_url, status);
                        for ep in r.endpoints.iter().filter(|e| !e.params.is_empty()) {
                            let mut t = crate::recon::to_template(ep);
                            t.name = format!("{} {}", ep.method, ep.url);
                            templates.push(t);
                        }
                    }
                }
                // 대상 자체(쿼리 파라미터 포함)도 포함.
                let mut base = Template::get(&target_url);
                if let Ok(parsed) = url::Url::parse(&target_url) {
                    for (k, v) in parsed.query_pairs() {
                        base.params.push(crate::storm::Param::new(&k, &v));
                    }
                }
                base.name = format!("GET {}", base.url);
                templates.insert(0, base);
                plan.templates = templates;

                let report = engine.run(&plan, &auth, tx).await;
                match report {
                    Ok(r) => {
                        let mut msg = format!("스톰 완료 — 요청 {} · {:.1} req/s · 이상 {}건", r.requests, r.rps, r.anomalies.len());
                        for a in r.anomalies.iter().take(20) {
                            msg.push_str(&format!("\n  [{}] {} {:?} payload={:?} 신호={:?}", a.severity, a.template, a.param, a.payload, a.signals));
                        }
                        shared.emit(AgentEvent::Note(msg));
                    }
                    Err(e) => shared.emit(AgentEvent::Error(format!("스톰 실패: {e}"))),
                }
            });
            // 브로드캐스트 수신 태스크.
            let shared2 = shared.clone();
            tokio::spawn(async move {
                while let Ok(ev) = rx.recv().await {
                    match &ev {
                        StormEvent::Anomaly(a) => {
                            shared2.emit(AgentEvent::Note(format!(
                                "이상 [{}] {} {:?} — {} (신호 {:?})",
                                a.severity, a.template, a.param, a.payload, a.signals
                            )));
                        }
                        StormEvent::Finished { requests, anomalies } => {
                            shared2.emit(AgentEvent::Note(format!("스톰 종료 — 요청 {requests} · 이상 {anomalies}")));
                        }
                        _ => {}
                    }
                    shared2.emit(AgentEvent::Storm(ev));
                }
            });
            app.status = "스톰을 시작했습니다.".into();
        }
        "idor" => {
            let Some(target) = app.target.clone() else {
                app.status = "먼저 /target 을 지정하세요.".into();
                return;
            };
            let param = rest.split_whitespace().next().unwrap_or("id").to_string();
            let Some(auth) = app.scope.clone() else {
                app.status = "인가 파일이 없어 실행할 수 없습니다.".into();
                return;
            };
            let (host, port, _) = match crate::scope::split_authority(&target) {
                Ok(v) => v,
                Err(e) => {
                    app.push_log("err", format!("URL 오류: {e}"));
                    return;
                }
            };
            if let Err(e) = auth.check(&host, port) {
                app.push_log("err", format!("인가 게이트 차단: {e}"));
                app.status = "인가 게이트가 차단했습니다.".into();
                return;
            }
            app.busy = Some("IDOR 탐색 중".into());
            let shared = shared.clone();
            tokio::spawn(async move {
                let client = match crate::probes::ProbeClient::new(Arc::new(auth)) {
                    Ok(c) => c,
                    Err(e) => {
                        shared.emit(AgentEvent::Error(format!("프로브 클라이언트 실패: {e}")));
                        return;
                    }
                };
                let cfg = crate::probes::idor::IdorConfig::new(&target, &param);
                match crate::probes::idor::run(&client, &cfg).await {
                    Ok(report) => {
                        for f in &report.findings {
                            shared.add_finding(f.clone());
                        }
                        let mut msg = format!("IDOR 탐색 — {} · 요청 {}건 · 판정 {:?}", report.param, report.requests, report.verdict);
                        for s in report.samples.iter().filter(|s| s.differs).take(10) {
                            msg.push_str(&format!("
  {}={} → status {} len {} {:?}", report.param, s.value, s.status, s.len, s.identifiers));
                        }
                        if !report.findings.is_empty() {
                            for f in &report.findings {
                                msg.push_str(&format!("
  [{}] {} — {}", f.severity, f.title, f.remediation));
                            }
                        }
                        shared.emit(AgentEvent::Note(msg));
                    }
                    Err(e) => shared.emit(AgentEvent::Error(format!("IDOR 탐색 실패: {e}"))),
                }
            });
            app.status = "IDOR 탐색을 시작했습니다.".into();
        }
        "tamper" => {
            let Some(target) = app.target.clone() else {
                app.status = "먼저 /target 을 지정하세요.".into();
                return;
            };
            let param = rest.split_whitespace().next().unwrap_or("price").to_string();
            let Some(auth) = app.scope.clone() else {
                app.status = "인가 파일이 없어 실행할 수 없습니다.".into();
                return;
            };
            let (host, port, _) = match crate::scope::split_authority(&target) {
                Ok(v) => v,
                Err(e) => {
                    app.push_log("err", format!("URL 오류: {e}"));
                    return;
                }
            };
            if let Err(e) = auth.check(&host, port) {
                app.push_log("err", format!("인가 게이트 차단: {e}"));
                app.status = "인가 게이트가 차단했습니다.".into();
                return;
            }
            app.busy = Some("가격 변조 탐색 중".into());
            let shared = shared.clone();
            tokio::spawn(async move {
                let client = match crate::probes::ProbeClient::new(Arc::new(auth)) {
                    Ok(c) => c,
                    Err(e) => {
                        shared.emit(AgentEvent::Error(format!("프로브 클라이언트 실패: {e}")));
                        return;
                    }
                };
                let mut cfg = crate::probes::tamper::TamperConfig::new(&target, &param);
                if target.contains("?") {
                    cfg.method = "GET".into();
                }
                match crate::probes::tamper::run(&client, &cfg).await {
                    Ok(report) => {
                        for f in &report.findings {
                            shared.add_finding(f.clone());
                        }
                        let mut msg = format!("가격 변조 탐색 — {} · 기준 합계 {:?} · 요청 {}건", report.param, report.baseline_total, report.requests);
                        for a in report.attempts.iter().take(10) {
                            msg.push_str(&format!("
  {}={} → status {} {:?} 합계 {:?}", report.param, a.value, a.status, a.verdict, a.observed_total));
                        }
                        if !report.findings.is_empty() {
                            for f in &report.findings {
                                msg.push_str(&format!("
  [{}] {} — {}", f.severity, f.title, f.remediation));
                            }
                        }
                        shared.emit(AgentEvent::Note(msg));
                    }
                    Err(e) => shared.emit(AgentEvent::Error(format!("가격 변조 탐색 실패: {e}"))),
                }
            });
            app.status = "가격 변조 탐색을 시작했습니다.".into();
        }
        "kernel" => app.tab = Tab::Kernel,
        "findings" => app.tab = Tab::Findings,
        "report" => {
            let md = build_report(app);
            let dir = cli::report_dir();
            let path = dir.join(format!("report-{}.md", chrono::Local::now().format("%Y%m%d-%H%M%S")));
            match std::fs::write(&path, md) {
                Ok(_) => {
                    app.report_path = Some(path.display().to_string());
                    app.push_log("report", format!("리포트 저장: {}", path.display()));
                    app.status = "리포트를 생성했습니다.".into();
                }
                Err(e) => app.push_log("err", format!("리포트 저장 실패: {e}")),
            }
            app.tab = Tab::Report;
        }
        "autopilot" => {
            if rest.is_empty() {
                app.status = "사용법: /autopilot <목표>".into();
            } else {
                start_agent(app, rest, shared);
            }
        }
        "stop" => {
            app.agent_running = false;
            app.busy = None;
            app.status = "중지 요청.".into();
        }
        "clear" => app.log.clear(),
        "quit" => app.should_quit = true,
        other => {
            app.push_log("err", format!("알 수 없는 명령: /{other} (F1 또는 /help)"));
        }
    }
}

/// 자율 에이전트 시작.
fn start_agent(app: &mut App, goal: &str, shared: &Arc<Shared>) {
    let goal = goal.to_string();
    let Some(auth) = app.scope.clone() else {
        app.status = "인가 파일이 없어 에이전트를 시작할 수 없습니다 (fail-closed).".into();
        app.push_log("err", "인가 파일 없음 — 에이전트 실행 차단.");
        return;
    };
    let Some(provider) = crate::agent::default_provider() else {
        app.status = "연결된 LLM 이 없습니다 — ~/.redcell/providers.json 을 설정하세요.".into();
        app.push_log("err", "LLM 미연결 — /providers 로 확인하세요.");
        return;
    };
    if provider.api_key.is_none() && provider.kind != "openai-compat" {
        app.status = "API 키가 없습니다.".into();
        app.push_log("err", "API 키 미설정.");
        return;
    }
    app.agent_running = true;
    app.busy = Some("에이전트 실행 중".into());
    app.status = "자율 점검을 시작했습니다.".into();
    app.push_log("agent", format!("▶ 목표: {goal}"));

    let shared = shared.clone();
    let kernel = app.kernel.clone();
    let auth = Arc::new(auth);
    let target = app.target.clone();
    tokio::spawn(async move {
        // 커널이 없으면 기동.
        let kernel = match kernel {
            Some(k) => k,
            None => {
                let dir = cli::run_dir();
                match Kernel::start(Some(auth.source.as_path()), target.as_deref(), &dir).await {
                    Ok(k) => k,
                    Err(e) => {
                        shared.emit(AgentEvent::Error(format!("커널 기동 실패: {e}")));
                        return;
                    }
                }
            }
        };
        let agent = Agent {
            provider,
            kernel,
            auth,
            shared: shared.clone(),
            config: AgentConfig::default(),
            target,
            fingerprint: shared.fingerprint.lock().clone(),
        };
        match agent.run(&goal).await {
            Ok(summary) => shared.emit(AgentEvent::Done(summary)),
            Err(e) => shared.emit(AgentEvent::Error(format!("에이전트 오류: {e}"))),
        }
    });
}

/// 에이전트 이벤트 처리.
fn handle_agent_event(app: &mut App, ev: AgentEvent) {
    match ev {
        AgentEvent::Turn(n) => app.push_log("agent", format!("── 턴 {n} ──")),
        AgentEvent::Assistant(text) => {
            for line in text.lines() {
                app.push_log("llm", line.to_string());
            }
        }
        AgentEvent::ToolStart { name, summary } => app.push_log("tool", format!("→ {name}: {}", summary.replace('\n', " "))),
        AgentEvent::ToolEnd { name, summary } => app.push_log("tool", format!("← {name}: {}", summary.replace('\n', " "))),
        AgentEvent::Storm(ev) => handle_storm_event(app, ev),
        AgentEvent::KernelOutput(text) => {
            app.kernel_output.push_str(&text);
            app.kernel_output.push(char::from(10));
            if app.kernel_output.len() > 60_000 {
                let cut = app.kernel_output.len() - 40_000;
                app.kernel_output = app.kernel_output[cut..].to_string();
            }
            app.status = "커널 실행 완료.".into();
        }
        AgentEvent::Note(text) => {
            for line in text.lines() {
                app.push_log("note", line.to_string());
            }
        }
        AgentEvent::Done(summary) => {
            app.agent_running = false;
            app.busy = None;
            app.push_log("agent", format!("■ 완료: {summary}"));
            app.status = "점검이 끝났습니다 — /report 로 리포트 생성.".into();
            app.findings = app.shared.findings.lock().clone();
        }
        AgentEvent::Error(msg) => {
            app.agent_running = false;
            app.busy = None;
            app.push_log("err", msg.clone());
            app.status = msg;
        }
    }
}

/// 스톰 이벤트 처리.
fn handle_storm_event(app: &mut App, ev: StormEvent) {
    match ev {
        StormEvent::Progress { done, total, rps } => {
            app.storm_progress = Some((done, total, rps));
            app.storm_requests = done;
        }
        StormEvent::Anomaly(a) => {
            app.anomalies.insert(0, a);
            if app.anomalies.len() > 200 {
                app.anomalies.pop();
            }
        }
        StormEvent::Finished { requests, .. } => {
            app.storm_requests = requests;
            app.busy = None;
        }
        _ => {}
    }
}

/// 리포트 생성.
fn build_report(app: &App) -> String {
    let mut findings = app.shared.findings.lock().clone();
    for a in &app.anomalies {
        if a.signals.is_empty() {
            continue;
        }
        for sig in &a.signals {
            findings.push(report::finding_from_signal(
                sig,
                &a.template,
                &a.evidence,
                &format!("{} 에 payload={:?} 주입 → status {} · lenΔ {}", a.template, a.payload, a.status, a.len_delta),
            ));
        }
    }
    report::sort_findings(&mut findings);
    let scope_list: Vec<String> = app
        .scope
        .as_ref()
        .map(|a| a.allow.iter().map(|r| format!("{r:?}")).collect())
        .unwrap_or_default();
    let rep = Report {
        generated_at: chrono::Local::now().to_rfc3339(),
        engagement: app.scope.as_ref().map(|a| a.engagement.name.clone()).unwrap_or_else(|| "(미설정)".into()),
        scope: scope_list,
        target: app.target.clone(),
        summary: ReportSummary::of(&findings),
        findings,
        stats: vec![
            ("스톰 요청".into(), app.storm_requests.to_string()),
            ("이상 응답".into(), app.anomalies.len().to_string()),
            ("커널 기록".into(), app.kernel_output.lines().count().to_string()),
        ],
    };
    report::to_markdown(&rep)
}

/// 화면 그리기.
fn draw(f: &mut ratatui::Frame, app: &App) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5), Constraint::Length(3), Constraint::Length(1)])
        .split(area);

    draw_header(f, chunks[0], app);
    draw_body(f, chunks[1], app);
    draw_input(f, chunks[2], app);
    draw_status(f, chunks[3], app);

    if app.palette_open {
        draw_palette(f, area, app);
    }
}

/// 헤더.
fn draw_header(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let scope_text = match (&app.scope, &app.scope_error) {
        (Some(a), _) => format!(
            "✔ 인가 {} · 대상 {} · RPS {:?}",
            a.engagement.name,
            app.target.clone().unwrap_or_else(|| "-".into()),
            a.rps_limit()
        ),
        (None, Some(e)) => format!("✖ 인가 없음 — {e}"),
        _ => "✖ 인가 없음".into(),
    };
    let provider_text = app
        .providers
        .iter()
        .find(|p| p.has_key)
        .map(|p| format!("LLM {}", p.name))
        .unwrap_or_else(|| "LLM 미연결".into());
    let line = Line::from(vec![
        Span::styled(" REDFORGE ", Style::default().fg(Color::Black).bg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::raw(format!(" {scope_text}  │  {provider_text}")),
    ]);
    let block = Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(Color::DarkGray));
    f.render_widget(Paragraph::new(line).block(block), area);
}

/// 본문 (탭 + 콘텐츠).
fn draw_body(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let rows = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(1), Constraint::Min(1)]).split(area);
    let titles: Vec<Line> = Tab::ALL.iter().map(|t| Line::from(t.title())).collect();
    f.render_widget(
        Tabs::new(titles)
            .select(Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0))
            .highlight_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        rows[0],
    );

    match app.tab {
        Tab::Console => {
            let items: Vec<ListItem> = app
                .log
                .iter()
                .rev()
                .take(400)
                .rev()
                .map(|l| {
                    let color = match l.kind {
                        "you" => Color::Cyan,
                        "llm" => Color::Green,
                        "tool" => Color::Magenta,
                        "err" => Color::Red,
                        "help" => Color::DarkGray,
                        "note" => Color::Yellow,
                        "scope" => Color::Blue,
                        _ => Color::Gray,
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{} ", l.at), Style::default().fg(Color::DarkGray)),
                        Span::styled(l.text.clone(), Style::default().fg(color)),
                    ]))
                })
                .collect();
            let block = Block::default().borders(Borders::ALL).title(" 콘솔 ");
            f.render_widget(List::new(items).block(block), rows[1]);
        }
        Tab::Kernel => {
            let cols = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);
            let code = Paragraph::new(app.kernel_code.as_str())
                .block(Block::default().borders(Borders::ALL).title(" 커널 코드 (타이핑=편집 · Ctrl+Enter 실행) "))
                .wrap(Wrap { trim: false });
            let out = Paragraph::new(app.kernel_output.as_str())
                .block(Block::default().borders(Borders::ALL).title(" 실행 결과 "))
                .wrap(Wrap { trim: false });
            f.render_widget(code, cols[0]);
            f.render_widget(out, cols[1]);
        }
        Tab::Storm => {
            let inner = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(3), Constraint::Min(1)]).split(rows[1]);
            let (done, total, rps) = app.storm_progress.unwrap_or((0, 0, 0.0));
            let ratio = if total > 0 { done as f64 / total as f64 } else { 0.0 };
            let gauge = Gauge::default()
                .block(Block::default().borders(Borders::ALL).title(" 스톰 진행 "))
                .ratio(ratio.clamp(0.0, 1.0))
                .label(format!("{done}/{total} · {rps:.1} req/s · 요청 {}", app.storm_requests));
            f.render_widget(gauge, inner[0]);
            let items: Vec<ListItem> = app
                .anomalies
                .iter()
                .take(300)
                .map(|a| {
                    let color = match a.severity.as_str() {
                        "critical" => Color::Red,
                        "high" => Color::LightRed,
                        "medium" => Color::Yellow,
                        _ => Color::Gray,
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("[{}] ", a.severity), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                        Span::raw(format!("{} ", a.template)),
                        Span::styled(format!("{:?}", a.param), Style::default().fg(Color::Cyan)),
                        Span::raw(format!(" → {}", a.payload.replace('\n', " "))),
                        Span::styled(format!("  status={} lenΔ={}", a.status, a.len_delta), Style::default().fg(Color::DarkGray)),
                    ]))
                })
                .collect();
            f.render_widget(List::new(items).block(Block::default().borders(Borders::ALL).title(" 이상 응답 ")), inner[1]);
        }
        Tab::Findings => {
            let findings = app.shared.findings.lock().clone();
            let items: Vec<ListItem> = findings
                .iter()
                .map(|f| {
                    let color = match f.severity.as_str() {
                        "critical" => Color::Red,
                        "high" => Color::LightRed,
                        "medium" => Color::Yellow,
                        _ => Color::Gray,
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("[{}] ", f.severity), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                        Span::raw(f.title.clone()),
                        Span::styled(format!("  — {}", f.target), Style::default().fg(Color::DarkGray)),
                    ]))
                })
                .collect();
            f.render_widget(List::new(items).block(Block::default().borders(Borders::ALL).title(" 발견 ")), rows[1]);
        }
        Tab::Report => {
            let md = build_report(app);
            let text = if let Some(p) = &app.report_path {
                format!("저장됨: {p}\n\n{md}")
            } else {
                md
            };
            f.render_widget(
                Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" 리포트 ")).wrap(Wrap { trim: false }),
                rows[1],
            );
        }
    }
}

/// 입력창.
fn draw_input(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" 입력 (목표 또는 /명령) ");
    let text = if app.input.is_empty() {
        Line::from(Span::styled("목표를 입력하거나 /help 로 명령 목록을 보세요", Style::default().fg(Color::DarkGray)))
    } else {
        Line::from(app.input.as_str())
    };
    f.render_widget(Paragraph::new(text).block(block), area);
}

/// 상태줄.
fn draw_status(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let left = if let Some(busy) = &app.busy {
        format!("● {busy}")
    } else {
        "○ idle".to_string()
    };
    let right = "Tab 탭전환 · Ctrl+P 명령 · Ctrl+C 중지/종료".to_string();
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(left, Style::default().fg(Color::Green)),
            Span::raw("  │  "),
            Span::raw(app.status.clone()),
            Span::styled(format!("   {right}"), Style::default().fg(Color::DarkGray)),
        ])),
        area,
    );
}

/// 명령 팔레트.
fn draw_palette(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let list = filtered_commands(&app.palette_filter);
    let width = area.width.saturating_sub(20).min(70).max(30);
    let height = (list.len() as u16 + 4).min(area.height.saturating_sub(4)).max(6);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 3;
    let rect = Rect { x, y, width, height };
    f.render_widget(Clear, rect);
    let items: Vec<ListItem> = list
        .iter()
        .enumerate()
        .map(|(i, (cmd, desc))| {
            let style = if i == app.palette_index {
                Style::default().fg(Color::Black).bg(Color::Red)
            } else {
                Style::default().fg(Color::Gray)
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{cmd:<12}"), style),
                Span::styled(format!(" {desc}"), Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" 명령 (필터: {}) ", app.palette_filter));
    f.render_widget(List::new(items).block(block), rect);
}
