//! REDFORGE 터미널 UI — 시큐리티 콘솔.
//!
//! 설계 원칙:
//!   - **키보드 우선** — 마우스 없이 모든 기능에 도달한다.
//!   - **정보 밀도** — 한 화면에 대상·상태·진행률·결과를 함께 보여준다.
//!   - **하나의 디자인 시스템** — 모든 색/간격은 `theme` 모듈이 관리한다.
//!   - **작은 터미널에서도 살아남는다** — 24×8 이하면 최소 레이아웃으로 폴백.
//!
//! 탭: 콘솔 · 커널 · 스톰 · 스캔 · 표면 · 발견 · 리포트

use std::io::{stdout, Stdout};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap};
use ratatui::Terminal;

use crate::agent::{Agent, AgentConfig, AgentEvent, Shared};
use crate::cli;
use crate::kernel::Kernel;
use crate::providers;
use crate::report::{self, Finding, Report, ReportSummary};
use crate::scope::Authorization;
use crate::storm::{Anomaly, StormEngine, StormEvent, StormPlan, Template};
use crate::theme;

/// TUI 시작 설정.
pub struct TuiConfig {
    pub scope_path: Option<std::path::PathBuf>,
    pub target: Option<String>,
}

/// 탭.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Console,
    Kernel,
    Storm,
    Scan,
    Surface,
    Findings,
    Report,
}

impl Tab {
    pub const ALL: [Tab; 7] = [
        Tab::Console,
        Tab::Kernel,
        Tab::Storm,
        Tab::Scan,
        Tab::Surface,
        Tab::Findings,
        Tab::Report,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Console => "콘솔",
            Tab::Kernel => "커널",
            Tab::Storm => "스톰",
            Tab::Scan => "스캔",
            Tab::Surface => "표면",
            Tab::Findings => "발견",
            Tab::Report => "리포트",
        }
    }

    /// 탭 바로의 아이콘.
    pub fn glyph(self) -> &'static str {
        match self {
            Tab::Console => "▸",
            Tab::Kernel => "⧉",
            Tab::Storm => "⚡",
            Tab::Scan => "◎",
            Tab::Surface => "▦",
            Tab::Findings => "◆",
            Tab::Report => "▤",
        }
    }

    /// 숫자 단축키 (1부터).
    pub fn shortcut(self) -> u8 {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0) as u8 + 1
    }
}

/// 로그 한 줄.
#[derive(Debug, Clone)]
struct LogLine {
    kind: &'static str,
    text: String,
    at: String,
}

/// 스캔 결과 한 행 (호스트/포트/서비스).
#[derive(Debug, Clone)]
pub struct ScanRow {
    pub host: String,
    pub port: u16,
    pub state: String,
    pub service: String,
    pub version: String,
    pub note: String,
}

/// 공격 표면 한 행 (엔드포인트/파라미터).
#[derive(Debug, Clone)]
pub struct SurfaceRow {
    pub method: String,
    pub url: String,
    pub params: String,
    pub source: String,
    pub status: String,
}

/// UI 로 전달되는 메시지.
enum Msg {
    Key(KeyEvent),
    Mouse(u16),
    Resize,
    Agent(AgentEvent),
}

/// 토스트 알림.
#[derive(Debug, Clone)]
struct Toast {
    text: String,
    kind: &'static str,
    born: Instant,
}

/// 앱 상태.
struct App {
    tab: Tab,
    log: Vec<LogLine>,
    log_scroll: usize,
    input: String,
    cursor: usize,
    history: Vec<String>,
    history_idx: Option<usize>,
    findings: Vec<Finding>,
    finding_sel: usize,
    anomalies: Vec<Anomaly>,
    storm_progress: Option<(u64, u64, f64)>,
    storm_requests: u64,
    scan_rows: Vec<ScanRow>,
    surface_rows: Vec<SurfaceRow>,
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
    help_open: bool,
    approval: Option<String>,
    toasts: Vec<Toast>,
    frame: u64,
    should_quit: bool,
}

impl App {
    fn new(shared: Arc<Shared>) -> Self {
        Self {
            tab: Tab::Console,
            log: Vec::new(),
            log_scroll: 0,
            input: String::new(),
            cursor: 0,
            history: Vec::new(),
            history_idx: None,
            findings: Vec::new(),
            finding_sel: 0,
            anomalies: Vec::new(),
            storm_progress: None,
            storm_requests: 0,
            scan_rows: Vec::new(),
            surface_rows: Vec::new(),
            kernel_code: "# 파이썬 커널 — 직접 실행되는 코드\n# Ctrl+Enter 로 실행\n".to_string(),
            kernel_output: String::new(),
            scope: None,
            scope_error: None,
            target: None,
            providers: providers::list(),
            shared,
            kernel: None,
            agent_running: false,
            status: "준비됨 — Ctrl+P 명령 팔레트 · F1 도움말".into(),
            busy: None,
            report_path: None,
            palette_open: false,
            palette_index: 0,
            palette_filter: String::new(),
            help_open: false,
            approval: None,
            toasts: Vec::new(),
            frame: 0,
            should_quit: false,
        }
    }

    fn push_log(&mut self, kind: &'static str, text: impl Into<String>) {
        let at = chrono::Local::now().format("%H:%M:%S").to_string();
        self.log.push(LogLine { kind, text: text.into(), at });
        if self.log.len() > 2000 {
            let cut = self.log.len() - 1500;
            self.log.drain(0..cut);
        }
        self.log_scroll = 0;
    }

    fn toast(&mut self, kind: &'static str, text: impl Into<String>) {
        self.toasts.push(Toast { text: text.into(), kind, born: Instant::now() });
        if self.toasts.len() > 5 {
            self.toasts.remove(0);
        }
    }

    fn refresh_providers(&mut self) {
        self.providers = providers::list();
    }
}

/// 명령 팔레트 항목.
const COMMANDS: &[(&str, &str, &str)] = &[
    ("/help", "명령 목록 보기", "F1"),
    ("/target", "대상 URL 설정", "/target http://127.0.0.1:8080"),
    ("/scope", "인가 상태 보기", ""),
    ("/providers", "LLM 연결 상태 보기", ""),
    ("/recon", "정찰 — 엔드포인트·지문 추출", ""),
    ("/scan", "포트 스캔 — 열린 포트·서비스 탐지", "/scan 10.0.0.0/24"),
    ("/discover", "콘텐츠 디스커버리 — 숨은 경로·파일 탐색", "/discover"),
    ("/templates", "템플릿 스캔 — 알려진 취약점·노출 점검", "/templates"),
    ("/storm", "스톰 실행 — 고속 변이 퍼징", ""),
    ("/idor", "IDOR 탐색 (다른 주체 리소스 접근)", "/idor id"),
    ("/tamper", "가격/수량 변조 탐색", "/tamper price"),
    ("/kernel", "커널 탭으로 이동", ""),
    ("/findings", "발견 탭으로 이동", ""),
    ("/report", "리포트 생성·저장 (Markdown + HTML)", ""),
    ("/autopilot", "자율 점검 실행", "/autopilot IDOR 를 찾아라"),
    ("/stop", "진행 중인 작업 중지", ""),
    ("/clear", "콘솔 지우기", ""),
    ("/quit", "종료", ""),
];

/// TUI 실행.
pub async fn run(cfg: TuiConfig) -> anyhow::Result<()> {
    let shared = Shared::new();
    let mut app = App::new(shared.clone());

    // 인가 로드 (fail-closed).
    match cli::load_authorization(cfg.scope_path.as_deref()) {
        Ok(auth) => {
            app.push_log("scope", format!(
                "인가 로드 완료 — engagement '{}' · 허용 {}건 · RPS {:.0}",
                auth.engagement.name,
                auth.allow.len(),
                auth.effective_rps()
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

    // 파이썬 커널 기동.
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
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = event_loop(&mut terminal, &mut app, shared).await;

    // 복구.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
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
                Ok(Event::Mouse(m)) => {
                    if tx.send(Msg::Mouse(m.row)).is_err() {
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

    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    loop {
        terminal.draw(|f| draw(f, app))?;
        tokio::select! {
            msg = rx.recv() => {
                let Some(msg) = msg else { break };
                match msg {
                    Msg::Key(k) => handle_key(app, k, &shared),
                    Msg::Mouse(y) => app.scroll_by(y),
                    Msg::Resize => {}
                    Msg::Agent(ev) => handle_agent_event(app, ev),
                }
            }
            _ = ticker.tick() => {
                app.frame = app.frame.wrapping_add(1);
                app.expire_toasts();
            }
        }
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

impl App {
    fn scroll_by(&mut self, y: u16) {
        // 마우스 휠: 위로 스크롤(작은 y) 하면 이전 내용을 본다.
        let delta = match y {
            0..=2 => 3,
            _ => 0,
        };
        self.log_scroll = (self.log_scroll + delta).min(self.log.len());
    }

    fn expire_toasts(&mut self) {
        let now = Instant::now();
        self.toasts.retain(|t| now.duration_since(t.born) < Duration::from_secs(4));
    }
}

/// 키 입력 처리.
fn handle_key(app: &mut App, key: KeyEvent, shared: &Arc<Shared>) {
    // 최우선: 승인 모달.
    if app.approval.is_some() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                app.approval = None;
                shared.resolve_approval(true);
                app.toast("ok", "코드 실행 승인");
                app.status = "코드를 실행합니다.".into();
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                app.approval = None;
                shared.set_auto_approve(true);
                shared.resolve_approval(true);
                app.toast("ok", "세션 전체 자동 승인 (주의)");
                app.status = "이후 모델 코드는 승인 없이 실행됩니다.".into();
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                app.approval = None;
                shared.resolve_approval(false);
                app.toast("err", "실행 거부");
                app.status = "실행을 거부했습니다.".into();
            }
            _ => {}
        }
        return;
    }

    // 팔레트.
    if app.palette_open {
        handle_palette_key(app, key, shared);
        return;
    }

    // 도움말 오버레이.
    if app.help_open {
        app.help_open = false;
        return;
    }

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Char('c') if ctrl => {
            if app.agent_running || app.busy.is_some() {
                app.agent_running = false;
                app.busy = None;
                app.status = "작업 중지 요청됨.".into();
                app.toast("err", "작업 중지");
                app.push_log("sys", "작업 중지 요청됨.");
            } else {
                app.should_quit = true;
            }
        }
        KeyCode::Char('q') if ctrl => app.should_quit = true,
        KeyCode::Char('p') if ctrl => {
            app.palette_open = true;
            app.palette_index = 0;
            app.palette_filter.clear();
        }
        KeyCode::F(1) => app.help_open = true,
        KeyCode::Char('?') => app.help_open = true,
        KeyCode::Char('r') if ctrl => {
            if app.tab == Tab::Kernel {
                run_kernel_code(app);
            } else {
                app.status = "Ctrl+R 은 커널 탭에서 코드를 실행합니다.".into();
            }
        }
        KeyCode::Tab => {
            let idx = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
            let next = if key.modifiers.contains(KeyModifiers::SHIFT) {
                (idx + Tab::ALL.len() - 1) % Tab::ALL.len()
            } else {
                (idx + 1) % Tab::ALL.len()
            };
            app.tab = Tab::ALL[next];
        }
        KeyCode::BackTab => {
            let idx = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
            app.tab = Tab::ALL[(idx + Tab::ALL.len() - 1) % Tab::ALL.len()];
        }
        KeyCode::Char(c @ '1'..='7') => {
            // 숫자 단축키는 **입력이 비어 있을 때만** — 입력창에 숫자를 쳐야 할 때 먹히면 안 된다.
            if app.input.is_empty() && app.tab != Tab::Kernel {
                if let Some(tab) = Tab::ALL.get(c as usize - 1) {
                    app.tab = *tab;
                }
            } else {
                let idx = char_index(&app.input, app.cursor);
                app.input.insert(idx, c);
                app.cursor += 1;
            }
        }
        KeyCode::PageUp => app.log_scroll = (app.log_scroll + 10).min(app.log.len()),
        KeyCode::PageDown => app.log_scroll = app.log_scroll.saturating_sub(10),
        KeyCode::Home if ctrl => app.log_scroll = app.log.len(),
        KeyCode::End if ctrl => app.log_scroll = 0,
        KeyCode::Up => {
            if app.tab == Tab::Findings {
                app.finding_sel = app.finding_sel.saturating_sub(1);
            } else {
                recall_history(app, -1);
            }
        }
        KeyCode::Down => {
            if app.tab == Tab::Findings {
                let max = app.findings.len().saturating_sub(1);
                app.finding_sel = (app.finding_sel + 1).min(max);
            } else {
                recall_history(app, 1);
            }
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
            if app.tab == Tab::Kernel {
                if ctrl {
                    run_kernel_code(app);
                } else {
                    app.kernel_code.push('\n');
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
            if app.tab == Tab::Kernel && !ctrl {
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

/// 팔레트 키 처리.
fn handle_palette_key(app: &mut App, key: KeyEvent, shared: &Arc<Shared>) {
    let list = filtered_commands(&app.palette_filter);
    match key.code {
        KeyCode::Esc => {
            app.palette_open = false;
            app.palette_filter.clear();
        }
        KeyCode::Up => app.palette_index = app.palette_index.saturating_sub(1),
        KeyCode::Down => app.palette_index = (app.palette_index + 1).min(list.len().saturating_sub(1)),
        KeyCode::Backspace => {
            app.palette_filter.pop();
            app.palette_index = 0;
        }
        KeyCode::Enter => {
            let list = filtered_commands(&app.palette_filter);
            if let Some((cmd, _, _)) = list.get(app.palette_index) {
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
}

/// 입력 히스토리.
fn recall_history(app: &mut App, dir: i32) {
    if app.history.is_empty() {
        return;
    }
    let idx = match app.history_idx {
        None => {
            if dir < 0 {
                app.history.len() - 1
            } else {
                return;
            }
        }
        Some(i) => {
            let next = i as i32 + dir;
            if next < 0 {
                return;
            }
            if next as usize >= app.history.len() {
                app.history_idx = None;
                app.input.clear();
                app.cursor = 0;
                return;
            }
            next as usize
        }
    };
    app.history_idx = Some(idx);
    app.input = app.history[idx].clone();
    app.cursor = app.input.chars().count();
}

/// 커널 탭의 코드를 실행한다.
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
            Ok(out) => format!("$ {}\n{}", code, out.combined()),
            Err(e) => format!("커널 오류: {}", e),
        };
        shared.emit(AgentEvent::KernelOutput(text));
    });
}

fn char_index(s: &str, char_pos: usize) -> usize {
    s.char_indices().nth(char_pos).map(|(i, _)| i).unwrap_or(s.len())
}

fn filtered_commands(filter: &str) -> Vec<(&'static str, &'static str, &'static str)> {
    let f = filter.trim_start_matches('/').to_lowercase();
    COMMANDS
        .iter()
        .filter(|(cmd, desc, _)| f.is_empty() || cmd.to_lowercase().contains(&f) || desc.contains(&f))
        .copied()
        .collect()
}

/// 입력 제출 — 명령 또는 목표.
fn submit(app: &mut App, shared: &Arc<Shared>) {
    let text = app.input.trim().to_string();
    app.input.clear();
    app.cursor = 0;
    app.history_idx = None;
    if text.is_empty() {
        return;
    }
    app.history.push(text.clone());
    app.push_log("you", &text);

    if let Some(cmd) = text.strip_prefix('/') {
        let (name, rest) = cmd.split_once(' ').unwrap_or((cmd, ""));
        let rest = rest.trim();
        run_command(app, name, rest, shared);
        return;
    }

    start_agent(app, &text, shared);
}

/// 내부 명령 실행.
fn run_command(app: &mut App, name: &str, rest: &str, shared: &Arc<Shared>) {
    match name {
        "help" => {
            for (cmd, desc, hint) in COMMANDS {
                let hint = if hint.is_empty() { String::new() } else { format!("  ({hint})") };
                app.push_log("help", format!("{cmd:<12} {desc}{hint}"));
            }
            app.status = "명령 목록을 콘솔에 출력했습니다.".into();
        }
        "target" => {
            if rest.is_empty() {
                app.status = "사용법: /target http://host:port".into();
            } else {
                app.target = Some(rest.to_string());
                app.push_log("scope", format!("대상 설정: {rest}"));
                app.toast("scope", "대상 설정됨");
                app.status = "대상이 설정되었습니다.".into();
            }
        }
        "scope" => {
            match &app.scope {
                Some(a) => {
                    app.push_log("scope", format!(
                        "engagement={} · until={} · allow={} · deny={} · rps={:.0} · 포트={:?}",
                        a.engagement.name,
                        a.engagement.authorized_until.clone().unwrap_or_else(|| "-".into()),
                        a.allow.len(),
                        a.deny.len(),
                        a.effective_rps(),
                        a.ports
                    ));
                }
                None => app.push_log("scope", format!("✖ {}", app.scope_error.clone().unwrap_or_default())),
            }
        }
        "providers" => {
            app.refresh_providers();
            let snapshot = app.providers.clone();
            for p in snapshot {
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
        "recon" => run_recon(app, shared),
        "scan" => run_scan(app, rest, shared),
        "discover" => run_discover(app, rest, shared),
        "templates" => run_templates(app, rest, shared),
        "storm" => run_storm(app, shared),
        "idor" => run_idor(app, rest, shared),
        "tamper" => run_tamper(app, rest, shared),
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
                    app.toast("report", "리포트 생성됨");
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
        "clear" => {
            app.log.clear();
            app.log_scroll = 0;
        }
        "quit" => app.should_quit = true,
        other => {
            app.push_log("err", format!("알 수 없는 명령: /{other} (F1 또는 /help)"));
        }
    }
}

/// 대상 확인 — 없으면 안내하고 종료.
fn require_target(app: &mut App) -> Option<String> {
    match &app.target {
        Some(t) => Some(t.clone()),
        None => {
            app.status = "먼저 /target 으로 대상을 지정하세요.".into();
            app.toast("err", "대상 미지정");
            None
        }
    }
}

/// 인가 확인 — 없으면 fail-closed.
fn require_scope(app: &mut App) -> Option<Authorization> {
    match &app.scope {
        Some(a) => Some(a.clone()),
        None => {
            app.status = "인가 파일이 없어 실행할 수 없습니다 (fail-closed).".into();
            app.toast("err", "인가 없음 — 차단");
            None
        }
    }
}

/// 정찰 실행.
fn run_recon(app: &mut App, shared: &Arc<Shared>) {
    let Some(target) = require_target(app) else { return };
    let Some(auth) = require_scope(app) else { return };
    app.busy = Some("정찰 중".into());
    let shared = shared.clone();
    tokio::spawn(async move {
        let client = match crate::http::HttpClient::new(Arc::new(auth)) {
            Ok(c) => c,
            Err(e) => {
                shared.emit(AgentEvent::Error(format!("클라이언트 실패: {e}")));
                return;
            }
        };
        match client.get(&target).await {
            Ok(resp) => {
                let r = crate::recon::extract(&resp.body, &target, resp.status);
                if !r.fingerprint.key.is_empty() {
                    *shared.fingerprint.lock() = r.fingerprint.key.clone();
                }
                let mut msg = format!(
                    "status={} · 지문={} · 엔드포인트 {}개",
                    resp.status,
                    if r.fingerprint.key.is_empty() { "(미확인)" } else { &r.fingerprint.key },
                    r.endpoints.len()
                );
                for ep in r.endpoints.iter().take(30) {
                    msg.push_str(&format!("\n  {} {} [{}]", ep.method, ep.url, ep.source));
                }
                shared.emit(AgentEvent::Note(msg));
            }
            Err(e) => shared.emit(AgentEvent::Error(format!("정찰 실패: {e}"))),
        }
    });
    app.status = "정찰을 시작했습니다.".into();
}

/// 포트 스캔 실행.
fn run_scan(app: &mut App, rest: &str, shared: &Arc<Shared>) {
    let Some(auth) = require_scope(app) else { return };
    let target = if rest.is_empty() {
        match &app.target {
            Some(t) => t.clone(),
            None => {
                app.status = "사용법: /scan <호스트 또는 CIDR>".into();
                return;
            }
        }
    } else {
        rest.to_string()
    };
    app.tab = Tab::Scan;
    app.busy = Some("포트 스캔 중".into());
    let shared = shared.clone();
    tokio::spawn(async move {
        let hosts = match crate::net::expand_hosts(&target) {
            Ok(h) => h,
            Err(e) => {
                shared.emit(AgentEvent::Error(format!("대상 해석 실패: {e}")));
                return;
            }
        };
        let mut plan = crate::net::ScanPlan {
            hosts,
            ports: crate::net::default_ports(),
            timeout_ms: 1200,
            concurrency: 128,
            grab_banner: true,
            max_hosts: 4096,
        };
        if let Ok(parsed) = url::Url::parse(&target) {
            if let Some(p) = parsed.port() {
                plan.ports = vec![p];
            }
        }
        match crate::net::scan(&auth, &plan).await {
            Ok(report) => {
                for f in &report.findings {
                    shared.add_finding(f.clone());
                }
                let mut msg = format!(
                    "스캔 완료 — 호스트 {} · 열린 포트 {} · {:.1}초",
                    report.hosts.len(),
                    report.open,
                    report.duration_ms as f64 / 1000.0
                );
                for h in &report.hosts {
                    for p in &h.ports {
                        msg.push_str(&format!(
                            "\n  {}:{}{} {}",
                            h.host,
                            p.port,
                            p.state.label(),
                            p.service
                                .as_ref()
                                .map(|s| format!(" {} {}", s.name, s.version.clone().unwrap_or_default()))
                                .unwrap_or_default()
                        ));
                    }
                }
                shared.emit(AgentEvent::Note(msg));
                shared.emit(AgentEvent::ScanDone(report));
            }
            Err(e) => shared.emit(AgentEvent::Error(format!("스캔 실패: {e}"))),
        }
    });
    app.status = "포트 스캔을 시작했습니다.".into();
}

/// 콘텐츠 디스커버리 실행.
fn run_discover(app: &mut App, rest: &str, shared: &Arc<Shared>) {
    let rest = rest.to_string();
    let Some(target) = require_target(app) else { return };
    let Some(auth) = require_scope(app) else { return };
    app.tab = Tab::Surface;
    app.busy = Some("콘텐츠 디스커버리 중".into());
    let shared = shared.clone();
    tokio::spawn(async move {
        let client = match crate::http::HttpClient::new(Arc::new(auth)) {
            Ok(c) => c,
            Err(e) => {
                shared.emit(AgentEvent::Error(format!("클라이언트 실패: {e}")));
                return;
            }
        };
        let mut plan = crate::discover::default_plan(&target);
        // "/discover 800" → 요청 상한, "/discover php,bak" → 확장자
        if let Ok(n) = rest.trim().parse::<usize>() {
            plan.max_requests = n.clamp(50, 20_000);
        } else if !rest.is_empty() {
            plan.extensions = rest.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }
        match crate::discover::run(&client, &plan).await {
            Ok(report) => {
                for f in &report.findings {
                    shared.add_finding(f.clone());
                }
                let mut msg = format!(
                    "디스커버리 완료 — 요청 {}건 · 발견 {}건",
                    report.requests,
                    report.hits.len()
                );
                for h in report.hits.iter().take(40) {
                    msg.push_str(&format!("\n  [{}] {} {}", h.kind.label(), h.status, h.url));
                }
                shared.emit(AgentEvent::Note(msg));
                shared.emit(AgentEvent::DiscoverDone(report));
            }
            Err(e) => shared.emit(AgentEvent::Error(format!("디스커버리 실패: {e}"))),
        }
    });
    app.status = "콘텐츠 디스커버리를 시작했습니다.".into();
}

/// 템플릿 스캔 실행.
fn run_templates(app: &mut App, rest: &str, shared: &Arc<Shared>) {
    let rest = rest.to_string();
    let Some(target) = require_target(app) else { return };
    let Some(auth) = require_scope(app) else { return };
    app.busy = Some("템플릿 스캔 중".into());
    let shared = shared.clone();
    tokio::spawn(async move {
        let client = match crate::http::HttpClient::new(Arc::new(auth)) {
            Ok(c) => c,
            Err(e) => {
                shared.emit(AgentEvent::Error(format!("클라이언트 실패: {e}")));
                return;
            }
        };
        let tags: Vec<String> = rest
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let tag_filter = if tags.is_empty() { None } else { Some(tags.as_slice()) };
        let mut matches = Vec::new();
        for t in crate::templates::builtin_templates() {
            if let Ok(m) = crate::templates::execute(&client, &t, &target, tag_filter, "info").await {
                matches.extend(m);
            }
        }
        let findings = crate::templates::to_findings(&matches);
        for f in &findings {
            shared.add_finding(f.clone());
        }
        let mut msg = format!("템플릿 스캔 완료 — 매칭 {}건", matches.len());
        for m in matches.iter().take(40) {
            msg.push_str(&format!("\n  [{}] {} — {}", m.severity, m.name, m.url));
        }
        shared.emit(AgentEvent::Note(msg));
    });
    app.status = "템플릿 스캔을 시작했습니다.".into();
}

/// 스톰 실행.
fn run_storm(app: &mut App, shared: &Arc<Shared>) {
    let Some(target) = require_target(app) else { return };
    let Some(auth) = require_scope(app) else { return };
    app.tab = Tab::Storm;
    app.busy = Some("정찰 → 스톰 실행 중".into());
    let shared_run = shared.clone();
    let (tx, mut rx) = tokio::sync::broadcast::channel::<StormEvent>(256);
    let target_url = target.clone();
    let mut plan = StormPlan::default();
    plan.rps = Some(auth.effective_rps());
    tokio::spawn(async move {
        let shared = shared_run.clone();
        let engine = match StormEngine::new() {
            Ok(e) => e,
            Err(e) => {
                shared.emit(AgentEvent::Error(format!("스톰 엔진 실패: {e}")));
                return;
            }
        };
        // 1) 정찰 — 실제 파라미터가 있는 표면부터.
        let mut templates: Vec<Template> = Vec::new();
        if let Ok(client) = crate::http::HttpClient::new(Arc::new(auth.clone())) {
            if let Ok(resp) = client.get(&target_url).await {
                let r = crate::recon::extract(&resp.body, &target_url, resp.status);
                for ep in r.endpoints.iter().filter(|e| !e.params.is_empty()) {
                    let mut t = crate::recon::to_template(ep);
                    t.name = format!("{} {}", ep.method, ep.url);
                    templates.push(t);
                }
            }
        }
        let mut base = Template::get(&target_url);
        if let Ok(parsed) = url::Url::parse(&target_url) {
            for (k, v) in parsed.query_pairs() {
                base.params.push(crate::storm::Param::new(k.as_ref(), v.as_ref()));
            }
        }
        base.name = format!("GET {}", base.url);
        templates.insert(0, base);
        plan.templates = templates;

        let report = engine.run(&plan, &auth, tx).await;
        match report {
            Ok(r) => {
                let mut msg = format!(
                    "스톰 완료 — 요청 {} · {:.1} req/s · 이상 {}건",
                    r.requests,
                    r.rps,
                    r.anomalies.len()
                );
                for a in r.anomalies.iter().take(20) {
                    msg.push_str(&format!(
                        "\n  [{}] {} {:?} payload={:?} 신호={:?}",
                        a.severity, a.template, a.param, a.payload, a.signals
                    ));
                }
                shared.emit(AgentEvent::Note(msg));
            }
            Err(e) => shared.emit(AgentEvent::Error(format!("스톰 실패: {e}"))),
        }
    });
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

/// IDOR 탐색 실행.
fn run_idor(app: &mut App, rest: &str, shared: &Arc<Shared>) {
    let Some(target) = require_target(app) else { return };
    let Some(auth) = require_scope(app) else { return };
    if !auth.probe_allowed("idor") {
        app.status = "IDOR 프로브는 인가 파일의 optional_probes 에 명시되어야 합니다.".into();
        app.toast("err", "프로브 미인가");
        return;
    }
    let param = rest.split_whitespace().next().unwrap_or("id").to_string();
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
                let mut msg = format!(
                    "IDOR 탐색 — {} · 요청 {}건 · 판정 {:?}",
                    report.param, report.requests, report.verdict
                );
                for s in report.samples.iter().filter(|s| s.differs).take(10) {
                    msg.push_str(&format!(
                        "\n  {}={} → status {} len {} {:?}",
                        report.param, s.value, s.status, s.len, s.identifiers
                    ));
                }
                if !report.findings.is_empty() {
                    for f in &report.findings {
                        msg.push_str(&format!("\n  [{}] {} — {}", f.severity, f.title, f.remediation));
                    }
                }
                shared.emit(AgentEvent::Note(msg));
            }
            Err(e) => shared.emit(AgentEvent::Error(format!("IDOR 탐색 실패: {e}"))),
        }
    });
    app.status = "IDOR 탐색을 시작했습니다.".into();
}

/// 가격 변조 탐색 실행.
fn run_tamper(app: &mut App, rest: &str, shared: &Arc<Shared>) {
    let Some(target) = require_target(app) else { return };
    let Some(auth) = require_scope(app) else { return };
    if !auth.probe_allowed("tamper") {
        app.status = "변조 프로브는 인가 파일의 optional_probes 에 명시되어야 합니다.".into();
        app.toast("err", "프로브 미인가");
        return;
    }
    let param = rest.split_whitespace().next().unwrap_or("price").to_string();
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
        if target.contains('?') {
            cfg.method = "GET".into();
        }
        match crate::probes::tamper::run(&client, &cfg).await {
            Ok(report) => {
                for f in &report.findings {
                    shared.add_finding(f.clone());
                }
                let mut msg = format!(
                    "가격 변조 탐색 — {} · 기준 합계 {:?} · 요청 {}건",
                    report.param, report.baseline_total, report.requests
                );
                for a in report.attempts.iter().take(10) {
                    msg.push_str(&format!(
                        "\n  {}={} → status {} {:?} 합계 {:?}",
                        report.param, a.value, a.status, a.verdict, a.observed_total
                    ));
                }
                if !report.findings.is_empty() {
                    for f in &report.findings {
                        msg.push_str(&format!("\n  [{}] {} — {}", f.severity, f.title, f.remediation));
                    }
                }
                shared.emit(AgentEvent::Note(msg));
            }
            Err(e) => shared.emit(AgentEvent::Error(format!("가격 변조 탐색 실패: {e}"))),
        }
    });
    app.status = "가격 변조 탐색을 시작했습니다.".into();
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
        AgentEvent::ToolStart { name, summary } => {
            app.push_log("tool", format!("→ {name}: {}", summary.replace('\n', " ")));
        }
        AgentEvent::ToolEnd { name, summary } => {
            app.push_log("tool", format!("← {name}: {}", summary.replace('\n', " ")));
        }
        AgentEvent::Storm(ev) => handle_storm_event(app, ev),
        AgentEvent::KernelOutput(text) => {
            app.kernel_output.push_str(&text);
            app.kernel_output.push('\n');
            if app.kernel_output.len() > 60_000 {
                let cut = app.kernel_output.len() - 40_000;
                app.kernel_output = app.kernel_output[cut..].to_string();
            }
            app.status = "커널 실행 완료.".into();
        }
        AgentEvent::ApprovalNeeded { code } => {
            app.approval = Some(code.clone());
            app.push_log("err", "⏸ 실행 승인 대기 — 모델이 작성한 코드를 검토하세요 (y 승인 / n 거부).");
            app.status = "코드 실행 승인을 기다리는 중입니다.".into();
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
            app.toast("ok", "점검 완료");
            app.status = "점검이 끝났습니다 — /report 로 리포트 생성.".into();
            app.findings = app.shared.findings.lock().clone();
        }
        AgentEvent::Error(msg) => {
            app.agent_running = false;
            app.busy = None;
            app.push_log("err", msg.clone());
            app.toast("err", msg.clone());
            app.status = msg;
        }
        AgentEvent::ScanDone(report) => {
            app.scan_rows.clear();
            for h in &report.hosts {
                for p in &h.ports {
                    app.scan_rows.push(ScanRow {
                        host: h.host.clone(),
                        port: p.port,
                        state: p.state.label().to_string(),
                        service: p.service.as_ref().map(|s| s.name.clone()).unwrap_or_default(),
                        version: p.service.as_ref().and_then(|s| s.version.clone()).unwrap_or_default(),
                        note: p.service.as_ref().and_then(|s| s.product.clone()).unwrap_or_default(),
                    });
                }
            }
        }
        AgentEvent::DiscoverDone(report) => {
            app.surface_rows.clear();
            for h in &report.hits {
                app.surface_rows.push(SurfaceRow {
                    method: "GET".into(),
                    url: h.url.clone(),
                    params: String::new(),
                    source: h.kind.label().to_string(),
                    status: h.status.to_string(),
                });
            }
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
            if app.anomalies.len() > 500 {
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
                &format!(
                    "{} 에 payload={:?} 주입 → status {} · lenΔ {}",
                    a.template, a.payload, a.status, a.len_delta
                ),
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
        engagement: app
            .scope
            .as_ref()
            .map(|a| a.engagement.name.clone())
            .unwrap_or_else(|| "(미설정)".into()),
        scope: scope_list,
        target: app.target.clone(),
        summary: ReportSummary::of(&findings),
        findings,
        stats: vec![
            ("스톰 요청".into(), app.storm_requests.to_string()),
            ("이상 응답".into(), app.anomalies.len().to_string()),
            ("발견".into(), app.findings.len().to_string()),
            ("스캔 포트".into(), app.scan_rows.len().to_string()),
        ],
    };
    report::to_markdown(&rep)
}

// ─────────────────────────────────────────────────────────────────────────────
// 렌더링
// ─────────────────────────────────────────────────────────────────────────────

/// 화면 그리기.
fn draw(f: &mut ratatui::Frame, app: &App) {
    let area = f.area();
    if area.width < 40 || area.height < 10 {
        let p = Paragraph::new("터미널이 너무 작습니다. 80×24 이상으로 키워 주세요.")
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(p, area);
        return;
    }

    let compact = area.height < 20;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Min(4),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(f, chunks[0], app);
    draw_tabs(f, chunks[1], app);
    draw_body(f, chunks[2], app);
    draw_input(f, chunks[3], app);
    draw_status(f, chunks[4], app);

    draw_toasts(f, area, app);
    if app.palette_open {
        draw_palette(f, area, app);
    }
    if app.help_open {
        draw_help(f, area);
    }
    if let Some(code) = &app.approval {
        draw_approval(f, area, code);
    }
    let _ = compact;
}

/// 헤더 — 브랜드 + 상태 정보.
fn draw_header(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let scope_ok = app.scope.is_some();
    let target = app.target.clone().unwrap_or_else(|| "대상 미지정".into());
    let engagement = app
        .scope
        .as_ref()
        .map(|a| a.engagement.name.clone())
        .unwrap_or_else(|| "인가 없음".into());
    let llm = app
        .providers
        .iter()
        .find(|p| p.has_key)
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "LLM 미연결".into());

    let left = Line::from(vec![
        Span::styled(" ⬢ ", Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled("REDFORGE", Style::default().fg(theme::FG).add_modifier(Modifier::BOLD)),
        Span::styled("  ", theme::dim()),
        Span::styled(
            format!("{engagement}"),
            if scope_ok { theme::ok() } else { theme::crit() },
        ),
        Span::styled(" · ", theme::dim()),
        Span::styled(theme::truncate(&target, 40), theme::fg()),
    ]);

    let running = app.busy.is_some() || app.agent_running;
    let right = Line::from(vec![
        Span::styled(
            if running {
                format!("{} ", theme::spinner(app.frame))
            } else {
                "● ".to_string()
            },
            if running { theme::warn() } else { theme::dim() },
        ),
        Span::styled(
            if running { app.busy.clone().unwrap_or_default() } else { "idle".into() },
            if running { theme::warn() } else { theme::muted() },
        ),
        Span::styled("   │   ", theme::dim()),
        Span::styled("LLM ", theme::dim()),
        Span::styled(llm, theme::info()),
    ]);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);
    let block = Block::default().borders(Borders::BOTTOM).border_style(theme::border());
    f.render_widget(Paragraph::new(left).block(block.clone()), cols[0]);
    f.render_widget(
        Paragraph::new(right).block(block).alignment(Alignment::Right),
        cols[1],
    );
}

/// 탭 바.
fn draw_tabs(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| {
            Line::from(vec![
                Span::styled(format!("{} ", t.glyph()), theme::muted()),
                Span::styled(t.title(), theme::fg()),
                Span::styled(format!(" {}", t.shortcut()), theme::dim()),
                Span::raw("   "),
            ])
        })
        .collect();
    let idx = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
    f.render_widget(
        Tabs::new(titles)
            .select(idx)
            .highlight_style(Style::default().fg(theme::ACCENT).add_modifier(Modifier::BOLD))
            .divider(Span::styled(" │ ", theme::dim()))
            .style(theme::fg()),
        area,
    );
}

/// 본문 (탭별).
fn draw_body(f: &mut ratatui::Frame, area: Rect, app: &App) {
    match app.tab {
        Tab::Console => draw_console(f, area, app),
        Tab::Kernel => draw_kernel(f, area, app),
        Tab::Storm => draw_storm(f, area, app),
        Tab::Scan => draw_scan(f, area, app),
        Tab::Surface => draw_surface(f, area, app),
        Tab::Findings => draw_findings(f, area, app),
        Tab::Report => draw_report(f, area, app),
    }
}

/// 콘솔 — 로그 스트림.
fn draw_console(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let inner_h = area.height.saturating_sub(2) as usize;
    let total = app.log.len();
    let end = total.saturating_sub(app.log_scroll);
    let start = end.saturating_sub(inner_h);
    let items: Vec<ListItem> = app.log[start..end]
        .iter()
        .map(|l| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", l.at), theme::dim()),
                Span::styled(format!("{} ", theme::log_glyph(l.kind)), theme::log_kind(l.kind)),
                Span::styled(l.text.clone(), theme::log_kind(l.kind)),
            ]))
        })
        .collect();
    let title = if app.log_scroll > 0 {
        format!(" 콘솔 · 스크롤 {} ", app.log_scroll)
    } else {
        " 콘솔 ".to_string()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border())
        .title(Span::styled(title, theme::title()));
    f.render_widget(List::new(items).block(block), area);
}

/// 커널 — 코드 편집 + 실행 결과.
fn draw_kernel(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let code = Paragraph::new(app.kernel_code.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_focus())
                .title(Span::styled(" 커널 코드 · Ctrl+Enter 실행 ", theme::title())),
        )
        .wrap(Wrap { trim: false })
        .style(theme::fg());
    let out = Paragraph::new(app.kernel_output.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(" 실행 결과 ", theme::title())),
        )
        .wrap(Wrap { trim: false })
        .style(theme::fg());
    f.render_widget(code, cols[0]);
    f.render_widget(out, cols[1]);
}

/// 스톰 — 진행률 + 이상 목록.
fn draw_storm(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let (done, total, rps) = app.storm_progress.unwrap_or((0, 0, 0.0));
    let ratio = if total > 0 { done as f64 / total as f64 } else { 0.0 };
    let width = area.width.saturating_sub(4) as usize;
    let bar = theme::progress_bar(ratio, width);

    let stats = Line::from(vec![
        Span::styled(format!(" {done}"), theme::fg().add_modifier(Modifier::BOLD)),
        Span::styled(format!("/{total}"), theme::dim()),
        Span::styled("  요청 ", theme::dim()),
        Span::styled(format!("{rps:.1}"), theme::info()),
        Span::styled(" req/s", theme::dim()),
        Span::styled("   이상 ", theme::dim()),
        Span::styled(
            app.anomalies.len().to_string(),
            theme::severity(if app.anomalies.is_empty() { "low" } else { "medium" }),
        ),
        Span::styled("   누적 요청 ", theme::dim()),
        Span::styled(app.storm_requests.to_string(), theme::fg()),
    ]);

    let top = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(area);
    let gauge = Paragraph::new(Line::from(vec![
        Span::styled(format!(" {bar} "), Style::default().fg(theme::ACCENT)),
        Span::styled(format!(" {:>3.0}%", ratio * 100.0), theme::muted()),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::border())
            .title(Span::styled(" 스톰 진행 ", theme::title())),
    );
    f.render_widget(gauge, top[0]);
    f.render_widget(Paragraph::new(stats).style(theme::muted()), top[1].inner(ratatui::layout::Margin::new(1, 0)));

    let items: Vec<ListItem> = app
        .anomalies
        .iter()
        .take(400)
        .map(|a| {
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {:<8}", a.severity), theme::severity(&a.severity)),
                Span::styled(theme::truncate(&a.template, 28), theme::fg()),
                Span::styled(
                    format!(" {:?}", a.param),
                    theme::info(),
                ),
                Span::styled(format!("  {}", theme::truncate(&a.payload.replace('\n', " "), 28)), theme::warn()),
                Span::styled(format!("  {} Δ{}", a.status, a.len_delta), theme::dim()),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(" 이상 응답 ", theme::title())),
        ),
        top[1],
    );
}

/// 스캔 — 호스트/포트 표.
fn draw_scan(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .scan_rows
        .iter()
        .map(|r| {
            let state_style = match r.state.as_str() {
                "open" => theme::ok(),
                "closed" => theme::dim(),
                _ => theme::muted(),
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {:<24}", theme::truncate(&r.host, 24)), theme::fg()),
                Span::styled(format!("{:<6}", r.port), theme::info()),
                Span::styled(format!(" {:<8}", r.state), state_style),
                Span::styled(format!("{:<10}", theme::truncate(&r.service, 10)), theme::fg()),
                Span::styled(theme::truncate(&r.version, 12), theme::muted()),
                Span::styled(format!("  {}", theme::truncate(&r.note, 24)), theme::dim()),
            ]))
        })
        .collect();
    let empty = app.scan_rows.is_empty();
    if empty && app.busy.is_some() {
        let p = Paragraph::new(format!("{} 스캔 중…", theme::spinner(app.frame)))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::border())
                    .title(Span::styled(" 포트 스캔 ", theme::title())),
            )
            .style(theme::warn());
        f.render_widget(p, area);
        return;
    }
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::border())
            .title(Span::styled(format!(" 포트 스캔 · {} ", app.scan_rows.len()), theme::title())),
    );
    if empty {
        let p = Paragraph::new("스캔 결과가 없습니다. /scan <호스트|CIDR> 로 실행하세요.")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::border())
                    .title(Span::styled(" 포트 스캔 ", theme::title())),
            )
            .style(theme::muted());
        f.render_widget(p, area);
        return;
    }
    f.render_widget(list, area);
}

/// 표면 — 발견된 엔드포인트.
fn draw_surface(f: &mut ratatui::Frame, area: Rect, app: &App) {
    if app.surface_rows.is_empty() {
        let msg = if app.busy.is_some() {
            format!("{} 수집 중…", theme::spinner(app.frame))
        } else {
            "공격 표면이 비어 있습니다. /discover 또는 /recon 으로 채우세요.".to_string()
        };
        let p = Paragraph::new(msg)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::border())
                    .title(Span::styled(" 공격 표면 ", theme::title())),
            )
            .style(theme::muted());
        f.render_widget(p, area);
        return;
    }
    let items: Vec<ListItem> = app
        .surface_rows
        .iter()
        .map(|r| {
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {:<6}", r.method), theme::info()),
                Span::styled(format!("{:<7}", r.status), theme::ok()),
                Span::styled(theme::truncate(&r.url, 56), theme::fg()),
                Span::styled(format!("  {}", r.source), theme::dim()),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(format!(" 공격 표면 · {} ", app.surface_rows.len()), theme::title())),
        ),
        area,
    );
}

/// 발견 — 목록 + 상세.
fn draw_findings(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let findings = app.shared.findings.lock();
    if findings.is_empty() {
        let p = Paragraph::new("아직 확정된 발견이 없습니다.\n점검을 실행하거나 /autopilot 로 자율 점검을 시작하세요.")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::border())
                    .title(Span::styled(" 발견 ", theme::title())),
            )
            .style(theme::muted());
        f.render_widget(p, area);
        return;
    }
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);
    let items: Vec<ListItem> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let sel = i == app.finding_sel;
            let base = if sel {
                Style::default().bg(theme::SELECT_BG).fg(theme::SELECT_FG)
            } else {
                theme::fg()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {:<8}", f.severity), base.patch(theme::severity(&f.severity))),
                Span::styled(theme::truncate(&f.title, 40), base),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(app.finding_sel.min(findings.len().saturating_sub(1))));
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_focus())
                .title(Span::styled(format!(" 발견 · {} ", findings.len()), theme::title())),
        )
        .highlight_symbol("▌")
        .highlight_style(Style::default().bg(theme::SELECT_BG).fg(theme::SELECT_FG));
    f.render_stateful_widget(list, cols[0], &mut state);

    let detail = findings
        .get(app.finding_sel.min(findings.len().saturating_sub(1)))
        .map(|f| {
            let mut s = String::new();
            s.push_str(&format!("{}\n", f.title));
            s.push_str(&format!("심각도 {}\n", f.severity));
            s.push_str(&format!("분류   {}\n", f.category));
            s.push_str(&format!("대상   {}\n\n", f.target));
            if let Some(cvss) = report::cvss_for(&f.category) {
                s.push_str(&format!("CVSS    {:.1}  {}\n", cvss.score, cvss.cwe));
                s.push_str(&format!("       {}\n\n", cvss.vector));
            }
            s.push_str("── 근거 ──\n");
            s.push_str(&f.evidence);
            s.push_str("\n\n── 재현 절차 ──\n");
            s.push_str(&f.reproduction);
            s.push_str("\n\n── 보완 포인트 ──\n");
            s.push_str(&f.remediation);
            s
        })
        .unwrap_or_default();
    f.render_widget(
        Paragraph::new(detail)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::border())
                    .title(Span::styled(" 상세 ", theme::title())),
            )
            .wrap(Wrap { trim: false })
            .style(theme::fg()),
        cols[1],
    );
}

/// 리포트 미리보기.
fn draw_report(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let md = build_report(app);
    let text = if let Some(p) = &app.report_path {
        format!("저장됨: {p}\n\n{md}")
    } else {
        md
    };
    f.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::border())
                    .title(Span::styled(" 리포트 ", theme::title())),
            )
            .wrap(Wrap { trim: false })
            .style(theme::fg()),
        area,
    );
}

/// 입력창.
fn draw_input(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let prompt_style = if app.input.starts_with('/') { theme::accent() } else { theme::ok() };
    let text = if app.input.is_empty() {
        Line::from(vec![
            Span::styled("▸ ", prompt_style),
            Span::styled("목표를 입력하거나 /help · Ctrl+P 로 명령을 여세요", theme::dim()),
        ])
    } else {
        let before: String = app.input.chars().take(app.cursor).collect();
        let after: String = app.input.chars().skip(app.cursor).collect();
        Line::from(vec![
            Span::styled("▸ ", prompt_style),
            Span::styled(before, theme::fg()),
            Span::styled("▏", Style::default().fg(theme::ACCENT)),
            Span::styled(after, theme::muted()),
        ])
    };
    f.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_focus())
                .title(Span::styled(" 입력 ", theme::title())),
        ),
        area,
    );
}

/// 상태줄.
fn draw_status(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let left = if let Some(busy) = &app.busy {
        format!("{} {}", theme::spinner(app.frame), busy)
    } else {
        "○ idle".to_string()
    };
    let left_style = if app.busy.is_some() { theme::warn() } else { theme::dim() };
    let right = "1-7 탭 · Ctrl+P 명령 · F1 도움말 · PgUp/PgDn 스크롤 · Ctrl+C 중지";
    // 한글은 2칸을 차지한다 — 실제 표시 폭으로 열 폭을 계산해야 잘리지 않는다.
    let right_w = (unicode_width::UnicodeWidthStr::width(right) as u16).min(area.width.saturating_sub(20));
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(right_w)])
        .split(area);
    let status_w = cols[0].width.saturating_sub(8) as usize;
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(left, left_style),
            Span::styled("  │  ", theme::dim()),
            Span::styled(theme::truncate(&app.status, status_w), theme::fg()),
        ])),
        cols[0],
    );
    f.render_widget(
        Paragraph::new(right).style(theme::dim()).alignment(Alignment::Right),
        cols[1],
    );
}

/// 토스트 알림 (우측 하단).
fn draw_toasts(f: &mut ratatui::Frame, area: Rect, app: &App) {
    if app.toasts.is_empty() {
        return;
    }
    let n = app.toasts.len() as u16;
    let height = n + 2;
    let width = 44.min(area.width.saturating_sub(4));
    let rect = Rect {
        x: area.x + area.width.saturating_sub(width + 1),
        y: area.y + area.height.saturating_sub(height + 2),
        width,
        height,
    };
    f.render_widget(Clear, rect);
    let items: Vec<ListItem> = app
        .toasts
        .iter()
        .map(|t| {
            let style = match t.kind {
                "err" => theme::crit(),
                "ok" => theme::ok(),
                "report" => theme::info(),
                _ => theme::muted(),
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", theme::log_glyph(t.kind)), style),
                Span::styled(theme::truncate(&t.text, width as usize - 4), style),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(" 알림 ", theme::title())),
        ),
        rect,
    );
}

/// 명령 팔레트.
fn draw_palette(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let list = filtered_commands(&app.palette_filter);
    let width = area.width.saturating_sub(16).min(78).max(36);
    let height = (list.len() as u16 + 4).min(area.height.saturating_sub(4)).max(8);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 4;
    let rect = Rect { x, y, width, height };
    f.render_widget(Clear, rect);
    let items: Vec<ListItem> = list
        .iter()
        .enumerate()
        .map(|(i, (cmd, desc, hint))| {
            let sel = i == app.palette_index;
            let style = if sel {
                Style::default().bg(theme::SELECT_BG).fg(theme::SELECT_FG)
            } else {
                theme::fg()
            };
            let hint_style = if sel {
                Style::default().bg(theme::SELECT_BG).fg(theme::MUTED)
            } else {
                theme::dim()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {cmd:<12}"), style),
                Span::styled(format!(" {desc}"), style),
                Span::styled(format!("   {hint}"), hint_style),
            ]))
        })
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_focus())
        .title(Span::styled(
            format!(" 명령 팔레트 · 검색: {} ", if app.palette_filter.is_empty() { "∅" } else { &app.palette_filter }),
            theme::title(),
        ));
    f.render_widget(List::new(items).block(block), rect);
}

/// 도움말 오버레이.
fn draw_help(f: &mut ratatui::Frame, area: Rect) {
    let width = area.width.saturating_sub(8).min(76).max(40);
    let height = area.height.saturating_sub(4).min(26).max(12);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 4;
    let rect = Rect { x, y, width, height };
    f.render_widget(Clear, rect);

    let lines = vec![
        Line::from(Span::styled(" 키보드 ", theme::title())),
        Line::from(""),
        Line::from(vec![Span::styled("  1-7 / Tab ", theme::ok()), Span::raw("탭 전환")]),
        Line::from(vec![Span::styled("  Ctrl+P   ", theme::ok()), Span::raw("명령 팔레트 (한글 검색 가능)")]),
        Line::from(vec![Span::styled("  F1 / ?   ", theme::ok()), Span::raw("이 도움말")]),
        Line::from(vec![Span::styled("  Ctrl+Enter", theme::ok()), Span::raw("커널 코드 실행 (커널 탭)")]),
        Line::from(vec![Span::styled("  Ctrl+R   ", theme::ok()), Span::raw("커널 코드 실행 (대체 단축키)")]),
        Line::from(vec![Span::styled("  PgUp/PgDn", theme::ok()), Span::raw("콘솔 스크롤")]),
        Line::from(vec![Span::styled("  ↑ / ↓    ", theme::ok()), Span::raw("입력 히스토리 / 발견 목록 이동")]),
        Line::from(vec![Span::styled("  y / n / a ", theme::ok()), Span::raw("모델 코드 승인 / 거부 / 세션 자동 승인")]),
        Line::from(vec![Span::styled("  Ctrl+C   ", theme::ok()), Span::raw("작업 중지 (없으면 종료)")]),
        Line::from(vec![Span::styled("  Ctrl+Q   ", theme::ok()), Span::raw("종료")]),
        Line::from(""),
        Line::from(Span::styled(" 명령 ", theme::title())),
        Line::from(""),
        Line::from(vec![Span::styled("  /target  ", theme::accent()), Span::raw("대상 설정")]),
        Line::from(vec![Span::styled("  /recon   ", theme::accent()), Span::raw("엔드포인트·지문 추출")]),
        Line::from(vec![Span::styled("  /scan    ", theme::accent()), Span::raw("포트 스캔")]),
        Line::from(vec![Span::styled("  /discover", theme::accent()), Span::raw("콘텐츠 디스커버리")]),
        Line::from(vec![Span::styled("  /templates", theme::accent()), Span::raw("템플릿 스캔")]),
        Line::from(vec![Span::styled("  /storm   ", theme::accent()), Span::raw("고속 변이 퍼징")]),
        Line::from(vec![Span::styled("  /idor    ", theme::accent()), Span::raw("IDOR 탐색")]),
        Line::from(vec![Span::styled("  /tamper  ", theme::accent()), Span::raw("가격 변조 탐색")]),
        Line::from(vec![Span::styled("  /autopilot", theme::accent()), Span::raw("자율 점검 (LLM)")]),
        Line::from(vec![Span::styled("  /report  ", theme::accent()), Span::raw("리포트 생성")]),
        Line::from(""),
        Line::from(Span::styled(" 아무 키나 눌러 닫기 ", theme::dim())),
    ];
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border_focus())
                .title(Span::styled(" 도움말 ", theme::title())),
        ),
        rect,
    );
}

/// 코드 실행 승인 모달.
fn draw_approval(f: &mut ratatui::Frame, area: Rect, code: &str) {
    let width = area.width.saturating_sub(8).min(84).max(40);
    let height = area.height.saturating_sub(6).min(24).max(10);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 3;
    let rect = Rect { x, y, width, height };
    f.render_widget(Clear, rect);

    let mut lines = vec![
        Line::from(vec![
            Span::styled(" ⚠ ", theme::crit()),
            Span::styled("모델이 작성한 코드를 실행하려고 합니다.", theme::crit().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(Span::styled(" 아래 내용을 검토하세요.  y=승인  a=세션 전체 자동 승인  n=거부", theme::muted())),
        Line::from(""),
    ];
    for l in code.lines().take(16) {
        lines.push(Line::from(Span::styled(l.to_string(), theme::fg())));
    }
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::crit())
                .title(Span::styled(" 실행 승인 필요 ", theme::crit())),
        ),
        rect,
    );
}
