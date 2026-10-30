//! redcell TUI — 터미널 코딩-에이전트형 보안 진단 셸.
//!
//! 데스크톱과 같은 엔진(P0 스윕·risk 가드레일)을 터미널에서 다룬다.
//! Agent 실행은 redcell TS CLI(`run`)를 자식으로 띄워 스트리밍한다.
//!
//! 키: `/` 명령어 메뉴 (↑↓·Tab·Enter) · Esc 중지·닫기 ·
//!      Ctrl+Q 종료 · PgUp/Dn 스크롤 · 팝업은 ↑↓·Enter·Esc

mod composer;
mod engine;
mod providers;
mod scope;
mod session;
mod slash;
mod task;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Paragraph};
use ratatui::{Frame, Terminal};
use std::io::Stdout;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};
use unicode_width::UnicodeWidthStr;

use engine::probes::ProbeHit;
use engine::risk::RiskReport;
use session::{LineLevel, TuiSession};
use task::{AgentHandle, TaskMsg};

// ── 상태 ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Popup {
    None,
    Help,
    UrlPrompt,
    Onboarding,
    Setup,
    Providers,
    ProviderEdit,
    ProviderNew,
    Sessions,
    RenamePrompt,
    DeleteConfirm,
    Findings,
    FindingDetail,
    Report,
    ConsentStatic,
    ConsentRisk,
}

/// 온보딩 단계: 0 환영 · 1 프로바이더 · 2 인증방식 · 3 키 입력.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnboardMethod {
    ApiKey,
    OAuth,
    PiImport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsentChoice {
    Yes,
    No,
}

struct Field {
    label: &'static str,
    value: String,
    cursor: usize, // char idx
    secret: bool,
    cycle: Option<Vec<String>>,
}

impl Field {
    fn text(label: &'static str, value: String) -> Self {
        let cursor = value.chars().count();
        Field { label, value, cursor, secret: false, cycle: None }
    }
    fn secret(label: &'static str, value: String) -> Self {
        let cursor = value.chars().count();
        Field { label, value, cursor, secret: true, cycle: None }
    }
    fn display(&self) -> String {
        if self.secret && !self.value.is_empty() {
            format!("{}…({}자)", "•".repeat(8.min(self.value.chars().count())), self.value.chars().count())
        } else {
            self.value.clone()
        }
    }
    fn insert(&mut self, c: char) {
        let byte: usize = self.value.chars().take(self.cursor).map(|ch| ch.len_utf8()).sum();
        self.value.insert(byte, c);
        self.cursor += 1;
    }
    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor -= 1;
        let byte: usize = self.value.chars().take(self.cursor).map(|ch| ch.len_utf8()).sum();
        self.value.remove(byte);
    }
    fn move_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }
    fn move_right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.value.chars().count());
    }
    fn cycle_next(&mut self) {
        if let Some(opts) = &self.cycle {
            if opts.is_empty() {
                return;
            }
            let i = opts.iter().position(|o| o == &self.value).map(|i| (i + 1) % opts.len()).unwrap_or(0);
            self.value = opts[i].clone();
            self.cursor = self.value.chars().count();
        }
    }
    fn cycle_prev(&mut self) {
        if let Some(opts) = &self.cycle {
            if opts.is_empty() {
                return;
            }
            let i = opts.iter().position(|o| o == &self.value).map(|i| (i + opts.len() - 1) % opts.len()).unwrap_or(0);
            self.value = opts[i].clone();
            self.cursor = self.value.chars().count();
        }
    }
}

struct App {
    session: TuiSession,
    input: String,
    input_cursor: usize,
    input_history: composer::History,
    palette_draft: Option<(String, usize)>,
    llm_label: String,
    slash_sel: usize, // `/` 자동완성 선택행
    slash_open: bool, // `/` 메뉴 표시 여부 (Esc 로 닫으면 입력 변경 전까지 유지)
    scroll_off: usize, // 하단 기준 위로 올린 줄 수 (0 = 맨 아래 고정)
    popup: Popup,
    tx: Sender<TaskMsg>,
    rx: Receiver<TaskMsg>,
    sweep_running: bool,
    sweep_started: Instant,
    sweep_gen: u32,
    sweep_fb: Option<std::sync::Arc<engine::probes::SweepFeedback>>,
    agent: Option<AgentHandle>,
    agent_running: bool,
    agent_started: Instant,
    pending_instruction: Option<String>,
    pending_risk: Option<RiskReport>,
    consent_choice: ConsentChoice,
    consent_scroll: usize,
    status_msg: String,
    status_until: Option<Instant>,
    quit: bool,
    coached_report: bool,
    coached_agent: bool,
    // 팝업 상태
    url_field: Field,
    setup_fields: Vec<Field>,
    setup_sel: usize,
    prov_list: Vec<providers::ProviderView>,
    prov_sel: usize,
    prov_fields: Vec<Field>,
    prov_sel_field: usize,
    prov_edit_name: Option<String>,
    prov_edit_is_new: bool,
    // 온보딩 (첫 실행 LLM 연결 마법사)
    onboard_step: u8,
    onboard_prov_sel: usize,
    onboard_methods: Vec<OnboardMethod>,
    onboard_method_sel: usize,
    onboard_name: String,
    onboard_kind: String,
    onboard_base_url: String,
    onboard_fields: Vec<Field>,
    onboard_field_sel: usize,
    onboard_error: Option<String>,
    onboard_force_armed: bool,
    sess_list: Vec<(String, String, String, String)>,
    sess_sel: usize,
    new_name_buf: String,
    rename_field: Field,
    delete_target: Option<(String, String)>, // (id, 표시명)
    findings_sel: usize,
    finding_scroll: usize,
    report_scroll: usize,
    help_scroll: usize,
    detail_idx: usize,
}

impl App {
    fn boot() -> Self {
        let (tx, rx) = mpsc::channel();
        // 최근 세션 복원, 없으면 신규.
        let session = TuiSession::list()
            .first()
            .and_then(|(id, _, _, _)| TuiSession::load(id))
            .unwrap_or_else(|| TuiSession::fresh("session-1".into(), String::new()));
        let mut input_history = composer::History::default();
        for message in session.chat.iter().filter(|m| m.role == "user") {
            input_history.remember(&message.content);
        }
        let mut app = App {
            session,
            input: String::new(),
            input_cursor: 0,
            input_history,
            palette_draft: None,
            llm_label: String::new(),
            slash_sel: 0,
            slash_open: true,
            scroll_off: 0,
            popup: Popup::None,
            tx,
            rx,
            sweep_running: false,
            sweep_started: Instant::now(),
            sweep_gen: 0,
            sweep_fb: None,
            agent: None,
            agent_running: false,
            agent_started: Instant::now(),
            pending_instruction: None,
            pending_risk: None,
            consent_choice: ConsentChoice::No,
            consent_scroll: 0,
            status_msg: String::new(),
            status_until: None,
            quit: false,
            coached_report: false,
            coached_agent: false,
            url_field: Field::text("URL", String::new()),
            setup_fields: Vec::new(),
            setup_sel: 0,
            prov_list: Vec::new(),
            prov_sel: 0,
            prov_fields: Vec::new(),
            prov_sel_field: 0,
            prov_edit_name: None,
            prov_edit_is_new: false,
            onboard_step: 0,
            onboard_prov_sel: 0,
            onboard_methods: Vec::new(),
            onboard_method_sel: 0,
            onboard_name: String::new(),
            onboard_kind: String::new(),
            onboard_base_url: String::new(),
            onboard_fields: Vec::new(),
            onboard_field_sel: 0,
            onboard_error: None,
            onboard_force_armed: false,
            sess_list: Vec::new(),
            sess_sel: 0,
            new_name_buf: String::new(),
            rename_field: Field::text("이름", String::new()),
            delete_target: None,
            findings_sel: 0,
            finding_scroll: 0,
            report_scroll: 0,
            help_scroll: 0,
            detail_idx: 0,
        };
        app.session.save();
        // 첫 화면은 막지 않는다. 시작 안내에서 필요한 설정만 골라 연다.
        app.refresh_connection();
        app
    }

    fn refresh_connection(&mut self) {
        let cfg = providers::load_config();
        let name = if self.session.provider.is_empty() {
            cfg.default_provider.as_deref().unwrap_or("")
        } else {
            &self.session.provider
        };
        self.llm_label = providers::merged_view().iter()
            .find(|p| p.name == name && p.usable)
            .map(|p| {
                let model = if self.session.model.is_empty() {
                    cfg.default_model.as_deref().filter(|m| !m.is_empty()).unwrap_or(&p.model)
                } else {
                    &self.session.model
                };
                format!("{name}/{model}")
            }).unwrap_or_default();
    }

    fn reset_composer(&mut self) {
        self.input.clear();
        self.input_cursor = 0;
        self.slash_sel = 0;
        self.slash_open = true;
        self.palette_draft = None;
        self.input_history.reset();
    }

    fn say(&mut self, tag: &str, text: String, level: LineLevel) {
        self.session.push_log(tag, text, level);
        self.scroll_off = 0;
    }

    fn flash(&mut self, msg: String) {
        self.status_msg = msg;
        self.status_until = Some(Instant::now() + Duration::from_secs(5));
    }

    fn save(&mut self) {
        self.session.save();
    }
}

fn main() {
    // 패닉 시에도 터미널 복원.
    let orig = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        orig(info);
    }));
    let mut terminal = setup_terminal();
    let mut app = App::boot();
    let res = run_loop(&mut terminal, &mut app);
    restore_terminal();
    if let Err(e) = res {
        eprintln!("redcell-tui 오류: {e}");
    }
}

fn setup_terminal() -> Terminal<ratatui::backend::CrosstermBackend<Stdout>> {
    use crossterm::execute;
    use crossterm::event::EnableBracketedPaste;
    use crossterm::terminal::{enable_raw_mode, EnterAlternateScreen};
    enable_raw_mode().expect("raw mode");
    let mut out = std::io::stdout();
    execute!(out, EnterAlternateScreen, EnableBracketedPaste).expect("alt screen");
    Terminal::new(ratatui::backend::CrosstermBackend::new(out)).expect("terminal")
}

fn restore_terminal() {
    use crossterm::execute;
    use crossterm::event::DisableBracketedPaste;
    use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
    disable_raw_mode().ok();
    execute!(std::io::stdout(), DisableBracketedPaste, LeaveAlternateScreen).ok();
}

fn run_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<Stdout>>,
    app: &mut App,
) -> std::io::Result<()> {
    loop {
        terminal.draw(|f| render(f, app))?;
        // 백그라운드 메시지 수신.
        while let Ok(msg) = app.rx.try_recv() {
            on_task_msg(app, msg);
        }
        if app.quit {
            app.save();
            return Ok(());
        }
        // 입력 (100ms 폴링 — 스피너·경과 표시 갱신).
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(k) if k.kind != KeyEventKind::Release => on_key(app, k),
                Event::Paste(text) => on_paste(app, &text),
                _ => {}
            }
        }
        // 상태 메시지 만료.
        if let Some(until) = app.status_until {
            if Instant::now() >= until {
                app.status_msg.clear();
                app.status_until = None;
            }
        }
    }
}

// ── 키 처리 ──────────────────────────────────────────────────────────────────

fn on_key(app: &mut App, k: KeyEvent) {
    if k.modifiers.contains(KeyModifiers::CONTROL) {
        match k.code {
            KeyCode::Char('q') => {
                stop_agent(app, true);
                app.quit = true;
                return;
            }
            KeyCode::Char('c') => {
                if app.sweep_running || app.agent_running {
                    stop_agent(app, false);
                } else if app.popup != Popup::None {
                    on_key(app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
                } else if !app.input.is_empty() {
                    app.reset_composer();
                } else {
                    app.flash("종료하려면 Ctrl+Q 또는 /quit · Ctrl+C는 입력/작업 취소".into());
                }
                return;
            }
            _ => {}
        }
    }
    match app.popup {
        Popup::None => on_key_main(app, k),
        Popup::Help => on_key_scroll_popup(app, k, 0),
        Popup::Report => on_key_scroll_popup(app, k, 1),
        Popup::UrlPrompt => on_key_url(app, k),
        Popup::Onboarding => on_key_onboarding(app, k),
        Popup::Setup => on_key_form(app, k, true),
        Popup::ProviderEdit | Popup::ProviderNew => on_key_form(app, k, false),
        Popup::Providers => on_key_providers(app, k),
        Popup::Sessions => on_key_sessions(app, k),
        Popup::RenamePrompt => on_key_rename(app, k),
        Popup::DeleteConfirm => on_key_delete_confirm(app, k),
        Popup::Findings => on_key_findings(app, k),
        Popup::FindingDetail => on_key_detail(app, k),
        Popup::ConsentStatic | Popup::ConsentRisk => on_key_consent(app, k),
    }
}

fn slash_active(app: &App) -> bool {
    app.slash_open && app.input.starts_with('/') && !app.input.chars().any(char::is_whitespace)
}

/// 인자 편집 중에는 메뉴를 숨겨 ↑↓와 Enter를 입력창에 돌려준다.
fn slash_menu(app: &mut App) -> Vec<&'static slash::Command> {
    if !slash_active(app) {
        return Vec::new();
    }
    let c = slash::candidates(&app.input);
    app.slash_sel = app.slash_sel.min(c.len().saturating_sub(1));
    c
}

/// 선택된 후보를 입력창의 명령어 부분에 완성한다 (인자는 유지).
fn complete_slash(app: &mut App) {
    let cands = slash::candidates(&app.input);
    if cands.is_empty() {
        return;
    }
    let sel = cands[app.slash_sel.min(cands.len() - 1)];
    let rest = app.input.find(char::is_whitespace).map(|i| app.input[i..].to_string()).unwrap_or_default();
    let mut next = format!("/{}", sel.name);
    if sel.takes_arg && rest.trim().is_empty() {
        next.push(' ');
    } else {
        next.push_str(&rest);
    }
    app.input = next;
    app.input_cursor = app.input.chars().count();
    app.slash_sel = 0;
    app.slash_open = true;
}

fn insert_input(app: &mut App, text: &str) {
    let byte = composer::byte_index(&app.input, app.input_cursor);
    app.input.insert_str(byte, text);
    app.input_cursor += text.chars().count();
    app.input_history.reset();
    app.slash_sel = 0;
    app.slash_open = true;
}

fn on_paste(app: &mut App, raw: &str) {
    if app.popup == Popup::None {
        insert_input(app, &composer::pasted_text(raw, true));
        return;
    }
    let field = match app.popup {
        Popup::UrlPrompt => Some(&mut app.url_field),
        Popup::Setup => app.setup_fields.get_mut(app.setup_sel),
        Popup::ProviderEdit | Popup::ProviderNew => app.prov_fields.get_mut(app.prov_sel_field),
        Popup::Onboarding if app.onboard_step == 3 => {
            app.onboard_error = None;
            app.onboard_force_armed = false;
            app.onboard_fields.get_mut(app.onboard_field_sel)
        }
        Popup::RenamePrompt => Some(&mut app.rename_field),
        _ => None,
    };
    if let Some(field) = field.filter(|f| f.cycle.is_none()) {
        let text = composer::pasted_text(raw, false);
        let byte = composer::byte_index(&field.value, field.cursor);
        field.value.insert_str(byte, &text);
        field.cursor += text.chars().count();
    }
}

fn on_key_main(app: &mut App, k: KeyEvent) {
    if k.modifiers.contains(KeyModifiers::CONTROL) {
        match k.code {
            KeyCode::Char('p') => {
                if let Some((draft, cursor)) = app.palette_draft.take() {
                    app.input = draft;
                    app.input_cursor = cursor;
                    app.slash_open = false;
                } else {
                    app.palette_draft = Some((app.input.clone(), app.input_cursor));
                    app.input = "/".into();
                    app.input_cursor = 1;
                    app.slash_open = true;
                    app.slash_sel = 0;
                }
                return;
            }
            KeyCode::Char('a') => { app.input_cursor = 0; return; }
            KeyCode::Char('e') => { app.input_cursor = app.input.chars().count(); return; }
            KeyCode::Char('u') => {
                let byte = composer::byte_index(&app.input, app.input_cursor);
                app.input.replace_range(..byte, "");
                app.input_cursor = 0;
            }
            KeyCode::Char('w') => {
                let chars: Vec<char> = app.input.chars().collect();
                let end = app.input_cursor.min(chars.len());
                let mut start = end;
                while start > 0 && chars[start - 1].is_whitespace() { start -= 1; }
                while start > 0 && !chars[start - 1].is_whitespace() { start -= 1; }
                let a = composer::byte_index(&app.input, start);
                let b = composer::byte_index(&app.input, end);
                app.input.replace_range(a..b, "");
                app.input_cursor = start;
            }
            _ => return,
        }
        app.input_history.reset();
        app.slash_sel = 0;
        app.slash_open = true;
        return;
    }
    let mut touched = false;
    match k.code {
        KeyCode::Esc => {
            if let Some((draft, cursor)) = app.palette_draft.take() {
                app.input = draft;
                app.input_cursor = cursor;
                app.slash_open = false;
            } else if slash_active(app) {
                app.slash_open = false;
            } else if !app.input.is_empty() {
                app.reset_composer();
            } else if app.sweep_running || app.agent_running {
                stop_agent(app, false);
            } else {
                app.scroll_off = 0;
            }
        }
        KeyCode::Enter if k.modifiers.intersects(KeyModifiers::ALT | KeyModifiers::SHIFT) => {
            insert_input(app, "\n");
        }
        KeyCode::Enter => {
            if !slash_menu(app).is_empty() {
                complete_slash(app);
            }
            let text = app.input.trim().to_string();
            if text.is_empty() {
                if app.session.host.trim().is_empty() {
                    app.url_field = Field::text("URL", String::new());
                    app.popup = Popup::UrlPrompt;
                }
                return;
            }
            if text.starts_with('/') {
                let word = text[1..].split_whitespace().next().unwrap_or("");
                match slash::find(word) {
                    Some(c) if c.usage.starts_with('<') && !text.contains(char::is_whitespace) => {
                        if !app.input.ends_with(' ') {
                            app.input.push(' ');
                            app.input_cursor = app.input.chars().count();
                        }
                        app.flash(format!("{} — 내용을 입력한 뒤 Enter", slash::label(c)));
                        return;
                    }
                    None => {
                        run_slash(app, &text); // 오타를 고칠 수 있도록 입력은 유지.
                        return;
                    }
                    _ => {}
                }
            } else if app.agent_running {
                app.flash("작업 실행 중 — 입력은 보관됩니다. Ctrl+C로 중지 후 다시 Enter".into());
                return;
            }
            app.input_history.remember(&text);
            let draft = app.palette_draft.take();
            app.reset_composer();
            if text.starts_with('/') {
                run_slash(app, &text);
            } else {
                submit_instruction(app, text);
            }
            if let Some((input, cursor)) = draft {
                app.input = input;
                app.input_cursor = cursor;
                app.slash_open = false;
            }
        }
        KeyCode::Tab => {
            if !slash_menu(app).is_empty() { complete_slash(app); }
        }
        KeyCode::BackTab => {
            let n = slash_menu(app).len();
            if n > 0 { app.slash_sel = (app.slash_sel + n - 1) % n; }
        }
        KeyCode::Up | KeyCode::Down => {
            let up = k.code == KeyCode::Up;
            let n = slash_menu(app).len();
            if n > 0 {
                app.slash_sel = if up { (app.slash_sel + n - 1) % n } else { (app.slash_sel + 1) % n };
            } else if !slash_active(app) {
                if !app.input_history.browsing() {
                    if let Some(cursor) = composer::vertical_cursor(&app.input, app.input_cursor, up) {
                        app.input_cursor = cursor;
                        return;
                    }
                }
                let recalled = if up { app.input_history.previous(&app.input) } else { app.input_history.next() };
                if let Some(text) = recalled {
                    app.input = text;
                    app.input_cursor = app.input.chars().count();
                    app.slash_open = false;
                }
            }
        }
        KeyCode::Backspace => {
            if app.input_cursor > 0 {
                app.input_cursor -= 1;
                let byte = composer::byte_index(&app.input, app.input_cursor);
                app.input.remove(byte);
                touched = true;
            }
        }
        KeyCode::Delete => {
            let byte = composer::byte_index(&app.input, app.input_cursor);
            if byte < app.input.len() {
                app.input.remove(byte);
                touched = true;
            }
        }
        KeyCode::Left => app.input_cursor = app.input_cursor.saturating_sub(1),
        KeyCode::Right => app.input_cursor = (app.input_cursor + 1).min(app.input.chars().count()),
        KeyCode::Home => app.input_cursor = 0,
        KeyCode::End => app.input_cursor = app.input.chars().count(),
        KeyCode::Char(c) => {
            if !k.modifiers.contains(KeyModifiers::ALT) && !c.is_control() {
                insert_input(app, &c.to_string());
            }
        }
        KeyCode::PageUp => app.scroll_off = app.scroll_off.saturating_add(10),
        KeyCode::PageDown => app.scroll_off = app.scroll_off.saturating_sub(10),
        _ => {}
    }
    if touched {
        app.input_history.reset();
        app.slash_sel = 0;
        app.slash_open = true;
    }
}

/// 시작 URL 입력 모달 — Enter 면 저장 + 즉시 스윕.
fn on_key_url(app: &mut App, k: KeyEvent) {
    match k.code {
        KeyCode::Esc => app.popup = Popup::None,
        KeyCode::Enter => {
            let raw = app.url_field.value.trim().to_string();
            if raw.is_empty() {
                app.flash("URL을 입력하세요 (예: https://example.com:8443).".into());
                return;
            }
            if apply_url(app, &raw) {
                app.popup = Popup::None;
                start_sweep(app);
            }
        }
        KeyCode::Backspace => app.url_field.backspace(),
        KeyCode::Left => app.url_field.move_left(),
        KeyCode::Right => app.url_field.move_right(),
        KeyCode::Home => app.url_field.cursor = 0,
        KeyCode::Char(c) => {
            if !k.modifiers.contains(KeyModifiers::CONTROL) {
                app.url_field.insert(c);
            }
        }
        _ => {}
    }
}

/// URL 적용 (순수 저장 — 스윕은 호출자가 시작).
fn apply_url(app: &mut App, raw: &str) -> bool {
    let (mut host, port) = split_target(raw);
    if host.is_empty() {
        host = raw.trim().to_string();
    }
    if host.is_empty() {
        app.flash("URL을 해석할 수 없습니다.".into());
        return false;
    }
    app.session.host = host;
    app.session.port = port;
    app.session.name = if app.session.name.starts_with("session-") || app.session.name.is_empty() {
        app.session.target_label()
    } else {
        app.session.name.clone()
    };
    app.say("sys", format!("대상 저장 — {}", app.session.target_label()), LineLevel::Sys);
    app.save();
    true
}

/// 스크롤 전용 팝업 (which: 0=help, 1=report).
fn on_key_scroll_popup(app: &mut App, k: KeyEvent, which: u8) {
    let slot = if which == 0 { &mut app.help_scroll } else { &mut app.report_scroll };
    match k.code {
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
            app.popup = Popup::None;
            // 리포트를 처음 닫으면 다음 행동을 안내 (온보딩 코치).
            if which == 1 && !app.coached_report && !app.session.findings.is_empty() {
                app.coached_report = true;
                app.say("sys", "이제 아래 입력창에 질문하세요. 예: '로그인 페이지 취약점 가능성 분석해줘' (LLM 미연결 시 `/providers`)".into(), LineLevel::Sys);
            }
        }
        KeyCode::Up | KeyCode::Char('k') => *slot = slot.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => *slot += 1,
        KeyCode::PageUp => *slot = slot.saturating_sub(10),
        KeyCode::PageDown => *slot += 10,
        KeyCode::Home => *slot = 0,
        _ => {}
    }
}

/// 폼 팝업 (setup=true → 대상 설정, false → 프로바이더 편집).
fn on_key_form(app: &mut App, k: KeyEvent, setup: bool) {
    if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('s') {
        if setup { save_setup(app); } else { save_provider_edit(app); }
        return;
    }
    let (fields, sel) = if setup { (&mut app.setup_fields, &mut app.setup_sel) } else { (&mut app.prov_fields, &mut app.prov_sel_field) };
    match k.code {
        KeyCode::Esc => {
            app.popup = if setup { Popup::None } else { Popup::Providers };
        }
        KeyCode::Tab | KeyCode::Down => {
            *sel = (*sel + 1) % fields.len();
        }
        KeyCode::BackTab | KeyCode::Up => {
            *sel = (*sel + fields.len() - 1) % fields.len();
        }
        KeyCode::Enter => {
            // cycle 필드면 값 순환, 마지막 필드면 저장.
            let is_last = *sel + 1 >= fields.len();
            if fields[*sel].cycle.is_some() {
                fields[*sel].cycle_next();
            } else if is_last {
                if setup {
                    save_setup(app);
                } else {
                    save_provider_edit(app);
                }
            } else {
                *sel += 1;
            }
        }
        KeyCode::Char(' ') if fields[*sel].cycle.is_some() && k.modifiers.is_empty() => {
            fields[*sel].cycle_next();
        }
        KeyCode::Backspace => fields[*sel].backspace(),
        KeyCode::Left => {
            if fields[*sel].cycle.is_some() {
                fields[*sel].cycle_prev();
            } else {
                fields[*sel].move_left();
            }
        }
        KeyCode::Right => {
            if fields[*sel].cycle.is_some() {
                fields[*sel].cycle_next();
            } else {
                fields[*sel].move_right();
            }
        }
        KeyCode::Home => fields[*sel].cursor = 0,
        KeyCode::End => {
            let n = fields[*sel].value.chars().count();
            fields[*sel].cursor = n;
        }
        KeyCode::Char(c) => {
            if !k.modifiers.contains(KeyModifiers::CONTROL) && fields[*sel].cycle.is_none() {
                fields[*sel].insert(c);
            }
        }
        _ => {}
    }
}

fn on_key_consent(app: &mut App, k: KeyEvent) {
    match k.code {
        KeyCode::Esc => cancel_consent(app),
        KeyCode::Up | KeyCode::Char('k') => app.consent_scroll = app.consent_scroll.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => app.consent_scroll += 1,
        KeyCode::PageUp => app.consent_scroll = app.consent_scroll.saturating_sub(10),
        KeyCode::PageDown => app.consent_scroll += 10,
        KeyCode::Home => app.consent_scroll = 0,
        KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab => {
            app.consent_choice =
                if app.consent_choice == ConsentChoice::Yes { ConsentChoice::No } else { ConsentChoice::Yes };
        }
        KeyCode::Char('y') | KeyCode::Char('Y') => confirm_consent(app),
        KeyCode::Char('n') | KeyCode::Char('N') => cancel_consent(app),
        KeyCode::Enter => {
            if app.consent_choice == ConsentChoice::Yes {
                confirm_consent(app);
            } else {
                cancel_consent(app);
            }
        }
        _ => {}
    }
}

fn on_key_providers(app: &mut App, k: KeyEvent) {
    match k.code {
        KeyCode::Esc => app.popup = Popup::None,
        KeyCode::Up | KeyCode::Char('k') => app.prov_sel = app.prov_sel.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => {
            if !app.prov_list.is_empty() {
                app.prov_sel = (app.prov_sel + 1).min(app.prov_list.len() - 1);
            }
        }
        KeyCode::Enter | KeyCode::Char('e') => open_provider_edit(app, false),
        KeyCode::Char('n') => open_provider_edit(app, true),
        KeyCode::Char('d') => delete_provider(app),
        KeyCode::Char('u') => use_provider(app),
        KeyCode::Char('r') => {
            app.prov_list = providers::merged_view();
            app.prov_sel = app.prov_sel.min(app.prov_list.len().saturating_sub(1));
        }
        _ => {}
    }
}

fn on_key_sessions(app: &mut App, k: KeyEvent) {
    match k.code {
        KeyCode::Esc => app.popup = Popup::None,
        KeyCode::Up | KeyCode::Char('k') => app.sess_sel = app.sess_sel.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => {
            if !app.sess_list.is_empty() {
                app.sess_sel = (app.sess_sel + 1).min(app.sess_list.len() - 1);
            }
        }
        KeyCode::Enter => switch_session(app),
        KeyCode::Char('n') => new_session(app),
        KeyCode::Char('r') => open_rename(app),
        KeyCode::Char('d') => ask_delete_session(app),
        _ => {}
    }
}

/// 이름 변경 프롬프트 입력.
fn on_key_rename(app: &mut App, k: KeyEvent) {
    match k.code {
        KeyCode::Esc => app.popup = Popup::Sessions,
        KeyCode::Enter => apply_rename(app),
        KeyCode::Backspace => app.rename_field.backspace(),
        KeyCode::Left => app.rename_field.move_left(),
        KeyCode::Right => app.rename_field.move_right(),
        KeyCode::Home => app.rename_field.cursor = 0,
        KeyCode::End => {
            let n = app.rename_field.value.chars().count();
            app.rename_field.cursor = n;
        }
        KeyCode::Char(c) => {
            if !k.modifiers.contains(KeyModifiers::CONTROL) {
                app.rename_field.insert(c);
            }
        }
        _ => {}
    }
}

/// 삭제 확인 (`y` 확정).
fn on_key_delete_confirm(app: &mut App, k: KeyEvent) {
    match k.code {
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => app.popup = Popup::Sessions,
        KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => do_delete_session(app),
        _ => {}
    }
}

fn on_key_findings(app: &mut App, k: KeyEvent) {
    match k.code {
        KeyCode::Esc => app.popup = Popup::None,
        KeyCode::Up | KeyCode::Char('k') => app.findings_sel = app.findings_sel.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => {
            if !app.session.findings.is_empty() {
                app.findings_sel = (app.findings_sel + 1).min(app.session.findings.len() - 1);
            }
        }
        KeyCode::Enter => {
            if !app.session.findings.is_empty() {
                app.detail_idx = app.findings_sel;
                app.finding_scroll = 0;
                app.popup = Popup::FindingDetail;
            }
        }
        _ => {}
    }
}

fn on_key_detail(app: &mut App, k: KeyEvent) {
    match k.code {
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.popup = Popup::Findings,
        KeyCode::Up | KeyCode::Char('k') => app.finding_scroll = app.finding_scroll.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => app.finding_scroll += 1,
        KeyCode::PageUp => app.finding_scroll = app.finding_scroll.saturating_sub(10),
        KeyCode::PageDown => app.finding_scroll += 10,
        _ => {}
    }
}

// ── 액션 ─────────────────────────────────────────────────────────────────────

fn run_slash(app: &mut App, text: &str) {
    let mut parts = text[1..].split_whitespace();
    let cmd = parts.next().unwrap_or("").to_lowercase();
    let rest = text[text.find(char::is_whitespace).unwrap_or(text.len())..].trim().to_string();
    // 별칭은 카탈로그에서 정식 이름으로 푼다.
    let canon = slash::find(&cmd).map(|c| c.name).unwrap_or("");
    match canon {
        "help" => {
            app.help_scroll = 0;
            app.popup = Popup::Help;
        }
        "sweep" => start_sweep(app),
        "setup" => open_setup(app),
        // AI 연결 단일 진입점 — 미설정이면 마법사, 설정 후면 목록.
        "providers" => {
            if providers::needs_setup() {
                open_onboarding(app);
            } else {
                open_providers(app);
            }
        }
        "danger" => toggle_danger(app),
        "findings" => {
            app.findings_sel = 0;
            app.popup = Popup::Findings;
        }
        "sessions" => open_sessions(app),
        "stop" => stop_agent(app, false),
        "clear" => {
            app.session.log.clear();
            app.scroll_off = 0;
            app.save();
        }
        "quit" => {
            stop_agent(app, true);
            app.quit = true;
        }
        "say" => {
            if rest.is_empty() {
                app.flash("사용법: /say <메시지> — 채팅에만 기록 (실행 없음)".into());
            } else {
                app.session.push_chat("user", rest);
                app.save();
            }
        }
        _ => {
            // 오타 교정 제안 (편집거리 2 이하 중 최단).
            let hint = slash::CATALOG
                .iter()
                .map(|c| (c.name, edit_dist(&cmd, c.name)))
                .chain(slash::CATALOG.iter().flat_map(|c| c.aliases.iter().map(|a| (c.name, edit_dist(&cmd, a)))))
                .filter(|(_, d)| *d <= 2)
                .min_by_key(|(_, d)| *d)
                .map(|(n, _)| format!(" — `/{n}` 인가요?"));
            app.flash(format!("알 수 없는 명령: /{cmd}{} (`/` 메뉴·/help 참조)", hint.unwrap_or_default()));
        }
    }
}

/// 짧은 문자열용 편집거리 (명령어 오타 제안용).
fn edit_dist(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut dp: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut prev = dp[0];
        dp[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cur = dp[j + 1];
            dp[j + 1] = (prev + usize::from(ca != cb)).min(dp[j] + 1).min(cur + 1);
            prev = cur;
        }
    }
    dp[b.len()]
}

/// 지시 제출 — risk 게이트 → (필요시) 동의 모달 → agent 실행.
fn submit_instruction(app: &mut App, text: String) {
    if app.agent_running {
        app.flash("agent 실행 중입니다 — /stop 후 다시 시도하세요.".into());
        return;
    }
    if app.session.host.trim().is_empty() {
        app.session.push_chat("user", text.clone());
        app.session.goal = text;
        app.save();
        open_setup(app);
        app.flash("대상을 먼저 지정하세요 (`/setup`).".into());
        return;
    }
    app.session.push_chat("user", text.clone());
    app.session.goal = text.clone();
    app.save();
    let rep = engine::risk::assess(&text);
    if rep.needs_consent && !app.session.danger_consent {
        app.pending_instruction = Some(text);
        app.pending_risk = Some(rep);
        app.consent_choice = ConsentChoice::No;
        app.consent_scroll = 0;
        app.popup = Popup::ConsentRisk;
        return;
    }
    if rep.level == engine::risk::RiskLevel::Caution {
        app.say("sys", format!("주의: {} — 진행합니다.", rep.summary), LineLevel::Sys);
    }
    spawn_agent_task(app, text);
}

fn spawn_agent_task(app: &mut App, goal: String) {
    // TS `redcell run` 과 같은 fail-closed 인가 검사 — 실패 원인을 TUI 에서 바로 보인다.
    if !scope_preflight(app) {
        return;
    }
    // 프로바이더 확인 — 세션 지정 > redcell 기본값.
    let cfg = providers::load_config();
    let provider = if !app.session.provider.trim().is_empty() {
        app.session.provider.clone()
    } else {
        cfg.default_provider.clone().unwrap_or_default()
    };
    let model = if !app.session.model.trim().is_empty() {
        app.session.model.clone()
    } else {
        cfg.default_model.clone().unwrap_or_default()
    };
    if provider.trim().is_empty() {
        if providers::needs_setup() {
            open_onboarding(app);
            app.flash("LLM 연결이 필요합니다 — 마법사에서 프로바이더를 연결하세요.".into());
        } else {
            open_providers(app);
            app.flash("LLM 프로바이더를 먼저 연결하세요 (`/providers`).".into());
        }
        return;
    }
    // P0 스윕 결과를 agent 에 넘긴다:
    //   1) --target-map 파일 — 발견된 경로·파라미터를 인젝션 툴 인자로 자동 주입(정찰→공격 연결)
    //   2) goal 보강 — 상위 발견 요약을 목표 텍스트에 붙여 모델이 스윕 근거에서 출발하게.
    let target_map = write_target_map(&app.session.findings);
    let goal = enrich_goal(&goal, &app.session.findings);
    let has_map = target_map.is_some();
    match task::spawn_agent(
        app.tx.clone(),
        app.session.host.trim().to_string(),
        app.session.port,
        goal.clone(),
        provider.clone(),
        model.clone(),
        target_map,
    ) {
        Ok(handle) => {
            app.agent = Some(handle);
            app.agent_running = true;
            app.agent_started = Instant::now();
            app.session.status = "running".into();
            let map_note = if has_map { " · 스윕 표면 주입" } else { "" };
            app.say("agent", format!("실행 시작 — {provider}{} · goal {}자{map_note}", if model.is_empty() { String::new() } else { format!("/{model}") }, goal.chars().count()), LineLevel::Agent);
            app.save();
        }
        Err(e) => {
            app.say("sys", format!("실행 실패: {e}"), LineLevel::Error);
            app.session.status = "error".into();
            app.save();
        }
    }
}

/// 스윕 발견 → TS core/target-map.ts 규격의 표면 JSON (paths·params·idPath).
fn build_target_map(findings: &[ProbeHit]) -> Option<serde_json::Value> {
    let mut paths: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();
    let mut id_path: Option<String> = None;
    for h in findings {
        // target 은 "http(s)://host[:port]/path?query" 또는 경로/호스트일 수 있다.
        let t = h.target.trim();
        let pathq = match t.split_once("://") {
            Some((_, rest)) => match rest.find('/') {
                Some(i) => rest[i..].to_string(),
                None => "/".to_string(),
            },
            None => t.to_string(),
        };
        let (path, query) = match pathq.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (pathq.clone(), None),
        };
        // 경로 정규화 — "/" 단독은 표면 정보가 아니므로 제외.
        let meaningful = path.len() > 1 && !path.contains("%2e%2e") && !path.contains("..")
            && !path.contains("evil-probe") && path.len() <= 120;
        if let Some(q) = query {
            for kv in q.split('&') {
                if let Some((k, _)) = kv.split_once('=') {
                    let k = k.trim();
                    if !k.is_empty()
                        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '[' || c == ']')
                        && !params.iter().any(|p| p == k)
                        && params.len() < 8
                    {
                        params.push(k.to_string());
                    }
                }
            }
        }
        if meaningful && !paths.contains(&path) && paths.len() < 8 {
            paths.push(path.clone());
        }
        // IDOR 후보 — /…/숫자 로 끝나는 경로 하나만 (TS surfaceFrom 과 동일 규칙).
        if id_path.is_none() && h.category == "idor" {
            if let Some((_, rest)) = t.split_once("://") {
                if let Some((_, p)) = rest.split_once('/') {
                    let path = p.split(['?', '#']).next().unwrap_or("");
                    let last = path.rsplit('/').next().unwrap_or("");
                    if !last.is_empty() && last.chars().all(|c| c.is_ascii_digit()) {
                        id_path = Some(format!("/{path}"));
                    }
                }
            }
        }
    }
    if paths.is_empty() && params.is_empty() {
        return None;
    }
    let mut map = serde_json::Map::new();
    if !paths.is_empty() {
        map.insert("paths".into(), serde_json::Value::Array(paths.into_iter().map(serde_json::Value::String).collect()));
    }
    if !params.is_empty() {
        map.insert("params".into(), serde_json::Value::Array(params.into_iter().map(serde_json::Value::String).collect()));
    }
    if let Some(id) = id_path {
        map.insert("idPath".into(), serde_json::Value::String(id));
    }
    Some(serde_json::Value::Object(map))
}

/// build_target_map 결과를 0600 파일로 저장 — 세션 저장소에 보관해 재현성도 확보.
fn write_target_map(findings: &[ProbeHit]) -> Option<std::path::PathBuf> {
    let map = build_target_map(findings)?;
    let txt = map.to_string();
    let path = session::data_dir().join("target-map.json");
    if session::write_private(&path, &txt).is_err() {
        return None;
    }
    Some(path)
}

/// goal 에 상위 발견 요약을 덧붙여 모델이 스윕 근거에서 출발하게 한다 (상한 5건·800자).
fn enrich_goal(goal: &str, findings: &[ProbeHit]) -> String {
    let top: Vec<&ProbeHit> = findings
        .iter()
        .filter(|h| h.severity == "critical" || h.severity == "high" || h.severity == "medium")
        .take(5)
        .collect();
    if top.is_empty() {
        return goal.to_string();
    }
    let mut s = format!(
        "{goal}\n\n[P0 스윕 선행 결과 — 이 근거를 우선 검증·확장하세요. 전체는 /findings 참조]"
    );
    for h in top {
        let line = format!("\n- {}({}) {}", h.id, h.severity, one_word_summary(h));
        if s.chars().count() + line.chars().count() > 800 {
            break;
        }
        s.push_str(&line);
    }
    s
}

/// 발견 한 건의 한 줄 요약 — 제목 + 대상(최대 120자).
fn one_word_summary(h: &ProbeHit) -> String {
    let t = h.target.trim();
    let short_target = t
        .split_once("://")
        .map(|(_, rest)| {
            let p = rest.find('/').map(|i| &rest[i..]).unwrap_or("/");
            p.chars().take(60).collect::<String>()
        })
        .unwrap_or_else(|| t.chars().take(60).collect());
    format!("{} — {}", h.title, short_target)
}

fn stop_agent(app: &mut App, quiet: bool) {
    app.sweep_gen = app.sweep_gen.wrapping_add(1); // 진행 중 스윕 결과 무시
    if app.sweep_running {
        // 엔진에 진짜 중단 요청 (다음 체크포인트에서 즉시 종료).
        if let Some(fb) = &app.sweep_fb {
            fb.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        app.sweep_running = false;
        app.session.status = "stopped".into();
        if !quiet {
            app.say("sys", "P0 스윕 중단됨 — 지금까지 결과는 버려집니다.".into(), LineLevel::Warn);
        }
        app.save();
    }
    if let Some(h) = app.agent.take() {
        // 프로세스 그룹 전체 종료 — poison 된 락에서도 kill 이 생략되지 않는다.
        task::kill_agent(&h);
        app.agent_running = false;
        app.session.status = "stopped".into();
        if !quiet {
            app.say("agent", "중지됨.".into(), LineLevel::Warn);
        }
        app.save();
    } else if !quiet && !app.sweep_running {
        app.flash("실행 중인 작업이 없습니다.".into());
    }
}

/// 스윕·agent 실행 전 인가 사전 검사 — 차단 시 안내를 남기고 false.
/// (agent 자체는 TS ScopeGuard 가 다시 검사하지만, 여기서 걸러야 실패 원인이 즉시 보인다.)
fn scope_preflight(app: &mut App) -> bool {
    let host = app.session.host.trim().to_string();
    match scope::preflight(&host, app.session.port) {
        scope::ScopeDecision::Allowed | scope::ScopeDecision::Skip => true,
        scope::ScopeDecision::Missing => {
            app.flash(format!(
                "인가 목록이 없습니다 — `redcell auth add {host}` 로 인가 후 재시도하세요 (fail-closed)."
            ));
            app.say(
                "sys",
                format!("인가 차단 — '{host}' 가 인가 목록에 없습니다. 터미널에서 `redcell auth add {host}` 를 실행하세요."),
                LineLevel::Error,
            );
            app.save();
            false
        }
        scope::ScopeDecision::Denied(reason) => {
            app.flash(format!("인가 차단 — `redcell auth add {host}` 또는 목록 확인 필요."));
            app.say("sys", format!("인가 차단: {reason}"), LineLevel::Error);
            app.save();
            false
        }
    }
}

fn start_sweep(app: &mut App) {
    if app.sweep_running {
        app.flash("P0 스윕이 이미 실행 중입니다.".into());
        return;
    }
    if app.session.host.trim().is_empty() {
        open_setup(app);
        app.flash("대상을 먼저 지정하세요 (`/setup`).".into());
        return;
    }
    // TS `redcell run` 과 동일한 fail-closed 인가 검사 — 스윕이 ScopeGuard 를 우회하지 않게.
    if !scope_preflight(app) {
        return;
    }
    app.sweep_gen = app.sweep_gen.wrapping_add(1);
    let sweep_gen = app.sweep_gen;
    app.sweep_running = true;
    app.sweep_started = Instant::now();
    let danger = app.session.danger_consent;
    app.say(
        "p0",
        format!("P0 스윕 시작 — {}{} (Esc로 언제든 중단)", app.session.target_label(), if danger { " (파괴적 동의)" } else { "" }),
        LineLevel::Sys,
    );
    if danger {
        app.say("p0", "파괴적 프로브 실행 — 기본자격·IDOR 인접·쓰기 검증 (사용자 동의 기반)".into(), LineLevel::Warn);
    }
    let fb = std::sync::Arc::new(engine::probes::SweepFeedback::default());
    app.sweep_fb = Some(fb.clone());
    task::spawn_sweep(app.tx.clone(), sweep_gen, app.session.host.trim().to_string(), app.session.port, app.session.cookie.clone(), danger, fb);
    app.save();
}

fn on_task_msg(app: &mut App, msg: TaskMsg) {
    match msg {
        TaskMsg::SweepDone { sweep_gen, summary, hits, secs } => {
            // 중지·재시작된 이전 스윕의 늦은 결과는 폐기 (세대 번호 불일치).
            if !app.sweep_running || sweep_gen != app.sweep_gen {
                return;
            }
            app.sweep_running = false;
            app.session.findings = hits;
            app.findings_sel = 0;
            app.finding_scroll = 0;
            app.detail_idx = 0;
            let summary = summary.trim_start_matches("[sys]").trim_start().to_string();
            app.session.sweep_summary = summary.clone();
            let n = app.session.findings.len();
            app.say("p0", format!("{summary}"), LineLevel::Sys);
            app.say("sys", format!("발견 {n}건 ({secs}초) — `/findings`에서 확인.", ), LineLevel::Sys);
            if app.session.status == "running" && !app.agent_running {
                app.session.status = "done".into();
            }
            app.save();
            // 점검 리포트를 화면에 바로 표시 (동의 모달 방해 금지).
            if !matches!(app.popup, Popup::ConsentStatic | Popup::ConsentRisk) {
                app.report_scroll = 0;
                app.popup = Popup::Report;
            }
        }
        TaskMsg::AgentLine { line, err } => {
            let t = line.trim_end().to_string();
            if t.is_empty() {
                return;
            }
            // ANSI 이스케이프 제거 (간이).
            let clean = strip_ansi(&t);
            app.say("agent", clean.chars().take(500).collect(), if err { LineLevel::Warn } else { LineLevel::Agent });
        }
        TaskMsg::AgentDone { ok, secs, code } => {
            if !app.agent_running {
                return;
            }
            app.agent_running = false;
            app.agent = None;
            app.session.status = if ok { "done".into() } else { "error".into() };
            app.say("agent", format!("종료 — {} ({}초)", if ok { "성공" } else { "실패" }, secs), if ok { LineLevel::Sys } else { LineLevel::Error });
            // TS 의 의미있는 종료코드 — 즉시 다음 행동을 안내한다.
            if !ok {
                match code {
                    Some(3) => {
                        let host = app.session.host.trim().to_string();
                        app.say(
                            "sys",
                            format!("scope 차단(종료코드 3) — '{host}' 가 인가 목록에 없습니다. `redcell auth add {host}` 후 재시도하세요."),
                            LineLevel::Error,
                        );
                    }
                    Some(4) => {
                        app.say(
                            "sys",
                            "대상 도달 불가(종료코드 4) — host/port 를 확인하거나 서버 기동 상태를 점검하세요.".into(),
                            LineLevel::Error,
                        );
                    }
                    _ => {}
                }
            }
            if ok && !app.coached_agent {
                app.coached_agent = true;
                app.say("sys", "추가 점검이 끝나면 `/findings` 로 스윕 증거를 다시 확인하세요.".into(), LineLevel::Sys);
            }
            app.save();
        }
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.peek() {
                // CSI 시퀀스 스킵.
                Some('[') => {
                    chars.next();
                    for nc in chars.by_ref() {
                        if nc.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
                // OSC 시퀀스 (터미널 제목·하이퍼링크) — BEL 또는 ESC\ 까지 스킵.
                Some(']') => {
                    chars.next();
                    let mut done = false;
                    while let Some(nc) = chars.next() {
                        if nc == '\u{7}' {
                            done = true;
                            break;
                        }
                        if nc == '\u{1b}' {
                            if chars.next() == Some('\\') {
                                done = true;
                            }
                            break;
                        }
                    }
                    let _ = done;
                }
                _ => {}
            }
            continue;
        }
        if c.is_control() && c != '\t' {
            continue;
        }
        out.push(c);
    }
    out
}

// ── 동의 ─────────────────────────────────────────────────────────────────────

fn toggle_danger(app: &mut App) {
    if app.session.danger_consent {
        // 철회는 즉시.
        app.session.danger_consent = false;
        app.session.danger_consented_at.clear();
        app.say("sys", "파괴적 진단 동의 철회 — 읽기 전용 모드로 복귀합니다.".into(), LineLevel::Sys);
        app.save();
    } else {
        app.consent_choice = ConsentChoice::No;
        app.consent_scroll = 0;
        app.popup = Popup::ConsentStatic;
    }
}

fn confirm_consent(app: &mut App) {
    app.session.danger_consent = true;
    app.session.danger_consented_at = session::now();
    app.say("sys", "파괴적 진단 동의됨 — 기본자격·IDOR 인접·쓰기 검증 + 파괴적 지시 실행.".into(), LineLevel::Warn);
    app.popup = Popup::None;
    app.save();
    // 보류 중이던 지시 재시도.
    if let Some(inst) = app.pending_instruction.take() {
        app.pending_risk = None;
        spawn_agent_task(app, inst);
    } else {
        app.pending_risk = None;
    }
}

fn cancel_consent(app: &mut App) {
    app.pending_instruction = None;
    app.pending_risk = None;
    app.popup = Popup::None;
    app.session.push_chat("system", "파괴적 지시 보류됨 — 동의 없이 실행하지 않았습니다.".into());
    app.save();
}

// ── 대상 설정 ────────────────────────────────────────────────────────────────

fn open_setup(app: &mut App) {
    let mut prov = Field::text("provider", app.session.provider.clone());
    let mut names: Vec<String> = providers::merged_view().iter().map(|p| p.name.clone()).collect();
    names.insert(0, String::new());
    prov.cycle = Some(names);
    app.setup_fields = vec![
        Field::text("세션명", app.session.name.clone()),
        Field::text("host/URL", app.session.host.clone()),
        Field::text("port", app.session.port.map(|p| p.to_string()).unwrap_or_default()),
        prov,
        Field::text("model", app.session.model.clone()),
        Field::secret("세션 쿠키", app.session.cookie.clone()),
    ];
    app.setup_sel = 1;
    app.popup = Popup::Setup;
}

fn save_setup(app: &mut App) {
    let v = |i: usize| app.setup_fields.get(i).map(|f| f.value.trim().to_string()).unwrap_or_default();
    app.session.name = if v(0).is_empty() { app.session.name.clone() } else { v(0) };
    // URL/host:port 분해.
    let raw = v(1);
    let (mut host, mut port) = split_target(&raw);
    if let Ok(p) = v(2).parse::<u16>() {
        if p > 0 {
            port = Some(p);
        }
    }
    if host.is_empty() {
        host = raw;
    }
    app.session.host = host;
    app.session.port = port;
    app.session.provider = v(3);
    app.session.model = v(4);
    // 쿠키 필드는 기존 값이 채워져 시작하므로, 비운 것 = 명시적 삭제로 본다 (입력 = 진실).
    app.session.cookie = v(5);
    app.popup = Popup::None;
    app.refresh_connection();
    app.say("sys", format!("대상 저장 — {} · provider {}", app.session.target_label(), if app.session.provider.is_empty() { "(기본값)" } else { &app.session.provider }), LineLevel::Sys);
    app.save();
}

fn split_target(raw: &str) -> (String, Option<u16>) {
    let mut t = raw.trim();
    t = t.strip_prefix("https://").or_else(|| t.strip_prefix("http://")).unwrap_or(t);
    t = t.split('/').next().unwrap_or("");
    if t.is_empty() {
        return (String::new(), None);
    }
    if let Some(stripped) = t.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            let host = stripped[..end].to_string();
            let port = stripped[end + 1..].strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
        return (t.to_string(), None);
    }
    if t.matches(':').count() == 1 {
        if let Some((h, p)) = t.split_once(':') {
            return (h.to_string(), p.parse::<u16>().ok());
        }
    }
    (t.to_string(), None)
}

// ── 프로바이더 ───────────────────────────────────────────────────────────────

fn open_providers(app: &mut App) {
    app.prov_list = providers::merged_view();
    app.prov_sel = 0;
    app.popup = Popup::Providers;
}

fn open_provider_edit(app: &mut App, is_new: bool) {
    if !is_new && app.prov_list.is_empty() {
        return;
    }
    if !is_new {
        app.prov_sel = app.prov_sel.min(app.prov_list.len() - 1);
    }
    let customs = providers::load_customs();
    let cur_name = if is_new { String::new() } else { app.prov_list[app.prov_sel].name.clone() };
    let cur = customs.iter().find(|c| c.name == cur_name);
    let view = if is_new { None } else { app.prov_list.get(app.prov_sel) };
    let mut kind = Field::text("kind", cur.map(|c| c.kind.clone()).filter(|k| !k.is_empty()).or_else(|| view.map(|v| v.kind.clone())).unwrap_or_else(|| "openai-compat".into()));
    kind.cycle = Some(vec!["openai-compat".into(), "anthropic".into()]);
    let mut auth = Field::text("auth", cur.and_then(|c| c.auth_type.clone()).filter(|t| !t.trim().is_empty()).unwrap_or_else(|| "api_key".into()));
    auth.cycle = Some(vec!["api_key".into(), "oauth".into()]);
    app.prov_fields = vec![
        Field::text("name", cur_name.clone()),
        kind,
        Field::text("baseUrl", cur.and_then(|c| c.base_url.clone()).or_else(|| view.map(|v| v.base_url.clone())).unwrap_or_default()),
        Field::secret("key", String::new()),
        auth,
        Field::text("model", cur.and_then(|c| c.default_model.clone()).or_else(|| view.map(|v| v.model.clone())).unwrap_or_default()),
        Field::text("note", cur.and_then(|c| c.note.clone()).unwrap_or_default()),
    ];
    app.prov_sel_field = if is_new { 0 } else { 3 };
    app.prov_edit_name = if is_new { None } else { Some(cur_name) };
    app.prov_edit_is_new = is_new;
    app.popup = if is_new { Popup::ProviderNew } else { Popup::ProviderEdit };
}

fn save_provider_edit(app: &mut App) {
    let v = |i: usize| app.prov_fields.get(i).map(|f| f.value.trim().to_string()).unwrap_or_default();
    let name = if app.prov_edit_is_new { v(0) } else { app.prov_edit_name.clone().unwrap_or_default() };
    if name.is_empty() {
        app.flash("name 이 비어 있습니다.".into());
        return;
    }
    let auth = v(4);
    let spec = providers::CustomSpec {
        name: name.clone(),
        kind: v(1),
        base_url: if v(2).is_empty() { None } else { Some(v(2)) },
        env_keys: Vec::new(),
        api_key: if v(3).is_empty() { None } else { Some(v(3)) },
        auth_type: if auth.is_empty() { None } else { Some(auth) },
        default_model: if v(5).is_empty() { None } else { Some(v(5)) },
        note: if v(6).is_empty() { None } else { Some(v(6)) },
    };
    match providers::upsert_custom(spec) {
        Ok(()) => {
            app.flash(format!("'{name}' 저장됨."));
            app.prov_list = providers::merged_view();
            app.popup = Popup::Providers;
        }
        Err(e) => app.flash(format!("저장 실패: {e}")),
    }
}

fn delete_provider(app: &mut App) {
    if app.prov_list.is_empty() {
        return;
    }
    let name = app.prov_list[app.prov_sel.min(app.prov_list.len() - 1)].name.clone();
    match providers::remove_custom(&name) {
        Ok(true) => {
            app.flash(format!("'{name}' 사용자 정의 삭제됨 (빌트인은 유지)."));
            app.prov_list = providers::merged_view();
        }
        Ok(false) => app.flash(format!("'{name}' 사용자 정의 없음 (빌트인 삭제 불가).")),
        Err(e) => app.flash(format!("삭제 실패: {e}")),
    }
    app.refresh_connection();
}

fn use_provider(app: &mut App) {
    if app.prov_list.is_empty() {
        return;
    }
    let v = &app.prov_list[app.prov_sel.min(app.prov_list.len() - 1)];
    app.session.provider = v.name.clone();
    if !v.model.is_empty() && app.session.model.trim().is_empty() {
        app.session.model = v.model.clone();
    }
    // redcell 기본값으로도 기록 (CLI 직접 실행과 공유).
    let mut cfg = providers::load_config();
    cfg.default_provider = Some(v.name.clone());
    if !v.model.is_empty() {
        cfg.default_model = Some(v.model.clone());
    }
    match providers::save_config(&cfg) {
        Ok(()) => app.flash(format!("'{}' 사용 — 세션 + redcell 기본값에 반영.", v.name)),
        Err(e) => app.flash(format!("기본값 저장 실패: {e}")),
    }
    app.popup = Popup::None;
    app.refresh_connection();
    app.save();
}

// ── 온보딩 (첫 실행 LLM 연결 마법사) ─────────────────────────────────────────────

/// 마법사 열기 — 프로바이더 목록을 다시 읽고 환영 단계부터.
fn open_onboarding(app: &mut App) {
    app.prov_list = providers::merged_view();
    app.onboard_prov_sel = app
        .prov_list
        .iter()
        .position(|p| p.name == "anthropic")
        .unwrap_or(0)
        .min(app.prov_list.len().saturating_sub(1));
    app.onboard_step = 0;
    app.onboard_error = None;
    app.onboard_force_armed = false;
    app.popup = Popup::Onboarding;
}

/// 설정 완료/건너뛰기 모두 메인으로. 다음 설정을 강제로 열지 않는다.
fn close_onboarding(app: &mut App) {
    app.refresh_connection();
    app.popup = Popup::None;
}

fn onboard_method_label(m: OnboardMethod) -> (&'static str, &'static str) {
    match m {
        OnboardMethod::ApiKey => ("API 키 직접 입력", "발급받은 API 키를 붙여넣습니다"),
        OnboardMethod::OAuth => ("OAuth 토큰 붙여넣기", "다른 코딩 에이전트 로그인 토큰 (anthropic: Muse/ant 토큰)"),
        OnboardMethod::PiImport => ("pi-agent 에서 가져오기", "~/.pi/agent/auth.json 의 같은 이름 자격증명"),
    }
}

/// 단계별 키 처리.
fn on_key_onboarding(app: &mut App, k: KeyEvent) {
    match app.onboard_step {
        0 => match k.code {
            KeyCode::Esc => close_onboarding(app), // 건너뛰기
            KeyCode::Enter | KeyCode::Char(' ') => app.onboard_step = 1,
            _ => {}
        },
        1 => match k.code {
            KeyCode::Esc => app.onboard_step = 0,
            KeyCode::Up | KeyCode::Char('k') => app.onboard_prov_sel = app.onboard_prov_sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                if !app.prov_list.is_empty() {
                    app.onboard_prov_sel = (app.onboard_prov_sel + 1).min(app.prov_list.len() - 1);
                }
            }
            KeyCode::Enter => onboard_pick_provider(app),
            _ => {}
        },
        2 => match k.code {
            KeyCode::Esc => app.onboard_step = 1,
            KeyCode::Up | KeyCode::Char('k') => app.onboard_method_sel = app.onboard_method_sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                if !app.onboard_methods.is_empty() {
                    app.onboard_method_sel = (app.onboard_method_sel + 1).min(app.onboard_methods.len() - 1);
                }
            }
            KeyCode::Enter => onboard_pick_method(app),
            _ => {}
        },
        _ => on_key_onboarding_form(app, k),
    }
}

/// 1단계 확정 — 선택 프로바이더의 인증 방식 목록 구성.
fn onboard_pick_provider(app: &mut App) {
    if app.prov_list.is_empty() {
        return;
    }
    let v = &app.prov_list[app.onboard_prov_sel.min(app.prov_list.len() - 1)];
    app.onboard_name = v.name.clone();
    app.onboard_kind = v.kind.clone();
    app.onboard_base_url = v.base_url.clone();
    let mut methods = vec![OnboardMethod::ApiKey, OnboardMethod::OAuth];
    if providers::read_pi_auth(&v.name).is_some() {
        methods.push(OnboardMethod::PiImport);
    }
    app.onboard_methods = methods;
    app.onboard_method_sel = 0;
    app.onboard_error = None;
    app.onboard_step = 2;
}

/// 2단계 확정 — 키 입력 필드 준비 (pi 면 키까지 채움).
fn onboard_pick_method(app: &mut App) {
    if app.onboard_methods.is_empty() {
        return;
    }
    let m = app.onboard_methods[app.onboard_method_sel.min(app.onboard_methods.len() - 1)];
    let dflt_model = app
        .prov_list
        .iter()
        .find(|p| p.name == app.onboard_name)
        .map(|p| p.model.clone())
        .unwrap_or_default();
    let key = if m == OnboardMethod::PiImport {
        providers::read_pi_auth(&app.onboard_name).map(|(k, _)| k).unwrap_or_default()
    } else {
        String::new()
    };
    app.onboard_fields = vec![Field::secret("key", key), Field::text("model", dflt_model)];
    app.onboard_field_sel = 0;
    app.onboard_error = None;
    app.onboard_force_armed = false;
    app.onboard_step = 3;
}

/// 3단계 — 키·모델 입력 폼.
fn on_key_onboarding_form(app: &mut App, k: KeyEvent) {
    if app.onboard_fields.is_empty() {
        return;
    }
    let n = app.onboard_fields.len();
    let sel = app.onboard_field_sel;
    match k.code {
        KeyCode::Esc => {
            app.onboard_step = 2;
            app.onboard_error = None;
            app.onboard_force_armed = false;
        }
        KeyCode::Tab | KeyCode::Down => {
            app.onboard_field_sel = (sel + 1) % n;
            app.onboard_error = None;
        }
        KeyCode::BackTab | KeyCode::Up => {
            app.onboard_field_sel = (sel + n - 1) % n;
            app.onboard_error = None;
        }
        KeyCode::Enter => {
            if sel + 1 >= n {
                onboard_save(app);
            } else {
                app.onboard_field_sel = sel + 1;
            }
        }
        KeyCode::Backspace => {
            app.onboard_fields[sel].backspace();
            app.onboard_error = None;
            app.onboard_force_armed = false;
        }
        KeyCode::Left => app.onboard_fields[sel].move_left(),
        KeyCode::Right => app.onboard_fields[sel].move_right(),
        KeyCode::Home => app.onboard_fields[sel].cursor = 0,
        KeyCode::End => {
            let c = app.onboard_fields[sel].value.chars().count();
            app.onboard_fields[sel].cursor = c;
        }
        KeyCode::Char(c) => {
            if !k.modifiers.contains(KeyModifiers::CONTROL) {
                app.onboard_fields[sel].insert(c);
                app.onboard_error = None;
                app.onboard_force_armed = false;
            }
        }
        _ => {}
    }
}

/// 3단계 저장 — 검증(실패 시 2회 Enter 로 강제 저장) → 기본값 지정 → 닫기.
fn onboard_save(app: &mut App) {
    let key = app.onboard_fields.first().map(|f| f.value.trim().to_string()).unwrap_or_default();
    let model = app.onboard_fields.get(1).map(|f| f.value.trim().to_string()).unwrap_or_default();
    if key.is_empty() {
        app.onboard_error = Some("키를 입력하세요 (pi-agent 가져오기는 뒤로(Esc) → 인증 방식에서).".into());
        return;
    }
    if model.is_empty() {
        app.onboard_error = Some("모델을 입력하세요 (예: 프로바이더 기본 모델).".into());
        return;
    }
    let method = app.onboard_methods.get(app.onboard_method_sel).copied().unwrap_or(OnboardMethod::ApiKey);
    let auth_type = match method {
        OnboardMethod::ApiKey => "api_key".to_string(),
        OnboardMethod::OAuth => "oauth".to_string(),
        // pi 원본의 인증 방식을 그대로 계승한다.
        OnboardMethod::PiImport => providers::read_pi_auth(&app.onboard_name).map(|(_, t)| t).unwrap_or_else(|| "api_key".into()),
    };
    if app.onboard_kind == "openai-compat" && app.onboard_base_url.trim().is_empty() {
        app.onboard_error = Some("이 프로바이더에는 baseUrl 이 없습니다 — `/providers` → n 으로 baseUrl 과 함께 등록하세요.".into());
        return;
    }
    // best-effort 검증 — UI 를 최대 ~16초 붙잡을 수 있어 한 번만 시도한다.
    if !app.onboard_force_armed {
        if let Some(warn) = providers::verify_key(&app.onboard_kind, &app.onboard_base_url, &key, &auth_type) {
            app.onboard_error = Some(format!("{warn} — 그대로 저장하려면 다시 Enter."));
            app.onboard_force_armed = true;
            return;
        }
    }
    let name = app.onboard_name.clone();
    let spec = providers::CustomSpec {
        name: name.clone(),
        kind: app.onboard_kind.clone(),
        base_url: if app.onboard_base_url.trim().is_empty() { None } else { Some(app.onboard_base_url.clone()) },
        env_keys: Vec::new(),
        api_key: Some(key),
        auth_type: Some(auth_type.clone()),
        default_model: Some(model.clone()),
        note: None,
    };
    match providers::upsert_custom(spec) {
        Ok(()) => {
            app.session.provider = name.clone();
            app.session.model = model.clone();
            let mut cfg = providers::load_config();
            cfg.default_provider = Some(name.clone());
            cfg.default_model = Some(model.clone());
            if let Err(e) = providers::save_config(&cfg) {
                app.flash(format!("연결됐으나 기본값 저장 실패: {e}"));
            } else {
                app.flash(format!("'{name}' 연결됨 ({}).", if auth_type == "oauth" { "OAuth" } else { "API 키" }));
            }
            app.say("sys", format!("LLM 연결 — {name}/{model} (기본값 지정). `/providers` 에서 변경 가능."), LineLevel::Sys);
            app.save();
            close_onboarding(app);
        }
        Err(e) => app.onboard_error = Some(format!("저장 실패: {e}")),
    }
}

// ── 세션 ─────────────────────────────────────────────────────────────────────

fn open_sessions(app: &mut App) {
    app.save();
    app.sess_list = TuiSession::list();
    app.sess_sel = app.sess_list.iter().position(|(id, _, _, _)| id == &app.session.id).unwrap_or(0);
    app.new_name_buf.clear();
    app.popup = Popup::Sessions;
}

fn switch_session(app: &mut App) {
    if app.sess_list.is_empty() {
        return;
    }
    let id = app.sess_list[app.sess_sel.min(app.sess_list.len() - 1)].0.clone();
    if id == app.session.id {
        app.popup = Popup::None;
        return;
    }
    if app.agent_running || app.sweep_running {
        app.flash("실행 중에는 세션을 바꿀 수 없습니다 (/stop 후).".into());
        return;
    }
    app.save();
    if let Some(s) = TuiSession::load(&id) {
        app.session = s;
        app.scroll_off = 0;
        app.reset_composer();
        app.input_history = composer::History::default();
        for message in app.session.chat.iter().filter(|m| m.role == "user") {
            app.input_history.remember(&message.content);
        }
        app.refresh_connection();
        app.popup = Popup::None;
    }
}

fn new_session(app: &mut App) {
    if app.agent_running || app.sweep_running {
        app.flash("실행 중에는 새로 만들 수 없습니다 (/stop 후).".into());
        return;
    }
    app.save();
    let n = TuiSession::list().len() + 1;
    let mut s = TuiSession::fresh(format!("session-{n}"), String::new());
    s.push_log("sys", "새 세션 — `/setup` 에서 대상을 지정하세요.".into(), LineLevel::Sys);
    s.save();
    app.session = s;
    app.scroll_off = 0;
    app.reset_composer();
    app.input_history = composer::History::default();
    app.refresh_connection();
    app.popup = Popup::None;
}

/// 세션 목록에서 이름 변경 프롬프트 열기.
fn open_rename(app: &mut App) {
    if app.sess_list.is_empty() {
        return;
    }
    let cur = app.sess_list[app.sess_sel.min(app.sess_list.len() - 1)].1.clone();
    app.rename_field = Field::text("이름", cur);
    app.popup = Popup::RenamePrompt;
}

/// 이름 변경 적용 (현재·과거 세션 모두).
fn apply_rename(app: &mut App) {
    if app.sess_list.is_empty() {
        app.popup = Popup::Sessions;
        return;
    }
    let name = app.rename_field.value.trim().to_string();
    if name.is_empty() {
        app.flash("이름이 비어 있습니다.".into());
        return;
    }
    let id = app.sess_list[app.sess_sel.min(app.sess_list.len() - 1)].0.clone();
    if id == app.session.id {
        app.session.name = name.clone();
        app.save();
    } else if let Some(mut s) = TuiSession::load(&id) {
        s.name = name.clone();
        s.save();
    }
    app.sess_list = TuiSession::list();
    app.flash(format!("세션 이름 → '{name}'."));
    app.popup = Popup::Sessions;
}

/// 삭제 확인 모달 열기.
fn ask_delete_session(app: &mut App) {
    if app.sess_list.is_empty() {
        return;
    }
    let (id, name, _, _) = app.sess_list[app.sess_sel.min(app.sess_list.len() - 1)].clone();
    if (app.agent_running || app.sweep_running) && id == app.session.id {
        app.flash("실행 중인 현재 세션은 /stop 후 삭제하세요.".into());
        return;
    }
    app.delete_target = Some((id, name));
    app.popup = Popup::DeleteConfirm;
}

/// 삭제 확정 — 현재 세션이면 다른 세션으로 전환(없으면 새로 생성).
fn do_delete_session(app: &mut App) {
    let Some((id, name)) = app.delete_target.clone() else {
        app.popup = Popup::Sessions;
        return;
    };
    app.delete_target = None;
    TuiSession::delete(&id);
    if id == app.session.id {
        let rest = TuiSession::list();
        if let Some((next, _, _, _)) = rest.first() {
            if let Some(s) = TuiSession::load(next) {
                app.session = s;
                app.scroll_off = 0;
                app.input.clear();
                app.input_cursor = 0;
            }
        } else {
            let mut s = TuiSession::fresh("session-1".into(), String::new());
            s.push_log("sys", "새 세션 — /setup 에서 대상을 지정하세요.".into(), LineLevel::Sys);
            s.save();
            app.session = s;
            app.scroll_off = 0;
            app.input.clear();
            app.input_cursor = 0;
        }
        app.flash(format!("'{name}' 삭제됨 — 다른 세션으로 전환했습니다."));
    } else {
        app.flash(format!("'{name}' 삭제됨."));
    }
    app.sess_list = TuiSession::list();
    app.sess_sel = app.sess_sel.min(app.sess_list.len().saturating_sub(1));
    app.popup = Popup::Sessions;
}

// ── 렌더 ─────────────────────────────────────────────────────────────────────

fn level_style(level: LineLevel) -> Style {
    match level {
        LineLevel::Info => Style::default().fg(Color::Gray),
        LineLevel::Sys => Style::default().fg(Color::Cyan),
        LineLevel::Warn => Style::default().fg(Color::Yellow),
        LineLevel::Error => Style::default().fg(Color::Red),
        LineLevel::Chat => Style::default().fg(Color::White),
        LineLevel::Agent => Style::default().fg(Color::Green),
    }
}

fn status_style(status: &str) -> Style {
    match status {
        "running" => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        "done" => Style::default().fg(Color::DarkGray),
        "error" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        "stopped" => Style::default().fg(Color::Yellow),
        _ => Style::default().fg(Color::Gray),
    }
}

fn sev_color(sev: &str) -> Color {
    match sev {
        "critical" => Color::Red,
        "high" => Color::LightRed,
        "medium" => Color::Yellow,
        "low" => Color::Cyan,
        _ => Color::Gray,
    }
}

fn tag_color(tag: &str) -> Color {
    match tag {
        "p0" => Color::Magenta,
        "agent" => Color::Green,
        "sys" => Color::Cyan,
        "you" => Color::White,
        _ => Color::Gray,
    }
}

/// 한 줄을 폭에 맞게 자르기 (CJK 폭 고려, 가능하면 단어 경계).
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    let mut out = Vec::new();
    for raw in text.split('\n') {
        let mut cur = String::new();
        let mut w = 0;
        for ch in raw.chars() {
            let cw = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(1).max(1);
            if w + cw > width && !cur.is_empty() {
                // 단어 경계로 되돌아가기 (공백이 있을 때만).
                if let Some(sp) = cur.rfind(' ') {
                    let tail: String = cur[sp + 1..].to_string();
                    out.push(cur[..sp].to_string());
                    w = tail.width();
                    cur = tail;
                } else {
                    out.push(std::mem::take(&mut cur));
                    w = 0;
                }
            }
            // 공백으로 시작하는 줄 방지.
            if cur.is_empty() && ch == ' ' {
                continue;
            }
            cur.push(ch);
            w += cw;
        }
        out.push(cur);
    }
    out
}

/// 표시 폭 기준 우측 패딩 (CJK 2칸 고려 — `{:<w>}` 는 글자 수 기준이라 틀어진다).
fn pad_width(s: &str, w: usize) -> String {
    let cur = s.width();
    if cur >= w {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(w - cur))
    }
}

/// 필드 표시 윈도우 — 커서가 항상 보이도록 가로 스크롤 (CJK 폭 고려).
/// 반환: (보이는 문자열, 윈도우 내 커서 char idx).
fn field_window(disp: &str, cursor: usize, width: usize) -> (String, usize) {
    let chars: Vec<char> = disp.chars().collect();
    let cur = cursor.min(chars.len());
    if width == 0 || chars.is_empty() {
        return (String::new(), 0);
    }
    let widths: Vec<usize> =
        chars.iter().map(|c| unicode_width::UnicodeWidthChar::width(*c).unwrap_or(1).max(1)).collect();
    let mut start = 0;
    loop {
        let mut w = 0;
        let mut end = start;
        while end < chars.len() && w + widths[end] <= width {
            w += widths[end];
            end += 1;
        }
        if cur <= end {
            return (chars[start..end].iter().collect(), cur - start);
        }
        start += 1;
    }
}

#[derive(Clone)]
struct TLine {
    tag: String,
    text: String,
    level: LineLevel,
    ts: String,
}

/// 로그+채팅을 시각순으로 병합.
fn transcript(s: &TuiSession) -> Vec<TLine> {
    let mut v: Vec<TLine> = Vec::with_capacity(s.log.len() + s.chat.len());
    for l in &s.log {
        v.push(TLine { tag: l.tag.clone(), text: l.text.clone(), level: l.level, ts: l.ts.clone() });
    }
    for c in &s.chat {
        let (tag, level) = match c.role.as_str() {
            "user" => ("you".to_string(), LineLevel::Chat),
            "system" => ("sys".to_string(), LineLevel::Sys),
            _ => ("agent".to_string(), LineLevel::Agent),
        };
        v.push(TLine { tag, text: c.content.clone(), level, ts: c.ts.clone() });
    }
    v.sort_by(|a, b| a.ts.cmp(&b.ts));
    v
}

/// 입력창 높이 (멀티라인 증가 반영) — 레이아웃과 모달 클램프가 공유한다.
fn input_height(app: &App, area: &Rect) -> u16 {
    let input_rows = composer::layout(&app.input, app.input_cursor, area.width.saturating_sub(5) as usize).lines.len();
    (input_rows as u16).clamp(1, 5.min(area.height.saturating_sub(7)).max(1)) + 2
}

/// 모달이 그려져도 되는 영역 — 입력창과 절대 겹치지 않도록 하단을 제외한다.
fn modal_rect(area: Rect, app: &App) -> Rect {
    let h = area.height.saturating_sub(input_height(app, &area));
    Rect::new(area.x, area.y, area.width, h)
}

fn render(f: &mut Frame, app: &mut App) {
    let area = f.area();
    if area.width < 24 || area.height < 8 {
        f.render_widget(Paragraph::new("터미널이 너무 작습니다 (최소 24x8)."), area);
        return;
    }
    let header_h = if area.height >= 14 { 2 } else { 1 };
    let input_h = input_height(app, &area);
    let menu_h = if app.popup == Popup::None && slash_active(app) {
        // 검색 결과 수가 바뀌어도 입력창/커서의 세로 위치는 유지한다.
        10.min(area.height.saturating_sub(header_h + input_h + 1))
    } else { 0 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_h), Constraint::Min(0), Constraint::Length(1),
            Constraint::Length(input_h), Constraint::Length(menu_h),
        ])
        .split(area);
    render_header(f, app, chunks[0]);
    render_transcript(f, app, chunks[1]);
    render_status(f, app, chunks[2]);
    render_input(f, app, chunks[3]);
    if menu_h > 0 {
        render_slash_menu(f, app, chunks[4]);
    }
    match app.popup {
        Popup::None => {}
        Popup::Help => render_help(f, app, area),
        Popup::UrlPrompt => render_url_prompt(f, app, area),
        Popup::Onboarding => render_onboarding(f, app, area),
        Popup::Setup => render_form_popup(f, app, area, true),
        Popup::Providers => render_providers(f, app, area),
        Popup::ProviderEdit => render_form_popup(f, app, area, false),
        Popup::ProviderNew => render_form_popup(f, app, area, false),
        Popup::Sessions => render_sessions(f, app, area),
        Popup::RenamePrompt => render_rename(f, app, area),
        Popup::DeleteConfirm => render_delete_confirm(f, app, area),
        Popup::Findings => render_findings(f, app, area),
        Popup::FindingDetail => render_detail(f, app, area),
        Popup::Report => render_report(f, app, area),
        Popup::ConsentStatic => render_consent(f, app, area, false),
        Popup::ConsentRisk => render_consent(f, app, area, true),
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.session;
    let safety = if s.danger_consent { " 파괴적 켬 " } else { " 파괴적 끔 " };
    let safety_style = if s.danger_consent {
        Style::default().bg(Color::Red).fg(Color::White).add_modifier(Modifier::BOLD)
    } else { Style::default().fg(Color::DarkGray) };
    // 긴 세션명/모델명 때문에 동의 상태가 화면 밖으로 밀리지 않게 고정한다.
    let top = Rect::new(area.x, area.y, area.width, 1);
    let cols = Layout::horizontal([Constraint::Min(0), Constraint::Length(safety.width() as u16)]).split(top);
    // 좌측 가용 폭을 계산해 세션명·상태가 잘리지 않게 한다.
    let left_w = cols[0].width.saturating_sub(11) as usize;
    let name = s.name.chars().take(left_w.saturating_sub(6)).collect::<String>();
    let status = s.status.clone();
    f.render_widget(Paragraph::new(Line::from(vec![
        Span::styled(" RedCell ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" / {name} "), Style::default().fg(Color::White)),
        Span::styled(format!("· {status}"), status_style(&status)),
    ])), cols[0]);
    f.render_widget(Paragraph::new(Span::styled(safety, safety_style)), cols[1]);
    if area.height > 1 {
        let second = Rect::new(area.x, area.y + 1, area.width, 1);
        // 고정 백분율 대신 최소/길이 제약으로 — 긴 URL·모델명이 잘려도 다른 칸을 밀지 않는다.
        let cols = Layout::horizontal([Constraint::Min(24), Constraint::Min(18)]).split(second);
        let target = s.target_label();
        let tmax = cols[0].width.saturating_sub(6) as usize;
        let target = if target.chars().count() > tmax {
            let cut: String = target.chars().take(tmax.saturating_sub(1)).collect();
            format!("{cut}…")
        } else { target };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" 대상 ", Style::default().fg(Color::DarkGray)),
                Span::styled(target, Style::default().fg(Color::Gray)),
            ])),
            cols[0],
        );
        let llm = if app.llm_label.is_empty() { "미설정 · /providers 연결" } else { &app.llm_label };
        let lmax = cols[1].width.saturating_sub(6) as usize;
        let llm = if llm.chars().count() > lmax {
            let cut: String = llm.chars().take(lmax.saturating_sub(1)).collect();
            format!("{cut}…")
        } else { llm.to_string() };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" AI ", Style::default().fg(Color::DarkGray)),
                Span::styled(llm, Style::default().fg(Color::Gray)),
            ])),
            cols[1],
        );
    }
}

fn render_transcript(f: &mut Frame, app: &mut App, area: Rect) {
    if app.session.chat.is_empty() && app.session.log.iter().all(|l| l.tag == "sys")
        && app.session.sweep_summary.is_empty() && !app.sweep_running && !app.agent_running {
        render_welcome(f, app, area);
        return;
    }
    let width = (area.width as usize).saturating_sub(2);
    let entries = transcript(&app.session);
    let mut lines: Vec<Line> = Vec::new();
    for e in &entries {
        let prefix = format!("[{}] ", e.tag);
        let first_w = width.saturating_sub(prefix.width());
        let wrapped = wrap_text(&e.text, first_w.max(1));
        for (i, w) in wrapped.iter().enumerate() {
            if i == 0 {
                lines.push(Line::from(vec![
                    Span::styled(prefix.clone(), Style::default().fg(tag_color(&e.tag))),
                    Span::styled(w.clone(), level_style(e.level)),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::raw(" ".repeat(prefix.width().min(width))),
                    Span::styled(w.clone(), level_style(e.level)),
                ]));
            }
        }
    }
    let h = area.height.saturating_sub(2) as usize;
    let total = lines.len();
    let max_off = total.saturating_sub(h);
    app.scroll_off = app.scroll_off.min(max_off);
    let start = total.saturating_sub(h + app.scroll_off);
    let end = (start + h).min(total);
    let view = if start < end { lines[start..end].to_vec() } else { Vec::new() };
    let hint = if app.scroll_off > 0 { format!(" ↑{} ", app.scroll_off) } else { String::new() };
    let block = Block::bordered()
        .title(format!(" 로그·대화 ({}줄){} ", total, hint))
        .border_style(Style::default().fg(Color::DarkGray));
    f.render_widget(Paragraph::new(view).block(block), area);
}

fn render_welcome(f: &mut Frame, app: &App, area: Rect) {
    let inner = area.width.saturating_sub(4) as usize;
    let mut lines = vec![
        Line::from(Span::styled("작업을 시작할 준비를 해볼까요?", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];
    let target = if app.session.host.is_empty() { "대상 URL과 세션을 설정하세요" } else { "대상 설정 확인·변경" };
    let ai = if app.llm_label.is_empty() { "AI 연결 마법사 (기본 점검은 연결 없이 가능)" } else { "AI 연결 변경·추가" };
    for (cmd, desc) in [("/setup", target), ("/providers", ai), ("/help", "사용법과 단축키 살펴보기")] {
        if area.width >= 70 {
            lines.push(Line::from(vec![
                Span::styled(pad_width(cmd, 14), Style::default().fg(Color::Cyan)),
                Span::raw(desc),
            ]));
        } else {
            lines.push(Line::from(Span::styled(cmd, Style::default().fg(Color::Cyan))));
            for text in wrap_text(desc, inner.max(1)) { lines.push(Line::from(text)); }
        }
    }
    lines.push(Line::from(""));
    if app.session.host.is_empty() {
        for text in wrap_text("Enter 빠른 시작: URL 입력 창 열기 · /setup 상세 설정", inner.max(1)) {
            lines.push(Line::from(Span::styled(text, Style::default().fg(Color::Gray))));
        }
    }
    for text in wrap_text("/ 를 입력하면 명령어가 아래에 나타납니다. /설정처럼 한국어로도 검색하세요.", inner.max(1)) {
        lines.push(Line::from(Span::styled(text, Style::default().fg(Color::Gray))));
    }
    if area.height >= 15 {
        lines.push(Line::from(""));
        for text in wrap_text("대상 설정 → /sweep 기본 점검 → /findings 결과 확인. AI를 연결하면 대화형 작업도 할 수 있습니다.", inner.max(1)) {
            lines.push(Line::from(Span::styled(text, Style::default().fg(Color::Gray))));
        }
    }
    let block = Block::bordered().title(" 시작하기 ").border_style(Style::default().fg(Color::DarkGray));
    let content = block.inner(area);
    f.render_widget(block, area);
    let content = Rect::new(content.x + 1, content.y, content.width.saturating_sub(2), content.height);
    f.render_widget(Paragraph::new(lines), content);
}

/// braille 스피너 — 경과 기반 10fps.
fn spinner(elapsed: std::time::Duration) -> char {
    const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    FRAMES[(elapsed.as_millis() / 100 % 10) as usize]
}

/// 진행 바 (너비 w, clamp).
fn progress_bar(done: usize, total: usize, w: usize) -> String {
    if total == 0 || w == 0 {
        return "░".repeat(w);
    }
    let ratio = (done as f64 / total as f64).clamp(0.0, 1.0);
    let fill = (ratio * w as f64).round() as usize;
    format!("{}{}", "█".repeat(fill.min(w)), "░".repeat(w - fill.min(w)))
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    if !app.status_msg.is_empty() {
        f.render_widget(Paragraph::new(format!(" {}", app.status_msg)).style(Style::default().fg(Color::Yellow)), area);
        return;
    }
    let mut parts: Vec<Span> = Vec::new();
    if app.sweep_running {
        let (done, total, phase) = app.sweep_fb.as_ref().map(|fb| {
            use std::sync::atomic::Ordering;
            (fb.done.load(Ordering::Relaxed), fb.total.load(Ordering::Relaxed), fb.phase_label())
        }).unwrap_or((0, 0, String::new()));
        let bar = progress_bar(done, total.max(1), 12);
        let ph = if phase.is_empty() { "준비".to_string() } else { phase };
        parts.push(Span::styled(
            format!("{} P0 {ph} {bar} {done}/{} · {}초 · Esc 중단 ", spinner(app.sweep_started.elapsed()), total.max(1), app.sweep_started.elapsed().as_secs()),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    } else if !app.session.sweep_summary.is_empty() {
        parts.push(Span::styled(format!(" P0 {}건 ", app.session.findings.len()), Style::default().fg(Color::DarkGray)));
    }
    if app.agent_running {
        parts.push(Span::styled(
            format!(" {} agent {}초 · Esc 중단 ", spinner(app.agent_started.elapsed()), app.agent_started.elapsed().as_secs()),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ));
    }
    if !app.sweep_running && !app.agent_running {
        let hint = if slash_active(app) {
            " 이름·설명 검색 · /설정, /report 처럼 입력"
        } else if app.input.starts_with('/') && app.input.contains(char::is_whitespace) {
            " 인자를 입력하고 Enter · Esc 입력 취소"
        } else if area.width < 70 {
            " / 명령어 · Ctrl+P 메뉴 · /help 도움말"
        } else {
            " / 명령어 · Ctrl+P 메뉴 · ↑↓ 이력 · Alt+Enter 줄바꿈 · Ctrl+Q 종료"
        };
        parts.push(Span::styled(hint, Style::default().fg(Color::Gray)));
    }
    f.render_widget(Paragraph::new(Line::from(parts)), area);
}

/// 입력창 아래에 공간을 예약한다. 로그나 입력을 덮지 않는다.
fn render_slash_menu(f: &mut Frame, app: &mut App, area: Rect) {
    let cands = slash_menu(app);
    let hint = if area.width >= 70 { " ↑↓ 선택 · Tab 완성 · Enter 실행 · Esc 닫기 " } else { " ↑↓ · Tab · Enter · Esc " };
    let block = Block::bordered()
        .title(if cands.is_empty() { " 검색 결과 없음 ".into() } else { format!(" 명령어 {}/{} ", app.slash_sel + 1, cands.len()) })
        .title_bottom(hint)
        .border_style(Style::default().fg(Color::Cyan));
    if cands.is_empty() {
        f.render_widget(Paragraph::new(" 검색어 변경 · /help 도움말").block(block), area);
        return;
    }
    let rows = area.height.saturating_sub(2).max(1) as usize;
    let sel = app.slash_sel.min(cands.len() - 1);
    let start = sel.saturating_sub(rows / 2).min(cands.len().saturating_sub(rows));
    let end = (start + rows).min(cands.len());
    let items: Vec<ListItem> = cands[start..end].iter().enumerate().map(|(i, c)| {
        let selected = start + i == sel;
        let label = if area.width >= 70 { slash::label(c) } else { format!("/{}", c.name) };
        let name_width = if area.width >= 70 { 22 } else { 12 };
        let line = Line::from(vec![
            Span::raw(if selected { "> " } else { "  " }),
            Span::styled(pad_width(&label, name_width), if selected { Style::default() } else { Style::default().fg(Color::Cyan) }),
            Span::raw(c.desc),
        ]);
        ListItem::new(line).style(if selected {
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else { Style::default() })
    }).collect();
    f.render_widget(List::new(items).block(block), area);
}

fn render_input(f: &mut Frame, app: &App, area: Rect) {
    let layout = composer::layout(&app.input, app.input_cursor, area.width.saturating_sub(5) as usize);
    let height = area.height.saturating_sub(2).max(1) as usize;
    let start = layout.cursor_row.saturating_sub(height - 1);
    let focused = app.popup == Popup::None;
    let mut lines = Vec::new();
    for (row, text) in layout.lines.iter().enumerate().skip(start).take(height) {
        let prompt = if row == 0 { "❯ " } else { "  " };
        let body = if app.input.is_empty() && focused {
            Span::styled("질문·지시를 입력하세요…  / 명령어", Style::default().fg(Color::Gray))
        } else { Span::raw(text.clone()) };
        lines.push(Line::from(vec![Span::styled(prompt, Style::default().fg(Color::Cyan)), body]));
    }
    let title = if area.width >= 70 { " 입력 · Enter 전송 · Alt+Enter 줄바꿈 " } else { " 입력 · Enter 전송 " };
    let mut block = Block::bordered().title(title).border_style(Style::default().fg(if focused { Color::Cyan } else { Color::DarkGray }));
    if layout.lines.len() > height {
        block = block.title_bottom(format!(" {}–{}/{}줄 ", start + 1, (start + height).min(layout.lines.len()), layout.lines.len()));
    }
    f.render_widget(Paragraph::new(lines).block(block), area);
    if focused {
        f.set_cursor_position((
            (area.x + 3 + layout.cursor_col as u16).min(area.right().saturating_sub(2)),
            area.y + 1 + (layout.cursor_row - start) as u16,
        ));
    }
}

fn render_onboarding(f: &mut Frame, app: &mut App, area: Rect) {
    let area = centered(modal_rect(area, app), 74, 78);
    f.render_widget(Clear, area);
    let inner = (area.width as usize).saturating_sub(4);
    let steps = ["환영", "프로바이더", "인증 방식", "키 입력"];
    let crumb: Vec<String> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if i as u8 == app.onboard_step {
                format!("▶{s}")
            } else if (i as u8) < app.onboard_step {
                format!("✔{s}")
            } else {
                s.to_string()
            }
        })
        .collect();
    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(crumb.join("  →  "), Style::default().fg(Color::Cyan))),
        Line::from(""),
    ];
    match app.onboard_step {
        0 => {
            lines.push(Line::from(Span::styled(
                "RedCell 초기 설정 — LLM 연결",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            for w in wrap_text("agent 실행(대화형 점검)에 필요한 LLM 프로바이더가 아직 연결되어 있지 않습니다. 마법사에서 프로바이더를 고르고 API 키 또는 OAuth 토큰을 등록하세요.", inner) {
                lines.push(Line::from(w));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("• 키는 ~/.redcell/providers.json 에 소유자 전용(600)으로 저장됩니다", Style::default().fg(Color::DarkGray))));
            lines.push(Line::from(Span::styled("• env 키(ANTHROPIC_API_KEY 등)가 있으면 저장값보다 우선합니다", Style::default().fg(Color::DarkGray))));
            lines.push(Line::from(Span::styled("• pi-agent 를 쓰면 같은 이름 자격증명을 그대로 가져올 수 있습니다", Style::default().fg(Color::DarkGray))));
        }
        1 => {
            lines.push(Line::from(Span::styled("프로바이더 선택", Style::default().add_modifier(Modifier::BOLD))));
            lines.push(Line::from(""));
            // 긴 목록은 선택행이 보이도록 윈도우 스크롤.
            let max_rows = (area.height as usize).saturating_sub(11).max(4);
            let total = app.prov_list.len();
            let sel_idx = app.onboard_prov_sel.min(total.saturating_sub(1));
            let mut start = sel_idx.saturating_sub(max_rows / 2);
            if start + max_rows > total {
                start = total.saturating_sub(max_rows);
            }
            if start > 0 {
                lines.push(Line::from(Span::styled(format!("↑ {start}개 더"), Style::default().fg(Color::DarkGray))));
            }
            for (i, p) in app.prov_list.iter().enumerate().skip(start).take(max_rows) {
                let sel = i == sel_idx;
                let (dot, dot_c) = if p.usable {
                    ("●", Color::Green)
                } else if p.connected {
                    ("◐", Color::Yellow)
                } else {
                    ("○", Color::Red)
                };
                let st = if sel { Style::default().fg(Color::Black).bg(Color::Cyan) } else { Style::default() };
                let model = if p.model.is_empty() { "(모델 지정 필요)".to_string() } else { p.model.clone() };
                lines.push(Line::from(vec![
                    Span::styled(format!("{dot} "), Style::default().fg(dot_c)),
                    Span::styled(format!("{:<16}", p.name), st),
                    Span::raw(format!(" {:<26} {}", model.chars().take(26).collect::<String>(), p.ready)),
                ]));
            }
            let rest = total.saturating_sub(start + max_rows.min(total));
            if rest > 0 {
                lines.push(Line::from(Span::styled(format!("↓ {rest}개 더"), Style::default().fg(Color::DarkGray))));
            }
        }
        2 => {
            lines.push(Line::from(vec![
                Span::styled("인증 방식", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!(" — {}", app.onboard_name)),
            ]));
            lines.push(Line::from(""));
            for (i, m) in app.onboard_methods.iter().enumerate() {
                let sel = i == app.onboard_method_sel;
                let (label, desc) = onboard_method_label(*m);
                let st = if sel { Style::default().fg(Color::Black).bg(Color::Cyan) } else { Style::default().fg(Color::White) };
                lines.push(Line::from(vec![
                    Span::styled(format!("{label:<22}"), st),
                    Span::styled(format!(" {desc}"), Style::default().fg(Color::DarkGray)),
                ]));
            }
        }
        _ => {
            lines.push(Line::from(vec![
                Span::styled("키 입력", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!(" — {} ({})", app.onboard_name, match app.onboard_methods.get(app.onboard_method_sel).copied() {
                    Some(OnboardMethod::OAuth) => "OAuth",
                    Some(OnboardMethod::PiImport) => "pi-agent 가져옴",
                    _ => "API 키",
                })),
            ]));
            lines.push(Line::from(""));
            let val_w = inner.saturating_sub(10);
            for (i, fld) in app.onboard_fields.iter().enumerate() {
                let active = i == app.onboard_field_sel;
                let mut spans = vec![Span::styled(
                    format!("{:>7} ", fld.label),
                    if active { Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::DarkGray) },
                )];
                let disp = fld.display();
                let (vis, c) = field_window(&disp, fld.cursor, val_w);
                if active {
                    let chars: Vec<char> = vis.chars().collect();
                    let cc = c.min(chars.len());
                    let (a, b): (String, String) = (chars[..cc].iter().collect(), chars[cc..].iter().collect());
                    spans.push(Span::raw(a));
                    spans.push(Span::styled("▌", Style::default().fg(Color::Cyan)));
                    spans.push(Span::raw(b));
                } else {
                    spans.push(Span::raw(vis));
                }
                lines.push(Line::from(spans));
            }
            if let Some(err) = &app.onboard_error {
                lines.push(Line::from(""));
                for w in wrap_text(err, inner) {
                    lines.push(Line::from(Span::styled(w, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))));
                }
            } else {
                lines.push(Line::from(""));
                for w in wrap_text("키는 화면에 표시되지 않습니다 · 저장 후 연결을 확인합니다(실패해도 강제 저장 가능) · Enter 다음/저장 · Esc 뒤로", inner) {
                    lines.push(Line::from(Span::styled(w, Style::default().fg(Color::DarkGray))));
                }
            }
        }
    }
    // 3단계 이외의 에러 표시 (저장 실패 등).
    if app.onboard_step != 3 {
        if let Some(err) = &app.onboard_error {
            lines.push(Line::from(""));
            for w in wrap_text(err, inner) {
                lines.push(Line::from(Span::styled(w, Style::default().fg(Color::Red))));
            }
        }
        lines.push(Line::from(""));
        let hint = match app.onboard_step {
            0 => "Enter 시작 · Esc 건너뛰기 (P0 스윕은 LLM 없이도 가능)",
            1 => "↑↓ 선택 · Enter 다음 · Esc 뒤로",
            _ => "↑↓ 선택 · Enter 다음 · Esc 뒤로",
        };
        for w in wrap_text(hint, inner) {
            lines.push(Line::from(Span::styled(w, Style::default().fg(Color::DarkGray))));
        }
    }
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" RedCell 설정 마법사 ").border_style(Style::default().fg(Color::Cyan))),
        area,
    );
}

fn render_url_prompt(f: &mut Frame, app: &mut App, area: Rect) {
    let area = centered(modal_rect(area, app), 64, 34);
    f.render_widget(Clear, area);
    let inner = (area.width as usize).saturating_sub(2);
    let fld = &app.url_field;
    let (vis, c) = field_window(&fld.value, fld.cursor, inner.saturating_sub(6));
    let chars: Vec<char> = vis.chars().collect();
    let (a, b): (String, String) = (chars[..c].iter().collect(), chars[c..].iter().collect());
    let mut lines = vec![
        Line::from(Span::styled("점검할 URL을 입력하세요", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled("URL ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(a),
            Span::styled("▌", Style::default().fg(Color::Cyan)),
            Span::raw(b),
        ]),
        Line::from(""),
    ];
    for w in wrap_text("Enter 시작(즉시 스윕→리포트) · Esc 건너뛰기 · 예: https://example.com:8443", inner) {
        lines.push(Line::from(Span::styled(w, Style::default().fg(Color::DarkGray))));
    }
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" RedCell 점검 ").border_style(Style::default().fg(Color::Cyan))),
        area,
    );
}

fn centered(area: Rect, w_pct: u16, h_pct: u16) -> Rect {
    // 좁은 창에서는 퍼센트 여백보다 폼/설명의 가독성이 먼저다.
    let width = if area.width < 85 { area.width } else { (area.width as u32 * w_pct as u32 / 100) as u16 };
    let height = if area.height < 24 { area.height } else { ((area.height as u32 * h_pct as u32 / 100) as u16).max(10).min(area.height) };
    Rect::new(area.x + (area.width - width) / 2, area.y + (area.height - height) / 2, width, height)
}

fn render_help(f: &mut Frame, app: &mut App, area: Rect) {
    let area = centered(modal_rect(area, app), 78, 86);
    f.render_widget(Clear, area);
    let mut text = vec![
        Line::from(Span::styled("키", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled("`/`", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" 명령어 메뉴 (↑↓ 선택 · Tab 완성 · Enter 실행 · Esc 닫기)"),
        ]),
        Line::from("Ctrl+P 명령어 메뉴 (작성 중인 입력은 유지) · ↑↓ 입력 이력"),
        Line::from("Enter 전송 · Alt+Enter 줄바꿈 (지원 터미널: Shift+Enter)"),
        Line::from("Ctrl+A/E 처음/끝 · Ctrl+U 앞부분 삭제 · Ctrl+W 단어 삭제"),
        Line::from("Ctrl+C 입력/작업 취소 · Ctrl+Q 종료 · PgUp/Dn 로그 스크롤"),
        Line::from("팝업: ↑↓·Tab 이동 · Enter 확정 · Ctrl+S 폼 저장 · Esc 닫기"),
        Line::from("붙여넣기는 실행되지 않습니다. 내용을 확인한 뒤 Enter로 전송하세요."),
        Line::from(""),
        Line::from(Span::styled("명령어", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];
    for c in slash::CATALOG {
        let aliases = if c.aliases.is_empty() { String::new() } else { format!(" ({})", c.aliases.join(", ")) };
        text.push(Line::from(vec![
            Span::styled(pad_width(&slash::label(c), 20), Style::default().fg(Color::Cyan)),
            Span::styled(aliases, Style::default().fg(Color::DarkGray)),
            Span::raw(format!(" {}", c.desc)),
        ]));
    }
    text.extend([
        Line::from(""),
        Line::from(Span::styled("흐름", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("1. /setup 대상 설정 → /sweep 기본 점검 → /findings 결과 확인"),
        Line::from("2. AI가 필요하면 /providers 연결 (미설정 시 마법사 · 언제든 건너뛰기 가능)"),
        Line::from("3. 리포트를 닫으면 입력창에서 대화형 추가 점검 (지시 → agent 실행)"),
        Line::from("4. `/providers` — LLM 연결 (●사용가능 ◐보완필요 ○미연결 · u 사용 · e 키 입력)"),
        Line::from("5. `/setup` 대상·쿠키 설정 / `/sweep` 재스윕 / `/stop` 중지"),
        Line::from("6. `/sessions` — 세션 전환·생성·이름변경·삭제 한 곳에서"),
        Line::from("7. 파괴적 지시/프로브는 동의 모달 확인 후 (`/danger` 철회)"),
    ]);
    let text: Vec<Line> = text.into_iter().flat_map(|line| {
        wrap_text(&line.to_string(), area.width.saturating_sub(2).max(1) as usize)
            .into_iter().map(Line::from).collect::<Vec<_>>()
    }).collect();
    let total = text.len();
    let h = (area.height as usize).saturating_sub(2);
    app.help_scroll = app.help_scroll.min(total.saturating_sub(h));
    let view = text[app.help_scroll..(app.help_scroll + h).min(total)].to_vec();
    f.render_widget(Paragraph::new(view).block(Block::bordered().title(" 도움말 (Esc 닫기 · ↑↓ 스크롤) ")), area);
}

fn render_form_popup(f: &mut Frame, app: &mut App, area: Rect, setup: bool) {
    let area = centered(modal_rect(area, app), 70, if setup { 62 } else { 70 });
    f.render_widget(Clear, area);
    let (title, fields, sel) = if setup {
        (" 대상 설정 (Tab 이동 · Enter 다음/저장 · Esc 취소) ", &app.setup_fields, app.setup_sel)
    } else if app.popup == Popup::ProviderNew {
        (" 프로바이더 추가 (Tab 이동 · Enter 다음/저장 · Esc 취소) ", &app.prov_fields, app.prov_sel_field)
    } else {
        (" 프로바이더 편집 (Tab 이동 · Enter 다음/저장 · Esc 취소) ", &app.prov_fields, app.prov_sel_field)
    };
    let mut lines: Vec<Line> = Vec::new();
    let val_w = (area.width as usize).saturating_sub(14);
    for (i, fld) in fields.iter().enumerate() {
        let active = i == sel;
        let mut spans = vec![
            Span::styled(format!("{}{} ", " ".repeat(8usize.saturating_sub(fld.label.width())), fld.label), if active { Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Gray) }),
        ];
        let disp = fld.display();
        // 가로 스크롤 윈도우 (긴 값 CJK 클리핑 방지).
        let (vis, c) = field_window(&disp, fld.cursor, val_w);
        let chars: Vec<char> = vis.chars().collect();
        let (a, b): (String, String) = (chars[..c.min(chars.len())].iter().collect(), chars[c.min(chars.len())..].iter().collect());
        if active {
            spans.push(Span::raw(a));
            spans.push(Span::styled("▌", Style::default().fg(Color::Cyan)));
            spans.push(Span::raw(b));
            if fld.cycle.is_some() {
                spans.push(Span::styled("  ←→ 선택", Style::default().fg(Color::Gray)));
            }
        } else {
            spans.push(Span::raw(vis));
            let _ = (a, b);
        }
        lines.push(Line::from(spans));
    }
    let hint_w = (area.width as usize).saturating_sub(4);
    let mut hints: Vec<String> = Vec::new();
    if !setup {
        if let Some(name) = &app.prov_edit_name {
            if let Some(n) = providers::BUILTINS.iter().find(|b| b.name == name).and_then(|b| b.note) {
                hints.push(format!("참고: {n}"));
            }
        }
        hints.push("key 비우면 기존 유지(=auth 유지) · auth: api_key/OAuth · baseUrl 은 openai-compat 필수 · * = 사용자 정의".into());
    } else {
        hints.push("provider 빈칸 = redcell 기본값 사용 · cookie = 인증 스윕용".into());
    }
    lines.push(Line::from(""));
    for h in hints {
        for w in wrap_text(&h, hint_w.max(20)) {
            lines.push(Line::from(Span::styled(w, Style::default().fg(Color::DarkGray))));
        }
    }
    let height = area.height.saturating_sub(2).max(1) as usize;
    let offset = sel.saturating_sub(height.saturating_sub(1));
    let block = Block::bordered().title(title)
        .title_bottom(" Ctrl+S 저장 · Tab 이동 · Esc 취소 ")
        .border_style(Style::default().fg(Color::Cyan));
    f.render_widget(Paragraph::new(lines).scroll((offset as u16, 0)).block(block), area);
}

fn render_providers(f: &mut Frame, app: &mut App, area: Rect) {
    let area = centered(modal_rect(area, app), 82, 82);
    f.render_widget(Clear, area);
    let mut items: Vec<ListItem> = Vec::new();
    for (i, p) in app.prov_list.iter().enumerate() {
        let (dot, dot_c) = if p.usable {
            ("●", Color::Green)
        } else if p.connected {
            ("◐", Color::Yellow) // 연결됐으나 모델/baseUrl 부족
        } else {
            ("○", Color::Red)
        };
        let name_style = if i == app.prov_sel { Style::default().fg(Color::Black).bg(Color::Cyan) } else { Style::default().fg(Color::White) };
        let model = if p.model.is_empty() { "-".to_string() } else { p.model.clone() };
        let mark = if p.custom { "*" } else { " " };
        items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("{dot} "), Style::default().fg(dot_c)),
            Span::styled(format!("{:<16}", p.name), name_style),
            Span::raw(format!("{mark} {:<13} {:<28} {}", p.kind, model.chars().take(28).collect::<String>(), p.ready)),
        ])));
    }
    if items.is_empty() {
        items.push(ListItem::new("프로바이더 없음 — n 으로 추가"));
    }
    let mut state = ListState::default();
    state.select(Some(app.prov_sel.min(items.len().saturating_sub(1))));
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(4)])
        .split(area);
    f.render_stateful_widget(
        List::new(items).block(Block::bordered().title(" LLM 연결 ")),
        rows[0],
        &mut state,
    );
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled("● 사용가능 · ◐ 연결됐으나 모델/baseUrl 보완 필요 · ○ 미연결", Style::default().fg(Color::DarkGray))),
            Line::from(Span::styled("Enter/e 편집 · n 추가 · d 삭제 · u 사용 · r 새로고침 · Esc 닫기", Style::default().fg(Color::DarkGray))),
        ])
        .block(Block::bordered()),
        rows[1],
    );
}

fn render_sessions(f: &mut Frame, app: &mut App, area: Rect) {
    let area = centered(modal_rect(area, app), 72, 70);
    f.render_widget(Clear, area);
    let mut items: Vec<ListItem> = Vec::new();
    for (i, (id, name, target, updated)) in app.sess_list.iter().enumerate() {
        let cur_mark = if id == &app.session.id { "▶" } else { " " };
        let style = if i == app.sess_sel { Style::default().fg(Color::Black).bg(Color::Cyan) } else { Style::default() };
        items.push(ListItem::new(Line::from(vec![
            Span::raw(format!("{cur_mark} ")),
            Span::styled(format!("{name:<16}"), style),
            Span::styled(format!(" {target:<28} "), Style::default().fg(Color::Yellow)),
            Span::styled(updated.chars().take(19).collect::<String>(), Style::default().fg(Color::DarkGray)),
        ])));
    }
    if items.is_empty() {
        items.push(ListItem::new("세션 없음 — n 으로 생성"));
    }
    let mut state = ListState::default();
    state.select(Some(app.sess_sel.min(items.len().saturating_sub(1))));
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(4)])
        .split(area);
    f.render_stateful_widget(List::new(items).block(Block::bordered().title(" 세션 ")), rows[0], &mut state);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled("▶현재 · Enter 전환 · n 생성 · r 이름변경 · d 삭제 · Esc 닫기", Style::default().fg(Color::DarkGray))),
            Line::from(Span::styled("삭제는 확인 후 · 현재 삭제 시 다른 세션으로 자동 전환", Style::default().fg(Color::DarkGray))),
        ])
        .block(Block::bordered()),
        rows[1],
    );
}

fn render_rename(f: &mut Frame, app: &mut App, area: Rect) {
    let area = centered(modal_rect(area, app), 60, 26);
    f.render_widget(Clear, area);
    let inner = (area.width as usize).saturating_sub(2);
    let fld = &app.rename_field;
    let (vis, c) = field_window(&fld.value, fld.cursor, inner.saturating_sub(6));
    let chars: Vec<char> = vis.chars().collect();
    let cc = c.min(chars.len());
    let (a, b): (String, String) = (chars[..cc].iter().collect(), chars[cc..].iter().collect());
    f.render_widget(
        Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("이름 ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(a),
                Span::styled("▌", Style::default().fg(Color::Cyan)),
                Span::raw(b),
            ]),
            Line::from(""),
            Line::from(Span::styled("Enter 저장 · Esc 취소", Style::default().fg(Color::DarkGray))),
        ])
        .block(Block::bordered().title(" 세션 이름 변경 ").border_style(Style::default().fg(Color::Cyan))),
        area,
    );
}

fn render_delete_confirm(f: &mut Frame, app: &mut App, area: Rect) {
    let area = centered(modal_rect(area, app), 60, 30);
    f.render_widget(Clear, area);
    let inner = (area.width as usize).saturating_sub(4);
    let (is_cur, name) = match &app.delete_target {
        Some((id, name)) => (id == &app.session.id, name.clone()),
        None => (false, String::new()),
    };
    let mut lines = vec![Line::from(Span::styled(
        format!("'{name}' 세션을 삭제할까요?"),
        Style::default().add_modifier(Modifier::BOLD),
    ))];
    if is_cur {
        for w in wrap_text("현재 사용 중인 세션입니다. 삭제하면 다른 세션으로 자동 전환됩니다.", inner) {
            lines.push(Line::from(Span::styled(w, Style::default().fg(Color::Yellow))));
        }
    } else {
        lines.push(Line::from(Span::styled("대화·로그·발견 기록이 함께 지워집니다.", Style::default().fg(Color::Gray))));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" 삭제 (y) ", Style::default().bg(Color::Red).fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled(" 취소 (n) ", Style::default().bg(Color::White).fg(Color::Black).add_modifier(Modifier::BOLD)),
    ]));
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" 세션 삭제 확인 ").border_style(Style::default().fg(Color::Red))),
        area,
    );
}

fn render_findings(f: &mut Frame, app: &mut App, area: Rect) {
    let area = centered(modal_rect(area, app), 86, 84);
    f.render_widget(Clear, area);
    let mut items: Vec<ListItem> = Vec::new();
    for (i, h) in app.session.findings.iter().enumerate() {
        let sel = i == app.findings_sel;
        let bg = if sel { Style::default().bg(Color::Cyan).fg(Color::Black) } else { Style::default() };
        items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("[{}] ", h.id), Style::default().fg(Color::DarkGray).patch(bg)),
            Span::styled(format!("[{:<8}] ", h.severity), Style::default().fg(sev_color(&h.severity)).patch(bg)),
            Span::styled(format!("{:<14} ", h.category), Style::default().fg(Color::Magenta).patch(bg)),
            Span::styled(h.title.chars().take(60).collect::<String>(), bg),
        ])));
    }
    if items.is_empty() {
        items.push(ListItem::new(if app.session.sweep_summary.is_empty() {
            "아직 스윕 없음 — `/sweep` 으로 P0 스윕 실행"
        } else {
            "발견 없음 (클린)"
        }));
    }
    let mut state = ListState::default();
    state.select(Some(app.findings_sel.min(items.len().saturating_sub(1))));
    // 심각도별 건수 — 옛 /report 요약의 핵심을 제목에 흡수한다.
    let mut counts = String::new();
    for sev in ["critical", "high", "medium", "low", "info"] {
        let n = app.session.findings.iter().filter(|h| h.severity == sev).count();
        if n > 0 {
            counts.push_str(&format!(" · {sev} {n}"));
        }
    }
    f.render_stateful_widget(
        List::new(items).block(Block::bordered().title(format!(
            " Findings ({}건{counts} · Enter 상세 · Esc 닫기) ",
            app.session.findings.len()
        ))),
        area,
        &mut state,
    );
}

fn render_detail(f: &mut Frame, app: &mut App, area: Rect) {
    let area = centered(modal_rect(area, app), 82, 80);
    f.render_widget(Clear, area);
    let width = (area.width as usize).saturating_sub(4);
    let mut text: Vec<Line> = Vec::new();
    if let Some(h) = app.session.findings.get(app.detail_idx) {
        text.push(Line::from(vec![
            Span::styled(format!("[{}] ", h.id), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("[{}] ", h.severity), Style::default().fg(sev_color(&h.severity)).add_modifier(Modifier::BOLD)),
            Span::styled(h.category.clone(), Style::default().fg(Color::Magenta)),
        ]));
        text.push(Line::from(Span::styled(h.title.clone(), Style::default().add_modifier(Modifier::BOLD))));
        text.push(Line::from(""));
        for (label, body) in [("대상", h.target.as_str()), ("상세", h.detail.as_str()), ("증거", h.evidence.as_str()), ("요청", h.request.as_str())] {
            if body.is_empty() {
                continue;
            }
            text.push(Line::from(Span::styled(label, Style::default().fg(Color::Cyan))));
            for w in wrap_text(body, width) {
                text.push(Line::from(w));
            }
            text.push(Line::from(""));
        }
    } else {
        text.push(Line::from("발견 없음"));
    }
    let h = (area.height as usize).saturating_sub(2);
    app.finding_scroll = app.finding_scroll.min(text.len().saturating_sub(h));
    let view = text[app.finding_scroll..(app.finding_scroll + h).min(text.len())].to_vec();
    f.render_widget(Paragraph::new(view).block(Block::bordered().title(" 발견 상세 (Esc 목록) ")), area);
}

fn report_text(s: &TuiSession) -> Vec<Line<'_>> {
    let mut text: Vec<Line> = Vec::new();
    if s.sweep_summary.is_empty() {
        text.push(Line::from("아직 스윕 없음 — `/sweep` 으로 P0 스윕 실행"));
        return text;
    }
    text.push(Line::from(Span::styled(format!("대상: {}", s.target_label()), Style::default().add_modifier(Modifier::BOLD))));
    text.push(Line::from(Span::raw(s.sweep_summary.clone())));
    text.push(Line::from(""));
    for sev in ["critical", "high", "medium", "low", "info"] {
        let group: Vec<&ProbeHit> = s.findings.iter().filter(|h| h.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        text.push(Line::from(vec![
            Span::styled(format!("■ {sev} ({}건)", group.len()), Style::default().fg(sev_color(sev)).add_modifier(Modifier::BOLD)),
        ]));
        for h in group {
            text.push(Line::from(vec![
                Span::styled(format!("  [{}] ", h.id), Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{} — {}", h.title, h.target)),
            ]));
            if !h.evidence.is_empty() {
                text.push(Line::from(Span::styled(
                    format!("      증거: {}", h.evidence.chars().take(160).collect::<String>()),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
        text.push(Line::from(""));
    }
    text
}

fn render_report(f: &mut Frame, app: &mut App, area: Rect) {
    let area = centered(modal_rect(area, app), 84, 84);
    f.render_widget(Clear, area);
    let text = report_text(&app.session);
    let h = (area.height as usize).saturating_sub(2);
    app.report_scroll = app.report_scroll.min(text.len().saturating_sub(h));
    let view = text[app.report_scroll..(app.report_scroll + h).min(text.len())].to_vec();
    f.render_widget(Paragraph::new(view).block(Block::bordered().title(" 스윕 리포트 (Esc 닫기) ")), area);
}

fn render_consent(f: &mut Frame, app: &mut App, area: Rect, dynamic: bool) {
    let area = centered(modal_rect(area, app), 74, if dynamic { 82 } else { 72 });
    f.render_widget(Clear, area);
    let inner = (area.width as usize).saturating_sub(2).max(20);
    // 머리·꼬리는 고정, 가운데(근거 목록)만 스크롤 — 버튼이 절대 잘리지 않는다.
    let mut head: Vec<Line> = vec![
        Line::from(Span::styled(format!("대상: {}", app.session.target_label()), Style::default().fg(Color::Yellow))),
        Line::from(""),
    ];
    let mut middle: Vec<Line> = Vec::new();
    let mut tail: Vec<Line> = Vec::new();
    if !dynamic {
        head.push(Line::from("아래 프로브는 대상에 실제 영향을 줄 수 있어 기본적으로 꺼져 있습니다."));
        head.push(Line::from("동의하면 이 세션의 다음 진단부터 실행됩니다."));
        head.push(Line::from(""));
        for (t, r) in [
            ("기본자격 대입", "초기 자격 5종 로그인 시도 · 위험: 계정 잠금·로그 흔적"),
            ("IDOR 인접 확인", "본인 세션 인접 번호 조회 · 위험: 타인 데이터 수신(마스킹 저장)"),
            ("쓰기 검증", "무해 마커 1건 생성 후 삭제 · 위험: 잔여 파일 가능"),
        ] {
            middle.push(Line::from(vec![
                Span::styled(format!("• {t}"), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            ]));
            for w in wrap_text(&format!("  {r}"), inner) {
                middle.push(Line::from(Span::styled(w, Style::default().fg(Color::Gray))));
            }
        }
    } else if let Some(r) = &app.pending_risk {
        head.push(Line::from(vec![
            Span::styled(
                format!(" {} ", r.level_ko),
                if r.level == engine::risk::RiskLevel::Critical {
                    Style::default().bg(Color::Red).fg(Color::White).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().bg(Color::Yellow).fg(Color::Black).add_modifier(Modifier::BOLD)
                },
            ),
            Span::raw(format!(" {}", r.summary)),
        ]));
        head.push(Line::from(""));
        let mut flags: Vec<Span> = Vec::new();
        flags.push(flag_span("서비스 중단 가능", "서비스 중단 없음", r.shutdown_risk));
        flags.push(Span::raw(" "));
        flags.push(flag_span("데이터 손실 가능", "데이터 손실 없음", r.data_loss_risk));
        flags.push(Span::raw(" "));
        flags.push(flag_span("되돌릴 수 없음", "복구 가능", r.irreversible));
        head.push(Line::from(flags));
        head.push(Line::from(""));
        for c in r.concerns.iter().take(6) {
            for (i, w) in wrap_text(&format!("• {} — {}", c.title, c.impact), inner).iter().enumerate() {
                let span = if i == 0 {
                    Span::styled(w.clone(), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                } else {
                    Span::styled(w.clone(), Style::default().fg(Color::Red))
                };
                middle.push(Line::from(span));
            }
            for w in wrap_text(&format!("  근거: {} · {}", c.matched, if c.reversible { "복구 가능" } else { "비가역" }), inner) {
                middle.push(Line::from(Span::styled(w, Style::default().fg(Color::DarkGray))));
            }
        }
        // 설명문은 근거 뒤(스크롤 영역)로 — 꼬리는 질문·버튼만 남긴다.
        middle.push(Line::from(""));
        for w in wrap_text("동의하면 이 지시를 실행하고, 이 세션의 파괴적 진단이 함께 활성화됩니다.", inner) {
            middle.push(Line::from(Span::styled(w, Style::default().fg(Color::DarkGray))));
        }
    }
    tail.push(Line::from(""));
    for w in wrap_text("대상에 대한 명시적 진단 인가를 보유하고 있으며, 위 위험을 이해하고 동의합니까?", inner) {
        tail.push(Line::from(Span::styled(w, Style::default().add_modifier(Modifier::BOLD))));
    }
    tail.push(Line::from(""));
    let (ys, ns) = if app.consent_choice == ConsentChoice::Yes {
        (Style::default().bg(Color::Red).fg(Color::White).add_modifier(Modifier::BOLD), Style::default().fg(Color::DarkGray))
    } else {
        (Style::default().fg(Color::DarkGray), Style::default().bg(Color::White).fg(Color::Black).add_modifier(Modifier::BOLD))
    };
    // 좁은 화면에서는 버튼을 세로로 쌓는다 (가로 잘림 방지).
    if inner >= 30 {
        tail.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(" 동의하고 진행 (y) ", ys),
            Span::raw("   "),
            Span::styled(" 취소 (n) ", ns),
        ]));
    } else {
        tail.push(Line::from(vec![Span::raw("  "), Span::styled(" 동의하고 진행 (y) ", ys)]));
        tail.push(Line::from(vec![Span::raw("  "), Span::styled(" 취소 (n) ", ns)]));
    }
    // 가운데 윈도우 — 잘리면 ↑↓ 표시로 대체 (행 수 유지).
    let content_h = (area.height as usize).saturating_sub(2);
    // 극단적으로 짧으면 꼬리(질문·버튼)부터 확정하고 머리를 맞춘다.
    while tail.len() > content_h {
        if let Some(i) = tail.iter().position(|l| l.width() == 0) {
            tail.remove(i); // 빈줄 먼저
        } else {
            break;
        }
    }
    if tail.len() > content_h {
        let skip = tail.len() - content_h;
        tail.drain(..skip); // 뒤(버튼) 유지
    }
    // 머리: 빈줄부터 버리고, 그래도 근거 자리가 없으면 대상 외부터 버린다.
    if head.len() + tail.len() >= content_h {
        head.retain(|l| l.width() > 0);
    }
    while head.len() + tail.len() >= content_h {
        if let Some(i) = tail.iter().position(|l| l.width() == 0) {
            tail.remove(i);
        } else if head.len() > 1 {
            head.remove(1); // 대상(0번) 유지
        } else {
            break;
        }
    }
    if head.len() + tail.len() > content_h {
        // 근거 자리도 없을 만큼 극단적이면 머리를 포기하고 꼬리만 살린다.
        head.clear();
    }
    let mid_avail = content_h.saturating_sub(head.len() + tail.len());
    if mid_avail == 0 && !middle.is_empty() && !tail.is_empty() {
        // 근거를 한 줄도 못 보여주면 첫 빈줄에 안내를 끼운다 (버튼은 유지).
        tail[0] = Line::from(Span::styled(
            format!("↓ 근거 {}줄 생략 — 터미널을 키워 확인", middle.len()),
            Style::default().fg(Color::DarkGray),
        ));
    }
    app.consent_scroll = app.consent_scroll.min(middle.len().saturating_sub(mid_avail));
    let start = app.consent_scroll.min(middle.len());
    let end = (start + mid_avail).min(middle.len());
    let mut shown: Vec<Line> = middle[start..end].to_vec();
    if start > 0 && !shown.is_empty() {
        shown[0] = Line::from(Span::styled(format!("↑ 위 {start}줄 (↑ 스크롤)"), Style::default().fg(Color::DarkGray)));
    }
    if end < middle.len() && !shown.is_empty() {
        let n = middle.len() - end;
        let last = shown.len() - 1;
        shown[last] = Line::from(Span::styled(format!("↓ 아래 {n}줄 (↓ 스크롤)"), Style::default().fg(Color::DarkGray)));
    }
    let mut lines = head;
    lines.extend(shown);
    lines.extend(tail);
    let scrolled = if middle.len() > mid_avail { " · ↑↓ 스크롤" } else { "" };
    let title = if dynamic {
        format!(" 파괴적 지시 확인 (Tab 선택 · Enter 확정 · Esc 취소{scrolled}) ")
    } else {
        format!(" 파괴적 진단 동의 (Tab 선택 · Enter 확정 · Esc 취소{scrolled}) ")
    };
    f.render_widget(Paragraph::new(lines).block(Block::bordered().title(title).border_style(Style::default().fg(Color::Red))), area);
}

fn flag_span(on_label: &str, off_label: &str, on: bool) -> Span<'static> {
    if on {
        Span::styled(
            format!(" {on_label} "),
            Style::default().bg(Color::Red).fg(Color::White).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(format!(" {off_label} "), Style::default().fg(Color::DarkGray))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn wrap_cjk_width() {
        // 한글 2칸 — 폭 5에 2자씩.
        assert_eq!(wrap_text("가나다라마", 5), vec!["가나".to_string(), "다라".to_string(), "마".to_string()]);
        assert_eq!(wrap_text("ab\nc", 10), vec!["ab".to_string(), "c".to_string()]);
        assert_eq!(wrap_text("", 10), vec![String::new()]);
        // 단어 경계 우선 — URL 은 통째로 다음 줄.
        assert_eq!(wrap_text("예: https://example.com/a", 12), vec!["예:".to_string(), "https://exam".to_string(), "ple.com/a".to_string()]);
    }

    #[test]
    fn target_split_shapes() {
        assert_eq!(split_target("https://example.com:8443/x"), ("example.com".into(), Some(8443)));
        assert_eq!(split_target("http://h/"), ("h".into(), None));
        assert_eq!(split_target("h:1"), ("h".into(), Some(1)));
        assert_eq!(split_target("[::1]:8080"), ("::1".into(), Some(8080)));
        assert_eq!(split_target("bare"), ("bare".into(), None));
        assert_eq!(split_target(""), (String::new(), None));
    }

    #[test]
    fn ansi_stripped() {
        assert_eq!(strip_ansi("\u{1b}[32mok\u{1b}[0m"), "ok");
        assert_eq!(strip_ansi("a\u{1b}[1;33mb\u{1b}[0mc"), "abc");
        assert_eq!(strip_ansi("plain"), "plain");
    }

    #[test]
    fn transcript_merges_by_time() {
        let mut s = TuiSession::fresh("t".into(), "h".into());
        s.chat.push(session::ChatMsg { role: "user".into(), content: "hi".into(), ts: "2026-01-01T00:00:01Z".into() });
        s.log.push(session::LogLine { ts: "2026-01-01T00:00:02Z".into(), tag: "sys".into(), text: "ack".into(), level: LineLevel::Sys });
        let t = transcript(&s);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].tag, "you");
        assert_eq!(t[1].tag, "sys");
    }

    #[test]
    fn task_sweep_done_stores_findings() {
        let _g = ENV_LOCK.lock().unwrap();
        // 격리 저장소.
        let tmp = std::env::temp_dir().join(format!("rc-tui-test-{}", std::process::id()));
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let mut app = App::boot();
        app.sweep_gen = app.sweep_gen.wrapping_add(1);
        let sgen = app.sweep_gen;
        app.sweep_running = true;
        on_task_msg(
            &mut app,
            TaskMsg::SweepDone { sweep_gen: sgen, summary: "S".into(), hits: vec![], secs: 1 },
        );
        assert!(!app.sweep_running);
        assert_eq!(app.session.sweep_summary, "S");
        // 중단 후 결과는 무시.
        app.sweep_gen = app.sweep_gen.wrapping_add(1); // stop_agent 가 세대를 올린다
        on_task_msg(&mut app, TaskMsg::SweepDone { sweep_gen: sgen, summary: "STALE".into(), hits: vec![], secs: 1 });
        assert_eq!(app.session.sweep_summary, "S");
        // 세대 불일치(늦게 도착한 옛 스윕) 결과도 무시.
        app.sweep_running = true;
        app.sweep_gen = app.sweep_gen.wrapping_add(1);
        on_task_msg(&mut app, TaskMsg::SweepDone { sweep_gen: sgen, summary: "RACE".into(), hits: vec![], secs: 1 });
        assert_eq!(app.session.sweep_summary, "S");
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn target_map_built_from_findings() {
        let hits = vec![
            ProbeHit {
                id: "P-001".into(),
                category: "paths".into(),
                severity: "high".into(),
                target: "http://h:8080/api/search?q=1".into(),
                title: "노출".into(),
                detail: String::new(),
                evidence: String::new(),
                request: String::new(),
                status: Some(200),
            },
            ProbeHit {
                id: "P-002".into(),
                category: "xss".into(),
                severity: "medium".into(),
                target: "http://h:8080/?name=rc7xp00".into(),
                title: "반사".into(),
                detail: String::new(),
                evidence: String::new(),
                request: String::new(),
                status: Some(200),
            },
            ProbeHit {
                id: "P-003".into(),
                category: "idor".into(),
                severity: "high".into(),
                target: "http://h:8080/api/orders/42".into(),
                title: "인접".into(),
                detail: String::new(),
                evidence: String::new(),
                request: String::new(),
                status: Some(200),
            },
        ];
        let map = build_target_map(&hits).expect("target map");
        assert!(map["paths"].as_array().unwrap().iter().any(|p| p == "/api/search"));
        assert!(map["paths"].as_array().unwrap().iter().any(|p| p == "/api/orders/42"));
        assert!(map["params"].as_array().unwrap().iter().any(|p| p == "q"));
        assert!(map["params"].as_array().unwrap().iter().any(|p| p == "name"));
        assert_eq!(map["idPath"], "/api/orders/42");
        // 발견 없으면 None.
        assert!(build_target_map(&[]).is_none());
    }

    #[test]
    fn goal_enriched_with_top_findings() {
        let mk = |sev: &str, title: &str| ProbeHit {
            id: "P-001".into(),
            category: "paths".into(),
            severity: sev.into(),
            target: "http://h/.env".into(),
            title: title.into(),
            detail: String::new(),
            evidence: String::new(),
            request: String::new(),
            status: Some(200),
        };
        let hits = vec![mk("high", "비밀 파일 노출"), mk("info", "공개 정보 파일")];
        let g = enrich_goal("취약점 찾기", &hits);
        assert!(g.starts_with("취약점 찾기"));
        assert!(g.contains("비밀 파일 노출"));
        assert!(!g.contains("공개 정보 파일")); // info 는 제외
        assert_eq!(enrich_goal("취약점 찾기", &[]), "취약점 찾기");
    }

    #[test]
    fn osc_escapes_stripped() {
        assert_eq!(strip_ansi("\u{1b}]0;title\u{7}body"), "body");
        assert_eq!(strip_ansi("\u{1b}]8;;http://x\u{1b}\\link\u{1b}]8;;\u{1b}\\!"), "link!");
    }

    /// 프로바이더 env 격리 — 저장된 값 반환(복원용).
    fn scrub_provider_env() -> Vec<(String, Option<String>)> {
        let mut keys: Vec<String> =
            providers::BUILTINS.iter().flat_map(|b| b.env_keys.iter().map(|s| s.to_string())).collect();
        keys.extend(["REDCELL_OPENAI_BASE_URL", "REDCELL_MODEL", "REDCELL_HOME"].iter().map(|s| s.to_string()));
        let mut saved = Vec::new();
        for k in keys {
            saved.push((k.clone(), std::env::var(&k).ok()));
            unsafe { std::env::remove_var(&k) };
        }
        saved
    }

    fn restore_provider_env(saved: Vec<(String, Option<String>)>) {
        for (k, v) in saved {
            match v {
                Some(val) => unsafe { std::env::set_var(&k, val) },
                None => unsafe { std::env::remove_var(&k) },
            }
        }
    }

    /// 격리 REDCELL_HOME 에 사용 가능한 프로바이더 하나를 스테이징.
    fn stage_usable_provider(home: &std::path::Path) {
        unsafe { std::env::set_var("REDCELL_HOME", home) };
        providers::upsert_custom(providers::CustomSpec {
            name: "groq".into(),
            kind: "openai-compat".into(),
            base_url: Some("https://api.groq.com/openai/v1".into()),
            env_keys: vec![],
            api_key: Some("test-key".into()),
            auth_type: Some("api_key".into()),
            default_model: Some("openai/gpt-oss-120b".into()),
            note: None,
        })
        .unwrap();
    }

    #[test]
    fn boot_is_nonblocking_without_provider() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("rc-tui-boot-{}-ob", std::process::id()));
        let home = tmp.join("redcell-home");
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let saved = scrub_provider_env();
        unsafe { std::env::set_var("REDCELL_HOME", &home) };
        let app = App::boot();
        assert_eq!(app.popup, Popup::None);
        assert!(app.llm_label.is_empty());
        assert_eq!(app.onboard_step, 0);
        assert!(app.session.host.is_empty());
        restore_provider_env(saved);
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn boot_is_nonblocking_without_target() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("rc-tui-boot-{}", std::process::id()));
        let home = tmp.join("redcell-home");
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let saved = scrub_provider_env();
        stage_usable_provider(&home);
        let app = App::boot();
        assert_eq!(app.popup, Popup::None);
        assert!(app.session.host.is_empty());
        restore_provider_env(saved);
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn boot_skips_url_prompt_with_target() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("rc-tui-boot2-{}", std::process::id()));
        let home = tmp.join("redcell-home");
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let saved = scrub_provider_env();
        stage_usable_provider(&home);
        let s = TuiSession::fresh("t".into(), "example.com".into());
        s.save();
        let app = App::boot();
        assert_eq!(app.popup, Popup::None);
        assert_eq!(app.session.host, "example.com");
        restore_provider_env(saved);
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn onboarding_steps_advance_and_skip() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("rc-tui-ob-{}", std::process::id()));
        let home = tmp.join("redcell-home");
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let saved = scrub_provider_env();
        unsafe { std::env::set_var("REDCELL_HOME", &home) };
        let mut app = App::boot();
        open_onboarding(&mut app);
        assert_eq!(app.popup, Popup::Onboarding);
        // 환영 → Enter → 프로바이더.
        on_key_onboarding(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
        assert_eq!(app.onboard_step, 1);
        // 프로바이더 확정 → 인증 방식 (groq 선택).
        app.onboard_prov_sel = app.prov_list.iter().position(|p| p.name == "groq").unwrap();
        on_key_onboarding(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
        assert_eq!(app.onboard_step, 2);
        assert_eq!(app.onboard_name, "groq");
        assert!(app.onboard_methods.contains(&OnboardMethod::ApiKey));
        assert!(app.onboard_methods.contains(&OnboardMethod::OAuth));
        // 방식 확정 → 키 폼 (모델 기본값 채워짐).
        on_key_onboarding(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
        assert_eq!(app.onboard_step, 3);
        assert_eq!(app.onboard_fields.len(), 2);
        assert_eq!(app.onboard_fields[1].value, "openai/gpt-oss-120b");
        // 빈 키 저장 → 에러 (네트워크 호출 없음).
        app.onboard_field_sel = 1;
        on_key_onboarding(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
        assert!(app.onboard_error.as_deref().unwrap_or("").contains("키를 입력"));
        assert_eq!(app.onboard_step, 3);
        // Esc 로 뒤로 → 환영에서 Esc 면 건너뛰고 메인으로.
        on_key_onboarding(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
        assert_eq!(app.onboard_step, 2);
        on_key_onboarding(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
        assert_eq!(app.onboard_step, 1);
        on_key_onboarding(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
        assert_eq!(app.onboard_step, 0);
        on_key_onboarding(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
        assert_eq!(app.popup, Popup::None);
        restore_provider_env(saved);
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn apply_url_parses_and_saves() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("rc-tui-url-{}", std::process::id()));
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let mut app = App::boot();
        assert!(apply_url(&mut app, "https://example.com:8443/path"));
        assert_eq!(app.session.host, "example.com");
        assert_eq!(app.session.port, Some(8443));
        assert!(!apply_url(&mut app, "   "));
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn field_window_keeps_cursor_visible() {
        // 짧으면 전체.
        assert_eq!(field_window("abc", 3, 10), ("abc".to_string(), 3));
        // 길면 커서 포함 윈도우 (CJK 폭 포함).
        let (vis, c) = field_window("https://예시.com/긴경로", 20, 10);
        assert!(vis.width() <= 10, "{vis}");
        let chars: Vec<char> = vis.chars().collect();
        assert_eq!(c, chars.len()); // 커서가 맨 끝 → 윈도우 끝
        let (vis2, c2) = field_window("abcdef", 1, 3);
        assert_eq!((vis2.as_str(), c2), ("abc", 1));
    }

    #[test]
    fn pad_width_counts_cjk() {
        assert_eq!(pad_width("/sweep", 8), "/sweep  ");
        assert_eq!(pad_width("/say <메시지>", 20).width(), 20);
        assert_eq!(pad_width("abcdef", 4), "abcdef");
    }

    #[test]
    fn progress_bar_clamps() {
        assert_eq!(progress_bar(0, 100, 4), "░░░░");
        assert_eq!(progress_bar(50, 100, 4), "██░░");
        assert_eq!(progress_bar(200, 100, 4), "████");
        assert_eq!(progress_bar(0, 0, 4), "░░░░");
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    fn ch(c: char) -> KeyEvent {
        key(KeyCode::Char(c))
    }

    #[test]
    fn slash_menu_complete_and_execute() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("rc-tui-slash-{}", std::process::id()));
        let home = tmp.join("redcell-home");
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let saved = scrub_provider_env();
        stage_usable_provider(&home);
        let mut app = App::boot();
        app.popup = Popup::None;
        // `/` → 전체 메뉴.
        on_key_main(&mut app, ch('/'));
        assert_eq!(app.input, "/");
        assert_eq!(slash_menu(&mut app).len(), slash::CATALOG.len());
        // `/s` → 필터 (첫 후보 sweep).
        on_key_main(&mut app, ch('s'));
        let names: Vec<&str> = slash_menu(&mut app).iter().map(|c| c.name).collect();
        assert_eq!(names[0], "sweep");
        assert!(!names.contains(&"quit"));
        // Tab → 완성만.
        on_key_main(&mut app, key(KeyCode::Tab));
        assert_eq!(app.input, "/sweep");
        assert_eq!(app.popup, Popup::None);
        // Esc 2회 → 메뉴 닫기 → 입력 지움.
        on_key_main(&mut app, key(KeyCode::Esc));
        assert!(slash_menu(&mut app).is_empty());
        assert_eq!(app.input, "/sweep");
        on_key_main(&mut app, key(KeyCode::Esc));
        assert!(app.input.is_empty());
        // Enter → 선택 완성 + 실행 (대상 없어 /setup 으로).
        on_key_main(&mut app, ch('/'));
        on_key_main(&mut app, ch('s'));
        on_key_main(&mut app, key(KeyCode::Enter));
        assert_eq!(app.popup, Popup::Setup);
        assert!(app.input.is_empty());
        restore_provider_env(saved);
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn slash_navigation_and_arg_completion() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("rc-tui-slash2-{}", std::process::id()));
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let saved = scrub_provider_env();
        unsafe { std::env::set_var("REDCELL_HOME", tmp.join("rh")) };
        let mut app = App::boot();
        app.popup = Popup::None;
        on_key_main(&mut app, ch('/'));
        on_key_main(&mut app, ch('s'));
        assert_eq!(app.slash_sel, 0);
        on_key_main(&mut app, key(KeyCode::Down));
        assert_eq!(app.slash_sel, 1);
        on_key_main(&mut app, key(KeyCode::Up));
        assert_eq!(app.slash_sel, 0);
        // 인자 명령은 완성 시 공백 추가.
        app.input.clear();
        app.input_cursor = 0;
        for c in "/say".chars() {
            on_key_main(&mut app, ch(c));
        }
        on_key_main(&mut app, key(KeyCode::Tab));
        assert_eq!(app.input, "/say ");
        restore_provider_env(saved);
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn slash_typo_suggests() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("rc-tui-typo-{}", std::process::id()));
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let saved = scrub_provider_env();
        unsafe { std::env::set_var("REDCELL_HOME", tmp.join("rh")) };
        let mut app = App::boot();
        app.popup = Popup::None;
        run_slash(&mut app, "/swep");
        assert!(app.status_msg.contains("/sweep"), "{}", app.status_msg);
        run_slash(&mut app, "/zzzzzz");
        assert!(app.status_msg.contains("알 수 없는 명령"), "{}", app.status_msg);
        assert_eq!(edit_dist("swep", "sweep"), 1);
        assert_eq!(edit_dist("same", "same"), 0);
        assert_eq!(edit_dist("", "abc"), 3);
        restore_provider_env(saved);
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn rename_and_delete_flow() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("rc-tui-sess-{}", std::process::id()));
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let saved = scrub_provider_env();
        unsafe { std::env::set_var("REDCELL_HOME", tmp.join("rh")) };
        let mut app = App::boot();
        app.popup = Popup::None;
        // 이름 변경·삭제는 /sessions 한 곳에서 (r/d 키).
        run_slash(&mut app, "/sessions");
        assert_eq!(app.popup, Popup::Sessions);
        // 두 번째 세션 준비 후 목록에서 삭제 확인 흐름.
        let other = TuiSession::fresh("옛날".into(), "old.example".into());
        other.save();
        let other_id = other.id.clone();
        open_sessions(&mut app);
        assert_eq!(app.sess_list.len(), 2);
        app.sess_sel = app.sess_list.iter().position(|(id, _, _, _)| id == &other_id).unwrap();
        on_key_sessions(&mut app, ch('r'));
        assert_eq!(app.popup, Popup::RenamePrompt);
        assert_eq!(app.rename_field.value, "옛날");
        app.rename_field = Field::text("이름", "바뀐".into());
        on_key_rename(&mut app, key(KeyCode::Enter));
        assert_eq!(app.popup, Popup::Sessions);
        assert!(app.sess_list.iter().any(|(_, n, _, _)| n == "바뀐"));
        // 삭제: 확인 모달 → y → 목록 복귀.
        on_key_sessions(&mut app, ch('d'));
        assert_eq!(app.popup, Popup::DeleteConfirm);
        on_key_delete_confirm(&mut app, ch('n'));
        assert_eq!(app.popup, Popup::Sessions);
        assert_eq!(app.sess_list.len(), 2);
        on_key_sessions(&mut app, ch('d'));
        on_key_delete_confirm(&mut app, ch('y'));
        assert_eq!(app.popup, Popup::Sessions);
        assert_eq!(app.sess_list.len(), 1);
        // 현재 세션 삭제 → 새로 생성되어 끊기지 않음.
        app.sess_sel = 0;
        let cur_id = app.session.id.clone();
        on_key_sessions(&mut app, ch('d'));
        on_key_delete_confirm(&mut app, key(KeyCode::Enter));
        assert_eq!(app.sess_list.len(), 1);
        assert_ne!(app.session.id, cur_id);
        // 목록에서 다른 세션 삭제 흐름도 동일.
        let third = TuiSession::fresh("지울것".into(), "x.example".into());
        third.save();
        open_sessions(&mut app);
        app.sess_sel = app.sess_list.iter().position(|(_, n, _, _)| n == "지울것").unwrap();
        on_key_sessions(&mut app, ch('d'));
        assert_eq!(app.popup, Popup::DeleteConfirm);
        on_key_delete_confirm(&mut app, ch('y'));
        assert!(TuiSession::list().iter().all(|(_, n, _, _)| n != "지울것"));
        restore_provider_env(saved);
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn providers_routes_wizard_or_list_and_aliases_resolve() {
        with_ui_app(|app| {
            // 미설정 → 마법사.
            run_slash(app, "/providers");
            assert_eq!(app.popup, Popup::Onboarding);
            app.popup = Popup::None;
            // 설정 후 → 목록.
            providers::upsert_custom(providers::CustomSpec {
                name: "groq".into(),
                kind: "openai-compat".into(),
                base_url: Some("https://api.groq.com/openai/v1".into()),
                env_keys: vec![],
                api_key: Some("test-key".into()),
                auth_type: Some("api_key".into()),
                default_model: Some("openai/gpt-oss-120b".into()),
                note: None,
            })
            .unwrap();
            run_slash(app, "/providers");
            assert_eq!(app.popup, Popup::Providers);
            // 옛 이름은 같은 화면으로.
            run_slash(app, "/onboard");
            assert_eq!(app.popup, Popup::Providers);
            run_slash(app, "/report");
            assert_eq!(app.popup, Popup::Findings);
            // 통폐합으로 사라진 이름은 안내와 함께 거부.
            run_slash(app, "/new");
            assert!(app.status_msg.contains("알 수 없는 명령"), "{}", app.status_msg);
            run_slash(app, "/rename x");
            assert!(app.status_msg.contains("알 수 없는 명령"), "{}", app.status_msg);
            run_slash(app, "/delete x");
            assert!(app.status_msg.contains("알 수 없는 명령"), "{}", app.status_msg);
        });
    }

    #[test]
    fn slash_menu_renders_below_input() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("rc-tui-render-{}", std::process::id()));
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let saved = scrub_provider_env();
        unsafe { std::env::set_var("REDCELL_HOME", tmp.join("rh")) };
        let mut app = App::boot();
        app.popup = Popup::None;
        app.input = "/s".into();
        app.input_cursor = 2;
        // 새 백엔드에 한 프레임 그려 스냅샷 (TestBackend 는 diff 렌더라
        // 와이드 문자 잔상이 남을 수 있어 프레임마다 새로 만든다).
        fn snap(app: &mut App) -> String {
            let backend = ratatui::backend::TestBackend::new(100, 30);
            let mut term = ratatui::Terminal::new(backend).unwrap();
            term.draw(|f| render(f, app)).unwrap();
            term.backend()
                .buffer()
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect::<String>()
                .chars()
                .filter(|c| *c != ' ')
                .collect::<String>()
        }
        let shot = snap(&mut app);
        assert!(shot.contains("/sweep"), "메뉴에 /sweep 없음");
        assert!(shot.contains("/setup"), "메뉴에 /setup 없음");
        assert!(shot.contains("P0스윕"), "메뉴에 설명 없음");
        // 빈 입력이면 플레이스홀더.
        app.input.clear();
        app.input_cursor = 0;
        assert!(snap(&mut app).contains("질문·지시를입력하세요"), "플레이스홀더 없음");
        // 팝업이 열리면 메뉴는 숨는다.
        app.input = "/s".into();
        app.popup = Popup::Help;
        assert!(!snap(&mut app).contains(">/sweep"), "팝업 위 메뉴 노출됨");
        restore_provider_env(saved);
        unsafe { std::env::remove_var("XDG_DATA_HOME") };
        std::fs::remove_dir_all(&tmp).ok();
    }



    /// 새 저장소만 사용하는 UI 픽스처. 실제 키·세션·네트워크는 사용하지 않는다.
    fn with_ui_app(test: impl FnOnce(&mut App)) {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("rc-tui-ux-{}", uuid::Uuid::new_v4()));
        let xdg = std::env::var("XDG_DATA_HOME").ok();
        let saved = scrub_provider_env();
        unsafe {
            std::env::set_var("XDG_DATA_HOME", &tmp);
            std::env::set_var("REDCELL_HOME", tmp.join("config"));
        }
        let mut app = App::boot();
        test(&mut app);
        restore_provider_env(saved);
        match xdg {
            Some(value) => unsafe { std::env::set_var("XDG_DATA_HOME", value) },
            None => unsafe { std::env::remove_var("XDG_DATA_HOME") },
        }
        std::fs::remove_dir_all(tmp).ok();
    }

    fn screen(app: &mut App, width: u16, height: u16) -> Vec<String> {
        let mut term = Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        term.draw(|f| render(f, app)).unwrap();
        if app.popup == Popup::None && width >= 24 && height >= 8 {
            let cursor = term.get_cursor_position().unwrap();
            assert!(cursor.x < width && cursor.y < height, "커서가 화면 밖: {cursor:?}");
        }
        term.backend().buffer().content().chunks(width as usize).map(|row| {
            row.iter().map(|c| c.symbol()).collect::<String>().replace(' ', "")
        }).collect()
    }

    #[test]
    fn first_run_has_actionable_guide_without_blocking_modal() {
        with_ui_app(|app| {
            assert_eq!(app.popup, Popup::None);
            let shot = screen(app, 100, 30).join("\n");
            assert!(shot.contains("시작하기"));
            for command in ["/setup", "/providers", "/help"] {
                assert!(shot.contains(command), "시작 안내에 {command} 없음");
            }
            assert!(shot.contains("/providers연결"));
            on_key(app, key(KeyCode::Enter));
            assert_eq!(app.popup, Popup::UrlPrompt);
            on_key(app, key(KeyCode::Esc));
            assert_eq!(app.popup, Popup::None);
            open_onboarding(app);
            on_key(app, key(KeyCode::Esc));
            assert_eq!(app.popup, Popup::None);
        });
    }

    #[test]
    fn menu_is_below_composer_and_selected_row_survives_resize() {
        with_ui_app(|app| {
            for (width, height) in [(110, 32), (80, 24), (48, 16), (24, 8)] {
                app.input = "/".into();
                app.input_cursor = 1;
                app.slash_sel = slash::CATALOG.len() - 1;
                let rows = screen(app, width, height);
                let input = rows.iter().position(|l| l.contains("❯/")).unwrap();
                let n = slash::CATALOG.len();
                let menu = rows.iter().position(|l| l.contains(&format!("명령어{n}/{n}"))).unwrap();
                assert!(menu > input, "입력 아래 메뉴가 아님 ({width}x{height})");
                assert!(rows.iter().any(|l| l.contains(">/quit")), "선택 명령이 안 보임 ({width}x{height})");
                app.input = "/없는검색어".into();
                app.input_cursor = app.input.chars().count();
                let no_results = screen(app, width, height);
                assert!(no_results.join("").contains("검색결과없음"));
                assert_eq!(no_results.iter().position(|l| l.contains("❯/")).unwrap(), input, "검색 시 입력창이 이동함");
            }
        });
    }

    #[test]
    fn popups_never_overlap_the_composer_and_consent_keeps_buttons() {
        with_ui_app(|app| {
            app.session.host = "example.com".into();
            app.pending_risk = Some(engine::risk::assess("서버 전부 삭제하고 재부팅해줘"));
            let popups = [
                Popup::UrlPrompt, Popup::Onboarding, Popup::Setup, Popup::Providers,
                Popup::ProviderEdit, Popup::Sessions, Popup::Findings, Popup::FindingDetail,
                Popup::Report, Popup::ConsentStatic, Popup::ConsentRisk,
            ];
            for (width, height) in [(110, 32), (80, 24), (60, 18), (48, 16), (24, 8)] {
                for popup in popups {
                    app.popup = popup;
                    if popup == Popup::ProviderEdit {
                        open_providers(app);
                        open_provider_edit(app, false);
                    }
                    if popup == Popup::Onboarding {
                        open_onboarding(app);
                    }
                    let rows = screen(app, width, height);
                    let cursor = rows.iter().position(|l| l.contains("❯")).expect("입력창 없음");
                    assert!(rows[cursor.saturating_sub(1)].contains("입력"), "입력창 윗변 겹침 ({width}x{height} {popup:?})");
                    if popup == Popup::ConsentRisk || popup == Popup::ConsentStatic {
                        let shot = rows.join("");
                        assert!(shot.contains("동의하고진행"), "동의 버튼 잘림 ({width}x{height} {popup:?})");
                        assert!(shot.contains("취소"), "취소 버튼 잘림 ({width}x{height} {popup:?})");
                    }
                }
            }
            // 근거가 길면 스크롤로 전부 볼 수 있고 버튼은 유지된다.
            app.popup = Popup::ConsentRisk;
            for _ in 0..10 {
                on_key_consent(app, key(KeyCode::Down));
            }
            let shot = screen(app, 60, 18).join("");
            assert!(shot.contains("↑위"), "스크롤 표시 없음");
            assert!(shot.contains("동의하고진행"), "스크롤 후 버튼 잘림");
        });
    }

    #[test]
    fn required_arguments_are_edited_before_execution() {
        with_ui_app(|app| {
            insert_input(app, "/say");
            on_key_main(app, key(KeyCode::Enter));
            assert_eq!(app.input, "/say ");
            assert!(slash_menu(app).is_empty());
            assert!(app.session.chat.is_empty());
            on_key_main(app, key(KeyCode::Enter));
            assert_eq!(app.input, "/say ");
            insert_input(app, "한글 메모");
            on_key_main(app, key(KeyCode::Enter));
            assert_eq!(app.session.chat.last().unwrap().content, "한글 메모");
            assert!(app.input.is_empty());
            insert_input(app, "/swep");
            on_key_main(app, key(KeyCode::Enter));
            assert_eq!(app.input, "/swep");
            assert!(app.status_msg.contains("/sweep"));
            assert!(!app.sweep_running);
        });
    }

    #[test]
    fn palette_and_history_preserve_the_draft() {
        with_ui_app(|app| {
            app.input_history.remember("/say 이전 메모");
            insert_input(app, "작성 중인 초안");
            on_key_main(app, key(KeyCode::Up));
            assert_eq!(app.input, "/say 이전 메모");
            on_key_main(app, key(KeyCode::Down));
            assert_eq!(app.input, "작성 중인 초안");
            let ctrl_p = KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL);
            on_key(app, ctrl_p);
            assert_eq!(app.input, "/");
            on_key(app, key(KeyCode::Esc));
            assert_eq!(app.input, "작성 중인 초안");
            on_key(app, ctrl_p);
            insert_input(app, "help");
            on_key(app, key(KeyCode::Enter));
            assert_eq!(app.popup, Popup::Help);
            assert_eq!(app.input, "작성 중인 초안");
            on_key(app, key(KeyCode::Esc));
            on_key(app, KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
            assert!(app.input.is_empty());
            assert!(!app.quit);
        });
    }

    #[test]
    fn paste_and_multiline_editing_never_submit_implicitly() {
        with_ui_app(|app| {
            on_paste(app, "/say 붙여넣기\r\n두 번째 줄\r\n");
            assert_eq!(app.input, "/say 붙여넣기\n두 번째 줄\n");
            assert!(app.session.chat.is_empty());
            assert_eq!(app.popup, Popup::None);
            app.reset_composer();
            on_paste(app, "한글".repeat(100).as_str());
            on_key(app, KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT));
            insert_input(app, "마지막 줄");
            for (width, height) in [(110, 32), (80, 24), (48, 16), (24, 8)] {
                assert!(screen(app, width, height).join("").contains("마지막줄"));
            }
            open_setup(app);
            app.setup_sel = 5;
            on_paste(app, "test-cookie");
            assert_eq!(app.setup_fields[5].value, "test-cookie");
            for (width, height) in [(100, 30), (48, 16), (24, 8)] {
                let shot = screen(app, width, height).join("");
                assert!(shot.contains("세션쿠키"), "선택한 필드가 안 보임");
                assert!(!shot.contains("test-cookie"), "비밀 필드가 마스킹되지 않음");
            }
        });
    }

    #[test]
    fn latest_transcript_lines_are_not_clipped_by_the_border() {
        with_ui_app(|app| {
            for i in 0..50 { app.session.push_log("test", format!("line-{i}"), LineLevel::Info); }
            let shot = screen(app, 80, 24).join("\n");
            assert!(shot.contains("line-49"));
            assert!(shot.contains("line-48"));
            assert!(!shot.contains("line-0"));
            on_key_main(app, key(KeyCode::PageUp));
            assert!(!screen(app, 80, 24).join("\n").contains("line-49"));
        });
    }

    #[test]
    fn form_can_save_without_visiting_every_field() {
        with_ui_app(|app| {
            open_setup(app);
            app.setup_fields[0] = Field::text("세션명", "새 이름".into());
            on_key(app, KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
            assert_eq!(app.popup, Popup::None);
            assert_eq!(app.session.name, "새 이름");
            assert!(!app.sweep_running && !app.agent_running);
        });
    }





    #[test]
    fn risk_gate_blocks_without_consent() {
        let rep = engine::risk::assess("서버 재부팅해줘");
        assert!(rep.needs_consent && rep.shutdown_risk);
        assert!(!engine::risk::assess("합격자 목록 파일로 뽑아줘").needs_consent);
    }
}




