//! 세션 저장소 계층 — 세션/설정 데이터 모델과 디스크 I/O.
//!
//! 역할:
//!   - `Session`·`Settings`·`ProviderConn` 데이터 모델
//!   - 세션 JSON(메타+채팅)·이벤트 NDJSON(append-only)·설정 파일 저장/조회
//!   - 이벤트 append 와 상태 갱신의 원자화(IoGuard)·`_seq` 채번(EventSeqs)
//!
//! 저장 구조(앱 데이터 디렉터리 기준):
//!   sessions/<id>.json          — 세션 메타데이터 + 채팅 (이벤트는 담지 않는다)
//!   sessions/<id>.events.ndjson — 이벤트 1건 = 1줄, append-only
//!   settings.json               — 앱 설정 + 프로바이더 연결 정보

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Manager};

/// 세션 파일 read-modify-write 직렬화용 락(stdout/stderr 스레드 경합 방지).
pub struct IoGuard(pub Mutex<()>);

#[derive(Serialize, Deserialize, Clone)]
pub struct ChatMessage {
    pub role: String, // "user" | "assistant" | "system"
    pub content: String,
    pub ts: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub goal: String,
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_mode")]
    pub mode: String, // tools(고정 툴박스 오케스트레이터) | python(absolute-agent RLM)
    #[serde(default)]
    pub max: bool, // 공격 최대 모드(tools) — 전수 커버리지 + opt-in 전체 + python_exec
    #[serde(default)]
    pub diag: bool, // 서비스 진단 모드 — 설명 기반 공격 포인트/개선 권고 리포트
    #[serde(default)]
    pub deep: bool, // 정밀 진단 — 병렬 5분야 + fan-in 병합 (prime-agent builder 패턴)
    #[serde(default)]
    pub engine: String, // 실행 엔진: ""|"pi" = pi-coding-agent, "prime" = prime-agent(Rust 하네스)
    #[serde(default)]
    pub auth_cookie: String, // 로그인 영역 점검용 세션 쿠키 (Cookie 헤더 값, 사용자가 붙여넣음)
    #[serde(default)]
    pub danger_consent: bool, // 위험 검사 동의 (모달 명시 동의, 세션별, 철회 가능)
    #[serde(default)]
    pub danger_consented_at: String, // 동의 시각 (RFC3339, 감사 추적용)
    #[serde(default)]
    pub piq: String, // prime 모드: pi 세션 id(연속 대화 유지)
    #[serde(default = "status_idle")]
    pub status: String, // idle | running | done | error
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub chat: Vec<ChatMessage>,
    #[serde(default)]
    pub events: Vec<Value>,
}

pub fn default_provider() -> String {
    String::new() // mock 프로바이더는 존재하지 않는다 — 미지정 = 선택 안 함
}
pub fn default_mode() -> String {
    // 기본은 prime-agent(pi) 직접 실행 — 위에 대상 URL/호스트를 넣고 지시하면 CLI 처럼 쓴다.
    "prime".into()
}
pub fn status_idle() -> String {
    "idle".into()
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ProviderConn {
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub model: String,
    /// pi models.json 의 API 방언 — ""(기본)=openai-completions, "anthropic-messages".
    /// custom 카드에서 선택한다 (Databricks AI Gateway 같은 Anthropic 경로용).
    #[serde(default)]
    pub api: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Settings {
    #[serde(default)]
    pub redcell_dir: String,
    #[serde(default)]
    pub auth_path: String,
    #[serde(default)]
    pub default_provider: String,
    /// 사용자가 데스크톱 설정에서 직접 입력한 연결 정보(API 키/base URL/모델).
    /// 세션 실행 시 자식 프로세스의 환경변수로 주입된다.
    #[serde(default)]
    pub providers: HashMap<String, ProviderConn>,
}

pub fn now() -> String {
    Utc::now().to_rfc3339()
}

// ── 경로 헬퍼 ────────────────────────────────────────────────────────────────
pub fn root(app: &AppHandle) -> PathBuf {
    let dir = app.path().app_data_dir().unwrap_or_else(|_| PathBuf::from("."));
    fs::create_dir_all(&dir).ok();
    dir
}
pub fn sessions_dir(app: &AppHandle) -> PathBuf {
    let d = root(app).join("sessions");
    fs::create_dir_all(&d).ok();
    d
}
pub fn settings_file(app: &AppHandle) -> PathBuf {
    root(app).join("settings.json")
}
pub fn session_file(app: &AppHandle, id: &str) -> PathBuf {
    sessions_dir(app).join(format!("{id}.json"))
}

pub fn read_session(app: &AppHandle, id: &str) -> Option<Session> {
    let txt = fs::read_to_string(session_file(app, id)).ok()?;
    let mut s: Session = serde_json::from_str(&txt).ok()?;
    // 구버전 마이그레이션: 세션 JSON 에 embed 돼 있던 events 를 별도 NDJSON 으로 이관.
    if !s.events.is_empty() {
        let ev_path = events_file(app, id);
        if !ev_path.exists() {
            write_events_file(&ev_path, &s.events);
        }
        s.events.clear();
        let guard = app.state::<IoGuard>();
        let _lock = guard.0.lock().unwrap();
        if let Ok(txt) = serde_json::to_string_pretty(&s) {
            fs::write(session_file(app, id), txt).ok();
        }
    }
    s.events = read_events_file(&events_file(app, id));
    Some(s)
}

/// 세션 이벤트 저장소 — append-only NDJSON (`<id>.events.ndjson`).
/// 세션 JSON 은 메타데이터+채팅만 담고, 이벤트는 한 줄 1건으로 계속 덧붙인다.
/// (기존엔 이벤트 1건마다 세션 JSON 전체를 read-modify-write 해서 O(n²) I/O 발생)
pub fn events_file(app: &AppHandle, id: &str) -> PathBuf {
    sessions_dir(app).join(format!("{id}.events.ndjson"))
}

pub fn read_events_file(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .map(|txt| {
            txt.lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        })
        .unwrap_or_default()
}

pub fn write_events_file(path: &Path, events: &[Value]) {
    if let Ok(mut f) = fs::File::create(path) {
        use std::io::Write as _;
        for ev in events {
            if let Ok(line) = serde_json::to_string(ev) {
                let _ = writeln!(f, "{line}");
            }
        }
    }
}

/// 이벤트 `_seq` 채번 캐시(세션 id → 다음 순번). NDJSON 은 append-only 라
/// 줄 수를 세면 되지만, 이벤트마다 전체 파일을 다시 읽지 않게 프로세스 내 캐시를 쓴다.
/// 첫 접근 시 파일 줄 수로 초기화하므로 재시작 후에도 연속성이 유지된다.
pub struct EventSeqs(pub Mutex<HashMap<String, usize>>);

fn next_event_seq(app: &AppHandle, id: &str, path: &Path) -> usize {
    let state = app.state::<EventSeqs>();
    let mut m = state.0.lock().unwrap();
    if let Some(n) = m.get(id) {
        *n
    } else {
        let n = fs::read_to_string(path)
            .map(|txt| txt.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0);
        m.insert(id.to_string(), n);
        n
    }
}

fn bump_event_seq(app: &AppHandle, id: &str) {
    let state = app.state::<EventSeqs>();
    let mut m = state.0.lock().unwrap();
    m.entry(id.to_string()).and_modify(|n| *n += 1).or_insert(1);
}

pub fn write_session_locked(app: &AppHandle, s: &Session) {
    let guard = app.state::<IoGuard>();
    let _lock = guard.0.lock().unwrap();
    // events 는 <id>.events.ndjson 에만 산다 — 세션 JSON 에는 절대 기록하지 않는다.
    let mut out = s.clone();
    out.events = Vec::new();
    if let Ok(txt) = serde_json::to_string_pretty(&out) {
        fs::write(session_file(app, &s.id), txt).ok();
    }
}

/// 세션에 이벤트 하나를 append (IoGuard 로 원자화).
/// 이벤트에 `_ts`(epoch millis)·`_seq`(순번)를 찍어 UI 의 캡처 테이블이
/// 시간·순번 컬럼을 그릴 수 있게 한다. 저장된 값과 동일한 stamped 이벤트를 반환한다.
pub fn append_event(app: &AppHandle, id: &str, ev: &Value) -> Value {
    let guard = app.state::<IoGuard>();
    let _lock = guard.0.lock().unwrap();
    let p = events_file(app, id);
    let mut stamped = ev.clone();
    if let Some(obj) = stamped.as_object_mut() {
        obj.entry("_ts").or_insert(json!(Utc::now().timestamp_millis()));
        obj.entry("_seq").or_insert(json!(next_event_seq(app, id, &p)));
    }
    use std::io::Write as _;
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&p) {
        if let Ok(line) = serde_json::to_string(&stamped) {
            let _ = writeln!(f, "{line}");
        }
    }
    bump_event_seq(app, id);
    stamped
}

pub fn set_status(app: &AppHandle, id: &str, status: &str) {
    let guard = app.state::<IoGuard>();
    let _lock = guard.0.lock().unwrap();
    let p = session_file(app, id);
    if let Some(mut s) = fs::read_to_string(&p)
        .ok()
        .and_then(|t| serde_json::from_str::<Session>(&t).ok())
    {
        s.status = status.to_string();
        s.updated_at = now();
        if let Ok(txt) = serde_json::to_string_pretty(&s) {
            fs::write(p, txt).ok();
        }
    }
}
