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
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;

mod auth;

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
    if s.default_provider.trim().is_empty() {
        s.default_provider = "mock".into();
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
    s.updated_at = now();
    write_session_locked(&app, &s);
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
    ProviderMeta { name: "ollama", kind: "openai-compat", note: "로컬/원격 ollama 서버 (키 불필요)", default_model: "llama3.1", env_keys: &[], base_url: "http://localhost:11434/v1", needs_base: true },
    ProviderMeta { name: "custom", kind: "openai-compat", note: "임의 OpenAI 호환 엔드포인트 — vLLM·LM Studio·원격 ollama 등", default_model: "", env_keys: &["REDCELL_OPENAI_API_KEY"], base_url: "", needs_base: true },
];

/// 서비스 진단 모드에서 pi 에 주입하는 방법론 — 공격 포인트 + 개선 권고 중심.
const DIAG_METHOD: &str = r#"# RedCell 서비스 진단 방법론

당신은 서비스 보안 진단 전문가다. 아래 '서비스 설명'을 바탕으로 **공격 포인트와
개선(보완) 필요 사항**을 창의적으로 발굴해 진단 리포트를 작성한다.

## 리포트 형식 (Markdown, 아래 구조를 지킨다)
# 서비스 진단 리포트 — <서비스명>
## 1. 진단 범위 및 가정
  - 기술 스택·아키텍처 추정 (설명에 없는 부분은 [가정] 으로 표시)
  - 진단 경계: 설명 기반 판단 vs 실측 확인
## 2. 공격 표면 (Attack Surface)
  인증·세션·권한 / 입력 처리 / 데이터 흐름 / 외부 연동 / 배포·설정 / 비즈니스 로직
  각 표면의 노출 경로와 진입점(예상 엔드포인트·함수·플로우)
## 3. 창의적 공격 루트 (위험도 순)
  각 항목: **위험도(치명/높음/중간/낮음) · 공격 시나리오 · 영향 · 발생 가능성**
  주입류(SQLi·NoSQLi·명령·SSRF·SSTI), 인증·세션(JWT·OAuth·쿠키·토큰), 권한(IDOR·
  수평/수직 상승), 파일 업로드·경로, XXE·역직렬화, 레이스 컨디션, 캐시 오염, 요청
  스머글링, 비즈니스 로직 남용(할인·쿼터·순서·상태), 개인정보 노출, 유니코드·인코딩
  우회, 체인 공격(XSS→CSRF→관리자 권한 등)
## 4. 개선·보완 권고 (우선순위)
  각 항목: **우선순위(P0~P3) · 문제 · 구체적 보완 방법(코드·설정·프로세스 수준) ·
  검증 방법**
## 5. 실측 확인 (URL 이 주어진 경우)
  web_fetch/recon_http 로 확인한 사실과 '가정' 의 차이, 추가 확인 필요 항목

## 원칙
- **창의성**: 잘 알려진 취약점뿐 아니라 조합·비즈니스 로직·운영 방식에서 나오는
  공격 루트를 발굴한다. 공격자 관점에서 "실제로 어떻게 성공하는가"를 구체적으로.
- **보완 중심**: 모든 공격 루트마다 반드시 "미리 막는 방법"(방어 기재·설정·검증 방법)
  을 제시한다 — 진단기가 곧 개선 지침이 되도록.
- 로컬 컴퓨터 파일은 조사하지 말 것. 웹 실측은 반드시 web_fetch 툴로만.
"#;

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
        if !conn.api_key.trim().is_empty() {
            if let Some(k) = p.env_keys.last() {
                // 마지막 env 슬롯에 주입(앞쪽 OAUTH 등 실제 설정 env 가 있으면 그게 우선)
                cmd.env(k, conn.api_key.trim());
            }
        }
    }
}

/// pi 의 커스텀 프로바이더(baseUrl 기반)는 `~/.pi/agent/models.json` 에만 선언할 수 있다.
/// (docs/models.md: custom providers) 프로바이더 "custom"/"ollama" 는 baseUrl·apiKey·models 를
/// 여기에 기록해야 pi 가 프로바이더로 인식하고 키 없음 오류가 나지 않는다.
/// 사용자의 기존 파일(다른 프로바이더·이름·compat 등)은 보존하고 같은 이름만 병합(upsert)한다.
fn sync_pi_models_json_at(path: &Path, provider: &str, base_url: &str, api_key: &str, model: &str) -> Result<(), String> {
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
    if prov.get("api").is_none() {
        prov.insert("api".into(), Value::String("openai-completions".into()));
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
            models.push(json!({ "id": id }));
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

/// 연결 테스트 — node fetch 로 대상 엔드포인트 도달성/키 인증을 확인한다.
/// (reqwest 의존성 추가 없이 이미 있는 node 를 재사용)
#[tauri::command]
fn test_provider(provider: String, api_key: String, base_url: String) -> Result<String, String> {
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
    let path = if provider == "ollama" { "/tags" } else { "/models" };
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let script = r#"(async()=>{const u=process.env.RC_TEST_URL,k=process.env.RC_TEST_KEY||"";try{const r=await fetch(u,{headers:k?{Authorization:"Bearer "+k,"x-api-key":k,"anthropic-version":"2023-06-01"}:{}});console.log("OK "+r.status+" "+r.statusText)}catch(e){console.log("ERR "+String(e&&e.message||e))}})()"#;
    let mut probe = Command::new("node");
    probe
        .arg("-e")
        .arg(script)
        .env("RC_TEST_URL", url)
        .env("RC_TEST_KEY", api_key.trim())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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

/** prime 모드 실행: node <pi cli.js> --mode json -p "<목표>" — json 이벤트를 패널로 스트리밍. */
fn run_prime(
    app: &AppHandle,
    id: &str,
    s: &Session,
    settings: &Settings,
    redcell: &str,
    provider: &str,
) -> Result<(), String> {
    let cli = prime_cli_path(redcell)?;

    // 연속 대화: pi 세션 id 를 세션에 보관하고, 같은 id 로 --session-id 를 넘겨
    // CLI 처럼 이전 대화를 이어간다(첫 턴에 생성·저장, 이후 턴은 재사용).
    let mut s2 = s.clone();
    if s2.piq.trim().is_empty() {
        let id8 = s2.id.chars().take(8).collect::<String>();
        s2.piq = format!("rc-{id8}");
        write_session_locked(app, &s2);
    }
    let piq = s2.piq.clone();

    let port = s2.port;
    let target = match port {
        Some(p) if p == 443 || p == 8443 => format!("https://{}/", s2.host),
        Some(p) => format!("http://{}:{}/", s2.host, p),
        None => format!("http://{}/", s2.host),
    };
    let mut goal = s2.goal.trim().to_string();
    if goal.is_empty() {
        goal = if s2.diag {
            "이 서비스의 보안 진단 리포트를 작성해줘.".to_string()
        } else {
            "아래 사이트를 샅샅이 살펴보고 유용한 정보·정리된 자료를 찾아 정리해줘.".to_string()
        };
    }
    let instruction = if s2.diag {
        // 서비스 진단 모드: 설명 기반 공격 포인트 발굴 + 개선 권고 리포트.
        let scope = if s2.host.trim().is_empty() {
            "실측 없이 설명 기반 진단 — 추정은 [가정] 으로 표시".to_string()
        } else {
            let https_hint = match port {
                Some(p) if p != 443 && p != 8443 => format!("https://{}:{}/ 로도 접속을 시도해볼 것(둘 다 확인).", s2.host, p),
                _ => String::new(),
            };
            format!(
                "대상 사이트(인가됨): {target}\n{https_hint}\n가능하면 web_fetch 로 실제 페이지·헤더·엔드포인트를 열어 가정을 검증해줘(실측 확인은 필수가 아니다)."
            )
        };
        format!(
            "{DIAG_METHOD}\n\n## 서비스 설명\n\n{goal}\n\n## 진단 경계\n{scope}\n\n로컬 컴퓨터 파일 시스템(bash/read/edit/write)은 절대 조사하지 말 것 — 결과물 저장 외에 이 머신을 뒤지지 마라."
        )
    } else if s2.host.trim().is_empty() {
        // 대상 미지정: 순수 pi CLI 대화(인가 게이트는 대상 없는 로컬 작업만 통과).
        goal
    } else {
        let https_hint = match port {
            Some(p) if p != 443 && p != 8443 => format!("https://{}:{}/ 로도 접속을 시도해볼 것(둘 다 확인).", s2.host, p),
            _ => String::new(),
        };
        format!(
            "{goal}\n\n대상 사이트(인가됨): {target}\n{https_hint}\n인가 목록에 있는 대상이므로 필요한 만큼 자유롭게 조사·탐색하고 결과를 정리해줘.\n중요: 웹 조사는 반드시 web_fetch 툴로 수행한다. 이 컴퓨터의 파일 시스템(bash/read/edit/write)은 조사 대상이 아니라 — 결과물 저장 외에 로컬 머신을 뒤지지 마라."
        )
    };

    // RedCell 인가 확장(scope 게이트)을 `-e` 로 **명시 로드**한다 — 전역 설치·트러스트·settings
    // 병합이 없어도 패널에서 항상 게이트가 켜진다(다른 프로젝트의 pi 세션엔 영향 없음).
    let ext_path = PathBuf::from(redcell).join("prime-agent").join("index.ts");
    let ev3 = json!({ "type": "note", "text": "[sys] 인가 게이트: RedCell 확장을 -e 로 명시 로드 — pi 의 모든 툴 호출을 인가 목록으로 검사합니다(이 세션만)." });
    let stamped3 = append_event(app, id, &ev3);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped3 })).ok();

    let mut args: Vec<String> = vec![
        "-e".into(),
        ext_path.to_string_lossy().into_owned(),
        "--mode".into(),
        "json".into(),
        "--session-id".into(),
        piq.clone(),
        "-p".into(),
        instruction,
    ];
    args.push("--provider".into());
    args.push(provider.to_string());
    let conn = settings.providers.get(provider).cloned().unwrap_or_default();
    // 커스텀/로컬(baseUrl 필요) 프로바이더: pi 는 models.json 에만 존재할 수 있으므로
    // 앱 설정(base URL·키·모델)을 ~/.pi/agent/models.json 에 병합해 항상 동기화한다.
    if provider == "custom" || provider == "ollama" {
        let mpath = pi_models_json_path()?;
        sync_pi_models_json_at(&mpath, provider, &conn.base_url, &conn.api_key, &conn.model)?;
    }
    // 모델 지정: custom/ollama 도 --model 로 명시( pi 모델 패턴 "provider/id" 또는 순수 id ).
    {
        let m = conn.model.trim().to_string();
        if !m.is_empty() {
            args.push("--model".into());
            args.push(if provider == "custom" || provider == "ollama" { m } else { format!("{provider}/{m}") });
        } else if provider == "anthropic" || provider == "openai" || provider == "openrouter" {
            if let Some(d) = PROVIDER_CATALOG.iter().find(|x| x.name == provider) {
                if !d.default_model.is_empty() {
                    let d = d.default_model.to_string();
                    args.push("--model".into());
                    args.push(format!("{provider}/{d}"));
                }
            }
        }
    }
    // 키: CLI --api-key 가 pi 해석 1순위(GUI 환경에선 env 가 안 보일 수 있어 가장 확실).
    if !conn.api_key.trim().is_empty() {
        args.push("--api-key".into());
        args.push(conn.api_key.trim().to_string());
    }

    {
        let ev = json!({ "type": "note", "text": format!("[sys] prime-agent(pi) 턴 — session {piq}: node {} {}…", cli.display(), args.get(5).map(|a| a.chars().take(60).collect::<String>()).unwrap_or_default()) });
        let stamped = append_event(app, id, &ev);
        app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    }

    let node = first_on_path("node").unwrap_or_else(|| PathBuf::from("node"));
    let mut cmd = Command::new(node);
    cmd.arg(cli.as_os_str());
    cmd.current_dir(prime_cwd(redcell));
    cmd.args(&args);
    // 인가 게이트 명시 활성화: 확장의 tool_call 훅이 이 세션에서만 fail-closed 로 동작한다.
    cmd.env("REDCELL_GATE", "1");
    if let Some(conn) = settings.providers.get(provider) {
        inject_provider_env(&mut cmd, provider, conn);
    }
    hide_window(&mut cmd);
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("node(pi) 실행 실패 — node 설치 및 PATH 확인: {e}"))?;

    let stdout = child.stdout.take().ok_or("stdout 파이프 실패")?;
    let stderr = child.stderr.take().ok_or("stderr 파이프 실패")?;
    app.state::<Procs>().0.lock().unwrap().insert(id.to_string(), child);
    set_status(app, id, "running");
    app.emit("engagement-status", json!({ "sessionId": id, "status": "running" })).ok();

    // stderr → [sys] 노트(모델/스코프 로그).
    {
        let app = app.clone();
        let id = id.to_string();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let ev = json!({ "type": "note", "text": format!("[sys] {line}") });
                let stamped = append_event(&app, &id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            }
        });
    }

    // stdout → pi json 이벤트 스트림: text_delta 를 모아 text_end 에서 노트로,
    // tool_use 는 [pi-툴] 표시, 종료 시 상태 마감.
    {
        let app = app.clone();
        let id = id.to_string();
        thread::spawn(move || {
            let mut buf = String::new();
            let mut last_text: Option<String> = None; // text_end/message_end 중복 노트 방지
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let ev: Value = serde_json::from_str(line).unwrap_or_else(|_| json!({ "raw": line }));
                let ty = ev.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if ty == "tool_execution_start" {
                    let name = ev.get("toolName").and_then(|n| n.as_str()).unwrap_or("tool");
                    let a = ev.get("args").map(|v| v.to_string()).unwrap_or_default();
                    let a = a.chars().take(120).collect::<String>();
                    let ev2 = json!({ "type": "note", "text": format!("[pi-툴] {name} {a}") });
                    let stamped = append_event(&app, &id, &ev2);
                    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
                } else if ty == "message_update" {
                    if let Some(ae) = ev.get("assistantMessageEvent") {
                        match ae.get("type").and_then(|t| t.as_str()) {
                            Some("text_delta") => {
                                if let Some(d) = ae.get("delta").and_then(|d| d.as_str()) {
                                    buf.push_str(d);
                                }
                            }
                            Some("text_end") => {
                                let t = buf.trim().to_string();
                                if !t.is_empty() && last_text.as_deref() != Some(t.as_str()) {
                                    let ev2 = json!({ "type": "note", "text": t.clone() });
                                    let stamped = append_event(&app, &id, &ev2);
                                    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
                                    last_text = Some(t);
                                }
                                buf.clear();
                            }
                            _ => {}
                        }
                    }
                } else if ty == "message_end" {
                    if let Some(m) = ev.get("message") {
                        if m.get("role").and_then(|r| r.as_str()) == Some("assistant") {
                            if let Some(content) = m.get("content").and_then(|c| c.as_array()) {
                                for part in content {
                                    if part.get("type").and_then(|t| t.as_str()) == Some("text") {
                                        if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                                            let t = t.trim().to_string();
                                            if !t.is_empty() && last_text.as_deref() != Some(t.as_str()) {
                                                let ev2 = json!({ "type": "note", "text": t.clone() });
                                                let stamped = append_event(&app, &id, &ev2);
                                                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
                                                last_text = Some(t);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if ty == "error" {
                    let text = ev.get("error").and_then(|e| e.as_str()).unwrap_or("pi 오류").to_string();
                    let ev2 = json!({ "type": "note", "text": format!("[오류] {text}") });
                    let stamped = append_event(&app, &id, &ev2);
                    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
                }
            }
            if !buf.trim().is_empty() {
                let ev2 = json!({ "type": "note", "text": buf.trim().to_string() });
                let stamped = append_event(&app, &id, &ev2);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            }
            let removed = app.state::<Procs>().0.lock().unwrap().remove(&id);
            if let Some(mut c) = removed {
                let ok = c.wait().map(|st| st.success()).unwrap_or(false);
                let ev2 = json!({ "type": "note", "text": if ok { "[완료] prime-agent 종료.".to_string() } else { "[완료] prime-agent 비정상 종료(exit≠0).".to_string() } });
                let stamped = append_event(&app, &id, &ev2);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
                if let Some(cur) = read_session(&app, &id) {
                    if cur.status == "running" {
                        let st = if ok { "done" } else { "error" };
                        set_status(&app, &id, st);
                        app.emit("engagement-status", json!({ "sessionId": id, "status": st })).ok();
                    }
                }
            }
        });
    }
    Ok(())
}

#[tauri::command]
fn start_engagement(app: AppHandle, id: String) -> Result<(), String> {
    let s = read_session(&app, &id).ok_or("세션을 찾을 수 없습니다")?;
    // 프로바이더 설정 없으면 거부 — mock 은 제거됨(데스크톱은 명시적 설정만).
    let provider = s.provider.trim();
    if provider.is_empty() || provider == "mock" {
        return Err("provider 가 설정되지 않았습니다 — 설정(⚙) > 프로바이더에서 API 키/연결을 설정하세요.".into());
    }
    let provider = provider.to_string();
    // 앱이 죽었다 다시 켜진 경우 등: 상태가 running 이어도 실제 실행 프로세스가 없으면
    // 재실행을 허용한다(레지스트리 기준 — 스트림 종료 시 항목이 제거되므로 정확하다).
    let truly_running = app.state::<Procs>().0.lock().unwrap().contains_key(&id);
    if s.status == "running" && truly_running {
        return Err("이미 실행 중인 세션입니다".into());
    }
    let settings = get_settings(app.clone());
    let redcell = settings.redcell_dir.clone();
    if redcell.trim().is_empty() || !Path::new(&redcell).join("src/cli.ts").exists() {
        return Err(format!(
            "redcell 경로를 찾을 수 없습니다: '{redcell}'. 설정(⚙)에서 redcell_dir 을 지정하세요."
        ));
    }

    // 이 앱은 **prime-agent(pi) 전용 셸**이다 — 대상 URL/호스트를 위에 넣고, 우측 패널에서
    // 지시를 내리면 pi 가 대화를 이어가며 수행한다(해킹 전용 엔진 분기는 사용하지 않는다 —
    // 범용 지시가 더 잘 동작하므로). 인가 확장은 -e 로 명시 로드된다.
    return run_prime(&app, &id, &s, &settings, &redcell, &provider);
}
/// 실행 중지 — 등록된 redcell 자식 프로세스를 kill 하고 상태를 stopped 로 마감한다.
#[tauri::command]
fn stop_engagement(app: AppHandle, id: String) -> Result<(), String> {
    let removed = app.state::<Procs>().0.lock().unwrap().remove(&id);
    let mut child = removed.ok_or("실행 중인 세션이 아닙니다")?;
    let _ = child.kill();
    let _ = child.wait();

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

/// host 를 DNS 해석해 나온 IP 를 인가 목록에 추가한다. 반환: (새로 추가한 IP, 이미 있던 IP).
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
            delete_session,
            append_chat,
            start_engagement,
            stop_engagement,
            list_auth,
            add_auth,
            remove_auth,
            auth_ensure,
            get_providers,
            test_provider
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
        sync_pi_models_json_at(&path, "custom", "http://llm.corp.lge:8080/v1", "sk-test", "my-model").unwrap();
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
        // 두 번째 호출: 같은 모델 중복 없음 + 새 모델 추가.
        sync_pi_models_json_at(&path, "custom", "http://llm.corp.lge:8080/v1", "sk-test", "my-model").unwrap();
        sync_pi_models_json_at(&path, "custom", "http://llm.corp.lge:8080/v1", "sk-test", "second-model").unwrap();
        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let models = root["providers"]["custom"]["models"].as_array().unwrap();
        assert_eq!(models.len(), 2, "모델은 업서트(중복 없이 2개)여야 한다: {models:?}");
        assert_eq!(models[1]["id"], "second-model");
        // 모델 없는 새 프로바이더는 오류.
        let err = sync_pi_models_json_at(&path, "ollama", "http://localhost:11434/v1", "x", "").unwrap_err();
        assert!(err.contains("모델"), "모델 미지정 시 안내 오류: {err}");
        // 키 미설정이어도 placeholder 로 프로바이더가 살아남는다.
        sync_pi_models_json_at(&path, "ollama", "http://localhost:11434/v1", "", "llama3.1").unwrap();
        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(root["providers"]["ollama"]["apiKey"], "redcell-placeholder");
        assert_eq!(root["providers"]["ollama"]["models"][0]["id"], "llama3.1");
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
}
