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
    "mock".into()
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
            "mock".into()
        } else {
            provider
        },
        mode: match mode {
            Some(m) if !m.trim().is_empty() => m,
            _ => default_mode(),
        },
        max: max.unwrap_or(false),
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

/// 저장된 연결 정보를 자식 프로세스 환경변수로 주입한다.
/// (Windows 사용자는 시스템 환경변수를 직접 다루기 어려우므로 앱이 대신 처리)
fn inject_provider_env(cmd: &mut Command, provider: &str, conn: &ProviderConn) {
    if let Some(p) = PROVIDER_CATALOG.iter().find(|p| p.name == provider) {
        if !conn.api_key.trim().is_empty() {
            if let Some(k) = p.env_keys.last() {
                // 마지막 env 슬롯에 주입(앞쪽 OAUTH 등 실제 설정 env 가 있으면 그게 우선)
                cmd.env(k, conn.api_key.trim());
            }
        }
        if provider == "custom" && !conn.base_url.trim().is_empty() {
            cmd.env("REDCELL_OPENAI_BASE_URL", conn.base_url.trim());
        }
    }
    if !conn.model.trim().is_empty() {
        cmd.env("REDCELL_MODEL", conn.model.trim()); // 모든 프로바이더 공통 모델 지정
    }
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
/// pi CLI(prime-agent) 경로 탐색. 우선순위:
///   1) PI_PACKAGE_DIR 환경변수
///   2) redcell_dir/node_modules (로컬 설치)
///   3) APPDATA/npm (Windows), nvm($HOME/.nvm/versions/node/*), pnpm($HOME/.local/share/...),
///      bun($HOME/.bun/install/global), 시스템 위치(/usr·/usr/local·/opt/homebrew)
///   4) 마지막 보루: `npm root -g` 실행 결과(어느 패키지 매니저로 전역 설치됐든 찾는다)
fn prime_cli_path(redcell_dir: &str) -> Option<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Some(d) = std::env::var_os("PI_PACKAGE_DIR") {
        cands.push(PathBuf::from(d).join("dist").join("cli.js"));
    }
    cands.push(
        PathBuf::from(redcell_dir)
            .join("node_modules")
            .join("@earendil-works")
            .join("pi-coding-agent")
            .join("dist")
            .join("cli.js"),
    );
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
    // nvm: $HOME/.nvm/versions/node/<version>/lib/node_modules/...
    // 전역 설치가 흔한 곳(스캔은 존재하는 디렉터리만).
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        let nvm_versions = home.join(".nvm").join("versions").join("node");
        if let Ok(entries) = std::fs::read_dir(&nvm_versions) {
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
        // pnpm 전역 스토어: ~/.local/share/pnpm((/pnpm)? global/<ver>/node_modules ...)
        let pnpm_base = home.join(".local").join("share").join("pnpm");
        if let Ok(entries) = std::fs::read_dir(&pnpm_base) {
            for e in entries.flatten() {
                for sub in [e.path(), e.path().join("pnpm")] {
                    if sub.is_dir() {
                        if let Ok(children) = std::fs::read_dir(&sub) {
                            for c in children.flatten() {
                                cands.push(
                                    c.path()
                                        .join("node_modules")
                                        .join("@earendil-works")
                                        .join("pi-coding-agent")
                                        .join("dist")
                                        .join("cli.js"),
                                );
                            }
                        }
                    }
                }
            }
        }
        // bun 전역: ~/.bun/install/global/node_modules
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
    for p in [
        "/usr/lib/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
        "/usr/local/lib/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
        "/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
    ] {
        cands.push(PathBuf::from(p));
    }
    // 우선순위 순서대로 존재 확인.
    if let Some(found) = cands.into_iter().find(|p| p.is_file()) {
        return Some(found);
    }
    // 마지막 보루: npm root -g (네트워크 없음, ~100ms). 실패하면 None.
    let out = Command::new("npm")
        .args(["root", "-g"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    out.and_then(|root| {
        let p = PathBuf::from(root)
            .join("@earendil-works")
            .join("pi-coding-agent")
            .join("dist")
            .join("cli.js");
        p.is_file().then_some(p)
    })
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
    let cli = prime_cli_path(redcell).ok_or(
        "prime-agent(pi) 를 찾을 수 없습니다 — `npm i -g @earendil-works/pi-coding-agent` 후 재시도 (또는 PI_PACKAGE_DIR 설정). nvm/pnpm/bun 전역 설치와 `npm root -g` 까지 자동 탐색합니다.".to_string(),
    )?;

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
        goal = "아래 사이트를 샅샅이 살펴보고 유용한 정보·정리된 자료를 찾아 정리해줘.".to_string();
    }
    let instruction = if s2.host.trim().is_empty() {
        // 대상 미지정: 순수 pi CLI 대화(인가 게이트는 대상 없는 로컬 작업만 통과).
        goal
    } else {
        let https_hint = match port {
            Some(p) if p != 443 && p != 8443 => format!("https://{}:{}/ 로도 접속을 시도해볼 것(둘 다 확인).", s2.host, p),
            _ => String::new(),
        };
        format!(
            "{goal}\n\n대상 사이트(인가됨): {target}\n{https_hint}\n인가 목록에 있는 대상이므로 필요한 만큼 자유롭게 조사·탐색하고 결과를 정리해줘."
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
    if provider != "custom" {
        if let Some(m) = settings.providers.get(provider).and_then(|c| {
            let m = c.model.trim();
            if m.is_empty() {
                None
            } else {
                Some(format!("{provider}/{m}"))
            }
        }) {
            args.push("--model".into());
            args.push(m);
        }
    }

    {
        let ev = json!({ "type": "note", "text": format!("[sys] prime-agent(pi) 턴 — session {piq}: node {} {}…", cli.display(), args.get(5).map(|a| a.chars().take(60).collect::<String>()).unwrap_or_default()) });
        let stamped = append_event(app, id, &ev);
        app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    }

    let mut cmd = Command::new("node");
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
                                if !buf.trim().is_empty() {
                                    let ev2 = json!({ "type": "note", "text": buf.trim().to_string() });
                                    let stamped = append_event(&app, &id, &ev2);
                                    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
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
                                            if !t.trim().is_empty() {
                                                let ev2 = json!({ "type": "note", "text": t.trim().to_string() });
                                                let stamped = append_event(&app, &id, &ev2);
                                                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
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
    #[test]
    fn prime_cli_path_finds_pi_installation() {
        let redcell = std::env::current_dir()
            .unwrap()
            .ancestors()
            .find(|p| p.join("src").join("cli.ts").exists())
            .map(|p| p.to_path_buf())
            .or_else(|| std::env::var("REDCELL_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/opt/workspace/local/bsh/workspace/absolute-agent/redcell"));
        let found = prime_cli_path(&redcell.to_string_lossy());
        assert!(found.is_some(), "pi CLI 를 찾아야 한다 (nvm/pnpm/bun/npm root -g 탐색)");
        let p = found.unwrap();
        assert!(p.is_file(), "찾은 경로가 실제 파일이어야 한다: {p:?}");
        assert!(p.to_string_lossy().contains("pi-coding-agent"), "pi-coding-agent 경로여야 한다: {p:?}");
    }
}
