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
    "tools".into()
}
fn status_idle() -> String {
    "idle".into()
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct Settings {
    #[serde(default)]
    redcell_dir: String,
    #[serde(default)]
    auth_path: String,
    #[serde(default)]
    default_provider: String,
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

/// 세션 실행 — redcell CLI 를 --ndjson 으로 스폰하고 이벤트를 스트리밍한다.
/// 즉시 반환하며, 진행은 `engagement-event` / `engagement-status` 이벤트로 전달된다.
#[tauri::command]
fn start_engagement(app: AppHandle, id: String) -> Result<(), String> {
    let s = read_session(&app, &id).ok_or("세션을 찾을 수 없습니다")?;
    if s.status == "running" {
        return Err("이미 실행 중인 세션입니다".into());
    }
    let settings = get_settings(app.clone());
    let redcell = settings.redcell_dir.clone();
    if redcell.trim().is_empty() || !Path::new(&redcell).join("src/cli.ts").exists() {
        return Err(format!(
            "redcell 경로를 찾을 수 없습니다: '{redcell}'. 설정(⚙)에서 redcell_dir 을 지정하세요."
        ));
    }

    let provider = if s.provider.trim().is_empty() {
        "mock".to_string()
    } else {
        s.provider.clone()
    };
    // mode 에 따라 서브커맨드 선택: python → absolute-agent(RLM, 코드 작성→실행 반복),
    // 그 외 → 고정 툴박스 오케스트레이터.
    let subcommand = if s.mode == "python" { "pyrun" } else { "run" };
    let mut args: Vec<String> = vec![
        "tsx".into(),
        "src/cli.ts".into(),
        subcommand.into(),
        "--host".into(),
        s.host.clone(),
        "--provider".into(),
        provider,
        "--ndjson".into(),
    ];
    if let Some(p) = s.port {
        args.push("--port".into());
        args.push(p.to_string());
    }
    if !s.goal.trim().is_empty() {
        args.push("--goal".into());
        args.push(s.goal.clone());
    }
    if !settings.auth_path.trim().is_empty() {
        args.push("--auth".into());
        args.push(settings.auth_path.clone());
    }

    let mut child = Command::new("npx")
        .current_dir(&redcell)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("redcell 실행 실패 (npx/node 설치 확인): {e}"))?;

    let stdout = child.stdout.take().ok_or("stdout 파이프 실패")?;
    let stderr = child.stderr.take().ok_or("stderr 파이프 실패")?;

    // 자식 프로세스를 레지스트리에 등록(중지 시 kill 대상).
    app.state::<Procs>()
        .0
        .lock()
        .unwrap()
        .insert(id.clone(), child);

    set_status(&app, &id, "running");
    app.emit(
        "engagement-status",
        json!({ "sessionId": id, "status": "running" }),
    )
    .ok();

    // stderr → note 이벤트(모델/스코프 정보 등)
    {
        let app = app.clone();
        let id = id.clone();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if line.trim().is_empty() {
                    continue;
                }
                let ev = json!({ "type": "note", "text": format!("[sys] {line}") });
                let stamped = append_event(&app, &id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped }))
                    .ok();
            }
        });
    }

    // stdout → NDJSON 파싱 후 스트리밍
    {
        let app = app.clone();
        let id = id.clone();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let ev: Value = serde_json::from_str(line)
                    .unwrap_or_else(|_| json!({ "type": "note", "text": line }));
                let stamped = append_event(&app, &id, &ev);
                app.emit(
                    "engagement-event",
                    json!({ "sessionId": id, "event": stamped }),
                )
                .ok();
                if ev.get("type").and_then(|t| t.as_str()) == Some("done") {
                    set_status(&app, &id, "done");
                    app.emit(
                        "engagement-status",
                        json!({ "sessionId": id, "status": "done" }),
                    )
                    .ok();
                }
            }
            // 스트림 종료. 레지스트리에서 자식을 회수해 wait 한다.
            // 회수 결과가 None 이면 stop_engagement 가 이미 kill·마감했으므로 관여하지 않는다.
            let removed = app.state::<Procs>().0.lock().unwrap().remove(&id);
            if let Some(mut c) = removed {
                let ok = c.wait().map(|st| st.success()).unwrap_or(false);
                // done 이벤트를 못 받고 종료된 경우 상태 마감.
                if let Some(cur) = read_session(&app, &id) {
                    if cur.status == "running" {
                        let st = if ok { "done" } else { "error" };
                        set_status(&app, &id, st);
                        app.emit(
                            "engagement-status",
                            json!({ "sessionId": id, "status": st }),
                        )
                        .ok();
                    }
                }
            }
        });
    }

    Ok(())
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
#[derive(serde::Serialize)]
struct AuthEnsureResult {
    added: bool,
    existed: bool,
    host: String,
    path: String,
    yaml: bool,
    reason: Option<String>,
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
        });
    }
    if loaded.allows.iter().any(|a| a == &normalized) {
        return Ok(AuthEnsureResult {
            added: false,
            existed: true,
            host: normalized,
            path: loaded.path,
            yaml: false,
            reason: None,
        });
    }
    auth::ensure_allowed(&path, &host)?;
    Ok(AuthEnsureResult {
        added: true,
        existed: false,
        host: normalized,
        path: loaded.path,
        yaml: false,
        reason: None,
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
            delete_session,
            append_chat,
            start_engagement,
            stop_engagement,
            list_auth,
            add_auth,
            remove_auth,
            auth_ensure
        ])
        .run(tauri::generate_context!())
        .expect("RedCell Desktop 실행 중 오류");
}
