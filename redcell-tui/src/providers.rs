//! LLM 연결 — redcell TS CLI 와 동일한 저장소를 읽고 쓴다.
//!
//! - `$REDCELL_HOME/config.json` (기본 `~/.redcell/config.json`): 기본 프로바이더·모델
//! - `$REDCELL_HOME/providers.json`: 사용자 정의(키·baseUrl·모델) — env 보다 후순위
//! - 자격증명 해석: envKeys 순서대로 env 탐색 → 없으면 저장된 키 → ollama 류는 키 불필요
//! - 인증 방식: API 키 / OAuth 토큰 구분 저장 (`authType`, TS ProviderSpec 과 동일)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

pub fn redcell_home() -> PathBuf {
    std::env::var_os("REDCELL_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::session::home_dir().join(".redcell"))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedcellConfig {
    #[serde(default)]
    pub default_provider: Option<String>,
    #[serde(default)]
    pub default_model: Option<String>,
    #[serde(default)]
    pub auth_path: Option<String>,
}

pub fn load_config() -> RedcellConfig {
    std::fs::read_to_string(redcell_home().join("config.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save_config(cfg: &RedcellConfig) -> Result<(), String> {
    std::fs::create_dir_all(redcell_home()).map_err(|e| e.to_string())?;
    let txt = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    std::fs::write(redcell_home().join("config.json"), txt + "\n").map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomSpec {
    pub name: String,
    #[serde(default)]
    pub kind: String, // anthropic | openai-compat
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default)]
    pub env_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// 저장된 자격증명 종류: "api_key"(기본) | "oauth" — TS 와 동일 규격.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl CustomSpec {
    pub fn is_oauth(&self) -> bool {
        self.auth_type.as_deref().map(str::trim) == Some("oauth")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CustomFile {
    #[serde(default)]
    providers: Vec<CustomSpec>,
}

pub fn load_customs() -> Vec<CustomSpec> {
    std::fs::read_to_string(redcell_home().join("providers.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<CustomFile>(&t).ok())
        .map(|f| f.providers)
        .unwrap_or_default()
}

/// upsert — 동명 항목이 있으면 병합(빈 값은 기존 유지), 없으면 추가.
pub fn upsert_custom(spec: CustomSpec) -> Result<(), String> {
    if spec.name.trim().is_empty() {
        return Err("프로바이더 이름이 비어 있습니다.".into());
    }
    if spec.kind == "openai-compat" {
        match spec.base_url.as_deref().map(str::trim) {
            Some(b) if b.starts_with("http://") || b.starts_with("https://") => {}
            _ => return Err("openai-compat 는 baseUrl(http(s)://)이 필수입니다.".into()),
        }
    }
    let mut file = CustomFile { providers: load_customs() };
    if let Some(cur) = file.providers.iter_mut().find(|p| p.name == spec.name) {
        if !spec.kind.is_empty() {
            cur.kind = spec.kind.clone();
        }
        if let Some(b) = spec.base_url.clone().filter(|b| !b.trim().is_empty()) {
            cur.base_url = Some(b);
        }
        if !spec.env_keys.is_empty() {
            cur.env_keys = spec.env_keys.clone();
        }
        if let Some(k) = spec.api_key.clone().filter(|k| !k.trim().is_empty()) {
            cur.api_key = Some(k);
        }
        if let Some(t) = spec.auth_type.clone().filter(|t| !t.trim().is_empty()) {
            cur.auth_type = Some(t);
        }
        if let Some(m) = spec.default_model.clone().filter(|m| !m.trim().is_empty()) {
            cur.default_model = Some(m);
        }
        if spec.note.is_some() {
            cur.note = spec.note.clone();
        }
    } else {
        file.providers.push(spec);
    }
    write_custom_file(&file)
}

pub fn remove_custom(name: &str) -> Result<bool, String> {
    let mut file = CustomFile { providers: load_customs() };
    let before = file.providers.len();
    file.providers.retain(|p| p.name != name);
    if file.providers.len() == before {
        return Ok(false);
    }
    write_custom_file(&file)?;
    Ok(true)
}

/// providers.json 저장 — API 키가 들어가므로 temp(0600) 기록 후 원자적 치환.
/// (기존은 기본 권한으로 쓴 뒤 chmod 했으므로 노출 창이 있었다)
fn write_custom_file(file: &CustomFile) -> Result<(), String> {
    let txt = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    crate::session::write_private(&redcell_home().join("providers.json"), &(txt + "\n"))
}

/// 빌트인 카탈로그 미러 (redcell/src/providers/registry.ts 와 동일).
pub struct Builtin {
    pub name: &'static str,
    pub kind: &'static str,
    pub env_keys: &'static [&'static str],
    pub base_url: Option<&'static str>,
    pub default_model: Option<&'static str>,
    pub note: Option<&'static str>,
}

pub const BUILTINS: &[Builtin] = &[
    Builtin { name: "anthropic", kind: "anthropic", env_keys: &["ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_API_KEY"], base_url: None, default_model: Some("claude-opus-5"), note: Some("공식 Anthropic SDK") },
    Builtin { name: "openai", kind: "openai-compat", env_keys: &["OPENAI_API_KEY"], base_url: Some("https://api.openai.com/v1"), default_model: Some("gpt-5.4"), note: None },
    Builtin { name: "openrouter", kind: "openai-compat", env_keys: &["OPENROUTER_API_KEY"], base_url: Some("https://openrouter.ai/api/v1"), default_model: Some("moonshotai/kimi-k2.6"), note: None },
    Builtin { name: "prime-inference", kind: "openai-compat", env_keys: &["PRIME_API_KEY"], base_url: Some("https://api.pinference.ai/api/v1"), default_model: Some("z-ai/glm-5.2"), note: Some("Prime Intellect inference") },
    Builtin { name: "agnes", kind: "openai-compat", env_keys: &["AGNES_API_KEY"], base_url: Some("https://apihub.agnes-ai.com/v1"), default_model: Some("agnes-3.0-flash"), note: Some("Agnes AI") },
    Builtin { name: "groq", kind: "openai-compat", env_keys: &["GROQ_API_KEY"], base_url: Some("https://api.groq.com/openai/v1"), default_model: Some("openai/gpt-oss-120b"), note: None },
    Builtin { name: "cerebras", kind: "openai-compat", env_keys: &["CEREBRAS_API_KEY"], base_url: Some("https://api.cerebras.ai/v1"), default_model: Some("gpt-oss-120b"), note: None },
    Builtin { name: "xai", kind: "openai-compat", env_keys: &["XAI_API_KEY"], base_url: Some("https://api.x.ai/v1"), default_model: Some("grok-4.20-0309-reasoning"), note: None },
    Builtin { name: "deepseek", kind: "openai-compat", env_keys: &["DEEPSEEK_API_KEY"], base_url: Some("https://api.deepseek.com"), default_model: Some("deepseek-v4-pro"), note: None },
    Builtin { name: "mistral", kind: "openai-compat", env_keys: &["MISTRAL_API_KEY"], base_url: Some("https://api.mistral.ai/v1"), default_model: Some("devstral-medium-latest"), note: None },
    Builtin { name: "moonshotai", kind: "openai-compat", env_keys: &["MOONSHOT_API_KEY"], base_url: Some("https://api.moonshot.ai/v1"), default_model: Some("kimi-k2.6"), note: None },
    Builtin { name: "zai", kind: "openai-compat", env_keys: &["ZAI_API_KEY"], base_url: Some("https://api.z.ai/api/coding/paas/v4"), default_model: Some("glm-5.1"), note: None },
    Builtin { name: "ollama", kind: "openai-compat", env_keys: &[], base_url: Some("http://localhost:11434/v1"), default_model: None, note: Some("로컬. 모델 지정 필요") },
    Builtin { name: "custom", kind: "openai-compat", env_keys: &["REDCELL_OPENAI_API_KEY"], base_url: None, default_model: None, note: Some("REDCELL_OPENAI_BASE_URL 로 임의 엔드포인트") },
];

pub struct ProviderView {
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub model: String,
    /// ready 원인: env:KEY | 저장된 키/OAuth | 키 불필요 | 필요: ...
    pub ready: String,
    pub connected: bool,
    /// agent 실행 가능 여부 — 연결 + 모델 + (openai-compat 면 baseUrl).
    pub usable: bool,
    pub custom: bool,
}

/// 병합 뷰 — 빌트인 + 사용자 정의(custom 우선) + 연결 상태.
pub fn merged_view() -> Vec<ProviderView> {
    let customs: HashMap<String, CustomSpec> =
        load_customs().into_iter().map(|c| (c.name.clone(), c)).collect();
    // 모델 폴백: config 기본 모델 → REDCELL_MODEL (TS resolveModel 과 동일).
    let cfg = load_config();
    let model_fb = cfg
        .default_model
        .filter(|m| !m.trim().is_empty())
        .or_else(|| std::env::var("REDCELL_MODEL").ok().filter(|m| !m.trim().is_empty()));
    let mut out = Vec::new();
    for b in BUILTINS {
        let c = customs.get(b.name);
        let mut base_url = c
            .and_then(|x| x.base_url.clone())
            .or_else(|| b.base_url.map(|s| s.to_string()))
            .unwrap_or_default();
        if base_url.trim().is_empty() && b.name == "custom" {
            // 익명 custom 은 env 로 base URL 을 받는다 (TS 와 동일).
            base_url = std::env::var("REDCELL_OPENAI_BASE_URL").unwrap_or_default();
        }
        let model = c
            .and_then(|x| x.default_model.clone())
            .or_else(|| b.default_model.map(|s| s.to_string()))
            .or_else(|| model_fb.clone())
            .unwrap_or_default();
        let env_keys: Vec<String> = c
            .map(|x| x.env_keys.clone())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| b.env_keys.iter().map(|s| s.to_string()).collect());
        let oauth = c.map(|x| x.is_oauth()).unwrap_or(false);
        let (ready, connected) = credential_state(&env_keys, c.and_then(|x| x.api_key.clone()), oauth);
        let kind = c.map(|x| x.kind.clone()).filter(|k| !k.is_empty()).unwrap_or_else(|| b.kind.to_string());
        let usable = connected && !model.trim().is_empty() && (kind != "openai-compat" || !base_url.trim().is_empty());
        out.push(ProviderView {
            name: b.name.to_string(),
            kind,
            base_url,
            model,
            ready,
            connected,
            usable,
            custom: c.is_some(),
        });
    }
    // 빌트인에 없는 순수 custom.
    for (name, c) in customs.iter().filter(|(n, _)| !BUILTINS.iter().any(|b| b.name == n.as_str())) {
        let oauth = c.is_oauth();
        let (ready, connected) = credential_state(&c.env_keys, c.api_key.clone(), oauth);
        let kind = if c.kind.is_empty() { "openai-compat".into() } else { c.kind.clone() };
        let model = c.default_model.clone().or_else(|| model_fb.clone()).unwrap_or_default();
        let base_url = c.base_url.clone().unwrap_or_default();
        let usable = connected && !model.trim().is_empty() && (kind != "openai-compat" || !base_url.trim().is_empty());
        out.push(ProviderView {
            name: name.clone(),
            kind,
            base_url,
            model,
            ready,
            connected,
            usable,
            custom: true,
        });
    }
    out.sort_by(|a, b| {
        b.usable.cmp(&a.usable).then(b.connected.cmp(&a.connected)).then(a.name.cmp(&b.name))
    });
    out
}

/// 첫 실행 온보딩이 필요한가 — agent 실행 가능한 프로바이더가 하나도 없으면 true.
pub fn needs_setup() -> bool {
    !merged_view().iter().any(|v| v.usable)
}

fn credential_state(env_keys: &[String], stored: Option<String>, stored_oauth: bool) -> (String, bool) {
    if env_keys.is_empty() && stored.as_deref().map(str::trim).filter(|s| !s.is_empty()).is_none() {
        return ("키 불필요".to_string(), true); // 로컬 등
    }
    for k in env_keys {
        if std::env::var_os(k).map(|v| !v.is_empty()).unwrap_or(false) {
            return (format!("env:{k}"), true);
        }
    }
    if stored.as_deref().map(str::trim).filter(|s| !s.is_empty()).is_some() {
        return if stored_oauth { ("저장된 OAuth".to_string(), true) } else { ("저장된 키".to_string(), true) };
    }
    if env_keys.is_empty() {
        ("키 불필요".to_string(), true)
    } else {
        (format!("필요: {}", env_keys.join("·")), false)
    }
}

// ── pi-agent 가져오기 ──────────────────────────────────────────────────────────

/// pi-agent 자격증명 파일 (~/.pi/agent/auth.json).
pub fn pi_auth_path() -> PathBuf {
    crate::session::home_dir().join(".pi").join("agent").join("auth.json")
}

/// 파싱된 pi 자격증명: (키, auth_type "api_key"|"oauth").
pub fn parse_pi_auth_json(text: &str, name: &str) -> Option<(String, String)> {
    let root: serde_json::Value = serde_json::from_str(text).ok()?;
    let e = root.get(name)?;
    let typ = e.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let non_empty = |v: Option<&serde_json::Value>| {
        v.and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(|s| s.to_string())
    };
    if typ == "api_key" {
        return non_empty(e.get("key")).map(|k| (k, "api_key".to_string()));
    }
    for f in ["accessToken", "access_token", "token", "apiKey", "key"] {
        if let Some(k) = non_empty(e.get(f)) {
            return Some((k, "oauth".to_string()));
        }
    }
    None
}

pub fn read_pi_auth(name: &str) -> Option<(String, String)> {
    let text = std::fs::read_to_string(pi_auth_path()).ok()?;
    parse_pi_auth_json(&text, name)
}

// ── 키 검증 (best-effort) ──────────────────────────────────────────────────────

/// GET {base}/models 로 키를 확인한다. 성공이면 None, 아니면 경고 문구.
/// 저장 자체를 막지 않는다(오프라인·방화벽에서도 설정 가능해야 함).
pub fn verify_key(kind: &str, base_url: &str, key: &str, auth_type: &str) -> Option<String> {
    if kind == "anthropic" && auth_type.trim() == "oauth" {
        return None; // OAuth 는 agent 실행 시 검증
    }
    // 커스텀 baseUrl 우선 — anthropic 도 프록시/게이트웨이를 쓸 수 있다.
    let custom = base_url.trim().trim_end_matches('/');
    let url = if !custom.is_empty() {
        // 평문 http 로 API 키를 보내는 것은 루프백(로컬 LLM 게이트웨이) 외 금지.
        if custom.starts_with("http://") && !is_loopback_base(custom) {
            return Some("평문 http baseUrl 은 지원하지 않습니다 — https 를 쓰거나 로컬(localhost/127.0.0.1) 엔드포인트를 지정하세요.".to_string());
        }
        if kind == "anthropic" && !custom.ends_with("/v1") {
            format!("{custom}/v1/models")
        } else {
            format!("{custom}/models")
        }
    } else if kind == "anthropic" {
        "https://api.anthropic.com/v1/models".to_string()
    } else {
        return Some("baseUrl 없음 — 검증 생략".to_string());
    };
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(8))
        .timeout_read(std::time::Duration::from_secs(8))
        .redirects(0)
        .build();
    let mut req = agent.get(&url);
    if kind == "anthropic" {
        req = req.set("x-api-key", key).set("anthropic-version", "2023-06-01");
    } else {
        req = req.set("authorization", &format!("Bearer {key}"));
    }
    match req.call() {
        Ok(_) => None,
        Err(ureq::Error::Status(401, _) | ureq::Error::Status(403, _)) => {
            Some("인증 거부됨(HTTP 401/403) — 키를 확인하세요".to_string())
        }
        Err(ureq::Error::Status(code, _)) => Some(format!("서버 응답 HTTP {code} — 키는 저장됩니다")),
        Err(_) => Some("연결 실패(네트워크·시간초과) — 키는 저장됩니다".to_string()),
    }
}

/// http baseUrl 이 루프백(localhost·127.x·[::1]) 인지 — 로컬 LLM 게이트웨이 허용용.
fn is_loopback_base(base: &str) -> bool {
    let rest = base.strip_prefix("http://").unwrap_or(base);
    let hostport = rest.split('/').next().unwrap_or("");
    let host = if hostport.starts_with('[') {
        hostport.split(']').next().unwrap_or("").trim_start_matches('[')
    } else if let Some((h, _p)) = hostport.rsplit_once(':') {
        h
    } else {
        hostport
    };
    let h = host.trim();
    h.eq_ignore_ascii_case("localhost") || h.starts_with("127.") || h == "::1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_state_shapes() {
        let (r, ok) = credential_state(&[], None, false);
        assert!(ok && r == "키 불필요");
        let (r, ok) = credential_state(&["REDCELL_TUI_NOPE_1".into(), "REDCELL_TUI_NOPE_2".into()], None, false);
        assert!(!ok && r.contains("필요"));
        let (r, ok) = credential_state(&["REDCELL_TUI_NOPE_1".into()], Some("k".into()), false);
        assert!(ok && r == "저장된 키");
        let (r, ok) = credential_state(&["REDCELL_TUI_NOPE_1".into()], Some("t".into()), true);
        assert!(ok && r == "저장된 OAuth");
    }

    #[test]
    fn pi_auth_parses_api_key_and_oauth() {
        let js = r#"{"a":{"type":"api_key","key":"sk-a"},"b":{"type":"oauth","accessToken":"tok-b"},"c":{"type":"other"}}"#;
        assert_eq!(parse_pi_auth_json(js, "a"), Some(("sk-a".into(), "api_key".into())));
        assert_eq!(parse_pi_auth_json(js, "b"), Some(("tok-b".into(), "oauth".into())));
        assert_eq!(parse_pi_auth_json(js, "c"), None);
        assert_eq!(parse_pi_auth_json(js, "zzz"), None);
        assert_eq!(parse_pi_auth_json("{{{", "a"), None);
    }

    #[test]
    fn verify_skips_anthropic_oauth_and_empty_base() {
        assert_eq!(verify_key("anthropic", "", "t", "oauth"), None);
        assert!(verify_key("openai-compat", "", "k", "api_key").is_some());
    }

    #[test]
    fn verify_rejects_cleartext_remote_but_allows_loopback() {
        // 원격 http 로 키를 보내는 검증은 거부.
        assert!(verify_key("openai-compat", "http://api.example.com/v1", "k", "api_key")
            .unwrap()
            .contains("http"));
        // 로컬 게이트웨이는 허용 (네트워크 실패 경고만).
        let msg = verify_key("openai-compat", "http://127.0.0.1:11434/v1", "k", "api_key");
        assert!(msg.is_none() || msg.unwrap().contains("연결 실패"));
        let msg = verify_key("openai-compat", "http://localhost:8080/v1", "k", "api_key");
        assert!(msg.is_none() || msg.unwrap().contains("연결 실패"));
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_base("http://localhost:11434/v1"));
        assert!(is_loopback_base("http://127.0.0.1:8080"));
        assert!(is_loopback_base("http://[::1]:9000/v1"));
        assert!(!is_loopback_base("http://api.example.com/v1"));
        assert!(!is_loopback_base("http://evil.com:11434/v1"));
    }

    #[test]
    fn builtin_catalog_has_core_providers() {
        let names: Vec<&str> = BUILTINS.iter().map(|b| b.name).collect();
        for must in ["anthropic", "openai", "openrouter", "ollama", "custom"] {
            assert!(names.contains(&must), "{names:?}");
        }
    }
}
