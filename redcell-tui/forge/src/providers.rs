//! LLM 프로바이더 — redcell 저장소(`~/.redcell/*.json`)와 공유.
//!
//! 지원 형태:
//!   - anthropic  : Anthropic Messages API (`/v1/messages`)
//!   - openai-compat: OpenAI 호환 Chat Completions (`/v1/chat/completions`)
//!
//! 키 해석 순서: `envKeys` 의 env var → 저장된 `api_key` → (openai-compat 는 키 없이도 사용 가능).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// redcell 홈 디렉터리 (`REDCELL_HOME` 우선).
pub fn redcell_home() -> PathBuf {
    std::env::var_os("REDCELL_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".redcell")
        })
}

/// 프로바이더 목록 항목.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSpec {
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default)]
    pub env_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedcellConfig {
    #[serde(default)]
    pub default_provider: Option<String>,
    #[serde(default)]
    pub default_model: Option<String>,
}

/// 연결된 프로바이더 목록 (키 존재 여부 포함).
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    pub name: String,
    pub kind: String,
    pub base_url: Option<String>,
    pub default_model: Option<String>,
    pub has_key: bool,
}

/// 설정 파일 로드.
pub fn load_config() -> RedcellConfig {
    std::fs::read_to_string(redcell_home().join("config.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// 사용자 정의 프로바이더 로드.
pub fn load_specs() -> Vec<ProviderSpec> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct File {
        #[serde(default)]
        providers: Vec<ProviderSpec>,
    }
    std::fs::read_to_string(redcell_home().join("providers.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<File>(&t).ok())
        .map(|f| f.providers)
        .unwrap_or_default()
}

/// 프로바이더 목록 + 키 존재 여부.
pub fn list() -> Vec<ProviderInfo> {
    let specs = load_specs();
    let mut out: Vec<ProviderInfo> = specs
        .iter()
        .map(|s| ProviderInfo {
            name: s.name.clone(),
            kind: if s.kind.is_empty() { "openai-compat".into() } else { s.kind.clone() },
            base_url: s.base_url.clone(),
            default_model: s.default_model.clone(),
            has_key: resolve_key(s).is_some(),
        })
        .collect();
    // 내장 프로바이더 (저장소 등록이 없어도 env 키만으로 쓸 수 있다).
    if !out.iter().any(|p| p.name == "anthropic") {
        out.insert(0, ProviderInfo {
            name: "anthropic".into(),
            kind: "anthropic".into(),
            base_url: Some("https://api.anthropic.com".into()),
            default_model: None,
            has_key: std::env::var("ANTHROPIC_API_KEY").is_ok(),
        });
    }
    out
}

/// 프로바이더 이름으로 스펙 해석.
pub fn find(name: &str) -> Option<ProviderSpec> {
    load_specs().into_iter().find(|s| s.name == name)
}

/// 저장소 기본 프로바이더/모델.
pub fn default_pair() -> Option<(String, String)> {
    let cfg = load_config();
    let name = cfg.default_provider?;
    let spec = find(&name)?;
    let model = cfg.default_model.or(spec.default_model.clone())?;
    Some((name, model))
}

/// API 키 해석 — env 우선, 그다음 저장된 키.
pub fn resolve_key(spec: &ProviderSpec) -> Option<String> {
    for env in &spec.env_keys {
        if let Ok(v) = std::env::var(env) {
            if !v.trim().is_empty() {
                return Some(v);
            }
        }
    }
    if let Some(k) = &spec.api_key {
        if !k.trim().is_empty() {
            return Some(k.trim().to_string());
        }
    }
    None
}

/// 요청에 사용할 확정된 프로바이더 설정.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub kind: String,
    pub base_url: String,
    pub api_key: Option<String>,
    pub model: String,
    pub name: String,
}

/// 프로바이더 + 모델 확정.
pub fn resolve(name: &str, model: Option<&str>) -> Option<Resolved> {
    let specs = load_specs();
    let spec = specs.iter().find(|s| s.name == name).cloned().unwrap_or(ProviderSpec {
        name: name.to_string(),
        kind: if name == "anthropic" { "anthropic".into() } else { "openai-compat".into() },
        base_url: None,
        env_keys: default_env_keys(name),
        api_key: None,
        auth_type: None,
        default_model: None,
    });

    let kind = if spec.kind.is_empty() {
        if name.contains("anthropic") || name.contains("claude") { "anthropic".into() } else { "openai-compat".into() }
    } else {
        spec.kind.clone()
    };
    let base_url = spec
        .base_url
        .clone()
        .or_else(|| match kind.as_str() {
            "anthropic" => Some("https://api.anthropic.com".to_string()),
            _ => None,
        })
        .unwrap_or_default();
    let model = model
        .map(str::to_string)
        .or(spec.default_model.clone())
        .or_else(|| default_model_for(&kind).map(str::to_string))
        .unwrap_or_default();
    let api_key = resolve_key(&spec);
    Some(Resolved { kind, base_url, api_key, model, name: spec.name })
}

fn default_env_keys(name: &str) -> Vec<String> {
    match name {
        "anthropic" => vec!["ANTHROPIC_API_KEY".into()],
        "openai" => vec!["OPENAI_API_KEY".into()],
        "openrouter" => vec!["OPENROUTER_API_KEY".into()],
        "groq" => vec!["GROQ_API_KEY".into()],
        "together" => vec!["TOGETHER_API_KEY".into()],
        "deepseek" => vec!["DEEPSEEK_API_KEY".into()],
        "gemini" => vec!["GEMINI_API_KEY".into(), "GOOGLE_API_KEY".into()],
        "ollama" => vec!["OLLAMA_API_KEY".into()],
        _ => vec![format!("{}_API_KEY", name.to_uppercase().replace('-', "_"))],
    }
}

fn default_model_for(kind: &str) -> Option<&'static str> {
    match kind {
        "anthropic" => Some("claude-sonnet-4-5"),
        _ => None,
    }
}

/// 저장된 API 키를 마스킹한 형태로 (TUI 표시용).
pub fn mask(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() <= 8 {
        "•".repeat(chars.len())
    } else {
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{head}{}{tail}", "•".repeat(chars.len() - 8))
    }
}

/// 헤더 맵 (표시/디버그용).
pub fn header_preview(spec: &ProviderSpec) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Some(k) = resolve_key(spec) {
        map.insert("Authorization".into(), mask(&k));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_keys() {
        assert_eq!(mask("abcd1234efgh5678"), "abcd••••••••efgh5678".replace("efgh5678", "5678"));
        assert_eq!(mask("short"), "•••••");
    }

    #[test]
    fn resolves_builtin_anthropic() {
        let r = resolve("anthropic", Some("claude-sonnet-4-5")).unwrap();
        assert_eq!(r.kind, "anthropic");
        assert_eq!(r.base_url, "https://api.anthropic.com");
        assert_eq!(r.model, "claude-sonnet-4-5");
    }
}
