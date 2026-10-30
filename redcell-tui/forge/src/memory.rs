//! 스킬 메모리 — "이 대상 지문에서 뭐가 먹혔는가"를 누적한다.
//!
//! 성공한 전술은 지문(fingerprint)별로 기록되고, 다음 자율 라운드에서
//! LLM 프롬프트에 "먼저 시도할 전술"로 주입된다. (자기발전 루프의 기억 계층)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 전술 기록.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tactic {
    /// 대상 지문 키.
    pub fingerprint: String,
    /// 전술 이름 (예: "ID 경계값 스윕").
    pub name: String,
    /// 요약 메모.
    pub note: String,
    /// 시도 횟수.
    pub attempts: u32,
    /// 성공 횟수.
    pub successes: u32,
    /// 마지막 갱신 시각 (ISO8601).
    pub updated: String,
}

impl Tactic {
    /// 성공률 (Laplace 평활).
    pub fn score(&self) -> f64 {
        (self.successes as f64 + 1.0) / (self.attempts as f64 + 2.0)
    }
}

/// 기억 저장소.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Memory {
    #[serde(default)]
    pub tactics: Vec<Tactic>,
}

/// 메모리 파일 경로.
pub fn memory_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".local/share")
        });
    base.join("forge/memory.json")
}

/// 로드 (없으면 빈 기억).
pub fn load() -> Memory {
    std::fs::read_to_string(memory_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// 저장 (원자적 치환).
pub fn save(mem: &Memory) -> Result<(), String> {
    let path = memory_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(mem).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
}

/// 전술 기록/갱신.
pub fn record(mem: &mut Memory, fingerprint: &str, name: &str, note: &str, success: bool) {
    let now = chrono::Local::now().to_rfc3339();
    if let Some(t) = mem.tactics.iter_mut().find(|t| t.fingerprint == fingerprint && t.name == name) {
        t.attempts += 1;
        if success {
            t.successes += 1;
        }
        if !note.is_empty() {
            t.note = note.to_string();
        }
        t.updated = now;
        return;
    }
    mem.tactics.push(Tactic {
        fingerprint: fingerprint.to_string(),
        name: name.to_string(),
        note: note.to_string(),
        attempts: 1,
        successes: u32::from(success),
        updated: now,
    });
}

/// 지문에 맞는 전술 recall — 성공률 순.
pub fn recall(mem: &Memory, fingerprint: &str, limit: usize) -> Vec<Tactic> {
    let mut hits: Vec<Tactic> = mem
        .tactics
        .iter()
        .filter(|t| t.fingerprint == fingerprint)
        .cloned()
        .collect();
    hits.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap_or(std::cmp::Ordering::Equal));
    hits.truncate(limit);
    hits
}

/// 프롬프트에 붙일 요약.
pub fn prompt_hint(mem: &Memory, fingerprint: &str) -> String {
    let hits = recall(mem, fingerprint, 5);
    if hits.is_empty() {
        return String::new();
    }
    let mut out = String::from("[이 대상 지문에서 이미 시도한 전술 — 먼저 재사용]\n");
    for t in hits {
        out.push_str(&format!(
            "- {} (성공 {} / 시도 {}, 성공률 {:.0}%)\n",
            t.name,
            t.successes,
            t.attempts,
            t.score() * 100.0
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_recalls() {
        let mut mem = Memory::default();
        record(&mut mem, "nginx|django", "idor 스윕", "user_id 경계값", true);
        record(&mut mem, "nginx|django", "idor 스윕", "", true);
        record(&mut mem, "nginx|django", "cmdi", "", false);
        let hits = recall(&mem, "nginx|django", 5);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].name, "idor 스윕");
        assert!(hits[0].score() > hits[1].score());
        assert!(prompt_hint(&mem, "nginx|django").contains("idor 스윕"));
    }
}
