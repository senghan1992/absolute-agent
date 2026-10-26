//! TUI 세션 — 데스크톱과 독립 저장소 (`~/.local/share/redcell-tui/sessions/`).

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::engine::probes::ProbeHit;

pub fn data_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|s| !s.is_empty()) {
        return PathBuf::from(xdg).join("redcell-tui");
    }
    home_dir().join(".local").join("share").join("redcell-tui")
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn sessions_dir() -> PathBuf {
    let d = data_dir().join("sessions");
    std::fs::create_dir_all(&d).ok();
    #[cfg(unix)]
    {
        // 세션 파일엔 쿠키·대화·진단 증거가 담긴다 — 디렉터리도 소유자 전용.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).ok();
    }
    d
}

pub fn now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// 민감 파일(세션·프로바이더 키·target-map) 공용 저장 — temp(0600) 기록 후 원자적 치환.
/// 쓰는 순간부터 0600 이므로 세계Readable 노출 창이 없고, 중단돼도 반쯤 쓰인 파일이 남지 않는다.
pub fn write_private(path: &std::path::Path, txt: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).ok();
        }
    }
    let tmp = path.with_extension("tmp");
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        f.write_all(txt.as_bytes()).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).ok();
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, txt).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LineLevel {
    Info,
    Sys,
    Warn,
    Error,
    Chat,
    Agent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    pub ts: String,
    pub tag: String,
    pub text: String,
    pub level: LineLevel,
}

impl LogLine {
    pub fn new(tag: &str, text: String, level: LineLevel) -> Self {
        LogLine { ts: now(), tag: tag.to_string(), text, level }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMsg {
    pub role: String, // user | assistant | system
    pub content: String,
    pub ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuiSession {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub cookie: String,
    #[serde(default)]
    pub danger_consent: bool,
    #[serde(default)]
    pub danger_consented_at: String,
    #[serde(default)]
    pub goal: String,
    #[serde(default)]
    pub status: String, // idle | running | done | error | stopped
    #[serde(default)]
    pub chat: Vec<ChatMsg>,
    #[serde(default)]
    pub log: Vec<LogLine>,
    #[serde(default)]
    pub findings: Vec<ProbeHit>,
    #[serde(default)]
    pub sweep_summary: String,
    pub created_at: String,
    pub updated_at: String,
}

impl TuiSession {
    pub fn fresh(name: String, host: String) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let t = now();
        TuiSession {
            id,
            name,
            host,
            port: None,
            provider: String::new(),
            model: String::new(),
            cookie: String::new(),
            danger_consent: false,
            danger_consented_at: String::new(),
            goal: String::new(),
            status: "idle".into(),
            chat: Vec::new(),
            log: Vec::new(),
            findings: Vec::new(),
            sweep_summary: String::new(),
            created_at: t.clone(),
            updated_at: t,
        }
    }

    pub fn target_label(&self) -> String {
        if self.host.trim().is_empty() {
            "(대상 미지정)".to_string()
        } else if let Some(p) = self.port {
            format!("{}:{p}", self.host.trim())
        } else {
            self.host.trim().to_string()
        }
    }

    pub fn push_log(&mut self, tag: &str, text: String, level: LineLevel) {
        self.log.push(LogLine::new(tag, text, level));
        if self.log.len() > 3000 {
            self.log.drain(..self.log.len() - 3000);
        }
        self.updated_at = now();
    }

    pub fn push_chat(&mut self, role: &str, content: String) {
        self.chat.push(ChatMsg { role: role.to_string(), content, ts: now() });
        self.updated_at = now();
    }

    pub fn file_path(id: &str) -> PathBuf {
        sessions_dir().join(format!("{id}.json"))
    }

    pub fn save(&self) {
        let mut s = self.clone();
        s.updated_at = now();
        if let Ok(txt) = serde_json::to_string_pretty(&s) {
            // 저장 실패는 조용히 포기할 수 없다 — 다음 저장 재시도 전까지 최소한 로그로 남긴다.
            if let Err(e) = write_private(&Self::file_path(&s.id), &txt) {
                eprintln!("세션 저장 실패({}): {e}", s.id);
            }
        }
    }

    pub fn load(id: &str) -> Option<Self> {
        let txt = std::fs::read_to_string(Self::file_path(id)).ok()?;
        serde_json::from_str(&txt).ok().map(|mut s: TuiSession| {
            // 실행 중 표시로 남은 채 종료됐으면 idle 로 복원.
            if s.status == "running" {
                s.status = "idle".into();
            }
            s
        })
    }

    pub fn list() -> Vec<(String, String, String, String)> {
        // (id, name, target, updated) — 최신순.
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(sessions_dir()) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "json").unwrap_or(false) {
                    if let Ok(txt) = std::fs::read_to_string(&p) {
                        if let Ok(s) = serde_json::from_str::<TuiSession>(&txt) {
                            let label = s.target_label();
                            out.push((s.id, s.name, label, s.updated_at));
                        }
                    }
                }
            }
        }
        out.sort_by(|a, b| b.3.cmp(&a.3));
        out
    }

    pub fn delete(id: &str) {
        std::fs::remove_file(Self::file_path(id)).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_target_label_shapes() {
        let mut s = TuiSession::fresh("t".into(), "".into());
        assert_eq!(s.target_label(), "(대상 미지정)");
        s.host = "example.com".into();
        assert_eq!(s.target_label(), "example.com");
        s.port = Some(8080);
        assert_eq!(s.target_label(), "example.com:8080");
    }

    #[test]
    fn log_ring_caps_at_3000() {
        let mut s = TuiSession::fresh("t".into(), "h".into());
        for i in 0..3100 {
            s.push_log("t", format!("l{i}"), LineLevel::Info);
        }
        assert_eq!(s.log.len(), 3000);
        assert_eq!(s.log[0].text, "l100");
    }
}
