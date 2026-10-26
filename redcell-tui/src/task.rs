//! 백그라운드 작업 — P0 스윕 스레드 + redcell agent 자식 프로세스.
//! 결과는 채널로 UI 스레드에 전달한다.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};

use crate::engine::probes::{self, ProbeHit, SweepConfig};

pub enum TaskMsg {
    /// 시작 시 부여한 세대 번호(중단된 이전 스윕의 늦은 결과 무시용).
    SweepDone { sweep_gen: u32, summary: String, hits: Vec<ProbeHit>, secs: u64 },
    AgentLine { line: String, err: bool },
    /// code — Some(종료코드): 3 = scope 차단, 4 = 대상 도달 불가 등 TS 의 의미있는 종료.
    AgentDone { ok: bool, secs: u64, code: Option<i32> },
}

/// P0 스윕 실행 — 완료 시 요약 + 발견 전달 (진행률은 feedback 폴링).
pub fn spawn_sweep(
    tx: Sender<TaskMsg>,
    sweep_gen: u32,
    host: String,
    port: Option<u16>,
    cookie: String,
    danger: bool,
    feedback: std::sync::Arc<probes::SweepFeedback>,
) {
    thread::spawn(move || {
        let started = Instant::now();
        let mut cfg = SweepConfig::default();
        if !cookie.trim().is_empty() {
            cfg.cookie = Some(cookie.trim().to_string());
        }
        cfg.danger = danger;
        cfg.feedback = Some(feedback);
        let rep = probes::run_sweep_with_config(&host, port, cfg);
        let summary = probes::sweep_summary_line(&rep);
        let _ = tx.send(TaskMsg::SweepDone { sweep_gen, summary, hits: rep.hits, secs: started.elapsed().as_secs() });
    });
}

/// redcell TS CLI 탐색 — REDCELL_TUI_BIN? 아니, redcell 루트 탐색.
/// 순서: REDCELL_ROOT/bin/redcell → 실행파일·cwd 기준 ../redcell → PATH 의 redcell.
pub fn find_redcell_cmd() -> Option<(PathBuf, Vec<String>)> {
    // 1) 명시 루트.
    if let Some(root) = std::env::var_os("REDCELL_ROOT").filter(|s| !s.is_empty()) {
        let p = PathBuf::from(root).join("bin").join("redcell");
        if p.is_file() {
            return Some((p, vec![]));
        }
    }
    // 2) 실행파일·cwd 기준 형제 디렉터리.
    let mut bases: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            bases.push(d.to_path_buf());
            if d.file_name().map(|f| f == "deps").unwrap_or(false) {
                if let Some(p) = d.parent().and_then(|p| p.parent()) {
                    bases.push(p.to_path_buf());
                }
            }
            // target/debug → crate root → workspace root 후보.
            for up in d.ancestors().take(4) {
                bases.push(up.to_path_buf());
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd.clone());
        for up in cwd.ancestors().take(4) {
            bases.push(up.to_path_buf());
        }
    }
    for b in &bases {
        for cand in [b.join("redcell").join("bin").join("redcell"), b.join("bin").join("redcell")] {
            if cand.is_file() {
                return Some((cand, vec![]));
            }
        }
    }
    // 3) PATH 위 redcell (TS 런처).
    if let Some(p) = first_on_path("redcell") {
        return Some((p, vec![]));
    }
    None
}

fn first_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let c = dir.join(bin);
        if c.is_file() {
            return Some(c);
        }
    }
    None
}

/// 공유 자식 핸들 — 모니터 스레드가 종료를 감시하고, UI 가 중지시킨다.
pub type AgentHandle = std::sync::Arc<std::sync::Mutex<Child>>;

/// redcell run 스폰 — stdout/stderr 를 라인 단위로 펌프한다.
/// `target_map` — P0 스윕 결과에서 만든 표면 파일(--target-map 으로 주입).
pub fn spawn_agent(
    tx: Sender<TaskMsg>,
    host: String,
    port: Option<u16>,
    goal: String,
    provider: String,
    model: String,
    target_map: Option<PathBuf>,
) -> Result<AgentHandle, String> {
    let (prog, prefix) = find_redcell_cmd().ok_or_else(|| {
        "redcell CLI 를 찾지 못했습니다 (REDCELL_ROOT 또는 형제 redcell/ 필요)".to_string()
    })?;
    let mut args = prefix;
    args.push("run".to_string());
    args.push("--host".to_string());
    args.push(host);
    if let Some(p) = port {
        args.push("--port".to_string());
        args.push(p.to_string());
    }
    args.push("--goal".to_string());
    args.push(goal);
    if let Some(map) = target_map {
        args.push("--target-map".to_string());
        args.push(map.display().to_string());
    }
    if !provider.trim().is_empty() {
        args.push("--provider".to_string());
        args.push(provider);
    }
    if !model.trim().is_empty() {
        args.push("--model".to_string());
        args.push(model);
    }
    let mut cmd = Command::new(prog);
    cmd.args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    #[cfg(unix)]
    {
        // 자체 프로세스 그룹 — 중지 시 npx/node/headless-chrome 까지 한 번에 회수.
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().map_err(|e| format!("agent 실행 실패: {e}"))?;
    let started = Instant::now();
    // stdout 펌프.
    if let Some(out) = child.stdout.take() {
        let tx2 = tx.clone();
        thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                let _ = tx2.send(TaskMsg::AgentLine { line, err: false });
            }
        });
    }
    // stderr 펌프.
    if let Some(err) = child.stderr.take() {
        let tx2 = tx.clone();
        thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                let _ = tx2.send(TaskMsg::AgentLine { line, err: true });
            }
        });
    }
    // 종료 감시 — try_wait 폴링 후 AgentDone 전송.
    let shared: AgentHandle = std::sync::Arc::new(std::sync::Mutex::new(child));
    {
        let shared = shared.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(200));
            // 뮤텍스가 poison 돼도 자식 상태 확인은 계속 (락 안에서 패닉이 난 것뿐).
            let done = shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .try_wait()
                .ok()
                .flatten();
            if let Some(st) = done {
                // 회수 후 결과 전송.
                if let Ok(mut c) = shared.lock() {
                    let _ = c.wait();
                }
                let code = st.code();
                let _ = tx.send(TaskMsg::AgentDone { ok: st.success(), secs: started.elapsed().as_secs(), code });
                break;
            }
        });
    }
    Ok(shared)
}

/// agent 중지 — 프로세스 그룹 전체를 종료해 npx·node·headless-chrome 고아를 남기지 않는다.
/// 뮤텍스가 poison 돼도 (UI 스레드 패닉 등) kill 이 생략되지 않게 한다.
pub fn kill_agent(handle: &AgentHandle) {
    let mut child = handle.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    #[cfg(unix)]
    {
        let pid = child.id();
        // -pid: 우리가 만든 프로세스 그룹. 실패해도 아래 직접 kill 이 있다.
        unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redcell_cmd_missing_without_env() {
        // REDCELL_ROOT 가 가짜면 해당 경로는 스킵 (형제·PATH 는 환경 의존).
        unsafe { std::env::set_var("REDCELL_ROOT", "/nonexistent-rc-root-xyz") };
        let found = find_redcell_cmd();
        unsafe { std::env::remove_var("REDCELL_ROOT") };
        // 이 저장소에서는 형제 탐색으로 찾을 수도, 못 찾을 수도 — 패닉만 없으면 됨.
        let _ = found;
    }
}
