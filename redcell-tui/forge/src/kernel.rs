//! 파이썬 커널 브리지.
//!
//! 커널 스크립트(`py/forge_kernel.py`)는 바이너리에 내장(include_str)되어 실행
//! 시점에 임시 파일로 기록된다 → 배포 경로와 무관하게 항상 같은 코드가 돈다.
//!
//! 통신: stdin/stdout JSON Lines. 커널이 살아 있는 동안 네임스페이스가 유지되므로
//! LLM(또는 사용자)이 변수를 누적하며 여러 단계를 이어서 실행할 수 있다.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, Mutex};

/// 커널 소스 — 빌드 시점에 내장.
pub const KERNEL_SOURCE: &str = include_str!("../py/forge_kernel.py");

/// exec 결과.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub stdout: String,
    pub stderr: String,
    pub result: String,
    pub duration_ms: f64,
    pub ok: bool,
}

impl ExecOutcome {
    /// stdout+stderr 를 사람이 읽을 한 덩어리로.
    pub fn combined(&self) -> String {
        let mut out = String::new();
        if !self.stdout.trim().is_empty() {
            out.push_str(self.stdout.trim_end());
        }
        if !self.stderr.trim().is_empty() {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(self.stderr.trim_end());
        }
        if out.is_empty() {
            out.push_str(self.result.trim());
        }
        out
    }
}

/// 커널 오류.
#[derive(Debug)]
pub enum KernelError {
    Spawn(String),
    Io(String),
    Protocol(String),
    Timeout(String),
    Exited(String),
}

impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KernelError::Spawn(m) => write!(f, "커널 실행 실패: {m}"),
            KernelError::Io(m) => write!(f, "커널 통신 오류: {m}"),
            KernelError::Protocol(m) => write!(f, "커널 프로토콜 오류: {m}"),
            KernelError::Timeout(m) => write!(f, "커널 타임아웃: {m}"),
            KernelError::Exited(m) => write!(f, "커널 종료됨: {m}"),
        }
    }
}

impl std::error::Error for KernelError {}

type Pending = Arc<parking_lot::Mutex<HashMap<u64, oneshot::Sender<Value>>>>;

/// 디렉터리를 0700 으로 만든다 (Unix).
fn set_dir_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// SHA-256 16진 해시 (상위 16자).
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// 실행 중인 파이썬 커널 핸들.
pub struct Kernel {
    pending: Pending,
    stdin: Mutex<Option<tokio::process::ChildStdin>>,
    next_id: AtomicU64,
    child: Mutex<Option<Child>>,
    script_path: PathBuf,
    status: parking_lot::RwLock<Option<Value>>,
}

impl Kernel {
    /// 커널 기동. `scope_path` 가 없으면 커널이 스스로 모든 요청을 차단한다.
    ///
    /// 커널 스크립트는 샌드박스가 쓸 수 없는 **전용 디렉터리**에 기록하고,
    /// 기동 전 해시로 검증한다 (샌드박스가 스크립트를 덮어써 권한을 얻는 경로 차단).
    pub async fn start(scope_path: Option<&Path>, base_url: Option<&str>, run_dir: &Path) -> Result<Arc<Self>, KernelError> {
        std::fs::create_dir_all(run_dir).map_err(|e| KernelError::Spawn(format!("실행 디렉터리 생성 실패: {e}")))?;
        set_dir_private(run_dir);
        // 커널 스크립트는 **샌드박스가 손댈 수 없는 별도 위치**에 둔다.
        //   - 실행 디렉터리(runs/) 안에 두면 샌드박스가 덮어써 권한을 얻을 수 있다.
        //   - 프로세스마다 고유 경로를 써야 병렬 기동 시 서로를 덮어쓰지 않는다.
        let kernel_dir = std::env::temp_dir().join(format!("forge-kernel-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&kernel_dir).map_err(|e| KernelError::Spawn(format!("커널 디렉터리 생성 실패: {e}")))?;
        set_dir_private(&kernel_dir);
        let script_path = kernel_dir.join("forge_kernel.py");
        std::fs::write(&script_path, KERNEL_SOURCE)
            .map_err(|e| KernelError::Spawn(format!("커널 스크립트 기록 실패: {e}")))?;
        // 읽기 전용(0500) — 내용을 바꿀 수 없다.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o500));
        }
        // 해시 검증 — 기록 후 변조 여부를 확인한다.
        let digest = sha256_hex(KERNEL_SOURCE.as_bytes());
        let actual = sha256_hex(&std::fs::read(&script_path).unwrap_or_default());
        if digest != actual {
            let _ = std::fs::remove_dir_all(&kernel_dir);
            return Err(KernelError::Spawn("커널 스크립트 해시 불일치 — 변조될 수 있어 실행을 중단합니다.".into()));
        }

        let python = std::env::var("FORGE_PYTHON").unwrap_or_else(|_| "python3".to_string());
        let mut cmd = Command::new(&python);
        cmd.arg(&script_path)
            .arg("--run-dir")
            .arg(run_dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            // 환경변수 최소화 — 프록시·경로 등 민감한 값을 커널로 새지 않게 한다.
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()))
            .env("HOME", std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
            .env("LANG", "C.UTF-8")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONHASHSEED", "0");
        if let Some(scope) = scope_path {
            cmd.arg("--scope").arg(scope);
        }
        if let Some(base) = base_url {
            cmd.arg("--base-url").arg(base);
        }
        let mut child = cmd.spawn().map_err(|e| KernelError::Spawn(format!("{python} 실행 실패: {e}")))?;

        let stdout = child.stdout.take().ok_or_else(|| KernelError::Spawn("stdout 파이프 없음".into()))?;
        let stderr = child.stderr.take().ok_or_else(|| KernelError::Spawn("stderr 파이프 없음".into()))?;
        let stdin = child.stdin.take().ok_or_else(|| KernelError::Spawn("stdin 파이프 없음".into()))?;

        let pending: Pending = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let kernel = Arc::new(Kernel {
            pending: pending.clone(),
            stdin: Mutex::new(Some(stdin)),
            next_id: AtomicU64::new(1),
            child: Mutex::new(Some(child)),
            script_path,
            status: parking_lot::RwLock::new(None),
        });

        // stdout 판독 태스크 — 응답을 id 로 매칭해 돌려준다.
        {
            let pending = pending.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let Ok(value) = serde_json::from_str::<Value>(&line) else { continue };
                    let id = value.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                    if let Some(tx) = pending.lock().remove(&id) {
                        let _ = tx.send(value);
                    }
                }
                // stdout 이 닫히면 커널 종료 — 대기 중인 요청을 모두 실패 처리.
                let mut map = pending.lock();
                for (_, tx) in map.drain() {
                    let _ = tx.send(json!({"id": 0, "ok": false, "error": "커널 프로세스가 종료되었습니다."}));
                }
            });
        }
        // stderr 는 백그라운드로 소비 (파이썬 경고를 터미널에 흘리지 않기 위해).
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[kernel] {line}");
            }
        });

        // 준비 완료 배너 대기.
        let ready = kernel.request(json!({"op": "ping"}), 5.0).await?;
        if ready.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            *kernel.status.write() = ready.get("status").cloned();
        }
        Ok(kernel)
    }

    /// 상태 스냅샷 (기동 시 배너에서 얻은 정보).
    pub fn status(&self) -> Option<Value> {
        self.status.read().clone()
    }

    pub fn script_path(&self) -> &Path {
        &self.script_path
    }

    async fn request(&self, mut payload: Value, timeout_secs: f64) -> Result<Value, KernelError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        payload["id"] = json!(id);
        let line = serde_json::to_string(&payload).map_err(|e| KernelError::Protocol(e.to_string()))?;

        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(id, tx);

        {
            let mut guard = self.stdin.lock().await;
            let stdin = guard.as_mut().ok_or_else(|| KernelError::Exited("커널 stdin 이 닫혔습니다.".into()))?;
            stdin.write_all(line.as_bytes()).await.map_err(|e| KernelError::Io(e.to_string()))?;
            stdin.write_all(b"\n").await.map_err(|e| KernelError::Io(e.to_string()))?;
            stdin.flush().await.map_err(|e| KernelError::Io(e.to_string()))?;
        }

        match tokio::time::timeout(std::time::Duration::from_secs_f64(timeout_secs), rx).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(KernelError::Io("커널 응답 채널이 끊겼습니다.".into())),
            Err(_) => {
                self.pending.lock().remove(&id);
                Err(KernelError::Timeout(format!("{timeout_secs}s 안에 응답이 없습니다.")))
            }
        }
    }

    /// 코드 실행 — 네임스페이스는 유지된다.
    pub async fn exec(&self, code: &str, timeout_ms: u64) -> Result<ExecOutcome, KernelError> {
        let secs = (timeout_ms as f64 / 1000.0) + 5.0;
        let value = self
            .request(json!({"op": "exec", "code": code, "timeout_ms": timeout_ms}), secs)
            .await?;
        if value.get("error").is_some() {
            return Err(KernelError::Protocol(
                value.get("error").and_then(|v| v.as_str()).unwrap_or("알 수 없는 오류").to_string(),
            ));
        }
        Ok(ExecOutcome {
            stdout: value.get("stdout").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            stderr: value.get("stderr").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            result: value.get("result").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            duration_ms: value.get("duration_ms").and_then(|v| v.as_f64()).unwrap_or(0.0),
            ok: value.get("ok").and_then(|v| v.as_bool()).unwrap_or(true),
        })
    }

    /// 네임스페이스 초기화.
    pub async fn reset(&self) -> Result<(), KernelError> {
        self.request(json!({"op": "reset"}), 10.0).await.map(|_| ())
    }

    /// 현재 정의된 변수 목록.
    pub async fn vars(&self) -> Result<Value, KernelError> {
        self.request(json!({"op": "vars"}), 10.0).await
    }

    /// 기록된 노트/파인딩.
    pub async fn notes(&self) -> Result<Value, KernelError> {
        self.request(json!({"op": "notes"}), 10.0).await
    }

    /// 커널 종료.
    pub async fn shutdown(&self) {
        let _ = self.request(json!({"op": "shutdown"}), 2.0).await;
        if let Some(mut child) = self.child.lock().await.take() {
            let _ = child.start_kill();
        }
        // 커널 스크립트는 기동에만 필요하므로 정리한다.
        if let Some(dir) = self.script_path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn kernel_executes_and_keeps_state() {
        let dir = std::env::temp_dir().join(format!("forge-kernel-test-{}", uuid::Uuid::new_v4()));
        let kernel = Kernel::start(None, None, &dir).await.expect("커널 기동 실패");
        let out = kernel.exec("x = 21\nprint('hello')", 5000).await.expect("exec 실패");
        assert!(out.stdout.contains("hello"), "stdout 에 hello 가 없음: {}", out.stdout);
        let out2 = kernel.exec("print(x * 2)", 5000).await.expect("exec 실패");
        assert!(out2.stdout.contains("42"), "네임스페이스 유지 실패: {}", out2.stdout);
        kernel.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn kernel_captures_stderr_and_result() {
        let dir = std::env::temp_dir().join(format!("forge-kernel-test-{}", uuid::Uuid::new_v4()));
        let kernel = Kernel::start(None, None, &dir).await.unwrap();
        let out = kernel.exec("1/0", 15_000).await.unwrap();
        assert!(!out.stderr.is_empty(), "예외가 stderr 로 전달되지 않음");
        let out = kernel.exec("40 + 2", 15_000).await.unwrap();
        assert!(out.stdout.contains("42"), "마지막 표현식 값이 반환되지 않음: {}", out.stdout);
        kernel.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
