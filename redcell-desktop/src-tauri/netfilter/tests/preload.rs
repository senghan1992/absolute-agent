//! netfilter 통합 테스트 — 빌드된 .so 를 `LD_PRELOAD` 로 자식에 주입해
//! 허용/차단을 실측한다 (Linux + .so 존재 시에만, 없으면 스킵).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn find_so() -> Option<PathBuf> {
    // target/<profile>/deps/<test-exe> → 프로필 루트 복사본 우선, 없으면 deps/ 원본.
    let exe = std::env::current_exe().ok()?;
    let deps = exe.parent()?;
    let cands = [
        deps.parent().map(|p| p.join("libredcell_netfilter.so")),
        Some(deps.join("libredcell_netfilter.so")),
    ];
    cands.into_iter().flatten().find(|p| p.is_file())
}

fn py(code: &str, so: &PathBuf, allow: &str, log: &std::path::Path) -> (bool, String) {
    let out = Command::new("python3")
        .arg("-c")
        .arg(code)
        .env("LD_PRELOAD", so)
        .env("REDCELL_NETFILTER_ALLOW", allow)
        .env("REDCELL_NETFILTER_LOG", log)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output();
    match out {
        Ok(o) => (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))),
        Err(e) => (false, format!("spawn 실패: {e}")),
    }
}

#[test]
fn preload_allows_listed_and_blocks_rest() {
    if !cfg!(target_os = "linux") {
        eprintln!("linux 전용 — 스킵");
        return;
    }
    let Some(so) = find_so() else {
        eprintln!(".so 미빌드 — 스킵 (cargo build -p redcell-netfilter)");
        return;
    };
    // 허용 스텁 리스너.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        listener.set_nonblocking(false).ok();
        for conn in listener.incoming().flatten().take(2) {
            let mut c = conn;
            let mut buf = [0u8; 16];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"ok");
        }
    });
    std::thread::sleep(Duration::from_millis(100));
    let dir = std::env::temp_dir().join(format!("rc-nf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("audit.log");

    // 1) 허용: 127.0.0.1 명시 → 스텁 연결 성공.
    let (ok, out) = py(
        &format!("import socket;s=socket.create_connection(('127.0.0.1',{port}),timeout=5);s.sendall(b'hi');print(s.recv(2))"),
        &so,
        "127.0.0.1",
        &log,
    );
    assert!(ok && out.contains("ok"), "허용 연결 실패: {out}");

    // 2) 차단: allow 에 없는 IP → ECONNREFUSED + 감사 로그.
    let (ok2, out2) = py(
        "import socket;s=socket.create_connection(('127.0.0.2',9),timeout=5)",
        &so,
        "127.0.0.1",
        &log,
    );
    assert!(!ok2, "차단돼야 할 연결이 성공함: {out2}");
    let audit = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(audit.contains("blocked connect 127.0.0.2"), "감사 로그 누락: {audit}");

    // 3) DNS 차단: 해석은 되지만(로컬 hosts) 미인가인 이름 → EAI_NONAME + 감사.
    let (ok3, _) = py(
        "import socket;socket.getaddrinfo('localhost',80)",
        &so,
        "127.0.0.2",
        &log,
    );
    assert!(!ok3, "차단돼야 할 DNS 가 성공함");
    let audit = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(audit.contains("blocked dns localhost"), "DNS 감사 누락: {audit}");

    // 4) CIDR 허용: 127.0.0.0/8 → 127.0.0.1 성공.
    let (ok4, out4) = py(
        &format!("import socket;s=socket.create_connection(('127.0.0.1',{port}),timeout=5);s.sendall(b'hi');print(s.recv(2))"),
        &so,
        "127.0.0.0/8",
        &log,
    );
    assert!(ok4 && out4.contains("ok"), "CIDR 허용 실패: {out4}");
    std::fs::remove_dir_all(&dir).ok();
}
