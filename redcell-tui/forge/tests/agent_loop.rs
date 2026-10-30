//! 통합 테스트 — 모의 모델 서버로 자율 에이전트 루프 전체를 검증한다.
//!
//! 실제로 LLM 을 호출하지 않고, OpenAI 호환 API 를 흉내내는 로컬 서버가
//! "python → storm → finding → finish" 순서의 도구 호출을 반환한다.
//! 이를 통해 메시지 조립·도구 디스패치·커널 실행·스톰 실행·기록 반영이
//! 실제로 동작하는지 확인한다.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use forge::agent::{Agent, AgentConfig, AgentEvent, Shared};
use forge::kernel::Kernel;
use forge::providers::Resolved;
use forge::scope::Authorization;

/// 모의 모델 + 대상 서버.
struct MockServer {
    port: u16,
    calls: Arc<AtomicUsize>,
}

/// 간단한 HTTP/1.1 요청 파서 — 헤더와 본문을 돌려준다.
fn read_request(stream: &mut std::net::TcpStream) -> (String, String) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            return (String::new(), String::new());
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(idx) = text.find("\r\n\r\n") {
            let head = text[..idx].to_string();
            let rest = text[idx + 4..].to_string();
            let len = head
                .to_ascii_lowercase()
                .split("\r\n")
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if rest.len() >= len {
                return (head, rest[..len].to_string());
            }
        }
    }
}

/// HTTP 응답 전송.
fn write_response(stream: &mut std::net::TcpStream, status: &str, ctype: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

/// 대상 응답 — IDOR 취약 엔드포인트 (/api/user) 와 일반 엔드포인트 (/api/item).
fn lab_response(path: &str) -> (String, String, String) {
    if path.starts_with("/api/user") {
        let id = path
            .split("id=")
            .nth(1)
            .unwrap_or("1")
            .split('&')
            .next()
            .unwrap_or("1")
            .to_string();
        return match id.as_str() {
            "1" => (
                "200 OK".into(),
                "application/json".into(),
                r#"{"id":1,"name":"alice","email":"alice@lab.local"}"#.into(),
            ),
            "2" => (
                "200 OK".into(),
                "application/json".into(),
                r#"{"id":2,"name":"bob","email":"bob@lab.local"}"#.into(),
            ),
            "3" => (
                "200 OK".into(),
                "application/json".into(),
                r#"{"id":3,"name":"carol","email":"carol@lab.local"}"#.into(),
            ),
            _ => (
                "404 Not Found".into(),
                "application/json".into(),
                r#"{"error":"not found"}"#.into(),
            ),
        };
    }
    if path.starts_with("/api/item") {
        return (
            "200 OK".into(),
            "application/json".into(),
            r#"{"id":"1","name":"item-1"}"#.into(),
        );
    }
    ("200 OK".into(), "text/html".into(), "<html><body>lab</body></html>".into())
}

fn start_mock() -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_bg = calls.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let (head, _body) = read_request(&mut stream);
            let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();

            if path.starts_with("/v1/chat/completions") {
                let n = calls_bg.fetch_add(1, Ordering::SeqCst);
                write_response(&mut stream, "200 OK", "application/json", &mock_completion(n, port));
            } else {
                let (status, ctype, body) = lab_response(&path);
                write_response(&mut stream, &status, &ctype, &body);
            }
        }
    });

    MockServer { port, calls }
}

/// 모의 모델의 응답 — 단계별로 다른 도구를 호출한다.
fn mock_completion(n: usize, port: u16) -> String {
    let tool = |id: &str, name: &str, args: &str| {
        serde_json::json!({
            "id": id,
            "type": "function",
            "function": { "name": name, "arguments": args }
        })
    };
    let calls = match n {
        0 => vec![tool(
            "c1",
            "python",
            &serde_json::json!({
                "code": "import forge\nr = forge.get('/api/item?id=1')\nprint('kernel-ok', r['status'])"
            })
            .to_string(),
        )],
        1 => vec![tool(
            "c2",
            "storm",
            &serde_json::json!({
                "url": format!("http://127.0.0.1:{port}/api/item?id=1"),
                "params": [{ "name": "id", "value": "1" }],
                "payloads": ["'", "1 OR 1=1--"],
                "max_requests": 12
            })
            .to_string(),
        )],
        2 => vec![tool(
            "c3",
            "finding",
            &serde_json::json!({
                "title": "IDOR - 다른 사용자 데이터 노출",
                "severity": "high",
                "category": "idor",
                "target": "http://target/api/item",
                "evidence": "id=2 가 id=1 과 다른 데이터를 반환",
                "reproduction": "GET /api/item?id=2"
            })
            .to_string(),
        )],
        _ => vec![tool(
            "c4",
            "finish",
            &serde_json::json!({ "summary": "점검 완료 - IDOR 1건" }).to_string(),
        )],
    };
    serde_json::json!({
        "id": format!("resp-{n}"),
        "choices": [{
            "message": { "role": "assistant", "content": "", "tool_calls": calls },
            "finish_reason": "tool_calls"
        }]
    })
    .to_string()
}

/// IDOR 시나리오 — 에이전트가 idor 도구를 직접 호출한다.
fn mock_idor_completion(n: usize, port: u16) -> String {
    let tool = |id: &str, name: &str, args: &str| {
        serde_json::json!({
            "id": id,
            "type": "function",
            "function": { "name": name, "arguments": args }
        })
    };
    let calls = match n {
        0 => vec![tool(
            "i1",
            "idor",
            &serde_json::json!({
                "url": format!("http://127.0.0.1:{port}/api/user?id=1"),
                "param": "id"
            })
            .to_string(),
        )],
        _ => vec![tool(
            "i2",
            "finish",
            &serde_json::json!({ "summary": "IDOR 점검 완료" }).to_string(),
        )],
    };
    serde_json::json!({
        "id": format!("idor-resp-{n}"),
        "choices": [{
            "message": { "role": "assistant", "content": "", "tool_calls": calls },
            "finish_reason": "tool_calls"
        }]
    })
    .to_string()
}

/// IDOR 시나리오용 모의 서버.
fn start_idor_mock() -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_bg = calls.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let (head, _body) = read_request(&mut stream);
            let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            if path.starts_with("/v1/chat/completions") {
                let n = calls_bg.fetch_add(1, Ordering::SeqCst);
                write_response(&mut stream, "200 OK", "application/json", &mock_idor_completion(n, port));
            } else {
                let (status, ctype, body) = lab_response(&path);
                write_response(&mut stream, &status, &ctype, &body);
            }
        }
    });

    MockServer { port, calls }
}

fn scope_for(port: u16) -> Arc<Authorization> {
    let text = format!(
        "engagement:\n  name: \"unit\"\nscope:\n  allow:\n    - host: \"127.0.0.1\"\nports:\n  allow_tcp: [{}]\nlimits:\n  max_requests_per_second: 500\n",
        port
    );
    Arc::new(Authorization::parse(&text).expect("인가 파싱"))
}

#[tokio::test(flavor = "multi_thread")]
async fn autonomous_loop_runs_tools_and_records_findings() {
    let server = start_mock();
    let dir = std::env::temp_dir().join(format!("forge-agent-test-{}", uuid::Uuid::new_v4()));
    let auth = scope_for(server.port);

    let kernel = Kernel::start(None, Some(&format!("http://127.0.0.1:{}", server.port)), &dir)
        .await
        .expect("커널 기동");

    let shared = Shared::new();
    let mut events = shared.events.subscribe();

    let agent = Agent {
        provider: Resolved {
            kind: "openai-compat".into(),
            base_url: format!("http://127.0.0.1:{}", server.port),
            api_key: Some("test-key".into()),
            model: "mock".into(),
            name: "mock".into(),
        },
        kernel,
        auth: auth.clone(),
        shared: shared.clone(),
        // 헤드리스 실행이므로 승인 없이 자동 실행 (TUI 에서는 사람이 승인한다).
        config: AgentConfig { max_turns: 8, max_tool_calls: 12, auto: true, ..Default::default() },
        target: Some(format!("http://127.0.0.1:{}", server.port)),
        fingerprint: "unit-test".into(),
    };

    let summary = agent.run("IDOR 를 찾아라").await.expect("에이전트 실행");

    assert!(
        server.calls.load(Ordering::SeqCst) >= 4,
        "모델 호출 횟수 부족: {}",
        server.calls.load(Ordering::SeqCst)
    );

    let findings = shared.findings.lock().clone();
    assert_eq!(findings.len(), 1, "기록된 발견 수: {}", findings.len());
    assert_eq!(findings[0].category, "idor");
    assert_eq!(findings[0].severity, "high");

    assert!(summary.contains("점검 완료"), "요약: {summary}");

    let mut saw_tool = false;
    while let Ok(ev) = events.try_recv() {
        if matches!(ev, AgentEvent::ToolStart { .. }) {
            saw_tool = true;
        }
    }
    assert!(saw_tool, "도구 실행 이벤트가 없음");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_can_drive_idor_probe() {
    let server = start_idor_mock();
    let dir = std::env::temp_dir().join(format!("forge-agent-idor-{}", uuid::Uuid::new_v4()));
    let auth = scope_for(server.port);

    let kernel = Kernel::start(None, Some(&format!("http://127.0.0.1:{}", server.port)), &dir)
        .await
        .expect("커널 기동");
    let shared = Shared::new();

    let agent = Agent {
        provider: Resolved {
            kind: "openai-compat".into(),
            base_url: format!("http://127.0.0.1:{}", server.port),
            api_key: Some("test-key".into()),
            model: "mock".into(),
            name: "mock".into(),
        },
        kernel,
        auth: auth.clone(),
        shared: shared.clone(),
        config: AgentConfig { max_turns: 6, max_tool_calls: 8, auto: true, ..Default::default() },
        target: Some(format!("http://127.0.0.1:{}", server.port)),
        fingerprint: "unit-idor".into(),
    };

    let summary = agent.run("IDOR 를 찾아라").await.expect("에이전트 실행");
    assert!(summary.contains("IDOR 점검 완료"), "요약: {summary}");

    let findings = shared.findings.lock().clone();
    assert_eq!(findings.len(), 1, "기록된 발견 수: {}", findings.len());
    assert_eq!(findings[0].category, "idor", "분류: {}", findings[0].category);
    assert_eq!(findings[0].severity, "high");
    assert!(findings[0].evidence.contains("bob@lab.local"), "근거: {}", findings[0].evidence);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn scope_gate_blocks_out_of_scope_target() {
    let server = start_mock();
    let scope_text = format!(
        "engagement:\n  name: \"unit\"\nscope:\n  allow:\n    - host: \"10.0.0.1\"\nports:\n  allow_tcp: [{}]\n",
        server.port
    );
    let auth = Authorization::parse(&scope_text).expect("인가 파싱");
    let err = auth.check("127.0.0.1", Some(server.port)).expect_err("차단되어야 함");
    assert!(err.to_string().contains("인가 대상이 아닙니다"), "{err}");
}
