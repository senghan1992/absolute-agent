//! 통합 테스트 — IDOR / 가격 변조 탐지 모듈.
//!
//! 라벨에 취약한 엔드포인트와 안전한 엔드포인트가 함께 있는 모의 서버를 띄우고,
//! "취약한 것만 잡히고 안전한 것은 잡히지 않는지" 를 검증한다.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use forge::probes::idor::{self, IdorConfig, IdorVerdict};
use forge::probes::tamper::{self, TamperConfig, TamperVerdict};
use forge::probes::ProbeClient;
use forge::scope::Authorization;

/// 모의 대상 서버.
struct Lab {
    port: u16,
}

fn start_lab() -> Lab {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head, body) = loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break (String::new(), String::new());
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
                        break (head, rest[..len].to_string());
                    }
                }
            };

            let mut parts = head.split_whitespace();
            let method = parts.next().unwrap_or("GET").to_string();
            let target = parts.next().unwrap_or("/").to_string();
            let (path, query) = match target.split_once('?') {
                Some((p, q)) => (p.to_string(), q.to_string()),
                None => (target.clone(), String::new()),
            };

            let qparam = |name: &str| -> String {
                query
                    .split('&')
                    .filter_map(|kv| kv.split_once('='))
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_default()
            };

            let (status, body_out) = match (method.as_str(), path.as_str()) {
                // ── IDOR 취약: id 를 바꾸면 남의 데이터가 나온다 ──
                ("GET", "/api/user") => {
                    let id = qparam("id");
                    match id.as_str() {
                        "1" => (200, r#"{"id":1,"name":"alice","email":"alice@lab.local"}"#.to_string()),
                        "2" => (200, r#"{"id":2,"name":"bob","email":"bob@lab.local"}"#.to_string()),
                        "3" => (200, r#"{"id":3,"name":"carol","email":"carol@lab.local"}"#.to_string()),
                        _ => (404, r#"{"error":"not found"}"#.to_string()),
                    }
                }
                // ── 공개 카탈로그: id 가 달라도 같은 내용 (취약점 아님) ──
                ("GET", "/api/public") => {
                    (200, r#"{"items":[{"sku":"A1","name":"public item"}]}"#.to_string())
                }
                // ── 소유자 검증이 동작하는 엔드포인트 ──
                ("GET", "/api/guarded") => (403, r#"{"error":"forbidden"}"#.to_string()),
                // ── 가격 변조 취약: 서버가 받은 price 를 그대로 총액에 반영 ──
                ("POST", "/checkout") => {
                    let parsed: serde_json::Value =
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                    let price: f64 = parsed
                        .get("price")
                        .and_then(|v| v.as_f64())
                        .or_else(|| qparam("price").parse().ok())
                        .unwrap_or(10.0);
                    let qty: f64 = parsed
                        .get("qty")
                        .and_then(|v| v.as_f64())
                        .or_else(|| qparam("qty").parse().ok())
                        .unwrap_or(2.0);
                    let total = price * qty;
                    let resp = serde_json::json!({
                        "price": price,
                        "qty": qty,
                        "total": total,
                        "status": "ok"
                    })
                    .to_string();
                    (200, resp)
                }

                ("POST", "/checkout-safe") => {
                    let parsed: serde_json::Value =
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                    let price: f64 = parsed
                        .get("price")
                        .and_then(|v| v.as_f64())
                        .or_else(|| qparam("price").parse().ok())
                        .unwrap_or(10.0);
                    let qty: f64 = parsed
                        .get("qty")
                        .and_then(|v| v.as_f64())
                        .or_else(|| qparam("qty").parse().ok())
                        .unwrap_or(2.0);
                    if price <= 0.0 {
                        (400, r#"{"error":"invalid price"}"#.to_string())
                    } else {
                        (200, format!("{{\"total\":{},\"status\":\"ok\"}}", 1000.0 * qty))
                    }
                }
                _ => (404, r#"{"error":"not found"}"#.to_string()),
            };

            let resp = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_out.len(),
                body_out
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });

    Lab { port }
}

fn auth_for(port: u16) -> Arc<Authorization> {
    let text = format!(
        "engagement:\n  name: \"probe-test\"\nscope:\n  allow:\n    - host: \"127.0.0.1\"\nports:\n  allow_tcp: [{}]\nlimits:\n  max_requests_per_second: 500\n",
        port
    );
    Arc::new(Authorization::parse(&text).expect("인가 파싱"))
}

#[tokio::test(flavor = "multi_thread")]
async fn idor_confirms_other_users_data() {
    let lab = start_lab();
    let auth = auth_for(lab.port);
    let client = ProbeClient::new(auth).unwrap();

    let url = format!("http://127.0.0.1:{}/api/user?id=1", lab.port);
    let cfg = IdorConfig::new(&url, "id");
    let report = idor::run(&client, &cfg).await.expect("IDOR 탐색 실패");

    assert_eq!(report.verdict, IdorVerdict::Confirmed, "판정: {:?}", report.verdict);
    assert_eq!(report.findings.len(), 1, "발견 수: {}", report.findings.len());
    let f = &report.findings[0];
    assert_eq!(f.category, "idor");
    assert_eq!(f.severity, "high");
    // 근거에 남의 식별자가 들어 있어야 한다.
    assert!(f.evidence.contains("bob@lab.local"), "근거: {}", f.evidence);
    assert!(f.remediation.contains("소유자"), "보완 항목: {}", f.remediation);
}

#[tokio::test(flavor = "multi_thread")]
async fn idor_does_not_flag_public_catalogue() {
    let lab = start_lab();
    let client = ProbeClient::new(auth_for(lab.port)).unwrap();

    let url = format!("http://127.0.0.1:{}/api/public?id=1", lab.port);
    let cfg = IdorConfig::new(&url, "id");
    let report = idor::run(&client, &cfg).await.expect("IDOR 탐색 실패");

    assert_ne!(report.verdict, IdorVerdict::Confirmed, "공개 카탈로그를 IDOR 로 판정하면 안 됨");
    assert!(
        !report.findings.iter().any(|f| f.category == "idor"),
        "공개 카탈로그에 IDOR 발견이 생성됨: {:?}",
        report.findings
    );
    // 값을 무시하는 엔드포인트는 존재 경계도 없으므로 열거 신호조차 없다.
    assert_eq!(report.verdict, IdorVerdict::None, "판정: {:?}", report.verdict);
    assert!(report.findings.is_empty(), "발견이 있으면 안 됨: {:?}", report.findings);
}

#[tokio::test(flavor = "multi_thread")]
async fn idor_respects_ownership_checks() {
    let lab = start_lab();
    let client = ProbeClient::new(auth_for(lab.port)).unwrap();

    let url = format!("http://127.0.0.1:{}/api/guarded?id=1", lab.port);
    let cfg = IdorConfig::new(&url, "id");
    let report = idor::run(&client, &cfg).await.expect("IDOR 탐색 실패");

    assert_eq!(report.verdict, IdorVerdict::None, "403 응답은 안전해야 함");
    assert!(report.findings.is_empty(), "발견이 있으면 안 됨: {:?}", report.findings);
}

#[tokio::test(flavor = "multi_thread")]
async fn tamper_detects_price_override() {
    let lab = start_lab();
    let client = ProbeClient::new(auth_for(lab.port)).unwrap();

    let url = format!("http://127.0.0.1:{}/checkout", lab.port);
    let mut cfg = TamperConfig::new(&url, "price");
    cfg.method = "POST".into();
    cfg.baseline_value = "10".into();
    cfg.body = Some(r#"{"price":10,"qty":2}"#.to_string());
    cfg.values = vec!["0".into(), "-1".into(), "999999999".into()];
    let report = tamper::run(&client, &cfg).await.expect("변조 탐색 실패");

    assert!(
        report.attempts.iter().any(|a| a.verdict == TamperVerdict::FollowedTamper),
        "변조가 반영되지 않음: {:?}",
        report.attempts.iter().map(|a| (&a.value, &a.verdict)).collect::<Vec<_>>()
    );
    assert!(!report.findings.is_empty(), "가격 변조 발견이 없음");
    let f = &report.findings[0];
    assert_eq!(f.category, "price_tampering");
    // price=0 은 합계 0 → critical.
    assert_eq!(f.severity, "critical", "severity: {}", f.severity);
    assert!(f.evidence.contains("total"), "근거: {}", f.evidence);
}

#[tokio::test(flavor = "multi_thread")]
async fn tamper_does_not_flag_recalculated_server() {
    let lab = start_lab();
    let client = ProbeClient::new(auth_for(lab.port)).unwrap();

    let url = format!("http://127.0.0.1:{}/checkout-safe", lab.port);
    let mut cfg = TamperConfig::new(&url, "price");
    cfg.method = "POST".into();
    cfg.baseline_value = "10".into();
    cfg.body = Some(r#"{"price":10,"qty":2}"#.to_string());
    cfg.values = vec!["0".into(), "-1".into(), "999999999".into()];
    let report = tamper::run(&client, &cfg).await.expect("변조 탐색 실패");

    assert!(
        report.findings.is_empty(),
        "안전한 서버를 취약점으로 판정함: {:?}",
        report.findings
    );
    assert!(
        report.attempts.iter().any(|a| a.verdict == TamperVerdict::Rejected),
        "0/음수 값을 거부해야 함: {:?}",
        report.attempts.iter().map(|a| (&a.value, &a.verdict)).collect::<Vec<_>>()
    );
    assert!(
        report.attempts.iter().any(|a| a.verdict == TamperVerdict::Recalculated),
        "서버 재계산이 확인되어야 함: {:?}",
        report.attempts.iter().map(|a| (&a.value, &a.verdict)).collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn probes_block_out_of_scope_targets() {
    let lab = start_lab();
    // 인가가 다른 호스트만 허용하도록 만든다.
    let text = format!(
        "engagement:\n  name: \"probe-test\"\nscope:\n  allow:\n    - host: \"10.0.0.1\"\nports:\n  allow_tcp: [{}]\n",
        lab.port
    );
    let auth = Arc::new(Authorization::parse(&text).unwrap());
    let client = ProbeClient::new(auth).unwrap();

    let url = format!("http://127.0.0.1:{}/api/user?id=1", lab.port);
    let cfg = IdorConfig::new(&url, "id");
    let err = idor::run(&client, &cfg).await.expect_err("인가 밖 대상은 차단되어야 함");
    assert!(err.contains("인가 대상이 아닙니다"), "{err}");
}
