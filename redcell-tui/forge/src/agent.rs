//! 자율 에이전트 루프 — LLM 이 커널·스톰을 직접 조작한다.
//!
//! 흐름 (prime-agent 의 tool_call 루프와 같은 형태):
//!   모델이 도구를 호출 → 도구가 실제 동작(파이썬 실행 / 병렬 퍼징)을 수행 →
//!   관찰 결과를 메시지로 되돌려 다음 턴 → 예산 소진 또는 finish 호출 시 종료.
//!
//! 안전:
//!   - 모든 도구 호출은 인가 게이트를 통과한다 (fail-closed).
//!   - 파이썬 커널은 소켓 후킹으로 인가 밖 대상 연결을 차단한다.
//!   - 파괴적/DoS 계열 작업은 지시문으로 금지하고, 도구에서도 수행하지 않는다.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::kernel::Kernel;
use crate::memory;
use crate::providers::{self, Resolved};
use crate::recon;
use crate::report::Finding;
use crate::scope::Authorization;
use crate::storm::{StormEngine, StormPlan, Template};

/// 공유 상태 — TUI 와 에이전트가 함께 본다.
pub struct Shared {
    pub findings: parking_lot::Mutex<Vec<Finding>>,
    pub notes: parking_lot::Mutex<Vec<String>>,
    pub events: tokio::sync::broadcast::Sender<AgentEvent>,
    pub memory: parking_lot::Mutex<memory::Memory>,
    /// 대상 기술 스택 지문 (기억 조회/기록 키).
    pub fingerprint: parking_lot::Mutex<String>,
}

impl Default for Shared {
    fn default() -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(512);
        Self {
            findings: parking_lot::Mutex::new(Vec::new()),
            notes: parking_lot::Mutex::new(Vec::new()),
            events: tx,
            memory: parking_lot::Mutex::new(memory::Memory::default()),
            fingerprint: parking_lot::Mutex::new(String::new()),
        }
    }
}

impl Shared {
    pub fn new() -> Arc<Self> {
        let (tx, _rx) = tokio::sync::broadcast::channel(512);
        Arc::new(Self {
            findings: parking_lot::Mutex::new(Vec::new()),
            notes: parking_lot::Mutex::new(Vec::new()),
            events: tx,
            memory: parking_lot::Mutex::new(memory::load()),
            fingerprint: parking_lot::Mutex::new(String::new()),
        })
    }

    pub fn emit(&self, event: AgentEvent) {
        let _ = self.events.send(event);
    }

    pub fn add_finding(&self, finding: Finding) {
        self.findings.lock().push(finding);
    }
}

/// 에이전트 이벤트 (TUI 스트리밍용).
#[derive(Debug, Clone)]
pub enum AgentEvent {
    Turn(u32),
    Assistant(String),
    ToolStart { name: String, summary: String },
    ToolEnd { name: String, summary: String },
    Done(String),
    Error(String),
    Note(String),
    /// 커널 실행 결과 (커널 탭 표시용).
    KernelOutput(String),
    /// 스톰 엔진 진행/이상 이벤트.
    Storm(crate::storm::StormEvent),
}

/// 에이전트 실행 설정.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub max_turns: usize,
    /// 전체 도구 실행 예산 (요청 수 관점의 상한).
    pub max_tool_calls: usize,
    pub max_duration: Duration,
    pub exec_timeout_ms: u64,
    /// 자동 승인 모드 (도구 호출을 항상 실행).
    pub auto: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self { max_turns: 24, max_tool_calls: 200, max_duration: Duration::from_secs(600), exec_timeout_ms: 20_000, auto: true }
    }
}

/// 에이전트.
pub struct Agent {
    pub provider: Resolved,
    pub kernel: Arc<Kernel>,
    pub auth: Arc<Authorization>,
    pub shared: Arc<Shared>,
    pub config: AgentConfig,
    pub target: Option<String>,
    pub fingerprint: String,
}

/// 도구 정의 (Anthropic/OpenAI 공통 형태 → 프로바이더별로 변환).
fn tool_specs() -> Vec<Value> {
    vec![
        json!({
            "name": "python",
            "description": "파이썬 코드를 커널에서 실행한다. 네임스페이스는 유지되므로 이전 변수를 이어 쓸 수 있다. \
                            사용 가능: forge.get/post/request(스코프 검사됨), forge.burst(병렬 요청), forge.mutate(페이로드 생성), \
                            forge.analyze(응답 신호 추출), forge.diff(응답 비교), forge.note, forge.finding, requests, re 등 표준 라이브러리. \
                            결과를 print() 로 찍으면 그대로 반환된다.",
            "input_schema": {
                "type": "object",
                "properties": { "code": { "type": "string", "description": "실행할 파이썬 코드" } },
                "required": ["code"]
            }
        }),
        json!({
            "name": "storm",
            "description": "대상 엔드포인트에 페이로드를 고속 병렬로 주입하고 응답 차이를 분석한다. \
                            입력 파라미터 하나를 바꿔가며 시도하고, 기준선과 달라진 응답만 이상으로 보고한다.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "전체 URL (경로 포함)" },
                    "method": { "type": "string", "description": "HTTP 메서드 (기본 GET)" },
                    "params": { "type": "array", "items": { "type": "object", "properties": { "name": {"type":"string"}, "value": {"type":"string"} } }, "description": "원본 파라미터 목록" },
                    "payloads": { "type": "array", "items": { "type": "string" }, "description": "주입할 페이로드 목록 (비우면 기본 코퍼스)" },
                    "max_requests": { "type": "integer", "description": "최대 요청 수 (기본 200)" }
                },
                "required": ["url"]
            }
        }),
        json!({
            "name": "recon",
            "description": "대상을 GET 으로 받아 링크·폼·API 경로와 기술 스택 지문을 추출한다.",
            "input_schema": {
                "type": "object",
                "properties": { "url": { "type": "string" } },
                "required": ["url"]
            }
        }),
        json!({
            "name": "idor",
            "description": "IDOR(부적절한 객체 참조) 탐지. 대상 id 를 바꾸어 다른 주체의 리소스가                             반환되는지 확인한다. 응답의 식별자(메일·이름)가 실제로 달라지는지까지 본다.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "전체 URL (id 파라미터 포함)" },
                    "param": { "type": "string", "description": "바꿀 식별자 파라미터 (예: id)" },
                    "method": { "type": "string" },
                    "candidates": { "type": "array", "items": { "type": "string" }, "description": "직접 시도할 값" }
                },
                "required": ["url", "param"]
            }
        }),
        json!({
            "name": "tamper",
            "description": "가격/수량 변조 탐지. 금액 파라미터를 0·음수·아주 큰 값으로 바꿔 보내고,                             서버가 그 값을 그대로 신뢰하는지(합계가 따라가는지) 확인한다.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string" },
                    "param": { "type": "string", "description": "금액 파라미터 (예: price, amount, qty)" },
                    "method": { "type": "string" },
                    "values": { "type": "array", "items": { "type": "string" }, "description": "시도할 변조값" },
                    "body": { "type": "string", "description": "요청 본문 (JSON 또는 form)" }
                },
                "required": ["url", "param"]
            }
        }),
        json!({
            "name": "finding",
            "description": "확정된 취약점을 기록한다. 리포트(보완 포인트 포함)로 곧바로 묶인다.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "title": { "type": "string" },
                    "severity": { "type": "string", "description": "critical|high|medium|low" },
                    "category": { "type": "string", "description": "예: sqli,idor,ssrf,xss,cmdi,info_leak" },
                    "target": { "type": "string" },
                    "evidence": { "type": "string", "description": "요청/응답 근거 (최소 재현)" },
                    "reproduction": { "type": "string", "description": "재현 절차" },
                    "remediation": { "type": "string", "description": "수정/보완 제안" }
                },
                "required": ["title", "severity"]
            }
        }),
        json!({
            "name": "note",
            "description": "중간 결론·관찰을 기록한다. 다음 턴의 프롬프트 컨텍스트에 포함된다.",
            "input_schema": {
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }
        }),
        json!({
            "name": "finish",
            "description": "점검을 마무리하고 요약을 반환한다.",
            "input_schema": {
                "type": "object",
                "properties": { "summary": { "type": "string" } },
                "required": ["summary"]
            }
        }),
    ]
}

/// 시스템 프롬프트 — 방법론 + 도구 사용 규칙.
fn system_prompt(target: Option<&str>, hint: &str, notes: &[String]) -> String {
    let mut p = String::new();
    p.push_str("당신은 인가된 대상을 점검하는 시니어 보안 연구자다. 실제 SIEM/버그 bounty/CTF 환경에서 \
");
    p.push_str("수행하는 화이트해커와 같은 방식으로 일한다.
\n");
    p.push_str("[절대 규칙]\n");
    p.push_str("1. 인가 범위 밖의 대상은 절대 건드리지 않는다. 모든 도구는 자동으로 게이트된다.\n");
    p.push_str("2. 파괴적 행위(DROP TABLE, rm -rf, 파일 삭제, 대량 트래픽 DoS)는 금지한다. 최소 영향으로 증명한다.\n");
    p.push_str("3. 발견은 반드시 근거(요청/응답)를 남기고 finding 도구로 기록한다. 근거 없는 추측은 기록하지 않는다.\n");
    p.push_str("4. 실제 사용자 계정/실제 데이터 파괴를 목표로 하지 않는다.\n\n");
    p.push_str("[작업 방법]\n");
    p.push_str("1) recon 으로 표면을 파악하고 지문(프레임워크·헤더)을 확인한다.\n");
    p.push_str("2) python 으로 표면을 직접 만져본다(인증 우회尝试, 논리 오류, IDOR 경계값 등).\n");
    p.push_str("3) storm 으로 입력값을 변이하며 고속으로 시도하고, 기준선과 달라진 응답만 분석한다.\n");
    p.push_str("4) 응답 차이가 있으면 왜 그런지 해석하고(오류 메시지·타이밍·본문 변화), 재현 절차를 확정한다.\n");
    p.push_str("5) 확정된 것만 finding 으로 기록한다. 끝나면 finish 를 호출한다.\n\n");
    p.push_str("[도구 사용 팁]\n");
    p.push_str("- python 코드에서는 forge.get('/path') 로 요청하고, r = forge.get(...) 후 print(r['status'], r['body'][:500]) 로 확인한다.\n");
    p.push_str("- IDOR 는 ID 를 1,2,3,999999 로 바꿔 응답 본문 차이를 비교한다(forge.diff).\n");
    p.push_str("- SQLi 는 forge.mutate(['1']) 로 만든 변이값을 storm 에 넣고, 에러 메시지 변화에 집중한다.\n");
    p.push_str("- 인증 우회가 되면 그 세션 쿠키를 이후 요청에 붙여 더 넓은 표면을 확인한다.\n");
    if let Some(t) = target {
        p.push_str(&format!("\n[대상] {t}\n"));
    }
    if !hint.is_empty() {
        p.push_str(&format!("\n{hint}\n"));
    }
    if !notes.is_empty() {
        p.push_str("\n[이전 관찰]\n");
        for n in notes.iter().rev().take(8) {
            p.push_str(&format!("- {n}\n"));
        }
    }
    p
}

/// 모델의 한 턴 결과.
struct Turn {
    text: String,
    tool_calls: Vec<ToolCall>,
}

struct ToolCall {
    id: String,
    name: String,
    input: Value,
}

impl Agent {
    /// 목표를 주어 자율 루프 실행.
    pub async fn run(&self, goal: &str) -> Result<String, String> {
        let deadline = Instant::now() + self.config.max_duration;
        let hint = memory::prompt_hint(&self.shared.memory.lock(), &self.fingerprint);
        let notes = self.shared.notes.lock().clone();
        let system = system_prompt(self.target.as_deref(), &hint, &notes);

        let mut messages: Vec<Value> = vec![json!({ "role": "user", "content": goal })];

        let mut tool_calls_used = 0usize;
        let mut last_summary = String::new();

        for turn_idx in 1..=self.config.max_turns {
            if Instant::now() > deadline {
                let msg = format!("시간 예산({}초) 초과로 종료", self.config.max_duration.as_secs());
                self.shared.emit(AgentEvent::Error(msg.clone()));
                return Ok(last_summary);
            }
            self.shared.emit(AgentEvent::Turn(turn_idx as u32));

            let turn = self.call_model(&system, &messages).await?;
            if !turn.text.trim().is_empty() {
                self.shared.emit(AgentEvent::Assistant(turn.text.clone()));
            }
            messages.push(self.assistant_message(&turn));

            if turn.tool_calls.is_empty() {
                // 도구 호출 없이 답을 마치면 종료.
                last_summary = turn.text.clone();
                self.shared.emit(AgentEvent::Done(last_summary.clone()));
                return Ok(last_summary);
            }

            for call in turn.tool_calls {
                if tool_calls_used >= self.config.max_tool_calls {
                    let msg = "도구 실행 예산 소진 — 종료합니다.".to_string();
                    self.shared.emit(AgentEvent::Error(msg.clone()));
                    return Ok(last_summary);
                }
                tool_calls_used += 1;
                self.shared.emit(AgentEvent::ToolStart { name: call.name.clone(), summary: summarize_input(&call) });
                let result = self.run_tool(&call).await;
                let summary = truncate(&result, 4000);
                self.shared.emit(AgentEvent::ToolEnd { name: call.name.clone(), summary: truncate(&summary, 300) });
                messages.push(self.tool_result_message(&call, &result));
                if call.name == "finish" {
                    let s = call
                        .input
                        .get("summary")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&summary)
                        .to_string();
                    last_summary = s.clone();
                    self.shared.emit(AgentEvent::Done(s.clone()));
                    return Ok(last_summary);
                }
            }
        }
        let msg = format!("최대 턴({}) 도달 — 종료", self.config.max_turns);
        self.shared.emit(AgentEvent::Error(msg.clone()));
        Ok(last_summary)
    }

    /// 프로바이더에 한 턴 요청.
    async fn call_model(&self, system: &str, messages: &[Value]) -> Result<Turn, String> {
        let provider = &self.provider;
        match provider.kind.as_str() {
            "anthropic" => self.call_anthropic(system, messages).await,
            _ => self.call_openai(system, messages).await,
        }
    }

    async fn call_anthropic(&self, system: &str, messages: &[Value]) -> Result<Turn, String> {
        let tools: Vec<Value> = tool_specs()
            .iter()
            .map(|t| json!({
                "name": t["name"],
                "description": t["description"],
                "input_schema": t["input_schema"],
            }))
            .collect();
        let body = json!({
            "model": self.provider.model,
            "max_tokens": 4096,
            "system": system,
            "messages": messages,
            "tools": tools,
        });
        let url = format!("{}/v1/messages", self.provider.base_url.trim_end_matches('/'));
        let client = reqwest::Client::new();
        let mut req = client.post(&url).header("anthropic-version", "2023-06-01").json(&body);
        if let Some(key) = &self.provider.api_key {
            req = req.header("x-api-key", key);
        }
        let resp = req.send().await.map_err(|e| format!("요청 실패: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| format!("응답 읽기 실패: {e}"))?;
        if !status.is_success() {
            return Err(format!("Anthropic API {status}: {}", truncate(&text, 600)));
        }
        let json: Value = serde_json::from_str(&text).map_err(|e| format!("응답 JSON 파싱 실패: {e}"))?;
        let mut turn = Turn { text: String::new(), tool_calls: vec![] };
        if let Some(blocks) = json.get("content").and_then(|c| c.as_array()) {
            for block in blocks {
                match block.get("type").and_then(|t| t.as_str()).unwrap_or("") {
                    "text" => {
                        turn.text.push_str(block.get("text").and_then(|t| t.as_str()).unwrap_or(""));
                    }
                    "tool_use" => {
                        turn.tool_calls.push(ToolCall {
                            id: block.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            name: block.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            input: block.get("input").cloned().unwrap_or(json!({})),
                        });
                    }
                    _ => {}
                }
            }
        }
        Ok(turn)
    }

    async fn call_openai(&self, system: &str, messages: &[Value]) -> Result<Turn, String> {
        let tools: Vec<Value> = tool_specs()
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["input_schema"],
                    }
                })
            })
            .collect();
        let mut msgs: Vec<Value> = vec![json!({ "role": "system", "content": system })];
        msgs.extend_from_slice(messages);
        let body = json!({
            "model": self.provider.model,
            "messages": msgs,
            "tools": tools,
            "max_tokens": 4096,
        });
        let url = format!("{}/v1/chat/completions", self.provider.base_url.trim_end_matches('/'));
        let client = reqwest::Client::new();
        let mut req = client.post(&url).json(&body);
        if let Some(key) = &self.provider.api_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }
        let resp = req.send().await.map_err(|e| format!("요청 실패: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| format!("응답 읽기 실패: {e}"))?;
        if !status.is_success() {
            return Err(format!("OpenAI 호환 API {status}: {}", truncate(&text, 600)));
        }
        let json: Value = serde_json::from_str(&text).map_err(|e| format!("응답 JSON 파싱 실패: {e}"))?;
        let message = json
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .cloned()
            .unwrap_or(json!({}));
        let mut turn = Turn { text: message.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string(), tool_calls: vec![] };
        if let Some(calls) = message.get("tool_calls").and_then(|c| c.as_array()) {
            for call in calls {
                let name = call.pointer("/function/name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let args = call
                    .pointer("/function/arguments")
                    .and_then(|v| v.as_str())
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
                    .unwrap_or(json!({}));
                turn.tool_calls.push(ToolCall {
                    id: call.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    name,
                    input: args,
                });
            }
        }
        Ok(turn)
    }

    fn assistant_message(&self, turn: &Turn) -> Value {
        match self.provider.kind.as_str() {
            "anthropic" => {
                let mut content: Vec<Value> = Vec::new();
                if !turn.text.trim().is_empty() {
                    content.push(json!({ "type": "text", "text": turn.text }));
                }
                for c in &turn.tool_calls {
                    content.push(json!({ "type": "tool_use", "id": c.id, "name": c.name, "input": c.input }));
                }
                json!({ "role": "assistant", "content": content })
            }
            _ => {
                let mut msg = json!({ "role": "assistant", "content": turn.text });
                if !turn.tool_calls.is_empty() {
                    msg["tool_calls"] = json!(turn
                        .tool_calls
                        .iter()
                        .map(|c| json!({
                            "id": c.id,
                            "type": "function",
                            "function": { "name": c.name, "arguments": c.input.to_string() }
                        }))
                        .collect::<Vec<_>>());
                }
                msg
            }
        }
    }

    fn tool_result_message(&self, call: &ToolCall, result: &str) -> Value {
        match self.provider.kind.as_str() {
            "anthropic" => json!({
                "role": "user",
                "content": [{ "type": "tool_result", "tool_use_id": call.id, "content": result }]
            }),
            _ => json!({ "role": "tool", "tool_call_id": call.id, "name": call.name, "content": result }),
        }
    }

    /// 도구 실행 — 실제 동작을 수행하고 관찰 결과를 문자열로 반환.
    async fn run_tool(&self, call: &ToolCall) -> String {
        match call.name.as_str() {
            "python" => {
                let code = call.input.get("code").and_then(|v| v.as_str()).unwrap_or("");
                if code.trim().is_empty() {
                    return "코드가 비어 있습니다.".into();
                }
                match self.kernel.exec(code, self.config.exec_timeout_ms).await {
                    Ok(out) => {
                        let text = out.combined();
                        if text.trim().is_empty() {
                            format!("(출력 없음, {:.0}ms)", out.duration_ms)
                        } else {
                            text
                        }
                    }
                    Err(e) => format!("커널 오류: {e}"),
                }
            }
            "storm" => self.tool_storm(&call.input).await,
            "idor" => self.tool_idor(&call.input).await,
            "tamper" => self.tool_tamper(&call.input).await,
            "recon" => self.tool_recon(&call.input).await,
            "finding" => {
                let get = |k: &str| call.input.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let severity = {
                    let s = get("severity").to_lowercase();
                    if ["critical", "high", "medium", "low"].contains(&s.as_str()) { s } else { "medium".to_string() }
                };
                let finding = Finding {
                    title: get("title"),
                    severity,
                    category: get("category"),
                    target: get("target"),
                    evidence: get("evidence"),
                    reproduction: get("reproduction"),
                    remediation: get("remediation"),
                };
                self.shared.add_finding(finding.clone());
                // 자기발전: 성공한 전술을 지문별로 기억한다 (다음 라운드 우선순위).
                {
                    let mut mem = self.shared.memory.lock();
                    memory::record(&mut mem, &self.fingerprint, &finding.category, &finding.title, true);
                    let _ = memory::save(&mem);
                }
                format!("기록 완료 (총 {}건)", self.shared.findings.lock().len())
            }
            "note" => {
                let text = call.input.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string();
                self.shared.notes.lock().push(text.clone());
                self.shared.emit(AgentEvent::Note(text.clone()));
                format!("노트 기록 (총 {}건)", self.shared.notes.lock().len())
            }
            "finish" => call
                .input
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or("점검 종료")
                .to_string(),
            other => format!("알 수 없는 도구: {other}"),
        }
    }

    /// IDOR 탐지 도구.
    async fn tool_idor(&self, input: &Value) -> String {
        let url = input.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let param = input.get("param").and_then(|v| v.as_str()).unwrap_or("id").to_string();
        if url.is_empty() {
            return "url 이 필요합니다.".into();
        }
        let mut cfg = crate::probes::idor::IdorConfig::new(&url, &param);
        if let Some(m) = input.get("method").and_then(|v| v.as_str()) {
            cfg.method = m.to_uppercase();
        }
        if let Some(list) = input.get("candidates").and_then(|v| v.as_array()) {
            cfg.candidates = list.iter().filter_map(|v| v.as_str()).map(str::to_string).collect();
        }
        let client = match crate::probes::ProbeClient::new(self.auth.clone()) {
            Ok(c) => c,
            Err(e) => return format!("프로브 클라이언트 생성 실패: {e}"),
        };
        match crate::probes::idor::run(&client, &cfg).await {
            Ok(report) => {
                for f in &report.findings {
                    self.shared.add_finding(f.clone());
                    let mut mem = self.shared.memory.lock();
                    crate::memory::record(&mut mem, &self.fingerprint, &f.category, &f.title, true);
                    let _ = crate::memory::save(&mem);
                }
                let mut msg = format!(
                    "IDOR 탐색 — {} (요청 {}건, 판정 {:?})
{}",
                    report.param,
                    report.requests,
                    report.verdict,
                    crate::probes::summarize_findings(&report.findings)
                );
                for s in report.samples.iter().filter(|s| s.differs).take(8) {
                    msg.push_str(&format!(
                        "- {}={} → status {} len {} 식별자 {:?}
",
                        report.param, s.value, s.status, s.len, s.identifiers
                    ));
                }
                msg
            }
            Err(e) => format!("IDOR 탐색 실패: {e}"),
        }
    }

    /// 가격/수량 변조 탐지 도구.
    async fn tool_tamper(&self, input: &Value) -> String {
        let url = input.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let param = input.get("param").and_then(|v| v.as_str()).unwrap_or("price").to_string();
        if url.is_empty() {
            return "url 이 필요합니다.".into();
        }
        let mut cfg = crate::probes::tamper::TamperConfig::new(&url, &param);
        if let Some(m) = input.get("method").and_then(|v| v.as_str()) {
            cfg.method = m.to_uppercase();
        }
        if let Some(list) = input.get("values").and_then(|v| v.as_array()) {
            let vals: Vec<String> = list.iter().filter_map(|v| v.as_str()).map(str::to_string).collect();
            if !vals.is_empty() {
                cfg.values = vals;
            }
        }
        if let Some(b) = input.get("body").and_then(|v| v.as_str()) {
            cfg.body = Some(b.to_string());
        }
        let client = match crate::probes::ProbeClient::new(self.auth.clone()) {
            Ok(c) => c,
            Err(e) => return format!("프로브 클라이언트 생성 실패: {e}"),
        };
        match crate::probes::tamper::run(&client, &cfg).await {
            Ok(report) => {
                for f in &report.findings {
                    self.shared.add_finding(f.clone());
                    let mut mem = self.shared.memory.lock();
                    crate::memory::record(&mut mem, &self.fingerprint, &f.category, &f.title, true);
                    let _ = crate::memory::save(&mem);
                }
                let mut msg = format!(
                    "가격 변조 탐색 — {} (기준 {} 합계 {:?}, 요청 {}건)
{}",
                    report.param,
                    report.baseline_value,
                    report.baseline_total,
                    report.requests,
                    crate::probes::summarize_findings(&report.findings)
                );
                for a in report.attempts.iter().take(10) {
                    msg.push_str(&format!(
                        "- {}={} → status {} {:?} 합계 {:?}
",
                        report.param, a.value, a.status, a.verdict, a.observed_total
                    ));
                }
                msg
            }
            Err(e) => format!("가격 변조 탐색 실패: {e}"),
        }
    }

    async fn tool_storm(&self, input: &Value) -> String {
        let url = input.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if url.is_empty() {
            return "url 이 필요합니다.".into();
        }
        let method = input.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_uppercase();
        let mut template = Template::new(&format!("{method} {url}"), &method, &url);
        if let Some(params) = input.get("params").and_then(|v| v.as_array()) {
            for p in params {
                let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let value = p.get("value").and_then(|v| v.as_str()).unwrap_or("");
                if !name.is_empty() {
                    template.params.push(crate::storm::Param::new(name, value));
                }
            }
        }
        let mut plan = StormPlan::default();
        plan.templates = vec![template];
        if let Some(list) = input.get("payloads").and_then(|v| v.as_array()) {
            let payloads: Vec<String> = list.iter().filter_map(|v| v.as_str()).map(str::to_string).collect();
            if !payloads.is_empty() {
                plan.payloads = payloads;
            }
        }
        if let Some(max) = input.get("max_requests").and_then(|v| v.as_u64()) {
            plan.max_requests = max as usize;
        }
        plan.rps = self.auth.rps_limit();

        let engine = match StormEngine::new() {
            Ok(e) => e,
            Err(e) => return format!("스톰 엔진 초기화 실패: {e}"),
        };
        let (tx, _rx) = tokio::sync::broadcast::channel::<crate::storm::StormEvent>(64);
        match engine.run(&plan, &self.auth, tx).await {
            Ok(report) => {
                let mut lines = Vec::new();
                lines.push(format!(
                    "요청 {}건 · {:.1} req/s · 이상 {}건",
                    report.requests, report.rps, report.anomalies.len()
                ));
                for a in report.anomalies.iter().take(15) {
                    lines.push(format!(
                        "- [{}] {} {:?} payload={:?} status={} lenΔ={} 신호={:?}",
                        a.severity, a.template, a.param, a.payload, a.status, a.len_delta, a.signals
                    ));
                }
                lines.join("\n")
            }
            Err(e) => format!("스톰 실패: {e}"),
        }
    }

    async fn tool_recon(&self, input: &Value) -> String {
        let url = input.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if url.is_empty() {
            return "url 이 필요합니다.".into();
        }
        let (host, port, _) = match crate::scope::split_authority(&url) {
            Ok(v) => v,
            Err(e) => return format!("URL 오류: {e}"),
        };
        if let Err(e) = self.auth.check(&host, port) {
            return format!("인가 게이트 차단: {e}");
        }
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("REDFORGE/0.1")
            .build()
        {
            Ok(c) => c,
            Err(e) => return format!("HTTP 클라이언트 생성 실패: {e}"),
        };
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return format!("요청 실패: {e}"),
        };
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let result = recon::extract(&body, &url, status);
        if !result.fingerprint.key.is_empty() {
            *self.shared.fingerprint.lock() = result.fingerprint.key.clone();
        }
        let mut lines = vec![
            format!("status={status} len={}", body.len()),
            format!("지문: {}", if result.fingerprint.key.is_empty() { "(미확인)".into() } else { result.fingerprint.key.clone() }),
            format!("엔드포인트 {}개:", result.endpoints.len()),
        ];
        for ep in result.endpoints.iter().take(40) {
            lines.push(format!("- {} {} [{}] {:?}", ep.method, ep.url, ep.source, ep.params));
        }
        lines.join("\n")
    }
}

fn summarize_input(call: &ToolCall) -> String {
    match call.name.as_str() {
        "python" => truncate(call.input.get("code").and_then(|v| v.as_str()).unwrap_or(""), 160),
        "storm" => format!(
            "{} {:?}",
            call.input.get("url").and_then(|v| v.as_str()).unwrap_or(""),
            call.input.get("params").cloned().unwrap_or(json!([]))
        ),
        _other => truncate(&call.input.to_string(), 160),
    }
}

/// 문자열 절단 (도구 결과 크기 제한).
pub fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n… ({} 바이트 잘림)", &text[..end], text.len() - end)
}

/// 기본 프로바이더/모델 조합.
pub fn default_provider() -> Option<Resolved> {
    let (name, model) = providers::default_pair()?;
    providers::resolve(&name, Some(&model))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_on_char_boundary() {
        let s = "가나다라마바사아자차카타파하";
        let out = truncate(s, 7);
        // 잘린 본문은 원본의 접두사여야 하고, 경계를 깨지 않아야 한다.
        assert!(s.starts_with(out.split("
").next().unwrap()), "{out}");
        assert!(out.chars().count() < s.chars().count() + 40);
    }

    #[test]
    fn tool_specs_have_schemas() {
        for t in tool_specs() {
            assert!(t.get("name").is_some());
            assert!(t.get("input_schema").is_some());
        }
    }
}
