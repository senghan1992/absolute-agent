//! nuclei 스타일 YAML 템플릿 엔진 + 내장 템플릿 팩.
//!
//! 이 모듈의 목적은 "이 기술에서 알려진 취약점·노출"을 **선언적 템플릿**으로
//! 점검하는 것이다. nuclei 를 대체하는 것은 아니고, 같은 개념(템플릿 = 요청 +
//! 매처 + 추출기)을 Rust 로 작게 구현한 것이다.
//!
//! ## 안전 원칙 (이 모듈이 지킨 것)
//!
//!   1. **모든 트래픽은 `crate::http::HttpClient` 로만 나간다.**
//!      인가 게이트(호스트·포트), RPS 상한, 리다이렉트 매 홉 재검사, 본문 상한이
//!      저절로 적용된다. 자체 `reqwest::Client` 를 만들지 않는다.
//!   2. **파괴적 요청 없음.** 내장 템플릿은 GET/HEAD/OPTIONS 뿐이다.
//!      DELETE·DROP 같은 페이로드는 애초에 존재하지 않는다.
//!   3. **오탐 억제.** 상태코드나 본문 크기만으로는 매칭으로 인정하지 않는다.
//!      본문/헤더 계열 매처(word·regex)가 실제로 함께 걸려야 최종 매칭이 된다.
//!
//! ## 템플릿 스키마
//!
//! ```yaml
//! id: exposed-git-config
//! info:
//!   name: "Git config 노출"
//!   severity: high          # critical|high|medium|low|info
//!   author: forge
//!   description: "..."
//!   tags: exposure, config
//! requests:
//!   - method: GET
//!     paths:
//!       - "{{BaseURL}}/.git/config"
//!     headers:
//!       User-Agent: REDFORGE
//!     matchers:
//!       - type: word
//!         words: ["[core]"]
//!         part: body         # body(기본)|header|all
//!         condition: and     # and(기본)|or
//!         negative: false
//!       - type: status
//!         status: [200]
//!     extractors:
//!       - type: regex
//!         regex: ["url = \"(?P<u>[^\"]+)\""]
//!         group: 1
//! ```

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::report::Finding;
use crate::yaml::Yaml;

/// 증거로 남기는 본문 길이 (문자 단위).
pub const EVIDENCE_CHARS: usize = 800;

// ---------------------------------------------------------------------------
// 공개 타입
// ---------------------------------------------------------------------------

/// 매처가 바라보는 응답 부분.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchPart {
    /// 응답 본문.
    Body,
    /// 응답 헤더 전체를 `이름: 값` 줄로 이은 문자열.
    Header,
    /// 헤더 + 본문을 이어 붙인 문자열.
    All,
}

impl MatchPart {
    /// 사람이 읽는 이름.
    pub fn name(self) -> &'static str {
        match self {
            MatchPart::Body => "body",
            MatchPart::Header => "header",
            MatchPart::All => "all",
        }
    }
}

/// 매처 블록 안의 결합 조건.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// 블록 안 모든 매처가 참이어야 한다.
    And,
    /// 블록 안 매처가 하나라도 참이면 된다.
    Or,
}

/// 하나의 매처.
#[derive(Debug, Clone, PartialEq)]
pub enum Matcher {
    /// 본문(또는 헤더)에 모든 키워드가 포함되어야 한다.
    Word { words: Vec<String>, part: MatchPart, condition: Condition, negative: bool },
    /// 본문(또는 헤더)에 모든 정규식이 매치되어야 한다.
    Regex { regex: Vec<String>, part: MatchPart, condition: Condition, negative: bool },
    /// 응답 상태코드가 목록에 포함.
    Status { status: Vec<u16>, negative: bool },
    /// 응답 본문 길이 조건 — 지정된 gt/lt/eq 를 모두 만족해야 한다.
    Size { gt: Option<usize>, lt: Option<usize>, eq: Option<usize> },
}

impl Matcher {
    /// 본문/헤더 계열 매처인가 — 오탐 억제 규칙의 기준이 된다.
    pub fn is_content(&self) -> bool {
        matches!(self, Matcher::Word { .. } | Matcher::Regex { .. })
    }

    /// 이 매처가 속한 블록의 결합 조건.
    pub fn condition(&self) -> Condition {
        match self {
            Matcher::Word { condition, .. } | Matcher::Regex { condition, .. } => *condition,
            // 상태·크기 매처는 항상 and 블록의 보조 조건으로만 쓰인다.
            Matcher::Status { .. } | Matcher::Size { .. } => Condition::And,
        }
    }

    /// 매처를 사람이 읽는 설명으로 바꾼다.
    pub fn describe(&self) -> String {
        match self {
            Matcher::Word { words, part, .. } => {
                format!("word({}): {}", part.name(), words.join(", "))
            }
            Matcher::Regex { regex, part, .. } => {
                format!("regex({}): {}", part.name(), regex.join(", "))
            }
            Matcher::Status { status, .. } => {
                let codes: Vec<String> = status.iter().map(|s| s.to_string()).collect();
                format!("status: {}", codes.join(", "))
            }
            Matcher::Size { gt, lt, eq } => {
                let mut parts: Vec<String> = Vec::new();
                if let Some(v) = gt {
                    parts.push(format!("gt={v}"));
                }
                if let Some(v) = lt {
                    parts.push(format!("lt={v}"));
                }
                if let Some(v) = eq {
                    parts.push(format!("eq={v}"));
                }
                format!("size: {}", parts.join(", "))
            }
        }
    }
}

/// 추출기 — 응답에서 값을 뽑아 리포트에 남긴다.
#[derive(Debug, Clone, PartialEq)]
pub struct Extractor {
    /// 추출 방식. `regex`(기본, 본문) / `header`(헤더).
    pub kind: String,
    /// 정규식 목록 (첫 번째로 매치된 것만 사용).
    pub regex: Vec<String>,
    /// 사용할 그룹 번호 (1부터). named group 이 있으면 그 이름이 키가 된다.
    pub group: usize,
}

/// 템플릿의 요청 하나.
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateRequest {
    /// HTTP 메서드.
    pub method: String,
    /// 요청 경로 목록. `{{BaseURL}}` 는 대상 origin 으로 치환된다.
    pub paths: Vec<String>,
    /// 추가 헤더.
    pub headers: Vec<(String, String)>,
    /// 요청 본문 (없으면 없음).
    pub body: Option<String>,
    /// 매처 목록.
    pub matchers: Vec<Matcher>,
    /// 추출기 목록.
    pub extractors: Vec<Extractor>,
}

/// 템플릿 메타 정보.
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateInfo {
    /// 사람이 읽는 이름.
    pub name: String,
    /// 심각도 — critical|high|medium|low|info.
    pub severity: String,
    /// 작성자.
    pub author: String,
    /// 설명 (리포트 권고 문구에 재사용된다).
    pub description: String,
}

/// 템플릿 하나.
#[derive(Debug, Clone, PartialEq)]
pub struct Template {
    /// 템플릿 식별자 (고유).
    pub id: String,
    /// 메타 정보.
    pub info: TemplateInfo,
    /// 태그 — 태그 필터로 선택할 때 쓴다.
    pub tags: Vec<String>,
    /// 요청 목록.
    pub requests: Vec<TemplateRequest>,
}

/// 매칭 결과 하나.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TemplateMatch {
    /// 매칭된 템플릿 id.
    pub template_id: String,
    /// 템플릿 이름.
    pub name: String,
    /// 심각도.
    pub severity: String,
    /// 매칭된 URL.
    pub url: String,
    /// 어떤 매처가 걸렸는지 설명.
    pub matcher: String,
    /// 근거 — 시크릿을 마스킹한 본문 앞 800자.
    pub evidence: String,
    /// 추출된 값.
    pub extracted: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// 정규식 캐시 — 같은 패턴을 매번 컴파일하지 않는다.
// ---------------------------------------------------------------------------

fn regex_cache() -> &'static parking_lot::Mutex<BTreeMap<String, Option<Regex>>> {
    static CELL: OnceLock<parking_lot::Mutex<BTreeMap<String, Option<Regex>>>> = OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(BTreeMap::new()))
}

/// 정규식 컴파일(캐시). 실패하면 `None` — 템플릿 파싱 단계에서 이미 걸러진다.
fn compile_cached(pattern: &str) -> Option<Regex> {
    let mut cache = regex_cache().lock();
    if let Some(hit) = cache.get(pattern) {
        return hit.clone();
    }
    let compiled = Regex::new(pattern).ok();
    cache.insert(pattern.to_string(), compiled.clone());
    compiled
}

// ---------------------------------------------------------------------------
// 문자열 헬퍼 (네트워크 없이 테스트 가능한 순수 함수)
// ---------------------------------------------------------------------------

/// 헤더 목록을 `이름: 값` 줄 문자열로 바꾼다.
pub fn header_text(headers: &[(String, String)]) -> String {
    let mut out = String::new();
    for (k, v) in headers {
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push('\n');
    }
    out
}

/// 매처가 보는 문자열을 만든다.
pub fn part_text(part: MatchPart, body: &str, headers: &[(String, String)]) -> String {
    match part {
        MatchPart::Body => body.to_string(),
        MatchPart::Header => header_text(headers),
        MatchPart::All => {
            let mut out = header_text(headers);
            out.push_str(body);
            out
        }
    }
}

/// 대소문자 무시 포함 검사 (nuclei 와 동일하게 키워드는 case-insensitive).
fn contains_ignore_case(haystack_lower: &str, needle: &str) -> bool {
    haystack_lower.contains(&needle.to_ascii_lowercase())
}

/// 매처를 본문·헤더 문자열로 판정한다 — 네트워크 없이 테스트 가능.
pub fn match_on_parts(
    m: &Matcher,
    body: &str,
    headers: &[(String, String)],
    status: u16,
) -> bool {
    match m {
        Matcher::Word { words, part, negative, .. } => {
            let text = part_text(*part, body, headers);
            let lower = text.to_ascii_lowercase();
            let hit = words.iter().all(|w| contains_ignore_case(&lower, w));
            if *negative {
                !hit
            } else {
                hit
            }
        }
        Matcher::Regex { regex, part, negative, .. } => {
            let text = part_text(*part, body, headers);
            let hit = regex.iter().all(|p| {
                compile_cached(p).map(|re| re.is_match(&text)).unwrap_or(false)
            });
            if *negative {
                !hit
            } else {
                hit
            }
        }
        Matcher::Status { status: codes, negative } => {
            let hit = codes.contains(&status);
            if *negative {
                !hit
            } else {
                hit
            }
        }
        Matcher::Size { gt, lt, eq } => {
            // 지정된 모든 조건을 동시에 만족해야 한다 (gt/lt 는 범위).
            let len = body.len();
            let mut any = false;
            let mut ok = true;
            if let Some(v) = gt {
                any = true;
                ok = ok && len > *v;
            }
            if let Some(v) = lt {
                any = true;
                ok = ok && len < *v;
            }
            if let Some(v) = eq {
                any = true;
                ok = ok && len == *v;
            }
            // 아무 조건도 없으면 매치되지 않는다.
            any && ok
        }
    }
}

/// 매처를 실제 응답으로 판정한다.
pub fn match_block(m: &Matcher, resp: &HttpResponse) -> bool {
    match_on_parts(m, &resp.body, &resp.headers, resp.status)
}

/// 매처 목록을 블록으로 나눈다 — 같은 `condition` 을 가진 연속 매처가 한 블록이다.
fn blocks(matchers: &[Matcher]) -> Vec<Vec<&Matcher>> {
    let mut out: Vec<Vec<&Matcher>> = Vec::new();
    for m in matchers {
        match out.last_mut() {
            Some(last) if last.first().map(|f| f.condition()) == Some(m.condition()) => {
                last.push(m);
            }
            _ => out.push(vec![m]),
        }
    }
    out
}

/// 블록 설명 문자열을 만든다.
fn describe_block(condition: Condition, satisfied: &[&Matcher], method: &str) -> String {
    let joiner = match condition {
        Condition::And => " AND ",
        Condition::Or => " OR ",
    };
    let body: Vec<String> = satisfied.iter().map(|m| m.describe()).collect();
    let mut desc = body.join(joiner);
    // GET 이 아닌 메서드는 재생현 절차를 읽을 때 필요하므로 함께 적는다.
    let method = method.trim().to_ascii_uppercase();
    if !method.is_empty() && method != "GET" {
        desc = format!("{method}: {desc}");
    }
    desc
}

/// 추출기 실행 — 본문(또는 헤더)에서 그룹을 뽑는다.
pub fn extract_values(extractors: &[Extractor], body: &str, headers: &[(String, String)]) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for ext in extractors {
        let source = match ext.kind.trim().to_ascii_lowercase().as_str() {
            "header" => header_text(headers),
            _ => body.to_string(),
        };
        for pattern in &ext.regex {
            let Some(re) = compile_cached(pattern) else { continue };
            let Some(caps) = re.captures(&source) else { continue };
            // 지정 그룹이 없으면 named group 을 하나라도 찾아 쓴다.
            let mut index = ext.group;
            if caps.get(index).is_none() {
                let named = re
                    .capture_names()
                    .enumerate()
                    .find(|(i, name)| name.is_some() && caps.get(*i).is_some())
                    .map(|(i, _)| i);
                match named {
                    Some(i) => index = i,
                    None => continue,
                }
            }
            let Some(cap) = caps.get(index) else { continue };
            let key = re
                .capture_names()
                .nth(index)
                .flatten()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "extracted".to_string());
            // 첫 번째 값만 유지 (같은 키가 여러 번 나오면 첫 값 wins).
            out.entry(key).or_insert_with(|| crate::redact::redact_text(cap.as_str()));
        }
    }
    out
}

/// 요청 하나를 응답과 대조해 매칭 결과를 낸다.
///
/// 반환값: `(매칭 설명, 추출된 값)`. 매칭이 없으면 `None`.
///
/// 오탐 억제: 블록 하나가 매칭되더라도 **본문/헤더 계열 매처가 실제로 함께**
/// 걸렸어야 한다. 상태코드나 본문 크기만으로는 매칭으로 인정하지 않는다.
pub fn evaluate(
    req: &TemplateRequest,
    resp: &HttpResponse,
) -> Option<(String, BTreeMap<String, String>)> {
    for block in blocks(&req.matchers) {
        let satisfied: Vec<&Matcher> = block
            .iter()
            .copied()
            .filter(|m| match_block(m, resp))
            .collect();
        let condition = block.first().map(|m| m.condition()).unwrap_or(Condition::And);
        let hit = match condition {
            Condition::And => satisfied.len() == block.len(),
            Condition::Or => !satisfied.is_empty(),
        };
        if !hit {
            continue;
        }
        // 본문/헤더 계열 매처가 함께 걸렸어야 인정한다.
        if !satisfied.iter().any(|m| m.is_content()) {
            continue;
        }
        let desc = describe_block(condition, &satisfied, &req.method);
        let extracted = extract_values(&req.extractors, &resp.body, &resp.headers);
        return Some((desc, extracted));
    }
    None
}

// ---------------------------------------------------------------------------
// 파서
// ---------------------------------------------------------------------------

/// `{{BaseURL}}` 을 대상 origin 으로 치환한다.
pub fn substitute_base(path: &str, base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let mut out = String::with_capacity(path.len() + base.len());
    let mut rest = path;
    loop {
        let Some(idx) = rest.find("{{BaseURL}}") else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..idx]);
        out.push_str(base);
        let after = &rest[idx + "{{BaseURL}}".len()..];
        // 경로 구분자가 없으면 붙여 준다 ("http://h" + "x" → "http://h/x").
        if after.is_empty() || after.starts_with('/') || after.starts_with('?') || after.starts_with('#') {
            rest = after;
        } else {
            out.push('/');
            rest = after;
        }
    }
    out
}

/// YAML 문서 문자열(들)을 파싱해 템플릿 목록으로 만든다.
///
/// `---` 로 구분된 다중 문서를 지원한다.
pub fn parse_template(text: &str) -> Result<Vec<Template>, String> {
    let mut out: Vec<Template> = Vec::new();
    for (idx, doc) in split_documents(text).iter().enumerate() {
        if doc.trim().is_empty() {
            continue;
        }
        let tpl = parse_one(doc).map_err(|e| format!("문서 #{}: {}", idx + 1, e))?;
        out.push(tpl);
    }
    if out.is_empty() {
        return Err("템플릿 문서가 비어 있습니다.".into());
    }
    Ok(out)
}

/// `---` 구분자로 문서를 나눈다.
fn split_documents(text: &str) -> Vec<String> {
    let mut docs: Vec<String> = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if line.trim() == "---" {
            docs.push(std::mem::take(&mut cur));
            continue;
        }
        cur.push_str(line);
        cur.push('\n');
    }
    docs.push(cur);
    docs
}

/// YAML 한 문서를 템플릿으로 파싱한다.
fn parse_one(text: &str) -> Result<Template, String> {
    let doc = crate::yaml::parse(text).map_err(|e| format!("YAML 파싱 실패 — {e}"))?;
    let id = yaml_text(&doc, "id")
        .ok_or_else(|| "id 가 없습니다.".to_string())?
        .trim()
        .to_string();
    if id.is_empty() {
        return Err("id 가 비어 있습니다.".into());
    }

    let info_node = doc.get("info");
    let name = info_node
        .and_then(|i| yaml_text(i, "name"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| id.clone());
    let severity = info_node
        .and_then(|i| yaml_text(i, "severity"))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "info".to_string());
    if !matches!(severity.as_str(), "critical" | "high" | "medium" | "low" | "info") {
        return Err(format!("알 수 없는 severity: {severity}"));
    }
    let author = info_node
        .and_then(|i| yaml_text(i, "author"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "forge".to_string());
    let description = info_node
        .and_then(|i| yaml_text(i, "description"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let tags = match parse_tags(doc.get("tags")) {
        Some(top) if !top.is_empty() => top,
        _ => info_node
            .and_then(|i| parse_tags(i.get("tags")))
            .unwrap_or_default(),
    };

    let requests_node = doc
        .get("requests")
        .ok_or_else(|| "requests 가 없습니다.".to_string())?;
    let items = requests_node
        .as_seq()
        .ok_or_else(|| "requests 는 목록이어야 합니다.".to_string())?;
    if items.is_empty() {
        return Err("requests 가 비어 있습니다.".into());
    }
    let mut requests: Vec<TemplateRequest> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let req = parse_request(item).map_err(|e| format!("requests[{i}] — {e}"))?;
        requests.push(req);
    }

    Ok(Template { id, info: TemplateInfo { name, severity, author, description }, tags, requests })
}

/// 요청 하나를 파싱한다.
fn parse_request(node: &Yaml) -> Result<TemplateRequest, String> {
    let method = yaml_text(node, "method")
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "GET".to_string());
    let paths = yaml_string_list(node, "paths").ok_or_else(|| "paths 가 없습니다.".to_string())?;
    if paths.is_empty() {
        return Err("paths 가 비어 있습니다.".into());
    }
    let headers = parse_headers(node.get("headers"));
    let body = yaml_text(node, "body");

    let matchers = parse_matchers(node.get("matchers"))?;
    if matchers.is_empty() {
        return Err("matchers 가 없습니다.".into());
    }
    // 오탐 억제: 본문/헤더 계열 매처가 하나도 없으면(status·size 뿐인 경우) 거부한다.
    if !matchers.iter().any(|m| m.is_content()) {
        return Err(
            "상태 코드나 크기 매처만으로는 매칭을 인정하지 않습니다 — 본문/헤더 매처를 추가하세요."
                .into(),
        );
    }
    let extractors = parse_extractors(node.get("extractors"))?;

    Ok(TemplateRequest { method, paths, headers, body, matchers, extractors })
}

/// 매처 목록 파싱.
fn parse_matchers(node: Option<&Yaml>) -> Result<Vec<Matcher>, String> {
    let Some(node) = node else { return Ok(Vec::new()) };
    let items = node.as_seq().ok_or_else(|| "matchers 는 목록이어야 합니다.".to_string())?;
    let mut out: Vec<Matcher> = Vec::new();
    for item in items {
        out.push(parse_matcher(item)?);
    }
    Ok(out)
}

/// 매처 하나 파싱.
fn parse_matcher(node: &Yaml) -> Result<Matcher, String> {
    let mtype = yaml_text(node, "type")
        .map(|s| s.trim().to_ascii_lowercase())
        .ok_or_else(|| "매처에 type 이 없습니다.".to_string())?;
    let part = match yaml_text(node, "part")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "body".to_string())
        .as_str()
    {
        "body" => MatchPart::Body,
        "header" => MatchPart::Header,
        "all" => MatchPart::All,
        other => return Err(format!("알 수 없는 part: {other}")),
    };
    let condition = match yaml_text(node, "condition")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "and".to_string())
        .as_str()
    {
        "and" => Condition::And,
        "or" => Condition::Or,
        other => return Err(format!("알 수 없는 condition: {other}")),
    };
    let negative = node.get("negative").and_then(|v| v.as_bool()).unwrap_or(false);

    match mtype.as_str() {
        "word" => {
            let words = yaml_string_list(node, "words").ok_or_else(|| "words 가 없습니다.".to_string())?;
            if words.is_empty() {
                return Err("words 가 비어 있습니다.".into());
            }
            Ok(Matcher::Word { words, part, condition, negative })
        }
        "regex" => {
            let regex = yaml_string_list(node, "regex").ok_or_else(|| "regex 가 없습니다.".to_string())?;
            if regex.is_empty() {
                return Err("regex 가 비어 있습니다.".into());
            }
            for pattern in &regex {
                // 정규식 컴파일 실패는 파싱 단계에서 에러로 처리한다.
                Regex::new(pattern)
                    .map_err(|e| format!("정규식 컴파일 실패 — {pattern} ({e})"))?;
            }
            Ok(Matcher::Regex { regex, part, condition, negative })
        }
        "status" => {
            let codes = yaml_u16_list(node, "status").ok_or_else(|| "status 가 없습니다.".to_string())?;
            if codes.is_empty() {
                return Err("status 가 비어 있습니다.".into());
            }
            Ok(Matcher::Status { status: codes, negative })
        }
        "size" => {
            let gt = yaml_size(node, "gt");
            let lt = yaml_size(node, "lt");
            let eq = yaml_size(node, "eq");
            if gt.is_none() && lt.is_none() && eq.is_none() {
                return Err("size 는 gt/lt/eq 중 하나 이상이 필요합니다.".into());
            }
            Ok(Matcher::Size { gt, lt, eq })
        }
        other => Err(format!("알 수 없는 matcher type: {other}")),
    }
}

/// 추출기 목록 파싱.
fn parse_extractors(node: Option<&Yaml>) -> Result<Vec<Extractor>, String> {
    let Some(node) = node else { return Ok(Vec::new()) };
    let items = node.as_seq().ok_or_else(|| "extractors 는 목록이어야 합니다.".to_string())?;
    let mut out: Vec<Extractor> = Vec::new();
    for item in items {
        let kind = yaml_text(item, "type")
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "regex".to_string());
        if kind != "regex" && kind != "header" {
            return Err(format!("알 수 없는 extractor type: {kind}"));
        }
        let regex = yaml_string_list(item, "regex").ok_or_else(|| "extractor 의 regex 가 없습니다.".to_string())?;
        if regex.is_empty() {
            return Err("extractor 의 regex 가 비어 있습니다.".into());
        }
        for pattern in &regex {
            Regex::new(pattern)
                .map_err(|e| format!("추출기 정규식 컴파일 실패 — {pattern} ({e})"))?;
        }
        let group = yaml_size(item, "group").unwrap_or(1);
        out.push(Extractor { kind, regex, group });
    }
    Ok(out)
}

/// 헤더 파싱 — 맵 또는 `이름: 값` 목록.
fn parse_headers(node: Option<&Yaml>) -> Vec<(String, String)> {
    let Some(node) = node else { return Vec::new() };
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in node.as_str_map() {
        out.push((k, v));
    }
    if let Some(items) = node.as_seq() {
        for item in items {
            if let Some(line) = item.as_text() {
                if let Some((k, v)) = line.split_once(':') {
                    out.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
        }
    }
    out
}

// --- YAML 헬퍼 -------------------------------------------------------------

fn yaml_text(node: &Yaml, key: &str) -> Option<String> {
    node.get(key).and_then(|v| v.as_text())
}

/// 문자열 목록 — 시퀀스 또는 콤마 구분 문자열.
fn yaml_string_list(node: &Yaml, key: &str) -> Option<Vec<String>> {
    let Some(value) = node.get(key) else { return None };
    let mut out: Vec<String> = Vec::new();
    match value {
        Yaml::Seq(items) => {
            for item in items {
                if let Some(text) = item.as_text() {
                    let t = text.trim().to_string();
                    if !t.is_empty() {
                        out.push(t);
                    }
                }
            }
        }
        Yaml::Str(text) => {
            for part in text.split(',') {
                let t = part.trim().trim_matches('"').trim_matches('\'').to_string();
                if !t.is_empty() {
                    out.push(t);
                }
            }
        }
        _ => return None,
    }
    Some(out)
}

/// u16 목록 (상태 코드).
fn yaml_u16_list(node: &Yaml, key: &str) -> Option<Vec<u16>> {
    let Some(value) = node.get(key) else { return None };
    let mut out: Vec<u16> = Vec::new();
    match value {
        Yaml::Seq(items) => {
            for item in items {
                if let Some(n) = item.as_f64() {
                    if (0.0..=65535.0).contains(&n) {
                        out.push(n as u16);
                    }
                }
            }
        }
        Yaml::Num(n) => {
            if (0.0..=65535.0).contains(n) {
                out.push(*n as u16);
            }
        }
        _ => return None,
    }
    Some(out)
}

/// usize 값 하나.
fn yaml_size(node: &Yaml, key: &str) -> Option<usize> {
    let n = node.get(key).and_then(|v| v.as_f64())?;
    if n < 0.0 {
        return None;
    }
    Some(n as usize)
}

/// 태그 목록 — 시퀀스 또는 콤마 구분 문자열.
fn parse_tags(node: Option<&Yaml>) -> Option<Vec<String>> {
    let node = node?;
    let list = match node {
        Yaml::Seq(items) => items
            .iter()
            .filter_map(|i| i.as_text())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>(),
        Yaml::Str(text) => text
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>(),
        _ => return None,
    };
    Some(list)
}

// ---------------------------------------------------------------------------
// 실행
// ---------------------------------------------------------------------------

/// 심각도 → 순위 (높을수록 심각).
pub fn severity_rank(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

/// 템플릿을 실행한다.
///
/// - `tag_filter` 가 주어지면 태그가 하나라도 겹치는 템플릿만 실행한다.
/// - `min_severity` 보다 낮은 심각도의 템플릿은 실행하지 않는다.
/// - 각 경로는 최대 1회 요청한다(실패하면 조용히 넘어간다).
pub async fn execute(
    client: &HttpClient,
    t: &Template,
    base_url: &str,
    tag_filter: Option<&[String]>,
    min_severity: &str,
) -> Result<Vec<TemplateMatch>, String> {
    // 1) 태그 필터.
    if let Some(tags) = tag_filter {
        if !tags.is_empty() {
            let hit = t
                .tags
                .iter()
                .any(|tt| tags.iter().any(|w| w.eq_ignore_ascii_case(tt)));
            if !hit {
                return Ok(Vec::new());
            }
        }
    }
    // 2) 심각도 하한.
    if severity_rank(&t.info.severity) < severity_rank(min_severity) {
        return Ok(Vec::new());
    }

    let mut out: Vec<TemplateMatch> = Vec::new();
    for req in &t.requests {
        for path in &req.paths {
            let url = substitute_base(path, base_url);
            // 치환되지 않은 placeholder 가 남아 있으면 요청하지 않는다.
            if url.contains("{{") {
                continue;
            }
            let mut http_req = HttpRequest::new(&req.method, &url);
            http_req.headers = req.headers.clone();
            http_req.body = req.body.clone();
            http_req.follow_redirects = true;
            http_req.timeout_secs = 0;

            let Ok(resp) = client.send(&http_req).await else { continue };

            let Some((matcher, extracted)) = evaluate(req, &resp) else { continue };

            let redacted = crate::redact::redact_text(&resp.body);
            let evidence: String = redacted.chars().take(EVIDENCE_CHARS).collect();

            out.push(TemplateMatch {
                template_id: t.id.clone(),
                name: t.info.name.clone(),
                severity: t.info.severity.clone(),
                url: resp.url.clone(),
                matcher,
                evidence,
                extracted,
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 리포트 변환
// ---------------------------------------------------------------------------

/// 매칭 결과 → 리포트 발견.
pub fn to_findings(matches: &[TemplateMatch]) -> Vec<Finding> {
    matches
        .iter()
        .map(|m| Finding {
            title: m.name.clone(),
            severity: m.severity.clone(),
            category: format!("template:{}", m.template_id),
            target: m.url.clone(),
            evidence: m.evidence.clone(),
            reproduction: format!("GET {} (매처: {})", m.url, m.matcher),
            remediation: remediation_for(&m.template_id),
        })
        .collect()
}

/// 시그니처별 한국어 권고 문구.
pub fn remediation_for(template_id: &str) -> String {
    let text = match template_id {
        "exposed-git-config" => {
            "원본 저장소 디렉터리가 웹에서 내려받아집니다. 배포 산출물에 .git 을 포함하지 말고, \
             배포 파이프라인에서 버전 관리 메타데이터를 제거하세요. 서버에 이미 노출되었다면 \
             저장소 이력(비밀값 포함)을 회전시키세요."
        }
        "exposed-git-head" => {
            "Git HEAD 파일이 노출되어 브랜치·커밋 정보를 얻을 수 있습니다. .git 디렉터리를 \
             웹 루트 밖으로 옮기거나 배포 시 제거하세요."
        }
        "exposed-svn-entries" => {
            "Subversion 메타데이터가 노출되어 파일 목록을 알 수 있습니다. .svn 디렉터리를 배포 \
             산출물에서 제거하고, 정적 배포 시 VCS 메타데이터를 제외하세요."
        }
        "exposed-env-file" => {
            "환경 설정 파일이 노출되어 데이터베이스 자격증명·API 키가 유출될 수 있습니다. \
             .env 파일을 웹 루트 밖에 두고, 시크릿 관리자(Vault·Secrets Manager)로 옮기며 \
             노출된 값은 즉시 회전시키세요."
        }
        "exposed-web-config" => {
            "IIS web.config 가 노출되어 연결 문자열과 내부 경로가 드러납니다. 설정 파일을 \
             웹 루트 밖으로 옮기거나 배포 단계에서 연결 문자열을 환경 변수로 치환하세요."
        }
        "exposed-ds-store" => {
            "macOS 디렉터리 목록 파일(.DS_Store)이 노출되어 파일 이름이 유출됩니다. \
             운영 서버에서는 .DS_Store 를 삭제하고 배포 파이프라인에서 제외하세요."
        }
        "exposed-phpinfo" => {
            "phpinfo() 출력 페이지가 공개되어 PHP 버전·모듈·환경 변수·절대 경로가 노출됩니다. \
             해당 파일을 삭제하고 display_errors=Off 로 운영하세요."
        }
        "exposed-server-status" => {
            "Apache server-status 가 공개되어 요청 로그·프로세스 목록·원격 주소가 노출됩니다. \
             mod_status 접근을 로컬(127.0.0.1) 또는 관리자 대역으로 제한하세요."
        }
        "exposed-actuator-env" => {
            "Spring Boot actuator/env 가 노출되어 환경 변수·자격증명·내부 설정이 유출됩니다. \
             actuator 엔드포인트를 관리 포트/내부망으로 격리하고 management.endpoints.enabled-by-default \
             를 off 로 설정하세요."
        }
        "exposed-actuator-health" => {
            "헬스 체크 엔드포인트가 외부에 열려 있습니다. 상태 정보 노출 범위를 줄이고 \
             관리 포트를 분리하거나 인증을 걸어 사설망으로만 노출하세요."
        }
        "exposed-actuator-mappings" => {
            "actuator/mappings 가 라우팅 테이블을 노출합니다. 전체 라우팅을 알 수 있어 \
             숨겨진 관리 API 를 찾는 단서가 됩니다. actuator 를 내부망으로만 공개하세요."
        }
        "exposed-debug-vars" => {
            "디버그 변조 페이지가 노출되어 애플리케이션 내부 객체 구조가 드러납니다. \
             운영 환경에서 디버그 엔드포인트를 제거하거나 인증 뒤에 두세요."
        }
        "exposed-wp-login" => {
            "워드프레스 로그인 페이지가 노출되어 관리자 계정 존재 여부와 버전이 드러납니다. \
             로그인 페이지 접근 제한·2단계 인증·비밀번호 정책·xmlrpc 비활성화를 검토하세요."
        }
        "exposed-h2-console" => {
            "H2 데이터베이스 콘솔이 공개되어 임의 SQL 실행이 가능할 수 있습니다. \
             콘솔 엔드포인트를 제거하거나 사설망·인증 뒤에만 허용하고 JDBC URL 을 분리하세요."
        }
        "exposed-swagger-json" => {
            "Swagger/OpenAPI 명세가 노출되어 전체 API 구조·파라미터·권한 요구사항이 드러납니다. \
             운영 환경에서 문서 엔드포인트를 비활성화하거나 인증을 걸어 보호하세요."
        }
        "exposed-openapi-json" => {
            "OpenAPI 명세 파일이 노출되어 내부 API 계약이 드러납니다. 문서 엔드포인트를 \
             내부망 또는 인증 뒤로 옮기고, 민감한 내부 API 는 명세에서 제외하세요."
        }
        "exposed-api-docs" => {
            "API 문서 UI 가 공개되어 내부 API 를 목록화할 수 있습니다. 문서 서버를 사설망으로 \
             격리하거나 인증을 적용하세요."
        }
        "exposed-graphql" => {
            "GraphQL 엔드포인트가 공개되어 스키마 추측(introspection)으로 전체 구조를 볼 수 \
             있습니다. 운영 환경에서 introspection 을 끄고 쿼리 복잡도 제한과 인증을 적용하세요."
        }
        "exposed-security-txt" => {
            "security.txt 가 노출되어 보안 담당 연락처 정보가 공개됩니다. 민감한 내부 정보는 \
             넣지 말고, 표준 형식의 공개 문서로는 문제가 없습니다."
        }
        "exposed-sitemap" => {
            "사이트맵이 노출되어 숨겨진 경로·관리 페이지 후보가 드러납니다. 민감 경로가 포함되면 \
             사이트맵에서 제외하고, 노출된 경로에 인증을 적용하세요."
        }
        "exposed-backup-zip" => {
            "백업 압축 파일이 웹에서 내려받아집니다. 백업 파일을 웹 루트 밖의 별도 저장소로 \
             옮기고, 다운로드 접근을 차단하세요. 노출된 백업은 신뢰할 수 없으므로 폐기·회전이 필요합니다."
        }
        "exposed-dump-sql" => {
            "데이터베이스 덤프가 노출되어 테이블 구조와 데이터가 유출됩니다. 즉시 덤프를 삭제하고 \
             자격증명·비밀값을 회전시키세요. 웹 루트에 덤프를 두지 말고 백업 저장소를 분리하세요."
        }
        "missing-security-headers" => {
            "보안 응답 헤더(HSTS·X-Frame-Options·X-Content-Type-Options·Content-Security-Policy)가 \
             빠져 있습니다. 리버스 프록시 계층에서 헤더를 강제로 추가하세요."
        }
        "x-powered-by-version" => {
            "X-Powered-By 헤더로 서버 tech 스택과 버전이 노출됩니다. 해당 헤더를 제거하거나 \
             버전 정보를 무효화하세요."
        }
        "server-version-disclosure" => {
            "Server 헤더로 웹 서버 종류와 버전이 노출됩니다. 서버 배너를 숨기고 최신 패치 상태를 \
             유지하세요."
        }
        "cors-misconfiguration" => {
            "Access-Control-Allow-Origin: * 와 Access-Control-Allow-Credentials: true 가 함께 \
             설정되어 임의 출처의 요청이 자격증명을 탈취할 수 있습니다. 원본 출처를 명시적으로 \
             허용하고 와일드카드와 자격증명 허용을 함께 쓰지 마세요."
        }
        "directory-listing" => {
            "디렉터리 목록이 활성화되어 파일 구조가 노출됩니다. autoindex 를 끄고, 목록이 필요한 \
             경로는 인증 뒤에 두세요."
        }
        "php-info-page" => {
            "PHP 정보 페이지가 노출되어 버전·확장 모듈·환경 변수·절대 경로가 공개됩니다. \
             해당 페이지를 삭제하고 운영 환경에서 오류 표시를 끄세요."
        }
        "open-redirect" => {
            "외부 도메인으로 리다이렉트가 되어 피싱 URL 변조에 악용될 수 있습니다. \
             리다이렉트 대상을 허용 목록으로 검증하고 상대 경로만 허용하세요."
        }
        "options-method" => {
            "OPTIONS 응답이 PUT·DELETE·TRACE 같은 메서드를 허용한다고 밝힙니다. 서버 설정에서 \
             필요 없는 메서드를 비활성화하고, TRACE 는 반드시 차단하세요."
        }
        _ => {
            "노출된 표면을 최소화하고 재현 절차를 확인한 뒤 방어적으로 수정하세요."
        }
    };
    text.to_string()
}

// ---------------------------------------------------------------------------
// 내장 템플릿 팩
// ---------------------------------------------------------------------------

// --- 생성 도우미 -----------------------------------------------------------

fn m_word(words: &[&str], part: MatchPart, condition: Condition, negative: bool) -> Matcher {
    Matcher::Word {
        words: words.iter().map(|w| w.to_string()).collect(),
        part,
        condition,
        negative,
    }
}

fn m_regex(patterns: &[&str], part: MatchPart, condition: Condition, negative: bool) -> Matcher {
    Matcher::Regex {
        regex: patterns.iter().map(|p| p.to_string()).collect(),
        part,
        condition,
        negative,
    }
}

fn m_status(codes: &[u16]) -> Matcher {
    Matcher::Status { status: codes.to_vec(), negative: false }
}

fn m_extractor(patterns: &[&str], group: usize) -> Extractor {
    Extractor {
        kind: "regex".to_string(),
        regex: patterns.iter().map(|p| p.to_string()).collect(),
        group,
    }
}

fn m_header_extractor(patterns: &[&str], group: usize) -> Extractor {
    Extractor {
        kind: "header".to_string(),
        regex: patterns.iter().map(|p| p.to_string()).collect(),
        group,
    }
}

fn request(
    method: &str,
    paths: &[&str],
    headers: &[(&str, &str)],
    matchers: Vec<Matcher>,
    extractors: Vec<Extractor>,
) -> TemplateRequest {
    TemplateRequest {
        method: method.to_string(),
        paths: paths.iter().map(|p| p.to_string()).collect(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: None,
        matchers,
        extractors,
    }
}

fn template(
    id: &str,
    name: &str,
    severity: &str,
    description: &str,
    tags: &[&str],
    requests: Vec<TemplateRequest>,
) -> Template {
    Template {
        id: id.to_string(),
        info: TemplateInfo {
            name: name.to_string(),
            severity: severity.to_string(),
            author: "forge".to_string(),
            description: description.to_string(),
        },
        tags: tags.iter().map(|t| t.to_string()).collect(),
        requests,
    }
}

const UA: (&str, &str) = ("User-Agent", "REDFORGE");

/// 내장 템플릿 팩 (30개).
///
/// 노출(exposure) 계열과 설정/헤더 계열로 나뉘며, 모든 템플릿은
/// 본문/헤더 계열 매처를 하나 이상 포함한다(상태 코드만으로는 매칭되지 않는다).
pub fn builtin_templates() -> Vec<Template> {
    vec![
        // --- 노출(exposure) 계열 ---
        template(
            "exposed-git-config",
            "Git 설정 파일 노출",
            "high",
            "원본 저장소의 .git/config 가 웹에서 그대로 내려받아집니다.",
            &["exposure", "git", "config"],
            vec![request(
                "GET",
                &["{{BaseURL}}/.git/config"],
                &[UA],
                vec![
                    m_word(&["[core]"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![m_extractor(&[r"(?m)^\s*url\s*=\s*(?P<url>.+)$"], 1)],
            )],
        ),
        template(
            "exposed-git-head",
            "Git HEAD 노출",
            "high",
            ".git/HEAD 가 노출되어 브랜치·커밋 정보가 유출됩니다.",
            &["exposure", "git"],
            vec![request(
                "GET",
                &["{{BaseURL}}/.git/HEAD"],
                &[UA],
                vec![
                    m_word(&["ref:"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![m_extractor(&[r"(?m)^ref:\s*(?P<ref>\S+)"], 1)],
            )],
        ),
        template(
            "exposed-svn-entries",
            "Subversion 메타데이터 노출",
            "high",
            ".svn/entries 가 노출되어 파일 목록이 유출됩니다.",
            &["exposure", "svn"],
            vec![request(
                "GET",
                &["{{BaseURL}}/.svn/entries"],
                &[UA],
                vec![
                    m_regex(&[r"(?m)^(?:dir|file)\s*$"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-env-file",
            "환경 설정 파일 노출",
            "critical",
            ".env 파일이 노출되어 자격증명·API 키가 유출될 수 있습니다.",
            &["exposure", "secrets", "config"],
            vec![request(
                "GET",
                &["{{BaseURL}}/.env", "{{BaseURL}}/.env.local", "{{BaseURL}}/.env.production"],
                &[UA],
                vec![
                    m_regex(&[r"(?m)^[A-Z][A-Z0-9_]{2,}=[^\s]+$"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![m_extractor(&[r"(?m)^(?P<key>[A-Z][A-Z0-9_]{2,})="], 1)],
            )],
        ),
        template(
            "exposed-web-config",
            "IIS web.config 노출",
            "high",
            "web.config 가 노출되어 연결 문자열이 드러납니다.",
            &["exposure", "config", "iis"],
            vec![request(
                "GET",
                &["{{BaseURL}}/web.config", "{{BaseURL}}/Web.config"],
                &[UA],
                vec![
                    m_word(&["<configuration"], MatchPart::Body, Condition::And, false),
                    m_regex(&[r"(?i)<add\s+key=\S+"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-ds-store",
            ".DS_Store 노출",
            "low",
            "macOS 디렉터리 목록 파일이 노출되어 파일명이 유출됩니다.",
            &["exposure", "file"],
            vec![request(
                "GET",
                &["{{BaseURL}}/.DS_Store"],
                &[UA],
                vec![
                    m_word(&["Bud1"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-phpinfo",
            "phpinfo() 노출",
            "high",
            "phpinfo() 출력이 공개되어 PHP 버전과 환경이 노출됩니다.",
            &["exposure", "php", "debug"],
            vec![request(
                "GET",
                &["{{BaseURL}}/phpinfo.php", "{{BaseURL}}/phpinfo.php?x=1"],
                &[UA],
                vec![
                    m_word(&["phpinfo()"], MatchPart::Body, Condition::And, false),
                    m_word(&["php version"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-server-status",
            "Apache server-status 노출",
            "medium",
            "서버 상태 페이지가 공개되어 요청 로그가 유출됩니다.",
            &["exposure", "apache", "debug"],
            vec![request(
                "GET",
                &["{{BaseURL}}/server-status", "{{BaseURL}}/server-status/"],
                &[UA],
                vec![
                    m_word(&["server status"], MatchPart::Body, Condition::And, false),
                    m_regex(&[r"(?i)server\s+status\s+for"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-actuator-env",
            "Spring actuator/env 노출",
            "critical",
            "actuator/env 가 환경 변수와 자격증명을 그대로 노출합니다.",
            &["exposure", "spring", "secrets"],
            vec![request(
                "GET",
                &["{{BaseURL}}/actuator/env", "{{BaseURL}}/manage/actuator/env"],
                &[UA],
                vec![
                    m_word(&["propertysources"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-actuator-health",
            "Spring actuator/health 노출",
            "low",
            "헬스 체크 엔드포인트가 외부에 열려 있습니다.",
            &["exposure", "spring"],
            vec![request(
                "GET",
                &["{{BaseURL}}/actuator/health"],
                &[UA],
                vec![
                    m_word(&["\"status\""], MatchPart::Body, Condition::And, false),
                    m_regex(&[r#"(?i)"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE)""#], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-actuator-mappings",
            "Spring actuator/mappings 노출",
            "medium",
            "라우팅 테이블이 노출되어 내부 API 구조가 드러납니다.",
            &["exposure", "spring"],
            vec![request(
                "GET",
                &["{{BaseURL}}/actuator/mappings"],
                &[UA],
                vec![
                    m_word(&["\"mappings\""], MatchPart::Body, Condition::And, false),
                    m_regex(&[r#"(?i)"(handler|bean|resource)""#], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-debug-vars",
            "디버그 변조 엔드포인트 노출",
            "medium",
            "debug/vars 등이 노출되어 내부 객체 구조가 드러납니다.",
            &["exposure", "debug", "spring"],
            vec![request(
                "GET",
                &["{{BaseURL}}/debug/vars", "{{BaseURL}}/debug/pprof"],
                &[UA],
                vec![
                    m_word(&["classloader"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-wp-login",
            "워드프레스 로그인 노출",
            "low",
            "워드프레스 로그인 페이지가 공개되어 관리자 계정 존재가 드러납니다.",
            &["exposure", "wordpress"],
            vec![request(
                "GET",
                &["{{BaseURL}}/wp-login.php", "{{BaseURL}}/xmlrpc.php"],
                &[UA],
                vec![
                    m_word(&["user_login"], MatchPart::Body, Condition::And, false),
                    m_regex(&[r#"name=["']?user_login["']?"#], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-h2-console",
            "H2 데이터베이스 콘솔 노출",
            "critical",
            "H2 콘솔이 공개되어 임의 SQL 실행 위험이 있습니다.",
            &["exposure", "h2", "database"],
            vec![request(
                "GET",
                &["{{BaseURL}}/h2-console", "{{BaseURL}}/h2-console/login.do"],
                &[UA],
                vec![
                    m_word(&["h2 console"], MatchPart::Body, Condition::And, false),
                    m_regex(&[r"(?i)h2-console"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-swagger-json",
            "Swagger 명세 노출",
            "medium",
            "Swagger 2.0 명세가 공개되어 API 구조가 드러납니다.",
            &["exposure", "api-docs"],
            vec![request(
                "GET",
                &["{{BaseURL}}/swagger.json", "{{BaseURL}}/v2/api-docs"],
                &[UA],
                vec![
                    m_word(&["\"swagger\""], MatchPart::Body, Condition::And, false),
                    m_word(&["\"paths\""], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-openapi-json",
            "OpenAPI 명세 노출",
            "medium",
            "OpenAPI 3.0 명세가 공개되어 API 계약이 드러납니다.",
            &["exposure", "api-docs"],
            vec![request(
                "GET",
                &["{{BaseURL}}/openapi.json", "{{BaseURL}}/v3/api-docs"],
                &[UA],
                vec![
                    m_word(&["\"openapi\""], MatchPart::Body, Condition::And, false),
                    m_word(&["\"paths\""], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-api-docs",
            "API 문서 페이지 노출",
            "medium",
            "API 문서 UI 가 공개되어 내부 API 를 목록화할 수 있습니다.",
            &["exposure", "api-docs"],
            vec![request(
                "GET",
                &["{{BaseURL}}/api-docs", "{{BaseURL}}/api-docs/"],
                &[UA],
                vec![
                    m_word(&["swagger"], MatchPart::Body, Condition::And, false),
                    m_regex(&[r"(?i)(swagger-ui|api-docs)"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-graphql",
            "GraphQL 엔드포인트 노출",
            "medium",
            "GraphQL 엔드포인트가 공개되어 스키마를 추측할 수 있습니다.",
            &["exposure", "graphql", "api"],
            vec![request(
                "GET",
                &["{{BaseURL}}/graphql", "{{BaseURL}}/api/graphql", "{{BaseURL}}/graphiql"],
                &[UA],
                vec![
                    m_word(&["graphql"], MatchPart::Body, Condition::And, false),
                    m_regex(&[r#"(?i)"(data|errors|__typename)"\s*:"#], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-security-txt",
            "security.txt 노출",
            "info",
            "보안 담당자 연락처가 담긴 security.txt 가 공개되어 있습니다.",
            &["exposure", "info"],
            vec![request(
                "GET",
                &["{{BaseURL}}/.well-known/security.txt", "{{BaseURL}}/security.txt"],
                &[UA],
                vec![
                    m_regex(&[r"(?im)^contact:"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-sitemap",
            "사이트맵 노출",
            "info",
            "사이트맵이 공개되어 숨겨진 경로 후보가 드러납니다.",
            &["exposure", "info"],
            vec![request(
                "GET",
                &["{{BaseURL}}/sitemap.xml"],
                &[UA],
                vec![
                    m_regex(&[r"(?i)<urlset"], MatchPart::Body, Condition::And, false),
                    m_regex(&[r"(?i)<loc>"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-backup-zip",
            "백업 압축 파일 노출",
            "high",
            "백업 압축 파일이 웹에서 내려받아집니다.",
            &["exposure", "backup"],
            vec![request(
                "GET",
                &["{{BaseURL}}/backup.zip", "{{BaseURL}}/site.zip", "{{BaseURL}}/www.zip"],
                &[UA],
                vec![
                    m_regex(&[r"PK\x03\x04"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "exposed-dump-sql",
            "데이터베이스 덤프 노출",
            "critical",
            "SQL 덤프 파일이 공개되어 스키마와 데이터가 유출됩니다.",
            &["exposure", "backup", "database"],
            vec![request(
                "GET",
                &["{{BaseURL}}/dump.sql", "{{BaseURL}}/backup.sql", "{{BaseURL}}/db.sql"],
                &[UA],
                vec![
                    m_regex(&[r"(?i)CREATE\s+TABLE"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        // --- 설정/헤더 계열 ---
        template(
            "missing-security-headers",
            "보안 응답 헤더 미설정",
            "low",
            "HSTS·X-Frame-Options·X-Content-Type-Options·Content-Security-Policy 가 없습니다.",
            &["config", "headers"],
            vec![request(
                "GET",
                &["{{BaseURL}}"],
                &[UA],
                vec![
                    m_word(&["strict-transport-security"], MatchPart::Header, Condition::And, true),
                    m_word(&["x-frame-options"], MatchPart::Header, Condition::And, true),
                    m_word(&["x-content-type-options"], MatchPart::Header, Condition::And, true),
                    m_word(&["content-security-policy"], MatchPart::Header, Condition::And, true),
                ],
                vec![],
            )],
        ),
        template(
            "x-powered-by-version",
            "X-Powered-By 버전 노출",
            "low",
            "X-Powered-By 헤더로 기술 스택과 버전이 노출됩니다.",
            &["config", "headers", "fingerprint"],
            vec![request(
                "GET",
                &["{{BaseURL}}"],
                &[UA],
                vec![
                    m_word(&["x-powered-by"], MatchPart::Header, Condition::And, false),
                    m_regex(&[r"(?i)x-powered-by:\s*(?P<version>[^\r\n]{1,40})"], MatchPart::Header, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![m_header_extractor(&[r"(?i)x-powered-by:\s*(?P<version>[^\r\n]{1,40})"], 1)],
            )],
        ),
        template(
            "server-version-disclosure",
            "Server 헤더 버전 노출",
            "low",
            "Server 헤더로 웹 서버 종류와 버전이 노출됩니다.",
            &["config", "headers", "fingerprint"],
            vec![request(
                "GET",
                &["{{BaseURL}}"],
                &[UA],
                vec![
                    m_word(&["server:"], MatchPart::Header, Condition::And, false),
                    m_regex(&[r"(?im)^server:\s*(?P<server>[^\r\n]{1,80})$"], MatchPart::Header, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![m_header_extractor(&[r"(?im)^server:\s*(?P<server>[^\r\n]{1,80})$"], 1)],
            )],
        ),
        template(
            "cors-misconfiguration",
            "CORS 잘못된 설정",
            "critical",
            "와일드카드 ACAO 와 자격증명 허용이 함께 설정되어 있습니다.",
            &["config", "cors", "headers"],
            vec![request(
                "GET",
                &["{{BaseURL}}"],
                &[UA],
                vec![
                    m_word(&["access-control-allow-origin: *"], MatchPart::Header, Condition::And, false),
                    m_word(&["access-control-allow-credentials: true"], MatchPart::Header, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "directory-listing",
            "디렉터리 목록 활성화",
            "medium",
            "디렉터리 인덱스가 켜져 파일 구조가 노출됩니다.",
            &["config", "file"],
            vec![request(
                "GET",
                &["{{BaseURL}}/"],
                &[UA],
                vec![
                    m_word(&["index of /"], MatchPart::Body, Condition::And, false),
                    m_regex(&[r"(?i)<title>\s*index of\s+/"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "php-info-page",
            "PHP 정보 페이지 노출",
            "high",
            "PHP 버전·모듈·절대 경로가 노출됩니다.",
            &["exposure", "php", "debug"],
            vec![request(
                "GET",
                &["{{BaseURL}}/info.php", "{{BaseURL}}/php_info.php"],
                &[UA],
                vec![
                    m_word(&["phpinfo()"], MatchPart::Body, Condition::And, false),
                    m_regex(&[r"(?i)php\s+version\s+[0-9]+\.[0-9]"], MatchPart::Body, Condition::And, false),
                    m_status(&[200]),
                ],
                vec![],
            )],
        ),
        template(
            "open-redirect",
            "외부 도메인 리다이렉트",
            "low",
            "외부 도메인으로 리다이렉트되어 피싱에 악용될 수 있습니다.",
            &["config", "redirect"],
            vec![request(
                "GET",
                &[
                    "{{BaseURL}}/redirect?url=https://example.org/",
                    "{{BaseURL}}/?redirect=https://example.org/",
                    "{{BaseURL}}/login?next=https://example.org/",
                ],
                &[UA],
                vec![
                    m_regex(&[r"(?im)^location:\s*https?://example\.org"], MatchPart::Header, Condition::And, false),
                    m_status(&[301, 302, 303, 307, 308]),
                ],
                vec![],
            )],
        ),
        template(
            "options-method",
            "허용 메서드 노출",
            "medium",
            "OPTIONS 응답이 위험한 메서드를 허용한다고 밝힙니다.",
            &["config", "http"],
            vec![request(
                "OPTIONS",
                &["{{BaseURL}}"],
                &[UA],
                vec![
                    m_word(&["allow:"], MatchPart::Header, Condition::And, false),
                    m_regex(&[r"(?im)^allow:\s*[^\n]*(?:PUT|DELETE|TRACE|TRACK)"], MatchPart::Header, Condition::And, false),
                    m_status(&[200, 204]),
                ],
                vec![],
            )],
        ),
    ]
}

// ---------------------------------------------------------------------------
// 테스트
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
id: exposed-git-config
info:
  name: "Git config 노출"
  severity: high
  author: forge
  description: ".git/config 가 노출됩니다."
  tags: exposure, config
requests:
  - method: GET
    paths:
      - "{{BaseURL}}/.git/config"
    headers:
      User-Agent: REDFORGE
    matchers:
      - type: word
        words: ["[core]"]
        part: body
        condition: and
      - type: status
        status: [200]
    extractors:
      - type: regex
        regex: ["url = \"(?P<u>[^\"]+)\""]
        group: 1
"#;

    fn response(status: u16, body: &str, headers: &[(&str, &str)]) -> HttpResponse {
        HttpResponse {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
            url: "http://127.0.0.1:8080/".to_string(),
            elapsed_ms: 1,
            redirects: Vec::new(),
            truncated: false,
        }
    }

    #[test]
    fn parses_sample_template() {
        let tpls = parse_template(SAMPLE).unwrap();
        assert_eq!(tpls.len(), 1);
        let t = &tpls[0];
        assert_eq!(t.id, "exposed-git-config");
        assert_eq!(t.info.name, "Git config 노출");
        assert_eq!(t.info.severity, "high");
        assert_eq!(t.info.author, "forge");
        assert_eq!(t.tags, vec!["exposure".to_string(), "config".to_string()]);
        assert_eq!(t.requests.len(), 1);
        let req = &t.requests[0];
        assert_eq!(req.method, "GET");
        assert_eq!(req.paths, vec!["{{BaseURL}}/.git/config".to_string()]);
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.headers[0].0, "User-Agent");
        assert_eq!(req.matchers.len(), 2);
        match &req.matchers[0] {
            Matcher::Word { words, part, condition, negative } => {
                assert_eq!(words, &vec!["[core]".to_string()]);
                assert_eq!(*part, MatchPart::Body);
                assert_eq!(*condition, Condition::And);
                assert!(!*negative);
            }
            other => panic!("word 매처가 아님: {other:?}"),
        }
        match &req.matchers[1] {
            Matcher::Status { status, negative } => {
                assert_eq!(*status, vec![200]);
                assert!(!*negative);
            }
            other => panic!("status 매처가 아님: {other:?}"),
        }
        assert_eq!(req.extractors.len(), 1);
        assert_eq!(req.extractors[0].kind, "regex");
        assert_eq!(req.extractors[0].group, 1);
    }

    #[test]
    fn rejects_broken_yaml() {
        assert!(parse_template("이건 YAML 이 아님\n").is_err());
    }

    #[test]
    fn rejects_status_only_template() {
        let text = r#"
id: only-status
info:
  name: "상태만"
  severity: low
requests:
  - method: GET
    paths:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
"#;
        let err = parse_template(text).unwrap_err();
        assert!(err.contains("상태 코드"), "{err}");
    }

    #[test]
    fn rejects_broken_regex() {
        let text = r#"
id: bad-regex
info:
  name: "나쁜 정규식"
  severity: low
requests:
  - method: GET
    paths:
      - "{{BaseURL}}/"
    matchers:
      - type: regex
        regex: ["([unclosed"]
"#;
        let err = parse_template(text).unwrap_err();
        assert!(err.contains("정규식"), "{err}");
    }

    #[test]
    fn matches_words_and_regexes() {
        let headers = vec![("Server".to_string(), "nginx/1.18.0".to_string())];
        let word = Matcher::Word {
            words: vec!["[core]".to_string()],
            part: MatchPart::Body,
            condition: Condition::And,
            negative: false,
        };
        assert!(match_on_parts(&word, "[core]\n repositoryformatversion = 0", &headers, 200));
        assert!(!match_on_parts(&word, "hello", &headers, 200));

        // part: header
        let head = Matcher::Word {
            words: vec!["nginx".to_string()],
            part: MatchPart::Header,
            condition: Condition::And,
            negative: false,
        };
        assert!(match_on_parts(&head, "", &headers, 200));

        // negative 매처 — "일치하지 않으면" 참.
        let neg = Matcher::Word {
            words: vec!["[core]".to_string()],
            part: MatchPart::Body,
            condition: Condition::And,
            negative: true,
        };
        assert!(match_on_parts(&neg, "hello", &headers, 200));
        assert!(!match_on_parts(&neg, "[core]", &headers, 200));
    }

    #[test]
    fn status_and_size_matchers() {
        let status = Matcher::Status { status: vec![200, 204], negative: false };
        assert!(match_on_parts(&status, "", &[], 200));
        assert!(!match_on_parts(&status, "", &[], 404));

        let size = Matcher::Size { gt: Some(10), lt: Some(100), eq: None };
        assert!(match_on_parts(&size, "0123456789ab", &[], 200));
        assert!(!match_on_parts(&size, "0123", &[], 200));

        // 모든 조건이 None 이면 매치되지 않는다.
        let empty = Matcher::Size { gt: None, lt: None, eq: None };
        assert!(!match_on_parts(&empty, "anything", &[], 200));
    }

    #[test]
    fn evaluate_requires_content_matcher() {
        // 본문 매처 + 상태 코드 → 매칭.
        let req = TemplateRequest {
            method: "GET".into(),
            paths: vec!["{{BaseURL}}/".into()],
            headers: Vec::new(),
            body: None,
            matchers: vec![
                Matcher::Word {
                    words: vec!["[core]".into()],
                    part: MatchPart::Body,
                    condition: Condition::And,
                    negative: false,
                },
                Matcher::Status { status: vec![200], negative: false },
            ],
            extractors: vec![Extractor {
                kind: "regex".into(),
                regex: vec![r#"url = "(?P<u>[^"]+)""#.into()],
                group: 1,
            }],
        };
        let resp = response(200, "[core]\nurl = \"https://example.org/x.git\"", &[]);
        let (desc, extracted) = evaluate(&req, &resp).expect("매칭되어야 함");
        assert!(desc.contains("word"), "{desc}");
        assert_eq!(extracted.get("u").map(String::as_str), Some("https://example.org/x.git"));

        // 상태 코드만으로는 매칭되지 않는다.
        let status_only = TemplateRequest {
            matchers: vec![Matcher::Status { status: vec![200], negative: false }],
            ..req.clone()
        };
        assert!(evaluate(&status_only, &resp).is_none());
    }

    #[test]
    fn builtin_pack_is_valid() {
        let tpls = builtin_templates();
        assert!(tpls.len() >= 25, "내장 템플릿 수: {}", tpls.len());
        let mut ids: Vec<&str> = tpls.iter().map(|t| t.id.as_str()).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "템플릿 id 가 중복됨");

        for t in &tpls {
            assert!(!t.requests.is_empty(), "{}: 요청 없음", t.id);
            assert!(matches!(t.info.severity.as_str(), "critical" | "high" | "medium" | "low" | "info"));
            for req in &t.requests {
                assert!(
                    req.matchers.iter().any(|m| m.is_content()),
                    "{}: 상태/크기 매처만으로는 매칭되지 않아야 함",
                    t.id
                );
            }
            // 내장 템플릿은 YAML 경로로도 파싱될 수 있어야 한다.
            assert!(parse_template(&template_to_yaml(t)).is_ok(), "{}: 재직렬화 실패", t.id);
        }
    }

    #[test]
    fn builtin_templates_hit_synthetic_responses() {
        let pack = builtin_templates();
        let by_id = |id: &str| {
            pack.iter()
                .find(|t| t.id == id)
                .unwrap_or_else(|| panic!("템플릿 없음: {id}"))
        };

        // .git/config 본문.
        let git = by_id("exposed-git-config");
        let resp = response(
            200,
            "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.org/x.git\n",
            &[],
        );
        let (desc, extracted) = evaluate(&git.requests[0], &resp).expect(".git/config 매칭");
        assert!(desc.contains("word"), "{desc}");
        assert_eq!(
            extracted.get("url").map(String::as_str),
            Some("https://example.org/x.git")
        );

        // CORS 잘못된 설정 헤더.
        let cors = by_id("cors-misconfiguration");
        let resp = response(
            200,
            "ok",
            &[
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        );
        assert!(evaluate(&cors.requests[0], &resp).is_some(), "CORS 매칭 실패");

        // .env 본문.
        let env = by_id("exposed-env-file");
        let resp = response(200, "APP_KEY=base64:abc123\nDB_PASSWORD=hunter2\n", &[]);
        assert!(evaluate(&env.requests[0], &resp).is_some(), ".env 매칭 실패");

        // 보안 헤더가 없는 일반 응답.
        let headers_tpl = by_id("missing-security-headers");
        let resp = response(200, "<html>ok</html>", &[("Content-Type", "text/html")]);
        assert!(
            evaluate(&headers_tpl.requests[0], &resp).is_some(),
            "보안 헤더 누락 매칭 실패"
        );
    }

    #[test]
    fn builtin_templates_ignore_plain_page() {
        // 일반 HTML 응답은 노출 계열 템플릿을 걸어서는 안 된다 (오탐 억제 확인).
        let resp = response(
            200,
            "<html><head><title>Home</title></head><body><p>hello world</p></body></html>",
            &[("Content-Type", "text/html; charset=utf-8"), ("Server", "nginx")],
        );
        for t in builtin_templates() {
            if !t.id.starts_with("exposed-") {
                continue;
            }
            for req in &t.requests {
                assert!(
                    evaluate(req, &resp).is_none(),
                    "일반 페이지가 {} 템플릿을 잘못 매칭함",
                    t.id
                );
            }
        }
    }

    #[test]
    fn severity_rank_orders() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        assert!(severity_rank("low") > severity_rank("info"));
        assert_eq!(severity_rank("unknown"), 0);
    }

    #[test]
    fn findings_are_mapped() {
        let mut extracted = BTreeMap::new();
        extracted.insert("url".to_string(), "https://example.org/x.git".to_string());
        let m = TemplateMatch {
            template_id: "exposed-git-config".into(),
            name: "Git 설정 파일 노출".into(),
            severity: "high".into(),
            url: "http://127.0.0.1:8080/.git/config".into(),
            matcher: "word(body): [core]".into(),
            evidence: "[core]".into(),
            extracted,
        };
        let findings = to_findings(&[m]);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.category, "template:exposed-git-config");
        assert_eq!(f.severity, "high");
        assert_eq!(f.title, "Git 설정 파일 노출");
        assert_eq!(f.target, "http://127.0.0.1:8080/.git/config");
        assert!(f.reproduction.contains("GET http://127.0.0.1:8080/.git/config"), "{}", f.reproduction);
        assert!(f.remediation.contains("저장소"), "{}", f.remediation);
    }

    #[test]
    fn parses_multiple_documents() {
        let text = format!("{SAMPLE}\n---\n{SAMPLE}");
        let tpls = parse_template(&text).unwrap();
        assert_eq!(tpls.len(), 2);
        assert_eq!(tpls[0].id, tpls[1].id);
    }

    #[test]
    fn substitutes_base_url() {
        assert_eq!(
            substitute_base("{{BaseURL}}/.git/config", "http://127.0.0.1:8080/"),
            "http://127.0.0.1:8080/.git/config"
        );
        assert_eq!(
            substitute_base("{{BaseURL}}/a", "http://127.0.0.1:8080"),
            "http://127.0.0.1:8080/a"
        );
        // 치환되지 않은 placeholder 는 그대로 남는다.
        assert!(substitute_base("{{host}}/x", "http://h").contains("{{host}}"));
    }

    /// 내장 템플릿을 YAML 로 되돌려 파싱 경로도 함께 검증한다.
    fn template_to_yaml(t: &Template) -> String {
        let mut out = String::new();
        out.push_str(&format!("id: {}\n", t.id));
        out.push_str("info:\n");
        out.push_str(&format!("  name: \"{}\"\n", t.info.name));
        out.push_str(&format!("  severity: {}\n", t.info.severity));
        out.push_str(&format!("  author: {}\n", t.info.author));
        out.push_str(&format!("  description: \"{}\"\n", t.info.description));
        out.push_str("  tags: ");
        out.push_str(&t.tags.join(", "));
        out.push('\n');
        out.push_str("requests:\n");
        for req in &t.requests {
            out.push_str(&format!("  - method: {}\n", req.method));
            out.push_str("    paths:\n");
            for p in &req.paths {
                out.push_str(&format!("      - \"{p}\"\n"));
            }
            out.push_str("    matchers:\n");
            for m in &req.matchers {
                match m {
                    Matcher::Word { words, part, condition, negative } => {
                        out.push_str("      - type: word\n");
                        let quoted: Vec<String> = words.iter().map(|w| yaml_quote(w)).collect();
                        out.push_str(&format!("        words: [{}]\n", quoted.join(", ")));
                        out.push_str(&format!("        part: {}\n", part.name()));
                        out.push_str(&format!("        condition: {}\n", cond_name(*condition)));
                        out.push_str(&format!("        negative: {negative}\n"));
                    }
                    Matcher::Regex { regex, part, condition, negative } => {
                        out.push_str("      - type: regex\n");
                        let quoted: Vec<String> = regex.iter().map(|r| yaml_quote(r)).collect();
                        out.push_str(&format!("        regex: [{}]\n", quoted.join(", ")));
                        out.push_str(&format!("        part: {}\n", part.name()));
                        out.push_str(&format!("        condition: {}\n", cond_name(*condition)));
                        out.push_str(&format!("        negative: {negative}\n"));
                    }
                    Matcher::Status { status, negative } => {
                        out.push_str("      - type: status\n");
                        let codes: Vec<String> = status.iter().map(|s| s.to_string()).collect();
                        out.push_str(&format!("        status: [{}]\n", codes.join(", ")));
                        out.push_str(&format!("        negative: {negative}\n"));
                    }
                    Matcher::Size { gt, lt, eq } => {
                        out.push_str("      - type: size\n");
                        if let Some(v) = gt {
                            out.push_str(&format!("        gt: {v}\n"));
                        }
                        if let Some(v) = lt {
                            out.push_str(&format!("        lt: {v}\n"));
                        }
                        if let Some(v) = eq {
                            out.push_str(&format!("        eq: {v}\n"));
                        }
                    }
                }
            }
            if !req.extractors.is_empty() {
                out.push_str("    extractors:\n");
                for e in &req.extractors {
                    out.push_str(&format!("      - type: {}\n", e.kind));
                    let quoted: Vec<String> = e.regex.iter().map(|r| yaml_quote(r)).collect();
                    out.push_str(&format!("        regex: [{}]\n", quoted.join(", ")));
                    out.push_str(&format!("        group: {}\n", e.group));
                }
            }
        }
        out
    }

    /// YAML 더블 쿼트 문자열로 감싼다 (역슬래시·따옴표 이스케이프).
    fn yaml_quote(text: &str) -> String {
        format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
    }

    fn cond_name(c: Condition) -> &'static str {
        match c {
            Condition::And => "and",
            Condition::Or => "or",
        }
    }
}
