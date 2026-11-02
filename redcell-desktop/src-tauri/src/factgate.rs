//! 사실 검증 게이트 (Fact Gate) — 리포트 **발행 직전**의 결정적 게이트.
//!
//! 왜 필요한가: 리포트는 LLM 이 쓴다. LLM 은 그럴싸한 시나리오를 만들어내고
//! '확인된 취약점' 처럼 포장한다. 프롬프트에 "추측하지 마라" 고 적어도 보장되지
//! 않는다. 그래서 **발행 직전에 하네스가 리포트 본문을 다시 읽어 기계적으로
//! 대조**하고, 근거가 없는 주장은 발행본에서 걷어낸다.
//!
//! 규칙 (전부 결정적 — 프롬프트 성실도에 의존하지 않는다):
//!   1. 존재하지 않는 `[P-###]` 인용(환각)은 본문에서 제거한다.
//!   2. 루트의 검증 상태는 LLM 이 아니라 **하네스 실측**으로 다시 판정한다.
//!      - 실증: P0 결정적 스윕이 해당 결함을 직접 측정했다(유효 P-ID 인용 + 주제 일치).
//!      - 징후: 하네스가 그 URL 을 재요청해 인용한 증거 문구를 실제로 확인했다.
//!      - 미확인: 위 둘 다 아니다 → 공격 시나리오에서 빼고 '미확인 가능성'으로 강등.
//!   3. 위험도는 **근거의 최대 심각도**로 교정한다 (근거 없으면 '낮음').
//!   4. P0 실측 발견 **전량 원장**을 부록으로 붙인다 (LLM 이漏쳐도 실측은 안 사라진다).
//!   5. 무엇을 왜 고쳤는지 부록으로 남긴다 — 감사 추적(사람이 다시 확인 가능).
//!
//! 이 모듈은 네트워크 조회를除하면 순수 함수다. 테스트는 `fetched` 맵을 주입해
//! 네트워크 없이 돌린다.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;

use crate::auth;
use crate::probes;
use crate::deep_instr::{extract_p_ids, p_id_key, root_title_from_header, urls_in};

// ────────────────────────────── 실측 근거 색인 ──────────────────────────────

/// P0 실측 근거 1건 — 스윕 엔진이 직접 측정한 사실.
#[derive(Debug, Clone)]
pub struct HitFact {
    pub id: String,
    /// 엔진 심각도 — critical|high|medium|low|info.
    pub severity: String,
    pub category: String,
    pub title: String,
    pub target: String,
    pub evidence: String,
    /// confirmed(독립 확증) | signal(확증 필요 신호) | info(정찰 메모).
    pub verdict: String,
}

/// 실측 근거 색인 — 키 집합이 곧 **유효 [P-###] 집합**이다.
#[derive(Debug, Default, Clone)]
pub struct EvidenceIndex {
    pub hits: BTreeMap<String, HitFact>,
}

impl EvidenceIndex {
    pub fn from_report(rep: &probes::ProbeReport) -> Self {
        let mut hits = BTreeMap::new();
        for h in &rep.hits {
            hits.insert(
                h.id.clone(),
                HitFact {
                    id: h.id.clone(),
                    severity: h.severity.clone(),
                    category: h.category.clone(),
                    title: h.title.clone(),
                    target: h.target.clone(),
                    evidence: h.evidence.clone(),
                    verdict: h.verdict.clone(),
                },
            );
        }
        Self { hits }
    }

    /// 근거 존재 여부 — 괄호 유무와 무관하게 정규화해 비교한다.
    pub fn contains(&self, id: &str) -> bool {
        self.hits.contains_key(&p_id_key(id))
    }

    pub fn get(&self, id: &str) -> Option<&HitFact> {
        self.hits.get(&p_id_key(id))
    }

    /// 인용된 P-ID 중 엔진 심각도가 가장 높은 것 — 위험도 상한의 근거.
    pub fn max_severity(&self, ids: &[String]) -> Option<String> {
        let mut best: Option<(u8, String)> = None;
        for id in ids {
            let Some(h) = self.get(id) else { continue };
            let r = engine_sev_rank(&h.severity).unwrap_or(0);
            if best.as_ref().map_or(true, |(br, _)| r > *br) {
                best = Some((r, h.severity.clone()));
            }
        }
        best.map(|(_, s)| s)
    }
}

/// 엔진 심각도 랭크 — critical 4 > high 3 > medium 2 > low 1 > info 0.
pub fn engine_sev_rank(s: &str) -> Option<u8> {
    match s {
        "critical" => Some(4),
        "high" => Some(3),
        "medium" => Some(2),
        "low" => Some(1),
        "info" => Some(0),
        _ => None,
    }
}

/// 엔진 심각도 → 리포트 위험도 표기 (치명·높음·중간·낮음 4급).
pub fn engine_sev_ko(s: &str) -> &'static str {
    match s {
        "critical" => "치명",
        "high" => "높음",
        "medium" => "중간",
        _ => "낮음",
    }
}

/// 리포트 위험도 표기 랭크 — 치명 4 > 높음 3 > 중간 2 > 낮음 1.
pub fn claimed_sev_rank(s: &str) -> Option<u8> {
    match s {
        "치명" => Some(4),
        "높음" => Some(3),
        "중간" => Some(2),
        "낮음" => Some(1),
        "정보" => Some(0),
        _ => None,
    }
}

/// 위험도 표기 4종 — 치명·높음·중간·낮음.
pub const REPORT_SEVERITIES: [&str; 4] = ["치명", "높음", "중간", "낮음"];

// ────────────────────────────── URL · 재요청 ──────────────────────────────

pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let hostport = rest.split('/').next()?;
    if let Some(b) = hostport.strip_prefix('[') {
        b.split(']').next().map(|h| h.to_lowercase())
    } else {
        hostport.split(':').next().map(|h| h.to_lowercase())
    }
}

pub fn url_scheme(url: &str) -> Option<&str> {
    let s = url.split_once("://")?.0;
    if s == "http" || s == "https" {
        Some(s)
    } else {
        None
    }
}

/// URL 포트 — 명시 `:port` 우선, 없으면 스킴 기본값(https 443/http 80).
pub fn url_port(url: &str) -> Option<u16> {
    let rest = url.split_once("://")?.1;
    let hostport = rest.split('/').next()?;
    let (_, explicit) = split_host_port(hostport);
    explicit.or(match url_scheme(url) {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    })
}

/// `host:port` 분리 — IPv6 대괄호 표기(`[::1]:8080`)를 처리한다.
use crate::split_host_port;

/// 동일 호스트 절대화 — Location 이 상대경로면 base 와 결합, 절대는 호스트 일치 시만.
pub fn absolutize_same_host(base: &str, loc: &str) -> Option<String> {
    let loc = loc.trim();
    if loc.starts_with('/') && !loc.starts_with("//") {
        let scheme = url_scheme(base)?;
        let rest = base.split_once("://")?.1;
        let hostport = rest.split('/').next()?;
        return Some(format!("{scheme}://{hostport}{loc}"));
    }
    if url_scheme(loc).is_some() {
        if url_host(loc) == url_host(base) {
            return Some(loc.to_string());
        }
    }
    None
}

/// 재요청 — GET 1회 + 동일 호스트 리다이렉트 1홉, 8초·200KB 상한.
pub fn verify_fetch(url: &str, cookie: &str) -> Result<(u16, String, String), String> {
    let agent: ureq::Agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(8))
        .timeout_read(std::time::Duration::from_secs(8))
        .timeout_write(std::time::Duration::from_secs(8))
        .redirects(0)
        .user_agent("Mozilla/5.0 (RedCell authorized-agent; verify)")
        .build();
    let mut target = url.to_string();
    for _ in 0..2 {
        let mut req = agent.get(&target);
        if !cookie.trim().is_empty() {
            req = req.set("Cookie", cookie.trim());
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(e.to_string()),
        };
        let status = resp.status();
        if (300..400).contains(&status) {
            let loc = resp.header("Location").unwrap_or("").to_string();
            if let Some(next) = absolutize_same_host(&target, &loc) {
                target = next;
                continue;
            }
            return Err(format!("리다이렉트 추적 불가 ({status})"));
        }
        let mut hs = String::new();
        for name in resp.headers_names() {
            for v in resp.all(&name) {
                hs.push_str(&format!("{name}: {v}\n"));
            }
        }
        let mut buf = Vec::new();
        resp.into_reader()
            .take(200_000)
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        return Ok((status, hs, String::from_utf8_lossy(&buf).into_owned()));
    }
    Err("리다이렉트 과다".into())
}

/// 재요청 판정.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchVerdict {
    /// 인용한 증거 문구가 실제 응답에 그대로 등장했다.
    Confirmed,
    /// 응답은 받았지만 인용 문구가 없었다 (주장 근거 불일치).
    Mismatch(String),
    /// 재요청하지 못했다 (인가 밖·파싱 불가·네트워크 실패).
    Skipped(String),
}

/// (URL, 증거 발췌) → 재요청 판정. 같은 URL이라도 루트마다 인용문이 달라
/// 달라질 수 있어 URL 단독 키는 안 된다.
pub type FetchMap = HashMap<(String, String), FetchVerdict>;

/// 재요청 대상 카드 상한 — 대조 폭증 방지.
pub const VERIFY_CLAIM_CAP: usize = 12;
/// 재요청 총 요청 수 상한 — 발행 지연을 막기 위한 예산.
pub const VERIFY_FETCH_BUDGET: usize = 12;

/// fetch 맵 조회 키.
pub fn fetch_key(url: &str, excerpt: &str) -> (String, String) {
    (url.to_string(), excerpt.to_string())
}

// ────────────────────────────── 리포트 분해 ──────────────────────────────

/// 루트 카드 1장.
#[derive(Debug, Clone)]
pub struct RootCard {
    /// `### 루트 N. ...` 헤더 줄 전체.
    pub header: String,
    /// 루트 번호 (없으면 0).
    pub number: u32,
    /// 제목 (번호·등급 배지 제거).
    pub title: String,
    /// 카드 본문 (헤더 제외).
    pub body: String,
    /// LLM 이 주장한 위험도 (헤딩 배지 또는 '위험도:' 줄).
    pub claimed_severity: String,
    /// LLM 이 주장한 검증 상태 (실증·징후·가정).
    pub claimed_verification: String,
    /// 카드에 인용된 [P-###].
    pub p_ids: Vec<String>,
}

/// 리포트 분해 결과 — 본문 구간과 루트 카드가 번갈아 나온다.
#[derive(Debug, Clone)]
pub enum Segment {
    Text(String),
    Card(RootCard),
}

/// 헤딩에서 루트 제목 추출 — "### 루트 1. 이름 [높음]" → "이름".
pub fn card_title(header: &str) -> String {
    root_title_from_header(header)
}

/// 루트 카드에서 헤딩 제외 본문만 뽑아 제목·등급·검증·P-ID 를 읽는다.
fn make_card(header: &str, body: &str) -> RootCard {
    let header = header.trim_end().to_string();
    let number = root_number(&header);
    let title = card_title(&header);
    let mut claimed_severity = String::new();
    let mut claimed_verification = String::new();
    for line in body.lines() {
        let t = line.trim();
        if claimed_severity.is_empty() {
            if let Some(rest) = t.strip_prefix("위험도:").or_else(|| t.strip_prefix("위험도：")) {
                for tok in rest.split_whitespace() {
                    if let Some(g) = grade_token(tok) {
                        claimed_severity = g;
                        break;
                    }
                }
            }
        }
        if claimed_verification.is_empty() {
            if let Some(rest) = t.strip_prefix("검증:").or_else(|| t.strip_prefix("검증：")) {
                for st in ["실증", "징후", "가정"] {
                    if rest.contains(&format!("[{st}]")) || rest.trim_start().starts_with(st) {
                        claimed_verification = st.to_string();
                        break;
                    }
                }
            }
        }
    }
    if claimed_severity.is_empty() {
        for g in REPORT_SEVERITIES {
            if header.contains(&format!("[{g}]")) {
                claimed_severity = g.to_string();
                break;
            }
        }
    }
    let mut p_ids = extract_p_ids(&header);
    p_ids.extend(extract_p_ids(body));
    p_ids.sort();
    p_ids.dedup();
    RootCard { header, number, title, body: body.to_string(), claimed_severity, claimed_verification, p_ids }
}

/// "루트 12." 에서 12 추출.
fn root_number(header: &str) -> u32 {
    let rest = header.trim_start_matches('#').trim();
    let rest = rest.strip_prefix("루트").unwrap_or(rest).trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or(0)
}

/// 등급 토큰 판정 — `높음` 처럼 정확히 일치하거나 뒤에 구분자가 오는 경우.
fn grade_token(tok: &str) -> Option<String> {
    let t = tok.trim_matches(|c: char| matches!(c, '(' | ')' | '[' | ']' | ',' | '.' | ':' | '·' | '…'));
    for g in REPORT_SEVERITIES {
        if t == g {
            return Some(g.to_string());
        }
        if let Some(rest) = t.strip_prefix(g) {
            if rest.is_empty() || rest.starts_with(|c: char| matches!(c, '(' | ')' | ',' | '.' | ':' | '-')) {
                return Some(g.to_string());
            }
        }
    }
    None
}

/// 리포트를 본문 구간 · 루트 카드로 분해.
pub fn segment_report(text: &str) -> Vec<Segment> {
    let mut segs: Vec<Segment> = Vec::new();
    let mut buf = String::new();
    let mut card: Option<(String, String)> = None;

    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let is_root = trimmed.starts_with("### 루트");
        let is_h2 = line.starts_with("## ") && !line.starts_with("###");

        if is_root {
            if let Some((h, b)) = card.take() {
                segs.push(Segment::Card(make_card(&h, &b)));
            }
            if !buf.is_empty() {
                segs.push(Segment::Text(std::mem::take(&mut buf)));
            }
            card = Some((line.trim_end().to_string(), String::new()));
            continue;
        }
        if is_h2 {
            if let Some((h, b)) = card.take() {
                segs.push(Segment::Card(make_card(&h, &b)));
            }
        }
        match card.as_mut() {
            Some((_, b)) => b.push_str(line),
            None => buf.push_str(line),
        }
    }
    if let Some((h, b)) = card.take() {
        segs.push(Segment::Card(make_card(&h, &b)));
    }
    if !buf.is_empty() {
        segs.push(Segment::Text(buf));
    }
    segs
}

// ────────────────────────────── 카드 근거 추출 ──────────────────────────────

/// 카드 1장에서 검증 가능한 근거(URL + 증거 발췌)를 뽑는다.
#[derive(Debug, Clone)]
pub struct CardEvidence {
    pub url: String,
    pub excerpt: String,
    /// 보조 후보 URL — 같은 루트에 진입점·재현 curl 이 여러 개 있을 때.
    pub alt_urls: Vec<String>,
}

/// 카드 본문에서 증거 발췌을 뽑는다 — '증거:'/'근거:' 줄.
pub fn card_excerpt(body: &str) -> Option<String> {
    for line in body.lines() {
        let t = line.trim();
        let pos = t.find("증거:").or_else(|| t.find("근거:"));
        let Some(pos) = pos else { continue };
        let raw = &t[pos..];
        let e = raw
            .trim_start_matches("증거:")
            .trim_start_matches("근거:")
            .trim()
            .replace("**", "")
            .replace('`', "")
            .replace('"', "");
        // [가정] 이 붙은 발췌는 대조 대상이 아니다 (분명히 추측이라고 적은 것).
        if e.contains("[가정]") {
            continue;
        }
        if e.chars().count() >= 20 {
            return Some(e);
        }
    }
    None
}

/// 카드에서 검증 대상(URL + 발췌)을 뽑는다 — 발췌나 URL 이 없으면 검증 불가.
pub fn card_evidence(card: &RootCard) -> Option<CardEvidence> {
    let excerpt = card_excerpt(&card.body)?;
    let urls = urls_in(&card.body, 5);
    if urls.is_empty() {
        return None;
    }
    let url = urls[0].clone();
    let alt_urls: Vec<String> = urls.into_iter().filter(|u| u != &url).collect();
    Some(CardEvidence { url, excerpt, alt_urls })
}

/// 카드별 재요청 검증 — 하네스가 직접 대상을 다시 물어본다.
/// 반환: (URL, 발췌) → 판정. 네트워크 실패는 Skipped 로 남긴다(오류 아님).
///
/// 예산: 카드 `VERIFY_CLAIM_CAP` 개 · 카드당 후보 2개 · 전체 요청
/// `VERIFY_FETCH_BUDGET` 회. 한도가 오면 남은 카드는 검증 없음(=미확인)으로 둔다.
pub fn verify_cards(
    cards: &[RootCard],
    auth_list: &auth::AuthList,
    cookie: &str,
) -> FetchMap {
    let mut map: FetchMap = FetchMap::new();
    let mut budget = VERIFY_FETCH_BUDGET;
    let mut checked = 0usize;
    for card in cards {
        if checked >= VERIFY_CLAIM_CAP || budget == 0 {
            break;
        }
        let Some(ev) = card_evidence(card) else { continue };
        checked += 1;
        let mut candidates = vec![ev.url.clone()];
        candidates.extend(ev.alt_urls.iter().cloned());
        for url in candidates.into_iter().take(2) {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let host = url_host(url.as_str());
            let verdict = match host {
                None => FetchVerdict::Skipped("URL 파싱 불가".into()),
                Some(_) if url_scheme(url.as_str()).is_none() => {
                    FetchVerdict::Skipped("http(s) 아님".into())
                }
                Some(h) if !auth::is_host_port_allowed(auth_list, &h, url_port(url.as_str())) => {
                    FetchVerdict::Skipped("인가 밖 URL".into())
                }
                Some(_) => match verify_fetch(url.as_str(), cookie) {
                    Err(e) => FetchVerdict::Skipped(format!(
                        "재요청 실패: {}",
                        e.chars().take(80).collect::<String>()
                    )),
                    Ok((st, hs, body)) => {
                        if excerpt_matches(&body, &hs, &ev.excerpt) {
                            FetchVerdict::Confirmed
                        } else {
                            FetchVerdict::Mismatch(format!("HTTP {st} — 발췌 미출현"))
                        }
                    }
                },
            };
            // Confirmed 면 후보 탐색을 멈춘다 (하나만 맞아도 근거로 충분).
            let done = matches!(verdict, FetchVerdict::Confirmed);
            map.insert(fetch_key(url.as_str(), &ev.excerpt), verdict);
            if done {
                break;
            }
        }
    }
    map
}

/// 발췌 출현 판정 — 공백 정규화·대소문자 무시, 앞 60자 출현이면 참.
pub fn excerpt_matches(body: &str, headers: &str, excerpt: &str) -> bool {
    let need = norm_ws_lower(excerpt);
    if need.chars().count() < 20 {
        return false;
    }
    let key: String = need.chars().take(60).collect();
    norm_ws_lower(body).contains(&key) || norm_ws_lower(headers).contains(&key)
}

fn norm_ws_lower(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

// ────────────────────────────── P-ID 주제 일치 ──────────────────────────────

/// P-ID 인용이 그 루트의 주제와 맞는지 — 엉뚱한 근거를 끌어와 붙이는 환각을 잡는다.
pub fn p_id_matches(hit: &HitFact, card: &RootCard) -> bool {
    let hay = format!("{}\n{}", card.header, card.body).to_lowercase();
    // 1) 근거 대상 URL 이 카드에 실제로 등장 (가장 강한 신호).
    let target = hit.target.trim();
    if !target.is_empty() {
        let path = target
            .split_once("://")
            .map(|(_, rest)| rest.split_once('/').map(|(_, p)| p).unwrap_or(""))
            .unwrap_or("");
        let path = path.split('?').next().unwrap_or("");
        if !path.is_empty() && path.len() >= 3 && hay.contains(&path.to_lowercase()) {
            return true;
        }
        if hay.contains(&target.to_lowercase()) {
            return true;
        }
    }
    // 2) 분류(category) 키워드가 카드에 등장 — 영문 토큰이라 비교가 정확하다.
    let cat = hit.category.trim().to_lowercase();
    if cat.len() >= 4 && hay.contains(&cat) {
        return true;
    }
    // 3) 근거 제목의 어절이 카드에 등장 (한국어 포함).
    for tok in hit.title.split_whitespace() {
        let t = tok.trim_matches(|c: char| !c.is_alphanumeric()).to_lowercase();
        if t.chars().count() >= 2 && hay.contains(&t) {
            return true;
        }
    }
    false
}

// ────────────────────────────── 게이트 판정 ──────────────────────────────

/// 루트 1장의 게이트 판정 결과.
#[derive(Debug, Clone)]
pub struct CardVerdict {
    pub number: u32,
    pub title: String,
    /// 리포트가 주장한 위험도.
    pub claimed_severity: String,
    /// 게이트가 확정한 위험도.
    pub final_severity: String,
    /// 리포트가 주장한 검증 상태.
    pub claimed_verification: String,
    /// 게이트가 확정한 검증 상태 — 실증|징후|미확인.
    pub final_verification: String,
    /// 이 루트를 실제로 지탱하는 근거 P-ID.
    pub anchor_pids: Vec<String>,
    /// 인용했지만 존재하지 않는 P-ID (환각).
    pub hallucinated_pids: Vec<String>,
    /// 존재는 하나 주제 불일치 — 근거로 쓰지 않는다.
    pub miscited_pids: Vec<String>,
    /// 하네스 재요청 판정.
    pub fetch: Option<FetchVerdict>,
    /// 공격 시나리오에서 빼고 '미확인 가능성'으로 강등됐는가.
    pub demoted: bool,
    /// 사람이 읽을 판정 근거 (부록 기록용).
    pub notes: Vec<String>,
}

/// 루트 카드의 최종 검증 상태를 판정한다.
pub fn judge_card(
    card: &RootCard,
    index: &EvidenceIndex,
    fetched: &FetchMap,
    mode: GateMode,
) -> CardVerdict {
    let valid: Vec<String> = card.p_ids.iter().filter(|id| index.contains(id)).cloned().collect();
    let hallucinated: Vec<String> = card.p_ids.iter().filter(|id| !index.contains(id)).cloned().collect();
    let mut anchor_pids: Vec<String> = Vec::new();
    let mut miscited: Vec<String> = Vec::new();
    for id in &valid {
        if let Some(hit) = index.get(id) {
            if p_id_matches(hit, card) {
                anchor_pids.push(id.clone());
            } else {
                miscited.push(id.clone());
            }
        }
    }

    // 하네스 재요청 판정 — 카드가 인용한 증거 문구가 실제로 살아 있는지.
    let fetch = card_evidence(card).and_then(|ev| {
        let mut last: Option<FetchVerdict> = None;
        let mut cands = vec![ev.url.clone()];
        cands.extend(ev.alt_urls.iter().cloned());
        for u in &cands {
            if let Some(v) = fetched.get(&fetch_key(u, &ev.excerpt)) {
                if matches!(v, FetchVerdict::Confirmed) {
                    return Some(v.clone());
                }
                last = Some(v.clone());
            }
        }
        last
    });
    let fetch_confirmed = matches!(fetch, Some(FetchVerdict::Confirmed));

    let mut notes: Vec<String> = Vec::new();
    let (final_verification, final_severity, demoted) = if !anchor_pids.is_empty() {
        // P0 결정적 스윕이 직접 측정한 결함 — 하네스가 확인한 사실.
        let cap = index.max_severity(&anchor_pids).unwrap_or_else(|| "info".to_string());
        let cap_ko = engine_sev_ko(&cap);
        notes.push(format!(
            "P0 실측 근거 {} — 최대 심각도 {}",
            anchor_pids.join(", "),
            cap_ko
        ));
        if !miscited.is_empty() {
            notes.push(format!(
                "주제 불일치 인용 {} — 근거로 사용하지 않음",
                miscited.join(", ")
            ));
        }
        let claimed = if card.claimed_severity.is_empty() { "중간".to_string() } else { card.claimed_severity.clone() };
        let final_sev = if claimed_sev_rank(&claimed).unwrap_or(0) > claimed_sev_rank(cap_ko).unwrap_or(0) {
            notes.push(format!("위험도 {} → {} (근거 최대 심각도)", claimed, cap_ko));
            cap_ko.to_string()
        } else {
            claimed
        };
        // P0 판정이 'confirmed'(독립 확증)가 아니라 'signal'(확증 필요 신호)이면
        // 실증이 아니라 징후다 — 엔진이 스스로 확증 신호를 남긴 경우.
        let confirmed = anchor_pids
            .iter()
            .filter_map(|id| index.get(id))
            .any(|h| h.verdict == "confirmed");
        if confirmed {
            ("실증".to_string(), final_sev, false)
        } else {
            notes.push("P0 판정이 확정(confirmed)이 아닌 신호(signal) — 실증이 아니라 징후로 표기".into());
            ("징후".to_string(), final_sev, false)
        }
    } else if fetch_confirmed {
        // 증거 문구는 실제로 존재 — 하지만 취약성 확정은 P0 프로브가 아직 못 했다.
        let claimed = if card.claimed_severity.is_empty() { "중간".to_string() } else { card.claimed_severity.clone() };
        let final_sev = if claimed_sev_rank(&claimed).unwrap_or(0) > claimed_sev_rank("중간").unwrap_or(0) {
            notes.push(format!("위험도 {} → 중간 (P0 확정 없이 재요청 확인까지만)", claimed));
            "중간".to_string()
        } else {
            claimed
        };
        notes.push("하네스 재요청으로 증거 문구 확인 — 취약성 확정은 P0 프로브 미확정".into());
        ("징후".to_string(), final_sev, false)
    } else {
        let why = match &fetch {
            Some(FetchVerdict::Mismatch(m)) => format!("재요청 결과 증거 문구 미출현 ({})", m),
            Some(FetchVerdict::Skipped(m)) => format!("재요청 불가 ({})", m),
            _ => {
                if !valid.is_empty() {
                    "인용한 근거가 루트 주제와 불일치".to_string()
                } else {
                    "확인 가능한 근거 없음 (P-ID 인용·검증 가능한 증거 문구 모두 없음)".to_string()
                }
            }
        };
        if mode == GateMode::Lenient {
            // 실측 대상 자체가 없는 설명 기반 진단 — 항목을 지우지는 않지만
            // '확인된 취약점' 으로 읽히지 않게 검증 상태와 위험도를 묶는다.
            notes.push(format!("실측 대상 없음 — {}", why));
            let claimed = if card.claimed_severity.is_empty() { "중간".to_string() } else { card.claimed_severity.clone() };
            let final_sev = if claimed_sev_rank(&claimed).unwrap_or(0) > claimed_sev_rank("중간").unwrap_or(0) {
                notes.push(format!("위험도 {} → 중간 (실측 근거 없음)", claimed));
                "중간".to_string()
            } else {
                claimed
            };
            ("가정".to_string(), final_sev, false)
        } else {
            notes.push(format!("근거 미확보 — {}", why));
            ("미확인".to_string(), "낮음".to_string(), true)
        }
    };
    if !hallucinated.is_empty() {
        notes.push(format!("존재하지 않는 근거 인용 {} — 본문에서 제거", hallucinated.join(", ")));
    }

    CardVerdict {
        number: card.number,
        title: card.title.clone(),
        claimed_severity: card.claimed_severity.clone(),
        final_severity,
        claimed_verification: card.claimed_verification.clone(),
        final_verification,
        anchor_pids,
        hallucinated_pids: hallucinated,
        miscited_pids: miscited,
        fetch,
        demoted,
        notes,
    }
}

// ────────────────────────────── 본문 편집 ──────────────────────────────

/// 헤딩의 위험도 배지를 교체한다 (배지가 없으면 뒤에 붙인다).
fn set_header_badge(header: &str, sev: &str) -> String {
    let mut out = header.to_string();
    let mut replaced = false;
    for g in REPORT_SEVERITIES {
        let tag = format!("[{g}]");
        if out.contains(&tag) {
            out = out.replace(&tag, &format!("[{sev}]"));
            replaced = true;
        }
    }
    if !replaced {
        out.push_str(&format!(" [{sev}]"));
    }
    out
}

/// 본문의 '위험도:' 줄을 교체한다 (없으면 머리에 추가).
fn set_body_severity(body: &str, sev: &str) -> String {
    let mut lines: Vec<String> = body.lines().map(|s| s.to_string()).collect();
    let mut hit_idx: Option<usize> = None;
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t.starts_with("위험도:") || t.starts_with("위험도：") {
            hit_idx = Some(i);
            break;
        }
    }
    match hit_idx {
        Some(i) => {
            let indent: String = lines[i].chars().take_while(|c| c.is_whitespace()).collect();
            lines[i] = format!("{indent}위험도: {sev}");
        }
        None => {
            lines.insert(0, format!("위험도: {sev}"));
        }
    }
    let mut out = lines.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// 본문의 '검증:' 줄의 배지를 교체한다 (없으면 추가).
fn set_body_verification(body: &str, state: &str, reason: &str) -> String {
    let mut lines: Vec<String> = body.lines().map(|s| s.to_string()).collect();
    let mut hit_idx: Option<usize> = None;
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t.starts_with("검증:") || t.starts_with("검증：") {
            hit_idx = Some(i);
            break;
        }
    }
    let indent = hit_idx
        .and_then(|i| lines.get(i))
        .map(|l| l.chars().take_while(|c| c.is_whitespace()).collect::<String>())
        .unwrap_or_default();
    let line = if reason.trim().is_empty() {
        format!("{indent}검증: [{state}]")
    } else {
        format!("{indent}검증: [{state}] {reason}")
    };
    match hit_idx {
        Some(i) => lines[i] = line,
        None => lines.push(line),
    }
    let mut out = lines.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// 본문에서 존재하지 않는 [P-###] 인용을 제거한다.
fn strip_p_ids(body: &str, bad: &[String]) -> String {
    if bad.is_empty() {
        return body.to_string();
    }
    let mut out = String::new();
    for line in body.split_inclusive('\n') {
        let mut l = line.to_string();
        for id in bad {
            l = l.replace(id.as_str(), "");
        }
        // 인용만 남고 아무것도 안 남은 줄은 정리한다.
        let t = l.trim();
        if t.is_empty() || t.chars().all(|c| c == '[' || c == ']' || c == '-' || c == ' ' || c == '·' || c == '(' || c == ')') {
            continue;
        }
        out.push_str(&l);
    }
    out
}

/// 루트 본문에서 검증 상태 배지를 모두 지정 상태로 바꾼다 (강등 카드용).
fn neutralize_badges(body: &str) -> String {
    let mut out = String::new();
    for line in body.split_inclusive('\n') {
        let mut l = line.to_string();
        for st in ["실증", "징후", "가정"] {
            l = l.replace(&format!("[{st}]"), "[미확인]");
        }
        out.push_str(&l);
    }
    out
}

/// 'CVSS:' 줄을 근거 값으로 교체한다 — LLM 이 임의로 만든 점수는 그대로 남기지 않는다.
fn set_body_cvss(body: &str, cvss: Option<&str>) -> String {
    let mut lines: Vec<String> = body.lines().map(|s| s.to_string()).collect();
    let mut hit_idx: Option<usize> = None;
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t.starts_with("CVSS:") || t.starts_with("CVSS：") {
            hit_idx = Some(i);
            break;
        }
    }
    let value = cvss.unwrap_or("-");
    let line = format!("CVSS: {value}");
    match hit_idx {
        Some(i) => {
            // 기존 줄에 붙은 CWE·OWASP 표기는 남긴다 (분류는 근거가 있을 때만).
            let old = lines[i].clone();
            let tail: String = old
                .split_once("·")
                .map(|(_, t)| t.trim().to_string())
                .filter(|t| t.starts_with("CWE-") || t.starts_with("OWASP"))
                .unwrap_or_default();
            lines[i] = if tail.is_empty() { line } else { format!("{line} · {tail}") };
        }
        None => {
            // '위험도:' 줄 바로 뒤에 둔다 (리포트 고정 필드 순서: 위험도 → CVSS).
            let at = lines
                .iter()
                .position(|l| {
                    let t = l.trim();
                    t.starts_with("위험도:") || t.starts_with("위험도：")
                })
                .map(|i| i + 1)
                .unwrap_or(0);
            lines.insert(at, line);
        }
    }
    let mut out = lines.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

// ────────────────────────────── 요약 표 교정 ──────────────────────────────

/// '한눈에 보기' 표의 위험도·검증 칸을 게이트 판정으로 맞춘다.
fn fix_summary_table(text: &str, verdicts: &[CardVerdict]) -> String {
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        let t = line.trim();
        if !(t.starts_with('|') && t.contains("루트")) {
            out.push_str(line);
            continue;
        }
        // 루트 번호를 찾아 대응하는 판정을 찾는다.
        let num = extract_root_ref(t);
        let Some(v) = verdicts.iter().find(|v| v.number == num) else {
            out.push_str(line);
            continue;
        };
        // 강등된(근거 미확보) 루트는 요약 표에서 뺀다 — 본문에서 공격 시나리오가
        // 아니게 된 항목을 표가 '발견' 으로 세면 본문과 모순이다.
        if v.demoted {
            continue;
        }
        let cells: Vec<&str> = t.split('|').collect();
        let mut new_cells: Vec<String> = cells.iter().map(|c| c.trim().to_string()).collect();
        let mut sev_done = false;
        let mut ver_done = false;
        for c in new_cells.iter_mut() {
            let bare = c.trim_matches(|ch: char| matches!(ch, '*' | '`' | ' '));
            if !sev_done && REPORT_SEVERITIES.contains(&bare) {
                *c = v.final_severity.clone();
                sev_done = true;
                continue;
            }
            if !ver_done && ["실증", "징후", "가정", "미확인"].contains(&bare) {
                *c = v.final_verification.clone();
                ver_done = true;
                continue;
            }
        }
        if sev_done || ver_done {
            // 표 형태 유지 — 앞뒤 빈 칸은 '|' 로 되돌린다 (앞에 공백이 붙는 것 방지).
            let lead = new_cells.first().map(|c| c.is_empty()).unwrap_or(false);
            let trail = new_cells.last().map(|c| c.is_empty()).unwrap_or(false);
            let joined = if lead && trail && new_cells.len() >= 2 {
                format!("| {} |", new_cells[1..new_cells.len() - 1].join(" | "))
            } else {
                new_cells.join(" | ")
            };
            out.push_str(&joined);
            out.push_str(if line.ends_with('\n') { "\n" } else { "" });
        } else {
            out.push_str(line);
        }
    }
    out
}

/// 표 한 줄에서 '루트 N' 참조를 뽑는다 — "루트 1" / "루트. 2" 등 형태.
fn extract_root_ref(line: &str) -> u32 {
    let mut rest = line;
    while let Some(pos) = rest.find("루트") {
        let after = &rest[pos + "루트".len()..];
        let digits: String = after
            .trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '.' | ')' | ':' | ',' | '-'))
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !digits.is_empty() {
            return digits.parse().unwrap_or(0);
        }
        rest = after;
    }
    0
}

// ────────────────────────────── 부록 ──────────────────────────────

/// 부록 C — P0 실측 발견 전량 원장 (LLM 이 빼먹어도 사실은 남는다).
fn findings_ledger(index: &EvidenceIndex) -> String {
    if index.hits.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str("\n## 부록 C. P0 실측 발견 원장 (전량 — 하네스 확정)\n\n");
    out.push_str(
        "아래는 **LLM 이 아니라 결정적 스윕 엔진이 직접 측정한** 결과 전량이다. \
         본문 서술과 무관하게 항상 기재한다 — 본문이 이 발견을 빠뜨렸다면 본문의 \
         오류이며, 여기의 기록이 사실이다.\n\n",
    );
    out.push_str("| P-ID | 심각도 | 분류 | 대상 | 제목 | 근거 발췌 |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    for h in index.hits.values() {
        let ev: String = h.evidence.chars().take(120).collect();
        let ev_cell = if ev.is_empty() { "—".to_string() } else { ev.replace('|', "\\|") };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            h.id,
            probes::severity_ko(&h.severity),
            h.category,
            h.target.replace('|', "\\|"),
            h.title.replace('|', "\\|"),
            ev_cell
        ));
    }
    out
}

/// 부록 D — 게이트 적용 기록 (무엇을 왜 고쳤는지).
fn gate_audit(verdicts: &[CardVerdict], index: &EvidenceIndex) -> String {
    let mut out = String::new();
    out.push_str("\n## 부록 D. 사실 검증 게이트 적용 기록 (기계 판정)\n\n");
    out.push_str(
        "발행 직전 하네스가 본문을 재대조했다. 아래는 **기계가 고친 것**이다. \
         원문은 머신리저브(원본 리포트) 항목에서 확인할 수 있다.\n\n",
    );
    let mut any = false;
    for v in verdicts {
        let mut changes: Vec<String> = Vec::new();
        if v.claimed_verification != v.final_verification && !v.claimed_verification.is_empty() {
            changes.push(format!(
                "검증 {} → {}",
                v.claimed_verification, v.final_verification
            ));
        } else if v.final_verification != "실증" {
            changes.push(format!("검증 {}", v.final_verification));
        }
        if v.claimed_severity != v.final_severity && !v.claimed_severity.is_empty() {
            changes.push(format!("위험도 {} → {}", v.claimed_severity, v.final_severity));
        }
        if v.demoted {
            changes.push("공격 시나리오 → 미확인 가능성(강등)".to_string());
        }
        if !v.hallucinated_pids.is_empty() {
            changes.push(format!("존재하지 않는 근거 인용 {} 제거", v.hallucinated_pids.join(", ")));
        }
        if !v.miscited_pids.is_empty() {
            changes.push(format!("주제 불일치 인용 {} 제외", v.miscited_pids.join(", ")));
        }
        if changes.is_empty() {
            continue;
        }
        any = true;
        let head = if v.number > 0 { format!("루트 {} 「{}」", v.number, v.title) } else { format!("「{}」", v.title) };
        out.push_str(&format!("- **{head}**: {}\n", changes.join(" · ")));
        for n in &v.notes {
            out.push_str(&format!("  - {n}\n"));
        }
    }
    if !any {
        out.push_str("- 본문 대조에서 기계가 고칠 항목을 찾지 못했다 (기계 확인된 주장은 그대로 발행).\n");
    }
    // 게이트가 본 근거 요약 — 사람이 검증 범위를 알 수 있게.
    out.push_str(&format!(
        "\n게이트 근거: P0 실측 발견 {}건 중 리포트 본문에서 유효 근거로 쓰인 것 {}건.\n",
        index.hits.len(),
        verdicts.iter().map(|v| v.anchor_pids.len()).sum::<usize>()
    ));
    out
}

// ────────────────────────────── 게이트 본문 생성 ──────────────────────────────

/// 게이트 적용 결과.
#[derive(Debug, Clone)]
pub struct GateResult {
    /// 발행할 본문 (게이트 적용 후).
    pub text: String,
    /// 루트별 판정.
    pub verdicts: Vec<CardVerdict>,
    /// 사람이 읽을 요약 (노트용).
    pub summary: String,
}

/// '## ' 절 제목이 '미확인 가능성' 계열인가 — LLM 이 만든 가설 절을 찾아낸다.
fn is_hypothesis_section(text: &str) -> bool {
    let first = text.lines().next().unwrap_or("").trim();
    if !first.starts_with("## ") || first.starts_with("###") {
        return false;
    }
    let norm: String = first
        .trim_start_matches('#')
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    norm.contains("미확인가능성") || norm.contains("근거미확보")
}

/// '## ' 절 제목이 권고 절인가 — 우선순위 항목이 들어 있는 곳.
fn is_recommendation_section(text: &str) -> bool {
    let first = text.lines().next().unwrap_or("").trim();
    if !first.starts_with("## ") || first.starts_with("###") {
        return false;
    }
    let norm: String = first
        .trim_start_matches('#')
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    norm.contains("권고") || norm.contains("개선") || norm.contains("보완")
}

/// 권고 항목 중 **근거 미확보로 강등된 루트**를 가리키는 줄에 표시를 붙인다.
///
/// '지금 해야 할 일' 목록이 근거 없는 항목을 최우선으로 밀어내지 않게 한다.
/// 확정된 루트를 함께 가리키는 줄은 건드리지 않는다(오탐 방지).
fn annotate_recommendations(text: &str, demoted: &[String], anchored: &[String]) -> String {
    if demoted.is_empty() {
        return text.to_string();
    }
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        let is_prio = line.contains("[P0]") || line.contains("[P1]");
        if is_prio {
            let hit_demoted = demoted.iter().any(|t| t.chars().count() >= 4 && line.contains(t.as_str()));
            let hit_anchored = anchored.iter().any(|t| t.chars().count() >= 4 && line.contains(t.as_str()));
            if hit_demoted && !hit_anchored {
                let trimmed = line.trim_end_matches('\n');
                let eol = if line.ends_with('\n') { "\n" } else { "" };
                out.push_str(trimmed);
                out.push_str(" (확인 필요 — 근거 미확보 항목)");
                out.push_str(eol);
                continue;
            }
        }
        out.push_str(line);
    }
    out
}

/// 게이트 동작 모드.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    /// 엄격 — 실측 대상이 있다. 근거 없는 루트는 '미확인 가능성' 으로 강등한다.
    Strict,
    /// 완화 — 실측 대상 자체가 없다(설명 기반 진단). 근거 없는 루트를 지우지는
    /// 않지만 검증 상태를 '가정' 으로 낮추고 위험도를 '중간' 으로 묶는다.
    Lenient,
}

/// 리포트 본문에 사실 검증 게이트를 적용한다.
///
/// `fetched` 는 카드별 재요청 판정 — 네트워크 조회는 호출측(`verify_cards`)이
/// 미리 해둔다. 테스트는 빈 맵을 넣어 네트워크 없이 돌릴 수 있다.
pub fn gate_report(
    text: &str,
    index: &EvidenceIndex,
    fetched: &FetchMap,
    mode: GateMode,
) -> GateResult {
    let segs = segment_report(text);
    let mut cards: Vec<RootCard> = Vec::new();
    for s in &segs {
        if let Segment::Card(c) = s {
            cards.push(c.clone());
        }
    }
    let verdicts: Vec<CardVerdict> =
        cards.iter().map(|c| judge_card(c, index, fetched, mode)).collect();

    // 1) 본문 재생성 — 루트 카드는 판정대로 고치고, 근거 없는 카드는 빼낸다.
    //    '미확인 가능성' 절은 마지막 루트 카드 바로 뒤에 끼워 넣는다 —
    //    (문서 끝에 붙이면 '권고' 뒤에 와서 Attack 시나리오와 멀어진다)
    let mut chunks: Vec<(bool, String)> = Vec::new(); // (is_root_card, text)
    let mut demoted_blocks: Vec<String> = Vec::new();
    let mut llm_hypothesis = String::new();
    let mut demoted_titles: Vec<String> = Vec::new();
    let mut anchored_titles: Vec<String> = Vec::new();
    let mut last_card_pos: Option<usize> = None;
    let mut vi = 0usize;
    for seg in &segs {
        match seg {
            Segment::Text(t) => {
                // LLM 이 직접 만든 '미확인 가능성' 절은 게이트 절로 흡수한다 —
                // 같은 제목의 절이 두 개 생기면 독자가 헷갈린다.
                if is_hypothesis_section(t) {
                    llm_hypothesis.push_str(t);
                    continue;
                }
                // 권고 절 — 강등된 루트를 가리키는 우선순위 항목에는 표시를 붙인다.
                if is_recommendation_section(t) {
                    chunks.push((false, annotate_recommendations(t, &demoted_titles, &anchored_titles)));
                    continue;
                }
                chunks.push((false, t.clone()))
            }
            Segment::Card(c) => {
                let v = &verdicts[vi];
                vi += 1;
                if v.demoted {
                    demoted_titles.push(c.title.clone());
                    demoted_blocks.push(demoted_block(c, v, index));
                    // 강등된 카드가 있던 자리 — '미확인 가능성' 절을 그 자리에 세운다.
                    if !chunks.is_empty() {
                        last_card_pos = Some(chunks.len() - 1);
                    }
                    continue;
                }
                anchored_titles.push(c.title.clone());
                let header = set_header_badge(&c.header, &v.final_severity);
                let mut body = strip_p_ids(&c.body, &v.hallucinated_pids);
                body = set_body_severity(&body, &v.final_severity);
                body = set_body_verification(&body, &v.final_verification, &v.notes.join(" · "));
                // CVSS 는 근거(P0 스코어링)에서만 온다.
                let cvss = v
                    .anchor_pids
                    .iter()
                    .filter_map(|id| index.get(id))
                    .find_map(|h| probes::hit_scoring_note(&h.category));
                body = set_body_cvss(&body, cvss.as_deref());
                let mut card_text = String::new();
                card_text.push_str(&header);
                card_text.push('\n');
                card_text.push_str(&body);
                chunks.push((true, card_text));
                last_card_pos = Some(chunks.len() - 1);
            }
        }
    }

    // 2) 근거 없는 카드는 '미확인 가능성' 절로 분리한다.
    if !demoted_blocks.is_empty() || !llm_hypothesis.trim().is_empty() {
        let mut sec = String::new();
        sec.push_str("\n## 미확인 가능성 — 근거 미확보 (검증 필요 / 미검증 항목)\n\n");
        sec.push_str(
            "아래 항목은 **확인 가능한 근거를 확보하지 못해** '공격 시나리오'에서 제외했다. \
             확정된 취약점이 아니므로 위험도·검증 상태를 임의로 채우지 않는다. \
             각각에 대해 무엇을 확인해야 하는지 적었다 — 다음 점검의 우선 항목이다.\n\n",
        );
        for b in demoted_blocks {
            sec.push_str(&b);
            sec.push('\n');
        }
        if !llm_hypothesis.trim().is_empty() {
            // 원문 리포트가 스스로 지목한 확인 필요 항목 — 근거가 없다는 점을
            // 인정한 항목이므로 그대로 보존한다(근거 없는 단정만 제거).
            // 절 제목(##)은 떼어낸다 — 남기면 같은 제목의 절이 두 개 생긴다.
            let body = llm_hypothesis
                .trim()
                .split_once('\n')
                .filter(|(head, _)| head.trim_start().starts_with("## "))
                .map(|(_, rest)| rest.to_string())
                .unwrap_or_else(|| llm_hypothesis.trim().to_string());
            sec.push_str("### 원본 리포트가 지목한 확인 필요 항목\n");
            sec.push_str(body.trim_start_matches('\n'));
            sec.push('\n');
        }
        match last_card_pos {
            Some(pos) => chunks.insert(pos + 1, (false, sec)),
            None => chunks.push((false, sec)),
        }
    }

    let mut out = String::new();
    for (_, c) in &chunks {
        out.push_str(c);
    }

    // 3) 요약 표를 게이트 판정과 맞춘다 (본문이 고쳐졌는데 표가 옛값이면 모순).
    let fixed = fix_summary_table(&out, &verdicts);

    // 4) 사실 부록 — 실측 원장 + 게이트 기록.
    let mut final_text = fixed;
    final_text.push_str(&findings_ledger(index));
    final_text.push_str(&gate_audit(&verdicts, index));

    // 5) 요약 문장 — 노트·커버 블록용.
    let demoted_n = verdicts.iter().filter(|v| v.demoted).count();
    let proven_n = verdicts.iter().filter(|v| v.final_verification == "실증").count();
    let signal_n = verdicts.iter().filter(|v| v.final_verification == "징후").count();
    let summary = format!(
        "사실 검증 게이트 적용 — 확인된 취약점 {proven_n}건·징후 {signal_n}건·미확인(강등) {demoted_n}건 / P0 실측 발견 {}건",
        index.hits.len()
    );
    GateResult { text: final_text, verdicts, summary }
}

/// 강등된 카드를 '미확인 가능성' 항목으로 다시 쓴다.
fn demoted_block(card: &RootCard, v: &CardVerdict, index: &EvidenceIndex) -> String {
    let mut b = String::new();
    let head = if card.number > 0 {
        format!("#### 미확인 {}. {}", card.number, card.title)
    } else {
        format!("#### 미확인. {}", card.title)
    };
    b.push_str(&head);
    b.push('\n');
    let why = v.notes.join(" · ");
    b.push_str(&format!("- 근거 상태: {why}\n"));
    if !card.claimed_severity.is_empty() {
        b.push_str(&format!(
            "- 원문 주장 위험도: {} (근거 미확보로 낮춤 — 확정 취약점이 아님)\n",
            card.claimed_severity
        ));
    }
    if !v.anchor_pids.is_empty() {
        b.push_str(&format!("- 사용 근거: {}\n", v.anchor_pids.join(", ")));
    }
    // 원문에서 확인 가능한 사실만 남긴다 — 위험 단정 문장은 걷어낸다.
    let body = neutralize_badges(&strip_p_ids(&card.body, &v.hallucinated_pids));
    let body = set_body_severity(&body, "낮음");
    let body = set_body_verification(&body, "미확인", &why);
    // 근거가 없으면 CVSS 점수도 없다 — 지어낸 점수는 남기지 않는다.
    let body = set_body_cvss(&body, None);
    b.push_str(&body);
    // 다음에 무엇을 확인해야 하는지 — 원문 '검증:'/'보완:' 힌트 재사용.
    b.push_str("- 다음 검증: 이 항목의 진입점을 직접 요청해 응답 원문으로 확인한 뒤 확정한다.\n");
    let _ = index;
    b
}


#[cfg(test)]
mod tests {
    use super::*;

    /// 근거 색인 — 키는 스윕 히트 id("P-001") 형태다 (괄호 없음).
    fn idx() -> EvidenceIndex {
        let mut hits = BTreeMap::new();
        hits.insert(
            "P-001".to_string(),
            HitFact {
                id: "P-001".into(),
                severity: "high".into(),
                category: "headers".into(),
                title: "보안 헤더 누락".into(),
                target: "https://example.test/".into(),
                evidence: "content-security-policy 없음".into(),
                verdict: "confirmed".into(),
            },
        );
        hits.insert(
            "P-002".to_string(),
            HitFact {
                id: "P-002".into(),
                severity: "medium".into(),
                category: "sqli".into(),
                title: "SQL 오류 지문 노출".into(),
                target: "https://example.test/api/items?id=1".into(),
                evidence: "You have an error in your SQL syntax".into(),
                verdict: "confirmed".into(),
            },
        );
        EvidenceIndex { hits }
    }

    fn card(body: &str, header: &str) -> RootCard {
        make_card(header, body)
    }

    #[test]
    fn segments_split_root_cards() {
        let text = "# 리포트\n\n## 4. 공격 시나리오\n\n### 루트 1. SQL 주입 [높음]\n위험도: 높음\n검증: [실증] 확인함\n\n### 루트 2. 헤더 누락 [중간]\n위험도: 중간\n\n## 5. 권고\n- [P0] stuff\n";
        let segs = segment_report(text);
        let cards: Vec<&RootCard> = segs
            .iter()
            .filter_map(|s| match s {
                Segment::Card(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(cards.len(), 2, "{segs:?}");
        assert_eq!(cards[0].number, 1);
        assert_eq!(cards[0].title, "SQL 주입");
        assert_eq!(cards[0].claimed_severity, "높음");
        assert_eq!(cards[0].claimed_verification, "실증");
        assert_eq!(cards[1].number, 2);
    }

    #[test]
    fn p0_anchor_keeps_proof_and_caps_severity() {
        let c = card(
            "위험도: 치명\n검증: [실증] 재현함\n근거: [P-002]\n증거: You have an error in your SQL syntax near 'x'\n",
            "### 루트 1. SQL 주입 [치명]",
        );
        let v = judge_card(&c, &idx(), &FetchMap::new(), GateMode::Strict);
        assert_eq!(v.final_verification, "실증");
        assert_eq!(v.final_severity, "중간", "P0 근거 medium 보다 높게 유지되면 안 됨");
        assert!(v.anchor_pids.contains(&"[P-002]".to_string()), "{v:?}");
    }

    #[test]
    fn hallucinated_p_id_is_removed_and_card_demoted() {
        let c = card(
            "위험도: 치명\n검증: [실증] 확인함\n근거: [P-999]\n증거: totally made up evidence string that never existed\n",
            "### 루트 1. 가짜 루트 [치명]",
        );
        let v = judge_card(&c, &idx(), &FetchMap::new(), GateMode::Strict);
        assert!(v.hallucinated_pids.contains(&"[P-999]".to_string()), "{v:?}");
        assert!(v.demoted);
        assert_eq!(v.final_verification, "미확인");
        assert_eq!(v.final_severity, "낮음");
    }

    #[test]
    fn fetch_confirmed_marks_signal_not_proof() {
        let c = card(
            "위험도: 높음\n검증: [실증] 주장함\n진입점: https://example.test/a\n증거: You have an error in your SQL syntax near 'x'\n",
            "### 루트 1. SQL 오류 [높음]",
        );
        let mut m = FetchMap::new();
        m.insert(
            fetch_key("https://example.test/a", "You have an error in your SQL syntax near 'x'"),
            FetchVerdict::Confirmed,
        );
        let v = judge_card(&c, &idx(), &m, GateMode::Strict);
        assert_eq!(v.final_verification, "징후");
        assert_eq!(v.final_severity, "중간");
        assert!(!v.demoted);
    }

    #[test]
    fn mismatch_demotes_card() {
        let c = card(
            "위험도: 치명\n검증: [실증] 주장함\n증거: totally made up evidence string that never existed\n",
            "### 루트 1. 없는 취약점 [치명]",
        );
        let mut m = FetchMap::new();
        m.insert(
            fetch_key(
                "https://example.test/a",
                "totally made up evidence string that never existed",
            ),
            FetchVerdict::Mismatch("HTTP 404 — 발췌 미출현".into()),
        );
        let v = judge_card(&c, &idx(), &m, GateMode::Strict);
        assert!(v.demoted);
    }

    #[test]
    fn gate_report_moves_unanchored_card_to_hypothesis_section() {
        let text = "# 리포트\n\n## 0. 한눈에 보기\n\n| 루트 | 위험도 | 검증 |\n|---|---|---|\n| 루트 1 | 치명 | 실증 |\n\n## 4. 공격 시나리오\n\n### 루트 1. SQL 주입 [높음]\n위험도: 높음\n검증: [실증] 확인\n근거: [P-002]\n증거: You have an error in your SQL syntax near 'x'\n\n### 루트 2. 상상 취약점 [치명]\n위험도: 치명\n검증: [실증] 확인\n증거: totally made up evidence string that never existed\n\n## 5. 권고\n- [P0] 고친다\n";
        let g = gate_report(text, &idx(), &FetchMap::new(), GateMode::Strict);
        assert!(g.text.contains("미확인 가능성"), "{}", g.text);
        assert!(g.text.contains("#### 미확인 2. 상상 취약점"), "{}", g.text);
        assert!(
            !g.text.contains("### 루트 2. 상상 취약점"),
            "강등된 카드는 루트에서 빠져야 함:\n{}",
            g.text
        );
        // 요약 표도 교정돼야 한다.
        assert!(g.text.contains("| 루트 1 | 중간 | 실증 |"), "{}", g.text);
        // 실측 원장 부록이 붙는다.
        assert!(g.text.contains("부록 C. P0 실측 발견 원장"), "{}", g.text);
        assert!(g.text.contains("P-002"), "{}", g.text);
        // 게이트 기록 부록.
        assert!(g.text.contains("부록 D. 사실 검증 게이트 적용 기록"), "{}", g.text);
    }

    #[test]
    fn p_id_topic_mismatch_is_not_anchor() {
        // P-001 은 헤더 건인데 SQL 루트에 인용 → 주제 불일치.
        let c = card(
            "위험도: 높음\n검증: [실증] 확인\n근거: [P-001]\n증거: You have an error in your SQL syntax near 'x'\n",
            "### 루트 1. SQL 주입 [높음]",
        );
        let v = judge_card(&c, &idx(), &FetchMap::new(), GateMode::Strict);
        assert!(v.anchor_pids.is_empty(), "{v:?}");
        assert!(v.miscited_pids.contains(&"[P-001]".to_string()), "{v:?}");
        assert!(v.demoted);
    }

    #[test]
    fn hallucinated_citation_removed_from_body() {
        let c = card(
            "위험도: 중간\n검증: [실증] 확인\n증거: You have an error in your SQL syntax near 'x'\n근거: [P-999] 및 [P-002]\n",
            "### 루트 1. SQL 주입 [중간]",
        );
        let idxs = idx();
        let v = judge_card(&c, &idxs, &FetchMap::new(), GateMode::Strict);
        let body = strip_p_ids(&c.body, &v.hallucinated_pids);
        assert!(!body.contains("[P-999]"), "{body}");
        assert!(body.contains("[P-002]"), "{body}");
    }

    #[test]
    fn cvss_line_is_replaced_by_evidence_value() {
        let body = "CVSS: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) · CWE-89\n";
        let out = set_body_cvss(
            body,
            Some("CVSS 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) · CWE-89"),
        );
        assert!(out.contains("CVSS 7.5"), "{out}");
        assert!(!out.contains("9.8"), "{out}");
    }

    #[test]
    fn severity_cap_uses_evidence_not_claim() {
        let c = card(
            "위험도: 치명\n검증: [실증] 확인\n근거: [P-001]\n증거: content-security-policy 없음 — 보안 헤더 누락\n",
            "### 루트 1. 보안 헤더 [치명]",
        );
        let v = judge_card(&c, &idx(), &FetchMap::new(), GateMode::Strict);
        assert_eq!(v.final_severity, "높음", "{v:?}");
        assert_eq!(v.final_verification, "실증", "{v:?}");
    }

    #[test]
    fn p_id_bracket_form_matches_engine_id() {
        // 본문 인용 "[P-001]" 과 스윕 히트 id "P-001" 는 같은 근거로 본다.
        let ix = idx();
        assert!(ix.contains("[P-001]"));
        assert!(ix.contains("P-001"));
        assert!(!ix.contains("[P-999]"));
    }

    #[test]
    fn signal_verdict_is_not_proof() {
        let mut ix = idx();
        if let Some(h) = ix.hits.get_mut("P-002") {
            h.verdict = "signal".into();
        }
        let c = card(
            "위험도: 중간\n검증: [실증] 확인\n근거: [P-002]\n증거: You have an error in your SQL syntax near 'x'\n",
            "### 루트 1. SQL 주입 [중간]",
        );
        let v = judge_card(&c, &ix, &FetchMap::new(), GateMode::Strict);
        assert_eq!(v.final_verification, "징후", "{v:?}");
    }

    #[test]
    fn lenient_mode_keeps_card_but_marks_it_assumption() {
        // 실측 대상 자체가 없는 설명 기반 진단 — 항목을 지우지 않되 '확인' 으로 읽히지 않게 한다.
        let c = card(
            "위험도: 치명\n검증: [실증] 설명 기반 추론\n증거: never existed evidence string at all here\n",
            "### 루트 1. 설명 기반 주장 [치명]",
        );
        let v = judge_card(&c, &idx(), &FetchMap::new(), GateMode::Lenient);
        assert!(!v.demoted, "완화 모드에서 항목을 지우면 안 된다");
        assert_eq!(v.final_verification, "가정");
        assert_eq!(v.final_severity, "중간");
    }

    #[test]
    fn llm_hypothesis_section_is_absorbed_not_duplicated() {
        // LLM 이 스스로 만든 '미확인 가능성' 절과 게이트 절이 둘 생기면 안 된다.
        let text = "# 리포트\n\n## 4. 공격 시나리오\n\n### 루트 1. 상상 취약점 [치명]\n위험도: 치명\n검증: [실증] 확인\n증거: totally made up evidence string that never existed\n\n## 4-1. 미확인 가능성 (근거 미확보 — 검증 필요)\n\n### 미확인 9. 원본이 지목한 항목\n근거 상태: 확인 못 함\n\n## 5. 권고\n- [P0] 고친다\n";
        let g = gate_report(text, &idx(), &FetchMap::new(), GateMode::Strict);
        let n = g.text.matches("## 미확인 가능성").count();
        assert_eq!(n, 1, "미확인 가능성 절이 하나여야 한다:\n{}", g.text);
        assert!(g.text.contains("#### 미확인 1. 상상 취약점"), "{}", g.text);
        assert!(g.text.contains("원본 리포트가 지목한 확인 필요 항목"), "{}", g.text);
    }

    #[test]
    fn fetch_confirmed_evidence_keeps_card_as_signal() {
        // 하네스가 대상을 다시 물어보고 인용 문구가 실제로 나오는지 확인하는 경로 —
        // 실측 서버를 띄워 재요청까지 돌린다 (네트워크 경로 통합).
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().take(4) {
                let Ok(mut s) = stream else { break };
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let body = "SECRET_KEY=abcd1234efgh5678 설정값이 그대로 노출되었다";
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        });
        let text = format!(
            "# 리포트\n\n## 4. 공격 시나리오\n\n### 루트 1. .env 노출 [높음]\n위험도: 높음\n검증: [실증] 확인\n진입점: http://127.0.0.1:{port}/env\n증거: SECRET_KEY=abcd1234efgh5678 설정값이 그대로 노출되었다\n"
        );
        let cards: Vec<RootCard> = segment_report(&text)
            .into_iter()
            .filter_map(|seg| match seg {
                Segment::Card(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(cards.len(), 1);
        let auth = crate::auth::AuthList { allows: vec!["127.0.0.1".into()], ..Default::default() };
        let fetched = verify_cards(&cards, &auth, "");
        let v = judge_card(&cards[0], &idx(), &fetched, GateMode::Strict);
        assert_eq!(v.final_verification, "징후", "{v:?}");
        assert!(!v.demoted, "{v:?}");
        assert_eq!(v.final_severity, "중간", "재요청 확인까지만으로는 중간을 넘지 못한다");
    }

    #[test]
    fn recommendation_for_demoted_root_is_flagged() {
        // '지금 해야 할 일' 이 근거 없는 항목을 최우선으로 밀어내지 않게 표시한다.
        let text = "# 리포트\n\n## 4. 공격 시나리오\n\n### 루트 1. 상상 취약점 [치명]\n위험도: 치명\n검증: [실증] 확인\n증거: totally made up evidence string that never existed\n\n## 5. 개선·보완 권고 (우선순위)\n\n- [P0] 상상 취약점 패치 — 위험도 [치명] · 보완: 입력 검증 추가\n- [P1] SQL 오류 지문 노출 정리 — 위험도 [중간] · 보완: 오류 메시지 숨김\n";
        let g = gate_report(text, &idx(), &FetchMap::new(), GateMode::Strict);
        assert!(
            g.text.contains("- [P0] 상상 취약점 패치 — 위험도 [치명] · 보완: 입력 검증 추가 (확인 필요 — 근거 미확보 항목)"),
            "{}",
            g.text
        );
        assert!(
            g.text.contains("- [P1] SQL 오류 지문 노출 정리 — 위험도 [중간] · 보완: 오류 메시지 숨김\n"),
            "확정된 항목은 건드리지 않아야 한다:\n{}",
            g.text
        );
    }

    /// 대표 시나리오 — 그럴싸하게 포장된 리포트에 게이트를 걸었을 때의 결과.
    #[test]
    fn realistic_report_gate_result() {
        let text = r#"# 데모몰 진단 리포트

## 0. 한눈에 보기

| 루트 | 위험도 | CVSS | 검증 | 공격 방법 | 탈취 정보 | 보완 요약 |
|---|---|---|---|---|---|---|
| 루트 1 | 치명 | 9.8 | 실증 | OR 1=1 | 전체 DB | 파라미터라이즈 |
| 루트 2 | 치명 | 9.1 | 실증 | 쿠키 탈취 | 세션 | HttpOnly |

## 4. 공격 시나리오

### 루트 1. 로그인 SQL 주입으로 관리자 탈취 [치명]
위험도: 치명
CVSS: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) · CWE-89
근거: [P-001]
진입점: /login POST 폼
공격 흐름: 공격자 → /login → (SQL 주입) → 인증 우회 → (관리자 세션 탈취) → 전체 개인정보
증거: You have an error in your SQL syntax near '' at line 1
검증: [실증] 재현 성공
보완: Prepared statement 사용

### 루트 2. JWT alg=none 서명 우회 [치명]
위험도: 치명
CVSS: 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) · CWE-347
진입점: /api/me
공격 흐름: 공격자 → /api/me → (alg=none) → 관리자 권한 획득
증거: base64 decode 된 토큰에서 admin:true 확인
검증: [실증] 재현 성공
보완: 서명 검증 필수

## 5. 개선·보완 권고 (우선순위)

- [P0] 로그인 SQL 주입 — 위험도 [치명] · 보완: 파라미터라이즈
- [P1] JWT alg=none 서명 우회 — 위험도 [치명] · 보완: 서명 검증
"#;
        let mut hits = BTreeMap::new();
        hits.insert(
            "P-001".to_string(),
            HitFact {
                id: "P-001".into(),
                severity: "medium".into(),
                category: "sqli-signal".into(),
                title: "SQL 오류 지문 노출".into(),
                target: "https://demo.test/login".into(),
                evidence: "You have an error in your SQL syntax".into(),
                verdict: "confirmed".into(),
            },
        );
        let ix = EvidenceIndex { hits };
        let g = gate_report(text, &ix, &FetchMap::new(), GateMode::Strict);

        // ① 근거 있는 루트는 남고, 위험도는 근거(medium)로 낮아진다.
        assert!(g.text.contains("### 루트 1. 로그인 SQL 주입으로 관리자 탈취 [중간]"), "{}", g.text);
        assert!(g.text.contains("검증: [실증] P0 실측 근거 [P-001] — 최대 심각도 중간"), "{}", g.text);
        // ② 근거 없는 루트는 '공격 시나리오'에서 빠지고 미확인 가능성으로 간다.
        assert!(!g.text.contains("### 루트 2. JWT alg=none"), "{}", g.text);
        assert!(g.text.contains("#### 미확인 2. JWT alg=none 서명 우회"), "{}", g.text);
        assert!(g.text.contains("검증: [미확인]"), "{}", g.text);
        // ③ 지어낸 CVSS 점수는 남지 않는다.
        assert!(!g.text.contains("9.8 ("), "{}", g.text);
        assert!(!g.text.contains("9.1 ("), "{}", g.text);
        // ④ 요약 표는 남은 루트만, 게이트 판정과 일치.
        assert!(g.text.contains("| 루트 1 | 중간 |"), "{}", g.text);
        assert!(!g.text.contains("| 루트 2 |"), "{}", g.text);
        // ⑤ 미확인 가능성 절은 마지막 루트 바로 뒤에 온다.
        let root_pos = g.text.find("### 루트 1.").unwrap();
        let hypo_pos = g.text.find("## 미확인 가능성").unwrap();
        let fix_pos = g.text.find("## 5. 개선·보완 권고").unwrap();
        assert!(root_pos < hypo_pos && hypo_pos < fix_pos, "절 순서:\n{}", g.text);
        // ⑥ 강등된 루트를 가리키는 권고 항목에는 표시가 붙는다.
        assert!(
            g.text.contains("- [P1] JWT alg=none 서명 우회 — 위험도 [치명] · 보완: 서명 검증 (확인 필요 — 근거 미확보 항목)"),
            "{}",
            g.text
        );
        // ⑦ 실측 원장과 게이트 기록이 붙는다.
        assert!(g.text.contains("부록 C. P0 실측 발견 원장"), "{}", g.text);
        assert!(g.text.contains("부록 D. 사실 검증 게이트 적용 기록"), "{}", g.text);
        assert!(g.text.contains("P-001"), "{}", g.text);
    }

    #[test]
    fn demoted_card_body_drops_proof_badges() {
        let c = card(
            "위험도: 치명\n검증: [실증] 확인함\n증거: never existed evidence string at all here\n",
            "### 루트 1. 가짜 [치명]",
        );
        let v = judge_card(&c, &idx(), &FetchMap::new(), GateMode::Strict);
        assert!(v.demoted);
        let body = neutralize_badges(&c.body);
        assert!(!body.contains("[실증]"), "{body}");
        assert!(body.contains("[미확인]"), "{body}");
    }
}
