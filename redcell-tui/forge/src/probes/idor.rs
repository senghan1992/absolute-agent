//! IDOR(부적절한 객체 참조) 탐지.
//!
//! "이 요청에 쓰인 id 를 바꿔도 남의 리소스가 나온다" 를 검증한다.
//! 핵심은 **다른 id 에서 다른 사람의 데이터가 나오는지** 를 확인하는 것이다.
//! 본문이 단순히 id 를 반사하는 API(공개 카탈로그 등) 는 취약점이 아니므로
//! 식별자(PII) 집합이 실제로 달라지는지까지 봐야 확정한다.

use serde::Serialize;
use std::collections::BTreeSet;

use crate::probes::{
    ProbeClient, ProbeResponse, extract_identifiers, read_param, replace_param, resource_signature,
};
use crate::report::Finding;

/// IDOR 탐색 설정.
#[derive(Debug, Clone)]
pub struct IdorConfig {
    pub url: String,
    pub method: String,
    /// 바꿀 대상 파라미터 (예: "id").
    pub param: String,
    /// 기준값 — 보통 대상 URL 에 들어 있는 값.
    pub baseline_value: String,
    /// 직접 시도할 값 목록 (비우면 기준값 주변을 자동 생성).
    pub candidates: Vec<String>,
    /// 기준값 주변으로 몇 칸까지 탐색할지.
    pub spread: u32,
    /// 추가로 붙일 쿼리 파라미터.
    pub extra_query: Vec<(String, String)>,
    /// 요청 본문.
    pub body: Option<String>,
}

impl IdorConfig {
    pub fn new(url: &str, param: &str) -> Self {
        Self {
            url: url.to_string(),
            method: "GET".into(),
            param: param.to_string(),
            baseline_value: read_param(url, param),
            candidates: Vec::new(),
            spread: 3,
            extra_query: Vec::new(),
            body: None,
        }
    }

    /// 시도할 값 목록 — 명시 목록 + 기준값 주변 + 경계값.
    pub fn candidate_values(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let push = |v: String, out: &mut Vec<String>, seen: &mut BTreeSet<String>| {
            if !v.is_empty() && seen.insert(v.clone()) {
                out.push(v);
            }
        };
        for c in &self.candidates {
            push(c.clone(), &mut out, &mut seen);
        }
        if let Ok(base) = self.baseline_value.parse::<i64>() {
            for d in 1..=self.spread {
                let d = d as i64;
                push((base + d).to_string(), &mut out, &mut seen);
                push((base - d).to_string(), &mut out, &mut seen);
            }
            // 존재하지 않는 범위를 시험 — 404 가 오는지 (열거 가능성 판별용).
            push((base + 100_000).to_string(), &mut out, &mut seen);
            push("0".to_string(), &mut out, &mut seen);
        } else {
            push("1".to_string(), &mut out, &mut seen);
            push("999999999".to_string(), &mut out, &mut seen);
        }
        out
    }
}

/// 한 번의 관찰 결과.
#[derive(Debug, Clone, Serialize)]
pub struct IdorSample {
    pub value: String,
    pub status: u16,
    pub len: usize,
    /// id 값을 제외한 본문 서명.
    pub signature: String,
    /// 식별자(PII) 목록.
    pub identifiers: Vec<String>,
    /// 기준선과 내용이 다른가.
    pub differs: bool,
    pub elapsed_ms: u64,
    pub evidence: String,
}

impl IdorSample {
    fn from_response(value: &str, resp: &ProbeResponse) -> Self {
        Self {
            value: value.to_string(),
            status: resp.status,
            len: resp.len,
            signature: resource_signature(&resp.body, value),
            identifiers: extract_identifiers(&resp.body),
            differs: false,
            elapsed_ms: resp.elapsed_ms,
            evidence: resp.body.chars().take(400).collect(),
        }
    }

    fn accessible(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// 판정 결과.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdorVerdict {
    /// 다른 주체의 리소스가 반환됨 — 확정.
    Confirmed,
    /// 내용은 달라지지만 주체 식별이 안 됨 — 수동 확인 필요.
    Suspected,
    /// 열거만 가능 (본문 차이는 없음).
    Enumerable,
    /// 취약점 신호 없음.
    None,
}

/// IDOR 탐지 결과.
#[derive(Debug, Clone, Serialize)]
pub struct IdorReport {
    pub param: String,
    pub baseline_value: String,
    pub baseline: Option<IdorSample>,
    pub samples: Vec<IdorSample>,
    pub verdict: IdorVerdict,
    pub findings: Vec<Finding>,
    pub requests: usize,
}

/// 판정 로직 (순수 함수 — 단위 테스트 대상).
pub fn judge(baseline: &Option<IdorSample>, samples: &[IdorSample]) -> IdorVerdict {
    let Some(base) = baseline else { return IdorVerdict::None };
    let base_ids: BTreeSet<&str> = base.identifiers.iter().map(|s| s.as_str()).collect();
    let has_identity = !base.identifiers.is_empty();

    let accessible: Vec<&IdorSample> = samples.iter().filter(|s| s.accessible()).collect();
    if accessible.is_empty() {
        // 전부 거부되었으면 — 소유자 검증이 동작한다고 본다.
        return IdorVerdict::None;
    }
    // 존재 여부가 구분되려면 "있는 값은 2xx, 없는 값은 4xx" 가 함께 나타나야 한다.
    // 파라미터를 아예 무시하는 엔드포인트(항상 200) 는 열거 신호가 아니다.
    let denied: Vec<&IdorSample> = samples
        .iter()
        .filter(|s| !s.accessible() && s.status != 0)
        .collect();

    // 다른 주체의 데이터가 나왔는지.
    let mut confirmed = false;
    let mut suspected = false;
    for s in &accessible {
        if !s.differs {
            continue;
        }
        let new_ids: Vec<&String> = s.identifiers.iter().filter(|id| !base_ids.contains(id.as_str())).collect();
        if has_identity && !new_ids.is_empty() {
            confirmed = true;
        } else {
            suspected = true;
        }
    }
    if confirmed {
        return IdorVerdict::Confirmed;
    }
    if suspected {
        return IdorVerdict::Suspected;
    }
    // 내용은 모두 같지만 존재/부재가 구분된다면 — 열거 가능성.
    if denied.is_empty() {
        return IdorVerdict::None;
    }
    IdorVerdict::Enumerable
}

/// 탐색 실행.
pub async fn run(client: &ProbeClient, config: &IdorConfig) -> Result<IdorReport, String> {
    client.check_scope(&config.url)?;

    let mut requests = 0usize;

    // 1) 기준선.
    let (base_url, base_body) = replace_param(
        &config.url,
        config.body.as_deref(),
        &config.param,
        &config.baseline_value,
    );
    let base_resp = client
        .request(&config.method, &base_url, &config.extra_query, base_body.as_deref())
        .await?;
    requests += 1;
    let baseline = IdorSample::from_response(&config.baseline_value, &base_resp);

    // 2) 후보값 탐색.
    let mut samples: Vec<IdorSample> = Vec::new();
    for value in config.candidate_values() {
        let (url, body) = replace_param(&config.url, config.body.as_deref(), &config.param, &value);
        let resp = match client.request(&config.method, &url, &config.extra_query, body.as_deref()).await {
            Ok(r) => r,
            Err(e) => {
                samples.push(IdorSample {
                    value: value.clone(),
                    status: 0,
                    len: 0,
                    signature: String::new(),
                    identifiers: Vec::new(),
                    differs: false,
                    elapsed_ms: 0,
                    evidence: format!("요청 실패: {e}"),
                });
                continue;
            }
        };
        requests += 1;
        let mut sample = IdorSample::from_response(&value, &resp);
        sample.differs = sample.status != baseline.status || sample.signature != baseline.signature;
        samples.push(sample);
    }

    // 3) 판정.
    let verdict = judge(&Some(baseline.clone()), &samples);
    let mut findings: Vec<Finding> = Vec::new();

    match verdict {
        IdorVerdict::Confirmed => {
            let witness = samples
                .iter()
                .find(|s| {
                    s.accessible()
                        && s.differs
                        && s.identifiers
                            .iter()
                            .any(|id| !baseline.identifiers.iter().any(|b| b == id))
                })
                .cloned();
            let target_value = witness.as_ref().map(|w| w.value.clone()).unwrap_or_default();
            let new_ids: Vec<String> = witness
                .as_ref()
                .map(|w| {
                    w.identifiers
                        .iter()
                        .filter(|id| !baseline.identifiers.contains(id))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            findings.push(Finding {
                title: format!("IDOR — {} 값 변경으로 다른 주체의 리소스가 반환됨", config.param),
                severity: "high".into(),
                category: "idor".into(),
                target: format!("{} {}={}", config.url, config.param, target_value),
                evidence: format!(
                    "기준선 {}={} 의 식별자: {:?}\n위반 값 {}={} 의 식별자: {:?}\n응답: {}",
                    config.param,
                    config.baseline_value,
                    baseline.identifiers,
                    config.param,
                    target_value,
                    new_ids,
                    witness.as_ref().map(|w| w.evidence.clone()).unwrap_or_default()
                ),
                reproduction: format!(
                    "1) {} 를 정상값({})으로 요청\n2) 같은 요청에서 {}={} 로 변경\n3) 다른 주체의 데이터가 그대로 반환됨",
                    config.url, config.baseline_value, config.param, target_value
                ),
                remediation: "모든 객체 접근에서 요청 주체와 리소스 소유자를 서버 측에서 비교하세요. \
                              식별자를 순차적으로 바꿔도 404 를 반환하는지 확인하고, 인증 없이 다른 객체가 \
                              조회되면 안 됩니다. 가능하다면 불투명한 UUID 로 외부 식별자를 노출하지 마세요."
                    .into(),
            });
        }
        IdorVerdict::Suspected => {
            findings.push(Finding {
                title: format!("객체 참조 검증 미비 의심 — {} 값에 따라 응답 내용이 변경됨", config.param),
                severity: "medium".into(),
                category: "idor_suspected".into(),
                target: format!("{} {}", config.url, config.param),
                evidence: samples
                    .iter()
                    .filter(|s| s.accessible() && s.differs)
                    .map(|s| format!("{}={} → status {} len {} ({})", config.param, s.value, s.status, s.len, s.evidence))
                    .take(4)
                    .collect::<Vec<_>>()
                    .join("\n"),
                reproduction: format!(
                    "{} 의 {} 값을 다른 값으로 바꿔 요청했을 때 응답 본문이 변경됩니다. 소유자 검증 여부를 확인하세요.",
                    config.url, config.param
                ),
                remediation: "객체 접근 시 소유자/테넌트 검증이 실제로 수행되는지 확인하세요. \
                              식별자가 순차적이면 UUID 등 추측 불가능한 값으로 바꾸고, 권한 검증을 서비스 계층 한 곳에 모으세요."
                    .into(),
            });
        }
        IdorVerdict::Enumerable => {
            findings.push(Finding {
                title: format!("리소스 열거 가능 — {} 값 범위를 추측할 수 있음", config.param),
                severity: "low".into(),
                category: "enumeration".into(),
                target: format!("{} {}", config.url, config.param),
                evidence: format!(
                    "{} 가 일부 값에서는 2xx 를, 다른 값에서는 {} 를 반환해 존재 여부를 구분할 수 있습니다.
거부된 값: {:?}",
                    config.param,
                    samples
                        .iter()
                        .find(|s| !s.accessible() && s.status != 0)
                        .map(|s| s.status.to_string())
                        .unwrap_or_else(|| "4xx".into()),
                    samples
                        .iter()
                        .filter(|s| !s.accessible() && s.status != 0)
                        .map(|s| s.value.clone())
                        .collect::<Vec<_>>()
                ),
                reproduction: format!("{} 의 {} 를 연속 값으로 바꿔가며 요청하면 응답 존재 여부를 구분할 수 있습니다.", config.url, config.param),
                remediation: "존재하지 않는 리소스와 권한 없는 리소스를 동일하게 응답하도록 하고, 식별자를 추측 불가능하게 만드세요."
                    .into(),
            });
        }
        IdorVerdict::None => {}
    }

    Ok(IdorReport {
        param: config.param.clone(),
        baseline_value: config.baseline_value.clone(),
        baseline: Some(baseline),
        samples,
        verdict,
        findings,
        requests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(value: &str, status: u16, sig: &str, ids: &[&str]) -> IdorSample {
        IdorSample {
            value: value.into(),
            status,
            len: 100,
            signature: sig.into(),
            identifiers: ids.iter().map(|s| s.to_string()).collect(),
            differs: sig != "base",
            elapsed_ms: 1,
            evidence: String::new(),
        }
    }

    #[test]
    fn confirms_when_other_identity_appears() {
        let baseline = sample("1", 200, "base", &["email=alice@x.io", "name=alice"]);
        let samples = vec![sample("2", 200, "other", &["email=bob@x.io", "name=bob"])];
        assert_eq!(judge(&Some(baseline), &samples), IdorVerdict::Confirmed);
    }

    #[test]
    fn suspected_when_no_identity_in_baseline() {
        let baseline = sample("1", 200, "base", &[]);
        let samples = vec![sample("2", 200, "other", &[])];
        assert_eq!(judge(&Some(baseline), &samples), IdorVerdict::Suspected);
    }

    #[test]
    fn enumerable_when_content_same_and_missing_ids_denied() {
        let baseline = sample("1", 200, "base", &["email=alice@x.io"]);
        let samples = vec![
            sample("2", 200, "base", &["email=alice@x.io"]),
            sample("100001", 404, "not found", &[]),
        ];
        assert_eq!(judge(&Some(baseline), &samples), IdorVerdict::Enumerable);
    }

    #[test]
    fn not_enumerable_when_parameter_is_ignored() {
        // 값에 관계없이 항상 200 이면 존재 경계가 없으므로 열거 신호가 아니다.
        let baseline = sample("1", 200, "base", &["email=alice@x.io"]);
        let samples = vec![
            sample("2", 200, "base", &["email=alice@x.io"]),
            sample("100001", 200, "base", &["email=alice@x.io"]),
        ];
        assert_eq!(judge(&Some(baseline), &samples), IdorVerdict::None);
    }

    #[test]
    fn no_verdict_when_all_denied() {
        let baseline = sample("1", 200, "base", &["email=alice@x.io"]);
        let samples = vec![sample("2", 403, "denied", &[])];
        assert_eq!(judge(&Some(baseline), &samples), IdorVerdict::None);
    }

    #[test]
    fn candidate_values_cover_neighbors_and_boundary() {
        let mut cfg = IdorConfig::new("http://x/api/user?id=5", "id");
        cfg.spread = 2;
        let vals = cfg.candidate_values();
        assert!(vals.contains(&"6".to_string()), "{vals:?}");
        assert!(vals.contains(&"4".to_string()), "{vals:?}");
        assert!(vals.contains(&"100005".to_string()), "{vals:?}");
        assert_eq!(cfg.baseline_value, "5");
    }
}
