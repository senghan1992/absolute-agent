//! 가격/수량 변조 탐지.
//!
//! "클라이언트가 보낸 금액을 서버가 그대로 신뢰하는가" 를 검증한다.
//! 핵심 판정:
//!   - 총액이 기준선 + (변조값 - 원래값) 을 따라가면 → 서버가 값을 신뢰 (취약)
//!   - 총액이 기준선 그대로면 → 서버가 재계산 (안전)
//!   - 4xx/5xx 면 → 서버가 거부 (안전)
//!   - 금액 필드가 변조값을 그대로 되풀이하면 → 입력값 반사 (취약)

use serde::Serialize;
use std::collections::BTreeMap;

use crate::probes::{ProbeClient, ProbeResponse, extract_numeric_fields, replace_param};
use crate::report::Finding;

/// 합계로 볼 필드 (우선순위 순).
pub const TOTAL_FIELDS: &[&str] = &[
    "total", "grand_total", "total_price", "order_total", "payment_total", "amount_total",
    "subtotal", "payment", "charge", "amount", "total_amount",
];
/// 개별 단가 필드.
pub const PRICE_FIELDS: &[&str] = &["price", "unit_price", "list_price", "item_price", "sale_price"];

/// 탐색 설정.
#[derive(Debug, Clone)]
pub struct TamperConfig {
    pub url: String,
    pub method: String,
    /// 변조할 파라미터 (예: "price", "amount", "qty").
    pub param: String,
    /// 기준값 — 비우면 URL 에서 읽는다.
    pub baseline_value: String,
    /// 함께 보낼 다른 파라미터 (qty, sku 등).
    pub other_params: Vec<(String, String)>,
    pub body: Option<String>,
    /// 시도할 변조값.
    pub values: Vec<String>,
    /// 합계 필드 (비우면 기본 목록).
    pub watch_fields: Vec<String>,
}

impl TamperConfig {
    pub fn new(url: &str, param: &str) -> Self {
        Self {
            url: url.to_string(),
            method: "POST".into(),
            param: param.to_string(),
            baseline_value: crate::probes::read_param(url, param),
            other_params: Vec::new(),
            body: None,
            values: default_tamper_values(),
            watch_fields: Vec::new(),
        }
    }

    fn totals_watched(&self) -> Vec<String> {
        if self.watch_fields.is_empty() {
            TOTAL_FIELDS.iter().map(|s| s.to_string()).collect()
        } else {
            self.watch_fields.clone()
        }
    }
}

/// 기본 변조값 — 0·음수·아주 큰 값·정수 오버플로.
pub fn default_tamper_values() -> Vec<String> {
    vec![
        "0".into(),
        "-1".into(),
        "0.01".into(),
        "1".into(),
        "999999999".into(),
        "2147483648".into(),
        "-2147483649".into(),
        "99999999999999999999".into(),
    ]
}

/// 판정.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperVerdict {
    /// 서버가 변조를 거부 (안전).
    Rejected,
    /// 서버가 값을 무시하고 재계산 (안전).
    Recalculated,
    /// 총액이 변조값을 따라감 (취약).
    FollowedTamper,
    /// 금액 필드가 변조값을 그대로 반사 (취약).
    Reflected,
    /// 총액은 변했지만 클라이언트 값을 따라간다고 단정할 수 없음.
    ChangedUnexpected,
    /// 판정 불가 (금액 필드가 없음).
    Unknown,
}

/// 기준선 관찰.
#[derive(Debug, Clone)]
pub struct TamperSample {
    pub status: u16,
    pub numerics: BTreeMap<String, f64>,
    pub total: Option<f64>,
    pub body: String,
}

impl TamperSample {
    fn from_response(resp: &ProbeResponse, watched: &[String]) -> Self {
        let numerics = extract_numeric_fields(&resp.body);
        let total = watched.iter().find_map(|k| numerics.get(k).copied());
        Self { status: resp.status, numerics, total, body: resp.body.clone() }
    }
}

/// 한 번의 변조 시도.
#[derive(Debug, Clone, Serialize)]
pub struct TamperAttempt {
    pub value: String,
    pub status: u16,
    pub verdict: TamperVerdict,
    pub baseline_total: Option<f64>,
    pub observed_total: Option<f64>,
    pub delta: Option<f64>,
    pub reflected_fields: Vec<String>,
    pub evidence: String,
}

/// 탐지 결과.
#[derive(Debug, Clone, Serialize)]
pub struct TamperReport {
    pub param: String,
    pub baseline_value: String,
    pub baseline_total: Option<f64>,
    pub attempts: Vec<TamperAttempt>,
    pub findings: Vec<Finding>,
    pub requests: usize,
}

/// 판정 로직 (순수 함수).
pub fn judge(
    baseline: &TamperSample,
    attempt_status: u16,
    attempt_numerics: &BTreeMap<String, f64>,
    tamper_value: &str,
    baseline_value: f64,
    watched: &[String],
) -> (TamperVerdict, Option<f64>, Option<f64>, Option<f64>, Vec<String>) {
    // 1) 서버가 변조를 거부했는가.
    if !(200..300).contains(&attempt_status) {
        return (TamperVerdict::Rejected, None, None, None, Vec::new());
    }

    let observed_total = watched.iter().find_map(|k| attempt_numerics.get(k).copied());

    // 2) 입력값이 단가 필드에 그대로 반사되었는가 (총액은 3 에서 모델로 판정).
    let mut reflected: Vec<String> = Vec::new();
    if let Ok(tv) = tamper_value.parse::<f64>() {
        for (k, v) in attempt_numerics {
            if (v - tv).abs() < 0.0001 && PRICE_FIELDS.contains(&k.as_str()) {
                reflected.push(k.clone());
            }
        }
    }
    let delta_of = |observed: Option<f64>| match (observed, baseline.total) {
        (Some(o), Some(b)) => Some(o - b),
        _ => None,
    };

    if let (Some(observed), Some(base_total)) = (observed_total, baseline.total) {
        let delta = observed - base_total;
        // 3) 서버가 값을 신뢰했다면 총액은 아래 두 모델 중 하나를 따라간다.
        //    (가) 곱셈형: 합계 = 단가 x 수량  -> baseline * (변조/원래)
        //    (나) 가산형: 합계 = 원래합계 + (변조 - 원래)
        let tv = tamper_value.parse::<f64>().unwrap_or(base_total);
        let mul_expected = if baseline_value.abs() > f64::EPSILON {
            base_total * (tv / baseline_value)
        } else {
            base_total + tv
        };
        let add_expected = base_total + (tv - baseline_value);
        for candidate in [mul_expected, add_expected] {
            let tolerance = (candidate.abs() * 0.001).max(0.01);
            if (observed - candidate).abs() <= tolerance {
                return (TamperVerdict::FollowedTamper, Some(observed), Some(delta), Some(candidate), Vec::new());
            }
        }
        if !reflected.is_empty() {
            return (TamperVerdict::Reflected, Some(observed), Some(delta), None, reflected);
        }
        if delta.abs() < 0.0001 {
            return (TamperVerdict::Recalculated, Some(observed), Some(delta), Some(mul_expected), Vec::new());
        }
        return (TamperVerdict::ChangedUnexpected, Some(observed), Some(delta), Some(mul_expected), Vec::new());
    }

    // 4) 총액을 볼 수 없어도 단가 반사는 확인한다.
    if !reflected.is_empty() {
        return (TamperVerdict::Reflected, observed_total, delta_of(observed_total), None, reflected);
    }
    (TamperVerdict::Unknown, observed_total, None, None, Vec::new())
}

/// 탐색 실행.
pub async fn run(client: &ProbeClient, config: &TamperConfig) -> Result<TamperReport, String> {
    client.check_scope(&config.url)?;
    let watched = config.totals_watched();
    let mut requests = 0usize;

    // 1) 기준선 요청.
    let baseline_value = if config.baseline_value.is_empty() {
        "0".to_string()
    } else {
        config.baseline_value.clone()
    };
    let (base_url, base_body) = replace_param(
        &config.url,
        config.body.as_deref(),
        &config.param,
        &baseline_value,
    );
    let base_resp = client
        .request(&config.method, &base_url, &config.other_params, base_body.as_deref())
        .await?;
    requests += 1;
    let baseline = TamperSample::from_response(&base_resp, &watched);
    let baseline_value_num = baseline_value.parse::<f64>().unwrap_or(0.0);

    // 2) 변조 시도.
    let mut attempts: Vec<TamperAttempt> = Vec::new();
    for value in &config.values {
        let (url, body) = replace_param(&config.url, config.body.as_deref(), &config.param, value);
        let resp = match client.request(&config.method, &url, &config.other_params, body.as_deref()).await {
            Ok(r) => r,
            Err(e) => {
                attempts.push(TamperAttempt {
                    value: value.clone(),
                    status: 0,
                    verdict: TamperVerdict::Unknown,
                    baseline_total: baseline.total,
                    observed_total: None,
                    delta: None,
                    reflected_fields: vec![],
                    evidence: format!("요청 실패: {e}"),
                });
                continue;
            }
        };
        requests += 1;
        let numerics = extract_numeric_fields(&resp.body);
        let (verdict, observed, delta, _expected, reflected) = judge(
            &baseline,
            resp.status,
            &numerics,
            value,
            baseline_value_num,
            &watched,
        );
        attempts.push(TamperAttempt {
            value: value.clone(),
            status: resp.status,
            verdict: verdict.clone(),
            baseline_total: baseline.total,
            observed_total: observed,
            delta,
            reflected_fields: reflected,
            evidence: resp.body.chars().take(400).collect(),
        });
    }

    // 3) 발견 생성.
    let mut findings: Vec<Finding> = Vec::new();
    for a in &attempts {
        match a.verdict {
            TamperVerdict::FollowedTamper => {
                let negative = a.observed_total.map(|v| v <= 0.0).unwrap_or(false);
                findings.push(Finding {
                    title: format!(
                        "가격 변조 성공 — {} 값을 서버가 그대로 사용",
                        config.param
                    ),
                    severity: if negative { "critical".into() } else { "high".into() },
                    category: "price_tampering".into(),
                    target: format!("{} {}", config.url, config.param),
                    evidence: format!(
                        "기준선 {}= {} → 합계 {:?}\n변조 {}= {} → 합계 {:?} (차이 {:?})\n응답: {}",
                        config.param, baseline_value, baseline.total, config.param, a.value, a.observed_total, a.delta, a.evidence
                    ),
                    reproduction: format!(
                        "1) {} 에 정상값 {} 으로 요청\n2) {} 을 {} 로 바꿔 요청\n3) 합계가 그대로 반영됨 (차이 {:?})",
                        config.url, baseline_value, config.param, a.value, a.delta
                    ),
                    remediation: "금액·수량은 클라이언트를 절대 신뢰하지 말고 서버 측에서 상품 정보로 다시 계산하세요. \
                                  0·음수·비정상 큰 값·정수 오버플로를 반드시 거부하고, 소수점은 정수(최소 단위)로 처리하세요. \
                                  주문 확정 시점에 가격을 한 번 더 검증하는 것이 아니라 결제 직전 원본 DB 기준으로 재계산해야 합니다."
                        .into(),
                });
            }
            TamperVerdict::Reflected => {
                findings.push(Finding {
                    title: format!("클라이언트 제공 금액이 응답에 그대로 반영됨 — {}", config.param),
                    severity: "high".into(),
                    category: "price_tampering".into(),
                    target: format!("{} {}", config.url, config.param),
                    evidence: format!(
                        "{}={} 를 보냈을 때 응답의 {:?} 필드가 같은 값을 반환\n응답: {}",
                        config.param, a.value, a.reflected_fields, a.evidence
                    ),
                    reproduction: format!("{} 요청에서 {} 을 {} 로 지정하면 그대로 반영됩니다.", config.url, config.param, a.value),
                    remediation: "요청으로 들어온 금액 필드는 응답에 그대로 돌려주지 말고 서버가 계산한 값만 반환하세요. \
                                  응답 필드와 결제 금액의 일관성도 함께 검증하세요."
                        .into(),
                });
            }
            TamperVerdict::ChangedUnexpected => {
                findings.push(Finding {
                    title: format!("변조에 따라 합계가 변경됨 — 서버 계산 로직 확인 필요 ({})", config.param),
                    severity: "medium".into(),
                    category: "price_logic".into(),
                    target: format!("{} {}", config.url, config.param),
                    evidence: format!(
                        "기준선 합계 {:?} → 변조 {} 의 합계 {:?} (차이 {:?})\n응답: {}",
                        baseline.total, a.value, a.observed_total, a.delta, a.evidence
                    ),
                    reproduction: format!("{} 에 {}={} 를 넣으면 합계가 {:?} 로 변합니다.", config.url, config.param, a.value, a.observed_total),
                    remediation: "합계 계산 경로가 클라이언트 입력에 얼마나 의존하는지 확인하세요. \
                                  수량 한도·할인 규칙·반올림 정책이 서버에서 강제되는지 점검하세요."
                        .into(),
                });
            }
            TamperVerdict::Unknown => {}
            TamperVerdict::Rejected | TamperVerdict::Recalculated => {}
        }
    }

    Ok(TamperReport {
        param: config.param.clone(),
        baseline_value,
        baseline_total: baseline.total,
        attempts,
        findings,
        requests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(total: Option<f64>) -> TamperSample {
        let mut numerics = BTreeMap::new();
        if let Some(t) = total {
            numerics.insert("total".to_string(), t);
        }
        TamperSample { status: 200, numerics, total, body: String::new() }
    }

    fn watched() -> Vec<String> {
        TOTAL_FIELDS.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn rejected_when_status_error() {
        let base = sample(Some(100.0));
        let (v, _, _, _, _) = judge(&base, 400, &BTreeMap::new(), "0", 10.0, &watched());
        assert_eq!(v, TamperVerdict::Rejected);
    }

    #[test]
    fn followed_when_total_tracks_tamper() {
        // 기준선 price=10 total=100 → price=0 이면 total=0 이 되어야 한다.
        let base = sample(Some(100.0));
        let mut numerics = BTreeMap::new();
        numerics.insert("total".to_string(), 0.0);
        let (v, observed, delta, expected, _) = judge(&base, 200, &numerics, "0", 10.0, &watched());
        assert_eq!(v, TamperVerdict::FollowedTamper);
        assert_eq!(observed, Some(0.0));
        assert_eq!(delta, Some(-100.0));
        assert_eq!(expected, Some(0.0));
    }

    #[test]
    fn recalculated_when_total_unchanged() {
        let base = sample(Some(100.0));
        let mut numerics = BTreeMap::new();
        numerics.insert("total".to_string(), 100.0);
        let (v, _, _, _, _) = judge(&base, 200, &numerics, "0", 10.0, &watched());
        assert_eq!(v, TamperVerdict::Recalculated);
    }

    #[test]
    fn reflected_when_price_field_echoes_input() {
        let base = sample(Some(100.0));
        let mut numerics = BTreeMap::new();
        numerics.insert("price".to_string(), 0.0);
        let (v, _, _, _, fields) = judge(&base, 200, &numerics, "0", 10.0, &watched());
        assert_eq!(v, TamperVerdict::Reflected);
        assert!(fields.contains(&"price".to_string()));
    }

    #[test]
    fn unknown_without_money_fields() {
        let base = sample(None);
        let (v, _, _, _, _) = judge(&base, 200, &BTreeMap::new(), "0", 10.0, &watched());
        assert_eq!(v, TamperVerdict::Unknown);
    }
}
