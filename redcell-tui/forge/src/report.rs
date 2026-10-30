//! 리포트 생성 — 발견 → 재현 절차 → 보완(수정) 포인트.
//!
//! 이 툴의 목적은 "뚫는 것"만이 아니라 발견된 약점을 운영자가 고칠 수 있게
//! 하는 것이다. 그래서 모든 발견에 심각도·근거·재현 절차·권고 사항을 붙인다.

use serde::Serialize;
use std::fmt::Write as _;

use crate::signals;

/// 발견 하나.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub title: String,
    pub severity: String,
    pub category: String,
    pub target: String,
    pub evidence: String,
    pub reproduction: String,
    pub remediation: String,
}

/// 리포트.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub generated_at: String,
    pub engagement: String,
    pub scope: Vec<String>,
    pub target: Option<String>,
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
    pub stats: Vec<(String, String)>,
}

/// 요약 통계.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReportSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total: usize,
}

impl ReportSummary {
    pub fn of(findings: &[Finding]) -> Self {
        let mut s = ReportSummary { total: findings.len(), ..Default::default() };
        for f in findings {
            match f.severity.as_str() {
                "critical" => s.critical += 1,
                "high" => s.high += 1,
                "medium" => s.medium += 1,
                _ => s.low += 1,
            }
        }
        s
    }
}

/// 심각도 정렬 (중요도 순).
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by_key(|f| match f.severity.as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        _ => 3,
    });
}

/// 신호 기반 발견 생성.
pub fn finding_from_signal(signal: &str, target: &str, evidence: &str, reproduction: &str) -> Finding {
    Finding {
        title: format!("{} 패턴 노출", signal_label(signal)),
        severity: signals::severity(signal).to_string(),
        category: signal.to_string(),
        target: target.to_string(),
        evidence: evidence.chars().take(1200).collect(),
        reproduction: reproduction.to_string(),
        remediation: signals::remediation(signal).to_string(),
    }
}

/// 신호 한국어 라벨.
pub fn signal_label(signal: &str) -> &'static str {
    match signal {
        "sql_error" => "SQL 오류",
        "stack_trace" => "스택 트레이스",
        "debug_leak" => "디버그 정보",
        "php_error" => "PHP 오류 메시지",
        "path_disclosure" => "파일 경로",
        "framework_leak" => "프레임워크 식별 정보",
        "secret_like" => "시크릿 형태 값",
        "email_leak" => "이메일 주소",
        "internal_host" => "내부 호스트 주소",
        "sqli_marker" => "SQL 인젝션 마커",
        "xss_marker" => "스크립트 주입 마커",
        "cmd_marker" => "명령 실행 마커",
        "template_marker" => "템플릿 표현식",
        "xxe_marker" => "XML 외부 엔티티",
        _ => "정보 노출",
    }
}

/// Markdown 리포트.
pub fn to_markdown(report: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# 보안 점검 리포트 — {}", report.engagement);
    let _ = writeln!(out);
    let _ = writeln!(out, "- 생성 시각: {}", report.generated_at);
    if let Some(t) = &report.target {
        let _ = writeln!(out, "- 대상: {t}");
    }
    let _ = writeln!(out, "- 인가 범위: {}", report.scope.join(", "));
    let _ = writeln!(out);
    let _ = writeln!(out, "## 요약");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| 심각도 | 건수 |\n|---|---|\n| critical | {} |\n| high | {} |\n| medium | {} |\n| low | {} |\n| **합계** | **{}** |",
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.total
    );
    let _ = writeln!(out);
    if !report.stats.is_empty() {
        let _ = writeln!(out, "## 측정");
        let _ = writeln!(out);
        for (k, v) in &report.stats {
            let _ = writeln!(out, "- {k}: {v}");
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(out, "## 발견");
    let _ = writeln!(out);
    if report.findings.is_empty() {
        let _ = writeln!(out, "확정된 발견 없음. (미점검 표면이 남아 있을 수 있습니다.)");
    }
    for (i, f) in report.findings.iter().enumerate() {
        let _ = writeln!(out, "### {}. [{}] {}", i + 1, f.severity.to_uppercase(), f.title);
        let _ = writeln!(out);
        let _ = writeln!(out, "- 대상: {}", f.target);
        let _ = writeln!(out, "- 분류: {}", f.category);
        let _ = writeln!(out);
        let _ = writeln!(out, "**근거**");
        let _ = writeln!(out);
        let _ = writeln!(out, "~~~");
        let _ = writeln!(out, "{}", f.evidence);
        let _ = writeln!(out, "~~~");
        let _ = writeln!(out);
        let _ = writeln!(out, "**재현 절차**");
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", f.reproduction);
        let _ = writeln!(out);
        let _ = writeln!(out, "**보완(수정) 포인트**");
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", f.remediation);
        let _ = writeln!(out);
    }
    out
}

/// JSON 리포트.
pub fn to_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_contains_remediation() {
        let f = finding_from_signal("sql_error", "http://x/api", "SQL syntax error near", "GET /api?id=1'");
        let rep = Report {
            generated_at: "now".into(),
            engagement: "lab".into(),
            scope: vec!["127.0.0.1".into()],
            target: Some("http://x".into()),
            summary: ReportSummary::of(&[f.clone()]),
            findings: vec![f],
            stats: vec![],
        };
        let md = to_markdown(&rep);
        assert!(md.contains("보완(수정) 포인트"));
        assert!(md.contains("바인딩"));
    }
}
