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
        target: crate::redact::redact_url(target),
        evidence: crate::redact::redact_text(&evidence.chars().take(1200).collect::<String>()),
        reproduction: reproduction.to_string(),
        remediation: signals::remediation(signal).to_string(),
    }
}

/// CVSS v3.1 근사 벡터 — 분류별 매핑.
pub struct Cvss {
    pub score: f32,
    pub vector: &'static str,
    pub cwe: &'static str,
}

/// 분류 → CVSS 벡터.
pub fn cvss_for(category: &str) -> Option<Cvss> {
    let c = category.to_ascii_lowercase();
    let hit = |score: f32, vector: &'static str, cwe: &'static str| Some(Cvss { score, vector, cwe });
    if c.contains("sqli") || c.contains("sql") {
        hit(9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-89")
    } else if c.contains("cmdi") || c.contains("command") || c.contains("rce") {
        hit(9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-78")
    } else if c.contains("idor") || c.contains("exposed_sensitive_file") {
        hit(6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "CWE-639")
    } else if c.contains("xss") {
        hit(6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "CWE-79")
    } else if c.contains("ssrf") {
        hit(8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "CWE-918")
    } else if c.contains("xxe") {
        hit(9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "CWE-611")
    } else if c.contains("ssti") || c.contains("template_injection") || c.contains("template:inject") {
        hit(8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-1336")
    } else if c.starts_with("template:") {
        // 템플릿 ID 로 분류 (노출·설정·헤더 계열)
        let id = c.trim_start_matches("template:");
        if id.contains("cors") {
            hit(8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-942")
        } else if id.contains("security-header") || id.contains("header") {
            hit(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-693")
        } else if id.contains("open-redirect") || id.contains("redirect") {
            hit(6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "CWE-601")
        } else if id.contains("directory-listing") {
            hit(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-548")
        } else if id.contains("console") || id.contains("debug") || id.contains("phpinfo") {
            hit(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-215")
        } else {
            // 설정/시크릿 노출 계열
            hit(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-538")
        }
    } else if c.contains("template") {
        hit(8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-1336")
    } else if c.contains("lfi") || c.contains("traversal") || c.contains("path") {
        hit(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-22")
    } else if c.contains("jwt") {
        hit(9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "CWE-347")
    } else if c.contains("secret") || c.contains("credential") {
        hit(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-200")
    } else if c.contains("cookie") {
        hit(4.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "CWE-614")
    } else if c.contains("tls") || c.contains("cipher") {
        hit(5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-326")
    } else if c.contains("header") || c.contains("cors") || c.contains("directory_listing") {
        hit(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-693")
    } else {
        None
    }
}

/// 마크다운 안전 처리 — 제어문자 제거 + 코드펜스 탈출.
pub fn md_escape(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .filter(|c| *c != '\u{0}' && *c != '\r' && (*c != '\u{2028}'))
        .collect();
    cleaned.replace("```", "`` `")
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
        let _ = writeln!(out, "### {}. [{}] {}", i + 1, f.severity.to_uppercase(), md_escape(&f.title));
        let _ = writeln!(out);
        let _ = writeln!(out, "- 대상: {}", md_escape(&f.target));
        let _ = writeln!(out, "- 분류: {}", md_escape(&f.category));
        if let Some(cvss) = cvss_for(&f.category) {
            let _ = writeln!(out, "- CVSS: {:.1} ({}) · {}", cvss.score, cvss.vector, cvss.cwe);
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "**근거**");
        let _ = writeln!(out);
        let _ = writeln!(out, "~~~");
        let _ = writeln!(out, "{}", md_escape(&f.evidence));
        let _ = writeln!(out, "~~~");
        let _ = writeln!(out);
        let _ = writeln!(out, "**재현 절차**");
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", md_escape(&f.reproduction));
        let _ = writeln!(out);
        let _ = writeln!(out, "**보완(수정) 포인트**");
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", md_escape(&f.remediation));
        let _ = writeln!(out);
    }
    out
}

/// HTML 리포트 — 단일 파일, 인라인 스타일 (이메일·웹 공유용).
pub fn to_html(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">");
    out.push_str("<title>보안 점검 리포트</title><style>");
    out.push_str("body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:32px}");
    out.push_str("h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px;border-bottom:1px solid #30363d;padding-bottom:8px}");
    out.push_str("table{border-collapse:collapse;width:100%;margin:12px 0}");
    out.push_str("th,td{border:1px solid #30363d;padding:7px 10px;text-align:left;font-size:13px}");
    out.push_str("th{background:#161b22;color:#8b949e;font-weight:600}");
    out.push_str(".sev{font-weight:700;padding:2px 7px;border-radius:4px;font-size:11px}");
    out.push_str(".critical{background:#3d1418;color:#ff7b72}.high{background:#3d2b12;color:#ffa657}");
    out.push_str(".medium{background:#2d2a12;color:#e3b341}.low{background:#1c2430;color:#8b949e}");
    out.push_str("pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;overflow-x:auto;font-size:12px;line-height:1.45}");
    out.push_str(".meta{color:#8b949e;font-size:13px}code{background:#161b22;padding:2px 5px;border-radius:4px;font-size:12px}");
    out.push_str("</style></head><body>");
    let _ = write!(out, "<h1>보안 점검 리포트 — {}</h1>", html_escape(&report.engagement));
    let _ = write!(out, "<p class=\"meta\">생성 {} · 대상 {} · 인가 범위 {}</p>",
        html_escape(&report.generated_at),
        html_escape(report.target.as_deref().unwrap_or("-")),
        html_escape(&report.scope.join(", ")));
    out.push_str("<h2>요약</h2><table><tr><th>심각도</th><th>건수</th></tr>");
    let _ = write!(out, "<tr><td>critical</td><td>{}</td></tr>", report.summary.critical);
    let _ = write!(out, "<tr><td>high</td><td>{}</td></tr>", report.summary.high);
    let _ = write!(out, "<tr><td>medium</td><td>{}</td></tr>", report.summary.medium);
    let _ = write!(out, "<tr><td>low</td><td>{}</td></tr>", report.summary.low);
    let _ = write!(out, "<tr><td><b>합계</b></td><td><b>{}</b></td></tr></table>", report.summary.total);
    if !report.stats.is_empty() {
        out.push_str("<h2>측정</h2><table>");
        for (k, v) in &report.stats {
            let _ = write!(out, "<tr><td>{}</td><td>{}</td></tr>", html_escape(k), html_escape(v));
        }
        out.push_str("</table>");
    }
    out.push_str("<h2>발견</h2>");
    if report.findings.is_empty() {
        out.push_str("<p class=\"meta\">확정된 발견 없음.</p>");
    }
    for (i, f) in report.findings.iter().enumerate() {
        let sev = f.severity.to_ascii_lowercase();
        let _ = write!(
            out,
            "<h3><span class=\"sev {}\">{}</span> {}. {}</h3>",
            sev,
            sev.to_uppercase(),
            i + 1,
            html_escape(&f.title)
        );
        let _ = write!(out, "<p class=\"meta\">대상 <code>{}</code> · 분류 <code>{}</code>", html_escape(&f.target), html_escape(&f.category));
        if let Some(cvss) = cvss_for(&f.category) {
            let _ = write!(out, " · CVSS {:.1} ({})", cvss.score, cvss.vector);
        }
        out.push_str("</p>");
        let _ = write!(out, "<p><b>근거</b></p><pre>{}</pre>", html_escape(&f.evidence));
        let _ = write!(out, "<p><b>재현 절차</b></p><pre>{}</pre>", html_escape(&f.reproduction));
        let _ = write!(out, "<p><b>보완(수정) 포인트</b></p><p>{}</p>", html_escape(&f.remediation));
    }
    out.push_str("</body></html>");
    out
}

/// HTML 이스케이프.
pub fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
