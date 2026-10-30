//! 응답 신호 탐지 — 오류 메시지·스택트레이스·데이터 유출 패턴.
//!
//! 파이썬 커널 툴킷(`forge.analyze`)과 같은 규칙을 Rust 쪽에서도 사용한다.
//! 스톰 엔진이 수천 개 응답을 분류할 때 사용한다.

use regex::Regex;
use std::sync::OnceLock;

/// (신호 이름, 패턴) 목록.
const PATTERNS: &[(&str, &str)] = &[
    ("sql_error", r#"(?i)(sql syntax|mysql_fetch|ora-\d{5}|pg_query|sqlite3?\.OperationalError|unclosed quotation mark|you have an error in your sql|warning.*mysqli_)"#),
    ("stack_trace", r#"(?i)(traceback \(most recent call last\)|java\.lang\.|org\.apache\.|at [\w.$]+\([\w]+\.java:\d+\)|panic:|goroutine \d+|\.py\", line \d+)"#),
    ("debug_leak", r#"(?i)(debug mode|xdebug|traceback|internal server error|stack trace|verbose error|werkzeug debugger)"#),
    ("php_error", r#"(?i)(warning:|notice:|fatal error:|on line \d+)"#),
    ("path_disclosure", r#"(?i)((/var/www|/home/[a-z0-9_]+/|/usr/(local/)?lib/python|/opt/[a-z0-9_.-]+/[a-z0-9_.-]+\.py|[a-z]:\\[a-z0-9_\\.-]+)"#),
    ("framework_leak", r#"(?i)(django\.core\.exceptions|werkzeug|laravel\.framework|springframework|express error|rack::|jinja2|rails\.actioncontroller)"#),
    ("secret_like", r#"(?i)(api[_-]?key\s*[=:]\s*['"][A-Za-z0-9_\-]{12,}|secret[_-]?key\s*[=:]\s*['"][A-Za-z0-9_\-]{12,}|password\s*[=:]\s*['"][^'"]{4,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"#),
    ("email_leak", r#"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}"#),
    ("internal_host", r#"(?i)\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"#),
    ("sqli_marker", r#"(?i)(union\s+select|or\s+1\s*=\s*1|information_schema|sleep\(\d+\)|benchmark\(\d+)"#),
    ("xss_marker", r#"(?i)(<script|onerror=|javascript:)"#),
    ("cmd_marker", r#"(?i)(;\s*cat\s+/etc/passwd|\|\s*whoami|\$\(id\)|`id`)"#),
    ("template_marker", r#"(?i)(\{\{.*\}\}|<%=.*%>|#{.*})"#),
    ("xxe_marker", r#"(?i)(<!DOCTYPE[^>]*\[|<!ENTITY[^>]*SYSTEM)"#),
];

fn compiled() -> &'static Vec<(&'static str, Regex)> {
    static CELL: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        PATTERNS
            .iter()
            .filter_map(|(name, pat)| Regex::new(pat).ok().map(|re| (*name, re)))
            .collect()
    })
}

/// 텍스트에서 감지된 신호 이름 목록 (중복 제거, 발견 순서 유지).
pub fn detect(text: &str) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    for (name, re) in compiled() {
        if re.is_match(text) && !found.contains(name) {
            found.push(name);
        }
    }
    found
}

/// 신호 → 심각도/설명 (리포트 "보완 포인트" 매핑).
pub fn remediation(name: &str) -> &'static str {
    match name {
        "sql_error" => {
            "SQL 오류 메시지가 그대로 노출됩니다. 쿼리 파라미터 바인딩(프리페어드 스테이트먼트)를 사용하고, \
             오류 메시지를 사용자 응답에서 분리해 내부 로그로만 남기세요."
        }
        "stack_trace" => {
            "스택 트레이스/예외 세부 정보가 응답에 포함됩니다. 운영 환경에서 디버그 모드를 끄고 \
             오류 응답을 일반화(요청 ID + 일반 메시지)하세요."
        }
        "debug_leak" => {
            "디버그 모드/디버거가 노출되어 있습니다. 운영 환경에서 DEBUG=False 및 디버거 비활성화를 \
             보장하고 WAF·리버스프록시에서 /console 경로를 차단하세요."
        }
        "php_error" => {
            "PHP 경고/노티스가 노출됩니다. display_errors=Off, log_errors=On 으로 바꾸고 \
             커스텀 에러 핸들러로 출력을 차단하세요."
        }
        "path_disclosure" => {
            "서버 파일 경로가 노출됩니다. 절대 경로를 노출하지 않는 상대경로 처리, 오류 메시지 정규화, \
             웹 서버 디렉터리 구조를 모듈/프로세스로 분리하세요."
        }
        "framework_leak" => {
            "프레임워크 내부 식별 정보가 노출됩니다. 디버그 미드웨어·미들웨어를 production에서 제거하고 \
             X-Powered-By 등 버전 헤더를 제거하세요."
        }
        "secret_like" => {
            "비밀값으로 보이는 문자열이 응답에 포함됩니다. 하드코딩된 자격증명을 환경변수/시크릿 관리자로 \
             옮기고, 응답 본문에서 시크릿 마스킹을 적용하세요."
        }
        "email_leak" => {
            "사용자 이메일 등 개인정보가 노출됩니다. 응답 최소화(최소 권한 필드만 반환)와 마스킹을 \
             적용하고, 로그에서의 PII 취급 정책을 정비하세요."
        }
        "internal_host" => {
            "내부 네트워크 주소가 노출됩니다. 내부 호스트명을 외부 응답에 노출하지 않고, \
             리버스 프록시에서 내부 주소 참조를 제거하세요."
        }
        "sqli_marker" => {
            "응답에 SQL 인젝션 관련 마커가 포함됩니다. 입력값을 화이트리스트 검증하고, DB 계정 권한을 \
             최소화하며, WAF 규칙을 보조 방어로만 사용하세요."
        }
        "xss_marker" => {
            "응답에 스크립트 관련 마커가 포함됩니다. 사용자 입력 반사 시 컨텍스트별 이스케이프를 \
             적용하고 CSP 를 설정하세요."
        }
        "cmd_marker" => {
            "명령 실행 관련 마커가 포함됩니다. 셸 호출을 금지하고, 인자 배열 기반의 실행 API 만 사용하며 \
             컨테이너를 read-only 로 운영하세요."
        }
        "template_marker" => {
            "템플릿 표현식이 응답에 반영되었습니다. 서버사이드 템플릿 인젝션 가능성을 점검하고, \
             사용자 입력을 템플릿에 직접 결합하지 마세요."
        }
        "xxe_marker" => {
            "XML 외부 엔티티 선언이 포함됩니다. XML 파서에서 외부 엔티티/Doctype 를 비활성화하고 \
             JSON 등 안전한 포맷으로 전환하세요."
        }
        _ => "해당 패턴의 노출을 최소화하고, 재현 절차를 확인한 뒤 방어적으로 수정하세요.",
    }
}

/// 심각도 매핑.
pub fn severity(name: &str) -> &'static str {
    match name {
        "sqli_marker" | "cmd_marker" | "secret_like" | "xxe_marker" => "critical",
        "sql_error" | "debug_leak" | "stack_trace" | "template_marker" => "high",
        "path_disclosure" | "framework_leak" | "internal_host" | "email_leak" | "php_error" => "medium",
        "xss_marker" => "high",
        _ => "low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sql_error() {
        let sigs = detect("You have an error in your SQL syntax near 'x'");
        assert!(sigs.contains(&"sql_error"), "{sigs:?}");
    }

    #[test]
    fn detects_stack_trace() {
        let sigs = detect("Traceback (most recent call last):\n  File \"app.py\", line 42");
        assert!(sigs.contains(&"stack_trace"), "{sigs:?}");
    }

    #[test]
    fn clean_body_has_no_signals() {
        let sigs = detect("<html><body>hello world</body></html>");
        assert!(sigs.is_empty(), "{sigs:?}");
    }
}
