//! 기술 스택 지문 + 보안 헤더 감사 (whatweb · nikto 헤더 판별 대체).
//!
//! 한 번의 응답만으로 "이 서버가 무엇이고, 어떤 보안 설정이 빠졌는지"를 정리한다.
//! 발견은 **문제 있는 것만** 만든다 — 잘 설정된 서버는 조용히 넘어간다.

use regex::Regex;
use serde::Serialize;
use std::collections::BTreeMap;

/// 기술 스택 지문.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Fingerprint {
    pub web_server: Option<String>,
    pub frameworks: Vec<String>,
    pub cdn: Option<String>,
    pub waf: Option<String>,
    pub hosting: Option<String>,
    pub languages: Vec<String>,
    pub is_spa: bool,
    pub is_api: bool,
    pub graphql: bool,
    /// 기억/매칭 키.
    pub key: String,
}

/// 보안 헤더 감사 결과.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderAudit {
    pub name: String,
    pub present: bool,
    pub value: Option<String>,
    pub severity: &'static str,
    pub note: &'static str,
}

/// 쿠키 플래그 감사.
#[derive(Debug, Clone, Serialize)]
pub struct CookieAudit {
    pub name: String,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: Option<String>,
    pub issues: Vec<&'static str>,
}

/// 정찰 결과 묶음.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TechReport {
    pub fingerprint: Fingerprint,
    pub headers: BTreeMap<String, String>,
    pub security_headers: Vec<HeaderAudit>,
    pub cookies: Vec<CookieAudit>,
    pub status: u16,
}

impl TechReport {
    /// 발견(문제) 목록 — 심각도순.
    pub fn findings(&self, target: &str) -> Vec<crate::report::Finding> {
        let mut out = Vec::new();
        for h in &self.security_headers {
            if h.present || h.severity == "info" {
                continue;
            }
            out.push(crate::report::Finding {
                title: format!("보안 헤더 누락: {}", h.name),
                severity: h.severity.to_string(),
                category: "missing_security_header".to_string(),
                target: target.to_string(),
                evidence: format!("요청 응답에 `{}` 헤더가 없습니다. — {}", h.name, h.note),
                reproduction: format!("curl -sSI {target} | grep -i {}", h.name),
                remediation: h.note.to_string(),
            });
        }
        for c in &self.cookies {
            if c.issues.is_empty() {
                continue;
            }
            out.push(crate::report::Finding {
                title: format!("쿠키 보안 플래그 부족: {}", c.name),
                severity: if c.issues.iter().any(|i| i.contains("Secure")) { "high" } else { "medium" }.to_string(),
                category: "cookie_flags".to_string(),
                target: target.to_string(),
                evidence: format!("Set-Cookie: {}\n문제: {}", c.name, c.issues.join(", ")),
                reproduction: format!("curl -sSI {target} | grep -i set-cookie"),
                remediation: "쿠키에 Secure·HttpOnly·SameSite 속성을 모두 지정하고, 필요하면 Domain·Path 를 좁히세요.".to_string(),
            });
        }
        out
    }
}

/// 응답 헤더·본문에서 기술 스택을 추출한다.
pub fn fingerprint(headers: &[(String, String)], body: &str, _status: u16) -> Fingerprint {
    let mut fp = Fingerprint::default();
    let get = |name: &str| -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
    };
    fp.web_server = get("server");
    let powered = get("x-powered-by");
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = &fp.web_server {
        parts.push(s.clone());
    }
    if let Some(p) = &powered {
        parts.push(p.clone());
    }

    // CDN / 리버스 프록시
    for (name, probe) in [
        ("cloudflare", "cf-ray"),
        ("akamai", "x-akamai-"),
        ("fastly", "x-served-by"),
        ("cloudfront", "x-amz-cf-id"),
        ("vercel", "x-vercel-"),
        ("netlify", "x-nf-"),
        ("bunnycdn", "cdn-pull"),
    ] {
        if headers.iter().any(|(k, _)| k.to_ascii_lowercase().contains(probe)) {
            fp.cdn = Some(name.to_string());
            break;
        }
    }
    // WAF
    for (name, probe) in [
        ("cloudflare", "cf-mitigated"),
        ("akamai", "ak_bmsc"),
        ("sucuri", "x-sucuri-id"),
        ("incapsula", "x-iinfo"),
        ("imperva", "x-iinfo"),
    ] {
        if headers.iter().any(|(k, _)| k.to_ascii_lowercase().contains(probe)) {
            fp.waf = Some(name.to_string());
            break;
        }
    }
    // 호스팅
    for (name, probe) in [
        ("aws", "x-amz-"),
        ("gcp", "x-goog-"),
        ("azure", "x-azure-"),
        ("heroku", "x-heroku-"),
        ("digitalocean", "x-do-"),
    ] {
        if headers.iter().any(|(k, _)| k.to_ascii_lowercase().contains(probe)) {
            fp.hosting = Some(name.to_string());
            break;
        }
    }
    // 언어/프레임워크 (본문 지문)
    let markers: &[(&str, &str)] = &[
        ("django", r"(?i)(csrfmiddlewaretoken|django\.core|urlpatterns)"),
        ("flask", r"(?i)(werkzeug|jinja2)"),
        ("express", r"(?i)(x-powered-by:\s*express|express\.session)"),
        ("rails", r"(?i)(x-runtime:|rails\.info|/_rails/)"),
        ("spring", r"(?i)(whitelabel error page|x-application-context)"),
        ("laravel", r"(?i)(laravel_session|x-powered-by:\s*laravel)"),
        ("php", r"(?i)(x-powered-by:\s*php|php/)"),
        ("aspnet", r"(?i)(asp\.net|aspnet_sessionid|x-aspnet-version)"),
        ("nodejs", r"(?i)(x-powered-by:\s*node|node_modules)"),
        ("nextjs", r"(?i)(__NEXT_DATA__|/_next/)"),
        ("nuxt", r#"(?i)(__NUXT__|id="__nuxt")"#),
        ("svelte", r"(?i)(__sveltekit|svelte-[a-z0-9]{6})"),
        ("angular", r"(?i)(ng-version|ng-app=)"),
        ("vue", r"(?i)(__vue__|vue\.js|data-v-[0-9a-f]{8})"),
        ("react", r"(?i)(__react|reactroot|data-reactroot)"),
        ("wordpress", r"(?i)(wp-content|wp-includes)"),
        ("drupal", r"(?i)(drupal\.js|drupalSettings)"),
        ("joomla", r"(?i)(/media/jui/)"),
        ("shopify", r"(?i)(cdn\.shopify\.com)"),
        ("graphql", r"(?i)(__typename|graphql)"),
        ("swagger", r"(?i)(swagger-ui|swagger\.json)"),
    ];
    for (name, pat) in markers {
        let re = Regex::new(pat).unwrap();
        if re.is_match(body) || powered.as_deref().map(|p| re.is_match(p)).unwrap_or(false) {
            if !fp.frameworks.iter().any(|f| f == name) {
                fp.frameworks.push((*name).to_string());
            }
        }
    }
    // 언어 추정
    for (lang, probe) in [("php", "php"), ("java", "java"), ("nodejs", "node"), ("ruby", "ruby"), ("python", "python")] {
        if fp.frameworks.iter().any(|f| f == lang) && !fp.languages.iter().any(|l| l == lang) {
            fp.languages.push(lang.to_string());
        } else if fp.web_server.as_deref().map(|s| s.to_ascii_lowercase().contains(probe)).unwrap_or(false)
            && !fp.languages.iter().any(|l| l == lang)
        {
            fp.languages.push(lang.to_string());
        }
    }
    // SPA / API / GraphQL
    fp.is_spa = Regex::new(r#"(?i)(<div[^>]+id="?(root|app|__next)"?|__NEXT_DATA__|__NUXT__)"#).unwrap().is_match(body);
    fp.is_api = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("json"))
        || body.trim_start().starts_with('{')
        || body.trim_start().starts_with('[');
    fp.graphql = fp.frameworks.iter().any(|f| f == "graphql") || body.contains("/graphql");

    parts.extend(fp.frameworks.clone());
    if let Some(c) = &fp.cdn {
        parts.push(c.clone());
    }
    fp.key = parts.join("|").to_lowercase();
    fp
}

/// 보안 헤더 감사.
pub fn audit_security_headers(headers: &[(String, String)]) -> Vec<HeaderAudit> {
    let has = |name: &str| -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
    };
    let specs: &[(&str, &str, &str)] = &[
        (
            "strict-transport-security",
            "medium",
            "HTTPS 응답에 HSTS 헤더를 추가하세요 (max-age=31536000; includeSubDomains).",
        ),
        (
            "content-security-policy",
            "medium",
            "CSP 헤더를 추가해 XSS 표면을 줄이세요. 최소한 default-src 'self' 를 명시하세요.",
        ),
        (
            "x-frame-options",
            "medium",
            "클릭재킹 방어를 위해 X-Frame-Options: DENY 또는 SAMEORIGIN 을 지정하세요.",
        ),
        (
            "x-content-type-options",
            "low",
            "MIME 스니핑 방어를 위해 X-Content-Type-Options: nosniff 를 지정하세요.",
        ),
        (
            "referrer-policy",
            "low",
            "Referrer-Policy 를 지정해 Referer 로 인한 정보 유출을 줄이세요.",
        ),
        (
            "permissions-policy",
            "info",
            "브라우저 기능(카메라·마이크 등) 제한을 Permissions-Policy 로 명시하세요.",
        ),
        (
            "server",
            "low",
            "Server 헤더로 버전이 노출됩니다. 불필요하면 제거하거나 일반화하세요.",
        ),
        (
            "x-powered-by",
            "low",
            "X-Powered-By 헤더로 사용 기술을 노출합니다. 제거하세요.",
        ),
    ];
    specs
        .iter()
        .map(|(name, severity, note)| {
            let value = has(name);
            HeaderAudit {
                name: (*name).to_string(),
                present: value.is_some(),
                value,
                severity,
                note,
            }
        })
        .collect()
}

/// 쿠키 플래그 감사 — Set-Cookie 헤더들.
pub fn audit_cookies(headers: &[(String, String)]) -> Vec<CookieAudit> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| {
            let first = v.split(';').next().unwrap_or("").trim();
            let name = first.split('=').next().unwrap_or("cookie").trim().to_string();
            let lower = v.to_ascii_lowercase();
            let secure = lower.contains("; secure") || lower.contains(";secure");
            let httponly = lower.contains("httponly");
            let samesite = if lower.contains("samesite=none") {
                Some("None".to_string())
            } else if lower.contains("samesite=lax") {
                Some("Lax".to_string())
            } else if lower.contains("samesite=strict") {
                Some("Strict".to_string())
            } else {
                None
            };
            let mut issues = Vec::new();
            if !secure {
                issues.push("Secure 없음 — 평문 전송 가능");
            }
            if !httponly {
                issues.push("HttpOnly 없음 — XSS 로 JS 로 읽을 수 있음");
            }
            if samesite.is_none() {
                issues.push("SameSite 없음 — CSRF 방어 약함");
            }
            if samesite.as_deref() == Some("None") && !secure {
                issues.push("SameSite=None 인데 Secure 없음 — 위험한 조합");
            }
            CookieAudit { name, secure, httponly, samesite, issues }
        })
        .collect()
}

/// 전체 분석.
pub fn analyze(headers: &[(String, String)], body: &str, status: u16) -> TechReport {
    let mut map = BTreeMap::new();
    for (k, v) in headers {
        map.entry(k.to_ascii_lowercase()).or_insert_with(|| v.clone());
    }
    TechReport {
        fingerprint: fingerprint(headers, body, status),
        headers: map,
        security_headers: audit_security_headers(headers),
        cookies: audit_cookies(headers),
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn detects_cdn_and_framework() {
        let headers = h(&[("Server", "nginx/1.24.0"), ("cf-ray", "abc123"), ("X-Powered-By", "Express")]);
        let fp = fingerprint(&headers, "<html>x-powered-by: express</html>", 200);
        assert_eq!(fp.web_server.as_deref(), Some("nginx/1.24.0"));
        assert_eq!(fp.cdn.as_deref(), Some("cloudflare"));
        assert!(fp.frameworks.contains(&"express".to_string()), "{:?}", fp.frameworks);
        assert!(fp.key.contains("nginx"));
    }

    #[test]
    fn detects_api_response() {
        let headers = h(&[("Content-Type", "application/json")]);
        let fp = fingerprint(&headers, "{\"a\":1}", 200);
        assert!(fp.is_api);
        assert!(!fp.is_spa);
    }

    #[test]
    fn audits_missing_security_headers() {
        let report = analyze(&h(&[("Server", "nginx")]), "hello", 200);
        let missing: Vec<&str> = report
            .security_headers
            .iter()
            .filter(|a| !a.present)
            .map(|a| a.name.as_str())
            .collect();
        assert!(missing.contains(&"content-security-policy"));
        assert!(missing.contains(&"x-content-type-options"));
    }

    #[test]
    fn audits_cookie_flags() {
        let headers = h(&[("Set-Cookie", "sid=abc; Path=/")]);
        let report = analyze(&headers, "x", 200);
        assert_eq!(report.cookies.len(), 1);
        let c = &report.cookies[0];
        assert_eq!(c.name, "sid");
        assert!(!c.secure);
        assert!(!c.httponly);
        assert!(c.issues.len() >= 3);
    }

    #[test]
    fn secure_cookie_has_no_issues() {
        let headers = h(&[("Set-Cookie", "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")]);
        let report = analyze(&headers, "x", 200);
        assert!(report.cookies[0].issues.is_empty(), "{:?}", report.cookies[0].issues);
    }

    #[test]
    fn findings_only_for_problems() {
        let headers = h(&[("Set-Cookie", "sid=abc; Path=/")]);
        let report = analyze(&headers, "x", 200);
        let findings = report.findings("http://t/");
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.severity != "info"));
    }
}
