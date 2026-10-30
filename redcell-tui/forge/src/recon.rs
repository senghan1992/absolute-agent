//! 정찰 — 한 번의 응답에서 공격 표면을 추출한다.
//!
//! HTML/JS/JSON 응답에서 링크·폼·API 경로를 뽑고, 기술 스택 지문을 만든다.
//! 추출된 엔드포인트는 스톰 템플릿으로 바로 변환된다.

use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;

/// 발견된 엔드포인트.
#[derive(Debug, Clone, Serialize)]
pub struct Endpoint {
    pub method: String,
    pub url: String,
    /// 쿼리 파라미터 이름.
    pub params: Vec<String>,
    /// 발견 위치 (link / form / js-call / json / common-path).
    pub source: String,
}

/// 기술 스택 지문.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Fingerprint {
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub frameworks: Vec<String>,
    pub title: Option<String>,
    /// 지문 문자열 (기억/매칭 키).
    pub key: String,
}

/// 정찰 결과.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReconResult {
    pub endpoints: Vec<Endpoint>,
    pub fingerprint: Fingerprint,
    pub status: u16,
    pub body_len: usize,
}

/// 자주 확인하는 경로 — 표면이 드러나지 않아도 존재 여부만 확인.
pub const COMMON_PATHS: &[&str] = &[
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.env", "/.git/config",
    "/api", "/api/v1", "/api/docs", "/swagger", "/swagger.json", "/openapi.json",
    "/graphql", "/graphiql", "/health", "/healthz", "/status", "/metrics",
    "/admin", "/login", "/signin", "/register", "/console", "/actuator", "/debug",
];

/// 본문에서 엔드포인트를 추출한다.
pub fn extract(body: &str, base_url: &str, status: u16) -> ReconResult {
    let mut endpoints: Vec<Endpoint> = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();

    let base = url::Url::parse(base_url).ok();
    let resolve = |href: &str| -> Option<String> {
        if href.starts_with('#') || href.is_empty() {
            return None;
        }
        if href.starts_with("http://") || href.starts_with("https://") {
            return Some(href.split('#').next().unwrap_or(href).to_string());
        }
        match &base {
            Some(b) => match b.join(href) {
                Ok(mut joined) => {
                    joined.set_fragment(None);
                    Some(joined.to_string())
                }
                Err(_) => None,
            },
            None => None,
        }
    };

    // 1) 링크/스크립트/폼
    let link_re = Regex::new(r#"(?i)(?:href|src|action)\s*=\s*["']([^"'#>\s]+)["']"#).unwrap();
    for cap in link_re.captures_iter(body) {
        let href = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if href.starts_with("data:") || href.starts_with("javascript:") || href.starts_with("mailto:") {
            continue;
        }
        if let Some(url) = resolve(href) {
            if seen.insert(("GET".into(), url.clone())) {
                endpoints.push(Endpoint { method: "GET".into(), url, params: vec![], source: "link".into() });
            }
        }
    }

    // 2) 폼 — 메서드 + 입력 필드 이름
    let form_re = Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap();
    let action_re = Regex::new(r#"(?i)action\s*=\s*["']([^"']+)["']"#).unwrap();
    let method_re = Regex::new(r#"(?i)method\s*=\s*["']?([a-z]+)["']?"#).unwrap();
    let input_re = Regex::new(r#"(?i)<input\b[^>]*name\s*=\s*["']([^"']+)["'][^>]*>"#).unwrap();
    for form in form_re.captures_iter(body) {
        // 1번 그룹 = 여는 태그 속성, 2번 그룹 = 폼 본문.
        let attrs = form.get(1).map(|m| m.as_str()).unwrap_or("");
        let chunk = form.get(2).map(|m| m.as_str()).unwrap_or("");
        let action = action_re.captures(attrs).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("");
        let method = method_re
            .captures(attrs)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_uppercase())
            .unwrap_or_else(|| "GET".into());
        let Some(url) = resolve(action) else { continue };
        let params: Vec<String> = input_re
            .captures_iter(chunk)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();
        if seen.insert((method.clone(), url.clone())) {
            endpoints.push(Endpoint { method, url, params, source: "form".into() });
        }
    }

    // 3) JS 안의 API 호출
    let api_re = Regex::new(r#"(?i)\b(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["'`]([^"'`]{2,200})["'`]"#).unwrap();
    for cap in api_re.captures_iter(body) {
        let path = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if !path.starts_with('/') && !path.starts_with("http") {
            continue;
        }
        if let Some(url) = resolve(path) {
            if seen.insert(("GET".into(), url.clone())) {
                endpoints.push(Endpoint { method: "GET".into(), url, params: vec![], source: "js-call".into() });
            }
        }
    }

    // 4) JSON 응답의 URL 형태 값
    let json_url_re = Regex::new(r#"(?i)["']((?:https?://|/)[^"'\s]{4,200})["']"#).unwrap();
    for cap in json_url_re.captures_iter(body) {
        let path = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if path.contains(' ') {
            continue;
        }
        if let Some(url) = resolve(path) {
            if seen.insert(("GET".into(), url.clone())) {
                endpoints.push(Endpoint { method: "GET".into(), url, params: vec![], source: "json".into() });
            }
        }
    }

    // 5) 공통 경로 후보 (동일 호스트일 때만)
    if let Some(b) = &base {
        let host = b.host_str().unwrap_or("").to_string();
        for path in COMMON_PATHS {
            let url = format!("{}://{}{}", b.scheme(), host, path);
            if seen.insert(("GET".into(), url.clone())) {
                endpoints.push(Endpoint { method: "GET".into(), url, params: vec![], source: "common-path".into() });
            }
        }
    }

    ReconResult {
        endpoints,
        fingerprint: fingerprint(body, status),
        status,
        body_len: body.len(),
    }
}

/// 기술 스택 지문 추출.
pub fn fingerprint(body: &str, _status: u16) -> Fingerprint {
    let mut fp = Fingerprint::default();
    let server_re = Regex::new(r"(?im)^server:\s*(.+)$").unwrap();
    let powered_re = Regex::new(r"(?im)^x-powered-by:\s*(.+)$").unwrap();
    let title_re = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap();
    if let Some(c) = server_re.captures(body) {
        fp.server = Some(c.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default());
    }
    if let Some(c) = powered_re.captures(body) {
        fp.powered_by = Some(c.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default());
    }
    if let Some(c) = title_re.captures(body) {
        fp.title = Some(c.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default());
    }

    let markers: &[(&str, &str)] = &[
        ("django", r"(?i)(csrfmiddlewaretoken|django\.core|urlpatterns)"),
        ("flask", r"(?i)(werkzeug|jinja2)"),
        ("express", r"(?i)(x-powered-by:\s*express|express\.session)"),
        ("rails", r"(?i)(x-runtime:|rails\.info|/_rails/)"),
        ("spring", r"(?i)(whitelabel error page|x-application-context)"),
        ("laravel", r"(?i)(laravel_session|x-powered-by:\s*laravel)"),
        ("php", r"(?i)(x-powered-by:\s*php|php/)"),
        ("aspnet", r"(?i)(asp\.net|aspnet_sessionid|x-aspnet-version)"),
        ("react", r"(?i)(__react|reactroot)"),
        ("vue", r"(?i)(__vue|vue\.js)"),
        ("nextjs", r"(?i)(__next_data__|/_next/)"),
        ("graphql", r"(?i)(graphql|__typename)"),
    ];
    for (name, pat) in markers {
        if Regex::new(pat).unwrap().is_match(body) {
            fp.frameworks.push((*name).to_string());
        }
    }

    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = &fp.server {
        parts.push(s.clone());
    }
    if let Some(p) = &fp.powered_by {
        parts.push(p.clone());
    }
    parts.extend(fp.frameworks.clone());
    fp.key = parts.join("|").to_lowercase();
    fp
}

/// 엔드포인트 → 스톰 템플릿.
pub fn to_template(ep: &Endpoint) -> crate::storm::Template {
    let mut t = crate::storm::Template::new(&format!("{} {}", ep.method, ep.url), &ep.method, &ep.url);
    t.params = ep.params.iter().map(|p| crate::storm::Param::new(p, "")).collect();
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_links_and_forms() {
        let html = r#"
        <html><head><title>App</title></head>
        <body>
          <a href="/about">about</a>
          <script src="/static/app.js"></script>
          <form action="/login" method="post"><input name="user"><input name="pass"></form>
          <script>fetch('/api/items')</script>
        </body></html>"#;
        let r = extract(html, "http://127.0.0.1:8080/", 200);
        let urls: Vec<&str> = r.endpoints.iter().map(|e| e.url.as_str()).collect();
        assert!(urls.contains(&"http://127.0.0.1:8080/about"), "{urls:?}");
        assert!(urls.contains(&"http://127.0.0.1:8080/static/app.js"), "{urls:?}");
        assert!(urls.contains(&"http://127.0.0.1:8080/api/items"), "{urls:?}");
        let form = r.endpoints.iter().find(|e| e.source == "form").unwrap();
        assert_eq!(form.method, "POST");
        assert_eq!(form.params, vec!["user", "pass"]);
    }

    #[test]
    fn detects_framework() {
        let r = extract("<html>x-powered-by: Express</html>", "http://h/", 200);
        assert!(r.fingerprint.frameworks.contains(&"express".to_string()));
    }
}
