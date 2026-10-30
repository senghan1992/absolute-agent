//! 내장 코퍼스 — 네트워크가 없어도 즉시 쓸 수 있는 최소 단어 목록.
//!
//! 설계 원칙:
//!   - **오프라인 동작이 기본**: 첫 실행에 단어 목록을 내려받느라 멈추지 않는다
//!   - **양이 아니라命中率**: 이 목록은 "자주 실제로 존재하는 경로"만 담는다
//!   - **확장 가능**: 사용자 단어 목록 경로(`~/.redcell/wordlists/`)가 우선한다
//!
//! 대형 코퍼스(seclists 등)는 사용자가 직접 경로를 지정하도록 한다.
//! 라이선스 문제를 피하면서도, 즉席에서 90% 의 web 취약점 표면을 잡을 수 있는
//! 최소 집합을 목표로 한다.

/// 웹에서 자주 등장하는 경로.
pub const COMMON_PATHS: &[&str] = &[
    // 관리/인증
    "admin", "administrator", "admin/login", "admin/panel", "admincp", "adm", "manager", "panel",
    "login", "signin", "sign-in", "logout", "signout", "signup", "sign-up", "register",
    "auth", "auth/login", "oauth", "oauth2", "sso", "saml", "callback", "auth/callback",
    "password", "password-reset", "forgot-password", "reset-password", "recovery",
    "account", "my-account", "profile", "dashboard", "console", "portal", "home",
    // API/백엔드
    "api", "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger", "api/schema",
    "rest", "graphql", "graphiql", "playground", "query", "gql", "rpc", "jsonrpc",
    "swagger", "swagger-ui", "swagger-ui.html", "swagger.json", "swagger.yaml",
    "openapi", "openapi.json", "openapi.yaml", "docs", "doc", "documentation", "redoc",
    "health", "healthz", "healthcheck", "ready", "readyz", "live", "liveness", "readiness",
    "status", "stats", "metrics", "prometheus", "actuator", "actuator/health", "actuator/env",
    "info", "version", "build-info", "env", "config", "configuration", "settings",
    // 정적/자산
    "static", "assets", "public", "dist", "build", "www", "static/js", "static/css",
    "js", "css", "images", "img", "media", "uploads", "upload", "files", "download",
    "fonts", "vendor", "lib", "libs", "assets/js", "assets/css", "bundle.js", "main.js",
    "app.js", "chunk-vendors.js", "runtime.js", "polyfills.js", "manifest.json",
    "favicon.ico", "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
    // 데이터/파일
    "data", "database", "db", "backup", "backups", "bak", "old", "dump", "sql", "db.sql",
    "export", "exports", "import", "imports", "csv", "xls", "log", "logs", "tmp", "temp",
    "private", "internal", "secret", "secrets", "vault", "keys", "cert", "certs",
    // 사용자 데이터
    "user", "users", "account/users", "customer", "customers", "client", "clients",
    "member", "members", "customer/login", "order", "orders", "cart", "checkout", "payment",
    "product", "products", "item", "items", "invoice", "invoices", "subscription",
    // 콘텐츠
    "page", "pages", "post", "posts", "blog", "news", "article", "articles", "post/1",
    "about", "about-us", "contact", "contact-us", "faq", "help", "support", "terms",
    "privacy", "legal", "search", "tag", "tags", "category", "categories", "archive",
    "feed", "rss", "sitemap", "link", "links", "share", "share.php", "redirect",
    // 개발/디버그
    "debug", "trace", "test", "tests", "testing", "dev", "development", "staging", "sandbox",
    "phpinfo.php", "info.php", "test.php", "server-status", "server-info", "_debug",
    "shell", "terminal", "webshell", "c99", "r57", "b374k",
    "source", "src", "backup.zip", "site.zip", "web.zip", "www.zip", "public_html.zip",
    // API 문서/관리
    "swagger-resources", "webjars", "actuator/info", "actuator/mappings",
    "elixir", "elmah.axd", "trace.axd", "elmah", "metrics/prometheus", "actuator/jolokia",
    "manage", "management", "monitoring", "monitor", "grafana", "kibana",
    // 통합/결제
    "webhook", "webhooks", "notify", "notification", "notifications",
    "payments", "billing", "stripe", "paypal",
    "oauth2/callback", "signin/callback", "logout/callback",
    // 모바일/앱
    "api/v2/graphql", "graphql/schema", "mobile", "app", "ios", "android", "sitemap/app",
    "wp-admin", "wp-login.php", "wp-content", "administrator/index.php",
];

/// 민감 파일 — 존재만 확인되면 곧바로 위험 신호가 된다.
pub const SENSITIVE_FILES: &[&str] = &[
    ".env", ".env.local", ".env.production", ".env.development", ".env.backup", ".env.old",
    ".env.example", ".env.dist", ".git/config", ".git/HEAD", ".gitignore", ".gitattributes",
    ".svn/entries", ".hg/requires", ".DS_Store",
    "wp-config.php.bak", "wp-config.php~", "wp-config.php.old", "wp-config.php.save",
    "configuration.php.bak", "config.php.bak", "settings.php.bak",
    "web.config", "Web.config", "appsettings.json", "appsettings.Development.json",
    "application.properties", "application.yml", "application.yaml", "bootstrap.yml",
    "config.yml", "config.yaml", "config.json", "config.inc.php", "config.php",
    "database.yml", "database.sqlite3", "db.sqlite3", ".htpasswd", ".htaccess",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".ssh/id_rsa", ".ssh/authorized_keys",
    "server.key", "server.pem", "private.key", "private.pem", "certificate.pem",
    "credentials.json", "credentials", "secrets.json", "secrets.yaml", "secrets.yml",
    "secret_key_base", "master.key", "service-account.json", "kubeconfig", ".kube/config",
    "composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock",
    "Gemfile.lock", "requirements.txt", "Pipfile.lock", "poetry.lock", "pom.xml",
    "Cargo.toml", "go.sum", "go.mod", "Makefile", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", ".dockerignore", "Vagrantfile", "Jenkinsfile", ".gitlab-ci.yml",
    ".travis.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml",
    ".bash_history", ".mysql_history", ".psql_history", ".ssh/known_hosts",
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql", "db.sql", "site.zip", "www.zip",
    "web.zip", "app.zip", "source.zip", "public_html.zip", "html.zip", "dist.zip",
    "shell.php", "c99.php", "r57.php", "b374k.php", "cmd.php", "webshell.php",
    "error_log", "debug.log", "access.log", "php_errors.log", "laravel.log",
    "sitemap.xml", "crossdomain.xml", "security.txt", "humans.txt",
];

/// 확장자 — 경로 뒤에 붙여 시도할 목록.
pub const EXTENSIONS: &[&str] = &[
    "php", "asp", "aspx", "jsp", "jspx", "do", "action", "cgi", "pl", "py", "rb", "go",
    "html", "htm", "js", "json", "xml", "txt", "bak", "old", "orig", "save", "tmp", "log",
    "sql", "db", "sqlite", "zip", "tar", "gz", "7z", "rar", "tar.gz", "conf", "config",
    "env", "yml", "yaml", "ini", "cfg", "properties", "pem", "key", "crt", "cer",
];

/// 확장자 없이 시도할 "관리자 경로" — 로그인 화면 은닉 탐지용.
pub const HIDDEN_ADMIN_PATHS: &[&str] = &[
    "admin", "administrator", "manager", "cpanel", "webmail", "mail", "roundcube",
    "phpmyadmin", "pma", "adminer", "phppgadmin", "phpmyadmin/index.php", "admin/index.php",
    "wp-admin", "wp-login.php", "administrator/index.php", "typo3", "sitecore",
    "jenkins", "gitlab", "gitea", "grafana", "kibana", "prometheus", "portainer",
    "traefik", "cockpit", "webmin", "plesk", "cpanel", "xfinity", "console",
];

/// 서브도메인 무차별 대입용 라벨.
pub const SUBDOMAIN_LABELS: &[&str] = &[
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure",
    "vpn", "api", "dev", "staging", "test", "uat", "qa", "admin", "portal", "cdn", "static",
    "assets", "img", "docs", "help", "status", "git", "gitlab", "jenkins", "ci", "jira",
    "internal", "intranet", "erp", "crm", "db", "database", "mysql", "postgres", "redis",
    "mongo", "elastic", "kibana", "grafana", "monitor", "metrics", "logs", "backup",
    "old", "new", "demo", "beta", "alpha", "auth", "sso", "oauth", "identity", "login",
    "shop", "store", "pay", "payment", "billing", "crm2", "support", "ticket", "chat",
    "mobile", "app", "api2", "ws", "websocket", "socket", "cdn2", "edge", "lb", "gw",
];

/// 워드리스트 경로 후보 — 사용자 코퍼스를 찾는다.
pub fn wordlist_candidates() -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(custom) = std::env::var("FORGE_WORDLIST") {
        if !custom.trim().is_empty() {
            out.push(std::path::PathBuf::from(custom));
        }
    }
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    if let Some(home) = home {
        for dir in ["wordlists", "wordlist", "seclists", "lists"] {
            let base = home.join(".redcell").join(dir);
            if base.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&base) {
                    for e in entries.flatten() {
                        let p = e.path();
                        if p.is_file() {
                            out.push(p);
                        }
                    }
                }
            }
        }
    }
    out
}

/// 단어 목록 파일을 읽는다 (없으면 내장 목록).
pub fn load_lines(path: Option<&std::path::Path>) -> Vec<String> {
    if let Some(p) = path {
        if let Ok(text) = std::fs::read_to_string(p) {
            let lines: Vec<String> = text
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            if !lines.is_empty() {
                return lines;
            }
        }
    }
    COMMON_PATHS.iter().map(|s| s.to_string()).collect()
}

/// 경로 목록에 확장자 조합을 붙인다 (중복 제거, 순서 유지).
pub fn with_extensions(paths: &[String], exts: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for p in paths {
        for e in exts {
            let candidate = format!("{p}.{e}");
            if seen.insert(candidate.clone()) {
                out.push(candidate);
            }
        }
    }
    out
}

/// 경로 목록에서 `/{path}` 형태를 만든다.
pub fn to_paths(words: &[String]) -> Vec<String> {
    words
        .iter()
        .map(|w| {
            let w = w.trim().trim_start_matches('/');
            if w.is_empty() {
                String::new()
            } else {
                format!("/{w}")
            }
        })
        .filter(|w| !w.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpora_are_non_trivial() {
        assert!(COMMON_PATHS.len() > 100, "{}", COMMON_PATHS.len());
        assert!(SENSITIVE_FILES.len() > 50, "{}", SENSITIVE_FILES.len());
        assert!(SUBDOMAIN_LABELS.len() > 50, "{}", SUBDOMAIN_LABELS.len());
    }

    #[test]
    fn no_duplicate_paths() {
        let mut set = std::collections::BTreeSet::new();
        for p in COMMON_PATHS {
            assert!(set.insert(*p), "중복 경로: {p}");
        }
    }

    #[test]
    fn builds_paths() {
        let words = vec!["admin".to_string(), "/login".to_string(), "  ".to_string()];
        let out = to_paths(&words);
        assert_eq!(out, vec!["/admin".to_string(), "/login".to_string()]);
    }

    #[test]
    fn extends_without_duplicates() {
        let paths = vec!["/a".to_string()];
        let out = with_extensions(&paths, &["php".to_string(), "bak".to_string()]);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&"/a.php".to_string()));
    }
}
