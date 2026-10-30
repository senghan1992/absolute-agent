//! 인가 파일용 YAML 서브셋 파서.
//!
//! 전체 YAML 스펙을 구현하지 않는다. redcell `authorization.yaml` 이 쓰는 형태만
//! 다룬다: 중첩 맵, 시퀀스(맵 항목 포함), 인라인 리스트 `[80, 443]`, 스칼라.
//! 스칼라: `"..."` / `'...'` / true / false / null / 숫자 / 문자열.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Yaml {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Seq(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Yaml::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// `a.b.c` 경로 조회.
    pub fn path(&self, dotted: &str) -> Option<&Yaml> {
        let mut cur = self;
        for part in dotted.split('.') {
            cur = cur.get(part)?;
        }
        Some(cur)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Yaml::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// 문자열로 변환 (숫자·불리언 포함).
    pub fn as_text(&self) -> Option<String> {
        match self {
            Yaml::Str(s) => Some(s.clone()),
            Yaml::Num(n) => Some(n.to_string()),
            Yaml::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Yaml::Bool(b) => Some(*b),
            Yaml::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => Some(true),
                "false" | "no" | "off" | "0" => Some(false),
                _ => None,
            },
            Yaml::Num(n) => Some(*n != 0.0),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Yaml::Num(n) => Some(*n),
            Yaml::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn as_seq(&self) -> Option<&[Yaml]> {
        match self {
            Yaml::Seq(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    /// 맵 항목들을 key→문자열 로 내보낸다 (headers 같은 용도).
    pub fn as_str_map(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        if let Yaml::Map(entries) = self {
            for (k, v) in entries {
                if let Some(s) = v.as_str() {
                    out.insert(k.clone(), s.to_string());
                }
            }
        }
        out
    }
}

/// 파싱 오류 — 줄 번호를 포함해 인가 파일 오류를 즉시 알아낼 수 있게 한다.
#[derive(Debug)]
pub struct YamlError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for YamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "YAML {}번째 줄: {}", self.line, self.message)
    }
}

impl std::error::Error for YamlError {}

#[derive(Debug, Clone)]
struct Line {
    indent: usize,
    text: String,
    number: usize,
}

/// YAML 텍스트 → 트리.
pub fn parse(text: &str) -> Result<Yaml, YamlError> {
    let mut lines: Vec<Line> = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let number = idx + 1;
        let stripped = strip_comment(raw);
        if stripped.trim().is_empty() {
            continue;
        }
        let indent = stripped.len() - stripped.trim_start().len();
        lines.push(Line { indent, text: stripped.trim_end().to_string(), number });
    }
    if lines.is_empty() {
        return Ok(Yaml::Null);
    }
    let mut pos = 0usize;
    let node = parse_node(&lines, &mut pos, lines[0].indent)?;
    Ok(node)
}

/// `#` 주석 제거 — 따옴표 안의 `#` 은 보존.
fn strip_comment(line: &str) -> String {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    let mut prev_space = true;
    for ch in line.chars() {
        match quote {
            Some(q) => {
                out.push(ch);
                if ch == q {
                    quote = None;
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                    out.push(ch);
                    prev_space = false;
                    continue;
                }
                if ch == '#' && prev_space {
                    break;
                }
                prev_space = ch.is_whitespace();
                out.push(ch);
            }
        }
    }
    out
}

fn parse_node(lines: &[Line], pos: &mut usize, indent: usize) -> Result<Yaml, YamlError> {
    if *pos >= lines.len() {
        return Ok(Yaml::Null);
    }
    let cur = &lines[*pos];
    if cur.indent != indent {
        return Ok(Yaml::Null);
    }
    if cur.text.trim_start().starts_with("- ") || cur.text.trim() == "-" {
        parse_seq(lines, pos, indent)
    } else {
        parse_map(lines, pos, indent)
    }
}

fn parse_map(lines: &[Line], pos: &mut usize, indent: usize) -> Result<Yaml, YamlError> {
    let mut entries: Vec<(String, Yaml)> = Vec::new();
    while *pos < lines.len() {
        let line = lines[*pos].clone();
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            return Err(YamlError { line: line.number, message: "예상치 못한 들여쓰기입니다.".into() });
        }
        let body = line.text.trim_start();
        if body.starts_with("- ") || body == "-" {
            break;
        }
        let (key, rest) = split_key(body).ok_or_else(|| YamlError {
            line: line.number,
            message: format!("'key: value' 형태가 아닙니다: {body}"),
        })?;
        *pos += 1;
        let value = if rest.trim().is_empty() {
            // 중첩 블록 — 다음 줄이 더 깊어야 한다.
            if *pos < lines.len() && lines[*pos].indent > indent {
                let child_indent = lines[*pos].indent;
                parse_node(lines, pos, child_indent)?
            } else {
                Yaml::Null
            }
        } else {
            parse_scalar(rest.trim())?
        };
        entries.push((key, value));
    }
    Ok(Yaml::Map(entries))
}

fn parse_seq(lines: &[Line], pos: &mut usize, indent: usize) -> Result<Yaml, YamlError> {
    let mut items: Vec<Yaml> = Vec::new();
    while *pos < lines.len() {
        let line = lines[*pos].clone();
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            return Err(YamlError { line: line.number, message: "시퀀스 들여쓰기가 일관되지 않습니다.".into() });
        }
        let body = line.text.trim_start();
        if !(body.starts_with("- ") || body == "-") {
            break;
        }
        let rest = body.strip_prefix('-').unwrap_or("").trim().to_string();
        *pos += 1;
        if rest.is_empty() {
            let value = if *pos < lines.len() && lines[*pos].indent > indent {
                let child_indent = lines[*pos].indent;
                parse_node(lines, pos, child_indent)?
            } else {
                Yaml::Null
            };
            items.push(value);
            continue;
        }
        // `- key: value` → 맵 항목 첫 키. 뒤따르는 더 깊은 줄을 이어 붙인다.
        if let Some((key, vrest)) = split_key(&rest) {
            let mut entries: Vec<(String, Yaml)> = Vec::new();
            let value = if vrest.trim().is_empty() {
                if *pos < lines.len() && lines[*pos].indent > indent {
                    let child_indent = lines[*pos].indent;
                    parse_node(lines, pos, child_indent)?
                } else {
                    Yaml::Null
                }
            } else {
                parse_scalar(vrest.trim())?
            };
            entries.push((key, value));
            // 뒤따르는 continuation 라인(들)은 원래 indent+2 깊이.
            while *pos < lines.len() && lines[*pos].indent > indent {
                let cont_indent = lines[*pos].indent;
                let sub = parse_map(lines, pos, cont_indent)?;
                if let Yaml::Map(mut more) = sub {
                    entries.append(&mut more);
                }
            }
            items.push(Yaml::Map(entries));
        } else {
            items.push(parse_scalar(&rest)?);
        }
    }
    Ok(Yaml::Seq(items))
}

/// `key: value` 분리 — 콜론 뒤에 공백이 있거나 문자열 끝이어야 한다.
fn split_key(body: &str) -> Option<(String, &str)> {
    let mut quote: Option<char> = None;
    let bytes = body.as_bytes();
    for (i, ch) in body.char_indices() {
        match quote {
            Some(q) => {
                if ch == q {
                    quote = None;
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                    continue;
                }
                if ch == ':' {
                    let next = bytes.get(i + 1).copied();
                    let is_end = next.is_none();
                    if is_end || next == Some(b' ') || next == Some(b'\t') {
                        let key = body[..i].trim().trim_matches('"').trim_matches('\'').to_string();
                        return Some((key, &body[i + 1..]));
                    }
                }
            }
        }
    }
    None
}

fn parse_scalar(raw: &str) -> Result<Yaml, YamlError> {
    let t = raw.trim();
    if t.is_empty() {
        return Ok(Yaml::Null);
    }
    if t.starts_with('[') && t.ends_with(']') {
        let inner = &t[1..t.len() - 1];
        let mut items = Vec::new();
        for part in split_flow(inner) {
            if part.trim().is_empty() {
                continue;
            }
            items.push(parse_scalar(&part)?);
        }
        return Ok(Yaml::Seq(items));
    }
    if t.starts_with('{') && t.ends_with('}') {
        let inner = &t[1..t.len() - 1];
        let mut entries = Vec::new();
        for part in split_flow(inner) {
            if part.trim().is_empty() {
                continue;
            }
            if let Some((k, v)) = split_key(part.trim()) {
                entries.push((k, parse_scalar(v.trim())?));
            }
        }
        return Ok(Yaml::Map(entries));
    }
    if (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
        || (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2)
    {
        let inner = &t[1..t.len() - 1];
        return Ok(Yaml::Str(inner.replace("\\\"", "\"").replace("\\\\", "\\")));
    }
    match t.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" => return Ok(Yaml::Bool(true)),
        "false" | "no" | "off" => return Ok(Yaml::Bool(false)),
        "null" | "~" => return Ok(Yaml::Null),
        _ => {}
    }
    if let Ok(n) = t.parse::<f64>() {
        return Ok(Yaml::Num(n));
    }
    Ok(Yaml::Str(t.to_string()))
}

/// 인라인 리스트 원소 분리 — 괄호 깊이를 고려한다.
fn split_flow(inner: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut cur = String::new();
    for ch in inner.chars() {
        match quote {
            Some(q) => {
                cur.push(ch);
                if ch == q {
                    quote = None;
                }
            }
            None => match ch {
                '"' | '\'' => {
                    quote = Some(ch);
                    cur.push(ch);
                }
                '[' | '{' => {
                    depth += 1;
                    cur.push(ch);
                }
                ']' | '}' => {
                    depth = depth.saturating_sub(1);
                    cur.push(ch);
                }
                ',' if depth == 0 => {
                    parts.push(std::mem::take(&mut cur));
                }
                _ => cur.push(ch),
            },
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_authorization_shape() {
        let text = r#"
engagement:
  name: "local-lab"
  authorized_until: "2026-12-31"
scope:
  allow:
    - host: "127.0.0.1"
    - host: "localhost"
    - cidr: "10.13.37.0/24"
    - domain: "*.vulnlab.local"
  deny:
    - host: "10.13.37.1"
ports:
  allow_tcp: [80, 443, 8080]
limits:
  max_requests_per_second: 20
  disallow_destructive: true
credentials:
  headers:
    x-api-key: "test-key"
"#;
        let y = parse(text).unwrap();
        assert_eq!(y.path("engagement.name").unwrap().as_str(), Some("local-lab"));
        assert_eq!(y.path("scope.allow").unwrap().as_seq().unwrap().len(), 4);
        let allow = y.path("scope.allow").unwrap().as_seq().unwrap();
        assert_eq!(allow[0].get("host").unwrap().as_str(), Some("127.0.0.1"));
        assert_eq!(allow[2].get("cidr").unwrap().as_str(), Some("10.13.37.0/24"));
        assert_eq!(allow[3].get("domain").unwrap().as_str(), Some("*.vulnlab.local"));
        assert_eq!(y.path("ports.allow_tcp").unwrap().as_seq().unwrap().len(), 3);
        assert_eq!(y.path("limits.max_requests_per_second").unwrap().as_f64(), Some(20.0));
        assert_eq!(y.path("limits.disallow_destructive").unwrap().as_bool(), Some(true));
        assert_eq!(y.path("credentials.headers.x-api-key").unwrap().as_str(), Some("test-key"));
    }

    #[test]
    fn comments_and_quotes() {
        let y = parse("a: 1 # trailing\nb: \"has # hash\"\n").unwrap();
        assert_eq!(y.get("a").unwrap().as_f64(), Some(1.0));
        assert_eq!(y.get("b").unwrap().as_str(), Some("has # hash"));
    }

    #[test]
    fn rejects_broken_line() {
        assert!(parse("just text\n").is_err());
    }
}
