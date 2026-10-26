//! 슬래시 명령어 카탈로그 — `/` 자동완성 메뉴와 실행기가 공유한다.
//!
//! `/` 입력 시 입력창 아래에 후보를 띄우고
//! ↑↓·Tab 으로 고른다. 새 명령 추가는 여기 한 곳 + main.rs 실행 분기.

/// 명령어 정의 — description 은 자동완성 메뉴에 그대로 노출된다.
pub struct Command {
    /// 대표 이름 (`/` 뒤에 치는 단어).
    pub name: &'static str,
    /// 별칭 (자동완성 필터에도 걸린다).
    pub aliases: &'static [&'static str],
    /// 한 줄 설명 (한국어, 메뉴 노출용).
    pub desc: &'static str,
    /// 인자 힌트 (`/say <메시지>` 식 표시, 없으면 "").
    pub usage: &'static str,
    /// Tab 완성 시 뒤에 공백을 붙이는가 (인자를 받는 명령).
    pub takes_arg: bool,
}

/// 전체 카탈로그 — 메뉴 표시 순서 (자주 쓰는 순).
/// 한 기능은 하나의 메뉴로만: 같은 화면으로 가는 옛 이름은 별칭으로만 둔다.
pub const CATALOG: &[Command] = &[
    Command { name: "sweep", aliases: &["scan"], desc: "기본 점검 실행 (P0 스윕)", usage: "", takes_arg: false },
    Command { name: "stop", aliases: &[], desc: "실행 중지 (스윕·agent)", usage: "", takes_arg: false },
    Command { name: "setup", aliases: &["target"], desc: "대상 설정 (URL·포트·쿠키)", usage: "", takes_arg: false },
    Command { name: "providers", aliases: &["llm", "model", "login", "onboard"], desc: "AI 연결 (미설정 시 마법사·설정 후 목록)", usage: "", takes_arg: false },
    Command { name: "danger", aliases: &[], desc: "파괴적 진단 동의 / 철회", usage: "", takes_arg: false },
    Command { name: "findings", aliases: &["find", "report"], desc: "점검 결과 보기 (심각도별·상세)", usage: "", takes_arg: false },
    Command { name: "sessions", aliases: &["sess"], desc: "세션 관리 (전환·생성·이름변경·삭제)", usage: "", takes_arg: false },
    Command { name: "say", aliases: &[], desc: "메모 남기기 (실행 없음)", usage: "<메시지>", takes_arg: true },
    Command { name: "clear", aliases: &[], desc: "로그·대화 지우기", usage: "", takes_arg: false },
    Command { name: "help", aliases: &["h", "?"], desc: "도움말 보기", usage: "", takes_arg: false },
    Command { name: "quit", aliases: &["q", "exit"], desc: "종료", usage: "", takes_arg: false },
];

/// 이름·별칭으로 명령 찾기 (실행기용, 소문자 비교).
pub fn find(word: &str) -> Option<&'static Command> {
    let w = word.to_lowercase();
    CATALOG.iter().find(|c| c.name == w || c.aliases.contains(&w.as_str()))
}

/// 자동완성 후보 — 입력이 `/접두`면 접두 일치 순으로 반환.
/// `/` 단독이면 전체, `/` 로 시작하지 않으면 빈 목록.
pub fn candidates(input: &str) -> Vec<&'static Command> {
    let q = input.strip_prefix('/').unwrap_or("");
    // 명령어 부분까지만 본다 (`/say 안녕` → `say`).
    let q = q.split_whitespace().next().unwrap_or("").to_lowercase();
    if !input.starts_with('/') {
        return Vec::new();
    }
    let mut exact: Vec<&Command> = Vec::new();
    let mut prefix: Vec<&Command> = Vec::new();
    let mut alias_hit: Vec<&Command> = Vec::new();
    let mut description_hit: Vec<&Command> = Vec::new();
    for c in CATALOG {
        if q.is_empty() {
            prefix.push(c);
            continue;
        }
        if c.name == q {
            exact.push(c);
        } else if c.name.starts_with(&q) {
            prefix.push(c);
        } else if c.aliases.iter().any(|a| a.starts_with(&q)) {
            alias_hit.push(c);
        } else if c.name.contains(&q) || c.desc.to_lowercase().contains(&q) {
            description_hit.push(c);
        }
    }
    exact.extend(prefix);
    exact.extend(alias_hit);
    exact.extend(description_hit);
    exact
}

/// 표시용 한 줄 라벨: `/rename <이름>`.
pub fn label(c: &Command) -> String {
    if c.usage.is_empty() {
        format!("/{}", c.name)
    } else {
        format!("/{} {}", c.name, c.usage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_lists_all() {
        let all = candidates("/");
        assert_eq!(all.len(), CATALOG.len());
        assert_eq!(all[0].name, "sweep");
    }

    #[test]
    fn non_slash_has_no_candidates() {
        assert!(candidates("hello").is_empty());
        assert!(candidates("").is_empty());
    }

    #[test]
    fn prefix_and_alias_filter() {
        let names: Vec<&str> = candidates("/s").iter().map(|c| c.name).collect();
        assert!(names.contains(&"sweep"));
        assert!(names.contains(&"setup"));
        assert!(names.contains(&"sessions"));
        assert!(names.contains(&"say"));
        assert!(!names.contains(&"quit"));
        // 별칭으로도 검색.
        let names: Vec<&str> = candidates("/sc").iter().map(|c| c.name).collect();
        assert!(names.contains(&"sweep")); // scan 별칭
        // 정확 일치가 맨 앞.
        assert_eq!(candidates("/say hi")[0].name, "say");
        // 통폐합된 옛 이름은 별칭으로 같은 화면을 연다.
        assert_eq!(candidates("/rep")[0].name, "findings"); // report 별칭
        assert_eq!(find("onboard").unwrap().name, "providers");
        assert_eq!(find("report").unwrap().name, "findings");
        assert!(find("rename").is_none() && find("delete").is_none() && find("new").is_none());
    }

    #[test]
    fn find_resolves_aliases() {
        assert_eq!(find("scan").unwrap().name, "sweep");
        assert_eq!(find("Q").unwrap().name, "quit");
        assert!(find("nope").is_none());
    }

    #[test]
    fn search_matches_korean_descriptions_and_substrings() {
        assert!(candidates("/설정").iter().any(|c| c.name == "setup"));
        assert!(candidates("/세션").iter().any(|c| c.name == "sessions"));
        assert!(candidates("/연결").iter().any(|c| c.name == "providers"));
        assert!(candidates("/repo").iter().any(|c| c.name == "findings")); // report 별칭
        assert!(candidates("/없는검색어").is_empty());
        assert_eq!(candidates("/REPORT")[0].name, "findings");
    }

    #[test]
    fn catalog_has_unique_names() {
        let mut seen = std::collections::HashSet::new();
        for c in CATALOG {
            assert!(seen.insert(c.name), "중복: {}", c.name);
            for a in c.aliases {
                assert!(seen.insert(*a), "별칭 충돌: {a}");
            }
        }
    }
}
