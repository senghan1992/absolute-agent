//! 입력창의 이력·붙여넣기·표시 폭 처리. 터미널/네트워크 없이 검증한다.

use unicode_width::UnicodeWidthChar;

#[derive(Default)]
pub struct History {
    entries: Vec<String>,
    selected: Option<usize>,
    draft: String,
}

impl History {
    pub fn remember(&mut self, text: &str) {
        if !text.trim().is_empty() && self.entries.last().map(String::as_str) != Some(text) {
            self.entries.push(text.to_string());
            if self.entries.len() > 200 {
                self.entries.remove(0);
            }
        }
        self.reset();
    }

    pub fn previous(&mut self, input: &str) -> Option<String> {
        if self.entries.is_empty() {
            return None;
        }
        let i = match self.selected {
            None => {
                self.draft = input.to_string();
                self.entries.len() - 1
            }
            Some(i) => i.saturating_sub(1),
        };
        self.selected = Some(i);
        Some(self.entries[i].clone())
    }

    pub fn next(&mut self) -> Option<String> {
        let i = self.selected?;
        if i + 1 < self.entries.len() {
            self.selected = Some(i + 1);
            Some(self.entries[i + 1].clone())
        } else {
            self.selected = None;
            Some(std::mem::take(&mut self.draft))
        }
    }

    pub fn browsing(&self) -> bool {
        self.selected.is_some()
    }

    pub fn reset(&mut self) {
        self.selected = None;
        self.draft.clear();
    }
}

/// CRLF를 한 줄바꿈으로 바꾸고 터미널 제어문자를 제거한다.
/// 폼 필드는 한 줄만 허용하며, 붙여넣기는 어떤 경우에도 실행하지 않는다.
pub fn pasted_text(raw: &str, multiline: bool) -> String {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    normalized.chars().filter_map(|c| match c {
        '\n' if multiline => Some('\n'),
        '\n' | '\t' => Some(' '),
        c if c.is_control() => None,
        c => Some(c),
    }).collect()
}

pub fn byte_index(text: &str, cursor: usize) -> usize {
    text.char_indices().nth(cursor).map(|(i, _)| i).unwrap_or(text.len())
}

pub struct InputLayout {
    pub lines: Vec<String>,
    pub cursor_row: usize,
    pub cursor_col: usize,
}

/// CJK/결합문자의 실제 셀 폭으로 줄을 나누고 커서 좌표를 함께 계산한다.
pub fn layout(text: &str, cursor: usize, width: usize) -> InputLayout {
    let width = width.max(2);
    let mut result = InputLayout { lines: vec![String::new()], cursor_row: 0, cursor_col: 0 };
    let mut col = 0;
    let cursor = cursor.min(text.chars().count());
    for (i, c) in text.chars().enumerate() {
        let cw = c.width().unwrap_or(0);
        if c != '\n' && col + cw > width {
            result.lines.push(String::new());
            col = 0;
        }
        if i == cursor {
            result.cursor_row = result.lines.len() - 1;
            result.cursor_col = col;
        }
        if c == '\n' {
            result.lines.push(String::new());
            col = 0;
        } else {
            result.lines.last_mut().unwrap().push(c);
            col += cw;
        }
    }
    if cursor == text.chars().count() {
        if col >= width {
            result.lines.push(String::new());
            col = 0;
        }
        result.cursor_row = result.lines.len() - 1;
        result.cursor_col = col;
    }
    result
}

/// 논리 줄 사이 이동. 첫/마지막 줄에서만 이력 탐색으로 넘긴다.
pub fn vertical_cursor(text: &str, cursor: usize, up: bool) -> Option<usize> {
    let chars: Vec<char> = text.chars().collect();
    let cursor = cursor.min(chars.len());
    let start = chars[..cursor].iter().rposition(|c| *c == '\n').map(|i| i + 1).unwrap_or(0);
    let column = cursor - start;
    if up {
        if start == 0 {
            return None;
        }
        let end = start - 1;
        let prev = chars[..end].iter().rposition(|c| *c == '\n').map(|i| i + 1).unwrap_or(0);
        Some(prev + column.min(end - prev))
    } else {
        let end = cursor + chars[cursor..].iter().position(|c| *c == '\n')?;
        let next = end + 1;
        let len = chars[next..].iter().position(|c| *c == '\n').unwrap_or(chars.len() - next);
        Some(next + column.min(len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;

    #[test]
    fn history_restores_draft_and_deduplicates() {
        let mut h = History::default();
        assert_eq!(h.previous("초안"), None);
        h.remember("/help");
        h.remember("/help");
        h.remember("/say 메모");
        assert_eq!(h.previous("초안"), Some("/say 메모".into()));
        assert_eq!(h.previous("ignored"), Some("/help".into()));
        assert_eq!(h.previous("ignored"), Some("/help".into()));
        assert_eq!(h.next(), Some("/say 메모".into()));
        assert_eq!(h.next(), Some("초안".into()));
        assert_eq!(h.next(), None);
    }

    #[test]
    fn paste_normalizes_without_submitting() {
        assert_eq!(pasted_text("한글\r\n두 줄\r끝\t!\x1b\x00", true), "한글\n두 줄\n끝 !");
        assert_eq!(pasted_text("key\r\nvalue", false), "key value");
    }

    #[test]
    fn layout_wraps_cjk_and_tracks_middle_cursor() {
        let result = layout("가나다라마", 3, 5);
        assert_eq!(result.lines, ["가나", "다라", "마"]);
        assert_eq!((result.cursor_row, result.cursor_col), (1, 2));
        assert!(result.lines.iter().all(|s| s.width() <= 5));
        let result = layout("abcd", 4, 4);
        assert_eq!(result.lines, ["abcd", ""]);
        assert_eq!((result.cursor_row, result.cursor_col), (1, 0));
        let result = layout("a\ne\u{301}", 4, 10);
        assert_eq!((result.cursor_row, result.cursor_col), (1, 1));
    }

    #[test]
    fn multiline_cursor_does_not_jump_into_history() {
        assert_eq!(vertical_cursor("abc\n한글\nx", 6, true), Some(2));
        assert_eq!(vertical_cursor("abc\n한글\nx", 2, false), Some(6));
        assert_eq!(vertical_cursor("abc\n한글\nx", 1, true), None);
        assert_eq!(vertical_cursor("abc\n한글\nx", 8, false), None);
        assert_eq!(byte_index("a한글", 2), 4);
    }
}
