//! TUI 디자인 시스템 — 색·간격·타이포그래피의 단일 기준.
//!
//! 화면마다 색을 흩어 쓰면 UI 가 고提供服务 불가능해진다.
//! 여기서 정의한 역할(role)만 사용한다:
//!
//! ```text
//!   bg        화면 배경        panel     패널 배경        border    기본 테두리
//!   fg        기본 본문        muted     보조 텍스트      accent    브랜드/선택
//!   ok        정상/성공        warn      주의            crit      위험/치명
//!   info      정보             dim       매우 약한 강조
//! ```
//!
//! 색은 256색 인덱스를 사용한다 — 16색 터미널에서도 가까운 색으로 degrade 된다.

use ratatui::style::{Color, Modifier, Style};

/// 브랜드 액센트 (REDFORGE 레드).
pub const ACCENT: Color = Color::Indexed(203);
/// 정상/성공 — 초록.
pub const OK: Color = Color::Indexed(114);
/// 주의 — 앰버.
pub const WARN: Color = Color::Indexed(179);
/// 위험 — 빨강.
pub const CRIT: Color = Color::Indexed(210);
/// 정보 — 파랑.
pub const INFO: Color = Color::Indexed(110);
/// 보조 텍스트.
pub const MUTED: Color = Color::Indexed(245);
/// 매우 약한 강조(타임스탬프·구분자).
pub const DIM: Color = Color::Indexed(240);
/// 기본 테두리.
pub const BORDER: Color = Color::Indexed(238);
/// 활성 테두리.
pub const BORDER_FOCUS: Color = Color::Indexed(244);
/// 패널 배경.
pub const PANEL: Color = Color::Indexed(235);
/// 본문 색.
pub const FG: Color = Color::Indexed(252);
/// 선택 배경.
pub const SELECT_BG: Color = Color::Indexed(237);
/// 선택前景.
pub const SELECT_FG: Color = Color::Indexed(255);

/// 본문 스타일.
pub fn fg() -> Style {
    Style::default().fg(FG)
}

/// 보조 텍스트.
pub fn muted() -> Style {
    Style::default().fg(MUTED)
}

/// 아주 약한 강조.
pub fn dim() -> Style {
    Style::default().fg(DIM)
}

/// 브랜드 강조.
pub fn accent() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

/// 성공.
pub fn ok() -> Style {
    Style::default().fg(OK)
}

/// 주의.
pub fn warn() -> Style {
    Style::default().fg(WARN)
}

/// 위험.
pub fn crit() -> Style {
    Style::default().fg(CRIT).add_modifier(Modifier::BOLD)
}

/// 정보.
pub fn info() -> Style {
    Style::default().fg(INFO)
}

/// 패널 테두리.
pub fn border() -> Style {
    Style::default().fg(BORDER)
}

/// 활성 패널 테두리.
pub fn border_focus() -> Style {
    Style::default().fg(BORDER_FOCUS)
}

/// 심각도 → 스타일.
pub fn severity(sev: &str) -> Style {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => Style::default().fg(CRIT).add_modifier(Modifier::BOLD),
        "high" => Style::default().fg(Color::Indexed(215)).add_modifier(Modifier::BOLD),
        "medium" => Style::default().fg(WARN),
        "low" => Style::default().fg(MUTED),
        "info" => Style::default().fg(INFO),
        _ => fg(),
    }
}

/// 로그 종류(kind) → 스타일.
pub fn log_kind(kind: &str) -> Style {
    match kind {
        "you" => Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        "llm" => Style::default().fg(Color::Indexed(158)),
        "tool" => Style::default().fg(Color::Indexed(140)),
        "err" => Style::default().fg(CRIT),
        "help" => muted(),
        "note" => Style::default().fg(Color::Indexed(180)),
        "scope" => info(),
        "report" => Style::default().fg(Color::Indexed(150)),
        "agent" => Style::default().fg(Color::Indexed(183)),
        "kernel" => Style::default().fg(Color::Indexed(150)),
        "ok" => ok(),
        _ => fg(),
    }
}

/// 로그 종류 배지 문자.
pub fn log_glyph(kind: &str) -> &'static str {
    match kind {
        "you" => "›",
        "llm" => "◆",
        "tool" => "⚙",
        "err" => "✖",
        "help" => "?",
        "note" => "▸",
        "scope" => "⛨",
        "report" => "▤",
        "agent" => "◈",
        "kernel" => "⧉",
        "ok" => "✔",
        _ => "·",
    }
}

/// 패널 제목 스타일.
pub fn title() -> Style {
    Style::default().fg(BORDER_FOCUS).add_modifier(Modifier::BOLD)
}

/// 상태줄의 실행 중 인디케이터.
pub fn spinner(frame: u64) -> &'static str {
    const FRAMES: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
    FRAMES[(frame as usize) % FRAMES.len()]
}

/// 진행률 바 — 블록 문자로 그린다 (게이지보다 세밀).
pub fn progress_bar(ratio: f64, width: usize) -> String {
    let filled = ((ratio.clamp(0.0, 1.0)) * width as f64).round() as usize;
    let mut s = String::with_capacity(width * 3);
    for i in 0..width {
        if i < filled {
            s.push('█');
        } else if i == filled {
            s.push('▌');
        } else {
            s.push('·');
        }
    }
    s
}

/// 텍스트를 주어진 폭에 맞춰 자른다 (한글 폭 무시 — 대략적 경계).
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_bar_fills_ratio() {
        let bar = progress_bar(0.5, 10);
        assert_eq!(bar.chars().count(), 10);
        assert!(bar.starts_with('█'));
    }

    #[test]
    fn truncate_adds_ellipsis() {
        let out = truncate("abcdefghij", 5);
        assert_eq!(out.chars().count(), 5);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn severity_styles_differ() {
        assert_ne!(severity("critical"), severity("low"));
    }
}
