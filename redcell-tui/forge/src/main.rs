//! REDFORGE — 터미널 기반 자율 보안점검 에이전트.
//!
//! 구성:
//!   scope    — 인가 게이트 (fail-closed). 모든 트래픽의 단일 관문
//!   kernel   — 파이썬 커널 브리지 (prime-agent 스타일 영속 인터프리터)
//!   storm    — 고속 병렬 퍼징 + 응답 분류 + 이상 탐지
//!   agent    — LLM 자율 루프 (커널/스톰 도구 사용)
//!   tui      — 터미널 UI (대시보드·커널·파인딩·리포트)

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let args = forge::cli::parse_args();
    let handled = forge::cli::run(args.clone()).await?;
    if handled {
        return Ok(());
    }
    forge::tui::run(forge::tui::TuiConfig {
        scope_path: args.get("scope").map(std::path::PathBuf::from),
        target: args.get("target").map(str::to_string),
    })
    .await
}
