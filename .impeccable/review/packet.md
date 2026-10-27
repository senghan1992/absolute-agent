# Finish review packet — RedCell 심야 노선도 redesign (code-led)

## Original request (ko)
디자인 전면 개편. 지금은 촌스러운 분위기 → 세련되고 고급진 느낌으로. 기능에 절대 이상 없이 디자인만 변경. https://ui.aceternity.com/ 참고, fancy하고 심플하게.

## Confirmed answers
- init: 1순위 사용자=일반인·비전문가 / 핵심 작업=URL 원클릭 진단 / 변경 범위=HTML 구조 소폭 정리 허용(실제로는 CSS 전용 + favicon 1줄)
- direction round (structured-tool fallback; decision page unavailable headless, serve-question exit 2): 심야 노선도 (challenger, verdict wins) / seed c35dce75 / code-led

## Artifact
- redcell-desktop/ui/index.html (changed: favicon link 1 line only)
- redcell-desktop/ui/styles.css (full rewrite, same selectors/dimensions skeleton)
- redcell-desktop/ui/app.js, mock.js — UNTOUCHED (125 id + 13 selector + 18 class-toggle contract preserved; verified)
- Preview: redcell-desktop/preview.sh (port 9731); mock mode active in captures

## Screenshots (reviewer has no browser; these are the eyes)
- REQUIRED: .impeccable/review/desktop.png (1440x900 dark), .impeccable/review/mobile.png (390x844 dark)
- States: /tmp/cap1/hero.png /tmp/cap1/results.png /tmp/cap1/history.png /tmp/cap1/settings.png /tmp/cap1/auth.png /tmp/cap1/danger.png /tmp/cap1/diaginfo.png /tmp/cap1/main-light.png /tmp/cap1/main-dark.png /tmp/cap1/main-mobile.png

## Direction contract (from surface brief .impeccable/surfaces/redcell-desktop-ui-index-html.md)
THESIS: 진단은 여정이다. URL(출발역)에서 판정(종착역)까지를 노선으로 보여주고, 카테고리 기본값(네온 해커 콘솔 + 흩뿌린 상태점)을 거부한다.
OWN-WORLD: 미드나잇 에나멜 ground와 포슬린 헤어라인, 4 라인 잉크(주홍=치명·행동, 코발트=정보, 앰버=주의·진행, 그린=정상; high만 주홍-앰버 환승 오렌지). 타임테이블 카드, 환승 링, 역 도트.
STORY: 이해한다(노선으로 현재 위치), 믿는다(검증 배지+러닝타임), 행동한다(진단 시작 승차 → 리포트 판정 → 막는 방법).
FIRST VIEWPORT: 상단 셸 → 세션 헤더(출발역 주소 + 진단 시작 승차 버튼) → 서명 동작: 진단 진행 노선 + 달리는 열차(활동 바) → 라이브 시간표 → 우측 AI 도우미 패널.
FORM: catalog challenger wayfinding-cartography-signage-midnight-transit-diagram, verdict wins, seed c35dce75.
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

## Detector (hookless web build; run on changed targets)
- Initial: 84 findings → fixed all 31 gray-on-color + 7 low-contrast (faint token retint/brighten) + softened scarlet button glows
- Remaining 46 (see .impeccable/review/detect.json): 33 tiny/undersized-text (incumbent dense Operate sizes, kept to avoid reflow/copy-overflow risk), 10 dark-glow (softened to 20-26% offset shadows; threshold-insensitive), 1 icon-tile-stack (incumbent brand mark in empty state), 1 side-tab (neutral blockquote rule, likely false positive), 1 em-dash advisory (preserved copy)
- Runtime: 0 console errors across 10 scripted state captures incl. real-button modal/tab flows

## Craft bar (code-led: no approved comp; no decision comps generated in fallback round)
/tmp/qb/transit.webp (QUALITY BAR board), /tmp/qb/transit-hero.webp (hero). Rubric: /root/.agents/skills/impeccable/reference/degraded/finish-reviewer.md. Floor: /root/.agents/skills/impeccable/reference/craft-floor.md.

## Known notes for reviewer
- Mobile 390px live-table collapse is PRE-EXISTING: verified byte-identical behavior with HEAD CSS (git-stash A/B test). Real target is desktop Tauri app.
- Topbar gear icon slightly clipped at 390px only (brand-sub hide would fix; held for verdict to respect the 2-round ceiling).
- No shipping rasters were created (CSS-only + inline SVG data-uri favicon); provenance N/A.
