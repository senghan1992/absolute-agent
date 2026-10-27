---
name: RedCell
description: 인가된 대상만 진단하는 자기발전형 화이트해커 훈련 에이전트의 데스크톱 콘솔
colors:
  enamel-deep: "#0b1230"
  enamel-surface: "#0e1640"
  enamel-raised: "#131c4a"
  enamel-high: "#1a2454"
  enamel-elev: "#18214c"
  line-hairline: "rgba(235, 240, 255, 0.09)"
  line-strong: "rgba(235, 240, 255, 0.17)"
  ink-primary: "#f2f5fc"
  ink-muted: "#a9b3cc"
  ink-faint: "#93a0bb"
  line-scarlet: "#f04452"
  line-ember: "#ff7a45"
  line-cobalt: "#2e6bff"
  line-amber: "#ffc20e"
  line-green: "#2fce7e"
  line-ochre: "#f5a623"
  sev-info: "#8b95ad"
  sev-low: "#4c8dff"
  sev-medium: "#ffc20e"
  sev-high: "#ff8a3d"
  sev-critical: "#f04452"
  scarlet-fg: "#ff7d8a"
  cobalt-fg: "#7fa8ff"
  amber-fg: "#ffd25e"
  green-fg: "#5fe3a1"
  ochre-fg: "#ffbe5c"
  sev-info-fg: "#a7b0c4"
  sev-high-fg: "#ffa76b"
typography:
  headline:
    fontFamily: '"Pretendard", -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans KR", "Apple SD Gothic Neo", Roboto, sans-serif'
    fontSize: "15.5px"
    fontWeight: 700
    letterSpacing: "-0.02em"
  title:
    fontFamily: '"Pretendard", -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans KR", "Apple SD Gothic Neo", Roboto, sans-serif'
    fontSize: "13.5px"
    fontWeight: 700
    letterSpacing: "-0.02em"
  body:
    fontFamily: '"Pretendard", -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans KR", "Apple SD Gothic Neo", Roboto, sans-serif'
    fontSize: "13px"
    fontWeight: 400
  label:
    fontFamily: '"Pretendard", -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans KR", "Apple SD Gothic Neo", Roboto, sans-serif'
    fontSize: "10.5px"
    fontWeight: 700
    letterSpacing: "0.6px"
  mono:
    fontFamily: '"JetBrains Mono", "D2Coding", ui-monospace, "SF Mono", Menlo, Consolas, monospace'
    fontSize: "12.5px"
    fontWeight: 400
rounded:
  sm: "9px"
  md: "12px"
  lg: "16px"
  pill: "999px"
  round: "50%"
spacing:
  sm: "8px"
  md: "12px"
  lg: "16px"
components:
  button-primary:
    backgroundColor: "{colors.line-scarlet}"
    textColor: "#ffffff"
    rounded: "10px"
    padding: "7px 13px"
  button-primary-hover:
    backgroundColor: "{colors.line-scarlet}"
    textColor: "#ffffff"
    rounded: "10px"
    padding: "7px 13px"
  button-run:
    backgroundColor: "{colors.line-green}"
    textColor: "#06130c"
    rounded: "10px"
    padding: "9px 18px"
  button-stop:
    backgroundColor: "{colors.enamel-raised}"
    textColor: "{colors.scarlet-fg}"
    rounded: "10px"
    padding: "9px 18px"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.ink-primary}"
    rounded: "10px"
    padding: "7px 13px"
  button-icon:
    backgroundColor: "transparent"
    textColor: "{colors.ink-muted}"
    rounded: "10px"
    padding: "8px"
    size: "17px"
  tab-active:
    backgroundColor: "{colors.enamel-high}"
    textColor: "{colors.ink-primary}"
    rounded: "{rounded.sm}"
    padding: "6px 10px 6px 12px"
  badge-running:
    backgroundColor: "{colors.line-ochre}"
    textColor: "{colors.ochre-fg}"
    rounded: "20px"
    padding: "4px 11px"
  badge-done:
    backgroundColor: "{colors.line-green}"
    textColor: "{colors.green-fg}"
    rounded: "20px"
    padding: "4px 11px"
  input-target:
    backgroundColor: "{colors.enamel-raised}"
    textColor: "{colors.ink-primary}"
    typography: "{typography.mono}"
    rounded: "11px"
    padding: "5px 11px"
---

# Design System: RedCell

## Overview

**Creative North Star: "심야 노선도 (The Midnight Transit Diagram)"**

진단은 여정이다. URL이라는 출발역에서 판정이라는 종착역까지, 진단의 전 과정을 한 장의 심야 노선도로 그린다. 정보는 시간표처럼 정렬되고, 상태는 노선도의 라인 잉크처럼 읽힌다. 기본 다크 테마는 미드나잇 에나멜 특유의 광택을 품고, 라이트 테마는 같은 노선망의 주간 운행이다.

밀도는 높지만 소란스럽지 않다. 보안 초보자가 밤에 집 PC에서 URL 하나를 넣고 끝까지 해내는 것이 목표이므로, 모든 단계는 쉬운 말과 눈으로 보이는 진행으로 설명된다. 서체·팔레트·밀도·서명 한 동작(노선을 달리는 열차)만이 세계를 이룬다.

**Key Characteristics:**

- 미드나잇 에나멜 ground와 포슬린 헤어라인의 다크 프리미엄
- 4 라인 잉크(주홍·코발트·앰버·그린) + 환승 오렌지의 상태 어휘
- 시간표 카드·환승 링·역 도트의 철도 그래픽 언어
- tabular 숫자 + 모노스페이스 데이터 타이포
- 서명 동작 하나: 열차가 노선을 달리는 진행 바

## Colors

심야 노선도의 라인 잉크 4색이 행동과 상태를, 에나멜 5단 표면이 깊이를 맡는다.

### Primary

- **Line Scarlet (주홍)** (#f04452): 치명 상태와 1차 행동(진단 시작 승차, 저장, 보내기). 화면에서 가장 희귀하고 가장 강한 목소리.
- **Line Ember (노을 주홍)** (#ff7a45): 주홍의 그라디언트 파트너(브랜드 마크, 에나멜 광택 방향).

### Secondary

- **Line Cobalt (코발트)** (#2e6bff): 정보와 포커스. 포커스 링·캐럿·선택 영역·출발역 라벨이 이 색이다.
- **Line Amber (앰버)** (#ffc20e): 주의와 진행. 활성 스텝 도트와 서명 열차 바의 색이다.
- **Line Green (그린)** (#2fce7e): 정상과 실행. 실행 버튼과 완료 배지, 실증 카운트에 쓴다.
- **Line Ochre (황토)** (#f5a623): 실행 중(running) 상태 전용. 완료 전 진행 중 표시와 위험 액센트에 쓴다.

### Tertiary

- **Transfer Orange (환승 오렌지)** (#ff8a3d): high 등급 전용. 주홍-앰버 환승색으로, critical(주홍)과 medium(앰버) 사이를 잇는다.
- **Signal Blue (신호 파랑)** (#4c8dff): low 등급. 글자용으로는 cobalt-fg와 같은 값(#7fa8ff)을 쓴다.
- **Signal Grey (신호 회색)** (#8b95ad): info 등급과 미확인 상태.

### Neutral

- **Midnight Enamel 5단** (#0b1230 → #0e1640 → #131c4a → #1a2454, 상승 표면 #18214c): 배경→패널→올라온 표면→강조 표면. 깊이는 이 톤 계단으로 표현한다.
- **Porcelain Hairline (포슬린 헤어라인)** (rgba(235,240,255,0.09) / 강한 선 0.17): 모든 경계선. 진한 실선이 아니라 도자기 유약 위의 머리카락 선이다.
- **Ink 3단** (#f2f5fc / #a9b3cc / #93a0bb): 본문 / 보조 / 희미한 설명·플레이스홀더.
- **-fg 글자색 세트** (scarlet #ff7d8a, cobalt #7fa8ff, amber #ffd25e, green #5fe3a1, ochre #ffbe5c, info #a7b0c4, high #ffa76b): vivid 라인 잉크를 어두운 표면 위 글자로 쓸 때의 대비 보장 버전. 면(stroke·fill)에는 vivid, 글자에는 -fg를 쓴다.

### Named Rules (optional, powerful)

**The Line Ink Rule.** 상태와 행동은 오직 4 라인 잉크 + 환승 오렌지로 말한다. 화면에 이 팔레트 밖의 채색을 새로 들이지 않는다.
**The Rare Scarlet Rule.** 주홍은 치명과 1차 행동에만 쓴다. 한 화면에서 주홍 면적은 10% 이하로 유지한다. 그 희귀함이 곧 위급함의 신호다.
**The -fg Contrast Rule.** 어두운 표면 위의 컬러 글자는 반드시 -fg 토큰을 쓴다. vivid 값을 글자에 직접 쓰지 않는다.

## Typography

**Display Font:** 해당 없음 — 이 콘솔에는 히어로 디스플레이 타입이 없다. 가장 큰 활자는 이력 대시보드의 모노 숫자(20px)다.
**Body Font:** Pretendard 우선 시스템 스택 (Pretendard, -apple-system, … Noto Sans KR …). 오프라인 데스크톱이므로 외부 폰트 없이 시스템 스택으로 목소리를 낸다.
**Label/Mono Font:** JetBrains Mono 우선 모노 스택 (JetBrains Mono, D2Coding, ui-monospace …). 데이터·시간·숫자·주소 입력 전용.

**Character:** 본문은 조용하고 쉬운 한국어 산세리프, 데이터는 tabular 숫자의 단정한 모노스페이스. 읽는 글과 재는 글의 분업이 명확하다.

### Hierarchy

- **Headline** (700, 15.5px, -0.02em 자간): 세션 이름, 브랜드명. 화면당 1~2곳.
- **Title** (700, 13.5px, -0.02em 자간): 승차 버튼 문구, 리포트 제목, 대시보드 행 제목.
- **Body** (400, 13px): 기본 본문. 루트 폰트 크기이며 모든 UI 텍스트의 기준이다.
- **Label** (700, 10.5px, 0.6px 자간, 대문자): 상태 배지(IDLE/RUNNING…), 테이블 헤드, 캡션. 배지는 pill에 uppercase로 쓴다.
- **Mono Data** (400, 11~12.5px, tabular-nums): 스텝·메트릭·경과 시간·주소/포트 입력·검증 카운트. 숫자는 항상 tabular로 맞춘다.

### Named Rules (optional)

**The Timetable Numbers Rule.** 숫자·시간·카운트는 모노스페이스 + tabular-nums로 쓴다. 시간표의 열이 어긋나면 안 된다.
**The Quiet Korean Rule.** UI 문구는 쉬운 한국어 우선(~해요 말투), 전문 용어 병기는 최소화한다.

## Layout

2열 운영 콘솔 그리드: 좌측 진단 작업 영역(가변) + 우측 AI 도우미 패널(clamp(300px, 30vw, 400px)). 상단 셸(52px 고정) → 세션 헤더(출발역 입력 + 승차 액션) → 진행 리본(3역 스테퍼 + 메트릭) → 서브탭 → 스크롤 본문의 수직 흐름이다.

리포트 뷰는 얇은 요약 한 줄(등급·위험 수·내보내기, 높이 상한 min(38vh, 220px)) + 스크롤되는 본문 카드로, 요약이 본문을 절대 가리지 않는다. 본문 패딩은 좌우 clamp(12px, 1.6vw, 22px), 카드 간격 14px의 리듬이다.

좁은 창 대응: 1180px 이하에서 헤더 패딩 축소·요약 미니 카운트 숨김, 900px 이하에서는 2열이 상하 스택(도우미 패널 min 200px·40vh)으로 전환된다.

## Elevation & Depth

톤 계단 + 얇은 그림자의 하이브리드. 기본 깊이는 에나멜 5단 표면의 톤 차이와 포슬린 헤어라인으로 표현하고, 그림자는 떠 있는 것(팝오버·모달)에만 쓴다. 휴식 상태의 카드는 플랫하다.

### Shadow Vocabulary (if applicable)

- **Resting shadow** (`box-shadow: 0 6px 20px rgba(2, 5, 18, 0.5)`): 살짝 떠 있는 카드·버튼 광택의 받침.
- **Floating shadow** (`box-shadow: 0 24px 64px rgba(2, 5, 18, 0.62)`): 팝오버·모달 카드. 화면에서 가장 높이 뜬다.
- **Button enamel gloss** (`inset 0 1px 0 rgba(255,255,255,0.24~0.28)` + 컬러 글로우): 채운 버튼의 에나멜 광택. inset 하이라이트 없이는 주홍 단추가 아니다.

### Named Rules (optional)

**The Flat At Rest Rule.** 표면은 휴식 시 플랫하다. 그림자는 뜨거나(팝오버·모달) 눌리는(버튼) 상태의 응답으로만 나타난다.

## Shapes

둥글둥글한 에나멜 뱃지 언어. 기본 반경 12px(--r), 작은 요소 9px(--r-sm), 카드·팝오버 14~16px, 상태·카운트·스텝은 완전한 pill(999px), 역 도트·등급 링은 원(50%)이다. 경계는 1px 포슬린 헤어라인이 기본이며, 위험 카드·승차 액션 행에만 컬러 틴트 테두리를 허용한다.

역 도트(6~9px 원), 환승 링(2~2.5px 테두리 원), 등급 링(2px 컬러 테두리 + 모노 등급 문자)의 세 가지 원형 어휘가 노선도 문법을 이룬다. 아이콘은 1.6~1.7px stroke, currentColor, fill 없음의 인라인 세트로 자동 테밍된다.

## Components

### Buttons

- **Shape:** 부드럽게 둥근 직사각형(10px 반경), 기본 패딩 7px 13px.
- **Primary:** 주홍 에나멜(상단 22% 백색 혼합 그라디언트 + inset 광택 + 주홍 글로우), 흰 글자 700. 새 작업·보내기·저장·진단 시작에 쓴다.
- **Hover / Focus:** 밝기 1.06~1.08 상승(채운 버튼은 배경 유지 + filter만). 포커스는 2px 코발트 아웃라인 + 2px 오프셋. active는 0.5px 가라앉는다.
- **Run:** 그린 에나멜 + 어두운 글자(#06130c). 실행 중 유일한 그린 면이다.
- **Stop:** 주홍 틴트 표면 + 주홍 테두리 + scarlet-fg 글자의 아웃라인 버튼. "끊는 인터럽트"의 모양이다.
- **Ghost / Icon:** 투명 배경, hover 시 표면색. 아이콘 버튼은 17px 아이콘 + 8px 패딩.

### Chips (if used)

- **Style:** pill(999px), 틴트 배경(컬러 10~18% 혼합) + 컬러 테두리(30~40%) + -fg 글자.
- **State:** 등급·위험 플래그·검증 카운트에 사용. 선택 상태는 없다(표시 전용).

### Cards / Containers

- **Corner Style:** 12~14px 반경.
- **Background:** 상승 표면(--elev) + 은은한 컬러 워시(예: 리포트 요약 카드의 코발트 10% 그라디언트).
- **Shadow Strategy:** 휴식 시 플랫, Elevation 섹션의 Resting/Floating만 허용.
- **Border:** 1px 포슬린 헤어라인, 또는 컬러 24% 틴트 테두리(서명 카드).
- **Internal Padding:** 8~14px, 카드 헤드 행은 8px 14px.

### Inputs / Fields

- **Style:** 출발역 주소 입력은 표면-2 배경 + 헤어라인 + 11px 반경의 캡슐 행. 주소·포트·쿠키는 모노스페이스. 출발역 라벨 칩(코발트 틴트)이 앞에 붙는다.
- **Focus:** 코발트 55% 테두리 + 코발트 14% 3px 후광. 캐럿도 코발트다.
- **Error / Disabled:** 비활성은 opacity 0.5 + 그림자 제거. 에러 전용 입력 스타일은 없다(배지로 알린다).

### Navigation

세션 탭(역명 필): 투명 배경의 pill 행, hover/활성 시 표면-3. 활성 탭은 헤어라인 테두리 + inset 광택. 상태 도트(실행 중 황토 펄스 / 완료 그린 / 오류 주홍)가 앞에 붙는다. 서브탭은 하단 2px 밑줄형, 활성 시 주홍 밑줄 + 주홍 틴트 카운트.

### Signature Component: Train Line (서명 진행 바)

진행 중 화면 하단에 2px 노선 레일이 깔리고, 앰버 열차(그라디언트 펄스)가 2.6초 주기(ease cubic-bezier(0.16,1,0.3,1))로 무한 주행한다. 스테퍼의 3역(기본점검·정밀진단·리포트)과 함께 진단의 현재 위치를 보여주는, 이 세계의 유일한 상시 모션이다.

## Do's and Don'ts

Concrete visual guardrails grounded in the incumbent implementation.

### Do:

- **Do** 어두운 표면 위 컬러 글자에 -fg 토큰을 쓴다(Do: `color: var(--sev-high-fg)`).
- **Do** 숫자와 시간에 모노스페이스 + `font-variant-numeric: tabular-nums`를 붙인다.
- **Do** 새 상태 표시를 만들 때 기존 라인 잉크(주홍·코발트·앰버·그린·환승 오렌지) 안에서 고른다.
- **Do** 라이트/다크 두 테마에서 같은 토큰명으로 동작하게 만든다(값만 테마 블록에서 바꾼다).
- **Do** 채운 버튼에 inset 상단 광택(`inset 0 1px 0 rgba(255,255,255,0.24)`)을 넣어 에나멜 질감을 유지한다.
- **Do** `prefers-reduced-motion`에서 펄스·주행 모션을 끈다.

### Don't:

- **Don't** vivid 라인 잉크(hex 원색)를 어두운 배경 위 글자에 직접 쓰지 않는다 — -fg가 있다.
- **Don't** 주홍을 장식·정보·정상 상태에 쓰지 않는다. 주홍은 치명과 1차 행동 전용이다.
- **Don't** 휴식 상태 카드에 그림자를 얹지 않는다. 플랫이 기본이다.
- **Don't** 외부 폰트·외부 에셋을 불러오지 않는다. 오프라인 데스크톱이며 시스템 스택이 목소리다.
- **Don't** 새 상시 애니메이션을 추가하지 않는다. 상시 모션은 열차 바와 상태 펄스가 전부다.
- **Don't** id·클래스·상태 토글·레이아웃 골격을 바꾸지 않는다. 피부만 교체하는 것이 이 세계의 계약이다.
