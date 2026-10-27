# Surface brief — RedCell 진단 콘솔

Scope: redcell-desktop/ui 전체 (온보딩 히어로, 상단 셸·세션 탭, 세션 헤더, 진행·라이브·결과 뷰, AI 도우미 패널, 기록·설정·점검대상·위험·모델 모달, 빈 상태).
Visitor mode: Operate — 방문자는 작업을 끝내러 왔다. 진단을 시작하고 진행을 보고 리포트로 판정한다.
Audience/job/action: 보안 초보자(1순위). 밤 집·사무실 PC에서 URL 입력 → 진단 시작 → 리포트 확인 → 막는 방법 파악.
Proof/content: 실측 진단 데이터, 실증/징후/가정 검증 배지, 공격 흐름(환승 노선), 단계별 시간표, 등급 판정.
Constraints: JS DOM 계약 125개 id + querySelector 13종 + classList 토글 18종 전부 유지(인벤토리: redcell-desktop/ui/app.js·mock.js 기준). 모든 사용자 문구·플로우 순서·테마 전환(무플래시 init) 유지. CSS 전용 변경을 원칙으로 하고 HTML은 장식 span 추가까지만 허용. 라이트/다크 두 테마 모두 출하. 오프라인 데스크톱이므로 외부 폰트·에셋 없음 — Operate 모드 규칙에 따라 시스템 스택 + 워크호스 تای포로 목소리를 낸다.
Chosen direction: 심야 노선도 (catalog challenger wayfinding-cartography-signage-midnight-transit-diagram, verdict wins, seed c35dce75). 핀된 다크 프리미엄(aceternity 결)과 충돌 없음 — 세계 자체가 미드나잇 에나멜이다.
Memorable moment: 진단 시작과 함께 노선을 달리는 열차, 역이 하나씩 찍히는 진행, 결과에서 공격 경로가 환승 노선으로 읽히는 순간.
Unresolved: 없음.

## Direction contract

THESIS: 진단은 여정이다. URL(출발역)에서 판정(종착역)까지를 노선으로 보여주고, 카테고리 기본값(네온 해커 콘솔 + 흩뿌린 상태점)을 거부한다. 정보는 시간표처럼, 상태는 라인 잉크처럼.
OWN-WORLD: 미드나잇 에나멜 ground와 포슬린 헤어라인, 4 라인 잉크(주홍=치명·행동, 코발트=정보, 앰버=주의·진행, 그린=정상; high만 주홍-앰버 환승 오렌지). 타임테이블 카드(칩+값+단위+시간), 환승 링, 역 도트. 내용을 지워도 남는 것: 에나멜 광택, 라인 잉크, 역/환승 어휘, tabular 숫자.
STORY: 방문자는 이해한다(진단이 지금 어디쯤인지 노선으로), 믿는다(검증 배지와 러닝타임으로), 행동한다(진단 시작 승차 → 리포트 판정 → 막는 방법 확인).
FIRST VIEWPORT: 상단 셸(브랜드+세션 탭+액션) → 세션 헤더(출발역 주소 입력 + 진단 시작 승차 버튼 + 상태 배지) → 서명 동작: 진단 진행 노선(기본점검·정밀진단·리포트 3역 + 달리는 열차) → 라이브 시간표 테이블 → 우측 AI 도우미(역무원) 패널. 1차 액션은 헤더의 진단 시작 승차 버튼.
FORM: catalog challenger, verdict wins(두 축 모두 assigned를 앞섬), seed c35dce75.
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
