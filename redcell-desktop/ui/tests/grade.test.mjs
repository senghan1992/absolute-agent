// 리포트 위험도 등급 산정 단위 테스트 (node --test, 의존성 없음).
//
//   node --test ui/tests/grade.test.mjs
//
// 왜 이 테스트가 필요한가: 이전 등급 산정은 "심각도 가중치 × 증거 가중치"의
// *평균*이었다. 그 결과 "직접 확인된 치명 1건 + 추측 낮은 등급 5건"이
// '안전(A)' 으로 표시될 수 있었다 — 시니어 리포트에서 가장 위험한 실패 모드.
// 여기서는 그 회귀가 재발하지 않는지 고정한다.

import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";

// app.js 는 Tauri 전역(window.__TAURI__)을 전제로 하는 클래식 스크립트다.
// 등급 산정 함수(reportStats/gradeOf)만 순수 함수이므로 최소 shim 으로 로드한다.
const src = readFileSync(new URL("../app.js", import.meta.url), "utf8");
const ctx = { window: { addEventListener() {}, __TAURI__: null }, console };
vm.createContext(ctx);
vm.runInContext(src, ctx, { filename: "app.js" });

const { reportStats, gradeOf, reportCover, statsDocs } = ctx;
assert.equal(typeof reportStats, "function", "reportStats 로드 실패");
assert.equal(typeof gradeOf, "function", "gradeOf 로드 실패");

// 루트 하나를 "### 루트 N. 제목 [등급]" + 검증 라벨로 만든다.
const root = (title, sev, ver = "가정", extra = "") =>
  `### 루트 1. ${title} [${sev}]\n위험도: ${sev}\n검증: [${ver}] 근거\n${extra}`;

const doc = (...texts) => [{ text: texts.join("\n\n") }];

test("직접 확인된 치명은 다른 발견에 묻혀도 '안전'이 아니다", () => {
  const st = reportStats(doc([
    root("관리자 탈취", "치명", "실증"),
    root("헤더 누락", "낮음", "가정"),
    root("노출 가능성", "낮음", "가정"),
    root("설정 권고", "낮음", "가정"),
    root("정보 노출", "낮음", "가정"),
    root("문서화", "낮음", "가정"),
  ].join("\n\n")));
  assert.equal(st.grade.letter, "F", "확인된 치명은 F 이어야 한다");
  assert.equal(st.sev["치명"], 1);
  assert.equal(st.ver["실증"], 1);
  assert.equal(st.score, 10, "확인된 치명의 위험지수는 10/10");
});

test("등급 하한 규칙 (실증 치명 > 추정 치명 > 실증 높음 > 추정 높음 > 실증 중간)", () => {
  const g = (sev, ver) => gradeOf([{ sev, ver, title: "t" }]).letter;
  assert.equal(g("치명", "실증"), "F");
  assert.equal(g("치명", "가정"), "D");
  assert.equal(g("높음", "실증"), "D");
  assert.equal(g("높음", "가정"), "C");
  assert.equal(g("중간", "실증"), "C");
  assert.equal(g("중간", "가정"), "B");
  assert.equal(g("낮음", "실증"), "B");
  // C3) 낮음+가정 단독 → A 가 아니라 B.
  // 근거: A 는 '발견 0건' 만 뜻한다. 발견이 1건이라도 있으면 최소 B(양호)다 —
  // 화면에 'A 안전' 과 '3개 발견' 이 동시에 뜨던 혼선을 없애기 위한 규칙이다.
  // (확인하지 못한 것이 '확인되지 않은 것' 은 아니므로 A 로 내리지 않는다.)
  assert.equal(g("낮음", "가정"), "B", "발견이 있으면 A 로 내려가지 않는다");
});

test("낮음+가정 단독이면 B(양호) — '안전' 이라고 쓰지 않는다", () => {
  const g = gradeOf([{ sev: "낮음", ver: "가정", title: "보안 헤더 누락" }]);
  assert.equal(g.letter, "B");
  assert.equal(g.label, "양호");
  assert.notEqual(g.label, "안전", "A 라벨은 '이상 없음' 뿐이다");
});

test("등급 라벨은 다섯 가지로 통일된다 (A 이상 없음 / B 양호 / C 보통 / D 위험 / F 심각)", () => {
  const label = (sev, ver) => gradeOf([{ sev, ver, title: "t" }]).label;
  assert.equal(label("낮음", "가정"), "양호");
  assert.equal(label("중간", "실증"), "보통");
  assert.equal(label("높음", "가정"), "보통");
  assert.equal(label("높음", "실증"), "위험");
  assert.equal(label("치명", "가정"), "위험");
  assert.equal(label("치명", "실증"), "심각");
});

test("발견이 1건이라도 있으면 A 로 내려가지 않는다", () => {
  const st = reportStats(doc(root("보안 헤더 누락", "낮음", "가정")));
  assert.equal(st.roots, 1);
  assert.notEqual(st.grade.letter, "A", "발견 1건이면 A 가 아니다");
  assert.equal(st.grade.letter, "B");
});

test("발견 0건은 '이상 없음'으로 표기한다", () => {
  const st = reportStats(doc("점검 완료 — 알려진 결함 없음"));
  assert.equal(st.roots, 0);
  assert.equal(st.grade.letter, "A");
  assert.equal(st.grade.label, "이상 없음");
});

test("검증 라벨 줄이 뒤의 보조 근거로 덮어써지지 않는다", () => {
  const st = reportStats(doc([
    "### 루트 1. 반사형 XSS [높음]",
    "검증: [실증] web_fetch 재현 성공 — 관리자 쿠키 발급 확인",
    "근거: [가정] 추가 관찰",
  ].join("\n")));
  assert.equal(st.ver["실증"], 1, "확인 상태가 유지되어야 한다");
  assert.equal(st.ver["가정"], 0);
  assert.equal(st.grade.letter, "D");
});

test("최고 위험 루트 제목이 요약에 올라간다", () => {
  const st = reportStats(doc([
    root("낮은 것", "낮음", "가정"),
    root("가장 위험한 것", "치명", "실증"),
  ].join("\n\n")));
  assert.equal(st.worst.title, "가장 위험한 것");
  assert.equal(st.worst.sev, "치명");
  assert.equal(st.worst.ver, "실증");
});

test("표지 블록에 대상·등급·발견 분포가 실린다", () => {
  const docs = doc(root("SQL 주입", "높음", "실증"));
  const cover = reportCover({ host: "example.com", port: 8443 }, statsDocs(docs));
  assert.match(cover, /example\.com:8443/);
  assert.match(cover, /등급 D/);
  assert.match(cover, /위험지수 7\.5\/10/);
  assert.match(cover, /직접 확인 1/);
});

test("루트 헤딩이 없는 리포트도 배지로 집계한다 (포맷 편차 대비)", () => {
  const st = reportStats(doc("본문 중 [치명] 발견"));
  assert.equal(st.sev["치명"], 1);
  assert.ok(st.roots >= 1);
});
