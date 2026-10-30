# UI 테스트

## 1) 등급 산정 회귀 (node --test, 의존성 없음)

`grade.test.mjs` 는 `app.js` 의 순수 함수(`reportStats`/`gradeOf`)만 로드해
리포트 위험도 등급 규칙을 고정한다. 핵심 회귀:

- **직접 확인된 치명 1건이 다른 추측 항목에 묻혀 '안전(A)' 으로 내려가지 않는다**
  (이전 산정은 심각도×증거 가중치의 *평균*이라 이 사고가 가능했다)
- 등급 하한 규칙 (F≥확인 치명 · D≥추정 치명/확인 높음 · C≥추정 높음/확인 중간 ·
  B≥추정 중간/확인 낮음)
- `검증:` 라벨 줄이 뒤의 `근거: [가정]` 같은 보조 근거로 덮어써지지 않는다
- 요약 헤더용 최고 위험 루트 제목·표지 블록(대상·등급·위험지수·발견 분포)

```bash
node --test ui/tests/grade.test.mjs
```

## 2) UI smoke test (mock mode)

`smoke.py` drives the desktop UI in the browser against `preview.sh` +
`mock.js`: the protected core flow (URL → 진단 시작 → 결과 리포트) plus the
UX behaviors around it (live filter, tail-follow, quick chips, chat markdown,
Enter-to-diagnose, Esc-to-close, toast). Fails on any console error or any
blocking `alert()` dialog.

Requires Playwright + Chromium (external tooling, nothing added to the repo):

```bash
pip install playwright && playwright install chromium
cd redcell-desktop && ./preview.sh start
python3 ui/tests/smoke.py            # REDCELL_PREVIEW_URL to override
```

`mock.js` 의 데모 리포트는 실제 산출물 표준(`docs/REPORT_STANDARD.md`)을 따른다 —
CVSS 벡터·점수·CWE·재현 curl·한계 절까지 포함하므로, 미리보기 화면에서
UI 렌더링(CVSS 필드·재현 필드·루트 카드·등급 헤더)을 함께 확인할 수 있다.
