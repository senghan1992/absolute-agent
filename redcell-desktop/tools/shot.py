#!/usr/bin/env python3
"""결과 탭 스크린샷 — UI 변경의 시각 검수 도구.

    ./preview.sh start && python3 tools/shot.py [outdir]

mock 모드(preview.sh + ui/mock.js)로 진단을 1회 실행한 뒤 결과 탭을 캡처한다.
변경 전/후 스크린샷을 비교하면 정보 구조 개편의 효과를 눈으로 확인할 수 있다.
"""
import os
import sys
import time

BASE = os.environ.get("REDCELL_PREVIEW_URL", "http://localhost:5173")
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/rc-shots"


def main():
    from playwright.sync_api import sync_playwright

    os.makedirs(OUT, exist_ok=True)
    errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 950})
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(BASE + "/#dark", wait_until="networkidle")
        page.wait_for_timeout(1000)

        # 온보딩 → 진단 실행 (mock)
        page.click("#newSessionBtn")
        page.wait_for_timeout(400)
        page.fill("#shHost", "demo.vulnlab.local")
        page.fill("#shPort", "8080")
        opts = page.eval_on_selector(
            "#shProvider", "el => [...el.options].map(o => o.value)"
        )
        pick = next((v for v in opts if v and v != "__setup"), None)
        if pick:
            page.select_option("#shProvider", pick)
        page.click("#diagBtn")
        page.wait_for_function(
            "document.getElementById('statusBadge')?.dataset.status === 'done'",
            timeout=60000,
        )
        page.wait_for_timeout(800)

        # 결과 탭
        page.click(".subtab[data-view='results']")
        page.wait_for_timeout(900)
        page.screenshot(path=f"{OUT}/results-top.png")

        # 요약 카드 서랍 펼친 상태
        try:
            page.click("#rsToggle")
            page.wait_for_timeout(400)
            page.screenshot(path=f"{OUT}/results-drawer.png")
        except Exception as e:
            print("drawer toggle failed:", e)

        # 아래쪽(권고/한계/부록)까지 스크롤
        page.evaluate("document.getElementById('resultsBody').scrollTop = 999999")
        page.wait_for_timeout(600)
        page.screenshot(path=f"{OUT}/results-bottom.png")

        # 카드 종류 요약 (디버그 출력)
        info = page.evaluate(
            """() => {
              const cards = [...document.querySelectorAll('#resultsBody .md-card')];
              return {
                kinds: cards.map(c => (c.querySelector('.md-kind')||{}).textContent || ''),
                grade: (document.querySelector('#reportSummary .rs-letter')||{}).textContent || '',
                why: (document.querySelector('#reportSummary .rs-why-note')||{}).textContent || '',
                scoreFields: document.querySelectorAll('.diag-field.field-score').length,
                tables: document.querySelectorAll('#resultsBody table').length,
                scrollTables: document.querySelectorAll('#resultsBody .table-scroll').length,
                jump: [...document.querySelectorAll('.rs-jump-chip')].map(b => b.textContent.trim()),
                fixCardBeforeRoots: (() => {
                  const k = cards.findIndex(c => (c.querySelector('.md-kind')||{}).textContent === '해야 할 일');
                  const r = cards.findIndex(c => c.classList.contains('is-root'));
                  return k >= 0 && r >= 0 ? k < r : null;
                })(),
              };
            }"""
        )
        print("SUMMARY:", info)
        if errors:
            print("CONSOLE ERRORS:", errors[:5])
        else:
            print("CONSOLE ERRORS: none")
        browser.close()
    print(f"shots → {OUT}")


if __name__ == "__main__":
    main()
