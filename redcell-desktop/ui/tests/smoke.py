"""RedCell desktop UI smoke test (mock/preview mode).

Drives the protected core flow (URL -> diagnose -> results) plus the UX
behaviors around it, all against ``preview.sh`` + ``mock.js``. No repo
dependencies beyond Playwright + its bundled Chromium.

Run:
    cd redcell-desktop && ./preview.sh start
    python3 ui/tests/smoke.py            # REDCELL_PREVIEW_URL to override
"""
import os
import sys
import time

BASE = os.environ.get("REDCELL_PREVIEW_URL", "http://localhost:5173")

FAILURES = []
ERRORS = []
DIALOGS = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def pick_provider(page):
    """Select first connected provider in the session header. Returns name or ''."""
    opts = page.eval_on_selector(
        "#shProvider",
        "el => [...el.options].map(o => ({v: o.value, t: o.text}))",
    )
    for o in opts:
        if o["v"] and o["v"] != "__setup":
            page.select_option("#shProvider", o["v"])
            return o["v"]
    return ""


def new_session_with_target(page, host="demo.vulnlab.local", port="8080"):
    page.click("#newSessionBtn")
    page.wait_for_timeout(400)
    page.fill("#shHost", host)
    page.fill("#shPort", port)
    prov = pick_provider(page)
    return prov


def wait_badge(page, want, timeout_ms=45000):
    page.wait_for_function(
        f"document.getElementById('statusBadge').dataset.status === '{want}'",
        timeout=timeout_ms,
    )


def main():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.on("console", lambda m: ERRORS.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: ERRORS.append(str(e)))

        def on_dialog(d):
            DIALOGS.append(f"{d.type}: {d.message[:80]}")
            d.dismiss()

        page.on("dialog", on_dialog)
        page.goto(BASE + "/#dark", wait_until="networkidle")
        page.wait_for_timeout(1200)

        # 1. boot clean
        check("boot: tabs rendered", page.locator("#tabs .tab").count() >= 1)
        check("boot: no console errors yet", len(ERRORS) == 0, "; ".join(ERRORS[:3]))

        # 2. PROTECTED core flow: URL -> diagnose -> results
        prov = new_session_with_target(page)
        check("core: provider selectable in mock", bool(prov), "no connected provider option")
        if prov:
            page.click("#diagBtn")
            try:
                wait_badge(page, "running", 8000)
                running_seen = True
            except Exception:
                running_seen = False
            check("core: diagnosis starts (running)", running_seen)
            try:
                wait_badge(page, "done", 45000)
                done_seen = True
            except Exception:
                done_seen = False
            check("core: diagnosis completes (done)", done_seen)
            rows = page.locator("#capBody tr").count()
            check("core: live rows streamed", rows >= 10, f"rows={rows}")
            results_open = page.eval_on_selector("#view-results", "el => el.classList.contains('active')")
            res_cards = page.locator("#resultsBody .md-card").count()
            check("core: results view has report", results_open or res_cards > 0,
                  f"active={results_open} cards={res_cards}")
            check("core: run separator inserted", page.locator("#capBody tr.run-sep").count() >= 1)
            check("core: badge text Korean", page.locator("#statusBadge").inner_text().strip() == "완료",
                  page.locator("#statusBadge").inner_text().strip())

            # 2b. 결과 탭 정보 구조 — 새 리포트 표준 요소가 실제로 보이는지 확인한다.
            #     (실패해도 전체를 중단하지 않는다 — check() 가 FAIL 로 기록한다)
            try:
                if not page.locator("#view-results.active").count():
                    page.click('.subtab[data-view="results"]')
                page.wait_for_timeout(600)
            except Exception as e:
                check("report: results tab reachable", False, str(e))

            letter = page.eval_on_selector(".rs-letter", "el => el.textContent.trim()")
            check("report: grade letter shown", bool(letter) and letter in "ABCDF", f"letter={letter!r}")
            why = page.eval_on_selector(".rs-why-note", "el => el.textContent")
            check("report: grade reason with risk index", "위험지수" in why, why[:60])

            n_root = page.locator("#resultsBody .md-card.is-root").count()
            check("report: root cards exist", n_root >= 1, f"roots={n_root}")
            order = page.evaluate(
                "() => { const cards=[...document.querySelectorAll('#resultsBody .md-card')];"
                " const fix=cards.findIndex(c=>c.querySelector('.md-kind.fix'));"
                " const root=cards.findIndex(c=>c.classList.contains('is-root'));"
                " return {fix: fix, root: root}; }")
            check("report: '해야 할 일' card comes before root cards",
                  order["fix"] >= 0 and order["root"] >= 0 and order["fix"] < order["root"],
                  f"fix={order['fix']} root={order['root']}")

            n_score = page.locator("#resultsBody .diag-field.field-score").count()
            check("report: CVSS shown as score/classification fields", n_score >= 1, f"field-score={n_score}")

            n_tbl = page.locator("#resultsBody table").count()
            n_scroll = page.locator("#resultsBody .table-scroll table").count()
            check("report: table wrapped in horizontal scroll container",
                  n_tbl >= 1 and n_scroll == n_tbl, f"tables={n_tbl} wrapped={n_scroll}")

            # 툴팁(abbr) — 비전문가가 모르는 전문어에 설명이 붙는지
            abbrs = page.eval_on_selector_all(
                "#resultsBody abbr[title]",
                "els => els.map(e => ({t: e.textContent.trim(), tip: e.getAttribute('title')}))")
            check("report: jargon tooltips (abbr[title]) exist in body",
                  len(abbrs) >= 3, f"abbr={len(abbrs)}")
            check("report: every tooltip carries a plain-language explanation",
                  bool(abbrs) and all(a["tip"] and len(a["tip"]) >= 6 for a in abbrs),
                  str(abbrs[:2]))
            check("report: no nested tooltips (중복 감싸기 금지)",
                  page.locator("#resultsBody abbr abbr").count() == 0)
            dup = page.evaluate(
                "() => { let worst = 0;"
                " for (const c of document.querySelectorAll('#resultsBody .md-card')) {"
                "  const seen = {};"
                "  for (const a of c.querySelectorAll('abbr[title]')) {"
                "   const t = a.textContent.trim(); seen[t] = (seen[t] || 0) + 1;"
                "   if (seen[t] > worst) worst = seen[t]; } }"
                " return worst; }")
            check("report: a term is wrapped only once per document", dup <= 1, f"max={dup}")

            # 위험도 필터(치명) → 보이는 루트 카드 수가 줄어든다
            before_roots = page.locator("#resultsBody .md-card.is-root").count()
            page.evaluate(
                "() => { const c=[...document.querySelectorAll('#reportSummary .rs-nav-chip')]"
                ".find(e=>e.dataset.f==='치명'); if(c) c.click(); }")
            page.wait_for_timeout(400)
            after_roots = page.locator("#resultsBody .md-card.is-root").count()
            check("report: severity filter narrows root cards",
                  0 <= after_roots < before_roots, f"{before_roots}->{after_roots}")
            page.evaluate(
                "() => { const c=[...document.querySelectorAll('#reportSummary .rs-nav-chip')]"
                ".find(e=>e.dataset.f==='치명'); if(c) c.click(); }")
            page.wait_for_timeout(300)

            jumps = page.eval_on_selector_all(
                "#reportSummary .rs-jump-chip", "els => els.map(e => e.textContent.trim())")
            check("report: jump nav labels by kind", any("해야 할 일" in j for j in jumps),
                  f"jumps={jumps[:6]}")
            # memory panel roundtrip (preview mock is stateful)
            page.locator('.subtab[data-view="live"]').click()
            page.wait_for_timeout(300)
            page.locator("#memPanel summary").click()
            page.wait_for_timeout(200)
            page.fill("#memText", "smoke-memo-1234")
            page.click("#memAddBtn")
            page.wait_for_timeout(400)
            mem_items = page.locator("#memList .mem-item").count()
            check("core: memory add shows item", mem_items >= 1, f"items={mem_items}")
            if mem_items:
                page.locator("#memList .mem-del").first.click()
                page.wait_for_timeout(400)
            check("core: memory delete clears item", page.locator("#memList .mem-item").count() == 0)
            page.click('.subtab[data-view="live"]')
            page.wait_for_timeout(300)

        # 3. chat run streams mixed rows (vuln path, no diag keywords)
        prov2 = new_session_with_target(page)
        if prov2:
            page.fill("#chatInput", "웹 취약점 정찰해줘")
            page.click("#chatSend")
            try:
                page.wait_for_function(
                    "document.querySelectorAll('#capBody tr').length >= 20", timeout=30000)
                streamed = True
            except Exception:
                streamed = False
            check("chat: rows stream", streamed)
            try:
                wait_badge(page, "done", 45000)
            except Exception:
                pass
            tools = page.eval_on_selector_all(
                "#capBody td.c-tool", "els => els.map(e => e.textContent.trim())")
            check("ux: friendly tool labels in table",
                  any("웹 응답 파악" in t for t in tools), f"sample={tools[:4]}")
            phases = page.eval_on_selector_all(
                "#capBody td.c-phase", "els => els.map(e => e.textContent.trim())")
            check("ux: friendly phase labels in table",
                  any(x in phases for x in ("정찰", "수집", "검증", "정리")), f"sample={sorted(set(phases))[:6]}")
            n_find = page.locator("#capBody tr.row-finding").count()
            check("chat: finding rows present", n_find >= 1, f"findings={n_find}")

            # 4. live filter chips
            has_filter = page.locator("#liveFilter .lf-chip").count() >= 2
            check("ux: live filter chips exist", has_filter)
            if has_filter:
                page.click('#liveFilter .lf-chip[data-f="finding"]')
                page.wait_for_timeout(300)
                vis = page.eval_on_selector_all(
                    "#capBody tr", "els => els.filter(e => e.offsetParent !== null).length")
                check("ux: filter shows only findings", 1 <= vis <= n_find,
                      f"visible={vis} findings={n_find}")
                page.click('#liveFilter .lf-chip[data-f="all"]')
                page.wait_for_timeout(300)

            # 5. tail-follow button
            scrollable = page.evaluate(
                "const c = document.querySelector('.capture'); c.scrollHeight > c.clientHeight + 50")
            check("ux: capture scrollable for tail test", scrollable)
            if scrollable:
                page.evaluate("document.querySelector('.capture').scrollTop = 0")
                page.wait_for_timeout(400)
                tail_visible = page.locator("#tailBtn").count() > 0 and page.locator("#tailBtn").is_visible()
                check("ux: tail button appears when scrolled up", tail_visible)
                if tail_visible:
                    # evaluate-click: Playwright의 scroll-into-view가 컨테이너를
                    # 건드려 버튼을 숨기므로(제품 정상 동작) 직접 클릭 배선만 검증
                    page.evaluate("document.getElementById('tailBtn').click()")
                    page.wait_for_timeout(300)
                    at_bottom = page.evaluate(
                        "const c = document.querySelector('.capture');"
                        " (c.scrollHeight - c.scrollTop - c.clientHeight) < 40")
                    check("ux: tail button jumps to bottom", at_bottom)
                else:
                    check("ux: tail button jumps to bottom", False, "button missing")

            # 6. detail pane hides raw dump behind toggle
            n_row = page.locator("#capBody tr.row-finding").count()
            if n_row > 0:
                # evaluate-click: sticky thead가 행 상단 클릭점을 가릴 수 있어 배선만 검증
                page.evaluate("document.querySelector('#capBody tr.row-finding').click()")
                page.wait_for_timeout(300)
                check("ux: detail raw dump behind <details>",
                      page.locator("#detail details.d-raw").count() == 1)
            else:
                check("ux: detail raw dump behind <details>", False, "no finding rows")

            # 7. message clamp
            clamp = page.evaluate(
                "const el = document.querySelector('#capBody td.c-msg');"
                " el ? getComputedStyle(el).webkitLineClamp : 'missing'")
            check("ux: long messages clamped", clamp == "3", f"line-clamp={clamp}")

        # 8. quick starter chips
        new_session_with_target(page)
        chips = page.locator("#quickGoals .chip").count()
        check("ux: quick starter chips exist", chips >= 2, f"chips={chips}")
        if chips:
            before = page.locator("#chatMessages .msg.user").count()
            page.locator("#quickGoals .chip").first.click()
            page.wait_for_timeout(600)
            after = page.locator("#chatMessages .msg.user").count()
            check("ux: chip click sends chat", after == before + 1, f"{before}->{after}")

        # 9. chat markdown for assistant messages
        try:
            md = page.evaluate("window.chatHtml('**굵게**와 `코드`')")
            check("ux: chat markdown renders", "<strong>" in md and "<code>" in md, md[:80])
        except Exception as e:
            check("ux: chat markdown renders", False, f"chatHtml missing: {e}")

        # 10. Enter in address starts diagnosis
        new_session_with_target(page)
        page.fill("#shHost", "demo.vulnlab.local")
        page.locator("#shHost").press("Enter")
        try:
            wait_badge(page, "running", 8000)
            enter_ok = True
        except Exception:
            enter_ok = False
        check("ux: Enter in address starts diagnosis", enter_ok)
        if enter_ok:
            page.click("#diagBtn")  # stop (mode=stop while running)
            page.wait_for_timeout(800)

        # 11. Esc closes modals
        page.click("#settingsBtn")
        page.wait_for_timeout(400)
        check("ux: settings opens", page.locator("#settingsModal").is_visible())
        page.keyboard.press("Escape")
        page.wait_for_timeout(300)
        check("ux: Esc closes modal", not page.locator("#settingsModal").is_visible())

        # 12. toast instead of blocking alert
        page.click("#newSessionBtn")
        page.wait_for_timeout(400)
        page.fill("#shHost", "")
        page.click("#diagBtn")
        page.wait_for_timeout(600)
        check("ux: empty-host shows toast",
              page.locator("#toast.show").count() == 1)
        check("ux: no blocking dialogs anywhere", len(DIALOGS) == 0, "; ".join(DIALOGS[:3]))

        # 13. 온보딩(첫 화면) — AI 모델이 연결돼 있지 않으면 '진단 시작' 전에 안내가 보인다
        #     기존 세션을 모두 지우면 URL 입력 첫 화면(히어로)이 드러난다.
        page.evaluate("() => { window.confirm = () => true; }")
        for _ in range(12):
            if page.locator("#tabs .tab").count() == 0:
                break
            page.evaluate(
                "() => { const c = document.querySelector('#tabs .tab .tclose'); if (c) c.click(); }")
            page.wait_for_timeout(250)
        page.wait_for_timeout(400)
        check("onboard: URL-first hero shown when no session exists",
              page.locator("#onboardHero").is_visible())
        setup_txt = ""
        if page.locator("#obSetup").count():
            setup_txt = page.eval_on_selector("#obSetup", "el => el.textContent")
        check("onboard: 'AI 모델 연결' guide card visible before starting",
              page.locator("#obSetup").is_visible()
              and "AI 모델" in setup_txt and "연결" in setup_txt,
              setup_txt[:80])
        setup_btn = ""
        if page.locator("#obSetup #obSetupBtn").count():
            setup_btn = page.eval_on_selector("#obSetup #obSetupBtn", "el => el.textContent")
        check("onboard: guide card offers 'AI 모델 연결하기' button",
              "AI 모델 연결하기" in setup_btn, setup_btn[:40])

        # 14. 엔진 선택지 라벨이 사람 말인가 (pi · prime-agent 원어 노출 금지)
        eng_labels = page.eval_on_selector_all(
            "#obEngine option", "els => els.map(e => e.textContent.trim())")
        check("onboard: engine options are plain Korean",
              any("자동" in l for l in eng_labels)
              and any("기본 검사 엔진" in l for l in eng_labels)
              and any("심화 검사 엔진" in l for l in eng_labels)
              and not any("prime-agent" in l or l.strip() == "pi" for l in eng_labels),
              str(eng_labels))
        eng_hint = ""
        if page.locator("#obEngineHint").count():
            eng_hint = page.eval_on_selector("#obEngineHint", "el => el.textContent.trim()")
        check("onboard: engine hint line visible under the selector", len(eng_hint) > 8, eng_hint[:60])

        # 15. 진단 시작을 눌렀는데 AI 모델이 없으면 — 왜 멈췄는지 정직하게 말한다
        page.fill("#obUrl", "https://demo.vulnlab.local")
        page.click("#obDiag")
        page.wait_for_timeout(600)
        err_txt = page.eval_on_selector("#obError", "el => el.textContent")
        toast_txt = page.eval_on_selector("#toast", "el => el.textContent")
        check("onboard: missing AI model explained on '진단 시작'",
              page.locator("#providerModal").is_visible()
              and ("AI 모델 연결이 필요해요" in err_txt
                   or "AI 모델 연결이 필요해요" in toast_txt),
              f"err={err_txt[:50]} toast={toast_txt[:50]}")
        page.evaluate(
            "() => { const b = document.getElementById('providerClose'); if (b) b.click(); }")
        page.wait_for_timeout(200)

        check("final: zero console errors", len(ERRORS) == 0, "; ".join(ERRORS[:5]))
        browser.close()

    print(f"\n{len(FAILURES)} failure(s)" + (": " + ", ".join(FAILURES) if FAILURES else ""))
    return 1 if FAILURES else 0


def await_count(loc):
    try:
        return loc.count()
    except Exception:
        return 0


if __name__ == "__main__":
    sys.exit(main())
