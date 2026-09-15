// Report-screen (Results tab) regression check for the RedCell desktop UI.
//
// The results tab shows a diagnostic report with a summary bar on top. This script
// guards the fix that keeps that summary from covering the report body:
//   1. the summary never overflows the results view (no clipping),
//   2. the body always keeps usable height,
//   3. collapse/expand really frees vertical space,
//   4. the severity filter narrows the root cards,
//   5. the jump nav scrolls to the target card.
//
// Usage (one-time deps, then run against the static preview):
//   ./preview.sh                       # serves redcell-desktop/ui on :5173
//   npm i playwright && npx playwright install chromium
//   node .verify/report-ui.mjs
//
// Screenshots are written to $OUT_DIR (default /tmp/ui-shot).
// Exits non-zero when any check fails.

import { chromium } from "playwright";

const URL = process.env.PREVIEW_URL || "http://localhost:5173/";
const OUT = process.env.OUT_DIR || "/tmp/ui-shot";

// "diagnostic" tab name in the mock store is Korean (데모몰-진단) -> match by label prefix
const DIAG_TAB_LABEL = "\uC9C4\uB2E8";
const SEV_HIGH = "\uB192\uC74C";
const SEV_ALL = "ALL"; // "show every severity" chip

const SIZES = [
  { name: "default-1360x860", width: 1360, height: 860 },
  { name: "min-960x600", width: 960, height: 600 },
];

const browser = await chromium.launch({ args: ["--no-sandbox"] });
const failures = [];

for (const size of SIZES) {
  const ctx = await browser.newContext({
    viewport: { width: size.width, height: size.height },
    permissions: ["clipboard-read", "clipboard-write"],
  });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => failures.push(`${size.name} pageerror: ${e.message}`));
  page.on("console", (m) => { if (m.type() === "error") failures.push(`${size.name} console error: ${m.text()}`); });

  await page.goto(URL, { waitUntil: "networkidle" });
  await page.evaluate(() => localStorage.clear());
  await page.reload({ waitUntil: "networkidle" });

  const tab = page.locator(".tab", { hasText: DIAG_TAB_LABEL }).first();
  await tab.locator(".tname").click().catch(async () => { await tab.click(); });
  await page.locator('.subtab[data-view="results"]').click();
  await page.waitForTimeout(300);

  const stateOf = () => page.evaluate(() => {
    const rv = document.querySelector("#view-results").getBoundingClientRect();
    const sm = document.querySelector("#reportSummary").getBoundingClientRect();
    const bd = document.querySelector("#resultsBody").getBoundingClientRect();
    const outside = (r) => Math.round(Math.max(0, r.bottom - rv.bottom)) + Math.round(Math.max(0, rv.top - r.top));
    return {
      collapsed: document.querySelector("#reportSummary .rs-card").classList.contains("collapsed"),
      viewH: Math.round(rv.height),
      summaryH: Math.round(sm.height),
      bodyH: Math.round(bd.height),
      summaryOutsidePx: outside(sm),
      bodyOutsidePx: outside(bd),
      scrollTop: Math.round(document.querySelector("#resultsBody").scrollTop),
    };
  });

  // 1) initial render: nothing clipped, body keeps usable height
  const initial = await stateOf();
  await page.screenshot({ path: `${OUT}/${size.name}-report.png` });
  console.log(size.name, "initial", JSON.stringify(initial));
  if (initial.bodyH < 120) failures.push(`${size.name}: report body only ${initial.bodyH}px tall`);
  if (initial.bodyOutsidePx > 1) failures.push(`${size.name}: report body overflows the view by ${initial.bodyOutsidePx}px`);
  if (initial.summaryOutsidePx > 1) failures.push(`${size.name}: summary overflows the view by ${initial.summaryOutsidePx}px`);

  // 2) collapse/expand toggle changes the split (collapsed => more body space)
  await page.locator("#rsToggle").click();
  await page.waitForTimeout(200);
  await page.screenshot({ path: `${OUT}/${size.name}-toggled.png` });
  const toggled = await stateOf();
  console.log(size.name, "toggle", JSON.stringify(toggled));
  if (toggled.collapsed === initial.collapsed) failures.push(`${size.name}: toggle did not change state`);
  const collapsedState = toggled.collapsed ? toggled : initial;
  const expandedState = toggled.collapsed ? initial : toggled;
  if (collapsedState.bodyH <= expandedState.bodyH) {
    failures.push(`${size.name}: collapsed summary does not free body height`);
  }
  // leave the summary expanded so the drawer controls are reachable
  if (toggled.collapsed) { await page.locator("#rsToggle").click(); await page.waitForTimeout(200); }

  // 3) severity filter keeps only root cards of that severity
  await page.locator(`#reportSummary .rs-nav-chip[data-f="${SEV_HIGH}"]`).first().click();
  await page.waitForTimeout(250);
  const filtered = await page.evaluate(() => {
    const cards = [...document.querySelectorAll("#resultsBody .md-card")];
    return { cards: cards.length, rootCards: cards.filter((c) => c.classList.contains("is-root")).length };
  });
  console.log(size.name, "filter", JSON.stringify(filtered));
  if (filtered.rootCards !== 1) failures.push(`${size.name}: severity filter kept ${filtered.rootCards} root cards`);
  await page.locator(`#reportSummary .rs-nav-chip[data-f="${SEV_ALL}"]`).first().click();
  await page.waitForTimeout(200);

  // 4) jump nav scrolls the body to the card, and scrolling collapses the summary
  const beforeJump = await stateOf();
  await page.locator('#reportSummary .rs-jump-chip[data-goto="2"]').first().click();
  await page.waitForTimeout(700);
  await page.screenshot({ path: `${OUT}/${size.name}-jump.png` });
  const afterJump = await stateOf();
  console.log(size.name, "jump", JSON.stringify(afterJump));
  if (afterJump.scrollTop <= beforeJump.scrollTop) failures.push(`${size.name}: jump nav did not scroll the body`);
  if (!afterJump.collapsed) failures.push(`${size.name}: summary did not auto-collapse while scrolled`);
  if (afterJump.summaryH >= expandedState.summaryH) failures.push(`${size.name}: auto-collapse did not shrink the summary`);

  // 5) back to top returns to the window's default state
  await page.evaluate(() => { document.getElementById("resultsBody").scrollTop = 0; });
  await page.waitForTimeout(300);
  const back = await stateOf();
  console.log(size.name, "back-to-top", JSON.stringify(back));
  if (back.collapsed !== initial.collapsed) {
    failures.push(`${size.name}: back-to-top did not restore the default state (initial=${initial.collapsed}, now=${back.collapsed})`);
  }
  // 7) copy / export: the status element moved out of the action row, so it must still
  //    report progress in place (ok or a graceful failure), without throwing.
  const diag = page.locator(".tab", { hasText: DIAG_TAB_LABEL }).first();
  await diag.locator(".tname").click().catch(async () => { await diag.click(); });
  await page.locator('.subtab[data-view="results"]').click();
  await page.waitForTimeout(300);
  await page.locator("#rsCopy").click();
  await page.waitForTimeout(400);
  const copied = await page.evaluate(async () => {
    const st = document.querySelector("#rsExportStatus");
    let clip = "";
    try { clip = await navigator.clipboard.readText(); } catch (e) { clip = "unreadable"; }
    return { statusText: st.textContent.trim(), statusClass: st.className, clipLen: clip.length, visible: st.offsetHeight > 0 };
  });
  console.log(size.name, "copy", JSON.stringify(copied));
  if (!copied.visible) failures.push(`${size.name}: export status line is not visible after copy`);
  if (!/ok|err/.test(copied.statusClass)) failures.push(`${size.name}: copy did not report status (${copied.statusClass})`);
  await page.locator("#rsExport").click();
  await page.waitForTimeout(500);
  const exported = await page.evaluate(() => {
    const st = document.querySelector("#rsExportStatus");
    return { statusText: st.textContent.trim(), statusClass: st.className, disabled: document.querySelector("#rsExport").disabled };
  });
  console.log(size.name, "export-md", JSON.stringify(exported));
  if (!exported.statusText) failures.push(`${size.name}: MD export left the status line empty`);
  if (exported.disabled) failures.push(`${size.name}: MD export button stayed disabled`);
  await page.screenshot({ path: `${OUT}/${size.name}-export-status.png` });

  // 6) non-diagnostic session (plain markdown results): the diagnostic summary must
  //    stay hidden and the results timeline must still fit without clipping.
  const plain = page.locator(".tab", { hasText: "vulnlab-web" }).first();
  await plain.locator(".tname").click().catch(async () => { await plain.click(); });
  await page.locator('.subtab[data-view="results"]').click();
  await page.waitForTimeout(300);
  const plainState = await page.evaluate(() => {
    const rv = document.querySelector("#view-results").getBoundingClientRect();
    const bd = document.querySelector("#resultsBody").getBoundingClientRect();
    return {
      summaryHidden: document.querySelector("#reportSummary").classList.contains("hidden"),
      cards: document.querySelectorAll("#resultsBody .md-card").length,
      bodyH: Math.round(bd.height),
      viewOverflowPx: Math.round(Math.max(0, bd.bottom - rv.bottom)),
    };
  });
  await page.screenshot({ path: `${OUT}/${size.name}-plain.png` });
  console.log(size.name, "plain-session", JSON.stringify(plainState));
  if (!plainState.summaryHidden) failures.push(`${size.name}: summary shown for a non-diagnostic session`);
  if (plainState.cards < 1) failures.push(`${size.name}: non-diagnostic results did not render`);
  if (plainState.bodyH < 120 || plainState.viewOverflowPx > 1) failures.push(`${size.name}: non-diagnostic results clipped (${JSON.stringify(plainState)})`);

  await ctx.close();
}

await browser.close();
if (failures.length) {
  console.log("FAIL\n" + failures.join("\n"));
  process.exit(1);
}
console.log("ALL CHECKS PASSED");