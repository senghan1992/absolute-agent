/**
 * RedCell 탐지 정확도 벤치마크 (CLI 러너).
 *
 * 각 탐지 툴을 (1) 취약 참조 앱과 (2) 견고(hardened) 참조 앱에 대해 실행하고,
 * 정답(ground truth)과 대조해 재현율(recall)·정밀도(precision)·오탐을 측정한다.
 *   - 취약 앱에서 탐지 실패 = False Negative(놓침)
 *   - 견고 앱에서 탐지     = False Positive(오탐)
 *
 * 실행: npm run bench   (또는 npx tsx bench/bench.ts)
 * 채점 로직은 score.ts 에 있고, 회귀 테스트(test/bench.test.ts)와 공유한다.
 */

import { CASES, scoreBenchmark } from "./score.js";

function pct(n: number, d: number): string {
  return d === 0 ? "n/a" : `${((100 * n) / d).toFixed(1)}%`;
}

async function main(): Promise<void> {
  const t0 = Date.now();
  const r = await scoreBenchmark();

  console.log("\n═══ RedCell 탐지 정확도 벤치마크 ═══\n");
  console.log(`${"취약점 클래스".padEnd(24)}${"툴".padEnd(16)}${"취약앱".padEnd(10)}견고앱(오탐)`);
  console.log("─".repeat(70));
  const fnList: string[] = [];
  const fpList: string[] = [];
  for (let i = 0; i < CASES.length; i++) {
    const v = r.vuln[i];
    const h = r.hard[i];
    const decoy = CASES[i].kind === "decoy";
    if (decoy) {
      // 미끼: 두 앱 모두 탐지하면 오탐(FP), 아니면 정상. FN 개념 없음.
      if (v.detected) fpList.push(`${v.klass} (${v.tool}) sev=${v.sev} — ${v.summary} [미끼 오탐]`);
      if (h.detected) fpList.push(`${h.klass} (${h.tool}) sev=${h.sev} — ${h.summary} [미끼 오탐]`);
      const vMark = v.detected ? `⚠️ FP ${v.sev}` : `✓ 미끼회피`;
      const hMark = h.detected ? `⚠️ FP ${h.sev}` : `✓ 미끼회피`;
      console.log(`${v.klass.padEnd(24)}${v.tool.padEnd(16)}${vMark.padEnd(10)}${hMark}`);
      continue;
    }
    if (!v.detected) fnList.push(`${v.klass} (${v.tool}) — ${v.summary}`);
    if (h.detected) fpList.push(`${h.klass} (${h.tool}) sev=${h.sev} — ${h.summary}`);
    const vMark = v.detected ? `✅ ${v.sev}` : `❌ (${v.sev})`;
    const hMark = h.detected ? `⚠️ FP ${h.sev}` : `✓ clean`;
    console.log(`${v.klass.padEnd(24)}${v.tool.padEnd(16)}${vMark.padEnd(10)}${hMark}`);
  }
  console.log("─".repeat(70));

  console.log(`\n총 케이스: ${CASES.length}  (취약앱 ${CASES.length} + 견고앱 ${CASES.length} = ${CASES.length * 2} 판정)`);
  console.log(`TP=${r.tp}  FN=${r.fn}  FP=${r.fp}  TN=${r.tn}`);
  console.log(`재현율(Recall,    취약점 탐지율)  : ${pct(r.tp, r.tp + r.fn)}  (${r.tp}/${r.tp + r.fn})`);
  console.log(`오탐율(FP rate,    견고앱 오경보)  : ${pct(r.fp, r.fp + r.tn)}  (${r.fp}/${r.fp + r.tn})`);
  console.log(`정밀도(Precision, 경보의 정확도)  : ${pct(r.tp, r.tp + r.fp)}  (${r.tp}/${r.tp + r.fp})`);
  console.log(`F1 score                          : ${(r.f1 * 100).toFixed(1)}%`);

  if (fnList.length) {
    console.log(`\n놓친 취약점(False Negatives) ${fnList.length}건:`);
    for (const s of fnList) console.log(`  ❌ ${s}`);
  }
  if (fpList.length) {
    console.log(`\n오탐(False Positives) ${fpList.length}건:`);
    for (const s of fpList) console.log(`  ⚠️ ${s}`);
  }
  console.log(`\n소요 ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  // 회귀 게이트: 재현율<90% 또는 오탐 발생 시 실패 종료(CI 연동).
  const ok = r.recall >= 0.9 && r.fp === 0;
  console.log(ok ? "\n✅ 벤치마크 통과 (재현율≥90%, 오탐 0)\n" : "\n❌ 벤치마크 기준 미달\n");
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error("bench 오류:", e);
  process.exit(2);
});
