/**
 * python-agent.test — "absolute-agent" 코어(에이전트가 파이썬을 스스로 써서 공격) 검증.
 *
 * 핵심은 두 가지다:
 *   1) 안전: 임의 코드 실행 경로에서도 ScopeGuard·타임아웃·정적 위험 스캔이 강제되는가.
 *   2) 동작: 코드 작성→실행→관찰→다음 코드 루프가 돌고 발견이 수집되는가(MockCoder 로 오프라인).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { runPython, scanDanger } from "../src/py/broker.js";
import { PythonAgent } from "../src/py/python-agent.js";
import { MockCoder } from "../src/py/mock-coder.js";

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/item") {
      const id = url.searchParams.get("id") ?? "";
      if (id.includes("'")) {
        res.statusCode = 500;
        res.end("You have an error in your SQL syntax near MySQL");
        return;
      }
      res.statusCode = 200;
      res.end("item ok");
      return;
    }
    res.setHeader("Server", "nginx/1.18.0");
    res.end("<html>root</html>");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

function auth(): AuthorizationFile {
  return {
    engagement: { name: "py", authorized_from: "2000-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
    scope: { allow: [{ host: "127.0.0.1" }] },
    limits: { max_requests_per_second: 200 },
  };
}
const guard = () => new ScopeGuard(auth());
const target = () => ({ host: "127.0.0.1", port });

describe("정적 위험 스캔(scanDanger)", () => {
  it("파괴적/우회 패턴을 실행 전에 차단한다", () => {
    expect(scanDanger("import shutil\nshutil.rmtree('/x')")).toMatch(/rmtree/);
    expect(scanDanger("import socket")).toMatch(/socket/);
    expect(scanDanger("import requests")).toMatch(/requests/);
    expect(scanDanger("import urllib.request")).toMatch(/urllib/);
    expect(scanDanger("os.system('id')")).toMatch(/os.system/);
    // rc 헬퍼만 쓰는 정상 코드는 통과.
    expect(scanDanger("r = rc.get('/')\nrc.log(r.status)")).toBeNull();
  });
});

describe("AST 허용목록 샌드박스(정규식 우회 방지)", () => {
  // 정적 정규식(scanDanger)을 통과하는 난독화·탈출 시도라도 runner 의 AST 검증이 막는다.
  it("동적 import(__import__)로 우회하려 해도 거부한다", async () => {
    const r = await runPython("m = __import__('so' + 'cket')\nm.socket()", { guard: guard(), target: target(), isolation: "off" });
    expect(r.ok).toBe(false);
    expect(r.danger).toBeDefined();
    expect(r.requests).toBe(0);
  });

  it("던더 접근(__class__ 체인)으로 샌드박스 탈출을 시도해도 거부한다", async () => {
    const code = "cls = ().__class__.__bases__[0]\nsubs = cls.__subclasses__()";
    const r = await runPython(code, { guard: guard(), target: target(), isolation: "off" });
    expect(r.ok).toBe(false);
    expect(r.danger).toMatch(/던더|dunder|__/);
    expect(r.requests).toBe(0);
  });

  it("operator.attrgetter + 문자열 던더로 runner 글로벌 탈취를 시도해도 거부한다", async () => {
    // 문자열 리터럴 속 던더는 AST Attribute 검사를 우회한다 — operator 제외 + 문자열-던더
    // 거부로 이 고전적 샌드박스 탈출(attrgetter('__class__...') / '...__globals__')을 막는다.
    const code = "import operator\nG = operator.attrgetter('http.__func__.__globals__')(rc)";
    const r = await runPython(code, { guard: guard(), target: target(), isolation: "off" });
    expect(r.ok).toBe(false);
    expect(r.danger).toMatch(/operator|던더|문자열/);
    expect(r.requests).toBe(0);
  });

  it("문자열 리터럴 안의 던더를 거부한다(문자열 경유 속성접근 방지)", async () => {
    const r = await runPython("s = '__globals__'\nrc.log(s)", { guard: guard(), target: target(), isolation: "off" });
    expect(r.ok).toBe(false);
    expect(r.danger).toMatch(/문자열 리터럴 내 던더/);
    expect(r.requests).toBe(0);
  });

  it("str.format 던더 게이더로 속성 체인 접근을 시도해도 거부한다", async () => {
    // '{0.__class__}'.format(obj) 는 포맷 문자열로 속성에 닿는 동적 게이더다.
    const r = await runPython("x = '{0.__class__}'.format(())", { guard: guard(), target: target(), isolation: "off" });
    expect(r.ok).toBe(false);
    expect(r.danger).toMatch(/던더|동적 속성접근|format/);
    expect(r.requests).toBe(0);
  });

  it("eval/getattr 등 위험 빌트인 호출을 거부한다", async () => {
    const r = await runPython("eval('1+1')", { guard: guard(), target: target(), isolation: "off" });
    expect(r.ok).toBe(false);
    expect(r.danger).toMatch(/eval/);
    expect(r.requests).toBe(0);
  });

  it("허용 목록 밖 모듈 import 를 거부한다(정적 스캔이 놓치는 모듈 포함)", async () => {
    // scanDanger 정규식에 없는 위험 모듈(pickle)도 AST 화이트리스트가 막는다.
    const r = await runPython("import pickle\npickle.loads(b'')", { guard: guard(), target: target(), isolation: "off" });
    expect(r.ok).toBe(false);
    expect(r.danger).toMatch(/import 금지|pickle/);
    expect(r.requests).toBe(0);
  });

  it("허용된 안전 모듈(json/hashlib 등)은 정상 사용할 수 있다", async () => {
    const code = [
      "import json, hashlib",
      "h = hashlib.sha256(b'x').hexdigest()",
      "rc.log('hash', h[:8], json.dumps({'ok': True}))",
    ].join("\n");
    const r = await runPython(code, { guard: guard(), target: target(), isolation: "off" });
    expect(r.ok).toBe(true);
    expect(r.logs.join(" ")).toMatch(/hash/);
  });
});

describe("broker: 안전 실행", () => {
  it("정적 스캔에 걸리면 프로세스를 실행하지 않는다", async () => {
    const r = await runPython("import socket\ns = socket.socket()", { guard: guard(), target: target(), isolation: "off" });
    expect(r.ok).toBe(false);
    expect(r.danger).toMatch(/socket/);
    expect(r.exitCode).toBeNull();
    expect(r.requests).toBe(0);
  });

  it("scope 안(127.0.0.1)은 통과하고 scope 밖 호스트는 브로커가 차단한다", async () => {
    const code = [
      "r = rc.get('/item?id=1')",
      "rc.log('in-scope', r.status)",
      "try:",
      "    rc.get('http://169.254.169.254/latest/meta-data/')",
      "    rc.log('reached out-of-scope')",
      "except rc.ScopeError as e:",
      "    rc.log('blocked', str(e))",
    ].join("\n");
    const r = await runPython(code, { guard: guard(), target: target(), isolation: "off" });
    expect(r.ok).toBe(true);
    expect(r.requests).toBe(1); // in-scope 1건만 실제 전송
    expect(r.blockedRequests).toBe(1); // out-of-scope 는 차단
    expect(r.logs.join(" ")).toMatch(/in-scope 200/);
    expect(r.logs.join(" ")).toMatch(/blocked/);
    expect(r.logs.join(" ")).not.toMatch(/reached out-of-scope/);
  });

  it("rc.finding 을 구조화 발견으로 파싱한다", async () => {
    const code = [
      "r = rc.get(\"/item?id=1'\")",
      "if 'SQL syntax' in r.text:",
      "    rc.finding('SQLi', severity='high', evidence=r.text[:40])",
    ].join("\n");
    const r = await runPython(code, { guard: guard(), target: target(), isolation: "off" });
    expect(r.ok).toBe(true);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ title: "SQLi", severity: "high" });
    expect(r.findings[0].evidence).toMatch(/SQL syntax/);
  });

  it("무한 루프는 타임아웃으로 강제 종료한다", async () => {
    const r = await runPython("while True:\n    pass", { guard: guard(), target: target(), isolation: "off", timeoutMs: 1200 });
    expect(r.timedOut).toBe(true);
    expect(r.ok).toBe(false);
  });

  it("요청 예산을 초과하면 브로커가 막는다", async () => {
    const code = [
      "blocked = 0",
      "for i in range(10):",
      "    try:",
      "        rc.get('/item?id=%d' % i)",
      "    except rc.ScopeError:",
      "        blocked += 1",
      "rc.log('blocked', blocked)",
    ].join("\n");
    const r = await runPython(code, { guard: guard(), target: target(), isolation: "off", maxRequests: 3 });
    expect(r.requests).toBe(3);
    expect(r.blockedRequests).toBeGreaterThanOrEqual(7);
  });
});

describe("broker: 리다이렉트 per-hop scope 재검증(우회 불가)", () => {
  // 대상이 scope 밖 호스트/포트로 3xx 리다이렉트해도, redirect='follow' 가 이를 따라가
  // scope 밖에 요청을 보내면 안 된다. 브로커는 최초 URL 뿐 아니라 각 리다이렉트 홉을
  // ScopeGuard 로 재검증해야 한다(SSRF/내부 메타데이터 도달 차단).
  let inScope: http.Server;
  let outScope: http.Server;
  let inPort: number;
  let outPort: number;
  let secretHit = false;

  beforeAll(async () => {
    outScope = http.createServer((_req, res) => {
      secretHit = true;
      res.statusCode = 200;
      res.end("SECRET-INTERNAL-DATA");
    });
    await new Promise<void>((r) => outScope.listen(0, "127.0.0.1", r));
    outPort = (outScope.address() as AddressInfo).port;

    inScope = http.createServer((_req, res) => {
      // scope 밖(다른 포트) 호스트로 리다이렉트.
      res.statusCode = 302;
      res.setHeader("location", `http://127.0.0.1:${outPort}/secret`);
      res.end();
    });
    await new Promise<void>((r) => inScope.listen(0, "127.0.0.1", r));
    inPort = (inScope.address() as AddressInfo).port;
  });
  afterAll(() => {
    inScope.close();
    outScope.close();
  });

  // 인가는 in-scope 포트만 허용(ports.allow_tcp) → out-scope 포트는 scope 밖.
  function portScopedGuard(): ScopeGuard {
    return new ScopeGuard({
      engagement: { name: "py", authorized_from: "2000-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
      scope: { allow: [{ host: "127.0.0.1" }] },
      ports: { allow_tcp: [inPort] },
      limits: { max_requests_per_second: 200 },
    });
  }

  it("redirect='follow' 로 scope 밖 홉을 따라가지 않는다(자격증명·요청 모두 미발송)", async () => {
    secretHit = false;
    const r = await runPython(
      ["r = rc.get('/start', redirect='follow')", "rc.log('status', r.status)"].join("\n"),
      { guard: portScopedGuard(), target: { host: "127.0.0.1", port: inPort }, isolation: "off" },
    );
    expect(r.ok).toBe(true);
    // scope 밖 서버는 절대 요청을 받지 않아야 한다.
    expect(secretHit).toBe(false);
    // 추종이 멈춰 3xx 가 그대로 반환된다.
    expect(r.logs.join(" ")).toMatch(/status 30\d/);
  });
});

describe("broker: OS 격리 fail-closed 정책(신뢰불가 코드 거부)", () => {
  // 이 환경(중첩 컨테이너)에는 동작하는 격리 백엔드가 없다. 따라서:
  //  - 신뢰불가(trusted=false) + isolation="required" → 실행 거부(fail-closed), 대상 통신 0건.
  //  - trusted=true(예: MockCoder) 또는 isolation="off" → 실행 허용.
  const safeCode = "r = rc.get('/')\nrc.log('status', r.status)";

  it("격리 백엔드 없이 신뢰불가 코드는 실행을 거부한다(요청 0건)", async () => {
    const r = await runPython(safeCode, { guard: guard(), target: target() }); // 기본 required·trusted 미설정
    expect(r.ok).toBe(false);
    expect(r.danger).toMatch(/격리|fail-closed/);
    expect(r.requests).toBe(0);
    expect(r.exitCode).toBeNull();
    expect(r.isolation?.backend).toBeNull();
  });

  it("trusted=true 면 격리 백엔드 없이도 실행한다(MockCoder 등 신뢰 어댑터 경로)", async () => {
    const r = await runPython(safeCode, { guard: guard(), target: target(), trusted: true });
    expect(r.danger).toBeUndefined();
    expect(r.exitCode).toBe(0);
    expect(r.requests).toBeGreaterThanOrEqual(1);
  });

  it('isolation="off" 면 격리 강제 없이 실행한다', async () => {
    const r = await runPython(safeCode, { guard: guard(), target: target(), isolation: "off" });
    expect(r.danger).toBeUndefined();
    expect(r.exitCode).toBe(0);
  });

  it('best-effort 는 백엔드 없어도 경고만 하고 실행한다', async () => {
    const r = await runPython(safeCode, { guard: guard(), target: target(), isolation: "best-effort" });
    expect(r.exitCode).toBe(0);
    expect(r.isolation?.warning).toMatch(/격리/);
  });
});

describe("PythonAgent: 코드 작성→실행→관찰 루프", () => {
  it("MockCoder 로 스스로 코드를 써가며 SQLi 를 발견한다", async () => {
    const events: string[] = [];
    const agent = new PythonAgent(guard(), new MockCoder(), {
      maxIterations: 5,
      onEvent: (e) => events.push(e.type),
    });
    const log = await agent.run(target(), "id 파라미터 취약점 탐색");
    expect(log.findings.some((f) => /SQL Injection/i.test(f.title) && f.severity === "high")).toBe(true);
    // 코드 시도(action) → 실행 결과(tool_result) → 발견(finding) 이벤트가 흘렀다.
    expect(events).toContain("action");
    expect(events).toContain("tool_result");
    expect(events).toContain("finding");
    // transcript 에 실제 작성한 파이썬 코드가 남는다(패널 표시용).
    expect(log.transcript.join("\n")).toMatch(/rc\.get/);
  });

  it("미인가 대상은 코드 실행 이전에 거부한다", async () => {
    const agent = new PythonAgent(guard(), new MockCoder(), { maxIterations: 3 });
    const log = await agent.run({ host: "10.99.99.99", port: 80 }, "테스트");
    expect(log.findings).toHaveLength(0);
    expect(log.transcript.join("\n")).toMatch(/거부/);
  });
});
