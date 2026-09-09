import type { Tool, ToolBox } from "../core/types.js";
import { httpProbe } from "./http-probe.js";
import { dirEnum } from "./dir-enum.js";
import { headerAudit } from "./header-audit.js";
import { sqliProbe } from "./sqli-probe.js";
import { portScan } from "./port-scan.js";
import { apiDiscover } from "./api-discover.js";
import { apiProbe } from "./api-probe.js";
import { cookieAudit } from "./cookie-audit.js";
import { corsAudit } from "./cors-audit.js";
import { secretScan } from "./secret-scan.js";
import { graphqlProbe } from "./graphql-probe.js";
import { xssProbe } from "./xss-probe.js";
import { pathTraversal } from "./path-traversal.js";
import { openRedirect } from "./open-redirect.js";
import { ssrfProbe } from "./ssrf-probe.js";
import { idorProbe } from "./idor-probe.js";
import { wafDetect } from "./waf-detect.js";
import { crawl } from "./crawl.js";
import { sstiProbe } from "./ssti-probe.js";
import { cmdiProbe } from "./cmdi-probe.js";
import { xxeProbe } from "./xxe-probe.js";
import { jwtAudit } from "./jwt-audit.js";
import { csrfAudit } from "./csrf-audit.js";
import { uploadProbe } from "./upload-probe.js";
import { methodAudit } from "./method-audit.js";
import { hostHeaderAudit } from "./host-header-audit.js";
import { accessControlProbe } from "./access-control.js";
import { paramPollution } from "./param-pollution.js";
import { deserializeProbe } from "./deserialize-probe.js";
import { authSessionProbe } from "./auth-session-probe.js";
import { cachePoisonProbe } from "./cache-poison-probe.js";
import { nosqlProbe } from "./nosql-probe.js";
import { crlfProbe } from "./crlf-probe.js";
import { protoPollutionProbe } from "./proto-pollution-probe.js";
import { storedXssProbe } from "./stored-xss-probe.js";
import { uploadVerify } from "./upload-verify.js";
import { raceProbe } from "./race-probe.js";
import { logicProbe } from "./logic-probe.js";
import { smuggleProbe } from "./smuggle-probe.js";
import { cacheDeceptionProbe } from "./cache-deception-probe.js";
import { jwtAttack } from "./jwt-attack.js";

/**
 * 기본 툴 세트: 정찰→열거→익스플로잇 단계를 다양한 벡터로 아우른다(intent 기준 분류).
 *   recon:     http_probe, header_audit, api_discover, cookie_audit, waf_detect, crawl, jwt_audit
 *   enumerate: dir_enum, api_probe, port_scan, cors_audit, secret_scan, graphql_probe, csrf_audit,
 *              upload_probe, http_method_audit, host_header_audit, deserialize_probe, auth_session_probe
 *   exploit:   sqli_probe, xss_probe, path_traversal, open_redirect, ssrf_probe, idor_probe, ssti_probe,
 *              cmdi_probe, xxe_probe, access_control_probe, param_pollution, cache_poison_probe, logic_probe
 */
export const DEFAULT_TOOLS: Tool[] = [
  // recon
  httpProbe,
  headerAudit,
  apiDiscover,
  cookieAudit,
  wafDetect,
  crawl,
  jwtAudit,
  // enumerate
  dirEnum,
  apiProbe,
  portScan,
  corsAudit,
  secretScan,
  graphqlProbe,
  csrfAudit,
  uploadProbe,
  methodAudit,
  hostHeaderAudit,
  deserializeProbe,
  authSessionProbe,
  // exploit
  sqliProbe,
  xssProbe,
  pathTraversal,
  openRedirect,
  ssrfProbe,
  idorProbe,
  sstiProbe,
  cmdiProbe,
  xxeProbe,
  accessControlProbe,
  paramPollution,
  cachePoisonProbe,
  logicProbe,
  nosqlProbe,
  crlfProbe,
  protoPollutionProbe,
  storedXssProbe,
  uploadVerify,
  raceProbe,
  smuggleProbe,
  cacheDeceptionProbe,
  jwtAttack,
];
/**
 * 명시적 opt-in 이 필요한 툴(대상별 승인 뒤에만 자동 실행).
 *   - logic_probe        : 가격/수량/권한 파라미터에 비정상 값을 주입한다. 읽기 관찰만이라도
 *                          결제/주문/권한 로직을 건드릴 수 있어(부작용·상태변경 위험) 대상별 동의가 필요.
 *   - cache_poison_probe : 고유 cache-buster 로 blast radius=0 을 설계하지만, 캐시 계층을 오염시키는
 *                          성격상 운영 캐시/CDN 앞단 대상에서는 오탐·부작용 위험이 있어 opt-in 으로 둔다.
 *   - stored_xss_probe   : 저장(POST)을 실제로 수행한다 — 상태변경 수반.
 *   - upload_verify      : 파일 업로드를 실제로 수행한다 — 상태변경 수반.
 *   - race_probe         : 상태를 실제로 변경(단일+동시 3회)한다 — 상태변경 수반.
 * 자율 드라이버(AutoPilot)·모델 드라이버(Orchestrator)는 이 목록의 툴을 opt-in 없이는 실행하지 않는다.
 * (authorization.yaml 의 optional_probes 또는 CLI --enable 로 대상별로 켠다.)
 */
export const OPT_IN_TOOLS: ReadonlySet<string> = new Set(["logic_probe", "cache_poison_probe", "stored_xss_probe", "upload_verify", "race_probe"]);

/** 기본 툴 레지스트리. 새 툴을 추가하려면 여기에 등록한다. */
export class DefaultToolBox implements ToolBox {
  private tools = new Map<string, Tool>();

  constructor(tools: Tool[] = DEFAULT_TOOLS) {
    for (const t of tools) this.tools.set(t.name, t);
  }

  register(tool: Tool): void {
    this.tools.set(tool.name, tool);
  }

  get(name: string): Tool | undefined {
    return this.tools.get(name);
  }

  list(): Tool[] {
    return [...this.tools.values()];
  }
}
