import type { Tool, ToolBox } from "../core/types.js";
import { httpProbe } from "./http-probe.js";
import { dirEnum } from "./dir-enum.js";
import { headerAudit } from "./header-audit.js";
import { sqliProbe } from "./sqli-probe.js";
import { portScan } from "./port-scan.js";

/** 기본 툴 세트: 정찰→열거→익스플로잇 단계를 아우른다. */
export const DEFAULT_TOOLS: Tool[] = [httpProbe, headerAudit, portScan, dirEnum, sqliProbe];

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
