/**
 * @earendil-works/pi-coding-agent 최소 타입 폴백.
 *
 * RedCell 확장을 이 저장소 단독으로 타입체크하기 위한 ambient 선언이다.
 * prime-agent 체크아웃 안에서 로드될 때는 실제 패키지 타입이 이 선언을 대체한다.
 * (문서: packages/coding-agent/src/core/extensions/types.ts)
 */
declare module "@earendil-works/pi-coding-agent" {
  import type { TSchema, Static } from "@sinclair/typebox";

  export interface ExtensionContext {
    ui?: { info?(msg: string): void; warn?(msg: string): void };
    hasUI?: boolean;
    cwd: string;
    abort(): void;
    getSystemPrompt?(): string;
    [key: string]: unknown;
  }

  export interface AgentToolResult<T = unknown> {
    content: Array<{ type: "text"; text: string } | { type: "image"; [k: string]: unknown }>;
    details: T;
    isError?: boolean;
    terminate?: boolean;
  }

  export interface ToolDefinition<TParams extends TSchema = TSchema, TDetails = unknown, TState = unknown> {
    name: string;
    label: string;
    description: string;
    promptSnippet?: string;
    promptGuidelines?: string[];
    parameters: TParams;
    executionMode?: "sequential" | "parallel";
    prepareArguments?(args: unknown): Static<TParams>;
    execute(
      toolCallId: string,
      params: Static<TParams>,
      signal?: AbortSignal,
      onUpdate?: (u: unknown) => void,
      ctx?: ExtensionContext,
    ): Promise<AgentToolResult<TDetails>>;
  }

  export function defineTool<TParams extends TSchema, TDetails = unknown, TState = unknown>(
    tool: ToolDefinition<TParams, TDetails, TState>,
  ): ToolDefinition<TParams, TDetails, TState>;

  export interface RegisteredCommand {
    description?: string;
    handler(ctx: ExtensionContext, args?: string): Promise<void> | void;
  }

  export type ToolCallHookResult = { block: true; reason: string } | void;

  export interface ExtensionAPI {
    on(event: "tool_call", handler: (event: any, ctx: ExtensionContext) => Promise<ToolCallHookResult> | ToolCallHookResult): void;
    on(event: string, handler: (event: any, ctx: ExtensionContext) => unknown): void;
    registerTool?(tool: ToolDefinition<any, any, any>): void;
    registerCommand?(name: string, options: Omit<RegisteredCommand, "name">): void;
    appendSystemPrompt?(text: string): void;
    [key: string]: unknown;
  }

  export type ExtensionFactory = (pi: ExtensionAPI) => void | Promise<void>;
}
