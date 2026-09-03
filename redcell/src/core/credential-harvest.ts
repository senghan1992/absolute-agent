/**
 * CredentialHarvester — 발견 체이닝(finding chaining)의 핵심.
 *
 * 한 툴이 노출시킨 자격증명(JWT/API 키/세션)을 주워, **다음 툴 요청에 실어** 로그인 뒤
 * 표면까지 이어서 점검한다. "노출된 .env → 그 키로 인증된 API 접근" 같은 실제 공격 체인을
 * 자동으로 잇는다. 오직 대상 자신이 흘린 값만 재사용한다(외부 유입 없음, 비파괴).
 *
 * 안전 원칙:
 *   - 대상이 응답/노출한 값만 수집(우리가 만들어내지 않음).
 *   - 헤더로 그대로 쓸 수 있는 형태(Bearer/쿠키/키)만 채택 — 로그인 자동화(폼 POST)는 하지 않는다.
 *   - 이미 인가 파일 credentials 가 있으면 그것을 덮지 않는다(운영자 의도 우선).
 */

const JWT_RE = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/;
/** .env/설정 노출에서 자주 보이는 키. `KEY=value` 또는 `"key": "value"`. */
const KEY_PATTERNS: Array<{ re: RegExp; header: string; label: string }> = [
  { re: /\b(?:api[_-]?key|apikey|x[_-]?api[_-]?key)\b["'\s:=]+([A-Za-z0-9._\-]{12,})/i, header: "x-api-key", label: "API 키" },
  { re: /\b(?:access[_-]?token|auth[_-]?token)\b["'\s:=]+([A-Za-z0-9._\-]{12,})/i, header: "authorization", label: "액세스 토큰" },
];

export interface Harvest {
  headers: Record<string, string>;
  notes: string[];
}

/**
 * 문자열(툴 요약/증거/본문 스니펫)에서 재사용 가능한 자격증명을 추출한다.
 * `existing` 에 이미 있는 헤더는 건드리지 않는다.
 */
export function harvestCredentials(text: string, existing: Record<string, string> = {}): Harvest {
  const headers: Record<string, string> = {};
  const notes: string[] = [];
  if (!text) return { headers, notes };

  const jwt = JWT_RE.exec(text);
  if (jwt && !("authorization" in existing)) {
    headers["authorization"] = `Bearer ${jwt[0]}`;
    notes.push("노출된 JWT 를 Bearer 로 채택");
  }
  for (const { re, header, label } of KEY_PATTERNS) {
    if (header in existing || header in headers) continue;
    const m = re.exec(text);
    if (m) {
      headers[header] = header === "authorization" ? `Bearer ${m[1]}` : m[1];
      notes.push(`노출된 ${label}를 ${header} 헤더로 채택`);
    }
  }
  return { headers, notes };
}

/** ToolResult 유사 객체에서 검사 대상 텍스트를 모은다(요약+증거+data 직렬화 일부). */
export function harvestFromResult(res: { summary?: string; data?: unknown }): Harvest {
  const parts = [res.summary ?? ""];
  const d = res.data as { evidence?: string } | undefined;
  if (d?.evidence) parts.push(d.evidence);
  try {
    parts.push(JSON.stringify(res.data).slice(0, 4000));
  } catch {
    /* 직렬화 불가 무시 */
  }
  return harvestCredentials(parts.join("\n"));
}
