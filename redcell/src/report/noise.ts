/**
 * noise — 방어자 시점 요약.
 *
 * 이 실행이 대상의 관찰자( 접근 로그·WAF·IDS)에게 어떻게 보였는지 정리한다.
 * 목적은 은폐가 아니라 **인계**다: 인가된 점검이 끝나면 "그 시간대에 어떤 요청이
 * 몇 건, 어떤 상태코드로, 어떤 시그니처로 는지"를 그대로 블루팀/SOC 에 넘겨
 * 탐지 커버리지를 함께 검증한다. 흔적을 지우는 기능이 아니라 흔적을 문서화한다.
 *
 * 결정성: 세는 값은 요청 수·경로·상태코드이다(시각·응답시간은 넣지 않는다).
 * 같은 대상·같은 옵션이면 같은 요약이 나와야 보고서 재현성이 유지된다.
 * 주의: 여기서 세는 값은 RedCell 이 **보낸** 요청이다. 스머글링·파이프라이닝 페이로드는
 * 서버가 추가 요청으로 파싱할 수 있어, 대상 로그가 이 수보다 많게 보일 수 있다(그 자체가
 * 인계 시 같이 설명할 사실이다).
 */

/** 대상에 도달한 요청 1건(경로는 쿼리 포함, 상태는 최종 응답 코드). */
export interface NoiseSample {
  method: string;
  path: string;
  status: number;
}

/** 경로별 요청 수(대표 상태코드 포함). */
export interface NoisePathLine {
  path: string;
  /** 그 경로에서 가장 많이 본 상태코드(동률이면 작은 코드). */
  status: number;
  count: number;
}

export interface NoiseSummary {
  /** 대상에 보낸 요청 수(리다이렉트 홉 포함, 응답을 못 받은 시도 포함). */
  requests: number;
  /** 상태코드 묶음별 건수. */
  statuses: {
    ok2xx: number;
    redirect3xx: number;
    /** 401/403 — 대상이 접근통제로 거부한 요청. */
    denied: number;
    notFound: number;
    /** 429 — 방어 장치(레이트리밋)가 실제로 발동한 요청. */
    limited: number;
    other4xx: number;
    server5xx: number;
    /** 응답을 못 받은 시도(타임아웃·연결 종료) — 대상은 받았을 수 있다. */
    unanswered: number;
  };
  /** 요청이 많은 경로 상위 N(동률은 경로 사전순 → 결정적). */
  topPaths: NoisePathLine[];
  /** URL 에 시그니처성 페이로드가 들어간 요청 수(사실 기록). */
  signatureHits: number;
  /** 시그니처별 건수(많은 순, 동률은 이름 사전순). */
  signatures: Array<{ name: string; count: number }>;
  /** 사람이 읽는 요약 문장(블루 인계용). */
  notes: string[];
}

/**
 * 관찰자가 시그니처로 잡기 쉬운 형태. URL(경로+쿼리)만 본다 — 본문은 담지 않는다
 * (자격증명·개인정보를 요약에 옮기지 않기 위함). 이름은 무엇을 썼는지에 대한 사실 기록이다.
 */
export const SIGNATURE_RULES: Array<{ name: string; re: RegExp }> = [
  { name: "SQL 주입(불린/UNION/시간 지연)", re: /('|%27)\s*or\s|1\s*=\s*1|union\s+select|sleep\s*\(|benchmark\s*\(/i },
  { name: "XSS(스크립트 태그/이벤트 속성)", re: /<script|onerror\s*=|javascript:/i },
  { name: "경로 조작(상위 이동/시스템 파일)", re: /\.\.\/|%2e%2e|etc\/passwd|win\.ini/i },
  { name: "명령 주입(셸 메타문자/치환)", re: /[;|]\s*(cat|id|whoami|ls|echo)\b|\$\(|`/i },
  { name: "SSRF(메타데이터/파일 스킴)", re: /169\.254\.169\.254|file:\/\//i },
  { name: "템플릿 주입({{ }}, ${ })", re: /\{\{|\$\{/ },
  { name: "XXE(외부 엔티티)", re: /<!entity|<!doctype[^>]*system/i },
  { name: "JNDI 조회(로그4j 형태)", re: /\$\{jndi:/i },
];

/** 관찰 정보(URL·상태)를 요약용 표본으로 바꾼다(쿼리는 유지 — 시그니처 판정에 필요). */
export function toNoiseSample(o: { method: string; url: string; status: number }): NoiseSample {
  let path = o.url;
  try {
    const u = new URL(o.url);
    path = `${u.pathname}${u.search}`;
  } catch {
    // URL 파싱 실패 시 원문 유지(결정적).
  }
  return { method: o.method.toUpperCase(), path, status: o.status };
}

function emptyStatuses(): NoiseSummary["statuses"] {
  return { ok2xx: 0, redirect3xx: 0, denied: 0, notFound: 0, limited: 0, other4xx: 0, server5xx: 0, unanswered: 0 };
}

/** 상태코드 → 묶음 키. */
function bucketOf(status: number): keyof NoiseSummary["statuses"] | null {
  if (status === 0) return "unanswered"; // 응답 없음(타임아·연결 종료)
  if (status >= 200 && status < 300) return "ok2xx";
  if (status >= 300 && status < 400) return "redirect3xx";
  if (status === 401 || status === 403) return "denied";
  if (status === 404) return "notFound";
  if (status === 429) return "limited";
  if (status >= 500) return "server5xx";
  if (status >= 400) return "other4xx";
  return null; // 1xx 등
}

/**
 * 표본 → 방어자 시점 요약. 순수 함수(시각·난수 미사용) → 같은 입력이면 같은 출력.
 */
export function summarizeNoise(samples: NoiseSample[], opts: { top?: number } = {}): NoiseSummary {
  const top = Math.max(0, opts.top ?? 5);
  const statuses = emptyStatuses();
  const perPath = new Map<string, { count: number; byStatus: Map<number, number> }>();
  const sigCount = new Map<string, number>();
  let signatureHits = 0;

  for (const s of samples) {
    const b = bucketOf(s.status);
    if (b) statuses[b]++;
    const entry = perPath.get(s.path) ?? { count: 0, byStatus: new Map<number, number>() };
    entry.count++;
    entry.byStatus.set(s.status, (entry.byStatus.get(s.status) ?? 0) + 1);
    perPath.set(s.path, entry);
    for (const r of SIGNATURE_RULES) {
      if (r.re.test(s.path)) {
        sigCount.set(r.name, (sigCount.get(r.name) ?? 0) + 1);
        signatureHits++;
      }
    }
  }

  // 대표 상태코드: 최다 득표, 동률이면 작은 코드(결정적).
  const topPaths: NoisePathLine[] = [...perPath.entries()]
    .map(([path, e]) => {
      const ranked = [...e.byStatus.entries()].sort((a, b) => (b[1] - a[1]) || (a[0] - b[0]));
      return { path, status: ranked[0][0], count: e.count };
    })
    .sort((a, b) => (b.count - a.count) || a.path.localeCompare(b.path))
    .slice(0, top);

  const signatures = [...sigCount.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => (b.count - a.count) || a.name.localeCompare(b.name));

  const requests = samples.length;
  const notes: string[] = [];
  if (requests === 0) {
    notes.push("대상에 도달한 요청이 0건 — 기록된 관찰 신호가 없다.");
  } else {
    notes.push(
      `요청 ${requests}건 — 2xx ${statuses.ok2xx} · 3xx ${statuses.redirect3xx} · 401/403 ${statuses.denied} · ` +
        `404 ${statuses.notFound} · 429 ${statuses.limited} · 그 밖 4xx ${statuses.other4xx} · 5xx ${statuses.server5xx} · ` +
        `무응답 ${statuses.unanswered}`,
    );
    if (statuses.denied > 0) {
      notes.push(`접근 거부(401/403) ${statuses.denied}건 — 방어자 로그에 차단 신호로 남는다.`);
    }
    if (statuses.limited > 0) {
      notes.push(`레이트리밋(429) ${statuses.limited}건 — 방어 장치가 실제로 발동했다. 초당 요청 상한을 낮춰 다시 실행하는 편이 좋다.`);
    }
    if (statuses.server5xx > 0) {
      notes.push(`대상 오류(5xx) ${statuses.server5xx}건 — 운영 영향 여부를 대상 담당자와 확인해야 한다.`);
    }
    if (statuses.unanswered > 0) {
      notes.push(
        `응답을 못 받은 시도 ${statuses.unanswered}건 — 대상은 요청을 받았을 수 있으니 그 시간대 로그와 대조해야 한다.`,
      );
    }
    if (signatureHits > 0) {
      notes.push(
        `시그니처성 페이로드가 든 요청 ${signatureHits}건(URL 기준) — WAF/IDS 룰에 걸 수 있으니 탐지 여부를 블루팀에 확인한다.`,
      );
    }
  }
  return { requests, statuses, topPaths, signatureHits, signatures, notes };
}
