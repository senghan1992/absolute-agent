/**
 * profile — 시스템 텍스트 설명 → SystemProfile(구성요소/포트/플래그) 결정적 추출.
 *
 * 정규식 스캔 기반이다(모델 불필요, 오프라인 가능):
 *  - COMPONENT_DICT: 구성 요소 키워드 → 정규화 키 + 기본 포트.
 *  - FLAG_DICT: 속성 플래그(보안 통제 여부) → 패턴.
 *  - 버전/포트 패턴: 명시값을 그대로 마저. 추출 못한 것은 notes(확인 필요)로 남겨둔다.
 *
 * 설계 원칙: "추론"은 명시적으로 마크한다. 구성 요소의 기본 포트를 포트 목록에 더할 때
 * 원문에 그 포트가 없으면 notes 에 "기본 포트(추론)"을 남겨, 리포트에서 '확인 필요'로 구분한다.
 */
import fs from "node:fs";
import path from "node:path";
import type { ComponentRef, SystemProfile } from "./types.js";

/** 구성 요소 사전: 키워드(정규식) → 정규화 키, 원문 표기 라벨, 기본 포트(추론용). */
const COMPONENT_DICT: Array<{ key: string; re: RegExp; ports?: number[]; versionRe?: RegExp }> = [
  { key: "gitlab", re: /gitlab/i, versionRe: /gitlab\s*(?:버전|v)?\s*(\d{1,2}\.\d{1,3}(?:\.\d{1,3})?)/i },
  { key: "jenkins", re: /jenkins/i, ports: [8080, 9090] },
  { key: "grafana", re: /grafana/i, ports: [3000] },
  { key: "prometheus", re: /prometheus/i, ports: [9090] },
  { key: "kibana", re: /kibana/i, ports: [5601] },
  { key: "elasticsearch", re: /elasticsearch/i, ports: [9200] },
  { key: "nginx", re: /nginx/i, ports: [80, 443] },
  { key: "apache", re: /apache|httpd/i, ports: [80, 443] },
  { key: "mysql", re: /mysql/i, ports: [3306] },
  { key: "mariadb", re: /mariadb/i, ports: [3306] },
  { key: "postgresql", re: /postgres/i, ports: [5432] },
  { key: "redis", re: /redis/i, ports: [6379] },
  { key: "mongodb", re: /mongo(db)?/i, ports: [27017] },
  { key: "rabbitmq", re: /rabbitmq|amqp/i, ports: [5672, 15672] },
  { key: "kafka", re: /kafka/i, ports: [9092] },
  { key: "mqtt", re: /mqtt/i, ports: [1883, 8883] },
  { key: "ldap", re: /ldap/i, ports: [389, 636] },
  { key: "docker", re: /docker|컨테이너(?: 기반)?\s*서버|containerized/i, ports: [2375] },
  { key: "kubernetes", re: /kubernetes|k8s/i, ports: [6443] },
  { key: "etcd", re: /\betcd\b/i, ports: [2379, 2380] },
  { key: "haproxy", re: /haproxy/i, ports: [8404] },
  { key: "traefik", re: /traefik/i, ports: [8080] },
  { key: "consul", re: /consul/i, ports: [8500] },
  { key: "vault", re: /\bvault\b/i, ports: [8200] },
  { key: "minio", re: /minio/i, ports: [9000, 9001] },
  { key: "nextcloud", re: /nextcloud/i },
  { key: "wordpress", re: /wordpress/i },
  { key: "zabbix", re: /zabbix/i, ports: [10051] },
  { key: "sonarqube", re: /sonar(qube)?/i, ports: [9000] },
  { key: "smtp", re: /smtp|메일(?: 서버| 계정이 아닌| relay|relay)|mail relay/i, ports: [25, 587, 465] },
  { key: "ssh", re: /\bssh\b|서버 원격 접근/i, ports: [22] },
  { key: "graphql", re: /graphql/i },
  { key: "websocket", re: /websocket|\bws:\/\/|실시간 채팅/i, ports: [8083] },
  { key: "jwt", re: /\bJWT\b/ },
  { key: "static-app", re: /정적 (?:웹 ?)?앱|static (?:web )?app|싱글 페이지/i },
];

/**
 * 플래그 사전: (flag, 패턴 목록). 첫 패턴만 매치되면 flag.
 * 부정 플래그(no-mfa 등)는 "긍정 표현이 없으면 붙인다"는 특수 처리가 있다(아래 seeAbsent).
 */
const FLAG_DICT: Array<{ flag: string; re: RegExp[] }> = [
  {
    flag: "no-auth",
    re: [
      /no[\s-]?auth(entication|orization)?/i,
      /unauthenticated/i,
      /인가 없이/i,
      /인증 없이/i,
      /공개 액세스|개방형 접근/i,
      /open access/i,
    ],
  },
  {
    flag: "has-mfa",
    re: [/\bmfa\b/i, /\b2fa\b/i, /totp/i, /다중 (?:인증|인증기)/i, /multi[- ]?factor/i],
  },
  {
    flag: "default-creds",
    re: [/default (?:password|credentials|user)/i, /기본 (?:비밀번호|계정|자격증명)/i, /미변경 (?:비밀번호|계정)/i],
  },
  {
    flag: "debug",
    re: [/\bdebug (?:mode|build|flag)/i, /디버그 (?:모드|활성|켜)/i, /디버그가 켜져/i],
  },
  {
    flag: "exposed",
    re: [
      /internet(?:\s*facing)?/i,
      /public(?:ly)?\s+(?:exposed|accessible|facing)/i,
      /외부망(?:에)? (?:개방|노출|접근|서빙)/i,
      /인터넷에 (?:개방|노출)/i,
      /자주 (?:열어|개방)/i,
      /exposed/i,
    ],
  },
  {
    flag: "internal",
    re: [/internal only/i, /내부망만/i, /intranet/i, /외부 접근 불가/i],
  },
  {
    flag: "cloud",
    re: [/\baws\b/i, /\bgcp\b/i, /google cloud/i, /\bazure\b/i, /클라우드 (?:에|기반)/i, /cloud[- ]?hosted/i],
  },
  {
    flag: "container",
    re: [/\bdocker\b/i, /container(ized)?/i, /컨테이너/i, /kubernetes/i, /\bk8s\b/i],
  },
  {
    flag: "mobile",
    re: [/mobile (?:app|client)/i, /모바일 (?:앱|애플리케이션)/i, /\bandroid\b/i, /\bios app\b/i],
  },
  {
    flag: "http-only",
    re: [/http:\/\/(?!.*https)/i, /tls 없이/i, /비암호화/i, /unencrypted/i, /plain(?:text)?\s+(?:http|connection)/i],
  },
  {
    flag: "admin",
    re: [/admin(istrator)? panel/i, /관리자 (?:패널|화면|계정)/i, /admin (?:interface|ui|console)/i],
  },
  {
    flag: "secrets-in-code",
    re: [
      /secrets? (?:in|in the)\s+(?:repo|code|git)/i,
      /(?:시크릿|보관문|키|토큰)을?(?: 코드| 리포지토리| git)?에 (?:써넣|적|저장|넣)/i,
      /\.env\b/i,
      /committed (?:keys|tokens|secrets)/i,
    ],
  },
];

/** 부정 플래그: 긍정 표현(패턴)이 원문에 없으면 flag 를 붙인다. */
const ABSENT_FLAGS: Array<{ flag: string; positive: RegExp[] }> = [
  {
    flag: "no-mfa",
    positive: [/\bmfa\b/i, /\b2fa\b/i, /totp/i, /다중 (?:인증|인증기)/i, /multi[- ]?factor/i],
  },
];

/** 포트 패턴: "포트 9999", "port 8080", "9999 port", "9999번" */
const PORT_PATTERNS = [
  /(?:포트|port|ports)\s*[:=]?\s*(\d{2,5})\b/gi,
  /(\d{2,5})\s*(?:번|number)?\s*(?:포트|port)\b/gi,
  /on port\s*(\d{2,5})\b/gi,
];

/** 합리적 포트 범위(1..65535). */
function validPort(n: number): boolean {
  return n >= 1 && n <= 65535;
}

function uniqueNumbers(list: number[]): number[] {
  return [...new Set(list)].sort((a, b) => a - b);
}

/**
 * 시스템 텍스트 설명 → SystemProfile. 결정적이며 모델이 필요하다.
 * 원문에서 찾지 못한 내용은 profile.notes 에 "확인 필요" 단서로 남겨둔다.
 */
export function describeSystem(text: string, name?: string): SystemProfile {
  const raw = text.trim();
  const notes: string[] = [];

  // 1) 구성 요소 추출 + 버전 마저.
  const components: ComponentRef[] = [];
  for (const def of COMPONENT_DICT) {
    const m = raw.match(def.re);
    if (!m) continue;
    const label = m[0];
    let version: string | undefined;
    if (def.versionRe) {
      const vm = raw.match(def.versionRe);
      if (vm) version = vm[1];
    }
    components.push({ key: def.key, label, version });
  }

  // 2) 명시 포트 추출.
  const explicitPorts: number[] = [];
  for (const re of PORT_PATTERNS) {
    re.lastIndex = 0;
    for (const m of raw.matchAll(re)) {
      const p = parseInt(m[1], 10);
      if (validPort(p)) explicitPorts.push(p);
    }
  }

  // 3) 구성 요소별 기본 포트(추론) — 명시 포트와 겹치지 않는 것만 notes 로 표시하며 추가.
  const inferredPorts: number[] = [];
  for (const c of components) {
    const def = COMPONENT_DICT.find((d) => d.key === c.key);
    for (const p of def?.ports ?? []) {
      if (!explicitPorts.includes(p)) inferredPorts.push(p);
    }
  }
  const ports = uniqueNumbers([...explicitPorts, ...inferredPorts]);

  // 4) 플래그 추출.
  const flags = new Set<string>();
  for (const def of FLAG_DICT) {
    if (def.re.some((re) => re.test(raw))) flags.add(def.flag);
  }
  for (const def of ABSENT_FLAGS) {
    if (!def.positive.some((re) => re.test(raw))) {
      flags.add(def.flag);
      notes.push(`${def.flag} — 원문에 MFA 언급이 없어 '확인 필요'로 취급`);
    }
  }
  if (!flags.has("has-mfa") && !flags.has("no-mfa")) flags.add("no-mfa");

  // 5) 판단 못한 단서: 원문에 버전은 언급됐는데 인식되지 못한 것, "안전"이라는 표현 등.
  const versionMentions = raw.match(/\d{1,2}\.\d{1,3}(?:\.\d{1,3})/g);
  if (versionMentions && components.length === 0) {
    notes.push(`버전 기호 ${[...new Set(versionMentions)].join(", ")} 발견 — 어떤 구성 요소인지 확인 필요`);
  }
  const controlMentions = raw.match(
    /(waf|화이트리스트|allowlist|rate limit|레이트리밋|hsts|secure cookie|네트워크 분할|segmentation|isolation|분할|백업|monitoring|모니터링)/gi,
  );
  if (controlMentions) {
    notes.push(`방어 통제 언급: ${[...new Set(controlMentions.map((s) => s.toLowerCase()))].join(", ")}`);
  }

  return {
    name: name ?? (raw.split(/\s+/).slice(0, 6).join(" ") || "system"),
    raw,
    components,
    ports,
    flags: [...flags].sort(),
    notes,
  };
}

/**
 * 시스템 파일(JSON 또는 텍스트)에서 SystemProfile.
 *  - .json: { name?, description?, components?: [{name,version}], ports?, flags?, notes? } 구조.
 *    components.name 은 COMPONENT_DICT 키워드로 매핑해 key 를 부여한다.
 *  - 그 외: 파일 전체를 텍스트로 보고 describeSystem.
 */
export function parseProfileFile(filePath: string): SystemProfile {
  const abs = path.resolve(filePath);
  const text = fs.readFileSync(abs, "utf8");
  if (abs.toLowerCase().endsWith(".json")) {
    const obj = JSON.parse(text) as {
      name?: string;
      description?: string;
      components?: Array<{ name: string; version?: string }>;
      ports?: number[];
      flags?: string[];
      notes?: string[];
    };
    const profile = describeSystem(obj.description ?? "", obj.name);
    for (const c of obj.components ?? []) {
      const hit = COMPONENT_DICT.find((d) => new RegExp(d.key, "i").test(c.name));
      profile.components.push({
        key: hit?.key ?? c.name.toLowerCase(),
        label: c.name,
        version: c.version,
      });
    }
    profile.components = dedupeComponents(profile.components);
    profile.ports = uniqueNumbers([...profile.ports, ...(obj.ports ?? []).filter(validPort)]);
    profile.flags = [...new Set([...profile.flags, ...(obj.flags ?? [])])].sort();
    profile.notes = [...profile.notes, ...(obj.notes ?? [])];
    profile.name = obj.name ?? profile.name;
    return profile;
  }
  return describeSystem(text);
}

function dedupeComponents(list: ComponentRef[]): ComponentRef[] {
  const byKey = new Map<string, ComponentRef>();
  for (const c of list) byKey.set(c.key, byKey.get(c.key) ?? c);
  return [...byKey.values()];
}

/** 프로필에서 구성 요소를 판정(키 또는 라벨 매칭, 대소문자 무시). */
export function hasComponent(profile: SystemProfile, key: string): boolean {
  return profile.components.some((c) => c.key === key || c.label.toLowerCase().includes(key.toLowerCase()));
}

/** 프로필에 포트가 있거나(보유) 또는 구성 요소의 기본 포트(추론)에 포함되는지. */
export function portHeld(profile: SystemProfile, port: number): boolean {
  return profile.ports.includes(port);
}

/** 플래그 존재 판정. */
export function hasFlag(profile: SystemProfile, flag: string): boolean {
  return profile.flags.includes(flag);
}
