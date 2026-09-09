import { describe, it, expect } from "vitest";
import { verifyExposure, verificationBadge } from "../../src/assault/verify.js";

describe("assault verifyExposure — 검증 엔진", () => {
  it("secret: 자격증명 키-값이 있으면 실증(verified), proof 는 마스킹된다", () => {
    const raw = [
      "PORT=8080",
      "DB_HOST=127.0.0.1",
      "DB_USER=admin",
      "DB_PASSWORD=supersecretkey",
      "JWT_SECRET=abcdefghijklmnopqrstuvwxyz123456",
    ].join("\n");
    const v = verifyExposure("secret", raw);
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("자격증명 형식 항목 3개");
    expect(v.proof).toContain("DB_PASSWORD=supe…ey");
    expect(v.proof).not.toContain("supersecretkey");
    expect(v.proof).not.toContain("abcdefghijklmnopqrstuvwxyz123456");
  });

  it("secret: --no-redact(redact:false) 이면 proof 에 원문이 남는다", () => {
    const v = verifyExposure("secret", "DB_PASSWORD=supersecretkey\n", { redact: false });
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("supersecretkey");
  });

  it("secret: 자격증명 키가 없으면 징후(partial), 값이 없으면 미확인", () => {
    expect(verifyExposure("secret", "APP_NAME=acme\nREGION=ap-northeast-2\n").status).toBe("partial");
    expect(verifyExposure("secret", "hello world\n").status).toBe("unverified");
  });

  it("secret: 이메일 같은 실제 개인정보 패턴은 proof 에서 마스킹된다", () => {
    const v = verifyExposure("secret", "ADMIN_MAIL=kim@corp.local\nADMIN_PASSWORD=hunter2\n");
    expect(v.status).toBe("verified");
    expect(v.proof).not.toContain("kim@");
  });

  it("error: DB 엔진 지문을 식별하면 실증", () => {
    const v = verifyExposure("error", "SQLSTATE[42000]: Syntax error in query near ' or 1=1 --");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("MySQL/MariaDB");
    expect(v.proof).toContain("SQLSTATE");
    const or = verifyExposure("error", "ORA-00933: SQL command not properly ended");
    expect(or.status).toBe("verified");
    expect(or.proof).toContain("Oracle");
  });

  it("error: UNION 데이터 추출 실증 라인은 검증된 착취(verified)로 배지가 올라간다", () => {
    const v = verifyExposure("error", "SQLSTATE[42000] ... in mysql query\nUNION 데이터 추출 실증: MySQL/MariaDB 8.0.32 (컬럼 1개)");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("UNION 실증");
    expect(v.proof).toContain("8.0.32");
    expect(v.proof).toContain("검증된 착취");
  });

  it("error: 엔진 미식별이면 징후, DB 신호 없으면 미확인", () => {
    expect(verifyExposure("error", "Error: invalid query").status).toBe("partial");
    expect(verifyExposure("error", "just a page").status).toBe("unverified");
  });

  it("pii: distinct ≥2 또는 민감 필드면 실증", () => {
    const v = verifyExposure("pii", "무인증으로 id 1,2 가 서로 다른 사적 객체 반환(distinct=2, 개인정보 신호 2건)\n후보 id: 1, 2");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("2건");
    const v2 = verifyExposure("pii", "GET /users/1 → 200 fields=id,name,email,ssn 민감=email,ssn");
    expect(v2.status).toBe("verified");
    expect(v2.proof).toContain("민감 필드");
  });

  it("pii: 개인정보 신호가 없으면 징후/미확인", () => {
    expect(verifyExposure("pii", "후보 id: 7, 8, 9").status).toBe("partial");
    expect(verifyExposure("pii", "nothing here").status).toBe("unverified");
  });

  it("schema: introspection 구조 확인 시 실증", () => {
    const v = verifyExposure("schema", "introspection 성공 — query 타입 4개, mutation 2개 확인");
    expect(v.status).toBe("verified");
    const v2 = verifyExposure("schema", "graphql endpoint found");
    expect(v2.status).toBe("partial");
    const v3 = verifyExposure("schema", "");
    expect(v3.status).toBe("unverified");
  });

  it("config/backup/endpoint: 본문 확보 시 실증, 빈 본문은 미확인", () => {
    expect(verifyExposure("config", '{"env":"prod","debug":false}').status).toBe("verified");
    expect(verifyExposure("backup", "main.go\nfunc main() {\n  fmt.Println(1)\n}\n").status).toBe("verified");
    expect(verifyExposure("endpoint", "/admin returns 200 with login form").status).toBe("verified");
    expect(verifyExposure("endpoint", "  ").status).toBe("unverified");
  });

  it("endpoint: dir_enum 경로 목록은 본문이 아니라 접근 결과로 검증한다", () => {
    const v = verifyExposure("endpoint", "/admin → 200; /.env → 200; /tmp → 403");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("2/3건 200");
    expect(v.proof).not.toContain("본문 확보");
    const v2 = verifyExposure("config", "/x → 404; /y → 404");
    expect(v2.status).toBe("partial");
  });

  it("endpoint: 응답은 있으나 본문이 빈약하면 징후", () => {
    expect(verifyExposure("endpoint", "ok").status).toBe("partial");
  });

  it("빈 본문은 모든 분류에서 미확인", () => {
    for (const c of ["secret", "pii", "schema", "config"] as const) {
      expect(verifyExposure(c, "")).toEqual({ status: "unverified", proof: "본문 미확보 — 수동 확인 필요" });
    }
  });

  it("배지 문자열: verified → ✅ 실증", () => {
    expect(verificationBadge("verified")).toBe("✅ 실증");
    expect(verificationBadge("partial")).toBe("⚠️ 징후");
    expect(verificationBadge("unverified")).toBe("❓ 미확인");
  });
});
describe("assault verifyExposure — 익스플로잇(exploit) 실증", () => {
  it("xss: 실행 가능 문맥 반사 마커 → verified, proof 에 XSS 실증 접두사", () => {
    const v = verifyExposure("exploit", "무해 마커가 HTML/JS 컨텍스트에 실행 가능하게 반사됨 (/, 태그/속성 breakout): rcabc123");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("XSS 실증:");
    expect(v.proof).toContain("context=태그/속성 breakout");
  });

  it("ssti: 산술 평가 결과 노출 → verified", () => {
    const v = verifyExposure("exploit", "산술식이 서버에서 평가되어 결과 58054189 노출 (path=/, payload={{7919*7331}})");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("SSTI 실증:");
    expect(v.proof).toContain("58054189");
  });

  it("ssrf: 메타데이터 시그니처 반사 → verified", () => {
    const v = verifyExposure("exploit", "메타데이터 시그니처가 응답에 반사됨 (path=/, target=http://169.254.169.254/latest/meta-data/)");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("SSRF 실증:");
    expect(v.proof).toContain("169.254.169.254");
  });

  it("lfi: /etc/passwd root 라인 시그니처 → verified(uid 0), 원문 라인은 proof 에 미노출", () => {
    const v = verifyExposure("exploit", "unix /etc/passwd 시그니처 노출 (path=/, payload=../../../../../../etc/passwd): root:x:0:0:0:root:/root:/bin/bash");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("LFI 실증:");
    expect(v.proof).toContain("root");
    expect(v.proof).not.toContain("x:0:0:0");
  });

  it("redirect: Location 의 canary 도메인 → verified", () => {
    const v = verifyExposure("exploit", "HTTP 302 Location: https://trusted.example.com@redcell-canary.example.net/");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("오픈 리다이렉트 실증:");
    expect(v.proof).toContain("redcell-canary.example.net");
  });

  it("xxe: 내부 엔티티 확장 마커 → verified", () => {
    const v = verifyExposure("exploit", "내부 엔티티가 확장되어 마커 반사됨 → 외부 엔티티(파일/SSRF) 처리 가능성. 서버측 DTD 비활성 권고.");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("XXE 실증:");
  });

  it("실증 마커 없이 신호 문자열만 있으면 partial, 무관 본문은 unverified", () => {
    expect(verifyExposure("exploit", "무언가 반사/주입된 것 같은 문자열").status).toBe("partial");
    expect(verifyExposure("exploit", "일반 문서 내용입니다").status).toBe("unverified");
    expect(verifyExposure("exploit", "").status).toBe("unverified");
  });
});
