/**
 * target-map — 정찰(crawl) 표면 → 공격 툴 인자 자동 배선(P0-1) 회귀 테스트.
 *
 * crawl 이 fingerprint.indicators 에 남긴 endpoint 를 인젝션/탐지 툴의 paths/params 로
 * 자동 변환해, 운영자 개입 없이 발견된 표면 전체를 발산 스윕하는지 확인한다.
 */

import { describe, it, expect } from "vitest";
import { endpointsFrom, surfaceFrom, deriveArgs } from "../src/core/target-map.js";

const IND = [
  "endpoint /item?id=1",
  "endpoint /search?q=x&cat=books",
  "endpoint /api/orders/1000",
  "endpoint /login",
  "noise (무시)",
];

describe("target-map 자동 배선", () => {
  it("indicators 에서 endpoint 경로만 추출한다", () => {
    expect(endpointsFrom(IND)).toEqual(["/item?id=1", "/search?q=x&cat=books", "/api/orders/1000", "/login"]);
    expect(endpointsFrom([])).toEqual([]);
  });

  it("표면을 경로/파라미터/ID경로로 분해한다", () => {
    const s = surfaceFrom(IND);
    expect(s.paths).toContain("/item");
    expect(s.paths).toContain("/login");
    expect(s.paramPaths).toContain("/item");
    expect(s.paramPaths).toContain("/search");
    expect(s.paramPaths).not.toContain("/login"); // 파라미터 없음
    expect(s.params).toEqual(expect.arrayContaining(["id", "q", "cat"]));
    expect(s.idPath).toBe("/api/orders/1000"); // 숫자 id 로 끝나는 경로
  });

  it("인젝션 툴은 파라미터 경로 전체 + 파라미터명을 스윕 인자로 받는다", () => {
    const a = deriveArgs("sqli_probe", IND);
    expect(a.paths).toEqual(expect.arrayContaining(["/item", "/search"]));
    expect(a.params).toEqual(expect.arrayContaining(["id", "q", "cat"]));
  });

  it("idor_probe 는 숫자 id 경로를 단일 path 로 받는다", () => {
    expect(deriveArgs("idor_probe", IND)).toEqual({ path: "/api/orders/1000" });
  });

  it("경로만 필요한 툴(host_header_audit)은 단일 path 를 받는다", () => {
    const a = deriveArgs("host_header_audit", IND);
    expect(typeof a.path).toBe("string");
  });

  it("표면 정보가 없으면 빈 인자({})를 반환해 툴 기본값을 쓰게 한다", () => {
    expect(deriveArgs("sqli_probe", [])).toEqual({});
    expect(deriveArgs("idor_probe", [])).toEqual({});
  });

  it("배선 규칙에 없는 툴(access_control_probe)은 자체 기본값을 쓰도록 빈 인자를 준다", () => {
    expect(deriveArgs("access_control_probe", IND)).toEqual({});
  });
});
