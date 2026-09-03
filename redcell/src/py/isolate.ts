/**
 * py/isolate — pyrun 페이로드를 위한 OS 레벨 격리 백엔드.
 *
 * 왜 필요한가: in-process AST 허용목록 샌드박스(broker.ts)는 알려진 탈출을 닫지만
 * CPython 인트로스펙션 표면이 넓어 "구성적으로 불가능"을 보장하지 못한다. pyrun 이 돌리는
 * 코드는 **LLM 이 작성**하고, 그 LLM 은 **공격 대상의 응답을 컨텍스트로 삼는다**(프롬프트
 * 인젝션 경로). 따라서 신뢰불가 코드로 취급해야 하며, 탈출이 발생해도 호스트가 털리지
 * 않도록 OS 레벨 경계(네임스페이스/샌드박스)를 둔다.
 *
 * 이 모듈은 **런타임에 실제 동작하는 백엔드를 탐지**한다(설치 여부가 아니라 실제 실행 성공).
 * 커널이 비특권 네임스페이스를 막은 환경(중첩 컨테이너 등)에서는 bwrap 이 설치돼 있어도
 * 동작하지 않으므로, 반드시 probe 로 확인한다. 백엔드가 없으면 상위(runPython)가
 * fail-closed 정책으로 신뢰불가 코드 실행을 거부한다.
 */

import { spawn } from "node:child_process";

export interface IsolationBackend {
  /** 백엔드 이름(리포트/감사 로그용). */
  name: string;
  /**
   * 주어진 실행 argv 를 샌드박스 안에서 돌도록 감싼 argv 로 변환한다.
   * workDir 는 rw 로 바인드되고 그 외 파일시스템은 read-only/tmpfs 로 최소화된다.
   */
  wrap(argv: string[], workDir: string): string[];
  /** 파일시스템/프로세스 격리를 제공하는가(호스트 FS 읽기·쓰기·영속 차단). */
  fsIsolated: boolean;
  /** IP 네트워크 egress 를 물리적으로 차단하는가(현재 백엔드는 브로커 TCP 를 위해 net 공유 → false). */
  networkIsolated: boolean;
}

let cached: IsolationBackend | null | undefined;

/** 실제로 동작하는 격리 백엔드를 탐지(결과 캐시). 없으면 null. */
export async function detectIsolation(): Promise<IsolationBackend | null> {
  if (cached !== undefined) return cached;
  cached = (await probeBwrap()) ?? null;
  return cached;
}

/** 테스트용: 탐지 캐시 초기화. */
export function _resetIsolationCache(): void {
  cached = undefined;
}

/** bwrap 이 이 환경에서 실제로 네임스페이스를 만들 수 있는지 실행으로 확인한다. */
async function probeBwrap(): Promise<IsolationBackend | null> {
  const ok = await tryRun("bwrap", [
    "--ro-bind", "/usr", "/usr",
    "--ro-bind-try", "/bin", "/bin",
    "--ro-bind-try", "/lib", "/lib",
    "--ro-bind-try", "/lib64", "/lib64",
    "--proc", "/proc",
    "--dev", "/dev",
    "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
    "--die-with-parent",
    "/bin/true",
  ]);
  if (!ok) return null;
  return {
    name: "bubblewrap",
    fsIsolated: true,
    networkIsolated: false, // 브로커(127.0.0.1 TCP) 도달을 위해 net 은 공유한다.
    wrap(argv, workDir) {
      // 호스트 FS 는 read-only 최소 노출, /tmp 는 tmpfs, 작업 디렉터리만 rw.
      // 사용자/PID/IPC/UTS 네임스페이스 분리 + 부모와 함께 종료 + 새 세션.
      return [
        "bwrap",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind-try", "/bin", "/bin",
        "--ro-bind-try", "/sbin", "/sbin",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind-try", "/etc/alternatives", "/etc/alternatives",
        "--ro-bind-try", "/etc/ssl", "/etc/ssl",
        "--ro-bind-try", "/root/.pyenv", "/root/.pyenv",
        "--ro-bind-try", "/usr/local", "/usr/local",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--bind", workDir, workDir,
        "--chdir", workDir,
        "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
        "--die-with-parent", "--new-session",
        "--",
        ...argv,
      ];
    },
  };
}

function tryRun(cmd: string, args: string[]): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: boolean) => {
      if (!done) {
        done = true;
        resolve(v);
      }
    };
    try {
      const child = spawn(cmd, args, { stdio: "ignore" });
      child.on("error", () => finish(false));
      child.on("close", (code) => finish(code === 0));
      setTimeout(() => {
        child.kill("SIGKILL");
        finish(false);
      }, 4000);
    } catch {
      finish(false);
    }
  });
}
