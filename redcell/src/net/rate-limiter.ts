/**
 * RateLimiter + 동시성 유틸 — 성능(병렬 스캔)과 안전(RPS 상한)을 동시에.
 *
 * 동시 실행을 허용하되 초당 요청수(RPS)를 토큰버킷으로 전역 제한한다.
 * 여러 툴/스캐너가 이 하나의 리미터를 공유하면 폭주 없이 최대 처리량을 낸다.
 */

export class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private queue: Array<() => void> = [];

  constructor(
    private readonly rps: number,
    private readonly burst: number = Math.max(1, rps),
  ) {
    this.tokens = this.burst;
    this.lastRefill = Date.now();
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    if (elapsed <= 0) return;
    this.tokens = Math.min(this.burst, this.tokens + elapsed * this.rps);
    this.lastRefill = now;
  }

  /** 토큰 하나를 소비할 수 있을 때까지 대기 */
  async acquire(): Promise<void> {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return;
    }
    // 부족하면 대기 후 재시도
    const waitMs = Math.ceil(((1 - this.tokens) / this.rps) * 1000);
    await new Promise<void>((resolve) => {
      this.queue.push(resolve);
      setTimeout(() => {
        const r = this.queue.shift();
        r?.();
      }, Math.max(1, waitMs));
    });
    return this.acquire();
  }
}

/**
 * 동시성 상한을 두고 배열을 매핑. 각 작업은 최대 `concurrency`개까지 병렬 실행.
 * (RPS 는 RateLimiter 로, 병렬 개수는 이 함수로 제어)
 */
export async function mapLimit<T, R>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const workers: Promise<void>[] = [];
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  };
  const n = Math.max(1, Math.min(concurrency, items.length));
  for (let w = 0; w < n; w++) workers.push(worker());
  await Promise.all(workers);
  return results;
}
