# 외부 벤치 매니페스트

외부 독립 타겟용 기대·미스 선언. 정답지(`bench_run.py`)와 달리 완전한
ground truth가 없으므로 **관측된 참값에서만 기대를 도출**하고,
미탐은 `known_misses`에 사유와 함께 기록한다 (조용한 미탐 금지).

## 필드

- `id`: 벤치 ID (파일명과 일치 권장).
- `target`: 스윕 대상 URL.
- `authorized`: 테스트 승인 근거 (공개 데모·운영자 승인 등). 반드시 기재.
- `sweep_args`: sweep 인자 배열 (외부·공유 대상은 `--rps 5 --threads 4` 이하 권장).
- `timeout`: 실행 타임아웃 초 (기본 420).
- `clean`: true면 high/critical 1건이라도 FP-CLEAN 실패.
- `expected[]`: 기대 발견.
  - `id`, `category`, `min_severity`, `target_contains`, `title_contains`.
  - 기대는 **실측에서 확인된 참값**만 등록한다. 추측 등록 금지.
- `known_misses[]`: 알지만 못 잡는 항목 (`id`, `target`, `reason`).
  - 해소되면 expected로 승격하고 이 기록은 제거한다.

## 실행

```sh
cd redcell-desktop/gate
python3 extbench.py [sweep 바이너리] [manifest ...] [--twice] [--out DIR]
```

- `--twice`: 동일 타겟 2회 실행 후 지문 다중집합 비교 (결정성).
- 기대外 high/critical은 REVIEW로 보고 (수동 트리아지, 자동 실패 아님).
