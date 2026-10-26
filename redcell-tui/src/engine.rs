//! 데스크톱 엔진 재사용 — P0 스윕(probes) + 지시문 가드레일(risk).
//! 소스를 그대로 include 하므로 규칙이 항상 데스크톱과 동일하다.

#[allow(dead_code)]
#[path = "../../redcell-desktop/src-tauri/src/probes.rs"]
pub mod probes;

#[allow(dead_code)]
#[path = "../../redcell-desktop/src-tauri/src/risk.rs"]
pub mod risk;
