fn main() {
    tauri_build::build();
    build_netfilter_cdylib();
}

/// netfilter 선행 차단 .so 를 프로필 디렉터리로 복사한다.
///
/// 의존성 빌드가 `deps/libredcell_netfilter.so` 를 이미 만들므로(cdylib+rlib),
/// 실행기 탐색 위치(실행파일 옆)에 복사만 한다. 배포 시에도 바이너리 옆에 두면 된다.
/// 실패해도 빌드는 계속된다 — 실행기는 .so 부재 시 반응형 킬게이트로 폴백한다.
#[allow(clippy::all)]
fn build_netfilter_cdylib() {
    println!("cargo:rerun-if-changed=netfilter/src/lib.rs");
    println!("cargo:rerun-if-changed=netfilter/Cargo.toml");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let out_dir = std::env::var("OUT_DIR").unwrap_or_default();
    // target/<profile>/build/<pkg>-<hash>/out → target/<profile>
    let profile_dir = std::path::Path::new(&out_dir).ancestors().nth(3).map(|p| p.to_path_buf());
    let Some(profile_dir) = profile_dir else {
        println!("cargo:warning=netfilter: OUT_DIR 해석 실패 — 선행 차단 .so 없이 빌드");
        return;
    };
    let src = profile_dir.join("deps").join("libredcell_netfilter.so");
    let dest = profile_dir.join("libredcell_netfilter.so");
    if !src.is_file() {
        println!("cargo:warning=netfilter: deps 산출물 없음 — 다음 빌드에서 복사");
        return;
    }
    let fresh = dest
        .metadata()
        .and_then(|dm| src.metadata().map(|sm| (dm, sm)))
        .map(|(dm, sm)| dm.modified().ok().zip(sm.modified().ok()).map(|(d, s)| d >= s).unwrap_or(false))
        .unwrap_or(false);
    if fresh {
        return;
    }
    if std::fs::copy(&src, &dest).is_ok() {
        println!("cargo:warning=netfilter: {}", dest.display());
    } else {
        println!("cargo:warning=netfilter: 복사 실패 — 킬게이트 폴백");
    }
}
