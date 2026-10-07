fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(
            &[
                "proto/zidecar.proto",
                "proto/lightwalletd.proto",
            ],
            &["proto"],
        )?;

    // Zakura node `Indexer` gRPC (zebra.indexer.rpc). Client-only: zidecar is
    // the consumer of the tip + mempool push streams, never the server. Kept a
    // separate pass so the existing surfaces above stay deliberately
    // server-only. Optional path - only used when --zakura-indexer-url is set.
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["proto/indexer.proto"], &["proto"])?;

    // embed the full git commit at build time: GetLightdInfo reports it and
    // wallets link it to the exact source on github. ZIDECAR_GIT_HASH wins, for
    // builds without a .git (docker, tarballs), which otherwise say "unknown".
    // Once a build script prints any rerun-if line, cargo reruns it ONLY on
    // those, so a new commit must be one of them or the old hash stays baked in:
    // HEAD (moves on checkout, holds the hash when detached), the branch ref it
    // points at, and packed-refs.
    println!("cargo:rerun-if-env-changed=ZIDECAR_GIT_HASH");
    let git_path = |p: &str| {
        std::process::Command::new("git")
            .args(["rev-parse", "--git-path", p])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    };
    if let Some(head) = git_path("HEAD") {
        println!("cargo:rerun-if-changed={head}");
        if let Some(r) = std::fs::read_to_string(&head)
            .ok()
            .and_then(|h| h.strip_prefix("ref: ").map(|r| r.trim().to_string()))
        {
            if let Some(ref_path) = git_path(&r) {
                println!("cargo:rerun-if-changed={ref_path}");
            }
        }
    }
    if let Some(packed) = git_path("packed-refs") {
        println!("cargo:rerun-if-changed={packed}");
    }
    let git_hash = std::env::var("ZIDECAR_GIT_HASH")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=GIT_HASH={}", git_hash.trim());

    Ok(())
}
