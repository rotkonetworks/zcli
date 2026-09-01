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

    // embed git commit hash at build time
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output();
    let git_hash = output
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=GIT_HASH={}", git_hash.trim());

    Ok(())
}
