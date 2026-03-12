fn main() -> Result<(), Box<dyn std::error::Error>> {
    // only run proto codegen for CLI builds (not wasm)
    if std::env::var("CARGO_FEATURE_CLI").is_ok() {
        tonic_build::configure()
            .build_server(false)
            .build_client(false)
            .compile(
                &["proto/zidecar.proto", "proto/lightwalletd.proto"],
                &["proto"],
            )?;
    }
    Ok(())
}
