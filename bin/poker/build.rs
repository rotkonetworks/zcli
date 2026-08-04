fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile(&["../relay/proto/relay.proto"], &["../relay/proto"])?;
    Ok(())
}
