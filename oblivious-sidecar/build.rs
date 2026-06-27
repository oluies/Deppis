fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile the store.proto gRPC contract (uses the system `protoc`).
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true) // client generated for in-process tests
        .compile_protos(&["proto/store.proto", "proto/notify.proto"], &["proto"])?;
    Ok(())
}
