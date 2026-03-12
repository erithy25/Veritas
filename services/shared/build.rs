fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../../proto";

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/gen")
        .compile_protos(
            &[
                &format!("{proto_root}/veritas/api/v1/gateway.proto"),
                &format!("{proto_root}/veritas/api/v1/dashboard.proto"),
                &format!("{proto_root}/veritas/api/v1/compliance.proto"),
                &format!("{proto_root}/veritas/api/v1/sandbox.proto"),
            ],
            &[proto_root],
        )?;

    Ok(())
}
