pub mod config;
pub mod error;
pub mod kafka;
pub mod metrics;
pub mod models;
pub mod telemetry;
pub mod types;

/// Re-export generated protobuf types.
/// Generated code is committed to the repository so downstream crates
/// can build without needing protoc installed.
pub mod proto {
    pub mod veritas {
        pub mod api {
            pub mod v1 {
                include!("gen/veritas.api.v1.rs");
            }
        }
    }
}
