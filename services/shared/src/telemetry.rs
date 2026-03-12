use crate::config::TracingConfig;
use anyhow::Result;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the tracing/logging subsystem.
///
/// In production (`json_logs = true`), outputs structured JSON logs suitable
/// for OpenSearch / ELK ingestion. In development, uses human-readable
/// colored output.
pub fn init_tracing(service_name: &str, config: &TracingConfig) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let registry = tracing_subscriber::registry().with(env_filter);

    if config.json_logs {
        let json_layer = fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true);

        registry.with(json_layer).init();
    } else {
        let fmt_layer = fmt::layer()
            .with_target(true)
            .with_thread_ids(false)
            .with_file(false);

        registry.with(fmt_layer).init();
    }

    tracing::info!(service = service_name, "Tracing initialized");
    Ok(())
}
