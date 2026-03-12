use axum::{routing::get, Router};
use std::net::SocketAddr;
use tracing::info;
use veritas_shared::metrics;

/// Serve HTTP health checks and Prometheus metrics on a separate port.
pub async fn serve_health_and_metrics(addr: SocketAddr) {
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(readiness_handler))
        .route("/metrics", get(metrics_handler));

    info!(%addr, "Health and metrics server starting");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_handler() -> &'static str {
    "OK"
}

async fn readiness_handler() -> &'static str {
    // TODO: Check Kafka, Redis, and DB connectivity
    "READY"
}

async fn metrics_handler() -> String {
    metrics::gather_metrics()
}
