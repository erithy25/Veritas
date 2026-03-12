use anyhow::Result;
use std::net::SocketAddr;
use tracing::info;

mod auth;
mod grpc_service;
mod health;
mod rate_limiter;

use veritas_shared::config::AppConfig;
use veritas_shared::telemetry;

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load("gateway")?;
    telemetry::init_tracing("veritas-gateway", &config.tracing)?;

    info!("Starting Veritas Gateway service");
    info!(
        grpc_port = config.server.grpc_port,
        metrics_port = config.server.metrics_port,
        environment = ?config.environment,
    );

    // Initialize Kafka producer for dispatching to ingestion pipeline
    let kafka_producer = veritas_shared::kafka::create_producer(&config.kafka)?;

    // Initialize Redis client for rate limiting and auth token cache
    let redis_client = redis::Client::open(config.redis.url.as_str())?;

    // Build the rate limiter
    let rate_limiter = rate_limiter::RateLimiter::new(redis_client.clone());

    // Build the gRPC service
    let analysis_service = grpc_service::AnalysisServiceImpl::new(
        kafka_producer,
        redis_client,
        rate_limiter,
        config.clone(),
    );

    // Start health check and metrics servers in the background
    let metrics_addr: SocketAddr = ([0, 0, 0, 0], config.server.metrics_port).into();
    tokio::spawn(health::serve_health_and_metrics(metrics_addr));

    // Start the main gRPC server
    let grpc_addr: SocketAddr = ([0, 0, 0, 0], config.server.grpc_port).into();
    info!(%grpc_addr, "gRPC server starting");

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<grpc_service::AnalysisServer>()
        .await;

    tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(grpc_service::AnalysisServer::new(analysis_service))
        .serve(grpc_addr)
        .await?;

    Ok(())
}
