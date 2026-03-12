use anyhow::Result;
use rdkafka::consumer::StreamConsumer;
use rdkafka::message::Message;
use rdkafka::producer::FutureProducer;
use std::net::SocketAddr;
use tokio_stream::StreamExt;
use tracing::{error, info};

mod signer;

use veritas_shared::config::AppConfig;
use veritas_shared::kafka::{self, topics};
use veritas_shared::telemetry;

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load("signer")?;
    telemetry::init_tracing("veritas-signer", &config.tracing)?;

    info!("Starting Veritas Crypto Signer service");

    let consumer: StreamConsumer =
        kafka::create_consumer(&config.kafka, &[topics::VERDICTS])?;
    let producer: FutureProducer = kafka::create_producer(&config.kafka)?;

    // Initialize the signing engine
    // In production, this connects to an HSM via PKCS#11
    let signing_engine = signer::SigningEngine::new_local_dev()?;
    info!(key_id = %signing_engine.key_id(), "Signing engine initialized");

    let metrics_addr: SocketAddr = ([0, 0, 0, 0], config.server.metrics_port).into();
    tokio::spawn(serve_health(metrics_addr));

    info!("Signer pipeline running, consuming from {}", topics::VERDICTS);

    let mut stream = consumer.stream();
    while let Some(result) = stream.next().await {
        match result {
            Ok(msg) => {
                if let Some(payload) = msg.payload() {
                    match signing_engine.sign_verdict(payload) {
                        Ok(signed) => {
                            let record = rdkafka::producer::FutureRecord::to(topics::VERDICTS)
                                .key(msg.key().unwrap_or_default())
                                .payload(&signed);
                            if let Err((e, _)) = producer.send(record, std::time::Duration::from_secs(5)).await {
                                error!("Failed to publish signed verdict: {}", e);
                            }
                        }
                        Err(e) => error!("Signing failed: {}", e),
                    }
                    let _ = rdkafka::consumer::Consumer::commit_message(
                        &consumer, &msg, rdkafka::consumer::CommitMode::Async,
                    );
                }
            }
            Err(e) => error!("Kafka error: {}", e),
        }
    }

    Ok(())
}

async fn serve_health(addr: SocketAddr) {
    let app = axum::Router::new()
        .route("/health", axum::routing::get(|| async { "OK" }))
        .route("/metrics", axum::routing::get(|| async { veritas_shared::metrics::gather_metrics() }));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
