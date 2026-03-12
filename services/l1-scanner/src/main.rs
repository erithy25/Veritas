//! Veritas L1 Scanner -- first-tier deepfake detection microservice.
//!
//! Consumes raw video metadata from `veritas.ingest.raw`, performs fast
//! heuristic checks (metadata analysis, perceptual hash lookup, compression
//! anomaly detection), and produces results to `veritas.l1.results`.
//! Suspicious videos are additionally forwarded to `veritas.l2.queue` for
//! biometric analysis.

use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{Context, Result};
use axum::{routing::get, Router};
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::Message;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde::{Deserialize, Serialize};
use tokio::signal;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use veritas_shared::config::AppConfig;
use veritas_shared::kafka::{self, topics};
use veritas_shared::metrics;
use veritas_shared::telemetry;
use veritas_shared::types::{KafkaEnvelope, ScanContext};

mod hash;
mod scanner;

use scanner::{L1Config, L1Decision, VideoMetadata};

// ── Kafka message types ─────────────────────────────────────────────

/// Inbound message from the ingest service on `veritas.ingest.raw`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IngestPayload {
    /// Scan context propagated through the pipeline.
    scan_context: ScanContext,
    /// Parsed video metadata extracted during ingestion.
    metadata: VideoMetadata,
    /// S3/MinIO object key where the raw video bytes are stored.
    object_key: String,
    /// Sampled frames encoded as base64 PNG (lightweight keyframe thumbnails
    /// extracted by the ingest service for L1 hash comparison).
    sample_frame_keys: Vec<String>,
}

/// Outbound message to `veritas.l1.results`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct L1ResultPayload {
    scan_context: ScanContext,
    decision: String,
    detection_result: veritas_shared::types::L1DetectionResult,
    reason_codes: Vec<veritas_shared::types::ReasonCodeEntry>,
}

/// Outbound escalation message to `veritas.l2.queue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct L2EscalationPayload {
    scan_context: ScanContext,
    object_key: String,
    l1_metadata_score: f32,
    l1_compression_score: f32,
    l1_detected_tools: Vec<String>,
}

// ── Entry point ─────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load("l1-scanner")?;
    telemetry::init_tracing("veritas-l1-scanner", &config.tracing)?;

    info!("Starting Veritas L1 Scanner service");
    info!(
        metrics_port = config.server.metrics_port,
        environment = ?config.environment,
        kafka_brokers = %config.kafka.brokers,
        redis_url = %config.redis.url,
    );

    // ── Initialize infrastructure clients ───────────────────────
    let consumer: StreamConsumer =
        kafka::create_consumer(&config.kafka, &[topics::INGEST_RAW])?;
    let producer: FutureProducer = kafka::create_producer(&config.kafka)?;
    let redis_client = redis::Client::open(config.redis.url.as_str())
        .context("Failed to create Redis client")?;
    let redis_conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .context("Failed to connect to Redis")?;

    // ── Start metrics / health HTTP server ───────────────────────
    let metrics_addr: SocketAddr = ([0, 0, 0, 0], config.server.metrics_port).into();
    tokio::spawn(serve_metrics(metrics_addr));

    // ── Run the main scan loop ──────────────────────────────────
    let l1_config = L1Config::default();

    info!("L1 Scanner ready, entering consume loop");

    tokio::select! {
        result = consume_loop(&consumer, &producer, redis_conn, &l1_config) => {
            if let Err(e) = result {
                error!(error = %e, "Consume loop exited with error");
                return Err(e);
            }
        }
        _ = shutdown_signal() => {
            info!("Shutdown signal received, draining...");
        }
    }

    info!("L1 Scanner shutting down");
    Ok(())
}

// ── Consume loop ────────────────────────────────────────────────────

/// Main loop: pull messages from Kafka, scan, produce results.
async fn consume_loop(
    consumer: &StreamConsumer,
    producer: &FutureProducer,
    mut redis_conn: redis::aio::MultiplexedConnection,
    l1_config: &L1Config,
) -> Result<()> {
    use rdkafka::message::BorrowedMessage;
    use tokio_stream::StreamExt;

    let mut stream = consumer.stream();

    while let Some(msg_result) = stream.next().await {
        let msg: BorrowedMessage<'_> = match msg_result {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "Kafka consumer error, skipping");
                continue;
            }
        };

        let payload_bytes = match msg.payload() {
            Some(p) => p,
            None => {
                warn!(
                    partition = msg.partition(),
                    offset = msg.offset(),
                    "Empty Kafka message payload, skipping"
                );
                consumer.commit_message(&msg, CommitMode::Async)?;
                continue;
            }
        };

        // Deserialize the envelope.
        let envelope: KafkaEnvelope<IngestPayload> = match serde_json::from_slice(payload_bytes) {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    error = %e,
                    partition = msg.partition(),
                    offset = msg.offset(),
                    "Failed to deserialize ingest message, skipping"
                );
                consumer.commit_message(&msg, CommitMode::Async)?;
                continue;
            }
        };

        let scan_id = envelope.scan_id;
        let tenant_id = envelope.tenant_id;
        let payload = envelope.payload;

        info!(
            scan_id = %scan_id,
            tenant_id = %tenant_id,
            object_key = %payload.object_key,
            "Processing L1 scan"
        );

        metrics::ACTIVE_REQUESTS.inc();
        let scan_start = Instant::now();

        // ── Execute L1 sub-scans ────────────────────────────────
        let metadata_result = scanner::scan_metadata(&payload.metadata);

        // For hash scanning, we would normally load the sampled frames from
        // object storage. Here we pass an empty slice; the ingest service
        // pre-extracts keyframe thumbnails and we would decode them from
        // `sample_frame_keys`. The hash scan gracefully handles zero frames.
        let hash_result = scanner::scan_hash(
            &mut redis_conn,
            &[],  // TODO: decode frames from sample_frame_keys via object storage
            &l1_config.hash_thresholds,
        )
        .await
        .unwrap_or_else(|e| {
            warn!(scan_id = %scan_id, error = %e, "Hash scan failed, continuing without");
            scanner::HashScanResult {
                match_found: false,
                match_id: None,
                best_match: None,
                reason_codes: vec![],
            }
        });

        let compression_result = scanner::scan_compression(&payload.metadata);

        let duration_ms = scan_start.elapsed().as_millis() as u32;
        let tenant_str = tenant_id.to_string();

        let evaluation = scanner::evaluate_l1(
            l1_config,
            &metadata_result,
            &hash_result,
            &compression_result,
            duration_ms,
            &tenant_str,
        );

        metrics::ACTIVE_REQUESTS.dec();

        // ── Produce L1 result ───────────────────────────────────
        let result_payload = L1ResultPayload {
            scan_context: payload.scan_context.clone(),
            decision: evaluation.decision.as_str().to_string(),
            detection_result: evaluation.detection_result.clone(),
            reason_codes: evaluation.reason_codes.clone(),
        };

        let result_envelope = KafkaEnvelope::new(tenant_id, scan_id, result_payload);
        let result_json = serde_json::to_vec(&result_envelope)
            .context("Failed to serialize L1 result")?;

        let key = scan_id.to_string();
        let record = FutureRecord::to(topics::L1_RESULTS)
            .key(&key)
            .payload(&result_json);

        if let Err((e, _)) = producer.send(record, rdkafka::util::Timeout::Never).await {
            error!(
                scan_id = %scan_id,
                error = %e,
                "Failed to produce L1 result to Kafka"
            );
        } else {
            debug!(scan_id = %scan_id, topic = topics::L1_RESULTS, "L1 result published");
        }

        // ── Escalate to L2 if needed ────────────────────────────
        if evaluation.decision == L1Decision::Escalate {
            let escalation_payload = L2EscalationPayload {
                scan_context: payload.scan_context.clone(),
                object_key: payload.object_key.clone(),
                l1_metadata_score: metadata_result.anomaly_score,
                l1_compression_score: compression_result.anomaly_score,
                l1_detected_tools: metadata_result.detected_tools.clone(),
            };

            let escalation_envelope =
                KafkaEnvelope::new(tenant_id, scan_id, escalation_payload);
            let escalation_json = serde_json::to_vec(&escalation_envelope)
                .context("Failed to serialize L2 escalation")?;

            let esc_key = scan_id.to_string();
            let escalation_record = FutureRecord::to(topics::L2_QUEUE)
                .key(&esc_key)
                .payload(&escalation_json);

            if let Err((e, _)) = producer
                .send(escalation_record, rdkafka::util::Timeout::Never)
                .await
            {
                error!(
                    scan_id = %scan_id,
                    error = %e,
                    "Failed to produce L2 escalation to Kafka"
                );
            } else {
                info!(
                    scan_id = %scan_id,
                    topic = topics::L2_QUEUE,
                    metadata_score = metadata_result.anomaly_score,
                    compression_score = compression_result.anomaly_score,
                    "Escalated to L2 queue"
                );
            }
        }

        // ── Commit offset ───────────────────────────────────────
        consumer.commit_message(&msg, CommitMode::Async)?;

        info!(
            scan_id = %scan_id,
            decision = evaluation.decision.as_str(),
            duration_ms,
            metadata_score = metadata_result.anomaly_score,
            compression_score = compression_result.anomaly_score,
            hash_match = hash_result.match_found,
            "L1 scan completed"
        );
    }

    Ok(())
}

// ── Metrics / health HTTP server ────────────────────────────────────

/// Serve Prometheus metrics and a basic health endpoint over HTTP.
async fn serve_metrics(addr: SocketAddr) {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .route("/ready", get(readiness_handler));

    info!(%addr, "Metrics/health server starting");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, "Failed to bind metrics server");
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!(error = %e, "Metrics server exited with error");
    }
}

async fn metrics_handler() -> String {
    metrics::gather_metrics()
}

async fn health_handler() -> &'static str {
    "OK"
}

async fn readiness_handler() -> &'static str {
    // In production this would check Kafka/Redis connectivity.
    "OK"
}

// ── Graceful shutdown ───────────────────────────────────────────────

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
