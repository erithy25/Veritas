use anyhow::Result;
use rdkafka::consumer::StreamConsumer;
use rdkafka::message::Message;
use rdkafka::producer::FutureProducer;
use std::net::SocketAddr;
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

mod extractor;
mod face_detect;
mod normalizer;

use veritas_shared::config::AppConfig;
use veritas_shared::kafka::{self, topics};
use veritas_shared::telemetry;

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load("ingest")?;
    telemetry::init_tracing("veritas-ingest", &config.tracing)?;

    info!("Starting Veritas Ingestion service");

    // Kafka consumer for incoming raw uploads
    let consumer: StreamConsumer =
        kafka::create_consumer(&config.kafka, &[topics::INGEST_RAW])?;

    // Kafka producer for dispatching extracted frames to L1
    let producer: FutureProducer = kafka::create_producer(&config.kafka)?;

    // Health/metrics server
    let metrics_addr: SocketAddr = ([0, 0, 0, 0], config.server.metrics_port).into();
    tokio::spawn(serve_health(metrics_addr));

    info!("Ingestion pipeline running, consuming from {}", topics::INGEST_RAW);

    // Main processing loop
    let mut message_stream = consumer.stream();

    while let Some(result) = message_stream.next().await {
        match result {
            Ok(msg) => {
                let payload = match msg.payload() {
                    Some(p) => p,
                    None => {
                        warn!("Received empty message, skipping");
                        continue;
                    }
                };

                match process_message(payload, &producer).await {
                    Ok(()) => {
                        // Commit offset on success
                        if let Err(e) = rdkafka::consumer::Consumer::commit_message(
                            &consumer,
                            &msg,
                            rdkafka::consumer::CommitMode::Async,
                        ) {
                            error!("Failed to commit offset: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to process message: {}", e);
                        // TODO: Send to dead letter queue after N retries
                    }
                }
            }
            Err(e) => {
                error!("Kafka consumer error: {}", e);
            }
        }
    }

    Ok(())
}

/// Process a single ingestion message: extract frames, detect faces, normalize, and forward.
async fn process_message(payload: &[u8], producer: &FutureProducer) -> Result<()> {
    let envelope: veritas_shared::types::KafkaEnvelope<IngestRequest> =
        serde_json::from_slice(payload)?;

    let scan_id = envelope.scan_id;
    let tenant_id = envelope.tenant_id;
    let request = envelope.payload;

    info!(
        %scan_id,
        %tenant_id,
        upload_id = %request.upload_id,
        size_bytes = request.video_size_bytes,
        "Processing ingestion request"
    );

    let start = std::time::Instant::now();

    // Step 1: Extract key frames from the video
    // In production, this decodes the video using FFmpeg bindings.
    // For now, we create a frame extraction result.
    let frames = extractor::extract_keyframes(&request.upload_id, request.video_size_bytes)?;

    info!(
        %scan_id,
        frame_count = frames.len(),
        "Extracted key frames"
    );

    // Step 2: Detect faces in each frame
    let face_regions = face_detect::detect_faces(&frames)?;

    info!(
        %scan_id,
        faces_detected = face_regions.len(),
        "Face detection complete"
    );

    // Step 3: Normalize face crops for downstream analysis
    let normalized = normalizer::normalize_face_crops(&face_regions)?;

    // Step 4: Forward normalized data to L1 scanner via Kafka
    let l1_payload = L1Input {
        upload_id: request.upload_id.clone(),
        frame_count: frames.len() as u32,
        faces_detected: normalized.len() as u32,
        face_crop_hashes: normalized
            .iter()
            .map(|f| f.content_hash.clone())
            .collect(),
        video_size_bytes: request.video_size_bytes,
        max_tier: request.max_tier,
        priority: request.priority,
    };

    let output_envelope =
        veritas_shared::types::KafkaEnvelope::new(tenant_id, scan_id, l1_payload);

    let output_bytes = serde_json::to_vec(&output_envelope)?;
    let partition_key = format!("{tenant_id}:{}", request.upload_id);

    let record = rdkafka::producer::FutureRecord::to(topics::L1_RESULTS)
        .key(&partition_key)
        .payload(&output_bytes);

    producer
        .send(record, std::time::Duration::from_secs(5))
        .await
        .map_err(|(e, _)| anyhow::anyhow!("Kafka produce failed: {}", e))?;

    let duration = start.elapsed();
    info!(
        %scan_id,
        duration_ms = duration.as_millis() as u64,
        frames = frames.len(),
        faces = face_regions.len(),
        "Ingestion complete, forwarded to L1"
    );

    veritas_shared::metrics::REQUEST_DURATION
        .with_label_values(&["ingest", "process", "ok"])
        .observe(duration.as_secs_f64());

    Ok(())
}

#[derive(serde::Deserialize)]
struct IngestRequest {
    upload_id: String,
    video_size_bytes: u64,
    max_tier: u8,
    priority: veritas_shared::types::ScanPriority,
}

#[derive(serde::Serialize)]
struct L1Input {
    upload_id: String,
    frame_count: u32,
    faces_detected: u32,
    face_crop_hashes: Vec<String>,
    video_size_bytes: u64,
    max_tier: u8,
    priority: veritas_shared::types::ScanPriority,
}

async fn serve_health(addr: SocketAddr) {
    let app = axum::Router::new()
        .route("/health", axum::routing::get(|| async { "OK" }))
        .route(
            "/metrics",
            axum::routing::get(|| async { veritas_shared::metrics::gather_metrics() }),
        );
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
