use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Result;
use axum::{routing::get, Router};
use chrono::Utc;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::Message;
use rdkafka::producer::FutureProducer;
use rdkafka::producer::FutureRecord;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use veritas_shared::config::AppConfig;
use veritas_shared::kafka::{self, topics};
use veritas_shared::metrics;
use veritas_shared::telemetry;
use veritas_shared::types::{
    KafkaEnvelope, L1DetectionResult, L2DetectionResult, L3DetectionResult, ScanResult,
    VerdictDecision,
};

mod policy;
mod scoring;

use policy::{PolicyOutput, PolicyStore, TenantPolicy};
use scoring::{ContentContext, ScoringOutput, ScoringWeights};

// ---------------------------------------------------------------------------
// Kafka message types
// ---------------------------------------------------------------------------

/// Envelope payload received from each detection layer.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "layer", rename_all = "snake_case")]
enum LayerResult {
    L1 {
        result: L1DetectionResult,
        #[serde(default)]
        context: Option<ContentContext>,
    },
    L2 {
        result: L2DetectionResult,
        #[serde(default)]
        context: Option<ContentContext>,
    },
    L3 {
        result: L3DetectionResult,
        #[serde(default)]
        context: Option<ContentContext>,
    },
}

/// Intermediate accumulation of layer results for a given scan.
#[derive(Debug, Clone, Default)]
struct ScanAccumulator {
    tenant_id: Uuid,
    l1: Option<L1DetectionResult>,
    l2: Option<L2DetectionResult>,
    l3: Option<L3DetectionResult>,
    context: ContentContext,
    max_tier_received: u8,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load("scorer")?;
    telemetry::init_tracing("veritas-scorer", &config.tracing)?;

    info!("Starting Veritas Risk Scorer service");
    info!(
        metrics_port = config.server.metrics_port,
        environment = ?config.environment,
    );

    // Kafka producer for emitting verdicts.
    let producer = kafka::create_producer(&config.kafka)?;

    // Kafka consumer subscribed to all detection-layer result topics.
    let consumer = kafka::create_consumer(
        &config.kafka,
        &[topics::L1_RESULTS, topics::L2_RESULTS, topics::L3_RESULTS],
    )?;

    // Policy store (in production, this would be loaded from a database
    // and hot-reloaded).
    let policy_store = Arc::new(RwLock::new(PolicyStore::new()));

    // Default scoring weights.
    let weights = ScoringWeights::default();

    // Start health/metrics HTTP server.
    let metrics_addr: SocketAddr = ([0, 0, 0, 0], config.server.metrics_port).into();
    tokio::spawn(serve_health_and_metrics(metrics_addr));

    // Main consumption loop.
    info!("Scorer consumer loop starting");
    run_consumer_loop(consumer, producer, policy_store, weights).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Consumer loop
// ---------------------------------------------------------------------------

/// Main consumer loop that reads from L1/L2/L3 result topics, scores the
/// accumulated results, and produces verdicts.
async fn run_consumer_loop(
    consumer: StreamConsumer,
    producer: FutureProducer,
    policy_store: Arc<RwLock<PolicyStore>>,
    weights: ScoringWeights,
) {
    // In-memory scan accumulator.  In production, partial results would be
    // stored in Redis with TTL so that multiple scorer replicas can
    // cooperate, and so that results survive restarts.
    let mut accumulators: std::collections::HashMap<Uuid, ScanAccumulator> =
        std::collections::HashMap::new();

    let mut message_stream = consumer.stream();

    while let Some(result) = message_stream.next().await {
        let message = match result {
            Ok(m) => m,
            Err(e) => {
                error!(error = %e, "Kafka consumer error");
                continue;
            }
        };

        let topic = message.topic();
        let payload = match message.payload_view::<str>() {
            Some(Ok(s)) => s,
            Some(Err(e)) => {
                warn!(error = %e, topic, "Failed to decode message payload as UTF-8");
                if let Err(e) = consumer.commit_message(&message, rdkafka::consumer::CommitMode::Async) {
                    warn!(error = %e, "Failed to commit message offset");
                }
                continue;
            }
            None => {
                debug!(topic, "Received message with empty payload; skipping");
                if let Err(e) = consumer.commit_message(&message, rdkafka::consumer::CommitMode::Async) {
                    warn!(error = %e, "Failed to commit message offset");
                }
                continue;
            }
        };

        let scan_id = process_layer_message(
            topic,
            payload,
            &mut accumulators,
        );

        let scan_id = match scan_id {
            Ok(id) => id,
            Err(e) => {
                warn!(error = %e, topic, "Failed to process layer message");
                if let Err(e) = consumer.commit_message(&message, rdkafka::consumer::CommitMode::Async) {
                    warn!(error = %e, "Failed to commit message offset");
                }
                continue;
            }
        };

        // Determine whether we have enough layers to score.
        // We score as soon as we have all available layers or at minimum
        // after L1.  In production the decision to wait for L2/L3 would
        // depend on the scan's `max_tier` field.
        if let Some(acc) = accumulators.get(&scan_id) {
            let ready = acc.l1.is_some()
                && (acc.max_tier_received >= 3
                    || (acc.l2.is_some() && acc.l3.is_some()));

            if ready || acc.l3.is_some() {
                // Remove accumulator -- we are done with this scan.
                let acc = accumulators.remove(&scan_id).unwrap();
                if let Err(e) =
                    score_and_emit(&scan_id, acc, &weights, &policy_store, &producer).await
                {
                    error!(error = %e, %scan_id, "Failed to score and emit verdict");
                }
            }
        }

        // Commit offset.
        if let Err(e) = consumer.commit_message(&message, rdkafka::consumer::CommitMode::Async) {
            warn!(error = %e, "Failed to commit message offset");
        }
    }

    warn!("Kafka message stream ended; scorer shutting down");
}

/// Parse a detection-layer message and fold it into the accumulator map.
///
/// Returns the scan_id on success.
#[instrument(skip(payload, accumulators), fields(scan_id))]
fn process_layer_message(
    topic: &str,
    payload: &str,
    accumulators: &mut std::collections::HashMap<Uuid, ScanAccumulator>,
) -> Result<Uuid> {
    // All messages are wrapped in KafkaEnvelope<serde_json::Value>.
    let envelope: KafkaEnvelope<serde_json::Value> = serde_json::from_str(payload)?;
    let scan_id = envelope.scan_id;
    tracing::Span::current().record("scan_id", tracing::field::display(&scan_id));

    let acc = accumulators
        .entry(scan_id)
        .or_insert_with(|| ScanAccumulator {
            tenant_id: envelope.tenant_id,
            ..Default::default()
        });

    match topic {
        topics::L1_RESULTS => {
            let result: L1DetectionResult = serde_json::from_value(envelope.payload)?;
            debug!(%scan_id, "Received L1 result");
            acc.l1 = Some(result);
            acc.max_tier_received = acc.max_tier_received.max(1);
        }
        topics::L2_RESULTS => {
            let result: L2DetectionResult = serde_json::from_value(envelope.payload)?;
            debug!(%scan_id, "Received L2 result");
            acc.l2 = Some(result);
            acc.max_tier_received = acc.max_tier_received.max(2);
        }
        topics::L3_RESULTS => {
            let result: L3DetectionResult = serde_json::from_value(envelope.payload)?;
            debug!(%scan_id, "Received L3 result");
            acc.l3 = Some(result);
            acc.max_tier_received = acc.max_tier_received.max(3);
        }
        other => {
            warn!(topic = other, "Unexpected topic; ignoring");
        }
    }

    Ok(scan_id)
}

// ---------------------------------------------------------------------------
// Scoring & verdict emission
// ---------------------------------------------------------------------------

/// Score accumulated layer results, evaluate policy, and produce the verdict
/// to the verdicts topic.
#[instrument(skip_all, fields(%scan_id, verdict))]
async fn score_and_emit(
    scan_id: &Uuid,
    acc: ScanAccumulator,
    weights: &ScoringWeights,
    policy_store: &Arc<RwLock<PolicyStore>>,
    producer: &FutureProducer,
) -> Result<()> {
    let start = std::time::Instant::now();

    // Run scoring algorithm.
    let scoring_output: ScoringOutput = scoring::compute_risk_score(
        acc.l1.as_ref(),
        acc.l2.as_ref(),
        acc.l3.as_ref(),
        &acc.context,
        weights,
    );

    // Load tenant policy and evaluate.
    let policy = {
        let store = policy_store
            .read()
            .map_err(|e| anyhow::anyhow!("Policy store lock poisoned: {e}"))?;
        store.get(&acc.tenant_id)
    };

    let policy_output: PolicyOutput =
        policy::evaluate_policy(&acc.tenant_id, &scoring_output, &policy);

    tracing::Span::current().record("verdict", policy_output.verdict.as_str());

    let duration_ms = start.elapsed().as_millis() as u32;

    info!(
        %scan_id,
        tenant_id = %acc.tenant_id,
        risk_score = policy_output.risk_score,
        verdict = policy_output.verdict.as_str(),
        override_rule = ?policy_output.override_rule_id,
        duration_ms,
        "Verdict computed"
    );

    // Build the scan result.
    let scan_result = ScanResult {
        scan_context: veritas_shared::types::ScanContext {
            scan_id: *scan_id,
            upload_id: String::new(), // Populated upstream; not available here.
            tenant_id: acc.tenant_id,
            priority: veritas_shared::types::ScanPriority::Normal,
            max_tier: acc.max_tier_received,
            created_at: Utc::now(),
            processing_region: String::new(),
        },
        l1_result: acc.l1,
        l2_result: acc.l2,
        l3_result: acc.l3,
        reason_codes: policy_output.reason_codes,
        risk_score: policy_output.risk_score,
        context_multiplier: scoring_output.context_multiplier,
        public_figure_detected: acc.context.public_figure_detected,
        political_context_score: acc.context.political_content_score,
        verdict: policy_output.verdict,
        model_versions: std::collections::HashMap::new(),
        total_duration_ms: duration_ms,
    };

    // Wrap in envelope and publish to the verdicts topic.
    let envelope = KafkaEnvelope::new(acc.tenant_id, *scan_id, &scan_result);
    let payload = serde_json::to_string(&envelope)?;

    let record = FutureRecord::to(topics::VERDICTS)
        .key(&scan_id.to_string())
        .payload(&payload);

    producer
        .send(record, Duration::from_secs(5))
        .await
        .map_err(|(e, _)| anyhow::anyhow!("Kafka produce failed: {e}"))?;

    // Record metrics.
    metrics::DETECTION_RESULT_TOTAL
        .with_label_values(&["scorer", policy_output.verdict.as_str(), &acc.tenant_id.to_string()])
        .inc();

    info!(%scan_id, "Verdict published to {}", topics::VERDICTS);
    Ok(())
}

// ---------------------------------------------------------------------------
// Health & metrics HTTP server
// ---------------------------------------------------------------------------

async fn serve_health_and_metrics(addr: SocketAddr) {
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/ready", get(|| async { "READY" }))
        .route("/metrics", get(|| async { metrics::gather_metrics() }));

    info!(%addr, "Health and metrics server starting");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
