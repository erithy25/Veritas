//! Veritas Compliance Engine — EU AI Act, C2PA, DSA, GDPR monitoring.
//!
//! Consumes from `veritas.compliance.events` and signed verdicts,
//! persists audit logs to PostgreSQL + ClickHouse, generates C2PA
//! Content Credential manifests, monitors GDPR data retention
//! constraints, and produces regulatory incident reports.

use anyhow::Result;
use rdkafka::consumer::StreamConsumer;
use rdkafka::message::Message;
use rdkafka::producer::FutureProducer;
use std::net::SocketAddr;
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

mod ai_act;
mod c2pa;
mod dsa;
mod gdpr;

use veritas_shared::config::AppConfig;
use veritas_shared::kafka::{self, topics};
use veritas_shared::telemetry;

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load("compliance")?;
    telemetry::init_tracing("veritas-compliance", &config.tracing)?;

    info!("Starting Veritas Compliance Engine");

    // Connect to databases
    let pg_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.postgres.max_connections)
        .min_connections(config.postgres.min_connections)
        .connect(&config.postgres.url)
        .await?;

    info!("Connected to PostgreSQL");

    let ch_client = clickhouse::Client::default()
        .with_url(&config.clickhouse.url)
        .with_database(&config.clickhouse.database);

    info!("Connected to ClickHouse");

    // Kafka consumer — listen to compliance events, verdicts, and alerts
    let consumer: StreamConsumer = kafka::create_consumer(
        &config.kafka,
        &[topics::COMPLIANCE_EVENTS, topics::VERDICTS, topics::ALERTS],
    )?;
    let producer: FutureProducer = kafka::create_producer(&config.kafka)?;

    // Initialize sub-engines
    let ai_act_engine = ai_act::AiActEngine::new(pg_pool.clone(), ch_client.clone());
    let c2pa_engine = c2pa::C2paEngine::new();
    let dsa_engine = dsa::DsaEngine::new(pg_pool.clone());
    let gdpr_monitor = gdpr::GdprMonitor::new(pg_pool.clone(), ch_client.clone());

    // Spawn health / metrics server
    let metrics_addr: SocketAddr = ([0, 0, 0, 0], config.server.metrics_port).into();
    tokio::spawn(serve_health(metrics_addr));

    // Spawn GDPR retention enforcement as a background task
    tokio::spawn({
        let monitor = gdpr_monitor.clone();
        async move {
            monitor.run_retention_enforcement_loop().await;
        }
    });

    info!("Compliance pipeline running");

    let mut stream = consumer.stream();
    while let Some(result) = stream.next().await {
        match result {
            Ok(msg) => {
                let topic = msg.topic();
                if let Some(payload) = msg.payload() {
                    let outcome = match topic {
                        topics::VERDICTS => {
                            process_verdict(
                                payload,
                                &ai_act_engine,
                                &c2pa_engine,
                                &dsa_engine,
                                &producer,
                            )
                            .await
                        }
                        topics::COMPLIANCE_EVENTS => {
                            process_compliance_event(payload, &ai_act_engine).await
                        }
                        topics::ALERTS => {
                            process_alert(payload, &dsa_engine).await
                        }
                        _ => {
                            warn!(topic, "Unexpected topic");
                            Ok(())
                        }
                    };

                    if let Err(e) = outcome {
                        error!(%e, topic, "Failed to process compliance message");
                    }

                    let _ = rdkafka::consumer::Consumer::commit_message(
                        &consumer,
                        &msg,
                        rdkafka::consumer::CommitMode::Async,
                    );
                }
            }
            Err(e) => error!("Kafka error: {}", e),
        }
    }

    Ok(())
}

/// Process a signed verdict — generate EU AI Act audit log, C2PA manifest,
/// DSA transparency record.
async fn process_verdict(
    payload: &[u8],
    ai_act: &ai_act::AiActEngine,
    c2pa: &c2pa::C2paEngine,
    dsa: &dsa::DsaEngine,
    producer: &FutureProducer,
) -> Result<()> {
    let verdict: serde_json::Value = serde_json::from_slice(payload)?;
    let scan_id = verdict["scan_id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    info!(scan_id = %scan_id, "Processing verdict for compliance");

    // 1. EU AI Act — mandatory audit logging
    ai_act.log_decision(&verdict).await?;

    // 2. C2PA — generate Content Credential manifest if verdict is BLOCK or FLAG
    let decision = verdict["payload"]["decision"]
        .as_str()
        .unwrap_or("ALLOW");

    if decision == "BLOCK" || decision == "FLAG" || decision == "FLAG_URGENT" {
        let manifest = c2pa.generate_manifest(&verdict)?;

        // Publish C2PA manifest as a compliance event
        let event = serde_json::json!({
            "event_type": "c2pa_manifest_generated",
            "scan_id": scan_id,
            "manifest": manifest,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let record = rdkafka::producer::FutureRecord::to(topics::COMPLIANCE_EVENTS)
            .key(scan_id.as_bytes())
            .payload(&serde_json::to_vec(&event)?);

        if let Err((e, _)) = producer
            .send(record, std::time::Duration::from_secs(5))
            .await
        {
            error!(%e, "Failed to publish C2PA manifest event");
        }
    }

    // 3. DSA — transparency record for flagged/blocked content
    if decision != "ALLOW" {
        dsa.record_decision(&verdict).await?;
    }

    VERDICTS_PROCESSED.inc();
    info!(scan_id = %scan_id, decision, "Compliance processing complete");
    Ok(())
}

/// Process a compliance event (e.g., model version update, audit trigger).
async fn process_compliance_event(
    payload: &[u8],
    ai_act: &ai_act::AiActEngine,
) -> Result<()> {
    let event: serde_json::Value = serde_json::from_slice(payload)?;
    let event_type = event["event_type"]
        .as_str()
        .unwrap_or("unknown");

    info!(event_type, "Processing compliance event");

    match event_type {
        "model_version_update" => {
            ai_act.log_model_change(&event).await?;
        }
        "c2pa_manifest_generated" => {
            ai_act.log_c2pa_issuance(&event).await?;
        }
        "audit_requested" => {
            ai_act.generate_audit_snapshot(&event).await?;
        }
        _ => {
            info!(event_type, "Compliance event recorded");
        }
    }

    COMPLIANCE_EVENTS_PROCESSED.inc();
    Ok(())
}

/// Process an alert (potential deepfake wave, targeted attack).
async fn process_alert(
    payload: &[u8],
    dsa: &dsa::DsaEngine,
) -> Result<()> {
    let alert: serde_json::Value = serde_json::from_slice(payload)?;
    let alert_type = alert["alert_type"]
        .as_str()
        .unwrap_or("unknown");

    info!(alert_type, "Processing alert for DSA reporting");
    dsa.evaluate_systemic_risk(&alert).await?;

    ALERTS_PROCESSED.inc();
    Ok(())
}

// --- Prometheus Metrics ---

use prometheus::{register_int_counter, IntCounter};
use std::sync::LazyLock;

static VERDICTS_PROCESSED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "veritas_compliance_verdicts_processed_total",
        "Total verdicts processed by compliance engine"
    )
    .unwrap()
});

static COMPLIANCE_EVENTS_PROCESSED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "veritas_compliance_events_processed_total",
        "Total compliance events processed"
    )
    .unwrap()
});

static ALERTS_PROCESSED: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "veritas_compliance_alerts_processed_total",
        "Total alerts processed"
    )
    .unwrap()
});

async fn serve_health(addr: SocketAddr) {
    let app = axum::Router::new()
        .route(
            "/health",
            axum::routing::get(|| async { "OK" }),
        )
        .route(
            "/metrics",
            axum::routing::get(|| async { veritas_shared::metrics::gather_metrics() }),
        );
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
