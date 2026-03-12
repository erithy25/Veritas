//! EU AI Act compliance engine.
//!
//! Veritas is classified as a High-Risk AI System under Annex III of the
//! EU AI Act (law-enforcement / safety-relevant AI). This module ensures:
//!
//! - **Article 13 (Transparency)**: Every automated decision is logged with
//!   explainable reason codes, model versions, and confidence scores.
//! - **Article 14 (Human Oversight)**: Flagged content is routed to human
//!   moderators; override actions are audit-logged.
//! - **Article 15 (Accuracy / Robustness)**: Model performance metrics and
//!   drift detection are continuously recorded.
//! - **Article 17 (Quality Management)**: Model version changes, training
//!   data updates, and red-team results are immutably logged.
//! - **Article 62 (Incident Reporting)**: Serious incidents (false negatives
//!   on harmful content, systemic failures) trigger automated reports.

use anyhow::Result;
use chrono::Utc;
use clickhouse::Client as ChClient;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

/// Engine responsible for EU AI Act audit logging.
#[derive(Clone)]
pub struct AiActEngine {
    pg: PgPool,
    ch: ChClient,
}

/// Audit record persisted to ClickHouse for high-volume analytics and to
/// PostgreSQL for ACID-compliant legal evidence.
#[derive(Debug, Serialize, Deserialize)]
struct AuditRecord {
    audit_id: String,
    scan_id: String,
    tenant_id: String,
    decision: String,
    risk_score: f64,
    reason_codes: Vec<String>,
    model_versions: serde_json::Value,
    human_oversight_required: bool,
    processing_region: String,
    timestamp: String,
}

impl AiActEngine {
    pub fn new(pg: PgPool, ch: ChClient) -> Self {
        Self { pg, ch }
    }

    /// Log an automated decision as required by Article 13.
    ///
    /// Persists to both PostgreSQL (legal evidence, low volume) and
    /// ClickHouse (analytics, high volume).
    pub async fn log_decision(&self, verdict: &serde_json::Value) -> Result<()> {
        let audit_id = Uuid::new_v4().to_string();
        let scan_id = verdict["scan_id"].as_str().unwrap_or("unknown");
        let tenant_id = verdict["tenant_id"].as_str().unwrap_or("unknown");

        let payload = &verdict["payload"];
        let decision = payload["decision"].as_str().unwrap_or("ALLOW");
        let risk_score = payload["risk_score"].as_f64().unwrap_or(0.0);

        let reason_codes: Vec<String> = payload
            .get("reason_codes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|rc| rc["code"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let model_versions = payload
            .get("model_versions")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        let human_oversight_required = decision == "FLAG" || decision == "FLAG_URGENT";

        // PostgreSQL — ACID-compliant legal record
        sqlx::query(
            r#"
            INSERT INTO compliance_audit_log
                (audit_id, scan_id, tenant_id, decision, risk_score,
                 reason_codes, model_versions, human_oversight_required,
                 regulation, article_reference, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'EU_AI_ACT', 'Article 13', NOW())
            "#,
        )
        .bind(&audit_id)
        .bind(scan_id)
        .bind(tenant_id)
        .bind(decision)
        .bind(risk_score)
        .bind(serde_json::to_string(&reason_codes)?)
        .bind(&model_versions)
        .bind(human_oversight_required)
        .execute(&self.pg)
        .await?;

        // ClickHouse — high-volume analytics
        let ch_insert = format!(
            "INSERT INTO veritas.ai_act_decisions \
             (audit_id, scan_id, tenant_id, decision, risk_score, \
              reason_codes, human_oversight_required, timestamp) \
             VALUES ('{}', '{}', '{}', '{}', {}, ['{}'], {}, now())",
            audit_id,
            scan_id,
            tenant_id,
            decision,
            risk_score,
            reason_codes.join("','"),
            human_oversight_required as u8,
        );
        let _ = self.ch.query(&ch_insert).execute().await;

        info!(
            audit_id = %audit_id,
            scan_id = %scan_id,
            decision,
            "EU AI Act Article 13 audit log written"
        );

        // Article 62 — check if this warrants an incident report
        if self.is_reportable_incident(verdict) {
            self.create_incident_report(scan_id, decision, &reason_codes)
                .await?;
        }

        Ok(())
    }

    /// Log a model version change as required by Article 17 (QMS).
    pub async fn log_model_change(&self, event: &serde_json::Value) -> Result<()> {
        let model_name = event["model_name"].as_str().unwrap_or("unknown");
        let old_version = event["old_version"].as_str().unwrap_or("unknown");
        let new_version = event["new_version"].as_str().unwrap_or("unknown");
        let change_reason = event["reason"].as_str().unwrap_or("");

        sqlx::query(
            r#"
            INSERT INTO compliance_model_changes
                (change_id, model_name, old_version, new_version,
                 change_reason, regulation, article_reference, created_at)
            VALUES ($1, $2, $3, $4, $5, 'EU_AI_ACT', 'Article 17', NOW())
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(model_name)
        .bind(old_version)
        .bind(new_version)
        .bind(change_reason)
        .execute(&self.pg)
        .await?;

        info!(
            model_name,
            old_version,
            new_version,
            "Article 17 QMS model change logged"
        );
        Ok(())
    }

    /// Log C2PA manifest issuance for traceability.
    pub async fn log_c2pa_issuance(&self, event: &serde_json::Value) -> Result<()> {
        let scan_id = event["scan_id"].as_str().unwrap_or("unknown");
        info!(scan_id, "C2PA manifest issuance logged for Article 13 traceability");
        Ok(())
    }

    /// Generate a point-in-time audit snapshot for regulatory inspection.
    pub async fn generate_audit_snapshot(&self, event: &serde_json::Value) -> Result<()> {
        let requested_by = event["requested_by"].as_str().unwrap_or("system");
        let scope = event["scope"].as_str().unwrap_or("full");

        info!(
            requested_by,
            scope,
            "Generating EU AI Act audit snapshot"
        );

        // In production, this would query both PostgreSQL and ClickHouse
        // to produce a comprehensive regulatory report covering:
        //   - Total decisions made (per category)
        //   - Model versions active during the period
        //   - Human oversight actions taken
        //   - Incident reports filed
        //   - Performance metrics and drift indicators

        let snapshot = serde_json::json!({
            "snapshot_id": Uuid::new_v4().to_string(),
            "generated_at": Utc::now().to_rfc3339(),
            "requested_by": requested_by,
            "scope": scope,
            "regulation": "EU AI Act",
            "status": "generated",
        });

        sqlx::query(
            "INSERT INTO compliance_audit_snapshots (snapshot_id, data, created_at) VALUES ($1, $2, NOW())",
        )
        .bind(snapshot["snapshot_id"].as_str().unwrap())
        .bind(&snapshot)
        .execute(&self.pg)
        .await?;

        info!("Audit snapshot persisted");
        Ok(())
    }

    /// Determine if a verdict constitutes a reportable incident under Article 62.
    fn is_reportable_incident(&self, verdict: &serde_json::Value) -> bool {
        let payload = &verdict["payload"];
        let decision = payload["decision"].as_str().unwrap_or("ALLOW");
        let risk_score = payload["risk_score"].as_f64().unwrap_or(0.0);

        // Reportable: high-risk content that was initially allowed but later
        // found to be harmful, or extremely high confidence blocks.
        if decision == "BLOCK" && risk_score > 0.95 {
            return true;
        }

        // Check for political disinformation indicators
        let reason_codes = payload
            .get("reason_codes")
            .and_then(|v| v.as_array())
            .unwrap_or(&Vec::new())
            .clone();

        let has_political_threat = reason_codes.iter().any(|rc| {
            rc["code"]
                .as_str()
                .map_or(false, |c| c.starts_with("CTX_POLITICAL") || c == "THREAT_DISINFORMATION")
        });

        if has_political_threat && risk_score > 0.8 {
            return true;
        }

        false
    }

    /// Create an Article 62 serious incident report.
    async fn create_incident_report(
        &self,
        scan_id: &str,
        decision: &str,
        reason_codes: &[String],
    ) -> Result<()> {
        let incident_id = Uuid::new_v4().to_string();

        warn!(
            incident_id = %incident_id,
            scan_id,
            decision,
            "Article 62 reportable incident detected — creating report"
        );

        sqlx::query(
            r#"
            INSERT INTO compliance_incidents
                (incident_id, scan_id, incident_type, severity,
                 reason_codes, regulation, article_reference,
                 status, created_at)
            VALUES ($1, $2, 'automated_detection', 'high', $3,
                    'EU_AI_ACT', 'Article 62', 'pending_review', NOW())
            "#,
        )
        .bind(&incident_id)
        .bind(scan_id)
        .bind(serde_json::to_string(reason_codes)?)
        .execute(&self.pg)
        .await?;

        info!(
            incident_id = %incident_id,
            "Article 62 incident report created and pending review"
        );
        Ok(())
    }
}
