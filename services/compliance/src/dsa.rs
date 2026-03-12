//! Digital Services Act (DSA) transparency and reporting engine.
//!
//! The DSA (Regulation 2022/2065) requires platforms to:
//! - Maintain transparency reports on content moderation (Article 15/24)
//! - Report systemic risks (Article 34/35) — deepfake waves, coordinated
//!   campaigns
//! - Provide statement of reasons for content restrictions (Article 17)
//! - Support out-of-court dispute settlement (Article 21)

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

/// DSA compliance engine for transparency reporting.
#[derive(Clone)]
pub struct DsaEngine {
    pg: PgPool,
}

/// Statement of reasons for a content restriction decision (Article 17).
#[derive(Debug, Serialize, Deserialize)]
struct StatementOfReasons {
    statement_id: String,
    scan_id: String,
    tenant_id: String,
    decision: String,
    /// Legal basis for the restriction
    legal_basis: String,
    /// Automated detection indicators
    automated_detection: bool,
    /// Factual grounds
    facts: Vec<String>,
    /// Specific provision of terms of service violated
    tos_provision: Option<String>,
    /// Information about redress possibilities
    redress_info: RedressInfo,
    created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RedressInfo {
    /// Internal complaint mechanism available
    internal_complaint: bool,
    /// Out-of-court dispute settlement body
    dispute_settlement_body: String,
    /// Judicial redress information
    judicial_redress: String,
}

impl DsaEngine {
    pub fn new(pg: PgPool) -> Self {
        Self { pg }
    }

    /// Record a content moderation decision with DSA-compliant statement
    /// of reasons (Article 17).
    pub async fn record_decision(&self, verdict: &serde_json::Value) -> Result<()> {
        let scan_id = verdict["scan_id"].as_str().unwrap_or("unknown");
        let tenant_id = verdict["tenant_id"].as_str().unwrap_or("unknown");
        let payload = &verdict["payload"];
        let decision = payload["decision"].as_str().unwrap_or("ALLOW");
        let risk_score = payload["risk_score"].as_f64().unwrap_or(0.0);

        // Generate factual grounds from reason codes
        let facts = self.extract_factual_grounds(payload);

        // Determine legal basis
        let legal_basis = self.determine_legal_basis(payload);

        let statement = StatementOfReasons {
            statement_id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            tenant_id: tenant_id.to_string(),
            decision: decision.to_string(),
            legal_basis,
            automated_detection: true,
            facts,
            tos_provision: Some("Section 4.2 — Manipulated Media Policy".to_string()),
            redress_info: RedressInfo {
                internal_complaint: true,
                dispute_settlement_body: "Certified DSA dispute body (to be designated)".to_string(),
                judicial_redress: "Users may seek judicial redress in the courts of their Member State of establishment".to_string(),
            },
            created_at: Utc::now().to_rfc3339(),
        };

        // Persist to PostgreSQL
        sqlx::query(
            r#"
            INSERT INTO dsa_statements_of_reasons
                (statement_id, scan_id, tenant_id, decision, legal_basis,
                 automated_detection, facts, tos_provision, redress_info,
                 created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            "#,
        )
        .bind(&statement.statement_id)
        .bind(scan_id)
        .bind(tenant_id)
        .bind(decision)
        .bind(&statement.legal_basis)
        .bind(statement.automated_detection)
        .bind(serde_json::to_string(&statement.facts)?)
        .bind(&statement.tos_provision)
        .bind(serde_json::to_value(&statement.redress_info)?)
        .execute(&self.pg)
        .await?;

        info!(
            statement_id = %statement.statement_id,
            scan_id,
            decision,
            "DSA Article 17 statement of reasons recorded"
        );

        // Track for transparency reporting (Article 15/24)
        self.update_transparency_counters(decision).await?;

        Ok(())
    }

    /// Evaluate whether an alert constitutes a systemic risk requiring
    /// reporting under Articles 34/35.
    pub async fn evaluate_systemic_risk(&self, alert: &serde_json::Value) -> Result<()> {
        let alert_type = alert["alert_type"].as_str().unwrap_or("unknown");
        let severity = alert["severity"].as_str().unwrap_or("low");

        // Systemic risk indicators
        let is_systemic = match alert_type {
            "deepfake_wave" => true,
            "coordinated_campaign" => true,
            "political_disinformation_surge" => true,
            "identity_theft_cluster" => {
                // Only systemic if affecting many users
                alert["affected_users"]
                    .as_u64()
                    .map_or(false, |n| n > 100)
            }
            _ => severity == "critical",
        };

        if is_systemic {
            warn!(
                alert_type,
                severity,
                "Systemic risk detected — creating DSA Article 34 report"
            );

            let report_id = Uuid::new_v4().to_string();

            sqlx::query(
                r#"
                INSERT INTO dsa_systemic_risk_reports
                    (report_id, alert_type, severity, alert_data,
                     status, created_at)
                VALUES ($1, $2, $3, $4, 'pending_submission', NOW())
                "#,
            )
            .bind(&report_id)
            .bind(alert_type)
            .bind(severity)
            .bind(alert)
            .execute(&self.pg)
            .await?;

            info!(
                report_id = %report_id,
                alert_type,
                "DSA systemic risk report created"
            );
        }

        Ok(())
    }

    /// Extract human-readable factual grounds from detection reason codes.
    fn extract_factual_grounds(&self, payload: &serde_json::Value) -> Vec<String> {
        let mut facts = Vec::new();

        if let Some(reason_codes) = payload.get("reason_codes").and_then(|v| v.as_array()) {
            for rc in reason_codes {
                if let Some(explanation) = rc["explanation"].as_str() {
                    facts.push(explanation.to_string());
                }
            }
        }

        if facts.is_empty() {
            let risk_score = payload["risk_score"].as_f64().unwrap_or(0.0);
            facts.push(format!(
                "Automated analysis detected indicators of media manipulation \
                 with a confidence score of {:.1}%.",
                risk_score * 100.0
            ));
        }

        facts
    }

    /// Determine the applicable legal basis for the content restriction.
    fn determine_legal_basis(&self, payload: &serde_json::Value) -> String {
        let decision = payload["decision"].as_str().unwrap_or("ALLOW");

        match decision {
            "BLOCK" => {
                "Terms of service violation: Manipulated media policy — \
                 content identified as synthetic/deepfake with high confidence"
                    .to_string()
            }
            "FLAG_URGENT" => {
                "Terms of service violation: Potentially manipulated media \
                 requiring urgent human review"
                    .to_string()
            }
            "FLAG" => {
                "Terms of service: Content flagged for human review based on \
                 automated analysis indicators"
                    .to_string()
            }
            _ => "No restriction applied".to_string(),
        }
    }

    /// Update DSA transparency report counters (Article 15/24).
    async fn update_transparency_counters(&self, decision: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO dsa_transparency_counters
                (period, decision_type, count, updated_at)
            VALUES (date_trunc('month', NOW()), $1, 1, NOW())
            ON CONFLICT (period, decision_type)
            DO UPDATE SET count = dsa_transparency_counters.count + 1,
                          updated_at = NOW()
            "#,
        )
        .bind(decision)
        .execute(&self.pg)
        .await?;

        Ok(())
    }
}
