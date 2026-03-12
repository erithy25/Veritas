use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Tenant identity extracted from authentication context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantContext {
    pub tenant_id: Uuid,
    pub tenant_name: String,
    pub jurisdiction: Jurisdiction,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Jurisdiction {
    Eu,
    Us,
    Apac,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    AnalyzeSync,
    AnalyzeAsync,
    ResultsRead,
    DashboardRead,
    DashboardModerate,
    PolicyRead,
    PolicyWrite,
    ReportsRead,
    SandboxWrite,
}

/// Internal scan identifier used throughout the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanContext {
    pub scan_id: Uuid,
    pub upload_id: String,
    pub tenant_id: Uuid,
    pub priority: ScanPriority,
    pub max_tier: u8,
    pub created_at: DateTime<Utc>,
    pub processing_region: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScanPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Verdict decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictDecision {
    Allow,
    Flag,
    FlagUrgent,
    Block,
}

impl VerdictDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Flag => "FLAG",
            Self::FlagUrgent => "FLAG_URGENT",
            Self::Block => "BLOCK",
        }
    }
}

/// L1 detection result (metadata & hash check).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1DetectionResult {
    pub hash_match_found: bool,
    pub hash_match_id: Option<String>,
    pub metadata_anomaly_score: f32,
    pub compression_anomaly_score: f32,
    pub c2pa_chain_valid: Option<bool>,
    pub detected_editing_tools: Vec<String>,
    pub duration_ms: u32,
}

/// L2 detection result (biometric inconsistency).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2DetectionResult {
    pub micro_flicker_score: f32,
    pub rppg_absence_score: f32,
    pub rppg_signal_quality: f32,
    pub eye_movement_anomaly_score: f32,
    pub skin_texture_anomaly_score: f32,
    pub facial_symmetry_score: f32,
    pub faces_analyzed: u32,
    pub duration_ms: u32,
}

/// L3 detection result (deep neural network).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L3DetectionResult {
    pub vit_general_score: f32,
    pub efficientnet_gan_score: f32,
    pub tcn_temporal_score: f32,
    pub diffusion_artifact_score: f32,
    pub lipsync_mismatch_score: f32,
    pub ensemble_score: f32,
    pub model_agreement_ratio: f32,
    pub duration_ms: u32,
}

/// Reason code attached to a verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonCodeEntry {
    pub code: String,
    pub category: ReasonCategory,
    pub explanation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReasonCategory {
    L1Metadata,
    L1Hash,
    L2Biometric,
    L3Neural,
    Context,
}

/// Composite scan result passed through the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_context: ScanContext,
    pub l1_result: Option<L1DetectionResult>,
    pub l2_result: Option<L2DetectionResult>,
    pub l3_result: Option<L3DetectionResult>,
    pub reason_codes: Vec<ReasonCodeEntry>,
    pub risk_score: f32,
    pub context_multiplier: f32,
    pub public_figure_detected: bool,
    pub political_context_score: f32,
    pub verdict: VerdictDecision,
    pub model_versions: std::collections::HashMap<String, String>,
    pub total_duration_ms: u32,
}

/// Message envelope for Kafka inter-service communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaEnvelope<T: Serialize> {
    pub message_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub tenant_id: Uuid,
    pub scan_id: Uuid,
    pub payload: T,
}

impl<T: Serialize> KafkaEnvelope<T> {
    pub fn new(tenant_id: Uuid, scan_id: Uuid, payload: T) -> Self {
        Self {
            message_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            tenant_id,
            scan_id,
            payload,
        }
    }
}
