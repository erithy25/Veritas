use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};
use veritas_shared::types::{
    L1DetectionResult, L2DetectionResult, L3DetectionResult, ReasonCategory, ReasonCodeEntry,
    VerdictDecision,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configurable weights for combining detection-layer signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringWeights {
    /// Weight given to L1 (metadata / hash) signals.
    pub l1_weight: f32,
    /// Weight given to L2 (biometric inconsistency) signals.
    pub l2_weight: f32,
    /// Weight given to L3 (deep neural network) signals.
    pub l3_weight: f32,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            l1_weight: 0.20,
            l2_weight: 0.35,
            l3_weight: 0.45,
        }
    }
}

/// Context flags that influence the risk multiplier.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentContext {
    /// Whether a known public figure was detected in the media.
    pub public_figure_detected: bool,
    /// A score in [0,1] indicating political content relevance.
    pub political_content_score: f32,
    /// Whether the uploading account shows trust-model anomalies.
    pub account_trust_anomaly: bool,
}

/// Multiplier increments applied when context flags are active.
const PUBLIC_FIGURE_MULTIPLIER: f32 = 0.30;
const POLITICAL_CONTENT_MULTIPLIER: f32 = 0.20;
const ACCOUNT_TRUST_ANOMALY_MULTIPLIER: f32 = 0.15;

// ---------------------------------------------------------------------------
// Score computation
// ---------------------------------------------------------------------------

/// The output of the risk scoring pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringOutput {
    /// Weighted base risk score before context adjustment, in [0, 1].
    pub base_score: f32,
    /// Context multiplier (>= 1.0) applied to the base score.
    pub context_multiplier: f32,
    /// Final risk score, clamped to [0, 1].
    pub final_score: f32,
    /// Mapped verdict decision.
    pub verdict: VerdictDecision,
    /// Machine-readable reason codes explaining the score.
    pub reason_codes: Vec<ReasonCodeEntry>,
}

/// Compute the composite L1 score from individual signals.
///
/// Returns a value in [0, 1] where higher means more suspicious.
fn compute_l1_score(result: &L1DetectionResult) -> f32 {
    let mut score: f32 = 0.0;
    let mut components = 0u32;

    // Known-bad hash match is a very strong signal.
    if result.hash_match_found {
        score += 1.0;
        components += 1;
    }

    // Metadata anomaly.
    score += result.metadata_anomaly_score;
    components += 1;

    // Compression analysis.
    score += result.compression_anomaly_score;
    components += 1;

    // C2PA provenance chain -- missing or invalid is mildly suspicious.
    if let Some(valid) = result.c2pa_chain_valid {
        if !valid {
            score += 0.6;
        }
        components += 1;
    }

    // Editing tools detected (each tool adds a small bump, capped).
    if !result.detected_editing_tools.is_empty() {
        let tool_signal = (result.detected_editing_tools.len() as f32 * 0.15).min(0.6);
        score += tool_signal;
        components += 1;
    }

    if components == 0 {
        return 0.0;
    }

    (score / components as f32).clamp(0.0, 1.0)
}

/// Compute the composite L2 score from biometric signals.
fn compute_l2_score(result: &L2DetectionResult) -> f32 {
    if result.faces_analyzed == 0 {
        // No faces means L2 has nothing to contribute; treat as neutral.
        return 0.0;
    }

    let weighted = result.micro_flicker_score * 0.20
        + result.rppg_absence_score * 0.25
        + result.eye_movement_anomaly_score * 0.20
        + result.skin_texture_anomaly_score * 0.15
        + result.facial_symmetry_score * 0.20;

    weighted.clamp(0.0, 1.0)
}

/// Compute the composite L3 score from neural-network signals.
fn compute_l3_score(result: &L3DetectionResult) -> f32 {
    // The ensemble_score is already a weighted combination from the L3 service;
    // we use it as the primary signal but adjust for model agreement.
    let agreement_factor = if result.model_agreement_ratio >= 0.8 {
        1.0
    } else if result.model_agreement_ratio >= 0.5 {
        0.9
    } else {
        0.75
    };

    (result.ensemble_score * agreement_factor).clamp(0.0, 1.0)
}

/// Compute the context multiplier.  Always >= 1.0.
fn compute_context_multiplier(ctx: &ContentContext) -> f32 {
    let mut multiplier: f32 = 1.0;

    if ctx.public_figure_detected {
        multiplier += PUBLIC_FIGURE_MULTIPLIER;
    }

    // Political content score is continuous; scale the increment.
    multiplier += POLITICAL_CONTENT_MULTIPLIER * ctx.political_content_score;

    if ctx.account_trust_anomaly {
        multiplier += ACCOUNT_TRUST_ANOMALY_MULTIPLIER;
    }

    multiplier
}

/// Map a final score to a verdict decision.
fn map_verdict(score: f32) -> VerdictDecision {
    if score < 0.30 {
        VerdictDecision::Allow
    } else if score < 0.60 {
        VerdictDecision::Flag
    } else if score < 0.85 {
        VerdictDecision::FlagUrgent
    } else {
        VerdictDecision::Block
    }
}

/// Run the full scoring pipeline over available detection results.
///
/// At least one of `l1`, `l2`, or `l3` must be `Some`; the scorer will
/// re-normalize weights across the layers that are present.
#[instrument(skip_all, fields(base_score, final_score, verdict))]
pub fn compute_risk_score(
    l1: Option<&L1DetectionResult>,
    l2: Option<&L2DetectionResult>,
    l3: Option<&L3DetectionResult>,
    context: &ContentContext,
    weights: &ScoringWeights,
) -> ScoringOutput {
    let mut reason_codes: Vec<ReasonCodeEntry> = Vec::new();

    // Compute per-layer scores and accumulate reasons.
    let (l1_score, l1_active) = match l1 {
        Some(result) => {
            let s = compute_l1_score(result);
            collect_l1_reasons(result, s, &mut reason_codes);
            (s, true)
        }
        None => (0.0, false),
    };

    let (l2_score, l2_active) = match l2 {
        Some(result) => {
            let s = compute_l2_score(result);
            collect_l2_reasons(result, s, &mut reason_codes);
            (s, true)
        }
        None => (0.0, false),
    };

    let (l3_score, l3_active) = match l3 {
        Some(result) => {
            let s = compute_l3_score(result);
            collect_l3_reasons(result, s, &mut reason_codes);
            (s, true)
        }
        None => (0.0, false),
    };

    // Re-normalize weights across the layers that actually contributed.
    let total_weight = if l1_active { weights.l1_weight } else { 0.0 }
        + if l2_active { weights.l2_weight } else { 0.0 }
        + if l3_active { weights.l3_weight } else { 0.0 };

    let base_score = if total_weight > 0.0 {
        let normed = (if l1_active { weights.l1_weight } else { 0.0 } * l1_score
            + if l2_active { weights.l2_weight } else { 0.0 } * l2_score
            + if l3_active { weights.l3_weight } else { 0.0 } * l3_score)
            / total_weight;
        normed.clamp(0.0, 1.0)
    } else {
        warn!("No detection layers produced results; defaulting base score to 0");
        0.0
    };

    // Context multiplier & final score.
    let context_multiplier = compute_context_multiplier(context);
    collect_context_reasons(context, &mut reason_codes);

    let final_score = (base_score * context_multiplier).clamp(0.0, 1.0);
    let verdict = map_verdict(final_score);

    debug!(
        l1_score,
        l2_score,
        l3_score,
        base_score,
        context_multiplier,
        final_score,
        verdict = verdict.as_str(),
        reason_count = reason_codes.len(),
        "Risk score computed"
    );

    // Record tracing span fields.
    tracing::Span::current().record("base_score", base_score);
    tracing::Span::current().record("final_score", final_score);
    tracing::Span::current().record("verdict", verdict.as_str());

    ScoringOutput {
        base_score,
        context_multiplier,
        final_score,
        verdict,
        reason_codes,
    }
}

// ---------------------------------------------------------------------------
// Reason-code generation helpers
// ---------------------------------------------------------------------------

fn collect_l1_reasons(
    result: &L1DetectionResult,
    composite: f32,
    reasons: &mut Vec<ReasonCodeEntry>,
) {
    if result.hash_match_found {
        reasons.push(ReasonCodeEntry {
            code: "L1_HASH_MATCH".to_string(),
            category: ReasonCategory::L1Hash,
            explanation: format!(
                "Media matches known deepfake hash{}",
                result
                    .hash_match_id
                    .as_deref()
                    .map(|id| format!(" (id: {id})"))
                    .unwrap_or_default()
            ),
            confidence: 0.99,
        });
    }

    if result.metadata_anomaly_score > 0.5 {
        reasons.push(ReasonCodeEntry {
            code: "L1_METADATA_ANOMALY".to_string(),
            category: ReasonCategory::L1Metadata,
            explanation: format!(
                "Metadata anomaly detected (score: {:.2})",
                result.metadata_anomaly_score
            ),
            confidence: result.metadata_anomaly_score,
        });
    }

    if result.compression_anomaly_score > 0.5 {
        reasons.push(ReasonCodeEntry {
            code: "L1_COMPRESSION_ANOMALY".to_string(),
            category: ReasonCategory::L1Metadata,
            explanation: format!(
                "Compression pattern anomaly (score: {:.2})",
                result.compression_anomaly_score
            ),
            confidence: result.compression_anomaly_score,
        });
    }

    if let Some(false) = result.c2pa_chain_valid {
        reasons.push(ReasonCodeEntry {
            code: "L1_C2PA_INVALID".to_string(),
            category: ReasonCategory::L1Metadata,
            explanation: "C2PA provenance chain is invalid or tampered".to_string(),
            confidence: 0.80,
        });
    }

    if !result.detected_editing_tools.is_empty() {
        reasons.push(ReasonCodeEntry {
            code: "L1_EDITING_TOOLS".to_string(),
            category: ReasonCategory::L1Metadata,
            explanation: format!(
                "Editing tool artifacts detected: {}",
                result.detected_editing_tools.join(", ")
            ),
            confidence: (composite * 0.8).clamp(0.0, 1.0),
        });
    }
}

fn collect_l2_reasons(
    result: &L2DetectionResult,
    _composite: f32,
    reasons: &mut Vec<ReasonCodeEntry>,
) {
    if result.faces_analyzed == 0 {
        return;
    }

    if result.micro_flicker_score > 0.5 {
        reasons.push(ReasonCodeEntry {
            code: "L2_MICRO_FLICKER".to_string(),
            category: ReasonCategory::L2Biometric,
            explanation: format!(
                "Micro-flicker anomaly in facial region (score: {:.2})",
                result.micro_flicker_score
            ),
            confidence: result.micro_flicker_score,
        });
    }

    if result.rppg_absence_score > 0.6 {
        reasons.push(ReasonCodeEntry {
            code: "L2_RPPG_ABSENT".to_string(),
            category: ReasonCategory::L2Biometric,
            explanation: format!(
                "Remote photo-plethysmography signal absent or synthetic (score: {:.2})",
                result.rppg_absence_score
            ),
            confidence: result.rppg_absence_score,
        });
    }

    if result.eye_movement_anomaly_score > 0.5 {
        reasons.push(ReasonCodeEntry {
            code: "L2_EYE_ANOMALY".to_string(),
            category: ReasonCategory::L2Biometric,
            explanation: format!(
                "Eye movement pattern inconsistent with natural behavior (score: {:.2})",
                result.eye_movement_anomaly_score
            ),
            confidence: result.eye_movement_anomaly_score,
        });
    }

    if result.skin_texture_anomaly_score > 0.5 {
        reasons.push(ReasonCodeEntry {
            code: "L2_SKIN_TEXTURE".to_string(),
            category: ReasonCategory::L2Biometric,
            explanation: format!(
                "Skin texture inconsistency detected (score: {:.2})",
                result.skin_texture_anomaly_score
            ),
            confidence: result.skin_texture_anomaly_score,
        });
    }

    if result.facial_symmetry_score > 0.5 {
        reasons.push(ReasonCodeEntry {
            code: "L2_FACIAL_SYMMETRY".to_string(),
            category: ReasonCategory::L2Biometric,
            explanation: format!(
                "Unnatural facial symmetry pattern (score: {:.2})",
                result.facial_symmetry_score
            ),
            confidence: result.facial_symmetry_score,
        });
    }
}

fn collect_l3_reasons(
    result: &L3DetectionResult,
    _composite: f32,
    reasons: &mut Vec<ReasonCodeEntry>,
) {
    if result.ensemble_score > 0.5 {
        reasons.push(ReasonCodeEntry {
            code: "L3_ENSEMBLE_HIGH".to_string(),
            category: ReasonCategory::L3Neural,
            explanation: format!(
                "Neural network ensemble indicates synthetic media (score: {:.2}, agreement: {:.0}%)",
                result.ensemble_score,
                result.model_agreement_ratio * 100.0
            ),
            confidence: result.ensemble_score,
        });
    }

    if result.vit_general_score > 0.6 {
        reasons.push(ReasonCodeEntry {
            code: "L3_VIT_DETECTION".to_string(),
            category: ReasonCategory::L3Neural,
            explanation: format!(
                "Vision Transformer detected synthetic artifacts (score: {:.2})",
                result.vit_general_score
            ),
            confidence: result.vit_general_score,
        });
    }

    if result.efficientnet_gan_score > 0.6 {
        reasons.push(ReasonCodeEntry {
            code: "L3_GAN_DETECTION".to_string(),
            category: ReasonCategory::L3Neural,
            explanation: format!(
                "GAN-specific detector triggered (score: {:.2})",
                result.efficientnet_gan_score
            ),
            confidence: result.efficientnet_gan_score,
        });
    }

    if result.tcn_temporal_score > 0.6 {
        reasons.push(ReasonCodeEntry {
            code: "L3_TEMPORAL_ANOMALY".to_string(),
            category: ReasonCategory::L3Neural,
            explanation: format!(
                "Temporal consistency analysis flagged anomalies (score: {:.2})",
                result.tcn_temporal_score
            ),
            confidence: result.tcn_temporal_score,
        });
    }

    if result.diffusion_artifact_score > 0.6 {
        reasons.push(ReasonCodeEntry {
            code: "L3_DIFFUSION_ARTIFACT".to_string(),
            category: ReasonCategory::L3Neural,
            explanation: format!(
                "Diffusion model artifacts detected (score: {:.2})",
                result.diffusion_artifact_score
            ),
            confidence: result.diffusion_artifact_score,
        });
    }

    if result.lipsync_mismatch_score > 0.6 {
        reasons.push(ReasonCodeEntry {
            code: "L3_LIPSYNC_MISMATCH".to_string(),
            category: ReasonCategory::L3Neural,
            explanation: format!(
                "Lip-sync mismatch with audio track (score: {:.2})",
                result.lipsync_mismatch_score
            ),
            confidence: result.lipsync_mismatch_score,
        });
    }
}

fn collect_context_reasons(context: &ContentContext, reasons: &mut Vec<ReasonCodeEntry>) {
    if context.public_figure_detected {
        reasons.push(ReasonCodeEntry {
            code: "CTX_PUBLIC_FIGURE".to_string(),
            category: ReasonCategory::Context,
            explanation: "Public figure detected -- risk multiplier applied (+0.30)".to_string(),
            confidence: 0.90,
        });
    }

    if context.political_content_score > 0.3 {
        reasons.push(ReasonCodeEntry {
            code: "CTX_POLITICAL_CONTENT".to_string(),
            category: ReasonCategory::Context,
            explanation: format!(
                "Political content detected (score: {:.2}) -- risk multiplier applied",
                context.political_content_score
            ),
            confidence: context.political_content_score,
        });
    }

    if context.account_trust_anomaly {
        reasons.push(ReasonCodeEntry {
            code: "CTX_ACCOUNT_ANOMALY".to_string(),
            category: ReasonCategory::Context,
            explanation: "Account trust anomaly detected -- risk multiplier applied (+0.15)"
                .to_string(),
            confidence: 0.75,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_l1_clean() -> L1DetectionResult {
        L1DetectionResult {
            hash_match_found: false,
            hash_match_id: None,
            metadata_anomaly_score: 0.1,
            compression_anomaly_score: 0.05,
            c2pa_chain_valid: Some(true),
            detected_editing_tools: vec![],
            duration_ms: 5,
        }
    }

    fn make_l2_clean() -> L2DetectionResult {
        L2DetectionResult {
            micro_flicker_score: 0.05,
            rppg_absence_score: 0.10,
            rppg_signal_quality: 0.9,
            eye_movement_anomaly_score: 0.08,
            skin_texture_anomaly_score: 0.05,
            facial_symmetry_score: 0.04,
            faces_analyzed: 1,
            duration_ms: 120,
        }
    }

    fn make_l3_clean() -> L3DetectionResult {
        L3DetectionResult {
            vit_general_score: 0.10,
            efficientnet_gan_score: 0.08,
            tcn_temporal_score: 0.05,
            diffusion_artifact_score: 0.03,
            lipsync_mismatch_score: 0.02,
            ensemble_score: 0.07,
            model_agreement_ratio: 0.95,
            duration_ms: 400,
        }
    }

    #[test]
    fn clean_media_scores_allow() {
        let l1 = make_l1_clean();
        let l2 = make_l2_clean();
        let l3 = make_l3_clean();
        let ctx = ContentContext::default();
        let weights = ScoringWeights::default();

        let out = compute_risk_score(Some(&l1), Some(&l2), Some(&l3), &ctx, &weights);
        assert!(out.final_score < 0.30, "Expected ALLOW, got {}", out.final_score);
        assert_eq!(out.verdict, VerdictDecision::Allow);
        assert!(out.reason_codes.is_empty());
    }

    #[test]
    fn known_hash_triggers_block() {
        let l1 = L1DetectionResult {
            hash_match_found: true,
            hash_match_id: Some("known-deepfake-42".to_string()),
            metadata_anomaly_score: 0.9,
            compression_anomaly_score: 0.8,
            c2pa_chain_valid: Some(false),
            detected_editing_tools: vec!["FakeApp".to_string()],
            duration_ms: 3,
        };
        let l2 = L2DetectionResult {
            micro_flicker_score: 0.9,
            rppg_absence_score: 0.95,
            rppg_signal_quality: 0.1,
            eye_movement_anomaly_score: 0.85,
            skin_texture_anomaly_score: 0.8,
            facial_symmetry_score: 0.9,
            faces_analyzed: 1,
            duration_ms: 100,
        };
        let l3 = L3DetectionResult {
            vit_general_score: 0.95,
            efficientnet_gan_score: 0.90,
            tcn_temporal_score: 0.88,
            diffusion_artifact_score: 0.85,
            lipsync_mismatch_score: 0.92,
            ensemble_score: 0.93,
            model_agreement_ratio: 0.95,
            duration_ms: 350,
        };
        let ctx = ContentContext {
            public_figure_detected: true,
            political_content_score: 0.8,
            account_trust_anomaly: true,
        };
        let weights = ScoringWeights::default();

        let out = compute_risk_score(Some(&l1), Some(&l2), Some(&l3), &ctx, &weights);
        assert!(out.final_score >= 0.85, "Expected BLOCK, got {}", out.final_score);
        assert_eq!(out.verdict, VerdictDecision::Block);
        assert!(out.reason_codes.iter().any(|r| r.code == "L1_HASH_MATCH"));
    }

    #[test]
    fn context_multiplier_increases_score() {
        let l1 = make_l1_clean();
        // Moderate L3 signal that would be FLAG on its own.
        let l3 = L3DetectionResult {
            vit_general_score: 0.55,
            efficientnet_gan_score: 0.50,
            tcn_temporal_score: 0.45,
            diffusion_artifact_score: 0.40,
            lipsync_mismatch_score: 0.35,
            ensemble_score: 0.48,
            model_agreement_ratio: 0.80,
            duration_ms: 400,
        };
        let ctx_none = ContentContext::default();
        let ctx_elevated = ContentContext {
            public_figure_detected: true,
            political_content_score: 0.9,
            account_trust_anomaly: false,
        };
        let weights = ScoringWeights::default();

        let out_none = compute_risk_score(Some(&l1), None, Some(&l3), &ctx_none, &weights);
        let out_elevated =
            compute_risk_score(Some(&l1), None, Some(&l3), &ctx_elevated, &weights);

        assert!(
            out_elevated.final_score > out_none.final_score,
            "Context should increase score: {} vs {}",
            out_elevated.final_score,
            out_none.final_score,
        );
        assert!(out_elevated.context_multiplier > 1.0);
    }

    #[test]
    fn missing_layers_renormalize() {
        let l3 = make_l3_clean();
        let ctx = ContentContext::default();
        let weights = ScoringWeights::default();

        // Only L3 present -- should still produce a valid score.
        let out = compute_risk_score(None, None, Some(&l3), &ctx, &weights);
        assert!(out.final_score >= 0.0 && out.final_score <= 1.0);
    }
}
