//! Core L1 scanning logic.
//!
//! L1 is the fastest tier in the Veritas pipeline. It performs three checks
//! that complete in single-digit milliseconds:
//!
//! 1. **Metadata scan** -- EXIF/container metadata for editing-tool signatures.
//! 2. **Hash scan** -- perceptual hash lookup against a Redis database of
//!    known deepfakes and known-authentic references.
//! 3. **Compression scan** -- bitrate/GOP consistency analysis to detect
//!    re-encoding or splicing artifacts.
//!
//! The combined result produces one of three outcomes:
//! - `Allow` -- no indicators; video passes L1 without further analysis.
//! - `Block` -- a definitive match against a known deepfake hash.
//! - `Escalate` -- suspicious signals warrant L2 biometric analysis.

use anyhow::{Context, Result};
use image::DynamicImage;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, info, instrument, warn};
use veritas_shared::metrics::{DETECTION_RESULT_TOTAL, L1_SCAN_DURATION};
use veritas_shared::types::{L1DetectionResult, ReasonCategory, ReasonCodeEntry};

use crate::hash::{self, DistanceThresholds, FrameHashes, HashMatch};

// ── Configuration ───────────────────────────────────────────────────

/// L1-specific scanning thresholds. These can be overridden per-tenant
/// through the policy engine; these are safe global defaults.
#[derive(Debug, Clone)]
pub struct L1Config {
    /// Minimum metadata anomaly score to trigger escalation.
    pub metadata_escalation_threshold: f32,
    /// Minimum compression anomaly score to trigger escalation.
    pub compression_escalation_threshold: f32,
    /// Combined score above which we escalate to L2.
    pub combined_escalation_threshold: f32,
    /// Hamming distance thresholds per hash family.
    pub hash_thresholds: DistanceThresholds,
}

impl Default for L1Config {
    fn default() -> Self {
        Self {
            metadata_escalation_threshold: 0.4,
            compression_escalation_threshold: 0.5,
            combined_escalation_threshold: 0.35,
            hash_thresholds: DistanceThresholds::default(),
        }
    }
}

// ── L1 decision enum ────────────────────────────────────────────────

/// The three possible L1 outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum L1Decision {
    /// No anomalies detected. Video is allowed through without further scanning.
    Allow,
    /// Definitive match against a known deepfake hash. Block immediately.
    Block,
    /// Suspicious indicators found. Escalate to L2 for biometric analysis.
    Escalate,
}

impl L1Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Block => "BLOCK",
            Self::Escalate => "ESCALATE",
        }
    }
}

// ── Video metadata representation ───────────────────────────────────

/// Parsed metadata extracted from the video container (MP4 atoms, MKV
/// elements, EXIF tags, etc.) by the ingest service and forwarded in
/// the Kafka message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoMetadata {
    /// Human-readable codec name (e.g., "h264", "h265", "vp9").
    pub codec: Option<String>,
    /// Container format (e.g., "mp4", "mkv", "webm").
    pub container: Option<String>,
    /// Software/encoder field from container metadata.
    pub encoder: Option<String>,
    /// All EXIF/XMP key-value pairs as flat strings.
    pub exif_tags: Vec<(String, String)>,
    /// Average bitrate in kbps.
    pub bitrate_kbps: Option<f64>,
    /// Frame rate.
    pub fps: Option<f64>,
    /// Duration in seconds.
    pub duration_secs: Option<f64>,
    /// Width in pixels.
    pub width: Option<u32>,
    /// Height in pixels.
    pub height: Option<u32>,
    /// GOP (Group of Pictures) sizes observed, if parseable.
    pub gop_sizes: Vec<u32>,
    /// Whether a valid C2PA provenance chain was found.
    pub c2pa_valid: Option<bool>,
}

// ── Known deepfake tool signatures ──────────────────────────────────

/// Patterns that indicate a video was processed by a known deepfake or
/// face-swapping tool. Matched case-insensitively against encoder tags,
/// EXIF software fields, and comment metadata.
const DEEPFAKE_TOOL_SIGNATURES: &[(&str, &str)] = &[
    ("deepfacelab", "DeepFaceLab"),
    ("faceswap", "FaceSwap"),
    ("faceswap-gan", "FaceSwap-GAN"),
    ("deepfakes", "Deepfakes"),
    ("facefusion", "FaceFusion"),
    ("roop", "Roop"),
    ("simswap", "SimSwap"),
    ("ghost", "GHOST"),
    ("infoswap", "InfoSwap"),
    ("hififace", "HiFiFace"),
    ("megaportraits", "MegaPortraits"),
];

/// Tools that are suspicious but not conclusive evidence of deepfakery.
/// Professional editing software can be used legitimately, but their
/// presence raises the metadata anomaly score.
const SUSPICIOUS_TOOL_SIGNATURES: &[(&str, f32)] = &[
    ("after effects", 0.15),
    ("premiere", 0.05),
    ("davinci resolve", 0.05),
    ("ffmpeg", 0.10),
    ("handbrake", 0.08),
    ("obs", 0.03),
    ("avisynth", 0.12),
    ("vapoursynth", 0.12),
    ("nuke", 0.10),
    ("blender", 0.10),
];

// ── Metadata scan ───────────────────────────────────────────────────

/// Result of the metadata scan sub-stage.
#[derive(Debug, Clone)]
pub struct MetadataScanResult {
    pub anomaly_score: f32,
    pub detected_tools: Vec<String>,
    pub reason_codes: Vec<ReasonCodeEntry>,
}

/// Analyze video metadata for editing-tool signatures and structural anomalies.
///
/// Returns a score in [0.0, 1.0] where 0 means no anomalies and 1.0 means
/// strong evidence of manipulation.
#[instrument(skip(metadata), level = "debug")]
pub fn scan_metadata(metadata: &VideoMetadata) -> MetadataScanResult {
    let start = Instant::now();
    let mut score: f32 = 0.0;
    let mut detected_tools: Vec<String> = Vec::new();
    let mut reason_codes: Vec<ReasonCodeEntry> = Vec::new();

    // Collect all searchable text fields.
    let searchable_fields: Vec<String> = build_searchable_fields(metadata);
    let combined_lower: String = searchable_fields.join(" ").to_lowercase();

    // Check for known deepfake tool signatures.
    for &(pattern, display_name) in DEEPFAKE_TOOL_SIGNATURES {
        if combined_lower.contains(pattern) {
            score += 0.7;
            detected_tools.push(display_name.to_string());
            reason_codes.push(ReasonCodeEntry {
                code: format!("L1_META_TOOL_{}", display_name.to_uppercase().replace(' ', "_")),
                category: ReasonCategory::L1Metadata,
                explanation: format!(
                    "Known deepfake tool signature detected: {display_name}"
                ),
                confidence: 0.9,
            });
            info!(tool = display_name, "Deepfake tool signature detected in metadata");
        }
    }

    // Check for suspicious (but not conclusive) tool signatures.
    for &(pattern, weight) in SUSPICIOUS_TOOL_SIGNATURES {
        if combined_lower.contains(pattern) {
            score += weight;
            detected_tools.push(pattern.to_string());
            reason_codes.push(ReasonCodeEntry {
                code: format!(
                    "L1_META_SUSPICIOUS_{}",
                    pattern.to_uppercase().replace(' ', "_")
                ),
                category: ReasonCategory::L1Metadata,
                explanation: format!(
                    "Suspicious editing tool detected: {pattern} (weight {weight})"
                ),
                confidence: weight,
            });
            debug!(tool = pattern, weight, "Suspicious tool signature");
        }
    }

    // Check for missing or stripped metadata (common in deepfakes).
    if metadata.exif_tags.is_empty()
        && metadata.encoder.is_none()
        && metadata.codec.is_some()
    {
        score += 0.15;
        reason_codes.push(ReasonCodeEntry {
            code: "L1_META_STRIPPED".to_string(),
            category: ReasonCategory::L1Metadata,
            explanation: "Video metadata appears to have been stripped".to_string(),
            confidence: 0.5,
        });
        debug!("Metadata appears stripped");
    }

    // Check for resolution inconsistencies (non-standard aspect ratios can
    // indicate cropping to hide deepfake boundaries).
    if let (Some(w), Some(h)) = (metadata.width, metadata.height) {
        let aspect = w as f64 / h as f64;
        let is_standard = [16.0 / 9.0, 9.0 / 16.0, 4.0 / 3.0, 3.0 / 4.0, 1.0]
            .iter()
            .any(|&standard| (aspect - standard).abs() < 0.02);

        if !is_standard {
            score += 0.08;
            reason_codes.push(ReasonCodeEntry {
                code: "L1_META_NONSTANDARD_ASPECT".to_string(),
                category: ReasonCategory::L1Metadata,
                explanation: format!(
                    "Non-standard aspect ratio {aspect:.3} ({w}x{h}) may indicate cropping"
                ),
                confidence: 0.3,
            });
            debug!(width = w, height = h, aspect, "Non-standard aspect ratio");
        }
    }

    // C2PA provenance: if a valid chain exists and is intact, lower the score.
    if metadata.c2pa_valid == Some(true) {
        score = (score - 0.2).max(0.0);
        debug!("Valid C2PA provenance chain found, reducing metadata anomaly score");
    }

    // Clamp to [0.0, 1.0]
    score = score.clamp(0.0, 1.0);

    debug!(
        score,
        tool_count = detected_tools.len(),
        elapsed_us = start.elapsed().as_micros() as u64,
        "Metadata scan complete"
    );

    MetadataScanResult {
        anomaly_score: score,
        detected_tools,
        reason_codes,
    }
}

/// Build a list of searchable text fields from the video metadata.
fn build_searchable_fields(metadata: &VideoMetadata) -> Vec<String> {
    let mut fields = Vec::new();
    if let Some(ref enc) = metadata.encoder {
        fields.push(enc.clone());
    }
    if let Some(ref codec) = metadata.codec {
        fields.push(codec.clone());
    }
    if let Some(ref container) = metadata.container {
        fields.push(container.clone());
    }
    for (key, value) in &metadata.exif_tags {
        fields.push(format!("{key}={value}"));
    }
    fields
}

// ── Hash scan ───────────────────────────────────────────────────────

/// Result of the hash scan sub-stage.
#[derive(Debug, Clone)]
pub struct HashScanResult {
    pub match_found: bool,
    pub match_id: Option<String>,
    pub best_match: Option<HashMatch>,
    pub reason_codes: Vec<ReasonCodeEntry>,
}

/// Compute perceptual hashes for sampled frames and check Redis for
/// near-duplicate matches against the known-deepfake database.
#[instrument(skip(conn, frames), fields(frame_count = frames.len()), level = "debug")]
pub async fn scan_hash(
    conn: &mut redis::aio::MultiplexedConnection,
    frames: &[DynamicImage],
    thresholds: &DistanceThresholds,
) -> Result<HashScanResult> {
    let start = Instant::now();

    if frames.is_empty() {
        debug!("No frames provided for hash scan");
        return Ok(HashScanResult {
            match_found: false,
            match_id: None,
            best_match: None,
            reason_codes: vec![],
        });
    }

    let best_match = hash::batch_query(conn, frames, thresholds).await?;

    let (match_found, match_id, reason_codes) = match &best_match {
        Some(m) => {
            info!(
                reference_id = %m.reference_id,
                family = %m.family,
                distance = m.distance,
                "Known deepfake hash match found"
            );
            let codes = vec![ReasonCodeEntry {
                code: "L1_HASH_MATCH".to_string(),
                category: ReasonCategory::L1Hash,
                explanation: format!(
                    "Perceptual hash match against known deepfake: {} (family={}, distance={})",
                    m.reference_id, m.family, m.distance
                ),
                confidence: match m.distance {
                    0 => 1.0,
                    1..=3 => 0.95,
                    4..=6 => 0.85,
                    _ => 0.70,
                },
            }];
            (true, Some(m.reference_id.clone()), codes)
        }
        None => {
            debug!(
                elapsed_us = start.elapsed().as_micros() as u64,
                "No hash match found"
            );
            (false, None, vec![])
        }
    };

    Ok(HashScanResult {
        match_found,
        match_id,
        best_match,
        reason_codes,
    })
}

// ── Compression scan ────────────────────────────────────────────────

/// Result of the compression analysis sub-stage.
#[derive(Debug, Clone)]
pub struct CompressionScanResult {
    pub anomaly_score: f32,
    pub reason_codes: Vec<ReasonCodeEntry>,
}

/// Analyze compression characteristics for signs of re-encoding or splicing.
///
/// Deepfake videos frequently exhibit:
/// - Double-compression artifacts (the original video was decoded, face-swapped,
///   then re-encoded, adding a second generation of lossy compression).
/// - Inconsistent GOP structures from splicing multiple sources.
/// - Anomalous bitrate for the given resolution (over-compressed to hide
///   artifacts, or unusually high to preserve deepfake quality).
#[instrument(skip(metadata), level = "debug")]
pub fn scan_compression(metadata: &VideoMetadata) -> CompressionScanResult {
    let start = Instant::now();
    let mut score: f32 = 0.0;
    let mut reason_codes: Vec<ReasonCodeEntry> = Vec::new();

    // ---- GOP consistency check ----
    if metadata.gop_sizes.len() >= 2 {
        let mean_gop: f64 =
            metadata.gop_sizes.iter().map(|&g| g as f64).sum::<f64>() / metadata.gop_sizes.len() as f64;

        let variance: f64 = metadata
            .gop_sizes
            .iter()
            .map(|&g| {
                let diff = g as f64 - mean_gop;
                diff * diff
            })
            .sum::<f64>()
            / metadata.gop_sizes.len() as f64;

        let std_dev = variance.sqrt();
        let coefficient_of_variation = if mean_gop > 0.0 {
            std_dev / mean_gop
        } else {
            0.0
        };

        // A CV above 0.3 suggests the GOP structure is inconsistent,
        // which is a strong indicator of splicing or re-encoding.
        if coefficient_of_variation > 0.3 {
            let gop_score = (coefficient_of_variation as f32 - 0.3).min(0.5);
            score += gop_score;
            reason_codes.push(ReasonCodeEntry {
                code: "L1_COMP_GOP_INCONSISTENT".to_string(),
                category: ReasonCategory::L1Metadata,
                explanation: format!(
                    "GOP structure inconsistency detected: CV={coefficient_of_variation:.3}, \
                     mean_gop={mean_gop:.1}, std_dev={std_dev:.1}"
                ),
                confidence: (gop_score * 1.5).min(1.0),
            });
            debug!(
                coefficient_of_variation,
                mean_gop,
                std_dev,
                gop_score,
                "GOP inconsistency detected"
            );
        }
    }

    // ---- Bitrate anomaly check ----
    if let (Some(bitrate), Some(width), Some(height)) =
        (metadata.bitrate_kbps, metadata.width, metadata.height)
    {
        let pixel_count = (width as f64) * (height as f64);

        // Expected bitrate heuristic: ~0.1 bits per pixel at 30fps for H.264.
        // This is intentionally broad; we only flag extreme outliers.
        let expected_bpp = 0.1;
        let fps = metadata.fps.unwrap_or(30.0);
        let expected_bitrate_kbps = pixel_count * expected_bpp * fps / 1000.0;

        let ratio = bitrate / expected_bitrate_kbps;

        // Under-compressed (ratio < 0.15): deepfake with aggressive compression
        // to hide artifacts.
        if ratio < 0.15 {
            let severity = (0.15 - ratio as f32).min(0.3);
            score += severity;
            reason_codes.push(ReasonCodeEntry {
                code: "L1_COMP_UNDERCOMPRESSED".to_string(),
                category: ReasonCategory::L1Metadata,
                explanation: format!(
                    "Bitrate anomalously low for resolution: {bitrate:.0} kbps for \
                     {width}x{height} (expected ~{expected_bitrate_kbps:.0} kbps, ratio={ratio:.3})"
                ),
                confidence: severity,
            });
            debug!(bitrate, expected_bitrate_kbps, ratio, "Under-compressed");
        }

        // Over-compressed (ratio > 4.0): unusual but can indicate re-encoding
        // at maximum quality to preserve deepfake detail.
        if ratio > 4.0 {
            let severity = ((ratio as f32 - 4.0) * 0.05).min(0.2);
            score += severity;
            reason_codes.push(ReasonCodeEntry {
                code: "L1_COMP_OVERCOMPRESSED".to_string(),
                category: ReasonCategory::L1Metadata,
                explanation: format!(
                    "Bitrate anomalously high for resolution: {bitrate:.0} kbps for \
                     {width}x{height} (expected ~{expected_bitrate_kbps:.0} kbps, ratio={ratio:.3})"
                ),
                confidence: severity,
            });
            debug!(bitrate, expected_bitrate_kbps, ratio, "Over-compressed");
        }
    }

    // ---- Double-encoding detection ----
    // If encoder metadata explicitly references a known transcoding tool AND
    // GOP structure is irregular, bump the score.
    if let Some(ref encoder) = metadata.encoder {
        let encoder_lower = encoder.to_lowercase();
        let is_transcoder = ["ffmpeg", "handbrake", "avidemux", "mencoder"]
            .iter()
            .any(|&t| encoder_lower.contains(t));

        if is_transcoder && !metadata.gop_sizes.is_empty() {
            // We already checked GOP above; add a small additional signal
            // for the combination of transcoder + any GOP data present.
            score += 0.05;
            reason_codes.push(ReasonCodeEntry {
                code: "L1_COMP_TRANSCODED".to_string(),
                category: ReasonCategory::L1Metadata,
                explanation: format!(
                    "Video was processed by transcoding tool ({encoder}) with explicit GOP data"
                ),
                confidence: 0.3,
            });
            debug!(encoder = encoder_lower.as_str(), "Transcoder detected");
        }
    }

    score = score.clamp(0.0, 1.0);

    debug!(
        score,
        reason_count = reason_codes.len(),
        elapsed_us = start.elapsed().as_micros() as u64,
        "Compression scan complete"
    );

    CompressionScanResult {
        anomaly_score: score,
        reason_codes,
    }
}

// ── L1 evaluation (combines all sub-scans) ──────────────────────────

/// Combined L1 output used for Kafka publishing and downstream consumption.
#[derive(Debug, Clone)]
pub struct L1Evaluation {
    pub decision: L1Decision,
    pub detection_result: L1DetectionResult,
    pub reason_codes: Vec<ReasonCodeEntry>,
}

/// Combine the three L1 sub-scan results into a final decision.
///
/// Decision logic:
/// 1. If a hash match is found with distance 0 -> **Block** (exact known deepfake).
/// 2. If a hash match is found with small distance -> **Block** (near-exact match).
/// 3. If metadata anomaly score or compression anomaly score exceeds their
///    respective thresholds -> **Escalate** to L2.
/// 4. If the weighted combination of all signals exceeds the combined
///    threshold -> **Escalate**.
/// 5. Otherwise -> **Allow**.
#[instrument(skip(metadata_result, hash_result, compression_result), level = "debug")]
pub fn evaluate_l1(
    config: &L1Config,
    metadata_result: &MetadataScanResult,
    hash_result: &HashScanResult,
    compression_result: &CompressionScanResult,
    duration_ms: u32,
    tenant_id: &str,
) -> L1Evaluation {
    let mut all_reason_codes: Vec<ReasonCodeEntry> = Vec::new();
    all_reason_codes.extend(metadata_result.reason_codes.clone());
    all_reason_codes.extend(hash_result.reason_codes.clone());
    all_reason_codes.extend(compression_result.reason_codes.clone());

    // ---- Hash match -> Block ----
    if hash_result.match_found {
        let decision = if hash_result
            .best_match
            .as_ref()
            .is_some_and(|m| m.distance <= 3)
        {
            L1Decision::Block
        } else {
            // Weaker hash match: escalate rather than block outright.
            L1Decision::Escalate
        };

        let decision_str = decision.as_str();
        info!(
            decision = decision_str,
            match_id = ?hash_result.match_id,
            metadata_score = metadata_result.anomaly_score,
            compression_score = compression_result.anomaly_score,
            "L1 evaluation: hash match found"
        );

        DETECTION_RESULT_TOTAL
            .with_label_values(&["l1", decision_str, tenant_id])
            .inc();
        L1_SCAN_DURATION
            .with_label_values(&[decision_str])
            .observe(duration_ms as f64);

        return L1Evaluation {
            decision,
            detection_result: L1DetectionResult {
                hash_match_found: true,
                hash_match_id: hash_result.match_id.clone(),
                metadata_anomaly_score: metadata_result.anomaly_score,
                compression_anomaly_score: compression_result.anomaly_score,
                c2pa_chain_valid: None,
                detected_editing_tools: metadata_result.detected_tools.clone(),
                duration_ms,
            },
            reason_codes: all_reason_codes,
        };
    }

    // ---- Threshold-based escalation ----
    let metadata_exceeds = metadata_result.anomaly_score >= config.metadata_escalation_threshold;
    let compression_exceeds =
        compression_result.anomaly_score >= config.compression_escalation_threshold;

    // Weighted combination: metadata signals are weighted higher because
    // deepfake tool signatures are a stronger prior than compression heuristics.
    let combined_score =
        metadata_result.anomaly_score * 0.6 + compression_result.anomaly_score * 0.4;
    let combined_exceeds = combined_score >= config.combined_escalation_threshold;

    let decision = if metadata_exceeds || compression_exceeds || combined_exceeds {
        L1Decision::Escalate
    } else {
        L1Decision::Allow
    };

    let decision_str = decision.as_str();
    info!(
        decision = decision_str,
        metadata_score = metadata_result.anomaly_score,
        compression_score = compression_result.anomaly_score,
        combined_score,
        metadata_exceeds,
        compression_exceeds,
        combined_exceeds,
        "L1 evaluation complete"
    );

    DETECTION_RESULT_TOTAL
        .with_label_values(&["l1", decision_str, tenant_id])
        .inc();
    L1_SCAN_DURATION
        .with_label_values(&[decision_str])
        .observe(duration_ms as f64);

    L1Evaluation {
        decision,
        detection_result: L1DetectionResult {
            hash_match_found: false,
            hash_match_id: None,
            metadata_anomaly_score: metadata_result.anomaly_score,
            compression_anomaly_score: compression_result.anomaly_score,
            c2pa_chain_valid: None,
            detected_editing_tools: metadata_result.detected_tools.clone(),
            duration_ms,
        },
        reason_codes: all_reason_codes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_metadata() -> VideoMetadata {
        VideoMetadata {
            codec: Some("h264".to_string()),
            container: Some("mp4".to_string()),
            encoder: None,
            exif_tags: vec![],
            bitrate_kbps: None,
            fps: None,
            duration_secs: None,
            width: Some(1920),
            height: Some(1080),
            gop_sizes: vec![],
            c2pa_valid: None,
        }
    }

    #[test]
    fn clean_metadata_scores_low() {
        let meta = empty_metadata();
        let result = scan_metadata(&meta);
        // Clean video with standard resolution and no suspicious tags
        // should score very low. The stripped-metadata check adds 0.15.
        assert!(result.anomaly_score < 0.5, "Clean metadata should score low");
        assert!(result.detected_tools.is_empty());
    }

    #[test]
    fn deepfacelab_detected() {
        let mut meta = empty_metadata();
        meta.encoder = Some("Lavf58.29.100 DeepFaceLab".to_string());

        let result = scan_metadata(&meta);
        assert!(result.anomaly_score >= 0.7, "DeepFaceLab should score high");
        assert!(result.detected_tools.contains(&"DeepFaceLab".to_string()));
    }

    #[test]
    fn faceswap_detected() {
        let mut meta = empty_metadata();
        meta.exif_tags.push(("Software".to_string(), "faceswap v2.1".to_string()));

        let result = scan_metadata(&meta);
        assert!(result.anomaly_score >= 0.7);
        assert!(result.detected_tools.contains(&"FaceSwap".to_string()));
    }

    #[test]
    fn c2pa_valid_reduces_score() {
        let mut meta = empty_metadata();
        meta.encoder = Some("ffmpeg".to_string());
        meta.c2pa_valid = Some(true);

        let result = scan_metadata(&meta);
        // ffmpeg alone adds 0.10. C2PA subtracts 0.20. Result clamped to 0.
        assert!(result.anomaly_score < 0.05);
    }

    #[test]
    fn consistent_gop_scores_low() {
        let mut meta = empty_metadata();
        // All GOPs identical = CV of 0 -> no anomaly.
        meta.gop_sizes = vec![30, 30, 30, 30, 30];
        meta.bitrate_kbps = Some(5000.0);

        let result = scan_compression(&meta);
        assert!(
            result.anomaly_score < 0.1,
            "Consistent GOP should score low, got {}",
            result.anomaly_score
        );
    }

    #[test]
    fn inconsistent_gop_scores_higher() {
        let mut meta = empty_metadata();
        // Wildly varying GOP sizes.
        meta.gop_sizes = vec![5, 60, 10, 90, 3, 120];
        meta.bitrate_kbps = Some(5000.0);

        let result = scan_compression(&meta);
        assert!(
            result.anomaly_score > 0.1,
            "Inconsistent GOP should score higher, got {}",
            result.anomaly_score
        );
    }

    #[test]
    fn evaluate_l1_allow_on_clean() {
        let config = L1Config::default();

        let meta_result = MetadataScanResult {
            anomaly_score: 0.0,
            detected_tools: vec![],
            reason_codes: vec![],
        };
        let hash_result = HashScanResult {
            match_found: false,
            match_id: None,
            best_match: None,
            reason_codes: vec![],
        };
        let compression_result = CompressionScanResult {
            anomaly_score: 0.0,
            reason_codes: vec![],
        };

        let eval = evaluate_l1(&config, &meta_result, &hash_result, &compression_result, 5, "test");
        assert_eq!(eval.decision, L1Decision::Allow);
    }

    #[test]
    fn evaluate_l1_block_on_exact_hash() {
        let config = L1Config::default();

        let meta_result = MetadataScanResult {
            anomaly_score: 0.0,
            detected_tools: vec![],
            reason_codes: vec![],
        };
        let hash_result = HashScanResult {
            match_found: true,
            match_id: Some("ref-12345".to_string()),
            best_match: Some(HashMatch {
                reference_id: "ref-12345".to_string(),
                family: hash::HashFamily::PHash,
                distance: 0,
            }),
            reason_codes: vec![ReasonCodeEntry {
                code: "L1_HASH_MATCH".to_string(),
                category: ReasonCategory::L1Hash,
                explanation: "Exact hash match".to_string(),
                confidence: 1.0,
            }],
        };
        let compression_result = CompressionScanResult {
            anomaly_score: 0.0,
            reason_codes: vec![],
        };

        let eval = evaluate_l1(&config, &meta_result, &hash_result, &compression_result, 3, "test");
        assert_eq!(eval.decision, L1Decision::Block);
    }

    #[test]
    fn evaluate_l1_escalate_on_high_metadata_score() {
        let config = L1Config::default();

        let meta_result = MetadataScanResult {
            anomaly_score: 0.8,
            detected_tools: vec!["DeepFaceLab".to_string()],
            reason_codes: vec![],
        };
        let hash_result = HashScanResult {
            match_found: false,
            match_id: None,
            best_match: None,
            reason_codes: vec![],
        };
        let compression_result = CompressionScanResult {
            anomaly_score: 0.0,
            reason_codes: vec![],
        };

        let eval = evaluate_l1(&config, &meta_result, &hash_result, &compression_result, 4, "test");
        assert_eq!(eval.decision, L1Decision::Escalate);
    }
}
