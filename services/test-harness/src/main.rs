use std::time::Instant;

use anyhow::Result;
use veritas_shared::types::{
    L1DetectionResult, L2DetectionResult, L3DetectionResult, VerdictDecision,
};

// ═══════════════════════════════════════════════════════════════════
//  Veritas Test Harness - Interactive Smoke Tests
// ═══════════════════════════════════════════════════════════════════

fn main() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║          VERITAS B2B - Test Harness v0.1.0                  ║");
    println!("║          Deepfake Detection Middleware                      ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let start = Instant::now();
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut sections = Vec::new();

    // ── Section 1: Scoring Engine ──────────────────────────────────
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  [1/4]  Scoring Engine                                      │");
    println!("└──────────────────────────────────────────────────────────────┘");

    run_test("Clean media -> ALLOW verdict", &mut passed, &mut failed, || {
        let l1 = make_l1_clean();
        let l2 = make_l2_clean();
        let l3 = make_l3_clean();
        let score = compute_risk_score(Some(&l1), Some(&l2), Some(&l3), false, 0.0, false);
        assert(score.final_score < 0.30, format!("Expected score < 0.30, got {:.3}", score.final_score))?;
        assert(score.verdict == VerdictDecision::Allow, format!("Expected ALLOW, got {:?}", score.verdict))?;
        Ok(format!("score={:.3} verdict={}", score.final_score, score.verdict.as_str()))
    });

    run_test("Known hash match -> BLOCK verdict", &mut passed, &mut failed, || {
        let l1 = make_l1_malicious();
        let l2 = make_l2_malicious();
        let l3 = make_l3_malicious();
        let score = compute_risk_score(Some(&l1), Some(&l2), Some(&l3), true, 0.8, true);
        assert(score.final_score >= 0.85, format!("Expected score >= 0.85, got {:.3}", score.final_score))?;
        assert(score.verdict == VerdictDecision::Block, format!("Expected BLOCK, got {:?}", score.verdict))?;
        Ok(format!("score={:.3} verdict={}", score.final_score, score.verdict.as_str()))
    });

    run_test("Moderate signal -> FLAG verdict", &mut passed, &mut failed, || {
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
        let score = compute_risk_score(None, None, Some(&l3), false, 0.0, false);
        assert(score.final_score >= 0.30 && score.final_score < 0.60,
            format!("Expected 0.30 <= score < 0.60, got {:.3}", score.final_score))?;
        assert(score.verdict == VerdictDecision::Flag, format!("Expected FLAG, got {:?}", score.verdict))?;
        Ok(format!("score={:.3} verdict={}", score.final_score, score.verdict.as_str()))
    });

    run_test("Context multiplier raises score", &mut passed, &mut failed, || {
        let l1 = make_l1_clean();
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
        let no_ctx = compute_risk_score(Some(&l1), None, Some(&l3), false, 0.0, false);
        let with_ctx = compute_risk_score(Some(&l1), None, Some(&l3), true, 0.9, false);
        assert(with_ctx.final_score > no_ctx.final_score,
            format!("Context should increase score: {:.3} vs {:.3}", with_ctx.final_score, no_ctx.final_score))?;
        assert(with_ctx.context_multiplier > 1.0,
            format!("Multiplier should be > 1.0, got {:.3}", with_ctx.context_multiplier))?;
        Ok(format!("without={:.3} with_ctx={:.3} multiplier={:.2}x",
            no_ctx.final_score, with_ctx.final_score, with_ctx.context_multiplier))
    });

    run_test("Missing layers re-normalize weights", &mut passed, &mut failed, || {
        let l3 = make_l3_clean();
        let score = compute_risk_score(None, None, Some(&l3), false, 0.0, false);
        assert(score.final_score >= 0.0 && score.final_score <= 1.0,
            format!("Score out of range: {:.3}", score.final_score))?;
        Ok(format!("L3-only score={:.3} verdict={}", score.final_score, score.verdict.as_str()))
    });

    sections.push(("Scoring Engine", passed, failed));

    // ── Section 2: L1 Scanner Logic ────────────────────────────────
    println!();
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  [2/4]  L1 Scanner Logic                                    │");
    println!("└──────────────────────────────────────────────────────────────┘");

    let sec_start_p = passed;
    let sec_start_f = failed;

    run_test("Clean metadata -> low anomaly score", &mut passed, &mut failed, || {
        let score = scan_metadata(None, "h264", "mp4", &[], None, None, None, None, &[]);
        assert(score < 0.5, format!("Clean metadata should score < 0.5, got {:.3}", score))?;
        Ok(format!("anomaly_score={:.3}", score))
    });

    run_test("DeepFaceLab in encoder -> high score", &mut passed, &mut failed, || {
        let score = scan_metadata(
            Some("Lavf58.29.100 DeepFaceLab"), "h264", "mp4", &[], None, None, None, None, &[]
        );
        assert(score >= 0.7, format!("DeepFaceLab should score >= 0.7, got {:.3}", score))?;
        Ok(format!("anomaly_score={:.3}", score))
    });

    run_test("FaceSwap in EXIF -> high score", &mut passed, &mut failed, || {
        let score = scan_metadata(
            None, "h264", "mp4", &[("Software", "faceswap v2.1")], None, None, None, None, &[]
        );
        assert(score >= 0.7, format!("FaceSwap should score >= 0.7, got {:.3}", score))?;
        Ok(format!("anomaly_score={:.3}", score))
    });

    run_test("Valid C2PA reduces score", &mut passed, &mut failed, || {
        let score_without = scan_metadata(
            Some("ffmpeg"), "h264", "mp4", &[], None, None, None, None, &[]
        );
        let score_with = scan_metadata(
            Some("ffmpeg"), "h264", "mp4", &[], None, None, None, Some(true), &[]
        );
        assert(score_with < score_without,
            format!("C2PA should reduce score: with={:.3} vs without={:.3}", score_with, score_without))?;
        Ok(format!("without_c2pa={:.3} with_c2pa={:.3}", score_without, score_with))
    });

    run_test("Consistent GOP -> low compression score", &mut passed, &mut failed, || {
        let score = scan_compression(&[30, 30, 30, 30, 30], Some(5000.0), Some(1920), Some(1080), None, None);
        assert(score < 0.1, format!("Consistent GOP should score < 0.1, got {:.3}", score))?;
        Ok(format!("compression_score={:.3}", score))
    });

    run_test("Inconsistent GOP -> higher score", &mut passed, &mut failed, || {
        let score = scan_compression(&[5, 60, 10, 90, 3, 120], Some(5000.0), Some(1920), Some(1080), None, None);
        assert(score > 0.1, format!("Inconsistent GOP should score > 0.1, got {:.3}", score))?;
        Ok(format!("compression_score={:.3}", score))
    });

    run_test("Perceptual hash: Hamming distance", &mut passed, &mut failed, || {
        let d1 = hamming_distance(0xDEADBEEF, 0xDEADBEEF);
        assert(d1 == 0, format!("Identical hashes should have distance 0, got {}", d1))?;
        let d2 = hamming_distance(0b1000, 0b0000);
        assert(d2 == 1, format!("Single bit flip should have distance 1, got {}", d2))?;
        let d3 = hamming_distance(0u64, u64::MAX);
        assert(d3 == 64, format!("All bits flipped should have distance 64, got {}", d3))?;
        Ok(format!("identical=0 one_bit=1 all_bits=64"))
    });

    sections.push(("L1 Scanner", passed - sec_start_p, failed - sec_start_f));

    // ── Section 3: Cryptographic Signing ───────────────────────────
    println!();
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  [3/4]  Cryptographic Signing (Ed25519)                     │");
    println!("└──────────────────────────────────────────────────────────────┘");

    let sec_start_p = passed;
    let sec_start_f = failed;

    run_test("Sign and verify verdict", &mut passed, &mut failed, || {
        let (signed, key_id) = sign_test_verdict()?;
        let verified = verify_signed_verdict(&signed)?;
        assert(verified, "Signature verification failed".to_string())?;
        Ok(format!("key_id={} signed_size={} bytes verified=true", key_id, signed.len()))
    });

    run_test("Tampered verdict fails verification", &mut passed, &mut failed, || {
        let (signed, _) = sign_test_verdict()?;
        // Tamper with the verdict
        let mut verdict: serde_json::Value = serde_json::from_slice(&signed)?;
        if let Some(obj) = verdict.as_object_mut() {
            obj.insert("verdict".to_string(), serde_json::json!("ALLOW"));
        }
        let tampered = serde_json::to_vec(&verdict)?;
        let verified = verify_signed_verdict(&tampered)?;
        assert(!verified, "Tampered verdict should NOT verify".to_string())?;
        Ok("tampered_verdict correctly rejected".to_string())
    });

    run_test("Signature contains required fields", &mut passed, &mut failed, || {
        let (signed, _) = sign_test_verdict()?;
        let verdict: serde_json::Value = serde_json::from_slice(&signed)?;
        let sig = verdict.get("signature").ok_or(anyhow::anyhow!("No signature field"))?;
        assert(sig.get("signature_bytes").is_some(), "Missing signature_bytes".to_string())?;
        assert(sig.get("key_id").is_some(), "Missing key_id".to_string())?;
        assert(sig.get("algorithm").is_some(), "Missing algorithm".to_string())?;
        assert(sig.get("content_hash").is_some(), "Missing content_hash".to_string())?;
        assert(sig.get("signed_at").is_some(), "Missing signed_at".to_string())?;
        let algo = sig["algorithm"].as_str().unwrap_or("");
        Ok(format!("algorithm={} fields=5/5", algo))
    });

    sections.push(("Crypto Signing", passed - sec_start_p, failed - sec_start_f));

    // ── Section 4: Type System & Serialization ─────────────────────
    println!();
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  [4/4]  Type System & Serialization                         │");
    println!("└──────────────────────────────────────────────────────────────┘");

    let sec_start_p = passed;
    let sec_start_f = failed;

    run_test("VerdictDecision serialization roundtrip", &mut passed, &mut failed, || {
        for verdict in &[VerdictDecision::Allow, VerdictDecision::Flag, VerdictDecision::FlagUrgent, VerdictDecision::Block] {
            let json = serde_json::to_string(verdict)?;
            let back: VerdictDecision = serde_json::from_str(&json)?;
            assert(back == *verdict, format!("Roundtrip failed for {:?}", verdict))?;
        }
        Ok("Allow/Flag/FlagUrgent/Block all roundtrip OK".to_string())
    });

    run_test("L1DetectionResult JSON roundtrip", &mut passed, &mut failed, || {
        let l1 = make_l1_malicious();
        let json = serde_json::to_string_pretty(&l1)?;
        let back: L1DetectionResult = serde_json::from_str(&json)?;
        assert(back.hash_match_found == l1.hash_match_found, "hash_match_found mismatch".to_string())?;
        assert(back.metadata_anomaly_score == l1.metadata_anomaly_score, "metadata score mismatch".to_string())?;
        Ok(format!("json_size={} bytes", json.len()))
    });

    run_test("ScanResult full pipeline roundtrip", &mut passed, &mut failed, || {
        let scan = veritas_shared::types::ScanResult {
            scan_context: veritas_shared::types::ScanContext {
                scan_id: uuid::Uuid::new_v4(),
                upload_id: "upload-test-123".to_string(),
                tenant_id: uuid::Uuid::new_v4(),
                priority: veritas_shared::types::ScanPriority::High,
                max_tier: 3,
                created_at: chrono::Utc::now(),
                processing_region: "eu-west-1".to_string(),
            },
            l1_result: Some(make_l1_clean()),
            l2_result: Some(make_l2_clean()),
            l3_result: Some(make_l3_clean()),
            reason_codes: vec![],
            risk_score: 0.15,
            context_multiplier: 1.0,
            public_figure_detected: false,
            political_context_score: 0.0,
            verdict: VerdictDecision::Allow,
            model_versions: [("vit".to_string(), "v1.2.0".to_string())].into(),
            total_duration_ms: 525,
        };
        let json = serde_json::to_string(&scan)?;
        let back: veritas_shared::types::ScanResult = serde_json::from_str(&json)?;
        assert(back.verdict == scan.verdict, "Verdict mismatch".to_string())?;
        assert(back.risk_score == scan.risk_score, "Risk score mismatch".to_string())?;
        Ok(format!("json_size={} bytes verdict={}", json.len(), back.verdict.as_str()))
    });

    run_test("KafkaEnvelope wrapping", &mut passed, &mut failed, || {
        let tenant_id = uuid::Uuid::new_v4();
        let scan_id = uuid::Uuid::new_v4();
        let envelope = veritas_shared::types::KafkaEnvelope::new(
            tenant_id, scan_id, make_l1_clean()
        );
        let json = serde_json::to_string(&envelope)?;
        assert(json.contains(&tenant_id.to_string()), "Missing tenant_id in envelope".to_string())?;
        assert(json.contains(&scan_id.to_string()), "Missing scan_id in envelope".to_string())?;
        Ok(format!("envelope_size={} bytes", json.len()))
    });

    sections.push(("Types & Serialization", passed - sec_start_p, failed - sec_start_f));

    // ── Summary ────────────────────────────────────────────────────
    let elapsed = start.elapsed();
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                      TEST SUMMARY                          ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    for (name, p, f) in &sections {
        let status = if *f == 0 { "PASS" } else { "FAIL" };
        println!("║  {:<28} {:>3} passed  {:>3} failed  [{}] ║",
            name, p, f, status);
    }
    println!("╠══════════════════════════════════════════════════════════════╣");
    let total = passed + failed;
    let overall = if failed == 0 { "ALL PASSED" } else { "FAILURES" };
    println!("║  Total: {}/{} passed in {:.1}ms           {:>10}  ║",
        passed, total, elapsed.as_secs_f64() * 1000.0, overall);
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    if failed > 0 {
        std::process::exit(1);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Test runner
// ═══════════════════════════════════════════════════════════════════

fn run_test<F>(name: &str, passed: &mut u32, failed: &mut u32, f: F)
where
    F: FnOnce() -> Result<String>,
{
    let start = Instant::now();
    match f() {
        Ok(detail) => {
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            println!("  \x1b[32mPASS\x1b[0m  {:<42} [{:.1}ms] {}", name, ms, detail);
            *passed += 1;
        }
        Err(e) => {
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            println!("  \x1b[31mFAIL\x1b[0m  {:<42} [{:.1}ms] {}", name, ms, e);
            *failed += 1;
        }
    }
}

fn assert(condition: bool, msg: String) -> Result<()> {
    if !condition {
        anyhow::bail!(msg);
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
//  Inline scoring engine (mirrors services/scorer logic)
// ═══════════════════════════════════════════════════════════════════

struct ScoringOutput {
    #[allow(dead_code)]
    base_score: f32,
    context_multiplier: f32,
    final_score: f32,
    verdict: VerdictDecision,
}

fn compute_risk_score(
    l1: Option<&L1DetectionResult>,
    l2: Option<&L2DetectionResult>,
    l3: Option<&L3DetectionResult>,
    public_figure: bool,
    political_score: f32,
    account_anomaly: bool,
) -> ScoringOutput {
    let l1_weight: f32 = 0.20;
    let l2_weight: f32 = 0.35;
    let l3_weight: f32 = 0.45;

    let (l1_score, l1_active) = l1.map(|r| (compute_l1_score(r), true)).unwrap_or((0.0, false));
    let (l2_score, l2_active) = l2.map(|r| (compute_l2_score(r), true)).unwrap_or((0.0, false));
    let (l3_score, l3_active) = l3.map(|r| (compute_l3_score(r), true)).unwrap_or((0.0, false));

    let total_weight = if l1_active { l1_weight } else { 0.0 }
        + if l2_active { l2_weight } else { 0.0 }
        + if l3_active { l3_weight } else { 0.0 };

    let base_score = if total_weight > 0.0 {
        ((if l1_active { l1_weight } else { 0.0 } * l1_score
            + if l2_active { l2_weight } else { 0.0 } * l2_score
            + if l3_active { l3_weight } else { 0.0 } * l3_score)
            / total_weight)
            .clamp(0.0, 1.0)
    } else {
        0.0
    };

    let mut multiplier: f32 = 1.0;
    if public_figure { multiplier += 0.30; }
    multiplier += 0.20 * political_score;
    if account_anomaly { multiplier += 0.15; }

    let final_score = (base_score * multiplier).clamp(0.0, 1.0);
    let verdict = if final_score < 0.30 {
        VerdictDecision::Allow
    } else if final_score < 0.60 {
        VerdictDecision::Flag
    } else if final_score < 0.85 {
        VerdictDecision::FlagUrgent
    } else {
        VerdictDecision::Block
    };

    ScoringOutput { base_score, context_multiplier: multiplier, final_score, verdict }
}

fn compute_l1_score(r: &L1DetectionResult) -> f32 {
    let mut score: f32 = 0.0;
    let mut components = 0u32;
    if r.hash_match_found { score += 1.0; components += 1; }
    score += r.metadata_anomaly_score; components += 1;
    score += r.compression_anomaly_score; components += 1;
    if let Some(valid) = r.c2pa_chain_valid {
        if !valid { score += 0.6; }
        components += 1;
    }
    if !r.detected_editing_tools.is_empty() {
        score += (r.detected_editing_tools.len() as f32 * 0.15).min(0.6);
        components += 1;
    }
    if components == 0 { return 0.0; }
    (score / components as f32).clamp(0.0, 1.0)
}

fn compute_l2_score(r: &L2DetectionResult) -> f32 {
    if r.faces_analyzed == 0 { return 0.0; }
    (r.micro_flicker_score * 0.20
        + r.rppg_absence_score * 0.25
        + r.eye_movement_anomaly_score * 0.20
        + r.skin_texture_anomaly_score * 0.15
        + r.facial_symmetry_score * 0.20)
        .clamp(0.0, 1.0)
}

fn compute_l3_score(r: &L3DetectionResult) -> f32 {
    let agreement_factor = if r.model_agreement_ratio >= 0.8 {
        1.0
    } else if r.model_agreement_ratio >= 0.5 {
        0.9
    } else {
        0.75
    };
    (r.ensemble_score * agreement_factor).clamp(0.0, 1.0)
}

// ═══════════════════════════════════════════════════════════════════
//  Inline L1 scanner logic (metadata + compression)
// ═══════════════════════════════════════════════════════════════════

const DEEPFAKE_TOOL_SIGNATURES: &[(&str, &str)] = &[
    ("deepfacelab", "DeepFaceLab"),
    ("faceswap", "FaceSwap"),
    ("facefusion", "FaceFusion"),
    ("roop", "Roop"),
    ("simswap", "SimSwap"),
];

const SUSPICIOUS_TOOL_SIGNATURES: &[(&str, f32)] = &[
    ("after effects", 0.15),
    ("ffmpeg", 0.10),
    ("handbrake", 0.08),
];

#[allow(clippy::too_many_arguments)]
fn scan_metadata(
    encoder: Option<&str>,
    codec: &str,
    container: &str,
    exif_tags: &[(&str, &str)],
    _bitrate: Option<f64>,
    _width: Option<u32>,
    _height: Option<u32>,
    c2pa_valid: Option<bool>,
    _gop_sizes: &[u32],
) -> f32 {
    let mut score: f32 = 0.0;
    let mut fields = Vec::new();
    if let Some(enc) = encoder { fields.push(enc.to_string()); }
    fields.push(codec.to_string());
    fields.push(container.to_string());
    for (k, v) in exif_tags { fields.push(format!("{}={}", k, v)); }
    let combined = fields.join(" ").to_lowercase();

    for &(pattern, _name) in DEEPFAKE_TOOL_SIGNATURES {
        if combined.contains(pattern) { score += 0.7; }
    }
    for &(pattern, weight) in SUSPICIOUS_TOOL_SIGNATURES {
        if combined.contains(pattern) { score += weight; }
    }
    if exif_tags.is_empty() && encoder.is_none() { score += 0.15; }
    if c2pa_valid == Some(true) { score = (score - 0.2).max(0.0); }
    score.clamp(0.0, 1.0)
}

fn scan_compression(
    gop_sizes: &[u32],
    bitrate_kbps: Option<f64>,
    width: Option<u32>,
    height: Option<u32>,
    _fps: Option<f64>,
    _encoder: Option<&str>,
) -> f32 {
    let mut score: f32 = 0.0;

    if gop_sizes.len() >= 2 {
        let mean: f64 = gop_sizes.iter().map(|&g| g as f64).sum::<f64>() / gop_sizes.len() as f64;
        let variance: f64 = gop_sizes.iter().map(|&g| { let d = g as f64 - mean; d * d }).sum::<f64>() / gop_sizes.len() as f64;
        let cv = if mean > 0.0 { variance.sqrt() / mean } else { 0.0 };
        if cv > 0.3 {
            score += (cv as f32 - 0.3).min(0.5);
        }
    }

    if let (Some(bitrate), Some(w), Some(h)) = (bitrate_kbps, width, height) {
        let pixel_count = w as f64 * h as f64;
        let expected = pixel_count * 0.1 * 30.0 / 1000.0;
        let ratio = bitrate / expected;
        if ratio < 0.15 { score += (0.15 - ratio as f32).min(0.3); }
        if ratio > 4.0 { score += ((ratio as f32 - 4.0) * 0.05).min(0.2); }
    }

    score.clamp(0.0, 1.0)
}

fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

// ═══════════════════════════════════════════════════════════════════
//  Inline signing logic (Ed25519)
// ═══════════════════════════════════════════════════════════════════

fn sign_test_verdict() -> Result<(Vec<u8>, String)> {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha512};

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let key_id = format!("veritas-test-{}", &hex_encode(&verifying_key.to_bytes()[..4]));

    let verdict = serde_json::json!({
        "scan_id": uuid::Uuid::new_v4().to_string(),
        "verdict": "BLOCK",
        "risk_score": 0.92,
        "reason_codes": ["L1_HASH_MATCH", "L3_ENSEMBLE_HIGH"],
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let canonical = canonical_json(&verdict)?;
    let mut hasher = Sha512::new();
    hasher.update(canonical.as_bytes());
    let content_hash = hasher.finalize();
    let signature = signing_key.sign(&content_hash);

    let mut signed = verdict.clone();
    if let Some(obj) = signed.as_object_mut() {
        obj.insert("signature".to_string(), serde_json::json!({
            "signature_bytes": hex_encode(&signature.to_bytes()),
            "key_id": key_id,
            "algorithm": "Ed25519",
            "content_hash": hex_encode(&content_hash),
            "signed_at": chrono::Utc::now().to_rfc3339(),
        }));
    }

    // Store verifying key in a thread-local for verify
    VERIFY_KEY.set(verifying_key.to_bytes());

    Ok((serde_json::to_vec(&signed)?, key_id))
}

fn verify_signed_verdict(signed_bytes: &[u8]) -> Result<bool> {
    use ed25519_dalek::VerifyingKey;

    let verdict: serde_json::Value = serde_json::from_slice(signed_bytes)?;
    let sig_obj = verdict.get("signature").ok_or(anyhow::anyhow!("No signature"))?;

    let sig_hex = sig_obj["signature_bytes"].as_str().ok_or(anyhow::anyhow!("No sig bytes"))?;
    let content_hash_hex = sig_obj["content_hash"].as_str().ok_or(anyhow::anyhow!("No hash"))?;

    let sig_bytes = hex_decode(sig_hex)?;
    let content_hash = hex_decode(content_hash_hex)?;

    // Re-compute content hash from the verdict (excluding signature)
    let canonical = canonical_json(&verdict)?;
    let mut hasher = sha2::Sha512::new();
    use sha2::Digest;
    hasher.update(canonical.as_bytes());
    let recomputed_hash = hasher.finalize();

    // Check content hash matches
    if recomputed_hash.as_slice() != content_hash.as_slice() {
        return Ok(false);
    }

    let key_bytes = VERIFY_KEY.get();
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)?;

    Ok(verifying_key.verify_strict(&content_hash, &signature).is_ok())
}

// Simple thread-local to pass the verification key between sign/verify
use std::cell::Cell;
thread_local! {
    static VERIFY_KEY: Cell<[u8; 32]> = const { Cell::new([0u8; 32]) };
}

fn canonical_json(value: &serde_json::Value) -> Result<String> {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            let entries: Vec<String> = sorted
                .into_iter()
                .filter(|(k, _)| *k != "signature")
                .map(|(k, v)| {
                    let v_str = canonical_json(v).unwrap_or_default();
                    format!("\"{}\":{}", k, v_str)
                })
                .collect();
            Ok(format!("{{{}}}", entries.join(",")))
        }
        serde_json::Value::Array(arr) => {
            let entries: Vec<String> = arr.iter().map(|v| canonical_json(v).unwrap_or_default()).collect();
            Ok(format!("[{}]", entries.join(",")))
        }
        _ => Ok(value.to_string()),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| anyhow::anyhow!("Hex: {}", e)))
        .collect()
}

// ═══════════════════════════════════════════════════════════════════
//  Test data factories
// ═══════════════════════════════════════════════════════════════════

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

fn make_l1_malicious() -> L1DetectionResult {
    L1DetectionResult {
        hash_match_found: true,
        hash_match_id: Some("known-deepfake-42".to_string()),
        metadata_anomaly_score: 0.9,
        compression_anomaly_score: 0.8,
        c2pa_chain_valid: Some(false),
        detected_editing_tools: vec!["FakeApp".to_string()],
        duration_ms: 3,
    }
}

fn make_l2_malicious() -> L2DetectionResult {
    L2DetectionResult {
        micro_flicker_score: 0.9,
        rppg_absence_score: 0.95,
        rppg_signal_quality: 0.1,
        eye_movement_anomaly_score: 0.85,
        skin_texture_anomaly_score: 0.8,
        facial_symmetry_score: 0.9,
        faces_analyzed: 1,
        duration_ms: 100,
    }
}

fn make_l3_malicious() -> L3DetectionResult {
    L3DetectionResult {
        vit_general_score: 0.95,
        efficientnet_gan_score: 0.90,
        tcn_temporal_score: 0.88,
        diffusion_artifact_score: 0.85,
        lipsync_mismatch_score: 0.92,
        ensemble_score: 0.93,
        model_agreement_ratio: 0.95,
        duration_ms: 350,
    }
}
