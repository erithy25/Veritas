use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use image::DynamicImage;
use sha2::{Digest, Sha512};
use veritas_shared::types::VerdictDecision;

// ═══════════════════════════════════════════════════════════════════
//  Veritas B2B - Deepfake Detection Demo
//  Standalone pipeline: L1 Scan → Scoring → Signing → Verdict
// ═══════════════════════════════════════════════════════════════════

fn main() -> Result<()> {
    let signing_engine = SigningEngine::init()?;

    loop {
        print_banner();
        print_menu();

        match read_choice() {
            1 => analyze_file(&signing_engine)?,
            2 => run_demo_scenarios(&signing_engine)?,
            3 => verify_verdict_interactive(&signing_engine)?,
            4 => show_system_info(&signing_engine),
            0 => {
                println!("\n  Auf Wiedersehen!\n");
                break;
            }
            _ => println!("\n  \x1b[33mUngueltige Auswahl. Bitte 0-4 eingeben.\x1b[0m"),
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
//  UI
// ═══════════════════════════════════════════════════════════════════

fn print_banner() {
    println!();
    println!("\x1b[36m╔══════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[36m║\x1b[0m  \x1b[1;37mVERITAS B2B\x1b[0m - Deepfake Detection Middleware              \x1b[36m║\x1b[0m");
    println!("\x1b[36m║\x1b[0m  \x1b[90mv0.1.0 | Ed25519 Signing | 3-Tier Analysis\x1b[0m               \x1b[36m║\x1b[0m");
    println!("\x1b[36m╚══════════════════════════════════════════════════════════════╝\x1b[0m");
}

fn print_menu() {
    println!();
    println!("  \x1b[1m[1]\x1b[0m  Bild/Video analysieren (Dateipfad eingeben)");
    println!("  \x1b[1m[2]\x1b[0m  Demo-Szenarien ausfuehren (Clean / Deepfake / Edge-Case)");
    println!("  \x1b[1m[3]\x1b[0m  Signiertes Verdict verifizieren");
    println!("  \x1b[1m[4]\x1b[0m  System-Info anzeigen");
    println!("  \x1b[1m[0]\x1b[0m  Beenden");
    println!();
}

fn read_choice() -> u32 {
    print!("  \x1b[1m>\x1b[0m ");
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    input.trim().parse().unwrap_or(99)
}

fn read_line(prompt: &str) -> String {
    print!("  {} ", prompt);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    input.trim().to_string()
}

fn pause() {
    print!("\n  \x1b[90mDruecke Enter um fortzufahren...\x1b[0m");
    io::stdout().flush().ok();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).ok();
}

// ═══════════════════════════════════════════════════════════════════
//  Option 1: Datei analysieren
// ═══════════════════════════════════════════════════════════════════

fn analyze_file(engine: &SigningEngine) -> Result<()> {
    println!("\n  \x1b[1m── Datei-Analyse ──\x1b[0m\n");

    let path_str = read_line("Dateipfad:");
    if path_str.is_empty() {
        println!("  \x1b[33mKein Pfad eingegeben.\x1b[0m");
        return Ok(());
    }

    let path = Path::new(&path_str);
    if !path.exists() {
        println!("  \x1b[31mDatei nicht gefunden: {}\x1b[0m", path_str);
        return Ok(());
    }

    let total_start = Instant::now();
    let scan_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();

    println!();
    println!("  \x1b[90m┌─ Scan gestartet ─────────────────────────────────────┐\x1b[0m");
    println!("  \x1b[90m│\x1b[0m  Scan-ID:   \x1b[1m{}\x1b[0m", scan_id);
    println!("  \x1b[90m│\x1b[0m  Tenant-ID: {}", tenant_id);
    println!("  \x1b[90m│\x1b[0m  Datei:     {}", path_str);

    // Try to load as image for perceptual hashing
    let image_result = image::open(path);
    let file_meta = std::fs::metadata(path)?;

    println!("  \x1b[90m│\x1b[0m  Groesse:   {} bytes", file_meta.len());
    if let Ok(ref img) = image_result {
        println!("  \x1b[90m│\x1b[0m  Bild:      {}x{} px", img.width(), img.height());
    }
    println!("  \x1b[90m└──────────────────────────────────────────────────────┘\x1b[0m");

    // ── L1: Metadata Scan ──
    let l1_start = Instant::now();
    print!("\n  \x1b[33m▶\x1b[0m  L1 Metadata-Scan...");
    io::stdout().flush().ok();

    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("unknown");
    let file_size = file_meta.len();

    let metadata_result = analyze_metadata(path, extension, file_size);
    let l1_ms = l1_start.elapsed().as_secs_f64() * 1000.0;
    println!(" \x1b[32m✓\x1b[0m  [{:.1}ms]", l1_ms);

    print_l1_result(&metadata_result);

    // ── L1: Perceptual Hash ──
    let mut hash_result = HashResult::no_match();
    if let Ok(ref img) = image_result {
        print!("  \x1b[33m▶\x1b[0m  L1 Perceptual-Hash...");
        io::stdout().flush().ok();
        let h_start = Instant::now();
        hash_result = compute_perceptual_hashes(img);
        let h_ms = h_start.elapsed().as_secs_f64() * 1000.0;
        println!(" \x1b[32m✓\x1b[0m  [{:.1}ms]", h_ms);

        println!("      aHash: {:016x}", hash_result.ahash);
        println!("      dHash: {:016x}", hash_result.dhash);
        println!("      pHash: {:016x}", hash_result.phash);
    }

    // ── L2: Biometric (simulated) ──
    print!("  \x1b[33m▶\x1b[0m  L2 Biometric-Analyse (simuliert)...");
    io::stdout().flush().ok();
    let l2_start = Instant::now();
    let l2_result = simulate_l2(&metadata_result);
    let l2_ms = l2_start.elapsed().as_secs_f64() * 1000.0;
    println!(" \x1b[32m✓\x1b[0m  [{:.1}ms]", l2_ms);

    // ── L3: Neural Network (simulated) ──
    print!("  \x1b[33m▶\x1b[0m  L3 Neural-Network-Analyse (simuliert)...");
    io::stdout().flush().ok();
    let l3_start = Instant::now();
    let l3_result = simulate_l3(&metadata_result);
    let l3_ms = l3_start.elapsed().as_secs_f64() * 1000.0;
    println!(" \x1b[32m✓\x1b[0m  [{:.1}ms]", l3_ms);

    // ── Scoring ──
    print!("  \x1b[33m▶\x1b[0m  Risk-Scoring...");
    io::stdout().flush().ok();
    let scoring = compute_risk_score(
        &metadata_result,
        &l2_result,
        &l3_result,
        false,
        0.0,
        false,
    );
    println!(" \x1b[32m✓\x1b[0m");

    // ── Signing ──
    print!("  \x1b[33m▶\x1b[0m  Ed25519 Signierung...");
    io::stdout().flush().ok();
    let verdict_json = build_verdict_json(
        &scan_id, &tenant_id, &path_str, &scoring, &metadata_result, &hash_result,
    );
    let signed = engine.sign_verdict(verdict_json.to_string().as_bytes())?;
    println!(" \x1b[32m✓\x1b[0m");

    let total_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    // ── Result ──
    print_verdict(&scoring, total_ms);
    print_reason_codes(&metadata_result);

    println!("\n  \x1b[90m── Signiertes Verdict (JSON) ──\x1b[0m\n");
    let signed_pretty: serde_json::Value = serde_json::from_slice(&signed)?;
    let pretty = serde_json::to_string_pretty(&signed_pretty)?;
    for line in pretty.lines() {
        println!("  \x1b[90m│\x1b[0m {}", line);
    }

    // Verify
    let valid = engine.verify(&signed)?;
    println!("\n  Signatur-Verifikation: {}", if valid {
        "\x1b[32m✓ GUELTIG\x1b[0m"
    } else {
        "\x1b[31m✗ UNGUELTIG\x1b[0m"
    });

    pause();
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
//  Option 2: Demo-Szenarien
// ═══════════════════════════════════════════════════════════════════

fn run_demo_scenarios(engine: &SigningEngine) -> Result<()> {
    println!("\n  \x1b[1m── Demo-Szenarien ──\x1b[0m\n");

    let scenarios: Vec<(&str, Scenario)> = vec![
        ("Authentisches Video (Smartphone-Upload)", Scenario {
            metadata: MetadataResult {
                anomaly_score: 0.05,
                compression_score: 0.02,
                detected_tools: vec![],
                c2pa_valid: Some(true),
                codec: "h264".into(),
                container: "mp4".into(),
                encoder: Some("iPhone 15 Pro".into()),
                resolution: Some((3840, 2160)),
                reasons: vec![],
            },
            public_figure: false,
            political_score: 0.0,
            account_anomaly: false,
        }),
        ("DeepFaceLab Deepfake (bekannter Hash)", Scenario {
            metadata: MetadataResult {
                anomaly_score: 0.85,
                compression_score: 0.60,
                detected_tools: vec!["DeepFaceLab".into(), "FFmpeg".into()],
                c2pa_valid: None,
                codec: "h264".into(),
                container: "mp4".into(),
                encoder: Some("Lavf58.29 DeepFaceLab".into()),
                resolution: Some((1920, 1080)),
                reasons: vec![
                    "L1_META_TOOL_DEEPFACELAB: Deepfake-Tool Signatur erkannt".into(),
                    "L1_COMP_GOP_INCONSISTENT: GOP-Struktur inkonsistent (CV=0.85)".into(),
                ],
            },
            public_figure: true,
            political_score: 0.7,
            account_anomaly: true,
        }),
        ("Verdaechtiges Video (Grenzfall)", Scenario {
            metadata: MetadataResult {
                anomaly_score: 0.35,
                compression_score: 0.25,
                detected_tools: vec!["After Effects".into()],
                c2pa_valid: None,
                codec: "h265".into(),
                container: "mkv".into(),
                encoder: Some("x265 - After Effects CC 2024".into()),
                resolution: Some((1920, 1080)),
                reasons: vec![
                    "L1_META_SUSPICIOUS_AFTER_EFFECTS: Editing-Software erkannt".into(),
                ],
            },
            public_figure: false,
            political_score: 0.3,
            account_anomaly: false,
        }),
        ("AI-generiertes Bild (Diffusion Model)", Scenario {
            metadata: MetadataResult {
                anomaly_score: 0.15,
                compression_score: 0.10,
                detected_tools: vec![],
                c2pa_valid: Some(false),
                codec: "png".into(),
                container: "png".into(),
                encoder: None,
                resolution: Some((1024, 1024)),
                reasons: vec![
                    "L1_C2PA_INVALID: C2PA Provenance-Chain ungueltig".into(),
                    "L1_META_STRIPPED: Metadata entfernt".into(),
                ],
            },
            public_figure: true,
            political_score: 0.9,
            account_anomaly: false,
        }),
    ];

    for (i, (name, scenario)) in scenarios.iter().enumerate() {
        let total_start = Instant::now();
        let scan_id = uuid::Uuid::new_v4();
        let tenant_id = uuid::Uuid::new_v4();

        println!("  \x1b[1m━━━ Szenario {} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m", i + 1);
        println!("  \x1b[1m{}\x1b[0m", name);
        println!("  Scan-ID: \x1b[90m{}\x1b[0m", scan_id);
        println!();

        // Show metadata
        let meta = &scenario.metadata;
        println!("    Codec:     {}", meta.codec);
        println!("    Container: {}", meta.container);
        if let Some(ref enc) = meta.encoder {
            println!("    Encoder:   {}", enc);
        }
        if let Some((w, h)) = meta.resolution {
            println!("    Aufloesung: {}x{}", w, h);
        }
        if !meta.detected_tools.is_empty() {
            println!("    Tools:     \x1b[33m{}\x1b[0m", meta.detected_tools.join(", "));
        }
        match meta.c2pa_valid {
            Some(true) => println!("    C2PA:      \x1b[32mgueltig\x1b[0m"),
            Some(false) => println!("    C2PA:      \x1b[31mungueltig\x1b[0m"),
            None => println!("    C2PA:      \x1b[90mnicht vorhanden\x1b[0m"),
        }
        println!();

        // L2/L3 simulated
        let l2 = simulate_l2(meta);
        let l3 = simulate_l3(meta);

        // Scoring
        let scoring = compute_risk_score(
            meta,
            &l2,
            &l3,
            scenario.public_figure,
            scenario.political_score,
            scenario.account_anomaly,
        );

        // Signing
        let verdict_json = build_verdict_json(
            &scan_id, &tenant_id, name, &scoring, meta, &HashResult::no_match(),
        );
        let signed = engine.sign_verdict(verdict_json.to_string().as_bytes())?;
        let valid = engine.verify(&signed)?;

        let total_ms = total_start.elapsed().as_secs_f64() * 1000.0;

        // Print results
        println!("    \x1b[90m┌─ Ergebnis ─────────────────────────────────────┐\x1b[0m");
        println!("    \x1b[90m│\x1b[0m  Metadata-Score:     {}", score_bar(meta.anomaly_score));
        println!("    \x1b[90m│\x1b[0m  Compression-Score:  {}", score_bar(meta.compression_score));
        println!("    \x1b[90m│\x1b[0m  L2 Biometric:       {}", score_bar(l2.composite_score));
        println!("    \x1b[90m│\x1b[0m  L3 Neural:          {}", score_bar(l3.composite_score));
        println!("    \x1b[90m│\x1b[0m");
        println!("    \x1b[90m│\x1b[0m  Base-Score:         {:.3}", scoring.base_score);
        println!("    \x1b[90m│\x1b[0m  Context-Multiplier: {:.2}x{}", scoring.context_multiplier,
            if scenario.public_figure { " (Public Figure)" } else { "" });
        println!("    \x1b[90m│\x1b[0m  \x1b[1mFinal Risk Score:   {}\x1b[0m", score_bar(scoring.final_score));
        println!("    \x1b[90m│\x1b[0m");
        println!("    \x1b[90m│\x1b[0m  \x1b[1mVerdict: {}\x1b[0m", verdict_colored(&scoring.verdict));
        println!("    \x1b[90m│\x1b[0m  Signatur: {} | Key: {}", if valid { "\x1b[32m✓\x1b[0m" } else { "\x1b[31m✗\x1b[0m" }, engine.key_id());
        println!("    \x1b[90m│\x1b[0m  Latenz: {:.1}ms", total_ms);
        println!("    \x1b[90m└────────────────────────────────────────────────┘\x1b[0m");

        if !meta.reasons.is_empty() {
            println!("    Reason-Codes:");
            for reason in &meta.reasons {
                println!("      \x1b[33m⚠\x1b[0m  {}", reason);
            }
        }
        println!();
    }

    pause();
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
//  Option 3: Verdict verifizieren
// ═══════════════════════════════════════════════════════════════════

fn verify_verdict_interactive(engine: &SigningEngine) -> Result<()> {
    println!("\n  \x1b[1m── Verdict-Verifikation ──\x1b[0m\n");
    println!("  Erzeuge ein Test-Verdict und verifiziere es...\n");

    let scan_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();

    let verdict = serde_json::json!({
        "scan_id": scan_id.to_string(),
        "tenant_id": tenant_id.to_string(),
        "verdict": "BLOCK",
        "risk_score": 0.92,
        "reason_codes": ["L1_HASH_MATCH", "L3_ENSEMBLE_HIGH", "CTX_PUBLIC_FIGURE"],
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "source": "veritas-demo"
    });

    println!("  \x1b[90m1.\x1b[0m Original-Verdict erstellt");
    let signed = engine.sign_verdict(verdict.to_string().as_bytes())?;
    println!("  \x1b[90m2.\x1b[0m Ed25519 Signatur erstellt ({} bytes)", signed.len());

    let valid = engine.verify(&signed)?;
    println!("  \x1b[90m3.\x1b[0m Verifikation: {}\n", if valid {
        "\x1b[32m✓ SIGNATUR GUELTIG\x1b[0m"
    } else {
        "\x1b[31m✗ SIGNATUR UNGUELTIG\x1b[0m"
    });

    // Tamper test
    println!("  \x1b[90m4.\x1b[0m Manipulationstest: Aendere verdict BLOCK -> ALLOW...");
    let mut tampered: serde_json::Value = serde_json::from_slice(&signed)?;
    if let Some(obj) = tampered.as_object_mut() {
        obj.insert("verdict".to_string(), serde_json::json!("ALLOW"));
    }
    let tampered_bytes = serde_json::to_vec(&tampered)?;
    let tampered_valid = engine.verify(&tampered_bytes)?;
    println!("  \x1b[90m5.\x1b[0m Verifikation manipuliert: {}\n", if tampered_valid {
        "\x1b[31m✗ WARNUNG: Manipulation nicht erkannt!\x1b[0m"
    } else {
        "\x1b[32m✓ Manipulation korrekt erkannt und abgelehnt\x1b[0m"
    });

    println!("  \x1b[90m── Signiertes Verdict ──\x1b[0m\n");
    let pretty: serde_json::Value = serde_json::from_slice(&signed)?;
    for line in serde_json::to_string_pretty(&pretty)?.lines() {
        println!("  \x1b[90m│\x1b[0m {}", line);
    }

    pause();
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
//  Option 4: System-Info
// ═══════════════════════════════════════════════════════════════════

fn show_system_info(engine: &SigningEngine) {
    println!("\n  \x1b[1m── System-Info ──\x1b[0m\n");
    println!("  \x1b[90m┌──────────────────────────────────────────────────────┐\x1b[0m");
    println!("  \x1b[90m│\x1b[0m  Version:          0.1.0");
    println!("  \x1b[90m│\x1b[0m  Signing-Key:      {}", engine.key_id());
    println!("  \x1b[90m│\x1b[0m  Algorithmus:       Ed25519 (RFC 8032)");
    println!("  \x1b[90m│\x1b[0m  Hash:             SHA-512");
    println!("  \x1b[90m│\x1b[0m  Public Key:       {}", hex_encode(&engine.public_key()));
    println!("  \x1b[90m│\x1b[0m");
    println!("  \x1b[90m│\x1b[0m  Detection-Tiers:");
    println!("  \x1b[90m│\x1b[0m    L1: Metadata + Hash + Compression  (< 10ms)");
    println!("  \x1b[90m│\x1b[0m    L2: Biometric Inconsistency        (simuliert)");
    println!("  \x1b[90m│\x1b[0m    L3: Neural Network Ensemble        (simuliert)");
    println!("  \x1b[90m│\x1b[0m");
    println!("  \x1b[90m│\x1b[0m  Scoring-Weights:");
    println!("  \x1b[90m│\x1b[0m    L1: 20%  |  L2: 35%  |  L3: 45%");
    println!("  \x1b[90m│\x1b[0m");
    println!("  \x1b[90m│\x1b[0m  Verdict-Schwellenwerte:");
    println!("  \x1b[90m│\x1b[0m    ALLOW:      < 0.30");
    println!("  \x1b[90m│\x1b[0m    FLAG:       0.30 - 0.59");
    println!("  \x1b[90m│\x1b[0m    FLAG_URGENT: 0.60 - 0.84");
    println!("  \x1b[90m│\x1b[0m    BLOCK:      >= 0.85");
    println!("  \x1b[90m│\x1b[0m");
    println!("  \x1b[90m│\x1b[0m  Deepfake-Tool Signaturen:");
    for (_, name) in DEEPFAKE_TOOL_SIGNATURES {
        println!("  \x1b[90m│\x1b[0m    \x1b[31m●\x1b[0m {}", name);
    }
    println!("  \x1b[90m│\x1b[0m");
    println!("  \x1b[90m│\x1b[0m  Nutzung:");
    println!("  \x1b[90m│\x1b[0m    cargo run --bin veritas");
    println!("  \x1b[90m│\x1b[0m    cargo run --bin veritas-test   (Unit-Tests)");
    println!("  \x1b[90m│\x1b[0m    cargo test --all               (Alle Tests)");
    println!("  \x1b[90m└──────────────────────────────────────────────────────┘\x1b[0m");

    pause();
}

// ═══════════════════════════════════════════════════════════════════
//  Display helpers
// ═══════════════════════════════════════════════════════════════════

fn score_bar(score: f32) -> String {
    let blocks = (score * 20.0).round() as usize;
    let bar: String = "█".repeat(blocks) + &"░".repeat(20 - blocks);
    let color = if score < 0.30 {
        "\x1b[32m" // green
    } else if score < 0.60 {
        "\x1b[33m" // yellow
    } else if score < 0.85 {
        "\x1b[38;5;208m" // orange
    } else {
        "\x1b[31m" // red
    };
    format!("{}{}\x1b[0m {:.3}", color, bar, score)
}

fn verdict_colored(verdict: &VerdictDecision) -> String {
    match verdict {
        VerdictDecision::Allow => "\x1b[32m✓ ALLOW\x1b[0m  - Kein Deepfake erkannt".into(),
        VerdictDecision::Flag => "\x1b[33m⚠ FLAG\x1b[0m   - Verdaechtig, manuelle Pruefung empfohlen".into(),
        VerdictDecision::FlagUrgent => "\x1b[38;5;208m⚠ FLAG_URGENT\x1b[0m - Dringend, sofortige Pruefung noetig".into(),
        VerdictDecision::Block => "\x1b[31m✗ BLOCK\x1b[0m  - Deepfake erkannt, Upload blockiert".into(),
    }
}

fn print_verdict(scoring: &ScoringResult, total_ms: f64) {
    println!("\n  \x1b[1m━━━ ANALYSE-ERGEBNIS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");
    println!("    Risk Score:    {}", score_bar(scoring.final_score));
    println!("    Base Score:    {:.3}", scoring.base_score);
    println!("    Multiplier:    {:.2}x", scoring.context_multiplier);
    println!();
    println!("    \x1b[1mVerdict: {}\x1b[0m", verdict_colored(&scoring.verdict));
    println!("    Latenz:  {:.1}ms (gesamte Pipeline)", total_ms);
}

fn print_l1_result(meta: &MetadataResult) {
    println!("      Metadata-Score:    {}", score_bar(meta.anomaly_score));
    println!("      Compression-Score: {}", score_bar(meta.compression_score));
    if let Some(ref enc) = meta.encoder {
        println!("      Encoder:           {}", enc);
    }
    println!("      Format:            {} / {}", meta.codec, meta.container);
    if !meta.detected_tools.is_empty() {
        println!("      \x1b[33mTools erkannt:     {}\x1b[0m", meta.detected_tools.join(", "));
    }
    match meta.c2pa_valid {
        Some(true) => println!("      C2PA:              \x1b[32mgueltig\x1b[0m"),
        Some(false) => println!("      C2PA:              \x1b[31mungueltig/manipuliert\x1b[0m"),
        None => {}
    }
}

fn print_reason_codes(meta: &MetadataResult) {
    if !meta.reasons.is_empty() {
        println!("\n  \x1b[90m── Reason-Codes ──\x1b[0m");
        for reason in &meta.reasons {
            println!("    \x1b[33m⚠\x1b[0m  {}", reason);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  L1 Metadata Analysis (real file)
// ═══════════════════════════════════════════════════════════════════

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

#[derive(Clone)]
struct MetadataResult {
    anomaly_score: f32,
    compression_score: f32,
    detected_tools: Vec<String>,
    c2pa_valid: Option<bool>,
    codec: String,
    container: String,
    encoder: Option<String>,
    resolution: Option<(u32, u32)>,
    reasons: Vec<String>,
}

fn analyze_metadata(path: &Path, extension: &str, file_size: u64) -> MetadataResult {
    let mut score: f32 = 0.0;
    let mut detected_tools = Vec::new();
    let mut reasons = Vec::new();

    // Read first bytes to check for magic bytes / container format
    let file_bytes = std::fs::read(path).unwrap_or_default();
    let header_str = String::from_utf8_lossy(&file_bytes[..file_bytes.len().min(4096)]).to_lowercase();

    // Check for deepfake tool signatures in file content
    for &(pattern, display_name) in DEEPFAKE_TOOL_SIGNATURES {
        if header_str.contains(pattern) {
            score += 0.7;
            detected_tools.push(display_name.to_string());
            reasons.push(format!("L1_META_TOOL_{}: Deepfake-Tool Signatur '{}' in Datei erkannt",
                display_name.to_uppercase().replace(' ', "_"), display_name));
        }
    }

    for &(pattern, weight) in SUSPICIOUS_TOOL_SIGNATURES {
        if header_str.contains(pattern) {
            score += weight;
            detected_tools.push(pattern.to_string());
            reasons.push(format!("L1_META_SUSPICIOUS_{}: Editing-Tool '{}' erkannt (weight={:.2})",
                pattern.to_uppercase().replace(' ', "_"), pattern, weight));
        }
    }

    // Check for metadata stripping
    let has_exif = header_str.contains("exif") || header_str.contains("xmp");
    if !has_exif && (extension == "jpg" || extension == "jpeg" || extension == "mp4") {
        score += 0.10;
        reasons.push("L1_META_STRIPPED: EXIF/XMP Metadata fehlt (moeglicherweise entfernt)".into());
    }

    // Non-standard resolution detection
    let resolution = if let Ok(img) = image::open(path) {
        let (w, h) = (img.width(), img.height());
        let aspect = w as f64 / h as f64;
        let standard = [16.0/9.0, 9.0/16.0, 4.0/3.0, 3.0/4.0, 1.0];
        if !standard.iter().any(|&s| (aspect - s).abs() < 0.02) {
            score += 0.05;
            reasons.push(format!("L1_META_NONSTANDARD_ASPECT: Ungewoehnliches Seitenverhaeltnis {:.3} ({}x{})", aspect, w, h));
        }
        Some((w, h))
    } else {
        None
    };

    // Compression score based on file size heuristics
    let compression_score = if let Some((w, h)) = resolution {
        let pixels = w as f64 * h as f64;
        let bytes_per_pixel = file_size as f64 / pixels;
        // Very low bytes/pixel can indicate aggressive re-compression
        if bytes_per_pixel < 0.1 {
            let s = (0.1 - bytes_per_pixel as f32).min(0.3);
            reasons.push(format!("L1_COMP_AGGRESSIVE: Ungewoehnlich niedrige Dateigroesse ({:.3} bytes/pixel)", bytes_per_pixel));
            s
        } else {
            0.0
        }
    } else {
        0.0
    };

    let codec = match extension {
        "jpg" | "jpeg" => "jpeg",
        "png" => "png",
        "webp" => "webp",
        "gif" => "gif",
        "mp4" | "m4v" => "h264",
        "mkv" => "h265",
        "webm" => "vp9",
        "avi" => "mpeg4",
        _ => extension,
    };

    let container = match extension {
        "jpg" | "jpeg" | "png" | "webp" | "gif" => extension,
        "mp4" | "m4v" => "mp4",
        "mkv" => "mkv",
        "webm" => "webm",
        "avi" => "avi",
        _ => extension,
    };

    MetadataResult {
        anomaly_score: score.clamp(0.0, 1.0),
        compression_score: compression_score.clamp(0.0, 1.0),
        detected_tools,
        c2pa_valid: None,
        codec: codec.into(),
        container: container.into(),
        encoder: None,
        resolution,
        reasons,
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Perceptual Hashing (real implementation)
// ═══════════════════════════════════════════════════════════════════

struct HashResult {
    ahash: u64,
    dhash: u64,
    phash: u64,
}

impl HashResult {
    fn no_match() -> Self {
        Self { ahash: 0, dhash: 0, phash: 0 }
    }
}

fn compute_perceptual_hashes(img: &DynamicImage) -> HashResult {
    let gray = img.to_luma8();

    HashResult {
        ahash: compute_ahash(&gray),
        dhash: compute_dhash(&gray),
        phash: compute_phash(&gray),
    }
}

fn compute_ahash(gray: &image::GrayImage) -> u64 {
    let resized = image::imageops::resize(gray, 8, 8, image::imageops::FilterType::Lanczos3);
    let pixels: Vec<u8> = resized.pixels().map(|p| p.0[0]).collect();
    let mean: u64 = pixels.iter().map(|&p| p as u64).sum::<u64>() / pixels.len() as u64;
    let mut hash: u64 = 0;
    for (i, &pixel) in pixels.iter().enumerate() {
        if pixel as u64 > mean { hash |= 1 << i; }
    }
    hash
}

fn compute_dhash(gray: &image::GrayImage) -> u64 {
    let resized = image::imageops::resize(gray, 9, 8, image::imageops::FilterType::Lanczos3);
    let mut hash: u64 = 0;
    let mut bit = 0;
    for y in 0..8 {
        for x in 0..8 {
            let left = resized.get_pixel(x, y).0[0] as i16;
            let right = resized.get_pixel(x + 1, y).0[0] as i16;
            if left > right { hash |= 1 << bit; }
            bit += 1;
        }
    }
    hash
}

fn compute_phash(gray: &image::GrayImage) -> u64 {
    let size: u32 = 32;
    let resized = image::imageops::resize(gray, size, size, image::imageops::FilterType::Lanczos3);
    let pixels: Vec<f64> = resized.pixels().map(|p| p.0[0] as f64).collect();

    let mut dct = vec![0.0f64; (size * size) as usize];
    for row in 0..size {
        for u in 0..size {
            let mut sum = 0.0;
            for x in 0..size {
                sum += pixels[(row * size + x) as usize]
                    * ((2.0 * x as f64 + 1.0) * u as f64 * std::f64::consts::PI / (2.0 * size as f64)).cos();
            }
            let alpha = if u == 0 { (1.0 / size as f64).sqrt() } else { (2.0 / size as f64).sqrt() };
            dct[(row * size + u) as usize] = alpha * sum;
        }
    }

    let row_dct = dct.clone();
    for col in 0..size {
        for v in 0..size {
            let mut sum = 0.0;
            for y in 0..size {
                sum += row_dct[(y * size + col) as usize]
                    * ((2.0 * y as f64 + 1.0) * v as f64 * std::f64::consts::PI / (2.0 * size as f64)).cos();
            }
            let alpha = if v == 0 { (1.0 / size as f64).sqrt() } else { (2.0 / size as f64).sqrt() };
            dct[(v * size + col) as usize] = alpha * sum;
        }
    }

    let mut low_freq: Vec<f64> = Vec::with_capacity(63);
    for y in 0..8u32 {
        for x in 0..8u32 {
            if x == 0 && y == 0 { continue; }
            low_freq.push(dct[(y * size + x) as usize]);
        }
    }

    let median = {
        let mut sorted = low_freq.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        sorted[sorted.len() / 2]
    };

    let mut hash: u64 = 0;
    for (i, &coeff) in low_freq.iter().enumerate() {
        if coeff > median { hash |= 1 << i; }
    }
    hash
}

// ═══════════════════════════════════════════════════════════════════
//  L2/L3 Simulation
// ═══════════════════════════════════════════════════════════════════

struct L2Result {
    composite_score: f32,
}

struct L3Result {
    composite_score: f32,
}

fn simulate_l2(meta: &MetadataResult) -> L2Result {
    // Correlate L2 with L1 signals (in production this would be real biometric analysis)
    let base = meta.anomaly_score * 0.6 + meta.compression_score * 0.4;
    let noise = 0.05; // small variance
    L2Result {
        composite_score: (base + noise).clamp(0.0, 1.0),
    }
}

fn simulate_l3(meta: &MetadataResult) -> L3Result {
    let base = meta.anomaly_score * 0.7 + meta.compression_score * 0.3;
    let noise = 0.08;
    L3Result {
        composite_score: (base + noise).clamp(0.0, 1.0),
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Scoring Engine
// ═══════════════════════════════════════════════════════════════════

struct ScoringResult {
    base_score: f32,
    context_multiplier: f32,
    final_score: f32,
    verdict: VerdictDecision,
}

fn compute_risk_score(
    meta: &MetadataResult,
    l2: &L2Result,
    l3: &L3Result,
    public_figure: bool,
    political_score: f32,
    account_anomaly: bool,
) -> ScoringResult {
    let l1_score = (meta.anomaly_score * 0.6 + meta.compression_score * 0.4).clamp(0.0, 1.0);
    let l2_score = l2.composite_score;
    let l3_score = l3.composite_score;

    let base_score = (l1_score * 0.20 + l2_score * 0.35 + l3_score * 0.45).clamp(0.0, 1.0);

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

    ScoringResult { base_score, context_multiplier: multiplier, final_score, verdict }
}

// ═══════════════════════════════════════════════════════════════════
//  Signing Engine (Ed25519)
// ═══════════════════════════════════════════════════════════════════

struct SigningEngine {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    key_id: String,
}

impl SigningEngine {
    fn init() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let key_id = format!("veritas-dev-{}", &hex_encode(&verifying_key.to_bytes()[..4]));
        Ok(Self { signing_key, verifying_key, key_id })
    }

    fn key_id(&self) -> &str { &self.key_id }
    fn public_key(&self) -> [u8; 32] { self.verifying_key.to_bytes() }

    fn sign_verdict(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut verdict: serde_json::Value = serde_json::from_slice(payload)
            .context("Invalid JSON payload")?;

        let canonical = canonical_json(&verdict)?;
        let mut hasher = Sha512::new();
        hasher.update(canonical.as_bytes());
        let content_hash = hasher.finalize();
        let signature = self.signing_key.sign(&content_hash);

        if let Some(obj) = verdict.as_object_mut() {
            obj.insert("signature".to_string(), serde_json::json!({
                "signature_bytes": hex_encode(&signature.to_bytes()),
                "key_id": self.key_id,
                "algorithm": "Ed25519",
                "content_hash": hex_encode(content_hash.as_slice()),
                "signed_at": chrono::Utc::now().to_rfc3339(),
            }));
        }

        Ok(serde_json::to_vec(&verdict)?)
    }

    fn verify(&self, signed_bytes: &[u8]) -> Result<bool> {
        let verdict: serde_json::Value = serde_json::from_slice(signed_bytes)?;
        let sig_obj = verdict.get("signature").ok_or(anyhow::anyhow!("No signature"))?;

        let sig_hex = sig_obj["signature_bytes"].as_str().ok_or(anyhow::anyhow!("No sig"))?;
        let content_hash_hex = sig_obj["content_hash"].as_str().ok_or(anyhow::anyhow!("No hash"))?;

        let sig_bytes = hex_decode(sig_hex)?;
        let stored_hash = hex_decode(content_hash_hex)?;

        let canonical = canonical_json(&verdict)?;
        let mut hasher = Sha512::new();
        hasher.update(canonical.as_bytes());
        let recomputed = hasher.finalize();

        if recomputed.as_slice() != stored_hash.as_slice() {
            return Ok(false);
        }

        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)?;
        Ok(self.verifying_key.verify_strict(&stored_hash, &signature).is_ok())
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Verdict JSON builder
// ═══════════════════════════════════════════════════════════════════

fn build_verdict_json(
    scan_id: &uuid::Uuid,
    tenant_id: &uuid::Uuid,
    source: &str,
    scoring: &ScoringResult,
    meta: &MetadataResult,
    hashes: &HashResult,
) -> serde_json::Value {
    serde_json::json!({
        "scan_id": scan_id.to_string(),
        "tenant_id": tenant_id.to_string(),
        "source": source,
        "verdict": scoring.verdict.as_str(),
        "risk_score": (scoring.final_score * 1000.0).round() / 1000.0,
        "base_score": (scoring.base_score * 1000.0).round() / 1000.0,
        "context_multiplier": (scoring.context_multiplier * 100.0).round() / 100.0,
        "l1_metadata_score": (meta.anomaly_score * 1000.0).round() / 1000.0,
        "l1_compression_score": (meta.compression_score * 1000.0).round() / 1000.0,
        "detected_tools": meta.detected_tools,
        "codec": meta.codec,
        "container": meta.container,
        "perceptual_hashes": {
            "ahash": format!("{:016x}", hashes.ahash),
            "dhash": format!("{:016x}", hashes.dhash),
            "phash": format!("{:016x}", hashes.phash),
        },
        "reason_codes": meta.reasons,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })
}

// ═══════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════

struct Scenario {
    metadata: MetadataResult,
    public_figure: bool,
    political_score: f32,
    account_anomaly: bool,
}

fn canonical_json(value: &serde_json::Value) -> Result<String> {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            let entries: Vec<String> = sorted.into_iter()
                .filter(|(k, _)| *k != "signature")
                .map(|(k, v)| Ok(format!("\"{}\":{}", k, canonical_json(v)?)))
                .collect::<Result<_>>()?;
            Ok(format!("{{{}}}", entries.join(",")))
        }
        serde_json::Value::Array(arr) => {
            let entries: Vec<String> = arr.iter()
                .map(|v| canonical_json(v))
                .collect::<Result<_>>()?;
            Ok(format!("[{}]", entries.join(",")))
        }
        _ => Ok(value.to_string()),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| anyhow::anyhow!("Hex: {}", e)))
        .collect()
}
