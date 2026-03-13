#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::time::Instant;

use eframe::egui;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use image::DynamicImage;
use sha2::{Digest, Sha512};
use veritas_shared::types::VerdictDecision;

const VIDEO_EXTENSIONS: &[&str] = &["mp4", "mkv", "avi", "webm", "mov", "m4v", "flv", "wmv", "3gp"];

// ═══════════════════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════════════════

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 750.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Veritas B2B – Deepfake Detection",
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(VeritasApp::new()))
        }),
    )
}

fn setup_fonts(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(22.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(15.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(13.0, egui::FontFamily::Monospace),
    );
    style.visuals.override_text_color = Some(egui::Color32::from_gray(220));
    ctx.set_style(style);
}

// ═══════════════════════════════════════════════════════════════════
//  App State
// ═══════════════════════════════════════════════════════════════════

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Analyze,
    Demos,
    Verify,
    Info,
}

struct AnalysisResult {
    file_path: String,
    file_size: u64,
    resolution: Option<(u32, u32)>,
    scan_id: String,
    metadata: MetadataResult,
    hashes: Option<HashResult>,
    l2_score: f32,
    l3_score: f32,
    scoring: ScoringResult,
    signed_json: String,
    signature_valid: bool,
    latency_ms: f64,
    // Video-specific
    is_video: bool,
    video_info: Option<VideoInfo>,
    frame_analyses: Vec<FrameAnalysis>,
}

#[allow(dead_code)]
struct VideoInfo {
    duration_secs: f64,
    fps: f64,
    total_frames: u64,
    video_codec: String,
    audio_codec: String,
    width: u32,
    height: u32,
    bitrate_kbps: u64,
    frames_extracted: usize,
}

struct FrameAnalysis {
    frame_index: usize,
    timestamp_secs: f64,
    hashes: HashResult,
    anomaly_score: f32,
    reason: String,
}

struct DemoResult {
    name: String,
    scoring: ScoringResult,
    metadata: MetadataResult,
    signed_valid: bool,
}

struct VerifyResult {
    original_verdict: String,
    signed_json: String,
    valid: bool,
    tampered_valid: bool,
}

struct VeritasApp {
    tab: Tab,
    signing_engine: SigningEngine,

    // Analyze tab
    analysis: Option<AnalysisResult>,
    analyzing: bool,
    file_rx: Option<mpsc::Receiver<PathBuf>>,

    // Demos tab
    demo_results: Vec<DemoResult>,

    // Verify tab
    verify_result: Option<VerifyResult>,

    // Context options for analysis
    is_public_figure: bool,
    political_score: f32,
    has_account_anomaly: bool,
}

impl VeritasApp {
    fn new() -> Self {
        Self {
            tab: Tab::Analyze,
            signing_engine: SigningEngine::init(),
            analysis: None,
            analyzing: false,
            file_rx: None,
            demo_results: Vec::new(),
            verify_result: None,
            is_public_figure: false,
            political_score: 0.0,
            has_account_anomaly: false,
        }
    }
}

impl eframe::App for VeritasApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check for file dialog result
        if let Some(rx) = &self.file_rx {
            if let Ok(path) = rx.try_recv() {
                self.run_analysis(&path);
                self.file_rx = None;
            }
        }

        // Dark background
        let frame_bg = egui::Frame::new()
            .fill(egui::Color32::from_rgb(18, 18, 24))
            .inner_margin(egui::Margin::same(0));

        egui::CentralPanel::default().frame(frame_bg).show(ctx, |ui| {
            self.render_header(ui);
            ui.add_space(4.0);
            self.render_tabs(ui);
            ui.add_space(8.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                let content_frame = egui::Frame::new()
                    .inner_margin(egui::Margin::symmetric(24, 16));
                content_frame.show(ui, |ui| {
                    match self.tab {
                        Tab::Analyze => self.render_analyze(ui),
                        Tab::Demos => self.render_demos(ui),
                        Tab::Verify => self.render_verify(ui),
                        Tab::Info => self.render_info(ui),
                    }
                });
            });
        });
    }
}

// ═══════════════════════════════════════════════════════════════════
//  UI Rendering
// ═══════════════════════════════════════════════════════════════════

impl VeritasApp {
    fn render_header(&self, ui: &mut egui::Ui) {
        let header_frame = egui::Frame::new()
            .fill(egui::Color32::from_rgb(25, 25, 40))
            .inner_margin(egui::Margin::symmetric(24, 16));

        header_frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("VERITAS B2B")
                        .size(26.0)
                        .strong()
                        .color(egui::Color32::from_rgb(100, 180, 255)),
                );
                ui.label(
                    egui::RichText::new("  Deepfake Detection Middleware")
                        .size(16.0)
                        .color(egui::Color32::from_gray(140)),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new("v0.1.0 | Ed25519 | 3-Tier Analysis")
                            .size(12.0)
                            .color(egui::Color32::from_gray(100)),
                    );
                });
            });
        });
    }

    fn render_tabs(&mut self, ui: &mut egui::Ui) {
        let tab_frame = egui::Frame::new()
            .fill(egui::Color32::from_rgb(22, 22, 35))
            .inner_margin(egui::Margin::symmetric(24, 8));

        tab_frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                self.tab_button(ui, Tab::Analyze, "Datei analysieren");
                ui.add_space(8.0);
                self.tab_button(ui, Tab::Demos, "Demo-Szenarien");
                ui.add_space(8.0);
                self.tab_button(ui, Tab::Verify, "Signatur verifizieren");
                ui.add_space(8.0);
                self.tab_button(ui, Tab::Info, "System-Info");
            });
        });
    }

    fn tab_button(&mut self, ui: &mut egui::Ui, tab: Tab, label: &str) {
        let active = self.tab == tab;
        let bg = if active {
            egui::Color32::from_rgb(60, 60, 100)
        } else {
            egui::Color32::from_rgb(35, 35, 55)
        };
        let text_color = if active {
            egui::Color32::from_rgb(140, 200, 255)
        } else {
            egui::Color32::from_gray(160)
        };

        let button = egui::Button::new(
            egui::RichText::new(label).color(text_color).size(14.0),
        )
        .fill(bg)
        .corner_radius(egui::CornerRadius::same(6))
        .min_size(egui::vec2(140.0, 32.0));

        if ui.add(button).clicked() {
            self.tab = tab;
        }
    }

    // ── Analyze Tab ──

    fn render_analyze(&mut self, ui: &mut egui::Ui) {
        ui.heading("Datei analysieren");
        ui.add_space(12.0);

        // Context options
        ui.group(|ui| {
            ui.label(egui::RichText::new("Kontext-Einstellungen").strong().size(14.0));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.is_public_figure, "Public Figure");
                ui.add_space(16.0);
                ui.checkbox(&mut self.has_account_anomaly, "Account-Anomalie");
                ui.add_space(16.0);
                ui.label("Politischer Kontext:");
                ui.add(egui::Slider::new(&mut self.political_score, 0.0..=1.0).fixed_decimals(2));
            });
        });

        ui.add_space(12.0);

        // File selection button
        let btn = egui::Button::new(
            egui::RichText::new("Datei auswaehlen & analysieren")
                .size(16.0)
                .color(egui::Color32::WHITE),
        )
        .fill(egui::Color32::from_rgb(40, 100, 200))
        .corner_radius(egui::CornerRadius::same(8))
        .min_size(egui::vec2(300.0, 44.0));

        if ui.add(btn).clicked() && !self.analyzing {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Bilder & Videos", &["jpg", "jpeg", "png", "webp", "gif", "bmp", "mp4", "mkv", "avi", "webm", "mov", "m4v", "flv"])
                .add_filter("Alle Dateien", &["*"])
                .pick_file()
            {
                self.run_analysis(&path);
            }
        }

        ui.add_space(16.0);

        // Show results
        if let Some(result) = &self.analysis {
            self.render_analysis_result(ui, result);
        } else {
            ui.label(
                egui::RichText::new("Waehle eine Datei zur Analyse aus.")
                    .color(egui::Color32::from_gray(100))
                    .italics(),
            );
        }
    }

    fn render_analysis_result(&self, ui: &mut egui::Ui, r: &AnalysisResult) {
        // File info
        section_header(ui, "Scan-Details");
        ui.horizontal(|ui| {
            info_label(ui, "Scan-ID:", &r.scan_id);
        });
        ui.horizontal(|ui| {
            info_label(ui, "Datei:", &r.file_path);
        });
        ui.horizontal(|ui| {
            if r.is_video {
                ui.label(
                    egui::RichText::new(" VIDEO ")
                        .size(12.0)
                        .strong()
                        .color(egui::Color32::WHITE)
                        .background_color(egui::Color32::from_rgb(60, 100, 180)),
                );
                ui.add_space(8.0);
            }
            info_label(ui, "Groesse:", &format_file_size(r.file_size));
            if let Some((w, h)) = r.resolution {
                ui.add_space(20.0);
                info_label(ui, "Aufloesung:", &format!("{}x{} px", w, h));
            }
        });

        // Video info
        if let Some(vi) = &r.video_info {
            ui.add_space(8.0);
            let video_card = egui::Frame::new()
                .fill(egui::Color32::from_rgb(20, 30, 50))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 80, 140)))
                .corner_radius(egui::CornerRadius::same(6))
                .inner_margin(egui::Margin::symmetric(16, 10));

            video_card.show(ui, |ui| {
                ui.label(egui::RichText::new("Video-Details").strong().size(14.0).color(egui::Color32::from_rgb(100, 160, 255)));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    info_label(ui, "Dauer:", &format_duration(vi.duration_secs));
                    ui.add_space(16.0);
                    info_label(ui, "FPS:", &format!("{:.2}", vi.fps));
                    ui.add_space(16.0);
                    info_label(ui, "Frames total:", &format!("{}", vi.total_frames));
                });
                ui.horizontal(|ui| {
                    info_label(ui, "Video-Codec:", &vi.video_codec);
                    ui.add_space(16.0);
                    info_label(ui, "Audio-Codec:", &vi.audio_codec);
                    ui.add_space(16.0);
                    info_label(ui, "Bitrate:", &format!("{} kbps", vi.bitrate_kbps));
                });
                ui.horizontal(|ui| {
                    info_label(ui, "Aufloesung:", &format!("{}x{}", vi.width, vi.height));
                    ui.add_space(16.0);
                    info_label(ui, "Frames analysiert:", &format!("{}", vi.frames_extracted));
                });
            });
        }

        ui.add_space(12.0);

        // Score bars
        section_header(ui, "Analyse-Ergebnisse");
        ui.add_space(4.0);

        score_row(ui, "L1 Metadata-Score", r.metadata.anomaly_score);
        score_row(ui, "L1 Compression-Score", r.metadata.compression_score);
        score_row(ui, "L2 Biometric (sim.)", r.l2_score);
        score_row(ui, "L3 Neural Net (sim.)", r.l3_score);

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            info_label(ui, "Base-Score:", &format!("{:.3}", r.scoring.base_score));
            ui.add_space(20.0);
            info_label(
                ui,
                "Context-Multiplier:",
                &format!("{:.2}x", r.scoring.context_multiplier),
            );
        });
        ui.add_space(4.0);

        score_row(ui, "FINAL RISK SCORE", r.scoring.final_score);

        ui.add_space(12.0);

        // Verdict
        let (verdict_text, verdict_desc, verdict_color) = verdict_display(&r.scoring.verdict);
        let verdict_frame = egui::Frame::new()
            .fill(verdict_color.linear_multiply(0.15))
            .stroke(egui::Stroke::new(2.0, verdict_color))
            .corner_radius(egui::CornerRadius::same(8))
            .inner_margin(egui::Margin::symmetric(20, 14));

        verdict_frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(verdict_text)
                        .size(22.0)
                        .strong()
                        .color(verdict_color),
                );
                ui.add_space(12.0);
                ui.label(
                    egui::RichText::new(verdict_desc)
                        .size(15.0)
                        .color(egui::Color32::from_gray(200)),
                );
            });
        });

        ui.add_space(8.0);

        // Signature + latency
        ui.horizontal(|ui| {
            let sig_icon = if r.signature_valid { "Signatur GUELTIG" } else { "Signatur UNGUELTIG" };
            let sig_color = if r.signature_valid {
                egui::Color32::from_rgb(80, 200, 120)
            } else {
                egui::Color32::from_rgb(220, 60, 60)
            };
            ui.label(egui::RichText::new(sig_icon).color(sig_color).strong());
            ui.add_space(20.0);
            info_label(ui, "Latenz:", &format!("{:.1}ms", r.latency_ms));
        });

        // Frame-by-frame analysis for videos
        if !r.frame_analyses.is_empty() {
            ui.add_space(12.0);
            section_header(ui, &format!("Frame-Analyse ({} Frames)", r.frame_analyses.len()));

            // Anomaly timeline bar
            let bar_width = ui.available_width().min(800.0);
            let bar_height = 40.0;
            let (rect, _) = ui.allocate_exact_size(
                egui::vec2(bar_width, bar_height),
                egui::Sense::hover(),
            );
            let painter = ui.painter();
            painter.rect_filled(rect, egui::CornerRadius::same(4), egui::Color32::from_rgb(30, 30, 45));

            let n = r.frame_analyses.len();
            if n > 0 {
                let slot_w = bar_width / n as f32;
                for (i, fa) in r.frame_analyses.iter().enumerate() {
                    let x = rect.min.x + i as f32 * slot_w;
                    let fill = egui::Rect::from_min_size(
                        egui::pos2(x, rect.min.y),
                        egui::vec2(slot_w.max(2.0), bar_height),
                    );
                    painter.rect_filled(fill, egui::CornerRadius::ZERO, score_color(fa.anomaly_score));
                }
            }
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new("Timeline: Jeder Block = 1 analysierter Frame (gruen=sicher, rot=verdaechtig)")
                    .size(11.0)
                    .color(egui::Color32::from_gray(110)),
            );

            ui.add_space(8.0);

            // Detailed per-frame results in collapsible
            egui::CollapsingHeader::new(
                egui::RichText::new("Frame-Details").size(13.0),
            )
            .show(ui, |ui| {
                egui::Grid::new("frame_grid")
                    .num_columns(6)
                    .spacing([12.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        // Header
                        ui.label(egui::RichText::new("Frame").strong().size(12.0));
                        ui.label(egui::RichText::new("Zeit").strong().size(12.0));
                        ui.label(egui::RichText::new("Score").strong().size(12.0));
                        ui.label(egui::RichText::new("aHash").strong().size(12.0));
                        ui.label(egui::RichText::new("dHash").strong().size(12.0));
                        ui.label(egui::RichText::new("Befund").strong().size(12.0));
                        ui.end_row();

                        for fa in &r.frame_analyses {
                            ui.label(egui::RichText::new(format!("#{}", fa.frame_index + 1)).monospace().size(12.0));
                            ui.label(egui::RichText::new(format!("{:.1}s", fa.timestamp_secs)).monospace().size(12.0));
                            ui.label(
                                egui::RichText::new(format!("{:.3}", fa.anomaly_score))
                                    .monospace()
                                    .size(12.0)
                                    .color(score_color(fa.anomaly_score)),
                            );
                            ui.label(egui::RichText::new(format!("{:016x}", fa.hashes.ahash)).monospace().size(10.0).color(egui::Color32::from_gray(140)));
                            ui.label(egui::RichText::new(format!("{:016x}", fa.hashes.dhash)).monospace().size(10.0).color(egui::Color32::from_gray(140)));
                            ui.label(
                                egui::RichText::new(&fa.reason)
                                    .size(11.0)
                                    .color(if fa.anomaly_score > 0.3 {
                                        egui::Color32::from_rgb(255, 200, 100)
                                    } else {
                                        egui::Color32::from_gray(130)
                                    }),
                            );
                            ui.end_row();
                        }
                    });
            });
        }

        // Perceptual hashes (for images)
        if r.frame_analyses.is_empty() {
            if let Some(h) = &r.hashes {
                ui.add_space(8.0);
                section_header(ui, "Perceptual Hashes");
                ui.horizontal(|ui| {
                    hash_label(ui, "aHash", h.ahash);
                    ui.add_space(16.0);
                    hash_label(ui, "dHash", h.dhash);
                    ui.add_space(16.0);
                    hash_label(ui, "pHash", h.phash);
                });
            }
        }

        // Detected tools
        if !r.metadata.detected_tools.is_empty() {
            ui.add_space(8.0);
            section_header(ui, "Erkannte Tools");
            for tool in &r.metadata.detected_tools {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("!").color(egui::Color32::from_rgb(255, 180, 50)).strong());
                    ui.label(egui::RichText::new(tool).color(egui::Color32::from_rgb(255, 200, 80)));
                });
            }
        }

        // Reason codes
        if !r.metadata.reasons.is_empty() {
            ui.add_space(8.0);
            section_header(ui, "Reason-Codes");
            for reason in &r.metadata.reasons {
                ui.label(egui::RichText::new(format!("  {}", reason)).size(12.0).color(egui::Color32::from_rgb(255, 200, 100)));
            }
        }

        // Signed JSON (collapsible)
        ui.add_space(12.0);
        egui::CollapsingHeader::new(
            egui::RichText::new("Signiertes Verdict (JSON)").size(14.0),
        )
        .show(ui, |ui| {
            egui::ScrollArea::vertical().max_height(250.0).show(ui, |ui| {
                ui.label(egui::RichText::new(&r.signed_json).monospace().size(12.0).color(egui::Color32::from_gray(180)));
            });
        });
    }

    // ── Demos Tab ──

    fn render_demos(&mut self, ui: &mut egui::Ui) {
        ui.heading("Demo-Szenarien");
        ui.add_space(8.0);

        let btn = egui::Button::new(
            egui::RichText::new("Alle Szenarien ausfuehren")
                .size(15.0)
                .color(egui::Color32::WHITE),
        )
        .fill(egui::Color32::from_rgb(40, 140, 80))
        .corner_radius(egui::CornerRadius::same(8))
        .min_size(egui::vec2(260.0, 40.0));

        if ui.add(btn).clicked() {
            self.run_demos();
        }

        ui.add_space(16.0);

        if self.demo_results.is_empty() {
            ui.label(
                egui::RichText::new("Klicke den Button um die Demo-Szenarien auszufuehren.")
                    .color(egui::Color32::from_gray(100))
                    .italics(),
            );
            return;
        }

        for demo in &self.demo_results {
            let (verdict_text, _, verdict_color) = verdict_display(&demo.scoring.verdict);

            let card = egui::Frame::new()
                .fill(egui::Color32::from_rgb(28, 28, 42))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(50)))
                .corner_radius(egui::CornerRadius::same(8))
                .inner_margin(egui::Margin::symmetric(16, 12));

            card.show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(&demo.name)
                            .strong()
                            .size(15.0)
                            .color(egui::Color32::from_gray(230)),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new(verdict_text)
                                .size(16.0)
                                .strong()
                                .color(verdict_color),
                        );
                        let sig_text = if demo.signed_valid { "Signiert" } else { "!" };
                        let sig_color = if demo.signed_valid {
                            egui::Color32::from_rgb(80, 200, 120)
                        } else {
                            egui::Color32::from_rgb(220, 60, 60)
                        };
                        ui.label(egui::RichText::new(sig_text).color(sig_color).size(12.0));
                        ui.add_space(8.0);
                    });
                });

                ui.add_space(6.0);
                score_row(ui, "Metadata", demo.metadata.anomaly_score);
                score_row(ui, "Risk Score", demo.scoring.final_score);

                if !demo.metadata.detected_tools.is_empty() {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Tools:").size(12.0).color(egui::Color32::from_gray(120)));
                        ui.label(
                            egui::RichText::new(demo.metadata.detected_tools.join(", "))
                                .size(12.0)
                                .color(egui::Color32::from_rgb(255, 200, 80)),
                        );
                    });
                }
            });
            ui.add_space(6.0);
        }
    }

    // ── Verify Tab ──

    fn render_verify(&mut self, ui: &mut egui::Ui) {
        ui.heading("Signatur verifizieren");
        ui.add_space(8.0);

        let btn = egui::Button::new(
            egui::RichText::new("Test-Verdict erzeugen & verifizieren")
                .size(15.0)
                .color(egui::Color32::WHITE),
        )
        .fill(egui::Color32::from_rgb(140, 80, 200))
        .corner_radius(egui::CornerRadius::same(8))
        .min_size(egui::vec2(320.0, 40.0));

        if ui.add(btn).clicked() {
            self.run_verify();
        }

        ui.add_space(16.0);

        if let Some(vr) = &self.verify_result {
            section_header(ui, "1. Original-Verdict");
            ui.label(egui::RichText::new(&vr.original_verdict).monospace().size(12.0).color(egui::Color32::from_gray(170)));

            ui.add_space(8.0);
            section_header(ui, "2. Signatur-Verifikation");
            let (text, color) = if vr.valid {
                ("SIGNATUR GUELTIG", egui::Color32::from_rgb(80, 200, 120))
            } else {
                ("SIGNATUR UNGUELTIG", egui::Color32::from_rgb(220, 60, 60))
            };
            ui.label(egui::RichText::new(text).size(18.0).strong().color(color));

            ui.add_space(8.0);
            section_header(ui, "3. Manipulationstest (BLOCK -> ALLOW)");
            let (text2, color2) = if !vr.tampered_valid {
                ("Manipulation korrekt erkannt und abgelehnt", egui::Color32::from_rgb(80, 200, 120))
            } else {
                ("WARNUNG: Manipulation nicht erkannt!", egui::Color32::from_rgb(220, 60, 60))
            };
            ui.label(egui::RichText::new(text2).size(15.0).strong().color(color2));

            ui.add_space(12.0);
            egui::CollapsingHeader::new("Signiertes JSON").show(ui, |ui| {
                egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    ui.label(egui::RichText::new(&vr.signed_json).monospace().size(12.0).color(egui::Color32::from_gray(170)));
                });
            });
        } else {
            ui.label(
                egui::RichText::new("Klicke den Button um ein Test-Verdict zu erzeugen und zu verifizieren.")
                    .color(egui::Color32::from_gray(100))
                    .italics(),
            );
        }
    }

    // ── Info Tab ──

    fn render_info(&self, ui: &mut egui::Ui) {
        ui.heading("System-Info");
        ui.add_space(12.0);

        let card = egui::Frame::new()
            .fill(egui::Color32::from_rgb(28, 28, 42))
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(50)))
            .corner_radius(egui::CornerRadius::same(8))
            .inner_margin(egui::Margin::symmetric(20, 16));

        card.show(ui, |ui| {
            info_label(ui, "Version:", "0.1.0");
            info_label(ui, "Signing-Key:", self.signing_engine.key_id());
            info_label(ui, "Algorithmus:", "Ed25519 (RFC 8032)");
            info_label(ui, "Hash:", "SHA-512");
            info_label(ui, "Public Key:", &hex_encode(&self.signing_engine.public_key()));

            ui.add_space(12.0);
            section_header(ui, "Detection-Tiers");
            ui.label("  L1: Metadata + Hash + Compression  (echte Analyse)");
            ui.label("  L2: Biometric Inconsistency        (simuliert)");
            ui.label("  L3: Neural Network Ensemble        (simuliert)");

            ui.add_space(12.0);
            section_header(ui, "Scoring-Weights");
            ui.label("  L1: 20%  |  L2: 35%  |  L3: 45%");

            ui.add_space(12.0);
            section_header(ui, "Verdict-Schwellenwerte");

            ui.horizontal(|ui| {
                verdict_threshold_label(ui, "ALLOW", "< 0.30", egui::Color32::from_rgb(80, 200, 120));
                ui.add_space(12.0);
                verdict_threshold_label(ui, "FLAG", "0.30–0.59", egui::Color32::from_rgb(255, 200, 50));
                ui.add_space(12.0);
                verdict_threshold_label(ui, "FLAG_URGENT", "0.60–0.84", egui::Color32::from_rgb(255, 140, 40));
                ui.add_space(12.0);
                verdict_threshold_label(ui, "BLOCK", ">= 0.85", egui::Color32::from_rgb(220, 60, 60));
            });

            ui.add_space(12.0);
            section_header(ui, "Erkannte Deepfake-Tools");
            ui.horizontal_wrapped(|ui| {
                for &(_, name) in DEEPFAKE_TOOL_SIGNATURES {
                    ui.label(
                        egui::RichText::new(format!(" {} ", name))
                            .size(12.0)
                            .color(egui::Color32::from_rgb(255, 100, 100))
                            .background_color(egui::Color32::from_rgb(60, 20, 20)),
                    );
                }
            });

            ui.add_space(12.0);
            section_header(ui, "Starten");
            ui.label(egui::RichText::new("  cargo run --bin veritas-gui").monospace().size(13.0));
        });
    }
}

// ═══════════════════════════════════════════════════════════════════
//  UI Helpers
// ═══════════════════════════════════════════════════════════════════

fn section_header(ui: &mut egui::Ui, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .strong()
            .size(14.0)
            .color(egui::Color32::from_rgb(100, 180, 255)),
    );
    ui.add_space(4.0);
}

fn info_label(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(label)
                .size(13.0)
                .color(egui::Color32::from_gray(130)),
        );
        ui.label(
            egui::RichText::new(value)
                .size(13.0)
                .color(egui::Color32::from_gray(220)),
        );
    });
}

fn score_row(ui: &mut egui::Ui, label: &str, score: f32) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(format!("{:.<24}", label))
                .monospace()
                .size(13.0)
                .color(egui::Color32::from_gray(150)),
        );

        // Draw score bar
        let bar_width = 200.0;
        let bar_height = 16.0;
        let (rect, _) = ui.allocate_exact_size(
            egui::vec2(bar_width, bar_height),
            egui::Sense::hover(),
        );

        let painter = ui.painter();
        painter.rect_filled(
            rect,
            egui::CornerRadius::same(3),
            egui::Color32::from_rgb(40, 40, 55),
        );

        let fill_width = bar_width * score;
        let fill_color = score_color(score);
        painter.rect_filled(
            egui::Rect::from_min_size(rect.min, egui::vec2(fill_width, bar_height)),
            egui::CornerRadius::same(3),
            fill_color,
        );

        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(format!("{:.3}", score))
                .monospace()
                .size(13.0)
                .color(fill_color),
        );
    });
}

fn score_color(score: f32) -> egui::Color32 {
    if score < 0.30 {
        egui::Color32::from_rgb(80, 200, 120) // green
    } else if score < 0.60 {
        egui::Color32::from_rgb(255, 200, 50) // yellow
    } else if score < 0.85 {
        egui::Color32::from_rgb(255, 140, 40) // orange
    } else {
        egui::Color32::from_rgb(220, 60, 60) // red
    }
}

fn verdict_display(verdict: &VerdictDecision) -> (&'static str, &'static str, egui::Color32) {
    match verdict {
        VerdictDecision::Allow => (
            "ALLOW",
            "Kein Deepfake erkannt",
            egui::Color32::from_rgb(80, 200, 120),
        ),
        VerdictDecision::Flag => (
            "FLAG",
            "Verdaechtig, manuelle Pruefung empfohlen",
            egui::Color32::from_rgb(255, 200, 50),
        ),
        VerdictDecision::FlagUrgent => (
            "FLAG_URGENT",
            "Dringend, sofortige Pruefung noetig",
            egui::Color32::from_rgb(255, 140, 40),
        ),
        VerdictDecision::Block => (
            "BLOCK",
            "Deepfake erkannt, Upload blockiert",
            egui::Color32::from_rgb(220, 60, 60),
        ),
    }
}

fn verdict_threshold_label(ui: &mut egui::Ui, name: &str, range: &str, color: egui::Color32) {
    ui.label(egui::RichText::new(name).strong().color(color).size(13.0));
    ui.label(egui::RichText::new(range).size(12.0).color(egui::Color32::from_gray(140)));
}

fn hash_label(ui: &mut egui::Ui, name: &str, value: u64) {
    ui.label(
        egui::RichText::new(format!("{}: {:016x}", name, value))
            .monospace()
            .size(12.0)
            .color(egui::Color32::from_gray(160)),
    );
}

// ═══════════════════════════════════════════════════════════════════
//  Logic: Analysis, Demos, Verify
// ═══════════════════════════════════════════════════════════════════

impl VeritasApp {
    fn run_analysis(&mut self, path: &Path) {
        let total_start = Instant::now();
        let scan_id = uuid::Uuid::new_v4().to_string();

        let file_meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };

        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("unknown")
            .to_lowercase();
        let file_size = file_meta.len();
        let is_video = VIDEO_EXTENSIONS.contains(&extension.as_str());

        let mut metadata = analyze_metadata(path, &extension, file_size);
        let mut hashes: Option<HashResult> = None;
        let mut resolution: Option<(u32, u32)> = None;
        let mut video_info: Option<VideoInfo> = None;
        let mut frame_analyses: Vec<FrameAnalysis> = Vec::new();

        if is_video {
            // Extract video info via ffprobe
            let vi = probe_video(path);

            // Extract frames via ffmpeg and analyze each
            let temp_dir = std::env::temp_dir().join(format!("veritas-frames-{}", uuid::Uuid::new_v4()));
            let _ = std::fs::create_dir_all(&temp_dir);

            let frames = extract_video_frames(path, &temp_dir, &vi);

            let mut max_anomaly: f32 = 0.0;
            let mut prev_hashes: Option<HashResult> = None;

            for (i, (frame_path, timestamp)) in frames.iter().enumerate() {
                if let Ok(img) = image::open(frame_path) {
                    let fh = compute_perceptual_hashes(&img);

                    // Cross-frame consistency check
                    let mut anomaly: f32 = metadata.anomaly_score * 0.3;
                    let mut reason = String::from("OK");

                    if let Some(ref prev) = prev_hashes {
                        let a_dist = hamming_distance(fh.ahash, prev.ahash);
                        let d_dist = hamming_distance(fh.dhash, prev.dhash);
                        let p_dist = hamming_distance(fh.phash, prev.phash);

                        // Large perceptual hash jumps between adjacent frames = splice
                        if p_dist > 20 {
                            anomaly += 0.4;
                            reason = format!("SPLICE: pHash-Sprung d={} (>20)", p_dist);
                            metadata.reasons.push(format!(
                                "L1_FRAME_SPLICE: Frame {} pHash-Distanz {} (Verdacht auf Splice)",
                                i + 1, p_dist
                            ));
                        } else if d_dist > 25 {
                            anomaly += 0.25;
                            reason = format!("JUMP: dHash-Sprung d={} (>25)", d_dist);
                        } else if a_dist > 15 && d_dist > 15 {
                            anomaly += 0.15;
                            reason = format!("SHIFT: Multi-Hash-Aenderung a={} d={}", a_dist, d_dist);
                        } else {
                            reason = format!("OK (a={} d={} p={})", a_dist, d_dist, p_dist);
                        }
                    }

                    anomaly = anomaly.clamp(0.0, 1.0);
                    if anomaly > max_anomaly {
                        max_anomaly = anomaly;
                    }

                    if i == 0 {
                        resolution = Some((img.width(), img.height()));
                        hashes = Some(HashResult {
                            ahash: fh.ahash,
                            dhash: fh.dhash,
                            phash: fh.phash,
                        });
                    }

                    frame_analyses.push(FrameAnalysis {
                        frame_index: i,
                        timestamp_secs: *timestamp,
                        hashes: fh,
                        anomaly_score: anomaly,
                        reason,
                    });

                    prev_hashes = Some(HashResult {
                        ahash: frame_analyses.last().unwrap().hashes.ahash,
                        dhash: frame_analyses.last().unwrap().hashes.dhash,
                        phash: frame_analyses.last().unwrap().hashes.phash,
                    });
                }
            }

            // Boost metadata score based on frame analysis
            if max_anomaly > metadata.anomaly_score {
                metadata.anomaly_score = (metadata.anomaly_score + max_anomaly) / 2.0;
            }

            // Count suspicious frames
            let suspicious_count = frame_analyses.iter().filter(|f| f.anomaly_score > 0.3).count();
            if suspicious_count > 0 {
                metadata.reasons.push(format!(
                    "L1_FRAME_ANALYSIS: {}/{} Frames verdaechtig (Score > 0.3)",
                    suspicious_count, frame_analyses.len()
                ));
            }

            let mut vi = vi;
            vi.frames_extracted = frame_analyses.len();
            video_info = Some(vi);

            // Cleanup temp frames
            let _ = std::fs::remove_dir_all(&temp_dir);
        } else {
            // Image analysis (existing logic)
            let image_result = image::open(path);
            resolution = image_result.as_ref().ok().map(|img| (img.width(), img.height()));
            hashes = image_result.as_ref().ok().map(compute_perceptual_hashes);
        }

        let l2 = simulate_l2(&metadata);
        let l3 = simulate_l3(&metadata);

        let scoring = compute_risk_score(
            &metadata,
            &l2,
            &l3,
            self.is_public_figure,
            self.political_score,
            self.has_account_anomaly,
        );

        let verdict_json = build_verdict_json(
            &scan_id,
            &path.display().to_string(),
            &scoring,
            &metadata,
            hashes.as_ref(),
        );
        let signed = self
            .signing_engine
            .sign_verdict(verdict_json.to_string().as_bytes());
        let (signed_json, signature_valid) = match signed {
            Ok(bytes) => {
                let valid = self.signing_engine.verify(&bytes).unwrap_or(false);
                let pretty = serde_json::to_string_pretty(
                    &serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default(),
                )
                .unwrap_or_default();
                (pretty, valid)
            }
            Err(_) => ("Signing failed".into(), false),
        };

        let latency_ms = total_start.elapsed().as_secs_f64() * 1000.0;

        self.analysis = Some(AnalysisResult {
            file_path: path.display().to_string(),
            file_size,
            resolution,
            scan_id,
            metadata,
            hashes,
            l2_score: l2.composite_score,
            l3_score: l3.composite_score,
            scoring,
            signed_json,
            signature_valid,
            latency_ms,
            is_video,
            video_info,
            frame_analyses,
        });
    }

    fn run_demos(&mut self) {
        let scenarios = demo_scenarios();
        self.demo_results.clear();

        for (name, scenario) in scenarios {
            let l2 = simulate_l2(&scenario.metadata);
            let l3 = simulate_l3(&scenario.metadata);

            let scoring = compute_risk_score(
                &scenario.metadata,
                &l2,
                &l3,
                scenario.public_figure,
                scenario.political_score,
                scenario.account_anomaly,
            );

            let verdict_json = build_verdict_json(
                &uuid::Uuid::new_v4().to_string(),
                name,
                &scoring,
                &scenario.metadata,
                None,
            );
            let signed = self.signing_engine.sign_verdict(verdict_json.to_string().as_bytes());
            let signed_valid = match signed {
                Ok(ref bytes) => self.signing_engine.verify(bytes).unwrap_or(false),
                Err(_) => false,
            };

            self.demo_results.push(DemoResult {
                name: name.to_string(),
                scoring,
                metadata: scenario.metadata.clone(),
                signed_valid,
            });
        }
    }

    fn run_verify(&mut self) {
        let scan_id = uuid::Uuid::new_v4();

        let verdict = serde_json::json!({
            "scan_id": scan_id.to_string(),
            "verdict": "BLOCK",
            "risk_score": 0.92,
            "reason_codes": ["L1_HASH_MATCH", "L3_ENSEMBLE_HIGH", "CTX_PUBLIC_FIGURE"],
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "source": "veritas-demo"
        });

        let original_verdict = serde_json::to_string_pretty(&verdict).unwrap_or_default();

        let signed = match self.signing_engine.sign_verdict(verdict.to_string().as_bytes()) {
            Ok(s) => s,
            Err(_) => return,
        };

        let valid = self.signing_engine.verify(&signed).unwrap_or(false);

        // Tamper test
        let tampered_valid = {
            let mut tampered: serde_json::Value = serde_json::from_slice(&signed).unwrap_or_default();
            if let Some(obj) = tampered.as_object_mut() {
                obj.insert("verdict".to_string(), serde_json::json!("ALLOW"));
            }
            let tampered_bytes = serde_json::to_vec(&tampered).unwrap_or_default();
            self.signing_engine.verify(&tampered_bytes).unwrap_or(false)
        };

        let signed_json = serde_json::to_string_pretty(
            &serde_json::from_slice::<serde_json::Value>(&signed).unwrap_or_default(),
        )
        .unwrap_or_default();

        self.verify_result = Some(VerifyResult {
            original_verdict,
            signed_json,
            valid,
            tampered_valid,
        });
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Video Processing (ffmpeg/ffprobe)
// ═══════════════════════════════════════════════════════════════════

fn probe_video(path: &Path) -> VideoInfo {
    let mut vi = VideoInfo {
        duration_secs: 0.0,
        fps: 0.0,
        total_frames: 0,
        video_codec: "unknown".into(),
        audio_codec: "none".into(),
        width: 0,
        height: 0,
        bitrate_kbps: 0,
        frames_extracted: 0,
    };

    // Use ffprobe to get video info
    let output = Command::new("ffprobe")
        .args([
            "-v", "quiet",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
        ])
        .arg(path)
        .output();

    if let Ok(out) = output {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
            // Parse format
            if let Some(format) = json.get("format") {
                vi.duration_secs = format
                    .get("duration")
                    .and_then(|d| d.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                vi.bitrate_kbps = format
                    .get("bit_rate")
                    .and_then(|b| b.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
                    / 1000;
            }

            // Parse streams
            if let Some(streams) = json.get("streams").and_then(|s| s.as_array()) {
                for stream in streams {
                    let codec_type = stream
                        .get("codec_type")
                        .and_then(|c| c.as_str())
                        .unwrap_or("");

                    if codec_type == "video" {
                        vi.video_codec = stream
                            .get("codec_name")
                            .and_then(|c| c.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        vi.width = stream
                            .get("width")
                            .and_then(|w| w.as_u64())
                            .unwrap_or(0) as u32;
                        vi.height = stream
                            .get("height")
                            .and_then(|h| h.as_u64())
                            .unwrap_or(0) as u32;

                        // Parse fps from r_frame_rate (e.g. "30/1" or "30000/1001")
                        if let Some(rate) = stream.get("r_frame_rate").and_then(|r| r.as_str()) {
                            let parts: Vec<&str> = rate.split('/').collect();
                            if parts.len() == 2 {
                                let num = parts[0].parse::<f64>().unwrap_or(0.0);
                                let den = parts[1].parse::<f64>().unwrap_or(1.0);
                                if den > 0.0 {
                                    vi.fps = num / den;
                                }
                            }
                        }

                        // Total frames
                        vi.total_frames = stream
                            .get("nb_frames")
                            .and_then(|n| n.as_str())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or_else(|| {
                                if vi.fps > 0.0 {
                                    (vi.duration_secs * vi.fps) as u64
                                } else {
                                    0
                                }
                            });
                    } else if codec_type == "audio" {
                        vi.audio_codec = stream
                            .get("codec_name")
                            .and_then(|c| c.as_str())
                            .unwrap_or("none")
                            .to_string();
                    }
                }
            }
        }
    }

    vi
}

/// Extract up to N frames from a video using ffmpeg scene detection + interval sampling.
fn extract_video_frames(path: &Path, temp_dir: &Path, vi: &VideoInfo) -> Vec<(PathBuf, f64)> {
    let mut frames: Vec<(PathBuf, f64)> = Vec::new();

    // Strategy: extract ~20 frames spread across the video
    // Use scene detection + fixed interval sampling
    let max_frames: usize = 20;
    let interval = if vi.duration_secs > 0.0 {
        (vi.duration_secs / max_frames as f64).max(0.5)
    } else {
        1.0
    };

    // Method 1: ffmpeg with fps filter for interval-based extraction
    let output_pattern = temp_dir.join("frame_%04d.png");
    let fps_filter = format!("fps=1/{:.2}", interval);

    let result = Command::new("ffmpeg")
        .args([
            "-i",
        ])
        .arg(path)
        .args([
            "-vf", &fps_filter,
            "-frames:v", &max_frames.to_string(),
            "-q:v", "2",
            "-y",
        ])
        .arg(&output_pattern)
        .output();

    if result.is_err() {
        return frames;
    }

    // Collect extracted frames
    if let Ok(entries) = std::fs::read_dir(temp_dir) {
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "png"))
            .collect();
        paths.sort();

        for (i, frame_path) in paths.into_iter().enumerate() {
            let timestamp = i as f64 * interval;
            frames.push((frame_path, timestamp));
        }
    }

    frames
}

/// Hamming distance for cross-frame comparison.
fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

fn format_duration(secs: f64) -> String {
    let total = secs as u64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    let ms = ((secs - secs.floor()) * 100.0) as u64;
    if h > 0 {
        format!("{}:{:02}:{:02}.{:02}", h, m, s, ms)
    } else {
        format!("{}:{:02}.{:02}", m, s, ms)
    }
}

fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Analysis Engine (from demo.rs)
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
#[allow(dead_code)]
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

struct HashResult {
    ahash: u64,
    dhash: u64,
    phash: u64,
}

struct L2Result {
    composite_score: f32,
}

struct L3Result {
    composite_score: f32,
}

struct ScoringResult {
    base_score: f32,
    context_multiplier: f32,
    final_score: f32,
    verdict: VerdictDecision,
}

struct Scenario {
    metadata: MetadataResult,
    public_figure: bool,
    political_score: f32,
    account_anomaly: bool,
}

fn analyze_metadata(path: &Path, extension: &str, file_size: u64) -> MetadataResult {
    let mut score: f32 = 0.0;
    let mut detected_tools = Vec::new();
    let mut reasons = Vec::new();

    // Only read the first 8KB for header analysis (NOT the entire file!)
    let header_bytes = {
        use std::io::Read;
        let mut buf = vec![0u8; 8192];
        if let Ok(mut f) = std::fs::File::open(path) {
            let n = f.read(&mut buf).unwrap_or(0);
            buf.truncate(n);
        } else {
            buf.clear();
        }
        buf
    };
    let header_str = String::from_utf8_lossy(&header_bytes).to_lowercase();

    for &(pattern, display_name) in DEEPFAKE_TOOL_SIGNATURES {
        if header_str.contains(pattern) {
            score += 0.7;
            detected_tools.push(display_name.to_string());
            reasons.push(format!(
                "L1_META_TOOL_{}: Deepfake-Tool Signatur '{}' erkannt",
                display_name.to_uppercase().replace(' ', "_"),
                display_name
            ));
        }
    }

    for &(pattern, weight) in SUSPICIOUS_TOOL_SIGNATURES {
        if header_str.contains(pattern) {
            score += weight;
            detected_tools.push(pattern.to_string());
            reasons.push(format!(
                "L1_META_SUSPICIOUS_{}: Editing-Tool '{}' erkannt (weight={:.2})",
                pattern.to_uppercase().replace(' ', "_"),
                pattern,
                weight
            ));
        }
    }

    let has_exif = header_str.contains("exif") || header_str.contains("xmp");
    if !has_exif && (extension == "jpg" || extension == "jpeg" || extension == "mp4") {
        score += 0.10;
        reasons.push("L1_META_STRIPPED: EXIF/XMP Metadata fehlt".into());
    }

    let is_video_ext = VIDEO_EXTENSIONS.contains(&extension);

    // Only try image::open for non-video files (videos would OOM or fail)
    let resolution = if !is_video_ext {
        if let Ok(img) = image::open(path) {
            let (w, h) = (img.width(), img.height());
            let aspect = w as f64 / h as f64;
            let standard = [16.0 / 9.0, 9.0 / 16.0, 4.0 / 3.0, 3.0 / 4.0, 1.0];
            if !standard.iter().any(|&s| (aspect - s).abs() < 0.02) {
                score += 0.05;
                reasons.push(format!(
                    "L1_META_NONSTANDARD_ASPECT: Seitenverhaeltnis {:.3} ({}x{})",
                    aspect, w, h
                ));
            }
            Some((w, h))
        } else {
            None
        }
    } else {
        None
    };

    let compression_score = if let Some((w, h)) = resolution {
        let pixels = w as f64 * h as f64;
        let bytes_per_pixel = file_size as f64 / pixels;
        if bytes_per_pixel < 0.1 {
            let s = (0.1 - bytes_per_pixel as f32).min(0.3);
            reasons.push(format!(
                "L1_COMP_AGGRESSIVE: Niedrige Dateigroesse ({:.3} bytes/pixel)",
                bytes_per_pixel
            ));
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
        if pixel as u64 > mean {
            hash |= 1 << i;
        }
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
            if left > right {
                hash |= 1 << bit;
            }
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
                    * ((2.0 * x as f64 + 1.0) * u as f64 * std::f64::consts::PI
                        / (2.0 * size as f64))
                        .cos();
            }
            let alpha = if u == 0 {
                (1.0 / size as f64).sqrt()
            } else {
                (2.0 / size as f64).sqrt()
            };
            dct[(row * size + u) as usize] = alpha * sum;
        }
    }

    let row_dct = dct.clone();
    for col in 0..size {
        for v in 0..size {
            let mut sum = 0.0;
            for y in 0..size {
                sum += row_dct[(y * size + col) as usize]
                    * ((2.0 * y as f64 + 1.0) * v as f64 * std::f64::consts::PI
                        / (2.0 * size as f64))
                        .cos();
            }
            let alpha = if v == 0 {
                (1.0 / size as f64).sqrt()
            } else {
                (2.0 / size as f64).sqrt()
            };
            dct[(v * size + col) as usize] = alpha * sum;
        }
    }

    let mut low_freq: Vec<f64> = Vec::with_capacity(63);
    for y in 0..8u32 {
        for x in 0..8u32 {
            if x == 0 && y == 0 {
                continue;
            }
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
        if coeff > median {
            hash |= 1 << i;
        }
    }
    hash
}

fn simulate_l2(meta: &MetadataResult) -> L2Result {
    let base = meta.anomaly_score * 0.6 + meta.compression_score * 0.4;
    L2Result {
        composite_score: (base + 0.05).clamp(0.0, 1.0),
    }
}

fn simulate_l3(meta: &MetadataResult) -> L3Result {
    let base = meta.anomaly_score * 0.7 + meta.compression_score * 0.3;
    L3Result {
        composite_score: (base + 0.08).clamp(0.0, 1.0),
    }
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
    let base_score = (l1_score * 0.20 + l2.composite_score * 0.35 + l3.composite_score * 0.45)
        .clamp(0.0, 1.0);

    let mut multiplier: f32 = 1.0;
    if public_figure {
        multiplier += 0.30;
    }
    multiplier += 0.20 * political_score;
    if account_anomaly {
        multiplier += 0.15;
    }

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

    ScoringResult {
        base_score,
        context_multiplier: multiplier,
        final_score,
        verdict,
    }
}

fn build_verdict_json(
    scan_id: &str,
    source: &str,
    scoring: &ScoringResult,
    meta: &MetadataResult,
    hashes: Option<&HashResult>,
) -> serde_json::Value {
    serde_json::json!({
        "scan_id": scan_id,
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
        "perceptual_hashes": hashes.map(|h| serde_json::json!({
            "ahash": format!("{:016x}", h.ahash),
            "dhash": format!("{:016x}", h.dhash),
            "phash": format!("{:016x}", h.phash),
        })),
        "reason_codes": meta.reasons,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })
}

fn demo_scenarios() -> Vec<(&'static str, Scenario)> {
    vec![
        (
            "Authentisches Smartphone-Video",
            Scenario {
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
            },
        ),
        (
            "DeepFaceLab Deepfake",
            Scenario {
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
                        "L1_COMP_GOP_INCONSISTENT: GOP-Struktur inkonsistent".into(),
                    ],
                },
                public_figure: true,
                political_score: 0.7,
                account_anomaly: true,
            },
        ),
        (
            "Verdaechtiges Video (Grenzfall)",
            Scenario {
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
            },
        ),
        (
            "AI-generiertes Bild (Diffusion Model)",
            Scenario {
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
            },
        ),
    ]
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
    fn init() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let key_id = format!(
            "veritas-dev-{}",
            &hex_encode(&verifying_key.to_bytes()[..4])
        );
        Self {
            signing_key,
            verifying_key,
            key_id,
        }
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn public_key(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    fn sign_verdict(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut verdict: serde_json::Value =
            serde_json::from_slice(payload).map_err(|e| anyhow::anyhow!("{}", e))?;

        let canonical = canonical_json(&verdict)?;
        let mut hasher = Sha512::new();
        hasher.update(canonical.as_bytes());
        let content_hash = hasher.finalize();
        let signature = self.signing_key.sign(&content_hash);

        if let Some(obj) = verdict.as_object_mut() {
            obj.insert(
                "signature".to_string(),
                serde_json::json!({
                    "signature_bytes": hex_encode(&signature.to_bytes()),
                    "key_id": self.key_id,
                    "algorithm": "Ed25519",
                    "content_hash": hex_encode(content_hash.as_slice()),
                    "signed_at": chrono::Utc::now().to_rfc3339(),
                }),
            );
        }

        Ok(serde_json::to_vec(&verdict)?)
    }

    fn verify(&self, signed_bytes: &[u8]) -> anyhow::Result<bool> {
        let verdict: serde_json::Value = serde_json::from_slice(signed_bytes)?;
        let sig_obj = verdict
            .get("signature")
            .ok_or(anyhow::anyhow!("No signature"))?;

        let sig_hex = sig_obj["signature_bytes"]
            .as_str()
            .ok_or(anyhow::anyhow!("No sig"))?;
        let content_hash_hex = sig_obj["content_hash"]
            .as_str()
            .ok_or(anyhow::anyhow!("No hash"))?;

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
        Ok(self
            .verifying_key
            .verify_strict(&stored_hash, &signature)
            .is_ok())
    }
}

fn canonical_json(value: &serde_json::Value) -> anyhow::Result<String> {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            let entries: Vec<String> = sorted
                .into_iter()
                .filter(|(k, _)| *k != "signature")
                .map(|(k, v)| Ok(format!("\"{}\":{}", k, canonical_json(v)?)))
                .collect::<anyhow::Result<_>>()?;
            Ok(format!("{{{}}}", entries.join(",")))
        }
        serde_json::Value::Array(arr) => {
            let entries: Vec<String> = arr
                .iter()
                .map(|v| canonical_json(v))
                .collect::<anyhow::Result<_>>()?;
            Ok(format!("[{}]", entries.join(",")))
        }
        _ => Ok(value.to_string()),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> anyhow::Result<Vec<u8>> {
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| anyhow::anyhow!("Hex: {}", e))
        })
        .collect()
}
