use anyhow::Result;
use tracing::info;

/// Represents a single extracted video frame.
#[derive(Debug, Clone)]
pub struct ExtractedFrame {
    pub frame_index: u32,
    pub timestamp_ms: u64,
    pub width: u32,
    pub height: u32,
    /// Raw pixel data (RGB, row-major).
    /// In production, this is populated by FFmpeg hardware-accelerated decoding.
    pub pixel_data: Vec<u8>,
}

/// Extract key frames from a video.
///
/// Strategy:
/// - Videos < 10s: extract all frames at native FPS
/// - Videos 10s-60s: extract 1 frame/second
/// - Videos > 60s: extract 1 frame every 2 seconds
///
/// In production, this uses FFmpeg via Rust bindings (ffmpeg-next) with
/// NVDEC hardware acceleration for GPU-accelerated decoding.
pub fn extract_keyframes(upload_id: &str, video_size_bytes: u64) -> Result<Vec<ExtractedFrame>> {
    // Estimate video duration from size (rough heuristic for placeholder)
    // Real implementation decodes the container to get exact duration.
    let estimated_duration_secs = (video_size_bytes as f64 / 500_000.0).max(1.0);

    let frame_interval_ms: u64 = if estimated_duration_secs < 10.0 {
        33 // ~30fps
    } else if estimated_duration_secs < 60.0 {
        1000 // 1 fps
    } else {
        2000 // 0.5 fps
    };

    let total_frames =
        ((estimated_duration_secs * 1000.0) / frame_interval_ms as f64).ceil() as u32;
    let total_frames = total_frames.min(300); // Cap at 300 frames max

    info!(
        upload_id = upload_id,
        estimated_duration_secs = estimated_duration_secs,
        frame_interval_ms = frame_interval_ms,
        total_frames = total_frames,
        "Extracting keyframes"
    );

    let mut frames = Vec::with_capacity(total_frames as usize);

    for i in 0..total_frames {
        let timestamp_ms = i as u64 * frame_interval_ms;

        // In production: ffmpeg decode → raw RGB pixels
        // Placeholder: empty frame data (real implementation fills this)
        frames.push(ExtractedFrame {
            frame_index: i,
            timestamp_ms,
            width: 1920,
            height: 1080,
            pixel_data: Vec::new(), // Populated by FFmpeg in production
        });
    }

    Ok(frames)
}
