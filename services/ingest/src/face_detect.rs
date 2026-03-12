use crate::extractor::ExtractedFrame;
use anyhow::Result;

/// A detected face region within a frame.
#[derive(Debug, Clone)]
pub struct FaceRegion {
    pub frame_index: u32,
    pub timestamp_ms: u64,
    /// Bounding box: (x, y, width, height) in pixels
    pub bbox: (u32, u32, u32, u32),
    /// Detection confidence from the face detector
    pub confidence: f32,
    /// Cropped face pixel data (RGB)
    pub crop_data: Vec<u8>,
    pub crop_width: u32,
    pub crop_height: u32,
}

/// Run face detection on extracted frames.
///
/// In production, this uses MTCNN or RetinaFace via ONNX Runtime
/// for fast, accurate face detection. The detector runs on CPU
/// (or optionally GPU via ONNX CUDA EP) and returns bounding boxes
/// with confidence scores.
///
/// Only frames containing faces are forwarded to L2/L3 analysis.
pub fn detect_faces(frames: &[ExtractedFrame]) -> Result<Vec<FaceRegion>> {
    let mut face_regions = Vec::new();

    for frame in frames {
        // In production: run MTCNN/RetinaFace inference
        // For the scaffold, we simulate face detection on every frame
        // with a single face detected.
        //
        // Real implementation:
        // let detections = mtcnn_model.detect(&frame.pixel_data, frame.width, frame.height)?;
        // for det in detections {
        //     if det.confidence > 0.9 {
        //         let crop = crop_face(&frame.pixel_data, &det.bbox, frame.width);
        //         face_regions.push(FaceRegion { ... });
        //     }
        // }

        if frame.pixel_data.is_empty() {
            // Placeholder: generate synthetic face region metadata
            face_regions.push(FaceRegion {
                frame_index: frame.frame_index,
                timestamp_ms: frame.timestamp_ms,
                bbox: (480, 200, 256, 256),
                confidence: 0.98,
                crop_data: Vec::new(), // Populated by real detector
                crop_width: 224,
                crop_height: 224,
            });
        }
    }

    Ok(face_regions)
}
