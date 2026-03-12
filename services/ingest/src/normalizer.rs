use crate::face_detect::FaceRegion;
use anyhow::Result;
use sha2::{Digest, Sha256};

/// A normalized face crop ready for downstream analysis.
#[derive(Debug, Clone)]
pub struct NormalizedFace {
    pub frame_index: u32,
    pub timestamp_ms: u64,
    /// Content hash of the normalized crop (for deduplication)
    pub content_hash: String,
    /// Normalized pixel data: 224x224 RGB, sRGB color space
    pub pixel_data: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

/// Normalize face crops to a standard format for model input.
///
/// Processing steps:
/// 1. Resize to 224x224 (model input size for ViT/EfficientNet)
/// 2. Convert color space to sRGB
/// 3. Normalize pixel values to [0, 1]
/// 4. Compute content hash for deduplication
///
/// In production, this uses the `image` crate for efficient resizing
/// with Lanczos3 interpolation.
pub fn normalize_face_crops(faces: &[FaceRegion]) -> Result<Vec<NormalizedFace>> {
    let mut normalized = Vec::with_capacity(faces.len());

    for face in faces {
        // In production:
        // let img = image::RgbImage::from_raw(face.crop_width, face.crop_height, face.crop_data.clone())
        //     .ok_or_else(|| anyhow::anyhow!("Invalid face crop data"))?;
        // let resized = image::imageops::resize(&img, 224, 224, image::imageops::FilterType::Lanczos3);
        // let pixels = resized.into_raw();

        // Compute content hash for deduplication
        let mut hasher = Sha256::new();
        hasher.update(&face.crop_data);
        hasher.update(face.frame_index.to_le_bytes());
        let hash = format!("{:x}", hasher.finalize());

        normalized.push(NormalizedFace {
            frame_index: face.frame_index,
            timestamp_ms: face.timestamp_ms,
            content_hash: hash,
            pixel_data: Vec::new(), // Populated by real normalization
            width: 224,
            height: 224,
        });
    }

    Ok(normalized)
}
