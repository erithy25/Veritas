/// Model version constants and model registry utilities.

/// Known model names in the L3 ensemble.
pub mod model_names {
    pub const VIT_GENERAL: &str = "vit-l16-general";
    pub const EFFICIENTNET_GAN: &str = "efficientnet-b7-gan";
    pub const TCN_TEMPORAL: &str = "tcn-temporal";
    pub const DIFFUSION_DETECTOR: &str = "diffusion-artifact-detector";
    pub const LIPSYNC_ANALYZER: &str = "syncnet-lipsync";
}

/// Default ensemble weights for score aggregation.
/// These are tunable per-model based on validation performance.
pub fn default_ensemble_weights() -> Vec<(&'static str, f32)> {
    vec![
        (model_names::VIT_GENERAL, 0.30),
        (model_names::EFFICIENTNET_GAN, 0.25),
        (model_names::TCN_TEMPORAL, 0.20),
        (model_names::DIFFUSION_DETECTOR, 0.15),
        (model_names::LIPSYNC_ANALYZER, 0.10),
    ]
}

/// Scoring thresholds — defaults, overridden by tenant policy.
#[derive(Debug, Clone, Copy)]
pub struct PolicyThresholds {
    pub allow_max: f32,
    pub flag_max: f32,
    pub flag_urgent_max: f32,
    // Anything above flag_urgent_max is BLOCK
}

impl Default for PolicyThresholds {
    fn default() -> Self {
        Self {
            allow_max: 0.30,
            flag_max: 0.60,
            flag_urgent_max: 0.85,
        }
    }
}
