"""Skin texture frequency analysis for deepfake detection.

GAN-generated faces exhibit characteristic spectral fingerprints in the
frequency domain.  Specifically:

1. **GAN grid artifacts**: GANs using transposed convolutions produce
   checkerboard patterns visible in the DCT/FFT spectrum as periodic peaks
   at specific spatial frequencies.

2. **Unnatural high-frequency falloff**: Real skin texture follows an
   approximately 1/f power spectrum.  Synthetic faces often show steeper
   or shallower falloff, or abnormal energy in mid-frequency bands.

3. **Patch-level inconsistency**: In face-swap deepfakes, the swapped
   region has different spectral statistics from the surrounding skin,
   creating measurable discontinuities.

This module extracts facial skin patches, computes their 2-D DCT spectra,
and scores anomalies against learned priors of real skin texture.
"""

from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np
from numpy.typing import NDArray
import structlog

logger = structlog.get_logger(__name__)

# Patch size for DCT analysis (must be power of 2 for efficiency).
_PATCH_SIZE: int = 64

# Minimum number of valid patches required for reliable analysis.
_MIN_PATCHES: int = 8

# Expected 1/f spectral slope for real human skin (log-log domain).
# Real skin typically has slope in [-2.5, -1.5].
_REAL_SKIN_SLOPE_LOW: float = -2.8
_REAL_SKIN_SLOPE_HIGH: float = -1.2

# Threshold for GAN grid artifact detection: ratio of peak energy
# at checkerboard frequencies vs. surrounding frequencies.
_GRID_ARTIFACT_RATIO_THRESHOLD: float = 2.5

# Minimum frames to analyze for temporal texture consistency.
_MIN_FRAMES_TEMPORAL: int = 30


@dataclass(frozen=True, slots=True)
class TextureAnalysisResult:
    """Result of skin texture frequency analysis."""

    anomaly_score: float
    """0.0 = natural skin texture, 1.0 = highly anomalous (likely fake)."""

    spectral_slope_anomaly: float
    """How far the spectral slope deviates from natural skin [0, 1]."""

    grid_artifact_score: float
    """Strength of GAN checkerboard artifacts detected [0, 1]."""

    patch_consistency_score: float
    """Cross-patch spectral consistency anomaly [0, 1]."""

    temporal_texture_drift: float
    """Frame-to-frame texture stability anomaly [0, 1]."""


def _extract_skin_patches(
    frame: NDArray[np.uint8],
    skin_mask: NDArray[np.bool_],
    patch_size: int = _PATCH_SIZE,
) -> list[NDArray[np.float64]]:
    """Extract non-overlapping skin patches from a frame.

    Only patches where >70% of pixels are skin (according to the mask)
    are kept, ensuring we analyze actual facial texture.

    Returns list of grayscale patches as float64 arrays.
    """
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(np.float64)
    h, w = gray.shape
    patches: list[NDArray[np.float64]] = []

    for y in range(0, h - patch_size + 1, patch_size):
        for x in range(0, w - patch_size + 1, patch_size):
            mask_patch = skin_mask[y : y + patch_size, x : x + patch_size]
            skin_ratio = mask_patch.sum() / (patch_size * patch_size)
            if skin_ratio > 0.7:
                patch = gray[y : y + patch_size, x : x + patch_size]
                patches.append(patch)

    return patches


def _compute_dct_spectrum(patch: NDArray[np.float64]) -> NDArray[np.float64]:
    """Compute 2-D DCT power spectrum of a patch.

    Returns the log-magnitude spectrum (excluding DC component).
    """
    # Subtract mean (remove DC) and apply window to reduce spectral leakage
    patch = patch - patch.mean()
    window = np.outer(np.hanning(patch.shape[0]), np.hanning(patch.shape[1]))
    windowed = patch * window

    # 2-D DCT via FFT (DCT-II can be computed efficiently this way)
    dct = cv2.dct(windowed)
    power = dct ** 2

    # Set DC component to zero
    power[0, 0] = 0

    return power


def _compute_spectral_slope(power_spectrum: NDArray[np.float64]) -> float:
    """Compute the spectral slope in log-log domain.

    For real images, power spectral density follows ~1/f^beta where
    beta is typically between 1.5 and 2.5.  We compute this by
    radially averaging the 2-D spectrum and fitting a line in log-log.

    Returns the slope (negative for natural images).
    """
    h, w = power_spectrum.shape
    cy, cx = h // 2, w // 2

    # Compute radial distance for each frequency bin
    y_coords, x_coords = np.ogrid[:h, :w]
    radial_dist = np.sqrt((y_coords - cy) ** 2 + (x_coords - cx) ** 2)

    # Radial averaging
    max_radius = min(cy, cx)
    radial_profile = np.zeros(max_radius)

    for r in range(1, max_radius):
        ring_mask = (radial_dist >= r - 0.5) & (radial_dist < r + 0.5)
        ring_values = power_spectrum[ring_mask]
        if len(ring_values) > 0:
            radial_profile[r] = ring_values.mean()

    # Fit line in log-log domain (skip DC and near-DC)
    valid = radial_profile[2:] > 0
    if valid.sum() < 3:
        return 0.0

    freqs = np.arange(2, max_radius)
    log_freq = np.log10(freqs[valid])
    log_power = np.log10(radial_profile[2:][valid])

    # Simple linear regression
    n = len(log_freq)
    sum_x = log_freq.sum()
    sum_y = log_power.sum()
    sum_xy = (log_freq * log_power).sum()
    sum_x2 = (log_freq ** 2).sum()

    denom = n * sum_x2 - sum_x ** 2
    if abs(denom) < 1e-10:
        return 0.0

    slope = float((n * sum_xy - sum_x * sum_y) / denom)
    return slope


def _detect_grid_artifacts(power_spectrum: NDArray[np.float64]) -> float:
    """Detect GAN checkerboard/grid artifacts in the spectrum.

    Transposed convolutions in GANs create periodic artifacts that manifest
    as peaks at specific frequencies (typically at 1/2 and 1/4 of the
    spatial frequency).  We check for abnormally strong peaks at these
    locations relative to their surroundings.

    Returns a score in [0, 1] where higher = stronger artifacts.
    """
    h, w = power_spectrum.shape

    # Check for peaks at checkerboard frequencies (N/2, N/4, N/8)
    artifact_freqs = [
        (h // 2, w // 2),
        (h // 4, w // 4),
        (h // 8, w // 8),
        (h // 4, w // 2),
        (h // 2, w // 4),
    ]

    max_ratio = 0.0

    for fy, fx in artifact_freqs:
        if fy >= h or fx >= w:
            continue

        # Peak value
        peak_val = power_spectrum[fy, fx]

        # Local neighborhood (5x5 excluding center)
        y_lo = max(0, fy - 2)
        y_hi = min(h, fy + 3)
        x_lo = max(0, fx - 2)
        x_hi = min(w, fx + 3)

        neighborhood = power_spectrum[y_lo:y_hi, x_lo:x_hi].copy()
        local_fy = fy - y_lo
        local_fx = fx - x_lo
        if local_fy < neighborhood.shape[0] and local_fx < neighborhood.shape[1]:
            neighborhood[local_fy, local_fx] = 0

        neighbor_mean = neighborhood.mean()
        if neighbor_mean > 0:
            ratio = peak_val / neighbor_mean
            max_ratio = max(max_ratio, ratio)

    # Map ratio to score
    if max_ratio < _GRID_ARTIFACT_RATIO_THRESHOLD:
        return 0.0
    elif max_ratio > _GRID_ARTIFACT_RATIO_THRESHOLD * 3:
        return 1.0
    else:
        return float(
            (max_ratio - _GRID_ARTIFACT_RATIO_THRESHOLD)
            / (_GRID_ARTIFACT_RATIO_THRESHOLD * 2)
        )


def _compute_patch_consistency(
    patch_spectra: list[NDArray[np.float64]],
) -> float:
    """Measure spectral consistency across patches.

    In real faces, neighboring skin patches have similar spectral
    characteristics.  In face-swapped deepfakes, the swapped region
    often has different spectral properties than surrounding areas,
    creating detectable discontinuities.

    Returns anomaly score in [0, 1].
    """
    if len(patch_spectra) < 2:
        return 0.0

    # Compute radial profiles for each patch
    slopes: list[float] = []
    energies: list[float] = []

    for spectrum in patch_spectra:
        slopes.append(_compute_spectral_slope(spectrum))
        energies.append(float(spectrum.sum()))

    slopes_arr = np.array(slopes)
    energies_arr = np.array(energies)

    # High variation in spectral slope across patches is suspicious
    slope_std = float(slopes_arr.std()) if len(slopes_arr) > 1 else 0.0

    # High variation in total energy is also suspicious
    energy_mean = energies_arr.mean()
    energy_cv = (
        float(energies_arr.std() / energy_mean) if energy_mean > 0 else 0.0
    )

    # Score: high slope variation or high energy variation
    slope_anomaly = min(1.0, slope_std / 0.8)  # std > 0.8 is very anomalous
    energy_anomaly = min(1.0, energy_cv / 0.6)  # CV > 0.6 is very anomalous

    consistency_score = 0.6 * slope_anomaly + 0.4 * energy_anomaly
    return float(max(0.0, min(1.0, consistency_score)))


def _compute_temporal_texture_drift(
    frame_spectral_slopes: list[float],
) -> float:
    """Measure frame-to-frame texture stability.

    Real skin texture is temporally stable -- the spectral slope should
    not change dramatically between consecutive frames (accounting for
    smooth illumination changes).  Deepfakes can exhibit sudden texture
    shifts when the generation model produces inconsistent frames.

    Returns anomaly score in [0, 1].
    """
    if len(frame_spectral_slopes) < 2:
        return 0.0

    slopes = np.array(frame_spectral_slopes)

    # First-order differences: frame-to-frame slope changes
    diffs = np.abs(np.diff(slopes))

    # Mean and max jumps
    mean_jump = float(diffs.mean())
    max_jump = float(diffs.max())

    # High-frequency jitter: changes that reverse direction rapidly
    if len(diffs) > 1:
        sign_changes = np.diff(np.sign(np.diff(slopes)))
        jitter_ratio = float((np.abs(sign_changes) > 0).sum() / len(sign_changes))
    else:
        jitter_ratio = 0.0

    # Score components
    mean_anomaly = min(1.0, mean_jump / 0.3)
    max_anomaly = min(1.0, max_jump / 0.8)
    jitter_anomaly = min(1.0, jitter_ratio / 0.7)  # >70% reversals is suspicious

    drift_score = 0.35 * mean_anomaly + 0.35 * max_anomaly + 0.30 * jitter_anomaly
    return float(max(0.0, min(1.0, drift_score)))


def analyze_texture(
    frames: list[NDArray[np.uint8]],
    skin_masks: list[NDArray[np.bool_]],
) -> TextureAnalysisResult:
    """Run skin texture frequency analysis across video frames.

    Parameters
    ----------
    frames:
        List of BGR frames (H, W, 3).
    skin_masks:
        Per-frame boolean masks for facial skin ROI.

    Returns
    -------
    TextureAnalysisResult with sub-scores and composite anomaly.
    """
    n_frames = len(frames)

    if n_frames == 0:
        return TextureAnalysisResult(
            anomaly_score=0.0,
            spectral_slope_anomaly=0.0,
            grid_artifact_score=0.0,
            patch_consistency_score=0.0,
            temporal_texture_drift=0.0,
        )

    all_slopes: list[float] = []
    all_grid_scores: list[float] = []
    all_consistency_scores: list[float] = []
    frame_mean_slopes: list[float] = []

    # Sample frames evenly (analyze every Nth frame for efficiency)
    step = max(1, n_frames // 30)
    sampled_indices = range(0, n_frames, step)

    for idx in sampled_indices:
        patches = _extract_skin_patches(frames[idx], skin_masks[idx])

        if len(patches) < _MIN_PATCHES:
            continue

        # Compute spectra for all patches
        spectra = [_compute_dct_spectrum(p) for p in patches]

        # Per-patch spectral slope
        slopes = [_compute_spectral_slope(s) for s in spectra]
        all_slopes.extend(slopes)
        frame_mean_slopes.append(float(np.mean(slopes)) if slopes else 0.0)

        # Per-patch grid artifact detection
        grid_scores = [_detect_grid_artifacts(s) for s in spectra]
        all_grid_scores.extend(grid_scores)

        # Cross-patch consistency for this frame
        consistency = _compute_patch_consistency(spectra)
        all_consistency_scores.append(consistency)

    # Aggregate results
    if not all_slopes:
        logger.warning(
            "texture_analysis_insufficient_patches",
            n_frames=n_frames,
        )
        return TextureAnalysisResult(
            anomaly_score=0.0,
            spectral_slope_anomaly=0.0,
            grid_artifact_score=0.0,
            patch_consistency_score=0.0,
            temporal_texture_drift=0.0,
        )

    # 1. Spectral slope anomaly: deviation from natural 1/f
    mean_slope = float(np.mean(all_slopes))
    if _REAL_SKIN_SLOPE_LOW <= mean_slope <= _REAL_SKIN_SLOPE_HIGH:
        spectral_slope_anomaly = 0.0
    elif mean_slope > _REAL_SKIN_SLOPE_HIGH:
        spectral_slope_anomaly = float(
            min(1.0, (mean_slope - _REAL_SKIN_SLOPE_HIGH) / 1.5)
        )
    else:
        spectral_slope_anomaly = float(
            min(1.0, (_REAL_SKIN_SLOPE_LOW - mean_slope) / 1.5)
        )

    # 2. GAN grid artifacts: take worst-case (95th percentile)
    grid_scores_arr = np.array(all_grid_scores)
    grid_artifact_score = float(np.percentile(grid_scores_arr, 95))

    # 3. Patch consistency: mean across frames
    patch_consistency_score = float(np.mean(all_consistency_scores))

    # 4. Temporal texture drift
    temporal_drift = _compute_temporal_texture_drift(frame_mean_slopes)

    # Composite anomaly score
    anomaly_score = float(
        0.25 * spectral_slope_anomaly
        + 0.30 * grid_artifact_score
        + 0.25 * patch_consistency_score
        + 0.20 * temporal_drift
    )
    anomaly_score = max(0.0, min(1.0, anomaly_score))

    logger.info(
        "texture_analysis_complete",
        anomaly_score=round(anomaly_score, 3),
        spectral_slope_anomaly=round(spectral_slope_anomaly, 3),
        grid_artifact_score=round(grid_artifact_score, 3),
        patch_consistency=round(patch_consistency_score, 3),
        temporal_drift=round(temporal_drift, 3),
        mean_spectral_slope=round(mean_slope, 3),
        n_patches_total=len(all_slopes),
        n_frames_analyzed=len(frame_mean_slopes),
    )

    return TextureAnalysisResult(
        anomaly_score=anomaly_score,
        spectral_slope_anomaly=spectral_slope_anomaly,
        grid_artifact_score=grid_artifact_score,
        patch_consistency_score=patch_consistency_score,
        temporal_texture_drift=temporal_drift,
    )
