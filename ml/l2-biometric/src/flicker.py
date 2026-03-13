"""Micro-flickering and boundary artifact detection for deepfake identification.

GAN-generated and diffusion-based face replacements exhibit two categories
of spatial instabilities:

1. **Bounding-box flicker**: The face region as a whole jitters at
   non-natural high frequencies due to frame-independent generation.

2. **Pixel-level boundary artifacts**: The blending boundary between the
   swapped face and the original frame creates gradient discontinuities,
   color bleeding, and texture mismatches that fluctuate across frames.

This module detects both artifact types through frequency-domain analysis
of bounding-box edges AND pixel-level gradient analysis along the face
boundary contour.
"""

from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np
from numpy.typing import NDArray
import structlog

logger = structlog.get_logger(__name__)

# Minimum frames needed for meaningful FFT analysis.
_MIN_FRAMES: int = 60

# Frequency above which oscillations are considered non-natural.
_NON_NATURAL_FREQ_HZ: float = 8.0

# Fraction of spectral energy in the high-frequency band that triggers a
# high flicker score.
_HF_ENERGY_RATIO_THRESHOLD: float = 0.15

# Boundary analysis: width of the analysis band around the face edge (pixels).
_BOUNDARY_BAND_WIDTH: int = 8

# Gradient discontinuity threshold (normalized).
_GRADIENT_DISCONTINUITY_THRESHOLD: float = 0.3


@dataclass(frozen=True, slots=True)
class FlickerResult:
    """Result of micro-flickering and boundary artifact analysis."""

    flicker_score: float
    """0.0 = stable boundaries (natural), 1.0 = strong flickering (likely fake)."""

    dominant_flicker_freq_hz: float | None
    """Dominant non-natural oscillation frequency, if detected."""

    hf_energy_ratio: float
    """Fraction of boundary-motion energy above the non-natural threshold."""

    boundary_gradient_anomaly: float
    """Pixel-level gradient discontinuity at face boundary [0, 1]."""

    boundary_color_bleed: float
    """Color inconsistency at face boundary [0, 1]."""

    boundary_temporal_instability: float
    """Frame-to-frame instability of boundary artifacts [0, 1]."""


def _extract_boundary_signals(
    bboxes: NDArray[np.float64],
) -> dict[str, NDArray[np.float64]]:
    """Extract per-edge position time-series from bounding boxes."""
    return {
        "left": bboxes[:, 0],
        "top": bboxes[:, 1],
        "right": bboxes[:, 2],
        "bottom": bboxes[:, 3],
        "width": bboxes[:, 2] - bboxes[:, 0],
        "height": bboxes[:, 3] - bboxes[:, 1],
    }


def _detrend(signal: NDArray[np.float64]) -> NDArray[np.float64]:
    """Remove linear trend from a signal (head motion compensation)."""
    n = len(signal)
    x = np.arange(n, dtype=np.float64)
    coeffs = np.polyfit(x, signal, deg=1)
    trend = np.polyval(coeffs, x)
    return signal - trend


def _analyze_boundary_spectrum(
    signal: NDArray[np.float64],
    fps: float,
) -> tuple[float, float | None]:
    """Compute high-frequency energy ratio and dominant non-natural frequency."""
    n = len(signal)
    windowed = signal * np.hanning(n)
    spectrum = np.abs(np.fft.rfft(windowed)) ** 2
    freqs = np.fft.rfftfreq(n, d=1.0 / fps)

    total_energy = spectrum.sum()
    if total_energy < 1e-12:
        return 0.0, None

    hf_mask = freqs >= _NON_NATURAL_FREQ_HZ
    if not hf_mask.any():
        return 0.0, None

    hf_energy = spectrum[hf_mask].sum()
    hf_ratio = float(hf_energy / total_energy)

    hf_spectrum = spectrum[hf_mask]
    peak_idx = np.argmax(hf_spectrum)
    dominant_freq = float(freqs[hf_mask][peak_idx])

    return hf_ratio, dominant_freq


def _extract_boundary_band(
    frame: NDArray[np.uint8],
    bbox: NDArray[np.float64],
    band_width: int = _BOUNDARY_BAND_WIDTH,
) -> tuple[NDArray[np.float64], NDArray[np.float64]] | None:
    """Extract inner and outer bands around the face bounding box.

    The inner band is just inside the face boundary, and the outer band
    is just outside.  Comparing these reveals blending artifacts.

    Returns (inner_band_pixels, outer_band_pixels) as float64 BGR arrays,
    or None if the face is too small or near frame edges.
    """
    h, w = frame.shape[:2]
    x1, y1, x2, y2 = int(bbox[0]), int(bbox[1]), int(bbox[2]), int(bbox[3])

    # Ensure enough room for outer band
    if (x1 - band_width < 0 or y1 - band_width < 0 or
            x2 + band_width >= w or y2 + band_width >= h):
        return None

    face_w = x2 - x1
    face_h = y2 - y1
    if face_w < 32 or face_h < 32:
        return None

    # Create masks for inner and outer bands
    inner_mask = np.zeros((h, w), dtype=bool)
    outer_mask = np.zeros((h, w), dtype=bool)

    # Inner band: inside the bbox, near edges
    inner_mask[y1:y1 + band_width, x1:x2] = True  # top strip
    inner_mask[y2 - band_width:y2, x1:x2] = True   # bottom strip
    inner_mask[y1:y2, x1:x1 + band_width] = True   # left strip
    inner_mask[y1:y2, x2 - band_width:x2] = True   # right strip

    # Outer band: outside the bbox, near edges
    outer_mask[y1 - band_width:y1, x1 - band_width:x2 + band_width] = True
    outer_mask[y2:y2 + band_width, x1 - band_width:x2 + band_width] = True
    outer_mask[y1:y2, x1 - band_width:x1] = True
    outer_mask[y1:y2, x2:x2 + band_width] = True

    frame_f = frame.astype(np.float64)
    inner_pixels = frame_f[inner_mask]
    outer_pixels = frame_f[outer_mask]

    if inner_pixels.size == 0 or outer_pixels.size == 0:
        return None

    return inner_pixels, outer_pixels


def _compute_gradient_discontinuity(
    frame: NDArray[np.uint8],
    bbox: NDArray[np.float64],
) -> float:
    """Measure gradient discontinuity at the face boundary.

    In natural video, the gradient across the face boundary is smooth.
    In face-swapped deepfakes, the blending creates sharp gradient
    transitions at the swap boundary.

    Returns a score in [0, 1] where higher = more discontinuous.
    """
    h, w = frame.shape[:2]
    x1, y1, x2, y2 = int(bbox[0]), int(bbox[1]), int(bbox[2]), int(bbox[3])

    # Clamp and validate
    x1, y1 = max(1, x1), max(1, y1)
    x2, y2 = min(w - 1, x2), min(h - 1, y2)

    if x2 - x1 < 16 or y2 - y1 < 16:
        return 0.0

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(np.float64)

    # Compute Laplacian (second derivative) -- highlights edges
    laplacian = np.abs(cv2.Laplacian(gray, cv2.CV_64F))

    # Sample gradient magnitude along the face boundary
    boundary_gradients: list[float] = []

    # Top edge
    if y1 > 0 and y1 < h:
        strip = laplacian[max(0, y1 - 2):min(h, y1 + 3), x1:x2]
        if strip.size > 0:
            boundary_gradients.append(float(strip.mean()))

    # Bottom edge
    if y2 > 0 and y2 < h:
        strip = laplacian[max(0, y2 - 2):min(h, y2 + 3), x1:x2]
        if strip.size > 0:
            boundary_gradients.append(float(strip.mean()))

    # Left edge
    if x1 > 0 and x1 < w:
        strip = laplacian[y1:y2, max(0, x1 - 2):min(w, x1 + 3)]
        if strip.size > 0:
            boundary_gradients.append(float(strip.mean()))

    # Right edge
    if x2 > 0 and x2 < w:
        strip = laplacian[y1:y2, max(0, x2 - 2):min(w, x2 + 3)]
        if strip.size > 0:
            boundary_gradients.append(float(strip.mean()))

    if not boundary_gradients:
        return 0.0

    # Compare boundary gradient to interior gradient
    interior = laplacian[y1 + 5:y2 - 5, x1 + 5:x2 - 5]
    if interior.size == 0:
        return 0.0

    interior_mean = float(interior.mean())
    boundary_mean = float(np.mean(boundary_gradients))

    if interior_mean < 1e-6:
        return 0.0

    # Ratio of boundary to interior gradient
    ratio = boundary_mean / interior_mean

    # Natural faces: ratio ~1.0-2.0 (edges at face boundary are moderate)
    # Deepfakes: ratio > 2.5 (sharp blending boundary)
    if ratio < 2.0:
        return 0.0
    elif ratio > 5.0:
        return 1.0
    else:
        return float((ratio - 2.0) / 3.0)


def _compute_boundary_color_bleed(
    frame: NDArray[np.uint8],
    bbox: NDArray[np.float64],
) -> float:
    """Detect color bleeding at the face boundary.

    Face-swap blending often produces subtle color inconsistencies where
    the swapped face meets the original frame -- slight hue shifts,
    saturation mismatches, or luminance discontinuities.

    Returns score in [0, 1].
    """
    result = _extract_boundary_band(frame, bbox)
    if result is None:
        return 0.0

    inner_pixels, outer_pixels = result

    # Compare color distributions between inner and outer bands
    # Using per-channel mean absolute difference
    inner_mean = inner_pixels.mean(axis=0) if inner_pixels.ndim > 1 else inner_pixels.mean()
    outer_mean = outer_pixels.mean(axis=0) if outer_pixels.ndim > 1 else outer_pixels.mean()

    color_diff = np.abs(inner_mean - outer_mean)

    if np.isscalar(color_diff):
        normalized_diff = float(color_diff) / 255.0
    else:
        normalized_diff = float(color_diff.mean()) / 255.0

    # Also check variance difference (blending smooths textures)
    inner_var = float(inner_pixels.var())
    outer_var = float(outer_pixels.var())
    max_var = max(inner_var, outer_var, 1.0)
    var_ratio = abs(inner_var - outer_var) / max_var

    # Combine color difference and variance difference
    score = 0.6 * min(1.0, normalized_diff / 0.08) + 0.4 * min(1.0, var_ratio / 0.4)
    return float(max(0.0, min(1.0, score)))


def analyze_flicker(
    face_bboxes: NDArray[np.float64],
    fps: float,
    frames: list[NDArray[np.uint8]] | None = None,
) -> FlickerResult:
    """Detect micro-flickering and boundary artifacts in face tracking data.

    Parameters
    ----------
    face_bboxes:
        Array of shape (N, 4) with per-frame bounding boxes
        [x_min, y_min, x_max, y_max] for a single tracked face.
    fps:
        Video frame rate.
    frames:
        Optional list of BGR frames for pixel-level boundary analysis.
        If None, only bounding-box flicker is analyzed.

    Returns
    -------
    FlickerResult with flicker score, boundary analysis, and frequencies.
    """
    n_frames = face_bboxes.shape[0]

    if n_frames < _MIN_FRAMES:
        logger.warning(
            "flicker_insufficient_frames",
            n_frames=n_frames,
            min_required=_MIN_FRAMES,
        )
        return FlickerResult(
            flicker_score=0.0,
            dominant_flicker_freq_hz=None,
            hf_energy_ratio=0.0,
            boundary_gradient_anomaly=0.0,
            boundary_color_bleed=0.0,
            boundary_temporal_instability=0.0,
        )

    # ---- Part 1: Bounding-box frequency analysis (original) ----
    boundary_signals = _extract_boundary_signals(face_bboxes)

    max_hf_ratio = 0.0
    max_dominant_freq: float | None = None

    for edge_name, raw_signal in boundary_signals.items():
        detrended = _detrend(raw_signal)
        hf_ratio, dominant_freq = _analyze_boundary_spectrum(detrended, fps)

        logger.debug(
            "flicker_edge_analysis",
            edge=edge_name,
            hf_energy_ratio=round(hf_ratio, 4),
            dominant_freq_hz=round(dominant_freq, 2) if dominant_freq else None,
        )

        if hf_ratio > max_hf_ratio:
            max_hf_ratio = hf_ratio
            max_dominant_freq = dominant_freq

    # Map bbox HF energy ratio to score
    if max_hf_ratio <= 0:
        bbox_flicker_score = 0.0
    elif max_hf_ratio >= _HF_ENERGY_RATIO_THRESHOLD * 2:
        bbox_flicker_score = 1.0
    else:
        bbox_flicker_score = float(
            min(1.0, max_hf_ratio / (_HF_ENERGY_RATIO_THRESHOLD * 2))
        )

    # ---- Part 2: Pixel-level boundary analysis (new) ----
    boundary_gradient_anomaly = 0.0
    boundary_color_bleed = 0.0
    boundary_temporal_instability = 0.0

    if frames is not None and len(frames) >= _MIN_FRAMES:
        gradient_scores: list[float] = []
        color_scores: list[float] = []

        # Sample every Nth frame for efficiency
        step = max(1, n_frames // 30)
        for idx in range(0, min(n_frames, len(frames)), step):
            grad = _compute_gradient_discontinuity(frames[idx], face_bboxes[idx])
            color = _compute_boundary_color_bleed(frames[idx], face_bboxes[idx])
            gradient_scores.append(grad)
            color_scores.append(color)

        if gradient_scores:
            # Use 90th percentile (robust against occasional clean frames)
            boundary_gradient_anomaly = float(np.percentile(gradient_scores, 90))
            boundary_color_bleed = float(np.percentile(color_scores, 90))

            # Temporal instability: how much do boundary artifacts vary?
            # In real video, boundary appearance is consistent.
            # In deepfakes, boundary artifacts can flicker frame-to-frame.
            if len(gradient_scores) >= 3:
                grad_diffs = np.abs(np.diff(gradient_scores))
                boundary_temporal_instability = float(
                    min(1.0, grad_diffs.mean() / 0.15)
                )

    # ---- Combine all signals into final flicker score ----
    if frames is not None:
        # Full analysis: weight both bbox and pixel-level signals
        flicker_score = float(
            0.30 * bbox_flicker_score
            + 0.30 * boundary_gradient_anomaly
            + 0.25 * boundary_color_bleed
            + 0.15 * boundary_temporal_instability
        )
    else:
        # Bbox-only analysis
        flicker_score = bbox_flicker_score

    flicker_score = max(0.0, min(1.0, flicker_score))

    logger.info(
        "flicker_analysis_complete",
        flicker_score=round(flicker_score, 3),
        bbox_flicker=round(bbox_flicker_score, 3),
        max_hf_energy_ratio=round(max_hf_ratio, 4),
        dominant_freq_hz=(
            round(max_dominant_freq, 2) if max_dominant_freq else None
        ),
        boundary_gradient=round(boundary_gradient_anomaly, 3),
        boundary_color=round(boundary_color_bleed, 3),
        boundary_temporal=round(boundary_temporal_instability, 3),
        n_frames=n_frames,
    )

    return FlickerResult(
        flicker_score=flicker_score,
        dominant_flicker_freq_hz=max_dominant_freq,
        hf_energy_ratio=max_hf_ratio,
        boundary_gradient_anomaly=boundary_gradient_anomaly,
        boundary_color_bleed=boundary_color_bleed,
        boundary_temporal_instability=boundary_temporal_instability,
    )
