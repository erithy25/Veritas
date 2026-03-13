"""Facial symmetry analysis for deepfake detection.

Real human faces are naturally asymmetric -- subtle differences exist
between the left and right halves in skin texture, pore distribution,
lighting response, and muscle tone.  Many deepfake generation methods
produce faces that are either:

1. **Too symmetric**: Autoencoder/GAN architectures with symmetric
   latent codes generate unnaturally perfect bilateral symmetry.

2. **Asymmetric in the wrong way**: Face-swapped content may exhibit
   asymmetry patterns that are inconsistent across frames or that
   don't match natural anatomical asymmetry.

3. **Boundary-asymmetric**: The blending boundary between swapped
   and original regions creates asymmetric artifact patterns that
   differ from natural facial asymmetry.

This module analyzes bilateral symmetry at multiple scales (pixel,
patch, and structural) across video frames to detect these anomalies.
"""

from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np
from numpy.typing import NDArray
import structlog

logger = structlog.get_logger(__name__)

# Minimum face width for reliable symmetry analysis.
_MIN_FACE_WIDTH: int = 64

# Minimum frames for temporal symmetry analysis.
_MIN_FRAMES: int = 30

# Natural asymmetry range: real faces have a pixel-level L/R difference
# of roughly 3-12% (normalized). Below or above this is suspicious.
_NATURAL_ASYMMETRY_LOW: float = 0.02
_NATURAL_ASYMMETRY_HIGH: float = 0.15


@dataclass(frozen=True, slots=True)
class SymmetryAnalysisResult:
    """Result of facial symmetry analysis."""

    anomaly_score: float
    """0.0 = natural asymmetry, 1.0 = highly anomalous (likely fake)."""

    pixel_symmetry_anomaly: float
    """Pixel-level bilateral symmetry deviation from natural range [0, 1]."""

    gradient_symmetry_anomaly: float
    """Edge/gradient symmetry anomaly (texture-level) [0, 1]."""

    temporal_symmetry_stability: float
    """How stable the symmetry pattern is across frames [0, 1].
    Unnaturally stable symmetry = suspicious."""

    frequency_symmetry_anomaly: float
    """Frequency-domain L/R spectral difference anomaly [0, 1]."""


def _extract_face_halves(
    frame: NDArray[np.uint8],
    bbox: NDArray[np.float64],
) -> tuple[NDArray[np.float64], NDArray[np.float64]] | None:
    """Extract left and right halves of a detected face.

    The face is cropped from the bounding box, converted to grayscale,
    and split at the vertical midline.  The right half is horizontally
    flipped so both halves can be directly compared.

    Returns (left_half, flipped_right_half) or None if face is too small.
    """
    x1, y1, x2, y2 = int(bbox[0]), int(bbox[1]), int(bbox[2]), int(bbox[3])
    h, w = frame.shape[:2]

    # Clamp to frame bounds
    x1, y1 = max(0, x1), max(0, y1)
    x2, y2 = min(w, x2), min(h, y2)

    face_w = x2 - x1
    face_h = y2 - y1

    if face_w < _MIN_FACE_WIDTH or face_h < _MIN_FACE_WIDTH:
        return None

    face_crop = frame[y1:y2, x1:x2]
    gray = cv2.cvtColor(face_crop, cv2.COLOR_BGR2GRAY).astype(np.float64)

    # Resize to standard size for consistent comparison
    std_size = 128
    gray = cv2.resize(gray, (std_size, std_size)).astype(np.float64)

    mid = std_size // 2
    left = gray[:, :mid]
    right = gray[:, mid:]

    # Flip right half horizontally for direct comparison
    right_flipped = right[:, ::-1].copy()

    return left, right_flipped


def _pixel_symmetry_score(
    left: NDArray[np.float64],
    right: NDArray[np.float64],
) -> float:
    """Compute normalized pixel-level difference between face halves.

    Returns a value in [0, 1] representing the relative difference.
    Low values indicate high symmetry, high values indicate high asymmetry.
    """
    diff = np.abs(left - right)
    max_val = max(left.max(), right.max(), 1.0)
    return float(diff.mean() / max_val)


def _gradient_symmetry_score(
    left: NDArray[np.float64],
    right: NDArray[np.float64],
) -> float:
    """Compare edge/gradient patterns between face halves.

    Uses Sobel gradients to capture texture-level symmetry rather than
    raw pixel values, making this robust to uniform illumination differences.
    """
    # Compute gradient magnitudes
    left_u8 = left.astype(np.uint8)
    right_u8 = right.astype(np.uint8)

    left_gx = cv2.Sobel(left_u8, cv2.CV_64F, 1, 0, ksize=3)
    left_gy = cv2.Sobel(left_u8, cv2.CV_64F, 0, 1, ksize=3)
    left_grad = np.sqrt(left_gx ** 2 + left_gy ** 2)

    right_gx = cv2.Sobel(right_u8, cv2.CV_64F, 1, 0, ksize=3)
    right_gy = cv2.Sobel(right_u8, cv2.CV_64F, 0, 1, ksize=3)
    right_grad = np.sqrt(right_gx ** 2 + right_gy ** 2)

    # Normalized difference of gradient magnitudes
    max_grad = max(left_grad.max(), right_grad.max(), 1.0)
    diff = np.abs(left_grad - right_grad)

    return float(diff.mean() / max_grad)


def _frequency_symmetry_score(
    left: NDArray[np.float64],
    right: NDArray[np.float64],
) -> float:
    """Compare frequency-domain spectra between face halves.

    GAN artifacts often appear differently in the left vs right half
    of the generated face, creating spectral asymmetries that differ
    from natural lighting-based asymmetries.
    """
    # 2-D FFT magnitude spectra
    left_spec = np.abs(np.fft.fft2(left - left.mean()))
    right_spec = np.abs(np.fft.fft2(right - right.mean()))

    # Avoid division by zero
    max_spec = max(left_spec.max(), right_spec.max(), 1.0)

    # Normalized spectral difference
    spec_diff = np.abs(left_spec - right_spec)
    return float(spec_diff.mean() / max_spec)


def _score_asymmetry_naturalness(asymmetry_value: float) -> float:
    """Score how natural a given asymmetry level is.

    Real faces have moderate asymmetry. Too symmetric (deepfake generated)
    or too asymmetric (bad face swap blending) are both suspicious.

    Returns anomaly score in [0, 1].
    """
    if _NATURAL_ASYMMETRY_LOW <= asymmetry_value <= _NATURAL_ASYMMETRY_HIGH:
        return 0.0
    elif asymmetry_value < _NATURAL_ASYMMETRY_LOW:
        # Too symmetric -- suspicious
        return float(
            min(1.0, (_NATURAL_ASYMMETRY_LOW - asymmetry_value) / _NATURAL_ASYMMETRY_LOW)
        )
    else:
        # Too asymmetric -- suspicious
        return float(
            min(1.0, (asymmetry_value - _NATURAL_ASYMMETRY_HIGH) / (1.0 - _NATURAL_ASYMMETRY_HIGH))
        )


def analyze_symmetry(
    frames: list[NDArray[np.uint8]],
    bboxes: NDArray[np.float64],
) -> SymmetryAnalysisResult:
    """Run facial symmetry analysis across video frames.

    Parameters
    ----------
    frames:
        List of BGR frames (H, W, 3).
    bboxes:
        Per-frame bounding boxes, shape (N, 4).

    Returns
    -------
    SymmetryAnalysisResult with sub-scores and composite anomaly.
    """
    n_frames = len(frames)

    if n_frames == 0:
        return SymmetryAnalysisResult(
            anomaly_score=0.0,
            pixel_symmetry_anomaly=0.0,
            gradient_symmetry_anomaly=0.0,
            temporal_symmetry_stability=0.0,
            frequency_symmetry_anomaly=0.0,
        )

    pixel_asymmetries: list[float] = []
    gradient_asymmetries: list[float] = []
    frequency_asymmetries: list[float] = []

    # Sample frames evenly
    step = max(1, n_frames // 30)
    sampled_indices = range(0, n_frames, step)

    for idx in sampled_indices:
        halves = _extract_face_halves(frames[idx], bboxes[idx])
        if halves is None:
            continue

        left, right = halves

        pixel_asymmetries.append(_pixel_symmetry_score(left, right))
        gradient_asymmetries.append(_gradient_symmetry_score(left, right))
        frequency_asymmetries.append(_frequency_symmetry_score(left, right))

    if not pixel_asymmetries:
        logger.warning(
            "symmetry_analysis_no_valid_faces",
            n_frames=n_frames,
        )
        return SymmetryAnalysisResult(
            anomaly_score=0.0,
            pixel_symmetry_anomaly=0.0,
            gradient_symmetry_anomaly=0.0,
            temporal_symmetry_stability=0.0,
            frequency_symmetry_anomaly=0.0,
        )

    # 1. Pixel-level symmetry anomaly
    mean_pixel_asym = float(np.mean(pixel_asymmetries))
    pixel_symmetry_anomaly = _score_asymmetry_naturalness(mean_pixel_asym)

    # 2. Gradient symmetry anomaly
    mean_gradient_asym = float(np.mean(gradient_asymmetries))
    gradient_symmetry_anomaly = _score_asymmetry_naturalness(mean_gradient_asym)

    # 3. Temporal symmetry stability
    # Real faces change symmetry slightly with expressions/lighting.
    # Deepfakes often have unnaturally consistent symmetry across frames.
    if len(pixel_asymmetries) >= 2:
        asym_std = float(np.std(pixel_asymmetries))
        # Very low std = unnaturally stable (suspicious)
        # Normal std is roughly 0.005 - 0.03
        if asym_std < 0.003:
            temporal_stability = float(min(1.0, (0.003 - asym_std) / 0.003))
        elif asym_std > 0.05:
            # Very high variation also suspicious (flickering symmetry)
            temporal_stability = float(min(1.0, (asym_std - 0.05) / 0.1))
        else:
            temporal_stability = 0.0
    else:
        temporal_stability = 0.0

    # 4. Frequency-domain symmetry anomaly
    mean_freq_asym = float(np.mean(frequency_asymmetries))
    # Frequency asymmetry follows different natural ranges
    if mean_freq_asym < 0.01:
        frequency_anomaly = float(min(1.0, (0.01 - mean_freq_asym) / 0.01))
    elif mean_freq_asym > 0.08:
        frequency_anomaly = float(min(1.0, (mean_freq_asym - 0.08) / 0.15))
    else:
        frequency_anomaly = 0.0

    # Composite score
    anomaly_score = float(
        0.25 * pixel_symmetry_anomaly
        + 0.25 * gradient_symmetry_anomaly
        + 0.25 * temporal_stability
        + 0.25 * frequency_anomaly
    )
    anomaly_score = max(0.0, min(1.0, anomaly_score))

    logger.info(
        "symmetry_analysis_complete",
        anomaly_score=round(anomaly_score, 3),
        pixel_anomaly=round(pixel_symmetry_anomaly, 3),
        gradient_anomaly=round(gradient_symmetry_anomaly, 3),
        temporal_stability=round(temporal_stability, 3),
        frequency_anomaly=round(frequency_anomaly, 3),
        mean_pixel_asymmetry=round(mean_pixel_asym, 4),
        n_frames_analyzed=len(pixel_asymmetries),
    )

    return SymmetryAnalysisResult(
        anomaly_score=anomaly_score,
        pixel_symmetry_anomaly=pixel_symmetry_anomaly,
        gradient_symmetry_anomaly=gradient_symmetry_anomaly,
        temporal_symmetry_stability=temporal_stability,
        frequency_symmetry_anomaly=frequency_anomaly,
    )
