"""Micro-flickering detection for deepfake identification.

GAN-generated and diffusion-based face replacements often exhibit subtle
spatial instabilities at face boundaries that are invisible to the naked eye
but detectable through frequency-domain analysis.  This module tracks face
bounding-box edges across consecutive frames and applies FFT to detect
non-natural high-frequency oscillations in boundary positions.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray
import structlog

logger = structlog.get_logger(__name__)

# Minimum frames needed for meaningful FFT analysis.
_MIN_FRAMES: int = 60

# Frequency above which oscillations are considered non-natural.
# Real face motion is smooth; deepfake boundaries may jitter at 8+ Hz.
_NON_NATURAL_FREQ_HZ: float = 8.0

# Fraction of spectral energy in the high-frequency band that triggers a
# high flicker score.
_HF_ENERGY_RATIO_THRESHOLD: float = 0.15


@dataclass(frozen=True, slots=True)
class FlickerResult:
    """Result of micro-flickering analysis on a face track."""

    flicker_score: float
    """0.0 = stable boundaries (natural), 1.0 = strong flickering (likely fake)."""

    dominant_flicker_freq_hz: float | None
    """Dominant non-natural oscillation frequency, if detected."""

    hf_energy_ratio: float
    """Fraction of boundary-motion energy above the non-natural threshold."""


def _extract_boundary_signals(
    bboxes: NDArray[np.float64],
) -> dict[str, NDArray[np.float64]]:
    """Extract per-edge position time-series from bounding boxes.

    Parameters
    ----------
    bboxes:
        Array of shape (N, 4) with columns [x_min, y_min, x_max, y_max].

    Returns
    -------
    Dict mapping edge name to 1-D position signal.
    """
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
    """Compute high-frequency energy ratio and dominant non-natural frequency.

    Parameters
    ----------
    signal:
        Detrended 1-D boundary position time-series.
    fps:
        Video frame rate.

    Returns
    -------
    (hf_energy_ratio, dominant_freq_hz)
    """
    n = len(signal)
    windowed = signal * np.hanning(n)
    spectrum = np.abs(np.fft.rfft(windowed)) ** 2
    freqs = np.fft.rfftfreq(n, d=1.0 / fps)

    total_energy = spectrum.sum()
    if total_energy < 1e-12:
        return 0.0, None

    # High-frequency band: above the non-natural threshold
    hf_mask = freqs >= _NON_NATURAL_FREQ_HZ
    if not hf_mask.any():
        return 0.0, None

    hf_energy = spectrum[hf_mask].sum()
    hf_ratio = float(hf_energy / total_energy)

    # Find dominant HF peak
    hf_spectrum = spectrum[hf_mask]
    peak_idx = np.argmax(hf_spectrum)
    dominant_freq = float(freqs[hf_mask][peak_idx])

    return hf_ratio, dominant_freq


def analyze_flicker(
    face_bboxes: NDArray[np.float64],
    fps: float,
) -> FlickerResult:
    """Detect micro-flickering in face boundary positions across frames.

    Parameters
    ----------
    face_bboxes:
        Array of shape (N, 4) with per-frame bounding boxes
        [x_min, y_min, x_max, y_max] for a single tracked face.
    fps:
        Video frame rate.

    Returns
    -------
    FlickerResult with flicker score, dominant frequency, and energy ratio.
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
        )

    boundary_signals = _extract_boundary_signals(face_bboxes)

    # Analyze each boundary edge and aggregate
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

    # Map HF energy ratio to a flicker score in [0, 1]
    if max_hf_ratio <= 0:
        flicker_score = 0.0
    elif max_hf_ratio >= _HF_ENERGY_RATIO_THRESHOLD * 2:
        flicker_score = 1.0
    else:
        flicker_score = float(
            min(1.0, max_hf_ratio / (_HF_ENERGY_RATIO_THRESHOLD * 2))
        )

    logger.info(
        "flicker_analysis_complete",
        flicker_score=round(flicker_score, 3),
        max_hf_energy_ratio=round(max_hf_ratio, 4),
        dominant_freq_hz=(
            round(max_dominant_freq, 2) if max_dominant_freq else None
        ),
        n_frames=n_frames,
    )

    return FlickerResult(
        flicker_score=flicker_score,
        dominant_flicker_freq_hz=max_dominant_freq,
        hf_energy_ratio=max_hf_ratio,
    )
