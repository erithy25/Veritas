"""Eye movement analysis for deepfake detection.

Real human eyes exhibit characteristic patterns: saccades (rapid jumps
between fixation points), micro-saccades, smooth pursuit, and regular blink
cycles.  GAN/diffusion deepfakes often produce unrealistic eye behavior --
overly smooth gaze trajectories, unnatural blink timing, or missing saccadic
dynamics.  This module tracks pupil positions and eyelid state across frames
to detect such anomalies.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray
import structlog

logger = structlog.get_logger(__name__)

# Physiological constants
_NORMAL_BLINK_RATE_MIN: float = 12.0  # blinks/minute
_NORMAL_BLINK_RATE_MAX: float = 25.0
_NORMAL_BLINK_DURATION_MIN_MS: float = 100.0
_NORMAL_BLINK_DURATION_MAX_MS: float = 400.0

# Saccade velocity threshold (pixels/frame, normalized by inter-pupil distance)
_SACCADE_VELOCITY_THRESHOLD: float = 0.02

# Minimum frames required for reliable analysis
_MIN_FRAMES: int = 90  # ~3 seconds at 30 fps


@dataclass(frozen=True, slots=True)
class EyeAnalysisResult:
    """Result of eye movement analysis on a face track."""

    anomaly_score: float
    """0.0 = natural eye behavior, 1.0 = highly anomalous (likely fake)."""

    blink_rate_per_min: float
    """Detected blink rate in blinks per minute."""

    blink_rate_anomaly: float
    """How far the blink rate deviates from the normal range [0, 1]."""

    mean_blink_duration_ms: float
    """Mean blink duration in milliseconds."""

    blink_duration_anomaly: float
    """How anomalous the blink durations are [0, 1]."""

    saccade_ratio: float
    """Fraction of inter-frame gaze shifts classified as saccades."""

    saccade_fixation_anomaly: float
    """Anomaly score for saccade-fixation patterns [0, 1]."""


def _compute_blink_metrics(
    eyelid_openness: NDArray[np.float64],
    fps: float,
) -> tuple[float, float, float, float]:
    """Analyze blink rate and duration from eyelid openness signal.

    Parameters
    ----------
    eyelid_openness:
        Per-frame eyelid openness ratio (0 = fully closed, 1 = fully open).
        Shape: (N,).
    fps:
        Video frame rate.

    Returns
    -------
    (blink_rate_per_min, blink_rate_anomaly, mean_duration_ms, duration_anomaly)
    """
    n = len(eyelid_openness)
    duration_sec = n / fps

    # Detect blinks as contiguous regions where openness drops below threshold
    blink_threshold = 0.3
    is_closed = eyelid_openness < blink_threshold

    # Find blink onset/offset transitions
    transitions = np.diff(is_closed.astype(np.int8))
    onsets = np.where(transitions == 1)[0]
    offsets = np.where(transitions == -1)[0]

    # Handle edge cases
    if len(onsets) == 0 or len(offsets) == 0:
        # No blinks detected -- suspicious for segments > 5 seconds
        blink_rate = 0.0
        rate_anomaly = 1.0 if duration_sec > 5.0 else 0.5
        return blink_rate, rate_anomaly, 0.0, 0.5

    # Align onsets and offsets
    if offsets[0] < onsets[0]:
        offsets = offsets[1:]
    min_len = min(len(onsets), len(offsets))
    onsets = onsets[:min_len]
    offsets = offsets[:min_len]

    # Blink rate
    n_blinks = len(onsets)
    blink_rate = (n_blinks / duration_sec) * 60.0 if duration_sec > 0 else 0.0

    # Rate anomaly: deviation from normal range
    if _NORMAL_BLINK_RATE_MIN <= blink_rate <= _NORMAL_BLINK_RATE_MAX:
        rate_anomaly = 0.0
    elif blink_rate < _NORMAL_BLINK_RATE_MIN:
        rate_anomaly = float(
            min(1.0, (_NORMAL_BLINK_RATE_MIN - blink_rate) / _NORMAL_BLINK_RATE_MIN)
        )
    else:
        rate_anomaly = float(
            min(1.0, (blink_rate - _NORMAL_BLINK_RATE_MAX) / _NORMAL_BLINK_RATE_MAX)
        )

    # Blink durations
    durations_frames = offsets - onsets
    durations_ms = (durations_frames / fps) * 1000.0
    mean_duration_ms = float(durations_ms.mean()) if len(durations_ms) > 0 else 0.0

    # Duration anomaly
    if (
        _NORMAL_BLINK_DURATION_MIN_MS <= mean_duration_ms
        <= _NORMAL_BLINK_DURATION_MAX_MS
    ):
        duration_anomaly = 0.0
    elif mean_duration_ms < _NORMAL_BLINK_DURATION_MIN_MS:
        duration_anomaly = float(
            min(
                1.0,
                (_NORMAL_BLINK_DURATION_MIN_MS - mean_duration_ms)
                / _NORMAL_BLINK_DURATION_MIN_MS,
            )
        )
    else:
        duration_anomaly = float(
            min(
                1.0,
                (mean_duration_ms - _NORMAL_BLINK_DURATION_MAX_MS)
                / _NORMAL_BLINK_DURATION_MAX_MS,
            )
        )

    # Also check regularity -- perfectly periodic blinks are suspicious
    if n_blinks >= 3:
        intervals = np.diff(onsets) / fps
        cv = float(intervals.std() / intervals.mean()) if intervals.mean() > 0 else 0
        # Very low coefficient of variation => robotic regularity
        if cv < 0.1:
            duration_anomaly = max(duration_anomaly, 0.6)

    return blink_rate, rate_anomaly, mean_duration_ms, duration_anomaly


def _compute_saccade_fixation_metrics(
    pupil_positions: NDArray[np.float64],
    inter_pupil_distance: float,
) -> tuple[float, float]:
    """Analyze saccade-fixation patterns from pupil position time-series.

    Parameters
    ----------
    pupil_positions:
        Per-frame pupil center positions, shape (N, 2) as (x, y).
    inter_pupil_distance:
        Approximate inter-pupil distance in pixels, used for normalization.

    Returns
    -------
    (saccade_ratio, saccade_fixation_anomaly)
    """
    if inter_pupil_distance < 1e-6:
        return 0.0, 0.5

    # Compute per-frame gaze velocity normalized by face scale
    deltas = np.diff(pupil_positions, axis=0)
    velocities = np.linalg.norm(deltas, axis=1) / inter_pupil_distance

    n_frames = len(velocities)
    if n_frames == 0:
        return 0.0, 0.5

    # Classify each frame as saccade or fixation
    is_saccade = velocities > _SACCADE_VELOCITY_THRESHOLD
    saccade_ratio = float(is_saccade.sum() / n_frames)

    # Anomaly scoring:
    # - Real eyes: mix of saccades (~10-20%) and fixations (~80-90%)
    # - Deepfakes: often either too smooth (0% saccades) or jittery (>40%)
    normal_saccade_low = 0.05
    normal_saccade_high = 0.30

    if normal_saccade_low <= saccade_ratio <= normal_saccade_high:
        pattern_anomaly = 0.0
    elif saccade_ratio < normal_saccade_low:
        # Too smooth -- suspicious
        pattern_anomaly = float(
            min(1.0, (normal_saccade_low - saccade_ratio) / normal_saccade_low)
        )
    else:
        # Too jittery
        pattern_anomaly = float(
            min(1.0, (saccade_ratio - normal_saccade_high) / (1.0 - normal_saccade_high))
        )

    # Check for natural saccade velocity distribution (should be bimodal)
    if n_frames >= 30:
        velocity_std = float(velocities.std())
        velocity_mean = float(velocities.mean())
        if velocity_mean > 0:
            cv = velocity_std / velocity_mean
            # Real eyes have high CV (bimodal: fixation + saccade)
            # Deepfakes tend to have lower CV (unimodal)
            if cv < 0.5:
                pattern_anomaly = max(pattern_anomaly, 0.4)

    return saccade_ratio, pattern_anomaly


def analyze_eyes(
    pupil_positions: NDArray[np.float64],
    eyelid_openness: NDArray[np.float64],
    inter_pupil_distance: float,
    fps: float,
) -> EyeAnalysisResult:
    """Run eye movement analysis on tracked pupil and eyelid data.

    Parameters
    ----------
    pupil_positions:
        Per-frame pupil center (x, y) positions, shape (N, 2).
    eyelid_openness:
        Per-frame eyelid openness ratio [0, 1], shape (N,).
    inter_pupil_distance:
        Mean inter-pupil distance in pixels (for scale normalization).
    fps:
        Video frame rate.

    Returns
    -------
    EyeAnalysisResult with composite anomaly score and sub-metrics.
    """
    n_frames = len(pupil_positions)

    if n_frames < _MIN_FRAMES:
        logger.warning(
            "eye_analysis_insufficient_frames",
            n_frames=n_frames,
            min_required=_MIN_FRAMES,
        )
        return EyeAnalysisResult(
            anomaly_score=0.0,
            blink_rate_per_min=0.0,
            blink_rate_anomaly=0.0,
            mean_blink_duration_ms=0.0,
            blink_duration_anomaly=0.0,
            saccade_ratio=0.0,
            saccade_fixation_anomaly=0.0,
        )

    # Blink analysis
    blink_rate, blink_rate_anomaly, mean_duration_ms, duration_anomaly = (
        _compute_blink_metrics(eyelid_openness, fps)
    )

    # Saccade-fixation analysis
    saccade_ratio, saccade_fixation_anomaly = _compute_saccade_fixation_metrics(
        pupil_positions, inter_pupil_distance
    )

    # Composite anomaly score (weighted combination)
    anomaly_score = float(
        0.30 * blink_rate_anomaly
        + 0.25 * duration_anomaly
        + 0.45 * saccade_fixation_anomaly
    )
    anomaly_score = max(0.0, min(1.0, anomaly_score))

    logger.info(
        "eye_analysis_complete",
        anomaly_score=round(anomaly_score, 3),
        blink_rate=round(blink_rate, 1),
        blink_rate_anomaly=round(blink_rate_anomaly, 3),
        mean_blink_duration_ms=round(mean_duration_ms, 1),
        blink_duration_anomaly=round(duration_anomaly, 3),
        saccade_ratio=round(saccade_ratio, 3),
        saccade_fixation_anomaly=round(saccade_fixation_anomaly, 3),
        n_frames=n_frames,
    )

    return EyeAnalysisResult(
        anomaly_score=anomaly_score,
        blink_rate_per_min=blink_rate,
        blink_rate_anomaly=blink_rate_anomaly,
        mean_blink_duration_ms=mean_duration_ms,
        blink_duration_anomaly=duration_anomaly,
        saccade_ratio=saccade_ratio,
        saccade_fixation_anomaly=saccade_fixation_anomaly,
    )
