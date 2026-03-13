"""Eye movement analysis for deepfake detection.

Real human eyes exhibit characteristic patterns: saccades (rapid jumps
between fixation points), micro-saccades, smooth pursuit, and regular blink
cycles.  GAN/diffusion deepfakes often produce unrealistic eye behavior --
overly smooth gaze trajectories, unnatural blink timing, or missing saccadic
dynamics.

Additionally, this module detects:

- **Left-right eye coordination anomalies**: In real faces, both eyes move
  in tandem (vergence).  Deepfakes sometimes generate independent eye
  movements or perfectly synchronized movements without natural vergence.

- **Gaze-head pose inconsistency**: When a person turns their head, the
  eyes partially compensate via the vestibulo-ocular reflex (VOR).
  Deepfakes often fail to reproduce this coupling correctly.

- **Pupil dynamics**: Real pupils respond to light changes with
  characteristic latency and oscillation patterns (hippus).  Deepfakes
  often have static or randomly-varying pupil sizes.
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

# Left-right eye correlation threshold
# Real eyes have correlation > 0.85 for horizontal movement
_LR_CORRELATION_MIN: float = 0.80

# Gaze-head coupling: expected VOR gain (ratio of compensatory eye
# movement to head movement). Normal range: 0.8-1.2
_VOR_GAIN_LOW: float = 0.6
_VOR_GAIN_HIGH: float = 1.4


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

    lr_coordination_anomaly: float
    """Left-right eye coordination anomaly [0, 1]."""

    gaze_head_coupling_anomaly: float
    """Gaze-head pose coupling (VOR) anomaly [0, 1]."""

    pupil_dynamics_anomaly: float
    """Pupil size dynamics anomaly [0, 1]."""


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


def _compute_lr_coordination(
    left_pupil_positions: NDArray[np.float64] | None,
    right_pupil_positions: NDArray[np.float64] | None,
) -> float:
    """Analyze left-right eye movement coordination.

    In natural gaze, both eyes move together (conjugate movements) except
    during vergence (focusing at different depths).  Deepfakes often
    generate each eye independently, leading to either:
    - Perfect correlation (no natural micro-differences)
    - Low correlation (independent random movements)

    Parameters
    ----------
    left_pupil_positions:
        Per-frame left pupil positions, shape (N, 2), or None.
    right_pupil_positions:
        Per-frame right pupil positions, shape (N, 2), or None.

    Returns anomaly score in [0, 1].
    """
    if left_pupil_positions is None or right_pupil_positions is None:
        return 0.0

    n = min(len(left_pupil_positions), len(right_pupil_positions))
    if n < _MIN_FRAMES:
        return 0.0

    left = left_pupil_positions[:n]
    right = right_pupil_positions[:n]

    # Compute velocity vectors for each eye
    left_vel = np.diff(left, axis=0)
    right_vel = np.diff(right, axis=0)

    # Horizontal correlation (should be high ~0.9+ for conjugate movement)
    left_h = left_vel[:, 0]
    right_h = right_vel[:, 0]

    if left_h.std() < 1e-8 or right_h.std() < 1e-8:
        # Both eyes static -- could be natural or could be fake
        return 0.3

    h_corr = float(np.corrcoef(left_h, right_h)[0, 1])

    # Vertical correlation (should also be high)
    left_v = left_vel[:, 1]
    right_v = right_vel[:, 1]

    if left_v.std() < 1e-8 or right_v.std() < 1e-8:
        v_corr = 1.0  # If no vertical movement, assume OK
    else:
        v_corr = float(np.corrcoef(left_v, right_v)[0, 1])

    avg_corr = (h_corr + v_corr) / 2.0

    # Score: too low correlation = independent eye movements (fake)
    # Perfect correlation (>0.99) with no micro-differences is also suspicious
    if avg_corr < _LR_CORRELATION_MIN:
        # Low correlation: eyes moving independently
        anomaly = float(min(1.0, (_LR_CORRELATION_MIN - avg_corr) / 0.3))
    elif avg_corr > 0.995:
        # Suspiciously perfect correlation (no natural micro-vergence)
        anomaly = 0.4
    else:
        anomaly = 0.0

    return anomaly


def _compute_gaze_head_coupling(
    pupil_positions: NDArray[np.float64],
    head_yaw_estimates: NDArray[np.float64] | None,
    inter_pupil_distance: float,
) -> float:
    """Analyze vestibulo-ocular reflex (VOR) coupling between gaze and head pose.

    When the head turns, the eyes reflexively move in the opposite direction
    to stabilize gaze (VOR).  The gain is normally ~1.0.  Deepfakes often
    show gaze that moves WITH the head or doesn't compensate at all.

    Parameters
    ----------
    pupil_positions:
        Per-frame average pupil center, shape (N, 2).
    head_yaw_estimates:
        Per-frame head yaw angle estimates in degrees, shape (N,), or None.
        If None, we estimate head rotation from inter-pupil distance changes.
    inter_pupil_distance:
        Mean inter-pupil distance for normalization.

    Returns anomaly score in [0, 1].
    """
    n = len(pupil_positions)
    if n < _MIN_FRAMES:
        return 0.0

    if inter_pupil_distance < 1.0:
        return 0.0

    # Estimate head rotation from pupil position horizontal velocity
    # (crude proxy when explicit head pose isn't available)
    gaze_h = pupil_positions[:, 0]

    if head_yaw_estimates is not None and len(head_yaw_estimates) >= n:
        head_vel = np.diff(head_yaw_estimates[:n])
    else:
        # Use the derivative of mean horizontal position as head estimate
        # This is a rough proxy -- assume slow gaze drift is head movement
        from scipy.signal import butter, filtfilt

        nyq = 15.0  # assume 30fps, nyquist = 15
        # Low-pass filter: head movement is < 2 Hz
        low = min(2.0 / nyq, 0.99)
        b, a = butter(2, low, btype="low")

        gaze_smooth = filtfilt(b, a, gaze_h)
        head_vel = np.diff(gaze_smooth)

    gaze_vel = np.diff(gaze_h) / inter_pupil_distance

    if len(head_vel) == 0 or len(gaze_vel) == 0:
        return 0.0

    min_len = min(len(head_vel), len(gaze_vel))
    head_vel = head_vel[:min_len]
    gaze_vel = gaze_vel[:min_len]

    # Only analyze frames with significant head movement
    head_speed = np.abs(head_vel)
    moving_mask = head_speed > np.percentile(head_speed, 70)

    if moving_mask.sum() < 10:
        return 0.0

    head_moving = head_vel[moving_mask]
    gaze_moving = gaze_vel[moving_mask]

    # Correlation: should be negative (VOR: eyes oppose head)
    if head_moving.std() < 1e-8 or gaze_moving.std() < 1e-8:
        return 0.3

    correlation = float(np.corrcoef(head_moving, gaze_moving)[0, 1])

    # VOR: expect negative correlation (counter-rotation)
    # Real: correlation ~ -0.5 to -0.9
    # Deepfake: often positive (gaze follows head) or zero
    if correlation > 0.0:
        # Positive correlation: gaze moves WITH head (no VOR)
        anomaly = float(min(1.0, 0.5 + correlation * 0.5))
    elif correlation > -0.3:
        # Weak negative correlation: poor VOR
        anomaly = float(0.3 * (1.0 - abs(correlation) / 0.3))
    else:
        # Strong negative correlation: healthy VOR
        anomaly = 0.0

    return anomaly


def _compute_pupil_dynamics_anomaly(
    eyelid_openness: NDArray[np.float64],
    fps: float,
) -> float:
    """Analyze pupil dynamics for naturalness.

    Real pupils exhibit:
    - Hippus: small rhythmic oscillations at ~0.5-1.5 Hz
    - Consensual response: both pupils react to light simultaneously
    - Dilation response latency: ~200-500ms after stimulus

    Deepfakes often produce:
    - Static pupil size (no hippus)
    - Random pupil size changes
    - Unnatural high-frequency pupil oscillations

    We use eyelid openness as a proxy since it correlates with pupil
    visibility and ambient light reaching the retina.

    Returns anomaly score in [0, 1].
    """
    n = len(eyelid_openness)
    if n < _MIN_FRAMES:
        return 0.0

    # Analyze the variation in eyelid openness during non-blink periods
    # (as a proxy for pupil dynamics visible through the eye opening)
    is_open = eyelid_openness > 0.5
    open_values = eyelid_openness[is_open]

    if len(open_values) < 30:
        return 0.0

    # Check for natural micro-variations (hippus-like)
    std_open = float(open_values.std())

    # Real eyes: std ~0.01-0.05 during fixation
    # Fake eyes: either perfectly static (std < 0.005) or noisy (std > 0.08)
    if std_open < 0.005:
        # Suspiciously static
        static_anomaly = float(min(1.0, (0.005 - std_open) / 0.005))
    elif std_open > 0.08:
        # Suspiciously noisy
        static_anomaly = float(min(1.0, (std_open - 0.08) / 0.1))
    else:
        static_anomaly = 0.0

    # Check for temporal autocorrelation
    # Real hippus has smooth, periodic character (high autocorrelation at lag 1)
    if len(open_values) > 10:
        lag1_corr = float(np.corrcoef(open_values[:-1], open_values[1:])[0, 1])
        # Real: lag-1 autocorrelation ~0.8-0.95 (smooth variation)
        # Fake: often < 0.5 (random noise) or > 0.99 (perfectly smooth/static)
        if lag1_corr < 0.5:
            autocorr_anomaly = float(min(1.0, (0.5 - lag1_corr) / 0.5))
        elif lag1_corr > 0.99:
            autocorr_anomaly = 0.3  # Too smooth
        else:
            autocorr_anomaly = 0.0
    else:
        autocorr_anomaly = 0.0

    return float(max(0.0, min(1.0, 0.5 * static_anomaly + 0.5 * autocorr_anomaly)))


def analyze_eyes(
    pupil_positions: NDArray[np.float64],
    eyelid_openness: NDArray[np.float64],
    inter_pupil_distance: float,
    fps: float,
    left_pupil_positions: NDArray[np.float64] | None = None,
    right_pupil_positions: NDArray[np.float64] | None = None,
    head_yaw_estimates: NDArray[np.float64] | None = None,
) -> EyeAnalysisResult:
    """Run comprehensive eye movement analysis.

    Parameters
    ----------
    pupil_positions:
        Per-frame average pupil center (x, y) positions, shape (N, 2).
    eyelid_openness:
        Per-frame eyelid openness ratio [0, 1], shape (N,).
    inter_pupil_distance:
        Mean inter-pupil distance in pixels.
    fps:
        Video frame rate.
    left_pupil_positions:
        Optional per-frame left pupil positions, shape (N, 2).
    right_pupil_positions:
        Optional per-frame right pupil positions, shape (N, 2).
    head_yaw_estimates:
        Optional per-frame head yaw estimates in degrees, shape (N,).

    Returns
    -------
    EyeAnalysisResult with comprehensive anomaly scores.
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
            lr_coordination_anomaly=0.0,
            gaze_head_coupling_anomaly=0.0,
            pupil_dynamics_anomaly=0.0,
        )

    # Original analyses
    blink_rate, blink_rate_anomaly, mean_duration_ms, duration_anomaly = (
        _compute_blink_metrics(eyelid_openness, fps)
    )

    saccade_ratio, saccade_fixation_anomaly = _compute_saccade_fixation_metrics(
        pupil_positions, inter_pupil_distance
    )

    # New analyses
    lr_coordination_anomaly = _compute_lr_coordination(
        left_pupil_positions, right_pupil_positions
    )

    gaze_head_coupling_anomaly = _compute_gaze_head_coupling(
        pupil_positions, head_yaw_estimates, inter_pupil_distance
    )

    pupil_dynamics = _compute_pupil_dynamics_anomaly(eyelid_openness, fps)

    # Composite anomaly score with expanded weights
    anomaly_score = float(
        0.18 * blink_rate_anomaly
        + 0.14 * duration_anomaly
        + 0.25 * saccade_fixation_anomaly
        + 0.15 * lr_coordination_anomaly
        + 0.15 * gaze_head_coupling_anomaly
        + 0.13 * pupil_dynamics
    )
    anomaly_score = max(0.0, min(1.0, anomaly_score))

    logger.info(
        "eye_analysis_complete",
        anomaly_score=round(anomaly_score, 3),
        blink_rate=round(blink_rate, 1),
        blink_rate_anomaly=round(blink_rate_anomaly, 3),
        saccade_fixation_anomaly=round(saccade_fixation_anomaly, 3),
        lr_coordination=round(lr_coordination_anomaly, 3),
        gaze_head_coupling=round(gaze_head_coupling_anomaly, 3),
        pupil_dynamics=round(pupil_dynamics, 3),
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
        lr_coordination_anomaly=lr_coordination_anomaly,
        gaze_head_coupling_anomaly=gaze_head_coupling_anomaly,
        pupil_dynamics_anomaly=pupil_dynamics,
    )
