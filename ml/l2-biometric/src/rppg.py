"""Remote photoplethysmography (rPPG) analysis for deepfake detection.

Extracts subtle color changes in facial skin regions caused by blood flow.
Real faces exhibit a periodic signal in the green channel corresponding to
heartbeat.  Deepfakes typically lack this physiological signal, producing a
high *absence score*.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray
from scipy.signal import butter, filtfilt
import structlog

logger = structlog.get_logger(__name__)

# Physiological frequency band: 42-240 BPM -> 0.7-4.0 Hz
_HR_FREQ_LOW: float = 0.7
_HR_FREQ_HIGH: float = 4.0
_BUTTER_ORDER: int = 4

# Minimum number of frames required for reliable rPPG estimation.
# At 30 fps this is ~5 seconds of video.
_MIN_FRAMES: int = 150

# Signal-to-noise ratio threshold below which we consider the rPPG signal
# absent (i.e., likely synthetic).
_SNR_ABSENCE_THRESHOLD: float = 3.0


@dataclass(frozen=True, slots=True)
class RppgResult:
    """Result of rPPG analysis on a single face track."""

    absence_score: float
    """0.0 = strong physiological signal (real), 1.0 = no signal (likely fake)."""

    signal_quality: float
    """Quality / SNR of the extracted rPPG signal (higher = better)."""

    estimated_bpm: float | None
    """Estimated heart rate in BPM, or None if signal was too weak."""


def _extract_skin_means(
    frames: list[NDArray[np.uint8]],
    roi_masks: list[NDArray[np.bool_]],
) -> NDArray[np.float64]:
    """Extract mean RGB values from facial skin ROI across frames.

    Parameters
    ----------
    frames:
        List of BGR frames (H, W, 3) as uint8.
    roi_masks:
        Per-frame boolean masks selecting facial skin pixels.

    Returns
    -------
    Signal array of shape (N, 3) with mean R, G, B per frame.
    """
    n = len(frames)
    means = np.zeros((n, 3), dtype=np.float64)

    for i, (frame, mask) in enumerate(zip(frames, roi_masks, strict=True)):
        skin_pixels = frame[mask]
        if skin_pixels.size == 0:
            continue
        # OpenCV uses BGR ordering; convert to RGB means.
        bgr_mean = skin_pixels.mean(axis=0)
        means[i, 0] = bgr_mean[2]  # R
        means[i, 1] = bgr_mean[1]  # G
        means[i, 2] = bgr_mean[0]  # B

    return means


def _bandpass_filter(
    signal: NDArray[np.float64],
    fps: float,
) -> NDArray[np.float64]:
    """Apply a Butterworth bandpass filter to isolate physiological frequencies.

    Parameters
    ----------
    signal:
        1-D time-series signal.
    fps:
        Sampling rate (frames per second).

    Returns
    -------
    Filtered signal.
    """
    nyquist = fps / 2.0
    low = _HR_FREQ_LOW / nyquist
    high = min(_HR_FREQ_HIGH / nyquist, 0.99)  # clamp to valid range

    b, a = butter(_BUTTER_ORDER, [low, high], btype="band")
    return filtfilt(b, a, signal).astype(np.float64)


def _compute_snr(
    filtered: NDArray[np.float64],
    fps: float,
) -> tuple[float, float | None]:
    """Compute signal-to-noise ratio and dominant frequency of the rPPG signal.

    Uses FFT to find the strongest frequency component in the physiological
    band and measures its power relative to the noise floor.

    Returns
    -------
    (snr, estimated_bpm)
        SNR in dB and estimated BPM (None if SNR is too low).
    """
    n = len(filtered)
    spectrum = np.abs(np.fft.rfft(filtered * np.hanning(n)))
    freqs = np.fft.rfftfreq(n, d=1.0 / fps)

    # Mask to physiological band
    band_mask = (freqs >= _HR_FREQ_LOW) & (freqs <= _HR_FREQ_HIGH)
    if not band_mask.any():
        return 0.0, None

    band_power = spectrum[band_mask]
    peak_idx = np.argmax(band_power)
    peak_power = band_power[peak_idx]

    # Noise = everything outside the peak +/- 1 bin
    noise_mask = np.ones(len(band_power), dtype=bool)
    noise_start = max(0, peak_idx - 1)
    noise_end = min(len(band_power), peak_idx + 2)
    noise_mask[noise_start:noise_end] = False

    if not noise_mask.any() or peak_power == 0:
        return 0.0, None

    noise_power = band_power[noise_mask].mean()
    if noise_power <= 0:
        snr = float(peak_power)  # effectively infinite, cap later
    else:
        snr = float(peak_power / noise_power)

    # Convert peak frequency to BPM
    peak_freq = freqs[band_mask][peak_idx]
    estimated_bpm = float(peak_freq * 60.0)

    return snr, estimated_bpm


def _snr_to_absence_score(snr: float) -> float:
    """Map SNR to an absence score in [0, 1].

    High SNR (strong heartbeat signal) -> low absence score (likely real).
    Low SNR (no heartbeat signal) -> high absence score (likely fake).
    """
    if snr <= 0:
        return 1.0
    if snr >= _SNR_ABSENCE_THRESHOLD * 2:
        return 0.0
    # Linear interpolation between thresholds
    return float(max(0.0, min(1.0, 1.0 - snr / (_SNR_ABSENCE_THRESHOLD * 2))))


def analyze_rppg(
    frames: list[NDArray[np.uint8]],
    roi_masks: list[NDArray[np.bool_]],
    fps: float,
) -> RppgResult:
    """Run rPPG analysis on a sequence of frames with facial skin ROIs.

    Parameters
    ----------
    frames:
        List of BGR frames (H, W, 3).
    roi_masks:
        Per-frame boolean masks indicating facial skin pixels.
    fps:
        Video frame rate.

    Returns
    -------
    RppgResult with absence score, signal quality, and estimated BPM.
    """
    n_frames = len(frames)

    if n_frames < _MIN_FRAMES:
        logger.warning(
            "rppg_insufficient_frames",
            n_frames=n_frames,
            min_required=_MIN_FRAMES,
        )
        return RppgResult(
            absence_score=0.5,
            signal_quality=0.0,
            estimated_bpm=None,
        )

    # Step 1: Extract mean skin color per frame
    rgb_means = _extract_skin_means(frames, roi_masks)

    # Step 2: Use the green channel (strongest rPPG signal)
    green_signal = rgb_means[:, 1]

    # Normalize to zero-mean, unit-variance
    std = green_signal.std()
    if std < 1e-8:
        logger.warning("rppg_flat_signal", std=float(std))
        return RppgResult(absence_score=1.0, signal_quality=0.0, estimated_bpm=None)

    green_signal = (green_signal - green_signal.mean()) / std

    # Step 3: Bandpass filter to isolate heartbeat frequencies
    filtered = _bandpass_filter(green_signal, fps)

    # Step 4: Compute SNR and estimate BPM
    snr, estimated_bpm = _compute_snr(filtered, fps)

    absence_score = _snr_to_absence_score(snr)
    signal_quality = float(min(snr / _SNR_ABSENCE_THRESHOLD, 1.0))

    logger.info(
        "rppg_analysis_complete",
        snr=round(snr, 3),
        absence_score=round(absence_score, 3),
        signal_quality=round(signal_quality, 3),
        estimated_bpm=round(estimated_bpm, 1) if estimated_bpm else None,
        n_frames=n_frames,
    )

    return RppgResult(
        absence_score=absence_score,
        signal_quality=signal_quality,
        estimated_bpm=estimated_bpm,
    )
