"""Remote photoplethysmography (rPPG) analysis for deepfake detection.

Extracts subtle color changes in facial skin regions caused by blood flow.
Real faces exhibit a periodic signal corresponding to heartbeat.  Deepfakes
typically lack this physiological signal, producing a high *absence score*.

This implementation uses the CHROM (Chrominance-based) method which combines
R, G, B channels via a linear projection that suppresses specular reflections
and motion artifacts while preserving the blood-volume pulse signal.
Additionally, it cross-validates using an independent POS (Plane Orthogonal
to Skin) projection.  The dual-method approach dramatically improves
robustness compared to single-channel (green-only) extraction.
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

# Window size for CHROM/POS overlap-add (in frames).  60 frames at 30fps
# gives 2-second windows which capture ~1-3 heartbeat cycles.
_CHROM_WINDOW: int = 60


@dataclass(frozen=True, slots=True)
class RppgResult:
    """Result of rPPG analysis on a single face track."""

    absence_score: float
    """0.0 = strong physiological signal (real), 1.0 = no signal (likely fake)."""

    signal_quality: float
    """Quality / SNR of the extracted rPPG signal (higher = better)."""

    estimated_bpm: float | None
    """Estimated heart rate in BPM, or None if signal was too weak."""

    chrom_snr: float
    """SNR from the CHROM method specifically."""

    pos_snr: float
    """SNR from the POS method specifically."""

    cross_method_agreement: float
    """Agreement between CHROM and POS BPM estimates [0, 1]. Low agreement
    on a seemingly strong signal can indicate a fake with injected pulse."""


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
    """Apply a Butterworth bandpass filter to isolate physiological frequencies."""
    nyquist = fps / 2.0
    low = _HR_FREQ_LOW / nyquist
    high = min(_HR_FREQ_HIGH / nyquist, 0.99)

    b, a = butter(_BUTTER_ORDER, [low, high], btype="band")
    return filtfilt(b, a, signal).astype(np.float64)


def _chrom_extract(
    rgb_means: NDArray[np.float64],
) -> NDArray[np.float64]:
    """Extract rPPG signal using the CHROM (Chrominance-based) method.

    CHROM projects the normalized RGB signal into a chrominance space
    that separates the pulse component from specular and diffuse
    reflection noise.

    Reference: De Haan & Jeanne (2013), "Robust pulse rate from
    chrominance-based rPPG".

    Parameters
    ----------
    rgb_means:
        Shape (N, 3) with columns [R, G, B].

    Returns
    -------
    1-D pulse signal of length N.
    """
    n = len(rgb_means)
    pulse = np.zeros(n, dtype=np.float64)
    window = _CHROM_WINDOW

    for start in range(0, n - window + 1, window // 2):
        end = start + window
        segment = rgb_means[start:end].copy()

        # Temporal normalization: divide each channel by its mean
        col_means = segment.mean(axis=0)
        col_means[col_means < 1e-6] = 1.0
        normalized = segment / col_means

        # CHROM projection:
        # Xs = 3*R - 2*G
        # Ys = 1.5*R + G - 1.5*B
        xs = 3.0 * normalized[:, 0] - 2.0 * normalized[:, 1]
        ys = 1.5 * normalized[:, 0] + normalized[:, 1] - 1.5 * normalized[:, 2]

        # Adaptive combination: alpha = std(Xs) / std(Ys)
        std_xs = xs.std()
        std_ys = ys.std()

        if std_ys > 1e-8:
            alpha = std_xs / std_ys
        else:
            alpha = 1.0

        # Pulse for this window
        window_pulse = xs - alpha * ys

        # Overlap-add with Hanning window
        hann = np.hanning(window)
        pulse[start:end] += window_pulse * hann

    return pulse


def _pos_extract(
    rgb_means: NDArray[np.float64],
) -> NDArray[np.float64]:
    """Extract rPPG signal using the POS (Plane Orthogonal to Skin) method.

    POS uses a projection that is orthogonal to the skin-tone vector in
    normalized color space, providing an independent estimate from CHROM.

    Reference: Wang et al. (2017), "Algorithmic principles of remote PPG".

    Parameters
    ----------
    rgb_means:
        Shape (N, 3) with columns [R, G, B].

    Returns
    -------
    1-D pulse signal of length N.
    """
    n = len(rgb_means)
    pulse = np.zeros(n, dtype=np.float64)
    window = _CHROM_WINDOW

    for start in range(0, n - window + 1, window // 2):
        end = start + window
        segment = rgb_means[start:end].copy()

        # Temporal normalization
        col_means = segment.mean(axis=0)
        col_means[col_means < 1e-6] = 1.0
        normalized = segment / col_means

        # POS projection (plane orthogonal to skin tone)
        # P = [0, 1, -1; -2, 1, 1] (projection matrix)
        s1 = normalized[:, 1] - normalized[:, 2]       # G - B
        s2 = -2.0 * normalized[:, 0] + normalized[:, 1] + normalized[:, 2]  # -2R + G + B

        # Adaptive combination
        std_s1 = s1.std()
        std_s2 = s2.std()

        if std_s2 > 1e-8:
            alpha = std_s1 / std_s2
        else:
            alpha = 1.0

        window_pulse = s1 + alpha * s2

        # Overlap-add
        hann = np.hanning(window)
        pulse[start:end] += window_pulse * hann

    return pulse


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
        SNR ratio and estimated BPM (None if SNR is too low).
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

    # Noise = everything outside the peak +/- 2 bins (wider exclusion)
    noise_mask = np.ones(len(band_power), dtype=bool)
    noise_start = max(0, peak_idx - 2)
    noise_end = min(len(band_power), peak_idx + 3)
    noise_mask[noise_start:noise_end] = False

    if not noise_mask.any() or peak_power == 0:
        return 0.0, None

    noise_power = band_power[noise_mask].mean()
    if noise_power <= 0:
        snr = float(peak_power)
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
    return float(max(0.0, min(1.0, 1.0 - snr / (_SNR_ABSENCE_THRESHOLD * 2))))


def _compute_cross_method_agreement(
    chrom_bpm: float | None,
    pos_bpm: float | None,
) -> float:
    """Compute agreement between CHROM and POS BPM estimates.

    If both methods detect a plausible BPM and they agree within 5 BPM,
    the signal is very likely genuine.  If they disagree significantly,
    it could indicate an injected/artificial pulse signal that only
    fools one extraction method.

    Returns agreement score in [0, 1] where 1 = perfect agreement.
    """
    if chrom_bpm is None or pos_bpm is None:
        return 0.0

    diff = abs(chrom_bpm - pos_bpm)

    if diff < 3.0:
        return 1.0
    elif diff < 8.0:
        return float(1.0 - (diff - 3.0) / 5.0)
    elif diff < 15.0:
        return float(0.3 * (1.0 - (diff - 8.0) / 7.0))
    else:
        return 0.0


def analyze_rppg(
    frames: list[NDArray[np.uint8]],
    roi_masks: list[NDArray[np.bool_]],
    fps: float,
) -> RppgResult:
    """Run dual-method rPPG analysis on a sequence of frames.

    Uses both CHROM and POS methods for robust pulse extraction with
    cross-validation.

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
    RppgResult with absence score, signal quality, estimated BPM,
    per-method SNR, and cross-method agreement.
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
            chrom_snr=0.0,
            pos_snr=0.0,
            cross_method_agreement=0.0,
        )

    # Step 1: Extract mean skin color per frame
    rgb_means = _extract_skin_means(frames, roi_masks)

    # Check for flat signal (all-black frames, broken pipeline)
    channel_stds = rgb_means.std(axis=0)
    if channel_stds.max() < 1e-6:
        logger.warning("rppg_flat_signal", stds=channel_stds.tolist())
        return RppgResult(
            absence_score=1.0,
            signal_quality=0.0,
            estimated_bpm=None,
            chrom_snr=0.0,
            pos_snr=0.0,
            cross_method_agreement=0.0,
        )

    # Step 2: Extract pulse using CHROM method
    chrom_pulse = _chrom_extract(rgb_means)
    chrom_std = chrom_pulse.std()
    if chrom_std > 1e-8:
        chrom_pulse = (chrom_pulse - chrom_pulse.mean()) / chrom_std
        chrom_filtered = _bandpass_filter(chrom_pulse, fps)
        chrom_snr, chrom_bpm = _compute_snr(chrom_filtered, fps)
    else:
        chrom_snr, chrom_bpm = 0.0, None

    # Step 3: Extract pulse using POS method
    pos_pulse = _pos_extract(rgb_means)
    pos_std = pos_pulse.std()
    if pos_std > 1e-8:
        pos_pulse = (pos_pulse - pos_pulse.mean()) / pos_std
        pos_filtered = _bandpass_filter(pos_pulse, fps)
        pos_snr, pos_bpm = _compute_snr(pos_filtered, fps)
    else:
        pos_snr, pos_bpm = 0.0, None

    # Step 4: Combine results
    # Take the better SNR as the primary signal quality indicator
    best_snr = max(chrom_snr, pos_snr)
    best_bpm = chrom_bpm if chrom_snr >= pos_snr else pos_bpm

    # Cross-method agreement
    agreement = _compute_cross_method_agreement(chrom_bpm, pos_bpm)

    # Absence score: primarily from best SNR, but penalize low agreement
    base_absence = _snr_to_absence_score(best_snr)

    # If we have a strong signal but methods disagree on BPM, the signal
    # might be artificial (injected periodic noise).  Increase absence score.
    if best_snr > _SNR_ABSENCE_THRESHOLD and agreement < 0.3:
        # Strong signal but methods disagree => suspicious
        absence_score = float(min(1.0, base_absence + 0.3 * (1.0 - agreement)))
    else:
        absence_score = base_absence

    signal_quality = float(min(best_snr / _SNR_ABSENCE_THRESHOLD, 1.0))

    logger.info(
        "rppg_analysis_complete",
        chrom_snr=round(chrom_snr, 3),
        pos_snr=round(pos_snr, 3),
        best_snr=round(best_snr, 3),
        absence_score=round(absence_score, 3),
        signal_quality=round(signal_quality, 3),
        chrom_bpm=round(chrom_bpm, 1) if chrom_bpm else None,
        pos_bpm=round(pos_bpm, 1) if pos_bpm else None,
        cross_agreement=round(agreement, 3),
        n_frames=n_frames,
    )

    return RppgResult(
        absence_score=absence_score,
        signal_quality=signal_quality,
        estimated_bpm=best_bpm,
        chrom_snr=chrom_snr,
        pos_snr=pos_snr,
        cross_method_agreement=agreement,
    )
