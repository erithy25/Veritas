"""L2 Biometric Analyzer -- comprehensive biometric deepfake detection.

Combines five independent analysis signals:
1. **rPPG** (dual CHROM+POS): Blood-flow pulse detection with cross-validation
2. **Micro-flicker + boundary artifacts**: Bounding-box jitter AND pixel-level
   gradient/color discontinuities at face boundaries
3. **Eye movement**: Blink dynamics, saccade patterns, left-right coordination,
   gaze-head coupling (VOR), and pupil dynamics
4. **Skin texture frequency**: DCT spectral fingerprints, GAN grid artifacts,
   patch consistency, temporal texture drift
5. **Facial symmetry**: Bilateral pixel/gradient/frequency symmetry and
   temporal stability

Receives pre-extracted facial landmarks and frame data from the Kafka
pipeline, runs all analyses, computes a composite biometric score,
and decides whether to escalate to L3.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import cv2
import numpy as np
from numpy.typing import NDArray
from prometheus_client import Counter, Histogram, Summary
import structlog

from src.eye_analysis import EyeAnalysisResult, analyze_eyes
from src.flicker import FlickerResult, analyze_flicker
from src.rppg import RppgResult, analyze_rppg
from src.symmetry_analysis import SymmetryAnalysisResult, analyze_symmetry
from src.texture_analysis import TextureAnalysisResult, analyze_texture

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------
L2_ANALYSIS_DURATION = Histogram(
    "veritas_l2_analysis_duration_seconds",
    "Time spent running full L2 biometric analysis",
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)
L2_FACES_ANALYZED = Summary(
    "veritas_l2_faces_analyzed",
    "Number of faces analyzed per scan",
)
L2_ESCALATION_TOTAL = Counter(
    "veritas_l2_escalation_total",
    "Number of scans escalated to L3",
)
L2_PASS_TOTAL = Counter(
    "veritas_l2_pass_total",
    "Number of scans that passed L2 without escalation",
)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
_ESCALATION_THRESHOLD: float = 0.35

# Sub-signal weights in the composite score (5 signals, sum = 1.0).
_WEIGHT_RPPG: float = 0.25
_WEIGHT_FLICKER: float = 0.20
_WEIGHT_EYE: float = 0.20
_WEIGHT_TEXTURE: float = 0.20
_WEIGHT_SYMMETRY: float = 0.15

# Minimum face region area (in pixels) to attempt analysis.
_MIN_FACE_AREA: int = 64 * 64


@dataclass(frozen=True, slots=True)
class FaceTrack:
    """Pre-extracted tracking data for a single face across frames."""

    face_id: int
    """Unique identifier for this face within the video."""

    frames: list[NDArray[np.uint8]]
    """BGR frames cropped/full containing the face."""

    bboxes: NDArray[np.float64]
    """Bounding boxes shape (N, 4): [x_min, y_min, x_max, y_max]."""

    skin_masks: list[NDArray[np.bool_]]
    """Per-frame boolean masks for facial skin ROI (in full-frame coords)."""

    pupil_positions: NDArray[np.float64]
    """Per-frame pupil center (x, y), shape (N, 2)."""

    eyelid_openness: NDArray[np.float64]
    """Per-frame eyelid openness ratio [0, 1], shape (N,)."""

    inter_pupil_distance: float
    """Mean inter-pupil distance in pixels."""

    left_pupil_positions: NDArray[np.float64] | None = None
    """Per-frame left pupil center (x, y), shape (N, 2), or None."""

    right_pupil_positions: NDArray[np.float64] | None = None
    """Per-frame right pupil center (x, y), shape (N, 2), or None."""

    head_yaw_estimates: NDArray[np.float64] | None = None
    """Per-frame head yaw angle in degrees, shape (N,), or None."""


@dataclass(frozen=True, slots=True)
class L2FaceResult:
    """L2 analysis result for a single face."""

    face_id: int
    rppg: RppgResult
    flicker: FlickerResult
    eye: EyeAnalysisResult
    texture: TextureAnalysisResult
    symmetry: SymmetryAnalysisResult
    composite_score: float


@dataclass(slots=True)
class L2AnalysisResult:
    """Aggregate L2 analysis result for an entire video."""

    face_results: list[L2FaceResult] = field(default_factory=list)
    composite_score: float = 0.0
    escalate_to_l3: bool = False
    faces_analyzed: int = 0
    duration_ms: int = 0

    # Per-signal scores (worst-case across all faces)
    micro_flicker_score: float = 0.0
    rppg_absence_score: float = 0.0
    rppg_signal_quality: float = 0.0
    eye_movement_anomaly_score: float = 0.0
    skin_texture_anomaly_score: float = 0.0
    facial_symmetry_score: float = 0.0

    # Reason codes for explainability
    reason_codes: list[dict[str, object]] = field(default_factory=list)


def _compute_face_composite(
    rppg: RppgResult,
    flicker: FlickerResult,
    eye: EyeAnalysisResult,
    texture: TextureAnalysisResult,
    symmetry: SymmetryAnalysisResult,
) -> float:
    """Compute weighted composite score for a single face."""
    score = (
        _WEIGHT_RPPG * rppg.absence_score
        + _WEIGHT_FLICKER * flicker.flicker_score
        + _WEIGHT_EYE * eye.anomaly_score
        + _WEIGHT_TEXTURE * texture.anomaly_score
        + _WEIGHT_SYMMETRY * symmetry.anomaly_score
    )
    return float(max(0.0, min(1.0, score)))


def _generate_reason_codes(
    result: L2AnalysisResult,
) -> list[dict[str, object]]:
    """Generate XAI reason codes based on detection thresholds."""
    codes: list[dict[str, object]] = []

    if result.rppg_absence_score > 0.6:
        codes.append({
            "code": "BIO_RPPG_ABSENT",
            "category": "L2_BIOMETRIC",
            "explanation": (
                "No plausible blood-flow signal detected via dual CHROM+POS "
                "analysis. Genuine faces exhibit periodic color changes from "
                "heartbeat that are consistent across extraction methods."
            ),
            "confidence": result.rppg_absence_score,
        })

    if result.micro_flicker_score > 0.5:
        codes.append({
            "code": "BIO_BOUNDARY_FLICKER",
            "category": "L2_BIOMETRIC",
            "explanation": (
                "Boundary artifacts detected: high-frequency spatial instability "
                "and/or gradient discontinuities at face boundaries suggesting "
                "frame-level synthesis or blending artifacts."
            ),
            "confidence": result.micro_flicker_score,
        })

    if result.eye_movement_anomaly_score > 0.5:
        codes.append({
            "code": "BIO_EYE_ANOMALY",
            "category": "L2_BIOMETRIC",
            "explanation": (
                "Eye movement patterns deviate from natural behavior: anomalous "
                "saccade-fixation dynamics, blink patterns, left-right "
                "coordination, gaze-head coupling, or pupil dynamics."
            ),
            "confidence": result.eye_movement_anomaly_score,
        })

    if result.skin_texture_anomaly_score > 0.5:
        codes.append({
            "code": "BIO_TEXTURE_ANOMALY",
            "category": "L2_BIOMETRIC",
            "explanation": (
                "Skin texture frequency analysis detected anomalies: spectral "
                "slope deviates from natural 1/f distribution, GAN grid "
                "artifacts, cross-patch inconsistency, or temporal texture drift."
            ),
            "confidence": result.skin_texture_anomaly_score,
        })

    if result.facial_symmetry_score > 0.5:
        codes.append({
            "code": "BIO_SYMMETRY_ANOMALY",
            "category": "L2_BIOMETRIC",
            "explanation": (
                "Facial symmetry pattern is unnatural: bilateral symmetry "
                "deviates from normal human asymmetry range at pixel, "
                "gradient, or frequency level."
            ),
            "confidence": result.facial_symmetry_score,
        })

    return codes


def analyze_video(
    face_tracks: list[FaceTrack],
    fps: float,
) -> L2AnalysisResult:
    """Run full L2 biometric analysis on all tracked faces in a video.

    Parameters
    ----------
    face_tracks:
        Pre-extracted face tracking data from the ingest pipeline.
    fps:
        Video frame rate.

    Returns
    -------
    L2AnalysisResult with composite scores and escalation decision.
    """
    start_time = time.monotonic()
    result = L2AnalysisResult()

    if not face_tracks:
        logger.info("l2_no_faces", msg="No face tracks provided, skipping L2")
        result.duration_ms = int((time.monotonic() - start_time) * 1000)
        return result

    for track in face_tracks:
        # Skip very small faces
        face_areas = (
            (track.bboxes[:, 2] - track.bboxes[:, 0])
            * (track.bboxes[:, 3] - track.bboxes[:, 1])
        )
        mean_area = float(face_areas.mean())
        if mean_area < _MIN_FACE_AREA:
            logger.debug(
                "l2_face_too_small",
                face_id=track.face_id,
                mean_area=round(mean_area, 0),
            )
            continue

        # Run all five sub-analyses
        rppg_result = analyze_rppg(track.frames, track.skin_masks, fps)

        flicker_result = analyze_flicker(
            track.bboxes, fps, frames=track.frames,
        )

        eye_result = analyze_eyes(
            track.pupil_positions,
            track.eyelid_openness,
            track.inter_pupil_distance,
            fps,
            left_pupil_positions=track.left_pupil_positions,
            right_pupil_positions=track.right_pupil_positions,
            head_yaw_estimates=track.head_yaw_estimates,
        )

        texture_result = analyze_texture(track.frames, track.skin_masks)

        symmetry_result = analyze_symmetry(track.frames, track.bboxes)

        composite = _compute_face_composite(
            rppg_result, flicker_result, eye_result,
            texture_result, symmetry_result,
        )

        face_result = L2FaceResult(
            face_id=track.face_id,
            rppg=rppg_result,
            flicker=flicker_result,
            eye=eye_result,
            texture=texture_result,
            symmetry=symmetry_result,
            composite_score=composite,
        )
        result.face_results.append(face_result)

        logger.info(
            "l2_face_scored",
            face_id=track.face_id,
            composite=round(composite, 3),
            rppg_absence=round(rppg_result.absence_score, 3),
            flicker=round(flicker_result.flicker_score, 3),
            eye_anomaly=round(eye_result.anomaly_score, 3),
            texture_anomaly=round(texture_result.anomaly_score, 3),
            symmetry_anomaly=round(symmetry_result.anomaly_score, 3),
        )

    result.faces_analyzed = len(result.face_results)
    L2_FACES_ANALYZED.observe(result.faces_analyzed)

    if result.face_results:
        # Take worst-case (highest) scores across all faces
        result.micro_flicker_score = max(
            fr.flicker.flicker_score for fr in result.face_results
        )
        result.rppg_absence_score = max(
            fr.rppg.absence_score for fr in result.face_results
        )
        result.rppg_signal_quality = min(
            fr.rppg.signal_quality for fr in result.face_results
        )
        result.eye_movement_anomaly_score = max(
            fr.eye.anomaly_score for fr in result.face_results
        )
        result.skin_texture_anomaly_score = max(
            fr.texture.anomaly_score for fr in result.face_results
        )
        result.facial_symmetry_score = max(
            fr.symmetry.anomaly_score for fr in result.face_results
        )
        result.composite_score = max(
            fr.composite_score for fr in result.face_results
        )

    # Escalation decision
    result.escalate_to_l3 = result.composite_score >= _ESCALATION_THRESHOLD

    # Generate reason codes
    result.reason_codes = _generate_reason_codes(result)

    elapsed = time.monotonic() - start_time
    result.duration_ms = int(elapsed * 1000)

    L2_ANALYSIS_DURATION.observe(elapsed)
    if result.escalate_to_l3:
        L2_ESCALATION_TOTAL.inc()
    else:
        L2_PASS_TOTAL.inc()

    logger.info(
        "l2_analysis_complete",
        composite_score=round(result.composite_score, 3),
        escalate_to_l3=result.escalate_to_l3,
        faces_analyzed=result.faces_analyzed,
        duration_ms=result.duration_ms,
        n_reason_codes=len(result.reason_codes),
    )

    return result
