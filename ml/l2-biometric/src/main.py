"""Veritas L2 Biometric - Kafka consumer for biometric analysis pipeline.

Consumes from veritas.l2.queue, runs rPPG / micro-flicker / eye-movement
analysis, and produces results to veritas.l2.results (or escalates to
veritas.l3.queue).
"""

import json
import os
import signal
import sys
import time
from typing import Any

import numpy as np
import structlog
from kafka import KafkaConsumer, KafkaProducer
from prometheus_client import Counter, Histogram, start_http_server

from .analyzer import FaceTrack, L2AnalysisResult, analyze_video

logger = structlog.get_logger()

# Prometheus metrics
L2_SCAN_DURATION = Histogram(
    "veritas_l2_scan_duration_seconds",
    "Total L2 scan duration",
    buckets=[0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
)
L2_MESSAGES_PROCESSED = Counter(
    "veritas_l2_messages_processed_total",
    "Total L2 messages processed",
    ["status"],
)


class L2BiometricService:
    """L2 Biometric analysis service."""

    def __init__(
        self,
        kafka_brokers: str = "localhost:9092",
    ) -> None:
        self.consumer = KafkaConsumer(
            "veritas.l2.queue",
            bootstrap_servers=kafka_brokers,
            group_id="veritas-l2-biometric",
            value_deserializer=lambda m: json.loads(m.decode()),
            auto_offset_reset="earliest",
            enable_auto_commit=False,
        )
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_brokers,
            value_serializer=lambda v: json.dumps(v).encode(),
            compression_type="lz4",
        )
        self.running = True

        logger.info("L2 Biometric service initialized")

    def run(self) -> None:
        """Main processing loop."""
        logger.info("Starting L2 processing loop")

        for message in self.consumer:
            if not self.running:
                break

            try:
                self._process_message(message.value)
                self.consumer.commit()
                L2_MESSAGES_PROCESSED.labels(status="success").inc()
            except Exception:
                logger.exception(
                    "Failed to process L2 message",
                    scan_id=message.value.get("scan_id", "unknown"),
                )
                L2_MESSAGES_PROCESSED.labels(status="error").inc()

    def _process_message(self, envelope: dict[str, Any]) -> None:
        """Process a single L2 analysis request."""
        scan_id = envelope.get("scan_id", "unknown")
        tenant_id = envelope.get("tenant_id", "unknown")
        payload = envelope.get("payload", {})

        logger.info("Processing L2 analysis", scan_id=scan_id)
        start_time = time.monotonic()

        # Extract face track data from the payload.
        # In production, face_tracks contain actual frame data from the ingest
        # pipeline.  For the scaffold we build placeholder FaceTrack objects so
        # the analysis pipeline can execute.
        face_tracks = self._extract_face_tracks(payload)
        fps = float(payload.get("fps", 30.0))

        # Run the L2 biometric analysis
        result: L2AnalysisResult = analyze_video(face_tracks, fps)

        total_duration = time.monotonic() - start_time
        L2_SCAN_DURATION.observe(total_duration)

        # Build result envelope
        l2_result = {
            "message_id": envelope.get("message_id"),
            "timestamp": time.time(),
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "payload": {
                "micro_flicker_score": result.micro_flicker_score,
                "rppg_absence_score": result.rppg_absence_score,
                "rppg_signal_quality": result.rppg_signal_quality,
                "eye_movement_anomaly_score": result.eye_movement_anomaly_score,
                "skin_texture_anomaly_score": result.skin_texture_anomaly_score,
                "facial_symmetry_score": result.facial_symmetry_score,
                "composite_score": result.composite_score,
                "escalate_to_l3": result.escalate_to_l3,
                "faces_analyzed": result.faces_analyzed,
                "reason_codes": result.reason_codes,
                "duration_ms": round(total_duration * 1000),
            },
        }

        # Route: either escalate to L3 or publish final L2 results
        if result.escalate_to_l3:
            self.producer.send("veritas.l3.queue", value=l2_result)
            logger.info(
                "L2 escalated to L3",
                scan_id=scan_id,
                composite_score=result.composite_score,
            )
        else:
            self.producer.send("veritas.l2.results", value=l2_result)

        logger.info(
            "L2 analysis complete",
            scan_id=scan_id,
            composite_score=round(result.composite_score, 4),
            escalated=result.escalate_to_l3,
            faces_analyzed=result.faces_analyzed,
            duration_ms=round(total_duration * 1000),
        )

    @staticmethod
    def _extract_face_tracks(payload: dict[str, Any]) -> list[FaceTrack]:
        """Extract FaceTrack objects from the ingest payload.

        In production this deserialises numpy arrays from the binary payload
        (face crops, landmarks, skin masks).  For local development it returns
        an empty list which causes the analyser to short-circuit gracefully.
        """
        raw_tracks = payload.get("face_tracks", [])
        if not raw_tracks:
            return []

        tracks: list[FaceTrack] = []
        for i, track_data in enumerate(raw_tracks):
            n_frames = track_data.get("n_frames", 0)
            if n_frames == 0:
                continue

            # Reconstruct numpy arrays from serialised payload
            try:
                frames = [
                    np.zeros((224, 224, 3), dtype=np.uint8)
                    for _ in range(n_frames)
                ]
                bboxes = np.array(
                    track_data.get("bboxes", [[0, 0, 224, 224]] * n_frames),
                    dtype=np.float64,
                )
                skin_masks = [
                    np.ones((224, 224), dtype=np.bool_)
                    for _ in range(n_frames)
                ]
                pupil_positions = np.array(
                    track_data.get(
                        "pupil_positions", [[112.0, 112.0]] * n_frames
                    ),
                    dtype=np.float64,
                )
                eyelid_openness = np.array(
                    track_data.get(
                        "eyelid_openness", [0.5] * n_frames
                    ),
                    dtype=np.float64,
                )

                tracks.append(
                    FaceTrack(
                        face_id=i,
                        frames=frames,
                        bboxes=bboxes,
                        skin_masks=skin_masks,
                        pupil_positions=pupil_positions,
                        eyelid_openness=eyelid_openness,
                        inter_pupil_distance=float(
                            track_data.get("inter_pupil_distance", 60.0)
                        ),
                    )
                )
            except (ValueError, KeyError):
                logger.warning(
                    "Skipping malformed face track",
                    face_index=i,
                )
        return tracks

    def shutdown(self) -> None:
        """Graceful shutdown."""
        self.running = False
        self.consumer.close()
        self.producer.close()
        logger.info("L2 Biometric service shut down")


def main() -> None:
    """Entry point."""
    start_http_server(9689)
    logger.info("Prometheus metrics server started on :9689")

    service = L2BiometricService(
        kafka_brokers=os.environ.get("VERITAS__KAFKA__BROKERS", "localhost:9092"),
    )

    def signal_handler(_sig: int, _frame: Any) -> None:
        logger.info("Shutdown signal received")
        service.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    service.run()


if __name__ == "__main__":
    main()
