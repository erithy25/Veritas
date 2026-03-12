"""Veritas L3 DeepNet - Neural network inference orchestrator.

Consumes from veritas.l3.queue, runs ensemble model inference via
NVIDIA Triton Inference Server, and produces results to veritas.l3.results.
"""

import json
import signal
import sys
import time
from typing import Any

import numpy as np
import structlog
from kafka import KafkaConsumer, KafkaProducer
from prometheus_client import Counter, Histogram, start_http_server

from .ensemble import EnsembleAggregator
from .triton_client import TritonModelClient

logger = structlog.get_logger()

# Prometheus metrics
INFERENCE_DURATION = Histogram(
    "veritas_l3_inference_duration_seconds",
    "L3 per-model inference latency",
    ["model"],
    buckets=[0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0],
)
INFERENCE_TOTAL = Counter(
    "veritas_l3_inference_total",
    "Total L3 inferences",
    ["model", "status"],
)
L3_SCAN_DURATION = Histogram(
    "veritas_l3_scan_duration_seconds",
    "Total L3 scan duration",
    buckets=[0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0],
)


class L3DeepNetService:
    """L3 Deep Neural Network analysis service."""

    def __init__(
        self,
        kafka_brokers: str = "localhost:9092",
        triton_url: str = "localhost:8001",
    ) -> None:
        self.consumer = KafkaConsumer(
            "veritas.l3.queue",
            bootstrap_servers=kafka_brokers,
            group_id="veritas-l3-deepnet",
            value_deserializer=lambda m: json.loads(m.decode()),
            auto_offset_reset="earliest",
            enable_auto_commit=False,
        )
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_brokers,
            value_serializer=lambda v: json.dumps(v).encode(),
            compression_type="lz4",
        )

        # Initialize Triton client for each model
        self.triton = TritonModelClient(triton_url)
        self.ensemble = EnsembleAggregator()
        self.running = True

        logger.info("L3 DeepNet service initialized", triton_url=triton_url)

    def run(self) -> None:
        """Main processing loop."""
        logger.info("Starting L3 processing loop")

        for message in self.consumer:
            if not self.running:
                break

            try:
                self._process_message(message.value)
                self.consumer.commit()
            except Exception:
                logger.exception(
                    "Failed to process L3 message",
                    scan_id=message.value.get("scan_id", "unknown"),
                )

    def _process_message(self, envelope: dict[str, Any]) -> None:
        """Process a single L3 analysis request."""
        scan_id = envelope.get("scan_id", "unknown")
        tenant_id = envelope.get("tenant_id", "unknown")
        payload = envelope.get("payload", {})

        logger.info("Processing L3 analysis", scan_id=scan_id)
        start_time = time.monotonic()

        # Run each model in the ensemble
        model_scores: dict[str, float] = {}

        for model_name in [
            "vit-l16-general",
            "efficientnet-b7-gan",
            "tcn-temporal",
            "diffusion-artifact-detector",
            "syncnet-lipsync",
        ]:
            model_start = time.monotonic()
            try:
                # In production, this sends real frame data to Triton
                # For scaffold, use placeholder inference
                score = self.triton.infer(model_name, payload)
                model_scores[model_name] = score

                duration = time.monotonic() - model_start
                INFERENCE_DURATION.labels(model=model_name).observe(duration)
                INFERENCE_TOTAL.labels(model=model_name, status="success").inc()

                logger.debug(
                    "Model inference complete",
                    model=model_name,
                    score=score,
                    duration_ms=round(duration * 1000),
                )
            except Exception:
                logger.exception("Model inference failed", model=model_name)
                INFERENCE_TOTAL.labels(model=model_name, status="error").inc()
                model_scores[model_name] = 0.0

        # Ensemble aggregation
        ensemble_result = self.ensemble.aggregate(model_scores)

        total_duration = time.monotonic() - start_time
        L3_SCAN_DURATION.observe(total_duration)

        # Produce result
        result = {
            "message_id": envelope.get("message_id"),
            "timestamp": time.time(),
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "payload": {
                "vit_general_score": model_scores.get("vit-l16-general", 0.0),
                "efficientnet_gan_score": model_scores.get("efficientnet-b7-gan", 0.0),
                "tcn_temporal_score": model_scores.get("tcn-temporal", 0.0),
                "diffusion_artifact_score": model_scores.get("diffusion-artifact-detector", 0.0),
                "lipsync_mismatch_score": model_scores.get("syncnet-lipsync", 0.0),
                "ensemble_score": ensemble_result["ensemble_score"],
                "model_agreement_ratio": ensemble_result["agreement_ratio"],
                "duration_ms": round(total_duration * 1000),
            },
        }

        self.producer.send("veritas.l3.results", value=result)

        logger.info(
            "L3 analysis complete",
            scan_id=scan_id,
            ensemble_score=ensemble_result["ensemble_score"],
            agreement=ensemble_result["agreement_ratio"],
            duration_ms=round(total_duration * 1000),
        )

    def shutdown(self) -> None:
        """Graceful shutdown."""
        self.running = False
        self.consumer.close()
        self.producer.close()
        logger.info("L3 DeepNet service shut down")


def main() -> None:
    """Entry point."""
    # Start Prometheus metrics server
    start_http_server(9690)
    logger.info("Prometheus metrics server started on :9690")

    import os

    service = L3DeepNetService(
        kafka_brokers=os.environ.get("VERITAS__KAFKA__BROKERS", "localhost:9092"),
        triton_url=os.environ.get("VERITAS__TRITON__URL", "localhost:8001"),
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
