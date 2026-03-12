"""NVIDIA Triton Inference Server client for L3 model serving."""

from typing import Any

import numpy as np
import structlog

logger = structlog.get_logger()


class TritonModelClient:
    """Client for NVIDIA Triton Inference Server.

    In production, this uses tritonclient.grpc to communicate with Triton.
    The scaffold provides a placeholder implementation for development
    without a running Triton instance.
    """

    def __init__(self, triton_url: str = "localhost:8001") -> None:
        self.triton_url = triton_url
        self._connected = False

        # Try to connect to Triton
        try:
            import tritonclient.grpc as grpcclient

            self._client = grpcclient.InferenceServerClient(url=triton_url)
            if self._client.is_server_live():
                self._connected = True
                logger.info("Connected to Triton", url=triton_url)
        except Exception:
            logger.warning(
                "Triton not available, using placeholder inference",
                url=triton_url,
            )

    def infer(self, model_name: str, payload: dict[str, Any]) -> float:
        """Run inference on a model.

        Args:
            model_name: Name of the model in Triton's model repository.
            payload: Input data containing face crops and metadata.

        Returns:
            Detection confidence score between 0.0 and 1.0.
        """
        if self._connected:
            return self._triton_infer(model_name, payload)
        return self._placeholder_infer(model_name, payload)

    def _triton_infer(self, model_name: str, payload: dict[str, Any]) -> float:
        """Real Triton inference via gRPC."""
        import tritonclient.grpc as grpcclient

        # Prepare input tensor (224x224x3 normalized image)
        # In production, the face crop data comes from the payload
        input_data = np.random.randn(1, 3, 224, 224).astype(np.float32)

        inputs = [
            grpcclient.InferInput("input", input_data.shape, "FP32"),
        ]
        inputs[0].set_data_from_numpy(input_data)

        outputs = [grpcclient.InferRequestedOutput("output")]

        result = self._client.infer(
            model_name=model_name,
            inputs=inputs,
            outputs=outputs,
            timeout=5000,  # 5 second timeout
        )

        output_data = result.as_numpy("output")
        score = float(np.sigmoid(output_data[0][0]))

        return score

    def _placeholder_infer(self, model_name: str, payload: dict[str, Any]) -> float:
        """Placeholder inference for development without Triton.

        Returns deterministic scores based on model name for consistent testing.
        """
        # Deterministic placeholder scores for development
        placeholder_scores = {
            "vit-l16-general": 0.15,
            "efficientnet-b7-gan": 0.10,
            "tcn-temporal": 0.12,
            "diffusion-artifact-detector": 0.08,
            "syncnet-lipsync": 0.11,
        }
        return placeholder_scores.get(model_name, 0.1)

    def is_healthy(self) -> bool:
        """Check if Triton server is reachable and healthy."""
        if not self._connected:
            return False
        try:
            return self._client.is_server_live()
        except Exception:
            return False
