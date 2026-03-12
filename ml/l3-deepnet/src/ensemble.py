"""Ensemble aggregation for L3 multi-model detection."""

import structlog

logger = structlog.get_logger()

# Default ensemble weights — tunable per validation performance.
DEFAULT_WEIGHTS: dict[str, float] = {
    "vit-l16-general": 0.30,
    "efficientnet-b7-gan": 0.25,
    "tcn-temporal": 0.20,
    "diffusion-artifact-detector": 0.15,
    "syncnet-lipsync": 0.10,
}

# Threshold for considering a model's prediction as "positive"
POSITIVE_THRESHOLD = 0.5


class EnsembleAggregator:
    """Weighted ensemble aggregation of multiple model scores."""

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = weights or DEFAULT_WEIGHTS

    def aggregate(self, model_scores: dict[str, float]) -> dict[str, float]:
        """Aggregate model scores into a single ensemble score.

        Args:
            model_scores: Dict of model_name -> confidence score [0.0, 1.0].

        Returns:
            Dict with ensemble_score and agreement_ratio.
        """
        if not model_scores:
            return {"ensemble_score": 0.0, "agreement_ratio": 0.0}

        # Weighted average
        weighted_sum = 0.0
        total_weight = 0.0

        for model_name, score in model_scores.items():
            weight = self.weights.get(model_name, 0.1)
            weighted_sum += score * weight
            total_weight += weight

        ensemble_score = weighted_sum / total_weight if total_weight > 0 else 0.0

        # Model agreement: fraction of models that agree on positive/negative
        positive_count = sum(
            1 for s in model_scores.values() if s > POSITIVE_THRESHOLD
        )
        total_models = len(model_scores)
        # Agreement = max(positive_ratio, negative_ratio)
        positive_ratio = positive_count / total_models if total_models > 0 else 0.0
        agreement_ratio = max(positive_ratio, 1.0 - positive_ratio)

        # Log disagreement if models don't agree
        if agreement_ratio < 0.6:
            logger.warning(
                "Low model agreement detected",
                agreement_ratio=round(agreement_ratio, 3),
                model_scores={k: round(v, 3) for k, v in model_scores.items()},
            )

        return {
            "ensemble_score": round(ensemble_score, 6),
            "agreement_ratio": round(agreement_ratio, 4),
        }
