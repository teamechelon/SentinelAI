"""Isolation Forest implementation with fixed preprocessing and calibration."""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Sequence

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from sentinel_ai import config
from sentinel_ai.domain import FeatureVector, ModelScore
from sentinel_ai.features import feature_row


class IsolationForestDetector:
    """Train on normal history and expose a rank-based anomaly contribution."""

    def __init__(self, random_state: int = config.RANDOM_SEED) -> None:
        self._pipeline = Pipeline(
            steps=(
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
                (
                    "model",
                    IsolationForest(
                        n_estimators=200,
                        contamination="auto",
                        max_samples="auto",
                        random_state=random_state,
                        n_jobs=1,
                    ),
                ),
            )
        )
        self._status = "untrained"
        self._calibration_scores: list[float] = []
        self._training_row_count = 0

    @property
    def status(self) -> str:
        return self._status

    @property
    def training_row_count(self) -> int:
        return self._training_row_count

    def fit(self, features: Sequence[FeatureVector]) -> str:
        self._training_row_count = len(features)
        if len(features) < config.MIN_MODEL_TRAINING_ROWS:
            self._status = "insufficient_training_data"
            self._calibration_scores = []
            return self._status
        matrix = np.asarray([feature_row(feature) for feature in features], dtype=float)
        self._pipeline.fit(matrix)
        nonconformity = -self._pipeline.score_samples(matrix)
        self._calibration_scores = sorted(float(score) for score in nonconformity)
        self._status = "ready"
        return self._status

    def score(self, feature: FeatureVector) -> ModelScore:
        if self._status != "ready" or not self._calibration_scores:
            return ModelScore(
                status=self._status,
                raw_score=None,
                anomaly_percentile=None,
                contribution=0.0,
                model_version=config.MODEL_VERSION,
                message="Isolation Forest is unavailable; the result uses rules and context only.",
            )
        matrix = np.asarray([feature_row(feature)], dtype=float)
        raw_score = float(-self._pipeline.score_samples(matrix)[0])
        percentile = 100.0 * bisect_right(self._calibration_scores, raw_score) / len(self._calibration_scores)
        contribution = max(0.0, (percentile - 50.0) / 50.0 * config.AI_MAX_CONTRIBUTION)
        return ModelScore(
            status="ready",
            raw_score=round(raw_score, 6),
            anomaly_percentile=round(percentile, 2),
            contribution=round(min(config.AI_MAX_CONTRIBUTION, contribution), 2),
            model_version=config.MODEL_VERSION,
            message="Percentile ranks model nonconformity against normal training history; it is not an attack probability.",
        )

