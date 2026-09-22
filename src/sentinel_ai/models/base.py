"""Replaceable anomaly-detector contract."""

from __future__ import annotations

from typing import Protocol, Sequence

from sentinel_ai.domain import FeatureVector, ModelScore


class AnomalyDetector(Protocol):
    @property
    def status(self) -> str: ...

    def fit(self, features: Sequence[FeatureVector]) -> str: ...

    def score(self, feature: FeatureVector) -> ModelScore: ...

