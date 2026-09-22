"""Replaceable anomaly-detector interfaces, adapters, and model status."""

from sentinel_ai.models.base import AnomalyDetector
from sentinel_ai.models.isolation_forest import IsolationForestDetector

__all__ = ["AnomalyDetector", "IsolationForestDetector"]

