"""Central, versioned configuration for SentinelAI detection behavior."""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "sentinel_ai.db"

RANDOM_SEED = 42
MIN_MODEL_TRAINING_ROWS = 50
MODEL_VERSION = "iforest-v1"
FEATURE_SCHEMA_VERSION = "behavior-features-v1"
RULE_VERSION = "rules-v1"

FEATURE_ORDER = (
    "login_hour_deviation",
    "outside_working_hours",
    "unknown_device",
    "location_anomaly",
    "failed_login_count",
    "download_count_deviation",
    "download_size_deviation",
    "sensitive_file",
    "privilege_escalation",
    "travel_speed_kmh",
    "impossible_travel",
)

RULE_WEIGHTS = {
    "OUTSIDE_WORKING_HOURS": 10.0,
    "UNKNOWN_DEVICE": 12.0,
    "UNUSUAL_LOCATION": 15.0,
    "IMPOSSIBLE_TRAVEL": 30.0,
    "REPEATED_FAILED_LOGINS": 20.0,
    "BULK_DOWNLOAD": 20.0,
    "LARGE_DOWNLOAD": 15.0,
    "SENSITIVE_FILE_ACCESS": 12.0,
    "PRIVILEGE_ESCALATION": 30.0,
}

FAILED_LOGIN_THRESHOLD = 5
BULK_DOWNLOAD_MIN_COUNT = 40
BULK_DOWNLOAD_COUNT_MULTIPLIER = 3.0
LARGE_DOWNLOAD_MIN_MB = 500.0
LARGE_DOWNLOAD_SIZE_MULTIPLIER = 8.0
IMPOSSIBLE_TRAVEL_MIN_DISTANCE_KM = 300.0
IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH = 900.0
AI_MAX_CONTRIBUTION = 25.0
CONTEXT_MAX_CONTRIBUTION = 15.0
ALERT_MINIMUM_SCORE = 30.0

RISK_BANDS = (
    (80.0, "Critical"),
    (60.0, "High"),
    (30.0, "Medium"),
    (0.0, "Low"),
)

ALERT_STATUSES = ("New", "Investigating", "Resolved", "False Positive")

