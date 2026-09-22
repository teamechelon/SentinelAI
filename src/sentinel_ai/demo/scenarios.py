"""User-facing simulation scenario definitions."""

from __future__ import annotations


SIMULATION_SCENARIOS = {
    "Normal login": "normal_login",
    "Unknown-device login": "unknown_device_login",
    "Impossible-travel login": "impossible_travel",
    "Brute-force attempt": "brute_force_attempt",
    "Bulk download": "bulk_download",
    "Sensitive-file access": "sensitive_file_access",
    "Privilege escalation": "privilege_escalation",
    "Combined account compromise": "combined_account_compromise",
    "Legitimate employee travel": "legitimate_travel",
}

