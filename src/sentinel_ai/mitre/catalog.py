"""Small, audited subset of Enterprise ATT&CK used by SentinelAI.

The runtime intentionally does not fetch ATT&CK data. Entries were selected from
the official Enterprise ATT&CK v19.2 release and are limited to behaviours the
current SentinelAI telemetry can support with direct evidence.
"""

from __future__ import annotations

from sentinel_ai.mitre.models import Technique


ATTACK_VERSION = "Enterprise ATT&CK v19.2"
ATTACK_SOURCE_URL = "https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2"

_TECHNIQUES = (
    Technique(
        technique_id="T1110",
        name="Brute Force",
        tactics=("Credential Access",),
        description="Repeated or failed authentication attempts used to obtain account access.",
        source_version=ATTACK_VERSION,
        source_url="https://attack.mitre.org/techniques/T1110/",
    ),
    Technique(
        technique_id="T1078",
        name="Valid Accounts",
        tactics=("Initial Access", "Persistence", "Privilege Escalation", "Stealth"),
        description="Use of legitimate credentials or accounts in an anomalous or compromised context.",
        source_version=ATTACK_VERSION,
        source_url="https://attack.mitre.org/techniques/T1078/",
    ),
    Technique(
        technique_id="T1098",
        name="Account Manipulation",
        tactics=("Persistence", "Privilege Escalation"),
        description="Account or permission changes that preserve or elevate access.",
        source_version=ATTACK_VERSION,
        source_url="https://attack.mitre.org/techniques/T1098/",
    ),
    Technique(
        technique_id="T1005",
        name="Data from Local System",
        tactics=("Collection",),
        description="Access to files or other local sources containing information of interest.",
        source_version=ATTACK_VERSION,
        source_url="https://attack.mitre.org/techniques/T1005/",
    ),
)

_BY_ID = {item.technique_id: item for item in _TECHNIQUES}


def catalog() -> tuple[Technique, ...]:
    return _TECHNIQUES


def get_technique(technique_id: str) -> Technique:
    return _BY_ID[technique_id]
