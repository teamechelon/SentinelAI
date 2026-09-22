"""Deterministic, explainable employee-activity threat rules."""

from __future__ import annotations

from sentinel_ai import config
from sentinel_ai.domain import ActivityEvent, BehaviourProfile, FeatureVector, RuleHit


def _hit(rule_name: str, reason: str, observed: object, expected: object) -> RuleHit:
    return RuleHit(
        rule_name=rule_name,
        contribution=config.RULE_WEIGHTS[rule_name],
        reason=reason,
        observed_value=str(observed),
        expected_value=str(expected),
    )


def evaluate_rules(event: ActivityEvent, profile: BehaviourProfile, features: FeatureVector) -> tuple[RuleHit, ...]:
    hits: list[RuleHit] = []
    if features.outside_working_hours:
        hits.append(
            _hit(
                "OUTSIDE_WORKING_HOURS",
                "Login occurred outside the employee's learned working-hour range.",
                event.timestamp.strftime("%H:%M"),
                f"{profile.normal_login_start:.2f}–{profile.normal_login_end:.2f}",
            )
        )
    if features.unknown_device:
        hits.append(
            _hit(
                "UNKNOWN_DEVICE",
                "Activity used a device outside the employee's known-device baseline.",
                event.device_id,
                ", ".join(profile.known_devices),
            )
        )
    if features.location_anomaly and not event.is_approved_travel:
        hits.append(
            _hit(
                "UNUSUAL_LOCATION",
                "Login location is outside the employee's usual countries or cities.",
                f"{event.city}, {event.country}",
                f"cities={', '.join(profile.usual_cities)}; countries={', '.join(profile.usual_countries)}",
            )
        )
    if features.impossible_travel:
        hits.append(
            _hit(
                "IMPOSSIBLE_TRAVEL",
                "Consecutive successful logins require implausible travel speed.",
                f"{features.travel_speed_kmh:.0f} km/h",
                f"≤ {config.IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH:.0f} km/h",
            )
        )
    if event.failed_login_count >= config.FAILED_LOGIN_THRESHOLD:
        hits.append(
            _hit(
                "REPEATED_FAILED_LOGINS",
                "A successful activity followed an excessive failed-login count.",
                event.failed_login_count,
                f"< {config.FAILED_LOGIN_THRESHOLD}",
            )
        )

    bulk_count_threshold = max(config.BULK_DOWNLOAD_MIN_COUNT, profile.average_download_count * config.BULK_DOWNLOAD_COUNT_MULTIPLIER)
    if event.download_count >= bulk_count_threshold:
        hits.append(
            _hit(
                "BULK_DOWNLOAD",
                "Download count is far above the employee's historical baseline.",
                event.download_count,
                f"< {bulk_count_threshold:.0f} files",
            )
        )

    large_size_threshold = max(config.LARGE_DOWNLOAD_MIN_MB, profile.average_download_size_mb * config.LARGE_DOWNLOAD_SIZE_MULTIPLIER)
    total_download_size = event.download_count * event.download_size_mb
    if total_download_size >= large_size_threshold:
        hits.append(
            _hit(
                "LARGE_DOWNLOAD",
                "Total transferred data exceeds the employee's expected download volume.",
                f"{total_download_size:.1f} MB",
                f"< {large_size_threshold:.1f} MB",
            )
        )
    if features.sensitive_file:
        hits.append(
            _hit(
                "SENSITIVE_FILE_ACCESS",
                "The resource sensitivity is outside the employee's typical access pattern.",
                event.file_sensitivity,
                ", ".join(profile.typical_file_sensitivity),
            )
        )
    if features.privilege_escalation:
        hits.append(
            _hit(
                "PRIVILEGE_ESCALATION",
                "The account moved to a higher privilege level.",
                f"{event.previous_privilege} → {event.current_privilege}",
                f"normal level: {profile.normal_privilege}",
            )
        )
    return tuple(hits)

