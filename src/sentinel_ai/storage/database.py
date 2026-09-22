"""SQLite persistence for SentinelAI events, profiles, detections, and alerts."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from sentinel_ai import config
from sentinel_ai.domain import ActivityEvent, Alert, BehaviourProfile, DetectionResult, Employee


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS employees (
    employee_id TEXT PRIMARY KEY,
    employee_name TEXT NOT NULL,
    department TEXT NOT NULL,
    home_country TEXT NOT NULL,
    home_city TEXT NOT NULL,
    home_latitude REAL NOT NULL,
    home_longitude REAL NOT NULL,
    known_devices_json TEXT NOT NULL,
    normal_privilege TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_events (
    event_id TEXT PRIMARY KEY,
    employee_id TEXT NOT NULL REFERENCES employees(employee_id),
    employee_name TEXT NOT NULL,
    department TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    activity_type TEXT NOT NULL,
    login_success INTEGER NOT NULL,
    failed_login_count INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    country TEXT NOT NULL,
    city TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    device_id TEXT NOT NULL,
    is_known_device INTEGER NOT NULL,
    file_name TEXT NOT NULL,
    file_sensitivity TEXT NOT NULL,
    download_count INTEGER NOT NULL,
    download_size_mb REAL NOT NULL,
    previous_privilege TEXT NOT NULL,
    current_privilege TEXT NOT NULL,
    scenario TEXT NOT NULL,
    is_suspicious INTEGER NOT NULL,
    is_approved_travel INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_employee_time ON activity_events(employee_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_scenario ON activity_events(scenario);

CREATE TABLE IF NOT EXISTS behavior_profiles (
    employee_id TEXT PRIMARY KEY REFERENCES employees(employee_id),
    normal_login_start REAL NOT NULL,
    normal_login_end REAL NOT NULL,
    usual_countries_json TEXT NOT NULL,
    usual_cities_json TEXT NOT NULL,
    known_devices_json TEXT NOT NULL,
    average_download_count REAL NOT NULL,
    average_download_size_mb REAL NOT NULL,
    typical_file_sensitivity_json TEXT NOT NULL,
    normal_privilege TEXT NOT NULL,
    average_failed_login_count REAL NOT NULL,
    history_event_count INTEGER NOT NULL,
    confidence REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detection_results (
    detection_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE REFERENCES activity_events(event_id),
    employee_id TEXT NOT NULL REFERENCES employees(employee_id),
    detected_at TEXT NOT NULL,
    final_risk_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    rule_contribution REAL NOT NULL,
    ai_contribution REAL NOT NULL,
    contextual_contribution REAL NOT NULL,
    triggered_rules_json TEXT NOT NULL,
    explanation TEXT NOT NULL,
    recommended_response TEXT NOT NULL,
    model_status TEXT NOT NULL,
    model_raw_score REAL,
    anomaly_percentile REAL,
    feature_values_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_detections_employee ON detection_results(employee_id, detected_at);
CREATE INDEX IF NOT EXISTS idx_detections_risk ON detection_results(risk_level, final_risk_score);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    detection_id TEXT NOT NULL UNIQUE REFERENCES detection_results(detection_id),
    event_id TEXT NOT NULL REFERENCES activity_events(event_id),
    employee_id TEXT NOT NULL REFERENCES employees(employee_id),
    created_at TEXT NOT NULL,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    risk_score REAL NOT NULL,
    risk_level TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at);

CREATE TABLE IF NOT EXISTS investigation_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    note TEXT NOT NULL
);
"""


class SentinelDatabase:
    def __init__(self, path: str | Path = config.DEFAULT_DATABASE_PATH) -> None:
        self.path = Path(path)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connection() as connection:
            connection.executescript(SCHEMA)

    def clear_all(self) -> None:
        with self.connection() as connection:
            connection.execute("DELETE FROM investigation_notes")
            connection.execute("DELETE FROM alerts")
            connection.execute("DELETE FROM detection_results")
            connection.execute("DELETE FROM behavior_profiles")
            connection.execute("DELETE FROM activity_events")
            connection.execute("DELETE FROM employees")

    def is_empty(self) -> bool:
        with self.connection() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM employees").fetchone()
        return not row or row["count"] == 0

    def insert_employees(self, employees: list[Employee]) -> None:
        values = [
            (
                employee.employee_id,
                employee.employee_name,
                employee.department,
                employee.home_country,
                employee.home_city,
                employee.home_latitude,
                employee.home_longitude,
                json.dumps(employee.known_devices),
                employee.normal_privilege,
            )
            for employee in employees
        ]
        with self.connection() as connection:
            connection.executemany(
                """
                INSERT INTO employees VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(employee_id) DO UPDATE SET
                    employee_name=excluded.employee_name,
                    department=excluded.department,
                    home_country=excluded.home_country,
                    home_city=excluded.home_city,
                    home_latitude=excluded.home_latitude,
                    home_longitude=excluded.home_longitude,
                    known_devices_json=excluded.known_devices_json,
                    normal_privilege=excluded.normal_privilege
                """,
                values,
            )

    def insert_events(self, events: list[ActivityEvent]) -> int:
        columns = (
            "event_id", "employee_id", "employee_name", "department", "timestamp", "activity_type",
            "login_success", "failed_login_count", "ip_address", "country", "city", "latitude",
            "longitude", "device_id", "is_known_device", "file_name", "file_sensitivity",
            "download_count", "download_size_mb", "previous_privilege", "current_privilege", "scenario",
            "is_suspicious", "is_approved_travel",
        )
        placeholders = ", ".join("?" for _ in columns)
        values = [tuple(event.to_record()[column] for column in columns) for event in events]
        with self.connection() as connection:
            before = connection.total_changes
            connection.executemany(
                f"INSERT OR IGNORE INTO activity_events ({', '.join(columns)}) VALUES ({placeholders})",
                values,
            )
            return connection.total_changes - before

    def upsert_profiles(self, profiles: list[BehaviourProfile]) -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        values = [
            (
                profile.employee_id,
                profile.normal_login_start,
                profile.normal_login_end,
                json.dumps(profile.usual_countries),
                json.dumps(profile.usual_cities),
                json.dumps(profile.known_devices),
                profile.average_download_count,
                profile.average_download_size_mb,
                json.dumps(profile.typical_file_sensitivity),
                profile.normal_privilege,
                profile.average_failed_login_count,
                profile.history_event_count,
                profile.confidence,
                created_at,
            )
            for profile in profiles
        ]
        with self.connection() as connection:
            connection.executemany(
                """
                INSERT INTO behavior_profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(employee_id) DO UPDATE SET
                    normal_login_start=excluded.normal_login_start,
                    normal_login_end=excluded.normal_login_end,
                    usual_countries_json=excluded.usual_countries_json,
                    usual_cities_json=excluded.usual_cities_json,
                    known_devices_json=excluded.known_devices_json,
                    average_download_count=excluded.average_download_count,
                    average_download_size_mb=excluded.average_download_size_mb,
                    typical_file_sensitivity_json=excluded.typical_file_sensitivity_json,
                    normal_privilege=excluded.normal_privilege,
                    average_failed_login_count=excluded.average_failed_login_count,
                    history_event_count=excluded.history_event_count,
                    confidence=excluded.confidence,
                    created_at=excluded.created_at
                """,
                values,
            )

    def insert_detection(self, result: DetectionResult) -> None:
        rule_payload = [asdict(hit) for hit in result.triggered_rules]
        values = (
            result.detection_id,
            result.event_id,
            result.employee_id,
            result.detected_at.isoformat(),
            result.final_risk_score,
            result.risk_level,
            result.rule_contribution,
            result.ai_contribution,
            result.contextual_contribution,
            json.dumps(rule_payload),
            result.explanation,
            result.recommended_response,
            result.model_status,
            result.model_raw_score,
            result.anomaly_percentile,
            json.dumps(result.feature_values),
        )
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO detection_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    detected_at=excluded.detected_at,
                    final_risk_score=excluded.final_risk_score,
                    risk_level=excluded.risk_level,
                    rule_contribution=excluded.rule_contribution,
                    ai_contribution=excluded.ai_contribution,
                    contextual_contribution=excluded.contextual_contribution,
                    triggered_rules_json=excluded.triggered_rules_json,
                    explanation=excluded.explanation,
                    recommended_response=excluded.recommended_response,
                    model_status=excluded.model_status,
                    model_raw_score=excluded.model_raw_score,
                    anomaly_percentile=excluded.anomaly_percentile,
                    feature_values_json=excluded.feature_values_json
                """,
                values,
            )

    def create_alert(self, alert: Alert) -> bool:
        with self.connection() as connection:
            before = connection.total_changes
            connection.execute(
                "INSERT OR IGNORE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    alert.alert_id,
                    alert.detection_id,
                    alert.event_id,
                    alert.employee_id,
                    alert.created_at.isoformat(),
                    alert.status,
                    alert.title,
                    alert.risk_score,
                    alert.risk_level,
                ),
            )
            return connection.total_changes > before

    def update_alert_status(self, alert_id: str, status: str) -> None:
        if status not in config.ALERT_STATUSES:
            raise ValueError(f"Invalid alert status: {status}")
        with self.connection() as connection:
            cursor = connection.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
            if cursor.rowcount == 0:
                raise KeyError(f"Unknown alert: {alert_id}")

    def add_investigation_note(self, alert_id: str, note: str) -> int:
        cleaned = note.strip()
        if not cleaned:
            raise ValueError("Investigation note cannot be empty")
        with self.connection() as connection:
            exists = connection.execute("SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if not exists:
                raise KeyError(f"Unknown alert: {alert_id}")
            cursor = connection.execute(
                "INSERT INTO investigation_notes (alert_id, created_at, note) VALUES (?, ?, ?)",
                (alert_id, datetime.now(timezone.utc).isoformat(), cleaned),
            )
            return int(cursor.lastrowid)

    def list_investigation_notes(self, alert_id: str) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT note_id, alert_id, created_at, note FROM investigation_notes WHERE alert_id = ? ORDER BY created_at DESC",
                (alert_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_employees(self) -> list[Employee]:
        with self.connection() as connection:
            rows = connection.execute("SELECT * FROM employees ORDER BY employee_name").fetchall()
        return [self._employee_from_row(row) for row in rows]

    def get_employee(self, employee_id: str) -> Employee | None:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM employees WHERE employee_id = ?", (employee_id,)).fetchone()
        return self._employee_from_row(row) if row else None

    def list_profiles(self) -> dict[str, BehaviourProfile]:
        with self.connection() as connection:
            rows = connection.execute("SELECT * FROM behavior_profiles").fetchall()
        return {row["employee_id"]: self._profile_from_row(row) for row in rows}

    def get_profile(self, employee_id: str) -> BehaviourProfile | None:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM behavior_profiles WHERE employee_id = ?", (employee_id,)).fetchone()
        return self._profile_from_row(row) if row else None

    def list_activity_events(self, employee_id: str | None = None) -> list[ActivityEvent]:
        query = "SELECT * FROM activity_events"
        parameters: tuple[Any, ...] = ()
        if employee_id:
            query += " WHERE employee_id = ?"
            parameters = (employee_id,)
        query += " ORDER BY timestamp, event_id"
        with self.connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._event_from_row(row) for row in rows]

    def get_event(self, event_id: str) -> ActivityEvent | None:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM activity_events WHERE event_id = ?", (event_id,)).fetchone()
        return self._event_from_row(row) if row else None

    def previous_successful_login(self, employee_id: str, before: datetime) -> ActivityEvent | None:
        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM activity_events
                WHERE employee_id = ? AND activity_type = 'login' AND login_success = 1 AND timestamp < ?
                ORDER BY timestamp DESC LIMIT 1
                """,
                (employee_id, before.isoformat()),
            ).fetchone()
        return self._event_from_row(row) if row else None

    def list_event_rows(self) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT e.*, d.final_risk_score, d.risk_level, d.rule_contribution, d.ai_contribution,
                       d.contextual_contribution, d.triggered_rules_json, d.explanation,
                       d.recommended_response, d.model_status, d.anomaly_percentile,
                       a.alert_id, a.status AS alert_status
                FROM activity_events e
                LEFT JOIN detection_results d ON d.event_id = e.event_id
                LEFT JOIN alerts a ON a.event_id = e.event_id
                ORDER BY e.timestamp DESC
                """
            ).fetchall()
        return [self._decode_row(row) for row in rows]

    def list_detection_rows(self, employee_id: str | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT d.*, e.timestamp, e.employee_name, e.department, e.activity_type, e.scenario
            FROM detection_results d JOIN activity_events e ON e.event_id = d.event_id
        """
        parameters: tuple[Any, ...] = ()
        if employee_id:
            query += " WHERE d.employee_id = ?"
            parameters = (employee_id,)
        query += " ORDER BY e.timestamp DESC"
        with self.connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._decode_row(row) for row in rows]

    def list_alert_rows(self) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT a.*, e.employee_name, e.department, e.timestamp, e.activity_type, e.scenario,
                       d.rule_contribution, d.ai_contribution, d.contextual_contribution,
                       d.triggered_rules_json, d.explanation, d.recommended_response,
                       d.model_status, d.anomaly_percentile, d.feature_values_json
                FROM alerts a
                JOIN activity_events e ON e.event_id = a.event_id
                JOIN detection_results d ON d.detection_id = a.detection_id
                ORDER BY a.created_at DESC
                """
            ).fetchall()
        return [self._decode_row(row) for row in rows]

    def get_alert_row(self, alert_id: str) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT a.*, e.*, d.rule_contribution, d.ai_contribution, d.contextual_contribution,
                       d.triggered_rules_json, d.explanation, d.recommended_response,
                       d.model_status, d.model_raw_score, d.anomaly_percentile, d.feature_values_json
                FROM alerts a
                JOIN activity_events e ON e.event_id = a.event_id
                JOIN detection_results d ON d.detection_id = a.detection_id
                WHERE a.alert_id = ?
                """,
                (alert_id,),
            ).fetchone()
        return self._decode_row(row) if row else None

    @staticmethod
    def _employee_from_row(row: sqlite3.Row) -> Employee:
        return Employee(
            employee_id=row["employee_id"],
            employee_name=row["employee_name"],
            department=row["department"],
            home_country=row["home_country"],
            home_city=row["home_city"],
            home_latitude=float(row["home_latitude"]),
            home_longitude=float(row["home_longitude"]),
            known_devices=tuple(json.loads(row["known_devices_json"])),
            normal_privilege=row["normal_privilege"],
        )

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> ActivityEvent:
        return ActivityEvent(
            event_id=row["event_id"],
            employee_id=row["employee_id"],
            employee_name=row["employee_name"],
            department=row["department"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            activity_type=row["activity_type"],
            login_success=bool(row["login_success"]),
            failed_login_count=int(row["failed_login_count"]),
            ip_address=row["ip_address"],
            country=row["country"],
            city=row["city"],
            latitude=row["latitude"],
            longitude=row["longitude"],
            device_id=row["device_id"],
            is_known_device=bool(row["is_known_device"]),
            file_name=row["file_name"],
            file_sensitivity=row["file_sensitivity"],
            download_count=int(row["download_count"]),
            download_size_mb=float(row["download_size_mb"]),
            previous_privilege=row["previous_privilege"],
            current_privilege=row["current_privilege"],
            scenario=row["scenario"],
            is_suspicious=bool(row["is_suspicious"]),
            is_approved_travel=bool(row["is_approved_travel"]),
        )

    @staticmethod
    def _profile_from_row(row: sqlite3.Row) -> BehaviourProfile:
        return BehaviourProfile(
            employee_id=row["employee_id"],
            normal_login_start=float(row["normal_login_start"]),
            normal_login_end=float(row["normal_login_end"]),
            usual_countries=tuple(json.loads(row["usual_countries_json"])),
            usual_cities=tuple(json.loads(row["usual_cities_json"])),
            known_devices=tuple(json.loads(row["known_devices_json"])),
            average_download_count=float(row["average_download_count"]),
            average_download_size_mb=float(row["average_download_size_mb"]),
            typical_file_sensitivity=tuple(json.loads(row["typical_file_sensitivity_json"])),
            normal_privilege=row["normal_privilege"],
            average_failed_login_count=float(row["average_failed_login_count"]),
            history_event_count=int(row["history_event_count"]),
            confidence=float(row["confidence"]),
        )

    @staticmethod
    def _decode_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        for key in ("triggered_rules_json", "feature_values_json"):
            if key in result and result[key] is not None:
                result[key.removesuffix("_json")] = json.loads(result.pop(key))
        return result

