"""Safe, idempotent initialization for demo deployments."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from sentinel_ai.api import create_app
from sentinel_ai.services import SentinelService


def _counts(service: SentinelService) -> dict[str, int]:
    return {
        "employees": len(service.employees()),
        "events": len(service.event_rows()),
        "detections": len(service.detection_rows()),
        "alerts": len(service.alert_rows()),
        "attack_runs": len(service.database.list_simulation_runs()),
    }


@pytest.fixture(scope="module")
def seeded_database(tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("bootstrap-seed") / "sentinel.db"
    service = SentinelService(path)
    assert service.initialize(bootstrap_demo_data=True) is True
    return str(path)


def test_empty_database_bootstraps_existing_demo_dataset(tmp_path) -> None:
    path = tmp_path / "brand-new.db"
    service = SentinelService(path)

    assert service.initialize(bootstrap_demo_data=True) is True

    counts = _counts(service)
    assert counts["employees"] == 30
    assert counts["events"] >= 1_300
    assert counts["detections"] == counts["events"]
    assert counts["alerts"] > 0
    assert counts["attack_runs"] == 0
    assert service.model_status == "ready"


def test_default_startup_does_not_seed_an_empty_database(tmp_path) -> None:
    service = SentinelService(tmp_path / "safe-default.db")

    assert service.initialize() is False
    assert _counts(service) == {"employees": 0, "events": 0, "detections": 0, "alerts": 0, "attack_runs": 0}


def test_populated_database_is_preserved_and_repeated_startup_is_idempotent(seeded_database, tmp_path) -> None:
    path = tmp_path / "populated.db"
    shutil.copy2(seeded_database, path)
    service = SentinelService(path)
    service.initialize()
    employee_id = service.employees()[0].employee_id
    run = service.run_attack_lab(
        "account_compromise",
        employee_id,
        datetime(2025, 8, 1, 12, 0, tzinfo=timezone.utc),
    )
    expected = _counts(service)
    expected_graph_findings = len(service.build_graph().findings)
    expected_mitre_stories = service.mitre_overview()["story_count"]

    first_restart = SentinelService(path)
    assert first_restart.initialize(bootstrap_demo_data=True) is False
    assert _counts(first_restart) == expected
    assert first_restart.simulation_run(run.simulation_id).event_ids == run.event_ids
    assert len(first_restart.build_graph().findings) == expected_graph_findings
    assert first_restart.mitre_overview()["story_count"] == expected_mitre_stories

    second_restart = SentinelService(path)
    assert second_restart.initialize(bootstrap_demo_data=True) is False
    assert _counts(second_restart) == expected
    assert len(second_restart.build_graph().findings) == expected_graph_findings
    assert second_restart.mitre_overview()["story_count"] == expected_mitre_stories


def test_bootstrapped_graph_and_mitre_overview_use_real_seed_evidence(seeded_database, tmp_path) -> None:
    path = tmp_path / "intelligence.db"
    shutil.copy2(seeded_database, path)
    service = SentinelService(path)
    service.initialize()

    graph = service.build_graph()
    assert graph.nodes
    assert graph.edges
    assert all(edge.source_id in graph.nodes and edge.target_id in graph.nodes for edge in graph.edges)

    overview = service.mitre_overview()
    assert overview["mapped_technique_count"] > 0
    assert overview["story_count"] > 0
    assert overview["recent_reports"]
    for report in overview["recent_reports"]:
        assert report.supporting_events
        assert all(mapping.supporting_rule_names or mapping.supporting_sequence_findings for mapping in report.mappings)


def test_api_honours_demo_bootstrap_environment_flag(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_BOOTSTRAP_DEMO_DATA", "true")
    with TestClient(create_app(tmp_path / "environment.db")) as client:
        status = client.get("/api/system/status").json()
        overview = client.get("/api/mitre/overview").json()

    assert status["counts"]["employees"] == 30
    assert status["counts"]["activityEvents"] >= 1_300
    assert overview["mappedTechniqueCount"] > 0
    assert overview["storyCount"] > 0
