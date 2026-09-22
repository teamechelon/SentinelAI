"""Leakage-safe model evaluation contracts."""

from sentinel_ai.models.evaluation import evaluate_existing_models, prepare_evaluation_dataset
from sentinel_ai.models.quantum_kernel import evaluate_quantum_kernel


def test_evaluation_split_is_chronological_and_suspicious_is_test_only() -> None:
    dataset = prepare_evaluation_dataset()

    assert dataset.split == {
        "strategy": "Per-employee chronological 60/20/20 split on normal history; suspicious events are evaluation-only.",
        "baselineRows": 720,
        "trainingRows": 240,
        "normalTestRows": 240,
        "anomalyTestRows": 108,
        "futureDataUsed": False,
    }
    assert all(not event.is_suspicious for event, _ in dataset.training)
    assert all(event.is_suspicious for event, _ in dataset.anomaly_test)


def test_existing_model_evaluation_is_deterministic_and_explicit() -> None:
    report = evaluate_existing_models()

    assert report["classical"]["metrics"]["truePositive"] == 77
    assert report["classical"]["metrics"]["falsePositive"] == 8
    assert report["rules"]["metrics"]["truePositive"] == 108
    assert report["thresholds"]["classical"].endswith(">= 95")
    assert report["limitations"]


def test_quantum_kernel_is_real_small_sample_and_never_changes_risk() -> None:
    report = evaluate_quantum_kernel()

    assert report["status"] == "ready", report.get("reason")
    assert report["affectsProductionRisk"] is False
    assert report["configuration"]["qubits"] == 4
    assert report["configuration"]["trainingRows"] == 16
    assert report["versions"]["qiskit"]
    assert len(report["assessments"]) == 16
    assert all(item["eventId"] for item in report["assessments"])
    assert all(item["confidence"] is None for item in report["assessments"])
    assert all(value >= 0 for item in report["assessments"] for value in item["novelty"].values())
    assert any("different feature representations" in limitation for limitation in report["limitations"])
