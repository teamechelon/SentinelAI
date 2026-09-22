"""Small reproducible Qiskit kernel benchmark isolated from production risk."""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import version
from math import pi
from time import perf_counter
from typing import Any

import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.svm import OneClassSVM

from sentinel_ai import config
from sentinel_ai.baselines import build_behavioural_assessment
from sentinel_ai.domain import ActivityEvent, AnomalyAssessment, BehaviouralAssessment, FeatureVector
from sentinel_ai.models.evaluation import classification_metrics, prepare_evaluation_dataset
from sentinel_ai.models.isolation_forest import IsolationForestDetector


QUANTUM_FEATURES = ("personal_deviation", "peer_deviation", "login_hour", "combined_novelty")


def _assessment_document(item: AnomalyAssessment) -> dict[str, Any]:
    """Serialize one benchmark row using the public frontend/API contract."""

    return {
        "eventId": item.event_id,
        "scenario": item.scenario,
        "expectedAnomaly": item.expected_anomaly,
        "classicalScore": item.classical_score,
        "quantumScore": item.quantum_score,
        "personalDeviation": item.personal_deviation,
        "peerDeviation": item.peer_deviation,
        "classicalStatus": item.classical_status,
        "quantumStatus": item.quantum_status,
        "agreement": item.agreement,
        "confidence": item.confidence,
        "novelty": item.novelty,
    }


def _novelty(features: FeatureVector) -> dict[str, float]:
    return {
        "device": float(features.unknown_device),
        "location": float(features.location_anomaly),
        "download": min(1.0, max(0.0, features.download_count_deviation, features.download_size_deviation) / 5.0),
    }


def _quantum_row(event: ActivityEvent, features: FeatureVector, assessment: BehaviouralAssessment) -> list[float]:
    novelty = _novelty(features)
    return [
        float(assessment.personal_deviation or 0.0),
        float(assessment.peer_deviation or 0.0),
        event.timestamp.hour / 23.0,
        sum(novelty.values()) / len(novelty),
    ]


@lru_cache(maxsize=1)
def evaluate_quantum_kernel() -> dict[str, Any]:
    started = perf_counter()
    try:
        from qiskit.circuit.library import zz_feature_map
        from qiskit_aer.primitives import SamplerV2 as AerSampler
        from qiskit_machine_learning.kernels import FidelityQuantumKernel
        from qiskit_machine_learning.state_fidelities import ComputeUncompute
    except Exception as error:
        return {"status": "unavailable", "reason": f"Quantum dependencies unavailable: {error}", "affectsProductionRisk": False}

    try:
        dataset = prepare_evaluation_dataset()
        quantum_training = list(dataset.training[:16])
        evaluation = list(dataset.normal_test[:8]) + list(dataset.anomaly_test[:8])
        selected_ids = {event.event_id for event, _ in quantum_training + evaluation}
        employee_map = {employee.employee_id: employee for employee in dataset.employees}
        assessments: dict[str, BehaviouralAssessment] = {}
        history: list[ActivityEvent] = []
        for event in sorted(dataset.all_events, key=lambda item: (item.timestamp, item.event_id)):
            if event.event_id in selected_ids:
                assessments[event.event_id] = build_behavioural_assessment(event, employee_map[event.employee_id], list(dataset.employees), history)
            history.append(event)
        raw_train = np.asarray([_quantum_row(event, features, assessments[event.event_id]) for event, features in quantum_training], dtype=float)
        raw_test = np.asarray([_quantum_row(event, features, assessments[event.event_id]) for event, features in evaluation], dtype=float)
        scaler = MinMaxScaler(feature_range=(0.0, pi))
        train_matrix = scaler.fit_transform(raw_train)
        test_matrix = scaler.transform(raw_test)

        sampler = AerSampler(default_shots=256, seed=config.RANDOM_SEED)
        fidelity = ComputeUncompute(sampler=sampler)
        feature_map = zz_feature_map(feature_dimension=4, reps=2, entanglement="linear")
        kernel = FidelityQuantumKernel(feature_map=feature_map, fidelity=fidelity, enforce_psd=True)
        training_kernel = kernel.evaluate(x_vec=train_matrix)
        test_kernel = kernel.evaluate(x_vec=test_matrix, y_vec=train_matrix)
        estimator = OneClassSVM(kernel="precomputed", nu=0.1)
        estimator.fit(training_kernel)
        decisions = estimator.decision_function(test_kernel).reshape(-1)
        predictions = estimator.predict(test_kernel) == -1
        labels = np.asarray([event.is_suspicious for event, _ in evaluation], dtype=bool)

        classical = IsolationForestDetector()
        classical.fit([features for _, features in dataset.training])
        classical_scores = [classical.score(features).anomaly_percentile for _, features in evaluation]
        classical_predictions = [score is not None and score >= 95.0 for score in classical_scores]
        assessment_rows: list[AnomalyAssessment] = []
        for index, ((event, features), quantum_prediction) in enumerate(zip(evaluation, predictions, strict=True)):
            behavioural = assessments[event.event_id]
            classical_prediction = classical_predictions[index]
            assessment_rows.append(AnomalyAssessment(
                event_id=event.event_id, scenario=event.scenario, expected_anomaly=event.is_suspicious,
                classical_score=classical_scores[index], quantum_score=round(float(-decisions[index]), 6),
                personal_deviation=behavioural.personal_deviation, peer_deviation=behavioural.peer_deviation,
                classical_status="anomaly" if classical_prediction else "normal",
                quantum_status="anomaly" if quantum_prediction else "normal",
                agreement=bool(classical_prediction == quantum_prediction), confidence=None,
                novelty=_novelty(features),
            ))
        return {
            "status": "ready",
            "label": "Experimental small-sample benchmark",
            "implementation": "Qiskit FidelityQuantumKernel + Aer SamplerV2 + sklearn OneClassSVM (precomputed kernel)",
            "versions": {"qiskit": version("qiskit"), "qiskitAer": version("qiskit-aer"), "qiskitMachineLearning": version("qiskit-machine-learning"), "scikitLearn": version("scikit-learn")},
            "configuration": {"randomSeed": config.RANDOM_SEED, "shots": 256, "qubits": 4, "features": list(QUANTUM_FEATURES), "featureMap": "ZZFeatureMap", "repetitions": 2, "entanglement": "linear", "trainingRows": len(quantum_training), "normalTestRows": 8, "anomalyTestRows": 8, "oneClassNu": 0.1},
            "metrics": classification_metrics(labels.tolist(), predictions.tolist()),
            "runtimeSeconds": round(perf_counter() - started, 3),
            "assessments": [_assessment_document(item) for item in assessment_rows],
            "affectsProductionRisk": False,
            "limitations": [
                "This deliberately small synthetic benchmark is not evidence of quantum advantage.",
                "The quantum kernel and production Isolation Forest use different feature representations; their agreement is descriptive, not a like-for-like model comparison.",
                "Shot-based kernel estimates vary within the fixed simulator configuration.",
                "Quantum score is signed kernel-model novelty, not a probability or final risk value.",
                "Confidence is intentionally unavailable because this benchmark is not calibrated.",
            ],
        }
    except Exception as error:
        return {"status": "unavailable", "reason": f"Quantum benchmark failed: {type(error).__name__}: {error}", "runtimeSeconds": round(perf_counter() - started, 3), "affectsProductionRisk": False}
