from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ClassificationMetrics:
    sample_count: int
    correct_count: int
    accuracy: float | None
    confusion: dict[str, dict[str, int]]


@dataclass(frozen=True, slots=True)
class DetectionMetrics:
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float


def classification_metrics(
    expected: list[str], predicted: list[str]
) -> ClassificationMetrics:
    if len(expected) != len(predicted):
        raise ValueError("expected and predicted must have the same number of labels")
    confusion: dict[str, dict[str, int]] = {}
    correct = 0
    for actual, estimate in zip(expected, predicted):
        if not isinstance(actual, str) or not isinstance(estimate, str):
            raise ValueError("labels must be strings")
        row = confusion.setdefault(actual, {})
        row[estimate] = row.get(estimate, 0) + 1
        correct += actual == estimate
    total = len(expected)
    return ClassificationMetrics(
        sample_count=total,
        correct_count=correct,
        accuracy=correct / total if total else None,
        confusion=confusion,
    )


def evaluate_binary(expected: list[bool], predicted: list[bool]) -> DetectionMetrics:
    """Compute binary metrics only from caller-supplied labels and predictions."""
    if len(expected) != len(predicted):
        raise ValueError("expected and predicted must have the same number of labels")
    if not all(type(value) is bool for value in expected + predicted):
        raise ValueError("binary labels and predictions must be booleans")
    true_positive = sum(actual and estimate for actual, estimate in zip(expected, predicted))
    false_positive = sum(not actual and estimate for actual, estimate in zip(expected, predicted))
    false_negative = sum(actual and not estimate for actual, estimate in zip(expected, predicted))
    true_negative = sum(not actual and not estimate for actual, estimate in zip(expected, predicted))
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    false_positive_rate = (
        false_positive / (false_positive + true_negative)
        if false_positive + true_negative
        else 0.0
    )
    return DetectionMetrics(
        true_positive,
        false_positive,
        false_negative,
        true_negative,
        precision,
        recall,
        f1,
        false_positive_rate,
    )
