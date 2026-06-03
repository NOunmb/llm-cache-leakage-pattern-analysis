"""Simple leakage evaluator based on nearest-mean classification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List
import math
import random


@dataclass
class LeakageResult:
    accuracy: float
    random_baseline: float
    leakage_detected: bool
    threshold: float


@dataclass
class PredictionDetails:
    result: LeakageResult
    y_true: List[int]
    y_pred: List[int]


class NearestMeanLeakageEvaluator:
    """Predict the secret by comparing timing vectors to per-secret means."""

    def __init__(self, secret_space: int, seed: int = 7) -> None:
        self.secret_space = secret_space
        self.rng = random.Random(seed)
        self.means: Dict[int, List[float]] = {}

    @staticmethod
    def _distance(a: List[float], b: List[float]) -> float:
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

    def _train_test_split(self, X: List[List[float]], y: List[int], test_ratio: float = 0.3):
        indices = list(range(len(y)))
        self.rng.shuffle(indices)
        split = int(len(indices) * (1.0 - test_ratio))
        train_idx = indices[:split]
        test_idx = indices[split:]
        X_train = [X[i] for i in train_idx]
        y_train = [y[i] for i in train_idx]
        X_test = [X[i] for i in test_idx]
        y_test = [y[i] for i in test_idx]
        return X_train, y_train, X_test, y_test

    def fit(self, X_train: List[List[float]], y_train: List[int]) -> None:
        if not X_train:
            raise ValueError("Training data is empty")
        vector_len = len(X_train[0])
        self.means = {}
        for secret in range(self.secret_space):
            vectors = [x for x, label in zip(X_train, y_train) if label == secret]
            if not vectors:
                continue
            mean = [sum(v[i] for v in vectors) / len(vectors) for i in range(vector_len)]
            self.means[secret] = mean

    def predict_one(self, x: List[float]) -> int:
        if not self.means:
            raise RuntimeError("Evaluator must be fitted before prediction")
        return min(self.means, key=lambda secret: self._distance(x, self.means[secret]))

    def evaluate_with_predictions(self, X: List[List[float]], y: List[int], test_ratio: float = 0.3) -> PredictionDetails:
        """Evaluate and also return test-set predictions for deeper analysis."""
        X_train, y_train, X_test, y_test = self._train_test_split(X, y, test_ratio)
        if not X_test:
            raise ValueError("Testing data is empty; increase n_trials or test_ratio")
        self.fit(X_train, y_train)
        predictions = [self.predict_one(x) for x in X_test]
        correct = sum(int(pred == true) for pred, true in zip(predictions, y_test))
        accuracy = correct / len(y_test)
        random_baseline = 1.0 / self.secret_space

        # A simple engineering threshold for this prototype.
        # Later we can replace this with confidence intervals or statistical tests.
        threshold = random_baseline + 0.15
        leakage_detected = accuracy > threshold
        result = LeakageResult(
            accuracy=accuracy,
            random_baseline=random_baseline,
            leakage_detected=leakage_detected,
            threshold=threshold,
        )
        return PredictionDetails(result=result, y_true=y_test, y_pred=predictions)

    def evaluate(self, X: List[List[float]], y: List[int], test_ratio: float = 0.3) -> LeakageResult:
        return self.evaluate_with_predictions(X, y, test_ratio).result
