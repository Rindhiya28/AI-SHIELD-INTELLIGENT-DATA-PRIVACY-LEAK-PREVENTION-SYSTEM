"""Risk scoring (risk-service): rubric, feature extraction and Random Forest classifier."""
from __future__ import annotations

from collections import Counter
from typing import Iterable, List, Sequence

import numpy as np

from .detector import Entity

TYPES = ["PERSON", "EMAIL", "PHONE", "STUDENT_ID", "ID_NUMBER", "ADDRESS", "DATE_OF_BIRTH"]
HIGH_TYPES = {"STUDENT_ID", "ID_NUMBER", "ADDRESS"}
LEVELS = ["LOW", "MEDIUM", "HIGH"]


def rubric_label(entity_types: Sequence[str]) -> str:
    """Documented rubric used to label training documents and as the rule baseline."""
    types = list(entity_types)
    distinct = set(types)
    if distinct & HIGH_TYPES or ("PERSON" in distinct and len(distinct - {"PERSON"}) >= 2):
        return "HIGH"
    if len(types) == 0 or (len(types) == 1 and types[0] in {"EMAIL", "PERSON"}):
        return "LOW"
    return "MEDIUM"


def features(entities: Iterable[Entity], text_len: int) -> List[float]:
    ents = list(entities)
    c = Counter(e.type for e in ents)
    distinct = set(c)
    density = 1000.0 * len(ents) / max(text_len, 1)
    mean_conf = float(np.mean([e.confidence for e in ents])) if ents else 0.0
    return [c.get(t, 0) for t in TYPES] + [
        density, int(bool(distinct & HIGH_TYPES)), int("PERSON" in distinct and len(distinct) > 1), len(distinct), mean_conf]


def train_model(X: np.ndarray, y: Sequence[str], seed: int = 42):
    from sklearn.ensemble import RandomForestClassifier
    model = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=seed)
    model.fit(X, y)
    return model
