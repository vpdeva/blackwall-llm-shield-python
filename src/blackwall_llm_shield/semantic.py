from __future__ import annotations

from typing import Any, Dict, Optional

from .core import LightweightIntentScorer


class FastTextIntentScorer:
    def __init__(self, model: Any, threshold: float = 0.5):
        self.model = model
        self.threshold = threshold

    def score(self, text: Any, _: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        labels, probabilities = self.model.predict(str(text or ""), k=2)
        matches = []
        total = 0
        for label, probability in zip(labels, probabilities):
            normalized = str(label).replace("__label__", "")
            if normalized in {"jailbreak", "prompt_injection", "unsafe"} and probability >= self.threshold:
                score = min(40, int(probability * 40))
                total += score
                matches.append({
                    "id": f"fasttext_{normalized}",
                    "score": score,
                    "reason": f"Local semantic model flagged {normalized} intent",
                    "probability": round(float(probability), 3),
                })
        return {"score": min(total, 40), "matches": matches}


def load_local_intent_scorer(model_path: Optional[str] = None, threshold: float = 0.5) -> Any:
    try:  # pragma: no cover - optional dependency
        import fasttext  # type: ignore

        if model_path:
            return FastTextIntentScorer(fasttext.load_model(model_path), threshold=threshold)
    except Exception:
        pass
    return LightweightIntentScorer()
