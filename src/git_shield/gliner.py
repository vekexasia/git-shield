"""GLiNER-based PII detector as a lighter alternative to OpenAI Privacy Filter.

GLiNER (Generalist and Lightweight Named Entity Recognition) is a BERT-based
model that can detect arbitrary entity types including PII categories. It runs
significantly faster on CPU than OPF and uses less memory.

Install: pip install gliner
"""

from __future__ import annotations

import importlib

from .opf import PrivacyDetector, PrivacyFinding
from .output import info
from .structured import merge_findings, structured_findings


# Mapping from GLiNER entity types to our label names
_GLINER_LABEL_MAP = {
    "phone number": "private_phone",
    "telephone number": "private_phone",
    "person": "private_person",
    "person name": "private_person",
    "name": "private_person",
    "address": "private_address",
    "date of birth": "private_date",
    "account number": "account_number",
    "credit card number": "secret",
    "password": "secret",
    "api key": "secret",
}


_GLINER_LABELS = list(_GLINER_LABEL_MAP.keys())


class GLiNERDetector:
    """PII detector using GLiNER.

    Falls back gracefully if gliner is not installed.
    """

    def __init__(
        self,
        model_name: str = "urchade/gliner_medium-v2.1",
        device: str = "cpu",
        threshold: float = 0.5,
    ) -> None:
        self._model_name = model_name
        self._device = device
        self._threshold = threshold
        self._model = None

    def _load_model(self):
        """Lazy-load the GLiNER model."""
        if self._model is not None:
            return self._model
        try:
            gliner = importlib.import_module("gliner")
        except ImportError:
            raise RuntimeError(
                "gliner package not installed. Install with: pip install gliner"
            )
        info(f"Loading GLiNER model {self._model_name} on {self._device}...")
        self._model = gliner.GLiNER.from_pretrained(self._model_name)
        if self._device != "cpu":
            try:
                self._model = self._model.to(self._device)
            except Exception:
                info(f"Could not move model to {self._device}, using CPU.")
        return self._model

    def detect(self, text: str) -> list[PrivacyFinding]:
        return self.detect_many([text])[0] if text.strip() else []

    def detect_many(self, texts: list[str]) -> list[list[PrivacyFinding]]:
        if not texts:
            return []

        out: list[list[PrivacyFinding]] = []
        model = self._load_model()
        for text in texts:
            if not text.strip():
                out.append([])
                continue

            findings = structured_findings(text)
            entities = model.predict_entities(
                text,
                _GLINER_LABELS,
                threshold=self._threshold,
            )
            seen = {(f.label, f.start, f.end, f.text) for f in findings}
            for entity in entities:
                label = _GLINER_LABEL_MAP.get(entity.get("label", ""), entity.get("label", ""))
                if not label:
                    continue
                start = entity.get("start")
                end = entity.get("end")
                text_value = entity.get("text", "")
                key = (label, start, end, text_value)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(PrivacyFinding(
                    label=label,
                    text=text_value,
                    start=start,
                    end=end,
                ))
            out.append(findings)
        return out


def create_gliner_detector(
    model_name: str = "urchade/gliner_medium-v2.1",
    device: str = "cpu",
    threshold: float = 0.5,
) -> PrivacyDetector | None:
    """Create a GLiNER detector, returning None if gliner is not installed."""
    try:
        importlib.import_module("gliner")
    except ImportError:
        return None
    return GLiNERDetector(model_name=model_name, device=device, threshold=threshold)
