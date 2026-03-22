from __future__ import annotations

from typing import Any, Dict, Optional

import re

from .core import detect_prompt_injection, mask_text


EDGE_PATTERNS = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b")),
    ("API_KEY", re.compile(r"\b(?:sk|rk|pk|api)[-_][A-Za-z0-9_-]{8,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b")),
    ("BEARER", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b", re.IGNORECASE)),
    ("PHONE", re.compile(r"(\+?\d{1,3}[\s-]?)?(\(0\d\)|0\d|\(?\d{2,4}\)?)[\s-]?\d{3,4}[\s-]?\d{3,4}\b")),
]


def mask_text_lite(text: Any) -> Dict[str, Any]:
    masked = str(text or "")
    vault: Dict[str, str] = {}
    for label, pattern in EDGE_PATTERNS:
        masked = pattern.sub(lambda match: _replace_with_token(label, match.group(0), vault), masked)
    return {"masked": masked, "vault": vault, "has_sensitive_data": bool(vault)}


def _replace_with_token(label: str, value: str, vault: Dict[str, str]) -> str:
    token = f"[{label}_{len(vault) + 1}]"
    vault[token] = value
    return token


class LiteBlackwallShield:
    def guard_model_request(self, messages: Any, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        text = "\n".join(str((message or {}).get("content", "")) for message in (messages or []))
        masked = mask_text_lite(text) if metadata and metadata.get("edge_mode") else mask_text(text)
        injection = detect_prompt_injection(text)
        return {
            "allowed": not injection["blocked_by_default"],
            "blocked": injection["blocked_by_default"],
            "reason": "Prompt injection risk exceeded lite threshold" if injection["blocked_by_default"] else None,
            "messages": messages,
            "report": {
                "metadata": metadata or {},
                "prompt_injection": injection,
                "sensitive_data": masked,
            },
            "vault": masked["vault"],
        }
