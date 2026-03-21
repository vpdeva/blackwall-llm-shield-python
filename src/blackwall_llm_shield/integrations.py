from __future__ import annotations

from typing import Any, Dict, List, Optional

from .core import BlackwallFastAPIMiddleware, BlackwallShield

try:  # pragma: no cover - optional dependency
    from langchain_core.callbacks.base import BaseCallbackHandler
except Exception:  # pragma: no cover - optional dependency
    try:
        from langchain.callbacks.base import BaseCallbackHandler  # type: ignore
    except Exception:  # pragma: no cover - optional dependency
        class BaseCallbackHandler:  # type: ignore
            pass


class BlackwallMiddleware(BlackwallFastAPIMiddleware):
    """Drop-in FastAPI/Starlette middleware alias."""


def _normalize_langchain_messages(messages: Any) -> List[Dict[str, str]]:
    normalized = []
    for message in messages or []:
        role = getattr(message, "type", None) or getattr(message, "role", None) or "user"
        content = getattr(message, "content", None) or ""
        normalized.append({"role": str(role), "content": str(content)})
    return normalized


class BlackwallLangChainCallback(BaseCallbackHandler):
    def __init__(self, shield: BlackwallShield, metadata: Optional[Dict[str, Any]] = None):
        self.shield = shield
        self.metadata = metadata or {}
        self.last_result: Optional[Dict[str, Any]] = None
        self.output_firewall = self.metadata.get("output_firewall")
        self.last_output_review: Optional[Dict[str, Any]] = None

    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any) -> None:
        for prompt in prompts or []:
            guarded = self.shield.guard_model_request(
                messages=[{"role": "user", "content": prompt}],
                metadata={**self.metadata, "framework": "langchain", "serialized": serialized.get("name") if serialized else None, **kwargs},
            )
            self.last_result = guarded
            if not guarded["allowed"]:
                raise ValueError(guarded["reason"])

    def on_chat_model_start(self, serialized: Dict[str, Any], messages: List[List[Any]], **kwargs: Any) -> None:
        for thread in messages or []:
            guarded = self.shield.guard_model_request(
                messages=_normalize_langchain_messages(thread),
                metadata={**self.metadata, "framework": "langchain_chat", "serialized": serialized.get("name") if serialized else None, **kwargs},
            )
            self.last_result = guarded
            if not guarded["allowed"]:
                raise ValueError(guarded["reason"])

    def on_llm_end(self, response: Any, **_: Any) -> Optional[Dict[str, Any]]:
        if self.output_firewall is None:
            return None
        generations = getattr(response, "generations", None) or []
        text = ""
        if generations and generations[0]:
            first = generations[0][0]
            text = getattr(first, "text", None) or getattr(getattr(first, "message", None), "content", "") or ""
        review = self.output_firewall.inspect(text)
        self.last_output_review = review
        if not review["allowed"]:
            raise ValueError("Blackwall blocked model output")
        return review


class BlackwallLlamaIndexCallback:
    def __init__(self, shield: BlackwallShield, metadata: Optional[Dict[str, Any]] = None):
        self.shield = shield
        self.metadata = metadata or {}
        self.last_result: Optional[Dict[str, Any]] = None
        self.output_firewall = self.metadata.get("output_firewall")
        self.last_output_review: Optional[Dict[str, Any]] = None

    async def on_event_start(self, event: Any) -> Dict[str, Any]:
        payload = getattr(event, "payload", None) or {}
        messages = payload.get("messages") or ([{"role": "user", "content": payload.get("prompt")}] if payload.get("prompt") else [])
        guarded = self.shield.guard_model_request(
            messages=messages,
            metadata={**self.metadata, "framework": "llamaindex", "event_type": getattr(event, "type", "unknown")},
        )
        self.last_result = guarded
        if not guarded["allowed"]:
            raise ValueError(guarded["reason"])
        return guarded

    async def on_event_end(self, event: Any) -> Optional[Dict[str, Any]]:
        if self.output_firewall is None:
            return None
        payload = getattr(event, "payload", None) or {}
        text = payload.get("response") or payload.get("output") or ""
        review = self.output_firewall.inspect(text)
        self.last_output_review = review
        if not review["allowed"]:
            raise ValueError("Blackwall blocked model output")
        return review
