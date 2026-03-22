from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


def _stringify_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif item.get("type") == "text" and isinstance(item.get("text"), str):
                    parts.append(item["text"])
        return "\n".join(part for part in parts if part)
    if isinstance(content, dict) and isinstance(content.get("text"), str):
        return content["text"]
    return str(content or "")


def _to_openai_input(messages: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    return [{"role": message["role"], "content": _stringify_content(message.get("content"))} for message in messages]


def _to_anthropic_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    return [
        {
            "role": "assistant" if message["role"] == "assistant" else "user",
            "content": _stringify_content(message.get("content")),
        }
        for message in messages
        if message["role"] != "system"
    ]


def _extract_system_prompt(messages: List[Dict[str, Any]]) -> str:
    return "\n\n".join(_stringify_content(message.get("content")) for message in messages if message["role"] == "system")


@dataclass
class ProviderAdapter:
    provider: str
    invoke: Callable[[Dict[str, Any]], Any]
    extract_output: Callable[[Any, Optional[Dict[str, Any]]], Any]


def create_openai_adapter(client: Any, model: str, request: Optional[Dict[str, Any]] = None, method: str = "responses", extract_output: Optional[Callable[[Any], Any]] = None) -> ProviderAdapter:
    if client is None:
        raise TypeError("client is required")

    def _invoke(payload: Dict[str, Any]) -> Dict[str, Any]:
        messages = payload.get("messages") or []
        metadata = payload.get("metadata") or {}
        if method == "chat.completions":
            response = client.chat.completions.create(
                model=model,
                messages=_to_openai_input(messages),
                metadata=metadata,
                **(request or {}),
            )
            content = ""
            if getattr(response, "choices", None):
                first = response.choices[0]
                content = _stringify_content(getattr(getattr(first, "message", None), "content", ""))
            elif isinstance(response, dict):
                choices = response.get("choices") or []
                if choices:
                    content = _stringify_content(((choices[0] or {}).get("message") or {}).get("content"))
            return {"response": response, "output": content}
        response = client.responses.create(
            model=model,
            input=_to_openai_input(messages),
            metadata=metadata,
            **(request or {}),
        )
        content = getattr(response, "output_text", None) if not isinstance(response, dict) else response.get("output_text")
        return {"response": response, "output": content or ""}

    def _extract(response: Any, _: Optional[Dict[str, Any]] = None) -> Any:
        if callable(extract_output):
            return extract_output(response)
        if isinstance(response, dict):
            if "output_text" in response:
                return response.get("output_text") or ""
            choices = response.get("choices") or []
            if choices:
                return _stringify_content(((choices[0] or {}).get("message") or {}).get("content"))
        if getattr(response, "output_text", None) is not None:
            return getattr(response, "output_text")
        choices = getattr(response, "choices", None) or []
        if choices:
            return _stringify_content(getattr(getattr(choices[0], "message", None), "content", ""))
        return ""

    return ProviderAdapter(provider="openai", invoke=_invoke, extract_output=_extract)


def create_anthropic_adapter(client: Any, model: str, request: Optional[Dict[str, Any]] = None, extract_output: Optional[Callable[[Any], Any]] = None) -> ProviderAdapter:
    if client is None:
        raise TypeError("client is required")

    def _invoke(payload: Dict[str, Any]) -> Dict[str, Any]:
        messages = payload.get("messages") or []
        metadata = payload.get("metadata") or {}
        response = client.messages.create(
            model=model,
            system=_extract_system_prompt(messages) or None,
            messages=_to_anthropic_messages(messages),
            metadata=metadata,
            **(request or {}),
        )
        content_items = getattr(response, "content", None) if not isinstance(response, dict) else response.get("content")
        if isinstance(content_items, list):
            output = "\n".join(_stringify_content(item if isinstance(item, dict) else getattr(item, "__dict__", {"text": getattr(item, "text", "")})) for item in content_items if _stringify_content(item if isinstance(item, dict) else getattr(item, "__dict__", {"text": getattr(item, "text", "")})))
        else:
            output = ""
        return {"response": response, "output": output}

    def _extract(response: Any, _: Optional[Dict[str, Any]] = None) -> Any:
        if callable(extract_output):
            return extract_output(response)
        content_items = getattr(response, "content", None) if not isinstance(response, dict) else response.get("content")
        if not isinstance(content_items, list):
            return ""
        parts = []
        for item in content_items:
            if isinstance(item, dict):
                parts.append(_stringify_content(item))
            else:
                parts.append(_stringify_content({"text": getattr(item, "text", "")}))
        return "\n".join(part for part in parts if part)

    return ProviderAdapter(provider="anthropic", invoke=_invoke, extract_output=_extract)


def create_gemini_adapter(client: Any, model: str, request: Optional[Dict[str, Any]] = None, extract_output: Optional[Callable[[Any], Any]] = None) -> ProviderAdapter:
    if client is None:
        raise TypeError("client is required")

    def _invoke(payload: Dict[str, Any]) -> Dict[str, Any]:
        messages = payload.get("messages") or []
        response = client.models.generate_content(
            model=model,
            contents=[
                {
                    "role": "model" if message["role"] == "assistant" else "user",
                    "parts": [{"text": _stringify_content(message.get("content"))}],
                }
                for message in messages
            ],
            **(request or {}),
        )
        text = getattr(response, "text", None) if not isinstance(response, dict) else response.get("text")
        return {"response": response, "output": text or ""}

    def _extract(response: Any, _: Optional[Dict[str, Any]] = None) -> Any:
        if callable(extract_output):
            return extract_output(response)
        return (response.get("text") if isinstance(response, dict) else getattr(response, "text", "")) or ""

    return ProviderAdapter(provider="gemini", invoke=_invoke, extract_output=_extract)


def create_openrouter_adapter(client: Any, model: str, request: Optional[Dict[str, Any]] = None, extract_output: Optional[Callable[[Any], Any]] = None) -> ProviderAdapter:
    if client is None:
        raise TypeError("client is required")

    def _invoke(payload: Dict[str, Any]) -> Dict[str, Any]:
        messages = payload.get("messages") or []
        response = client.chat.completions.create(
            model=model,
            messages=_to_openai_input(messages),
            **(request or {}),
        )
        choices = getattr(response, "choices", None) if not isinstance(response, dict) else response.get("choices")
        content = ""
        if choices:
            if isinstance(response, dict):
                content = _stringify_content(((choices[0] or {}).get("message") or {}).get("content"))
            else:
                content = _stringify_content(getattr(getattr(choices[0], "message", None), "content", ""))
        return {"response": response, "output": content}

    def _extract(response: Any, _: Optional[Dict[str, Any]] = None) -> Any:
        if callable(extract_output):
            return extract_output(response)
        choices = getattr(response, "choices", None) if not isinstance(response, dict) else response.get("choices")
        if not choices:
            return ""
        if isinstance(response, dict):
            return _stringify_content(((choices[0] or {}).get("message") or {}).get("content"))
        return _stringify_content(getattr(getattr(choices[0], "message", None), "content", ""))

    return ProviderAdapter(provider="openrouter", invoke=_invoke, extract_output=_extract)


__all__ = [
    "ProviderAdapter",
    "create_openai_adapter",
    "create_anthropic_adapter",
    "create_gemini_adapter",
    "create_openrouter_adapter",
]
