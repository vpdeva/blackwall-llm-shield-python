from __future__ import annotations

from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from typing import Any, Dict

from .core import BlackwallShield, OutputFirewall


def build_sidecar_components() -> Dict[str, Any]:
    shield = BlackwallShield(
        block_on_prompt_injection=True,
        prompt_injection_threshold=os.getenv("BLACKWALL_PROMPT_THRESHOLD", "high"),
        notify_on_risk_level=os.getenv("BLACKWALL_NOTIFY_THRESHOLD", "medium"),
        shadow_mode=os.getenv("BLACKWALL_SHADOW_MODE", "false").lower() == "true",
    )
    firewall = OutputFirewall(risk_threshold=os.getenv("BLACKWALL_OUTPUT_THRESHOLD", "high"))
    return {"shield": shield, "firewall": firewall}


class _SidecarHandler(BaseHTTPRequestHandler):
    components = build_sidecar_components()

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _write_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # pragma: no cover - exercised manually
        if self.path == "/healthz":
            self._write_json({"ok": True, "service": "blackwall-sidecar"})
            return
        self._write_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:  # pragma: no cover - exercised manually
        payload = self._read_json()
        if self.path == "/guard/request":
            result = self.components["shield"].guard_model_request(
                messages=payload.get("messages") or [{"role": "user", "content": payload.get("prompt", "")}],
                metadata=payload.get("metadata") or {},
                allow_system_messages=payload.get("allow_system_messages", False),
            )
            self._write_json(result, status=200 if result.get("allowed") else 403)
            return
        if self.path == "/guard/output":
            result = self.components["firewall"].inspect(payload.get("output"))
            self._write_json(result, status=200 if result.get("allowed") else 422)
            return
        self._write_json({"error": "Not found"}, status=404)


def main(argv: Any = None) -> None:
    parser = ArgumentParser(description="Run the Blackwall sidecar proxy")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    server = HTTPServer((args.host, args.port), _SidecarHandler)
    print(f"Blackwall sidecar running on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":  # pragma: no cover
    main()
