from __future__ import annotations

from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import ipaddress
import json
import os
import sys
from typing import Any, Dict

from .core import BlackwallShield, OutputFirewall, StreamingOutputFirewall


def build_sidecar_components() -> Dict[str, Any]:
    shield = BlackwallShield(
        block_on_prompt_injection=True,
        prompt_injection_threshold=os.getenv("BLACKWALL_PROMPT_THRESHOLD", "high"),
        notify_on_risk_level=os.getenv("BLACKWALL_NOTIFY_THRESHOLD", "medium"),
        shadow_mode=os.getenv("BLACKWALL_SHADOW_MODE", "false").lower() == "true",
    )
    firewall = OutputFirewall(risk_threshold=os.getenv("BLACKWALL_OUTPUT_THRESHOLD", "high"))
    stream_firewall = StreamingOutputFirewall(output_firewall=firewall)
    return {"shield": shield, "firewall": firewall, "stream_firewall": stream_firewall}


MAX_BODY_BYTES = int(os.getenv("BLACKWALL_MAX_BODY_BYTES", str(1024 * 1024)))


class _SidecarHandler(BaseHTTPRequestHandler):
    components = build_sidecar_components()

    server_version = "blackwall-sidecar"
    sys_version = ""
    allow_no_auth = False

    def log_message(self, fmt: str, *args: Any) -> None:  # never log request bodies or headers
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _authorized(self) -> bool:
        expected = os.getenv("BLACKWALL_API_KEY", "")
        if not expected:
            return self.allow_no_auth
        provided = self.headers.get("X-Blackwall-Api-Key") or ""
        return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))

    def _read_json(self) -> Any:  # returns dict, None for malformed, or 'too_large'
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self.close_connection = True
            return "too_large"
        if "json" not in (self.headers.get("Content-Type") or "").lower():
            return None
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return None
        return data if isinstance(data, dict) else None

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
        if not self._authorized():
            self._write_json({"error": "Unauthorized"}, status=401)
            return
        payload = self._read_json()
        if payload == "too_large":
            self._write_json({"error": "Request body is larger than %d bytes." % MAX_BODY_BYTES}, status=413)
            return
        if payload is None:
            self._write_json({"error": "Send a JSON object under %d bytes with Content-Type: application/json." % MAX_BODY_BYTES}, status=400)
            return
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
        if self.path == "/guard/stream":
            chunks = payload.get("chunks") or []
            latest = {"allowed": True, "blocked": False, "review": None}
            for chunk in chunks:
                latest = self.components["stream_firewall"].ingest(chunk)
                if latest.get("blocked"):
                    break
            self._write_json(latest, status=200 if latest.get("allowed") else 422)
            return
        self._write_json({"error": "Not found"}, status=404)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: Any = None) -> None:
    parser = ArgumentParser(description="Run the Blackwall sidecar proxy")
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind; loopback by default")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--allow-no-auth", action="store_true", help="permit requests without BLACKWALL_API_KEY (loopback only)")
    args = parser.parse_args(argv)
    has_key = bool(os.getenv("BLACKWALL_API_KEY"))
    if not has_key and not args.allow_no_auth:
        parser.error("set BLACKWALL_API_KEY, or pass --allow-no-auth for a loopback-only development run")
    if not has_key and not _is_loopback(args.host):
        parser.error("refusing to serve without BLACKWALL_API_KEY on a non-loopback interface")
    if has_key and len(os.getenv("BLACKWALL_API_KEY", "")) < 32:
        parser.error("BLACKWALL_API_KEY must be at least 32 characters")
    _SidecarHandler.allow_no_auth = args.allow_no_auth and not has_key
    server = ThreadingHTTPServer((args.host, args.port), _SidecarHandler)
    server.daemon_threads = True
    print(f"Blackwall sidecar running on http://{args.host}:{args.port}" + ("" if has_key else " (no auth, loopback only)"))
    server.serve_forever()


if __name__ == "__main__":  # pragma: no cover
    main()
