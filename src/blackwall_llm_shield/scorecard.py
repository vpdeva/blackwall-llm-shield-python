from __future__ import annotations

from argparse import ArgumentParser
import json
from pathlib import Path
from typing import Any

from .core import BlackwallShield, run_red_team_suite


def _parse_scalar(value: str) -> Any:
    trimmed = value.strip()
    if trimmed == "true":
        return True
    if trimmed == "false":
        return False
    if trimmed.lstrip("-").isdigit():
        return int(trimmed)
    return trimmed.strip("'\"")


def load_config(path: str) -> Any:
    raw = Path(path).read_text(encoding="utf-8")
    if path.endswith(".json"):
        return json.loads(raw)
    result = {}
    current_list = None
    current_item = None
    for line in raw.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if line[0].isalpha() and ":" in line:
            key, value = line.split(":", 1)
            if value.strip():
                result[key.strip()] = _parse_scalar(value)
                current_list = None
                current_item = None
            else:
                result[key.strip()] = []
                current_list = result[key.strip()]
                current_item = None
            continue
        if line.strip().startswith("- ") and current_list is not None:
            key, value = line.strip()[2:].split(":", 1)
            current_item = {key.strip(): _parse_scalar(value)}
            current_list.append(current_item)
            continue
        if current_item is not None and ":" in line:
            key, value = line.strip().split(":", 1)
            current_item[key.strip()] = _parse_scalar(value)
    return result


def main(argv: Any = None) -> None:
    parser = ArgumentParser(description="Run the Blackwall red-team security scorecard")
    parser.add_argument("command", nargs="?", default="run")
    parser.add_argument("--config")
    parser.add_argument("--shadow-mode", action="store_true")
    parser.add_argument("--prompt-threshold", default="high")
    args = parser.parse_args(argv)
    config = load_config(args.config) if args.config else {}
    shield = BlackwallShield(
        block_on_prompt_injection=True,
        prompt_injection_threshold=args.prompt_threshold,
        shadow_mode=args.shadow_mode,
        **config,
    )
    scorecard = run_red_team_suite(shield, metadata={"source": "cli", "mode": args.command})
    print(json.dumps(scorecard, indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
