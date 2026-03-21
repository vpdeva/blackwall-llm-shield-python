from __future__ import annotations

from argparse import ArgumentParser
import json
from typing import Any

from .core import BlackwallShield, run_red_team_suite


def main(argv: Any = None) -> None:
    parser = ArgumentParser(description="Run the Blackwall red-team security scorecard")
    parser.add_argument("--shadow-mode", action="store_true")
    parser.add_argument("--prompt-threshold", default="high")
    args = parser.parse_args(argv)
    shield = BlackwallShield(
        block_on_prompt_injection=True,
        prompt_injection_threshold=args.prompt_threshold,
        shadow_mode=args.shadow_mode,
    )
    scorecard = run_red_team_suite(shield, metadata={"source": "cli"})
    print(json.dumps(scorecard, indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
