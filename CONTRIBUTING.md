# Contributing

Thanks for helping improve the project.

## Good First Issues

- Add more FastAPI and Flask examples for streaming, document review, and tool-gated agents
- Improve `StreamingOutputFirewall` regression coverage with partial-token leak cases
- Expand plugin examples for output scanning, retrieval sanitization, and telemetry enrichment
- Add more multilingual red-team prompts and mutation fixtures to strengthen corpus hardening
- Tighten docs around `generate_coverage_report()` and how to regenerate the checked-in OWASP badge
- Improve lightweight runtime examples and document the tradeoffs versus the full Python runtime

## Development

```bash
python -m unittest discover -s tests
```

## Guidelines

- Keep patches focused
- Add tests for behavior changes
- Prefer understandable rules over complex heuristics
- Document any security tradeoffs clearly
