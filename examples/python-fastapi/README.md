# FastAPI Example

This example shows a Python gateway that blocks risky prompts before they reach an LLM provider.

## Files

- `main.py`
- `requirements.txt`
- `.env.example`

## Notes

- The shield should live in the only outbound LLM path
- Send alerts to your security webhook or SIEM
- Persist the vault only if your workflow truly requires rehydration

