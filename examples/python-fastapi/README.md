# FastAPI Example

This example shows a Python gateway that uses Blackwall middleware before requests reach your LLM path, plus a small Streamlit SOC dashboard for visualizing security events.

## Files

- `main.py`
- `streamlit_app.py`
- `requirements.txt`
- `.env.example`

## Notes

- The shield should live in the only outbound LLM path
- `main.py` uses `BlackwallFastAPIMiddleware` for drop-in interception on `/chat`
- `streamlit_app.py` visualizes audit events, alerts, and retrieval-poisoning findings
- Send alerts to your security webhook or SIEM
- Persist the vault only if your workflow truly requires rehydration
