# Running Examples

This page is wiki-ready and can be copied directly into the GitHub Wiki for the Python package if you want the examples guide to live there permanently.

## Available Examples

- `examples/python-fastapi`

## FastAPI Gateway Example

Path: [`examples/python-fastapi`](/Users/vishnu/Documents/blackwall-llm-shield/blackwall-llm-shield-python/examples/python-fastapi)

This example shows a Python gateway that applies Blackwall middleware before requests reach your LLM route, plus a small Streamlit dashboard for security visibility.

### Run the API

1. Create and activate a virtual environment.
2. Install the example requirements.
3. Copy environment values from [`.env.example`](/Users/vishnu/Documents/blackwall-llm-shield/blackwall-llm-shield-python/examples/python-fastapi/.env.example).
4. Start the API:

```bash
cd examples/python-fastapi
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

The API will start on `http://127.0.0.1:8000`.

### Run the Dashboard

In a second terminal, from the same folder:

```bash
source .venv/bin/activate
streamlit run streamlit_app.py
```

### What It Demonstrates

- `BlackwallFastAPIMiddleware` on `/chat`
- request interception before model access
- telemetry and audit-friendly event handling
- a simple local dashboard for security operations

### Main Files

- [`main.py`](/Users/vishnu/Documents/blackwall-llm-shield/blackwall-llm-shield-python/examples/python-fastapi/main.py)
- [`streamlit_app.py`](/Users/vishnu/Documents/blackwall-llm-shield/blackwall-llm-shield-python/examples/python-fastapi/streamlit_app.py)
- [`dashboard_model.py`](/Users/vishnu/Documents/blackwall-llm-shield/blackwall-llm-shield-python/examples/python-fastapi/dashboard_model.py)
- [`requirements.txt`](/Users/vishnu/Documents/blackwall-llm-shield/blackwall-llm-shield-python/examples/python-fastapi/requirements.txt)

## Suggested Wiki Placement

If you want this to live in the GitHub Wiki instead of the repo tree, publish it as:

- `Running Examples`

and keep the in-repo copy as the source of truth for future edits.
