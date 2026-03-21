FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

WORKDIR /app

COPY src /app/src

EXPOSE 8080

CMD ["python", "-m", "blackwall_llm_shield.sidecar", "--host", "0.0.0.0", "--port", "8080"]
