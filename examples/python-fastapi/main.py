import os

from fastapi import FastAPI, Request
from pydantic import BaseModel

from blackwall_llm_shield import BlackwallFastAPIMiddleware, BlackwallShield


app = FastAPI(title="Blackwall LLM Shield Gateway")


class ChatPayload(BaseModel):
    messages: list[dict]
    tenant_id: str | None = None
    user_id: str | None = None


shield = BlackwallShield(
    block_on_prompt_injection=True,
    prompt_injection_threshold="high",
    notify_on_risk_level="medium",
    shadow_mode=True,
    shadow_policy_packs=["healthcare", "finance"],
    webhook_url=os.getenv("BLACKWALL_ALERT_WEBHOOK_URL"),
)
app.add_middleware(BlackwallFastAPIMiddleware, shield=shield, path_prefixes=["/chat"])


@app.post("/chat")
async def guarded_chat(payload: ChatPayload, request: Request):
    guarded = getattr(request.state, "blackwall", None)
    # Replace this section with your actual model invocation.
    return {
        "ok": True,
        "guarded_messages": guarded["messages"] if guarded else payload.messages,
        "report": guarded["report"] if guarded else None,
        "note": "Call your model provider here with guarded_messages.",
    }
