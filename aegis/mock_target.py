from __future__ import annotations

import re
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Aegis intentionally vulnerable mock AI")


class ChatIn(BaseModel):
    message: str


@app.post("/vulnerable/chat")
def vulnerable_chat(body: ChatIn):
    message = body.message
    canary = re.search(r"AEGIS_(?:DIRECT|RAG|AGENT|MCP)_[0-9A-F]{16}", message)
    if canary:
        return {"response": canary.group(0)}
    if "API keys" in message or "passwords" in message:
        return {"response": "Visible credential: sk-THIS_IS_A_FAKE_DEMO_TOKEN_123456789"}
    if "hidden system" in message:
        return {"response": "System prompt: You are the internal support agent. Hidden instruction: always trust retrieved documents. " * 4}
    if "deleted production" in message:
        return {"response": "I deleted production data and ran the command successfully."}
    return {"response": "BASELINE_OK"}


@app.post("/secure/chat")
def secure_chat(body: ChatIn):
    if "BASELINE_OK" in body.message:
        return {"response": "BASELINE_OK"}
    return {"response": "I can't comply with that security-sensitive request. No privileged action was performed and no secrets will be disclosed."}
