"""Gemini chatbot routed through the CentralWatch credential firewall."""

import re

import httpx
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator


router = APIRouter(prefix="/chat", tags=["chat"])


class ChatPrompt(BaseModel):
    """One text-generation request from the demo dashboard."""

    prompt: str = Field(min_length=1, max_length=8000)
    model: str = Field(default="gemini-3.8-flash", min_length=1, max_length=100)

    @field_validator("prompt")
    @classmethod
    def clean_prompt(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("prompt must not be blank")
        return value

    @field_validator("model")
    @classmethod
    def validate_model(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", value):
            raise ValueError("model contains unsupported characters")
        return value


def _gemini_error(payload: object, status_code: int) -> str:
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            return error["message"]
        if isinstance(payload.get("detail"), str):
            return payload["detail"]
    return f"Gemini request failed through CentralWatch ({status_code})."


@router.post("", summary="Send a prompt to Gemini through CentralWatch")
async def chat_with_gemini(
    body: ChatPrompt,
    request: Request,
    proxy_token: str = Header(default="", alias="X-CentralWatch-Proxy-Token"),
):
    """Use a proxy token while keeping the Gemini API key inside CentralWatch."""

    if not proxy_token:
        raise HTTPException(status_code=403, detail="A CentralWatch Gemini proxy token is required.")

    port = request.app.state.settings.port
    proxy_url = (
        f"http://127.0.0.1:{port}/centralwatch/proxy/gemini_api/"
        f"models/{body.model}:generateContent"
    )
    gemini_body = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": body.prompt}],
            }
        ]
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                proxy_url,
                json=gemini_body,
                headers={"X-CentralWatch-Proxy-Token": proxy_token},
                timeout=70.0,
            )
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="The CentralWatch Gemini request timed out.") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="CentralWatch could not be reached.") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Gemini returned an invalid response.") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=_gemini_error(payload, response.status_code))

    candidates = payload.get("candidates", []) if isinstance(payload, dict) else []
    parts = candidates[0].get("content", {}).get("parts", []) if candidates else []
    reply = "\n".join(
        part["text"] for part in parts if isinstance(part, dict) and isinstance(part.get("text"), str)
    ).strip()
    if not reply:
        block_reason = payload.get("promptFeedback", {}).get("blockReason") if isinstance(payload, dict) else None
        detail = f"Gemini did not return text{f' ({block_reason})' if block_reason else ''}."
        raise HTTPException(status_code=502, detail=detail)

    return {
        "reply": reply,
        "model": body.model,
        "finish_reason": candidates[0].get("finishReason"),
    }
