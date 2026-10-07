"""Groq call (OpenAI-compatible chat completions). The default provider.

Findings come back through response_format json_schema. On models that support strict mode
(qwen/qwen3.8-27b, openai/gpt-oss-20b, openai/gpt-oss-120b) Groq uses constrained decoding, so the
content always matches FINDINGS_SCHEMA. Other models get best-effort mode, so the result is still checked.
Docs: https://console.groq.com/docs/structured-outputs"""

from __future__ import annotations

import json
import os

from .llm import FINDINGS_SCHEMA, SYSTEM_PROMPT, GateError, call_with_retries, user_message

API_URL = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/") + "/chat/completions"

STRICT_MODELS = {"qwen/qwen3.8-27b", "openai/gpt-oss-20b", "openai/gpt-oss-120b"}


def build_payload(diff: str, policy: dict) -> dict:
    model = policy["model"]
    payload = {
        "model": model,
        "max_completion_tokens": policy["max_tokens"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT + "\nAnswer only with JSON that matches the report_findings schema."},
            {"role": "user", "content": user_message(diff, policy, "Return your result as report_findings JSON.")},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "report_findings", "strict": model in STRICT_MODELS, "schema": FINDINGS_SCHEMA},
        },
    }
    if model.startswith("qwen/"):
        # Qwen reasoning output must be "parsed" or "hidden" when JSON mode is on; we only need the answer.
        payload["reasoning_format"] = "hidden"
    return payload


def _parse(content: str | None) -> dict | None:
    try:
        result = json.loads(content or "")
    except json.JSONDecodeError:
        return None
    if not isinstance(result, dict) or not isinstance(result.get("findings", []), list):
        return None
    return result


def review_diff(diff: str, policy: dict, api_key: str, retries: int = 3, timeout: int = 300) -> dict:
    payload = build_payload(diff, policy)
    headers = {"authorization": f"Bearer {api_key}"}

    for _ in range(2):  # best-effort models can return unusable JSON, so ask once more
        body = call_with_retries("Groq", API_URL, headers, payload, retries, timeout)
        choice = (body.get("choices") or [{}])[0]
        if choice.get("finish_reason") == "length":
            raise GateError("Groq response was cut off (finish_reason: length). Raise max_tokens or narrow the diff.")
        result = _parse((choice.get("message") or {}).get("content"))
        if result is not None:
            result.setdefault("summary", "")
            result.setdefault("findings", [])
            result["usage"] = body.get("usage", {})
            result["model"] = body.get("model", policy["model"])
            return result
    raise GateError("Groq response did not contain valid report_findings JSON.")
