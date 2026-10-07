"""Anthropic (Claude) call, used when the policy sets provider: anthropic.

The findings come back through a strict report_findings tool call, so they are schema-valid JSON.
Current models (Sonnet 5.5, Opus 5.5) reject forced tool_choice, so the call uses "auto" plus a prompt
instruction, and retries if the model answers without calling the tool."""

from __future__ import annotations

import os

from .llm import FINDINGS_SCHEMA, SYSTEM_PROMPT, GateError, call_with_retries, user_message

__all__ = ["GateError", "review_diff"]

API_URL = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/") + "/v1/messages"
API_VERSION = "2023-06-01"

FINDINGS_TOOL = {
    "name": "report_findings",
    "description": "Report the result of reviewing the pull request diff.",
    "strict": True,
    "input_schema": FINDINGS_SCHEMA,
}


def review_diff(diff: str, policy: dict, api_key: str, retries: int = 3, timeout: int = 300) -> dict:
    payload = {
        "model": policy["model"],
        "max_tokens": policy["max_tokens"],
        "system": SYSTEM_PROMPT + " Always answer by calling the report_findings tool exactly once.",
        "tools": [FINDINGS_TOOL],
        "tool_choice": {"type": "auto"},
        "messages": [{"role": "user", "content": user_message(diff, policy, "Call the report_findings tool once with your result.")}],
    }
    headers = {"x-api-key": api_key, "anthropic-version": API_VERSION}

    for _ in range(2):  # "auto" tool choice does not guarantee a call, so ask once more if it is missing
        body = call_with_retries("Claude", API_URL, headers, payload, retries, timeout)
        stop = body.get("stop_reason")
        if stop == "max_tokens":
            raise GateError("Claude response was cut off (max_tokens). Raise max_tokens or narrow the diff.")
        if stop == "refusal":
            category = (body.get("stop_details") or {}).get("category")
            raise GateError(f"Claude declined to review this diff (refusal, category: {category}).")
        for block in body.get("content", []):
            if block.get("type") == "tool_use" and block.get("name") == "report_findings":
                result = block["input"]
                result.setdefault("findings", [])
                result["usage"] = body.get("usage", {})
                result["model"] = body.get("model", policy["model"])
                return result
    raise GateError("Claude response did not contain a report_findings call.")
