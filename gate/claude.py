"""Claude API call. The findings come back through a strict report_findings tool call, so they are schema-valid JSON.

Current models (Sonnet 5.5, Opus 5.5) reject forced tool_choice, so the call uses "auto" plus a prompt
instruction, and retries if the model answers without calling the tool."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from .config import SEVERITIES

API_URL = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/") + "/v1/messages"
API_VERSION = "2023-06-01"

SYSTEM_PROMPT = """You are a senior application-security and code-quality reviewer acting as a merge gate.
You review ONLY the lines added or changed in the diff. Context lines are there to help you understand them.

Report real, specific problems:
- security: injection (SQL, command, template), XSS, SSRF, path traversal, broken auth or access control,
  hard-coded secrets, insecure crypto, unsafe deserialization, missing input validation, sensitive data in logs
  (map to OWASP Top 10 / CWE where it fits)
- quality: bugs, unhandled errors, race conditions, resource leaks, dead or unreachable code,
  obvious performance problems, missing tests for risky logic

Severity guide:
- critical: exploitable now, or data loss / full compromise (e.g. SQL injection on user input, leaked prod secret)
- high: likely security hole or bug that will hit users
- medium: real weakness that needs a fix but is not immediately exploitable
- low: maintainability or minor robustness issue
- info: suggestion only

Do not report style nits, formatting, or speculation about code you cannot see. If the diff is fine, return no
findings. Always answer by calling the report_findings tool exactly once."""

FINDINGS_TOOL = {
    "name": "report_findings",
    "description": "Report the result of reviewing the pull request diff.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "summary": {"type": "string", "description": "Two or three sentences on the overall state of the change."},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "severity": {"type": "string", "enum": SEVERITIES},
                        "category": {"type": "string", "enum": ["security", "quality"]},
                        "title": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "description": "Line number in the new file, 0 if unknown."},
                        "description": {"type": "string"},
                        "recommendation": {"type": "string"},
                        "reference": {"type": "string", "description": "CWE / OWASP id if relevant, else empty."},
                    },
                    "required": ["severity", "category", "title", "file", "line", "description", "recommendation", "reference"],
                },
            },
        },
        "required": ["summary", "findings"],
    },
}


class GateError(RuntimeError):
    """The gate could not produce a verdict (as opposed to a FAIL verdict)."""


def _post(payload: dict, api_key: str, timeout: int) -> dict:
    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode(),
        headers={
            "x-api-key": api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def review_diff(diff: str, policy: dict, api_key: str, retries: int = 3, timeout: int = 300) -> dict:
    user = "Review this pull request diff.\n\n"
    if policy.get("extra_instructions"):
        user += f"Project-specific rules:\n{policy['extra_instructions'].strip()}\n\n"
    user += f"<diff>\n{diff}\n</diff>\n\nCall the report_findings tool once with your result."

    payload = {
        "model": policy["model"],
        "max_tokens": policy["max_tokens"],
        "system": SYSTEM_PROMPT,
        "tools": [FINDINGS_TOOL],
        "tool_choice": {"type": "auto"},
        "messages": [{"role": "user", "content": user}],
    }

    for _ in range(2):  # "auto" tool choice does not guarantee a call, so ask once more if it is missing
        body = _call(payload, api_key, retries, timeout)
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


def _call(payload: dict, api_key: str, retries: int, timeout: int) -> dict:
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            return _post(payload, api_key, timeout)
        except urllib.error.HTTPError as e:
            last_err = e
            # 429 rate limit, 5xx and 529 overloaded are worth retrying; 4xx is a config problem.
            if e.code != 429 and e.code < 500:
                detail = e.read().decode(errors="replace")[:500]
                raise GateError(f"Claude API returned {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
        if attempt + 1 < retries:
            time.sleep(2 ** (attempt + 1))
    raise GateError(f"Claude API unreachable after {retries} attempts: {last_err}")
