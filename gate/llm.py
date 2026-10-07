"""Provider-neutral pieces of the review call: prompt, findings schema, HTTP retries and provider dispatch."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from .config import PROVIDERS, SEVERITIES
from .http_client import build_request

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
findings."""

# JSON Schema for the result. Every property is required and objects are closed, which both
# Anthropic strict tools and Groq strict json_schema mode require.
FINDINGS_SCHEMA = {
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
}

class GateError(RuntimeError):
    """The gate could not produce a verdict (as opposed to a FAIL verdict)."""


def user_message(diff: str, policy: dict, closing: str) -> str:
    text = "Review this pull request diff.\n\n"
    if policy.get("extra_instructions"):
        text += f"Project-specific rules:\n{policy['extra_instructions'].strip()}\n\n"
    return text + f"<diff>\n{diff}\n</diff>\n\n{closing}"


def post_json(url: str, headers: dict, payload: dict, timeout: int) -> dict:
    req = build_request(
        url,
        data=json.dumps(payload).encode(),
        headers={**headers, "content-type": "application/json", "accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def call_with_retries(label: str, url: str, headers: dict, payload: dict, retries: int, timeout: int) -> dict:
    """POST with backoff on 429, 498 (Groq flex capacity) and 5xx. Other 4xx are config problems and fail at once."""
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            return post_json(url, headers, payload, timeout)
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code not in (429, 498) and e.code < 500:
                detail = e.read().decode(errors="replace")[:500]
                if "error code: 1010" in detail:
                    detail += " (Cloudflare blocked the request signature, usually the User-Agent)"
                raise GateError(f"{label} API returned {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
        if attempt + 1 < retries:
            time.sleep(2 ** (attempt + 1))
    raise GateError(f"{label} API unreachable after {retries} attempts: {last_err}")


def review_diff(diff: str, policy: dict, api_key: str) -> dict:
    """Send the diff to the provider named in the policy and return {summary, findings, model, usage}."""
    provider = policy.get("provider", "groq")
    if provider == "groq":
        from . import groq

        return groq.review_diff(diff, policy, api_key)
    if provider == "anthropic":
        from . import claude

        return claude.review_diff(diff, policy, api_key)
    raise GateError(f"Unknown provider {provider!r}; use one of {', '.join(PROVIDERS)}.")
