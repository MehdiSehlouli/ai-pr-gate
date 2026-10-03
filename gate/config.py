"""Policy loading. Every key has a default, so an empty policy file is valid."""

from __future__ import annotations

import copy
from pathlib import Path

import yaml

SEVERITIES = ["critical", "high", "medium", "low", "info"]

DEFAULTS = {
    "model": "claude-sonnet-5-5",
    "max_tokens": 16000,
    # Fail the PR if any finding is at or above this severity.
    "fail_on": "high",
    # Optional per-severity caps, e.g. {"medium": 5} fails on the 6th medium finding.
    "max_findings": {},
    # What to do when the gate itself breaks (API down, bad response): "fail" or "pass".
    "on_error": "fail",
    "diff": {
        "max_chars": 120_000,
        "include": ["**"],
        "exclude": [
            "**/*.lock",
            "**/package-lock.json",
            "**/yarn.lock",
            "**/poetry.lock",
            "**/*.min.js",
            "**/*.map",
            "**/*.svg",
            "**/*.png",
            "**/*.jpg",
            "**/vendor/**",
            "**/node_modules/**",
            "**/dist/**",
            "**/migrations/**",
        ],
    },
    # Extra project-specific rules appended to the review prompt.
    "extra_instructions": "",
    "notify": {
        "on": "fail",  # "fail", "always" or "never"
        "slack_webhook_env": "SLACK_WEBHOOK_URL",
        "teams_webhook_env": "TEAMS_WEBHOOK_URL",
        "email": {
            "to": [],
            "smtp_host_env": "SMTP_HOST",
            "smtp_port_env": "SMTP_PORT",
            "smtp_user_env": "SMTP_USER",
            "smtp_password_env": "SMTP_PASSWORD",
            "from_env": "SMTP_FROM",
        },
    },
    "pr_comment": True,
}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_policy(path: str | None) -> dict:
    data = {}
    if path and Path(path).is_file():
        data = yaml.safe_load(Path(path).read_text()) or {}
    policy = _merge(DEFAULTS, data)
    policy["max_findings"] = policy["max_findings"] or {}
    if policy["fail_on"] not in SEVERITIES + ["none"]:
        raise ValueError(f"fail_on must be one of {SEVERITIES + ['none']}, got {policy['fail_on']!r}")
    for sev in policy["max_findings"]:
        if sev not in SEVERITIES:
            raise ValueError(f"max_findings has unknown severity {sev!r}")
    if policy["on_error"] not in ("fail", "pass"):
        raise ValueError("on_error must be 'fail' or 'pass'")
    return policy
