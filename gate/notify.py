"""Slack, Teams and email alerts. Each channel is skipped when its env var is not set."""

from __future__ import annotations

import json
import os
import smtplib
import urllib.request
from email.message import EmailMessage

from .http_client import build_request


def _post_json(url: str, payload: dict) -> None:
    req = build_request(url, data=json.dumps(payload).encode(), headers={"content-type": "application/json"})
    urllib.request.urlopen(req, timeout=20).read()


def _headline(verdict: str, context: dict) -> str:
    return f"AI quality gate {verdict}: {context.get('repo', 'repo')} PR #{context.get('pr', '?')} ({context.get('branch', '?')} → {context.get('target', '?')})"


def _short(verdict: dict, findings: list[dict], limit: int = 5) -> str:
    lines = ["; ".join(verdict["reasons"]) or "No blocking findings."]
    for f in findings[:limit]:
        lines.append(f"• [{f['severity']}] {f['title']} ({f.get('file', '?')})")
    if len(findings) > limit:
        lines.append(f"• …and {len(findings) - limit} more")
    return "\n".join(lines)


def send_all(verdict: dict, findings: list[dict], report_md: str, context: dict, policy: dict) -> list[str]:
    """Send alerts according to policy. Returns the channels that failed, so the caller can log them.

    A broken webhook must never change the gate verdict, so errors are collected, not raised.
    """
    cfg = policy["notify"]
    if cfg["on"] == "never" or (cfg["on"] == "fail" and verdict["verdict"] == "PASS"):
        return []

    headline = _headline(verdict["verdict"], context)
    body = _short(verdict, findings)
    link = context.get("url", "")
    errors = []

    slack = os.environ.get(cfg["slack_webhook_env"])
    if slack:
        try:
            text = f"*{headline}*\n{body}" + (f"\n<{link}|Open pull request>" if link else "")
            _post_json(slack, {"text": text})
        except Exception as e:  # noqa: BLE001
            errors.append(f"slack: {e}")

    teams = os.environ.get(cfg["teams_webhook_env"])
    if teams:
        try:
            # Plain MessageCard; works with both classic incoming webhooks and Workflows webhooks.
            card = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": headline,
                "themeColor": "D13438" if verdict["verdict"] == "FAIL" else "2EB886",
                "title": headline,
                "text": body.replace("\n", "<br>"),
            }
            if link:
                card["potentialAction"] = [{"@type": "OpenUri", "name": "Open pull request", "targets": [{"os": "default", "uri": link}]}]
            _post_json(teams, card)
        except Exception as e:  # noqa: BLE001
            errors.append(f"teams: {e}")

    email = cfg["email"]
    host = os.environ.get(email["smtp_host_env"])
    if email["to"] and host:
        try:
            msg = EmailMessage()
            msg["Subject"] = headline
            msg["From"] = os.environ.get(email["from_env"]) or os.environ.get(email["smtp_user_env"], "ai-gate@localhost")
            msg["To"] = ", ".join(email["to"])
            msg.set_content(f"{body}\n\n{link}\n\nFull report:\n\n{report_md}")
            port = int(os.environ.get(email["smtp_port_env"], "587"))
            with smtplib.SMTP(host, port, timeout=30) as s:
                s.starttls()
                user = os.environ.get(email["smtp_user_env"])
                if user:
                    s.login(user, os.environ.get(email["smtp_password_env"], ""))
                s.send_message(msg)
        except Exception as e:  # noqa: BLE001
            errors.append(f"email: {e}")

    return errors
