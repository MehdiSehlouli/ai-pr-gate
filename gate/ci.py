"""CI platform detection and PR comments for GitHub Actions and Bitbucket Pipelines."""

from __future__ import annotations

import json
import os
import urllib.request

from .report import COMMENT_MARKER

HEADING = "## AI quality gate:"


def detect() -> dict:
    env = os.environ
    if env.get("GITHUB_ACTIONS") == "true":
        event = {}
        if env.get("GITHUB_EVENT_PATH") and os.path.isfile(env["GITHUB_EVENT_PATH"]):
            with open(env["GITHUB_EVENT_PATH"]) as fh:
                event = json.load(fh)
        pr = event.get("pull_request", {})
        return {
            "platform": "github",
            "repo": env.get("GITHUB_REPOSITORY"),
            "pr": pr.get("number"),
            "url": pr.get("html_url", ""),
            "branch": env.get("GITHUB_HEAD_REF"),
            "target": env.get("GITHUB_BASE_REF"),
            "base_ref": f"origin/{env['GITHUB_BASE_REF']}" if env.get("GITHUB_BASE_REF") else None,
            "commit": pr.get("head", {}).get("sha") or env.get("GITHUB_SHA"),
        }
    if env.get("BITBUCKET_BUILD_NUMBER"):
        repo = env.get("BITBUCKET_REPO_FULL_NAME")
        pr_id = env.get("BITBUCKET_PR_ID")
        target = env.get("BITBUCKET_PR_DESTINATION_BRANCH")
        return {
            "platform": "bitbucket",
            "repo": repo,
            "pr": pr_id,
            "url": f"https://bitbucket.org/{repo}/pull-requests/{pr_id}" if repo and pr_id else "",
            "branch": env.get("BITBUCKET_BRANCH"),
            "target": target,
            "base_ref": f"origin/{target}" if target else None,
            "commit": env.get("BITBUCKET_COMMIT"),
        }
    return {"platform": "local", "repo": os.path.basename(os.getcwd()), "pr": None, "url": "", "base_ref": None}


def _request(method: str, url: str, headers: dict, payload: dict | None = None) -> dict | list:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={**headers, "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else {}


def to_bitbucket_markdown(md: str) -> str:
    """Bitbucket does not render <details>, <sub> or HTML comments."""
    return (
        md.replace(COMMENT_MARKER + "\n", "")
        .replace("<details><summary>Details and fixes</summary>\n", "**Details and fixes**\n")
        .replace("</details>\n", "")
        .replace("<sub>", "_")
        .replace("</sub>", "_")
    )


def upsert_pr_comment(context: dict, markdown: str) -> str | None:
    """Create or update the gate's single PR comment. Returns an error string, or None on success."""
    try:
        if context["platform"] == "github":
            token = os.environ.get("GITHUB_TOKEN")
            if not (token and context.get("pr")):
                return "skipped: GITHUB_TOKEN or PR number missing"
            api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
            headers = {"authorization": f"Bearer {token}", "accept": "application/vnd.github+json"}
            base = f"{api}/repos/{context['repo']}/issues"
            comments = _request("GET", f"{base}/{context['pr']}/comments?per_page=100", headers)
            mine = next((c for c in comments if COMMENT_MARKER in (c.get("body") or "")), None)
            if mine:
                _request("PATCH", f"{base}/comments/{mine['id']}", headers, {"body": markdown})
            else:
                _request("POST", f"{base}/{context['pr']}/comments", headers, {"body": markdown})
            return None

        if context["platform"] == "bitbucket":
            token = os.environ.get("BITBUCKET_ACCESS_TOKEN")
            if not (token and context.get("pr")):
                return "skipped: BITBUCKET_ACCESS_TOKEN or PR id missing"
            headers = {"authorization": f"Bearer {token}"}
            base = f"https://api.bitbucket.org/2.0/repositories/{context['repo']}/pullrequests/{context['pr']}/comments"
            body = {"content": {"raw": to_bitbucket_markdown(markdown)}}
            page = _request("GET", f"{base}?pagelen=100", headers)
            mine = next(
                (c for c in page.get("values", []) if (c.get("content", {}).get("raw") or "").startswith(HEADING) and not c.get("deleted")),
                None,
            )
            if mine:
                _request("PUT", f"{base}/{mine['id']}", headers, body)
            else:
                _request("POST", base, headers, body)
            return None
    except Exception as e:  # noqa: BLE001
        return f"PR comment failed: {e}"
    return None
