"""Markdown audit report, used for the PR comment, the CI summary and the artifact."""

from __future__ import annotations

from datetime import datetime, timezone

ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
COMMENT_MARKER = "<!-- ai-pr-gate -->"


def render(result: dict, verdict: dict, reviewed: list[str], skipped: list[str], context: dict) -> str:
    status = "✅ PASS" if verdict["verdict"] == "PASS" else "❌ FAIL"
    lines = [
        COMMENT_MARKER,
        f"## AI quality gate: {status}",
        "",
    ]
    if verdict["reasons"]:
        lines += ["**Blocked because:** " + "; ".join(verdict["reasons"]), ""]

    counts = " · ".join(f"{ICONS[s]} {s}: {n}" for s, n in verdict["counts"].items())
    lines += [counts, "", result.get("summary", "").strip(), ""]

    findings = result.get("findings", [])
    if findings:
        lines += ["| Severity | Category | Location | Finding |", "|---|---|---|---|"]
        for f in findings:
            loc = f"`{f.get('file', '?')}`" + (f":{f['line']}" if f.get("line") else "")
            lines.append(f"| {ICONS.get(f['severity'], '')} {f['severity']} | {f['category']} | {loc} | {_cell(f['title'])} |")
        lines.append("")
        lines.append("<details><summary>Details and fixes</summary>\n")
        for i, f in enumerate(findings, 1):
            ref = f" ({f['reference']})" if f.get("reference") else ""
            lines += [
                f"**{i}. {f['title']}**{ref}",
                "",
                f"{f['description'].strip()}",
                "",
                f"*Fix:* {f['recommendation'].strip()}",
                "",
            ]
        lines.append("</details>\n")
    else:
        lines += ["No findings.", ""]

    meta = [f"{len(reviewed)} file(s) reviewed" + (": " + ", ".join(f"`{p}`" for p in reviewed) if 0 < len(reviewed) <= 10 else "")]
    if skipped:
        meta.append(f"{len(skipped)} skipped for size: " + ", ".join(f"`{p}`" for p in skipped))
    if context.get("commit"):
        meta.append(f"commit `{context['commit'][:10]}`")
    meta.append(f"model `{result.get('model', '?')}`")
    meta.append(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    lines += ["<sub>" + " · ".join(meta) + "</sub>", ""]
    return "\n".join(lines)


def render_error(message: str, on_error: str) -> str:
    outcome = "the PR is blocked until it runs" if on_error == "fail" else "the PR was let through (on_error: pass)"
    return f"{COMMENT_MARKER}\n## AI quality gate: ⚠️ ERROR\n\nThe audit could not run, so {outcome}.\n\n```\n{message}\n```\n"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")
