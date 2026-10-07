"""GitHub Actions workflow-command annotations (::error / ::warning / ::notice)."""

from __future__ import annotations

from .policy import _rank

TITLE = "AI quality gate"


def escape_data(value: str) -> str:
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(value: str) -> str:
    return escape_data(value).replace(":", "%3A").replace(",", "%2C")


def command(level: str, message: str, **props) -> str:
    parts = ",".join(f"{k}={escape_property(v)}" for k, v in props.items() if v not in (None, ""))
    return f"::{level}{' ' + parts if parts else ''}::{escape_data(message)}"


def verdict_line(verdict: dict, findings: list[dict]) -> str:
    if verdict["verdict"] == "FAIL":
        return command("error", "FAIL - " + "; ".join(verdict["reasons"]), title=TITLE)
    return command("notice", f"PASS - {len(findings)} finding(s), none blocking", title=TITLE)


def finding_lines(findings: list[dict], policy: dict) -> list[str]:
    fail_on = policy["fail_on"]
    lines = []
    for f in findings:
        sev = f.get("severity", "info")
        blocking = fail_on != "none" and _rank(sev) <= _rank(fail_on)
        props = {}
        if f.get("file"):
            props["file"] = f["file"]
            line = _positive_int(f.get("line"))
            if line:
                props["line"] = str(line)
        props["title"] = f"{sev}: {f.get('title', '')}"
        lines.append(command("error" if blocking else "warning", (f.get("description") or "").strip(), **props))
    return lines


def _positive_int(value) -> int | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None
