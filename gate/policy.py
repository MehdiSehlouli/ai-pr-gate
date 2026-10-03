"""Turn findings into a PASS/FAIL verdict using the severity rules."""

from __future__ import annotations

from collections import Counter

from .config import SEVERITIES


def _rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def evaluate(findings: list[dict], policy: dict) -> dict:
    counts = Counter(f.get("severity", "info") for f in findings)
    reasons = []

    if policy["fail_on"] != "none":
        threshold = _rank(policy["fail_on"])
        blocking = [f for f in findings if _rank(f.get("severity", "info")) <= threshold]
        if blocking:
            reasons.append(f"{len(blocking)} finding(s) at or above '{policy['fail_on']}'")

    for sev, cap in policy["max_findings"].items():
        if counts.get(sev, 0) > cap:
            reasons.append(f"{counts[sev]} '{sev}' finding(s), limit is {cap}")

    return {
        "verdict": "FAIL" if reasons else "PASS",
        "reasons": reasons,
        "counts": {s: counts.get(s, 0) for s in SEVERITIES},
    }


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (_rank(f.get("severity", "info")), f.get("file", ""), f.get("line") or 0))
