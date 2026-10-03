"""Entry point: python -m gate [--base origin/qa] [--policy .ai-gate.yml]

Exit codes: 0 = PASS, 1 = FAIL (blocking findings), 2 = the gate itself errored and on_error is "fail".
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import ci, claude, notify, policy as pol, report
from .config import load_policy
from .diff import filter_diff, git_diff


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ai-pr-gate", description="Claude-powered security and quality gate for pull requests.")
    p.add_argument("--base", help="Base ref to diff against (default: the PR target branch from CI, else origin/main)")
    p.add_argument("--head", default="HEAD")
    p.add_argument("--policy", default=".ai-gate.yml", help="Policy file (default: .ai-gate.yml)")
    p.add_argument("--out-dir", default="ai-gate-report", help="Where to write report.md and findings.json")
    p.add_argument("--diff-file", help="Review this diff file instead of running git diff")
    p.add_argument("--findings-file", help="Skip the API and evaluate saved findings JSON (for testing policies)")
    p.add_argument("--no-comment", action="store_true", help="Do not post a PR comment")
    p.add_argument("--no-notify", action="store_true", help="Do not send Slack/Teams/email alerts")
    args = p.parse_args(argv)

    try:
        policy = load_policy(args.policy)
    except Exception as e:  # noqa: BLE001
        print(f"AI gate error: invalid policy {args.policy}: {e}", file=sys.stderr)
        return 2
    context = ci.detect()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    try:
        if args.diff_file:
            raw = Path(args.diff_file).read_text()
        else:
            raw = git_diff(args.base or context.get("base_ref") or "origin/main", args.head)
        d = policy["diff"]
        diff, reviewed, skipped = filter_diff(raw, d["include"], d["exclude"], d["max_chars"])

        if args.findings_file:
            result = json.loads(Path(args.findings_file).read_text())
        elif not diff.strip():
            result = {"summary": "No reviewable changes in this PR.", "findings": [], "model": "none"}
        else:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise claude.GateError("ANTHROPIC_API_KEY is not set. Add it as a CI secret.")
            result = claude.review_diff(diff, policy, api_key)
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        print(f"::error::AI gate error: {msg}" if context["platform"] == "github" else f"AI gate error: {msg}", file=sys.stderr)
        md = report.render_error(msg, policy["on_error"])
        (out / "report.md").write_text(md)
        _publish(md, context, args, policy)
        return 2 if policy["on_error"] == "fail" else 0

    result["findings"] = pol.sort_findings(result.get("findings", []))
    verdict = pol.evaluate(result["findings"], policy)
    md = report.render(result, verdict, reviewed, skipped, context)

    (out / "report.md").write_text(md)
    (out / "findings.json").write_text(json.dumps({**result, **verdict, "reviewed": reviewed, "skipped": skipped}, indent=2))
    print(md)

    _publish(md, context, args, policy)
    if not args.no_notify:
        for err in notify.send_all(verdict, result["findings"], md, context, policy):
            print(f"warning: notification failed ({err})", file=sys.stderr)

    return 1 if verdict["verdict"] == "FAIL" else 0


def _publish(md: str, context: dict, args, policy: dict) -> None:
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(md + "\n")
    if policy["pr_comment"] and not args.no_comment and context["platform"] != "local":
        err = ci.upsert_pr_comment(context, md)
        if err:
            print(f"warning: {err}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
