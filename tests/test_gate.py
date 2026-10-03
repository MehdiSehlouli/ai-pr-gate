import io
import json
import urllib.error

import pytest

from gate import ci, claude, notify, report
from gate.__main__ import main
from gate.config import DEFAULTS, load_policy
from gate.diff import filter_diff
from gate.policy import evaluate, sort_findings

DIFF = """diff --git a/app/routes.py b/app/routes.py
index 1111111..2222222 100644
--- a/app/routes.py
+++ b/app/routes.py
@@ -10,3 +10,6 @@ def index():
+@app.route("/search")
+def search():
+    q = request.args["q"]
+    return db.engine.execute(f"SELECT * FROM user WHERE username = '{q}'")
diff --git a/package-lock.json b/package-lock.json
index 3333333..4444444 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1 +1 @@
-{}
+{"lockfileVersion": 3}
"""

SQLI = {
    "severity": "critical",
    "category": "security",
    "title": "SQL injection in /search",
    "file": "app/routes.py",
    "line": 13,
    "description": "User input is formatted into raw SQL.",
    "recommendation": "Use a bound parameter or the ORM.",
    "reference": "CWE-89",
}
NIT = {**SQLI, "severity": "low", "category": "quality", "title": "Missing docstring", "line": 11}


def policy(**overrides):
    p = load_policy(None)
    p.update(overrides)
    return p


# --- policy ---------------------------------------------------------------

def test_fail_on_threshold():
    assert evaluate([SQLI], policy())["verdict"] == "FAIL"
    assert evaluate([NIT], policy())["verdict"] == "PASS"
    assert evaluate([NIT], policy(fail_on="low"))["verdict"] == "FAIL"
    assert evaluate([SQLI], policy(fail_on="none"))["verdict"] == "PASS"


def test_max_findings_cap():
    p = policy(fail_on="none", max_findings={"low": 1})
    assert evaluate([NIT], p)["verdict"] == "PASS"
    v = evaluate([NIT, NIT], p)
    assert v["verdict"] == "FAIL" and "limit is 1" in v["reasons"][0]


def test_sort_puts_critical_first():
    assert sort_findings([NIT, SQLI])[0]["severity"] == "critical"


def test_policy_file_merges_with_defaults(tmp_path):
    f = tmp_path / "p.yml"
    f.write_text("fail_on: medium\ndiff:\n  max_chars: 10\n")
    p = load_policy(str(f))
    assert p["fail_on"] == "medium"
    assert p["diff"]["max_chars"] == 10
    assert p["diff"]["exclude"] == DEFAULTS["diff"]["exclude"]


def test_policy_rejects_bad_severity(tmp_path):
    f = tmp_path / "p.yml"
    f.write_text("fail_on: severe\n")
    with pytest.raises(ValueError):
        load_policy(str(f))


# --- diff -----------------------------------------------------------------

def test_filter_excludes_lockfiles():
    diff, reviewed, skipped = filter_diff(DIFF, ["**"], DEFAULTS["diff"]["exclude"], 100_000)
    assert reviewed == ["app/routes.py"]
    assert "package-lock.json" not in diff
    assert skipped == []


def test_filter_skips_whole_files_over_budget():
    _, reviewed, skipped = filter_diff(DIFF, ["**"], [], 50)
    assert reviewed == [] and skipped == ["app/routes.py", "package-lock.json"]


# --- claude client ----------------------------------------------------------

class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def tool_response(findings):
    return {
        "model": "claude-sonnet-5-5",
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 10, "output_tokens": 20},
        "content": [{"type": "tool_use", "name": "report_findings", "input": {"summary": "s", "findings": findings}}],
    }


def test_review_diff_parses_tool_call(monkeypatch):
    sent = {}

    def fake_urlopen(req, timeout):
        sent["headers"] = dict(req.headers)
        sent["body"] = json.loads(req.data)
        return FakeResp(json.dumps(tool_response([SQLI])).encode())

    monkeypatch.setattr(claude.urllib.request, "urlopen", fake_urlopen)
    out = claude.review_diff(DIFF, policy(extra_instructions="No raw SQL."), "sk-test")
    assert out["findings"] == [SQLI]
    assert sent["body"]["tool_choice"] == {"type": "auto"}
    assert sent["body"]["tools"][0]["strict"] is True
    assert "No raw SQL." in sent["body"]["messages"][0]["content"]
    assert sent["headers"]["X-api-key"] == "sk-test"


def test_review_diff_retries_on_overload(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.HTTPError(req.full_url, 529, "overloaded", {}, io.BytesIO(b""))
        return FakeResp(json.dumps(tool_response([])).encode())

    monkeypatch.setattr(claude.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(claude.time, "sleep", lambda s: None)
    assert claude.review_diff(DIFF, policy(), "k")["findings"] == []
    assert calls["n"] == 2


def test_review_diff_does_not_retry_auth_error(monkeypatch):
    def fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 401, "unauthorized", {}, io.BytesIO(b'{"error":"invalid x-api-key"}'))

    monkeypatch.setattr(claude.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(claude.GateError, match="401"):
        claude.review_diff(DIFF, policy(), "bad")


def test_review_diff_asks_again_when_tool_is_not_called(monkeypatch):
    replies = [
        {"model": "m", "stop_reason": "end_turn", "content": [{"type": "text", "text": "Looks fine."}]},
        tool_response([SQLI]),
    ]
    monkeypatch.setattr(claude.urllib.request, "urlopen", lambda req, timeout: FakeResp(json.dumps(replies.pop(0)).encode()))
    assert claude.review_diff(DIFF, policy(), "k")["findings"] == [SQLI]


def test_truncated_response_is_an_error(monkeypatch):
    body = {**tool_response([]), "stop_reason": "max_tokens"}
    monkeypatch.setattr(claude.urllib.request, "urlopen", lambda req, timeout: FakeResp(json.dumps(body).encode()))
    with pytest.raises(claude.GateError, match="max_tokens"):
        claude.review_diff(DIFF, policy(), "k")


# --- report / ci / notify ------------------------------------------------------

def test_report_escapes_pipes_and_lists_skipped():
    f = {**SQLI, "title": "a | b"}
    md = report.render({"summary": "s", "findings": [f], "model": "m"}, evaluate([f], policy()), ["x.py"], ["big.py"], {})
    assert "a \\| b" in md and "`big.py`" in md and "FAIL" in md


def test_bitbucket_markdown_drops_html():
    md = report.render({"summary": "s", "findings": [SQLI], "model": "m"}, evaluate([SQLI], policy()), [], [], {})
    bb = ci.to_bitbucket_markdown(md)
    assert "<details>" not in bb and "<!--" not in bb and bb.startswith(ci.HEADING)


def test_notify_skips_on_pass_and_survives_broken_webhook(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/x")
    posted = []
    monkeypatch.setattr(notify, "_post_json", lambda url, payload: posted.append(payload))
    assert notify.send_all(evaluate([], policy()), [], "", {}, policy()) == []
    assert posted == []

    def boom(url, payload):
        raise OSError("connection refused")

    monkeypatch.setattr(notify, "_post_json", boom)
    errors = notify.send_all(evaluate([SQLI], policy()), [SQLI], "", {"pr": 7}, policy())
    assert errors and errors[0].startswith("slack")


def test_detect_bitbucket(monkeypatch):
    for k in ("GITHUB_ACTIONS",):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("BITBUCKET_BUILD_NUMBER", "12")
    monkeypatch.setenv("BITBUCKET_REPO_FULL_NAME", "acme/api")
    monkeypatch.setenv("BITBUCKET_PR_ID", "42")
    monkeypatch.setenv("BITBUCKET_PR_DESTINATION_BRANCH", "qa")
    ctx = ci.detect()
    assert ctx["platform"] == "bitbucket" and ctx["base_ref"] == "origin/qa"
    assert ctx["url"] == "https://bitbucket.org/acme/api/pull-requests/42"


# --- end to end -------------------------------------------------------------

@pytest.fixture
def local_env(monkeypatch, tmp_path):
    for k in ("GITHUB_ACTIONS", "BITBUCKET_BUILD_NUMBER", "GITHUB_STEP_SUMMARY", "ANTHROPIC_API_KEY", "SLACK_WEBHOOK_URL", "TEAMS_WEBHOOK_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pr.diff").write_text(DIFF)
    return tmp_path


def test_cli_fails_on_critical_finding(local_env):
    (local_env / "f.json").write_text(json.dumps({"summary": "s", "findings": [NIT, SQLI], "model": "m"}))
    code = main(["--diff-file", "pr.diff", "--findings-file", "f.json", "--no-notify"])
    assert code == 1
    saved = json.loads((local_env / "ai-gate-report" / "findings.json").read_text())
    assert saved["verdict"] == "FAIL" and saved["findings"][0]["severity"] == "critical"


def test_cli_passes_clean_change(local_env):
    (local_env / "f.json").write_text(json.dumps({"summary": "s", "findings": [NIT], "model": "m"}))
    assert main(["--diff-file", "pr.diff", "--findings-file", "f.json", "--no-notify"]) == 0


def test_cli_missing_key_fails_closed(local_env):
    assert main(["--diff-file", "pr.diff", "--no-notify"]) == 2
    assert "ERROR" in (local_env / "ai-gate-report" / "report.md").read_text()


def test_cli_missing_key_can_fail_open(local_env):
    (local_env / ".ai-gate.yml").write_text("on_error: pass\n")
    assert main(["--diff-file", "pr.diff", "--no-notify"]) == 0
