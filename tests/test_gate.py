import io
import json
import urllib.error

import pytest

import gate
from gate import ci, claude, groq, llm, notify, report
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


def test_policy_defaults_to_groq_qwen():
    p = load_policy(None)
    assert p["provider"] == "groq" and p["model"] == "qwen/qwen3.8-27b"


def test_policy_anthropic_gets_claude_default(tmp_path):
    f = tmp_path / "p.yml"
    f.write_text("provider: anthropic\n")
    assert load_policy(str(f))["model"] == "claude-sonnet-5-5"


def test_policy_rejects_claude_model_on_groq(tmp_path):
    f = tmp_path / "p.yml"
    f.write_text("model: claude-sonnet-5-5\n")
    with pytest.raises(ValueError, match="provider: anthropic"):
        load_policy(str(f))


def test_policy_rejects_unknown_provider(tmp_path):
    f = tmp_path / "p.yml"
    f.write_text("provider: openai\n")
    with pytest.raises(ValueError, match="provider"):
        load_policy(str(f))


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


# --- groq client (default) ----------------------------------------------------

def anthropic_policy(**overrides):
    return policy(provider="anthropic", model="claude-sonnet-5-5", **overrides)


def groq_response(findings, finish_reason="stop", content=None):
    return {
        "model": "qwen/qwen3.8-27b",
        "usage": {"prompt_tokens": 10, "completion_tokens": 20},
        "choices": [{
            "index": 0,
            "finish_reason": finish_reason,
            "message": {"role": "assistant", "content": content if content is not None else json.dumps({"summary": "s", "findings": findings})},
        }],
    }

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


def test_groq_review_parses_json_schema_output(monkeypatch):
    sent = {}

    def fake_urlopen(req, timeout):
        sent["url"] = req.full_url
        sent["headers"] = dict(req.headers)
        sent["body"] = json.loads(req.data)
        return FakeResp(json.dumps(groq_response([SQLI])).encode())

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    out = llm.review_diff(DIFF, policy(extra_instructions="No raw SQL."), "gsk-test")
    assert out["findings"] == [SQLI] and out["model"] == "qwen/qwen3.8-27b"
    assert sent["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert sent["headers"]["Authorization"] == "Bearer gsk-test"
    # urllib capitalizes header keys; an explicit UA avoids Cloudflare 1010 on Groq.
    assert sent["headers"]["User-agent"] == f"ai-pr-gate/{gate.__version__}"
    assert sent["headers"]["Accept"] == "application/json"
    body = sent["body"]
    assert body["model"] == "qwen/qwen3.8-27b"
    assert body["max_completion_tokens"] == 16000
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["response_format"]["json_schema"]["schema"]["required"] == ["summary", "findings"]
    assert body["reasoning_format"] == "hidden"
    assert body["messages"][0]["role"] == "system"
    assert "No raw SQL." in body["messages"][1]["content"]


def test_groq_non_strict_model_uses_best_effort():
    body = groq.build_payload(DIFF, policy(model="llama-3.3-70b-versatile"))
    assert body["response_format"]["json_schema"]["strict"] is False
    assert "reasoning_format" not in body


def test_groq_retries_on_rate_limit_and_flex_capacity(monkeypatch):
    codes = [429, 498]

    def fake_urlopen(req, timeout):
        if codes:
            raise urllib.error.HTTPError(req.full_url, codes.pop(0), "busy", {}, io.BytesIO(b""))
        return FakeResp(json.dumps(groq_response([])).encode())

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    assert groq.review_diff(DIFF, policy(), "k")["findings"] == []
    assert codes == []


def test_groq_does_not_retry_auth_error(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout):
        calls["n"] += 1
        raise urllib.error.HTTPError(req.full_url, 401, "unauthorized", {}, io.BytesIO(b'{"error":{"message":"Invalid API Key"}}'))

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(llm.GateError, match="Groq API returned 401"):
        groq.review_diff(DIFF, policy(), "bad")
    assert calls["n"] == 1


def test_groq_cloudflare_1010_is_explained(monkeypatch):
    def fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "forbidden", {}, io.BytesIO(b"error code: 1010"))

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(llm.GateError, match="Groq API returned 403: error code: 1010 .*Cloudflare"):
        groq.review_diff(DIFF, policy(), "k")


def test_pr_comment_and_webhook_send_user_agent(monkeypatch):
    seen = []

    def fake_urlopen(req, timeout):
        seen.append(req.get_header("User-agent"))
        return FakeResp(b"[]")

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    ci._request("GET", "https://api.github.com/x", {"authorization": "Bearer t"})
    notify._post_json("https://hooks.slack.com/x", {"text": "hi"})
    assert seen == [f"ai-pr-gate/{gate.__version__}"] * 2


def test_groq_unreachable_after_retries(monkeypatch):
    def fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 503, "unavailable", {}, io.BytesIO(b""))

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    with pytest.raises(llm.GateError, match="unreachable after 3 attempts"):
        groq.review_diff(DIFF, policy(), "k")


def test_groq_truncated_response_is_an_error(monkeypatch):
    body = groq_response([], finish_reason="length", content='{"summary": "s", "find')
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda req, timeout: FakeResp(json.dumps(body).encode()))
    with pytest.raises(llm.GateError, match="cut off"):
        groq.review_diff(DIFF, policy(), "k")


def test_groq_asks_again_on_invalid_json(monkeypatch):
    replies = [groq_response([], content="Looks fine."), groq_response([SQLI])]
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda req, timeout: FakeResp(json.dumps(replies.pop(0)).encode()))
    assert groq.review_diff(DIFF, policy(), "k")["findings"] == [SQLI]


def test_groq_gives_up_after_two_invalid_answers(monkeypatch):
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda req, timeout: FakeResp(json.dumps(groq_response([], content="")).encode()))
    with pytest.raises(llm.GateError, match="valid report_findings JSON"):
        groq.review_diff(DIFF, policy(), "k")


# --- anthropic client (provider: anthropic) ---------------------------------------


def test_anthropic_parses_tool_call(monkeypatch):
    sent = {}

    def fake_urlopen(req, timeout):
        sent["url"] = req.full_url
        sent["headers"] = dict(req.headers)
        sent["body"] = json.loads(req.data)
        return FakeResp(json.dumps(tool_response([SQLI])).encode())

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    out = llm.review_diff(DIFF, anthropic_policy(extra_instructions="No raw SQL."), "sk-test")
    assert out["findings"] == [SQLI]
    assert sent["body"]["tool_choice"] == {"type": "auto"}
    assert sent["body"]["tools"][0]["strict"] is True
    assert "No raw SQL." in sent["body"]["messages"][0]["content"]
    assert sent["headers"]["X-api-key"] == "sk-test"
    assert sent["url"] == claude.API_URL and sent["body"]["model"] == "claude-sonnet-5-5"


def test_anthropic_retries_on_overload(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.HTTPError(req.full_url, 529, "overloaded", {}, io.BytesIO(b""))
        return FakeResp(json.dumps(tool_response([])).encode())

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    assert claude.review_diff(DIFF, anthropic_policy(), "k")["findings"] == []
    assert calls["n"] == 2


def test_anthropic_does_not_retry_auth_error(monkeypatch):
    def fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 401, "unauthorized", {}, io.BytesIO(b'{"error":"invalid x-api-key"}'))

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(llm.GateError, match="401"):
        claude.review_diff(DIFF, anthropic_policy(), "bad")


def test_anthropic_asks_again_when_tool_is_not_called(monkeypatch):
    replies = [
        {"model": "m", "stop_reason": "end_turn", "content": [{"type": "text", "text": "Looks fine."}]},
        tool_response([SQLI]),
    ]
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda req, timeout: FakeResp(json.dumps(replies.pop(0)).encode()))
    assert claude.review_diff(DIFF, anthropic_policy(), "k")["findings"] == [SQLI]


def test_anthropic_truncated_response_is_an_error(monkeypatch):
    body = {**tool_response([]), "stop_reason": "max_tokens"}
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda req, timeout: FakeResp(json.dumps(body).encode()))
    with pytest.raises(llm.GateError, match="max_tokens"):
        claude.review_diff(DIFF, anthropic_policy(), "k")


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
    for k in ("GITHUB_ACTIONS", "BITBUCKET_BUILD_NUMBER", "GITHUB_STEP_SUMMARY", "GROQ_API_KEY", "ANTHROPIC_API_KEY", "SLACK_WEBHOOK_URL", "TEAMS_WEBHOOK_URL"):
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
    md = (local_env / "ai-gate-report" / "report.md").read_text()
    assert "ERROR" in md and "GROQ_API_KEY is not set" in md


def test_cli_anthropic_provider_needs_anthropic_key(local_env, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-unused")
    (local_env / ".ai-gate.yml").write_text("provider: anthropic\n")
    assert main(["--diff-file", "pr.diff", "--no-notify"]) == 2
    assert "ANTHROPIC_API_KEY is not set" in (local_env / "ai-gate-report" / "report.md").read_text()


def test_cli_groq_end_to_end(local_env, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda req, timeout: FakeResp(json.dumps(groq_response([SQLI])).encode()))
    assert main(["--diff-file", "pr.diff", "--no-notify"]) == 1
    md = (local_env / "ai-gate-report" / "report.md").read_text()
    assert "FAIL" in md and "model `qwen/qwen3.8-27b`" in md


def test_cli_missing_key_can_fail_open(local_env):
    (local_env / ".ai-gate.yml").write_text("on_error: pass\n")
    assert main(["--diff-file", "pr.diff", "--no-notify"]) == 0
