# ai-pr-gate

A merge gate for pull requests. Claude audits the PR diff for security and code-quality problems, a policy turns the findings into PASS/FAIL, and branch protection stops failed PRs from merging into QA. Works with GitHub Actions and Bitbucket Pipelines.

What it does on every PR:
1. Diffs the PR branch against the merge base with the target branch, skipping lockfiles, vendored code and anything the policy excludes.
2. Sends the diff to the Claude API and asks for a strict `report_findings` tool call, so findings come back as structured JSON (severity, category, file, line, fix, CWE).
3. Applies the policy (`fail_on` threshold and per-severity caps) and exits `0` PASS, `1` FAIL, or `2` if the audit itself failed (fail-closed by default).
4. Posts or updates a single PR comment, writes `ai-gate-report/report.md` and `findings.json`, and on failure alerts Slack, Teams or email.

## Setup: GitHub

1. Copy `examples/github-workflow.yml` to `.github/workflows/ai-gate.yml` and `examples/.ai-gate.yml` to the repo root.
2. Add the repo secret `ANTHROPIC_API_KEY` (Settings → Secrets and variables → Actions). Optional: `SLACK_WEBHOOK_URL`, `TEAMS_WEBHOOK_URL`.
3. Settings → Rules → Rulesets (or Branches → Branch protection) for `qa`: require a pull request and require the status check **AI quality gate**.

## Setup: Bitbucket

1. Copy `examples/bitbucket-pipelines.yml` (or merge its `pull-requests` section) and `examples/.ai-gate.yml`.
2. Repository settings → Repository variables (secured): `ANTHROPIC_API_KEY`, and `BITBUCKET_ACCESS_TOKEN` (a repository access token with Pull requests: Write) for the PR comment.
3. Repository settings → Branch restrictions for `qa`: add the merge check requiring at least 1 successful build and no failed builds. Note: Bitbucket only *enforces* merge checks (blocks the merge button) on Premium plans; on Standard they show as warnings.

## Policy

See `examples/.ai-gate.yml`. Main keys: `model`, `fail_on` (`critical|high|medium|low|info|none`), `max_findings`, `on_error` (`fail|pass`), `diff.include/exclude/max_chars`, `extra_instructions` (project rules added to the prompt), `notify`.

## Running locally

```bash
pip install .
ANTHROPIC_API_KEY=... ai-pr-gate --base origin/main
ai-pr-gate --diff-file pr.diff --findings-file saved.json   # replay saved findings, no API call
```

## Security notes

- The API key only lives in CI secrets; it is never printed or written to the report.
- Only the diff is sent to the API, not the whole repo.
- PRs from forks don't receive secrets on GitHub, so the gate errors (and blocks) instead of running with no key.

## Tests

```bash
pip install -e . pytest && pytest -q
```
