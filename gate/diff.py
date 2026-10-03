"""Collect the PR diff and drop files the policy excludes."""

from __future__ import annotations

import fnmatch
import re
import subprocess

_FILE_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+)$", re.M)


def git_diff(base_ref: str, head_ref: str = "HEAD") -> str:
    """Three-dot diff: only what the PR branch adds on top of the merge base."""
    proc = subprocess.run(
        ["git", "diff", "--unified=5", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/", f"{base_ref}...{head_ref}"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git diff {base_ref}...{head_ref} failed: {proc.stderr.strip()}")
    return proc.stdout


def _matches(path: str, patterns: list[str]) -> bool:
    # "**/x" should also match "x" at the repo root.
    return any(fnmatch.fnmatch(path, p) or (p.startswith("**/") and fnmatch.fnmatch(path, p[3:])) for p in patterns)


def split_files(diff: str) -> list[tuple[str, str]]:
    """Split a unified diff into (path, chunk) pairs."""
    starts = [m for m in _FILE_HEADER.finditer(diff)]
    out = []
    for i, m in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(diff)
        out.append((m.group(2), diff[m.start():end]))
    return out


def filter_diff(diff: str, include: list[str], exclude: list[str], max_chars: int) -> tuple[str, list[str], list[str]]:
    """Return (filtered diff, reviewed paths, skipped paths).

    Files beyond max_chars are skipped whole rather than cut mid-hunk, and are
    listed in the report so nobody thinks they were reviewed.
    """
    kept, reviewed, skipped = [], [], []
    size = 0
    for path, chunk in split_files(diff):
        if not _matches(path, include) or _matches(path, exclude):
            continue
        if size + len(chunk) > max_chars:
            skipped.append(path)
            continue
        kept.append(chunk)
        reviewed.append(path)
        size += len(chunk)
    return "".join(kept), reviewed, skipped
