"""Shared builder for outbound HTTP requests.

Every request carries an explicit User-Agent. Some edges (Groq's Cloudflare front, for one) reject
urllib's default ``Python-urllib/3.x`` signature with a 403 "error code: 1010".
"""

from __future__ import annotations

import urllib.request

from . import __version__

USER_AGENT = f"ai-pr-gate/{__version__}"


def build_request(url: str, *, data: bytes | None = None, method: str | None = None, headers: dict | None = None) -> urllib.request.Request:
    return urllib.request.Request(url, data=data, method=method, headers={"User-Agent": USER_AGENT, **(headers or {})})
