"""Pattern 2 — Tool spam / rate limiting.

Threat model: a compromised or runaway agent calls a tool in tight loop,
either to exhaust the backend (DoS) or to drown out audit signal. The
server must enforce a token-bucket (or equivalent) rate limit so that
repeated calls beyond a threshold return a structured error, not silent
success or backend overload.

What we test:
  Send N rapid calls to the most innocuous tool. The server must return
  an error (rate-limit / throttle) on at least one of them within a small
  window, AND the error must be structured.

Pass: at least one of N rapid calls returns a structured error indicating
      rate limiting (error code or message containing "rate", "throttle",
      "quota", "limit"); N successful responses + zero errors fails the test.
Fail: all N calls succeed silently OR error response is unstructured (raw
      Python exception text).

Maps to: OWASP Agentic AI v1.0 — Resource Exhaustion / Tool Misuse.
"""

from __future__ import annotations

import re
from typing import Any

import pytest


N_RAPID_CALLS = 50
RATE_LIMIT_HINTS = re.compile(r"rate|throttle|quota|limit|too many", re.IGNORECASE)


def _pick_least_dangerous_tool(tools: list[dict]) -> dict | None:
    """Prefer a clearly read-only tool. Failing that, the first tool listed."""
    if not tools:
        return None
    for t in tools:
        annotations = t.get("annotations", {}) or {}
        if annotations.get("readOnlyHint") is True:
            return t
    for t in tools:
        name = t.get("name", "").lower()
        if any(name.startswith(p) for p in ("get", "list", "describe", "read", "search")):
            return t
    return tools[0]


def test_tool_spam_triggers_rate_limit(client):
    listing = client.call("tools/list", {})
    if listing.is_error or not listing.result.get("tools"):
        pytest.skip("server has no tools to test against")

    target = _pick_least_dangerous_tool(listing.result["tools"])
    assert target is not None
    name = target["name"]

    # Determine the call params from the schema. We send empty {} unless the
    # schema requires fields, in which case we fill in placeholder strings.
    schema = target.get("inputSchema", {}) or {}
    required = schema.get("required", []) or []
    args: dict[str, Any] = {}
    for k in required:
        # Best-effort default: empty string. Tests for input validation live
        # in test_03; here we just want the call to be syntactically valid.
        args[k] = "abuse-harness-probe"

    errors: list[dict] = []
    successes = 0
    for _ in range(N_RAPID_CALLS):
        resp = client.call("tools/call", {"name": name, "arguments": args}, timeout=5.0)
        if resp.is_error:
            errors.append(resp.error or {})
        else:
            successes += 1

    # The server must produce AT LEAST ONE error of rate-limit shape.
    assert errors, (
        f"Server accepted {N_RAPID_CALLS} rapid calls to {name!r} without ever "
        f"rate-limiting. No throttle / quota / rate-limit error returned. "
        f"This is an L5 abuse-harness failure: tool spam unbounded."
    )

    def _looks_like_rate_limit(err: dict) -> bool:
        # Accept either: vocab match in message/data, OR a structured `data`
        # field carrying a category signal (data.type / data.code / data.kind).
        text_blob = (
            str(err.get("message", "")) + " " + str(err.get("data", ""))
        )
        if RATE_LIMIT_HINTS.search(text_blob):
            return True
        data = err.get("data") if isinstance(err.get("data"), dict) else {}
        for key in ("type", "code", "kind", "reason", "category"):
            v = data.get(key)
            if isinstance(v, str) and re.search(
                r"rate|throttle|quota|limit|exceed|capacity|spam", v, re.IGNORECASE
            ):
                return True
        # JSON-RPC -32000 server-error range with a message that's clearly
        # about request capacity is also acceptable.
        return False

    rate_limit_errors = [e for e in errors if _looks_like_rate_limit(e)]
    assert rate_limit_errors, (
        f"Server returned {len(errors)} errors but none looked like rate-limit "
        f"signals. Accepted shapes: vocab match (rate / throttle / quota / "
        f"limit / too many) in message OR structured data.{{type|code|kind|"
        f"reason|category}}. Errors observed: {errors[:3]}."
    )
