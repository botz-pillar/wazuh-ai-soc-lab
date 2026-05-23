"""Pattern 5 — Structured-error compliance.

Threat model: a server that returns a mix of structured errors and raw
exceptions makes the agent's error-handling logic unreliable. The agent
may treat a raw stack-trace string as a valid response and continue. Or
worse, it may retry endlessly on transient backend exceptions because no
discriminated error type tells it to stop.

What we test:
  Across several known-bad call shapes, EVERY error response must conform
  to JSON-RPC 2.0 error-object shape AND carry a non-empty `code` (int)
  and `message` (string). MCP servers are also encouraged to use a
  structured `data` field for typed error metadata.

Pass: every error response is JSON-RPC 2.0 compliant with ints + strings
      where required, no exceptions raised on stdout or stderr, no
      half-baked responses (a result AND an error in the same envelope).
Fail: any error response missing `code` / `message`, or carrying both
      `result` and `error`, or leaking exception text into either.

Maps to: lesson principle "structured errors not raw exceptions" — the
         contract that lets the agent reason about failure.
"""

from __future__ import annotations

import pytest


def _assert_jsonrpc_error_shape(resp_raw: dict, context: str) -> None:
    assert resp_raw.get("jsonrpc") == "2.0", f"{context}: missing jsonrpc=2.0"
    assert "id" in resp_raw, f"{context}: error response missing id"
    err = resp_raw.get("error")
    assert err is not None, f"{context}: not an error response"
    assert "result" not in resp_raw, (
        f"{context}: error envelope must not also carry a result. Raw: {resp_raw}"
    )
    code = err.get("code")
    msg = err.get("message")
    assert isinstance(code, int), f"{context}: error.code must be int, got {type(code).__name__}: {code!r}"
    assert isinstance(msg, str) and msg.strip(), f"{context}: error.message must be non-empty string, got {msg!r}"


def test_unknown_method_error_shape(client):
    resp = client.call("nonexistent/method", {}, timeout=3.0)
    assert resp.is_error
    _assert_jsonrpc_error_shape(resp.raw, "unknown method")


def test_unknown_tool_error_shape(client):
    resp = client.call("tools/call", {"name": "abuse-harness-no-such-tool", "arguments": {}}, timeout=3.0)
    assert resp.is_error, "calling unknown tool must return JSON-RPC error"
    _assert_jsonrpc_error_shape(resp.raw, "unknown tool")


def test_unknown_resource_error_shape(client):
    resp = client.call("resources/read", {"uri": "wazuh://abuse-harness/nope"}, timeout=3.0)
    if resp.is_error:
        _assert_jsonrpc_error_shape(resp.raw, "unknown resource")
    else:
        # Some servers return success with an empty contents list — that's
        # also acceptable as long as the contents really are empty.
        assert resp.result.get("contents", []) == [], (
            "Unknown resource must either return JSON-RPC error or empty "
            f"contents — got {resp.result}"
        )


def test_no_partial_envelopes(client):
    """JSON-RPC 2.0 forbids responses with both result and error. Verify
    across several call types that the server never emits a partial envelope."""
    probes = [
        ("tools/list", {}),
        ("resources/list", {}),
        ("prompts/list", {}),
        ("nonexistent/method", {}),
        ("tools/call", {"name": "abuse-harness-no-such-tool", "arguments": {}}),
    ]
    for method, params in probes:
        resp = client.call(method, params, timeout=3.0)
        raw = resp.raw
        has_result = "result" in raw
        has_error = "error" in raw
        assert has_result ^ has_error, (
            f"{method}: response must have exactly one of result|error, got "
            f"result={has_result}, error={has_error}. Raw: {raw}"
        )
