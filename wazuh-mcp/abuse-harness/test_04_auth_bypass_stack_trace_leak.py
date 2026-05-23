"""Pattern 4 — Auth bypass / stack-trace leak.

Threat model: when the server's backend (Wazuh API) returns 401/403 or
when the server itself encounters an unexpected condition, the response
must not leak:
  - raw Python tracebacks
  - file paths / line numbers from the server's source
  - secrets visible in environment (API keys, passwords)
  - internal endpoint URLs that include credentials

What we test:
  - Force the server into error paths (call a tool with bogus auth-shaped
    args, attempt protocol-violating requests).
  - Inspect both the JSON-RPC response body AND the server's stderr buffer.
  - Assert no traceback / file-path / env-secret leakage in either.

Pass: errors are structured, opaque, and free of internal detail.
Fail: any of the leak patterns appear in response content or stderr.

Maps to: OWASP Agentic AI v1.0 — Tool/Plugin Compromise via Information Leak;
         basic AppSec.
"""

from __future__ import annotations

import re
from typing import Any

import pytest


# Patterns that should NEVER appear in a response to an external caller.
TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\)")
PYTHON_FILE_RE = re.compile(r' {2,}File "[^"]+\.py", line \d+')
INTERNAL_PATH_RE = re.compile(
    r"/Users/[^\s\"]+|/home/[^\s\"]+|C:\\\\Users\\\\|"
    r"/opt/[a-zA-Z][^\s\"]+|/var/[a-zA-Z][^\s\"]+|/srv/[^\s\"]+|"
    r"/app/[^\s\"]+|/usr/src/app[^\s\"]*"
)
SECRET_KEY_RE = re.compile(
    # Original: key=value shape
    r"(api[_-]?key|password|token|secret|bearer)[\"'\s:=]+[A-Za-z0-9_\-./]{12,}|"
    # AWS access keys
    r"AKIA[A-Z0-9]{16}|"
    # JWT shapes (3 base64 segments separated by dots)
    r"eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]+|"
    # Connection strings with embedded creds
    r"(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@",
    re.IGNORECASE,
)


def _scan_for_leaks(blob: str) -> list[str]:
    leaks: list[str] = []
    if TRACEBACK_RE.search(blob):
        leaks.append("python-traceback")
    if PYTHON_FILE_RE.search(blob):
        leaks.append("python-file-line")
    if INTERNAL_PATH_RE.search(blob):
        leaks.append("internal-fs-path")
    if SECRET_KEY_RE.search(blob):
        leaks.append("possible-secret")
    return leaks


def _flatten_response(resp_dict: dict) -> str:
    return str(resp_dict)


def test_unknown_method_returns_clean_error(client):
    resp = client.call("nonexistent/method", {"foo": "bar"}, timeout=3.0)
    leaks = _scan_for_leaks(_flatten_response(resp.raw)) + _scan_for_leaks(client.stderr_text)
    assert resp.is_error, "Unknown method should return JSON-RPC error"
    assert not leaks, f"Leaks in response/stderr to unknown method: {leaks}"


def test_malformed_arguments_return_clean_error(client):
    resp = client.call(
        "tools/call",
        {"name": "definitely-not-a-real-tool", "arguments": {"x": object().__repr__()}},
        timeout=3.0,
    )
    leaks = _scan_for_leaks(_flatten_response(resp.raw)) + _scan_for_leaks(client.stderr_text)
    assert resp.is_error, "Calling unknown tool should return error"
    assert not leaks, f"Leaks when calling unknown tool: {leaks}"


def test_oversize_input_does_not_leak(client):
    """Pump a comically-large argument; if the server crashes, we want
    the failure mode to be a structured error, not a stack trace."""
    listing = client.call("tools/list", {})
    if listing.is_error or not listing.result.get("tools"):
        pytest.skip("server has no tools")

    for tool in listing.result["tools"]:
        schema = tool.get("inputSchema", {}) or {}
        props = schema.get("properties", {}) or {}
        # find first string param
        first_str = next((k for k, v in props.items() if isinstance(v, dict) and v.get("type") == "string"), None)
        if not first_str:
            continue
        huge = "X" * 1_000_000  # 1MB string
        resp = client.call(
            "tools/call",
            {"name": tool["name"], "arguments": {first_str: huge}},
            timeout=10.0,
        )
        leaks = _scan_for_leaks(_flatten_response(resp.raw)) + _scan_for_leaks(client.stderr_text)
        assert not leaks, (
            f"Tool {tool['name']!r} leaked internal detail when given a 1MB "
            f"string input: {leaks}"
        )
        return  # one tool tested is enough — they all share error machinery
    pytest.skip("no string-typed tool args to probe")


def test_malformed_jsonrpc_does_not_crash_or_leak(client):
    """Send a syntactically-bad JSON-RPC line; the server should reject
    cleanly (the spec allows ignoring; what it CANNOT do is dump a
    traceback to stderr)."""
    client.send_raw('{"jsonrpc": "2.0", "id": "broken", "method": "incomplete')
    # Give the server a beat to react.
    import time
    time.sleep(0.3)
    leaks = _scan_for_leaks(client.stderr_text)
    assert not leaks, f"Leaks after malformed JSON-RPC line: {leaks}"
