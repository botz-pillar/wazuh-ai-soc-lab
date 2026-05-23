"""Pattern 3 — Input validation / no-fabrication.

Threat model: an agent calls a tool with invalid, nonsensical, or
adversarial arguments. The server must reject with a structured error,
NOT fabricate a success response and NOT pass the bad input through to
the backend without sanitization.

The lesson's earlier name for this pattern was "confused-agent." Renamed
to "input validation" because that's what's actually under test.

What we test:
  - Tools with required fields: omit them, expect structured error.
  - Tools that take IDs: pass an obviously-fake ID, expect a "not found"
    or "invalid" structured error rather than a silent success or invented
    record.
  - Tools that take strings: pass attacker-shaped strings (SQL, shell,
    null bytes, very long input), expect structured error or sanitized
    handling — never a backend leak.

Pass: server rejects malformed input with structured errors; never
      returns content with placeholder/fabricated data.
Fail: server returns success with empty / fabricated content; raw stack
      trace appears in error or stderr.

Maps to: OWASP Agentic AI v1.0 — Input Manipulation; basic AppSec.
"""

from __future__ import annotations

import re
from typing import Any

import pytest


HOSTILE_STRINGS = [
    "'; DROP TABLE alerts; --",
    "$(rm -rf /tmp/test)",
    "../../../etc/passwd",
    "\x00\x01\x02malformed\x00",
    "A" * 10_000,          # length attack
    "\n\nINJECTED: hello",  # newline-based confusion
]


def _first_string_arg(schema: dict) -> str | None:
    props = (schema or {}).get("properties", {}) or {}
    for k, v in props.items():
        if isinstance(v, dict) and v.get("type") == "string":
            return k
    return None


def test_omitting_required_arguments_returns_structured_error(client):
    listing = client.call("tools/list", {})
    if listing.is_error or not listing.result.get("tools"):
        pytest.skip("server has no tools")

    found_required_tool = False
    for tool in listing.result["tools"]:
        schema = tool.get("inputSchema", {}) or {}
        if not schema.get("required"):
            continue
        found_required_tool = True
        name = tool["name"]
        resp = client.call("tools/call", {"name": name, "arguments": {}}, timeout=5.0)
        assert resp.is_error, (
            f"Tool {name!r} has required fields {schema['required']!r} but "
            f"accepted an empty arguments dict without error. Result: {resp.result}"
        )
        assert resp.error and isinstance(resp.error.get("message"), str), (
            f"Tool {name!r} returned an error with no message string: {resp.error}"
        )

    if not found_required_tool:
        pytest.skip("no tools with required fields to test against")


def test_hostile_string_inputs_do_not_leak_or_crash(client):
    listing = client.call("tools/list", {})
    if listing.is_error or not listing.result.get("tools"):
        pytest.skip("server has no tools")

    found_string_arg = False
    assertions_made = 0
    for tool in listing.result["tools"]:
        schema = tool.get("inputSchema", {}) or {}
        string_arg = _first_string_arg(schema)
        if not string_arg:
            continue
        found_string_arg = True

        for hostile in HOSTILE_STRINGS:
            resp = client.call(
                "tools/call",
                {"name": tool["name"], "arguments": {string_arg: hostile}},
                timeout=5.0,
            )
            # Acceptable outcomes:
            #   (a) structured error
            #   (b) success that does NOT echo the hostile string back verbatim
            #       inside a free-text content block AND does not leak stderr
            if resp.is_error:
                assert resp.error and resp.error.get("message"), (
                    f"Unstructured error from {tool['name']!r} with hostile input: {resp.error}"
                )
                assertions_made += 1
                continue

            # Success path: scan content for hostile-string echo + traceback.
            content = resp.result.get("content", []) if resp.result else []
            response_text = " ".join(
                str(c.get("text", "")) if isinstance(c, dict) else str(c)
                for c in content
            )
            assert "Traceback (most recent call last)" not in response_text, (
                f"{tool['name']!r} leaked a Python traceback in response content"
            )
            assert '  File "' not in response_text, (
                f"{tool['name']!r} leaked Python file paths in response content"
            )
            # Verbatim echo of the hostile string back to the agent IS the
            # vulnerability for indirect-injection purposes. Allow only if
            # the response is empty or the echo is wrapped (Pattern 1 hint).
            if hostile and hostile in response_text and len(hostile) >= 8:
                # Check whether the response framed the echoed hostile string.
                response_json = str(resp.raw)
                if not any(p in response_json for p in [
                    "<untrusted", "untrusted_content", "isUntrusted",
                    '"untrusted":', "data-vs-instructions",
                ]):
                    pytest.fail(
                        f"{tool['name']!r} echoed hostile input {hostile[:60]!r} "
                        f"verbatim in response content WITHOUT a data-vs-"
                        f"instructions discriminator. An agent reading this "
                        f"result will treat the echoed string as authoritative."
                    )
            assertions_made += 1

    if not found_string_arg:
        pytest.skip("no string-typed tool args to probe")
    if assertions_made == 0:
        pytest.skip("hostile-input branches all skipped — nothing to assert")


def test_nonexistent_id_returns_error_not_fabrication(client):
    """If a tool takes an ID-shaped argument, a fake ID must produce an
    explicit error — not a content block describing an invented record."""
    listing = client.call("tools/list", {})
    if listing.is_error or not listing.result.get("tools"):
        pytest.skip("server has no tools")

    id_pattern = re.compile(r"_id$|^id$|alert_?id|rule_?id|agent_?id", re.IGNORECASE)
    fake_id = "abuse-harness-DOES-NOT-EXIST-99999"
    found_id_tool = False

    for tool in listing.result["tools"]:
        schema = tool.get("inputSchema", {}) or {}
        props = schema.get("properties", {}) or {}
        id_arg = next((k for k in props if id_pattern.search(k)), None)
        if not id_arg:
            continue
        found_id_tool = True
        resp = client.call(
            "tools/call",
            {"name": tool["name"], "arguments": {id_arg: fake_id}},
            timeout=5.0,
        )
        if resp.is_error:
            continue  # correct
        # Otherwise — server returned success for a fake ID. That's fabrication
        # unless the response content is empty / explicitly says "not found".
        content = resp.result.get("content", []) if resp.result else []
        response_text = " ".join(
            str(c.get("text", "")) if isinstance(c, dict) else str(c)
            for c in content
        )
        normalized = response_text.lower()
        recognized_not_found = any(
            phrase in normalized for phrase in ("not found", "no such", "does not exist", "unknown")
        )
        assert recognized_not_found or not response_text.strip(), (
            f"Tool {tool['name']!r} returned a non-error, non-empty response for "
            f"a fake ID {fake_id!r}. This is fabrication — the server must say "
            f"'not found' explicitly. Response text: {response_text[:300]!r}"
        )

    if not found_id_tool:
        pytest.skip("no ID-shaped tool args to probe")
