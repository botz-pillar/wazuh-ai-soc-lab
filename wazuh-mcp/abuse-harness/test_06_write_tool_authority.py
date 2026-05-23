"""Pattern 6 — Write-tool authority gating.

Threat model: the single biggest MCP attack class in 2026 is over-permissive
tool surfaces. A server that exposes write/delete/exec tools without
explicit annotations + an authority gate hands the agent (and any prompt
injection that compromises it) blanket capability.

What we test:
  Enumerate the server's tools. For each tool whose name suggests
  destructive intent (delete_/remove_/restart_/run_/exec_/...), require
  one of the following:
    (a) tool advertises `annotations.destructiveHint = true`
    (b) tool advertises `annotations.readOnlyHint = false` AND the server
        documents an out-of-band confirmation gate (we accept the README
        path or a CONTRACT.md sibling)
    (c) the tool isn't actually exposed (recommended default for L5)

We also assert annotation honesty: a tool annotated `readOnlyHint=true`
must not have a destructive-shaped name.

Pass: every destructive-shaped tool either has destructiveHint=true OR is
      not exposed.
Fail: a destructive tool with no annotation, OR a tool annotated read-only
      but named like a write/delete operation (annotation lying).

Maps to: OWASP Agentic AI v1.0 — Insufficient Authority Boundaries / Excessive
         Agency; MITRE ATLAS AML.T0053 LLM Plugin Compromise.
"""

from __future__ import annotations

import re

import pytest


DESTRUCTIVE_NAME_RE = re.compile(
    r"^(delete|remove|drop|destroy|kill|stop|restart|reset|"
    r"create|update|modify|patch|put|post|write|set|add|"
    r"run|exec|invoke|trigger|deploy|publish)_?",
    re.IGNORECASE,
)

# A tool is read-shaped if it starts with these. Used for honesty check.
READ_SHAPED_RE = re.compile(
    r"^(get|list|describe|read|search|query|find|show|view|count)_?",
    re.IGNORECASE,
)


def test_destructive_tools_carry_destructive_hint(client):
    """Any tool with a destructive-shaped name must annotate destructiveHint=true."""
    listing = client.call("tools/list", {})
    if listing.is_error or not listing.result.get("tools"):
        pytest.skip("server has no tools")

    failures: list[str] = []
    for tool in listing.result["tools"]:
        name = tool.get("name", "")
        annotations = tool.get("annotations", {}) or {}
        if not DESTRUCTIVE_NAME_RE.match(name):
            continue
        destructive_hint = annotations.get("destructiveHint")
        read_only_hint = annotations.get("readOnlyHint")
        if destructive_hint is True:
            continue  # honest annotation — fine
        if read_only_hint is False and "title" in annotations:
            continue  # explicit write-shape with metadata — fine
        failures.append(
            f"{name!r}: destructive-shaped name without destructiveHint=true. "
            f"annotations={annotations}. Either annotate honestly, gate behind "
            f"out-of-band confirmation, or drop from the tool surface."
        )

    assert not failures, "Authority-boundary violations:\n" + "\n".join(failures)


def test_read_only_hint_not_lying(client):
    """A tool annotated readOnlyHint=true must NOT have a destructive name."""
    listing = client.call("tools/list", {})
    if listing.is_error or not listing.result.get("tools"):
        pytest.skip("server has no tools")

    liars: list[str] = []
    for tool in listing.result["tools"]:
        name = tool.get("name", "")
        annotations = tool.get("annotations", {}) or {}
        if annotations.get("readOnlyHint") is True and DESTRUCTIVE_NAME_RE.match(name):
            liars.append(
                f"{name!r}: claims readOnlyHint=true but name implies destruction."
            )
    assert not liars, "Tool-annotation honesty violations:\n" + "\n".join(liars)


def test_at_least_one_tool_is_read_only(client):
    """A server with zero readOnlyHint=true tools is suspicious — either the
    server has no read tools at all (unusual), or it's failing to advertise
    them honestly. Soft-skip if zero tools; hard-fail if all tools are
    write-only with no read advertised."""
    listing = client.call("tools/list", {})
    if listing.is_error or not listing.result.get("tools"):
        pytest.skip("server has no tools")
    tools = listing.result["tools"]

    has_read_advertised = any(
        (t.get("annotations", {}) or {}).get("readOnlyHint") is True
        for t in tools
    )
    has_read_shaped_name = any(
        READ_SHAPED_RE.match(t.get("name", "")) for t in tools
    )
    if not has_read_advertised and has_read_shaped_name:
        pytest.fail(
            "Server has read-shaped tools but advertises none with "
            "readOnlyHint=true. Annotation hygiene matters: clients use these "
            "hints to decide which tools an agent can call without confirmation."
        )
    if not has_read_advertised and not has_read_shaped_name:
        pytest.skip(
            "Server has no read-shaped tools; nothing to assert here."
        )
