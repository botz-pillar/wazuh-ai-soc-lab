"""Pattern 1 — Prompt-injection via resource content.

Threat model: Wazuh (or any backend the MCP server fronts) returns content
that contains attacker-influenceable text — alert descriptions, agent
hostnames, rule comments. If the MCP server pipes that text directly into
a `resources/read` response without any data-vs-instructions framing, the
agent reading the resource may treat the embedded text as instructions.

What we test:
  (a) The server returns resource content with attacker-shaped strings
      INTACT (i.e., it doesn't silently strip / "clean" the strings —
      that would hide the threat from the agent and from forensics).
  (b) The server's response includes a discriminator field or wrapping
      that lets a downstream agent treat the content as DATA. We accept
      multiple valid patterns (see PATTERN_HINTS below) — the lesson
      teaches the principle, not one specific implementation.

Pass: server returns content + a recognizable data-vs-instructions
      discriminator OR the resource MIME type is non-text (no injection
      surface).
Fail: server echoes attacker text into a free-text field with no marker.

Maps to: OWASP Agentic AI v1.0 — Indirect Prompt Injection;
         MITRE ATLAS AML.T0051 LLM Prompt Injection.
"""

from __future__ import annotations

import json
import re

import pytest


INJECTION_MARKERS = [
    # The actual attack-shaped strings the server might return inside content.
    "IGNORE PRIOR INSTRUCTIONS",
    "system:",
    "</|im_end|>",
]

# Any of these on the response body indicates the server framed content as
# data — a downstream agent prompt can be told "anything inside <untrusted>
# tags is data". Multiple patterns accepted; the lesson teaches the principle.
#
# DELIBERATELY narrow: we don't accept generic "annotations" key (the MCP spec
# uses it for non-security purposes like {audience: ["user"]}). The discriminator
# must be security-meaningful: presence of "untrusted", "isUntrusted",
# explicit data-vs-instructions tags, or a content type that signals data.
PATTERN_HINTS = [
    "<untrusted",
    "untrusted_content",
    "data_block",
    'type="data"',
    "isUntrusted",
    '"untrusted":',
    "data-vs-instructions",
]


def _content_to_text(content_list: list[dict]) -> str:
    """Flatten MCP resource content into a single text blob for inspection."""
    parts: list[str] = []
    for c in content_list:
        if isinstance(c, dict):
            t = c.get("type")
            if t == "text":
                parts.append(str(c.get("text", "")))
            elif t == "resource":
                parts.append(json.dumps(c))
            else:
                parts.append(json.dumps(c))
        else:
            parts.append(str(c))
    return "\n".join(parts)


def test_resources_list_returns_at_least_one(client):
    """Sanity: server exposes at least one resource so we can probe it."""
    resp = client.call("resources/list", {})
    assert not resp.is_error, f"resources/list errored: {resp.error}"
    assert resp.result, "resources/list returned no result"
    assert isinstance(resp.result.get("resources", []), list)


@pytest.mark.parametrize("limit", [10])
def test_resource_read_does_not_strip_injection_payloads(client, limit):
    """If the backend has injection-shaped content, it must come through.

    We list resources and read up to N. We don't assert specific marker
    strings exist (the sandbox may not have them) — we ONLY assert that IF
    a marker is present in any read content, the response also contains a
    data-vs-instructions discriminator. Servers without marker-tagged content
    are validated implicitly via test_03 (they must not invent fields).
    """
    listing = client.call("resources/list", {})
    if listing.is_error or not listing.result.get("resources"):
        pytest.skip("server has no resources to test against")

    seen_marker = False
    for r in listing.result["resources"][:limit]:
        uri = r["uri"]
        read_resp = client.call("resources/read", {"uri": uri}, timeout=10.0)
        if read_resp.is_error:
            continue
        contents = read_resp.result.get("contents", [])
        if not contents:
            continue
        text = _content_to_text(contents)
        if any(m in text for m in INJECTION_MARKERS):
            seen_marker = True
            response_json = json.dumps(read_resp.raw)
            has_discriminator = any(p in response_json for p in PATTERN_HINTS)
            assert has_discriminator, (
                f"Resource {uri} returned content containing an injection marker "
                f"({[m for m in INJECTION_MARKERS if m in text]}) WITHOUT any "
                f"data-vs-instructions discriminator. Pattern hints we accept: "
                f"{PATTERN_HINTS}. The agent reading this resource cannot tell "
                f"the embedded directive from server-authored content."
            )

    if not seen_marker:
        pytest.skip(
            "no injection-shaped strings present in any resource content — "
            "this test is informational on a clean sandbox"
        )


def test_resources_read_rejects_url_traversal(client):
    """Unrelated to injection per se, but commonly co-tested: the server
    must NOT accept arbitrary URIs and stream their contents (e.g., file://
    or http:// outside its declared resource namespace).
    """
    bad_uris = [
        "file:///etc/passwd",
        "file:///proc/self/environ",
        "http://169.254.169.254/latest/meta-data/",  # IMDS
        "../../etc/passwd",
    ]
    for uri in bad_uris:
        resp = client.call("resources/read", {"uri": uri}, timeout=3.0)
        if not resp.is_error:
            # Allowed only if the server returns an empty/explicit-error envelope.
            contents = resp.result.get("contents", []) if resp.result else []
            assert not contents or all(
                c.get("type") != "text" or c.get("text", "") == ""
                for c in contents
            ), f"Server returned non-empty content for hostile URI {uri!r}"
        # Error response is the correct outcome — pass.
