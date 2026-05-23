"""Minimal JSON-RPC 2.0 stdio client for testing MCP servers.

Deliberately minimal: we want to send adversarial / malformed messages the
official mcp SDK might refuse to send, so we speak the wire protocol directly.

Usage:

    cmd = ["python", "-m", "my_wazuh_mcp"]
    with StdioMCPClient(cmd) as c:
        c.initialize()
        resp = c.call("resources/list", {})
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from queue import Empty, Queue
from typing import Any


DEFAULT_PROTOCOL_VERSION = "2025-06-18"
PROTOCOL_VERSION = os.environ.get("MCP_PROTOCOL_VERSION", DEFAULT_PROTOCOL_VERSION)
DEFAULT_INIT_TIMEOUT = 8.0
DEFAULT_CALL_TIMEOUT = 5.0


@dataclass
class JsonRpcResponse:
    raw: dict
    id: Any = None
    result: Any = None
    error: dict | None = None

    @classmethod
    def parse(cls, raw: dict) -> "JsonRpcResponse":
        return cls(
            raw=raw,
            id=raw.get("id"),
            result=raw.get("result"),
            error=raw.get("error"),
        )

    @property
    def is_error(self) -> bool:
        return self.error is not None


@dataclass
class StdioMCPClient:
    cmd: list[str]
    env: dict[str, str] | None = None
    cwd: str | None = None
    proc: subprocess.Popen | None = field(default=None, init=False)
    _next_id: int = field(default=1, init=False)
    _stderr_lines: list[str] = field(default_factory=list, init=False)
    _resp_queue: "Queue[dict]" = field(default_factory=Queue, init=False)
    _initialized: bool = field(default=False, init=False)

    def __enter__(self) -> "StdioMCPClient":
        self.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # ---------------- lifecycle ---------------- #

    def start(self) -> None:
        env = os.environ.copy()
        if self.env:
            env.update(self.env)
        self.proc = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=self.cwd,
            text=True,
            bufsize=1,
        )

        # Background readers so we never block on stdout/stderr.
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin.close()  # type: ignore[union-attr]
            except (OSError, ValueError):
                pass
            try:
                self.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    self.proc.kill()

    # ---------------- I/O ---------------- #

    def _read_stdout(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Server emitted non-JSON on stdout: protocol violation, but
                # the harness records it via stderr buffer for tests to assert.
                self._stderr_lines.append(f"NON-JSON-STDOUT: {line!r}")
                continue
            self._resp_queue.put(obj)

    def _read_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for line in self.proc.stderr:
            self._stderr_lines.append(line.rstrip("\n"))

    @property
    def stderr_text(self) -> str:
        return "\n".join(self._stderr_lines)

    # ---------------- JSON-RPC ---------------- #

    def _send(self, message: dict) -> None:
        assert self.proc and self.proc.stdin
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def _await_response(self, request_id: Any, timeout: float) -> JsonRpcResponse:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                msg = self._resp_queue.get(timeout=max(0.05, deadline - time.monotonic()))
            except Empty:
                continue
            if msg.get("id") == request_id:
                return JsonRpcResponse.parse(msg)
            # Otherwise it's a notification or another response; buffer-skip.
        raise TimeoutError(
            f"No response for id={request_id} within {timeout}s. Stderr:\n{self.stderr_text}"
        )

    def call(
        self,
        method: str,
        params: dict | None = None,
        *,
        timeout: float = DEFAULT_CALL_TIMEOUT,
    ) -> JsonRpcResponse:
        rid = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        return self._await_response(rid, timeout)

    def notify(self, method: str, params: dict | None = None) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def send_raw(self, payload: str) -> None:
        """Send a raw line — for malformed-input tests."""
        assert self.proc and self.proc.stdin
        self.proc.stdin.write(payload + "\n")
        self.proc.stdin.flush()

    # ---------------- MCP-specific ---------------- #

    def initialize(self, timeout: float = DEFAULT_INIT_TIMEOUT) -> JsonRpcResponse:
        resp = self.call(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "clientInfo": {"name": "ai-csl-abuse-harness", "version": "1.0.0"},
                "capabilities": {},
            },
            timeout=timeout,
        )
        if resp.is_error:
            raise RuntimeError(f"initialize failed: {resp.error}")
        self.notify("notifications/initialized")
        self._initialized = True
        return resp
