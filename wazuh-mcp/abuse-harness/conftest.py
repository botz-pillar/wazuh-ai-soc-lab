"""Pytest fixtures for the AI-CSL MCP abuse harness.

Configure the server under test via env vars:

    MCP_SERVER_CMD       — required. Shell-split into argv. Example:
                           "python -m my_wazuh_mcp"
    MCP_SERVER_CWD       — optional. Working dir to launch in.

Or via pytest --server-cmd / --server-cwd flags.
"""

from __future__ import annotations

import os
import shlex

import pytest

from harness.client import StdioMCPClient


def pytest_addoption(parser):
    parser.addoption("--server-cmd", default=None,
                     help="Command to launch the student's MCP server (shell-quoted).")
    parser.addoption("--server-cwd", default=None,
                     help="Working directory for the server.")


@pytest.fixture(scope="session")
def server_cmd(request) -> list[str]:
    cmd = request.config.getoption("--server-cmd") or os.environ.get("MCP_SERVER_CMD")
    if not cmd:
        pytest.skip(
            "MCP_SERVER_CMD not set. Configure the harness with:\n"
            "    export MCP_SERVER_CMD='python -m my_wazuh_mcp'\n"
            "or pass --server-cmd='...' on the pytest CLI."
        )
    return shlex.split(cmd)


@pytest.fixture(scope="session")
def server_cwd(request) -> str | None:
    return request.config.getoption("--server-cwd") or os.environ.get("MCP_SERVER_CWD")


@pytest.fixture
def client(server_cmd, server_cwd):
    """Fresh server process per test (isolation matters for state-y tests)."""
    with StdioMCPClient(cmd=server_cmd, cwd=server_cwd) as c:
        c.initialize()
        yield c
