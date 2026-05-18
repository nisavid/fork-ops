#!/usr/bin/env python3
"""Run the Fork Ops MCP server from a plugin checkout."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _plugin_root() -> Path:
    return Path(os.environ.get("PLUGIN_ROOT", Path(__file__).resolve().parents[1])).resolve()


sys.path.insert(0, str(_plugin_root() / "src"))

from fork_ops.mcp_server import main  # noqa: E402

if __name__ == "__main__":
    main()
