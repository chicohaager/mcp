"""Shared utilities for ZimaOS MCP tool modules."""

import asyncio
import os
from typing import Any

from config import ServerConfig


def make_response(success: bool, data: Any = None, error: str | None = None) -> dict:
    """Create a standardized tool response dict."""
    return {"success": success, "data": data, "error": error}


async def run_docker(
    args: list[str], config: ServerConfig, timeout: int = 30
) -> tuple[bool, str, str]:
    """Run a docker command with proper DOCKER_CONFIG.

    Args:
        args: Docker command arguments (without 'docker' prefix).
        config: Server configuration.
        timeout: Command timeout in seconds.

    Returns:
        Tuple of (success, stdout, stderr).
    """
    env = os.environ.copy()
    env["DOCKER_CONFIG"] = config.docker_config

    proc = await asyncio.create_subprocess_exec(
        "docker",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            proc.returncode == 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return False, "", "Command timed out"
