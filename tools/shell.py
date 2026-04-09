"""Shell execution tools for ZimaOS MCP Server."""

import asyncio
import os
import tempfile

from config import ServerConfig
from security import SecurityManager
from tools.utils import make_response


async def bash_exec(
    command: str,
    timeout: int = 60,
    cwd: str = "/DATA",
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Execute a shell command on ZimaOS.

    Args:
        command: Command to execute.
        timeout: Timeout in seconds (default: 60).
        cwd: Working directory (default: /DATA).
        config: Server configuration.
        security: Security manager.

    Returns:
        Dict with stdout, stderr, exit_code, timed_out.
    """
    # Rate limit
    ok, err = security.check_rate_limit()
    if not ok:
        return make_response(False, error=err)

    # Validate command
    ok, err = security.validate_command(command)
    if not ok:
        security.audit.log("bash_exec", {"command": command}, False, err)
        return make_response(False, error=err)

    # Clamp timeout
    timeout = min(timeout, config.max_timeout)

    env = os.environ.copy()
    env["DOCKER_CONFIG"] = config.docker_config

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            result = {
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "exit_code": proc.returncode,
                "timed_out": False,
            }
            security.audit.log(
                "bash_exec",
                {"command": command, "cwd": cwd},
                proc.returncode == 0,
            )
            return make_response(proc.returncode == 0, data=result)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            security.audit.log(
                "bash_exec", {"command": command}, False, "timed out"
            )
            return make_response(
                False,
                data={"stdout": "", "stderr": "", "exit_code": -1, "timed_out": True},
                error=f"Command timed out after {timeout}s",
            )
    except OSError as e:
        return make_response(False, error=str(e))


async def bash_script(
    script: str,
    interpreter: str = "/bin/bash",
    timeout: int = 60,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Execute a multi-line script on ZimaOS.

    Args:
        script: Script content (multi-line).
        interpreter: Shell interpreter (default: /bin/bash).
        timeout: Timeout in seconds.
        config: Server configuration.
        security: Security manager.

    Returns:
        Dict with stdout, stderr, exit_code, timed_out.
    """
    ok, err = security.check_rate_limit()
    if not ok:
        return make_response(False, error=err)

    # Validate interpreter
    allowed_interpreters = {"/bin/bash", "/bin/sh", "/bin/dash", "/bin/zsh"}
    if interpreter not in allowed_interpreters:
        return make_response(
            False, error=f"Interpreter not allowed: {interpreter}. Must be one of {allowed_interpreters}"
        )

    # Validate the entire script as a single string (catches multi-line constructs)
    ok, err = security.validate_command(script)
    if not ok:
        security.audit.log("bash_script", {"script": script[:200]}, False, err)
        return make_response(False, error=err)

    # Also validate each non-comment line individually
    for line in script.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ok, err = security.validate_command(line)
        if not ok:
            security.audit.log("bash_script", {"script": script[:200]}, False, err)
            return make_response(False, error=err)

    timeout = min(timeout, config.max_timeout)

    env = os.environ.copy()
    env["DOCKER_CONFIG"] = config.docker_config

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False
        ) as tmp:
            tmp.write(script)
            tmp_path = tmp.name

        try:
            proc = await asyncio.create_subprocess_exec(
                interpreter,
                tmp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                result = {
                    "stdout": stdout.decode("utf-8", errors="replace"),
                    "stderr": stderr.decode("utf-8", errors="replace"),
                    "exit_code": proc.returncode,
                    "timed_out": False,
                }
                security.audit.log(
                    "bash_script",
                    {"script_lines": len(script.splitlines())},
                    proc.returncode == 0,
                )
                return make_response(proc.returncode == 0, data=result)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return make_response(
                    False,
                    data={"stdout": "", "stderr": "", "exit_code": -1, "timed_out": True},
                    error=f"Script timed out after {timeout}s",
                )
        finally:
            os.unlink(tmp_path)
    except OSError as e:
        return make_response(False, error=str(e))
