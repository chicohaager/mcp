"""Network diagnostic tools for ZimaOS MCP Server."""

import asyncio
import re

from config import ServerConfig
from security import SecurityManager
from tools.utils import make_response

# Hostname/IP validation: alphanumeric, dots, colons (IPv6), hyphens
_VALID_HOST_RE = re.compile(r"^[a-zA-Z0-9.:_-]+$")


def _validate_host(host: str) -> tuple[bool, str]:
    """Validate a hostname/IP to prevent argument injection."""
    if not host or host.startswith("-"):
        return False, "Invalid host: must not start with '-'"
    if not _VALID_HOST_RE.match(host):
        return False, "Invalid host: contains disallowed characters"
    return True, ""


async def _run(cmd: list[str], timeout: int = 10) -> tuple[bool, str]:
    """Run a system command."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except OSError as e:
        return False, str(e)

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode("utf-8", errors="replace")
        if proc.returncode != 0:
            output += stderr.decode("utf-8", errors="replace")
        return proc.returncode == 0, output
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return False, "Command timed out"


async def net_ping(
    host: str, count: int = 4, *, config: ServerConfig, security: SecurityManager
) -> dict:
    """Ping a host.

    Args:
        host: Hostname or IP to ping.
        count: Number of pings (default: 4, max: 20).
        config: Server configuration.
        security: Security manager.
    """
    ok, err = _validate_host(host)
    if not ok:
        return make_response(False, error=err)
    count = min(count, 20)
    ok, output = await _run(["ping", "-c", str(count), "-W", "3", host], timeout=count * 4)
    security.audit.log("net_ping", {"host": host, "count": count}, ok)
    return make_response(ok, data={"host": host, "output": output})


async def net_dns(
    hostname: str, record_type: str = "A",
    *, config: ServerConfig, security: SecurityManager
) -> dict:
    """DNS lookup.

    Args:
        hostname: Domain name to resolve.
        record_type: DNS record type (A, AAAA, MX, CNAME, TXT, NS).
        config: Server configuration.
        security: Security manager.
    """
    ok, err = _validate_host(hostname)
    if not ok:
        return make_response(False, error=err)
    valid_types = {"A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA", "PTR"}
    record_type = record_type.upper()
    if record_type not in valid_types:
        return make_response(False, error=f"Invalid record type. Must be one of {valid_types}")

    # Try nslookup first (more commonly available)
    ok, output = await _run(["nslookup", f"-type={record_type}", hostname])
    if not ok:
        # Fallback to host command
        ok, output = await _run(["host", f"-t", record_type, hostname])

    security.audit.log("net_dns", {"hostname": hostname, "type": record_type}, ok)
    return make_response(ok, data={"hostname": hostname, "type": record_type, "output": output})


async def net_traceroute(
    host: str, max_hops: int = 15,
    *, config: ServerConfig, security: SecurityManager
) -> dict:
    """Traceroute to a host.

    Args:
        host: Target hostname or IP.
        max_hops: Maximum number of hops (default: 15, max: 30).
        config: Server configuration.
        security: Security manager.
    """
    ok, err = _validate_host(host)
    if not ok:
        return make_response(False, error=err)
    max_hops = min(max_hops, 30)
    ok, output = await _run(
        ["traceroute", "-m", str(max_hops), "-w", "2", host],
        timeout=max_hops * 3,
    )
    security.audit.log("net_traceroute", {"host": host}, ok)
    return make_response(ok, data={"host": host, "output": output})


async def net_port_check(
    host: str, port: int, timeout_s: int = 5,
    *, config: ServerConfig, security: SecurityManager
) -> dict:
    """Check if a TCP port is open.

    Args:
        host: Target hostname or IP.
        port: TCP port number.
        timeout_s: Connection timeout in seconds (default: 5).
        config: Server configuration.
        security: Security manager.
    """
    ok, err = _validate_host(host)
    if not ok:
        return make_response(False, error=err)
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout_s,
        )
        writer.close()
        await writer.wait_closed()
        result = {"host": host, "port": port, "open": True}
        security.audit.log("net_port_check", {"host": host, "port": port}, True)
        return make_response(True, data=result)
    except (ConnectionRefusedError, OSError):
        result = {"host": host, "port": port, "open": False}
        security.audit.log("net_port_check", {"host": host, "port": port}, True)
        return make_response(True, data=result)
    except asyncio.TimeoutError:
        result = {"host": host, "port": port, "open": False, "reason": "timeout"}
        return make_response(True, data=result)
