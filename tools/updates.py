"""ZimaOS update tools for MCP Server."""

import asyncio
import json
import os
import urllib.request
import urllib.error

from config import ServerConfig
from security import SecurityManager
from tools.utils import make_response

CASAOS_API = "http://localhost:9090"


async def _http_request(url: str, method: str = "GET", timeout: int = 10) -> tuple[bool, str]:
    """Make an HTTP request using urllib (no curl dependency)."""
    def _do():
        req = urllib.request.Request(url, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return True, resp.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)

    return await asyncio.to_thread(_do)


async def zima_update_check(*, config: ServerConfig, security: SecurityManager) -> dict:
    """Check for ZimaOS system updates.

    Queries the ZimaOS update API for available updates.

    Args:
        config: Server configuration.
        security: Security manager.
    """
    info = {}

    # Current version
    for ver_path in ["/etc/zimaos-version", "/host/etc/zimaos-version"]:
        if os.path.exists(ver_path):
            try:
                with open(ver_path) as f:
                    info["current_version"] = f.read().strip()
                break
            except OSError:
                pass
    else:
        # Parse from os-release style files
        for rel_path in ["/host/etc/zimaos-release", "/host/etc/os-release"]:
            if os.path.exists(rel_path):
                try:
                    with open(rel_path) as f:
                        for line in f:
                            if line.startswith("VERSION="):
                                info["current_version"] = line.split("=", 1)[1].strip().strip('"')
                                break
                    if "current_version" in info:
                        break
                except OSError:
                    pass

    # Check via CasaOS API (runs locally)
    ok, body = await _http_request(f"{CASAOS_API}/v2/zimaos/update/check")
    if ok:
        try:
            info["update_info"] = json.loads(body)
        except json.JSONDecodeError:
            info["update_raw"] = body
    else:
        info["update_check"] = f"Could not reach update API: {body}"

    security.audit.log("zima_update_check", {}, True)
    return make_response(True, data=info)


async def zima_update_apply(*, config: ServerConfig, security: SecurityManager) -> dict:
    """Apply ZimaOS system update.

    Triggers the update process via the ZimaOS API.
    WARNING: This may cause a system restart.

    Args:
        config: Server configuration.
        security: Security manager.
    """
    ok, body = await _http_request(f"{CASAOS_API}/v2/zimaos/update/apply", method="POST", timeout=30)
    security.audit.log("zima_update_apply", {}, ok)

    if ok:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {"raw": body}
        return make_response(True, data=data)
    else:
        return make_response(False, error=f"Update failed: {body}")


async def zima_changelog(*, config: ServerConfig, security: SecurityManager) -> dict:
    """Read ZimaOS release information as structured data.

    Reads /host/etc/zimaos-release or /host/etc/os-release and returns
    all fields as key-value pairs.

    Args:
        config: Server configuration.
        security: Security manager.
    """
    release_info = {}
    source = None

    for rel_path in ["/host/etc/zimaos-release", "/host/etc/os-release"]:
        if not os.path.exists(rel_path):
            continue
        try:
            with open(rel_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, _, value = line.partition("=")
                        # Strip surrounding quotes from value
                        value = value.strip().strip('"').strip("'")
                        release_info[key.strip()] = value
            source = rel_path
            break
        except OSError:
            continue

    if not release_info:
        return make_response(
            False,
            error="No release file found at /host/etc/zimaos-release or /host/etc/os-release",
        )

    security.audit.log("zima_changelog", {"source": source}, True)
    return make_response(True, data={"release_info": release_info, "source": source})
