"""ZimaOS-specific tools for MCP Server."""

import asyncio
import json
import os

from config import ServerConfig
from security import SecurityManager
from tools.utils import make_response, run_docker as _run_docker


async def zima_apps_list(*, config: ServerConfig, security: SecurityManager) -> dict:
    """List installed ZimaOS apps.

    Discovers apps by scanning Docker containers with CasaOS labels
    and compose files under /DATA/AppData/.

    Args:
        config: Server configuration.
        security: Security manager.
    """
    apps = []

    # Get containers with labels
    ok, stdout, stderr = await _run_docker(
        ["ps", "-a", "--format", "json"], config
    )
    if ok:
        containers = []
        for line in stdout.strip().splitlines():
            if line.strip():
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        for c in containers:
            apps.append({
                "name": c.get("Names", ""),
                "image": c.get("Image", ""),
                "status": c.get("Status", ""),
                "state": c.get("State", ""),
                "ports": c.get("Ports", ""),
            })

    # Also scan AppData for compose files
    appdata = "/DATA/AppData"
    if os.path.isdir(appdata):
        for entry in os.listdir(appdata):
            compose_path = os.path.join(appdata, entry, "docker-compose.yml")
            if os.path.exists(compose_path):
                # Check if already in apps list
                if not any(a["name"] == entry for a in apps):
                    apps.append({
                        "name": entry,
                        "compose_file": compose_path,
                        "status": "unknown (no running container)",
                    })

    security.audit.log("zima_apps_list", {}, True)
    return make_response(True, data={"apps": apps, "count": len(apps)})


async def zima_app_install(
    app_id: str,
    config_data: dict | None = None,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Install an app from a compose definition.

    Args:
        app_id: App identifier (used as directory name under /DATA/AppData/).
        config_data: Optional compose override dict.
        config: Server configuration.
        security: Security manager.
    """
    # Validate app_id against path traversal
    if "/" in app_id or "\\" in app_id or ".." in app_id:
        return make_response(False, error="Invalid app_id: must not contain path separators or '..'")

    app_dir = f"/DATA/AppData/{app_id}"
    ok, err = security.validate_path(app_dir, write=False)
    if not ok:
        return make_response(False, error=err)

    compose_file = os.path.join(app_dir, "docker-compose.yml")

    if not os.path.exists(compose_file):
        return make_response(
            False,
            error=f"No docker-compose.yml found at {compose_file}. "
            "Place the compose file first, then install.",
        )

    ok, stdout, stderr = await _run_docker(
        ["compose", "-f", compose_file, "up", "-d"], config, timeout=120
    )

    security.audit.log("zima_app_install", {"app_id": app_id}, ok)
    return make_response(
        ok,
        data={"app_id": app_id, "stdout": stdout},
        error=stderr if not ok else None,
    )


async def zima_app_config(
    app_id: str,
    config_data: dict | None = None,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Read or write app configuration.

    If config_data is None, reads the current compose config.
    If config_data is provided, writes it as JSON config for the app.

    Args:
        app_id: App identifier.
        config_data: Configuration dict to write (None = read).
        config: Server configuration.
        security: Security manager.
    """
    # Validate app_id against path traversal
    if "/" in app_id or "\\" in app_id or ".." in app_id:
        return make_response(False, error="Invalid app_id: must not contain path separators or '..'")

    app_dir = f"/DATA/AppData/{app_id}"
    write = config_data is not None
    ok, err = security.validate_path(app_dir, write=write)
    if not ok:
        return make_response(False, error=err)

    config_file = os.path.join(app_dir, "config.json")

    if config_data is None:
        # Read mode
        compose_file = os.path.join(app_dir, "docker-compose.yml")
        result = {}

        if os.path.exists(config_file):
            try:
                with open(config_file) as f:
                    result["config"] = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                result["config_error"] = str(e)

        if os.path.exists(compose_file):
            try:
                with open(compose_file) as f:
                    result["compose"] = f.read()
            except OSError as e:
                result["compose_error"] = str(e)

        if not result:
            return make_response(False, error=f"No config found for {app_id}")
        return make_response(True, data=result)
    else:
        # Write mode
        os.makedirs(app_dir, exist_ok=True)
        try:
            with open(config_file, "w") as f:
                json.dump(config_data, f, indent=2)
            security.audit.log(
                "zima_app_config", {"app_id": app_id, "action": "write"}, True
            )
            return make_response(True, data={"path": config_file})
        except OSError as e:
            return make_response(False, error=str(e))


async def zima_storage_info(*, config: ServerConfig, security: SecurityManager) -> dict:
    """Get ZimaOS storage pool and mount information.

    Args:
        config: Server configuration.
        security: Security manager.
    """
    info = {}

    # Mount points
    ok, stdout, _ = await _run_docker(
        ["run", "--rm", "-v", "/:/host:ro", "alpine", "cat", "/host/proc/mounts"],
        config,
        timeout=10,
    )
    # Fallback: read directly
    if not ok:
        try:
            with open("/proc/mounts") as f:
                stdout = f.read()
            ok = True
        except OSError:
            pass

    if ok:
        mounts = []
        for line in stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1].startswith("/DATA"):
                mounts.append({
                    "device": parts[0],
                    "mount": parts[1],
                    "fstype": parts[2],
                })
        info["data_mounts"] = mounts

    # Disk usage for /DATA
    proc = await asyncio.create_subprocess_exec(
        "df", "-h", "/DATA",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, _ = await proc.communicate()
    if proc.returncode == 0:
        lines = stdout_b.decode().strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            info["data_disk"] = {
                "device": parts[0],
                "size": parts[1],
                "used": parts[2],
                "available": parts[3],
                "percent": parts[4],
            }

    return make_response(True, data=info)


async def zima_shares(*, config: ServerConfig, security: SecurityManager) -> dict:
    """Get SMB/NFS share configuration.

    Args:
        config: Server configuration.
        security: Security manager.
    """
    info = {}

    # SMB config
    smb_paths = ["/etc/samba/smb.conf", "/host/etc/samba/smb.conf"]
    for path in smb_paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    info["smb_config"] = f.read()
                break
            except OSError:
                pass

    # NFS exports
    nfs_paths = ["/etc/exports", "/host/etc/exports"]
    for path in nfs_paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    info["nfs_exports"] = f.read()
                break
            except OSError:
                pass

    if not info:
        info["message"] = "No SMB/NFS configuration found"

    return make_response(True, data=info)
