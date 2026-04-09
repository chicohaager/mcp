"""Maintenance tools for ZimaOS MCP Server."""

import glob
import os
import shutil
import tarfile
import time

from config import ServerConfig
from security import SecurityManager
from tools.utils import make_response

BACKUP_DIR = "/DATA/AppData/zimaos-mcp/backups"


async def audit_log_rotate(
    max_size_mb: int = 10,
    keep_rotated: int = 3,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Rotate the audit log if it exceeds max size.

    Args:
        max_size_mb: Max size before rotation (default: 10 MB).
        keep_rotated: Number of rotated files to keep (default: 3).
        config: Server configuration.
        security: Security manager.
    """
    audit_path = config.audit_log
    if not os.path.exists(audit_path):
        return make_response(True, data={"message": "No audit log to rotate"})

    size_mb = os.path.getsize(audit_path) / (1024 * 1024)
    if size_mb < max_size_mb:
        return make_response(
            True,
            data={
                "message": f"Audit log is {size_mb:.1f} MB, below threshold of {max_size_mb} MB",
                "rotated": False,
            },
        )

    # Rotate: audit.log -> audit.log.1, audit.log.1 -> audit.log.2, etc.
    for i in range(keep_rotated, 0, -1):
        src = f"{audit_path}.{i}" if i > 0 else audit_path
        dst = f"{audit_path}.{i + 1}"
        if i == keep_rotated:
            # Delete oldest
            if os.path.exists(f"{audit_path}.{i}"):
                os.remove(f"{audit_path}.{i}")
        elif os.path.exists(src):
            shutil.move(src, dst)

    # Move current log
    shutil.move(audit_path, f"{audit_path}.1")

    # Create fresh empty log
    with open(audit_path, "w") as f:
        f.write("")

    security.audit.log("audit_log_rotate", {"size_mb": round(size_mb, 1)}, True)
    return make_response(
        True,
        data={
            "message": f"Rotated audit log ({size_mb:.1f} MB)",
            "rotated": True,
            "kept": keep_rotated,
        },
    )


async def backup_cleanup(
    max_age_days: int = 30,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Clean up old file backups.

    Args:
        max_age_days: Delete backups older than this (default: 30 days).
        config: Server configuration.
        security: Security manager.
    """
    if not os.path.isdir(BACKUP_DIR):
        return make_response(True, data={"message": "No backup directory", "deleted": 0})

    cutoff = time.time() - (max_age_days * 86400)
    deleted = []
    kept = 0

    for path in glob.glob(os.path.join(BACKUP_DIR, "*.bak")):
        if os.path.getmtime(path) < cutoff:
            os.remove(path)
            deleted.append(os.path.basename(path))
        else:
            kept += 1

    security.audit.log("backup_cleanup", {"max_age_days": max_age_days}, True)
    return make_response(
        True,
        data={
            "deleted_count": len(deleted),
            "kept": kept,
            "deleted_files": deleted[:20],  # cap for response size
        },
    )


async def server_health(
    *, config: ServerConfig, security: SecurityManager
) -> dict:
    """Comprehensive health check.

    Args:
        config: Server configuration.
        security: Security manager.

    Returns:
        Health status with checks for disk, Docker, audit log.
    """
    import asyncio

    checks = {}

    # Disk space
    try:
        stat = os.statvfs("/DATA")
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        total_gb = (stat.f_blocks * stat.f_frsize) / (1024**3)
        checks["disk"] = {
            "status": "ok" if free_gb > 1 else "warn" if free_gb > 0.1 else "error",
            "free_gb": round(free_gb, 1),
            "total_gb": round(total_gb, 1),
            "percent_used": round((1 - free_gb / total_gb) * 100, 1) if total_gb > 0 else 0,
        }
    except OSError:
        checks["disk"] = {"status": "error", "message": "Cannot stat /DATA"}

    # Docker socket
    docker_sock = "/var/run/docker.sock"
    checks["docker_socket"] = {
        "status": "ok" if os.path.exists(docker_sock) else "error",
        "path": docker_sock,
    }

    # Audit log
    audit_path = config.audit_log
    if os.path.exists(audit_path):
        size_mb = os.path.getsize(audit_path) / (1024 * 1024)
        checks["audit_log"] = {
            "status": "ok" if size_mb < 50 else "warn" if size_mb < 100 else "error",
            "size_mb": round(size_mb, 1),
        }
    else:
        checks["audit_log"] = {"status": "ok", "size_mb": 0}

    # Data directory writable
    try:
        test_file = os.path.join(config.data_dir, ".healthcheck")
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)
        checks["data_writable"] = {"status": "ok"}
    except OSError as e:
        checks["data_writable"] = {"status": "error", "message": str(e)}

    # Overall status
    statuses = [c["status"] for c in checks.values()]
    if "error" in statuses:
        overall = "error"
    elif "warn" in statuses:
        overall = "warn"
    else:
        overall = "ok"

    return make_response(True, data={"status": overall, "checks": checks})


async def backup_create(
    name: str,
    paths: list[str],
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Create a tar.gz backup of specified paths under /DATA.

    Args:
        name: Backup name (used in filename).
        paths: List of paths to include in the backup.
        config: Server configuration.
        security: Security manager.
    """
    # Validate all paths
    for path in paths:
        ok, err = security.validate_path(path, write=False)
        if not ok:
            return make_response(False, error=f"Path validation failed for '{path}': {err}")
        if not os.path.exists(path):
            return make_response(False, error=f"Path does not exist: {path}")

    # Validate backup name (alphanumeric + hyphens + underscores)
    import re
    if not re.match(r"^[a-zA-Z0-9._-]+$", name):
        return make_response(
            False, error="Invalid backup name. Only alphanumeric, hyphens, dots, and underscores allowed."
        )

    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"{name}_{ts}.tar.gz")

    try:
        with tarfile.open(backup_file, "w:gz") as tar:
            for path in paths:
                arcname = os.path.basename(path)
                tar.add(path, arcname=arcname)

        size = os.path.getsize(backup_file)
        security.audit.log("backup_create", {"name": name, "paths": paths, "file": backup_file}, True)
        return make_response(True, data={
            "file": backup_file,
            "name": name,
            "paths": paths,
            "size_bytes": size,
            "size_mb": round(size / (1024 * 1024), 2),
        })
    except Exception as e:
        # Clean up partial backup
        if os.path.exists(backup_file):
            os.remove(backup_file)
        return make_response(False, error=str(e))


async def backup_list(
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """List all backups in the backup directory with size and date.

    Args:
        config: Server configuration.
        security: Security manager.
    """
    if not os.path.isdir(BACKUP_DIR):
        return make_response(True, data={"backups": [], "count": 0})

    backups = []
    for entry in sorted(os.listdir(BACKUP_DIR)):
        path = os.path.join(BACKUP_DIR, entry)
        if not os.path.isfile(path):
            continue
        if not entry.endswith(".tar.gz"):
            continue
        try:
            stat = os.stat(path)
            backups.append({
                "file": entry,
                "path": path,
                "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
            })
        except OSError:
            continue

    security.audit.log("backup_list", {}, True)
    return make_response(True, data={"backups": backups, "count": len(backups)})


async def backup_restore(
    backup_file: str,
    restore_path: str = "/DATA",
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Extract a backup tar.gz to restore files.

    Args:
        backup_file: Filename of the backup (must be under the backup directory).
        restore_path: Directory to extract into (default: /DATA).
        config: Server configuration.
        security: Security manager.
    """
    # Resolve full path if just a filename
    if not os.path.sep in backup_file:
        full_path = os.path.join(BACKUP_DIR, backup_file)
    else:
        full_path = backup_file

    # Validate the backup file is under the backup directory
    resolved = os.path.realpath(full_path)
    if not resolved.startswith(os.path.realpath(BACKUP_DIR)):
        return make_response(False, error="Backup file must be under the backup directory")

    if not os.path.exists(full_path):
        return make_response(False, error=f"Backup file not found: {full_path}")

    # Validate restore path
    ok, err = security.validate_path(restore_path, write=True)
    if not ok:
        return make_response(False, error=f"Restore path validation failed: {err}")

    try:
        with tarfile.open(full_path, "r:gz") as tar:
            # Security: check for path traversal in tar members
            for member in tar.getmembers():
                member_path = os.path.join(restore_path, member.name)
                resolved_member = os.path.realpath(member_path)
                if not resolved_member.startswith(os.path.realpath(restore_path)):
                    return make_response(
                        False,
                        error=f"Unsafe path in archive: {member.name} (path traversal attempt)",
                    )

            tar.extractall(path=restore_path, filter="data")

        security.audit.log(
            "backup_restore",
            {"backup_file": backup_file, "restore_path": restore_path},
            True,
        )
        return make_response(True, data={
            "backup_file": full_path,
            "restore_path": restore_path,
            "restored": True,
        })
    except tarfile.TarError as e:
        return make_response(False, error=f"Failed to extract backup: {e}")
    except Exception as e:
        return make_response(False, error=str(e))
