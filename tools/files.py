"""Filesystem operation tools for ZimaOS MCP Server."""

import fnmatch
import os
import re
import shutil
import time
from pathlib import Path

from security import SecurityManager
from tools.utils import make_response

BACKUP_DIR = "/DATA/AppData/zimaos-mcp/backups"


async def files_read(
    path: str,
    encoding: str = "utf-8",
    tail: int | None = None,
    *,
    security: SecurityManager,
) -> dict:
    """Read file contents.

    Args:
        path: File path.
        encoding: File encoding (default: utf-8).
        tail: If set, read only last N lines.
        security: Security manager.
    """
    ok, err = security.validate_path(path, write=False)
    if not ok:
        return make_response(False, error=err)

    try:
        with open(path, "r", encoding=encoding) as f:
            if tail:
                lines = f.readlines()
                content = "".join(lines[-tail:])
            else:
                content = f.read()
        security.audit.log("files_read", {"path": path}, True)
        return make_response(True, data={"content": content, "path": path})
    except Exception as e:
        return make_response(False, error=str(e))


async def files_write(
    path: str,
    content: str,
    mode: str = "w",
    backup: bool = True,
    *,
    security: SecurityManager,
) -> dict:
    """Write content to a file. Creates backup automatically.

    Args:
        path: File path.
        content: Content to write.
        mode: Write mode ('w' for overwrite, 'a' for append).
        backup: Create backup before overwrite (default: True).
        security: Security manager.
    """
    ok, err = security.validate_path(path, write=True)
    if not ok:
        return make_response(False, error=err)

    # Validate write mode
    if mode not in ("w", "a"):
        return make_response(False, error=f"Invalid mode '{mode}'. Must be 'w' (overwrite) or 'a' (append).")

    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        # Create backup if file exists and mode is overwrite
        backup_path = None
        if backup and mode == "w" and os.path.exists(path):
            os.makedirs(BACKUP_DIR, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            filename = Path(path).name
            backup_path = os.path.join(BACKUP_DIR, f"{filename}.{ts}.bak")
            shutil.copy2(path, backup_path)

        with open(path, mode, encoding="utf-8") as f:
            f.write(content)

        result = {"path": path, "bytes_written": len(content.encode("utf-8"))}
        if backup_path:
            result["backup"] = backup_path

        security.audit.log("files_write", {"path": path, "mode": mode}, True)
        return make_response(True, data=result)
    except Exception as e:
        return make_response(False, error=str(e))


async def files_list(
    path: str,
    recursive: bool = False,
    pattern: str = "*",
    *,
    security: SecurityManager,
) -> dict:
    """List directory contents with glob pattern.

    Args:
        path: Directory path.
        recursive: Recurse into subdirectories.
        pattern: Glob pattern to filter (default: *).
        security: Security manager.
    """
    ok, err = security.validate_path(path, write=False)
    if not ok:
        return make_response(False, error=err)

    try:
        items = []
        if recursive:
            for root, dirs, files in os.walk(path):
                for name in dirs + files:
                    if fnmatch.fnmatch(name, pattern):
                        full = os.path.join(root, name)
                        items.append(_file_entry(full))
        else:
            for name in os.listdir(path):
                if fnmatch.fnmatch(name, pattern):
                    full = os.path.join(path, name)
                    items.append(_file_entry(full))

        return make_response(True, data={"items": items, "count": len(items)})
    except Exception as e:
        return make_response(False, error=str(e))


async def files_delete(
    path: str, recursive: bool = False, *, security: SecurityManager
) -> dict:
    """Delete a file or directory.

    Args:
        path: Path to delete.
        recursive: If True, delete directory recursively.
        security: Security manager.
    """
    ok, err = security.validate_path(path, write=True)
    if not ok:
        return make_response(False, error=err)

    try:
        if os.path.isdir(path):
            if recursive:
                shutil.rmtree(path)
            else:
                os.rmdir(path)
        else:
            os.remove(path)

        security.audit.log("files_delete", {"path": path, "recursive": recursive}, True)
        return make_response(True, data={"deleted": path})
    except Exception as e:
        return make_response(False, error=str(e))


async def files_copy(src: str, dst: str, *, security: SecurityManager) -> dict:
    """Copy files or directories.

    Args:
        src: Source path.
        dst: Destination path.
        security: Security manager.
    """
    ok, err = security.validate_path(src, write=False)
    if not ok:
        return make_response(False, error=err)
    ok, err = security.validate_path(dst, write=True)
    if not ok:
        return make_response(False, error=err)

    try:
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)

        security.audit.log("files_copy", {"src": src, "dst": dst}, True)
        return make_response(True, data={"src": src, "dst": dst})
    except Exception as e:
        return make_response(False, error=str(e))


async def files_move(src: str, dst: str, *, security: SecurityManager) -> dict:
    """Move or rename files/directories.

    Args:
        src: Source path.
        dst: Destination path.
        security: Security manager.
    """
    ok, err = security.validate_path(src, write=True)
    if not ok:
        return make_response(False, error=err)
    ok, err = security.validate_path(dst, write=True)
    if not ok:
        return make_response(False, error=err)

    try:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(src, dst)
        security.audit.log("files_move", {"src": src, "dst": dst}, True)
        return make_response(True, data={"src": src, "dst": dst})
    except Exception as e:
        return make_response(False, error=str(e))


async def files_info(path: str, *, security: SecurityManager) -> dict:
    """Get file metadata (size, mtime, permissions, owner).

    Args:
        path: File path.
        security: Security manager.
    """
    ok, err = security.validate_path(path, write=False)
    if not ok:
        return make_response(False, error=err)

    try:
        stat = os.stat(path)
        return make_response(
            True,
            data={
                "path": path,
                "size": stat.st_size,
                "mtime": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)
                ),
                "permissions": oct(stat.st_mode),
                "uid": stat.st_uid,
                "gid": stat.st_gid,
                "is_dir": os.path.isdir(path),
                "is_file": os.path.isfile(path),
                "is_link": os.path.islink(path),
            },
        )
    except Exception as e:
        return make_response(False, error=str(e))


async def files_search(
    path: str,
    pattern: str,
    recursive: bool = True,
    max_results: int = 100,
    context_lines: int = 0,
    *,
    security: SecurityManager,
) -> dict:
    """Search file contents under a directory for lines matching a regex pattern.

    Args:
        path: Directory path to search under.
        pattern: Regex pattern to match against file contents.
        recursive: Search subdirectories (default: True).
        max_results: Maximum number of matches to return (default: 100).
        context_lines: Number of lines before/after each match (default: 0).
        security: Security manager.
    """
    ok, err = security.validate_path(path, write=False)
    if not ok:
        return make_response(False, error=err)

    try:
        regex = re.compile(pattern)
    except re.error as e:
        return make_response(False, error=f"Invalid regex pattern: {e}")

    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

    def _is_binary(filepath: str) -> bool:
        """Check if a file is binary by looking for null bytes in first 1024 bytes."""
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(1024)
                return b"\x00" in chunk
        except (OSError, IOError):
            return True

    matches = []
    truncated = False

    try:
        if recursive:
            file_paths = []
            for root, _dirs, filenames in os.walk(path):
                for name in filenames:
                    file_paths.append(os.path.join(root, name))
        else:
            file_paths = [
                os.path.join(path, name)
                for name in os.listdir(path)
                if os.path.isfile(os.path.join(path, name))
            ]

        for filepath in file_paths:
            if len(matches) >= max_results:
                truncated = True
                break

            try:
                stat = os.stat(filepath)
                if stat.st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            if _is_binary(filepath):
                continue

            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except (OSError, IOError):
                continue

            for i, line in enumerate(lines):
                if regex.search(line):
                    match_entry = {
                        "file": filepath,
                        "line_num": i + 1,
                        "line": line.rstrip("\n"),
                    }
                    if context_lines > 0:
                        start = max(0, i - context_lines)
                        end = min(len(lines), i + context_lines + 1)
                        match_entry["context_before"] = [
                            l.rstrip("\n") for l in lines[start:i]
                        ]
                        match_entry["context_after"] = [
                            l.rstrip("\n") for l in lines[i + 1 : end]
                        ]
                    else:
                        match_entry["context_before"] = []
                        match_entry["context_after"] = []

                    matches.append(match_entry)
                    if len(matches) >= max_results:
                        truncated = True
                        break

        security.audit.log(
            "files_search",
            {"path": path, "pattern": pattern, "results": len(matches)},
            True,
        )
        return make_response(
            True,
            data={
                "matches": matches,
                "count": len(matches),
                "truncated": truncated,
            },
        )
    except Exception as e:
        return make_response(False, error=str(e))


async def files_chmod(
    path: str,
    mode: str,
    *,
    security: SecurityManager,
) -> dict:
    """Change file permissions.

    Args:
        path: File path.
        mode: Octal permission string (e.g. "755", "644").
        security: Security manager.
    """
    ok, err = security.validate_path(path, write=True)
    if not ok:
        return make_response(False, error=err)

    # Validate mode is a valid octal string (3 or 4 digits)
    if not re.match(r"^[0-7]{3,4}$", mode):
        return make_response(
            False, error=f"Invalid mode '{mode}'. Must be 3-4 octal digits (e.g. '755', '0644')."
        )

    try:
        octal_mode = int(mode, 8)
        os.chmod(path, octal_mode)
        security.audit.log("files_chmod", {"path": path, "mode": mode}, True)
        return make_response(True, data={
            "path": path,
            "mode": mode,
            "permissions": oct(octal_mode),
        })
    except FileNotFoundError:
        return make_response(False, error=f"File not found: {path}")
    except PermissionError:
        return make_response(False, error=f"Permission denied: {path}")
    except Exception as e:
        return make_response(False, error=str(e))


def _file_entry(path: str) -> dict:
    """Create a file entry dict for listings."""
    try:
        stat = os.stat(path)
        return {
            "name": os.path.basename(path),
            "path": path,
            "type": "dir" if os.path.isdir(path) else "file",
            "size": stat.st_size,
            "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
        }
    except OSError:
        return {"name": os.path.basename(path), "path": path, "type": "unknown"}
