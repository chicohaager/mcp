#!/usr/bin/env python3
"""ZimaOS Universal MCP Server.

Production-ready MCP server for ZimaOS with full system access.
Provides shell execution, filesystem, Docker, system info, and ZimaOS-specific tools.
"""

import json
import logging
import os
import sys

from mcp.server.fastmcp import FastMCP
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles

from config import ServerConfig, load_config
from security import SecurityManager, UserManager
from skills import SkillManager
from tools import shell, files, docker_tools, system, zima, cron, updates, network, maintenance, webhooks

# Load configuration
config = load_config()

# Setup logging
if config.log_format == "json":
    import json as _json

    class _JsonFormatter(logging.Formatter):
        def format(self, record):
            return _json.dumps({
                "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                "level": record.levelname,
                "logger": record.name,
                "msg": record.getMessage(),
            })

    _handler = logging.StreamHandler()
    _handler.setFormatter(_JsonFormatter())
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        handlers=[_handler],
    )
else:
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
logger = logging.getLogger("zimaos-mcp")

# Ensure data directory exists
os.makedirs(config.data_dir, exist_ok=True)

# Initialize security
security = SecurityManager(
    allowed_paths=config.allowed_paths,
    readonly_paths=config.readonly_paths,
    rate_limit=config.rate_limit,
    rate_window=config.rate_window,
    audit_log_path=config.audit_log,
)

# Initialize webhook manager
webhook_manager = webhooks.init_manager(config.data_dir)
security.webhook_manager = webhook_manager

# Initialize skill manager
skill_manager = SkillManager()

# Initialize FastMCP server
mcp = FastMCP(
    "zimaos-mcp",
    host=config.host,
    port=config.port,
    log_level=config.log_level.upper(),
)

# Load dynamic skills
_skill_count = skill_manager.load_all_skills(mcp)
logger.info("Loaded %d tools from skills", _skill_count)


# ── Shell Execution ──────────────────────────────────────────────────────────


@mcp.tool()
async def bash_exec(command: str, timeout: int = 60, cwd: str = "/DATA") -> dict:
    """Execute a shell command on ZimaOS.

    Args:
        command: Command to execute.
        timeout: Timeout in seconds (default: 60, max: 300).
        cwd: Working directory (default: /DATA).

    Returns:
        Dict with stdout, stderr, exit_code, timed_out.
    """
    return await shell.bash_exec(
        command, timeout=timeout, cwd=cwd, config=config, security=security
    )


@mcp.tool()
async def bash_script(
    script: str, interpreter: str = "/bin/bash", timeout: int = 60
) -> dict:
    """Execute a multi-line script on ZimaOS.

    Args:
        script: Script content (multi-line).
        interpreter: Shell interpreter (default: /bin/bash).
        timeout: Timeout in seconds (default: 60, max: 300).

    Returns:
        Dict with stdout, stderr, exit_code, timed_out.
    """
    return await shell.bash_script(
        script, interpreter=interpreter, timeout=timeout,
        config=config, security=security,
    )


# ── Filesystem Operations ────────────────────────────────────────────────────


@mcp.tool()
async def files_read(
    path: str, encoding: str = "utf-8", tail: int | None = None
) -> dict:
    """Read file contents.

    Args:
        path: File path (must be under allowed paths).
        encoding: File encoding (default: utf-8).
        tail: If set, read only last N lines.
    """
    return await files.files_read(
        path, encoding=encoding, tail=tail, security=security
    )


@mcp.tool()
async def files_write(
    path: str, content: str, mode: str = "w", backup: bool = True
) -> dict:
    """Write content to a file. Auto-creates backup on overwrite.

    Args:
        path: File path (must be under /DATA).
        content: Content to write.
        mode: 'w' for overwrite, 'a' for append.
        backup: Create backup before overwrite (default: True).
    """
    return await files.files_write(
        path, content, mode=mode, backup=backup, security=security
    )


@mcp.tool()
async def files_list(
    path: str, recursive: bool = False, pattern: str = "*"
) -> dict:
    """List directory contents with glob pattern.

    Args:
        path: Directory path.
        recursive: Recurse into subdirectories.
        pattern: Glob pattern (default: *).
    """
    return await files.files_list(
        path, recursive=recursive, pattern=pattern, security=security
    )


@mcp.tool()
async def files_delete(path: str, recursive: bool = False) -> dict:
    """Delete a file or directory.

    Args:
        path: Path to delete (must be under /DATA).
        recursive: If True, delete directory recursively.
    """
    return await files.files_delete(path, recursive=recursive, security=security)


@mcp.tool()
async def files_copy(src: str, dst: str) -> dict:
    """Copy files or directories.

    Args:
        src: Source path.
        dst: Destination path.
    """
    return await files.files_copy(src, dst, security=security)


@mcp.tool()
async def files_move(src: str, dst: str) -> dict:
    """Move or rename files/directories.

    Args:
        src: Source path.
        dst: Destination path.
    """
    return await files.files_move(src, dst, security=security)


@mcp.tool()
async def files_info(path: str) -> dict:
    """Get file metadata (size, mtime, permissions, owner).

    Args:
        path: File path.
    """
    return await files.files_info(path, security=security)


@mcp.tool()
async def files_search(
    path: str,
    pattern: str,
    recursive: bool = True,
    max_results: int = 100,
    context_lines: int = 0,
) -> dict:
    """Search file contents for lines matching a regex pattern (like grep).

    Args:
        path: Directory path to search under.
        pattern: Regex pattern to match against file contents.
        recursive: Search subdirectories (default: True).
        max_results: Maximum matches to return (default: 100).
        context_lines: Lines of context before/after each match (default: 0).
    """
    return await files.files_search(
        path,
        pattern,
        recursive=recursive,
        max_results=max_results,
        context_lines=context_lines,
        security=security,
    )


@mcp.tool()
async def files_chmod(path: str, mode: str) -> dict:
    """Change file permissions.

    Args:
        path: File path (must be under /DATA).
        mode: Octal permission string (e.g. "755", "644").
    """
    return await files.files_chmod(path, mode, security=security)


# ── Docker Management ────────────────────────────────────────────────────────


@mcp.tool()
async def docker_ps(all: bool = False, filters: dict | None = None) -> dict:
    """List Docker containers.

    Args:
        all: Include stopped containers.
        filters: Docker filter dict (e.g. {"status": "running"}).
    """
    return await docker_tools.docker_ps(
        all=all, filters=filters, config=config, security=security
    )


@mcp.tool()
async def docker_logs(
    container: str, tail: int = 100, since: str | None = None
) -> dict:
    """Get container logs.

    Args:
        container: Container name or ID.
        tail: Lines from end (default: 100).
        since: Show logs since (e.g. "2024-01-01", "1h").
    """
    return await docker_tools.docker_logs(
        container, tail=tail, since=since, config=config, security=security
    )


@mcp.tool()
async def docker_exec(
    container: str, command: str, user: str | None = None
) -> dict:
    """Execute a command inside a running container.

    Args:
        container: Container name or ID.
        command: Command to execute.
        user: User to run as (e.g. "root").
    """
    return await docker_tools.docker_exec(
        container, command, user=user, config=config, security=security
    )


@mcp.tool()
async def docker_compose(
    action: str, project_dir: str, services: list[str] | None = None
) -> dict:
    """Docker Compose operations.

    Args:
        action: One of: up, down, restart, pull, logs, ps.
        project_dir: Directory containing docker-compose.yml.
        services: Optional list of specific services.
    """
    return await docker_tools.docker_compose(
        action, project_dir, services=services, config=config, security=security
    )


@mcp.tool()
async def docker_stats(container: str | None = None) -> dict:
    """Get CPU/Memory stats for containers.

    Args:
        container: Specific container (or None for all).
    """
    return await docker_tools.docker_stats(
        container=container, config=config, security=security
    )


@mcp.tool()
async def docker_inspect(target: str, type: str = "container") -> dict:
    """Inspect Docker objects (container, image, network, volume).

    Args:
        target: Name or ID.
        type: One of: container, image, network, volume.
    """
    return await docker_tools.docker_inspect(
        target, type=type, config=config, security=security
    )


# ── System Information ────────────────────────────────────────────────────────


@mcp.tool()
async def system_info() -> dict:
    """Get system information: CPU, RAM, Disk, Uptime, ZimaOS version."""
    return await system.system_info(config=config, security=security)


@mcp.tool()
async def system_processes(sort_by: str = "cpu", limit: int = 20) -> dict:
    """Get top processes by CPU or memory.

    Args:
        sort_by: 'cpu' or 'mem'.
        limit: Number of processes (default: 20).
    """
    return await system.system_processes(
        sort_by=sort_by, limit=limit, config=config, security=security
    )


@mcp.tool()
async def system_services(filter: str | None = None) -> dict:
    """List systemd services.

    Args:
        filter: Optional filter for service names.
    """
    return await system.system_services(filter=filter, config=config, security=security)


@mcp.tool()
async def system_network() -> dict:
    """Get network info: IPs, listening ports, connections."""
    return await system.system_network(config=config, security=security)


@mcp.tool()
async def system_disk() -> dict:
    """Get disk usage including ZFS/RAID status if available."""
    return await system.system_disk(config=config, security=security)


@mcp.tool()
async def process_kill(pid: int, signal: str = "SIGTERM") -> dict:
    """Kill a process by PID.

    Args:
        pid: Process ID to kill (cannot be PID 1).
        signal: Signal to send (default: SIGTERM). E.g. SIGTERM, SIGKILL, SIGHUP.
    """
    return await system.process_kill(
        pid, signal_name=signal, config=config, security=security
    )


@mcp.tool()
async def system_service_control(service: str, action: str) -> dict:
    """Start/stop/restart/status a systemd service on the host.

    Args:
        service: Service name (e.g. 'casaos-gateway.service').
        action: One of: start, stop, restart, status.
    """
    return await system.system_service_control(
        service, action, config=config, security=security
    )


# ── ZimaOS-specific ──────────────────────────────────────────────────────────


@mcp.tool()
async def zima_apps_list() -> dict:
    """List installed ZimaOS apps (Docker containers + AppData compose files)."""
    return await zima.zima_apps_list(config=config, security=security)


@mcp.tool()
async def zima_app_install(app_id: str, config_data: dict | None = None) -> dict:
    """Install/start an app from its docker-compose.yml under /DATA/AppData/<app_id>/.

    Args:
        app_id: App directory name under /DATA/AppData/.
        config_data: Optional compose override configuration.
    """
    return await zima.zima_app_install(
        app_id, config_data=config_data, config=config, security=security
    )


@mcp.tool()
async def zima_app_config(app_id: str, config_data: dict | None = None) -> dict:
    """Read or write app configuration.

    Args:
        app_id: App identifier.
        config_data: Config dict to write (None = read current config).
    """
    return await zima.zima_app_config(
        app_id, config_data=config_data, config=config, security=security
    )


@mcp.tool()
async def zima_storage_info() -> dict:
    """Get ZimaOS storage pools and mount information."""
    return await zima.zima_storage_info(config=config, security=security)


@mcp.tool()
async def zima_shares() -> dict:
    """Get SMB/NFS share configuration."""
    return await zima.zima_shares(config=config, security=security)


# ── Cron & Scheduling ────────────────────────────────────────────────────────


@mcp.tool()
async def cron_list() -> dict:
    """List all managed cron jobs."""
    return await cron.cron_list(security=security)


@mcp.tool()
async def cron_add(
    schedule: str, command: str, name: str | None = None
) -> dict:
    """Add a cron job.

    Args:
        schedule: Cron expression (e.g. "0 * * * *" = every hour).
        command: Command to execute.
        name: Optional descriptive name.
    """
    return await cron.cron_add(
        schedule, command, name=name, security=security
    )


@mcp.tool()
async def cron_delete(job_id: str) -> dict:
    """Delete a cron job by ID.

    Args:
        job_id: Job ID from cron_list.
    """
    return await cron.cron_delete(job_id, security=security)


@mcp.tool()
async def cron_toggle(job_id: str, enabled: bool) -> dict:
    """Enable or disable a cron job without deleting it.

    Args:
        job_id: Job ID from cron_list.
        enabled: True to enable, False to disable.
    """
    return await cron.cron_toggle(job_id, enabled, security=security)


# ── Updates ───────────────────────────────────────────────────────────────────


@mcp.tool()
async def zima_update_check() -> dict:
    """Check for ZimaOS system updates."""
    return await updates.zima_update_check(config=config, security=security)


@mcp.tool()
async def zima_update_apply() -> dict:
    """Apply ZimaOS system update. WARNING: May cause system restart."""
    return await updates.zima_update_apply(config=config, security=security)


@mcp.tool()
async def zima_changelog() -> dict:
    """Read ZimaOS release information (version, build, etc.) as structured data."""
    return await updates.zima_changelog(config=config, security=security)


# ── Network Tools ───────────────────────────────────────────────────────


@mcp.tool()
async def net_ping(host: str, count: int = 4) -> dict:
    """Ping a host to check connectivity.

    Args:
        host: Hostname or IP address to ping.
        count: Number of ping packets (default: 4, max: 20).
    """
    return await network.net_ping(host, count=count, config=config, security=security)


@mcp.tool()
async def net_dns(hostname: str, record_type: str = "A") -> dict:
    """DNS lookup for a hostname.

    Args:
        hostname: Domain name to resolve.
        record_type: DNS record type (A, AAAA, MX, CNAME, TXT, NS).
    """
    return await network.net_dns(
        hostname, record_type=record_type, config=config, security=security
    )


@mcp.tool()
async def net_traceroute(host: str, max_hops: int = 15) -> dict:
    """Trace the route to a host.

    Args:
        host: Target hostname or IP.
        max_hops: Maximum hops (default: 15, max: 30).
    """
    return await network.net_traceroute(
        host, max_hops=max_hops, config=config, security=security
    )


@mcp.tool()
async def net_port_check(host: str, port: int, timeout_s: int = 5) -> dict:
    """Check if a TCP port is open on a host.

    Args:
        host: Target hostname or IP.
        port: TCP port number.
        timeout_s: Connection timeout in seconds (default: 5).
    """
    return await network.net_port_check(
        host, port, timeout_s=timeout_s, config=config, security=security
    )


# ── Docker Images ───────────────────────────────────────────────────────


@mcp.tool()
async def docker_images() -> dict:
    """List all Docker images."""
    return await docker_tools.docker_images(config=config, security=security)


@mcp.tool()
async def docker_pull(image: str) -> dict:
    """Pull a Docker image from registry.

    Args:
        image: Image name with optional tag (e.g. "nginx:latest").
    """
    return await docker_tools.docker_pull(image, config=config, security=security)


@mcp.tool()
async def docker_rmi(image: str, force: bool = False) -> dict:
    """Remove a Docker image.

    Args:
        image: Image name or ID.
        force: Force removal (default: False).
    """
    return await docker_tools.docker_rmi(
        image, force=force, config=config, security=security
    )


# ── Maintenance ─────────────────────────────────────────────────────────


@mcp.tool()
async def audit_log_rotate(max_size_mb: int = 10, keep_rotated: int = 3) -> dict:
    """Rotate the audit log if it exceeds max size.

    Args:
        max_size_mb: Max file size before rotation (default: 10 MB).
        keep_rotated: Number of old log files to keep (default: 3).
    """
    return await maintenance.audit_log_rotate(
        max_size_mb=max_size_mb, keep_rotated=keep_rotated,
        config=config, security=security,
    )


@mcp.tool()
async def backup_cleanup(max_age_days: int = 30) -> dict:
    """Delete old file backups.

    Args:
        max_age_days: Remove backups older than this (default: 30 days).
    """
    return await maintenance.backup_cleanup(
        max_age_days=max_age_days, config=config, security=security
    )


@mcp.tool()
async def server_health() -> dict:
    """Comprehensive server health check: disk, Docker, audit log, data dir."""
    return await maintenance.server_health(config=config, security=security)


@mcp.tool()
async def backup_create(name: str, paths: list[str]) -> dict:
    """Create a tar.gz backup of specified paths.

    Args:
        name: Backup name (used in filename).
        paths: List of paths to include in the backup.
    """
    return await maintenance.backup_create(
        name, paths, config=config, security=security
    )


@mcp.tool()
async def backup_list() -> dict:
    """List all backups with size and date."""
    return await maintenance.backup_list(config=config, security=security)


@mcp.tool()
async def backup_restore(backup_file: str, restore_path: str = "/DATA") -> dict:
    """Restore files from a backup tar.gz.

    Args:
        backup_file: Backup filename (from backup_list).
        restore_path: Directory to extract into (default: /DATA).
    """
    return await maintenance.backup_restore(
        backup_file, restore_path=restore_path, config=config, security=security
    )


# ── Webhooks ─────────────────────────────────────────────────────────────


@mcp.tool()
async def webhook_list() -> dict:
    """List all registered webhooks and supported event types."""
    return await webhooks.webhook_list(security=security)


@mcp.tool()
async def webhook_add(
    name: str, url: str, events: list[str], headers: dict | None = None
) -> dict:
    """Add a webhook to receive event notifications.

    Args:
        name: Human-readable name for the webhook.
        url: HTTP(S) URL to receive POST notifications.
        events: Event types to subscribe to (e.g. tool.failed, container.stopped).
        headers: Optional custom HTTP headers to include in requests.
    """
    return await webhooks.webhook_add(
        name, url, events, headers=headers, security=security
    )


@mcp.tool()
async def webhook_delete(webhook_id: str) -> dict:
    """Delete a webhook by ID.

    Args:
        webhook_id: The webhook identifier.
    """
    return await webhooks.webhook_delete(webhook_id, security=security)


@mcp.tool()
async def webhook_test(webhook_id: str) -> dict:
    """Send a test event to a specific webhook.

    Args:
        webhook_id: The webhook identifier.
    """
    return await webhooks.webhook_test(webhook_id, security=security)


# ── MCP Resources ────────────────────────────────────────────────────────────


@mcp.resource("zimaos://system/info")
async def resource_system_info() -> str:
    """Current system information (CPU, RAM, disk, uptime)."""
    result = await system.system_info(config=config, security=security)
    if result["success"]:
        return json.dumps(result["data"], indent=2)
    return f"Error: {result['error']}"


@mcp.resource("zimaos://docker/containers")
async def resource_docker_containers() -> str:
    """List of all Docker containers and their status."""
    result = await docker_tools.docker_ps(all=True, config=config, security=security)
    if result["success"]:
        return json.dumps(result["data"], indent=2)
    return f"Error: {result['error']}"


@mcp.resource("zimaos://system/version")
async def resource_system_version() -> str:
    """ZimaOS version and server info."""
    from config import VERSION
    info = {"mcp_version": VERSION, "server": "zimaos-mcp"}
    for path in ["/host/etc/zimaos-release", "/host/etc/os-release"]:
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    if line.startswith("VERSION="):
                        info["zimaos_version"] = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("PRETTY_NAME="):
                        info["pretty_name"] = line.split("=", 1)[1].strip().strip('"')
            break
    return json.dumps(info, indent=2)


@mcp.resource("zimaos://network/status")
async def resource_network_status() -> str:
    """Network interfaces and listening ports."""
    result = await system.system_network(config=config, security=security)
    if result["success"]:
        return json.dumps(result["data"], indent=2)
    return f"Error: {result['error']}"


@mcp.resource("zimaos://storage/pools")
async def resource_storage() -> str:
    """Storage pools and disk usage."""
    result = await system.system_disk(config=config, security=security)
    if result["success"]:
        return json.dumps(result["data"], indent=2)
    return f"Error: {result['error']}"


# ── MCP Prompts ──────────────────────────────────────────────────────────────


@mcp.prompt()
async def troubleshoot_container(container_name: str) -> str:
    """Troubleshoot a Docker container — check status, logs, and resource usage."""
    return f"""Please troubleshoot the Docker container '{container_name}':
1. First check if the container is running using docker_ps
2. Get the last 50 lines of logs using docker_logs with container='{container_name}'
3. Check resource usage with docker_stats for container='{container_name}'
4. If the container is stopped, check docker_inspect for exit code and error details
5. Summarize findings and suggest fixes"""


@mcp.prompt()
async def system_health_report() -> str:
    """Generate a comprehensive system health report."""
    return """Please generate a comprehensive health report:
1. Run system_info to get CPU, RAM, disk, and uptime
2. Run system_disk for detailed storage information
3. Run docker_ps with all=true to see all containers
4. Run server_health for MCP server health checks
5. Summarize: highlight any issues (high CPU, low disk, stopped containers, failed checks)"""


@mcp.prompt()
async def setup_backup(app_name: str) -> str:
    """Set up automated backup for a ZimaOS app."""
    return f"""Please set up a backup strategy for the app '{app_name}':
1. Check if the app exists using zima_apps_list
2. Find its data directory under /DATA/AppData/{app_name}
3. List important files using files_list
4. Create a backup using backup_create with appropriate paths
5. Set up a daily cron job using cron_add to automate the backup"""


@mcp.prompt()
async def network_diagnosis(target_host: str) -> str:
    """Diagnose network connectivity to a target host."""
    return f"""Please diagnose network connectivity to '{target_host}':
1. Ping the host using net_ping with count=5
2. Run DNS lookup using net_dns
3. If a specific port is needed, check it with net_port_check
4. Run net_traceroute to find where packets are being dropped
5. Check local network config with system_network
6. Summarize: is the host reachable? Where is the issue?"""


@mcp.prompt()
async def optimize_storage() -> str:
    """Analyze and optimize disk storage usage."""
    return """Please analyze storage usage and suggest optimizations:
1. Run system_disk for overall disk usage
2. Run docker_images to find large or unused images
3. Search for large files: files_search with path=/DATA and look for files > 1GB
4. Check backup directory with backup_list for old backups
5. Suggest: which images to remove, which backups to clean, which directories are using most space"""


# ── Dashboard API + Static Files ──────────────────────────────────────────────

# Mount REST API and web UI via FastMCP's custom Starlette routes
from api import create_api_routes

# Initialize RBAC user manager and migrate legacy api_key
user_manager = UserManager()
if config.api_key:
    user_manager.migrate_legacy_key(config.api_key)
logger.info("RBAC: %d user(s) loaded", len(user_manager.list_users()))

api_routes = create_api_routes(config, security, skill_manager, mcp, webhook_manager, user_manager=user_manager)
mcp._custom_starlette_routes.extend(api_routes)

# Mount static web UI (must be last - catches all unmatched paths)
web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
if os.path.isdir(web_dir):
    mcp._custom_starlette_routes.append(
        Mount("/", app=StaticFiles(directory=web_dir, html=True), name="web")
    )
    logger.info("Dashboard UI mounted from %s", web_dir)


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info(
        "Starting ZimaOS MCP Server on %s:%d", config.host, config.port
    )
    # Only show last 8 chars of API key for verification without full exposure
    masked_key = "..." + config.api_key[-8:] if len(config.api_key) > 8 else config.api_key
    logger.info("API Key: %s (see config.yaml for full key)", masked_key)
    logger.info("Dashboard: http://%s:%d/", config.host, config.port)

    # Start cron scheduler via startup event
    from tools.cron import scheduler as cron_scheduler
    from starlette.routing import Route

    async def _startup_scheduler(request=None):
        cron_scheduler.start()

    # Use a startup hook via a one-shot route that auto-fires
    import asyncio
    import atexit

    original_run = mcp.run

    def _run_with_scheduler(**kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.call_later(1.0, lambda: asyncio.ensure_future(_startup_scheduler()))
        atexit.register(cron_scheduler.stop)
        original_run(**kwargs)

    _run_with_scheduler(transport="streamable-http")
