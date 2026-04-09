"""System information tools for ZimaOS MCP Server."""

import asyncio
import os
import re
import signal

from config import ServerConfig
from security import SecurityManager
from tools.utils import make_response


async def _run(cmd: list[str], timeout: int = 10) -> tuple[bool, str]:
    """Run a system command."""
    return await _run_with_env(cmd, env=None, timeout=timeout)


async def _run_with_env(cmd: list[str], env: dict | None = None, timeout: int = 10) -> tuple[bool, str]:
    """Run a system command with optional extra environment variables."""
    full_env = None
    if env:
        full_env = os.environ.copy()
        full_env.update(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=full_env,
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


async def system_info(*, config: ServerConfig, security: SecurityManager) -> dict:
    """Get system information: CPU, RAM, Disk, Uptime, ZimaOS version.

    Args:
        config: Server configuration.
        security: Security manager.
    """
    info = {}

    # CPU info
    ok, output = await _run(["nproc"])
    if ok:
        info["cpu_cores"] = output.strip()

    ok, output = await _run(["cat", "/proc/loadavg"])
    if ok:
        parts = output.strip().split()
        info["load_avg"] = {"1m": parts[0], "5m": parts[1], "15m": parts[2]}

    # Memory
    ok, output = await _run(["free", "-b"])
    if ok:
        lines = output.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            total = int(parts[1])
            used = int(parts[2])
            available = int(parts[6]) if len(parts) > 6 else total - used
            info["memory"] = {
                "total_gb": round(total / (1024**3), 1),
                "used_gb": round(used / (1024**3), 1),
                "available_gb": round(available / (1024**3), 1),
                "percent_used": round(used / total * 100, 1) if total > 0 else 0,
            }

    # Disk
    ok, output = await _run(["df", "-h", "/DATA"])
    if ok:
        lines = output.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            info["disk_data"] = {
                "device": parts[0],
                "size": parts[1],
                "used": parts[2],
                "available": parts[3],
                "percent_used": parts[4],
            }

    # Uptime
    ok, output = await _run(["uptime", "-p"])
    if ok:
        info["uptime"] = output.strip()

    # Hostname
    ok, output = await _run(["hostname"])
    if ok:
        info["hostname"] = output.strip()

    # Kernel
    ok, output = await _run(["uname", "-r"])
    if ok:
        info["kernel"] = output.strip()

    # ZimaOS version
    for ver_path in ["/etc/zimaos-version", "/etc/casaos-version", "/host/etc/zimaos-version"]:
        if os.path.exists(ver_path):
            try:
                with open(ver_path) as f:
                    info["zimaos_version"] = f.read().strip()
                break
            except OSError:
                pass
    else:
        for rel_path in ["/host/etc/zimaos-release", "/host/etc/os-release"]:
            if os.path.exists(rel_path):
                try:
                    with open(rel_path) as f:
                        for line in f:
                            if line.startswith("VERSION="):
                                info["zimaos_version"] = line.split("=", 1)[1].strip().strip('"')
                                break
                    if "zimaos_version" in info:
                        break
                except OSError:
                    pass

    security.audit.log("system_info", {}, True)
    return make_response(True, data=info)


async def system_processes(
    sort_by: str = "cpu",
    limit: int = 20,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Get top processes by CPU or memory.

    Args:
        sort_by: Sort field ('cpu' or 'mem').
        limit: Number of processes to return.
        config: Server configuration.
        security: Security manager.
    """
    sort_flag = "-pcpu" if sort_by == "cpu" else "-pmem"
    ok, output = await _run([
        "ps", "aux", "--sort", sort_flag, "--no-headers"
    ])
    if not ok:
        return make_response(False, error=output)

    processes = []
    for line in output.strip().splitlines()[:limit]:
        parts = line.split(None, 10)
        if len(parts) >= 11:
            processes.append({
                "user": parts[0],
                "pid": parts[1],
                "cpu_pct": parts[2],
                "mem_pct": parts[3],
                "vsz": parts[4],
                "rss": parts[5],
                "command": parts[10],
            })

    return make_response(True, data={"processes": processes, "sort_by": sort_by})


async def system_services(
    filter: str | None = None,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """List systemd services.

    Args:
        filter: Optional filter string for service names.
        config: Server configuration.
        security: Security manager.
    """
    # Read services from host filesystem (systemctl not available in container)
    # Parse /host/run/systemd/units/ or fallback to /host/etc/systemd/system/
    services = []

    # Primary: parse unit files from host
    unit_dirs = ["/host/etc/systemd/system", "/host/usr/lib/systemd/system"]
    seen = set()
    for unit_dir in unit_dirs:
        if not os.path.isdir(unit_dir):
            continue
        for entry in os.listdir(unit_dir):
            if not entry.endswith(".service"):
                continue
            name = entry
            if filter and filter.lower() not in name.lower():
                continue
            if name in seen:
                continue
            seen.add(name)

            # Check if active via cgroup
            active = "unknown"
            cgroup_path = f"/host/sys/fs/cgroup/system.slice/{name}"
            if os.path.isdir(cgroup_path):
                active = "active"
            elif os.path.isdir(f"/host/sys/fs/cgroup/system.slice"):
                active = "inactive"

            services.append({
                "unit": name,
                "active": active,
                "source": unit_dir.replace("/host", ""),
            })

    services.sort(key=lambda s: s["unit"])
    return make_response(True, data={"services": services, "count": len(services)})


async def system_network(*, config: ServerConfig, security: SecurityManager) -> dict:
    """Get network information: IPs, ports, connections.

    Args:
        config: Server configuration.
        security: Security manager.
    """
    info = {}

    # IP addresses
    ok, output = await _run(["ip", "-j", "addr"])
    if ok:
        import json
        try:
            info["interfaces"] = json.loads(output)
        except json.JSONDecodeError:
            info["interfaces_raw"] = output

    # Listening ports
    ok, output = await _run(["ss", "-tlnp"])
    if ok:
        ports = []
        for line in output.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ports.append({
                    "state": parts[0],
                    "local_addr": parts[3],
                    "process": parts[-1] if len(parts) > 5 else "",
                })
        info["listening_ports"] = ports

    return make_response(True, data=info)


async def system_disk(*, config: ServerConfig, security: SecurityManager) -> dict:
    """Get disk usage including ZFS/RAID status if available.

    Args:
        config: Server configuration.
        security: Security manager.
    """
    info = {}

    # General disk usage
    ok, output = await _run(["df", "-h"])
    if ok:
        disks = []
        for line in output.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                disks.append({
                    "filesystem": parts[0],
                    "size": parts[1],
                    "used": parts[2],
                    "available": parts[3],
                    "percent": parts[4],
                    "mount": parts[5],
                })
        info["filesystems"] = disks

    # Block devices
    ok, output = await _run(["lsblk", "-J"])
    if ok:
        import json
        try:
            info["block_devices"] = json.loads(output)
        except json.JSONDecodeError:
            pass

    # ZFS status (optional)
    ok, output = await _run(["zpool", "status"])
    if ok:
        info["zfs_status"] = output

    # RAID status (optional)
    if os.path.exists("/proc/mdstat"):
        try:
            with open("/proc/mdstat") as f:
                info["mdstat"] = f.read()
        except OSError:
            pass

    return make_response(True, data=info)


async def process_kill(
    pid: int,
    signal_name: str = "SIGTERM",
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Kill a process by PID.

    Args:
        pid: Process ID to kill.
        signal_name: Signal to send (default: SIGTERM). E.g. SIGTERM, SIGKILL, SIGHUP.
        config: Server configuration.
        security: Security manager.
    """
    # Validate PID is a positive integer
    if not isinstance(pid, int) or pid <= 0:
        return make_response(False, error="PID must be a positive integer")

    # Never allow killing PID 1 (init)
    if pid == 1:
        return make_response(False, error="Cannot kill PID 1 (init process)")

    # Validate signal name
    signal_name = signal_name.upper()
    if not signal_name.startswith("SIG"):
        signal_name = f"SIG{signal_name}"

    try:
        sig = getattr(signal, signal_name)
    except AttributeError:
        return make_response(False, error=f"Unknown signal: {signal_name}")

    try:
        os.kill(pid, sig)
        security.audit.log("process_kill", {"pid": pid, "signal": signal_name}, True)
        return make_response(True, data={"pid": pid, "signal": signal_name, "sent": True})
    except ProcessLookupError:
        return make_response(False, error=f"No such process: {pid}")
    except PermissionError:
        return make_response(False, error=f"Permission denied killing PID {pid}")
    except Exception as e:
        return make_response(False, error=str(e))


async def system_service_control(
    service: str,
    action: str,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Start/stop/restart/status a systemd service on the host.

    Args:
        service: Service name (e.g. 'casaos-gateway.service').
        action: One of: start, stop, restart, status.
        config: Server configuration.
        security: Security manager.
    """
    valid_actions = {"start", "stop", "restart", "status"}
    if action not in valid_actions:
        return make_response(
            False, error=f"Invalid action: {action}. Must be one of {valid_actions}"
        )

    # Validate service name: alphanumeric + hyphens + dots + underscores only
    if not re.match(r"^[a-zA-Z0-9._-]+$", service):
        return make_response(
            False, error="Invalid service name. Only alphanumeric, hyphens, dots, and underscores allowed."
        )

    # Try nsenter approach first (works from privileged container with PID 1 access)
    ok, output = await _run(
        ["nsenter", "-t", "1", "-m", "--", "/usr/bin/systemctl", action, service],
        timeout=30,
    )

    if ok:
        security.audit.log(
            "system_service_control",
            {"service": service, "action": action, "method": "nsenter"},
            True,
        )
        return make_response(True, data={
            "service": service,
            "action": action,
            "output": output.strip(),
            "method": "nsenter",
        })

    # Fallback: try via host's systemctl binary directly
    host_systemctl = "/host/usr/bin/systemctl"
    if os.path.exists(host_systemctl):
        ok2, output2 = await _run_with_env(
            [host_systemctl, action, service],
            env={"DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/host/run/dbus/system_bus_socket"},
            timeout=30,
        )
        if ok2:
            security.audit.log(
                "system_service_control",
                {"service": service, "action": action, "method": "host-binary"},
                True,
            )
            return make_response(True, data={
                "service": service,
                "action": action,
                "output": output2.strip(),
                "method": "host-binary",
            })

    # Both methods failed
    security.audit.log(
        "system_service_control",
        {"service": service, "action": action},
        False,
    )
    return make_response(
        False,
        error=(
            f"Could not {action} service '{service}'. "
            f"nsenter failed: {output.strip()}. "
            "systemctl may not be accessible from this container. "
            "Try using bash_exec with an appropriate command instead."
        ),
    )
