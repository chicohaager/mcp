"""Cron and scheduling tools for ZimaOS MCP Server.

Includes an asyncio-based in-process scheduler that actually runs jobs.
"""

import asyncio
import json
import logging
import os
import time
import uuid

from security import SecurityManager
from tools.utils import make_response

logger = logging.getLogger("zimaos-mcp.cron")

CRON_DB = "/DATA/AppData/zimaos-mcp/cron_jobs.json"


def _load_jobs() -> list[dict]:
    """Load cron jobs from the JSON database."""
    if not os.path.exists(CRON_DB):
        return []
    try:
        with open(CRON_DB) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save_jobs(jobs: list[dict]) -> None:
    """Save cron jobs to the JSON database."""
    os.makedirs(os.path.dirname(CRON_DB), exist_ok=True)
    with open(CRON_DB, "w") as f:
        json.dump(jobs, f, indent=2)


def _sync_to_crontab(jobs: list[dict]) -> tuple[bool, str]:
    """Sync jobs to the system crontab file for the cron container."""
    cron_dir = "/DATA/AppData/zima-cron/config"
    os.makedirs(cron_dir, exist_ok=True)
    cron_file = os.path.join(cron_dir, "mcp-jobs")

    lines = [
        "# Managed by zimaos-mcp - DO NOT EDIT MANUALLY",
        "SHELL=/bin/bash",
        "",
    ]
    for job in jobs:
        if not job.get("enabled", True):
            continue
        name = job.get("name", job["id"])
        lines.append(f"# {name}")
        lines.append(f"{job['schedule']} {job['command']}")
        lines.append("")

    try:
        with open(cron_file, "w") as f:
            f.write("\n".join(lines) + "\n")
        return True, cron_file
    except OSError as e:
        return False, str(e)


ZIMAOS_CRON_DB = "/DATA/AppData/cron/tasks.json"


def _load_zimaos_cron_tasks() -> list[dict]:
    """Read ZimaOS-managed cron tasks from /DATA/AppData/cron/tasks.json."""
    if not os.path.exists(ZIMAOS_CRON_DB):
        return []
    try:
        with open(ZIMAOS_CRON_DB) as f:
            tasks = json.load(f)
        if not isinstance(tasks, list):
            return []

        result = []
        for task in tasks:
            result.append({
                "id": task.get("id", ""),
                "name": task.get("name", ""),
                "schedule": task.get("cron_expr", ""),
                "command": task.get("command", ""),
                "status": task.get("status", "unknown"),
                "category": task.get("category", ""),
                "timeout_sec": task.get("timeout_sec", 0),
                "last_result": task.get("last_result"),
                "source": "zimaos",
                "system": True,
            })
        return result
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to read ZimaOS cron tasks: %s", e)
        return []


async def cron_list(*, security: SecurityManager) -> dict:
    """List all cron jobs — both MCP-managed and system crontabs.

    Args:
        security: Security manager.
    """
    mcp_jobs = _load_jobs()
    system_jobs = _load_zimaos_cron_tasks()

    security.audit.log("cron_list", {}, True)
    return make_response(True, data={
        "jobs": mcp_jobs,
        "system_jobs": system_jobs,
        "count": len(mcp_jobs),
        "system_count": len(system_jobs),
        "total": len(mcp_jobs) + len(system_jobs),
    })


async def cron_add(
    schedule: str,
    command: str,
    name: str | None = None,
    *,
    security: SecurityManager,
) -> dict:
    """Add a new cron job.

    Args:
        schedule: Cron schedule expression (e.g. "0 * * * *").
        command: Command to execute.
        name: Optional descriptive name.
        security: Security manager.
    """
    # Validate command
    ok, err = security.validate_command(command)
    if not ok:
        return make_response(False, error=err)

    # Validate schedule format (basic check: 5 fields)
    parts = schedule.strip().split()
    if len(parts) != 5:
        return make_response(
            False,
            error="Invalid cron schedule. Expected 5 fields: min hour dom month dow",
        )

    job_id = str(uuid.uuid4())[:8]
    job = {
        "id": job_id,
        "name": name or f"job-{job_id}",
        "schedule": schedule,
        "command": command,
        "enabled": True,
    }

    jobs = _load_jobs()
    jobs.append(job)
    _save_jobs(jobs)

    # Sync to crontab
    ok, detail = _sync_to_crontab(jobs)

    security.audit.log("cron_add", {"schedule": schedule, "command": command}, True)
    return make_response(True, data={"job": job, "crontab_synced": ok})


async def cron_toggle(
    job_id: str,
    enabled: bool,
    *,
    security: SecurityManager,
) -> dict:
    """Enable or disable a cron job without deleting it.

    Args:
        job_id: The job ID to toggle.
        enabled: True to enable, False to disable.
        security: Security manager.
    """
    jobs = _load_jobs()
    found = False
    for job in jobs:
        if job["id"] == job_id:
            job["enabled"] = enabled
            found = True
            break

    if not found:
        return make_response(False, error=f"Job not found: {job_id}")

    _save_jobs(jobs)
    _sync_to_crontab(jobs)

    security.audit.log("cron_toggle", {"job_id": job_id, "enabled": enabled}, True)
    return make_response(True, data={"job_id": job_id, "enabled": enabled})


async def cron_delete(job_id: str, *, security: SecurityManager) -> dict:
    """Delete a cron job by ID.

    Args:
        job_id: The job ID to delete.
        security: Security manager.
    """
    jobs = _load_jobs()
    original_count = len(jobs)
    jobs = [j for j in jobs if j["id"] != job_id]

    if len(jobs) == original_count:
        return make_response(False, error=f"Job not found: {job_id}")

    _save_jobs(jobs)
    _sync_to_crontab(jobs)

    security.audit.log("cron_delete", {"job_id": job_id}, True)
    return make_response(True, data={"deleted": job_id, "remaining": len(jobs)})


# ── In-Process Scheduler ────────────────────────────────────────────────


def _parse_cron_field(field: str, min_val: int, max_val: int) -> set[int]:
    """Parse a single cron field into a set of matching values."""
    values = set()
    for part in field.split(","):
        if "/" in part:
            base, step = part.split("/", 1)
            step = int(step)
            if base == "*":
                start = min_val
            else:
                start = int(base)
            values.update(range(start, max_val + 1, step))
        elif "-" in part:
            low, high = part.split("-", 1)
            values.update(range(int(low), int(high) + 1))
        elif part == "*":
            values.update(range(min_val, max_val + 1))
        else:
            values.add(int(part))
    return values


def _cron_matches(schedule: str, now: time.struct_time) -> bool:
    """Check if a cron schedule matches the current time (minute precision)."""
    parts = schedule.strip().split()
    if len(parts) != 5:
        return False
    try:
        minutes = _parse_cron_field(parts[0], 0, 59)
        hours = _parse_cron_field(parts[1], 0, 23)
        doms = _parse_cron_field(parts[2], 1, 31)
        months = _parse_cron_field(parts[3], 1, 12)
        dows = _parse_cron_field(parts[4], 0, 6)
    except (ValueError, IndexError):
        return False

    # Convert Python weekday (Mon=0..Sun=6) to cron weekday (Sun=0..Sat=6)
    cron_wday = (now.tm_wday + 1) % 7

    return (
        now.tm_min in minutes
        and now.tm_hour in hours
        and now.tm_mday in doms
        and now.tm_mon in months
        and cron_wday in dows
    )


class CronScheduler:
    """Asyncio-based cron scheduler that runs in the background."""

    def __init__(self):
        self._task: asyncio.Task | None = None
        self._running = False

    def start(self) -> None:
        """Start the scheduler background task."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.ensure_future(self._loop())
        logger.info("Cron scheduler started")

    def stop(self) -> None:
        """Stop the scheduler."""
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        logger.info("Cron scheduler stopped")

    async def _loop(self) -> None:
        """Main scheduler loop — checks every 60 seconds."""
        while self._running:
            try:
                now = time.localtime()
                jobs = _load_jobs()
                for job in jobs:
                    if not job.get("enabled", True):
                        continue
                    if _cron_matches(job["schedule"], now):
                        logger.info("Running cron job: %s (%s)", job.get("name", job["id"]), job["command"])
                        asyncio.ensure_future(self._execute(job))
            except Exception as e:
                logger.error("Cron scheduler error: %s", e)

            # Sleep until the next minute boundary
            await asyncio.sleep(60 - time.time() % 60)

    async def _execute(self, job: dict) -> None:
        """Execute a single cron job."""
        env = os.environ.copy()
        env["DOCKER_CONFIG"] = os.environ.get("DOCKER_CONFIG", "/DATA/.docker")
        try:
            proc = await asyncio.create_subprocess_shell(
                job["command"],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/DATA",
                env=env,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            if proc.returncode != 0:
                logger.warning(
                    "Cron job '%s' failed (exit %d): %s",
                    job.get("name", job["id"]),
                    proc.returncode,
                    stderr.decode("utf-8", errors="replace")[:200],
                )
            else:
                logger.info("Cron job '%s' completed successfully", job.get("name", job["id"]))
        except asyncio.TimeoutError:
            logger.error("Cron job '%s' timed out", job.get("name", job["id"]))
        except Exception as e:
            logger.error("Cron job '%s' error: %s", job.get("name", job["id"]), e)


# Global scheduler instance
scheduler = CronScheduler()
