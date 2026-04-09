"""Security layer for ZimaOS MCP Server.

Provides path validation, command blocklist, rate limiting, audit logging,
and role-based access control (RBAC).
"""

import hmac
import json
import os
import re
import secrets
import time
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("zimaos-mcp.security")

# Dangerous commands/patterns that should never be executed
BLOCKED_PATTERNS: list[re.Pattern] = [
    # Destructive filesystem operations
    re.compile(r"rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+/(\s|$|\*)"),  # rm -rf / or rm -rf /*
    re.compile(r"rm\s+(-\w+\s+)*--no-preserve-root"),
    re.compile(r"mkfs\b"),
    re.compile(r"\bdd\s+.*\bif="),
    re.compile(r">\s*/dev/[a-z]"),
    re.compile(r"chmod\s+(-R\s+)?777\s+/(\s|$)"),
    # Fork bomb variants
    re.compile(r":\(\)\s*\{.*\|.*&\s*\}\s*;"),
    re.compile(r"\.\(\)\s*\{.*\|.*&\s*\}\s*;"),
    # Write to protected paths
    re.compile(r">\s*/proc/"),
    re.compile(r">\s*/sys/"),
    re.compile(r">\s*/etc/"),
    re.compile(r"\btee\s+/proc/"),
    re.compile(r"\btee\s+/sys/"),
    # System control
    re.compile(r"\bshutdown\b"),
    re.compile(r"\breboot\b"),
    re.compile(r"\binit\s+[06]\b"),
    re.compile(r"\bsystemctl\s+(poweroff|halt|reboot)\b"),
    # Nested shell execution (bypass attempts)
    re.compile(r"\bbash\s+-c\s+['\"].*\b(reboot|shutdown|mkfs|rm\s+-rf)\b"),
    re.compile(r"\bsh\s+-c\s+['\"].*\b(reboot|shutdown|mkfs|rm\s+-rf)\b"),
    re.compile(r"\bpython[23]?\s+-c\s+['\"].*\b(os\.system|subprocess)\b"),
    re.compile(r"\bperl\s+-e\s+['\"].*\b(system|exec)\b"),
    # Data exfiltration
    re.compile(r"\b(nc|ncat|netcat)\s+.*-[a-zA-Z]*[el]"),  # nc listeners
    re.compile(r"\bcurl\s+.*(-d|--data|--upload|-T)\s"),  # curl upload
    re.compile(r"\bwget\s+.*--post-(data|file)"),
    # Privilege escalation
    re.compile(r"\bchmod\s+[ugo]*\+s\b"),  # setuid
    re.compile(r"\bchown\s+root\b"),
    # Disk/partition manipulation
    re.compile(r"\bfdisk\b"),
    re.compile(r"\bparted\b"),
    re.compile(r"\blvremove\b"),
    re.compile(r"\bvgremove\b"),
    re.compile(r"\bpvremove\b"),
    re.compile(r"\bzpool\s+(destroy|export)\b"),
    re.compile(r"\bzfs\s+destroy\b"),
    # Kernel/module manipulation
    re.compile(r"\binsmod\b"),
    re.compile(r"\brmmod\b"),
    re.compile(r"\bmodprobe\s+-r\b"),
    re.compile(r"\bsysctl\s+-w\b"),
]

# Default allowed paths for file operations
DEFAULT_ALLOWED_PATHS: list[str] = [
    "/DATA/",
    "/tmp/",
    "/var/log/",
]

# Default read-only paths (can read but not write)
DEFAULT_READONLY_PATHS: list[str] = [
    "/var/log/",
    "/etc/",
    "/proc/",
    "/sys/",
]

AUDIT_LOG_PATH = "/DATA/AppData/zimaos-mcp/audit.log"
USERS_JSON_PATH = "/DATA/AppData/zimaos-mcp/users.json"

# ── RBAC: Roles & Permissions ────────────────────────────────────────────────

VALID_ROLES = {"admin", "operator", "viewer"}

# Tools that the viewer role is allowed to use (read-only operations)
VIEWER_TOOLS: set[str] = {
    "system_info", "system_disk", "system_network", "system_processes",
    "docker_ps", "docker_stats", "docker_logs", "docker_images",
    "files_read", "files_list", "files_info",
    "cron_list",
    "zima_apps_list", "zima_storage_info", "zima_shares", "zima_update_check",
    "zima_changelog",
    "net_ping", "net_dns", "net_traceroute", "net_port_check",
    "server_health",
    "backup_list",
}

# Special pseudo-tools for admin-only API operations
ADMIN_ONLY_TOOLS: set[str] = {"_user_management", "_config_update"}


@dataclass
class ApiUser:
    """Represents an authenticated API user with a role."""

    key: str
    name: str
    role: str
    created_at: str

    def to_dict(self) -> dict:
        """Serialize to dict (includes full key)."""
        return {
            "key": self.key,
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at,
        }

    def to_safe_dict(self) -> dict:
        """Serialize to dict with masked key (last 4 chars only)."""
        return {
            "key_suffix": self.key[-4:] if len(self.key) >= 4 else self.key,
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at,
        }


class UserManager:
    """Manages API users with role-based access control.

    Users are persisted to a JSON file. Each user has a unique API key,
    a name, and a role (admin, operator, viewer).
    """

    def __init__(self, users_path: str = USERS_JSON_PATH):
        self.users_path = users_path
        self._users: list[ApiUser] = []
        self._load()

    def _load(self) -> None:
        """Load users from disk."""
        if not os.path.exists(self.users_path):
            self._users = []
            return
        try:
            with open(self.users_path) as f:
                data = json.load(f)
            self._users = [
                ApiUser(
                    key=u["key"],
                    name=u["name"],
                    role=u["role"],
                    created_at=u.get("created_at", ""),
                )
                for u in data
            ]
        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger.error("Failed to load users from %s: %s", self.users_path, e)
            self._users = []

    def _save(self) -> None:
        """Persist users to disk with restricted permissions."""
        os.makedirs(os.path.dirname(self.users_path), exist_ok=True)
        fd = os.open(self.users_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump([u.to_dict() for u in self._users], f, indent=2)

    def authenticate(self, key: str) -> Optional[ApiUser]:
        """Look up a user by API key (timing-safe comparison).

        Returns the ApiUser if found, None otherwise.
        """
        for user in self._users:
            if hmac.compare_digest(user.key, key):
                return user
        return None

    def list_users(self) -> list[ApiUser]:
        """Return all users."""
        return list(self._users)

    def add_user(self, name: str, role: str) -> ApiUser:
        """Create a new user with an auto-generated API key.

        Args:
            name: Human-readable name.
            role: One of 'admin', 'operator', 'viewer'.

        Returns:
            The newly created ApiUser.

        Raises:
            ValueError: If role is invalid.
        """
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role '{role}'. Must be one of: {VALID_ROLES}")

        user = ApiUser(
            key=secrets.token_urlsafe(32),
            name=name,
            role=role,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        self._users.append(user)
        self._save()
        return user

    def delete_user(self, key: str) -> bool:
        """Delete a user by their full API key.

        Returns True if deleted, False if not found.
        """
        for i, user in enumerate(self._users):
            if hmac.compare_digest(user.key, key):
                self._users.pop(i)
                self._save()
                return True
        return False

    def migrate_legacy_key(self, api_key: str) -> None:
        """Migrate a legacy single api_key to a default admin user.

        Idempotent: if the key already exists as a user, this is a no-op.
        """
        if self.authenticate(api_key) is not None:
            return  # Already migrated

        user = ApiUser(
            key=api_key,
            name="admin",
            role="admin",
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        self._users.append(user)
        self._save()

    def has_permission(self, user: ApiUser, tool_name: str) -> bool:
        """Check if a user has permission to use a given tool.

        Args:
            user: The authenticated user.
            tool_name: The MCP tool name or pseudo-tool (_user_management, _config_update).

        Returns:
            True if permitted, False if denied.
        """
        if user.role == "admin":
            return True

        if tool_name in ADMIN_ONLY_TOOLS:
            return False

        if user.role == "operator":
            # Operators can use all real tools (not admin-only pseudo-tools)
            return True

        if user.role == "viewer":
            return tool_name in VIEWER_TOOLS

        return False


@dataclass
class RateLimiter:
    """Simple sliding window rate limiter."""

    max_requests: int = 60
    window_seconds: int = 60
    _timestamps: list[float] = field(default_factory=list)

    def check(self) -> bool:
        """Returns True if request is allowed, False if rate limited."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self.max_requests:
            return False
        self._timestamps.append(now)
        return True

    @property
    def remaining(self) -> int:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        active = sum(1 for t in self._timestamps if t > cutoff)
        return max(0, self.max_requests - active)

    @property
    def retry_after(self) -> int:
        """Seconds until the oldest request in the window expires."""
        if not self._timestamps:
            return 0
        now = time.monotonic()
        cutoff = now - self.window_seconds
        active = [t for t in self._timestamps if t > cutoff]
        if not active:
            return 0
        oldest = min(active)
        return max(1, int(self.window_seconds - (now - oldest)) + 1)


# Rate limit tiers: tools are classified by risk level
RATE_TIER_EXEC = "exec"      # shell execution, docker exec — strictest
RATE_TIER_WRITE = "write"    # file writes, config changes
RATE_TIER_READ = "read"      # reads, listings, status — most lenient

TOOL_RATE_TIERS: dict[str, str] = {
    "bash_exec": RATE_TIER_EXEC,
    "bash_script": RATE_TIER_EXEC,
    "docker_exec": RATE_TIER_EXEC,
    "docker_compose": RATE_TIER_EXEC,
    "zima_app_install": RATE_TIER_EXEC,
    "zima_update_apply": RATE_TIER_EXEC,
    "files_write": RATE_TIER_WRITE,
    "files_delete": RATE_TIER_WRITE,
    "files_move": RATE_TIER_WRITE,
    "files_copy": RATE_TIER_WRITE,
    "cron_add": RATE_TIER_WRITE,
    "cron_delete": RATE_TIER_WRITE,
    "cron_toggle": RATE_TIER_WRITE,
    "zima_app_config": RATE_TIER_WRITE,
    "process_kill": RATE_TIER_EXEC,
    "system_service_control": RATE_TIER_EXEC,
    "files_chmod": RATE_TIER_WRITE,
    "backup_create": RATE_TIER_WRITE,
    "backup_restore": RATE_TIER_EXEC,
}
# Everything else defaults to RATE_TIER_READ

# Multipliers relative to the base rate limit
TIER_MULTIPLIERS: dict[str, float] = {
    RATE_TIER_EXEC: 1.0,    # base limit (e.g. 60/min)
    RATE_TIER_WRITE: 2.0,   # 2x base limit
    RATE_TIER_READ: 5.0,    # 5x base limit
}


class AuditLogger:
    """Logs all tool invocations to an audit file."""

    def __init__(self, log_path: str = AUDIT_LOG_PATH):
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self._file_handler: Optional[logging.FileHandler] = None
        self._logger = logging.getLogger("zimaos-mcp.audit")
        self._setup()

    def _setup(self) -> None:
        if self._file_handler:
            return
        self._file_handler = logging.FileHandler(self.log_path)
        self._file_handler.setFormatter(
            logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        )
        self._logger.addHandler(self._file_handler)
        self._logger.setLevel(logging.INFO)

    def log(
        self, tool: str, args: dict, result_ok: bool, detail: str = "",
        user: str = "", webhook_manager=None, request_id: str = "",
    ) -> None:
        """Log a tool invocation.

        Args:
            tool: Tool name.
            args: Tool arguments.
            result_ok: Whether the call succeeded.
            detail: Optional detail string.
            user: Optional user name for RBAC attribution.
            webhook_manager: Optional WebhookManager to fire tool.failed events.
            request_id: Optional request UUID for correlation.
        """
        status = "OK" if result_ok else "FAIL"
        sanitized_args = {k: _mask_sensitive(k, _truncate(str(v), 200)) for k, v in args.items()}
        user_str = f" user={user}" if user else ""
        req_str = f" req={request_id}" if request_id else ""
        self._logger.info(f"{status} | {tool} | {sanitized_args} | {detail}{user_str}{req_str}")

        # Fire webhook on tool failure
        if not result_ok and webhook_manager is not None:
            try:
                import asyncio
                asyncio.ensure_future(webhook_manager.fire("tool.failed", {
                    "tool": tool,
                    "args": sanitized_args,
                    "detail": detail,
                    "user": user,
                }))
            except RuntimeError:
                pass  # No event loop running


class SecurityManager:
    """Central security manager for the MCP server."""

    def __init__(
        self,
        allowed_paths: list[str] | None = None,
        readonly_paths: list[str] | None = None,
        blocked_patterns: list[re.Pattern] | None = None,
        rate_limit: int = 60,
        rate_window: int = 60,
        audit_log_path: str = AUDIT_LOG_PATH,
    ):
        self.allowed_paths = allowed_paths or DEFAULT_ALLOWED_PATHS
        self.readonly_paths = readonly_paths or DEFAULT_READONLY_PATHS
        self.blocked_patterns = blocked_patterns or BLOCKED_PATTERNS
        self.rate_limiter = RateLimiter(
            max_requests=rate_limit, window_seconds=rate_window
        )
        # Per-tier rate limiters
        self._tier_limiters: dict[str, RateLimiter] = {
            tier: RateLimiter(
                max_requests=int(rate_limit * mult),
                window_seconds=rate_window,
            )
            for tier, mult in TIER_MULTIPLIERS.items()
        }
        self.audit = AuditLogger(audit_log_path)
        # Optional webhook manager — set by server.py after initialization
        self.webhook_manager: Optional[object] = None

    def validate_path(self, path: str, write: bool = False) -> tuple[bool, str]:
        """Validate that a path is within allowed directories.

        Args:
            path: The filesystem path to validate.
            write: If True, also checks that path is not in readonly areas.

        Returns:
            Tuple of (is_valid, error_message).
        """
        try:
            resolved = str(Path(path).resolve())
        except (ValueError, OSError) as e:
            return False, f"Invalid path: {e}"

        # Check for path traversal
        if ".." in Path(path).parts:
            return False, "Path traversal (..) not allowed"

        # Check if in readonly paths when writing
        if write:
            for ro_path in self.readonly_paths:
                if resolved.startswith(ro_path):
                    return False, f"Write access denied: {ro_path} is read-only"

        # Check if path is within any allowed path
        for allowed in self.allowed_paths:
            if resolved.startswith(allowed):
                return True, ""

        return False, f"Access denied: path must be under {self.allowed_paths}"

    def validate_command(self, command: str) -> tuple[bool, str]:
        """Check if a shell command is safe to execute.

        Args:
            command: The shell command string to validate.

        Returns:
            Tuple of (is_safe, error_message).
        """
        for pattern in self.blocked_patterns:
            if pattern.search(command):
                return False, f"Blocked command pattern detected: {pattern.pattern}"
        return True, ""

    def check_rate_limit(self, tool_name: str | None = None) -> tuple[bool, str]:
        """Check if rate limit allows this request.

        Args:
            tool_name: Optional tool name for per-tier rate limiting.

        Returns:
            Tuple of (is_allowed, error_message).
        """
        # Global rate limit
        if not self.rate_limiter.check():
            return False, (
                f"Rate limit exceeded: {self.rate_limiter.max_requests} "
                f"requests per {self.rate_limiter.window_seconds}s. "
                f"Remaining: {self.rate_limiter.remaining}"
            )
        # Per-tier rate limit
        if tool_name:
            tier = TOOL_RATE_TIERS.get(tool_name, RATE_TIER_READ)
            limiter = self._tier_limiters.get(tier, self.rate_limiter)
            if not limiter.check():
                return False, (
                    f"Rate limit exceeded for {tier} operations: "
                    f"{limiter.max_requests} per {limiter.window_seconds}s"
                )
        return True, ""


_SENSITIVE_KEYS = re.compile(r"(key|password|secret|token)", re.IGNORECASE)


def _mask_sensitive(key_name: str, value: str) -> str:
    """Mask values whose key name suggests they contain secrets."""
    if _SENSITIVE_KEYS.search(key_name):
        return "***"
    return value


def _truncate(s: str, max_len: int) -> str:
    """Truncate string for logging."""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."


class MetricsCollector:
    """Lightweight in-process metrics collector for Prometheus-style /metrics.

    Thread-safe counters for tool invocation tracking.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, str], int] = defaultdict(int)  # (tool, status) -> count
        self._start_time = time.monotonic()

    def record(self, tool: str, ok: bool) -> None:
        """Increment the counter for a tool invocation."""
        status = "ok" if ok else "fail"
        with self._lock:
            self._counters[(tool, status)] += 1

    def format_openmetrics(self, tool_count: int) -> str:
        """Render counters in Prometheus text exposition format."""
        lines: list[str] = []

        # Request counters
        lines.append("# HELP mcp_requests_total Total tool invocations")
        lines.append("# TYPE mcp_requests_total counter")
        with self._lock:
            for (tool, status), count in sorted(self._counters.items()):
                lines.append(f'mcp_requests_total{{tool="{tool}",status="{status}"}} {count}')

        # Uptime
        uptime = int(time.monotonic() - self._start_time)
        lines.append("# HELP mcp_uptime_seconds Server uptime")
        lines.append("# TYPE mcp_uptime_seconds gauge")
        lines.append(f"mcp_uptime_seconds {uptime}")

        # Tool count
        lines.append("# HELP mcp_tools_count Number of registered tools")
        lines.append("# TYPE mcp_tools_count gauge")
        lines.append(f"mcp_tools_count {tool_count}")

        lines.append("")  # trailing newline
        return "\n".join(lines)
