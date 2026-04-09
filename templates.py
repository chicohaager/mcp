"""Operations Console command templates.

Pre-built command workflows for common ZimaOS operations.
Each template defines a sequence of tool steps to execute.
"""

TEMPLATES = [
    {
        "id": "system-health",
        "name": "System Health Check",
        "description": "CPU, RAM, disk usage, and Docker container status",
        "icon": "heart",
        "category": "System",
        "steps": [
            {"tool": "system_info", "params": {}},
            {"tool": "system_disk", "params": {}},
            {"tool": "docker_ps", "params": {"all": True}},
        ],
    },
    {
        "id": "docker-overview",
        "name": "Docker Overview",
        "description": "All containers, images, and resource usage",
        "icon": "box",
        "category": "Docker",
        "steps": [
            {"tool": "docker_ps", "params": {"all": True}},
            {"tool": "docker_images", "params": {}},
            {"tool": "docker_stats", "params": {}},
        ],
    },
    {
        "id": "network-check",
        "name": "Network Diagnostics",
        "description": "Network interfaces, listening ports, connectivity test",
        "icon": "globe",
        "category": "Network",
        "steps": [
            {"tool": "system_network", "params": {}},
            {"tool": "net_ping", "params": {"host": "8.8.8.8", "count": 3}},
            {"tool": "net_dns", "params": {"hostname": "google.com"}},
        ],
    },
    {
        "id": "storage-report",
        "name": "Storage Report",
        "description": "Disk usage, ZimaOS storage pools, and mount points",
        "icon": "database",
        "category": "Storage",
        "steps": [
            {"tool": "system_disk", "params": {}},
            {"tool": "zima_storage_info", "params": {}},
        ],
    },
    {
        "id": "app-status",
        "name": "App Status",
        "description": "All installed ZimaOS apps and their running state",
        "icon": "grid",
        "category": "Apps",
        "steps": [
            {"tool": "zima_apps_list", "params": {}},
            {"tool": "docker_stats", "params": {}},
        ],
    },
    {
        "id": "security-audit",
        "name": "Security Audit",
        "description": "Server health, rate limits, and recent audit activity",
        "icon": "shield",
        "category": "Security",
        "steps": [
            {"tool": "server_health", "params": {}},
        ],
    },
    {
        "id": "update-check",
        "name": "Update Check",
        "description": "Check for ZimaOS system updates",
        "icon": "download",
        "category": "System",
        "steps": [
            {"tool": "zima_update_check", "params": {}},
        ],
    },
    {
        "id": "process-top",
        "name": "Top Processes",
        "description": "Top 20 processes by CPU and memory usage",
        "icon": "activity",
        "category": "System",
        "steps": [
            {"tool": "system_processes", "params": {"sort_by": "cpu", "limit": 20}},
        ],
    },
    {
        "id": "container-logs",
        "name": "Container Logs",
        "description": "View recent logs from a specific container",
        "icon": "file-text",
        "category": "Docker",
        "steps": [
            {"tool": "docker_ps", "params": {}},
        ],
        "interactive": True,
        "follow_up": {
            "prompt": "Select container name:",
            "field": "container",
            "tool": "docker_logs",
            "params": {"tail": 100},
        },
    },
    {
        "id": "shares-config",
        "name": "Network Shares",
        "description": "SMB and NFS share configuration",
        "icon": "share",
        "category": "Network",
        "steps": [
            {"tool": "zima_shares", "params": {}},
        ],
    },
    {
        "id": "cron-status",
        "name": "Scheduled Jobs",
        "description": "View all scheduled cron jobs",
        "icon": "clock",
        "category": "System",
        "steps": [
            {"tool": "cron_list", "params": {}},
        ],
    },
    {
        "id": "quick-command",
        "name": "Run Command",
        "description": "Execute a shell command on ZimaOS",
        "icon": "terminal",
        "category": "Advanced",
        "interactive": True,
        "steps": [],
        "follow_up": {
            "prompt": "Enter command:",
            "field": "command",
            "tool": "bash_exec",
            "params": {},
        },
    },
    {
        "id": "ping-host",
        "name": "Ping Host",
        "description": "Test connectivity to a host",
        "icon": "wifi",
        "category": "Network",
        "interactive": True,
        "steps": [],
        "follow_up": {
            "prompt": "Enter hostname or IP:",
            "field": "host",
            "tool": "net_ping",
            "params": {"count": 4},
        },
    },
    {
        "id": "file-search",
        "name": "Search Files",
        "description": "Search for text patterns in files under /DATA",
        "icon": "search",
        "category": "Files",
        "interactive": True,
        "steps": [],
        "follow_up": {
            "prompt": "Enter search pattern (regex):",
            "field": "pattern",
            "tool": "files_search",
            "params": {"path": "/DATA", "max_results": 50},
        },
    },
    {
        "id": "port-scan",
        "name": "Check Port",
        "description": "Check if a TCP port is open on a host",
        "icon": "link",
        "category": "Network",
        "interactive": True,
        "steps": [],
        "follow_up": {
            "prompt": "Enter host:port (e.g. 192.168.1.1:80):",
            "field": "_host_port",
            "tool": "net_port_check",
            "params": {},
        },
    },
    {
        "id": "services-list",
        "name": "System Services",
        "description": "List all systemd services",
        "icon": "layers",
        "category": "System",
        "steps": [
            {"tool": "system_services", "params": {}},
        ],
    },
    {
        "id": "docker-compose-status",
        "name": "App Compose Status",
        "description": "Check docker-compose status for an app",
        "icon": "package",
        "category": "Docker",
        "interactive": True,
        "steps": [],
        "follow_up": {
            "prompt": "Enter app name (directory under /DATA/AppData/):",
            "field": "project_dir",
            "tool": "docker_compose",
            "params": {"action": "ps"},
            "transform": {"project_dir": "/DATA/AppData/{value}"},
        },
    },
    {
        "id": "log-rotation",
        "name": "Rotate Audit Log",
        "description": "Rotate the MCP audit log if it's too large",
        "icon": "refresh-cw",
        "category": "Maintenance",
        "steps": [
            {"tool": "audit_log_rotate", "params": {}},
        ],
    },
    {
        "id": "cleanup-backups",
        "name": "Cleanup Old Backups",
        "description": "Remove file backups older than 30 days",
        "icon": "trash",
        "category": "Maintenance",
        "steps": [
            {"tool": "backup_cleanup", "params": {"max_age_days": 30}},
        ],
    },
    {
        "id": "webhooks-list",
        "name": "View Webhooks",
        "description": "List all configured webhook notifications",
        "icon": "bell",
        "category": "System",
        "steps": [
            {"tool": "webhook_list", "params": {}},
        ],
    },
]


def get_templates() -> list[dict]:
    """Return all available command templates."""
    return TEMPLATES


def get_template(template_id: str) -> dict | None:
    """Return a single template by ID, or None if not found."""
    for t in TEMPLATES:
        if t["id"] == template_id:
            return t
    return None
