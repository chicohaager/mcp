"""Configuration management for ZimaOS MCP Server."""

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

import yaml

VERSION = "1.2.3"


@dataclass
class ServerConfig:
    """MCP Server configuration."""

    host: str = "0.0.0.0"
    port: int = 8717
    log_level: str = "INFO"

    # Authentication
    api_key: str = ""  # Auto-generated on first start if empty

    # Security
    allowed_paths: list[str] = field(
        default_factory=lambda: ["/DATA/", "/tmp/", "/var/log/"]
    )
    readonly_paths: list[str] = field(
        default_factory=lambda: ["/var/log/", "/etc/", "/proc/", "/sys/"]
    )
    ip_whitelist: list[str] = field(default_factory=list)  # Empty = allow all
    rate_limit: int = 60
    rate_window: int = 60
    max_request_size: int = 1_048_576  # 1 MB

    # Paths
    data_dir: str = "/DATA/AppData/zimaos-mcp"
    audit_log: str = "/DATA/AppData/zimaos-mcp/audit.log"
    db_path: str = "/DATA/AppData/zimaos-mcp/mcp.db"

    # Docker
    docker_config: str = "/DATA/.docker"

    # Shell
    default_shell: str = "/bin/bash"
    default_timeout: int = 60
    max_timeout: int = 300

    # Logging
    log_format: str = "text"  # "text" or "json"


def load_config(config_path: str | None = None) -> ServerConfig:
    """Load configuration from YAML file with environment variable overrides.

    Args:
        config_path: Path to config.yaml. Defaults to /DATA/AppData/zimaos-mcp/config.yaml.

    Returns:
        ServerConfig instance.
    """
    import logging
    logger = logging.getLogger("zimaos-mcp.config")

    path = config_path or os.environ.get(
        "MCP_CONFIG", "/DATA/AppData/zimaos-mcp/config.yaml"
    )

    config = ServerConfig()

    # Load from YAML if exists
    if Path(path).exists():
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            logger.error("Invalid config YAML at %s: %s — using defaults", path, e)
            data = {}
        except OSError as e:
            logger.error("Cannot read config at %s: %s — using defaults", path, e)
            data = {}
        else:
            for key, value in data.items():
                if hasattr(config, key):
                    setattr(config, key, value)

    # Environment variable overrides
    env_map = {
        "MCP_HOST": "host",
        "MCP_PORT": ("port", int),
        "MCP_LOG_LEVEL": "log_level",
        "MCP_API_KEY": "api_key",
        "MCP_RATE_LIMIT": ("rate_limit", int),
        "MCP_RATE_WINDOW": ("rate_window", int),
        "MCP_DATA_DIR": "data_dir",
        "DOCKER_CONFIG": "docker_config",
        "MCP_DEFAULT_TIMEOUT": ("default_timeout", int),
        "MCP_MAX_TIMEOUT": ("max_timeout", int),
        "MCP_LOG_FORMAT": "log_format",
        "MCP_MAX_REQUEST_SIZE": ("max_request_size", int),
    }

    # IP whitelist from environment (comma-separated)
    ip_whitelist_env = os.environ.get("MCP_IP_WHITELIST", "")
    if ip_whitelist_env:
        config.ip_whitelist = [
            ip.strip() for ip in ip_whitelist_env.split(",") if ip.strip()
        ]

    for env_key, attr in env_map.items():
        env_val = os.environ.get(env_key)
        if env_val is not None:
            if isinstance(attr, tuple):
                attr_name, converter = attr
                try:
                    setattr(config, attr_name, converter(env_val))
                except (ValueError, TypeError) as e:
                    logger.warning(
                        "Invalid value for %s='%s': %s — keeping default", env_key, env_val, e
                    )
            else:
                setattr(config, attr, env_val)

    # Auto-generate API key if not set
    if not config.api_key:
        config.api_key = secrets.token_urlsafe(32)
        logger.info("Generated new API key (save it to config.yaml to persist)")
        _persist_api_key(path, config.api_key, logger)

    return config


def _persist_api_key(config_path: str, api_key: str, logger: "logging.Logger") -> None:
    """Save auto-generated API key back to config.yaml."""
    try:
        existing = {}
        if Path(config_path).exists():
            with open(config_path) as f:
                existing = yaml.safe_load(f) or {}

        existing["api_key"] = api_key
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            yaml.dump(existing, f, default_flow_style=False)
        logger.info("API key persisted to %s", config_path)
    except OSError as e:
        logger.warning("Could not persist API key to %s: %s", config_path, e)
