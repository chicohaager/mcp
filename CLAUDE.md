# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A FastMCP-based MCP server for ZimaOS with 53 tools, web dashboard, and skill marketplace. Provides shell execution, filesystem ops, Docker management (containers + images), system info, network diagnostics, ZimaOS-specific features, cron scheduling with in-process executor, maintenance tools, and updates. Runs as a Docker container on ZimaOS with streamable-http transport on port 8717.

## Build & Deploy

```bash
# Deploy to ZimaOS (from dev machine)
scp -r . root@<zimaos-ip>:/DATA/AppData/zimaos-mcp/
ssh root@<zimaos-ip> "cd /DATA/AppData/zimaos-mcp && DOCKER_CONFIG=/DATA/.docker docker compose up -d --build"

# Rebuild after code changes
ssh root@<zimaos-ip> "cd /DATA/AppData/zimaos-mcp && DOCKER_CONFIG=/DATA/.docker docker compose build --no-cache && DOCKER_CONFIG=/DATA/.docker docker compose up -d"

# View logs
ssh root@<zimaos-ip> "DOCKER_CONFIG=/DATA/.docker docker logs zimaos-mcp --tail 50"

# Get API key
ssh root@<zimaos-ip> "DOCKER_CONFIG=/DATA/.docker docker logs zimaos-mcp 2>&1 | grep 'API Key'"
```

## Run Tests

```bash
python -m pytest tests/test_security.py tests/test_rbac.py -v
```

## Architecture

`server.py` is the entry point. It creates a `FastMCP` instance, initializes `SecurityManager` (from `security.py`) and `ServerConfig` (from `config.py`), then registers all tools as thin wrappers that delegate to modules in `tools/`.

**Key pattern:** Every tool function in `server.py` is a `@mcp.tool()` decorated async function that passes `config` and `security` as keyword arguments to the actual implementation in `tools/`. The tool modules never import the MCP server directly.

**Shared utilities:** `tools/utils.py` contains `make_response()` and `run_docker()` — all tool modules import from here. Never duplicate these helpers.

**Security flow:** All tool calls go through `SecurityManager` which provides:
- RBAC with 3 roles: admin (all), operator (tools, no user/config mgmt), viewer (read-only tools)
- API key authentication (Bearer token or X-API-Key header) on all `/api/*` endpoints
- Users stored in `/DATA/AppData/zimaos-mcp/users.json` via `UserManager` class
- Legacy single `api_key` in config.yaml auto-migrated to admin user on first start
- Path validation (only `/DATA/`, `/tmp/`, `/var/log/` allowed; write-protected paths)
- Command blocklist (40+ regex patterns for destructive commands, nested shells, exfiltration)
- Tiered rate limiting (exec: 1x, write: 2x, read: 5x base limit)
- Audit logging with user attribution (every tool call logged to `/DATA/AppData/zimaos-mcp/audit.log`)

**Config precedence:** `config.yaml` → environment variables → defaults (see `config.py` `env_map`). API key is auto-generated and persisted on first start. Invalid YAML or env values are handled gracefully with warnings.

**Dashboard + API:** `api.py` provides REST endpoints mounted as custom Starlette routes via `mcp._custom_starlette_routes`. All endpoints except `/api/health` and `/api/auth` require authentication via `@require_auth` decorator. Static files from `web/` are mounted at `/`.

**Skill system:** `skills.py` manages skill lifecycle (install from marketplace/git/upload, toggle with hot-reload, uninstall). Skills from untrusted sources are flagged. Hot-reload registers/deregisters tools without server restart.

**Cron scheduler:** `tools/cron.py` includes an asyncio-based `CronScheduler` that runs in the background, checking jobs every 60 seconds and executing matching commands.

**Skill formats:** Two types supported:
1. SKILL.md (Anthropic format) — Markdown with YAML frontmatter
2. Python modules — .py files with `tool_*` prefixed functions or `_mcp_tool` attribute, registered via `mcp.add_tool()`

**Marketplace integration:** `skills.py` fetches `.claude-plugin/marketplace.json` from GitHub repos (default: anthropics/skills), downloads individual skill directories via GitHub API (no full clone).

## ZimaOS Constraints

- **Read-only root filesystem** — all persistent data under `/DATA/`
- **No apt/pip on host** — everything runs in Docker
- **DOCKER_CONFIG=/DATA/.docker** required for all docker commands on ZimaOS host
- **`docker compose restart` does NOT reload .env** — must `down` + `up`
- Reference: `ZIMAOS-KNOWLEDGE.md` in parent directory

## FastMCP API (mcp v1.27+)

- `host`, `port`, `log_level` go in `FastMCP.__init__()`, NOT in `run()`
- `run()` only takes `transport` and `mount_path`
- No `version` or `description` params on `FastMCP.__init__()`

## Response Format

All tools return: `{"success": bool, "data": ..., "error": str | None}`

## Version

Current version: `1.2.3` (defined in `config.py` as `VERSION`)
