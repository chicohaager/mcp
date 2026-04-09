"""REST API for ZimaOS MCP Dashboard.

Provides HTTP endpoints for the web UI to interact with the MCP server,
skill manager, audit logs, and configuration. Includes RBAC enforcement.
"""

import json
import logging
import os
import time
import uuid

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
    "Access-Control-Max-Age": "86400",
}

from config import ServerConfig, VERSION
from security import SecurityManager, ApiUser, UserManager, MetricsCollector
from skills import SkillManager
from templates import get_templates, get_template

logger = logging.getLogger("zimaos-mcp.api")

# Server start time for uptime calculation
_start_time = time.monotonic()


def _extract_key(request: Request) -> str | None:
    """Extract API key from request headers.

    Returns the raw key string, or None if no key was provided.
    """
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]

    api_key = request.headers.get("x-api-key", "")
    if api_key:
        return api_key

    return None


def _check_auth(
    request: Request,
    user_manager: UserManager,
    security: SecurityManager | None = None,
) -> ApiUser | None:
    """Validate API key and return the authenticated user.

    Returns ApiUser if valid, None if authentication fails.
    Logs failed authentication attempts via AuditLogger when security is provided.
    """
    key = _extract_key(request)
    if not key:
        return None
    user = user_manager.authenticate(key)
    if user is None and security is not None:
        ip = request.client.host if request.client else "unknown"
        key_prefix = key[:8] if len(key) >= 8 else key
        security.audit.log(
            "auth_failed",
            {"ip": ip, "key_prefix": key_prefix},
            False,
        )
    return user


def create_api_routes(
    config: ServerConfig,
    security: SecurityManager,
    skill_manager: SkillManager,
    mcp_server: object,
    webhook_manager=None,
    user_manager: UserManager | None = None,
) -> list[Route]:
    """Create Starlette routes for the dashboard REST API.

    Args:
        config: Server configuration.
        security: Security manager instance.
        skill_manager: Skill manager instance.
        mcp_server: FastMCP server instance (for tool introspection).
        webhook_manager: Optional WebhookManager instance.
        user_manager: UserManager for RBAC (created automatically if None).

    Returns:
        List of Starlette Route objects.
    """

    # Initialize user manager (legacy key migration done in server.py)
    if user_manager is None:
        user_manager = UserManager()

    # Metrics collector for Prometheus /metrics endpoint
    metrics = MetricsCollector()

    def cors(handler):
        """Wrap a handler to add CORS headers to all responses."""
        async def wrapper(request: Request) -> Response:
            # Handle preflight
            if request.method == "OPTIONS":
                return Response(status_code=204, headers=CORS_HEADERS)
            response = await handler(request)
            response.headers.update(CORS_HEADERS)
            return response
        return wrapper

    # ── Auth helpers ───────────────────────────────────────────────────────

    def require_auth(handler):
        """Decorator to require API key authentication and inject user.

        Also enforces: IP whitelist, request size limits, rate limiting,
        and assigns a unique request ID to each request.
        """
        async def wrapper(request: Request) -> JSONResponse:
            # ── Request ID ────────────────────────────────────────────
            request_id = str(uuid.uuid4())
            request.state.request_id = request_id

            # ── IP whitelist check ────────────────────────────────────
            if config.ip_whitelist:
                client_ip = request.client.host if request.client else "unknown"
                if client_ip not in config.ip_whitelist:
                    return JSONResponse(
                        {"error": "IP not allowed"},
                        status_code=403,
                        headers={"X-Request-ID": request_id},
                    )

            # ── Input size limit (for POST/PUT) ───────────────────────
            if request.method in ("POST", "PUT"):
                content_length = request.headers.get("content-length")
                if content_length is not None:
                    try:
                        if int(content_length) > config.max_request_size:
                            return JSONResponse(
                                {"error": "Payload too large"},
                                status_code=413,
                                headers={"X-Request-ID": request_id},
                            )
                    except (ValueError, TypeError):
                        pass

            # ── Authentication ────────────────────────────────────────
            user = _check_auth(request, user_manager, security)
            if user is None:
                key = _extract_key(request)
                if key is None:
                    msg = "Authentication required. Provide Authorization: Bearer <key> or X-API-Key header."
                else:
                    msg = "Invalid API key"
                return JSONResponse(
                    {"error": msg},
                    status_code=401,
                    headers={"X-Request-ID": request_id},
                )

            # ── Rate limit check ──────────────────────────────────────
            allowed, rate_msg = security.check_rate_limit()
            if not allowed:
                retry_after = security.rate_limiter.retry_after
                return JSONResponse(
                    {"error": rate_msg},
                    status_code=429,
                    headers={
                        "Retry-After": str(retry_after),
                        "X-Request-ID": request_id,
                    },
                )

            request.state.user = user
            response = await handler(request)

            # Inject X-Request-ID into every response
            if isinstance(response, JSONResponse):
                response.headers["X-Request-ID"] = request_id
            return response
        return wrapper

    def require_role(role: str):
        """Decorator factory for role-based access. Apply AFTER require_auth."""
        def decorator(handler):
            async def wrapper(request: Request) -> JSONResponse:
                user: ApiUser = request.state.user
                pseudo_tool = "_user_management" if role == "admin" else f"_{role}"
                if not user_manager.has_permission(user, pseudo_tool):
                    return JSONResponse(
                        {"error": f"Insufficient permissions. Required role: {role}"},
                        status_code=403,
                    )
                return await handler(request)
            return wrapper
        return decorator

    # ── Auth endpoint (no key required) ──────────────────────────────────

    async def api_auth_check(request: Request) -> JSONResponse:
        """Validate an API key without accessing protected resources."""
        user = _check_auth(request, user_manager)
        if user is None:
            return JSONResponse({"authenticated": False}, status_code=401)
        return JSONResponse({
            "authenticated": True,
            "user": user.to_safe_dict(),
        })

    # ── Status ────────────────────────────────────────────────────────────

    @require_auth
    async def api_status(request: Request) -> JSONResponse:
        """Server status and basic stats."""
        uptime_s = int(time.monotonic() - _start_time)
        hours, remainder = divmod(uptime_s, 3600)
        minutes, seconds = divmod(remainder, 60)

        # Count audit log entries for today
        today_requests = 0
        audit_path = config.audit_log
        if os.path.exists(audit_path):
            today = time.strftime("%Y-%m-%d")
            try:
                with open(audit_path) as f:
                    for line in f:
                        if line.startswith(today):
                            today_requests += 1
            except OSError:
                pass

        return JSONResponse({
            "status": "running",
            "version": VERSION,
            "uptime": f"{hours}h {minutes}m {seconds}s",
            "uptime_seconds": uptime_s,
            "port": config.port,
            "tool_count": len(mcp_server._tool_manager._tools) if hasattr(mcp_server, "_tool_manager") else 0,
            "skill_count": len(skill_manager.list_skills()),
            "requests_today": today_requests,
            "rate_limit_remaining": security.rate_limiter.remaining,
            "rate_limit_max": security.rate_limiter.max_requests,
        })

    # ── Tools ─────────────────────────────────────────────────────────────

    @require_auth
    async def api_tools(request: Request) -> JSONResponse:
        """List all registered MCP tools with their schemas."""
        tools = []
        if hasattr(mcp_server, "_tool_manager"):
            for name, tool in mcp_server._tool_manager._tools.items():
                tool_info = {
                    "name": name,
                    "description": tool.description or "",
                }
                if hasattr(tool, "parameters"):
                    tool_info["parameters"] = tool.parameters
                elif hasattr(tool, "fn"):
                    import inspect
                    sig = inspect.signature(tool.fn)
                    params = {}
                    for pname, param in sig.parameters.items():
                        if pname in ("config", "security"):
                            continue
                        pinfo = {"required": param.default is inspect.Parameter.empty}
                        if param.annotation is not inspect.Parameter.empty:
                            pinfo["type"] = str(param.annotation)
                        if param.default is not inspect.Parameter.empty:
                            pinfo["default"] = repr(param.default)
                        params[pname] = pinfo
                    tool_info["parameters"] = params
                tools.append(tool_info)
        return JSONResponse({"tools": tools, "count": len(tools)})

    @require_auth
    async def api_tool_test(request: Request) -> JSONResponse:
        """Execute a tool for testing purposes."""
        name = request.path_params["name"]
        user: ApiUser = request.state.user

        # Check RBAC permission for the tool
        if not user_manager.has_permission(user, name):
            return JSONResponse(
                {"error": f"Permission denied: role '{user.role}' cannot use tool '{name}'"},
                status_code=403,
            )

        try:
            body = await request.json()
        except Exception:
            body = {}

        if not hasattr(mcp_server, "_tool_manager"):
            return JSONResponse({"error": "Tool manager not available"}, status_code=500)

        tool = mcp_server._tool_manager._tools.get(name)
        if not tool:
            return JSONResponse({"error": f"Tool '{name}' not found"}, status_code=404)

        try:
            result = await tool.fn(**body)
            request_id = getattr(request.state, "request_id", "")
            security.audit.log(name, body, True, user=user.name, request_id=request_id)
            metrics.record(name, True)
            return JSONResponse({"result": result})
        except Exception as e:
            request_id = getattr(request.state, "request_id", "")
            security.audit.log(name, body, False, detail=str(e), user=user.name, request_id=request_id)
            metrics.record(name, False)
            return JSONResponse({"error": str(e)}, status_code=500)

    # ── Skills ────────────────────────────────────────────────────────────

    @require_auth
    async def api_skills(request: Request) -> JSONResponse:
        """List installed skills."""
        return JSONResponse({
            "skills": skill_manager.list_skills(),
            "count": len(skill_manager.list_skills()),
        })

    @require_auth
    async def api_skill_install(request: Request) -> JSONResponse:
        """Install a skill from git URL, marketplace, or file upload."""
        content_type = request.headers.get("content-type", "")

        if "multipart" in content_type:
            form = await request.form()
            upload = form.get("file")
            if upload:
                content = await upload.read()
                result = skill_manager.install_from_file(upload.filename, content)
                return JSONResponse(result, status_code=200 if result["success"] else 400)
            return JSONResponse({"error": "No file provided"}, status_code=400)
        else:
            try:
                body = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON"}, status_code=400)

            # Marketplace install (preferred for Anthropic skills)
            if body.get("marketplace"):
                skill_name = body.get("name")
                if not skill_name:
                    return JSONResponse({"error": "name required"}, status_code=400)
                result = skill_manager.install_from_marketplace(skill_name)
                return JSONResponse(result, status_code=200 if result["success"] else 400)

            # Git install
            git_url = body.get("git_url")
            skill_name = body.get("name")
            if not git_url:
                return JSONResponse({"error": "git_url or marketplace required"}, status_code=400)

            result = skill_manager.install_from_git(git_url, skill_name)
            return JSONResponse(result, status_code=200 if result["success"] else 400)

    @require_auth
    async def api_marketplace(request: Request) -> JSONResponse:
        """Browse available skills from marketplace registries."""
        result = skill_manager.fetch_marketplace()
        return JSONResponse(result, status_code=200 if result.get("success") else 500)

    @require_auth
    async def api_skill_content(request: Request) -> JSONResponse:
        """Get full SKILL.md content for an installed skill."""
        name = request.path_params["name"]
        result = skill_manager.get_skill_content(name)
        return JSONResponse(result, status_code=200 if result.get("success") else 404)

    @require_auth
    async def api_skill_toggle(request: Request) -> JSONResponse:
        """Toggle a skill active/inactive."""
        name = request.path_params["name"]
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        active = body.get("active", True)
        result = skill_manager.toggle(name, active, mcp=mcp_server)
        return JSONResponse(result, status_code=200 if result["success"] else 404)

    @require_auth
    async def api_skill_delete(request: Request) -> JSONResponse:
        """Uninstall a skill."""
        name = request.path_params["name"]
        result = skill_manager.uninstall(name)
        return JSONResponse(result, status_code=200 if result["success"] else 404)

    # ── Audit ─────────────────────────────────────────────────────────────

    @require_auth
    async def api_audit(request: Request) -> JSONResponse:
        """Get paginated audit log entries."""
        try:
            limit = int(request.query_params.get("limit", "50"))
            offset = int(request.query_params.get("offset", "0"))
        except (ValueError, TypeError):
            return JSONResponse({"error": "limit and offset must be integers"}, status_code=400)
        search = request.query_params.get("q", "")

        entries = []
        audit_path = config.audit_log
        if os.path.exists(audit_path):
            try:
                with open(audit_path) as f:
                    lines = f.readlines()

                # Filter if search query
                if search:
                    lines = [l for l in lines if search.lower() in l.lower()]

                # Reverse for newest first, apply pagination
                lines = list(reversed(lines))
                total = len(lines)
                lines = lines[offset : offset + limit]

                for line in lines:
                    line = line.strip()
                    if " | " in line:
                        parts = line.split(" | ", 3)
                        entries.append({
                            "timestamp": parts[0] if len(parts) > 0 else "",
                            "status": parts[1] if len(parts) > 1 else "",
                            "tool": parts[2] if len(parts) > 2 else "",
                            "detail": parts[3] if len(parts) > 3 else "",
                        })
                    else:
                        entries.append({"raw": line})
            except OSError:
                pass
        else:
            total = 0

        return JSONResponse({
            "entries": entries,
            "total": total,
            "limit": limit,
            "offset": offset,
        })

    # ── Config (admin only for writes) ───────────────────────────────────

    @require_auth
    async def api_config_get(request: Request) -> JSONResponse:
        """Get current configuration."""
        return JSONResponse({
            "host": config.host,
            "port": config.port,
            "log_level": config.log_level,
            "allowed_paths": config.allowed_paths,
            "readonly_paths": config.readonly_paths,
            "rate_limit": config.rate_limit,
            "rate_window": config.rate_window,
            "data_dir": config.data_dir,
            "default_timeout": config.default_timeout,
            "max_timeout": config.max_timeout,
        })

    @require_auth
    @require_role("admin")
    async def api_config_update(request: Request) -> JSONResponse:
        """Update configuration (writes to config.yaml). Admin only."""
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        import yaml
        config_path = os.path.join(config.data_dir, "config.yaml")

        # Load existing or start fresh
        existing = {}
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    existing = yaml.safe_load(f) or {}
            except Exception:
                pass

        # Merge updates
        allowed_keys = {
            "log_level", "allowed_paths", "readonly_paths",
            "rate_limit", "rate_window", "default_timeout", "max_timeout",
        }
        for key, value in body.items():
            if key in allowed_keys:
                existing[key] = value

        # Write with restricted permissions (config may contain API key)
        try:
            fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                yaml.dump(existing, f, default_flow_style=False)
            user: ApiUser = request.state.user
            security.audit.log("_config_update", body, True, user=user.name)
            return JSONResponse({
                "success": True,
                "note": "Restart server to apply all changes",
                "config": existing,
            })
        except OSError as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ── User Management (admin only) ─────────────────────────────────────

    @require_auth
    @require_role("admin")
    async def api_users_list(request: Request) -> JSONResponse:
        """List all API users (keys masked). Admin only."""
        users = user_manager.list_users()
        return JSONResponse({
            "users": [u.to_safe_dict() for u in users],
            "count": len(users),
        })

    @require_auth
    @require_role("admin")
    async def api_users_create(request: Request) -> JSONResponse:
        """Create a new API user. Admin only.

        Body: {"name": str, "role": "admin"|"operator"|"viewer"}
        Returns the full API key (only time it's shown).
        """
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        name = body.get("name")
        role = body.get("role")
        if not name or not role:
            return JSONResponse(
                {"error": "Both 'name' and 'role' are required"}, status_code=400
            )

        try:
            new_user = user_manager.add_user(name, role)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

        admin_user: ApiUser = request.state.user
        security.audit.log(
            "_user_management",
            {"action": "create", "name": name, "role": role},
            True,
            user=admin_user.name,
        )

        return JSONResponse({
            "success": True,
            "user": new_user.to_dict(),  # Full key shown on creation
        })

    @require_auth
    @require_role("admin")
    async def api_users_delete(request: Request) -> JSONResponse:
        """Delete an API user by key prefix (last 4+ chars match). Admin only."""
        key_prefix = request.path_params["key_prefix"]

        # Find user whose key ends with the given prefix
        target = None
        for u in user_manager.list_users():
            if u.key.endswith(key_prefix):
                target = u
                break

        if target is None:
            return JSONResponse(
                {"error": f"No user found matching key suffix '{key_prefix}'"},
                status_code=404,
            )

        # Prevent self-deletion
        admin_user: ApiUser = request.state.user
        if target.key == admin_user.key:
            return JSONResponse(
                {"error": "Cannot delete your own user account"},
                status_code=400,
            )

        user_manager.delete_user(target.key)
        security.audit.log(
            "_user_management",
            {"action": "delete", "name": target.name, "key_suffix": key_prefix},
            True,
            user=admin_user.name,
        )

        return JSONResponse({"success": True, "deleted": target.name})

    # ── Webhooks ──────────────────────────────────────────────────────────

    @require_auth
    async def api_webhooks_list(request: Request) -> JSONResponse:
        """List all registered webhooks."""
        if not webhook_manager:
            return JSONResponse({"error": "Webhooks not available"}, status_code=500)
        from tools.webhooks import EVENT_TYPES
        return JSONResponse({
            "webhooks": webhook_manager.list_webhooks(),
            "event_types": EVENT_TYPES,
        })

    @require_auth
    async def api_webhooks_add(request: Request) -> JSONResponse:
        """Add a new webhook."""
        if not webhook_manager:
            return JSONResponse({"error": "Webhooks not available"}, status_code=500)
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        name = body.get("name")
        url = body.get("url")
        events = body.get("events", [])
        headers = body.get("headers")

        if not name or not url or not events:
            return JSONResponse(
                {"error": "name, url, and events are required"}, status_code=400
            )

        try:
            webhook = webhook_manager.add(name, url, events, headers)
            return JSONResponse({"success": True, "data": webhook})
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    @require_auth
    async def api_webhooks_delete(request: Request) -> JSONResponse:
        """Delete a webhook by ID."""
        if not webhook_manager:
            return JSONResponse({"error": "Webhooks not available"}, status_code=500)
        webhook_id = request.path_params["id"]
        if webhook_manager.delete(webhook_id):
            return JSONResponse({"success": True, "deleted": webhook_id})
        return JSONResponse({"error": f"Webhook '{webhook_id}' not found"}, status_code=404)

    @require_auth
    async def api_webhooks_test(request: Request) -> JSONResponse:
        """Send a test event to a specific webhook."""
        if not webhook_manager:
            return JSONResponse({"error": "Webhooks not available"}, status_code=500)
        webhook_id = request.path_params["id"]
        from tools.webhooks import webhook_test as _wh_test
        result = await _wh_test(webhook_id, security=security)
        status_code = 200 if result.get("success") else 404
        return JSONResponse(result, status_code=status_code)

    # ── Templates (Operations Console) ─────────────────────────────────

    @require_auth
    async def api_templates_list(request: Request) -> JSONResponse:
        """List all available command templates."""
        return JSONResponse({"templates": get_templates(), "count": len(get_templates())})

    @require_auth
    async def api_templates_run(request: Request) -> JSONResponse:
        """Execute a template's steps sequentially and return aggregated results."""
        template_id = request.path_params["id"]
        template = get_template(template_id)
        if template is None:
            return JSONResponse(
                {"error": f"Template '{template_id}' not found"}, status_code=404
            )

        user: ApiUser = request.state.user

        try:
            body = await request.json()
        except Exception:
            body = {}

        if not hasattr(mcp_server, "_tool_manager"):
            return JSONResponse({"error": "Tool manager not available"}, status_code=500)

        results = []

        # Execute each step, catching exceptions per-step
        for i, step in enumerate(template.get("steps", [])):
            tool_name = step["tool"]
            params = dict(step.get("params", {}))

            # Check RBAC permission
            if not user_manager.has_permission(user, tool_name):
                results.append({
                    "step": i + 1,
                    "tool": tool_name,
                    "result": {"success": False, "error": f"Permission denied for tool '{tool_name}'"},
                })
                continue

            tool = mcp_server._tool_manager._tools.get(tool_name)
            if not tool:
                results.append({
                    "step": i + 1,
                    "tool": tool_name,
                    "result": {"success": False, "error": f"Tool '{tool_name}' not found"},
                })
                continue

            try:
                result = await tool.fn(**params)
                security.audit.log(tool_name, params, True, user=user.name)
                metrics.record(tool_name, True)
                results.append({"step": i + 1, "tool": tool_name, "result": result})
            except Exception as e:
                security.audit.log(tool_name, params, False, detail=str(e), user=user.name)
                metrics.record(tool_name, False)
                results.append({
                    "step": i + 1,
                    "tool": tool_name,
                    "result": {"success": False, "error": str(e)},
                })

        # Handle follow_up if template has one and body contains the input field
        follow_up = template.get("follow_up")
        if follow_up:
            field = follow_up["field"]
            field_value = body.get(field)

            if field_value is not None:
                fu_tool_name = follow_up["tool"]
                fu_params = dict(follow_up.get("params", {}))

                # Special handling: _host_port splits into host and port
                if field == "_host_port" and isinstance(field_value, str) and ":" in field_value:
                    parts = field_value.rsplit(":", 1)
                    fu_params["host"] = parts[0]
                    try:
                        fu_params["port"] = int(parts[1])
                    except ValueError:
                        results.append({
                            "step": "follow_up",
                            "tool": fu_tool_name,
                            "result": {"success": False, "error": f"Invalid port in '{field_value}'"},
                        })
                        return JSONResponse({"success": True, "template": template_id, "results": results})
                elif field != "_host_port":
                    # Apply transform if defined
                    transform = follow_up.get("transform", {})
                    if field in transform:
                        fu_params[field] = transform[field].replace("{value}", str(field_value))
                    else:
                        fu_params[field] = field_value

                # Check RBAC permission for follow_up tool
                if not user_manager.has_permission(user, fu_tool_name):
                    results.append({
                        "step": "follow_up",
                        "tool": fu_tool_name,
                        "result": {"success": False, "error": f"Permission denied for tool '{fu_tool_name}'"},
                    })
                else:
                    tool = mcp_server._tool_manager._tools.get(fu_tool_name)
                    if not tool:
                        results.append({
                            "step": "follow_up",
                            "tool": fu_tool_name,
                            "result": {"success": False, "error": f"Tool '{fu_tool_name}' not found"},
                        })
                    else:
                        try:
                            result = await tool.fn(**fu_params)
                            security.audit.log(fu_tool_name, fu_params, True, user=user.name)
                            metrics.record(fu_tool_name, True)
                            results.append({"step": "follow_up", "tool": fu_tool_name, "result": result})
                        except Exception as e:
                            security.audit.log(fu_tool_name, fu_params, False, detail=str(e), user=user.name)
                            metrics.record(fu_tool_name, False)
                            results.append({
                                "step": "follow_up",
                                "tool": fu_tool_name,
                                "result": {"success": False, "error": str(e)},
                            })

        return JSONResponse({"success": True, "template": template_id, "results": results})

    # ── Metrics (no auth -- for Prometheus scraping) ─────────────────────

    async def api_metrics(request: Request) -> Response:
        """Prometheus-compatible metrics endpoint."""
        tool_count = 0
        if hasattr(mcp_server, "_tool_manager"):
            tool_count = len(mcp_server._tool_manager._tools)
        body = metrics.format_openmetrics(tool_count)
        return Response(
            content=body,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    # ── Readiness (no auth -- for orchestrators) ───────────────────────

    async def api_ready(request: Request) -> JSONResponse:
        """Readiness check: Docker socket, writable data dir, tools registered."""
        checks: dict[str, bool] = {}
        # Docker socket
        checks["docker_socket"] = os.path.exists("/var/run/docker.sock")

        # Data directory writable
        try:
            probe = os.path.join(config.data_dir, ".ready_probe")
            with open(probe, "w") as f:
                f.write("ok")
            os.remove(probe)
            checks["data_dir_writable"] = True
        except OSError:
            checks["data_dir_writable"] = False

        # At least one MCP tool registered
        tool_count = 0
        if hasattr(mcp_server, "_tool_manager"):
            tool_count = len(mcp_server._tool_manager._tools)
        checks["tools_registered"] = tool_count > 0

        all_ok = all(checks.values())
        return JSONResponse(
            {"ready": all_ok, "checks": checks, "tool_count": tool_count},
            status_code=200 if all_ok else 503,
        )

    # ── Health (no auth required -- for monitoring) ──────────────────────

    async def api_health(request: Request) -> JSONResponse:
        """Lightweight health check for load balancers / Docker HEALTHCHECK."""
        return JSONResponse({"status": "ok", "version": VERSION})

    # ── OpenAPI Spec (for Open WebUI and other OpenAPI clients) ──────────

    # Essential tools for LLM function-calling (keep prompt small)
    ESSENTIAL_TOOLS = {
        "bash_exec", "files_read", "files_write", "files_list", "files_search",
        "docker_ps", "docker_logs", "docker_stats",
        "system_info", "system_disk", "system_processes",
        "net_ping", "net_dns", "net_port_check",
        "zima_apps_list", "cron_list", "server_health",
    }

    async def api_openapi(request: Request) -> JSONResponse:
        """Auto-generated OpenAPI 3.1 spec from registered MCP tools.

        Query params:
            filter: 'essential' for ~17 key tools (default), 'all' for all 53
        """
        import inspect

        tool_filter = request.query_params.get("filter", "essential")
        paths = {}
        tool_schemas = {}

        if hasattr(mcp_server, "_tool_manager"):
            for name, tool in mcp_server._tool_manager._tools.items():
                # Filter tools to keep LLM prompt manageable
                if tool_filter == "essential" and name not in ESSENTIAL_TOOLS:
                    continue
                # Build parameter schema from function signature
                properties = {}
                required = []

                if hasattr(tool, "fn"):
                    sig = inspect.signature(tool.fn)
                    for pname, param in sig.parameters.items():
                        if pname in ("config", "security"):
                            continue
                        ptype = "string"
                        if param.annotation is not inspect.Parameter.empty:
                            ann = param.annotation
                            if ann in (int, float):
                                ptype = "integer" if ann is int else "number"
                            elif ann is bool:
                                ptype = "boolean"
                            elif ann is dict or str(ann).startswith("dict"):
                                ptype = "object"
                            elif ann is list or str(ann).startswith("list"):
                                ptype = "array"

                        prop = {"type": ptype}
                        if param.default is not inspect.Parameter.empty:
                            prop["default"] = param.default if not isinstance(param.default, type(None)) else None
                        else:
                            required.append(pname)
                        properties[pname] = prop

                schema = {"type": "object", "properties": properties}
                if required:
                    schema["required"] = required

                paths[f"/api/tools/{name}/test"] = {
                    "post": {
                        "operationId": name,
                        "summary": (tool.description or name).split(".")[0].split("\n")[0][:80],
                        "description": (tool.description or "").split("\n\n")[0][:200],
                        "requestBody": {
                            "required": bool(required),
                            "content": {
                                "application/json": {
                                    "schema": schema,
                                }
                            },
                        },
                        "responses": {
                            "200": {
                                "description": "Tool result",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "result": {
                                                    "type": "object",
                                                    "properties": {
                                                        "success": {"type": "boolean"},
                                                        "data": {},
                                                        "error": {"type": "string", "nullable": True},
                                                    },
                                                }
                                            },
                                        }
                                    }
                                },
                            },
                            "401": {"description": "Authentication required"},
                            "403": {"description": "Permission denied"},
                        },
                        "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    }
                }

        spec = {
            "openapi": "3.1.0",
            "info": {
                "title": "ZimaOS MCP Server",
                "version": VERSION,
                "description": "AI-powered system management for ZimaOS. "
                "Provides shell execution, Docker management, filesystem operations, "
                "network diagnostics, backup, cron scheduling, and more.",
            },
            "servers": [
                {"url": f"http://{request.headers.get('host', 'localhost:8717')}"}
            ],
            "paths": paths,
            "components": {
                "securitySchemes": {
                    "BearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                    },
                    "ApiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key",
                    },
                }
            },
        }
        return JSONResponse(spec)

    # ── Return Routes ─────────────────────────────────────────────────────

    return [
        Route("/openapi.json", cors(api_openapi), methods=["GET", "OPTIONS"]),
        Route("/api/health", cors(api_health), methods=["GET", "OPTIONS"]),
        Route("/api/ready", cors(api_ready), methods=["GET", "OPTIONS"]),
        Route("/api/metrics", cors(api_metrics), methods=["GET", "OPTIONS"]),
        Route("/api/auth", cors(api_auth_check), methods=["POST", "OPTIONS"]),
        Route("/api/status", cors(api_status), methods=["GET", "OPTIONS"]),
        Route("/api/tools", cors(api_tools), methods=["GET", "OPTIONS"]),
        Route("/api/tools/{name}/test", cors(api_tool_test), methods=["POST", "OPTIONS"]),
        Route("/api/marketplace", cors(api_marketplace), methods=["GET", "OPTIONS"]),
        Route("/api/skills", cors(api_skills), methods=["GET", "OPTIONS"]),
        Route("/api/skills/install", cors(api_skill_install), methods=["POST", "OPTIONS"]),
        Route("/api/skills/{name}/content", cors(api_skill_content), methods=["GET", "OPTIONS"]),
        Route("/api/skills/{name}/toggle", cors(api_skill_toggle), methods=["POST", "OPTIONS"]),
        Route("/api/skills/{name}", cors(api_skill_delete), methods=["DELETE", "OPTIONS"]),
        Route("/api/audit", cors(api_audit), methods=["GET", "OPTIONS"]),
        Route("/api/config", cors(api_config_get), methods=["GET", "OPTIONS"]),
        Route("/api/config", cors(api_config_update), methods=["PUT", "OPTIONS"]),
        Route("/api/users", cors(api_users_list), methods=["GET", "OPTIONS"]),
        Route("/api/users", cors(api_users_create), methods=["POST", "OPTIONS"]),
        Route("/api/users/{key_prefix}", cors(api_users_delete), methods=["DELETE", "OPTIONS"]),
        Route("/api/webhooks", cors(api_webhooks_list), methods=["GET", "OPTIONS"]),
        Route("/api/webhooks", cors(api_webhooks_add), methods=["POST", "OPTIONS"]),
        Route("/api/webhooks/{id}", cors(api_webhooks_delete), methods=["DELETE", "OPTIONS"]),
        Route("/api/webhooks/{id}/test", cors(api_webhooks_test), methods=["POST", "OPTIONS"]),
        Route("/api/templates", cors(api_templates_list), methods=["GET", "OPTIONS"]),
        Route("/api/templates/{id}/run", cors(api_templates_run), methods=["POST", "OPTIONS"]),
    ]
