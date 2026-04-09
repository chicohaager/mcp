"""Webhook notification system for ZimaOS MCP Server.

Provides webhook management and event-driven HTTP notifications.
"""

import asyncio
import json
import logging
import os
import re
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone
from typing import Optional

from tools.utils import make_response

logger = logging.getLogger("zimaos-mcp.webhooks")

# Supported event types
EVENT_TYPES = [
    "tool.failed",
    "container.stopped",
    "disk.warning",
    "rate_limit.hit",
    "cron.failed",
    "cron.completed",
    "skill.installed",
]

# Basic URL validation pattern
_URL_RE = re.compile(r"^https?://\S+$")


class WebhookManager:
    """Manages webhook registrations and event delivery."""

    def __init__(self, data_dir: str = "/DATA/AppData/zimaos-mcp"):
        self._path = os.path.join(data_dir, "webhooks.json")
        self._webhooks: list[dict] = []
        self._load()

    def _load(self) -> None:
        """Load webhook configs from disk."""
        if os.path.exists(self._path):
            try:
                with open(self._path) as f:
                    self._webhooks = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load webhooks from %s: %s", self._path, e)
                self._webhooks = []
        else:
            self._webhooks = []

    def _save(self) -> None:
        """Persist webhook configs to disk."""
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        try:
            with open(self._path, "w") as f:
                json.dump(self._webhooks, f, indent=2)
        except OSError as e:
            logger.error("Failed to save webhooks to %s: %s", self._path, e)

    def list_webhooks(self) -> list[dict]:
        """Return all registered webhooks."""
        return list(self._webhooks)

    def add(
        self,
        name: str,
        url: str,
        events: list[str],
        headers: Optional[dict[str, str]] = None,
    ) -> dict:
        """Add a new webhook registration.

        Returns:
            The created webhook dict, or raises ValueError on invalid input.
        """
        if not _URL_RE.match(url):
            raise ValueError(f"Invalid URL format: {url}")

        invalid = [e for e in events if e not in EVENT_TYPES]
        if invalid:
            raise ValueError(f"Unknown event types: {invalid}. Valid: {EVENT_TYPES}")

        webhook = {
            "id": uuid.uuid4().hex[:12],
            "name": name,
            "url": url,
            "events": events,
            "active": True,
            "headers": headers or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._webhooks.append(webhook)
        self._save()
        return webhook

    def delete(self, webhook_id: str) -> bool:
        """Delete a webhook by ID. Returns True if found and deleted."""
        before = len(self._webhooks)
        self._webhooks = [w for w in self._webhooks if w["id"] != webhook_id]
        if len(self._webhooks) < before:
            self._save()
            return True
        return False

    def get(self, webhook_id: str) -> Optional[dict]:
        """Get a webhook by ID."""
        for w in self._webhooks:
            if w["id"] == webhook_id:
                return w
        return None

    async def fire(self, event_type: str, data: dict) -> None:
        """Send HTTP POST to all active webhooks matching the event type.

        Non-blocking, never raises — failures are logged only.
        """
        matching = [
            w for w in self._webhooks
            if w.get("active") and event_type in w.get("events", [])
        ]
        if not matching:
            return

        payload = json.dumps({
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "server": "zimaos-mcp",
            "data": data,
        }).encode("utf-8")

        for webhook in matching:
            asyncio.ensure_future(self._deliver(webhook, payload))

    async def _deliver(self, webhook: dict, payload: bytes) -> None:
        """Deliver a payload to a single webhook endpoint."""
        try:
            req = urllib.request.Request(
                webhook["url"],
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # Add custom headers
            for key, value in webhook.get("headers", {}).items():
                req.add_header(key, value)

            await asyncio.to_thread(
                urllib.request.urlopen, req, timeout=5
            )
            logger.info(
                "Webhook delivered: %s -> %s", webhook["name"], webhook["url"]
            )
        except Exception as e:
            logger.warning(
                "Webhook delivery failed: %s -> %s: %s",
                webhook["name"], webhook["url"], e,
            )


# ── Tool functions ──────────────────────────────────────────────────────────


async def webhook_list(*, security) -> dict:
    """List all registered webhooks.

    Args:
        security: SecurityManager instance.

    Returns:
        Standardized response with webhook list.
    """
    security.audit.log("webhook_list", {}, True)
    # WebhookManager is accessed via the module-level instance set by server.py
    return make_response(True, {
        "webhooks": _manager.list_webhooks(),
        "event_types": EVENT_TYPES,
    })


async def webhook_add(
    name: str,
    url: str,
    events: list[str],
    headers: dict[str, str] | None = None,
    *,
    security,
) -> dict:
    """Add a new webhook.

    Args:
        name: Human-readable name for the webhook.
        url: HTTP(S) URL to receive POST notifications.
        events: List of event types to subscribe to.
        headers: Optional custom HTTP headers to include.
        security: SecurityManager instance.

    Returns:
        Standardized response with created webhook.
    """
    try:
        webhook = _manager.add(name, url, events, headers)
    except ValueError as e:
        security.audit.log("webhook_add", {"name": name, "url": url}, False, str(e))
        return make_response(False, error=str(e))

    security.audit.log("webhook_add", {"name": name, "url": url}, True)
    return make_response(True, webhook)


async def webhook_delete(webhook_id: str, *, security) -> dict:
    """Delete a webhook by ID.

    Args:
        webhook_id: The webhook identifier.
        security: SecurityManager instance.

    Returns:
        Standardized response.
    """
    if _manager.delete(webhook_id):
        security.audit.log("webhook_delete", {"id": webhook_id}, True)
        return make_response(True, {"deleted": webhook_id})
    security.audit.log("webhook_delete", {"id": webhook_id}, False, "not found")
    return make_response(False, error=f"Webhook '{webhook_id}' not found")


async def webhook_test(webhook_id: str, *, security) -> dict:
    """Send a test event to a specific webhook.

    Args:
        webhook_id: The webhook identifier.
        security: SecurityManager instance.

    Returns:
        Standardized response with delivery result.
    """
    webhook = _manager.get(webhook_id)
    if not webhook:
        security.audit.log("webhook_test", {"id": webhook_id}, False, "not found")
        return make_response(False, error=f"Webhook '{webhook_id}' not found")

    payload = json.dumps({
        "event": "test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "server": "zimaos-mcp",
        "data": {"message": "Test event from ZimaOS MCP Server"},
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            webhook["url"],
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        for key, value in webhook.get("headers", {}).items():
            req.add_header(key, value)

        resp = await asyncio.to_thread(urllib.request.urlopen, req, timeout=5)
        status = resp.getcode()
        security.audit.log("webhook_test", {"id": webhook_id}, True, f"HTTP {status}")
        return make_response(True, {"webhook_id": webhook_id, "status_code": status})
    except Exception as e:
        security.audit.log("webhook_test", {"id": webhook_id}, False, str(e))
        return make_response(False, error=f"Delivery failed: {e}")


# Module-level manager instance — set by server.py at startup
_manager: WebhookManager = None  # type: ignore[assignment]


def init_manager(data_dir: str = "/DATA/AppData/zimaos-mcp") -> WebhookManager:
    """Initialize the module-level WebhookManager.

    Called from server.py during startup.

    Returns:
        The initialized WebhookManager instance.
    """
    global _manager
    _manager = WebhookManager(data_dir)
    return _manager
