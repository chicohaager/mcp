"""Tests for security & observability features (v2).

Covers: MetricsCollector, sensitive data masking, RateLimiter.retry_after,
IP whitelist config, max_request_size config.
"""

import os
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security import (
    AuditLogger,
    MetricsCollector,
    RateLimiter,
    _mask_sensitive,
)
from config import ServerConfig


# ── Sensitive Data Masking ────────────────────────────────────────────────


class TestSensitiveMasking:
    """Tests for _mask_sensitive helper."""

    def test_masks_key(self):
        assert _mask_sensitive("api_key", "abc123") == "***"

    def test_masks_password(self):
        assert _mask_sensitive("password", "hunter2") == "***"

    def test_masks_secret(self):
        assert _mask_sensitive("client_secret", "xyz") == "***"

    def test_masks_token(self):
        assert _mask_sensitive("auth_token", "tok_abc") == "***"

    def test_case_insensitive(self):
        assert _mask_sensitive("API_KEY", "abc") == "***"
        assert _mask_sensitive("Password", "abc") == "***"

    def test_no_mask_normal_key(self):
        assert _mask_sensitive("command", "ls -la") == "ls -la"

    def test_no_mask_path(self):
        assert _mask_sensitive("path", "/DATA/test") == "/DATA/test"


class TestAuditLoggerMasking:
    """Tests that AuditLogger masks sensitive args."""

    def test_masks_password_in_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "audit.log")
            audit = AuditLogger(log_path)
            audit.log("test_tool", {"password": "hunter2", "path": "/DATA"}, True)

            for handler in audit._logger.handlers:
                handler.flush()

            with open(log_path) as f:
                content = f.read()
            assert "hunter2" not in content
            assert "***" in content
            assert "/DATA" in content

    def test_request_id_in_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "audit.log")
            audit = AuditLogger(log_path)
            audit.log("test_tool", {}, True, request_id="abc-123-def")

            for handler in audit._logger.handlers:
                handler.flush()

            with open(log_path) as f:
                content = f.read()
            assert "abc-123-def" in content


# ── MetricsCollector ─────────────────────────────────────────────────────


class TestMetricsCollector:
    """Tests for the Prometheus metrics collector."""

    def test_record_and_format(self):
        mc = MetricsCollector()
        mc.record("bash_exec", True)
        mc.record("bash_exec", True)
        mc.record("bash_exec", False)
        mc.record("docker_ps", True)

        output = mc.format_openmetrics(42)
        assert 'mcp_requests_total{tool="bash_exec",status="ok"} 2' in output
        assert 'mcp_requests_total{tool="bash_exec",status="fail"} 1' in output
        assert 'mcp_requests_total{tool="docker_ps",status="ok"} 1' in output
        assert "mcp_tools_count 42" in output
        assert "mcp_uptime_seconds" in output

    def test_empty_metrics(self):
        mc = MetricsCollector()
        output = mc.format_openmetrics(0)
        assert "mcp_requests_total" in output  # header still present
        assert "mcp_tools_count 0" in output

    def test_format_includes_help_and_type(self):
        mc = MetricsCollector()
        output = mc.format_openmetrics(10)
        assert "# HELP mcp_requests_total" in output
        assert "# TYPE mcp_requests_total counter" in output
        assert "# TYPE mcp_uptime_seconds gauge" in output
        assert "# TYPE mcp_tools_count gauge" in output


# ── RateLimiter.retry_after ──────────────────────────────────────────────


class TestRateLimiterRetryAfter:
    """Tests for the retry_after property."""

    def test_retry_after_empty(self):
        rl = RateLimiter(max_requests=5, window_seconds=60)
        assert rl.retry_after == 0

    def test_retry_after_full(self):
        rl = RateLimiter(max_requests=2, window_seconds=10)
        rl.check()
        rl.check()
        # Should be close to window_seconds
        assert rl.retry_after > 0
        assert rl.retry_after <= 11

    def test_retry_after_is_int(self):
        rl = RateLimiter(max_requests=1, window_seconds=5)
        rl.check()
        assert isinstance(rl.retry_after, int)


# ── Config additions ─────────────────────────────────────────────────────


class TestConfigAdditions:
    """Tests for new config fields."""

    def test_default_ip_whitelist_empty(self):
        cfg = ServerConfig()
        assert cfg.ip_whitelist == []

    def test_default_max_request_size(self):
        cfg = ServerConfig()
        assert cfg.max_request_size == 1_048_576

    def test_ip_whitelist_from_env(self):
        os.environ["MCP_IP_WHITELIST"] = "192.168.1.1, 10.0.0.1"
        try:
            from config import load_config
            cfg = load_config("/tmp/nonexistent_test_cfg.yaml")
            assert "192.168.1.1" in cfg.ip_whitelist
            assert "10.0.0.1" in cfg.ip_whitelist
        finally:
            del os.environ["MCP_IP_WHITELIST"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
