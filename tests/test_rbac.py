"""Tests for Role-Based Access Control (RBAC) system."""

import json
import os
import secrets
import sys
import tempfile

import pytest

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security import ApiUser, UserManager, VIEWER_TOOLS


class TestApiUser:
    """Tests for the ApiUser dataclass."""

    def test_create_user(self):
        user = ApiUser(key="test-key", name="Alice", role="admin", created_at="2026-01-01")
        assert user.key == "test-key"
        assert user.name == "Alice"
        assert user.role == "admin"
        assert user.created_at == "2026-01-01"

    def test_to_dict(self):
        user = ApiUser(key="test-key", name="Bob", role="operator", created_at="2026-01-01")
        d = user.to_dict()
        assert d["key"] == "test-key"
        assert d["name"] == "Bob"
        assert d["role"] == "operator"

    def test_to_safe_dict_masks_key(self):
        user = ApiUser(key="abcdefghijklmnop", name="Charlie", role="viewer", created_at="2026-01-01")
        d = user.to_safe_dict()
        assert d["key_suffix"] == "mnop"
        assert "key" not in d
        assert d["name"] == "Charlie"


class TestUserManager:
    """Tests for UserManager CRUD operations."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.users_path = os.path.join(self.tmpdir, "users.json")
        self.mgr = UserManager(users_path=self.users_path)

    def test_add_user(self):
        user = self.mgr.add_user("Alice", "admin")
        assert user.name == "Alice"
        assert user.role == "admin"
        assert len(user.key) > 16  # auto-generated key should be long enough

    def test_add_user_persists(self):
        self.mgr.add_user("Alice", "admin")
        # Reload from disk
        mgr2 = UserManager(users_path=self.users_path)
        assert len(mgr2.list_users()) == 1
        assert mgr2.list_users()[0].name == "Alice"

    def test_authenticate_valid_key(self):
        user = self.mgr.add_user("Alice", "admin")
        found = self.mgr.authenticate(user.key)
        assert found is not None
        assert found.name == "Alice"

    def test_authenticate_invalid_key(self):
        self.mgr.add_user("Alice", "admin")
        found = self.mgr.authenticate("wrong-key")
        assert found is None

    def test_authenticate_uses_hmac(self):
        """Authentication should be timing-safe."""
        user = self.mgr.add_user("Alice", "admin")
        # Should not crash or behave differently with various lengths
        assert self.mgr.authenticate("") is None
        assert self.mgr.authenticate("short") is None
        assert self.mgr.authenticate("x" * 1000) is None
        assert self.mgr.authenticate(user.key) is not None

    def test_delete_user(self):
        user = self.mgr.add_user("Alice", "admin")
        assert self.mgr.delete_user(user.key) is True
        assert len(self.mgr.list_users()) == 0

    def test_delete_nonexistent_user(self):
        assert self.mgr.delete_user("nonexistent-key") is False

    def test_list_users(self):
        self.mgr.add_user("Alice", "admin")
        self.mgr.add_user("Bob", "operator")
        self.mgr.add_user("Charlie", "viewer")
        users = self.mgr.list_users()
        assert len(users) == 3
        names = {u.name for u in users}
        assert names == {"Alice", "Bob", "Charlie"}

    def test_migrate_legacy_key(self):
        """Legacy api_key should be migrated as default admin user."""
        legacy_key = "legacy-api-key-12345"
        mgr = UserManager(users_path=self.users_path)
        mgr.migrate_legacy_key(legacy_key)
        user = mgr.authenticate(legacy_key)
        assert user is not None
        assert user.role == "admin"
        assert user.name == "admin"

    def test_migrate_legacy_key_idempotent(self):
        """Migrating the same key twice should not create duplicates."""
        legacy_key = "legacy-api-key-12345"
        self.mgr.migrate_legacy_key(legacy_key)
        self.mgr.migrate_legacy_key(legacy_key)
        assert len(self.mgr.list_users()) == 1

    def test_invalid_role_rejected(self):
        with pytest.raises(ValueError, match="Invalid role"):
            self.mgr.add_user("Alice", "superuser")

    def test_empty_users_file(self):
        """Empty or missing users.json should work gracefully."""
        mgr = UserManager(users_path=os.path.join(self.tmpdir, "nonexistent.json"))
        assert mgr.list_users() == []


class TestPermissions:
    """Tests for role-based permission checks."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.users_path = os.path.join(self.tmpdir, "users.json")
        self.mgr = UserManager(users_path=self.users_path)
        self.admin = self.mgr.add_user("Admin", "admin")
        self.operator = self.mgr.add_user("Operator", "operator")
        self.viewer = self.mgr.add_user("Viewer", "viewer")

    # Admin can do everything
    def test_admin_can_use_any_tool(self):
        assert self.mgr.has_permission(self.admin, "bash_exec") is True
        assert self.mgr.has_permission(self.admin, "files_write") is True
        assert self.mgr.has_permission(self.admin, "system_info") is True
        assert self.mgr.has_permission(self.admin, "docker_exec") is True

    def test_admin_can_manage_users(self):
        assert self.mgr.has_permission(self.admin, "_user_management") is True
        assert self.mgr.has_permission(self.admin, "_config_update") is True

    # Operator can use most tools but not user/config management
    def test_operator_can_use_tools(self):
        assert self.mgr.has_permission(self.operator, "bash_exec") is True
        assert self.mgr.has_permission(self.operator, "files_write") is True
        assert self.mgr.has_permission(self.operator, "docker_exec") is True
        assert self.mgr.has_permission(self.operator, "cron_add") is True

    def test_operator_cannot_manage_users(self):
        assert self.mgr.has_permission(self.operator, "_user_management") is False
        assert self.mgr.has_permission(self.operator, "_config_update") is False

    # Viewer can only use read-only tools
    def test_viewer_can_read(self):
        assert self.mgr.has_permission(self.viewer, "system_info") is True
        assert self.mgr.has_permission(self.viewer, "system_disk") is True
        assert self.mgr.has_permission(self.viewer, "docker_ps") is True
        assert self.mgr.has_permission(self.viewer, "docker_logs") is True
        assert self.mgr.has_permission(self.viewer, "files_read") is True
        assert self.mgr.has_permission(self.viewer, "files_list") is True
        assert self.mgr.has_permission(self.viewer, "server_health") is True

    def test_viewer_cannot_write(self):
        assert self.mgr.has_permission(self.viewer, "bash_exec") is False
        assert self.mgr.has_permission(self.viewer, "files_write") is False
        assert self.mgr.has_permission(self.viewer, "docker_exec") is False
        assert self.mgr.has_permission(self.viewer, "cron_add") is False

    def test_viewer_cannot_manage(self):
        assert self.mgr.has_permission(self.viewer, "_user_management") is False
        assert self.mgr.has_permission(self.viewer, "_config_update") is False

    def test_viewer_tools_list_complete(self):
        """All viewer tools should be in the VIEWER_TOOLS set."""
        expected = {
            "system_info", "system_disk", "system_network", "system_processes",
            "docker_ps", "docker_stats", "docker_logs", "docker_images",
            "files_read", "files_list", "files_info",
            "cron_list",
            "zima_apps_list", "zima_storage_info", "zima_shares", "zima_update_check",
            "zima_changelog", "backup_list",
            "net_ping", "net_dns", "net_traceroute", "net_port_check",
            "server_health",
        }
        assert VIEWER_TOOLS == expected


class TestAuditWithUser:
    """Tests for audit logging with user context."""

    def test_audit_log_includes_user(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            from security import AuditLogger
            log_path = os.path.join(tmpdir, "audit.log")
            audit = AuditLogger(log_path)
            audit.log("bash_exec", {"command": "ls"}, True, user="Alice")

            for handler in audit._logger.handlers:
                handler.flush()

            with open(log_path) as f:
                content = f.read()
            assert "Alice" in content
            assert "bash_exec" in content

    def test_audit_log_without_user(self):
        """Backwards compatible: no user field still works."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from security import AuditLogger
            log_path = os.path.join(tmpdir, "audit.log")
            audit = AuditLogger(log_path)
            audit.log("bash_exec", {"command": "ls"}, True)

            for handler in audit._logger.handlers:
                handler.flush()

            with open(log_path) as f:
                content = f.read()
            assert "bash_exec" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
