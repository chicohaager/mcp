"""Skill manager for ZimaOS MCP Server.

Handles dynamic loading, installation, and management of MCP tool skills.
Supports two skill formats:
  1. SKILL.md (Anthropic format) - Markdown instructions with YAML frontmatter
  2. Python modules - .py files with MCP tool functions

Skills are stored in /DATA/AppData/zimaos-mcp/skills/.
"""

import importlib.util
import inspect
import json
import logging
import os
import re
import shutil
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("zimaos-mcp.skills")

SKILLS_DIR = "/DATA/AppData/zimaos-mcp/skills"
SKILLS_DB = "/DATA/AppData/zimaos-mcp/skills.json"

# Known marketplace registries
DEFAULT_REGISTRIES = [
    {
        "name": "Anthropic Official",
        "owner": "anthropics",
        "repo": "skills",
        "branch": "main",
        "marketplace_path": ".claude-plugin/marketplace.json",
    },
]

GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"


@dataclass
class SkillInfo:
    """Metadata for an installed skill."""

    name: str
    description: str = ""
    source: str = ""  # git URL, "marketplace:owner/repo", or "local"
    active: bool = True
    installed_at: str = ""
    tools: list[str] = field(default_factory=list)
    file_path: str = ""
    skill_type: str = "python"  # "python" or "skillmd"
    content: str = ""  # For SKILL.md skills: the markdown content

    def to_dict(self, truncate_content: bool = True) -> dict:
        content = self.content
        if truncate_content and content:
            content = content[:500]
        return {
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "active": self.active,
            "installed_at": self.installed_at,
            "tools": self.tools,
            "file_path": self.file_path,
            "skill_type": self.skill_type,
            "content": content or "",
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SkillInfo":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class SkillManager:
    """Manages MCP tool skills: install, uninstall, enable, disable."""

    def __init__(self, skills_dir: str = SKILLS_DIR, db_path: str = SKILLS_DB):
        self.skills_dir = skills_dir
        self.db_path = db_path
        self._skills: dict[str, SkillInfo] = {}
        self._loaded_tools: dict[str, list[str]] = {}  # skill_name -> [tool_names]
        os.makedirs(skills_dir, exist_ok=True)
        self._load_db()

    def _load_db(self) -> None:
        """Load skills metadata from JSON database."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path) as f:
                    data = json.load(f)
                for item in data:
                    skill = SkillInfo.from_dict(item)
                    self._skills[skill.name] = skill
            except (json.JSONDecodeError, OSError) as e:
                logger.error("Failed to load skills database: %s", e)

    def _save_db(self) -> None:
        """Persist skills metadata to JSON database."""
        data = [s.to_dict(truncate_content=False) for s in self._skills.values()]
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with open(self.db_path, "w") as f:
            json.dump(data, f, indent=2)

    def list_skills(self) -> list[dict]:
        """List all installed skills."""
        return [s.to_dict() for s in self._skills.values()]

    def get_skill(self, name: str) -> dict | None:
        """Get skill info by name."""
        skill = self._skills.get(name)
        return skill.to_dict() if skill else None

    def load_all_skills(self, mcp: Any) -> int:
        """Load all active skills and register their tools with FastMCP.

        Args:
            mcp: FastMCP server instance.

        Returns:
            Number of tools registered.
        """
        total = 0
        for skill in self._skills.values():
            if skill.active:
                count = self._load_skill_module(skill, mcp)
                total += count
                logger.info("Loaded skill '%s' with %d tools", skill.name, count)
        return total

    def _load_skill_module(self, skill: SkillInfo, mcp: Any) -> int:
        """Load a single skill Python file and register its tools.

        Args:
            skill: Skill metadata.
            mcp: FastMCP server instance.

        Returns:
            Number of tools registered.
        """
        file_path = skill.file_path or os.path.join(self.skills_dir, skill.name, "skill.py")
        if not os.path.exists(file_path):
            logger.warning("Skill file not found: %s", file_path)
            return 0

        try:
            spec = importlib.util.spec_from_file_location(
                f"skill_{skill.name}", file_path
            )
            if spec is None or spec.loader is None:
                return 0

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            registered = []
            for name, obj in inspect.getmembers(module, inspect.isfunction):
                # Look for functions decorated with metadata or matching pattern
                if hasattr(obj, "_mcp_tool") or name.startswith("tool_"):
                    mcp.add_tool(obj)
                    registered.append(name)

            skill.tools = registered
            self._loaded_tools[skill.name] = registered
            self._save_db()
            return len(registered)
        except Exception as e:
            logger.error("Failed to load skill '%s': %s", skill.name, e)
            return 0

    # Trusted Git sources (skills from these are marked as verified)
    TRUSTED_SOURCES = [
        "github.com/anthropics/",
        "github.com/IceWhaleTech/",
    ]

    def _is_trusted_source(self, url: str) -> bool:
        """Check if a git URL is from a trusted source."""
        return any(trusted in url for trusted in self.TRUSTED_SOURCES)

    def install_from_git(self, git_url: str, skill_name: str | None = None) -> dict:
        """Install a skill from a Git repository.

        Args:
            git_url: Git repository URL.
            skill_name: Optional name override (defaults to repo name).

        Returns:
            Result dict with success status.
        """
        if skill_name is None:
            # Extract name from URL: https://github.com/user/repo -> repo
            skill_name = git_url.rstrip("/").split("/")[-1].replace(".git", "")

        if skill_name in self._skills:
            return {"success": False, "error": f"Skill '{skill_name}' already installed"}

        trusted = self._is_trusted_source(git_url)

        target_dir = os.path.join(self.skills_dir, skill_name)

        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", git_url, target_dir],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                return {"success": False, "error": f"Git clone failed: {result.stderr}"}

            # Find skill files
            skill_file = self._find_skill_file(target_dir)
            if not skill_file:
                shutil.rmtree(target_dir, ignore_errors=True)
                return {
                    "success": False,
                    "error": "No skill.py or tool_*.py files found in repository",
                }

            # Read description from SKILL.md or README.md
            description = self._read_skill_description(target_dir)

            skill = SkillInfo(
                name=skill_name,
                description=description,
                source=git_url,
                active=True,
                installed_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                file_path=skill_file,
            )
            self._skills[skill_name] = skill
            self._save_db()

            result = {"success": True, "skill": skill.to_dict(), "trusted": trusted}
            if not trusted:
                result["warning"] = (
                    f"Skill installed from untrusted source: {git_url}. "
                    "Review the code before enabling. Python skills execute arbitrary code."
                )
            return result
        except subprocess.TimeoutExpired:
            shutil.rmtree(target_dir, ignore_errors=True)
            return {"success": False, "error": "Git clone timed out"}
        except Exception as e:
            shutil.rmtree(target_dir, ignore_errors=True)
            return {"success": False, "error": str(e)}

    def install_from_file(self, filename: str, content: bytes) -> dict:
        """Install a skill from an uploaded Python file.

        Args:
            filename: Original filename.
            content: File content bytes.

        Returns:
            Result dict.
        """
        skill_name = Path(filename).stem

        if skill_name in self._skills:
            return {"success": False, "error": f"Skill '{skill_name}' already installed"}

        skill_dir = os.path.join(self.skills_dir, skill_name)
        os.makedirs(skill_dir, exist_ok=True)

        file_path = os.path.join(skill_dir, "skill.py")
        try:
            with open(file_path, "wb") as f:
                f.write(content)

            skill = SkillInfo(
                name=skill_name,
                description=f"Uploaded skill: {filename}",
                source="local",
                active=True,
                installed_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                file_path=file_path,
            )
            self._skills[skill_name] = skill
            self._save_db()
            return {
                "success": True,
                "skill": skill.to_dict(),
                "trusted": False,
                "warning": "Uploaded skill executes as server code. Review before use.",
            }
        except Exception as e:
            shutil.rmtree(skill_dir, ignore_errors=True)
            return {"success": False, "error": str(e)}

    def uninstall(self, skill_name: str) -> dict:
        """Uninstall a skill.

        Args:
            skill_name: Name of skill to remove.

        Returns:
            Result dict.
        """
        if skill_name not in self._skills:
            return {"success": False, "error": f"Skill '{skill_name}' not found"}

        skill_dir = os.path.join(self.skills_dir, skill_name)
        if os.path.exists(skill_dir):
            shutil.rmtree(skill_dir)

        del self._skills[skill_name]
        self._loaded_tools.pop(skill_name, None)
        self._save_db()
        return {"success": True, "uninstalled": skill_name}

    def toggle(self, skill_name: str, active: bool, mcp: Any = None) -> dict:
        """Enable or disable a skill with optional hot-reload.

        Args:
            skill_name: Skill to toggle.
            active: True to enable, False to disable.
            mcp: FastMCP server instance for hot-reload (optional).

        Returns:
            Result dict.
        """
        if skill_name not in self._skills:
            return {"success": False, "error": f"Skill '{skill_name}' not found"}

        self._skills[skill_name].active = active
        self._save_db()

        hot_reloaded = False
        if mcp and active:
            # Hot-load: register tools immediately
            count = self._load_skill_module(self._skills[skill_name], mcp)
            if count > 0:
                hot_reloaded = True
        elif mcp and not active:
            # Unregister tools
            tool_names = self._loaded_tools.get(skill_name, [])
            if hasattr(mcp, "_tool_manager") and tool_names:
                for tname in tool_names:
                    mcp._tool_manager._tools.pop(tname, None)
                self._loaded_tools.pop(skill_name, None)
                hot_reloaded = True

        return {
            "success": True,
            "skill": skill_name,
            "active": active,
            "hot_reloaded": hot_reloaded,
            "note": "" if hot_reloaded else "Restart server to fully apply changes",
        }

    def _find_skill_file(self, directory: str) -> str | None:
        """Find the main skill Python file in a directory."""
        # Priority: skill.py > tools.py > first tool_*.py > first .py
        for name in ["skill.py", "tools.py"]:
            path = os.path.join(directory, name)
            if os.path.exists(path):
                return path

        for path in Path(directory).glob("tool_*.py"):
            return str(path)

        for path in Path(directory).glob("*.py"):
            if path.name != "__init__.py" and path.name != "setup.py":
                return str(path)

        return None

    def _read_skill_description(self, directory: str) -> str:
        """Read skill description from SKILL.md or README.md."""
        for name in ["SKILL.md", "README.md"]:
            path = os.path.join(directory, name)
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        content = f.read(500)
                    return _parse_skillmd_description(content)
                except OSError:
                    pass
        return ""

    # ── Marketplace ──────────────────────────────────────────────────────

    def fetch_marketplace(self, registry: dict | None = None) -> dict:
        """Fetch available skills from a marketplace registry.

        Args:
            registry: Registry dict with owner, repo, branch, marketplace_path.
                      Defaults to Anthropic official.

        Returns:
            Dict with plugins and skill listings.
        """
        reg = registry or DEFAULT_REGISTRIES[0]
        url = (
            f"{GITHUB_RAW}/{reg['owner']}/{reg['repo']}"
            f"/{reg['branch']}/{reg['marketplace_path']}"
        )

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "zimaos-mcp/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                marketplace = json.loads(resp.read().decode())
        except Exception as e:
            return {"success": False, "error": f"Failed to fetch marketplace: {e}"}

        # Enrich with individual skill info
        skills_list = []
        for plugin in marketplace.get("plugins", []):
            for skill_path in plugin.get("skills", []):
                # skill_path is like "./skills/frontend-design"
                skill_name = skill_path.rstrip("/").split("/")[-1]
                installed = skill_name in self._skills
                skills_list.append({
                    "name": skill_name,
                    "plugin": plugin.get("name", ""),
                    "plugin_description": plugin.get("description", ""),
                    "path": skill_path,
                    "installed": installed,
                    "registry": f"{reg['owner']}/{reg['repo']}",
                })

        return {
            "success": True,
            "registry": f"{reg['owner']}/{reg['repo']}",
            "metadata": marketplace.get("metadata", {}),
            "skills": skills_list,
            "count": len(skills_list),
        }

    def install_from_marketplace(
        self, skill_name: str, registry: dict | None = None
    ) -> dict:
        """Install a single skill from a marketplace registry via GitHub API.

        Downloads only the specific skill directory (SKILL.md + any files),
        not the entire repository.

        Args:
            skill_name: Name of the skill (e.g. "frontend-design").
            registry: Registry dict. Defaults to Anthropic official.

        Returns:
            Result dict.
        """
        if skill_name in self._skills:
            return {"success": False, "error": f"Skill '{skill_name}' already installed"}

        reg = registry or DEFAULT_REGISTRIES[0]
        skill_dir = os.path.join(self.skills_dir, skill_name)
        os.makedirs(skill_dir, exist_ok=True)

        try:
            # List files in the skill directory via GitHub API
            api_url = (
                f"{GITHUB_API}/repos/{reg['owner']}/{reg['repo']}"
                f"/contents/skills/{skill_name}?ref={reg['branch']}"
            )
            req = urllib.request.Request(
                api_url, headers={"User-Agent": "zimaos-mcp/1.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                files = json.loads(resp.read().decode())

            if not isinstance(files, list):
                shutil.rmtree(skill_dir, ignore_errors=True)
                return {"success": False, "error": f"Skill '{skill_name}' not found in registry"}

            # Download each file
            skill_content = ""
            description = ""
            downloaded = []

            for file_info in files:
                if file_info["type"] != "file":
                    continue
                fname = file_info["name"]
                download_url = file_info.get("download_url")
                if not download_url:
                    continue

                file_req = urllib.request.Request(
                    download_url, headers={"User-Agent": "zimaos-mcp/1.0"}
                )
                with urllib.request.urlopen(file_req, timeout=15) as file_resp:
                    content = file_resp.read()

                local_path = os.path.join(skill_dir, fname)
                with open(local_path, "wb") as f:
                    f.write(content)
                downloaded.append(fname)

                # Parse SKILL.md
                if fname == "SKILL.md":
                    skill_content = content.decode("utf-8", errors="replace")
                    description = _parse_skillmd_description(skill_content)

            if not downloaded:
                shutil.rmtree(skill_dir, ignore_errors=True)
                return {"success": False, "error": "No files found for this skill"}

            # Determine skill type
            has_skillmd = "SKILL.md" in downloaded
            has_python = any(f.endswith(".py") for f in downloaded)
            skill_type = "python" if has_python else "skillmd"

            # Find main file
            file_path = ""
            if has_skillmd:
                file_path = os.path.join(skill_dir, "SKILL.md")
            if has_python:
                file_path = self._find_skill_file(skill_dir) or file_path

            skill = SkillInfo(
                name=skill_name,
                description=description or f"Skill from {reg['owner']}/{reg['repo']}",
                source=f"marketplace:{reg['owner']}/{reg['repo']}",
                active=True,
                installed_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                file_path=file_path,
                skill_type=skill_type,
                content=skill_content,
            )
            self._skills[skill_name] = skill
            self._save_db()

            return {
                "success": True,
                "skill": skill.to_dict(),
                "files": downloaded,
            }
        except Exception as e:
            shutil.rmtree(skill_dir, ignore_errors=True)
            return {"success": False, "error": str(e)}

    def get_skill_content(self, skill_name: str) -> dict:
        """Get the full SKILL.md content for a skill.

        Args:
            skill_name: Name of the skill.

        Returns:
            Dict with content or error.
        """
        if skill_name not in self._skills:
            return {"success": False, "error": f"Skill '{skill_name}' not found"}

        skill = self._skills[skill_name]
        skill_dir = os.path.join(self.skills_dir, skill_name)

        # Try to read SKILL.md
        skillmd_path = os.path.join(skill_dir, "SKILL.md")
        if os.path.exists(skillmd_path):
            try:
                with open(skillmd_path) as f:
                    content = f.read()
                return {"success": True, "content": content, "type": "skillmd"}
            except OSError as e:
                return {"success": False, "error": str(e)}

        # Try Python skill file
        if skill.file_path and os.path.exists(skill.file_path):
            try:
                with open(skill.file_path) as f:
                    content = f.read()
                return {"success": True, "content": content, "type": "python"}
            except OSError as e:
                return {"success": False, "error": str(e)}

        return {"success": False, "error": "No content file found"}


def _parse_skillmd_description(content: str) -> str:
    """Extract description from SKILL.md content (YAML frontmatter or first paragraph)."""
    lines = content.strip().splitlines()

    # Check for YAML frontmatter
    if lines and lines[0].strip() == "---":
        in_frontmatter = True
        for line in lines[1:]:
            if line.strip() == "---":
                break
            if line.strip().startswith("description:"):
                desc = line.split(":", 1)[1].strip().strip('"').strip("'")
                return desc[:200]

    # Fallback: first non-header, non-empty line
    for line in lines:
        line = line.strip()
        if line and not line.startswith(("#", "---", ">", "<!--")):
            return line[:200]
    return ""
