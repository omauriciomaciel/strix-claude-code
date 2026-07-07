"""Pluggable agent CLI backends (Claude Code, opencode).

Each backend knows how to check availability, set up auth/trust, and build
the subprocess argv/env to drive a non-interactive agent run against the
shared MCP config produced by ``create_mcp_config``.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Protocol


class AgentBackend(Protocol):
    name: str

    def check_available(self) -> bool: ...

    def write_trust_config(self, project_cwd: str) -> None: ...

    def build_command(
        self,
        mcp_config: dict[str, Any],
        system_prompt: str,
        cwd: str,
    ) -> tuple[list[str], dict[str, str]]:
        """Returns (argv_base, extra_env). argv_base excludes the prompt itself."""
        ...

    def prompt_args(self, initial_prompt: str, print_mode: bool) -> list[str]: ...


class ClaudeBackend:
    name = "claude"

    def check_available(self) -> bool:
        return shutil.which("claude") is not None

    def write_trust_config(self, project_cwd: str) -> None:
        _bypass_permissions = {
            "defaultMode": "bypassPermissions",
            "allow": [
                "Bash", "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep",
                "WebFetch", "WebSearch", "Task", "TodoWrite", "mcp__strix-pentest__*",
            ],
            "deny": [],
        }

        home_claude_json = Path.home() / ".claude.json"
        try:
            claude_data = json.loads(home_claude_json.read_text()) if home_claude_json.exists() else {}
        except Exception:
            claude_data = {}
        claude_data.update({
            "bypassPermissionsModeAccepted": True,
            "hasCompletedOnboarding": True,
            "skipDangerousModePermissionPrompt": True,
            "model": "opusplan",
            "permissions": _bypass_permissions,
        })
        projects = claude_data.get("projects", {})
        projects[project_cwd] = {"hasTrustDialogAccepted": True, **projects.get(project_cwd, {})}
        claude_data["projects"] = projects
        home_claude_json.write_text(json.dumps(claude_data))

        home_settings = Path.home() / ".claude" / "settings.json"
        try:
            settings_data = json.loads(home_settings.read_text()) if home_settings.exists() else {}
        except Exception:
            settings_data = {}
        settings_data.update({
            "skipDangerousModePermissionPrompt": True,
            "model": "opusplan",
            "permissions": _bypass_permissions,
        })
        home_settings.parent.mkdir(parents=True, exist_ok=True)
        home_settings.write_text(json.dumps(settings_data))

    def build_command(self, mcp_config, system_prompt, cwd):
        mcp_path = Path(cwd) / "mcp-config.json"
        mcp_path.write_text(json.dumps(mcp_config))
        argv = [
            "claude",
            "--mcp-config", str(mcp_path),
            "--permission-mode", "bypassPermissions",
            "--dangerously-skip-permissions",
            "--append-system-prompt", system_prompt,
        ]
        return argv, {}

    def prompt_args(self, initial_prompt, print_mode):
        return ["--print", initial_prompt] if print_mode else [initial_prompt]


class OpencodeBackend:
    name = "opencode"

    def check_available(self) -> bool:
        return shutil.which("opencode") is not None

    def write_trust_config(self, project_cwd: str) -> None:
        auth_json = Path.home() / ".local" / "share" / "opencode" / "auth.json"
        if not auth_json.exists() and not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError(
                "opencode has no provider configured — run `opencode auth login` "
                "or set ANTHROPIC_API_KEY first"
            )

    def build_command(self, mcp_config, system_prompt, cwd):
        oc_mcp = {
            name: {
                "type": "local",
                "command": [srv["command"], *srv.get("args", [])],
                "environment": srv.get("env", {}),
                "enabled": True,
            }
            for name, srv in mcp_config["mcpServers"].items()
        }

        prompt_path = Path(cwd) / "strix-system-prompt.txt"
        prompt_path.write_text(system_prompt)

        oc_config = {
            "$schema": "https://opencode.ai/config.json",
            "mcp": oc_mcp,
            "agent": {"strix": {"prompt": "{file:./strix-system-prompt.txt}"}},
        }
        cfg_path = Path(cwd) / "opencode.jsonc"
        cfg_path.write_text(json.dumps(oc_config))

        argv = ["opencode", "run", "--agent", "strix", "--dangerously-skip-permissions"]
        return argv, {"OPENCODE_CONFIG": str(cfg_path)}

    def prompt_args(self, initial_prompt, print_mode):
        return ["--format", "json", initial_prompt]


BACKENDS: dict[str, AgentBackend] = {
    "claude": ClaudeBackend(),
    "opencode": OpencodeBackend(),
}
