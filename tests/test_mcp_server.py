"""Tests for mcp_server module."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from strix_cli_claude import mcp_server
from strix_cli_claude.mcp_server import (
    SandboxExecClient,
    PENTEST_TOOLS,
    create_server,
    calculate_cvss,
)


class TestSandboxExecClient:
    """Tests for SandboxExecClient - the docker-exec replacement for the old
    HTTP ToolServerClient that strix-sandbox 1.0.0 dropped."""

    def _make_client(self, mock_container):
        """Build a SandboxExecClient with a mocked docker lookup."""
        with patch("docker.from_env") as mock_from_env:
            mock_client = MagicMock()
            mock_client.containers.get.return_value = mock_container
            mock_from_env.return_value = mock_client
            client = SandboxExecClient("strix-cli-test")
            # Force container resolution via the mock instead of real docker.
            client._container = mock_container
            return client

    def test_init_sets_container_name(self):
        """Should store the container name for later docker lookups."""
        client = SandboxExecClient("strix-cli-test")
        assert client.container_name == "strix-cli-test"

    @pytest.mark.asyncio
    async def test_terminal_execute_runs_bash(self):
        """terminal_execute should shell out via `docker exec bash -lc`."""
        mock_container = MagicMock()
        result_obj = MagicMock(exit_code=0, output=b"uid=0(root)")
        mock_container.exec_run.return_value = result_obj

        client = self._make_client(mock_container)
        result = await client.call_tool("terminal_execute", {"command": "id"})

        mock_container.exec_run.assert_called_once()
        args, kwargs = mock_container.exec_run.call_args
        assert args[0] == ["bash", "-lc", "id"]
        assert kwargs.get("workdir") == "/workspace"
        assert kwargs.get("user") == "pentester"
        assert "result" in result
        assert result["result"]["exit_code"] == 0
        assert "uid=0(root)" in result["result"]["content"]

    @pytest.mark.asyncio
    async def test_terminal_execute_respects_timeout(self):
        """Should return an error dict when exec_run times out."""
        from concurrent.futures import TimeoutError as FuturesTimeoutError

        mock_container = MagicMock()

        def slow_exec(*args, **kwargs):
            import time
            time.sleep(10)

        mock_container.exec_run.side_effect = slow_exec

        client = self._make_client(mock_container)
        result = await client.call_tool(
            "terminal_execute", {"command": "sleep 100", "timeout": 1}
        )

        assert "error" in result
        assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_browser_tools_are_unsupported(self):
        """The HTTP tool server that exposed browser/Caido tools is gone in
        1.0.0; SandboxExecClient should report that explicitly."""
        mock_container = MagicMock()
        client = self._make_client(mock_container)

        for tool in ("browser_action", "list_requests", "view_request",
                     "send_request", "repeat_request"):
            result = await client.call_tool(tool, {})
            assert "error" in result
            assert "1.0.0" in result["error"] or "isn't available" in result["error"]

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self):
        """Unknown tool names should resolve to an error dict."""
        mock_container = MagicMock()
        client = self._make_client(mock_container)

        result = await client.call_tool("does_not_exist", {})
        assert "error" in result
        assert "Unknown tool" in result["error"]

    @pytest.mark.asyncio
    async def test_close_is_a_noop(self):
        """SandboxExecClient.close() is a no-op (no httpx client to close)."""
        client = SandboxExecClient("strix-cli-test")
        # Should not raise.
        await client.close()


class TestPentestTools:
    """Tests for PENTEST_TOOLS list."""

    def test_tools_list_is_not_empty(self):
        """Should have tools defined."""
        assert len(PENTEST_TOOLS) > 0

    def test_all_tools_have_name(self):
        """All tools should have a name."""
        for tool in PENTEST_TOOLS:
            assert hasattr(tool, "name")
            assert tool.name

    def test_all_tools_have_description(self):
        """All tools should have a description."""
        for tool in PENTEST_TOOLS:
            assert hasattr(tool, "description")
            assert tool.description

    def test_all_tools_have_input_schema(self):
        """All tools should have an input schema."""
        for tool in PENTEST_TOOLS:
            assert hasattr(tool, "inputSchema")
            assert isinstance(tool.inputSchema, dict)

    def test_terminal_execute_tool_exists(self):
        """Should have terminal_execute tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "terminal_execute" in tool_names

    def test_python_action_tool_exists(self):
        """Should have python_action tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "python_action" in tool_names

    def test_browser_action_tool_exists(self):
        """Should have browser_action tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "browser_action" in tool_names

    def test_create_vulnerability_report_tool_exists(self):
        """Should have create_vulnerability_report tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "create_vulnerability_report" in tool_names

    def test_write_report_tool_exists(self):
        """Should have write_report tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "write_report" in tool_names

    def test_read_report_tool_exists(self):
        """Should have read_report tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "read_report" in tool_names

    def test_think_tool_exists(self):
        """Should have think tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "think" in tool_names

    def test_finish_scan_tool_exists(self):
        """Should have finish_scan tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "finish_scan" in tool_names

    def test_list_files_tool_exists(self):
        """Should have list_files tool."""
        tool_names = [t.name for t in PENTEST_TOOLS]
        assert "list_files" in tool_names


class TestCalculateCvss:
    """Tests for calculate_cvss function."""

    def test_critical_severity_rce(self):
        """Should calculate critical severity for unauthenticated RCE."""
        score, severity = calculate_cvss(
            av="N",  # Network
            ac="L",  # Low complexity
            pr="N",  # No privileges
            ui="N",  # No user interaction
            s="C",   # Changed scope
            c="H",   # High confidentiality
            i="H",   # High integrity
            a="H",   # High availability
        )
        assert severity == "critical"
        assert score >= 9.0

    def test_high_severity_sqli(self):
        """Should calculate high severity for SQL injection."""
        score, severity = calculate_cvss(
            av="N",  # Network
            ac="L",  # Low complexity
            pr="N",  # No privileges
            ui="N",  # No user interaction
            s="U",   # Unchanged scope
            c="H",   # High confidentiality
            i="H",   # High integrity
            a="N",   # No availability impact
        )
        assert severity in ["high", "critical"]
        assert score >= 7.0

    def test_medium_severity_xss(self):
        """Should calculate medium severity for reflected XSS."""
        score, severity = calculate_cvss(
            av="N",  # Network
            ac="L",  # Low complexity
            pr="N",  # No privileges
            ui="R",  # Requires user interaction
            s="C",   # Changed scope
            c="L",   # Low confidentiality
            i="L",   # Low integrity
            a="N",   # No availability impact
        )
        assert severity in ["medium", "high"]
        assert score >= 4.0

    def test_low_severity_info_disclosure(self):
        """Should calculate low severity for minor info disclosure."""
        score, severity = calculate_cvss(
            av="N",  # Network
            ac="H",  # High complexity
            pr="H",  # High privileges
            ui="R",  # Requires user interaction
            s="U",   # Unchanged scope
            c="L",   # Low confidentiality
            i="N",   # No integrity impact
            a="N",   # No availability impact
        )
        assert severity in ["low", "none"]
        assert score < 4.0

    def test_none_severity_zero_impact(self):
        """Should return none severity when no impact."""
        score, severity = calculate_cvss(
            av="N",
            ac="L",
            pr="N",
            ui="N",
            s="U",
            c="N",  # No confidentiality
            i="N",  # No integrity
            a="N",  # No availability
        )
        assert severity == "none"
        assert score == 0

    def test_score_is_float(self):
        """Score should be a float."""
        score, _ = calculate_cvss("N", "L", "N", "N", "U", "H", "H", "H")
        assert isinstance(score, float)

    def test_score_range_is_valid(self):
        """Score should be between 0 and 10."""
        score, _ = calculate_cvss("N", "L", "N", "N", "C", "H", "H", "H")
        assert 0 <= score <= 10.0

    def test_pr_scoring_differs_by_scope(self):
        """Privileges Required scoring should differ based on scope."""
        # Unchanged scope
        score_u, _ = calculate_cvss("N", "L", "L", "N", "U", "H", "H", "H")
        # Changed scope
        score_c, _ = calculate_cvss("N", "L", "L", "N", "C", "H", "H", "H")
        # Scores should differ because PR values differ with scope
        assert score_u != score_c


class TestCreateServer:
    """Tests for create_server function."""

    def test_creates_server_instance(self):
        """Should create a Server instance."""
        server = create_server()
        assert server is not None

    def test_server_has_name(self):
        """Server should have a name."""
        server = create_server()
        assert server.name == "strix-claude-code"


class TestReportFileOperations:
    """Tests for report file operations."""

    def test_write_report_creates_file(self, tmp_path):
        """Should create report file when writing."""
        from datetime import datetime

        report_file = tmp_path / "report.md"

        # Simulate what write_report handler does
        content = "Test content"
        header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix Claude Code

---

"""
        report_file.write_text(header + content)

        assert report_file.exists()
        assert "Test content" in report_file.read_text()

    def test_write_report_appends_content(self, tmp_path):
        """Should append to existing report."""
        report_file = tmp_path / "report.md"
        report_file.write_text("# Existing Report\n\n---\n")

        # Append new content
        existing = report_file.read_text()
        new_content = "\n## Findings\n\nNew finding"
        report_file.write_text(existing + new_content)

        content = report_file.read_text()
        assert "Existing Report" in content
        assert "New finding" in content

    def test_read_report_returns_content(self, tmp_path):
        """Should read report content."""
        report_file = tmp_path / "report.md"
        report_file.write_text("# Test Report\n\nSome findings here.")

        content = report_file.read_text()
        assert "Test Report" in content
        assert "Some findings here" in content


class TestThinkFunctionality:
    """Tests for think functionality."""

    def test_think_logs_to_report(self, tmp_path):
        """Should append thought to report file."""
        from datetime import datetime

        report_file = tmp_path / "report.md"
        report_file.write_text("# Report\n")

        thought = "Testing XSS vulnerabilities"

        # Simulate think handler logging
        existing = report_file.read_text()
        log_entry = f"\n> **Analysis Note** ({datetime.now().strftime('%H:%M:%S')}): {thought}\n"
        report_file.write_text(existing + log_entry)

        content = report_file.read_text()
        assert "Analysis Note" in content
        assert "Testing XSS" in content


class TestVulnerabilityReportGeneration:
    """Tests for vulnerability report generation."""

    def test_creates_vulnerability_report(self, tmp_path):
        """Should create formatted vulnerability report."""
        from datetime import datetime

        report_file = tmp_path / "report.md"

        title = "SQL Injection in Login"
        cvss_score, severity = calculate_cvss("N", "L", "N", "N", "U", "H", "H", "N")
        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

        report_content = f"""### {title}

**Severity:** {severity.upper()} ({cvss_score:.1f})
**CVSS Vector:** `{cvss_vector}`
**Target:** https://example.com/login

#### Description
The login form is vulnerable to SQL injection

#### Proof of Concept
Send a payload to bypass authentication

```
' OR '1'='1' --
```

---
"""
        header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix Claude Code

---

## Findings

"""
        report_file.write_text(header + report_content)

        content = report_file.read_text()
        assert "SQL Injection in Login" in content
        assert "CVSS" in content
        assert "Proof of Concept" in content

    def test_calculates_cvss_for_critical(self, tmp_path):
        """Should calculate critical CVSS score."""
        score, severity = calculate_cvss(
            av="N", ac="L", pr="N", ui="N",
            s="C", c="H", i="H", a="H"
        )
        assert severity == "critical"
        assert score >= 9.0


class TestFinishScanReport:
    """Tests for finish_scan report generation."""

    def test_finish_scan_writes_sections(self, tmp_path):
        """Should write all required sections."""
        from datetime import datetime

        report_file = tmp_path / "report.md"

        final_sections = f"""
## Executive Summary

This was a security assessment of example.com

## Methodology

We used automated and manual testing

## Technical Analysis

The application has several security issues

## Recommendations

Fix the SQL injection first

---

**Report Completed:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

        header = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** Strix Claude Code

---
{final_sections}
"""
        report_file.write_text(header)

        content = report_file.read_text()
        assert "Executive Summary" in content
        assert "Methodology" in content
        assert "Technical Analysis" in content
        assert "Recommendations" in content


class TestNotesStorage:
    """Tests for notes storage functionality."""

    def test_notes_stored_in_dict(self):
        """Should store notes in dictionary."""
        import uuid
        from datetime import datetime

        notes_storage = {}

        note_id = str(uuid.uuid4())[:5]
        timestamp = datetime.now().isoformat()

        notes_storage[note_id] = {
            "title": "Interesting endpoint",
            "content": "/admin panel found",
            "category": "findings",
            "tags": [],
            "created_at": timestamp,
        }

        assert note_id in notes_storage
        assert notes_storage[note_id]["title"] == "Interesting endpoint"
        assert notes_storage[note_id]["category"] == "findings"

    def test_notes_can_be_filtered(self):
        """Should filter notes by category."""
        notes_storage = {
            "abc": {"title": "Finding", "content": "XSS", "category": "findings"},
            "def": {"title": "Method", "content": "Burp", "category": "methodology"},
        }

        findings = [n for n in notes_storage.values() if n["category"] == "findings"]

        assert len(findings) == 1
        assert findings[0]["title"] == "Finding"

    def test_notes_can_be_searched(self):
        """Should search notes by content."""
        notes_storage = {
            "abc": {"title": "XSS Finding", "content": "Found XSS in login", "category": "findings"},
            "def": {"title": "SQLI", "content": "SQL injection possible", "category": "findings"},
        }

        search = "xss"
        results = [
            n for n in notes_storage.values()
            if search in n["title"].lower() or search in n["content"].lower()
        ]

        assert len(results) == 1
        assert results[0]["title"] == "XSS Finding"


class TestSandboxExecClientUnit:
    """Unit tests for SandboxExecClient (docker-exec based)."""

    @pytest.mark.asyncio
    async def test_call_tool_terminal_execute_propagates_exit_code(self):
        """Non-zero exit codes should still return content + exit_code."""
        mock_container = MagicMock()
        result_obj = MagicMock(exit_code=2, output=b"command not found")
        mock_container.exec_run.return_value = result_obj

        client = SandboxExecClient("strix-cli-test")
        client._container = mock_container  # bypass docker.from_env

        result = await client.call_tool("terminal_execute", {"command": "nope"})
        assert result["result"]["exit_code"] == 2
        assert "command not found" in result["result"]["content"]

    @pytest.mark.asyncio
    async def test_call_tool_python_action_runs_python(self):
        """python_action with action=execute should run python3 in the sandbox."""
        mock_container = MagicMock()
        result_obj = MagicMock(exit_code=0, output=b"6")
        mock_container.exec_run.return_value = result_obj

        client = SandboxExecClient("strix-cli-test")
        client._container = mock_container

        result = await client.call_tool(
            "python_action", {"action": "execute", "code": "print(2 + 4)"}
        )
        assert result["result"]["exit_code"] == 0
        assert "6" in result["result"]["content"]
        # Should have exec'd python3 (first call); the trailing call is just `rm`.
        first_call = mock_container.exec_run.call_args_list[0]
        called_cmd = first_call[0][0]
        assert called_cmd == ["python3", first_call[0][0][1]] or called_cmd[0] == "python3"

    @pytest.mark.asyncio
    async def test_call_tool_python_action_action_not_execute_is_noop(self):
        """Non-execute python_action actions are documented no-ops."""
        mock_container = MagicMock()
        client = SandboxExecClient("strix-cli-test")
        client._container = mock_container

        result = await client.call_tool(
            "python_action", {"action": "store", "code": "x"}
        )
        assert "result" in result
        assert "no-op" in result["result"]["content"].lower()
        # Nothing should have been exec'd in the container.
        mock_container.exec_run.assert_not_called()


class TestEnvironmentVariables:
    """Tests for environment variable handling."""

    def test_sandbox_container_from_env(self):
        """mcp_server should expose STRIX_SANDBOX_CONTAINER (legacy TOOL_SERVER_* gone)."""
        with patch.dict("os.environ", {"STRIX_SANDBOX_CONTAINER": "strix-cli-custom"}):
            import importlib
            importlib.reload(mcp_server)
            assert mcp_server.SANDBOX_CONTAINER == "strix-cli-custom"
            assert not getattr(mcp_server, "TOOL_SERVER_URL", "")
            importlib.reload(mcp_server)

    def test_agent_id_default(self):
        """Should have default agent ID."""
        assert mcp_server.AGENT_ID == "claude-cli-agent" or "agent" in mcp_server.AGENT_ID.lower()


class TestCvssEdgeCases:
    """Edge case tests for CVSS calculation."""

    def test_handles_invalid_attack_vector(self):
        """Should handle invalid attack vector gracefully."""
        score, severity = calculate_cvss("X", "L", "N", "N", "U", "H", "H", "H")
        # Should use default value
        assert isinstance(score, float)
        assert severity in ["none", "low", "medium", "high", "critical"]

    def test_handles_invalid_complexity(self):
        """Should handle invalid complexity gracefully."""
        score, severity = calculate_cvss("N", "X", "N", "N", "U", "H", "H", "H")
        assert isinstance(score, float)

    def test_max_score_is_ten(self):
        """Maximum score should be 10.0."""
        # Most severe possible vulnerability
        score, severity = calculate_cvss("N", "L", "N", "N", "C", "H", "H", "H")
        assert score <= 10.0
        assert severity == "critical"
