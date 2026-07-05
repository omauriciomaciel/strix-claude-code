"""Tests for verifier.py prompt assembly.

Covers the strix-sandbox 1.0.0 rewrite: `agent-browser` + Debian `chromium`
ship in the image; Playwright was removed upstream. The verifier prompt must
not instruct the agent to install Playwright anymore.
"""

import pytest

from strix_cli_claude.verifier import _driver_steps, build_verifier_prompt


@pytest.fixture
def base_finding():
    return {
        "title": "Reflected XSS in /search",
        "severity": "high",
        "vuln_type": "XSS",
        "asset": "https://app.example.com",
        "source_ref": "https://github.com/example/app",
        "commit_ref": "deadbeef",
        "repro": "Open /search?q=<svg/onload=alert(1)>",
    }


class TestDriverStepsBrowserSetup:
    """The reusable `browser_setup` block must reflect the 1.0.0 image."""

    ASSET_TYPES = [
        "CHROME_EXTENSION",
        "VSCODE_EXTENSION",
        "URL",
        "DOMAIN",
        "NPM",
        "SOURCE_CODE",
        "",  # default branch
    ]

    @pytest.mark.parametrize("at", ASSET_TYPES)
    def test_no_playwright_mentioned(self, at):
        """No asset_type driver may tell the agent to install Playwright.

        Upstream strix-sandbox 1.0.0 removed Playwright from the image; the
        verifier must not waste a run trying to `pip install playwright`.
        """
        out = _driver_steps(at, "https://example.com/ref", "deadbeef")
        assert "playwright" not in out.lower()
        assert "playwright install" not in out.lower()
        assert "record_video_dir" not in out.lower()

    @pytest.mark.parametrize("at", ASSET_TYPES)
    def test_mentions_agent_browser(self, at):
        """Every browser-using branch must point at the `agent-browser` CLI."""
        out = _driver_steps(at, "https://example.com/ref", "deadbeef")
        # NPM is a terminal-only PoC and has no browser block.
        if at == "NPM":
            assert "agent-browser" not in out
        else:
            assert "agent-browser" in out

    @pytest.mark.parametrize("at", ASSET_TYPES)
    def test_mentions_chromium_native_or_executable_path(self, at):
        """chromium is preinstalled in 1.0.0; we reference it directly."""
        out = _driver_steps(at, "https://example.com/ref", "deadbeef")
        if at == "NPM":
            return  # terminal-only, no browser
        # Either the bare `chromium` binary or the agent-browser executable-path
        # flag pointing at /usr/bin/chromium is acceptable.
        assert "chromium" in out.lower()

    @pytest.mark.parametrize("at", ASSET_TYPES)
    def test_mentions_xvfb_and_ffmpeg(self, at):
        """xvfb + ffmpeg are still required (not in the base image) and must
        be apt-installed by the agent at runtime."""
        out = _driver_steps(at, "https://example.com/ref", "deadbeef")
        if at == "NPM":
            return  # terminal-only, no display needed
        assert "xvfb" in out.lower()
        assert "ffmpeg" in out.lower()

    @pytest.mark.parametrize("at", ASSET_TYPES)
    def test_no_playwright_pip_install(self, at):
        """The explicit pip/npm install Playwright lines must be gone."""
        out = _driver_steps(at, "https://example.com/ref", "deadbeef")
        assert "pip install playwright" not in out.lower()
        assert "npm i -D playwright" not in out.lower()


class TestChromeExtensionDriver:
    """CHROME_EXTENSION got the most surgical rewrite (launchPersistentContext
    Playwright API -> agent-browser --extension)."""

    def test_uses_agent_browser_extension_flag(self):
        out = _driver_steps(
            "CHROME_EXTENSION",
            "https://github.com/example/ext",
            "v1.2.3",
        )
        assert "agent-browser" in out
        assert "--extension" in out  # agent-browser's MV3 loader flag

    def test_does_not_use_launchPersistentContext(self):
        out = _driver_steps(
            "CHROME_EXTENSION",
            "https://github.com/example/ext",
            "v1.2.3",
        )
        assert "launchPersistentContext" not in out
        assert "playwright" not in out.lower()

    def test_uses_headed_chromium(self):
        out = _driver_steps(
            "CHROME_EXTENSION",
            "https://github.com/example/ext",
            "v1.2.3",
        )
        assert "--headed" in out
        assert "/usr/bin/chromium" in out

    def test_refers_caido_ca(self):
        """The 1.0.0 entrypoint already trusts the Caido CA into Chromium's
        NSS DB; the prompt should mention that, not tell the agent to import it."""
        out = _driver_steps(
            "CHROME_EXTENSION",
            "https://github.com/example/ext",
            "v1.2.3",
        )
        assert "Caido" in out


class TestBuildVerifierPrompt:
    """End-to-end prompt assembly must inherit the new browser_setup."""

    def test_no_playwright_in_full_prompt(self, base_finding):
        prompt = build_verifier_prompt(base_finding)
        assert "playwright" not in prompt.lower()
        assert "agent-browser" in prompt or base_finding["asset_type"] == "NPM"