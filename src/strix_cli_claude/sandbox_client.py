"""Executes MCP tool calls directly against a running sandbox container via
``docker exec``, replacing the HTTP bridge to the in-container tool server that
strix-sandbox dropped in 1.0.0 (see sandbox.py for why).

This runs inside the MCP server subprocess (a separate process from the one
that started the container), so it looks the container up by name instead of
holding a reference to the Sandbox object.

The flock of tool calls handled here:
  * ``terminal_execute`` / ``python_action`` / ``str_replace_editor`` /
    ``list_files`` - thin shims over ``docker exec``.
  * ``browser_action`` - shells out to the ``agent-browser`` CLI that ships in
    the 1.0.0 image (Playwright was removed upstream).
  * ``list_requests`` / ``view_request`` - host-side Caido GraphQL via the
    :class:`~strix_cli_claude.caido_client.CaidoClient`.
  * ``send_request`` / ``repeat_request`` - shell out to ``curl`` *inside* the
    sandbox, where the entrypoint's ``/etc/profile.d/proxy.sh`` funnels the
    traffic through Caido's proxy so it gets captured automatically (avoids
    the replay-session machinery upstream's SDK wraps).
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from io import BytesIO
from tarfile import TarFile, TarInfo
from typing import Any

from strix_cli_claude.caido_client import CaidoClient, CaidoError

logger = logging.getLogger(__name__)

WORKSPACE = "/workspace"

# Directory the 1.0.0 image's entrypoint pre-creates for agent-browser
# screenshots (AGENT_BROWSER_SCREENSHOT_DIR=/workspace/.agent-browser-screenshots).
_AGENT_BROWSER_SHOT_DIR = "/workspace/.agent-browser-screenshots"

# Preloaded once per container so python_action gets the same "batteries
# included" feel the old tool_server advertised.
_PYTHON_PREAMBLE = (
    "import json, base64, hashlib, re, asyncio\n"
    "import requests, httpx, aiohttp\n"
    "from bs4 import BeautifulSoup\n"
)

_EDITOR_HELPER_PATH = "/tmp/_strix_editor_helper.py"
_EDITOR_HELPER_SRC = r'''
import json, os, sys

def _resolve(path):
    if not path.startswith("/"):
        path = os.path.join("/workspace", path)
    return path

def view(path, view_range=None):
    path = _resolve(path)
    if os.path.isdir(path):
        return {"content": "\n".join(sorted(os.listdir(path)))}
    with open(path) as f:
        lines = f.readlines()
    start, end = 1, len(lines)
    if view_range:
        start, end = view_range[0], view_range[1] if view_range[1] != -1 else len(lines)
    numbered = [f"{i:6d}\t{lines[i-1].rstrip(chr(10))}" for i in range(start, min(end, len(lines)) + 1)]
    return {"content": "\n".join(numbered)}

def create(path, file_text):
    path = _resolve(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(file_text or "")
    return {"content": f"Created {path}"}

def str_replace(path, old_str, new_str):
    path = _resolve(path)
    with open(path) as f:
        content = f.read()
    count = content.count(old_str)
    if count == 0:
        return {"error": f"old_str not found in {path}"}
    if count > 1:
        return {"error": f"old_str is not unique in {path} ({count} occurrences)"}
    with open(path, "w") as f:
        f.write(content.replace(old_str, new_str or "", 1))
    return {"content": f"Replaced 1 occurrence in {path}"}

def insert(path, insert_line, new_str):
    path = _resolve(path)
    with open(path) as f:
        lines = f.readlines()
    idx = max(0, min(insert_line, len(lines)))
    text = (new_str or "")
    if not text.endswith("\n"):
        text += "\n"
    lines.insert(idx, text)
    with open(path, "w") as f:
        f.writelines(lines)
    return {"content": f"Inserted at line {insert_line} in {path}"}

def list_files(path, recursive=False):
    path = _resolve(path)
    if not os.path.exists(path):
        return {"error": f"Path does not exist: {path}"}
    entries = []
    if recursive:
        for root, dirs, files in os.walk(path):
            for name in dirs:
                entries.append(os.path.join(root, name) + "/")
            for name in files:
                entries.append(os.path.join(root, name))
    else:
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            entries.append(name + "/" if os.path.isdir(full) else name)
    return {"content": "\n".join(sorted(entries))}

_DISPATCH = {
    "view": lambda a: view(a["path"], a.get("view_range")),
    "create": lambda a: create(a["path"], a.get("file_text", "")),
    "str_replace": lambda a: str_replace(a["path"], a.get("old_str", ""), a.get("new_str", "")),
    "insert": lambda a: insert(a["path"], a.get("insert_line", 0), a.get("new_str", "")),
    "list_files": lambda a: list_files(a["path"], a.get("recursive", False)),
}

if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        args = json.load(f)
    op = args.pop("_op")
    try:
        result = _DISPATCH[op](args)
    except Exception as e:
        result = {"error": f"{type(e).__name__}: {e}"}
    sys.stdout.write(json.dumps(result))
'''


class SandboxExecClient:
    """Drop-in replacement for the old HTTP ToolServerClient.

    Same ``call_tool(tool_name, params) -> dict`` contract (``{"result": {...}}``
    or ``{"error": ...}``) so mcp_server.py's dispatch code doesn't need to change.
    """

    def __init__(self, container_name: str, caido_url: str | None = None):
        self.container_name = container_name
        self._container = None
        self._helper_installed = False
        # Lazy: only bootstrapped on the first proxy tool call. Storing the
        # URL up front lets STRIX_CAIDO_URL override flow through naturally.
        self._caido_url = caido_url or os.getenv("STRIX_CAIDO_URL") or None
        self._caido: CaidoClient | None = None

    def _get_container(self):
        if self._container is None:
            import docker

            client = docker.from_env()
            self._container = client.containers.get(self.container_name)
        return self._container

    def _exec(
        self, cmd: list[str] | str, timeout: int = 300, user: str = "pentester",
    ) -> dict[str, Any]:
        container = self._get_container()
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                container.exec_run, cmd, workdir=WORKSPACE, user=user,
            )
            try:
                result = future.result(timeout=timeout)
            except FuturesTimeoutError:
                return {"error": f"Command timed out after {timeout}s"}
        output = result.output.decode("utf-8", errors="replace") if result.output else ""
        return {"result": {"content": output, "exit_code": result.exit_code}}

    def _put_file(self, container, path: str, data: bytes) -> None:
        buf = BytesIO()
        with TarFile(fileobj=buf, mode="w") as tar:
            info = TarInfo(name=path.lstrip("/"))
            info.size = len(data)
            tar.addfile(info, BytesIO(data))
        buf.seek(0)
        container.put_archive("/", buf.getvalue())

    def _ensure_editor_helper(self, container) -> None:
        if self._helper_installed:
            return
        result = container.exec_run(["test", "-f", _EDITOR_HELPER_PATH])
        if result.exit_code != 0:
            self._put_file(container, _EDITOR_HELPER_PATH, _EDITOR_HELPER_SRC.encode())
        self._helper_installed = True

    def _run_editor_op(self, op: str, args: dict[str, Any], timeout: int = 60) -> dict[str, Any]:
        container = self._get_container()
        self._ensure_editor_helper(container)

        op_path = f"/tmp/_strix_op_{uuid.uuid4().hex}.json"
        payload = {"_op": op, **args}
        self._put_file(container, op_path, json.dumps(payload).encode())

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                container.exec_run,
                ["python3", _EDITOR_HELPER_PATH, op_path],
                workdir=WORKSPACE,
                user="pentester",
            )
            try:
                result = future.result(timeout=timeout)
            except FuturesTimeoutError:
                return {"error": f"'{op}' timed out after {timeout}s"}
        container.exec_run(["rm", "-f", op_path])

        raw = result.output.decode("utf-8", errors="replace") if result.output else ""
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"error": f"Malformed editor helper output: {raw[:500]}"}
        if "error" in parsed:
            return {"error": parsed["error"]}
        return {"result": parsed}

    def _python_action(self, params: dict[str, Any]) -> dict[str, Any]:
        action = params.get("action", "execute")
        if action != "execute":
            # ponytail: no persistent REPL sessions - each call is a fresh
            # interpreter. Upgrade to a real docker-exec socket bridge if
            # agents start relying on cross-call state.
            return {"result": {
                "content": (
                    f"'{action}' is a no-op in this build: python_action runs each "
                    "'execute' call in a fresh interpreter (no persistent sessions)."
                ),
            }}
        code = params.get("code", "")
        timeout = int(params.get("timeout") or 30)
        script = _PYTHON_PREAMBLE + code
        container = self._get_container()
        op_path = f"/tmp/_strix_py_{uuid.uuid4().hex}.py"
        self._put_file(container, op_path, script.encode())
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                container.exec_run, ["python3", op_path], workdir=WORKSPACE, user="pentester",
            )
            try:
                result = future.result(timeout=timeout)
            except FuturesTimeoutError:
                return {"error": f"Command timed out after {timeout}s"}
        container.exec_run(["rm", "-f", op_path])
        output = result.output.decode("utf-8", errors="replace") if result.output else ""
        return {"result": {"content": output, "exit_code": result.exit_code}}

    async def call_tool(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "terminal_execute":
            command = params.get("command", "")
            timeout = int(params.get("timeout") or 300)
            return self._exec(["bash", "-lc", command], timeout=timeout)

        if tool_name == "python_action":
            return self._python_action(params)

        if tool_name == "str_replace_editor":
            command = params.get("command")
            if command not in ("view", "create", "str_replace", "insert"):
                return {"error": f"Unknown str_replace_editor command: {command}"}
            args = {"path": params.get("path")}
            if command == "view":
                args["view_range"] = params.get("view_range")
            elif command == "create":
                args["file_text"] = params.get("file_text", "")
            elif command == "str_replace":
                args["old_str"] = params.get("old_str", "")
                args["new_str"] = params.get("new_str", "")
            elif command == "insert":
                args["insert_line"] = params.get("insert_line", 0)
                args["new_str"] = params.get("new_str", "")
            return self._run_editor_op(command, args)

        if tool_name == "list_files":
            return self._run_editor_op(
                "list_files",
                {"path": params.get("path"), "recursive": params.get("recursive", False)},
            )

        if tool_name == "browser_action":
            return await self._browser_action(params)

        if tool_name == "list_requests":
            return await self._list_requests(params)

        if tool_name == "view_request":
            return await self._view_request(params)

        if tool_name == "send_request":
            return await self._send_request(params)

        if tool_name == "repeat_request":
            return await self._repeat_request(params)

        return {"error": f"Unknown tool: {tool_name}"}

    async def close(self) -> None:
        if self._caido is not None:
            try:
                await self._caido.close()
            except Exception as e:
                logger.debug("Error closing Caido client: %s}", e)
            self._caido = None

    # ------------------------------------------------------------------ #
    # Caido (proxy inspection)
    # ------------------------------------------------------------------ #

    async def _get_caido(self) -> CaidoClient:
        """Lazily bootstrap the Caido client on the first proxy tool call."""
        if self._caido is None:
            client = CaidoClient(self._caido_url)
            await client.bootstrap()
            self._caido = client
        return self._caido

    async def _list_requests(self, params: dict[str, Any]) -> dict[str, Any]:
        try:
            client = await self._get_caido()
            data = await client.list_requests(
                host=params.get("host"),
                method=params.get("method"),
                path=params.get("path"),
                status_code=params.get("status_code"),
                limit=int(params.get("limit") or 50),
            )
        except CaidoError as e:
            return {"error": f"list_requests failed: {e}"}
        # Surface the edges + page info as JSON text; the agent can parse it.
        return {"result": {"content": json.dumps(data, default=str), "exit_code": 0}}

    async def _view_request(self, params: dict[str, Any]) -> dict[str, Any]:
        request_id = params.get("request_id")
        if not request_id:
            return {"error": "view_request requires 'request_id'"}
        try:
            client = await self._get_caido()
            data = await client.view_request(str(request_id))
        except CaidoError as e:
            return {"error": f"view_request failed: {e}"}
        return {"result": {"content": json.dumps(data, default=str), "exit_code": 0}}

    async def _send_request(self, params: dict[str, Any]) -> dict[str, Any]:
        """Send an ad-hoc HTTP request from inside the sandbox via curl.

        Going through ``docker exec`` means the request automatically flows
        through Caido's proxy (env vars in /etc/profile.d/proxy.sh) and gets
        captured - no replay-session machinery needed.
        """
        method = (params.get("method") or "GET").upper()
        url = params.get("url")
        if not url:
            return {"error": "send_request requires 'url'"}
        headers = params.get("headers") or {}
        body = params.get("body")

        curl_cmd = ["curl", "-sS", "-i", "-X", method]
        for k, v in headers.items():
            curl_cmd.extend(["-H", f"{k}: {v}"])
        body_path: str | None = None
        if body is not None:
            # Write body to a temp file inside the container to avoid shell
            # quoting issues with large / binary payloads.
            body_path = f"/tmp/_strix_send_{uuid.uuid4().hex}.bin"
            container = self._get_container()
            self._put_file(
                container, body_path,
                body.encode() if isinstance(body, str) else (body or b""),
            )
            curl_cmd.extend(["--data-binary", f"@{body_path}"])
        curl_cmd.append(url)

        result = self._exec(curl_cmd, timeout=60)
        # Clean up the temp body file if we wrote one.
        if body_path is not None:
            try:
                container = self._get_container()
                container.exec_run(["rm", "-f", body_path])
            except Exception:
                pass
        return result

    async def _repeat_request(self, params: dict[str, Any]) -> dict[str, Any]:
        """Replay a captured request with optional modifications.

        Implementation: fetch the original raw request via the Caido GraphQL
        endpoint (we need its host/port/method/path), then send it from inside
        the sandbox with curl using the same headers/body the agent can tweak.
        Modifications is {headers: {}, params: {}, body: str}.
        """
        request_id = params.get("request_id")
        if not request_id:
            return {"error": "repeat_request requires 'request_id'"}
        mods = params.get("modifications") or {}

        try:
            client = await self._get_caido()
            data = await client.view_request(str(request_id))
        except CaidoError as e:
            return {"error": f"repeat_request could not load original: {e}"}

        req = (data or {}).get("request") or {}
        if not req.get("host"):
            return {"error": f"request {request_id} not found or has no host"}

        # Reconstruct the URL. Caido exposes isTls/port/path/query.
        scheme = "https" if req.get("isTls") else "http"
        port = req.get("port")
        host = req["host"]
        url = f"{scheme}://{host}"
        if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
            url += f":{port}"
        url += req.get("path") or "/"
        if req.get("query"):
            url += f"?{req['query']}"

        # Apply header modifications. Caido's `raw` is the full raw request -
        # we'd have to parse it to get individual headers. For simplicity (and
        # since this matches upstream's MCP tool description), we fetch the
        # raw, hand it to curl via --data-binary is wrong - we want the raw
        # request to drive method/headers. So: parse the raw request.
        raw = req.get("raw") or ""
        method, headers, body = _parse_raw_http(raw)

        # Merge user modifications.
        for k, v in (mods.get("headers") or {}).items():
            headers[str(k)] = str(v)
        if mods.get("body") is not None:
            body = mods["body"]

        return await self._send_request({
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
        })

    # ------------------------------------------------------------------ #
    # Browser (agent-browser CLI inside the container)
    # ------------------------------------------------------------------ #

    async def _browser_action(self, params: dict[str, Any]) -> dict[str, Any]:
        """Drive the in-container ``agent-browser`` CLI.

        The 1.0.0 image ships agent-browser@0.26.0 globally (npm) + Debian
        ``chromium`` (AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium). We
        shell out via ``docker exec`` - refs from ``snapshot`` reuse across
        actions so ``click @e2`` etc. just work.
        """
        action = params.get("action")
        if not action:
            return {"error": "browser_action requires 'action'"}

        # Build the agent-browser argv from the high-level MCP params.
        try:
            argv = _agent_browser_argv(action, params)
        except ValueError as e:
            return {"error": str(e)}

        # Headed mode is opt-in via params["headed"] (default false=headless).
        headed = ["--headed"] if params.get("headed") else []
        # The 1.0.0 image ships chromium at /usr/bin/chromium.
        executable = ["--executable-path", "/usr/bin/chromium"]

        # agent-browser is a subcommand-based CLI - the per-action argv above
        # is the subcommand + its args. Global flags must precede the subcommand.
        full_argv = ["agent-browser", *headed, *executable, *argv]
        return self._exec(full_argv, timeout=120)


def _parse_raw_http(raw: str) -> tuple[str, dict[str, str], str | None]:
    """Parse a raw HTTP request (as captured by Caido) into (method, headers, body)."""
    if not raw:
        return "GET", {}, None
    # Normalize CRLF -> LF for splitting, but keep \r\n\r\n as the sep.
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.replace("\r\n", "\n").split("\n")
    if not lines:
        return "GET", {}, None
    parts = lines[0].split(" ")
    method = parts[0] if parts else "GET"
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    return method, headers, body or None


def _agent_browser_argv(action: str, params: dict[str, Any]) -> list[str]:
    """Translate an MCP browser_action call into an agent-browser argv.

    Raises ``ValueError`` for unknown/unsupported actions so the caller can
    wrap it in an ``{"error": ...}`` dict.
    """
    if action == "launch":
        # `agent-browser open [url]` (no url = launch on about:blank).
        return ["open"] + ([params["url"]] if params.get("url") else [])
    if action == "goto":
        url = params.get("url")
        if not url:
            raise ValueError("goto requires 'url'")
        return ["open", url]
    if action == "click":
        sel = params.get("selector")
        if not sel:
            raise ValueError("click requires 'selector'")
        return ["click", sel]
    if action == "type":
        sel = params.get("selector")
        text = params.get("text", "")
        if not sel:
            raise ValueError("type requires 'selector'")
        return ["type", sel, text]
    if action == "scroll":
        direction = params.get("direction") or "down"
        # `direction` may be "up"/"down" or a CSS selector.
        if direction in ("up", "down", "left", "right"):
            return ["scroll", direction]
        return ["scrollinto", direction]
    if action == "screenshot":
        path = params.get("path") or f"{_AGENT_BROWSER_SHOT_DIR}/shot-{uuid.uuid4().hex}.png"
        return ["screenshot", path]
    if action == "execute_js":
        script = params.get("script")
        if not script:
            raise ValueError("execute_js requires 'script'")
        return ["eval", script]
    if action == "get_html":
        # `agent-browser get html <sel|body>`. Default to whole document.
        sel = params.get("selector") or "body"
        return ["get", "html", sel]
    if action == "close":
        return ["close"]
    raise ValueError(f"Unknown browser_action: {action}")
