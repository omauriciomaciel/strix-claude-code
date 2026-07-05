"""Executes MCP tool calls directly against a running sandbox container via
``docker exec``, replacing the HTTP bridge to the in-container tool server that
strix-sandbox dropped in 1.0.0 (see sandbox.py for why).

This runs inside the MCP server subprocess (a separate process from the one
that started the container), so it looks the container up by name instead of
holding a reference to the Sandbox object.
"""

from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from io import BytesIO
from tarfile import TarFile, TarInfo
from typing import Any

WORKSPACE = "/workspace"

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

    def __init__(self, container_name: str):
        self.container_name = container_name
        self._container = None
        self._helper_installed = False

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

        if tool_name in ("browser_action", "list_requests", "view_request", "send_request", "repeat_request"):
            return {"error": (
                f"'{tool_name}' isn't available yet on strix-sandbox 1.0.0. "
                "Upstream removed the in-container tool server this used to talk "
                "to; browser control now needs the 'agent-browser' CLI and proxy "
                "inspection needs the Caido SDK - neither is wired up here yet."
            )}

        return {"error": f"Unknown tool: {tool_name}"}

    async def close(self) -> None:
        pass
