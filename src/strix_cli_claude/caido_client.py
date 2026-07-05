"""Host-side client for the Caido GraphQL sidecar inside the strix sandbox.

The strix-sandbox 1.0.0 entrypoint brings up a Caido CLI sidecar bound to
``0.0.0.0:48080`` inside the container and exposes its GraphQL endpoint on the
host via a published port. This module talks to that endpoint directly with
``httpx`` (no SDK) so the wrapper keeps its ``requires-python = ">=3.11"`` -
the upstream ``caido-sdk-client`` (used by strix itself) requires Python >=3.12.

Scope intentionally narrow: this replaces only the inspection half of the old
in-container HTTP tool server (``list_requests`` / ``view_request``). Sending
and replaying requests is done by shelling out to ``curl`` *inside* the
sandbox, where the entrypoint's ``/etc/profile.d/proxy.sh`` makes traffic flow
through Caido's proxy automatically - so we get capture + replay without the
replay-session machinery upstream's SDK wraps.

The schema fragments here mirror the public Caido GraphQL documents shipped
with ``caido-sdk-client`` 0.2.0 (``request.graphql`` / ``project.graphql``),
trimmed to the fields this wrapper actually uses.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# Default Caido listen URL *from the host's perspective*. The container always
# listens on port 48080 internally; the host reaches it via the random host
# port the Sandbox publishes (sandbox_info["caido_port"]). Callers override
# this with STRIX_CAIDO_URL.
_DEFAULT_CAIDO_URL = "http://127.0.0.1:48080"


def caido_url() -> str:
    """Resolve the Caido GraphQL base URL from the env or fall back to default."""
    return os.environ.get("STRIX_CAIDO_URL", _DEFAULT_CAIDO_URL).rstrip("/")


# GraphQL operations ------------------------------------------------------------

_LOGIN_AS_GUEST = (
    'mutation { loginAsGuest { token { accessToken } } }'
)

_CREATE_PROJECT = """
mutation CreateProject($input: CreateProjectInput!) {
  createProject(input: $input) {
    project { id name }
    error { __typename }
  }
}
"""

_SELECT_PROJECT = """
mutation SelectProject($id: ID!) {
  selectProject(id: $id) { project { id name } }
}
"""

# Trimmed from caido-sdk-client 0.2.0 graphql/documents/request.graphql.
_REQUESTS_QUERY = """
query Requests(
  $first: Int
  $filter: HTTPQLInput
  $includeRequestRaw: Boolean!
  $includeResponseRaw: Boolean!
) {
  requests(first: $first, filter: $filter) {
    edges {
      cursor
      node {
        id
        host
        port
        method
        path
        query
        isTls
        createdAt
        raw @include(if: $includeRequestRaw)
        response {
          id
          statusCode
          roundtripTime
          length
          createdAt
          raw @include(if: $includeResponseRaw)
        }
      }
    }
    pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
  }
}
"""

_REQUEST_QUERY = """
query Request(
  $id: ID!
  $includeRequestRaw: Boolean!
  $includeResponseRaw: Boolean!
) {
  request(id: $id) {
    id
    host
    port
    method
    path
    query
    isTls
    createdAt
    raw @include(if: $includeRequestRaw)
    response {
      id
      statusCode
      roundtripTime
      length
      createdAt
      raw @include(if: $includeResponseRaw)
    }
  }
}
"""


class CaidoError(Exception):
    """Raised when the Caido GraphQL sidecar returns an error or is unreachable."""


class CaidoClient:
    """Async client wrapping the subset of Caido's GraphQL we need.

    Lifecycle: call :meth:`bootstrap` once to log in as guest and select a
    fresh temporary project, then :meth:`list_requests` / :meth:`view_request`
    as often as needed, then :meth:`close` to release the underlying httpx
    client. The temporary project is owned by the guest session and will be
    garbage-collected by Caido when the session ends; there is no explicit
    delete in this build.
    """

    REQUEST_TIMEOUT = 30.0

    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or caido_url()).rstrip("/")
        self._token: str | None = None
        self._project_id: str | None = None
        # trust_env=False so httpx doesn't pick up host proxy env that would
        # loop requests back through Caido on the *host* side.
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.REQUEST_TIMEOUT,
                trust_env=False,
            )
        return self._client

    async def _gql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute a GraphQL request and return the ``data`` payload."""
        client = await self._http()
        try:
            response = await client.post(
                "/graphql",
                json={"query": query, "variables": variables or {}},
            )
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise CaidoError(f"Caido GraphQL request failed: {e}") from e

        try:
            payload = response.json()
        except json.JSONDecodeError as e:
            raise CaidoError(f"Caido returned non-JSON: {response.text[:200]}") from e

        if payload.get("errors"):
            messages = "; ".join(
                err.get("message", str(err)) for err in payload["errors"]
            )
            raise CaidoError(f"Caido GraphQL errors: {messages}")
        return payload.get("data") or {}

    async def bootstrap(self) -> None:
        """Log in as guest and create+select a temporary project.

        Mirrors upstream ``strix/runtime/caido_bootstrap.py``: we pass through
        the guest login mutation, take the access token, create a temporary
        project named ``sandbox``, and select it. The token is stored and
        re-used on subsequent requests.
        """
        data = await self._gql(_LOGIN_AS_GUEST)
        token = (
            data.get("loginAsGuest", {}).get("token", {}).get("accessToken")
        )
        if not token:
            raise CaidoError(f"loginAsGuest returned no token: {data}")
        self._token = str(token)
        # Reset the client so subsequent calls pick up the Authorization header.
        if self._client is not None:
            await self._client.aclose()
            self._client = None

        data = await self._gql(
            _CREATE_PROJECT,
            {"input": {"name": "sandbox", "temporary": True}},
        )
        project = (data.get("createProject") or {}).get("project") or {}
        project_id = project.get("id")
        if not project_id:
            raise CaidoError(f"createProject returned no project id: {data}")
        self._project_id = str(project_id)

        await self._gql(_SELECT_PROJECT, {"id": self._project_id})
        logger.info("Caido project selected: %s", self._project_id)

    async def list_requests(
        self,
        *,
        host: str | None = None,
        method: str | None = None,
        path: str | None = None,
        status_code: int | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List HTTP requests captured by Caido. Returns the GraphQL payload."""
        httpql = _build_httpql_filter(host=host, method=method, path=path, status_code=status_code)
        data = await self._gql(
            _REQUESTS_QUERY,
            {
                "first": limit,
                "filter": httpql,
                "includeRequestRaw": False,
                "includeResponseRaw": False,
            },
        )
        return data

    async def view_request(self, request_id: str) -> dict[str, Any]:
        """Fetch a single request with its raw bytes + response raw."""
        data = await self._gql(
            _REQUEST_QUERY,
            {
                "id": request_id,
                "includeRequestRaw": True,
                "includeResponseRaw": True,
            },
        )
        return data

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _build_httpql_filter(
    *,
    host: str | None = None,
    method: str | None = None,
    path: str | None = None,
    status_code: int | None = None,
) -> dict[str, Any] | None:
    """Compose a Caido HTTPQL filter.

    Caido's HTTPQL is an OR-of-ANDs expression; the simplest filter is a list
    of single-condition clauses that we AND together via the ``and`` operator
    exposed by ``HTTPQLInput``. We only support the four fields this wrapper
    exposes to the agent; users wanting more can hit the GraphQL endpoint
    directly. Each clause is ``{ "<field>": {"op": "<eq|contains>", "value":
    ... } }``. Caido accepts lowercase field names (``host``, ``method``,
    ``path``, ``resp.status``).
    """
    clauses: list[dict[str, Any]] = []
    if host:
        clauses.append({"host": {"eq": host}})
    if method:
        clauses.append({"method": {"eq": method.upper()}})
    if path:
        clauses.append({"path": {"contains": path}})
    if status_code is not None:
        clauses.append({"resp.status": {"eq": status_code}})
    if not clauses:
        return None
    if len(clauses) == 1:
        return clauses[0]
    return {"and": clauses}