"""Tests for the host-side Caido GraphQL client.

The strix-sandbox 1.0.0 image runs a Caido CLI sidecar that exposes a GraphQL
endpoint on the host's published port. ``caido_client.CaidoClient`` talks to
it directly with ``httpx`` (no ``caido-sdk-client`` dependency, which would
force ``requires-python >= 3.12``). These tests mock httpx and assert the
GraphQL payloads we send + the data we surface back to ``SandboxExecClient``.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from strix_cli_claude import caido_client
from strix_cli_claude.caido_client import CaidoClient, CaidoError, _build_httpql_filter


# --------------------------------------------------------------------------- #
# _build_httpql_filter
# --------------------------------------------------------------------------- #


class TestBuildHttpqlFilter:
    def test_returns_none_when_no_filters(self):
        assert _build_httpql_filter() is None
        assert _build_httpql_filter(host=None, method=None) is None

    def test_single_clause_returns_clause_directly(self):
        result = _build_httpql_filter(host="example.com")
        assert result == {"host": {"eq": "example.com"}}

    def test_multiple_clauses_anded(self):
        result = _build_httpql_filter(
            host="example.com", method="get", path="/api", status_code=200
        )
        assert result == {
            "and": [
                {"host": {"eq": "example.com"}},
                {"method": {"eq": "GET"}},
                {"path": {"contains": "/api"}},
                {"resp.status": {"eq": 200}},
            ]
        }

    def test_method_uppercased(self):
        result = _build_httpql_filter(method="post")
        assert result == {"method": {"eq": "POST"}}

    def test_path_uses_contains_not_eq(self):
        result = _build_httpql_filter(path="/admin")
        assert result == {"path": {"contains": "/admin"}}


# --------------------------------------------------------------------------- #
# CaidoClient env / url
# --------------------------------------------------------------------------- #


class TestCaidoUrl:
    def test_default_when_no_env(self):
        with patch.dict("os.environ", {}, clear=True):
            assert caido_client.caido_url() == "http://127.0.0.1:48080"

    def test_env_override(self):
        with patch.dict("os.environ", {"STRIX_CAIDO_URL": "http://host:12345"}, clear=True):
            assert caido_client.caido_url() == "http://host:12345"

    def test_trailing_slash_stripped(self):
        with patch.dict("os.environ", {"STRIX_CAIDO_URL": "http://host:12345/"}, clear=True):
            assert caido_client.caido_url() == "http://host:12345"


class TestCaidoClientInit:
    def test_default_base_url(self):
        with patch.dict("os.environ", {}, clear=True):
            c = CaidoClient()
            assert c.base_url == "http://127.0.0.1:48080"

    def test_explicit_base_url(self):
        c = CaidoClient("http://override:9999/")
        assert c.base_url == "http://override:9999"

    def test_no_token_until_bootstrap(self):
        c = CaidoClient()
        assert c._token is None
        assert c._project_id is None


# --------------------------------------------------------------------------- #
# bootstrap() - guest login + temp project + select
# --------------------------------------------------------------------------- #


class TestCaidoBootstrap:
    @pytest.mark.asyncio
    async def test_bootstrap_sets_token_and_project(self):
        c = CaidoClient("http://test:48080")

        # Sequence of /graphql responses: loginAsGuest -> createProject -> selectProject.
        responses = [
            MagicMock(
                status_code=200,
                json=lambda: {"data": {"loginAsGuest": {"token": {"accessToken": "tok-123"}}}},
            ),
            MagicMock(
                status_code=200,
                json=lambda: {
                    "data": {"createProject": {"project": {"id": "proj-1", "name": "sandbox"}, "error": None}}
                },
            ),
            MagicMock(
                status_code=200,
                json=lambda: {"data": {"selectProject": {"project": {"id": "proj-1", "name": "sandbox"}}}},
            ),
        ]
        c._gql = AsyncMock(side_effect=[r.json()["data"] if r.status_code == 200 else {} for r in responses])

        await c.bootstrap()

        assert c._token == "tok-123"
        assert c._project_id == "proj-1"
        # Three GraphQL ops: loginAsGuest, createProject, selectProject.
        assert c._gql.call_count == 3

    @pytest.mark.asyncio
    async def test_bootstrap_raises_when_no_token(self):
        c = CaidoClient("http://test:48080")
        c._gql = AsyncMock(return_value={"loginAsGuest": {"token": {}}})
        with pytest.raises(CaidoError) as exc_info:
            await c.bootstrap()
        assert "loginAsGuest" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_bootstrap_raises_when_no_project_id(self):
        c = CaidoClient("http://test:48080")
        c._gql = AsyncMock(return_value={"loginAsGuest": {"token": {"accessToken": "tok"}}})
        # Second call: createProject returns no project id.
        # Override _gql to return differently on the second call.
        c._gql = AsyncMock(
            side_effect=[
                {"loginAsGuest": {"token": {"accessToken": "tok"}}},
                {"createProject": {"project": {}}},
            ]
        )
        with pytest.raises(CaidoError) as exc_info:
            await c.bootstrap()
        assert "createProject" in str(exc_info.value)


# --------------------------------------------------------------------------- #
# list_requests / view_request
# --------------------------------------------------------------------------- #


class TestListRequests:
    @pytest.mark.asyncio
    async def test_calls_graphql_with_filter_and_no_raw(self):
        c = CaidoClient("http://test:48080")
        c._gql = AsyncMock(
            return_value={"requests": {"edges": [], "pageInfo": {"hasNextPage": False}}}
        )

        result = await c.list_requests(host="example.com", method="get", limit=10)

        assert result == {"requests": {"edges": [], "pageInfo": {"hasNextPage": False}}}
        call = c._gql.call_args
        # First positional is the query string.
        assert "query Requests" in call.args[0]
        # Second positional is the variables dict (we call positionally).
        variables = call.args[1] if len(call.args) > 1 else call.kwargs.get("variables", {})
        assert variables["first"] == 10
        assert variables["includeRequestRaw"] is False
        assert variables["includeResponseRaw"] is False
        # The composed HTTPQL filter is passed as the `filter` variable.
        assert variables["filter"] == {
            "and": [
                {"host": {"eq": "example.com"}},
                {"method": {"eq": "GET"}},
            ]
        }

    @pytest.mark.asyncio
    async def test_no_filters_passes_none(self):
        c = CaidoClient("http://test:48080")
        c._gql = AsyncMock(return_value={"requests": {"edges": []}})
        await c.list_requests()
        call = c._gql.call_args
        variables = call.args[1] if len(call.args) > 1 else call.kwargs.get("variables", {})
        assert variables["filter"] is None

    @pytest.mark.asyncio
    async def test_default_limit_50(self):
        c = CaidoClient("http://test:48080")
        c._gql = AsyncMock(return_value={"requests": {"edges": []}})
        await c.list_requests()
        call = c._gql.call_args
        variables = call.args[1] if len(call.args) > 1 else call.kwargs.get("variables", {})
        assert variables["first"] == 50


class TestViewRequest:
    @pytest.mark.asyncio
    async def test_includes_raw_bytes(self):
        c = CaidoClient("http://test:48080")
        c._gql = AsyncMock(
            return_value={"request": {"id": "r1", "host": "example.com", "raw": "GET / HTTP/1.1\r\n"}}
        )

        result = await c.view_request("r1")

        assert result["request"]["id"] == "r1"
        call = c._gql.call_args
        variables = call.args[1] if len(call.args) > 1 else call.kwargs.get("variables", {})
        assert variables["id"] == "r1"
        assert variables["includeRequestRaw"] is True
        assert variables["includeResponseRaw"] is True


# --------------------------------------------------------------------------- #
# close()
# --------------------------------------------------------------------------- #


class TestCaidoClose:
    @pytest.mark.asyncio
    async def test_close_releases_httpx_client(self):
        c = CaidoClient("http://test:48080")
        # Force the lazy client to be created.
        await c._http()
        assert c._client is not None
        await c.close()
        assert c._client is None

    @pytest.mark.asyncio
    async def test_close_idempotent_when_no_client(self):
        c = CaidoClient("http://test:48080")
        # Should not raise even when nothing was opened.
        await c.close()
        assert c._client is None


# --------------------------------------------------------------------------- #
# httpx round-trip (mocked at the transport level)
# --------------------------------------------------------------------------- #


class TestGqlHttpRoundTrip:
    """End-to-end through _gql -> httpx.AsyncClient.post, mocked."""

    @pytest.mark.asyncio
    async def test_propagates_authorization_header_after_bootstrap(self, monkeypatch):
        c = CaidoClient("http://test:48080")

        # Mock httpx.AsyncClient.post so we can introspect the headers it sent.
        post_calls = []

        class MockResponse:
            status_code = 200

            def json(self):
                return {"data": {"loginAsGuest": {"token": {"accessToken": "tok-1"}}}}

            def raise_for_status(self):
                pass

        async def fake_post(url, json=None, **kwargs):
            post_calls.append({"url": url, "json": json, "headers": kwargs.get("headers")})
            return MockResponse()

        # Patch the *uninitialized* client instance to capture post calls.
        # We skip the real httpx.AsyncClient by overriding _http to return a stub.
        class StubClient:
            def __init__(self):
                self.headers = {}

            async def post(self, url, json=None, **kwargs):
                # Headers should include Authorization after the token is set.
                post_calls.append({"url": url, "json": json, "auth": self.headers.get("Authorization")})
                return MockResponse()

            async def aclose(self):
                pass

        stub = StubClient()
        c._client = stub  # bypass _http()
        c._token = "tok-1"  # simulate post-bootstrap
        stub.headers["Authorization"] = "Bearer tok-1"

        await c._gql('mutation { loginAsGuest { token { accessToken } } }')

        assert len(post_calls) == 1
        assert post_calls[0]["auth"] == "Bearer tok-1"
        assert post_calls[0]["url"] == "/graphql"

    @pytest.mark.asyncio
    async def test_raises_on_graphql_errors(self):
        c = CaidoClient("http://test:48080")

        class MockResponse:
            status_code = 200

            def json(self):
                return {"errors": [{"message": "field XXX does not exist"}]}

            def raise_for_status(self):
                pass

        async def fake_post(url, json=None, **kwargs):
            return MockResponse()

        class StubClient:
            async def post(self, url, json=None, **kwargs):
                return MockResponse()

            async def aclose(self):
                pass

        c._client = StubClient()
        with pytest.raises(CaidoError) as exc_info:
            await c._gql("query { foo }")
        assert "field XXX" in str(exc_info.value)