"""Minimal read-only HackerOne API client.

Auth is HTTP Basic: H1_USERNAME (API username) + H1_TOKEN (API token).
The token is read from process env at construction and never echoed in
return values or exception messages.

Only the endpoints we need for scope ingestion are exposed:
  - list_programs()         -> /hackers/programs
  - get_structured_scopes() -> /hackers/programs/{handle}/structured_scopes

No write endpoints. Submission is done manually on hackerone.com.
"""

from __future__ import annotations

import base64
import os
import time
from typing import Any

import httpx

API_BASE = "https://api.hackerone.com/v1"
PAGE_SIZE = 100
MAX_RETRIES = 3


class H1Error(Exception):
    """Raised for any HackerOne API failure. Never contains the token."""


class H1Client:
    def __init__(self, timeout: float = 30.0) -> None:
        username = (os.environ.get("H1_USERNAME") or "").strip()
        token = (os.environ.get("H1_TOKEN") or "").strip()
        if not username or not token:
            raise H1Error(
                "H1_USERNAME and H1_TOKEN must be set in environment "
                "(export them in your shell rc)"
            )
        creds = base64.b64encode(f"{username}:{token}".encode()).decode()
        self._client = httpx.Client(
            headers={
                "Authorization": f"Basic {creds}",
                "Accept": "application/json",
                "User-Agent": "strix-claude-code/1.0",
            },
            timeout=timeout,
            follow_redirects=True,
        )

    def __enter__(self) -> "H1Client":
        return self

    def __exit__(self, *_: Any) -> None:
        self._client.close()

    def close(self) -> None:
        self._client.close()

    # -------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{API_BASE}{path}"
        last_status: int | None = None
        for attempt in range(MAX_RETRIES):
            r = self._client.get(url, params=params)
            last_status = r.status_code

            if r.status_code == 429:
                retry_after = int(r.headers.get("Retry-After") or "5")
                time.sleep(min(retry_after, 60))
                continue

            if r.status_code == 401:
                raise H1Error(
                    "HackerOne API auth failed (HTTP 401). "
                    "Verify H1_USERNAME and H1_TOKEN."
                )
            if r.status_code == 403:
                raise H1Error(
                    f"HackerOne API access denied (HTTP 403) for {path}"
                )
            if r.status_code == 404:
                raise H1Error(f"HackerOne API endpoint not found: {path}")
            if 500 <= r.status_code < 600:
                time.sleep(1.0 + attempt)
                continue
            if r.status_code >= 400:
                # Truncate body to avoid leaking unexpected content
                snippet = (r.text or "")[:300]
                raise H1Error(
                    f"HackerOne API error {r.status_code} on {path}: {snippet}"
                )

            return r.json()

        raise H1Error(
            f"HackerOne API failed after {MAX_RETRIES} attempts "
            f"(last status: {last_status}) on {path}"
        )

    def _paginate(self, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            data = self._get(
                path,
                params={"page[number]": page, "page[size]": PAGE_SIZE},
            )
            batch = data.get("data") or []
            if not batch:
                break
            items.extend(batch)
            links = data.get("links") or {}
            if not links.get("next"):
                break
            page += 1
            if page > 200:  # hard safety
                break
        return items

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def list_programs(self) -> list[dict[str, Any]]:
        """Return all programs visible to the authenticated user."""
        raw = self._paginate("/hackers/programs")
        results: list[dict[str, Any]] = []
        for item in raw:
            attrs = item.get("attributes") or {}
            handle = attrs.get("handle")
            if not handle:
                continue
            results.append(
                {
                    "handle": handle,
                    "name": attrs.get("name") or handle,
                    "policy_url": f"https://hackerone.com/{handle}",
                    "offers_bounty": bool(attrs.get("offers_bounties")),
                    "submission_state": attrs.get("submission_state"),
                    "state": attrs.get("state"),
                }
            )
        return results

    def get_structured_scopes(self, handle: str) -> list[dict[str, Any]]:
        """Return structured scopes for a program."""
        raw = self._paginate(f"/hackers/programs/{handle}/structured_scopes")
        results: list[dict[str, Any]] = []
        for item in raw:
            attrs = item.get("attributes") or {}
            asset_type = attrs.get("asset_type")
            identifier = attrs.get("asset_identifier")
            if not asset_type or not identifier:
                continue
            results.append(
                {
                    "asset_type": asset_type,
                    "asset_identifier": identifier,
                    "instruction": attrs.get("instruction"),
                    "max_severity": attrs.get("max_severity"),
                    "eligible_for_bounty": bool(attrs.get("eligible_for_bounty")),
                    "eligible_for_submission": bool(
                        attrs.get("eligible_for_submission")
                    ),
                }
            )
        return results
