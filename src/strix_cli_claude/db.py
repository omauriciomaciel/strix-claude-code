"""SQLite-backed persistent store for H1 programs, targets, and findings.

Database lives at ~/.strix/strix.db (mode 0700 on parent dir).
Single writer pattern is enough for this workload; concurrent claims are
serialized with BEGIN IMMEDIATE in claim_next_target().
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DB_DIR = Path.home() / ".strix"
DB_PATH = DB_DIR / "strix.db"

# How long a row may stay 'in_progress' before another claimer can steal it.
STALE_CLAIM_SECONDS = 4 * 3600

SCHEMA_VERSION = 1


def _ensure_dir() -> None:
    DB_DIR.mkdir(mode=0o700, exist_ok=True)
    # If it pre-existed with looser perms, tighten it.
    try:
        os.chmod(DB_DIR, 0o700)
    except PermissionError:
        pass


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    _ensure_dir()
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Create tables and run migrations if needed."""
    with get_conn() as conn:
        current = conn.execute("PRAGMA user_version").fetchone()[0]

        if current < 1:
            conn.executescript(
                """
                BEGIN;

                CREATE TABLE IF NOT EXISTS programs (
                    handle           TEXT PRIMARY KEY,
                    name             TEXT,
                    policy_url       TEXT,
                    offers_bounty    INTEGER NOT NULL DEFAULT 0,
                    submission_state TEXT,
                    last_synced_at   INTEGER,
                    archived         INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS targets (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_handle      TEXT NOT NULL
                                          REFERENCES programs(handle) ON DELETE CASCADE,
                    asset_type          TEXT NOT NULL,
                    identifier          TEXT NOT NULL,
                    eligible_for_bounty INTEGER NOT NULL DEFAULT 1,
                    max_severity        TEXT,
                    instruction         TEXT,
                    scan_status         TEXT NOT NULL DEFAULT 'pending',
                                          -- pending|in_progress|done|skipped|error
                    scan_started_at     INTEGER,
                    scan_finished_at    INTEGER,
                    summary             TEXT,
                    UNIQUE(program_handle, asset_type, identifier)
                );
                CREATE INDEX IF NOT EXISTS idx_targets_status
                    ON targets(scan_status);
                CREATE INDEX IF NOT EXISTS idx_targets_program
                    ON targets(program_handle);
                CREATE INDEX IF NOT EXISTS idx_targets_asset_type
                    ON targets(asset_type);

                CREATE TABLE IF NOT EXISTS findings (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id     INTEGER NOT NULL
                                    REFERENCES targets(id) ON DELETE CASCADE,
                    title         TEXT NOT NULL,
                    severity      TEXT,
                    vuln_type     TEXT,
                    asset         TEXT,
                    poc_path      TEXT,
                    notes         TEXT,
                    status        TEXT NOT NULL DEFAULT 'candidate',
                                    -- candidate|confirmed|rejected|submitted|duplicate
                    h1_report_id  TEXT,
                    created_at    INTEGER NOT NULL,
                    updated_at    INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_status
                    ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_findings_target
                    ON findings(target_id);

                COMMIT;
                """
            )
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


# ---------------------------------------------------------------------------
# Programs
# ---------------------------------------------------------------------------

def upsert_program(
    conn: sqlite3.Connection,
    handle: str,
    name: str | None,
    policy_url: str | None,
    offers_bounty: bool,
    submission_state: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO programs
            (handle, name, policy_url, offers_bounty, submission_state, last_synced_at, archived)
        VALUES (?, ?, ?, ?, ?, ?, 0)
        ON CONFLICT(handle) DO UPDATE SET
            name             = excluded.name,
            policy_url       = excluded.policy_url,
            offers_bounty    = excluded.offers_bounty,
            submission_state = excluded.submission_state,
            last_synced_at   = excluded.last_synced_at,
            archived         = 0
        """,
        (
            handle,
            name,
            policy_url,
            1 if offers_bounty else 0,
            submission_state,
            int(time.time()),
        ),
    )


def list_programs(handle_filter: str | None = None) -> list[dict[str, Any]]:
    with get_conn() as conn:
        if handle_filter:
            rows = conn.execute(
                "SELECT * FROM programs WHERE handle LIKE ? AND archived=0 ORDER BY handle",
                (f"%{handle_filter}%",),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM programs WHERE archived=0 ORDER BY handle"
            ).fetchall()
    return [dict(r) for r in rows]


def mark_programs_archived_except(handles: list[str]) -> None:
    """Mark all programs NOT in `handles` as archived. Call after a full sync."""
    if not handles:
        return
    placeholders = ",".join("?" * len(handles))
    with get_conn() as conn:
        conn.execute(
            f"UPDATE programs SET archived=1 WHERE handle NOT IN ({placeholders})",
            handles,
        )


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

def upsert_target(
    conn: sqlite3.Connection,
    program_handle: str,
    asset_type: str,
    identifier: str,
    eligible_for_bounty: bool,
    max_severity: str | None,
    instruction: str | None,
) -> None:
    conn.execute(
        """
        INSERT INTO targets
            (program_handle, asset_type, identifier, eligible_for_bounty,
             max_severity, instruction, scan_status)
        VALUES (?, ?, ?, ?, ?, ?, 'pending')
        ON CONFLICT(program_handle, asset_type, identifier) DO UPDATE SET
            eligible_for_bounty = excluded.eligible_for_bounty,
            max_severity        = excluded.max_severity,
            instruction         = excluded.instruction
        """,
        (
            program_handle,
            asset_type,
            identifier,
            1 if eligible_for_bounty else 0,
            max_severity,
            instruction,
        ),
    )


def claim_next_target(
    program_handles: list[str] | None = None,
    asset_types: list[str] | None = None,
) -> dict[str, Any] | None:
    """Atomically claim the next pending (or stale in-progress) target.

    Returns the target row as a dict, or None if nothing eligible.
    Caller becomes responsible for calling mark_target() to settle the row.
    """
    stale_cutoff = int(time.time()) - STALE_CLAIM_SECONDS
    where_parts = [
        "(scan_status = 'pending'"
        " OR (scan_status = 'in_progress' AND COALESCE(scan_started_at, 0) < ?))"
    ]
    params: list[Any] = [stale_cutoff]

    if program_handles:
        ph = ",".join("?" * len(program_handles))
        where_parts.append(f"program_handle IN ({ph})")
        params.extend(program_handles)

    if asset_types:
        ph = ",".join("?" * len(asset_types))
        where_parts.append(f"asset_type IN ({ph})")
        params.extend(asset_types)

    where_sql = " AND ".join(where_parts)

    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            f"SELECT * FROM targets WHERE {where_sql} ORDER BY id LIMIT 1",
            params,
        ).fetchone()

        if row is None:
            conn.execute("COMMIT")
            return None

        conn.execute(
            "UPDATE targets SET scan_status='in_progress', scan_started_at=?"
            " WHERE id=?",
            (int(time.time()), row["id"]),
        )
        conn.execute("COMMIT")
        return dict(row)


def mark_target(
    target_id: int,
    status: str,
    summary: str | None = None,
) -> None:
    if status not in ("pending", "in_progress", "done", "skipped", "error"):
        raise ValueError(f"invalid scan_status: {status}")
    with get_conn() as conn:
        conn.execute(
            "UPDATE targets"
            " SET scan_status=?, scan_finished_at=?, summary=COALESCE(?, summary)"
            " WHERE id=?",
            (status, int(time.time()), summary, target_id),
        )


def scan_status_counts(program_handle: str | None = None) -> dict[str, int]:
    with get_conn() as conn:
        if program_handle:
            rows = conn.execute(
                "SELECT scan_status, COUNT(*) n FROM targets"
                " WHERE program_handle=? GROUP BY scan_status",
                (program_handle,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT scan_status, COUNT(*) n FROM targets GROUP BY scan_status"
            ).fetchall()
    return {r["scan_status"]: r["n"] for r in rows}


def scope_summary(program_handle: str | None = None) -> list[dict[str, Any]]:
    """Return per-(program × asset_type) counts.

    If program_handle is given, return rows for that program only with status breakdown.
    Otherwise return one row per (program, asset_type) with total + pending counts.
    """
    with get_conn() as conn:
        if program_handle:
            rows = conn.execute(
                """
                SELECT asset_type,
                       COUNT(*) AS total,
                       SUM(scan_status='pending')      AS pending,
                       SUM(scan_status='in_progress')  AS in_progress,
                       SUM(scan_status='done')         AS done,
                       SUM(scan_status='skipped')      AS skipped,
                       SUM(scan_status='error')        AS errored
                FROM targets
                WHERE program_handle=?
                GROUP BY asset_type
                ORDER BY total DESC
                """,
                (program_handle,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT t.program_handle,
                       p.offers_bounty,
                       t.asset_type,
                       COUNT(*) AS total,
                       SUM(t.scan_status='pending') AS pending,
                       SUM(t.scan_status='done')    AS done
                FROM targets t
                JOIN programs p ON p.handle = t.program_handle
                WHERE p.archived = 0
                GROUP BY t.program_handle, t.asset_type
                ORDER BY total DESC
                """
            ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def create_finding(
    target_id: int,
    title: str,
    severity: str | None,
    vuln_type: str | None,
    asset: str | None,
    poc_path: str | None,
    notes: str | None,
) -> int:
    now = int(time.time())
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO findings
                (target_id, title, severity, vuln_type, asset, poc_path, notes,
                 status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'candidate', ?, ?)
            """,
            (target_id, title, severity, vuln_type, asset, poc_path, notes, now, now),
        )
        return int(cur.lastrowid)


def update_finding_status(
    finding_id: int,
    status: str,
    extra_note: str | None = None,
) -> None:
    if status not in ("candidate", "confirmed", "rejected", "submitted", "duplicate"):
        raise ValueError(f"invalid finding status: {status}")
    now = int(time.time())
    with get_conn() as conn:
        if extra_note:
            conn.execute(
                "UPDATE findings"
                " SET status=?, notes=COALESCE(notes,'') || ?, updated_at=?"
                " WHERE id=?",
                (status, f"\n[{status}] {extra_note}", now, finding_id),
            )
        else:
            conn.execute(
                "UPDATE findings SET status=?, updated_at=? WHERE id=?",
                (status, now, finding_id),
            )


def list_findings(
    status: str | None = None,
    program_handle: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    where: list[str] = []
    params: list[Any] = []
    if status:
        where.append("f.status = ?")
        params.append(status)
    if program_handle:
        where.append("t.program_handle = ?")
        params.append(program_handle)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT f.*,
                   t.program_handle,
                   t.asset_type,
                   t.identifier AS target_identifier
            FROM findings f
            JOIN targets  t ON t.id = f.target_id
            {where_sql}
            ORDER BY f.created_at DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    return [dict(r) for r in rows]
