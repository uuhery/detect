"""
Cross-session audit persistence (~/.detect/audit_history.db).

Design: incremental delta auditing — not naive save/restore.

On save (after report):
  - Stores completed session snapshot (facts, chains, completed_checks)
  - Updates finding_timeline: first_seen / last_confirmed / status per chain

On load (before profiler returns):
  - Returns prior session for this target if one exists
  - build_resume_state() computes smart pending_checks:
      * skip: completed AND no findings (stable, waste to re-run)
      * re-run: had findings (detect resolution or new variants)
      * re-run: in verification_needed of prior speculative chain
      * run: never executed before
  - Pre-populates facts + attack_chains so analyze LLM has full context

Value: second audit focuses automatically on "where problems were" and
"what LLM suspected but couldn't confirm". Finding timeline enables
"unresolved for N days" reporting.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from switch_audit.core.logging import logger

_DB_PATH = Path.home() / ".detect" / "audit_history.db"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_sessions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    target           TEXT NOT NULL,
    device_os        TEXT,
    session_id       TEXT NOT NULL UNIQUE,
    started_at       TEXT,
    completed_at     TEXT,
    completed_checks TEXT,   -- JSON list of check_ids
    facts            TEXT,   -- JSON list of Fact dicts
    chains           TEXT    -- JSON list of AttackChain dicts
);

CREATE TABLE IF NOT EXISTS finding_timeline (
    target           TEXT NOT NULL,
    chain_title_hash TEXT NOT NULL,   -- sha1 of title (stable across sessions)
    chain_title      TEXT,
    severity         TEXT,
    first_seen_at    TEXT,
    last_confirmed_at TEXT,
    session_count    INTEGER DEFAULT 1,
    status           TEXT DEFAULT 'active',  -- 'active' | 'resolved'
    PRIMARY KEY (target, chain_title_hash)
);
"""


def _get_db() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def _title_hash(title: str) -> str:
    import hashlib
    return hashlib.sha1(title.strip().lower().encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------

def save_session(
    target: str,
    device_os: str,
    session_id: str,
    started_at: str,
    completed_checks: list[str],
    facts: list[dict],
    chains: list[dict],
) -> None:
    """Persist completed audit session. Called from report() node."""
    completed_at = datetime.now(timezone.utc).isoformat()
    try:
        conn = _get_db()

        conn.execute(
            """INSERT OR REPLACE INTO audit_sessions
               (target, device_os, session_id, started_at, completed_at,
                completed_checks, facts, chains)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                target, device_os, session_id, started_at, completed_at,
                json.dumps(completed_checks),
                json.dumps(facts),
                json.dumps(chains),
            ),
        )

        # Update finding timeline for confirmed/likely chains
        for chain in chains:
            if chain.get("confidence") in ("confirmed", "likely"):
                _upsert_timeline(conn, target, chain, completed_at)

        conn.commit()
        conn.close()
        logger.info(
            "session_store.saved",
            target=target,
            session_id=session_id[:8],
            facts=len(facts),
            chains=len(chains),
        )
    except Exception as exc:
        logger.warning("session_store.save_failed", error=str(exc))


def _upsert_timeline(conn: sqlite3.Connection, target: str, chain: dict, now: str) -> None:
    h = _title_hash(chain["title"])
    existing = conn.execute(
        "SELECT first_seen_at, session_count FROM finding_timeline WHERE target=? AND chain_title_hash=?",
        (target, h),
    ).fetchone()

    if existing:
        conn.execute(
            """UPDATE finding_timeline
               SET last_confirmed_at=?, session_count=session_count+1, status='active',
                   severity=?, chain_title=?
               WHERE target=? AND chain_title_hash=?""",
            (now, chain.get("severity", "medium"), chain["title"], target, h),
        )
    else:
        conn.execute(
            """INSERT INTO finding_timeline
               (target, chain_title_hash, chain_title, severity,
                first_seen_at, last_confirmed_at, session_count, status)
               VALUES (?,?,?,?,?,?,1,'active')""",
            (target, h, chain["title"], chain.get("severity", "medium"), now, now),
        )


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------

def load_prior_session(target: str) -> dict | None:
    """Return the most recent completed session for this target, or None."""
    try:
        conn = _get_db()
        row = conn.execute(
            """SELECT device_os, session_id, completed_at, completed_checks, facts, chains
               FROM audit_sessions WHERE target=?
               ORDER BY completed_at DESC LIMIT 1""",
            (target,),
        ).fetchone()
        conn.close()

        if not row:
            return None

        return {
            "device_os":        row[0],
            "session_id":       row[1],
            "completed_at":     row[2],
            "completed_checks": json.loads(row[3] or "[]"),
            "facts":            json.loads(row[4] or "[]"),
            "attack_chains":    json.loads(row[5] or "[]"),
        }
    except Exception as exc:
        logger.warning("session_store.load_failed", error=str(exc))
        return None


def load_finding_timeline(target: str) -> list[dict]:
    """Return active findings with age info for report enrichment."""
    try:
        conn = _get_db()
        rows = conn.execute(
            """SELECT chain_title, severity, first_seen_at, last_confirmed_at, session_count, status
               FROM finding_timeline WHERE target=? ORDER BY
               CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                             WHEN 'medium' THEN 2 ELSE 3 END""",
            (target,),
        ).fetchall()
        conn.close()
        return [
            {
                "title": r[0], "severity": r[1],
                "first_seen_at": r[2], "last_confirmed_at": r[3],
                "session_count": r[4], "status": r[5],
            }
            for r in rows
        ]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Smart pending_checks builder
# ---------------------------------------------------------------------------

def build_resume_state(prior: dict, methodology: list[dict]) -> dict:
    """Compute which checks to run on resume and pre-load prior evidence.

    Pending check selection logic:
      SKIP  — completed last session AND produced zero Facts (stable, clean)
      RE-RUN — completed last session AND produced Facts (detect resolution/changes)
      RE-RUN — in verification_needed of a prior speculative/likely chain
      RUN    — never executed before
    """
    prior_completed = set(prior["completed_checks"])
    prior_fact_checks = {f["source_check"] for f in prior["facts"]}
    prior_speculative_needed = {
        cid
        for c in prior["attack_chains"]
        if c.get("confidence") in ("speculative", "likely")
        for cid in c.get("verification_needed", [])
    }

    pending: list[str] = []
    skip: list[str] = []

    for check in methodology:
        cid = check["id"]
        if cid not in prior_completed:
            pending.append(cid)          # never ran
        elif cid in prior_speculative_needed:
            pending.append(cid)          # needed to confirm a prior hypothesis
        elif cid in prior_fact_checks:
            pending.append(cid)          # had findings — re-check for changes
        else:
            skip.append(cid)             # clean + stable → skip

    logger.info(
        "session_store.resume",
        target=prior.get("device_os", "?"),
        prior_session=prior["session_id"][:8],
        prior_completed_at=prior["completed_at"],
        pending=len(pending),
        skipped=len(skip),
        skip_ids=skip,
    )

    return {
        "facts":            prior["facts"],
        "attack_chains":    prior["attack_chains"],
        "completed_checks": prior["completed_checks"],
        "pending_checks":   pending,
    }
