"""
ChromaDB-backed cross-session attack pattern memory.

Stores CONFIRMED attack chain narratives (not individual Facts).
The unit of storage is a reusable pattern: what combination of conditions
on what device OS leads to what exploitable path.

On retrieval, search_memory formats results as a "## Historical Patterns"
block injected into the analyze LLM's user message — giving it expert
knowledge from prior audits of similar devices.

All methods fail silently — ChromaDB unavailability never blocks the audit.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

_log = logging.getLogger(__name__)
_DB_PATH = Path.home() / ".detect" / "guides"
_COLLECTION = "chain_patterns"
_col = None


def _get_collection():
    global _col
    if _col is not None:
        return _col
    try:
        import chromadb
        from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

        _DB_PATH.mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(path=str(_DB_PATH))
        _col = client.get_or_create_collection(
            _COLLECTION, embedding_function=DefaultEmbeddingFunction()
        )
        return _col
    except Exception as exc:
        _log.warning("guide_store.init_failed error=%s", exc)
        return None


def _anonymize(text: str) -> str:
    text = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "{IP}", text)
    text = re.sub(r"(password|secret|key)\s+\S+", r"\1 {REDACTED}", text, flags=re.I)
    return text


def store_chain_pattern(device_os: str, chain: dict) -> None:
    """Store a confirmed attack chain as a reusable pattern for future audits.

    Stored text = full narrative, anonymised. Metadata carries severity + title
    for formatting. Upserted by content hash so re-running the same audit
    doesn't create duplicate entries.
    """
    col = _get_collection()
    if col is None:
        return
    try:
        narrative = _anonymize(chain.get("attack_narrative", ""))
        title = chain.get("title", "")
        severity = chain.get("severity", "medium")
        # Document = what the LLM will read: structured pattern description
        document = (
            f"[{severity.upper()}] {title}\n"
            f"Attack path: {narrative}"
        )
        doc_id = hashlib.md5(f"{device_os}:{title}:{narrative[:100]}".encode()).hexdigest()
        col.upsert(
            documents=[document],
            metadatas=[{"device_os": device_os, "severity": severity, "title": title}],
            ids=[doc_id],
        )
        _log.info("guide_store.stored device_os=%s title=%s", device_os, title)
    except Exception as exc:
        _log.warning("guide_store.store_failed error=%s", exc)


def search_chain_patterns(device_os: str, n: int = 5) -> str:
    """Return a formatted Markdown block of historical confirmed chains for
    this device OS, ready to inject into the analyze LLM context.

    Returns "" if no prior patterns exist or ChromaDB is unavailable.
    """
    col = _get_collection()
    if col is None:
        return ""
    try:
        where = {"device_os": {"$eq": device_os}} if device_os not in ("unknown", "") else None
        kwargs: dict = {
            "query_texts": [f"attack chain {device_os} security vulnerability"],
            "n_results": n,
        }
        if where:
            kwargs["where"] = where
        results = col.query(**kwargs)
        docs = results.get("documents", [[]])[0]
        if not docs:
            return ""

        lines = [
            f"## Historical Attack Patterns ({device_os} — {len(docs)} prior confirmed chain(s))",
            "",
            "These patterns were confirmed on similar devices in prior audit sessions.",
            "Use them to recognise familiar attack paths faster — but still require raw_evidence.",
            "",
        ]
        for doc in docs:
            lines.append(f"- {doc}")
        return "\n".join(lines)
    except Exception as exc:
        _log.warning("guide_store.search_failed error=%s", exc)
        return ""
