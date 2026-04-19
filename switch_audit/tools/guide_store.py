"""
ChromaDB-backed audit memory.

Stores anonymised security findings and attack chain summaries so future
audits of the same device type start with prior knowledge instead of cold.

All methods fail silently — a missing chromadb install or unavailable
embedding endpoint must never crash the audit pipeline.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

_log = logging.getLogger(__name__)

_DB_PATH = Path.home() / ".detect" / "guides"
_COLLECTION = "audit_findings"

_col = None  # lazy-initialised singleton


def _get_collection():
    global _col
    if _col is not None:
        return _col
    try:
        import chromadb
        from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction

        from switch_audit.core.config import settings

        _DB_PATH.mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(path=str(_DB_PATH))
        ef = OpenAIEmbeddingFunction(
            api_key=settings.OPENAI_API_KEY,
            model_name="text-embedding-3-small",
        )
        _col = client.get_or_create_collection(_COLLECTION, embedding_function=ef)
        _log.info("guide_store.ready", path=str(_DB_PATH))
        return _col
    except Exception as exc:
        _log.warning("guide_store.init_failed error=%s", exc)
        return None


def _anonymize(text: str) -> str:
    text = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "{IP}", text)
    text = re.sub(r"(password|secret|key)\s+\S+", r"\1 {REDACTED}", text, flags=re.I)
    return text


def search_findings(device_os: str, context: str, n: int = 5) -> list[dict]:
    """Return up to n relevant prior findings for device_os + context query."""
    col = _get_collection()
    if col is None:
        return []
    try:
        where = {"device_os": {"$eq": device_os}} if device_os not in ("unknown", "") else None
        kwargs: dict = {"query_texts": [f"{device_os} {context}"], "n_results": n}
        if where:
            kwargs["where"] = where
        results = col.query(**kwargs)
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        if not docs:
            return []
        return [{"content": d, "meta": m} for d, m in zip(docs, metas)]
    except Exception as exc:
        _log.warning("guide_store.search_failed error=%s", exc)
        return []


def store_finding(
    device_os: str,
    check_id: str,
    content: str,
    severity: str,
) -> None:
    """Upsert one anonymised finding into the collection."""
    col = _get_collection()
    if col is None:
        return
    try:
        anon = _anonymize(content)
        doc_id = hashlib.md5(f"{device_os}:{check_id}:{anon}".encode()).hexdigest()
        col.upsert(
            documents=[anon],
            metadatas=[{"device_os": device_os, "check_id": check_id, "severity": severity}],
            ids=[doc_id],
        )
    except Exception as exc:
        _log.warning("guide_store.store_failed error=%s", exc)
