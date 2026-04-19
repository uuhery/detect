"""
Graph nodes — pure functions: AuditState → dict (partial state update).

Phase 1 node contract:
  profiler()  — identify device OS + select access method (runs once)
  adviser()   — pick next check_id from pending_checks (sequential in Phase 1)
  executor()  — run check via DeviceAccessLayer, always returns structured CheckResult
  analyze()   — extract Facts and AttackChains from the latest CheckResult
  report()    — write final Markdown audit report

Each node only returns the fields it modifies.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from langchain_openai import ChatOpenAI

logging.getLogger("netmiko").setLevel(logging.WARNING)
logging.getLogger("paramiko").setLevel(logging.WARNING)

from switch_audit.core.config import settings
from switch_audit.core.langgraph.state import AttackChain, AuditState, CheckResult, Fact
from switch_audit.core.logging import logger
from switch_audit.prompts import load_analyze_prompt
from switch_audit.tools import ssh_exec
from switch_audit.tools.crypto import decode_type7
from switch_audit.tools.device_access import (
    classify_device_os,
    execute_check,
    load_methodology,
    probe_napalm,
)
from switch_audit.tools.guide_store import search_findings, store_finding

_TYPE7_RE = re.compile(r"((?:password|key)\s+7\s+([0-9A-Fa-f]{4,}))")

_llm = ChatOpenAI(
    model=settings.DEFAULT_LLM_MODEL,
    temperature=settings.DEFAULT_LLM_TEMPERATURE,
    api_key=settings.OPENAI_API_KEY,
    base_url=settings.OPENAI_BASE_URL,
)


# ---------------------------------------------------------------------------
# profiler — runs once; identifies device and selects access method
# ---------------------------------------------------------------------------

def profiler(state: AuditState) -> dict:
    """Identify device OS and determine which access layer to use.

    Idempotent: returns {} if device_vendor is already set (subsequent loop iterations).

    Steps:
      1. SSH `show version` for raw device identity text
      2. classify_device_os() → canonical device_os + vendor
      3. probe_napalm() → confirm NAPALM connectivity if driver exists
      4. Initialize pending_checks from audit_methodology.yaml
    """
    if state.get("device_vendor"):
        return {}

    logger.info("node.profiler", target=state["target"])

    raw = ssh_exec(
        host=state["target"],
        port=settings.SSH_PORT,
        username=settings.SSH_USERNAME,
        password=settings.SSH_PASSWORD,
        command="show version",
        timeout=settings.SSH_TIMEOUT,
        device_type=settings.SSH_DEVICE_TYPE,
    )

    device_os, device_vendor = classify_device_os(raw)
    napalm_ok = probe_napalm(state["target"], device_os)
    access_method = "napalm" if napalm_ok else "ntc-templates"

    pending = [c["id"] for c in load_methodology()]

    logger.info(
        "node.profiler.done",
        device_os=device_os,
        device_vendor=device_vendor,
        access_method=access_method,
        pending_checks=len(pending),
    )

    return {
        "device_os": device_os,
        "device_vendor": device_vendor,
        "access_method": access_method,
        "pending_checks": pending,
        "completed_checks": [],
        "check_results": [],
    }


# ---------------------------------------------------------------------------
# search_memory — query ChromaDB for prior findings on this device type
# ---------------------------------------------------------------------------

def search_memory(state: AuditState) -> dict:
    """Search historical findings for this device OS (runs once per session).

    Idempotent: returns {} if enriched_strategy is already populated.
    Populates enriched_strategy for the adviser node (used in Phase 2
    when adviser becomes LLM-driven; no-op for Phase 1 sequential adviser).
    """
    if state.get("enriched_strategy"):
        return {}

    device_os = state.get("device_os", "unknown")
    logger.info("node.search_memory", device_os=device_os)

    findings = search_findings(device_os, f"security audit {device_os}", n=5)

    if not findings:
        logger.info("node.search_memory.cold_start", device_os=device_os)
        return {"enriched_strategy": ""}

    lines = [
        f"[{f['meta'].get('severity', '?')}][{f['meta'].get('check_id', '?')}] {f['content']}"
        for f in findings
    ]
    strategy = "\n".join(lines)
    logger.info("node.search_memory.found", device_os=device_os, count=len(findings))
    return {"enriched_strategy": strategy}


# ---------------------------------------------------------------------------
# store_success — persist new findings from this trial into ChromaDB
# ---------------------------------------------------------------------------

def store_success(state: AuditState) -> dict:
    """Store anonymised findings from the current trial into ChromaDB.

    Stores:
    - New Facts produced in this trial (low-severity defaults to 'medium')
    - AttackChains that first became 'confirmed' in this trial
    """
    device_os = state.get("device_os", "unknown")
    current_trial = state["trial_count"] - 1  # executor already incremented

    new_facts = [f for f in state.get("facts", []) if f["trial"] == current_trial]
    for fact in new_facts:
        store_finding(
            device_os=device_os,
            check_id=fact["source_check"],
            content=fact["content"],
            severity="medium",
        )

    new_confirmed_chains = [
        c for c in state.get("attack_chains", [])
        if c.get("confidence") == "confirmed" and c.get("trial_first_seen") == current_trial
    ]
    for chain in new_confirmed_chains:
        store_finding(
            device_os=device_os,
            check_id="attack_chain",
            content=f"{chain['title']}: {chain['attack_narrative']}",
            severity=chain.get("severity", "medium"),
        )

    logger.info(
        "node.store_success.done",
        device_os=device_os,
        facts_stored=len(new_facts),
        chains_stored=len(new_confirmed_chains),
    )
    return {}


# ---------------------------------------------------------------------------
# adviser — selects next check_id from pending_checks
# ---------------------------------------------------------------------------

def adviser(state: AuditState) -> dict:
    """Select the next audit check to execute.

    Phase 1: sequential — first item in pending_checks.
    Phase 2: LLM-driven selection based on attack_chains.verification_needed
             and ChromaDB enriched_strategy (not yet implemented).
    """
    pending = state.get("pending_checks", [])
    if not pending:
        return {"proposed_check_id": ""}

    # Phase 1: sequential order (methodology defines priority by position)
    proposed = pending[0]
    logger.info("node.adviser", proposed_check_id=proposed, remaining=len(pending))
    return {"proposed_check_id": proposed}


# ---------------------------------------------------------------------------
# executor — runs the proposed check via DeviceAccessLayer
# ---------------------------------------------------------------------------

def executor(state: AuditState) -> dict:
    """Execute the proposed check; always produces a structured CheckResult.

    Delegates access-layer selection to execute_check(), which tries:
      NAPALM → ntc-templates → ssh-raw
    in that order, returning the first that succeeds.
    """
    check_id = state.get("proposed_check_id", "")
    if not check_id:
        logger.warning("node.executor.no_check_id")
        return {}

    logger.info(
        "node.executor",
        check_id=check_id,
        trial=state["trial_count"],
        access_method=state.get("access_method"),
    )

    result = execute_check(check_id, state)

    logger.info(
        "node.executor.done",
        check_id=check_id,
        access_method=result["access_method"],
        confidence=result["confidence"],
    )

    pending = [c for c in state.get("pending_checks", []) if c != check_id]
    completed = state.get("completed_checks", []) + [check_id]

    return {
        "check_results": state.get("check_results", []) + [result],
        "pending_checks": pending,
        "completed_checks": completed,
        "trial_count": state["trial_count"] + 1,
    }


# ---------------------------------------------------------------------------
# analyze — extract Facts and AttackChains from latest CheckResult
# ---------------------------------------------------------------------------

def _extract_text_for_precompute(result: CheckResult) -> str:
    """Return any raw text in a CheckResult for algorithmic processing (e.g. Type 7 decode)."""
    data = result.get("data", {})
    # NAPALM config: {"running": "...", "startup": "...", "candidate": ""}
    if "running" in data:
        return data["running"]
    # ssh-raw: {"raw": "...", "status": "ok"}
    if "raw" in data:
        return data["raw"]
    return ""


def _precompute_decoded_passwords(text: str) -> str:
    """Decode Cisco Type 7 passwords found in config text, injected as ground truth."""
    lines = []
    for m in _TYPE7_RE.finditer(text):
        plaintext = decode_type7(m.group(2))
        lines.append(f"  {m.group(1)}  →  plaintext: {plaintext}")
    if not lines:
        return ""
    return (
        "\n\n## Pre-decoded Values (algorithmically verified — treat as ground truth)\n"
        "Type 7 passwords found in this check's data have been decoded. "
        "When creating Facts about these passwords, include the plaintext in `content`.\n"
        + "\n".join(lines)
    )


def _build_analyze_context(state: AuditState) -> str:
    """Build the user message for analyze()'s LLM call.

    Sections:
      1. Latest CheckResult — check_id, access_method, confidence, security_relevance, data
      2. Existing Facts summary (id + source_check + content)
      3. Existing AttackChains summary (id + title + fact_ids + confidence)
      4. ID hints (prevent LLM from hallucinating IDs)
      5. Pending checks (for Rule 6 speculative chain anchoring)
      6. Pre-decoded values (Type 7 passwords, algorithmic ground truth)
    """
    results = state.get("check_results", [])
    if not results:
        return "(no check results — analyze should not have been called)"

    latest = results[-1]
    current_trial = state["trial_count"] - 1  # executor already incremented trial_count

    # Load check metadata for security_relevance
    from switch_audit.tools.device_access import get_check_spec
    check_spec = get_check_spec(latest["check_id"]) or {}

    # Format data for LLM: readable JSON, capped to avoid context overflow
    data_str = json.dumps(latest["data"], indent=2, default=str)
    if len(data_str) > 8000:
        data_str = data_str[:8000] + "\n... (truncated)"

    latest_section = (
        f"## Latest Check: {latest['check_id']} (trial={current_trial})\n"
        f"Access method: {latest['access_method']} | confidence: {latest['confidence']}\n"
        f"Security relevance: {check_spec.get('security_relevance', '')}\n\n"
        f"Collected data:\n```json\n{data_str}\n```"
    )

    # Existing facts (full list, condensed: no raw_evidence to save tokens)
    existing_facts = state.get("facts", [])
    if existing_facts:
        facts_lines = [
            f"  [{f['id']}] (from check '{f['source_check']}', trial={f['trial']}): {f['content']}"
            for f in existing_facts
        ]
        facts_section = (
            "## Existing Facts (reference by id when building chains)\n"
            + "\n".join(facts_lines)
        )
    else:
        facts_section = "## Existing Facts\n  (none yet)"

    # Existing chains
    existing_chains = state.get("attack_chains", [])
    if existing_chains:
        chains_lines = [
            f"  [{c['id']}] \"{c['title']}\" | facts={c['fact_ids']} | "
            f"severity={c['severity']} | confidence={c['confidence']}"
            for c in existing_chains
        ]
        chains_section = (
            "## Existing AttackChains "
            "(set existing_chain_id to update, or null to create new)\n"
            + "\n".join(chains_lines)
        )
    else:
        chains_section = "## Existing AttackChains\n  (none yet)"

    # ID hints
    facts_this_trial = sum(1 for f in existing_facts if f["trial"] == current_trial)
    id_hint = (
        f"## ID Hints\n"
        f"  Current trial: {current_trial}\n"
        f"  New Fact IDs: f{current_trial}-{{index}} starting at f{current_trial}-{facts_this_trial}\n"
        f"  New Chain IDs (existing_chain_id=null only): c{current_trial}-{{index}}"
    )

    # Pending checks (for speculative chain anchoring)
    pending = state.get("pending_checks", [])
    if pending:
        pending_section = (
            "## Pending checks (not yet executed — use check_ids in verification_needed)\n"
            "You may anchor speculative chains to these, but do NOT create Facts from them.\n"
            + "\n".join(f"  - {cid}" for cid in pending)
        )
    else:
        pending_section = "## Pending checks\n  (all checks completed)"

    # Precomputed Type 7 passwords
    precomputed = _precompute_decoded_passwords(_extract_text_for_precompute(latest))

    return "\n\n".join([
        latest_section, facts_section, chains_section, id_hint, pending_section
    ]) + precomputed


def _parse_analyze_response(raw: str, current_trial: int) -> tuple[list, list]:
    """Parse LLM output into (new_facts, chain_updates).

    Three-layer defense:
      1. Regex extracts JSON block
      2. json.loads parses
      3. Field-level .get() with defaults — one bad field doesn't crash the whole response
    """
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    text = match.group(1) if match else raw.strip()

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("analyze.parse_failed", trial=current_trial, raw_preview=raw[:300])
        return [], []

    # Parse new_facts
    new_facts: list[dict] = []
    for i, f in enumerate(data.get("new_facts", [])):
        if not isinstance(f, dict):
            continue
        content = f.get("content", "").strip()
        if not content:
            continue
        new_facts.append({
            "id": f.get("id", f"f{current_trial}-{i}"),
            "trial": f.get("trial", current_trial),
            "source_check": f.get("source_check") or f.get("source_command", ""),
            "content": content,
            "raw_evidence": f.get("raw_evidence", ""),
        })

    # Parse chain_updates with confidence enforcement
    chain_updates: list[dict] = []
    for i, c in enumerate(data.get("chain_updates", [])):
        if not isinstance(c, dict) or not c.get("title", "").strip():
            continue
        fact_ids = c.get("fact_ids", [])
        verification = c.get("verification_needed", [])
        if not isinstance(fact_ids, list):
            fact_ids = [fact_ids] if fact_ids else []
        if not isinstance(verification, list):
            verification = [verification] if verification else []

        # Confidence is code-derived from verification_needed, not LLM-reported
        llm_confidence = c.get("confidence", "speculative")
        if llm_confidence == "refuted":
            confidence, verification = "refuted", []
        elif verification:
            confidence = llm_confidence if llm_confidence in ("speculative", "likely") else "likely"
        else:
            confidence = "confirmed"

        chain_updates.append({
            "existing_chain_id": c.get("existing_chain_id"),
            "id": c.get("id", f"c{current_trial}-{i}"),
            "title": c["title"].strip(),
            "fact_ids": fact_ids,
            "attack_narrative": c.get("attack_narrative", ""),
            "severity": c.get("severity", "medium"),
            "confidence": confidence,
            "verification_needed": verification,
            "trial_first_seen": c.get("trial_first_seen", current_trial),
        })

    return new_facts, chain_updates


def _find_overlapping_chain(existing: list, new_fact_ids: list) -> str | None:
    """Auto-match a new chain to an existing one by fact overlap (deduplication).

    Both directions must have ≥50% coverage and ≥2 shared facts.
    This prevents merging chains that share only one anchor fact but diverge in impact.
    """
    new_set = set(new_fact_ids)
    if len(new_set) < 2:
        return None
    best_id, best_overlap = None, 0
    for chain in existing:
        existing_set = set(chain.get("fact_ids", []))
        if not existing_set:
            continue
        overlap = len(new_set & existing_set)
        if (
            overlap >= 2
            and overlap >= len(new_set) // 2
            and overlap >= len(existing_set) // 2
            and overlap > best_overlap
        ):
            best_overlap, best_id = overlap, chain["id"]
    return best_id


def _upsert_attack_chains(existing: list, updates: list) -> list:
    """Merge chain_updates into existing attack_chains list.

    Rules:
    - existing_chain_id match → update (confidence is monotonically non-decreasing,
      except refuted which overrides everything)
    - no match → append new chain
    """
    _RANK = {"speculative": 0, "likely": 1, "confirmed": 2}
    id_to_idx = {c["id"]: i for i, c in enumerate(existing)}
    result = [dict(c) for c in existing]

    for update in updates:
        existing_id = update.get("existing_chain_id")
        if not existing_id or existing_id not in id_to_idx:
            auto = _find_overlapping_chain(result, update.get("fact_ids", []))
            if auto:
                logger.info("upsert.auto_dedup", new=update.get("title"), matched=auto)
                existing_id = auto

        if existing_id and existing_id in id_to_idx:
            t = result[id_to_idx[existing_id]]
            new_conf = update.get("confidence", "speculative")

            if new_conf == "refuted":
                t["confidence"] = "refuted"
                t["verification_needed"] = []
            elif t.get("confidence") != "refuted":
                if _RANK.get(new_conf, 0) > _RANK.get(t.get("confidence", "speculative"), 0):
                    t["confidence"] = new_conf

            existing_fids = set(t.get("fact_ids", []))
            for fid in update.get("fact_ids", []):
                if fid not in existing_fids:
                    t.setdefault("fact_ids", []).append(fid)
                    existing_fids.add(fid)

            if update.get("verification_needed") is not None:
                t["verification_needed"] = update["verification_needed"]
            if update.get("attack_narrative"):
                t["attack_narrative"] = update["attack_narrative"]
        else:
            new_chain = {k: update[k] for k in (
                "id", "title", "fact_ids", "attack_narrative",
                "severity", "confidence", "verification_needed", "trial_first_seen"
            ) if k in update}
            id_to_idx[new_chain["id"]] = len(result)
            result.append(new_chain)

    return result


def analyze(state: AuditState) -> dict:
    """Extract Facts and update AttackChains from the latest CheckResult.

    Skips if:
    - No check_results in state yet
    - Latest result access_method == "unavailable" (no data to analyze)
    """
    results = state.get("check_results", [])
    if not results:
        logger.warning("analyze.no_results")
        return {}

    latest = results[-1]
    current_trial = state["trial_count"] - 1

    if latest["access_method"] == "unavailable":
        logger.info("analyze.skipped_unavailable", check_id=latest["check_id"])
        return {}

    logger.info(
        "node.analyze",
        check_id=latest["check_id"],
        trial=current_trial,
        access_method=latest["access_method"],
        existing_facts=len(state.get("facts", [])),
        existing_chains=len(state.get("attack_chains", [])),
    )

    user_msg = _build_analyze_context(state)
    response = _llm.invoke([
        {"role": "system", "content": load_analyze_prompt()},
        {"role": "user", "content": user_msg},
    ])

    new_facts, chain_updates = _parse_analyze_response(
        response.content.strip(), current_trial=current_trial
    )

    updated_facts = state.get("facts", []) + new_facts
    updated_chains = _upsert_attack_chains(
        existing=state.get("attack_chains", []),
        updates=chain_updates,
    )

    # Clean up verification_needed: remove already-completed check IDs
    completed = set(state.get("completed_checks", []))
    for chain in updated_chains:
        chain["verification_needed"] = [
            cid for cid in chain.get("verification_needed", [])
            if cid not in completed
        ]

    logger.info(
        "node.analyze.done",
        new_facts=len(new_facts),
        chain_updates=len(chain_updates),
        total_facts=len(updated_facts),
        total_chains=len(updated_chains),
    )

    return {
        "facts": updated_facts,
        "attack_chains": updated_chains,
    }


# ---------------------------------------------------------------------------
# report — write final Markdown audit report
# ---------------------------------------------------------------------------

def _get_config_text(check_results: list[CheckResult]) -> str:
    """Extract raw running config text from check_results for credential scanning."""
    for r in check_results:
        if r["check_id"] == "running_config":
            data = r.get("data", {})
            return data.get("running") or data.get("raw", "")
    return ""


def report(state: AuditState) -> dict:
    """Generate the final Markdown audit report.

    Reads from: check_results, facts, attack_chains, device_os, target, started_at
    Writes: status ("completed"), report_path
    """
    target = state["target"]
    session_id = state["session_id"]
    started_at = state.get("started_at", "")
    ended_at = datetime.now(timezone.utc).isoformat()
    device_os = state.get("device_os", "unknown")
    device_vendor = state.get("device_vendor", "Unknown")
    access_method = state.get("access_method", "unknown")
    check_results = state.get("check_results", [])
    facts = state.get("facts", [])
    chains = state.get("attack_chains", [])

    # Severity ordering for report
    _SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    active_chains = [c for c in chains if c.get("confidence") != "refuted"]
    refuted_chains = [c for c in chains if c.get("confidence") == "refuted"]
    active_chains.sort(key=lambda c: _SEV_RANK.get(c.get("severity", "low"), 3))

    severity_counts = {s: 0 for s in ("critical", "high", "medium", "low")}
    for c in active_chains:
        sev = c.get("severity", "low")
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Decode Type 7 credentials from running config
    config_text = _get_config_text(check_results)
    decoded_creds: list[str] = []
    for m in _TYPE7_RE.finditer(config_text):
        plaintext = decode_type7(m.group(2))
        decoded_creds.append(f"| `{m.group(1)}` | `{plaintext}` |")

    lines: list[str] = [
        f"# Switch Security Audit Report",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| Target | `{target}` |",
        f"| Device | {device_vendor} `{device_os}` |",
        f"| Access method | {access_method} |",
        f"| Session | `{session_id[:8]}` |",
        f"| Started | {started_at} |",
        f"| Completed | {ended_at} |",
        f"| Checks executed | {len(check_results)} |",
        f"| Facts extracted | {len(facts)} |",
        f"",
        f"## Executive Summary",
        f"",
        f"| Severity | Count |",
        f"|---|---|",
        *(f"| {s.capitalize()} | {severity_counts[s]} |" for s in ("critical", "high", "medium", "low")),
        f"",
    ]

    if decoded_creds:
        lines += [
            f"## Recovered Credentials",
            f"",
            f"| Cipher | Plaintext |",
            f"|---|---|",
            *decoded_creds,
            f"",
        ]

    lines += [f"## Attack Chains ({len(active_chains)} active)", f""]
    for i, chain in enumerate(active_chains, 1):
        severity = chain.get("severity", "low").upper()
        confidence = chain.get("confidence", "speculative")
        fact_ids = ", ".join(chain.get("fact_ids", []))
        lines += [
            f"### {i}. {chain['title']}",
            f"**Severity:** {severity} | **Confidence:** {confidence} | **Facts:** {fact_ids}",
            f"",
            chain.get("attack_narrative", ""),
            f"",
        ]
        if chain.get("verification_needed"):
            lines += [
                f"*Still needs verification: {', '.join(chain['verification_needed'])}*",
                f"",
            ]

    if refuted_chains:
        lines += [f"## Refuted Hypotheses ({len(refuted_chains)})", f""]
        for chain in refuted_chains:
            lines += [f"- ~~{chain['title']}~~ — {chain.get('attack_narrative', '')}", f""]

    lines += [f"## Facts Index ({len(facts)} total)", f""]
    for f in facts:
        lines += [
            f"**{f['id']}** (check: `{f['source_check']}`, trial {f['trial']}): {f['content']}",
            f"> {f['raw_evidence']}",
            f"",
        ]

    lines += [
        f"## Checks Executed",
        f"",
        f"| Check ID | Access method | Confidence |",
        f"|---|---|---|",
        *(
            f"| {r['check_id']} | {r['access_method']} | {r['confidence']} |"
            for r in check_results
        ),
        f"",
        f"---",
        f"*Generated by switch-audit Phase 1*",
    ]

    # Write report
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)
    report_path = str(report_dir / f"{target}_{session_id[:8]}.md")
    Path(report_path).write_text("\n".join(lines), encoding="utf-8")

    logger.info("node.report.done", path=report_path, chains=len(active_chains), facts=len(facts))

    return {
        "status": "completed",
        "report_path": report_path,
    }
