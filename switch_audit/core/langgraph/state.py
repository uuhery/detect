"""
AuditState: the single source of truth for one audit session.

Design principles:
  1. Every field has exactly one writer — noted in the docstring.
  2. Structured data only — no raw CLI text in analysis fields.
  3. Minimal surface — no ephemeral scratchpad fields in the persisted state.

Node read/write contract:
  profiler()  writes: device_os, device_vendor, access_method,
                      pending_checks, completed_checks, check_results (empty)
  adviser()   writes: proposed_check_id
  executor()  writes: check_results (append), pending_checks (pop), completed_checks (append),
                      trial_count (+1)
  analyze()   writes: facts (append), attack_chains (upsert)
  report()    writes: status ("completed"), report_path
"""

from typing_extensions import TypedDict


# ---------------------------------------------------------------------------
# Evidence unit — what executor produces
# ---------------------------------------------------------------------------

class CheckResult(TypedDict):
    """Structured evidence from one audit check.

    'data' is always a dict, never raw text.
      - NAPALM path:        data = the getter's return value (already a dict/list → wrapped)
      - ntc-templates path: data = {"rows": [<parsed dicts>]}
      - ssh-raw path:       data = {"raw": "<output>", "status": "ok"|"ssh_error"}

    'access_method' + 'confidence' record how reliably the data was obtained,
    letting analyze() weight evidence appropriately.
    """
    check_id: str
    data: dict
    access_method: str   # "napalm" | "ntc-templates" | "ssh-raw" | "unavailable"
    confidence: str      # "high" | "medium" | "low"
    timestamp: str       # ISO 8601 UTC


# ---------------------------------------------------------------------------
# Analysis units — what analyze() produces
# ---------------------------------------------------------------------------

class Fact(TypedDict):
    """One atomic security-relevant observation from a single check result.

    Atomic means: one condition, one source, one sentence.
    Facts are the raw material for AttackChain construction.
    """
    id: str              # "f{trial}-{index}", globally unique
    trial: int           # which executor trial produced the source CheckResult
    source_check: str    # check_id of the CheckResult this fact came from
    content: str         # one-sentence observation; no inference, no impact assessment
    raw_evidence: str    # verbatim excerpt from check_result.data proving this fact


class AttackChain(TypedDict):
    """A multi-step exploitable path inferred from ≥2 facts from ≥2 different checks.

    The core value of an AI audit agent over a rule engine:
    rules fire on individual facts; this captures cross-check compound paths.

    confidence drives the audit loop:
      speculative/likely  → verification_needed check_ids are fed back to adviser
      confirmed           → no further probing needed for this chain
    """
    id: str                         # "c{trial}-{index}", globally unique
    title: str                      # one-line summary, e.g. "Weak password → HTTP admin access"
    fact_ids: list[str]             # ≥2 Fact IDs spanning ≥2 source_check values
    attack_narrative: str           # "Attacker can: 1) ... → 2) ... → 3) gain <impact>"
    severity: str                   # "critical" | "high" | "medium" | "low"
    confidence: str                 # "confirmed" | "likely" | "speculative" | "refuted"
    verification_needed: list[str]  # check_ids that would raise confidence; [] when confirmed
    trial_first_seen: int


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

class AuditState(TypedDict):
    # ── Session identity (set at init, never modified) ──────────────────────
    session_id: str   # LangGraph thread_id; enables checkpoint resume
    target: str       # IP or hostname; immutable
    started_at: str   # ISO 8601 UTC; used for audit window in report

    # ── Device profile (written once by profiler) ────────────────────────────
    device_os: str      # canonical OS token: "cisco_iosxe" | "frr" | "arista_eos" | ...
    device_vendor: str  # human name: "Cisco" | "FRR" | "Arista" | "Unknown"
    access_method: str  # "napalm" | "ntc-templates" | "ssh-raw"
                        # determines which DeviceAccessLayer path executor uses

    # ── Audit plan (pending shrinks, completed grows; both written by executor) ─
    pending_checks: list[str]    # check IDs not yet executed
    completed_checks: list[str]  # check IDs executed (in order)

    # ── Evidence (append-only, written by executor) ─────────────────────────
    check_results: list[CheckResult]  # one entry per executed check; always structured

    # ── Analysis outputs (written by analyze) ───────────────────────────────
    facts: list[Fact]
    attack_chains: list[AttackChain]

    # ── Per-iteration handoff (adviser writes, executor reads) ───────────────
    proposed_check_id: str
    adviser_reasoning: str  # one-sentence explanation of why this check was chosen

    # ── Memory enrichment (search_memory writes, adviser reads in Phase 2) ──
    enriched_strategy: str  # historical findings summary from ChromaDB; "" if cold start

    # ── Control ─────────────────────────────────────────────────────────────
    trial_count: int
    status: str      # "running" | "completed" | "error"
    report_path: str
