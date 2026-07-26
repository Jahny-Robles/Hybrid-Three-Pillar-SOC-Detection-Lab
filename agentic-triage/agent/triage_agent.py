"""
The triage agent: orchestrates the full pipeline for one email.

Flow:
  raw email
    -> tools.collect_facts()      (deterministic extraction, no LLM)
    -> LLM reasoning over facts   (verdict + confidence + rationale)
    -> governance.decide_action() (what the agent is allowed to do)
    -> audit log + case record    (immutable record of everything)

The LLM is given ONLY the extracted facts, never asked to invent auth results.
Its job is judgment over evidence — exactly the human skill being encoded.
"""

import json
import os
import datetime as dt
from pathlib import Path

from . import tools
from . import governance

# ── LLM call ───────────────────────────────────────────────────────────────
# Uses a hosted API. Key is read from the environment — never hardcode it.
# Swap MODEL / endpoint freely; the contract is: facts in, strict JSON out.

MODEL = os.environ.get("TRIAGE_MODEL", "claude-sonnet-4-6")

SYSTEM_PROMPT = """You are a Tier 1 SOC email-triage analyst. You are given a
bundle of FACTS already extracted deterministically from an email (sender, auth
results, URLs). Do not invent facts. Reason over what you are given.

Return STRICT JSON only, no prose, with keys:
  verdict:     "LEGITIMATE" | "PHISHING" | "SUSPICIOUS"
  confidence:  float 0.0-1.0
  rationale:   short string, the 2-4 concrete tells driving the verdict
  tells:       array of short strings

Weight DMARC failure, sender/domain mismatch, payloads hosted on generic
infrastructure that impersonates a brand, and urgency/threat social engineering.
Calibrate confidence honestly: uncertainty MUST lower it."""


def _call_llm(facts: dict) -> dict:
    """Call the hosted LLM. Returns parsed verdict dict."""
    import anthropic  # imported here so the module loads even without the SDK
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
    resp = client.messages.create(
        model=MODEL,
        max_tokens=500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(facts, indent=2)}],
    )
    text = "".join(b.text for b in resp.content if b.type == "text")
    text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(text)


# ── Orchestration ──────────────────────────────────────────────────────────

BASE = Path(__file__).resolve().parent.parent
AUDIT_DIR = BASE / "audit_logs"
CASE_DIR = BASE / "cases"


def triage(raw_text: str, source_label: str = "unknown", llm=_call_llm) -> dict:
    """Run one email end to end. `llm` is injectable so tests can stub it."""
    started = dt.datetime.now(dt.timezone.utc).isoformat()

    facts = tools.collect_facts(raw_text)
    verdict = llm(facts)
    action = governance.decide_action(verdict["verdict"], float(verdict["confidence"]))

    case_id = dt.datetime.now(dt.timezone.utc).strftime("CASE-%Y%m%d-%H%M%S")
    record = {
        "case_id": case_id,
        "source": source_label,
        "started_utc": started,
        "autonomy_level": governance.AUTONOMY_LEVEL,
        "confidence_floor": governance.CONFIDENCE_FLOOR,
        "facts": facts,
        "agent_verdict": verdict,
        "governed_action": action,
        "human_review": None,  # filled in by the analyst when they act on it
    }

    _write_audit(record)
    _write_case(record)
    return record


def _write_audit(record: dict) -> None:
    """Append one immutable JSONL line. Full trace, never overwritten."""
    AUDIT_DIR.mkdir(exist_ok=True)
    line = json.dumps(record, separators=(",", ":"))
    with open(AUDIT_DIR / "triage_audit.jsonl", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _write_case(record: dict) -> None:
    """Human-readable case file for the analyst to review/approve."""
    CASE_DIR.mkdir(exist_ok=True)
    v = record["agent_verdict"]
    a = record["governed_action"]
    md = f"""# {record['case_id']}

- **Source:** {record['source']}
- **Run (UTC):** {record['started_utc']}
- **Autonomy level:** L{record['autonomy_level']}  (floor {record['confidence_floor']})

## Extracted facts
- Sender: `{record['facts']['sender']}`
- Sender domain: `{record['facts']['sender_domain']}`
- Auth: SPF={record['facts']['auth']['spf']} DKIM={record['facts']['auth']['dkim']} DMARC={record['facts']['auth']['dmarc']}
- URL hosts: {', '.join(f'`{h}`' for h in record['facts']['url_hosts']) or '(none)'}

## Agent verdict
- **{v['verdict']}**  (confidence {v['confidence']})
- Rationale: {v['rationale']}
- Tells: {'; '.join(v.get('tells', []))}

## Governed action
- **{a['action']}** — {a['reason']}

## Human review
- [ ] Agree / [ ] Override → verdict: ______   analyst: ______   notes:
"""
    with open(CASE_DIR / f"{record['case_id']}.md", "w", encoding="utf-8") as f:
        f.write(md)
