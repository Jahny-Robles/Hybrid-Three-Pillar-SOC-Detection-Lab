#!/usr/bin/env python3
"""
Batch triage: run the agent over EVERY .eml file in a folder.

Usage:
    export ANTHROPIC_API_KEY=sk-...          (Windows: $env:ANTHROPIC_API_KEY = "sk-...")
    python run_batch.py                      # triages everything in samples/
    python run_batch.py path\\to\\folder      # or point it at another folder

For each email it writes the usual case file + audit line (same as run_triage.py),
then prints a ranked summary table: highest-confidence PHISHING first, so the
things a human should look at soonest float to the top. Also writes that summary
to batch_summary.md so you have a shareable artifact.

Stays true to the pilot's L0 design: every verdict is recommend-only. Nothing is
actioned, nothing in your mailbox is touched — these are exported .eml files.
"""

import sys
from pathlib import Path
from agent.triage_agent import triage

BASE = Path(__file__).resolve().parent


def sort_key(row: dict):
    """Rank: PHISHING first, then SUSPICIOUS, then LEGITIMATE; within each, highest confidence first."""
    order = {"PHISHING": 0, "SUSPICIOUS": 1, "LEGITIMATE": 2}
    verdict = row["verdict"].upper()
    return (order.get(verdict, 3), -row["confidence"])


def main():
    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE / "samples"
    if not folder.is_dir():
        print(f"Not a folder: {folder}")
        sys.exit(1)

    emls = sorted(folder.glob("*.eml"))
    if not emls:
        print(f"No .eml files found in {folder}")
        sys.exit(1)

    print(f"Triaging {len(emls)} email(s) from {folder}\n")

    rows = []
    for path in emls:
        raw = path.read_text(encoding="utf-8")
        record = triage(raw, source_label=path.name)
        v = record["agent_verdict"]
        a = record["governed_action"]
        rows.append({
            "file": path.name,
            "verdict": v["verdict"],
            "confidence": float(v["confidence"]),
            "action": a["action"],
            "case_id": record["case_id"],
        })
        print(f"  {path.name:40s} -> {v['verdict']:11s} {v['confidence']:.2f}  [{a['action']}]")

    rows.sort(key=sort_key)

    # Build a ranked summary table (Markdown) — highest-priority items on top.
    lines = [
        "# Batch triage summary",
        "",
        f"Triaged {len(rows)} emails. Ranked by priority (phishing + high confidence first).",
        "All verdicts are recommend-only (autonomy L0) — a human reviews every case.",
        "",
        "| Priority | File | Verdict | Confidence | Action | Case |",
        "|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(rows, 1):
        lines.append(
            f"| {i} | {r['file']} | {r['verdict']} | {r['confidence']:.2f} | {r['action']} | {r['case_id']} |"
        )
    summary = "\n".join(lines) + "\n"

    (BASE / "batch_summary.md").write_text(summary, encoding="utf-8")

    print(f"\nRanked summary (top = look at first):\n")
    for i, r in enumerate(rows, 1):
        print(f"  {i}. {r['verdict']:11s} {r['confidence']:.2f}  {r['file']}")
    print(f"\nFull table written to batch_summary.md")
    print(f"Individual case files in cases/, audit trail in audit_logs/\n")


if __name__ == "__main__":
    main()
