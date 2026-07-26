#!/usr/bin/env python3
"""
Run the triage agent against an email file.

Usage:
    export ANTHROPIC_API_KEY=sk-...
    python run_triage.py samples/02_phish_cloud_storage.eml

Writes an audit line to audit_logs/triage_audit.jsonl and a case file to cases/.
"""

import sys
from pathlib import Path
from agent.triage_agent import triage


def main():
    if len(sys.argv) != 2:
        print("usage: python run_triage.py <path-to-.eml>")
        sys.exit(1)
    path = Path(sys.argv[1])
    raw = path.read_text(encoding="utf-8")
    record = triage(raw, source_label=path.name)

    v = record["agent_verdict"]
    a = record["governed_action"]
    print(f"\n{record['case_id']}  (autonomy L{record['autonomy_level']})")
    print(f"  verdict : {v['verdict']}  conf {v['confidence']}")
    print(f"  action  : {a['action']} — {a['reason']}")
    print(f"  case    : cases/{record['case_id']}.md")
    print(f"  audit   : audit_logs/triage_audit.jsonl\n")


if __name__ == "__main__":
    main()
