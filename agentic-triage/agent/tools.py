"""
Deterministic analysis tools for the triage agent.

Design principle: the LLM does NOT parse headers or judge SPF/DKIM/DMARC itself.
These functions extract ground-truth facts from the raw email; the LLM reasons
OVER these facts. Keeping extraction deterministic is what makes the agent
auditable and keeps the LLM from hallucinating auth results.

Mirrors the 7-step methodology already documented in ../email-triage/methodology.md.
"""

import re
from email.parser import Parser
from email.policy import default


AUTH_RESULT_RE = re.compile(r"(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)


def parse_email(raw_text: str) -> dict:
    """Step 1-2: parse the raw email into structured headers + body."""
    msg = Parser(policy=default).parsestr(raw_text)
    return {
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "authentication_results": msg.get("Authentication-Results", ""),
        "received_spf": msg.get("Received-SPF", ""),
        "raw_headers": dict(msg.items()),
    }


def check_auth(parsed: dict) -> dict:
    """Step 3: extract SPF/DKIM/DMARC results deterministically. No LLM."""
    blob = " ".join([
        parsed.get("authentication_results", ""),
        parsed.get("received_spf", ""),
    ])
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for mech, value in AUTH_RESULT_RE.findall(blob):
        results[mech.lower()] = value.lower()
    return results


def extract_sender_domain(parsed: dict) -> str:
    """Pull the domain from the From header for alignment checks."""
    m = re.search(r"@([A-Za-z0-9.-]+)", parsed.get("from", ""))
    return m.group(1).lower() if m else ""


def extract_urls(raw_text: str) -> list:
    """Step 5: collect every URL and its host for payload evaluation."""
    urls = []
    for u in URL_RE.findall(raw_text):
        host = re.sub(r"^https?://", "", u).split("/")[0].lower()
        urls.append({"url": u, "host": host})
    return urls


def collect_facts(raw_text: str) -> dict:
    """Run all deterministic tools and return the fact bundle the LLM reasons over."""
    parsed = parse_email(raw_text)
    auth = check_auth(parsed)
    sender_domain = extract_sender_domain(parsed)
    urls = extract_urls(raw_text)
    return {
        "sender": parsed.get("from", ""),
        "sender_domain": sender_domain,
        "reply_to": parsed.get("reply_to", ""),
        "subject": parsed.get("subject", ""),
        "date": parsed.get("date", ""),
        "auth": auth,
        "dmarc_pass": auth.get("dmarc") == "pass",
        "urls": urls,
        "url_hosts": sorted({u["host"] for u in urls}),
    }
