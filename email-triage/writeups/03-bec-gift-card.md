# Writeup 03 — Business Email Compromise (CEO / gift-card) → verdict: MALICIOUS

**Source:** Sanitized representative sample modeled on well-documented BEC / CEO-fraud
patterns. Not a live capture. This case is important because BEC often has **no link
and no attachment** — the payload is pure social engineering, so auth checks alone
won't catch it.

## The email (representative)

- **From (display):** `Karen Whitfield` (the org's actual CEO's name)
- **From (address):** `karen.whitfield.ceo@gmail[.]com`  ← free webmail, not company domain
- **Reply-To:** `k.whitfield.exec@outlook[.]com`  ← different from From
- **Subject:** `Quick task`
- **Body:** "Are you at your desk? I'm going into a meeting and need you to grab some
  gift cards for a client. Send the codes as soon as you have them. Keep this between
  us for now — I'll explain later."

## Step 1 — Authentication results (representative)

- **SPF:** pass (for `gmail.com`)
- **DKIM:** pass (`d=gmail.com`)
- **DMARC:** pass (aligned to `gmail.com`)

**Teaching point:** Everything "passes" — because the attacker *really did* send it
from a real Gmail account. Auth confirms it came from that Gmail address; it says
nothing about the person being the CEO. **BEC defeats naive "auth pass = safe"
thinking entirely.** The signal here is identity and behavior, not authentication.

## Step 2 — Domain alignment / identity

- Display name = the real CEO; sending address = a **free webmail** account, not the
  company domain. Executives don't send internal requests from personal Gmail.
- **Reply-To differs from From** — a classic BEC tell (replies get funneled to an
  attacker-controlled inbox).

## Step 3 — Links / attachments

- **None.** That's the point — nothing for a URL/attachment scanner to catch.

## Step 4 — Social engineering (the whole payload)

- **Impersonated authority** (the CEO).
- **Urgency** ("going into a meeting," "as soon as you have them").
- **Secrecy** ("keep this between us").
- **Unusual financial request** (buy gift cards, send codes) — gift cards are
  irreversible and untraceable, which is exactly why BEC uses them.

## Step 5 — Verdict

**MALICIOUS — Business Email Compromise / CEO fraud.**

Authentication passing is irrelevant: the mail is from a personal webmail account
impersonating a named executive, with a mismatched Reply-To and a textbook
authority + urgency + secrecy + irreversible-payment pattern.

**Actions:** do **not** act on the request; verify the CEO through a **known**
channel (in person / known phone number — never the email's Reply-To); report to
security; warn finance/AP and other likely targets (assistants, finance staff);
block the sender and reply-to addresses; add the pattern to awareness training.

## Indicators recorded (defanged)

- From: `karen.whitfield.ceo@gmail[.]com` | Reply-To: `k.whitfield.exec@outlook[.]com`
- Payload: gift-card purchase + code exfiltration (financial fraud)
- Technique: **T1566** (Phishing) + social-engineering / financial fraud (BEC)
- Disposition: **do-not-act + verify out-of-band + report + warn targets**
