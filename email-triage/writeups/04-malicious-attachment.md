# Writeup 04 — Malicious attachment (fake invoice) → verdict: MALICIOUS

**Source:** Sanitized representative sample modeled on well-documented
malicious-attachment campaigns (invoice/PO lures delivering macro or archive
payloads). Not a live capture; the attachment is **described, never executed**.

## The email (representative)

- **From (display):** `Accounts Payable`
- **From (address):** `billing@invoice-sys[.]net`  ← unfamiliar third-party domain
- **Subject:** `Outstanding invoice #INV-40912 — payment overdue`
- **Body:** "Please find the attached overdue invoice. Payment is 15 days past due;
  open the attached document and confirm to avoid a late fee."
- **Attachment:** `Invoice_40912.htm`  (also seen as `.xlsm`, `.iso`, or
  `invoice.pdf.exe` in this family)

## Step 1 — Authentication results (representative)

- **SPF:** **fail** (sending IP not authorized for the From domain) *or* pass on a
  throwaway domain
- **DKIM:** none / fail
- **DMARC:** **fail** (misaligned)

**Teaching point:** Unlike the lookalike and BEC cases, this family often **fails**
authentication outright — a spoof or a throwaway domain. An auth failure on an
inbound "invoice" from an unknown domain is an immediate elevation signal.

## Step 2 — Domain alignment / identity

- No prior relationship with `invoice-sys[.]net`; it doesn't match any known vendor.
- Generic "Accounts Payable" display name with an unfamiliar domain.

## Step 3 — The attachment (inspected as metadata, not opened)

- `.htm/.html` attachment → commonly a **local credential-harvest page** that opens
  in the browser and posts credentials to an attacker server (evades some link
  scanners because the "link" is inside the file).
- Variants in this family: **macro-enabled** Office (`.xlsm/.docm`) prompting "Enable
  Content" to run a downloader; **`.iso`/`.zip`** hiding an executable or `.lnk`;
  **double extension** (`invoice.pdf.exe`) disguising an EXE.
- Red flags without opening: unexpected attachment, high-risk file type, urgency to
  open it.

## Step 4 — Social engineering

- Financial pressure + urgency ("overdue," "late fee").
- Reason to open the file immediately, before thinking.

## Step 5 — Verdict

**MALICIOUS — phishing with malicious attachment (T1566.001).**

Unknown/unaligned sender, authentication failure, and a high-risk attachment paired
with financial urgency. The attachment is the payload; the email is the delivery.

**Actions:** do **not** open the attachment; if sandbox detonation is available, do
it in an **isolated** environment only; extract the file hash and check reputation;
block sender domain and the file hash; hunt the environment for other copies and for
anyone who already opened it (→ possible host compromise, isolate and investigate);
report and escalate.

## Indicators recorded (defanged)

- Sender: `billing@invoice-sys[.]net`
- Attachment: `Invoice_40912.htm` (+ family: `.xlsm/.iso/.pdf.exe`)
- Auth: SPF/DKIM/DMARC fail or unaligned
- Technique: **T1566.001** (Phishing: Spearphishing Attachment)
- Disposition: **quarantine + hash-block + hunt + escalate**
