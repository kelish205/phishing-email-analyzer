# Phishing Email Analyzer

A Python tool for the first pass on a reported phishing email. Point it at an `.eml` file and it returns a scored verdict with the evidence behind it, the same checks I'd run by hand during triage.

No third-party packages are required. It uses only the Python standard library.

## What it checks

| Check | Why it matters |
|---|---|
| SPF, DKIM and DMARC results | Failed or missing authentication is a strong spoofing signal |
| From vs Reply-To and Return-Path | Replies routed to a different domain are common in BEC and credential phishing |
| Display name spoofing | A display name like `support@microsoft.com` hiding a different sender |
| Link text vs real target | Visible text says one domain while the href goes somewhere else |
| IP address URLs, URL shorteners and punycode | Common ways to hide the true destination |
| Attachments | SHA-256 hash for lookup plus a flag on risky extensions such as .html, .iso, .lnk and .one |
| Urgency language | Pressure phrases like "action required" or "password expires" |
| Received chain | Hop count and the first external hop for tracing the source |

Each finding has a weight. The total score maps to **likely benign**, **suspicious** or **malicious**. The weights are in `WEIGHTS` at the top of the script so they're easy to tune.

## Usage

```bash
python phish_analyzer.py tests/samples/phish.eml
python phish_analyzer.py tests/samples/phish.eml --json
```

Sample output:

```
Verdict: MALICIOUS  (score 22)
Subject: Action required: your password expires today
From: "support@microsoft.com" <alerts@micros0ft-support.com>
Auth: spf=fail, dkim=none, dmarc=fail

Findings:
  [+3] DMARC result: fail
  [+2] Reply-To helpdesk@freemail.example.org does not match From domain micros0ft-support.com
  [+2] Display name shows microsoft.com but sender is alerts@micros0ft-support.com
  [+3] link text mismatch: http://198.51.100.7/login.php
  [+3] Attachment Invoice_2026.html has risky extension .html
  ...
```

The `--json` output is built to drop into a ticket or a SOAR playbook step, so an analyst opens the case with the indicators already pulled out.

## Tests

```bash
python -m unittest discover tests
```

The samples in `tests/samples` are synthetic and use reserved example domains and documentation IP ranges.

## Ideas for next steps

- Send extracted URLs, hashes and IPs to the enrichment tool in [detection-engineering-lab](https://github.com/kelish205/detection-engineering-lab)
- Add lookalike domain scoring against a list of protected brands
- Parse `.msg` files from Outlook
