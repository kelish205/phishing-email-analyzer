"""Triage a suspicious email (.eml) and produce a scored verdict.

Checks sender alignment, SPF/DKIM/DMARC results, the Received chain, links
(including display text that does not match the real target), lookalike and
punycode domains and attachments with risky extensions. Output is a readable
report or JSON for a ticket or SOAR playbook.
"""

import argparse
import hashlib
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".bat", ".cmd",
    ".ps1", ".lnk", ".iso", ".img", ".vhd", ".one", ".msi", ".jar", ".docm", ".xlsm",
    ".pptm", ".html", ".htm", ".svg", ".zip", ".rar", ".7z",
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
URGENCY_TERMS = [
    "urgent", "immediately", "verify your account", "password expires", "suspended",
    "unusual activity", "wire transfer", "gift card", "invoice attached", "action required",
]
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)

WEIGHTS = {
    "spf_fail": 2, "dkim_fail": 2, "dmarc_fail": 3,
    "reply_to_mismatch": 2, "return_path_mismatch": 1,
    "display_name_spoof": 2, "link_text_mismatch": 3,
    "ip_url": 2, "shortener": 1, "punycode": 2,
    "risky_attachment": 3, "urgency_language": 1,
}


class LinkParser(HTMLParser):
    """Collect (href, visible text) pairs from HTML bodies."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def domain_of(address):
    _, addr = parseaddr(address or "")
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def registered_domain(host):
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def parse_auth_results(header_values):
    results = {}
    for value in header_values:
        for mech in ("spf", "dkim", "dmarc"):
            match = re.search(rf"\b{mech}=(\w+)", value, re.I)
            if match and mech not in results:
                results[mech] = match.group(1).lower()
    return results


def collect_bodies(msg):
    text, html, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename or "unnamed",
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            continue
        content = part.get_content() if hasattr(part, "get_content") else ""
        if part.get_content_type() == "text/html":
            html.append(content)
        elif part.get_content_type() == "text/plain":
            text.append(content)
    return "\n".join(text), "\n".join(html), attachments


def analyze_links(text, html):
    links = []
    parser = LinkParser()
    if html:
        parser.feed(html)
    for href, label in parser.links:
        links.append({"url": href, "text": label})
    known = {link["url"] for link in links}
    html_outside_links = re.sub(r"<a\b.*?</a>", " ", html, flags=re.I | re.S)
    for url in URL_RE.findall(text + "\n" + re.sub(r"<[^>]+>", " ", html_outside_links)):
        if url not in known:
            links.append({"url": url, "text": ""})
            known.add(url)

    for link in links:
        host = (urlparse(link["url"]).hostname or "").lower()
        link["host"] = host
        flags = []
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            flags.append("ip_url")
        if host in URL_SHORTENERS:
            flags.append("shortener")
        if "xn--" in host:
            flags.append("punycode")
        shown = URL_RE.search(link["text"]) or re.search(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", link["text"], re.I)
        if shown and host:
            shown_host = urlparse(shown.group(0) if "://" in shown.group(0) else "http://" + shown.group(0)).hostname or ""
            if registered_domain(shown_host) != registered_domain(host):
                flags.append("link_text_mismatch")
        link["flags"] = flags
    return links


def analyze(raw_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    findings = []

    from_header = str(msg.get("From", ""))
    display_name, from_addr = parseaddr(from_header)
    from_domain = domain_of(from_header)
    reply_to = getaddresses([str(v) for v in msg.get_all("Reply-To", [])])
    return_path = domain_of(str(msg.get("Return-Path", "")))

    auth = parse_auth_results([str(v) for v in msg.get_all("Authentication-Results", [])])
    for mech in ("spf", "dkim", "dmarc"):
        if auth.get(mech) in ("fail", "softfail", "permerror", "none"):
            findings.append((f"{mech}_fail", f"{mech.upper()} result: {auth[mech]}"))

    for _, addr in reply_to:
        rt_domain = addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""
        if rt_domain and registered_domain(rt_domain) != registered_domain(from_domain):
            findings.append(("reply_to_mismatch", f"Reply-To {addr} does not match From domain {from_domain}"))

    if return_path and from_domain and registered_domain(return_path) != registered_domain(from_domain):
        findings.append(("return_path_mismatch", f"Return-Path domain {return_path} differs from From domain {from_domain}"))

    name_domain = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", display_name or "", re.I)
    if name_domain and registered_domain(name_domain.group(0)) != registered_domain(from_domain):
        findings.append(("display_name_spoof", f"Display name shows {name_domain.group(0)} but sender is {from_addr}"))

    text, html, attachments = collect_bodies(msg)
    links = analyze_links(text, html)
    for link in links:
        for flag in link["flags"]:
            findings.append((flag, f"{flag.replace('_', ' ')}: {link['url']}"))

    for att in attachments:
        name = att["filename"].lower()
        ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        att["risky"] = ext in RISKY_EXTENSIONS
        if att["risky"]:
            findings.append(("risky_attachment", f"Attachment {att['filename']} has risky extension {ext}"))

    body = f"{msg.get('Subject', '')} {text} {re.sub(r'<[^>]+>', ' ', html)}".lower()
    hits = [term for term in URGENCY_TERMS if term in body]
    if hits:
        findings.append(("urgency_language", "Urgency or pressure language: " + ", ".join(hits)))

    score = sum(WEIGHTS.get(key, 0) for key, _ in findings)
    verdict = "malicious" if score >= 8 else "suspicious" if score >= 4 else "likely benign"

    received = [str(v) for v in msg.get_all("Received", [])]
    return {
        "subject": str(msg.get("Subject", "")),
        "from": from_header,
        "reply_to": [addr for _, addr in reply_to],
        "return_path": str(msg.get("Return-Path", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "authentication": auth,
        "received_hops": len(received),
        "first_hop": received[-1] if received else "",
        "links": links,
        "attachments": attachments,
        "findings": [{"rule": key, "detail": detail, "weight": WEIGHTS.get(key, 0)} for key, detail in findings],
        "score": score,
        "verdict": verdict,
    }


def render(report):
    lines = [
        f"Verdict: {report['verdict'].upper()}  (score {report['score']})",
        f"Subject: {report['subject']}",
        f"From: {report['from']}",
        f"Auth: " + ", ".join(f"{k}={v}" for k, v in report["authentication"].items()) if report["authentication"] else "Auth: no Authentication-Results header",
        f"Received hops: {report['received_hops']}",
        "",
        "Findings:",
    ]
    lines += [f"  [+{f['weight']}] {f['detail']}" for f in report["findings"]] or ["  none"]
    lines += ["", "Links:"]
    lines += [f"  {l['url']}" + (f"  flags={','.join(l['flags'])}" if l["flags"] else "") for l in report["links"]] or ["  none"]
    lines += ["", "Attachments:"]
    lines += [f"  {a['filename']}  {a['sha256']}" + ("  RISKY" if a["risky"] else "") for a in report["attachments"]] or ["  none"]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("eml", help="path to the .eml file")
    parser.add_argument("--json", action="store_true", help="output JSON")
    args = parser.parse_args(argv)
    with open(args.eml, "rb") as handle:
        report = analyze(handle.read())
    print(json.dumps(report, indent=2) if args.json else render(report))


if __name__ == "__main__":
    main()
