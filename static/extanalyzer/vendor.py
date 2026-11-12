"""I: brand domains. Groups the registrable domains the extension names as its own
(homepage_url, author email, mailto: addresses, privacy/terms/support/contact
links in its pages, URLs and addresses in _locales). More than one distinct
registrable domain gives a low `multiple-brand-domains` finding for human review
(rebranded or resold extensions, copied code, or a fake vendor page).
Free mail providers and browser stores do not count (intel/ignore.json).
"""

import glob
import json
import os
import re
from urllib.parse import urlsplit

from .common import finding

LINK_RE = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a\s*>""", re.I | re.S)
POLICY_RE = re.compile(r"privacy|policy|terms|support|help|contact|legal|about|faq|imprint|"
                       r"privacidade|termos|suporte|ajuda|contacto|pol[íi]tica|privacidad|t[ée]rminos|soporte", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63})\b")
URL_RE = re.compile(r"""https?://[^\s'"<>()]+""", re.I)
MAX_BYTES = 2 * 1024 * 1024


def _host(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(MAX_BYTES)
    except OSError:
        return ""


def collect(root, manifest):
    """[(host, where)] the extension presents as its own."""
    out = []
    hp = manifest.get("homepage_url")
    if isinstance(hp, str):
        out.append((_host(hp), "manifest homepage_url"))
    author = manifest.get("author")
    email = author.get("email") if isinstance(author, dict) else author if isinstance(author, str) else None
    if isinstance(email, str):
        for m in EMAIL_RE.finditer(email):
            out.append((m.group(1).lower(), "manifest author"))
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "_deob"]
        for fn in files:
            if not fn.lower().endswith((".html", ".htm")):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), root)
            text = _read(os.path.join(dirpath, fn))
            for m in LINK_RE.finditer(text):
                href, label = m.group(1), re.sub(r"<[^>]+>", " ", m.group(2))
                if href.lower().startswith("mailto:"):
                    for e in EMAIL_RE.finditer(href):
                        out.append((e.group(1).lower(), f"{rel} mailto link"))
                elif href.lower().startswith("http") and (POLICY_RE.search(href) or POLICY_RE.search(label)):
                    out.append((_host(href), f"{rel} link '{label.strip()[:40]}'"))
            for m in re.finditer(r"mailto:([^\"'\s>?]+)", text, re.I):
                for e in EMAIL_RE.finditer(m.group(1)):
                    out.append((e.group(1).lower(), f"{rel} mailto"))
    for path in sorted(glob.glob(os.path.join(root, "_locales", "*", "messages.json"))):
        rel = os.path.relpath(path, root)
        try:
            msgs = json.loads(_read(path).lstrip("﻿"))
        except ValueError:
            continue
        for key, v in (msgs.items() if isinstance(msgs, dict) else []):
            text = v.get("message", "") if isinstance(v, dict) else ""
            if not isinstance(text, str):
                continue
            for m in URL_RE.finditer(text):
                out.append((_host(m.group(0)), f"{rel} {key}"))
            for m in EMAIL_RE.finditer(text):
                out.append((m.group(1).lower(), f"{rel} {key}"))
    return [(h, w) for h, w in out if h and "." in h]


def analyze(root, manifest, registrable, intel):
    groups = {}
    for host, where in collect(root, manifest or {}):
        if host in intel.ignore_domains or host in intel.store_hosts or host in intel.mail_providers:
            continue
        reg = registrable(host)
        if reg in intel.mail_providers:
            continue
        groups.setdefault(reg, []).append(where)
    info = {"domains": {k: sorted(set(v))[:10] for k, v in sorted(groups.items())}}
    findings = []
    if len(groups) > 1:
        desc = "; ".join(f"{k} ({', '.join(sorted(set(v))[:3])})" for k, v in sorted(groups.items()))
        f = finding("VENDOR-MULTI-001", "Multiple brand domains", "low", "medium",
                    f"the extension presents {len(groups)} different registrable domains as its own: {desc}. "
                    "Review whether they belong to the same vendor (rebrand, resale or copied code)",
                    path="manifest.json", category="vendor")
        f["kind"] = "multiple-brand-domains"
        f["reachability"] = "n/a"
        f["scored"] = False
        findings.append(f)
    return findings, info
