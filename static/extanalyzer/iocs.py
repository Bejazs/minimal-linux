"""IOC extraction from all text files of the unpacked extension."""

import ipaddress
import os
import re
from urllib.parse import urlsplit

from .common import line_of

TEXT_EXT = {".js", ".mjs", ".cjs", ".html", ".htm", ".json", ".css", ".txt", ".xml", ".svg", ".map"}
MAX_FILE_BYTES = 8 * 1024 * 1024

URL_RE = re.compile(r"""\b(?:https?|wss?)://[^\s'"`<>()\\{}|^]{3,2048}""", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EXT_ID_RE = re.compile(r"(?<![a-z0-9])[a-p]{32}(?![a-z0-9])")

# Never IOCs (schemas, specs, placeholders, local).
IGNORE_DOMAINS = {"www.w3.org", "w3.org", "schema.org", "json-schema.org", "localhost", "xmlns.com",
                  "purl.org", "ns.adobe.com", "www.apache.org", "opensource.org", "mozilla.org",
                  "developer.mozilla.org", "developer.chrome.com", "reactjs.org", "fb.me", "github.com"}
# Kept as IOCs but marked common (excluded from Sigma to avoid noise).
COMMON_SUFFIXES = ("google.com", "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
                   "chrome.google.com", "cloudflare.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
                   "microsoft.com", "apple.com", "mozilla.net", "discord.com", "discordapp.com",
                   "telegram.org", "github.io", "githubusercontent.com", "amazonaws.com", "firebaseio.com")


def _is_common(domain):
    return any(domain == s or domain.endswith("." + s) for s in COMMON_SUFFIXES)


def extract(root: str, self_ids=()):
    urls, domains, ips, ext_ids = {}, {}, {}, {}

    def note(store, key, rel, ln, **extra):
        if key not in store:
            store[key] = {"value": key, "first_seen": f"{rel}:{ln}", "count": 0, **extra}
        store[key]["count"] += 1

    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "_deob"]
        for fn in files:
            if os.path.splitext(fn)[1].lower() not in TEXT_EXT:
                continue
            full = os.path.join(dirpath, fn)
            if os.path.getsize(full) > MAX_FILE_BYTES:
                continue
            rel = os.path.relpath(full, root)
            with open(full, encoding="utf-8", errors="replace") as f:
                text = f.read()
            for m in URL_RE.finditer(text):
                url = m.group(0).rstrip(".,;:'\"")
                try:
                    host = (urlsplit(url).hostname or "").lower()
                except ValueError:
                    continue
                if not host or host in IGNORE_DOMAINS or "${" in url or "{{" in url:
                    continue
                ln, _ = line_of(text, m.start())
                note(urls, url, rel, ln)
                try:
                    ipaddress.ip_address(host)
                    note(ips, host, rel, ln)
                except ValueError:
                    if "." in host:
                        note(domains, host, rel, ln, common=_is_common(host))
            for m in IPV4_RE.finditer(text):
                ip = m.group(0)
                try:
                    a = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if a.is_private or a.is_loopback or a.is_unspecified or a.is_reserved or a.is_multicast:
                    continue
                # skip version-like strings such as 1.2.3.4 in "version": "1.2.3.4"
                ctx = text[max(0, m.start() - 20):m.start()].lower()
                if "version" in ctx:
                    continue
                ln, _ = line_of(text, m.start())
                note(ips, ip, rel, ln)
            if fn.endswith((".js", ".html", ".json", ".mjs")):
                for m in EXT_ID_RE.finditer(text):
                    if m.group(0) in self_ids:
                        continue
                    ln, _ = line_of(text, m.start())
                    note(ext_ids, m.group(0), rel, ln)

    return {
        "urls": sorted(urls.values(), key=lambda x: x["value"]),
        "domains": sorted(domains.values(), key=lambda x: x["value"]),
        "ips": sorted(ips.values(), key=lambda x: x["value"]),
        "extension_ids": sorted(ext_ids.values(), key=lambda x: x["value"]),
    }
