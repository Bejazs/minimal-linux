"""IOC extraction from all text files of the unpacked extension.

No IOC literals live here: hosts to ignore and common suffixes come from
intel/ignore.json (see intel.py). Each IOC lists the files it appears in, so
data-only occurrences can be grouped per file (refs.py).
"""

import ipaddress
import os
import re
from urllib.parse import urlsplit

from . import intel as intel_mod
from .common import line_of

TEXT_EXT = {".js", ".mjs", ".cjs", ".html", ".htm", ".json", ".css", ".txt", ".xml", ".svg", ".map"}
MAX_FILE_BYTES = 8 * 1024 * 1024

URL_RE = re.compile(r"""\b(?:https?|wss?)://[^\s'"`<>()\\{}|^]{3,2048}""", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EXT_ID_RE = re.compile(r"(?<![a-z0-9])[a-p]{32}(?![a-z0-9])")

MAX_FILES_PER_IOC = 20


def extract(root: str, self_ids=(), intel=None):
    """IOCs of every text file. Ignore and common lists come from intel/ignore.json."""
    it = intel or intel_mod.load()
    ignore = it.ignore_domains
    urls, domains, ips, ext_ids = {}, {}, {}, {}

    def note(store, key, rel, ln, **extra):
        if key not in store:
            store[key] = {"value": key, "first_seen": f"{rel}:{ln}", "count": 0, "files": {}, **extra}
        store[key]["count"] += 1
        files = store[key]["files"]
        if rel in files or len(files) < MAX_FILES_PER_IOC:
            files[rel] = files.get(rel, 0) + 1

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
                if not host or host in ignore or "${" in url or "{{" in url:
                    continue
                ln, _ = line_of(text, m.start())
                note(urls, url, rel, ln)
                try:
                    ipaddress.ip_address(host)
                    note(ips, host, rel, ln)
                except ValueError:
                    if "." in host:
                        note(domains, host, rel, ln, common=it.is_common(host))
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
