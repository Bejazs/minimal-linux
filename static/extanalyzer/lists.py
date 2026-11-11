"""Offline domain enrichment from public lists downloaded by `ext-analyze --update-lists`.

The analysis container has no network: lists are read from a read-only folder
(default /lists). Every list is optional; a missing or unreadable one is reported
as a warning and the analysis continues.

  tranco-top-1m.csv.zip   Tranco top 1M (rank,domain)          -> popularity
  public_suffix_list.dat  Public Suffix List                    -> registrable domain
  urlhaus.csv             URLhaus export (needs an abuse.ch key) -> known-malicious hosts
  meta.json               download dates written by the updater
"""

import csv
import io
import json
import os
import zipfile
from urllib.parse import urlsplit

TRANCO_FILE = "tranco-top-1m.csv.zip"
PSL_FILE = "public_suffix_list.dat"
URLHAUS_FILE = "urlhaus.csv"
META_FILE = "meta.json"

# Registrable domains ranked at or above this are treated as "common" (kept as IOCs,
# but left out of YARA/Sigma to avoid noise). URLhaus hits are never common.
COMMON_RANK = 10000


class PSL:
    def __init__(self, text):
        self.rules, self.wild, self.exc = set(), set(), set()
        for line in text.splitlines():
            line = line.strip().split()[0] if line.strip() else ""
            if not line or line.startswith("//"):
                continue
            line = line.lower()
            if line.startswith("!"):
                self.exc.add(line[1:])
            elif line.startswith("*."):
                self.wild.add(line[2:])
            else:
                self.rules.add(line)

    def registrable(self, host):
        labels = host.lower().strip(".").split(".")
        if len(labels) < 2:
            return host
        # longest matching public suffix (PSL algorithm, default rule "*")
        suffix_len = 1
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in self.exc:
                suffix_len = len(labels) - i - 1
                break
            if cand in self.rules:
                suffix_len = len(labels) - i
                break
            if i + 1 < len(labels) and ".".join(labels[i + 1:]) in self.wild:
                suffix_len = len(labels) - i
                break
        if suffix_len >= len(labels):
            return host
        return ".".join(labels[-(suffix_len + 1):])


def _naive_registrable(host):
    return ".".join(host.lower().split(".")[-2:])


def enrich(domains, lists_dir):
    """Annotate domain IOC dicts in place. Returns (info, warnings)."""
    info = {"dir": lists_dir, "loaded": [], "meta": {}}
    warnings = []
    if not lists_dir or not os.path.isdir(lists_dir):
        warnings.append("domain lists not available: run `ext-analyze --update-lists` for Tranco/PSL/URLhaus enrichment")
        return info, warnings
    try:
        with open(os.path.join(lists_dir, META_FILE), encoding="utf-8") as f:
            info["meta"] = json.load(f)
    except (OSError, ValueError):
        pass

    psl = None
    try:
        with open(os.path.join(lists_dir, PSL_FILE), encoding="utf-8", errors="replace") as f:
            psl = PSL(f.read())
        info["loaded"].append("psl")
    except OSError:
        warnings.append("Public Suffix List missing: registrable domains use the last two labels")
    reg = psl.registrable if psl else _naive_registrable

    hosts = {d["value"].lower() for d in domains}
    regs = {}
    for d in domains:
        d["registrable_domain"] = reg(d["value"])
        regs.setdefault(d["registrable_domain"], []).append(d)

    # Tranco: stream the CSV and keep only the domains we care about.
    path = os.path.join(lists_dir, TRANCO_FILE)
    try:
        ranks = {}
        with zipfile.ZipFile(path) as z:
            name = next(n for n in z.namelist() if n.endswith(".csv"))
            with z.open(name) as raw:
                for row in csv.reader(io.TextIOWrapper(raw, encoding="utf-8", errors="replace")):
                    if len(row) < 2 or not row[0].isdigit():
                        continue
                    dom = row[1].strip().lower()
                    if dom in regs or dom in hosts:
                        ranks[dom] = int(row[0])
        for d in domains:
            r = ranks.get(d["value"].lower()) or ranks.get(d["registrable_domain"])
            d["tranco_rank"] = r
            if r is not None and r <= COMMON_RANK:
                d["common"] = True
        info["loaded"].append("tranco")
    except (OSError, zipfile.BadZipFile, StopIteration, ValueError):
        warnings.append("Tranco list missing or unreadable: no popularity ranks")

    # URLhaus: any line containing a URL; the host is compared exactly.
    path = os.path.join(lists_dir, URLHAUS_FILE)
    try:
        hits = {}
        with open(path, encoding="utf-8", errors="replace") as f:
            for row in csv.reader(line for line in f if not line.startswith("#")):
                for field in row:
                    if field.startswith(("http://", "https://")):
                        try:
                            h = (urlsplit(field).hostname or "").lower()
                        except ValueError:
                            break
                        if h in hosts:
                            hits[h] = hits.get(h, 0) + 1
                        break
        for d in domains:
            n = hits.get(d["value"].lower(), 0)
            d["urlhaus_hits"] = n
            if n:
                d["common"] = False
        info["loaded"].append("urlhaus")
    except OSError:
        warnings.append("URLhaus list missing (needs an abuse.ch Auth-Key, see README): no reputation check")

    return info, warnings
