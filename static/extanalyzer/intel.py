"""Threat intel and reference lists (static/intel/*.json), validated when loaded.

The built-in folder ships in the image. An optional local folder (the host's
~/analysis/intel, mounted read-only) is laid over it: its entries are added,
never replacing the built-in ones. Indicator entries need

  value, source, first_seen (YYYY-MM-DD), confidence (high|medium|low), expires (YYYY-MM-DD or null)

Invalid entries are dropped with a warning, and expired ones are ignored with a
warning. Nothing here is copied from analysed samples: entries are added on
purpose with bin/intel-add, which requires a source and a confidence.
"""

import datetime
import json
import os
import re

BUILTIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "intel")
CONFIDENCE = {"high", "medium", "low"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
INDICATOR_FILES = {"domains": "domains.json", "ips": "ips.json", "hashes": "hashes.json"}


def _date(s):
    try:
        return datetime.date.fromisoformat(s)
    except (TypeError, ValueError):
        return None


def validate_entry(e, today=None):
    """None if valid, else the reason. Expiry is reported separately."""
    if not isinstance(e, dict):
        return "not an object"
    if not isinstance(e.get("value"), str) or not e["value"].strip():
        return "missing value"
    if not isinstance(e.get("source"), str) or not e["source"].strip():
        return "missing source"
    if e.get("confidence") not in CONFIDENCE:
        return "confidence must be high, medium or low"
    if not isinstance(e.get("first_seen"), str) or not DATE_RE.match(e["first_seen"]) or not _date(e["first_seen"]):
        return "first_seen must be YYYY-MM-DD"
    exp = e.get("expires")
    if exp is not None and (not isinstance(exp, str) or not _date(exp)):
        return "expires must be YYYY-MM-DD or null"
    return None


def expired(e, today=None):
    exp = _date(e.get("expires")) if e.get("expires") else None
    return exp is not None and exp < (today or datetime.date.today())


class Intel:
    def __init__(self):
        self.domains, self.ips, self.hashes = [], [], []
        self.ignore_domains, self.common_suffixes = set(), ()
        self.libraries, self.disclosure = [], {}
        self.mail_providers, self.store_hosts = set(), set()
        self.loaded, self.warnings = [], []

    # ---- lookups ---------------------------------------------------------
    def domain_hits(self, host):
        host = host.lower().rstrip(".")
        return [e for e in self.domains if host == e["value"] or host.endswith("." + e["value"])]

    def ip_hits(self, ip):
        return [e for e in self.ips if ip == e["value"]]

    def hash_hits(self, sha256):
        return [e for e in self.hashes if sha256.lower() == e["value"]]

    def is_common(self, host):
        return any(host == s or host.endswith("." + s) for s in self.common_suffixes)

    def summary(self):
        return {"loaded": self.loaded, "counts": {"domains": len(self.domains), "ips": len(self.ips),
                                                  "hashes": len(self.hashes), "ignore": len(self.ignore_domains),
                                                  "libraries": len(self.libraries)}}


def _read(path, warnings):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        warnings.append(f"intel: cannot read {os.path.basename(path)}: {e}")
        return None


def _entries(doc, key="entries"):
    if isinstance(doc, dict):
        v = doc.get(key)
        return v if isinstance(v, list) else []
    return doc if isinstance(doc, list) and key == "entries" else []


def load(local_dir=None, builtin_dir=BUILTIN_DIR, today=None):
    it = Intel()
    for label, d in (("builtin", builtin_dir), ("local", local_dir)):
        if not d or not os.path.isdir(d):
            if label == "builtin":
                it.warnings.append(f"intel: built-in folder missing ({d})")
            continue
        it.loaded.append(label)
        for kind, fn in INDICATOR_FILES.items():
            doc = _read(os.path.join(d, fn), it.warnings)
            for e in _entries(doc):
                why = validate_entry(e)
                if why:
                    it.warnings.append(f"intel: {label}/{fn}: entry dropped ({why}): {str(e)[:80]}")
                    continue
                if expired(e, today):
                    it.warnings.append(f"intel: {label}/{fn}: expired entry ignored: {e['value']} (expired {e['expires']})")
                    continue
                e = dict(e, value=e["value"].strip().lower(), origin=label)
                getattr(it, kind).append(e)
        ign = _read(os.path.join(d, "ignore.json"), it.warnings)
        if ign:
            common = list(it.common_suffixes)
            for key, target in (("domains", "ignore"), ("common_suffixes", "common"),
                                ("mail_providers", "mail"), ("store_hosts", "store")):
                for e in _entries(ign, key):
                    why = validate_entry(e)
                    if why or expired(e, today):
                        it.warnings.append(f"intel: {label}/ignore.json: {key} entry skipped "
                                           f"({why or 'expired'}): {str(e)[:80]}")
                        continue
                    v = e["value"].strip().lower()
                    if target == "ignore":
                        it.ignore_domains.add(v)
                    elif target == "mail":
                        it.mail_providers.add(v)
                    elif target == "store":
                        it.store_hosts.add(v)
                    elif v not in common:
                        common.append(v)
            it.common_suffixes = tuple(common)
        libs = _read(os.path.join(d, "libraries.json"), it.warnings)
        for e in _entries(libs):
            try:
                pats = [re.compile(p) for p in e["patterns"]]
                it.libraries.append({"name": e["name"], "patterns": pats, "where": e.get("where", "header"),
                                     "source": e.get("source", "")})
            except (KeyError, TypeError, re.error) as ex:
                it.warnings.append(f"intel: {label}/libraries.json: entry dropped ({ex}): {str(e)[:80]}")
        disc = _read(os.path.join(d, "disclosure.json"), it.warnings)
        if isinstance(disc, dict):
            for name, c in (disc.get("categories") or {}).items():
                try:
                    it.disclosure[name] = {"keys": [re.compile(k, re.I) for k in c.get("keys", [])],
                                           "sources": set(c.get("sources", [])),
                                           "disclosure": [w.lower() for w in c.get("disclosure", [])]}
                except (TypeError, re.error) as ex:
                    it.warnings.append(f"intel: {label}/disclosure.json: {name} dropped ({ex})")
    return it
