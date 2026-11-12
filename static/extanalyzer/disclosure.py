"""F: what the extension says it collects vs what its code sends.

Disclosure text: `_locales/*/messages.json` messages and the visible text of its
HTML pages (and .txt/.md files). Sent data: field names in object literals at
network sends (fetch/XHR/sendBeacon/axios/jQuery) in code that is not
unreachable (one hop through a variable), plus the flow source kinds at that
send (cookies, typed input). A category from intel/disclosure.json that
is sent but never mentioned gives a `disclosure-mismatch` finding: category
privacy, outside the malware score, confidence low by default because matching
prose to field names is approximate.
"""

import glob
import json
import os
import re

from .common import finding
from .flows import _args, _obj_prop, _t

MAX_BYTES = 2 * 1024 * 1024
TAG_RE = re.compile(r"<(script|style)\b.*?</\1\s*>|<[^>]+>", re.I | re.S)


def corpus(root):
    parts = []
    for path in glob.glob(os.path.join(root, "_locales", "*", "messages.json")):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                msgs = json.loads(f.read(MAX_BYTES).lstrip("﻿"))
        except (OSError, ValueError):
            continue
        for v in (msgs.values() if isinstance(msgs, dict) else []):
            if isinstance(v, dict):
                parts += [str(v.get("message", "")), str(v.get("description", ""))]
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "_deob"]
        for fn in files:
            low = fn.lower()
            if low.endswith((".html", ".htm", ".txt", ".md")):
                try:
                    with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as f:
                        text = f.read(MAX_BYTES)
                except OSError:
                    continue
                parts.append(TAG_RE.sub(" ", text) if low.endswith((".html", ".htm")) else text)
    return re.sub(r"\s+", " ", " ".join(parts)).lower()


def _keys(node, src, unit_decls, depth=0):
    out = set()
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "pair":
            k = n.child_by_field_name("key")
            if k is not None:
                out.add(_t(k, src).strip("'\"`"))
        elif n.type == "shorthand_property_identifier":
            out.add(_t(n, src))
        elif n.type == "identifier" and depth == 0 and _t(n, src) in unit_decls:
            out |= _keys(unit_decls[_t(n, src)], src, unit_decls, 1)
        stack.extend(n.named_children)
    return out


SEND_RE = re.compile(r"^(?:(?:window\.|self\.)?fetch|axios(?:\.\w+)?|\$\.(?:get|post|ajax|getJSON)|"
                     r"jQuery\.(?:get|post|ajax)|navigator\.sendBeacon)$|(?:^|\.)_?(?:xhr|request|req|socket|ws|websocket|http)\w*\.send$", re.I)
# request options, not sent data (fetch/axios/jQuery option objects)
REQUEST_OPTS = {"url", "method", "headers", "type", "datatype", "credentials", "mode", "cache", "contenttype",
                "async", "timeout", "redirect", "referrer", "referrerpolicy", "integrity", "keepalive", "signal",
                "withcredentials", "responsetype", "xhrfields", "crossdomain", "processdata", "baseurl", "params"}


def _payload_keys(arg, src, decls):
    """Field names of the data a call sends: the body/data of an options object, else the object itself."""
    if arg.type == "object":
        inner = _obj_prop(arg, "body", src) or _obj_prop(arg, "data", src)
        if inner is not None:
            return _keys(inner, src, decls)
    keys = _keys(arg, src, decls)
    return {k for k in keys if k.lower() not in REQUEST_OPTS}


class Send:
    __slots__ = ("file", "line", "api", "keys", "sources", "dest", "reachability")


def sends(pkg, flows):
    """Network sends in code that is not unreachable, with the field names in their arguments."""
    by_line = {}
    for fl in flows:
        if fl.sink == "network-send":
            by_line.setdefault((fl.file, fl.line), []).append(fl)
    out = []
    for rel, units in pkg.units.items():
        for u in units:
            decls, calls = {}, []
            stack = [u.tree.root_node]
            while stack:
                n = stack.pop()
                if n.type == "variable_declarator":
                    nm, val = n.child_by_field_name("name"), n.child_by_field_name("value")
                    if nm is not None and val is not None and nm.type == "identifier" and val.type == "object":
                        decls[_t(nm, u.src)] = val
                elif n.type == "call_expression":
                    f = n.child_by_field_name("function")
                    if f is not None and f.end_byte - f.start_byte <= 120 and SEND_RE.search(_t(f, u.src)):
                        calls.append((n, _t(f, u.src)))
                stack.extend(n.named_children)
            for c, api in calls:
                line = c.start_point[0] + 1 + u.line_offset
                st = pkg.status(rel, line)
                if st == "unreachable":
                    continue
                keys = set()
                for a in _args(c):
                    keys |= _payload_keys(a, u.src, decls)
                fls = by_line.get((rel, line), [])
                if fls and all((x.dest or {}).get("class") == "self" for x in fls):
                    continue
                s = Send()
                s.file, s.line, s.api, s.reachability = rel, line, api, st
                s.keys = {k for k in keys if k and len(k) < 60}
                s.sources = set().union(*(set(x.sources) for x in fls)) if fls else set()
                s.dest = next(((x.dest or {}).get("host") for x in fls if (x.dest or {}).get("host")), None)
                args = _args(c)
                if s.dest is None and args and args[0].type == "string":
                    m = re.match(r"^['\"`](?:https?|wss?)://([^/'\"`:?#]+)", _t(args[0], u.src))
                    s.dest = m.group(1).lower() if m else None
                out.append(s)
    return out


def analyze(pkg, flows, intel, root):
    if pkg is None or not intel.disclosure:
        return [], {"checked": False}
    text = corpus(root)
    sent = {}          # category -> [(send, evidence)]
    for sd in sends(pkg, flows):
        for cat, spec in intel.disclosure.items():
            ev = sorted(k for k in sd.keys if any(p.search(k) for p in spec["keys"]))
            src = sorted(sd.sources & spec["sources"])
            if ev or src:
                sent.setdefault(cat, []).append((sd, ev + [f"source:{x}" for x in src]))
    findings, info = [], {"checked": True, "disclosure_text_chars": len(text), "categories_sent": {}}
    n = 0
    for cat, items in sorted(sent.items()):
        words = intel.disclosure[cat]["disclosure"]
        disclosed = [w for w in words if w in text]
        info["categories_sent"][cat] = {"disclosed": bool(disclosed), "words_found": disclosed[:5],
                                        "sends": [{"path": f.file, "line": f.line, "api": f.api, "evidence": e}
                                                  for f, e in items[:10]]}
        if disclosed:
            continue
        n += 1
        fl, ev = items[0]
        where = fl.dest or "its destination"
        f = finding(f"PRIV-DISCLOSURE-{n:03d}", f"Sends {cat} without mentioning it", "low", "low",
                    f"{fl.api} sends data matching '{cat}' ({', '.join(ev[:5])}) to {where}, and no text in "
                    f"_locales or the extension pages mentions it (looked for: {', '.join(words[:6])}). "
                    "Heuristic: field names and prose are compared through a synonym list"
                    + ("; the package has no disclosure text at all" if not text.strip() else ""),
                    path=fl.file, line_start=fl.line, category="privacy", match=fl.api)
        f["kind"] = "disclosure-mismatch"
        f["reachability"] = fl.reachability
        f["scored"] = False
        findings.append(f)
    return findings, info
