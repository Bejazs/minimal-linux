"""Semantic detectors B1-B9 on the syntax tree and the data flows (docs/rules.md).

Each detector looks at code structure only and never runs anything. B7 folds
string constants (concatenation, String.fromCharCode with numeric literals,
array join, atob/percent-decoding of literals) with a size limit, in Python.
Findings carry `category: detector`, a reachability status and a snippet; a
record of each match goes to behaviors.json (`detectors[]`).

  DET-SESSION-SEND      B1 session data -> network send to a non-primary destination
  DET-CRED-DYNURL       B2 credentialed request whose URL comes from data
  DET-CMD-DISPATCH      B3 network data selects which privileged action runs
  DET-WEAK-ORIGIN       B4 substring/prefix origin checks in message handlers
  DET-HIDDEN-WINDOW     B5 off-screen/tiny/minimized/unfocused windows (+ idle gating)
  DET-IDENTITY-HEADERS  B6 rewriting User-Agent, Sec-CH-UA*, Referer, Sec-Fetch-*
  DET-OBF-STRING        B7 URLs, domains or API names built to hide them
  DET-CODE-INJECT       B8 executeScript code/files, eval/Function, script src from data
  DET-FORCED-UI         B9 alert() in a content script + window focus/maximize
"""

import base64
import binascii
import json
import os
import re
from urllib.parse import unquote

from . import jsast
from .common import _BARE_DOMAIN_RE, finding
from .flows import PRIV_TEXT_RE, _args, _callee, _is_func, _obj_prop, _t

DETECTORS = {
    "DET-SESSION-SEND": {
        "plan": "B1", "title": "Session data sent over the network to a non-primary destination",
        "attack": ["T1539", "T1041"], "attack_gap": None,
        "why": "cookies or web storage reach fetch/XHR/sendBeacon/WebSocket (body, URL or headers); "
               "COMB-SESSION-EXFIL raises this to critical",
    },
    "DET-CRED-DYNURL": {
        "plan": "B2", "title": "Credentialed request to a URL taken from data",
        "attack": ["T1185"], "attack_gap": None,
        "why": "a request with credentials:'include' or withCredentials uses a URL that came from the "
               "network, a message or storage, so a remote party chooses where the user's session is used",
    },
    "DET-CMD-DISPATCH": {
        "plan": "B3", "title": "Network data selects which privileged action runs",
        "attack": ["T1071.001", "T1102"],
        "attack_gap": "ATT&CK has no technique for remote task execution inside end-user browsers",
        "why": "a value from a network response or WebSocket message is a switch discriminant or a handler "
               "name, and the branches it selects use tabs/scripting/cookies/requests/navigation",
    },
    "DET-WEAK-ORIGIN": {
        "plan": "B4", "title": "Weak origin check in a message handler",
        "attack": [],
        "attack_gap": "a weak origin check is a vulnerability (any page can reach the handler), "
                      "not an adversary technique",
        "why": "origin/URL/hostname compared with indexOf/includes/match/search/test or an open "
               "startsWith/endsWith, which a look-alike host passes",
    },
    "DET-HIDDEN-WINDOW": {
        "plan": "B5", "title": "Window opened hidden from the user",
        "attack": ["T1564.003"], "attack_gap": None,
        "why": "windows.create/update with off-screen coordinates, a size of 100 px or less, "
               "state 'minimized' or focused:false",
    },
    "DET-IDENTITY-HEADERS": {
        "plan": "B6", "title": "Rewrites browser identity request headers",
        "attack": [],
        "attack_gap": "no ATT&CK technique for rewriting browser identity headers; relevant to session "
                      "proxying (T1185) when combined with DET-CRED-DYNURL",
        "why": "declarativeNetRequest modifyHeaders or webRequest changes User-Agent, Sec-CH-UA*, Referer "
               "or Sec-Fetch-*, which makes requests look like they come from another browser or page",
    },
    "DET-OBF-STRING": {
        "plan": "B7", "title": "Sensitive string built to hide it",
        "attack": ["T1027"], "attack_gap": None,
        "why": "a URL, domain or sensitive API name is assembled from character codes, arrays, encoded "
               "literals or split fragments; the value was recovered by folding literals, without running code",
    },
    "DET-CODE-INJECT": {
        "plan": "B8", "title": "Code injection or dynamic code execution",
        "attack": ["T1059.007"], "attack_gap": None,
        "why": "executeScript with code or non-constant files, eval/Function on non-literal input, "
               "or a script element whose src is not a packaged file",
    },
    "DET-FORCED-UI": {
        "plan": "B9", "title": "Dialogs in pages combined with forced window focus",
        "attack": [],
        "attack_gap": "UI coercion (dialogs plus stolen focus) has no ATT&CK technique",
        "why": "a content script calls alert/confirm/prompt and the extension focuses, maximizes or "
               "full-screens browser windows; contextual signal only",
    },
}

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

MAX_FOLD_LEN = 4096
MAX_FOLD_DEPTH = 40
MAX_PER_DETECTOR = 50

ORIGINISH_RE = re.compile(r"(?:^|\.)(?:origin|hostname|host|href|url|referrer|domain)$", re.I)
WEAK_METHODS = {"indexOf", "lastIndexOf", "includes", "match", "search", "startsWith", "endsWith", "test"}
HANDLER_RE = re.compile(r"(?:^|\.)(?:onMessage(?:External)?|onConnect(?:External)?)\.addListener$")
IDENTITY_HEADERS_RE = re.compile(r"^(?:user-agent|referer|sec-ch-ua.*|sec-fetch-.*)$", re.I)
NET_SINK_RE = re.compile(r"^(?:(?:window\.|self\.)?fetch|navigator\.sendBeacon|\$\.(?:ajax|get|post|getJSON)|"
                         r"jQuery\.(?:ajax|get|post|getJSON)|axios(?:\.\w+)?)$|\.open$")
COOKIE_API_RE = re.compile(r"^(?:chrome|browser)\.cookies\.\w+$")
SENSITIVE_WORDS = {"cookie", "cookies", "getall", "document.cookie", "eval", "function", "executescript",
                   "localstorage", "sessionstorage", "password", "sendbeacon", "xmlhttprequest", "fetch",
                   "webrequest", "chrome.cookies", "debugger", "management", "withcredentials"}
URL_RE = re.compile(r"^(?:https?|wss?)://([^/\s:?#]+)", re.I)


class Ctx:
    def __init__(self, pkg, flows):
        self.pkg, self.flows = pkg, flows
        self.findings, self.records = [], []
        self.counts = {}
        self._idx = {}
        cs = pkg.manifest.get("content_scripts") or []
        self.content = {jsast.norm_ref(s) for c in cs for s in c.get("js") or []}

    def idx(self, unit):
        k = id(unit)
        if k not in self._idx:
            self._idx[k] = Index(unit)
        return self._idx[k]

    def emit(self, did, severity, confidence, reason, path, line, match=None, extra_attack=(), details=None):
        n = self.counts.get(did, 0) + 1
        if n > MAX_PER_DETECTOR:
            return None
        self.counts[did] = n
        d = DETECTORS[did]
        f = finding(f"{did}-{n:03d}", d["title"], severity, confidence, f"{d['why']}. {reason}",
                    path=path, line_start=line, attack=list(d["attack"]) + list(extra_attack),
                    category="detector", match=match)
        f["detector"] = d["plan"]
        if d["attack_gap"]:
            f["attack_gap"] = d["attack_gap"]
        f["reachability"] = self.pkg.status(path, line) if path else "n/a"
        fn = self.pkg.function_label(path, line) if path and line else None
        if fn:
            f["function"] = fn
        self.findings.append(f)
        self.records.append({"detector": did, "plan": d["plan"], "finding": f["id"], "severity": severity,
                             "confidence": confidence, "reachability": f["reachability"],
                             "location": {"path": path, "line": line}, "details": details or {}})
        return f


def _line(unit, node):
    return node.start_point[0] + 1 + unit.line_offset


def _walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.named_children))


def _units(pkg):
    for rel in sorted(pkg.units):
        for u in pkg.units[rel]:
            yield u


class Index:
    """One walk per unit: calls (with callee text), assignments, declarators, subscripts, functions."""

    __slots__ = ("calls", "assigns", "decls", "subs", "funcs")

    def __init__(self, unit):
        src = unit.src
        self.calls, self.assigns, self.decls, self.subs, self.funcs = [], [], [], [], []
        for n in _walk(unit.tree.root_node):
            t = n.type
            if t in ("call_expression", "new_expression"):
                f = n.child_by_field_name("function") or n.child_by_field_name("constructor")
                # callee text only when short: an IIFE callee is a whole function body
                name = _t(f, src) if f is not None and f.end_byte - f.start_byte <= 200 else ""
                self.calls.append((n, name))
            elif t == "assignment_expression":
                self.assigns.append(n)
            elif t == "variable_declarator":
                self.decls.append(n)
            elif t == "subscript_expression":
                self.subs.append(n)
            if _is_func(n):
                self.funcs.append(n)


# ---- B1, B2: from flows ----------------------------------------------------
def det_flows(ctx):
    for fl in ctx.flows:
        dest = fl.dest or {}
        cls = dest.get("class")
        if fl.sink == "network-send" and "session" in fl.sources and cls not in ("primary", "self"):
            conf = "medium" if cls == "unknown" else "high"
            where = dest.get("host") or "a URL computed at runtime"
            ctx.emit("DET-SESSION-SEND", "high", conf,
                     f"Flow: {'+'.join(fl.sources)} -> {fl.api} -> {where}"
                     + (f" via {', '.join(fl.transforms)}" if fl.transforms else "") + ".",
                     fl.file, fl.line, match=fl.api, details=fl.to_dict())
        if fl.sink == "privileged" and fl.api.endswith("(url from data)") and fl.credentialed:
            ext = sorted(set(fl.sources) & {"network", "message", "storage"})
            ctx.emit("DET-CRED-DYNURL", "high", "high",
                     f"URL from {'+'.join(ext)} in {fl.api.replace(' (url from data)', '')} with credentials; "
                     "COMB-AUTH-PROXY raises this to critical if the response is sent back out.",
                     fl.file, fl.line, match=fl.api, details=fl.to_dict())


# ---- B3: dispatch flows ------------------------------------------------------
def det_dispatch(ctx):
    for fl in ctx.flows:
        if fl.sink != "dispatch":
            continue
        computed = fl.api.endswith("()")
        sev, conf = ("high", "medium") if computed else ("high", "high")
        how = ("handler chosen by a computed name from network data" if computed
               else "switch on network data whose branches use privileged APIs")
        f = ctx.emit("DET-CMD-DISPATCH", sev, conf, f"{how}: `{fl.api}`"
                     + ("; runs from a timer" if fl.timer else "") + ".", fl.file, fl.line, match=fl.api,
                     details=fl.to_dict())
        if f is not None and conf == "high":
            f["verdict_floor"] = "likely_malicious"     # a remote command channel, like COMB-C2


# ---- B4: weak origin checks ----------------------------------------------------
def _handlers(unit, ix):
    """(handler node, how) for message/connect listeners in a unit."""
    src = unit.src
    named = None
    out = []
    for n, name in ix.calls:
        if n.type == "call_expression":
            if not (HANDLER_RE.search(name) or name.endswith("addEventListener")):
                continue
            args = _args(n)
            cb = None
            if HANDLER_RE.search(name):
                cb = args[0] if args else None
                how = name
            elif name.endswith("addEventListener") and len(args) >= 2 and \
                    _t(args[0], src).strip("'\"`") == "message":
                cb, how = args[1], name + "('message')"
            if cb is not None:
                if cb.type == "identifier":
                    if named is None:
                        named = {}
                        for fn in ix.funcs:
                            nm = jsast._func_name(fn, src)
                            if nm:
                                named.setdefault(nm, fn)
                    cb = named.get(_t(cb, src))
                if _is_func(cb):
                    out.append((cb, how))
    for n in ix.assigns:
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        if left is not None and left.type == "member_expression" and _is_func(right):
            prop = left.child_by_field_name("property")
            if prop is not None and _t(prop, src) == "onmessage":
                out.append((right, _t(left, src)[:80]))
    return out


def _weak_check(call, src):
    """Reason string if `call` is a weak origin comparison, else None."""
    f = call.child_by_field_name("function")
    if f is None or f.type != "member_expression":
        return None
    prop = f.child_by_field_name("property")
    method = _t(prop, src) if prop is not None else ""
    if method not in WEAK_METHODS:
        return None
    obj = f.child_by_field_name("object")
    args = _args(call)
    if method == "test":
        if obj is None or obj.type != "regex" or not args or not ORIGINISH_RE.search(_t(args[0], src)):
            return None
        pat = obj.child_by_field_name("pattern")
        p = _t(pat, src) if pat is not None else ""
        if p.startswith("^") and p.endswith("$"):
            return None
        return f"unanchored regex /{p[:60]}/ tested against {_t(args[0], src)[:60]}"
    if obj is None or not ORIGINISH_RE.search(_t(obj, src).rstrip("()")):
        return None
    lit = args[0] if args and args[0].type == "string" else None
    val = _t(lit, src)[1:-1] if lit is not None else None
    target = _t(obj, src)[:60]
    if method in ("indexOf", "lastIndexOf"):
        par = call.parent
        if par is not None and par.type == "binary_expression":
            other = [c for c in par.named_children if c != call]
            if other and _t(other[0], src) == "0" and _t(par.child_by_field_name("operator"), src) in ("===", "=="):
                method = "startsWith"
        if method != "startsWith":
            return f"substring test {target}.indexOf(...)"
    if method in ("includes", "match", "search"):
        return f"substring test {target}.{method}(...)"
    if method == "startsWith":
        if val is not None and re.match(r"^[a-z][a-z0-9+.-]*://[^/]+/", val, re.I):
            return None
        return f"open prefix test {target}.startsWith({_t(args[0], src)[:60] if args else ''})"
    if method == "endsWith":
        if val is not None and (val.startswith(".") or val.startswith("/")):
            return None
        return f"open suffix test {target}.endsWith({_t(args[0], src)[:60] if args else ''})"
    return None


def det_weak_origin(ctx):
    for u in _units(ctx.pkg):
        seen = set()
        for h, how in _handlers(u, ctx.idx(u)):
            priv = bool(PRIV_TEXT_RE.search(_t(h, u.src)))
            for n in _walk(h):
                if n.type != "call_expression" or n.start_byte in seen:
                    continue
                why = _weak_check(n, u.src)
                if why:
                    seen.add(n.start_byte)
                    ctx.emit("DET-WEAK-ORIGIN", "high" if priv else "medium", "medium",
                             f"{why} in a {how} handler"
                             + ("; the handler uses privileged APIs" if priv else "") + ".",
                             u.file, _line(u, n), match=_t(n, u.src)[:200])


# ---- B5: hidden windows ---------------------------------------------------------
def _num(node, src):
    if node is None:
        return None
    if node.type == "number":
        try:
            return float(_t(node, src))
        except ValueError:
            return None
    if node.type == "unary_expression" and _t(node, src).startswith("-"):
        v = _num(node.named_children[0] if node.named_children else None, src)
        return -v if v is not None else None
    return None


def det_hidden_window(ctx):
    idle = []
    idle_re = re.compile(rb"\bidle\.(?:queryState|onStateChanged)\b")
    for u in _units(ctx.pkg):
        for m in idle_re.finditer(u.src):
            ln = u.src.count(b"\n", 0, m.start()) + 1 + u.line_offset
            idle.append(f"{u.file}:{ln}")
    for u in _units(ctx.pkg):
        src = u.src
        for n, name in ctx.idx(u).calls:
            if n.type != "call_expression" or not re.match(r"^(?:chrome|browser)\.windows\.(?:create|update)$", name):
                continue
            opts = next((a for a in _args(n) if a.type == "object"), None)
            if opts is None:
                continue
            strong, weak = [], []
            for key in ("width", "height"):
                v = _num(_obj_prop(opts, key, src), src)
                if v is not None and v <= 100:
                    strong.append(f"{key} {int(v)}")
            for key in ("left", "top"):
                v = _num(_obj_prop(opts, key, src), src)
                if v is not None and (v < 0 or v >= 10000):
                    strong.append(f"{key} {int(v)}")
            st = _obj_prop(opts, "state", src)
            if st is not None and _t(st, src).strip("'\"`") == "minimized":
                strong.append("state minimized")
            fo = _obj_prop(opts, "focused", src)
            if fo is not None and _t(fo, src) == "false":
                weak.append("focused false")
            if not strong and not weak:
                continue
            signals = strong + weak
            if strong and idle:
                sev, extra = "high", ["T1497.002"]
            elif strong:
                sev, extra = "medium", []
            else:
                sev, extra = "low", []
            ctx.emit("DET-HIDDEN-WINDOW", sev, "high" if strong else "medium",
                     f"{name} with {', '.join(signals)}"
                     + (f"; idle-state checks at {', '.join(idle[:3])} (runs while the user is away)" if idle and strong else "")
                     + ".", u.file, _line(u, n), match=_t(n, src)[:200], extra_attack=extra,
                     details={"signals": signals, "idle_checks": idle[:10]})


# ---- B6: identity headers ---------------------------------------------------------
def _dnr_headers(node, src):
    """Request header names set/removed in object literals under a `requestHeaders` key."""
    out = []
    for n in _walk(node):
        if n.type == "pair":
            k = n.child_by_field_name("key")
            if k is not None and _t(k, src).strip("'\"") == "requestHeaders":
                for m in _walk(n.child_by_field_name("value")):
                    if m.type == "object":
                        h = _obj_prop(m, "header", src)
                        if h is not None and h.type == "string":
                            out.append((_t(h, src)[1:-1], m))
    return out


def det_identity_headers(ctx, cred_dynurl):
    hits = []
    for u in _units(ctx.pkg):
        src = u.src
        for n, name in ctx.idx(u).calls:
            if n.type != "call_expression":
                continue
            if re.search(r"declarativeNetRequest\.update(?:Dynamic|Session)Rules$", name):
                for h, m in _dnr_headers(n, src):
                    if IDENTITY_HEADERS_RE.match(h):
                        hits.append((u.file, _line(u, m), h, name))
            elif re.search(r"webRequest\.onBeforeSendHeaders\.addListener$", name):
                args = _args(n)
                cb = args[0] if args else None
                if _is_func(cb):
                    for m in _walk(cb):
                        if m.type == "string" and IDENTITY_HEADERS_RE.match(_t(m, src)[1:-1]):
                            hits.append((u.file, _line(u, m), _t(m, src)[1:-1], name))
    # static rulesets declared in the manifest
    dnr = (ctx.pkg.manifest.get("declarative_net_request") or {}).get("rule_resources") or []
    for res in dnr:
        rel = jsast.norm_ref(res.get("path")) if isinstance(res, dict) else None
        if not rel:
            continue
        try:
            with open(os.path.join(ctx.pkg.root, rel), encoding="utf-8", errors="replace") as f:
                text = f.read()
            rules = json.loads(text)
        except (OSError, ValueError):
            continue
        for r in rules if isinstance(rules, list) else []:
            act = (r or {}).get("action") or {} if isinstance(r, dict) else {}
            if act.get("type") != "modifyHeaders":
                continue
            for h in act.get("requestHeaders") or []:
                name = (h or {}).get("header", "") if isinstance(h, dict) else ""
                if isinstance(name, str) and IDENTITY_HEADERS_RE.match(name):
                    idx = text.lower().find('"' + name.lower() + '"')
                    line = text.count("\n", 0, idx) + 1 if idx >= 0 else None
                    hits.append((rel, line, name, f"ruleset {res.get('id') or rel}"))
    seen = set()
    for path, line, header, via in hits:
        if (path, line, header.lower()) in seen:
            continue
        seen.add((path, line, header.lower()))
        sev = "high" if cred_dynurl else "medium"
        ctx.emit("DET-IDENTITY-HEADERS", sev, "high",
                 f"request header `{header}` modified via {via}"
                 + ("; combined with DET-CRED-DYNURL in this package" if cred_dynurl else "") + ".",
                 path, line, match=header, extra_attack=["T1185"] if cred_dynurl else (),
                 details={"header": header, "via": via})


# ---- B7: obfuscated sensitive strings ----------------------------------------------
class Folder:
    """Static folding of literal expressions. Returns (value, techniques, fragments) or None."""

    def __init__(self, unit, ix):
        self.u, self.src = unit, unit.src
        self.consts = {}
        for n in ix.decls:
            nm, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if nm is not None and val is not None and nm.type == "identifier":
                self.consts.setdefault(_t(nm, self.src), val)

    def num(self, n, d=0):
        if n is None or d > MAX_FOLD_DEPTH:
            return None
        if n.type == "number":
            t = _t(n, self.src)
            try:
                return int(t, 0) if not re.search(r"[.eE]", t) or t.lower().startswith("0x") else int(float(t))
            except ValueError:
                return None
        if n.type == "parenthesized_expression" and n.named_children:
            return self.num(n.named_children[0], d + 1)
        if n.type == "unary_expression" and _t(n, self.src).startswith("-") and n.named_children:
            v = self.num(n.named_children[0], d + 1)
            return -v if v is not None else None
        if n.type == "binary_expression":
            op = _t(n.child_by_field_name("operator"), self.src)
            a, b = self.num(n.child_by_field_name("left"), d + 1), self.num(n.child_by_field_name("right"), d + 1)
            if a is None or b is None:
                return None
            return {"+": lambda: a + b, "-": lambda: a - b, "*": lambda: a * b, "^": lambda: a ^ b,
                    "|": lambda: a | b, "&": lambda: a & b}.get(op, lambda: None)()
        return None

    def chars(self, nodes, d):
        out = []
        for a in nodes:
            if a.type == "spread_element" and a.named_children:
                lst = self.lst(a.named_children[0], d + 1)
                if lst is None:
                    return None
                vals = lst[0]
                for v in vals:
                    if not isinstance(v, int):
                        return None
                    out.append(v)
                continue
            v = self.num(a, d + 1)
            if v is None:
                return None
            out.append(v)
        if not out or len(out) > MAX_FOLD_LEN or any(v < 0 or v > 0x10FFFF for v in out):
            return None
        return "".join(chr(v) for v in out)

    def lst(self, n, d=0):
        """([values], techs) for array literals, 'str'.split(sep), list.reverse()."""
        if n is None or d > MAX_FOLD_DEPTH:
            return None
        if n.type == "array":
            vals, techs = [], set()
            for e in n.named_children:
                v = self.num(e, d + 1)
                if v is not None:
                    vals.append(v)
                    continue
                s = self.fold(e, d + 1)
                if s is None:
                    return None
                vals.append(s[0])
                techs |= s[1]
            return vals, techs
        if n.type == "identifier" and _t(n, self.src) in self.consts and d < 6:
            return self.lst(self.consts[_t(n, self.src)], d + 2)
        if n.type == "call_expression":
            f = n.child_by_field_name("function")
            if f is None or f.type != "member_expression":
                return None
            m = _t(f.child_by_field_name("property"), self.src)
            obj = f.child_by_field_name("object")
            args = _args(n)
            if m == "split" and len(args) == 1:
                s, sep = self.fold(obj, d + 1), self.fold(args[0], d + 1)
                if s is None or sep is None:
                    return None
                return (list(s[0]) if sep[0] == "" else s[0].split(sep[0])), s[1] | {"split"}
            if m == "reverse" and not args:
                l = self.lst(obj, d + 1)
                return (l[0][::-1], l[1] | {"reverse"}) if l else None
        return None

    def fold(self, n, d=0):
        if n is None or d > MAX_FOLD_DEPTH:
            return None
        t = n.type
        if t == "string":
            v = _t(n, self.src)[1:-1]
            return v, set(), [v]
        if t == "template_string":
            v = jsast.string_value(n, self.src)
            return (v, set(), [v]) if v is not None else None
        if t == "parenthesized_expression" and n.named_children:
            return self.fold(n.named_children[0], d + 1)
        if t == "identifier" and _t(n, self.src) in self.consts and d < 6:
            return self.fold(self.consts[_t(n, self.src)], d + 2)
        if t == "binary_expression" and _t(n.child_by_field_name("operator"), self.src) == "+":
            a, b = self.fold(n.child_by_field_name("left"), d + 1), self.fold(n.child_by_field_name("right"), d + 1)
            if a is None or b is None or len(a[0]) + len(b[0]) > MAX_FOLD_LEN:
                return None
            return a[0] + b[0], a[1] | b[1] | {"concat"}, a[2] + b[2]
        if t == "call_expression":
            name, f = _callee(n, self.src)
            args = _args(n)
            if name == "String.fromCharCode":
                v = self.chars(args, d)
                return (v, {"fromCharCode"}, [v]) if v is not None else None
            if name == "String.fromCharCode.apply" and len(args) == 2:
                l = self.lst(args[1], d + 1)
                if l and all(isinstance(x, int) for x in l[0]) and 0 < len(l[0]) <= MAX_FOLD_LEN:
                    try:
                        v = "".join(chr(x) for x in l[0])
                    except ValueError:
                        return None
                    return v, {"fromCharCode"}, [v]
                return None
            if name in ("atob", "window.atob", "self.atob") and len(args) == 1:
                s = self.fold(args[0], d + 1)
                if s is None:
                    return None
                try:
                    raw = base64.b64decode(s[0], validate=True)
                    v = raw.decode("ascii")
                except (binascii.Error, ValueError, UnicodeDecodeError):
                    return None
                if not v.isprintable() or len(v) > MAX_FOLD_LEN:
                    return None
                return v, s[1] | {"atob"}, [v]
            if name in ("decodeURIComponent", "decodeURI", "unescape") and len(args) == 1:
                s = self.fold(args[0], d + 1)
                if s is None or "%" not in s[0]:
                    return None
                v = unquote(s[0])
                return v, s[1] | {"percent-decode"}, [v]
            if f is not None and f.type == "member_expression":
                m = _t(f.child_by_field_name("property"), self.src)
                obj = f.child_by_field_name("object")
                if m == "join" and len(args) <= 1:
                    l = self.lst(obj, d + 1)
                    sep = self.fold(args[0], d + 1) if args else (",", set(), [","])
                    if l is None or sep is None or any(not isinstance(x, str) for x in l[0]):
                        return None
                    v = sep[0].join(l[0])
                    if len(v) > MAX_FOLD_LEN:
                        return None
                    return v, l[1] | sep[1] | {"array-join"}, list(l[0])
                if m == "concat" and args:
                    parts = [self.fold(obj, d + 1)] + [self.fold(a, d + 1) for a in args]
                    if any(p is None for p in parts):
                        return None
                    v = "".join(p[0] for p in parts)
                    if len(v) > MAX_FOLD_LEN:
                        return None
                    return v, set().union(*(p[1] for p in parts)) | {"concat"}, [x for p in parts for x in p[2]]
        return None


FOLD_START = {"binary_expression", "call_expression"}


def _sensitive(value):
    """(kind, token) if the folded value is a URL, a domain or a sensitive API name."""
    v = value.strip()
    m = URL_RE.match(v)
    if m:
        return "url", m.group(1).lower()
    if _BARE_DOMAIN_RE.fullmatch(v):
        return "domain", v.lower()
    if v.lower() in SENSITIVE_WORDS:
        return "api", v
    return None


def _used_in_sink(node, src, name_uses):
    """'network'/'cookies'/'computed-property' if the expression (or its variable) feeds those."""
    p = node.parent
    while p is not None and p.type in ("parenthesized_expression", "arguments", "await_expression"):
        p = p.parent
    if p is not None and p.type == "subscript_expression" and p.child_by_field_name("index") == node:
        return "computed-property"
    if p is not None and p.type in ("call_expression", "new_expression"):
        name, _ = _callee(p, src)
        if COOKIE_API_RE.match(name):
            return "cookies"
        if NET_SINK_RE.search(name) or name in ("WebSocket", "EventSource"):
            return "network"
    if p is not None and p.type == "variable_declarator":
        nm = p.child_by_field_name("name")
        if nm is not None and nm.type == "identifier":
            return name_uses.get(_t(nm, src))
    return None


def _name_uses(unit, ix):
    """identifier -> sink kind for identifiers used directly as sink arguments or computed keys."""
    src, out = unit.src, {}
    for n in ix.subs:
        idx = n.child_by_field_name("index")
        if idx is not None and idx.type == "identifier":
            out.setdefault(_t(idx, src), "computed-property")
    for n, name in ix.calls:
        kind = ("cookies" if COOKIE_API_RE.match(name) else
                "network" if NET_SINK_RE.search(name) or name in ("WebSocket", "EventSource") else None)
        if kind:
            for a in _args(n):
                for m in _walk(a):
                    if m.type == "identifier":
                        out[_t(m, src)] = kind
    return out


def det_obf_strings(ctx):
    for u in _units(ctx.pkg):
        src = u.src
        folder = Folder(u, ctx.idx(u))
        uses = None
        stack = [u.tree.root_node]
        while stack:
            n = stack.pop()
            if n.type in FOLD_START:
                r = folder.fold(n)
                if r is not None:
                    value, techs, frags = r
                    sens = _sensitive(value) if techs else None
                    if sens and techs == {"concat"}:
                        # plain concatenation only counts when no single fragment holds the token
                        if any(sens[1].lower() in fr.lower() for fr in frags):
                            sens = None
                    if sens:
                        if uses is None:
                            uses = _name_uses(u, ctx.idx(u))
                        used = _used_in_sink(n, src, uses)
                        sev = "high" if used else "medium"
                        conf = "medium" if techs == {"concat"} else "high"   # split strings also occur by accident
                        ctx.emit("DET-OBF-STRING", sev, conf,
                                 f"{sens[0]} `{value[:120]}` recovered from {', '.join(sorted(techs))}"
                                 + (f"; the value is used as {used} input" if used else "") + ".",
                                 u.file, _line(u, n), match=value[:200],
                                 details={"value": value[:500], "kind": sens[0], "techniques": sorted(techs),
                                          "used_in": used})
                    continue      # children were part of this expression
            stack.extend(reversed(n.named_children))


# ---- B8: code injection -------------------------------------------------------------
def _is_literal(node):
    return node is not None and (node.type == "string" or
                                 (node.type == "template_string" and
                                  not any(c.type == "template_substitution" for c in node.children)))


def det_code_inject(ctx):
    tainted = {}
    for fl in ctx.flows:
        if fl.sink == "code-exec":
            tainted.setdefault((fl.file, fl.line), set()).update(fl.sources)
    ext = {"network", "message", "storage", "auth-response"}
    for u in _units(ctx.pkg):
        src = u.src
        ix = ctx.idx(u)
        script_vars = set()
        for n in ix.decls:
            nm, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if nm is not None and val is not None and val.end_byte - val.start_byte < 300 and \
                    re.search(r"createElement\s*\(\s*['\"]script['\"]", _t(val, src)):
                script_vars.add(_t(nm, src))
        for n in [c for c, _ in ix.calls] + ix.assigns:
            line = _line(u, n)
            ks = tainted.get((u.file, line), set())
            src_note = f"; data from {'+'.join(sorted(ks))}" if ks else ""
            if n.type in ("call_expression", "new_expression"):
                f = n.child_by_field_name("function") or n.child_by_field_name("constructor")
                name = _t(f, src) if f is not None and f.end_byte - f.start_byte <= 200 else ""
                if not name:
                    continue
                args = _args(n)
                if name.endswith("executeScript"):
                    opts = next((a for a in args if a.type == "object"), None)
                    if opts is None:
                        continue
                    code = _obj_prop(opts, "code", src)
                    files = _obj_prop(opts, "files", src) or _obj_prop(opts, "file", src)
                    func = _obj_prop(opts, "func", src) or _obj_prop(opts, "function", src)
                    if code is not None:
                        lit = _is_literal(code)
                        ctx.emit("DET-CODE-INJECT", "medium" if lit and not ks else "high", "high",
                                 f"{name} with a {'constant' if lit else 'non-constant'} code string{src_note}.",
                                 u.file, line, match=_t(n, src)[:200],
                                 extra_attack=["T1105"] if ks & ext else ())
                    elif files is not None:
                        lits = files.type == "array" and all(_is_literal(e) for e in files.named_children)
                        if not (lits or _is_literal(files)):
                            ctx.emit("DET-CODE-INJECT", "high" if ks & ext else "medium", "medium",
                                     f"{name} with file names computed at runtime{src_note}.",
                                     u.file, line, match=_t(n, src)[:200])
                    elif func is not None:
                        ctx.emit("DET-CODE-INJECT", "low", "high",
                                 f"{name} with a packaged function (`func`); the code is in the extension.",
                                 u.file, line, match=_t(n, src)[:200])
                elif name in ("eval", "window.eval", "self.eval", "globalThis.eval", "Function", "window.Function"):
                    if not args or all(_is_literal(a) for a in args):
                        continue
                    if ks & ext:
                        ctx.emit("DET-CODE-INJECT", "high", "high", f"{name} on data{src_note}.", u.file, line,
                                 match=_t(n, src)[:200], extra_attack=["T1105"])
                    else:
                        # common in template engines and bundlers; CODE-EVAL/CODE-FUNC already report it
                        ctx.emit("DET-CODE-INJECT", "low", "medium",
                                 f"{name} on a non-literal value whose origin was not resolved to a source.",
                                 u.file, line, match=_t(n, src)[:200])
                elif name.endswith(".setAttribute") and len(args) == 2 and _t(args[0], src).strip("'\"`") == "src":
                    obj = _t(n.child_by_field_name("function").child_by_field_name("object"), src)
                    if obj in script_vars:
                        _script_src(ctx, u, n, args[1], ks, src_note, line)
            elif n.type == "assignment_expression":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is not None and left.type == "member_expression":
                    prop = left.child_by_field_name("property")
                    obj = left.child_by_field_name("object")
                    if prop is not None and _t(prop, src) == "src" and obj is not None and \
                            (_t(obj, src) in script_vars or "script" in _t(obj, src).lower()):
                        _script_src(ctx, u, n, right, ks, src_note, line)


def _script_src(ctx, u, n, val, ks, src_note, line):
    src = u.src
    txt = _t(val, src)
    if "getURL" in txt or "runtime.getURL" in txt:
        return
    if _is_literal(val):
        v = jsast.string_value(val, src) or ""
        if "://" not in v and not v.startswith("//"):
            return
        ctx.emit("DET-CODE-INJECT", "medium", "high", f"script element loads remote URL `{v[:120]}`.",
                 u.file, line, match=_t(n, src)[:200], extra_attack=["T1105"])
        return
    ext = {"network", "message", "storage", "auth-response"}
    ctx.emit("DET-CODE-INJECT", "high" if ks & ext else "medium", "medium" if not ks else "high",
             f"script element src computed at runtime{src_note}.", u.file, line, match=_t(n, src)[:200],
             extra_attack=["T1105"] if ks & ext else ())


# ---- B9: forced UI ---------------------------------------------------------------
def det_forced_ui(ctx):
    focus = []
    for u in _units(ctx.pkg):
        src = u.src
        for n, name in ctx.idx(u).calls:
            if n.type != "call_expression" or not re.match(r"^(?:chrome|browser)\.windows\.update$", name):
                continue
            opts = next((a for a in _args(n) if a.type == "object"), None)
            if opts is None:
                continue
            fo = _obj_prop(opts, "focused", src)
            da = _obj_prop(opts, "drawAttention", src)
            st = _obj_prop(opts, "state", src)
            sig = []
            if fo is not None and _t(fo, src) == "true":
                sig.append("focused")
            if da is not None and _t(da, src) == "true":
                sig.append("drawAttention")
            if st is not None and _t(st, src).strip("'\"`") in ("maximized", "fullscreen"):
                sig.append("state " + _t(st, src).strip("'\"`"))
            if sig and ctx.pkg.status(u.file, _line(u, n)) != "unreachable":
                focus.append((f"{u.file}:{_line(u, n)}", sig))
    if not focus:
        return
    for rel in sorted(ctx.content):
        for u in ctx.pkg.units.get(rel, []):
            for n, name in ctx.idx(u).calls:
                if name in ("alert", "confirm", "prompt", "window.alert", "window.confirm", "window.prompt"):
                    where = ", ".join(f"{w} ({'/'.join(s)})" for w, s in focus[:3])
                    ctx.emit("DET-FORCED-UI", "medium", "low",
                             f"{name}() in content script; windows.update at {where}.",
                             u.file, _line(u, n), match=_t(n, u.src)[:200],
                             details={"window_updates": [w for w, _ in focus]})
                    break


def analyze(pkg, flows):
    """Returns (findings, records)."""
    ctx = Ctx(pkg, flows)
    det_flows(ctx)
    det_dispatch(ctx)
    det_weak_origin(ctx)
    det_hidden_window(ctx)
    cred = any(f["id"].startswith("DET-CRED-DYNURL") and f["reachability"] != "unreachable" for f in ctx.findings)
    det_identity_headers(ctx, cred)
    det_obf_strings(ctx)
    det_code_inject(ctx)
    det_forced_ui(ctx)
    return ctx.findings, ctx.records
