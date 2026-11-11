"""Source -> sink data flows on the syntax tree (approximate taint tracking).

Scope: inside one function including its nested callbacks (closures share
variables), plus one step into a named function that receives tainted
arguments. Variables are tracked by name. Nothing is executed.

Source kinds
  session  chrome.cookies.get/getAll, document.cookie, localStorage, sessionStorage
  input    keyboard/input event data in listeners, password field values
  network  fetch()/XHR/axios/$.ajax responses, WebSocket messages
  message  chrome.runtime.onMessage(External), window "message" events, ports
  storage  chrome.storage.*.get
  auth-response  body of a credentialed request whose URL came from outside

Sink kinds
  network-send  fetch body/URL, XMLHttpRequest.send, sendBeacon, WebSocket.send, img/script src
  code-exec     eval, Function, string timers, executeScript code/files, importScripts, script src
  privileged    chrome.tabs.create/update, chrome.windows.create, scripting, location changes
"""

import re
from urllib.parse import urlsplit

from . import jsast

EXTERNAL = {"network", "message", "storage"}

SESSION_RE = re.compile(r"^(?:chrome|browser)\.cookies\.(?:get|getAll)$")
NETWORK_CALL_RE = re.compile(r"^(?:fetch|axios(?:\.\w+)?|\$\.(?:get|post|ajax|getJSON)|jQuery\.(?:get|post|ajax))$")
STORAGE_GET_RE = re.compile(r"^(?:chrome|browser)\.storage\.\w+\.get$")
MESSAGE_LISTEN_RE = re.compile(r"(?:^|\.)(?:runtime\.onMessage(?:External)?|onMessage|onConnect(?:External)?)\.addListener$")
KEY_EVENTS = {"keydown", "keypress", "keyup", "input", "change", "submit"}
SERIALIZE = {"JSON.stringify", "btoa", "encodeURIComponent", "encodeURI", "escape"}
PRIV_RE = re.compile(r"^(?:chrome|browser)\.(?:tabs\.(?:create|update|executeScript)|windows\.(?:create|update)|"
                     r"scripting\.\w+|webNavigation\.\w+)$")
EXEC_CALLS = {"eval", "Function", "importScripts", "execScript"}


def _t(node, src):
    return jsast.text_of(node, src)


def _callee(call, src):
    f = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    return (_t(f, src) if f is not None else ""), f


def _args(call):
    a = call.child_by_field_name("arguments")
    return [c for c in a.named_children if c.type != "comment"] if a is not None else []


def _obj_prop(obj, key, src):
    """Value node of property `key` in an object literal."""
    if obj is None or obj.type != "object":
        return None
    for p in obj.named_children:
        if p.type == "pair":
            k = p.child_by_field_name("key")
            if k is not None and _t(k, src).strip("'\"") == key:
                return p.child_by_field_name("value")
        elif p.type == "shorthand_property_identifier" and _t(p, src) == key:
            return p
    return None


def _is_func(node):
    return node is not None and node.is_named and node.type in jsast.FUNC_TYPES


def _params(fn_node, src):
    ps = fn_node.child_by_field_name("parameters")
    if ps is None:
        p = fn_node.child_by_field_name("parameter")
        return [_t(p, src)] if p is not None else []
    out = []
    for c in ps.named_children:
        if c.type == "identifier":
            out.append(_t(c, src))
        elif c.type == "assignment_pattern":
            l = c.child_by_field_name("left")
            out.append(_t(l, src) if l is not None else "")
        else:
            out.append("")
    return out


class Env:
    """Variable scope of one function. Lookups walk up to enclosing functions (closures);
    a write goes to the scope that declares the name, or to the top scope."""

    __slots__ = ("vars", "declared", "parent")

    def __init__(self, parent=None):
        self.vars, self.declared, self.parent = {}, set(), parent

    def get(self, name, default=()):
        e = self
        while e is not None:
            if name in e.vars:
                return e.vars[name]
            if name in e.declared:
                return default
            e = e.parent
        return default

    def owner(self, name):
        e = self
        while e is not None:
            if name in e.declared:
                return e
            if e.parent is None:
                return e
            e = e.parent
        return self

    def bind(self, name, ks):
        if not name or not ks:
            return False
        cur = self.owner(name).vars.setdefault(name, set())
        if ks <= cur:
            return False
        cur |= ks
        return True


class Flow:
    def __init__(self, sources, sink, api, file, line, dest, transforms, credentialed=False):
        self.sources = sorted(sources)
        self.sink, self.api, self.file, self.line = sink, api, file, line
        self.dest = dest            # {"class": primary|third_party|unknown|self, "host": str|None}
        self.transforms = sorted(transforms)
        self.credentialed = credentialed
        self.timer = False          # runs from setInterval / chrome.alarms (filled in later)
        self.reachability = None
        self.function = None
        self.content_script = False

    def key(self):
        return (self.file, self.line, self.sink, self.api)

    def to_dict(self):
        return {"sources": self.sources, "sink": self.sink, "api": self.api,
                "location": {"path": self.file, "line": self.line}, "function": self.function,
                "destination": self.dest, "transforms": self.transforms, "credentialed": self.credentialed,
                "timer_driven": self.timer, "content_script": self.content_script,
                "reachability": self.reachability}


class Analyzer:
    """Taint pass over one unit (a parsed file or inline script)."""

    def __init__(self, unit, consts, classify, named_funcs):
        self.u, self.src = unit, unit.src
        self.consts = consts            # identifier -> string literal (package-wide)
        self.classify = classify        # url string or None -> dest dict
        self.named = named_funcs        # name -> [function nodes in this unit]
        self.flows = {}
        self.timer_names, self.timer_nodes = set(), set()
        self.envs = {}           # function start_byte -> Env (kept across passes)
        self.param_taint = {}    # function start_byte -> [kinds per parameter]

    def line(self, node):
        return node.start_point[0] + 1 + self.u.line_offset

    # ---- expression kinds ------------------------------------------------
    def kinds(self, node, taint, transforms=None, depth=0):
        """Source kinds an expression carries (does not enter nested functions)."""
        if node is None or depth > 60:
            return set()
        t = node.type
        if _is_func(node):
            return set()
        if t == "identifier":
            return set(taint.get(_t(node, self.src), ()))
        out = set()
        if t == "member_expression":
            txt = _t(node, self.src)
            if txt == "document.cookie" or txt.startswith(("localStorage", "sessionStorage", "window.localStorage",
                                                           "window.sessionStorage")):
                out.add("session")
            if txt.endswith((".responseText", ".responseJSON")):
                out.add("network")
            obj = node.child_by_field_name("object")
            out |= self.kinds(obj, taint, transforms, depth + 1)
            return out
        if t in ("call_expression", "new_expression"):
            name, f = _callee(node, self.src)
            if SESSION_RE.match(name):
                out.add("session")
            elif NETWORK_CALL_RE.match(name):
                out.add("network")
                if self._credentialed(node) and self._url_kinds(node, taint) & EXTERNAL:
                    out.add("auth-response")
            elif STORAGE_GET_RE.match(name):
                out.add("storage")
            elif name in ("localStorage.getItem", "sessionStorage.getItem"):
                out.add("session")
            if name in SERIALIZE and transforms is not None:
                transforms.add(name)
            if name.endswith(".querySelector") or name.endswith(".querySelectorAll"):
                a = _args(node)
                if a and "password" in _t(a[0], self.src):
                    out.add("input")
            # value flows through method chains (r.text(), x.then(...)) and arguments
            if f is not None and f.type == "member_expression":
                out |= self.kinds(f.child_by_field_name("object"), taint, transforms, depth + 1)
            for a in _args(node):
                out |= self.kinds(a, taint, transforms, depth + 1)
            return out
        for c in node.named_children:
            out |= self.kinds(c, taint, transforms, depth + 1)
        return out

    def _credentialed(self, call):
        a = _args(call)
        if len(a) >= 2:
            v = _obj_prop(a[1], "credentials", self.src)
            if v is not None and "include" in _t(v, self.src):
                return True
            v = _obj_prop(a[1], "withCredentials", self.src)
            if v is not None and _t(v, self.src) == "true":
                return True
        return False

    def _url_kinds(self, call, taint):
        a = _args(call)
        return self.kinds(a[0], taint) if a else set()

    def url_of(self, node):
        """Best-effort literal URL of an expression (prefix for templates/concatenation)."""
        if node is None:
            return None
        if node.type == "string":
            return _t(node, self.src)[1:-1]
        if node.type == "template_string":
            txt = _t(node, self.src)[1:-1]
            return txt.split("${", 1)[0] or None
        if node.type == "binary_expression":
            return self.url_of(node.child_by_field_name("left"))
        if node.type == "identifier":
            return self.consts.get(_t(node, self.src))
        if node.type in ("call_expression",):
            name, _ = _callee(node, self.src)
            if name.endswith("runtime.getURL"):
                return "chrome-extension://self/"
        return None

    # ---- statements -----------------------------------------------------
    def bind(self, name, ks, taint):
        return taint.bind(name, ks)

    def enter(self, fn, parent_env):
        env = self.envs.get(fn.start_byte)
        if env is None:
            env = self.envs[fn.start_byte] = Env(parent_env)
        env.parent = parent_env
        params = _params(fn, self.src)
        env.declared.update(p for p in params if p)
        for p, ks in zip(params, self.param_taint.get(fn.start_byte, ())):
            env.bind(p, ks)
        return env

    def run(self, root, taint, transforms, depth=0):
        """One pass over a subtree; returns True if taint grew."""
        grew = False
        stack = [(root, taint)]
        while stack:
            n, taint = stack.pop()
            t = n.type
            if _is_func(n) and n is not root:
                taint = self.enter(n, taint)
            if t == "variable_declarator":
                nm = n.child_by_field_name("name")
                if nm is not None:
                    taint.declared.update(_t(i, self.src) for i in _idents(nm))
                name = n.child_by_field_name("name")
                val = n.child_by_field_name("value")
                if name is not None and val is not None:
                    ks = self.kinds(val, taint, transforms)
                    if name.type == "identifier":
                        grew |= self.bind(_t(name, self.src), ks, taint)
                    else:  # destructuring: taint every bound name
                        for idn in _idents(name):
                            grew |= self.bind(_t(idn, self.src), ks, taint)
            elif t in ("assignment_expression", "augmented_assignment_expression"):
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                ks = self.kinds(right, taint, transforms)
                if left is not None:
                    if left.type == "identifier":
                        grew |= self.bind(_t(left, self.src), ks, taint)
                    elif left.type == "member_expression":
                        base = left
                        while base.type == "member_expression":
                            base = base.child_by_field_name("object")
                        if base.type == "identifier":
                            grew |= self.bind(_t(base, self.src), ks, taint)
                        self.sink_assign(n, left, right, taint, transforms)
            elif t in ("call_expression", "new_expression"):
                grew |= self.call(n, taint, transforms, depth)
            stack.extend((c, taint) for c in reversed(n.named_children))
        return grew

    def call(self, n, taint, transforms, depth):
        grew = False
        name, f = _callee(n, self.src)
        args = _args(n)
        # callbacks whose parameters receive source data
        cb_kinds = set()
        if f is not None and f.type == "member_expression":
            prop = f.child_by_field_name("property")
            pname = _t(prop, self.src) if prop is not None else ""
            if pname in ("then", "map", "forEach", "filter", "reduce", "catch", "finally"):
                cb_kinds |= self.kinds(f.child_by_field_name("object"), taint, transforms)
        if SESSION_RE.match(name):
            cb_kinds.add("session")
        if STORAGE_GET_RE.match(name):
            cb_kinds.add("storage")
        if MESSAGE_LISTEN_RE.search(name):
            cb_kinds.add("message")
        if name.endswith("addEventListener") and args:
            ev = _t(args[0], self.src).strip("'\"`")
            if ev in KEY_EVENTS:
                cb_kinds.add("input")
            elif ev == "message":
                cb_kinds.add("message" if "WebSocket" not in name else "network")
        if name.endswith(("onAlarm.addListener",)) or name in ("setInterval", "setTimeout"):
            for a in args[:1]:
                if _is_func(a):
                    self.timer_nodes.add(a.start_byte)
                elif a.type == "identifier":
                    self.timer_names.add(_t(a, self.src))
        if cb_kinds:
            for a in args:
                if _is_func(a):
                    cur = self.param_taint.setdefault(a.start_byte, [])
                    for i in range(len(_params(a, self.src))):
                        if i >= len(cur):
                            cur.append(set())
                        if not cb_kinds <= cur[i]:
                            cur[i] |= cb_kinds
                            grew = True
        # one step into a named function receiving tainted arguments
        if depth < 1 and f is not None and f.type == "identifier" and name in self.named:
            arg_kinds = [self.kinds(a, taint, transforms) for a in args]
            if any(arg_kinds):
                for fn_node in self.named[name]:
                    sub = Env(None)
                    for p, ks in zip(_params(fn_node, self.src), arg_kinds):
                        sub.declared.add(p)
                        sub.bind(p, ks)
                    body = fn_node.child_by_field_name("body")
                    if body is not None and sub:
                        for _ in range(3):
                            if not self.run(body, sub, transforms, depth + 1):
                                break
        self.sink_call(n, name, args, taint, transforms)
        return grew

    # ---- sinks ------------------------------------------------------------
    def add(self, sources, sink, api, node, dest, transforms, credentialed=False):
        if not sources:
            return
        fl = Flow(sources, sink, api, self.u.file, self.line(node), dest, transforms, credentialed)
        k = fl.key()
        if k in self.flows:
            old = self.flows[k]
            old.sources = sorted(set(old.sources) | set(sources))
            old.transforms = sorted(set(old.transforms) | set(transforms))
        else:
            self.flows[k] = fl

    def sink_call(self, n, name, args, taint, transforms):
        tr = set()
        if NETWORK_CALL_RE.match(name) and args:
            url_ks = self.kinds(args[0], taint, tr)
            body_ks = set()
            if len(args) >= 2:
                body_ks = self.kinds(_obj_prop(args[1], "body", self.src) or _obj_prop(args[1], "data", self.src), taint, tr)
                hdr = _obj_prop(args[1], "headers", self.src)
                body_ks |= self.kinds(hdr, taint, tr)
            dest = self.classify(self.url_of(args[0]))
            cred = self._credentialed(n)
            self.add(body_ks | (url_ks - EXTERNAL - {"auth-response"} if url_ks else set()),
                     "network-send", name, n, dest, tr | transforms, cred)
            if url_ks & EXTERNAL:
                self.add(url_ks, "privileged", name + " (url from data)", n, dest, tr | transforms, cred)
        elif name.endswith(".sendBeacon") and args:
            ks = set().union(*(self.kinds(a, taint, tr) for a in args[1:])) if len(args) > 1 else set()
            self.add(ks, "network-send", "navigator.sendBeacon", n, self.classify(self.url_of(args[0])), tr | transforms)
        elif name.endswith(".send") and args:
            ks = self.kinds(args[0], taint, tr)
            api = "WebSocket.send" if "ws" in name.lower() or "socket" in name.lower() else "XMLHttpRequest.send"
            self.add(ks, "network-send", api, n, self.classify(None), tr | transforms)
        elif name in EXEC_CALLS or name.endswith(".eval"):
            ks = set().union(*(self.kinds(a, taint, tr) for a in args)) if args else set()
            self.add(ks, "code-exec", name, n, None, tr | transforms)
        elif name in ("setTimeout", "setInterval") and args and args[0].type in ("string", "template_string",
                                                                                  "binary_expression", "identifier") \
                and not (args[0].type == "identifier" and args[0] and _t(args[0], self.src) in self.named):
            self.add(self.kinds(args[0], taint, tr), "code-exec", name + "(string)", n, None, tr | transforms)
        elif name.endswith("executeScript") and args:
            for a in args:
                for key in ("code", "files"):
                    v = _obj_prop(a, key, self.src)
                    if v is not None:
                        self.add(self.kinds(v, taint, tr), "code-exec", f"{name}({key})", n, None, tr | transforms)
        if PRIV_RE.match(name) and args:
            ks = set().union(*(self.kinds(a, taint, tr) for a in args))
            self.add(ks & (EXTERNAL | {"auth-response"}), "privileged", name, n, None, tr | transforms)

    def sink_assign(self, n, left, right, taint, transforms):
        prop = left.child_by_field_name("property")
        pname = _t(prop, self.src) if prop is not None else ""
        tr = set()
        ks = self.kinds(right, taint, tr)
        if not ks:
            return
        ltxt = _t(left, self.src)
        if pname == "src":
            self.add(ks, "network-send", ltxt, n, self.classify(self.url_of(right)), tr | transforms)
            if ks & EXTERNAL:
                self.add(ks, "code-exec", ltxt + " (remote src)", n, None, tr | transforms)
        elif pname in ("textContent", "text", "innerHTML") and "script" in ltxt.lower():
            self.add(ks, "code-exec", ltxt, n, None, tr | transforms)
        elif ltxt in ("location.href", "window.location", "location", "window.location.href", "document.location"):
            self.add(ks & (EXTERNAL | {"auth-response"}), "privileged", ltxt, n, None, tr | transforms)


def _idents(node):
    out, stack = [], [node]
    while stack:
        n = stack.pop()
        if n.type in ("identifier", "shorthand_property_identifier_pattern"):
            out.append(n)
        stack.extend(n.named_children)
    return out


def _string_consts(units):
    consts = {}
    for u in units:
        stack = [u.tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "variable_declarator":
                name, val = n.child_by_field_name("name"), n.child_by_field_name("value")
                if name is not None and val is not None and name.type == "identifier" and val.type in jsast.STRING_TYPES:
                    v = jsast.string_value(val, u.src)
                    if v and "://" in v:
                        consts.setdefault(jsast.text_of(name, u.src), v)
            stack.extend(n.named_children)
    return consts


def _named_nodes(unit):
    out = {}
    stack = [unit.tree.root_node]
    while stack:
        n = stack.pop()
        if n.type in jsast.FUNC_TYPES and n.is_named:
            nm = jsast._func_name(n, unit.src)
            if nm:
                out.setdefault(nm, []).append(n)
        stack.extend(n.named_children)
    return out


def make_classifier(primary_domains, registrable):
    def classify(url):
        if not url:
            return {"class": "unknown", "host": None}
        if url.startswith(("chrome-extension://", "/", "./")) or "://" not in url:
            return {"class": "self", "host": None}
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            host = ""
        if not host:
            return {"class": "unknown", "host": None}
        reg = registrable(host)
        return {"class": "primary" if reg in primary_domains else "third_party", "host": host}
    return classify


def analyze(pkg, primary_domains, registrable):
    """Flows for every parsed unit of a reach.Package."""
    units = [u for us in pkg.units.values() for u in us]
    consts = _string_consts(units)
    classify = make_classifier(primary_domains, registrable)
    content = {jsast.norm_ref(s) for cs in pkg.manifest.get("content_scripts") or [] for s in cs.get("js") or []}
    flows, timer_names, timer_ranges = {}, set(), []
    for u in units:
        a = Analyzer(u, consts, classify, _named_nodes(u))
        root = u.tree.root_node
        taint, tr = Env(None), set()
        for _ in range(4):                # fixpoint over the whole unit (closures share names)
            if not a.run(root, taint, tr):
                break
        for k, fl in a.flows.items():
            flows.setdefault(k, fl)
        timer_names |= a.timer_names
        timer_ranges += [(u.file, b) for b in a.timer_nodes]
    # timer-driven functions: passed to setInterval/onAlarm, plus what they call by name (2 levels)
    timer_ids = set()
    for fn in pkg.funcs.values():
        if fn.node is not None and ((fn.file, fn.node.start_byte) in timer_ranges or
                                    (fn.kind == "named" and fn.name in timer_names)):
            timer_ids.add(fn.id)
    frontier = set(timer_ids)
    for _ in range(2):
        nxt = set()
        for fid in frontier:
            fn = pkg.funcs[fid]
            nxt |= set(fn.inline_children)
            for nm in fn.names:
                nxt |= {g.id for g in pkg.by_name.get(nm, ())}
        frontier = nxt - timer_ids
        timer_ids |= nxt
    for fl in flows.values():
        fns = pkg.funcs_at(fl.file, fl.line)
        fl.function = fns[0].name if fns else None
        fl.timer = any(f.id in timer_ids or _inside_timer(pkg, f, timer_ids) for f in fns)
        fl.reachability = pkg.status(fl.file, fl.line)
        fl.content_script = fl.file in content
    return sorted(flows.values(), key=lambda f: (f.file, f.line))


def _inside_timer(pkg, fn, timer_ids):
    p, seen = fn.parent, set()
    while p and p not in seen:
        seen.add(p)
        if p in timer_ids:
            return True
        p = pkg.funcs[p].parent if p in pkg.funcs else None
    return False
