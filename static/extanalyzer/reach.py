"""Entry points, reference graph and reachability of code and findings.

Entry points come from the manifest (background, content scripts, extension
pages, web_accessible_resources) plus the scripts each page loads. From there a
function is reached when reached code mentions its name, contains it inline, or
names its file in a string (getURL, executeScript files, importScripts, ...).

Limits (reported in behaviors.json): names are resolved across the whole
package without lexical scoping, so collisions make more code reachable, never
less. Anything not parsed is "unknown" and still counts for the score.
"""

import fnmatch
import json
import os
import re

from . import jsast

JS_EXT = {".js", ".mjs", ".cjs"}
HTML_EXT = {".html", ".htm"}


def _load_manifest(root):
    try:
        with open(os.path.join(root, "manifest.json"), encoding="utf-8", errors="replace") as f:
            text = f.read().lstrip("﻿")
        try:
            return json.loads(text)
        except ValueError:
            return json.loads(re.sub(r"^\s*//.*$", "", text, flags=re.M))
    except (OSError, ValueError):
        return {}


def entry_points(m, all_files):
    """[(path, reason)] of files the browser loads directly."""
    out = []

    def add(p, why):
        if isinstance(p, str) and p:
            n = jsast.norm_ref(p)
            if n:
                out.append((n, why))

    bg = m.get("background") or {}
    add(bg.get("service_worker"), "background service worker")
    for s in bg.get("scripts") or []:
        add(s, "background script")
    add(bg.get("page"), "background page")
    for cs in m.get("content_scripts") or []:
        for s in cs.get("js") or []:
            add(s, "content script")
    for key in ("action", "browser_action", "page_action"):
        add((m.get(key) or {}).get("default_popup"), f"{key} popup")
    add(m.get("options_page"), "options page")
    add((m.get("options_ui") or {}).get("page"), "options page")
    add(m.get("devtools_page"), "devtools page")
    add((m.get("side_panel") or {}).get("default_path"), "side panel")
    for v in (m.get("chrome_url_overrides") or {}).values():
        add(v, "chrome_url_overrides page")
    for v in (m.get("sandbox") or {}).get("pages") or []:
        add(v, "sandbox page")
    patterns = []
    for w in m.get("web_accessible_resources") or []:
        if isinstance(w, str):
            patterns.append(w)
        elif isinstance(w, dict):
            patterns += [r for r in w.get("resources") or [] if isinstance(r, str)]
    for pat in patterns:
        pat = pat.lstrip("/")
        for f in all_files:
            if os.path.splitext(f)[1].lower() in JS_EXT | HTML_EXT and fnmatch.fnmatch(f, pat):
                out.append((os.path.normpath(f), "web_accessible_resources"))
    return out


class Package:
    def __init__(self, root, file_info):
        self.root = root
        self.manifest = _load_manifest(root)
        self.units = {}          # file -> [Unit]
        self.unparsed = []       # code files that could not be parsed
        self.funcs = {}          # id -> Func
        self.by_name = {}        # name -> [Func] (named functions only)
        self.file_tops = {}      # file -> [top Func ids]
        self.html_srcs = {}      # html file -> [script files]
        self.text_used = {}      # file -> text whose line numbers findings use
        self._load(file_info)

    def _read(self, rel):
        with open(os.path.join(self.root, rel), encoding="utf-8", errors="replace") as f:
            return f.read()

    def _load(self, file_info):
        beaut = {fi["path"]: fi.get("beautified_path") for fi in file_info or []}
        all_files = []
        for dirpath, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d != "_deob"]
            for fn in files:
                all_files.append(os.path.normpath(os.path.relpath(os.path.join(dirpath, fn), self.root)))
        self.all_files = sorted(all_files)
        for rel in self.all_files:
            ext = os.path.splitext(rel)[1].lower()
            if ext not in JS_EXT | HTML_EXT:
                continue
            text = self._read(beaut[rel] if beaut.get(rel) else rel)
            self.text_used[rel] = text
            pieces = []
            if ext in HTML_EXT:
                srcs, inline = jsast.html_scripts(text)
                self.html_srcs[rel] = [s for s in (jsast.norm_ref(x, rel) for x in srcs) if s]
                pieces = inline
            else:
                pieces = [(text, 0)]
            units = []
            ok = True
            for i, (code, off) in enumerate(pieces):
                u = jsast.parse_text(rel, code, off)
                if u is None:
                    ok = False
                    continue
                jsast.index_unit(u, f"{rel}#{i}")
                units.append(u)
            if not ok:
                self.unparsed.append(rel)
            self.units[rel] = units
            for u in units:
                for fn in u.funcs:
                    self.funcs[fn.id] = fn
                    if fn.kind == "named" and fn.name:
                        self.by_name.setdefault(fn.name, []).append(fn)
                self.file_tops.setdefault(rel, []).append(u.top.id)

    def compute(self):
        self.entries = entry_points(self.manifest, self.all_files)
        self.reached_files = set()
        self.reached = set()
        file_q = [p for p, _ in self.entries]
        func_q = []

        def reach_file(p):
            if p in self.reached_files:
                return
            self.reached_files.add(p)
            func_q.extend(self.file_tops.get(p, []))
            for s in self.html_srcs.get(p, []):
                file_q.append(s)

        while file_q or func_q:
            while file_q:
                reach_file(file_q.pop())
            if not func_q:
                break
            fid = func_q.pop()
            if fid in self.reached:
                continue
            self.reached.add(fid)
            fn = self.funcs[fid]
            func_q.extend(fn.inline_children)
            for name in fn.names:
                for g in self.by_name.get(name, ()):
                    func_q.append(g.id)
            for s in fn.strings:
                ref = jsast.norm_ref(s, fn.file)
                if ref and (ref in self.file_tops or ref in self.html_srcs):
                    file_q.append(ref)
                elif ref:
                    # basename match, e.g. getURL("inject.js") from a subfolder
                    base = os.path.basename(ref)
                    for f in self.file_tops:
                        if os.path.basename(f) == base:
                            file_q.append(f)
        return self

    # ---- queries -------------------------------------------------------
    def funcs_at(self, rel, line):
        """Innermost functions of a file whose range contains line (several if tied)."""
        cands = [fn for u in self.units.get(rel, []) for fn in u.funcs
                 if fn.start_line <= line <= fn.end_line]
        if not cands:
            return []
        best = min(fn.end_line - fn.start_line for fn in cands)
        return [fn for fn in cands if fn.end_line - fn.start_line == best]

    def status(self, rel, line=None):
        """reachable | unreachable | unknown for a location."""
        if rel is None:
            return "n/a"
        ext = os.path.splitext(rel)[1].lower()
        if ext not in JS_EXT | HTML_EXT:
            return "n/a"
        if rel in self.unparsed or rel not in self.units:
            return "unknown"
        if not self.units[rel]:      # html without inline code, or nothing parsed
            return "reachable" if rel in self.reached_files else "unreachable"
        if line is None:
            return "reachable" if rel in self.reached_files else "unreachable"
        fns = self.funcs_at(rel, line)
        if not fns:
            # html line outside any inline script (markup)
            return "reachable" if rel in self.reached_files else "unreachable"
        return "reachable" if any(f.id in self.reached for f in fns) else "unreachable"

    def function_label(self, rel, line):
        fns = self.funcs_at(rel, line) if rel and line else []
        return fns[0].name if fns else None

    def summary(self):
        code_files = sorted(self.units)
        named = [f for f in self.funcs.values() if f.kind != "top"]
        return {
            "parser": "tree-sitter" if jsast.available() else "unavailable",
            "entry_points": [{"path": p, "reason": r, "exists": p in self.units or p in self.all_files}
                             for p, r in self.entries],
            "files_reachable": sorted(f for f in code_files if f in self.reached_files),
            "files_unreachable": sorted(f for f in code_files if f not in self.reached_files and f not in self.unparsed),
            "files_unparsed": sorted(self.unparsed),
            "functions": {"total": len(named), "reachable": sum(1 for f in named if f.id in self.reached)},
            "unreachable_functions": sorted(
                (f.to_dict() for f in named if f.id not in self.reached and f.file in self.reached_files
                 and f.kind == "named"), key=lambda d: (d["file"], d["lines"][0]))[:200],
            "limits": [
                "names are resolved package-wide without lexical scope (over-approximation)",
                "inline callbacks are assumed to run when their enclosing function runs",
                "computed property calls (obj[k]()) are not resolved; their targets stay reachable",
                "files that fail to parse are 'unknown' and still count for the score",
            ],
        }


def analyze(root, file_info):
    if not jsast.available():
        return None
    return Package(root, file_info).compute()
