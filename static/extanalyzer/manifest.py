"""manifest.json checks: permissions, host access, content scripts, CSP,
externally_connectable, update_url, web_accessible_resources."""

import base64
import json
import os
import re

from .common import finding, snippet
from .unpack import id_from_pubkey

WEBSTORE_UPDATE_URLS = {
    "https://clients2.google.com/service/update2/crx",
    "http://clients2.google.com/service/update2/crx",
}

BROAD_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*", "http://*/", "https://*/"}

# permission -> (severity, confidence, reason, attack)
PERMISSIONS = {
    "debugger": ("high", "medium", "debugger lets the extension drive any tab via the DevTools protocol; rarely needed outside developer tools", ["T1185"]),
    "nativeMessaging": ("high", "medium", "nativeMessaging talks to a native binary on the host, a path out of the browser sandbox", ["T1559"]),
    "proxy": ("high", "medium", "proxy can route all browser traffic through an attacker-controlled server", ["T1090", "T1557"]),
    "cookies": ("medium", "medium", "cookies gives read access to session cookies; common in legitimate extensions too", ["T1539"]),
    "clipboardRead": ("medium", "medium", "clipboardRead can harvest copied passwords and wallet addresses", ["T1115"]),
    "desktopCapture": ("medium", "medium", "desktopCapture can record the screen", ["T1113"]),
    "tabCapture": ("medium", "medium", "tabCapture can record tab contents", ["T1113"]),
    "management": ("medium", "medium", "management can list, disable or uninstall other extensions (e.g. security tools)", ["T1562.001"]),
    "webRequestBlocking": ("medium", "medium", "webRequestBlocking (MV2) can modify or block requests in flight", ["T1185"]),
    "webRequest": ("medium", "low", "webRequest observes all requests; widely used by ad blockers and privacy tools", ["T1185"]),
    "declarativeNetRequest": ("low", "low", "declarativeNetRequest can rewrite headers or redirect requests; common in ad blockers", ["T1185"]),
    "declarativeNetRequestWithHostAccess": ("low", "low", "declarativeNetRequest with host access can redirect requests", ["T1185"]),
    "scripting": ("medium", "low", "scripting injects code into pages; common for page tools", ["T1059.007"]),
    "history": ("medium", "low", "history exposes browsing history", ["T1217"]),
    "privacy": ("medium", "low", "privacy can change browser privacy settings", ["T1562"]),
    "contentSettings": ("low", "low", "contentSettings can change per-site permissions", []),
    "identity": ("low", "low", "identity can obtain OAuth tokens for the user's Google account", ["T1528"]),
    "topSites": ("low", "low", "topSites exposes most visited sites", ["T1217"]),
    "bookmarks": ("low", "low", "bookmarks exposes saved sites", ["T1217"]),
    "downloads": ("low", "low", "downloads can save files to disk", ["T1105"]),
    "geolocation": ("low", "low", "geolocation exposes the user's location", []),
    "tabs": ("info", "low", "tabs exposes URLs and titles of open tabs; very common", []),
    "webNavigation": ("info", "low", "webNavigation tracks page navigation; common", []),
}


def _load(text: str):
    text = text.lstrip("﻿")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Chrome tolerates // comments in manifest.json
        stripped = re.sub(r'^\s*//.*$', "", text, flags=re.M)
        return json.loads(stripped)


def _key_line(lines, key, value=None):
    """Best-effort line number of a key (and optionally a value) in manifest.json."""
    pat_key = re.compile(r'"' + re.escape(key) + r'"\s*:')
    start = None
    for i, l in enumerate(lines, 1):
        if pat_key.search(l):
            start = i
            if value is None:
                return i
            break
    if value is not None:
        pat_val = re.compile(r'"' + re.escape(value) + r'"')
        for i in range(start or 1, len(lines) + 1):
            if pat_val.search(lines[i - 1]):
                return i
    return start or 1


def analyze(root: str):
    path = os.path.join(root, "manifest.json")
    if not os.path.isfile(path):
        return None, [finding("META-000", "manifest.json missing", "high", "high",
                              "a Chrome extension must have manifest.json at its root", category="manifest")]
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    lines = text.splitlines() or [""]
    try:
        m = _load(text)
    except json.JSONDecodeError as e:
        return None, [finding("META-001", f"manifest.json is not valid JSON: {e}", "medium", "high",
                              "Chrome would refuse to load it; may be a broken or tampered sample", category="manifest")]

    findings = []
    seq = [0]

    def add(prefix, title, sev, conf, reason, key, value=None, attack=None):
        seq[0] += 1
        ln = _key_line(lines, key, value)
        findings.append(finding(f"{prefix}-{seq[0]:03d}", title, sev, conf, reason, path="manifest.json",
                                line_start=ln, snippet_text=snippet(lines, ln), attack=attack, category="manifest"))

    mv = m.get("manifest_version")
    perms = [p for p in m.get("permissions", []) if isinstance(p, str)]
    opt = [p for p in m.get("optional_permissions", []) if isinstance(p, str)]
    hosts = [h for h in m.get("host_permissions", []) if isinstance(h, str)]
    if mv == 2:  # MV2 mixes host patterns into permissions
        hosts += [p for p in perms if "://" in p or p == "<all_urls>"]
    all_perms = set(perms) | set(opt)

    for p in perms + opt:
        if p in PERMISSIONS:
            sev, conf, reason, attack = PERMISSIONS[p]
            if sev == "info":
                continue
            where = "permissions" if p in perms else "optional_permissions"
            add("PERM", f"Permission: {p}" + (" (optional)" if p not in perms else ""), sev, conf, reason, where, p, attack)

    broad = [h for h in hosts if h in BROAD_HOSTS]
    if broad:
        combo = all_perms & {"cookies", "webRequest", "webRequestBlocking", "scripting", "debugger", "declarativeNetRequest"}
        sev = "high" if combo else "medium"
        reason = ("broad host access combined with " + ", ".join(sorted(combo)) +
                  " allows reading or altering data on every site") if combo else \
            "access to every site; legitimate for some tools but the widest possible scope"
        key = "host_permissions" if "host_permissions" in m else "permissions"
        add("HOST", f"Host access to all sites ({broad[0]})", sev, "medium", reason, key, broad[0], ["T1185"])

    for i, cs in enumerate(m.get("content_scripts", []) or []):
        matches = cs.get("matches", []) if isinstance(cs, dict) else []
        if any(x in BROAD_HOSTS for x in matches):
            extra = []
            if cs.get("all_frames"):
                extra.append("all_frames")
            if cs.get("run_at") == "document_start":
                extra.append("document_start")
            add("CS", "Content script injected into all sites" + (f" ({', '.join(extra)})" if extra else ""),
                "medium", "low", "runs inside every page the user visits; can read forms and DOM. Common for page tools",
                "content_scripts", next(x for x in matches if x in BROAD_HOSTS), ["T1185"])

    csp = m.get("content_security_policy")
    csp_text = json.dumps(csp) if isinstance(csp, dict) else (csp or "")
    if "unsafe-eval" in csp_text:
        add("CSP", "CSP allows unsafe-eval", "high", "high",
            "explicitly re-enables eval()/new Function in extension pages", "content_security_policy",
            attack=["T1059.007"])
    remote = re.findall(r"script-src[^;\"]*?(https?://[^\s;\"']+)", csp_text)
    if remote:
        add("CSP", f"CSP allows remote scripts ({remote[0]})", "high", "high",
            "extension pages may load code from a remote server, so behaviour can change after review",
            "content_security_policy", attack=["T1105"])

    ec = m.get("externally_connectable")
    if isinstance(ec, dict):
        ec_m = ec.get("matches", []) or []
        if "*" in (ec.get("ids") or []):
            add("EXT", "externally_connectable accepts any extension ID", "medium", "medium",
                "any installed extension can message this one", "externally_connectable")
        wide = [x for x in ec_m if re.match(r"^\*://\*\.[^/]+/", x) or x in BROAD_HOSTS]
        if wide:
            add("EXT", f"externally_connectable allows web pages: {wide[0]}", "medium", "low",
                "websites matching this pattern can send messages to the extension", "externally_connectable", wide[0])

    uu = m.get("update_url")
    if uu and uu not in WEBSTORE_UPDATE_URLS:
        add("META", f"update_url points outside the Chrome Web Store ({uu})", "high", "high",
            "updates come from a server the Web Store does not review", "update_url", attack=["T1105", "T1176"])

    for w in m.get("web_accessible_resources", []) or []:
        if isinstance(w, dict) and any(x in BROAD_HOSTS for x in w.get("matches", [])):
            add("WAR", "web_accessible_resources exposed to all sites", "low", "low",
                "any site can load these files, which allows fingerprinting the extension", "web_accessible_resources")
            break
        if isinstance(w, str):  # MV2 form: exposed to every site
            add("WAR", "web_accessible_resources exposed to all sites (MV2)", "low", "low",
                "any site can load these files, which allows fingerprinting the extension", "web_accessible_resources")
            break

    bg = m.get("background") or {}
    meta = {
        "name": m.get("name"),
        "version": m.get("version"),
        "manifest_version": mv,
        "description": m.get("description"),
        "permissions": perms,
        "optional_permissions": opt,
        "host_permissions": hosts,
        "update_url": uu,
        "background": bg.get("service_worker") or bg.get("scripts") or bg.get("page"),
        "content_scripts": [{"matches": cs.get("matches", []), "js": cs.get("js", [])}
                            for cs in (m.get("content_scripts") or []) if isinstance(cs, dict)],
        "id_from_key": None,
    }
    if isinstance(m.get("key"), str):
        try:
            meta["id_from_key"] = id_from_pubkey(base64.b64decode(m["key"]))
        except Exception:
            pass
    return meta, findings
