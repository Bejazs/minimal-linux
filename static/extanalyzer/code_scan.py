"""Pattern-based scan of extension JavaScript/HTML. Code is read as text only.

Each rule has a base confidence. Confidence is raised to "high" when a
dangerous sink sits next to a matching source (e.g. fetch() feeding eval()
within a few lines), and the reason says so.
"""

import math
import os
import re

from .common import finding, line_of, snippet

try:
    import jsbeautifier  # optional: used to produce readable copies of minified/obfuscated code
except ImportError:  # pragma: no cover
    jsbeautifier = None

CODE_EXT = {".js", ".mjs", ".cjs", ".html", ".htm"}
MAX_FILE_BYTES = 8 * 1024 * 1024
NEAR_LINES = 12

# (id, regex, title, severity, confidence, reason, attack, scope)
# scope: "any" | "content" (only reported in content scripts)
RULES = [
    ("CODE-EVAL", r"\beval\s*\(", "Dynamic code execution: eval()", "medium", "low",
     "eval() runs arbitrary strings as code; sometimes used by bundlers", ["T1059.007"], "any"),
    ("CODE-FUNC", r"\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"`a-zA-Z_$]", "Dynamic code execution: Function constructor",
     "medium", "low", "the Function constructor compiles strings into code", ["T1059.007"], "any"),
    ("CODE-TIMER", r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]", "String passed to setTimeout/setInterval", "medium", "medium",
     "a string argument is evaluated as code", ["T1059.007"], "any"),
    ("CODE-IMPORT", r"\bimportScripts\s*\(\s*['\"`]https?:", "importScripts() from a remote URL", "high", "high",
     "loads and runs remote code in the worker", ["T1105", "T1059.007"], "any"),
    ("CODE-SCRIPTTAG", r"createElement\s*\(\s*['\"]script['\"]\s*\)", "Creates <script> elements dynamically", "low", "low",
     "common in page tools; dangerous if the src is remote", ["T1059.007"], "any"),
    ("CODE-REMOTESRC", r"\.src\s*=\s*['\"`]https?://", "Script/iframe src set to a remote URL", "medium", "medium",
     "pulls content from a remote server at runtime", ["T1105"], "any"),
    ("CODE-EXEC", r"chrome\.(?:scripting\.executeScript|tabs\.executeScript)\s*\(", "Injects code into tabs (executeScript)",
     "low", "low", "standard API for page tools; risky if the injected code is remote", ["T1059.007"], "any"),
    ("CODE-WASM", r"\bWebAssembly\.(?:instantiate|compile|instantiateStreaming|compileStreaming)\b", "Loads WebAssembly",
     "low", "low", "WASM hides logic from JS review; used legitimately for performance", ["T1027"], "any"),
    ("CODE-ATOB-EVAL", r"\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(", "Executes decoded data (eval(atob(...)))",
     "high", "high", "decoding and executing a string in one step is a classic obfuscation pattern", ["T1027", "T1059.007"], "any"),
    ("DATA-COOKIES", r"chrome\.cookies\.getAll\s*\(", "Reads all cookies (chrome.cookies.getAll)", "medium", "medium",
     "can collect session cookies for every site the user is logged into", ["T1539"], "any"),
    ("DATA-DOCCOOKIE", r"\bdocument\.cookie\b(?!\s*=)", "Reads document.cookie", "low", "low",
     "reads cookies of the current page; common for analytics", ["T1539"], "any"),
    ("DATA-KEYLOG", r"addEventListener\s*\(\s*['\"](?:keydown|keypress|keyup|input)['\"]", "Keyboard/input listener in a content script",
     "medium", "low", "captures what the user types on web pages; also used by legitimate form helpers", ["T1056.001"], "content"),
    ("DATA-PASSWORD", r"""type\s*=\s*\\?['"]?password|\[type=\\?['"]?password""", "Accesses password fields", "medium", "medium",
     "selects password inputs on web pages", ["T1056.003"], "content"),
    ("DATA-CLIPBOARD", r"navigator\.clipboard\.readText|execCommand\s*\(\s*['\"]paste['\"]", "Reads the clipboard", "medium", "medium",
     "can capture copied passwords or crypto addresses", ["T1115"], "any"),
    ("DATA-HISTORY", r"chrome\.history\.search\s*\(", "Reads browsing history", "medium", "low",
     "history collection; legitimate for history tools", ["T1217"], "any"),
    ("DATA-SCREEN", r"chrome\.tabs\.captureVisibleTab\s*\(|chrome\.desktopCapture\.", "Captures screen or tab images", "medium", "medium",
     "screenshots of what the user sees", ["T1113"], "any"),
    ("DEF-MGMT", r"chrome\.management\.(?:setEnabled|uninstall)\s*\(", "Disables or uninstalls other extensions", "high", "medium",
     "can turn off security extensions", ["T1562.001"], "any"),
    ("DEF-DEBUGGER", r"chrome\.debugger\.attach\s*\(", "Attaches the debugger to tabs", "high", "medium",
     "full control of the page via DevTools protocol", ["T1185"], "any"),
    ("NET-PROXY", r"chrome\.proxy\.settings\.set\s*\(", "Changes browser proxy settings", "high", "medium",
     "can route traffic through an attacker server", ["T1090", "T1557"], "any"),
    ("NET-CSPSTRIP", r"""['"]content-security-policy['"]""", "Touches Content-Security-Policy headers", "medium", "low",
     "removing CSP headers weakens site protections; also seen in dev tools", ["T1562"], "any"),
    ("NET-BEACON", r"navigator\.sendBeacon\s*\(", "Sends data with navigator.sendBeacon", "low", "low",
     "fire-and-forget upload; common for analytics", ["T1041"], "any"),
    ("NET-WS", r"new\s+WebSocket\s*\(\s*['\"`]wss?://", "Opens a WebSocket to a hard-coded server", "low", "low",
     "persistent channel to a remote server", ["T1071.001"], "any"),
    ("EXFIL-DISCORD", r"discord(?:app)?\.com/api/webhooks/", "Discord webhook URL", "high", "high",
     "webhooks are a common exfiltration channel and rarely needed by extensions", ["T1567"], "any"),
    ("EXFIL-TELEGRAM", r"api\.telegram\.org/bot", "Telegram bot API URL", "high", "high",
     "Telegram bots are a common exfiltration/C2 channel", ["T1102", "T1567"], "any"),
    ("EVADE-WEBDRIVER", r"navigator\.webdriver|HeadlessChrome|__nightmare|callPhantom|_phantom",
     "Checks for automation/headless browser", "medium", "medium",
     "sandbox/analysis evasion: behaviour may differ under automated analysis", ["T1497.001"], "any"),
    ("EVADE-DELAY", r"set(?:Timeout|Interval)\s*\([^;]{0,200}?,\s*(?:\d{8,}|\d+\s*\*\s*60\s*\*\s*60\s*\*\s*1000)",
     "Long delay before running code", "low", "low", "time-based evasion: code may wait hours or days", ["T1497.003"], "any"),
    ("CRYPTO-WALLET", r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b(?![\w-])",
     "Hard-coded cryptocurrency address", "medium", "low", "may be a clipboard-hijack replacement address; can also be a donation link", ["T1565"], "any"),
]
RULES = [(r[0], re.compile(r[1]), *r[2:]) for r in RULES]

SOURCE_RE = re.compile(r"\bfetch\s*\(|XMLHttpRequest|\.open\s*\(\s*['\"](?:GET|POST)|\$\.(?:get|ajax|post)\s*\(|axios\.|chrome\.storage\.\w+\.get|\.responseText|\.text\s*\(\s*\)")
SINKS_WITH_SOURCE = {"CODE-EVAL", "CODE-FUNC", "CODE-EXEC", "CODE-SCRIPTTAG"}
FETCH_RE = re.compile(r"\bfetch\s*\(|XMLHttpRequest|\$\.(?:get|ajax|post)\s*\(|axios\.")
SEND_DATA_RE = re.compile(r"document\.cookie|chrome\.cookies|\.value\b|navigator\.clipboard|chrome\.history")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def obfuscation_signals(text: str) -> dict:
    lines = text.splitlines() or [""]
    longest = max(len(l) for l in lines)
    hexnames = len(re.findall(r"\b_0x[0-9a-f]{4,6}\b", text))
    escapes = len(re.findall(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", text))
    strings = re.findall(r"'([^'\\\n]{60,})'|\"([^\"\\\n]{60,})\"", text)
    high_ent = sum(1 for a, b in strings if entropy(a or b) > 5.2)
    return {"longest_line": longest, "hex_identifiers": hexnames, "escape_sequences": escapes,
            "high_entropy_strings": high_ent, "minified": longest > 1000 and len(lines) < 20}


def is_obfuscated(sig: dict) -> bool:
    return sig["hex_identifiers"] >= 20 or sig["escape_sequences"] >= 200 or sig["high_entropy_strings"] >= 3


def _scan_text(text, rel, content_script, findings, counters, deob_rel=None):
    lines = text.splitlines() or [""]
    source_lines = [line_of(text, m.start())[0] for m in SOURCE_RE.finditer(text)]
    fetch_lines = [line_of(text, m.start())[0] for m in FETCH_RE.finditer(text)]
    seen = set()
    for rid, rx, title, sev, conf, reason, attack, scope in RULES:
        if scope == "content" and not content_script:
            continue
        for m in rx.finditer(text):
            ln, col = line_of(text, m.start())
            if (rid, ln) in seen:
                continue
            seen.add((rid, ln))
            f_sev, f_conf, f_reason, f_title, f_attack = sev, conf, reason, title, list(attack)
            near_src = [s for s in source_lines if 0 <= ln - s <= NEAR_LINES]
            if rid in SINKS_WITH_SOURCE and near_src:
                f_sev, f_conf = "high", "high"
                f_title = title + " fed by network/storage data"
                f_reason = (f"a network or storage read (line {near_src[-1]}) is within {ln - near_src[-1]} lines "
                            f"before this sink, so remotely supplied code is likely executed")
                f_attack = sorted(set(f_attack) | {"T1105"})
            if rid in {"DATA-KEYLOG", "DATA-PASSWORD", "DATA-COOKIES", "DATA-CLIPBOARD"}:
                near_fetch = sorted((s for s in fetch_lines if abs(s - ln) <= NEAR_LINES), key=lambda s: abs(s - ln))
                if near_fetch:
                    f_sev, f_conf = "high", "high" if rid != "DATA-KEYLOG" else "medium"
                    f_title = title + " near a network send"
                    f_reason = (f"collected data and a network request (line {near_fetch[0]}) are within "
                                f"{abs(near_fetch[0] - ln)} lines, consistent with exfiltration")
                    f_attack = sorted(set(f_attack) | {"T1041"})
            counters[rid] = counters.get(rid, 0) + 1
            fid = f"{rid}-{counters[rid]:03d}"
            f = finding(fid, f_title, f_sev, f_conf, f_reason, path=rel, line_start=ln,
                        snippet_text=snippet(lines, ln, col), attack=f_attack, category="code",
                        deob_path=deob_rel, match=m.group(0))
            if deob_rel:
                f["location"]["lines_refer_to"] = deob_rel
            findings.append(f)


def analyze(root: str, manifest_meta: dict, deob_root: str):
    findings, counters, file_info = [], {}, []
    content_js = set()
    for cs in (manifest_meta or {}).get("content_scripts", []):
        content_js.update(os.path.normpath(p) for p in cs.get("js", []))

    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "_deob"]
        for fn in sorted(files):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            ext = os.path.splitext(fn)[1].lower()
            if ext == ".wasm":
                counters["CODE-WASMFILE"] = counters.get("CODE-WASMFILE", 0) + 1
                findings.append(finding(f"CODE-WASMFILE-{counters['CODE-WASMFILE']:03d}", f"WebAssembly module: {rel}",
                                        "low", "low", "compiled code that cannot be reviewed as JS; inspect the .wat in _deob",
                                        path=rel, attack=["T1027"], category="code"))
                continue
            if ext not in CODE_EXT or os.path.getsize(full) > MAX_FILE_BYTES:
                continue
            with open(full, encoding="utf-8", errors="replace") as f:
                text = f.read()
            sig = obfuscation_signals(text)
            obf = is_obfuscated(sig)
            deob_rel = None
            scan_text = text
            if (obf or sig["minified"]) and jsbeautifier and ext != ".html":
                try:
                    pretty = jsbeautifier.beautify(text)
                    deob_rel = os.path.join("_deob", rel)
                    out = os.path.join(deob_root, rel)
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    with open(out, "w", encoding="utf-8") as o:
                        o.write(pretty)
                    scan_text = pretty
                except Exception:
                    deob_rel = None
            if obf:
                counters["CODE-OBF"] = counters.get("CODE-OBF", 0) + 1
                findings.append(finding(
                    f"CODE-OBF-{counters['CODE-OBF']:03d}", f"Obfuscated JavaScript: {rel}", "medium", "medium",
                    f"{sig['hex_identifiers']} _0x identifiers, {sig['escape_sequences']} escape sequences, "
                    f"{sig['high_entropy_strings']} high-entropy strings; obfuscation hides intent from review",
                    path=rel, attack=["T1027"], category="code", deob_path=deob_rel))
            is_cs = os.path.normpath(rel) in content_js
            _scan_text(scan_text, rel, is_cs, findings, counters, deob_rel)
            file_info.append({"path": rel, "content_script": is_cs, "obfuscated": obf,
                              "minified": sig["minified"], "beautified_path": deob_rel})
    return findings, file_info
