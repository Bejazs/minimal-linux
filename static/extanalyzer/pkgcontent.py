"""E: content that does not belong in a browser extension package.

Executables (PE, ELF, Mach-O, Java archives) are high; server-side or shell
scripts (PHP, Python, shell, batch, PowerShell, ...) are medium. Detection uses
content signatures first and the file extension second; the files are only read.
"""

import os
import struct

from .common import finding

EXEC_EXT = {".exe", ".dll", ".scr", ".sys", ".msi", ".so", ".dylib", ".node", ".jar", ".apk", ".elf"}
SCRIPT_EXT = {".py", ".pyc", ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".wsf",
              ".php", ".phtml", ".pl", ".rb", ".cgi", ".asp", ".aspx", ".jsp"}
JS_EXT = {".js", ".mjs", ".cjs"}
MACHO = {b"\xcf\xfa\xed\xfe": "Mach-O 64-bit executable", b"\xce\xfa\xed\xfe": "Mach-O executable",
         b"\xfe\xed\xfa\xcf": "Mach-O 64-bit executable", b"\xfe\xed\xfa\xce": "Mach-O executable",
         b"\xca\xfe\xba\xbe": "Mach-O universal binary or Java class file"}


def _pe(head):
    if head[:2] != b"MZ" or len(head) < 0x40:
        return False
    off = struct.unpack_from("<I", head, 0x3C)[0]
    return off + 4 <= len(head) and head[off:off + 4] == b"PE\x00\x00"


def classify(rel, head):
    """(kind, label, by) or None. kind: executable | script."""
    ext = os.path.splitext(rel)[1].lower()
    if _pe(head):
        return "executable", "Windows PE executable", "signature"
    if head[:4] == b"\x7fELF":
        return "executable", "ELF executable", "signature"
    if head[:4] in MACHO:
        return "executable", MACHO[head[:4]], "signature"
    if head.lstrip()[:5].lower() == b"<?php" or (b"<?php" in head[:4096] and ext not in JS_EXT):
        return "script", "PHP script", "signature"
    if head[:2] == b"#!" and ext not in JS_EXT:
        line = head.split(b"\n", 1)[0][:80].decode("ascii", "replace")
        return "script", f"script with interpreter line `{line}`", "signature"
    if ext in EXEC_EXT:
        return "executable", f"{ext} file", "extension"
    if ext in SCRIPT_EXT:
        return "script", f"{ext} script", "extension"
    return None


def analyze(root, inventory):
    findings, n = [], 0
    for item in inventory:
        rel = item["path"]
        if rel.startswith("_deob"):
            continue
        try:
            with open(os.path.join(root, rel), "rb") as f:
                head = f.read(8192)
        except OSError:
            continue
        c = classify(rel, head)
        if not c:
            continue
        kind, label, by = c
        n += 1
        sev = "high" if kind == "executable" else "medium"
        conf = "high" if by == "signature" else "medium"
        f = finding(f"PKG-NONEXT-{n:03d}", f"Non-extension content in package: {label}", sev, conf,
                    f"{rel} is a {label} (detected by {by}); browsers never run it as part of an extension, so it "
                    "is either leftover build material or a payload for something outside the browser",
                    path=rel, attack=["T1027.009"] if kind == "executable" else [], category="package")
        f["kind"] = "non-extension-content-in-package"
        f["reachability"] = "n/a"
        f["sha256"] = item.get("sha256")
        findings.append(f)
    return findings
