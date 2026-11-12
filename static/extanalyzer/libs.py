"""G/J: known libraries (intel/libraries.json), identified by license headers or
distinctive strings. A library file gets `library: <name>` in files[], no
CODE-OBF (minified distributions look obfuscated), and its findings lose one
confidence step but stay visible: a library copy can be tampered with.
Combination rules (critical flows) are annotated, not lowered.
"""

import os

HEADER_BYTES = 4096
MAX_BYTES = 8 * 1024 * 1024
LOWER = {"high": "medium", "medium": "low", "low": "low"}


def detect(root, file_info, intel):
    for fi in file_info:
        try:
            with open(os.path.join(root, fi["path"]), encoding="utf-8", errors="replace") as f:
                text = f.read(MAX_BYTES)
        except OSError:
            continue
        head = text[:HEADER_BYTES]
        for lib in intel.libraries:
            hay = head if lib["where"] == "header" else text
            m = next((p.search(hay) for p in lib["patterns"] if p.search(hay)), None)
            if m:
                fi["library"] = lib["name"]
                fi["library_evidence"] = m.group(0)[:80]
                break


def adjust(findings, file_info):
    libs = {fi["path"]: (fi["library"], fi.get("library_evidence", "")) for fi in file_info if fi.get("library")}
    for f in findings:
        path = (f.get("location") or {}).get("path")
        if path not in libs:
            continue
        name, ev = libs[path]
        f["library"] = name
        note = f"; file identified as library {name} (`{ev}`)"
        rule = f["id"].rsplit("-", 1)[0]
        if rule == "CODE-OBF":
            f["severity"], f["confidence"] = "info", "low"
            f["attack"] = []
            f["confidence_reason"] += note + ": minified distribution, not counted as obfuscation"
        elif f.get("category") in ("code", "detector"):
            old = f["confidence"]
            f["confidence"] = LOWER[old]
            f["confidence_reason"] += note + f": confidence lowered from {old}; a library copy can still be modified"
            if rule == "DET-OBF-STRING" and "T1027" in f.get("attack", []) and f["severity"] == "high":
                f["severity"] = "medium"
        elif f.get("category") == "behavior":
            f["confidence_reason"] += note + " (combination rules are not lowered)"
