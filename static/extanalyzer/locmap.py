"""H: original (minified) and beautified locations for every finding.

Minified files are scanned and parsed in their beautified copy (_deob/...), so
line numbers point there. jsbeautifier only changes whitespace, so the same
position in the original file is the one with the same count of non-whitespace
characters before it. The mapping is checked by comparing the next characters
in both files; if they differ it is marked approximate.
"""

import os
import re

NONWS = re.compile(r"\S+")
CHECK = 24
MAX_BYTES = 16 * 1024 * 1024


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(MAX_BYTES)
    except OSError:
        return None


def _counts_at_lines(text, lines):
    """non-whitespace chars before the start of each wanted line (1-based)."""
    want = sorted(set(lines))
    out, count, i = {}, 0, 0
    for n, line in enumerate(text.split("\n"), start=1):
        while i < len(want) and want[i] == n:
            out[n] = count
            i += 1
        if i >= len(want):
            break
        count += len(line) - sum(1 for ch in line if ch.isspace())
    return out


def _offsets_for_counts(text, counts):
    """offset in text of the k-th non-whitespace char, for each k."""
    want = sorted(set(counts))
    out, c, i = {}, 0, 0
    if not want:
        return out
    for m in NONWS.finditer(text):
        L = m.end() - m.start()
        while i < len(want) and want[i] < c + L:
            out[want[i]] = m.start() + (want[i] - c)
            i += 1
        if i >= len(want):
            break
        c += L
    return out


def _nonws_prefix(text, off, n=CHECK):
    out = []
    for ch in text[off:off + n * 8]:
        if not ch.isspace():
            out.append(ch)
            if len(out) >= n:
                break
    return "".join(out)


def _line_col(text, off):
    line = text.count("\n", 0, off) + 1
    return line, off - (text.rfind("\n", 0, off) + 1) + 1


def map_locations(findings, unpacked, file_info):
    beaut = {fi["path"]: fi["beautified_path"] for fi in file_info if fi.get("beautified_path")}
    per_file = {}
    for f in findings:
        loc = f.get("location")
        if not loc or not loc.get("path"):
            continue
        p = loc["path"]
        if p in beaut and loc.get("line_start") and (loc.get("lines_refer_to") == beaut[p]
                                                     or f.get("category") in ("behavior", "detector")):
            per_file.setdefault(p, []).append(f)
        else:
            loc["minified_location"] = {"path": p, "line": loc.get("line_start"), "column": None}
    for p, fs in per_file.items():
        orig, pretty = _read(os.path.join(unpacked, p)), _read(os.path.join(unpacked, beaut[p]))
        if orig is None or pretty is None:
            continue
        counts = _counts_at_lines(pretty, [f["location"]["line_start"] for f in fs])
        starts = [0] + [m.end() for m in re.finditer("\n", pretty)]
        # position in the beautified line: the matched text when it is there, else the line start
        want = {}
        for f in fs:
            ln = f["location"]["line_start"]
            k = counts.get(ln)
            if k is None:
                continue
            ls = starts[ln - 1] if ln - 1 < len(starts) else len(pretty)
            le = starts[ln] - 1 if ln < len(starts) else len(pretty)
            pos = ls
            m = (f.get("match") or "").split("\n", 1)[0]
            if m and len(m) >= 3:
                i = pretty.find(m, ls, le)
                if i >= 0:
                    pos = i
                    k += sum(1 for ch in pretty[ls:i] if not ch.isspace())
            want[id(f)] = (k, pos)
        offs = _offsets_for_counts(orig, [k for k, _ in want.values()])
        for f in fs:
            loc = f["location"]
            ln = loc["line_start"]
            loc["beautified_location"] = {"path": beaut[p], "line": ln}
            loc["lines_refer_to"] = beaut[p]
            k, pos = want.get(id(f), (None, None))
            off = offs.get(k) if k is not None else None
            if off is None:
                loc["minified_location"] = {"path": p, "line": None, "column": None, "mapping": "not found"}
                continue
            ok = _nonws_prefix(orig, off) == _nonws_prefix(pretty, pos)
            oline, ocol = _line_col(orig, off)
            loc["minified_location"] = {"path": p, "line": oline, "column": ocol,
                                        "mapping": "verified" if ok else "approximate"}
