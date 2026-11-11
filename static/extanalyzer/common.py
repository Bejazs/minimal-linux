"""Shared helpers: finding records, defanging and code snippets."""

import re

SNIPPET_CONTEXT = 2
SNIPPET_MAX_LINE = 200

_URL_RE = re.compile(r"\b(https?|wss?)://([^/\s'\"`<>]+)", re.I)
_SCHEMES = {"http": "hxxp", "https": "hxxps", "ws": "wxs", "wss": "wxss"}
_TLDS = ("com|net|org|io|ru|cn|xyz|top|info|biz|me|co|app|dev|site|online|shop|tk|cc|pw|su|"
         "de|uk|fr|br|in|ir|kp|ua|us|eu|live|link|click|club|icu|cloud|host|website|space|fun|"
         "lol|gg|ly|to|ws|vip|work|store|tech|pro|xin|win|bid|loan|cam|rest|monster")
_BARE_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:" + _TLDS + r"))\b(?![.(\w])", re.I)


def defang(text: str) -> str:
    """Make URLs/domains non-clickable: https://a.example.com -> hxxps://a[.]example[.]com.
    Only URL hosts and bare tokens ending in a known TLD are touched, so code like
    chrome.cookies.getAll stays readable."""
    out, pos = [], 0
    for m in _URL_RE.finditer(text):
        out.append(_BARE_DOMAIN_RE.sub(lambda d: d.group(1).replace(".", "[.]"), text[pos:m.start()]))
        out.append(_SCHEMES[m.group(1).lower()] + "://" + m.group(2).replace(".", "[.]"))
        pos = m.end()
    out.append(_BARE_DOMAIN_RE.sub(lambda d: d.group(1).replace(".", "[.]"), text[pos:]))
    return "".join(out)


def defang_domain(d: str) -> str:
    return d.replace(".", "[.]")


def _clip(line: str, col: int = None) -> str:
    if len(line) <= SNIPPET_MAX_LINE:
        return line
    if col is None:
        return line[:SNIPPET_MAX_LINE] + " …"
    start = max(0, col - SNIPPET_MAX_LINE // 2)
    end = start + SNIPPET_MAX_LINE
    return ("… " if start else "") + line[start:end] + (" …" if end < len(line) else "")


def snippet(lines: list, line_no: int, col: int = None) -> str:
    """Lines around line_no (1-based); the suspicious line is marked with '>'."""
    lo = max(1, line_no - SNIPPET_CONTEXT)
    hi = min(len(lines), line_no + SNIPPET_CONTEXT)
    width = len(str(hi))
    out = []
    for n in range(lo, hi + 1):
        text = _clip(lines[n - 1].rstrip("\r\n"), col if n == line_no else None)
        mark = ">" if n == line_no else " "
        out.append(f"{str(n).rjust(width)} {mark}| {defang(text)}")
    return "\n".join(out)


def line_of(text: str, offset: int) -> tuple:
    """(1-based line, 0-based column) for a character offset."""
    line = text.count("\n", 0, offset) + 1
    col = offset - (text.rfind("\n", 0, offset) + 1)
    return line, col


def finding(fid, title, severity, confidence, confidence_reason, path=None,
            line_start=None, line_end=None, snippet_text=None, attack=None,
            category=None, deob_path=None, match=None):
    f = {
        "id": fid,
        "category": category,
        "title": title,
        "severity": severity,          # high | medium | low | info
        "confidence": confidence,      # high | medium | low
        "confidence_reason": confidence_reason,
        "attack": attack or [],
    }
    if path:
        loc = {"path": path, "line_start": line_start, "line_end": line_end or line_start}
        if deob_path:
            loc["deobfuscated_path"] = deob_path
        f["location"] = loc
    if snippet_text:
        f["snippet"] = snippet_text
    if match:
        f["match"] = match[:200]
    return f
