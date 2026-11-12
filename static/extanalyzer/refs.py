"""D: is an IOC referenced by reachable code, or only present as data?

code-referenced  the host/URL is in a string literal of reachable JavaScript, was
                 reconstructed by DET-OBF-STRING, is loaded by a reachable page
                 (<script>/<iframe>/<img>/<link> with a remote src/href), or sits in
                 a code file that could not be parsed (kept, to be safe)
data-only        anything else: JSON/CSS/text files, unreachable code, comments,
                 and URLs that only appear inside prose strings (documentation
                 links in library error messages, license text)

Only code-referenced IOCs go into YARA/Sigma, and only code-referenced intel or
URLhaus hits with high confidence change the verdict.
"""

import ipaddress
import re
from urllib.parse import urlsplit

URL_IN_RE = re.compile(r"""(?:https?|wss?)://[^\s'"`<>()\\{}|^]{3,2048}""", re.I)
HOST_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,63}$", re.I)
HTML_LOAD_RE = re.compile(r"""<(?:script|iframe|img|link|embed|object)\b[^>]*?\b(?:src|href|data)\s*=\s*["']"""
                          r"""((?:https?:|wss?:)?//[^"']+)""", re.I)
STRONG = ("code", "reconstructed", "html-load", "unparsed")


def _host(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _add(hosts, host, ctx):
    if host:
        hosts.setdefault(host, set()).add(ctx)


def _scan_literal(s, hosts, urls):
    for m in URL_IN_RE.finditer(s):
        url = m.group(0).rstrip(".,;:'\"")
        prose = m.start() > 0 and bool(re.search(r"\s", s))
        ctx = "message" if prose else "code"
        _add(hosts, _host(url), ctx)
        if not prose:
            urls.add(url)
    v = s.strip()
    if HOST_RE.fullmatch(v):
        _add(hosts, v.lower(), "code")
    else:
        try:
            ipaddress.ip_address(v)
            _add(hosts, v, "code")
        except ValueError:
            pass


def code_references(pkg, detector_records=()):
    """(host -> contexts, set of URLs) seen in reachable code."""
    hosts, urls = {}, set()
    for fn in pkg.funcs.values():
        if fn.id in pkg.reached:
            for s in fn.strings:
                if "." in s:
                    _scan_literal(s, hosts, urls)
    for rel in pkg.unparsed:
        for m in URL_IN_RE.finditer(pkg.text_used.get(rel, "")):
            url = m.group(0).rstrip(".,;:'\"")
            _add(hosts, _host(url), "unparsed")
            urls.add(url)
    for rel, text in pkg.text_used.items():
        if rel in pkg.html_srcs and rel in pkg.reached_files:
            for m in HTML_LOAD_RE.finditer(text):
                url = m.group(1)
                url = "https:" + url if url.startswith("//") else url
                _add(hosts, _host(url), "html-load")
                urls.add(url)
    for r in detector_records:
        if r.get("detector") == "DET-OBF-STRING" and r.get("reachability") != "unreachable":
            v = (r.get("details") or {}).get("value") or ""
            for m in URL_IN_RE.finditer(v):
                _add(hosts, _host(m.group(0)), "reconstructed")
                urls.add(m.group(0).rstrip(".,;:'\""))
            if HOST_RE.fullmatch(v.strip()):
                _add(hosts, v.strip().lower(), "reconstructed")
    return hosts, urls


def classify(found_iocs, pkg, detector_records=()):
    """Annotate IOC dicts in place with `reference` and `reference_reason`."""
    if pkg is None:
        for key in ("domains", "urls", "ips"):
            for i in found_iocs[key]:
                i["reference"] = "unclassified"
                i["reference_reason"] = "no syntax trees (tree-sitter missing): treated as code-referenced"
        return
    hosts, urls = code_references(pkg, detector_records)

    def files_of(i):
        return ", ".join(sorted(i.get("files") or {})[:5]) or i["first_seen"]

    for key in ("domains", "ips"):
        for i in found_iocs[key]:
            ctx = hosts.get(i["value"].lower(), set())
            strong = sorted(c for c in ctx if c in STRONG)
            if strong:
                i["reference"] = "code-referenced"
                i["reference_reason"] = "in reachable code (" + ", ".join(strong) + ")"
            elif "message" in ctx:
                i["reference"] = "data-only"
                i["reference_reason"] = "only inside prose strings (e.g. documentation links in error messages)"
            else:
                i["reference"] = "data-only"
                i["reference_reason"] = f"not in reachable code; found in {files_of(i)}"
    for i in found_iocs["urls"]:
        h = _host(i["value"])
        if i["value"] in urls or any(u.startswith(i["value"]) for u in urls if len(u) > len(i["value"])):
            i["reference"] = "code-referenced"
            i["reference_reason"] = "URL literal in reachable code"
        elif "code" in hosts.get(h, ()) or "reconstructed" in hosts.get(h, ()):
            i["reference"] = "data-only"
            i["reference_reason"] = "host is used by code, this URL is only data"
        else:
            i["reference"] = "data-only"
            i["reference_reason"] = f"not in reachable code; found in {files_of(i)}"


def is_code(i):
    return i.get("reference") in ("code-referenced", "unclassified", None)
