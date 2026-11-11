"""Combination rules: data flows that make an extension critical regardless of its score.

Each rule is documented in docs/rules.md (purpose, condition, closest legitimate
pattern, ATT&CK and gaps). Rules only use flows from flows.py; findings in code
that no entry point reaches are still emitted, marked unreachable, and do not
count for score v0.2.
"""

from .common import finding

EXFIL_DEST = {"third_party", "unknown"}

RULES = {
    "COMB-SESSION-EXFIL": {
        "title": "Session data sent to a third-party destination",
        "severity": "critical",
        "attack": ["T1539", "T1041"],
        "attack_gap": None,
        "why": "cookies or web storage are read and the data reaches a network send whose destination "
               "is not a domain the extension declares",
    },
    "COMB-INPUT-EXFIL": {
        "title": "Typed input or form data sent from a content script to a third party",
        "severity": "critical",
        "attack": ["T1056.001", "T1056.003", "T1041"],
        "attack_gap": None,
        "why": "keyboard/input events or password fields on web pages flow into a network send to an "
               "undeclared destination",
    },
    "COMB-REMOTE-CODE": {
        "title": "Network data executed as code",
        "severity": "critical",
        "attack": ["T1105", "T1059.007"],
        "attack_gap": None,
        "why": "a network response reaches eval/Function/executeScript code or a script src, so behaviour "
               "is defined by a server at runtime",
    },
    "COMB-C2": {
        "title": "Remote command channel (periodic poll controls privileged actions)",
        "severity": "high",
        "attack": ["T1071.001", "T1102", "T1059.007"],
        "attack_gap": "ATT&CK has no technique for remote task execution inside end-user browsers; "
                      "mapped to the closest C2 and execution techniques",
        "why": "code run from setInterval/chrome.alarms fetches data that then drives tab, window, "
               "scripting, navigation or request actions",
    },
    "COMB-AUTH-PROXY": {
        "title": "Authenticated requests to remotely chosen URLs, response sent back out",
        "severity": "critical",
        "attack": ["T1185", "T1041"],
        "attack_gap": "browser-session proxying for a remote operator has no dedicated technique; "
                      "mapped to Browser Session Hijacking",
        "why": "a credentialed request uses a URL that came from the network/messages/storage and its "
               "response body is sent to a remote destination",
    },
}


def _live(fl):
    return fl.reachability != "unreachable"


def evaluate(flows):
    """Returns (findings, matches) where matches are behaviour records for behaviors.json."""
    hits = {k: [] for k in RULES}
    for fl in flows:
        s = set(fl.sources)
        dest = (fl.dest or {}).get("class")
        if fl.sink == "network-send" and "session" in s and dest in EXFIL_DEST:
            hits["COMB-SESSION-EXFIL"].append(fl)
        if fl.sink == "network-send" and "input" in s and dest in EXFIL_DEST and fl.content_script:
            hits["COMB-INPUT-EXFIL"].append(fl)
        if fl.sink == "code-exec" and "network" in s:
            hits["COMB-REMOTE-CODE"].append(fl)
        if fl.timer and fl.sink in ("privileged", "code-exec") and s & {"network", "auth-response"}:
            hits["COMB-C2"].append(fl)
        if fl.sink == "network-send" and "auth-response" in s:
            hits["COMB-AUTH-PROXY"].append(fl)

    session_live = any(_live(f) for f in hits["COMB-SESSION-EXFIL"])
    findings, matches, n = [], [], 0
    for rid, fls in hits.items():
        rule = RULES[rid]
        for fl in fls:
            n += 1
            sev = rule["severity"]
            note = ""
            if rid == "COMB-C2" and session_live:
                sev, note = "critical", "; escalated because session data is also exfiltrated"
            dest = fl.dest or {}
            if dest.get("class") == "unknown" or (rid == "COMB-REMOTE-CODE" and "network" not in fl.sources):
                conf, why_conf = "medium", "destination is computed at runtime"
            else:
                conf, why_conf = "high", "source and sink are linked through variables in the syntax tree"
            where = dest.get("host") or dest.get("class") or ""
            reason = (f"{rule['why']}{note}. Flow: {'+'.join(fl.sources)} -> {fl.api}"
                      + (f" -> {where}" if where else "")
                      + (f" via {', '.join(fl.transforms)}" if fl.transforms else "")
                      + f". Confidence {conf}: {why_conf}.")
            f = finding(f"{rid}-{n:03d}", rule["title"], sev, conf, reason, path=fl.file, line_start=fl.line,
                        attack=list(rule["attack"]), category="behavior", match=fl.api)
            f["reachability"] = fl.reachability
            f["function"] = fl.function
            if rule["attack_gap"]:
                f["attack_gap"] = rule["attack_gap"]
            findings.append(f)
            matches.append({"rule": rid, "finding": f["id"], "severity": sev, "confidence": conf,
                            "reachability": fl.reachability, "flow": fl.to_dict()})
    return findings, matches
