"""Scoring, verdict and ATT&CK names.

score()      = v0.1: sum of severity x confidence over all findings (kept for comparison).
score_v0_2() = v0.2: only findings not marked unreachable; any critical combination
               rule (combine.py) makes the label "malicious" regardless of the sum.
"""

SEV_W = {"critical": 50, "high": 25, "medium": 10, "low": 3, "info": 0}
CONF_W = {"high": 1.0, "medium": 0.6, "low": 0.3}

# Names for the technique IDs the rules emit (MITRE ATT&CK Enterprise).
ATTACK_NAMES = {
    "T1027": "Obfuscated Files or Information",
    "T1041": "Exfiltration Over C2 Channel",
    "T1056.001": "Input Capture: Keylogging",
    "T1056.003": "Input Capture: Web Portal Capture",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1090": "Proxy",
    "T1102": "Web Service",
    "T1105": "Ingress Tool Transfer",
    "T1113": "Screen Capture",
    "T1115": "Clipboard Data",
    "T1176": "Software Extensions",
    "T1185": "Browser Session Hijacking",
    "T1217": "Browser Information Discovery",
    "T1497.001": "Virtualization/Sandbox Evasion: System Checks",
    "T1497.003": "Virtualization/Sandbox Evasion: Time Based Evasion",
    "T1497.002": "Virtualization/Sandbox Evasion: User Activity Based Checks",
    "T1528": "Steal Application Access Token",
    "T1539": "Steal Web Session Cookie",
    "T1557": "Adversary-in-the-Middle",
    "T1559": "Inter-Process Communication",
    "T1562": "Impair Defenses",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1564.003": "Hide Artifacts: Hidden Window",
    "T1565": "Data Manipulation",
    "T1567": "Exfiltration Over Web Service",
}

# Same rule repeated many times should not dominate the score.
MAX_PER_RULE = 3


def contribution(f):
    return SEV_W[f["severity"]] * CONF_W[f["confidence"]]


def rule_of(f):
    return f["id"].rsplit("-", 1)[0]


def score(findings):
    """v0.1 (unchanged behaviour)."""
    per_rule, contribs = {}, []
    for f in sorted(findings, key=contribution, reverse=True):
        r = rule_of(f)
        per_rule[r] = per_rule.get(r, 0) + 1
        if per_rule[r] <= MAX_PER_RULE:
            contribs.append((contribution(f), f))
    total = min(100, round(sum(c for c, _ in contribs)))
    strong = [f for f in findings if f["severity"] == "high" and f["confidence"] == "high"]
    if total >= 70 and strong:
        label = "likely_malicious"
    elif total >= 30:
        label = "suspicious"
    else:
        label = "low_risk"

    top = [f for c, f in contribs[:5] if c > 0]
    if not top:
        conf = "medium"
        reason = "no significant findings; static analysis cannot rule out remote or delayed behaviour"
    else:
        hi = sum(1 for f in top if f["confidence"] == "high")
        lo = sum(1 for f in top if f["confidence"] == "low")
        if hi >= max(1, len(top) // 2):
            conf = "high"
        elif lo > len(top) / 2:
            conf = "low"
        else:
            conf = "medium"
        reason = (f"based on the {len(top)} strongest findings: {hi} high-confidence, "
                  f"{len(top) - hi - lo} medium, {lo} low")
    techniques = sorted({t for f in findings if f["severity"] != "info" for t in f.get("attack", [])})
    return {
        "label": label,
        "score": total,
        "confidence": conf,
        "confidence_reason": reason,
        "top_findings": [f["id"] for f in top],
        "attack": [{"id": t, "name": ATTACK_NAMES.get(t, "")} for t in techniques],
    }


def score_v0_2(findings):
    live = [f for f in findings if f.get("reachability") != "unreachable"]
    base = score(live)
    crit = [f for f in live if f["severity"] == "critical"]
    unreachable = len(findings) - len(live)
    if crit:
        base["label"] = "malicious"
        base["score"] = 100
        hi = [f for f in crit if f["confidence"] == "high"]
        base["confidence"] = "high" if hi else "medium"
        base["confidence_reason"] = (f"{len(crit)} critical combination rule match(es) in reachable code: "
                                     + ", ".join(sorted({f['id'].rsplit('-', 1)[0] for f in crit})))
        base["top_findings"] = [f["id"] for f in crit[:5]] + [i for i in base["top_findings"]
                                                              if i not in {f["id"] for f in crit}][:max(0, 5 - len(crit))]
    else:
        # a high/high combination rule (e.g. COMB-C2) or a detector marked verdict_floor (DET-CMD-DISPATCH)
        # is never below likely_malicious
        comb = [f for f in live if (f.get("category") == "behavior" or f.get("verdict_floor"))
                and f["severity"] == "high" and f["confidence"] == "high"]
        if comb and base["label"] in ("low_risk", "suspicious"):
            base["label"] = "likely_malicious"
            base["score"] = max(base["score"], 70)
            base["confidence_reason"] += "; raised by " + comb[0]["id"].rsplit("-", 1)[0]
    base["rules_fired"] = sorted({f["id"].rsplit("-", 1)[0] for f in live if f.get("category") == "behavior"})
    base["unreachable_findings_excluded"] = unreachable
    base["version"] = "0.2"
    return base
