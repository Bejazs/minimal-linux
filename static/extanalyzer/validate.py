"""Offline validation over a corpus, measured per category (never per extension name).

Corpus layout (kept outside the repo, on the analysis instance):

  corpus/benign/<category>/<sample>      .crx, .zip or unpacked folder
  corpus/malicious/<category>/<sample>

  python3 -m extanalyzer --validate CORPUS [--baseline OLD/results.json] --out /out

Writes <out>/validation/results.json and report.md: detection rate per malicious
category, critical/high findings in benign samples for manual review, v0.1 vs
v0.2 labels, and changes against a baseline run. Both files hold verdicts, rule
ids, titles and path:line only, never code or snippets from the samples, so they
can be shared without sharing malware.

  python3 -m extanalyzer --validate-cases tests/cases --out /out

checks the synthetic cases (expected.json) and writes the same kind of report.
"""

import datetime
import json
import os
import shutil
import tempfile
import time

from . import __version__
from .unpack import UnpackError

DETECTED = {"malicious", "likely_malicious"}
SEV_RANK = {"info": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}


def _rule(f):
    return f["id"].rsplit("-", 1)[0]


def _where(f):
    loc = f.get("location") or {}
    ml = loc.get("minified_location") or {}
    w = loc.get("path") or ""
    if loc.get("line_start"):
        w += f":{loc['line_start']}"
    if loc.get("beautified_location") and ml.get("line"):
        w += f" (original {ml['line']}:{ml['column']})"
    return w


def summarize(rep):
    """What results.json keeps of a report: no snippets, no code."""
    v = rep["verdict"]
    strong = [f for f in rep["findings"] if SEV_RANK[f["severity"]] >= 2 and f.get("reachability") != "unreachable"
              and f.get("scored", True)]
    return {
        "name": rep["sample"]["name"], "version": rep["sample"]["version"],
        "sha256": rep["sample"]["sha256"] or rep["sample"]["tree_sha256"],
        "label": v["label"], "score": v["score"], "confidence": v["confidence"],
        "label_v0_1": (rep.get("score_v0.1") or {}).get("label"),
        "score_v0_1": (rep.get("score_v0.1") or {}).get("score"),
        "rules_fired": v.get("rules_fired", []),
        "critical_high": [{"id": f["id"], "rule": _rule(f), "title": f["title"], "severity": f["severity"],
                           "confidence": f["confidence"], "where": _where(f), "library": f.get("library")}
                          for f in strong][:50],
        "attack": [t["id"] for t in v.get("attack", [])],
    }


def _samples(corpus):
    for kind in ("benign", "malicious"):
        base = os.path.join(corpus, kind)
        if not os.path.isdir(base):
            continue
        for cat in sorted(os.listdir(base)):
            cdir = os.path.join(base, cat)
            if not os.path.isdir(cdir) or cat.startswith("."):
                continue
            for s in sorted(os.listdir(cdir)):
                if not s.startswith("."):
                    yield kind, cat, os.path.join(cdir, s)


def run(corpus, out_root, analyze_one, lists_dir=None, intel_dir=None, baseline=None):
    vdir = os.path.join(out_root, "validation")
    os.makedirs(vdir, exist_ok=True)
    work = tempfile.mkdtemp(prefix="validate-", dir=out_root)
    results = []
    try:
        for kind, cat, path in _samples(corpus):
            rel = os.path.relpath(path, corpus)
            t = time.time()
            try:
                _, rep = analyze_one(path, work, lists_dir, intel_dir)
                r = summarize(rep)
                r["error"] = None
            except (UnpackError, OSError, ValueError) as e:
                r = {"name": os.path.basename(path), "label": "error", "error": str(e)[:200]}
            r.update({"set": kind, "category": cat, "sample": rel, "seconds": round(time.time() - t, 1)})
            results.append(r)
            print(f"{kind:<9} {cat:<20} {r['label']:<17} {rel}", flush=True)
            for d in os.listdir(work):        # keep only the summary; the full reports are per-sample
                shutil.rmtree(os.path.join(work, d), ignore_errors=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    base = None
    if baseline:
        with open(baseline, encoding="utf-8") as f:
            base = json.load(f)
    doc = {"tool_version": __version__, "generated_at": _now(), "corpus": os.path.basename(os.path.abspath(corpus)),
           "samples": results, "metrics": metrics(results), "baseline": compare(results, base) if base else None}
    with open(os.path.join(vdir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    with open(os.path.join(vdir, "report.md"), "w", encoding="utf-8") as f:
        f.write(report_md(doc))
    return vdir, doc


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def metrics(results):
    m = {"malicious": {}, "benign": {}, "errors": sum(1 for r in results if r.get("error"))}
    for r in results:
        if r.get("error"):
            continue
        c = m[r["set"]].setdefault(r["category"], {"n": 0, "malicious": 0, "likely_malicious": 0, "suspicious": 0,
                                                   "low_risk": 0, "v0_1_detected": 0, "with_critical_high": 0})
        c["n"] += 1
        c[r["label"]] = c.get(r["label"], 0) + 1
        if r.get("label_v0_1") in DETECTED:
            c["v0_1_detected"] += 1
        if r["critical_high"]:
            c["with_critical_high"] += 1
    for cat, c in m["malicious"].items():
        c["detection_rate"] = round((c["malicious"] + c["likely_malicious"]) / c["n"], 3) if c["n"] else None
        c["v0_1_detection_rate"] = round(c["v0_1_detected"] / c["n"], 3) if c["n"] else None
    for cat, c in m["benign"].items():
        c["false_positive_rate"] = round((c["malicious"] + c["likely_malicious"]) / c["n"], 3) if c["n"] else None
        c["v0_1_false_positive_rate"] = round(c["v0_1_detected"] / c["n"], 3) if c["n"] else None
    return m


def compare(results, base):
    old = {r.get("sha256"): r for r in base.get("samples", []) if r.get("sha256")}
    changed, missing = [], 0
    for r in results:
        o = old.get(r.get("sha256"))
        if o is None:
            missing += 1
            continue
        if o.get("label") != r.get("label"):
            changed.append({"sample": r["sample"], "set": r["set"], "category": r["category"],
                            "old": o.get("label"), "new": r.get("label"),
                            "rules_added": sorted(set(r.get("rules_fired", [])) - set(o.get("rules_fired", []))),
                            "rules_removed": sorted(set(o.get("rules_fired", [])) - set(r.get("rules_fired", [])))})
    return {"baseline_version": base.get("tool_version"), "matched": len(results) - missing,
            "not_in_baseline": missing, "changed": changed}


def report_md(doc):
    m = doc["metrics"]
    md = [f"# Validation report — ext-analyze {doc['tool_version']}", "",
          f"Generated {doc['generated_at']}. Corpus `{doc['corpus']}`: {len(doc['samples'])} samples, "
          f"{m['errors']} errors. Measured per category. This file has no code from the samples.", ""]
    md += ["## Malicious: detection rate", "",
           "Detected = `malicious` or `likely_malicious`.", "",
           "| Category | n | detected v0.2 | rate v0.2 | rate v0.1 | malicious | likely | suspicious | low_risk |",
           "|---|---|---|---|---|---|---|---|---|"]
    for cat, c in sorted(m["malicious"].items()):
        md.append(f"| {cat} | {c['n']} | {c['malicious'] + c['likely_malicious']} | {c['detection_rate']} | "
                  f"{c['v0_1_detection_rate']} | {c['malicious']} | {c['likely_malicious']} | {c['suspicious']} | "
                  f"{c['low_risk']} |")
    if not m["malicious"]:
        md.append("| (none) | | | | | | | | |")
    md += ["", "## Benign: false positives", "",
           "| Category | n | FP v0.2 | FP rate v0.2 | FP rate v0.1 | suspicious | with critical/high findings |",
           "|---|---|---|---|---|---|---|"]
    for cat, c in sorted(m["benign"].items()):
        md.append(f"| {cat} | {c['n']} | {c['malicious'] + c['likely_malicious']} | {c['false_positive_rate']} | "
                  f"{c['v0_1_false_positive_rate']} | {c['suspicious']} | {c['with_critical_high']} |")
    if not m["benign"]:
        md.append("| (none) | | | | | | |")
    md += ["", "## Critical/high findings in benign samples (manual review)", ""]
    rows = [(r, f) for r in doc["samples"] if r["set"] == "benign" and not r.get("error") for f in r["critical_high"]]
    for r, f in rows[:300]:
        lib = f" [library {f['library']}]" if f.get("library") else ""
        md.append(f"- `{r['sample']}` ({r['label']}): {f['rule']} {f['severity']}/{f['confidence']} at "
                  f"`{f['where']}`{lib}. {f['title']}")
    if not rows:
        md.append("- none")
    missed = [r for r in doc["samples"] if r["set"] == "malicious" and not r.get("error") and r["label"] not in DETECTED]
    md += ["", "## Malicious samples not detected", ""]
    md += [f"- `{r['sample']}` ({r['category']}): {r['label']} {r['score']}; rules: "
           f"{', '.join(r['rules_fired']) or 'none'}" for r in missed] or ["- none"]
    flips = [r for r in doc["samples"] if not r.get("error") and r.get("label_v0_1") != r["label"]]
    md += ["", "## v0.1 → v0.2 label changes (same run)", ""]
    md += [f"- `{r['sample']}` ({r['set']}/{r['category']}): {r['label_v0_1']} → {r['label']}" for r in flips] or ["- none"]
    if doc.get("baseline"):
        b = doc["baseline"]
        md += ["", f"## Against baseline (tool {b['baseline_version']})", "",
               f"Matched by SHA-256: {b['matched']}; not in baseline: {b['not_in_baseline']}.", ""]
        md += [f"- `{c['sample']}` ({c['set']}/{c['category']}): {c['old']} → {c['new']}"
               + (f"; rules added {', '.join(c['rules_added'])}" if c["rules_added"] else "")
               + (f"; removed {', '.join(c['rules_removed'])}" if c["rules_removed"] else "")
               for c in b["changed"]] or ["- no label changes"]
    errs = [r for r in doc["samples"] if r.get("error")]
    if errs:
        md += ["", "## Errors", ""] + [f"- `{r['sample']}`: {r['error']}" for r in errs]
    return "\n".join(md) + "\n"


# ---- synthetic cases --------------------------------------------------------------
def run_cases(cases_dir, out_root, analyze_one):
    """Check tests/cases/*/expected.json; returns (vdir, doc)."""
    vdir = os.path.join(out_root, "validation")
    os.makedirs(vdir, exist_ok=True)
    work = tempfile.mkdtemp(prefix="cases-", dir=out_root)
    rows = []
    try:
        for name in sorted(os.listdir(cases_dir)):
            exp_path = os.path.join(cases_dir, name, "expected.json")
            if not os.path.isfile(exp_path):
                continue
            with open(exp_path, encoding="utf-8") as f:
                exp = json.load(f)
            _, rep = analyze_one(os.path.join(cases_dir, name), work, None, None)
            rows.append({"case": name, "expected": exp, "label": rep["verdict"]["label"],
                         "label_v0_1": rep["score_v0.1"]["label"], "problems": check_case(exp, rep)})
    finally:
        shutil.rmtree(work, ignore_errors=True)
    doc = {"tool_version": __version__, "generated_at": _now(), "cases": rows,
           "passed": sum(1 for r in rows if not r["problems"]), "total": len(rows)}
    with open(os.path.join(vdir, "cases.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    md = [f"# Synthetic cases — ext-analyze {doc['tool_version']}", "",
          f"{doc['passed']}/{doc['total']} cases pass. Positive cases must fire their rule, negative cases "
          "(the closest legitimate pattern) must not.", "",
          "| Case | Expected | v0.2 label | v0.1 label | Result |", "|---|---|---|---|---|"]
    for r in rows:
        e = r["expected"]
        def fmt(v):
            if isinstance(v, list):
                return ", ".join(v)
            if isinstance(v, dict):
                return ", ".join(f"{a} ≤ {b}" for a, b in v.items())
            return v
        want = "; ".join(f"{k}: {fmt(v)}" for k, v in e.items()
                         if k in ("present", "absent", "unreachable", "label", "not_label", "max_severity"))
        md.append(f"| {r['case']} | {want} | {r['label']} | {r['label_v0_1']} | "
                  + ("pass" if not r["problems"] else "FAIL: " + "; ".join(r["problems"])) + " |")
    with open(os.path.join(vdir, "cases.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    return vdir, doc


def check_case(exp, rep):
    rules = {}
    for f in rep["findings"]:
        rules.setdefault(_rule(f), []).append(f)
    p = []
    p += [f"missing {r}" for r in exp.get("present", []) if r not in rules]
    p += [f"unexpected {r}" for r in exp.get("absent", []) if r in rules]
    p += [f"{r} not unreachable" for r in exp.get("unreachable", [])
          if not all(f["reachability"] == "unreachable" for f in rules.get(r, []))]
    if "label" in exp and rep["verdict"]["label"] != exp["label"]:
        p.append(f"label {rep['verdict']['label']} != {exp['label']}")
    if "not_label" in exp and rep["verdict"]["label"] == exp["not_label"]:
        p.append(f"label is {exp['not_label']}")
    if "min_severity" in exp and exp.get("present"):
        top = max((SEV_RANK[f["severity"]] for r in exp["present"] for f in rules.get(r, [])), default=-2)
        if top < SEV_RANK[exp["min_severity"]]:
            p.append(f"severity below {exp['min_severity']}")
    for r, sev in exp.get("max_severity", {}).items():
        if any(SEV_RANK[f["severity"]] > SEV_RANK[sev] for f in rules.get(r, [])):
            p.append(f"{r} above {sev}")
    return p
