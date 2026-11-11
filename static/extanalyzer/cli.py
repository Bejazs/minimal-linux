"""ext-analyze entry point (runs inside the container).

  python3 -m extanalyzer SAMPLE [SAMPLE ...] --out /out
  python3 -m extanalyzer --diff OLD NEW --out /out
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

from . import __version__, code_scan, emit, iocs, manifest, score
from .unpack import UnpackError, inventory, unpack


def _slug(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:60] or "sample"


def _tree_hash(files):
    h = hashlib.sha256()
    for f in files:
        h.update(f["path"].encode() + b"\0" + f["sha256"].encode() + b"\n")
    return h.hexdigest()


def _wasm_to_wat(unpacked, deob):
    tool = shutil.which("wasm2wat")
    if not tool:
        return
    for dirpath, dirs, files in os.walk(unpacked):
        dirs[:] = [d for d in dirs if d != "_deob"]
        for fn in files:
            if fn.endswith(".wasm"):
                src = os.path.join(dirpath, fn)
                dst = os.path.join(deob, os.path.relpath(src, unpacked) + ".wat")
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                subprocess.run([tool, src, "-o", dst], timeout=60, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def analyze_one(sample, out_root):
    tmp = os.path.join(out_root, ".tmp-" + _slug(os.path.basename(sample.rstrip("/"))))
    shutil.rmtree(tmp, ignore_errors=True)
    unpacked = os.path.join(tmp, "unpacked")
    meta = unpack(sample, unpacked)
    files = inventory(unpacked)
    sha = (meta["hashes"] or {}).get("sha256") or _tree_hash(files)
    deob = os.path.join(unpacked, "_deob")

    m_meta, findings = manifest.analyze(unpacked)
    c_findings, file_info = code_scan.analyze(unpacked, m_meta, deob)
    findings += c_findings
    _wasm_to_wat(unpacked, deob)
    ext_id = meta.get("crx_id") or (m_meta or {}).get("id_from_key")
    found_iocs = iocs.extract(unpacked, self_ids={ext_id} if ext_id else ())
    findings = emit.sort_findings(findings)
    verdict = score.score(findings)

    name = (m_meta or {}).get("name") or meta["input"]
    if isinstance(name, str) and name.startswith("__MSG_"):
        name = meta["input"]
    out_dir = os.path.join(out_root, f"{_slug(str(name))}-{sha[:12]}")
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.rename(tmp, out_dir)
    unpacked = os.path.join(out_dir, "unpacked")

    report = {
        "tool": {"name": "minimal-linux ext-analyze", "version": __version__,
                 "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")},
        "sample": {
            "name": name, "version": (m_meta or {}).get("version"),
            "manifest_version": (m_meta or {}).get("manifest_version"),
            "input": meta["input"], "input_type": meta["input_type"],
            "sha256": sha if meta["hashes"] else None, "tree_sha256": None if meta["hashes"] else sha,
            "hashes": meta["hashes"], "crx_version": meta.get("crx_version"),
            "extension_id": ext_id, "file_count": len(files),
        },
        "verdict": verdict,
        "manifest": m_meta,
        "findings": findings,
        "iocs": found_iocs,
        "files": file_info,
        "inventory": files,
        "warnings": meta["warnings"],
        "artifacts": {},
    }
    report["artifacts"]["yara"] = emit.write_yara(report, out_dir, unpacked)
    report["artifacts"]["sigma"] = emit.write_sigma(report, out_dir)
    emit.write_iocs_csv(found_iocs, out_dir)
    emit.write_json(report, out_dir)
    emit.write_markdown(report, out_dir)
    return out_dir, report


def diff_reports(old, new, out_root):
    def perms(r):
        m = r.get("manifest") or {}
        return set(m.get("permissions", [])) | set(m.get("optional_permissions", [])) | set(m.get("host_permissions", []))

    def key(f):
        loc = f.get("location") or {}
        return (f["id"].rsplit("-", 1)[0], loc.get("path"), f.get("match"))

    old_inv = {f["path"]: f["sha256"] for f in old["inventory"]}
    new_inv = {f["path"]: f["sha256"] for f in new["inventory"]}
    old_keys = {key(f) for f in old["findings"]}
    new_findings = [f for f in new["findings"] if key(f) not in old_keys]
    old_dom = {d["value"] for d in old["iocs"]["domains"]}
    d = {
        "old": {"name": old["sample"]["name"], "version": old["sample"]["version"], "verdict": old["verdict"]},
        "new": {"name": new["sample"]["name"], "version": new["sample"]["version"], "verdict": new["verdict"]},
        "permissions_added": sorted(perms(new) - perms(old)),
        "permissions_removed": sorted(perms(old) - perms(new)),
        "update_url_changed": (old.get("manifest") or {}).get("update_url") != (new.get("manifest") or {}).get("update_url"),
        "files_added": sorted(set(new_inv) - set(old_inv)),
        "files_removed": sorted(set(old_inv) - set(new_inv)),
        "files_changed": sorted(p for p in set(new_inv) & set(old_inv) if new_inv[p] != old_inv[p]),
        "new_domains": sorted({x["value"] for x in new["iocs"]["domains"]} - old_dom),
        "new_findings": new_findings,
    }
    out = os.path.join(out_root, f"diff-{_slug(str(old['sample']['version']))}-to-{_slug(str(new['sample']['version']))}")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "diff.json"), "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    md = [f"# Diff {d['old']['version']} → {d['new']['version']} ({d['new']['name']})", "",
          f"Verdict: {d['old']['verdict']['label']} ({d['old']['verdict']['score']}) → "
          f"{d['new']['verdict']['label']} ({d['new']['verdict']['score']})", ""]
    for k in ("permissions_added", "permissions_removed", "files_added", "files_removed", "files_changed", "new_domains"):
        md.append(f"- {k.replace('_', ' ')}: " + (", ".join(f"`{x}`" for x in d[k]) or "none"))
    md.append(f"- update_url changed: {d['update_url_changed']}")
    md.append("")
    md.append("## New findings")
    for f in emit.sort_findings(new_findings):
        loc = f.get("location") or {}
        where = f"{loc.get('path')}" + (f":{loc['line_start']}" if loc.get("line_start") else "")
        md.append(f"- {f['id']} {f['title']} ({f['severity']}/{f['confidence']}) at {where}")
    if not new_findings:
        md.append("- none")
    with open(os.path.join(out, "diff.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ext-analyze", description="Static analysis of Chrome extensions (never executes them)")
    ap.add_argument("samples", nargs="*", help=".crx, .zip or unpacked folder")
    ap.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"), help="compare two versions of the same extension")
    ap.add_argument("--out", default="/out", help="output root (default /out)")
    args = ap.parse_args(argv)
    if not args.samples and not args.diff:
        ap.error("give at least one sample, or --diff OLD NEW")
    os.makedirs(args.out, exist_ok=True)
    rc = 0
    results = {}
    for sample in (args.diff or []) + args.samples:
        if sample in results:
            continue
        try:
            out_dir, rep = analyze_one(sample, args.out)
            results[sample] = rep
            v = rep["verdict"]
            print(f"{v['label']:<17} {v['score']:>3}/100  conf={v['confidence']:<6} "
                  f"{rep['sample']['name']} {rep['sample']['version'] or ''} -> {out_dir}/report.md")
        except (UnpackError, OSError, ValueError) as e:
            rc = 1
            print(f"error            {sample}: {e}", file=sys.stderr)
    if args.diff and all(s in results for s in args.diff):
        out = diff_reports(results[args.diff[0]], results[args.diff[1]], args.out)
        print(f"diff -> {out}/diff.md")
    return rc


if __name__ == "__main__":
    sys.exit(main())
