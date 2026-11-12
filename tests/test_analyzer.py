"""Tests for the static analyzer. Run from the repo root:

    PYTHONPATH=static python3 -m unittest discover -s tests -v
"""

import io
import json
import os
import shutil
import struct
import tempfile
import unittest
import zipfile

from extanalyzer import cli, jsast, lists, unpack, validate
from extanalyzer.common import defang

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")


def _varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def _ld(field, payload):
    return _varint(field << 3 | 2) + _varint(len(payload)) + payload


def make_crx3(zip_bytes, crx_id16):
    signed = _ld(1, crx_id16)
    header = _ld(10000, signed)
    return b"Cr24" + struct.pack("<II", 3, len(header)) + header + zip_bytes


def zip_folder(folder, extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for root, _, files in os.walk(folder):
            for fn in files:
                p = os.path.join(root, fn)
                z.write(p, os.path.relpath(p, folder))
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.out)

    def run_one(self, sample):
        out_dir, rep = cli.analyze_one(sample, self.out)
        with open(os.path.join(out_dir, "report.json")) as f:
            self.assertEqual(json.load(f)["verdict"], rep["verdict"])
        return out_dir, rep

    def test_benign_is_low_risk(self):
        _, rep = self.run_one(os.path.join(SAMPLES, "benign-notes"))
        self.assertEqual(rep["verdict"]["label"], "low_risk")
        self.assertFalse([f for f in rep["findings"] if f["severity"] in ("high", "medium")])

    def test_suspicious_findings_have_location_snippet_confidence(self):
        out_dir, rep = self.run_one(os.path.join(SAMPLES, "suspicious-helper-1.1"))
        self.assertEqual(rep["verdict"]["label"], "malicious" if jsast.available() else "likely_malicious")
        self.assertEqual(rep["score_v0.1"]["label"], "likely_malicious")
        ids = {f["id"].rsplit("-", 1)[0]: f for f in rep["findings"]}
        ev = ids["CODE-EVAL"]
        self.assertEqual((ev["severity"], ev["confidence"]), ("high", "high"))
        self.assertEqual(ev["location"]["path"], "bg.js")
        self.assertEqual(ev["location"]["line_start"], 6)
        self.assertIn(">|   eval(t);", ev["snippet"])
        self.assertIn("hxxps://cdn[.]example[.]net", ev["snippet"])
        self.assertTrue(ev["confidence_reason"])
        self.assertIn("META", ids)                      # off-store update_url
        self.assertIn("DATA-KEYLOG", ids)               # keydown listener in content script
        self.assertIn("CODE-OBF", ids)                  # _0x identifiers
        self.assertIn("EVADE-WEBDRIVER", ids)
        for f in rep["findings"]:
            self.assertIn(f["confidence"], ("high", "medium", "low"))
        doms = {d["value"] for d in rep["iocs"]["domains"]}
        self.assertTrue({"cdn.example.net", "collect.example.org", "updates.example.net"} <= doms)
        for fn in ("report.md", "iocs.csv", "rule.yar", "sigma/proxy.yml", "sigma/dns.yml"):
            self.assertTrue(os.path.isfile(os.path.join(out_dir, fn)), fn)
        if rep["artifacts"]["yara"]["validated"] is not None:
            self.assertTrue(rep["artifacts"]["yara"]["validated"])

    def test_diff_shows_new_permissions_and_findings(self):
        _, old = self.run_one(os.path.join(SAMPLES, "suspicious-helper-1.0"))
        _, new = self.run_one(os.path.join(SAMPLES, "suspicious-helper-1.1"))
        d_out = cli.diff_reports(old, new, self.out)
        with open(os.path.join(d_out, "diff.json")) as f:
            d = json.load(f)
        self.assertIn("cookies", d["permissions_added"])
        self.assertTrue(d["update_url_changed"])
        self.assertIn("js/cs.js", d["files_added"])
        self.assertTrue(any(f["id"].startswith("CODE-EVAL") for f in d["new_findings"]))

    def test_crx3_id_and_hash(self):
        crx_id16 = bytes(range(16))
        data = make_crx3(zip_folder(os.path.join(SAMPLES, "benign-notes")), crx_id16)
        p = os.path.join(self.out, "s.crx")
        with open(p, "wb") as f:
            f.write(data)
        _, rep = self.run_one(p)
        self.assertEqual(rep["sample"]["input_type"], "crx")
        self.assertEqual(rep["sample"]["crx_version"], 3)
        self.assertEqual(rep["sample"]["extension_id"], unpack.id_from_bytes(crx_id16))
        self.assertEqual(len(rep["sample"]["sha256"]), 64)

    def test_zip_path_traversal_is_skipped(self):
        data = zip_folder(os.path.join(SAMPLES, "benign-notes"), {"../../evil.txt": "x", "/abs.txt": "y"})
        p = os.path.join(self.out, "t.zip")
        with open(p, "wb") as f:
            f.write(data)
        out_dir, rep = self.run_one(p)
        self.assertFalse(os.path.exists(os.path.join(self.out, "evil.txt")))
        self.assertFalse(os.path.exists("/abs.txt"))
        self.assertTrue(any("path-traversal" in w for w in rep["warnings"]))

    def test_not_an_extension(self):
        p = os.path.join(self.out, "x.bin")
        with open(p, "wb") as f:
            f.write(b"hello")
        with self.assertRaises(unpack.UnpackError):
            cli.analyze_one(p, self.out)

    def test_defang_keeps_code_readable(self):
        self.assertEqual(defang("chrome.cookies.getAll(r.text())"), "chrome.cookies.getAll(r.text())")
        self.assertEqual(defang('fetch("https://a.example.net/x.js")'), 'fetch("hxxps://a[.]example[.]net/x.js")')

    def _make_lists(self):
        d = os.path.join(self.out, "lists")
        os.makedirs(d)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("top-1m.csv", "1,google.com\n500,example.org\n")
        with open(os.path.join(d, lists.TRANCO_FILE), "wb") as f:
            f.write(buf.getvalue())
        with open(os.path.join(d, lists.PSL_FILE), "w") as f:
            f.write("// comment\ncom\nnet\norg\nuk\nco.uk\n*.ck\n!www.ck\n")
        with open(os.path.join(d, lists.URLHAUS_FILE), "w") as f:
            f.write('# comment\n"1","2026-11-01","https://cdn.example.net/p.js","online"\n')
        with open(os.path.join(d, lists.META_FILE), "w") as f:
            f.write('{"tranco": "2026-11-11", "psl": "2026-11-11", "urlhaus": "2026-11-11"}')
        return d

    def test_psl_registrable(self):
        psl = lists.PSL("com\nuk\nco.uk\n*.ck\n!www.ck\n")
        self.assertEqual(psl.registrable("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(psl.registrable("x.foo.bar.ck"), "foo.bar.ck")
        self.assertEqual(psl.registrable("www.ck"), "www.ck")
        self.assertEqual(psl.registrable("cdn.example.com"), "example.com")

    def test_domain_lists_enrichment(self):
        d = self._make_lists()
        out_dir, rep = cli.analyze_one(os.path.join(SAMPLES, "suspicious-helper-1.1"), self.out, d)
        doms = {x["value"]: x for x in rep["iocs"]["domains"]}
        self.assertEqual(doms["collect.example.org"]["tranco_rank"], 500)
        self.assertTrue(doms["collect.example.org"]["common"])
        self.assertEqual(doms["cdn.example.net"]["urlhaus_hits"], 1)
        self.assertFalse(doms["cdn.example.net"]["common"])
        self.assertIsNone(doms["updates.example.net"]["tranco_rank"])
        hit = [f for f in rep["findings"] if f["id"].startswith("IOC-URLHAUS")]
        self.assertEqual(len(hit), 1)
        self.assertEqual((hit[0]["severity"], hit[0]["confidence"]), ("high", "high"))
        self.assertEqual(sorted(rep["lists"]["loaded"]), ["psl", "tranco", "urlhaus"])
        with open(os.path.join(out_dir, "report.md")) as f:
            md = f.read()
        self.assertIn("URLhaus: known malicious", md)
        self.assertIn("Tranco #500", md)

    def test_missing_lists_is_a_warning(self):
        _, rep = self.run_one(os.path.join(SAMPLES, "benign-notes"))
        self.assertTrue(any("--update-lists" in w for w in rep["warnings"]))


CASES = os.path.join(HERE, "cases")
SEV_RANK = {"info": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}


@unittest.skipUnless(jsast.available(), "tree-sitter not installed")
class BehaviorTests(unittest.TestCase):
    """Synthetic positive/negative cases per combination rule (tests/cases/*/expected.json)."""

    def setUp(self):
        self.out = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.out)

    def test_cases(self):
        names = sorted(d for d in os.listdir(CASES) if os.path.isdir(os.path.join(CASES, d)))
        self.assertTrue(names)
        for name in names:
            with self.subTest(case=name):
                with open(os.path.join(CASES, name, "expected.json")) as f:
                    exp = json.load(f)
                out_dir, rep = cli.analyze_one(os.path.join(CASES, name), self.out)
                self.assertEqual(validate.check_case(exp, rep), [], name)
                self.assertTrue(os.path.isfile(os.path.join(out_dir, "behaviors.json")))
                self.assertIn("score_v0.1", rep)

    def test_validate_corpus(self):
        corpus = os.path.join(self.out, "corpus")
        for kind, cat, case in (("malicious", "cookie-exfil", "session-exfil-pos"),
                                ("malicious", "command-channel", "c2-pos"),
                                ("malicious", "command-channel", "c2-neg"),       # a miss, on purpose
                                ("benign", "productivity", "session-exfil-neg"),
                                ("benign", "dev", "remote-code-neg")):
            shutil.copytree(os.path.join(CASES, case), os.path.join(corpus, kind, cat, case))
        vdir, doc = validate.run(corpus, os.path.join(self.out, "v1"), cli.analyze_one)
        m = doc["metrics"]
        self.assertEqual(m["malicious"]["cookie-exfil"]["detection_rate"], 1.0)
        self.assertEqual(m["malicious"]["command-channel"]["detection_rate"], 0.5)
        self.assertEqual(m["benign"]["productivity"]["false_positive_rate"], 0.0)
        with open(os.path.join(vdir, "report.md")) as f:
            md = f.read()
        self.assertIn("command-channel/c2-neg", md)                 # listed as not detected
        self.assertNotIn("```", md)                                  # no snippets
        with open(os.path.join(vdir, "results.json")) as f:
            self.assertNotIn("snippet", f.read())
        # baseline: same results, one label edited -> one change reported
        base = json.loads(json.dumps(doc))
        next(r for r in base["samples"] if r["label"] == "malicious")["label"] = "low_risk"
        bpath = os.path.join(self.out, "base.json")
        with open(bpath, "w") as f:
            json.dump(base, f)
        _, doc2 = validate.run(corpus, os.path.join(self.out, "v2"), cli.analyze_one, baseline=bpath)
        self.assertEqual(len(doc2["baseline"]["changed"]), 1)

    def test_reachability_in_sample(self):
        _, rep = cli.analyze_one(os.path.join(SAMPLES, "suspicious-helper-1.1"), self.out)
        by = {(f["id"].rsplit("-", 1)[0], (f.get("location") or {}).get("path")): f for f in rep["findings"]}
        self.assertEqual(by[("DATA-COOKIES", "bg.js")]["reachability"], "unreachable")   # collect() is never called
        self.assertEqual(by[("CODE-EVAL", "bg.js")]["reachability"], "reachable")        # refresh() runs on an alarm
        self.assertEqual(by[("CODE-OBF", "js/lib.min.js")]["reachability"], "unreachable")
        self.assertIn("js/lib.min.js", rep["reachability"]["files_unreachable"])


@unittest.skipUnless(jsast.available(), "tree-sitter not installed")
class ReportQualityTests(unittest.TestCase):
    """IOC reference (D), intel, libraries (G/J), package content (E), locations (H), vendor (I), disclosure (F)."""

    def setUp(self):
        self.out = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.out)

    def run_case(self, name, **kw):
        return cli.analyze_one(os.path.join(CASES, name), self.out, **kw)

    def test_ioc_reference(self):
        out_dir, rep = self.run_case("ioc-reference")
        ref = {d["value"]: d["reference"] for d in rep["iocs"]["domains"]}
        self.assertEqual(ref["api.example.com"], "code-referenced")
        for v in ("dead.example.net", "listed.example.org", "docs.example.org"):
            self.assertEqual(ref[v], "data-only", v)
        with open(os.path.join(out_dir, "rule.yar")) as f:
            rule = f.read()
        self.assertIn("api.example.com", rule)
        self.assertNotIn("listed.example.org", rule)
        with open(os.path.join(out_dir, "report.md")) as f:
            md = f.read()
        self.assertIn("Data-only", md)
        self.assertIn("data/list.json: 4 IOC(s)", md)

    def test_intel_local_folder(self):
        d = tempfile.mkdtemp(dir=self.out)
        entries = [
            {"value": "api.example.com", "source": "test fixture", "first_seen": "2026-01-01",
             "confidence": "high", "expires": None},
            {"value": "listed.example.org", "source": "test fixture", "first_seen": "2026-01-01",
             "confidence": "high", "expires": None},
            {"value": "old.example.org", "source": "test fixture", "first_seen": "2020-01-01",
             "confidence": "high", "expires": "2021-01-01"},
            {"value": "nosource.example.org", "first_seen": "2026-01-01", "confidence": "high", "expires": None},
        ]
        with open(os.path.join(d, "domains.json"), "w") as f:
            json.dump({"entries": entries}, f)
        _, rep = self.run_case("ioc-reference", intel_dir=d)
        hits = {f["match"]: f for f in rep["findings"] if f["id"].startswith("IOC-INTEL")}
        self.assertTrue(hits["api.example.com"]["scored"])            # code-referenced, high confidence
        self.assertFalse(hits["listed.example.org"]["scored"])        # data-only: reported, not scored
        self.assertEqual(rep["verdict"]["label"], "low_risk")         # one high/high IOC alone: 25 points
        self.assertTrue(any("expired entry ignored: old.example.org" in w for w in rep["warnings"]))
        self.assertTrue(any("missing source" in w for w in rep["warnings"]))
        self.assertEqual(rep["intel"]["loaded"], ["builtin", "local"])

    def test_library(self):
        _, rep = self.run_case("library-known")
        lib = {fi["path"]: fi.get("library") for fi in rep["files"]}
        self.assertEqual(lib["js/jquery.min.js"], "jQuery")
        obf = [f for f in rep["findings"] if f["id"].startswith("CODE-OBF")]
        self.assertEqual(obf[0]["severity"], "info")
        self.assertNotIn("T1027", [t["id"] for t in rep["verdict"]["attack"]])

    def test_non_extension_content(self):
        _, rep = self.run_case("nonext-content")
        by = {f["location"]["path"]: f for f in rep["findings"] if f["id"].startswith("PKG-NONEXT")}
        self.assertEqual(by["bin/helper.exe"]["severity"], "high")
        self.assertEqual(by["tools/run.sh"]["severity"], "medium")
        self.assertEqual(by["server/index.php"]["severity"], "medium")
        self.assertEqual(by["tools/run.sh"]["kind"], "non-extension-content-in-package")

    def test_line_mapping(self):
        _, rep = self.run_case("line-mapping")
        f = next(f for f in rep["findings"] if f["id"].startswith("CODE-EVAL"))
        with open(os.path.join(CASES, "line-mapping", "bg.js")) as fh:
            col = fh.read().index("eval(") + 1
        self.assertEqual(f["location"]["minified_location"], {"path": "bg.js", "line": 1, "column": col,
                                                              "mapping": "verified"})
        self.assertEqual(f["location"]["beautified_location"]["path"], os.path.join("_deob", "bg.js"))

    def test_vendor_and_disclosure_are_not_scored(self):
        _, rep = self.run_case("vendor-multi")
        v = next(f for f in rep["findings"] if f["id"].startswith("VENDOR-MULTI"))
        self.assertFalse(v["scored"])
        self.assertEqual(sorted(rep["vendor"]["domains"]), ["example.com", "example.net"])
        _, rep = self.run_case("disclosure-mismatch-pos")
        cats = {f["title"] for f in rep["findings"] if f["id"].startswith("PRIV-DISCLOSURE")}
        self.assertEqual(cats, {"Sends email address without mentioning it",
                                "Sends browsing history or URLs without mentioning it"})
        self.assertEqual(rep["verdict"]["unscored_findings"], 2)


class IntelTests(unittest.TestCase):
    def test_builtin_intel_is_valid(self):
        from extanalyzer import intel
        it = intel.load()
        self.assertEqual(it.warnings, [])
        self.assertIn("www.w3.org", it.ignore_domains)
        self.assertTrue(it.is_common("fonts.googleapis.com"))
        self.assertTrue(it.libraries)

    def test_entry_validation(self):
        from extanalyzer import intel
        ok = {"value": "a.example", "source": "s", "first_seen": "2026-01-01", "confidence": "high", "expires": None}
        self.assertIsNone(intel.validate_entry(ok))
        self.assertEqual(intel.validate_entry(dict(ok, confidence="certain")), "confidence must be high, medium or low")
        self.assertEqual(intel.validate_entry(dict(ok, first_seen="yesterday")), "first_seen must be YYYY-MM-DD")
        self.assertTrue(intel.expired(dict(ok, expires="2000-01-01")))


if __name__ == "__main__":
    unittest.main()
