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

from extanalyzer import cli, unpack
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
        self.assertEqual(rep["verdict"]["label"], "likely_malicious")
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


if __name__ == "__main__":
    unittest.main()
