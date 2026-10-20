import json
import unittest

from triage_ipsw_diff import analyze, categorize


class TestIPSWDiffTriage(unittest.TestCase):
    def test_categories(self):
        self.assertIn("gpu", categorize("System/Library/Extensions/AGXMetal.dylib"))
        self.assertIn("codesigning", categorize("usr/libexec/amfid"))
        self.assertIn("kernel", categorize("kernelcache.release"))
        self.assertEqual(categorize("foo/bar.txt"), ["other"])

    def test_deduplicate_and_hash(self):
        raw = json.dumps({"files": [{"path": "System/AGXMetal.dylib"}, {"path": "System/AGXMetal.dylib"}, {"path": "usr/libexec/amfid"}]}).encode()
        report = analyze(raw, "iPhone16,2")
        self.assertEqual(report["entries"], 2)
        self.assertEqual(report["categories"]["gpu"], 1)
        self.assertEqual(report["categories"]["codesigning"], 1)
        self.assertEqual(len(report["source_sha256"]), 64)

    def test_reject_wrong_device(self):
        with self.assertRaises(ValueError):
            analyze(b"{}", "iPhone18,1")

    def test_reject_unexpected_structure(self):
        with self.assertRaises(ValueError):
            analyze(b'"not a report"', "iPhone16,2")


if __name__ == "__main__":
    unittest.main()
