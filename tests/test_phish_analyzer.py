import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))

from phish_analyzer import analyze  # noqa: E402


def load(name):
    with open(os.path.join(HERE, "samples", name), "rb") as handle:
        return analyze(handle.read())


class TestPhishAnalyzer(unittest.TestCase):
    def test_phish_is_flagged_malicious(self):
        report = load("phish.eml")
        rules = {f["rule"] for f in report["findings"]}
        self.assertEqual(report["verdict"], "malicious")
        for expected in ("spf_fail", "dmarc_fail", "reply_to_mismatch", "display_name_spoof",
                         "link_text_mismatch", "ip_url", "shortener", "risky_attachment", "urgency_language"):
            self.assertIn(expected, rules)

    def test_attachment_is_hashed(self):
        report = load("phish.eml")
        self.assertEqual(len(report["attachments"]), 1)
        self.assertEqual(len(report["attachments"][0]["sha256"]), 64)

    def test_benign_is_clean(self):
        report = load("benign.eml")
        self.assertEqual(report["verdict"], "likely benign")
        self.assertEqual(report["findings"], [])


if __name__ == "__main__":
    unittest.main()
