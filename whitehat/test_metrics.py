import json
import tempfile
import unittest
from pathlib import Path

from .common import Invalid
from .metrics import benchmark, score


class Calibration(unittest.TestCase):
    def test_counts_and_abstentions(self):
        m = score([("confirmed",True),("confirmed",False),("not_reproduced",True),
                   ("not_reproduced",False),("insufficient",True),("hypothesis",False)])
        self.assertEqual(m["precision"], 0.5)
        self.assertEqual(m["recall_including_abstentions"], 1/3)
        self.assertEqual(m["decision_coverage"], 4/6)
        self.assertEqual(m["abstained"], 2)
        self.assertLess(m["precision_95_interval"][0], .5)
        self.assertGreater(m["precision_95_interval"][1], .5)

    def test_no_guessed_precision(self):
        m = score([("observed",True),("conflicting",False)])
        self.assertIsNone(m["precision"])
        self.assertIsNone(m["precision_95_interval"])
        self.assertEqual(m["decision_coverage"], 0)

    def test_mismatched_revision_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"truth.json"
            path.write_text(json.dumps({"one":{"revision":"v2","present":True}}))
            report = {"cases":[{"id":"one","revision":"v1","status":"confirmed","rule":{"kind":"http.nosniff"}}]}
            with self.assertRaises(Invalid):
                benchmark(report, path)
