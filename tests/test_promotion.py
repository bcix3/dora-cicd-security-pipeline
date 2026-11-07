"""Tests for scripts/promotion.py. Run with:  python3 -m unittest discover -s tests"""

import contextlib
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import promotion  # noqa: E402

REASON = "Lab study image; findings are the deliberate NodeGoat flaws under test."


class TestDecide(unittest.TestCase):
    def test_gate_passed_is_promoted(self):
        self.assertEqual(promotion.decide("success", "pass", ""), (True, "gate passed"))

    def test_gate_failed_without_reason_is_refused(self):
        promote, basis = promotion.decide("failure", "fail", "")
        self.assertFalse(promote)
        self.assertIn("no risk acceptance", basis)

    def test_short_reason_is_refused(self):
        promote, basis = promotion.decide("failure", "fail", "   ok, accepted    ")
        self.assertFalse(promote)
        self.assertIn("shorter than 20 characters", basis)

    def test_reason_of_minimum_length_is_accepted(self):
        self.assertEqual(promotion.decide("failure", "fail", "x" * 20),
                         (True, "gate failed; risk accepted"))

    def test_no_gate_result_is_refused_even_with_reason(self):
        for gate in (None, "", "cancelled", "skipped"):
            promote, basis = promotion.decide(gate, None, REASON)
            self.assertFalse(promote, gate)
            self.assertIn("no gate result", basis)

    def test_gate_and_report_disagree_is_refused(self):
        self.assertFalse(promotion.decide("success", "fail", REASON)[0])
        self.assertFalse(promotion.decide("failure", "pass", REASON)[0])

    def test_verdict_may_be_unavailable(self):
        # Older runs, or an expired aggregate-results artifact: the gate job decides.
        self.assertTrue(promotion.decide("success", None, "")[0])


class TestRecord(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "aggregated.json").write_text(json.dumps(
            {"gate": "fail", "blocking": {"SAST (Semgrep)": 10, "DAST": 1}}))
        (self.tmp / "evidence-manifest.json").write_text('{"files": []}\n')
        self.env = {"IMAGE": "ghcr.io/o/r:sha-abc", "DIGEST": "sha256:123", "COMMIT": "abc",
                    "GATE": "failure", "BUILD_RUN": "42", "BUILD_RUN_URL": "https://x/42",
                    "AGGREGATED": str(self.tmp / "aggregated.json"),
                    "MANIFEST": str(self.tmp / "evidence-manifest.json"),
                    "APPROVER": "someone", "RUN_URL": "https://x/99"}

    def run_main(self, **extra):
        out = self.tmp / "out"
        with mock.patch.dict("os.environ", dict(self.env, **extra), clear=True), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = promotion.main([str(out)])
        return rc, json.loads((out / "promotion-record.json").read_text()), \
            (out / "promotion-record.md").read_text()

    def test_refusal_is_recorded(self):
        rc, record, md = self.run_main()
        self.assertEqual(rc, 1)
        self.assertFalse(record["promote"])
        self.assertIsNone(record["risk_acceptance"])
        self.assertIn("⛔ **REFUSED**", md)

    def test_accepted_risk_is_recorded_with_approver_and_evidence(self):
        rc, record, md = self.run_main(RISK_ACCEPTANCE=f"  {REASON}\n")
        self.assertEqual(rc, 0)
        self.assertEqual(record["risk_acceptance"], REASON)
        self.assertEqual(record["approver"], "someone")
        self.assertEqual((record["gate"], record["verdict"]), ("failure", "fail"))
        self.assertEqual(record["blocking"], {"SAST (Semgrep)": 10, "DAST": 1})
        self.assertEqual(record["evidence_manifest_sha256"], hashlib.sha256(
            b'{"files": []}\n').hexdigest())
        self.assertIn("| Blocking findings | SAST (Semgrep) 10, DAST 1 |", md)
        self.assertIn("not independent (RTS 2024/1774 Art. 17(1)(b))", md)

    def test_reason_cannot_break_the_summary_table(self):
        _, _, md = self.run_main(RISK_ACCEPTANCE="accepted | <b>x</b>\nsecond line here")
        self.assertIn("| Risk acceptance | accepted \\| <b>x</b> second line here |", md)

    def test_missing_evidence_is_not_fatal_but_gate_is(self):
        rc, record, _ = self.run_main(GATE="", AGGREGATED="", MANIFEST="",
                                      RISK_ACCEPTANCE=REASON)
        self.assertEqual(rc, 1)
        self.assertIsNone(record["evidence_manifest_sha256"])
        self.assertIn("no gate result", record["basis"])


if __name__ == "__main__":
    unittest.main()
