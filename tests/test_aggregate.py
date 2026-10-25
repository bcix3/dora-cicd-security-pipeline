"""Tests for scripts/aggregate.py.

Fixtures in tests/fixtures/ are cut from the real output of reference run
38636367530 (14/10/26), in the artifact layout the aggregate job downloads.
Run with:  python3 -m unittest discover -s tests
"""

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import aggregate  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def by_title(findings):
    return {f["title"]: f for f in findings}


class TestParsers(unittest.TestCase):
    def test_semgrep(self):
        fs = aggregate.load(FIXTURES, "sast")
        self.assertEqual(len(fs), 3)
        f = by_title(fs)["code-string-concat"]
        self.assertEqual(f["rule"], "javascript.lang.security.audit.code-string-concat."
                                    "code-string-concat")  # folder prefix stripped
        self.assertEqual(f["location"], "app/app/routes/contributions.js:32")
        self.assertEqual((f["raw_severity"], f["severity"]), ("ERROR", "High"))
        self.assertEqual(f["cwe"], ["CWE-95"])
        self.assertEqual(f["ruleset"], "standard")

    def test_semgrep_nodejsscan(self):
        f = by_title(aggregate.load(FIXTURES, "sast"))["node_insecure_random_generator"]
        self.assertEqual(f["ruleset"], "nodejsscan")
        self.assertEqual(f["severity"], "Medium")
        self.assertEqual(f["cwe"], ["CWE-327"])  # nodejsscan gives a plain string

    def test_semgrep_info_is_low(self):
        f = by_title(aggregate.load(FIXTURES, "sast"))["cookie_session_default"]
        self.assertEqual((f["raw_severity"], f["severity"]), ("INFO", "Low"))

    def test_gitleaks(self):
        [f] = aggregate.load(FIXTURES, "secrets")
        self.assertEqual(f["rule"], "private-key")
        self.assertEqual(f["location"], "app/artifacts/cert/server.key:1 @ d8592a9")
        self.assertEqual(f["severity"], "High")

    def test_trivy_fs(self):
        fs = by_title(aggregate.load(FIXTURES, "sca"))
        f = fs["CVE-2019-20149 kind-of@6.0.2"]
        self.assertEqual((f["severity"], f["component"]), ("High", "app"))
        self.assertEqual(f["location"], "package-lock.json")
        self.assertEqual(fs["CVE-2017-16137 debug@4.1.1"]["severity"], "Low")

    def test_trivy_image_components(self):
        fs = aggregate.load(FIXTURES, "image")
        components = sorted(f["component"] for f in fs)
        self.assertEqual(components, ["app", "app", "base", "os", "os"])
        os_f = [f for f in fs if f["component"] == "os"]
        self.assertEqual({f["package"] for f in os_f}, {"libcrypto1.1@1.1.1n-r0",
                                                        "libssl1.1@1.1.1n-r0"})
        self.assertEqual(os_f[0]["location"], "OS (alpine 3.15.4)")

    def test_zap(self):
        fs = by_title(aggregate.load(FIXTURES, "dast"))
        f = fs["Missing Anti-clickjacking Header"]
        self.assertEqual((f["rule"], f["severity"]), ("10020", "Medium"))
        self.assertEqual(f["cwe"], ["CWE-1021"])
        self.assertTrue(f["location"].startswith("5 instance(s), e.g. http://web:4000"))
        f = fs["Authentication Request Identified"]
        self.assertEqual((f["severity"], f["cwe"]), ("Info", []))  # cweid -1


class TestDedup(unittest.TestCase):
    def setUp(self):
        self.findings = [f for s in aggregate.STAGES
                         for f in aggregate.load(FIXTURES, s)]

    def test_combined_counts(self):
        # 3 SAST + 1 secret + 2 app advisories (kind-of in SCA and twice in the
        # image counts once) + 1 base-image + 2 OS (one CVE, two packages) + 2 ZAP
        combined = aggregate.combine(self.findings)
        self.assertEqual(sum(combined.values()), 11)
        self.assertEqual(combined["High"], 5)

    def test_overlap(self):
        self.assertEqual(aggregate.dependency_overlap(self.findings), {
            "both": 1, "sca_only": 1, "image_only": 0, "image_base": 1, "image_os": 2})


class TestGate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        shutil.copytree(FIXTURES, self.tmp, dirs_exist_ok=True)
        self.addCleanup(shutil.rmtree, self.tmp)

    def run_main(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            rc = aggregate.main([str(self.tmp), *args])
        return rc, err.getvalue()

    def test_fails_on_high(self):
        rc, _ = self.run_main()
        self.assertEqual(rc, 1)
        result = json.loads((self.tmp / "aggregated.json").read_text())
        self.assertEqual(result["gate"], "fail")
        self.assertEqual(len(result["findings"]), 13)  # raw, not de-duplicated
        self.assertEqual(result["blocking"], {"SAST": 1, "Secrets": 1, "SCA": 1,
                                              "Container image": 4})
        report = (self.tmp / "aggregated-report.md").read_text()
        self.assertIn("# Security report: gate FAILED", report)

    def test_report_only_records_failure_but_exits_0(self):
        rc, _ = self.run_main("--report-only")
        self.assertEqual(rc, 0)
        result = json.loads((self.tmp / "aggregated.json").read_text())
        self.assertEqual(result["gate"], "fail")

    def test_report_only_still_fails_on_input_error(self):
        (self.tmp / "gitleaks-results" / "gitleaks.json").unlink()
        rc, _ = self.run_main("--report-only")
        self.assertEqual(rc, 2)

    def test_passes_without_critical_or_high(self):
        # ZAP fixture alone has only Medium and Info.
        rc, _ = self.run_main("--not-run", "sast", "--not-run", "secrets",
                              "--not-run", "sca", "--not-run", "image")
        self.assertEqual(rc, 0)
        report = (self.tmp / "aggregated-report.md").read_text()
        self.assertIn("# Security report: gate PASSED", report)
        self.assertIn("**Partial result.**", report)

    def test_missing_input_is_an_error(self):
        (self.tmp / "zap-results" / "zap-report.json").unlink()
        rc, err = self.run_main()
        self.assertEqual(rc, 2)
        self.assertIn("dast", err)
        self.assertFalse((self.tmp / "aggregated-report.md").exists())

    def test_not_run_stage_may_be_missing(self):
        shutil.rmtree(self.tmp / "zap-results")
        rc, _ = self.run_main("--not-run", "dast")
        self.assertEqual(rc, 1)
        report = (self.tmp / "aggregated-report.md").read_text()
        self.assertIn("| DAST | ZAP baseline | – |", report)

    def test_unknown_severity_is_an_error(self):
        path = self.tmp / "semgrep-results" / "semgrep.json"
        raw = json.loads(path.read_text())
        raw["results"][0]["extra"]["severity"] = "CRITICAL"
        path.write_text(json.dumps(raw))
        rc, err = self.run_main()
        self.assertEqual(rc, 2)
        self.assertIn("unknown severity 'CRITICAL'", err)

    def test_changed_schema_is_an_error(self):
        path = self.tmp / "zap-results" / "zap-report.json"
        raw = json.loads(path.read_text())
        del raw["site"][0]["alerts"][0]["riskcode"]
        path.write_text(json.dumps(raw))
        rc, err = self.run_main()
        self.assertEqual(rc, 2)
        self.assertIn("riskcode", err)


if __name__ == "__main__":
    unittest.main()
