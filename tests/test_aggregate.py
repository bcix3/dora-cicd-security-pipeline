"""Tests for scripts/aggregate.py.

Fixtures in tests/fixtures/ are cut from the real output of reference run
38636367530 (14/10/26), in the artifact layout the aggregate job downloads.
Run with:  python3 -m unittest discover -s tests
"""

import contextlib
import copy
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
        self.assertEqual(f["url"], "https://semgrep.dev/r/javascript.lang.security.audit."
                                   "code-string-concat.code-string-concat")

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
        self.assertEqual((f["fixed"], f["url"]),
                         ("6.0.3", "https://avd.aquasec.com/nvd/cve-2019-20149"))
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
        self.assertEqual(f["url"], "https://www.zaproxy.org/docs/alerts/10020/")
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


class TestChanges(unittest.TestCase):
    def setUp(self):
        self.findings = [f for s in aggregate.STAGES
                         for f in aggregate.load(FIXTURES, s)]

    def previous(self, findings, not_run=()):
        return {"findings": copy.deepcopy(findings), "not_run": list(not_run)}

    def test_no_changes(self):
        c = aggregate.changes(self.findings, self.previous(self.findings), [])
        self.assertEqual((c["new"], c["resolved"], c["rerated"]), ([], [], []))

    def test_new_resolved_and_rerated(self):
        prev = self.previous(self.findings)
        gone = prev["findings"].pop(0)                    # new in this run
        prev["findings"].append(dict(gone, rule="old-rule", location="x.js:1"))
        sca = next(f for f in prev["findings"] if f["stage"] == "sca")
        sca["severity"] = "Medium"                        # re-rated since
        c = aggregate.changes(self.findings, prev, [])
        self.assertEqual([f["rule"] for f in c["new"]], [gone["rule"]])
        self.assertEqual([f["rule"] for f in c["resolved"]], ["old-rule"])
        [(before, now)] = c["rerated"]
        self.assertEqual((before["severity"], now["severity"]), ("Medium", "High"))

    def test_zap_identified_by_rule_only(self):
        # A different instance count or example URL is the same alert type.
        prev = self.previous(self.findings)
        for f in prev["findings"]:
            if f["stage"] == "dast":
                f["location"] = "1 instance(s), e.g. http://web:4000/other"
        c = aggregate.changes(self.findings, prev, [])
        self.assertEqual((c["new"], c["resolved"]), ([], []))

    def test_image_copies_count_once(self):
        prev = self.previous([f for f in self.findings if f["title"] !=
                              "CVE-2019-20149 kind-of@6.0.2"])
        c = aggregate.changes(self.findings, prev, [])
        self.assertEqual(sorted(f["stage"] for f in c["new"]), ["image", "sca"])

    def test_stage_not_run_in_either_run_is_not_compared(self):
        prev = self.previous([f for f in self.findings if f["stage"] != "dast"],
                             not_run=["dast"])
        c = aggregate.changes(self.findings, prev, [])
        self.assertNotIn("dast", c["compared"])
        self.assertEqual(c["new"], [])


class TestReport(unittest.TestCase):
    ENV = {"GITHUB_SHA": "abcdef1234567", "GITHUB_REPOSITORY": "o/r",
           "GITHUB_SERVER_URL": "https://github.com"}

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        shutil.copytree(FIXTURES, self.tmp, dirs_exist_ok=True)
        self.addCleanup(shutil.rmtree, self.tmp)

    def render(self):
        with mock.patch.dict("os.environ", self.ENV), \
                contextlib.redirect_stdout(io.StringIO()):
            aggregate.main([str(self.tmp)])
        return (self.tmp / "aggregated-report.md").read_text()

    def section(self, report, heading):
        return report.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]

    def test_run_line(self):
        self.assertIn("Commit [abcdef1](https://github.com/o/r/commit/abcdef1234567) "
                      "(NodeGoat vendored in `app/`) · Semgrep 1.180.0 · Gitleaks 8.30.1 · "
                      "Trivy 0.75.0, DB 14/10/2026 19:14 UTC · ZAP 2.17.0", self.render())
        result = json.loads((self.tmp / "aggregated.json").read_text())
        self.assertEqual(result["tools"]["Gitleaks"], "8.30.1")
        self.assertEqual(result["trivy_db"], {"SCA": "2026-10-14T19:14:58.511503573Z"})

    def test_missing_version_is_not_an_error(self):
        (self.tmp / "gitleaks-results" / "gitleaks-version.txt").unlink()
        self.assertIn("Gitleaks (version not recorded)", self.render())

    def test_what_fails_the_gate(self):
        gate = self.section(self.render(), "What fails the gate")
        # SAST and secrets High are listed with links; dependency High is counted.
        self.assertIn("| 🟠 High | SAST | ERROR | [code-string-concat](https://semgrep.dev/r/"
                      "javascript.lang.security.audit.code-string-concat.code-string-concat) | "
                      "[app/app/routes/contributions.js:32](https://github.com/o/r/blob/"
                      "abcdef1234567/app/app/routes/contributions.js#L32) | – | "
                      "[CWE-95](https://cwe.mitre.org/data/definitions/95.html) |", gate)
        self.assertIn("[app/artifacts/cert/server.key:1 @ d8592a9](https://github.com/", gate)
        self.assertNotIn("kind-of", gate)
        self.assertIn("Plus 3 High dependency advisories (de-duplicated; a fixed version "
                      "exists for 3)", gate)

    def test_critical_dependency_listed_once(self):
        path = self.tmp / "trivy-deps-results" / "trivy-deps.json"
        raw = json.loads(path.read_text())
        raw["Results"][0]["Vulnerabilities"][0]["Severity"] = "CRITICAL"   # kind-of
        path.write_text(json.dumps(raw))
        gate = self.section(self.render(), "What fails the gate")
        [row] = [r for r in gate.splitlines() if "kind-of" in r]
        self.assertIn("| SCA, Container image | CRITICAL, HIGH | "
                      "[CVE-2019-20149](https://avd.aquasec.com/nvd/cve-2019-20149) "
                      "kind-of@6.0.2 | package-lock.json (+2 more) | 6.0.3 |", row)

    def test_sast_grouped_by_location(self):
        path = self.tmp / "semgrep-results" / "semgrep.json"
        raw = json.loads(path.read_text())
        twin = copy.deepcopy(next(r for r in raw["results"]
                                  if r["check_id"].endswith("code-string-concat")))
        twin["check_id"] = "results.semgrep-rules.ajinabraham.njsscan.eval.eval_nodejs"
        twin["extra"]["metadata"]["source"] = "https://semgrep.dev/r/eval_nodejs"
        raw["results"].append(twin)
        path.write_text(json.dumps(raw))
        report = self.render()
        self.assertIn("SAST (Semgrep): 4 at 3 locations", report)
        sast = report.split("SAST (Semgrep)", 1)[1].split("</details>", 1)[0]
        self.assertEqual(sast.count("contributions.js:32]"), 1)
        self.assertIn("[code-string-concat](", sast)
        self.assertIn(", [eval_nodejs](https://semgrep.dev/r/eval_nodejs) |", sast)

    def test_zap_readability(self):
        dast = self.render().split("DAST (ZAP baseline)", 1)[1]
        self.assertIn("| Medium, confidence Medium | [Missing Anti-clickjacking Header]"
                      "(https://www.zaproxy.org/docs/alerts/10020/) | 5 instance(s), e.g. / |",
                      dast)

    def test_long_zap_url_is_shortened(self):
        f = {"stage": "dast", "location": "1 instance(s), e.g. http://web:4000/learn?url="
             + "x" * 100}
        loc = aggregate.location_md(f)
        self.assertTrue(loc.startswith("1 instance(s), e.g. /learn?url=xxx"))
        self.assertTrue(loc.endswith("…") and len(loc) < 75)

    def test_fix_available(self):
        report = self.render()
        self.assertIn("2 package versions; fix available for 2 |", report)
        self.assertIn("A fixed version exists for 5 of these 5 advisories.", report)


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
        self.assertIn("**Gate FAILED.** Critical or High findings in 4 of 5 stages run", report)

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
        self.assertIn("**Gate PASSED.**", report)
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
        self.assertIn("| DAST | ZAP baseline | ⏭️ not run |", report)

    def test_report_compares_with_previous(self):
        self.run_main()
        previous = self.tmp / "previous.json"
        (self.tmp / "aggregated.json").rename(previous)
        raw = json.loads(previous.read_text())
        raw["run"], raw["url"] = "123", "https://example.invalid/runs/123"
        raw["findings"] = [f for f in raw["findings"] if f["stage"] != "secrets"]
        previous.write_text(json.dumps(raw))
        rc, _ = self.run_main("--previous", str(previous))
        self.assertEqual(rc, 1)
        report = (self.tmp / "aggregated-report.md").read_text()
        self.assertIn("Compared with [run 123](https://example.invalid/runs/123)", report)
        self.assertIn("| Secrets | 1 | 0 | 0 |", report)

    def test_missing_previous_is_an_error(self):
        rc, err = self.run_main("--previous", str(self.tmp / "nope.json"))
        self.assertEqual(rc, 2)
        self.assertIn("previous run", err)

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
