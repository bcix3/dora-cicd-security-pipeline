"""Tests for scripts/scoring_sheet.py. Run with:  python3 -m unittest discover -s tests"""

import contextlib
import csv
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import scoring_sheet  # noqa: E402

SCORING = ["catalogue_row", "m6_label", "match_rule", "triage_minutes", "notes"]


def finding(stage, rule, location, severity="High", cwe=(), **extra):
    return dict(stage=stage, rule=rule, title=extra.pop("title", rule), location=location,
                severity=severity, cwe=list(cwe), **extra)


def zap(rule, title, location, severity="Medium"):
    return finding("dast", rule, location, severity, title=title)


def dep(stage, cve, package, location, component="app"):
    return finding(stage, cve, location, title=f"{cve} {package}", package=package,
                   component=component)


RUN = {
    "run": "100", "commit": "abc",
    "stages": ["sast", "codeql", "secrets", "sca", "image", "dast"],
    "findings": [
        finding("sast", "eval_nodejs", "app/app/routes/contributions.js:32", cwe=["CWE-95"]),
        finding("sast", "code-string-concat", "app/app/routes/contributions.js:32"),
        finding("codeql", "js/request-forgery", "app/app/routes/research.js:16",
                "Critical", ["CWE-918"]),
        finding("secrets", "private-key", "app/artifacts/cert/server.key:1 @ d8592a9"),
        dep("sca", "CVE-2017-1000427", "marked@0.3.5", "package-lock.json"),
        dep("sca", "CVE-2016-10531", "marked@0.3.5", "package-lock.json"),
        dep("image", "CVE-2017-1000427", "marked@0.3.5",
            "home/node/app/node_modules/marked/package.json"),
        dep("image", "CVE-2017-1000427", "marked@0.3.5",
            "home/node/app/node_modules/x/node_modules/marked/package.json"),
        dep("image", "CVE-2022-2097", "libssl1.1@1.1.1n-r0", "OS (alpine 3.15.4)", "os"),
        zap("10038", "CSP Header Not Set", "5 instance(s), e.g. http://web:4000/login"),
        zap("10028", "Off-site Redirect",
            "1 instance(s), e.g. http://web:4000/learn?url=https://example.org/", "High"),
    ],
}


def rerun(**changes):
    return dict(RUN, run="101", **changes)


class TestSheet(unittest.TestCase):
    def setUp(self):
        self.rows = scoring_sheet.sheet(RUN)
        self.by_id = {r["finding_id"]: r for r in self.rows}

    def test_one_row_per_sast_finding_even_on_the_same_line(self):
        sast = [r for r in self.rows if r["stage"] == "SAST (Semgrep)"]
        self.assertEqual([r["rule"] for r in sast], ["code-string-concat", "eval_nodejs"])
        self.assertEqual({r["location"] for r in sast}, {"app/routes/contributions.js:32"})

    def test_paths_are_relative_to_app(self):
        self.assertEqual(self.by_id["codeql-001"]["location"], "app/routes/research.js:16")
        self.assertEqual(self.by_id["secrets-001"]["location"],
                         "artifacts/cert/server.key:1 @ d8592a9")

    def test_columns(self):
        r = self.by_id["codeql-001"]
        self.assertEqual((r["run"], r["stage"], r["tool"], r["rule"], r["cwe"], r["severity"]),
                         ("100", "SAST (CodeQL)", "CodeQL", "js/request-forgery", "CWE-918",
                          "Critical"))

    def test_dependency_rows_are_per_advisory_and_package_version(self):
        sca = [r["title"] for r in self.rows if r["stage"] == "SCA"]
        self.assertEqual(sca, ["CVE-2016-10531 marked@0.3.5", "CVE-2017-1000427 marked@0.3.5"])
        image = [r for r in self.rows if r["stage"] == "Container image"]
        self.assertEqual(len(image), 2)  # two install paths of marked are one flaw
        marked = next(r for r in image if "marked" in r["title"])
        self.assertEqual(marked["location"].count("; "), 1)

    def test_dast_one_row_per_alert_type_with_route(self):
        dast = [r for r in self.rows if r["stage"] == "DAST"]
        self.assertEqual([(r["finding_id"], r["rule"]) for r in dast],
                         [("dast-r1-001", "10028"), ("dast-r1-002", "10038")])
        self.assertEqual(dast[0]["location"], "/learn?url=https://example.org/ (1 instance)")
        self.assertEqual(dast[1]["location"], "/login (5 instances)")

    def test_repeat_runs_add_dast_rows_only(self):
        rows = scoring_sheet.sheet(RUN, [rerun(findings=RUN["findings"][-1:])])
        extra = rows[len(self.rows):]
        self.assertEqual([(r["finding_id"], r["run"], r["rule"]) for r in extra],
                         [("dast-r2-001", "101", "10028")])

    def test_ids_are_unique_and_stable(self):
        ids = [r["finding_id"] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))
        shuffled = dict(RUN, findings=list(reversed(RUN["findings"])))
        self.assertEqual(scoring_sheet.sheet(shuffled), self.rows)

    def test_stages_not_run_have_no_rows(self):
        rows = scoring_sheet.sheet(dict(RUN, stages=["sast"]))
        self.assertEqual({r["stage"] for r in rows}, {"SAST (Semgrep)"})

    def test_nothing_is_scored_automatically(self):
        for r in self.rows:
            for col in SCORING:
                self.assertNotIn(col, r)


class TestMain(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def write(self, name, data):
        path = self.tmp / name
        path.write_text(json.dumps(data) if not isinstance(data, str) else data)
        return str(path)

    def run_main(self, *argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = scoring_sheet.main(list(argv))
        return rc, err.getvalue()

    def test_writes_csv_with_empty_scoring_columns(self):
        out = self.tmp / "sheet.csv"
        rc, _ = self.run_main(self.write("a.json", RUN), "--dast",
                              self.write("b.json", rerun()), "-o", str(out))
        self.assertEqual(rc, 0)
        with out.open(newline="") as fh:
            reader = csv.DictReader(fh)
            self.assertEqual(reader.fieldnames, scoring_sheet.COLUMNS)
            rows = list(reader)
        self.assertEqual(len(rows), 10 + 2)  # 11 findings, one merged; 2 DAST repeats
        self.assertTrue(all(r[c] == "" for r in rows for c in SCORING))

    def test_repeat_run_of_another_commit_is_refused(self):
        rc, err = self.run_main(self.write("a.json", RUN), "--dast",
                                self.write("b.json", rerun(commit="def")))
        self.assertEqual(rc, 2)
        self.assertIn("not the scored run's commit", err)

    def test_repeat_run_without_dast_is_refused(self):
        rc, err = self.run_main(self.write("a.json", RUN), "--dast",
                                self.write("b.json", rerun(stages=["sast"])))
        self.assertEqual(rc, 2)
        self.assertIn("DAST did not run", err)

    def test_bad_input_is_refused(self):
        for content in ("not json", "[]", '{"run": "1"}'):
            rc, _ = self.run_main(self.write("a.json", content))
            self.assertEqual(rc, 2, content)
        self.assertEqual(self.run_main(str(self.tmp / "missing.json"))[0], 2)


if __name__ == "__main__":
    unittest.main()
