#!/usr/bin/env python3
"""Write the scoring sheet: one CSV row per finding, to be scored by hand.

Usage:  scoring_sheet.py AGGREGATED_JSON [--dast AGGREGATED_JSON ...] [-o SHEET_CSV]

AGGREGATED_JSON is a pipeline run's aggregated.json (from aggregate.py). Every
finding of that run gets a row. --dast adds the DAST alerts of further runs of
the same commit (DAST is repeated in the scored run; only their DAST rows are
used). Writes to SHEET_CSV, or to stdout.

Rows, per stage:
  - SAST (Semgrep, CodeQL) and secrets: one per finding (rule + file:line).
  - SCA and container image: one per advisory and package version. Copies of
    the same package at several install paths are one flaw, as in aggregate.py,
    and are listed together in the location column.
  - DAST: one per alert type per run, located by an example route.

File paths are relative to app/, as in the catalogue and the matching rule.
The scoring columns (catalogue_row, m6_label, match_rule, triage_minutes,
notes) are left empty: they are filled in by hand under the frozen matching
rule. Nothing is matched automatically.

Exit status: 0 = written, 2 = an input is missing, not an aggregated.json, or
from a different commit than the first.
"""

import argparse
import csv
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

STAGES = {  # order and labels as in aggregate.py
    "sast": ("SAST (Semgrep)", "Semgrep"),
    "codeql": ("SAST (CodeQL)", "CodeQL"),
    "secrets": ("Secrets", "Gitleaks"),
    "sca": ("SCA", "Trivy fs"),
    "image": ("Container image", "Trivy image"),
    "dast": ("DAST", "ZAP baseline"),
}
DEPENDENCY_STAGES = ("sca", "image")
SOURCE_ROOT = "app/"
COLUMNS = ["finding_id", "run", "stage", "tool", "rule", "title", "location", "cwe",
           "severity", "catalogue_row", "m6_label", "match_rule", "triage_minutes", "notes"]


class InputError(Exception):
    pass


def load(path):
    try:
        data = json.loads(Path(path).read_text())
    except OSError as e:
        raise InputError(f"{path}: {e.strerror}") from None
    except ValueError as e:
        raise InputError(f"{path}: not valid JSON ({e})") from None
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise InputError(f"{path}: not an aggregated.json (no findings list)")
    return data


def location(f):
    if f["stage"] == "dast":
        # "5 instance(s), e.g. http://web:4000/login" -> "/login (5 instances)"
        count, _, url = f["location"].partition(" instance(s), e.g. ")
        parts = urlsplit(url)
        route = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        return f"{route} ({count} instance{'' if count == '1' else 's'})"
    if f["stage"] in DEPENDENCY_STAGES:
        return f["location"]
    return f["location"].removeprefix(SOURCE_ROOT)


def stage_rows(findings, stage):
    """Rows for one stage, merged and sorted so the ids are stable across runs."""
    rows = {}
    for f in findings:
        if f["stage"] != stage:
            continue
        if stage in DEPENDENCY_STAGES:
            key = (f["component"], f["title"])
        else:
            key = (f["rule"], f["location"])
        row = rows.setdefault(key, {
            "stage": STAGES[stage][0], "tool": STAGES[stage][1], "rule": f["rule"],
            "title": f["title"], "locations": [], "cwe": [], "severity": f["severity"],
        })
        if location(f) not in row["locations"]:
            row["locations"].append(location(f))
        row["cwe"] += [c for c in f["cwe"] if c not in row["cwe"]]
    if stage == "dast":
        order = sorted(rows, key=lambda k: (int(k[0]) if k[0].isdigit() else 0, k))
    elif stage in DEPENDENCY_STAGES:
        # by package ("CVE-x pkg@1.0" -> "pkg@1.0"), as M5 scores per package
        order = sorted(rows, key=lambda k: (k[0], k[1].split(" ", 1)[-1], k[1]))
    else:
        order = sorted(rows, key=lambda k: (rows[k]["locations"][0], k))
    return [rows[k] for k in order]


def sheet(primary, dast_runs=()):
    out = []

    def add(data, stage, prefix):
        for n, row in enumerate(stage_rows(data["findings"], stage), 1):
            out.append({
                "finding_id": f"{prefix}-{n:03d}", "run": data.get("run") or "",
                "stage": row["stage"], "tool": row["tool"], "rule": row["rule"],
                "title": row["title"], "location": "; ".join(sorted(row["locations"])),
                "cwe": "; ".join(row["cwe"]), "severity": row["severity"],
            })

    for stage in STAGES:
        if stage in primary.get("stages", STAGES):
            add(primary, stage, "dast-r1" if stage == "dast" else stage)
    for n, data in enumerate(dast_runs, 2):
        add(data, "dast", f"dast-r{n}")
    return out


def write(fh, rows):
    writer = csv.DictWriter(fh, fieldnames=COLUMNS, restval="")
    writer.writeheader()
    writer.writerows(rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("aggregated", help="the scored run's aggregated.json")
    ap.add_argument("--dast", action="append", default=[], metavar="AGGREGATED_JSON",
                    help="a repeat run of the same commit; its DAST alerts are added")
    ap.add_argument("-o", "--output", type=Path, help="CSV to write (default: stdout)")
    args = ap.parse_args(argv)

    try:
        primary = load(args.aggregated)
        repeats = [load(p) for p in args.dast]
        for path, data in zip(args.dast, repeats):
            if data.get("commit") != primary.get("commit"):
                raise InputError(f"{path}: commit {data.get('commit')} is not the scored "
                                 f"run's commit {primary.get('commit')}")
            if "dast" not in data.get("stages", []):
                raise InputError(f"{path}: DAST did not run")
    except InputError as e:
        print(f"scoring_sheet: {e}", file=sys.stderr)
        return 2

    rows = sheet(primary, repeats)
    if args.output:
        with args.output.open("w", newline="") as fh:
            write(fh, rows)
        print(f"{len(rows)} rows written to {args.output}", file=sys.stderr)
    else:
        write(sys.stdout, rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
