#!/usr/bin/env python3
"""Combine the five scanners' results into one report and apply the pass/fail gate.

Usage:  aggregate.py RESULTS_DIR [--not-run STAGE ...] [--report-only]
                      [--previous AGGREGATED_JSON]

RESULTS_DIR holds one folder per uploaded artifact, the layout produced by
actions/download-artifact and by `gh run download <run-id> -D RESULTS_DIR`.
Writes RESULTS_DIR/aggregated-report.md (for the job summary) and
RESULTS_DIR/aggregated.json (every normalised finding, for mapping to the
catalogue).

Exit status: 0 = gate passed, 1 = gate failed, 2 = an input is missing or not in
the expected format. With --report-only the verdict is only recorded (in
aggregated.json and the report) and a failed gate also exits 0, so that a
separate step can enforce it. A stage listed with --not-run is reported as not
run instead of being treated as missing. --previous takes an earlier run's
aggregated.json and adds the new, resolved and re-rated findings to the report.
"""

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

# Common severity scale, most severe first.
SCALE = ["Critical", "High", "Medium", "Low", "Info"]

# Pass/fail criteria (DORA Art. 24): any finding at these levels fails the gate.
GATE_FAIL_ON = ("Critical", "High")

# Each tool's own vocabulary mapped onto SCALE. A value not listed here is an
# input error, so a schema change can't silently downgrade a finding.
SEMGREP_SEVERITY = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
TRIVY_SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
                  "LOW": "Low", "UNKNOWN": "High"}  # unrated: fail safe
ZAP_SEVERITY = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
GITLEAKS_SEVERITY = "High"  # Gitleaks has no severity; any leaked secret is High

# Rules loaded from local files get the folder path as a check_id prefix.
SEMGREP_RULES_PREFIX = "results.semgrep-rules."
NODEJSSCAN_MARKER = "ajinabraham.njsscan"

# WORKDIR of NodeGoat in the image (app/Dockerfile).
IMAGE_APP_ROOT = "home/node/app/"

STAGES = {
    "sast": ("SAST", "Semgrep", "semgrep-results/semgrep.json"),
    "secrets": ("Secrets", "Gitleaks", "gitleaks-results/gitleaks.json"),
    "sca": ("SCA", "Trivy fs", "trivy-deps-results/trivy-deps.json"),
    "image": ("Container image", "Trivy image", "trivy-image-results/trivy-image.json"),
    "dast": ("DAST", "ZAP baseline", "zap-results/zap-report.json"),
}


class InputError(Exception):
    pass


def mapped(table, value, tool):
    try:
        return table[value]
    except KeyError:
        raise InputError(f"{tool}: unknown severity {value!r}") from None


def cwe_ids(values):
    # Semgrep gives ["CWE-79: Improper ..."], or "cwe-79" for nodejsscan rules;
    # Trivy gives ["CWE-79"].
    if isinstance(values, str):
        values = [values]
    return [v.split(":")[0].upper() for v in values or []]


def parse_semgrep(raw):
    for r in raw["results"]:
        rule = r["check_id"].removeprefix(SEMGREP_RULES_PREFIX)
        yield {
            "rule": rule,
            "title": rule.rsplit(".", 1)[-1],
            "location": f"{r['path']}:{r['start']['line']}",
            "raw_severity": r["extra"]["severity"],
            "severity": mapped(SEMGREP_SEVERITY, r["extra"]["severity"], "semgrep"),
            "cwe": cwe_ids(r["extra"]["metadata"].get("cwe")),
            "ruleset": "nodejsscan" if NODEJSSCAN_MARKER in rule else "standard",
        }


def parse_gitleaks(raw):
    for r in raw:
        yield {
            "rule": r["RuleID"],
            "title": r["RuleID"],
            "location": f"{r['File']}:{r['StartLine']} @ {r['Commit'][:7]}",
            "raw_severity": "-",
            "severity": GITLEAKS_SEVERITY,
            "cwe": [],
        }


def parse_trivy(raw):
    for result in raw["Results"]:
        for v in result.get("Vulnerabilities") or []:
            path = v.get("PkgPath")
            if result["Class"] == "os-pkgs":
                # Target is "<image>@<digest> (alpine 3.15.4)"
                path = "OS (" + result["Target"].rsplit(" (", 1)[-1]
                component = "os"
            elif path and not path.startswith(IMAGE_APP_ROOT):
                component = "base"  # e.g. npm bundled with the node base image
            else:
                component = "app"
            yield {
                "rule": v["VulnerabilityID"],
                "title": f"{v['VulnerabilityID']} {v['PkgName']}@{v['InstalledVersion']}",
                "location": path or result["Target"],  # SCA: package-lock.json
                "raw_severity": v["Severity"],
                "severity": mapped(TRIVY_SEVERITY, v["Severity"], "trivy"),
                "cwe": cwe_ids(v.get("CweIDs")),
                "package": f"{v['PkgName']}@{v['InstalledVersion']}",
                "component": component,
            }


def parse_zap(raw):
    for site in raw["site"]:
        for a in site["alerts"]:
            instances = a["instances"]
            where = instances[0]["uri"] if instances else site["@name"]
            yield {
                "rule": a["pluginid"],
                "title": a["alert"],
                "location": f"{a['count']} instance(s), e.g. {where}",
                "raw_severity": a["riskdesc"],
                "severity": mapped(ZAP_SEVERITY, a["riskcode"], "zap"),
                "cwe": [f"CWE-{a['cweid']}"] if a["cweid"] not in ("", "-1", "0") else [],
            }


PARSERS = {"sast": parse_semgrep, "secrets": parse_gitleaks, "sca": parse_trivy,
           "image": parse_trivy, "dast": parse_zap}


def load(results_dir, stage):
    path = results_dir / STAGES[stage][2]
    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError:
        raise InputError(f"{stage}: {path} not found") from None
    except json.JSONDecodeError as e:
        raise InputError(f"{stage}: {path} is not valid JSON ({e})") from None
    try:
        return [dict(f, stage=stage) for f in PARSERS[stage](raw)]
    except (KeyError, TypeError) as e:
        raise InputError(f"{stage}: unexpected format in {path} ({e!r})") from None


def dedup_key(f):
    # The same advisory on the same package version is one flaw, whether the
    # lockfile scan, the image scan, or both report it, and however many paths
    # it is installed at. App and base-image copies stay separate: they are fixed
    # in different places.
    if f["stage"] in ("sca", "image"):
        return ("package", f["component"], f["title"])
    return (f["stage"], f["rule"], f["location"])


def combine(findings):
    unique = {}
    for f in findings:
        k = dedup_key(f)
        if k not in unique or SCALE.index(f["severity"]) < SCALE.index(unique[k]):
            unique[k] = f["severity"]
    return Counter(unique.values())


def dependency_overlap(findings):
    def keys(stage, component=None):
        return {f["title"] for f in findings if f["stage"] == stage
                and (component is None or f["component"] == component)}
    sca, image_app = keys("sca"), keys("image", "app")
    return {"both": len(sca & image_app), "sca_only": len(sca - image_app),
            "image_only": len(image_app - sca),
            "image_base": len(keys("image", "base")), "image_os": len(keys("image", "os"))}


def trivy_db_date(results_dir, artifact):
    try:
        info = json.loads((results_dir / artifact / "trivy-db.json").read_text())
        return info["VulnerabilityDB"]["UpdatedAt"]
    except (OSError, ValueError, KeyError):
        return None


ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "⚪"}


def md(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def sev(level):
    return f"{ICON[level]} {level}"


def identity(f):
    # Identifies a finding across runs. ZAP's instance count and example URL
    # change with what the spider happened to reach, so an alert type is
    # identified by its rule alone.
    if f["stage"] == "dast":
        return (f["stage"], f["rule"])
    if f["stage"] in ("sca", "image"):
        return (f["stage"], f["component"], f["title"])
    return (f["stage"], f["rule"], f["location"])


def changes(findings, previous, not_run):
    """Compare with a previous run's aggregated.json, for stages run in both."""
    compared = [s for s in STAGES if s not in not_run and s not in previous["not_run"]]
    now = {identity(f): f for f in findings if f["stage"] in compared}
    before = {identity(f): f for f in previous["findings"] if f["stage"] in compared}
    return {
        "compared": compared,
        "new": [now[k] for k in now.keys() - before.keys()],
        "resolved": [before[k] for k in before.keys() - now.keys()],
        "rerated": [(before[k], now[k]) for k in now.keys() & before.keys()
                    if now[k]["severity"] != before[k]["severity"]],
    }


def bar(n, top, width=30):
    eighths = round(n / top * width * 8) if top else 0
    full, part = divmod(eighths, 8)
    return "█" * full + (" ▏▎▍▌▋▊▉"[part] if part else "") or ("▏" if n else "")


def finding_table(rows, with_stage=False):
    head = "| Severity | " + ("Stage | " if with_stage else "") + \
        "Tool severity | Finding | Location | CWE |"
    lines = [head, "|" + "---|" * (head.count("|") - 1)]
    for f in sorted(rows, key=lambda f: SCALE.index(f["severity"])):
        stage = f"{STAGES[f['stage']][0]} | " if with_stage else ""
        lines.append(f"| {sev(f['severity'])} | {stage}{md(f['raw_severity'])} | "
                     f"{md(f['title'])} | {md(f['location'])} | {', '.join(f['cwe'])} |")
    return lines


def details(summary, body):
    return ["", f"<details><summary>{summary}</summary>", "", *body, "", "</details>"]


def report(results_dir, findings, not_run, passed, previous=None):
    by_stage = {s: [f for f in findings if f["stage"] == s] for s in STAGES}
    blocking = Counter(f["stage"] for f in findings if f["severity"] in GATE_FAIL_ON)
    commit = os.environ.get("GITHUB_SHA", "")[:7]
    lines = [f"# 🛡️ Security report{' · ' + commit if commit else ''}", ""]
    if passed:
        lines += ["> [!TIP]", f"> **Gate PASSED.** No {' or '.join(GATE_FAIL_ON)} findings."]
    else:
        lines += ["> [!CAUTION]",
                  f"> **Gate FAILED.** {' or '.join(GATE_FAIL_ON)} findings in "
                  f"{len(blocking)} of {len(STAGES) - len(not_run)} stages run: "
                  + " · ".join(f"{STAGES[s][0]} {n}" for s, n in blocking.items())]
    if not_run:
        lines += ["", "> [!WARNING]", "> **Partial result.** Not run in this pipeline run: "
                  + ", ".join(STAGES[s][0] for s in not_run) + "."]
    lines += ["", f"Criteria (DORA Art. 24): the gate fails on any "
              f"{' or '.join(GATE_FAIL_ON)} finding from any stage. Each tool's severity is "
              "mapped onto one scale (Gitleaks has none, so every leaked secret counts as High)."]

    lines += ["", "## Findings by stage", "",
              "| Stage | Tool | Gate | " + " | ".join(sev(s) for s in SCALE) + " | Total | Notes |",
              "|---|---|---|" + "--:|" * (len(SCALE) + 1) + "---|"]
    for stage, (label, tool, _) in STAGES.items():
        if stage in not_run:
            lines.append(f"| {label} | {tool} | ⏭️ not run |" + " – |" * (len(SCALE) + 1) + " |")
            continue
        fs = by_stage[stage]
        note = ""
        if stage == "sast":
            rs = Counter(f["ruleset"] for f in fs)
            note = (f"{len({f['location'] for f in fs})} locations; "
                    f"standard {rs['standard']}, nodejsscan {rs['nodejsscan']}")
        elif stage == "sca":
            note = f"{len({f['package'] for f in fs})} package versions"
        elif stage == "image":
            comp = Counter(f["component"] for f in fs)
            note = f"app {comp['app']}, base-image npm {comp['base']}, OS {comp['os']}"
        elif stage == "dast":
            note = f"alert types; {sum(int(f['location'].split()[0]) for f in fs)} instances"
        counts = Counter(f["severity"] for f in fs)
        gate = f"❌ {blocking[stage]}" if blocking[stage] else "✅"
        lines.append(f"| {label} | {tool} | {gate} | "
                     + " | ".join(str(counts[s]) for s in SCALE)
                     + f" | {len(fs)} | {note} |")
    combined = combine(findings)
    lines.append("| **Combined** | de-duplicated | | "
                 + " | ".join(str(combined[s]) for s in SCALE)
                 + f" | **{sum(combined.values())}** | package advisories counted once "
                 "per package version |")

    run = [s for s in STAGES if s not in not_run]
    top = max([blocking[s] for s in run] or [0])
    width = max(len(STAGES[s][0]) for s in STAGES)
    lines += ["", f"**{' + '.join(GATE_FAIL_ON)} by stage**", "```"]
    lines += [f"{STAGES[s][0]:<{width}}  {bar(blocking[s], top):<31}{blocking[s]:>4}"
              for s in run]
    lines += ["```"]

    lines += ["", "## Changes since the previous run"]
    if previous is None:
        lines += ["", "_No previous run to compare with._"]
    else:
        c = changes(findings, previous, not_run)
        ref = f"run {previous['run']}" if previous.get("run") else "the previous run"
        if previous.get("url"):
            ref = f"[{ref}]({previous['url']})"
        if previous.get("commit"):
            ref += f" (commit {previous['commit'][:7]})"
        lines += ["", f"Compared with {ref}."]
        skipped = [STAGES[s][0] for s in STAGES if s not in c["compared"]]
        if skipped:
            lines += ["", f"Not compared (not run in one of the two runs): {', '.join(skipped)}."]
        if not (c["new"] or c["resolved"] or c["rerated"]):
            lines += ["", "No new, resolved or re-rated findings."]
        else:
            lines += ["", "| Stage | 🆕 New | ✔️ Resolved | ↕️ Re-rated |", "|---|--:|--:|--:|"]
            for s in c["compared"]:
                n = [sum(1 for f in c[k] if f["stage"] == s) for k in ("new", "resolved")]
                r = sum(1 for _, f in c["rerated"] if f["stage"] == s)
                if any(n) or r:
                    lines.append(f"| {STAGES[s][0]} | {n[0]} | {n[1]} | {r} |")
            if c["new"]:
                lines += details(f"🆕 New: {len(c['new'])}", finding_table(c["new"], True))
            if c["resolved"]:
                lines += details(f"✔️ Resolved: {len(c['resolved'])}",
                                 finding_table(c["resolved"], True))
            if c["rerated"]:
                rows = ["| Stage | Finding | Before | Now |", "|---|---|---|---|"]
                rows += [f"| {STAGES[f['stage']][0]} | {md(f['title'])} | "
                         f"{sev(b['severity'])} | {sev(f['severity'])} |"
                         for b, f in c["rerated"]]
                lines += details(f"↕️ Re-rated: {len(c['rerated'])}", rows)
        if any(f["stage"] == "dast" for f in c["new"] + c["resolved"]):
            lines += ["", "> [!NOTE]", "> DAST changes can come from the spider reaching "
                      "different pages, not only from changes to the application."]

    if not {"sca", "image"} & set(not_run):
        o = dependency_overlap(findings)
        lines += ["", "## Dependencies", "",
                  "Unique advisory per package version: "
                  f"{o['both']} in both SCA and the image's app packages, "
                  f"{o['sca_only']} only in the lockfile (not installed in the image), "
                  f"{o['image_only']} only in the image's app packages. The image adds "
                  f"{o['image_base']} in the base image's bundled npm and {o['image_os']} "
                  "OS package findings, which the lockfile can't see."]
    dates = {a: trivy_db_date(results_dir, a) for s, a in
             (("sca", "trivy-deps-results"), ("image", "trivy-image-results"))
             if s not in not_run}
    if any(dates.values()):
        lines += ["", "Trivy DB: " + ", ".join(f"{a.split('-')[1]} {d}"
                                              for a, d in dates.items() if d) + "."]

    lines += ["", "## Details"]
    for stage, (label, tool, _) in STAGES.items():
        if by_stage[stage]:
            lines += details(f"{label} ({tool}): {len(by_stage[stage])}",
                             finding_table(by_stage[stage]))
    return "\n".join(lines) + "\n"


def run_url():
    env = os.environ
    if "GITHUB_RUN_ID" not in env:
        return None
    return (f"{env.get('GITHUB_SERVER_URL', 'https://github.com')}/"
            f"{env.get('GITHUB_REPOSITORY')}/actions/runs/{env['GITHUB_RUN_ID']}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("results_dir", type=Path)
    ap.add_argument("--not-run", action="append", default=[], choices=STAGES,
                    help="stage legitimately not run in this pipeline run")
    ap.add_argument("--report-only", action="store_true",
                    help="record the verdict but exit 0 when the gate fails")
    ap.add_argument("--previous", type=Path,
                    help="an earlier run's aggregated.json to compare with")
    args = ap.parse_args(argv)

    try:
        findings = [f for s in STAGES if s not in args.not_run
                    for f in load(args.results_dir, s)]
        previous = json.loads(args.previous.read_text()) if args.previous else None
    except InputError as e:
        print(f"::error::aggregate: {e}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as e:
        print(f"::error::aggregate: previous run: {e}", file=sys.stderr)
        return 2

    blocking = Counter(f["stage"] for f in findings if f["severity"] in GATE_FAIL_ON)
    passed = not blocking
    (args.results_dir / "aggregated-report.md").write_text(
        report(args.results_dir, findings, args.not_run, passed, previous))
    (args.results_dir / "aggregated.json").write_text(json.dumps({
        # Set in GitHub Actions; identifies this run when a later one compares.
        "run": os.environ.get("GITHUB_RUN_ID"),
        "commit": os.environ.get("GITHUB_SHA"),
        "url": run_url(),
        "gate": "pass" if passed else "fail",
        "fail_on": list(GATE_FAIL_ON),
        "not_run": args.not_run,
        "blocking": {STAGES[s][0]: n for s, n in blocking.items()},
        "findings": findings,
    }, indent=2) + "\n")

    if passed:
        print("Gate PASSED: no " + "/".join(GATE_FAIL_ON) + " findings")
        return 0
    print("Gate FAILED: " + ", ".join(
        f"{STAGES[s][0]} {n}" for s, n in blocking.items()) + " Critical/High findings")
    return 0 if args.report_only else 1


if __name__ == "__main__":
    sys.exit(main())
