#!/usr/bin/env python3
"""Combine the scanners' results into one report and apply the pass/fail gate.

Usage:  aggregate.py RESULTS_DIR [--not-run STAGE ...] [--report-only]
                      [--previous AGGREGATED_JSON]

RESULTS_DIR holds one folder per uploaded artifact, the layout produced by
actions/download-artifact and by `gh run download <run-id> -D RESULTS_DIR`.
Writes RESULTS_DIR/aggregated-report.md (for the job summary),
RESULTS_DIR/aggregated.json (every normalised finding, for mapping to the
catalogue) and the evidence record: RESULTS_DIR/evidence-manifest.json (size and
SHA-256 of every result file, SBOM and aggregated.json) and
RESULTS_DIR/evidence-manifest.sha256 (the same in `sha256sum -c` format, plus the
JSON manifest itself).

Exit status: 0 = gate passed, 1 = gate failed, 2 = an input (a result file or
another expected evidence file, such as an SBOM) is missing or not in the
expected format. With --report-only the verdict is only recorded (in
aggregated.json and the report) and a failed gate also exits 0, so that a
separate step can enforce it. A stage listed with --not-run is reported as not
run instead of being treated as missing. --previous takes an earlier run's
aggregated.json and adds the new, resolved and re-rated findings to the report.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
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
# CodeQL rates security queries 0-10 ("security-severity"); thresholds as GitHub uses them.
CODEQL_SEVERITY = [(9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"), (0.0, "Info")]

# Rules loaded from local files get the folder path as a check_id prefix.
SEMGREP_RULES_PREFIX = "results.semgrep-rules."
NODEJSSCAN_MARKER = "ajinabraham.njsscan"

# WORKDIR of NodeGoat in the image (app/Dockerfile).
IMAGE_APP_ROOT = "home/node/app/"

# CodeQL's paths are relative to its --source-root.
CODEQL_SOURCE_ROOT = "app/"
CODEQL_HELP_URL = "https://codeql.github.com/codeql-query-help/javascript/{}/"

SAST_STAGES = ("sast", "codeql")
DEPENDENCY_STAGES = ("sca", "image")
# CycloneDX SBOMs written next to each dependency stage's results (evidence, not a gate input).
SBOM_FILES = {"sca": "sbom-deps.cdx.json", "image": "sbom-image.cdx.json"}

MANIFEST_JSON = "evidence-manifest.json"
MANIFEST_SUMS = "evidence-manifest.sha256"
ZAP_ALERT_URL = "https://www.zaproxy.org/docs/alerts/{}/"
CWE_URL = "https://cwe.mitre.org/data/definitions/{}.html"

STAGES = {
    "sast": ("SAST (Semgrep)", "Semgrep", "semgrep-results/semgrep.json"),
    "codeql": ("SAST (CodeQL)", "CodeQL", "codeql-results/codeql.sarif"),
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


def codeql_severity(score):
    try:
        value = float(score)
    except (TypeError, ValueError):
        raise InputError(f"codeql: unknown security-severity {score!r}") from None
    if not 0 <= value <= 10:
        raise InputError(f"codeql: unknown security-severity {score!r}")
    return next(level for floor, level in CODEQL_SEVERITY if value >= floor)


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
            "url": r["extra"]["metadata"].get("source"),
        }


def parse_codeql(raw):
    # SARIF: each result names its rule; the rule holds the score and CWE tags.
    for run in raw["runs"]:
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        for r in run["results"]:
            rule = rules[r["ruleId"]]
            props = rule["properties"]
            where = r["locations"][0]["physicalLocation"]
            score = props.get("security-severity")
            yield {
                "rule": r["ruleId"],
                "title": rule["shortDescription"]["text"],
                "location": f"{CODEQL_SOURCE_ROOT}{where['artifactLocation']['uri']}:"
                            f"{where['region']['startLine']}",
                "raw_severity": f"{score} ({props.get('problem.severity', '-')})",
                "severity": codeql_severity(score),
                # "external/cwe/cwe-094" -> "CWE-94"
                "cwe": [f"CWE-{int(t.rsplit('-', 1)[1])}" for t in props.get("tags", [])
                        if t.startswith("external/cwe/cwe-")],
                "url": CODEQL_HELP_URL.format(r["ruleId"].replace("/", "-")),
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
            "location_url": r.get("Link"),  # the file at the leaking commit
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
                "fixed": v.get("FixedVersion", ""),
                "url": v.get("PrimaryURL"),
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
                "url": ZAP_ALERT_URL.format(a["pluginid"]),
            }


PARSERS = {"sast": parse_semgrep, "codeql": parse_codeql, "secrets": parse_gitleaks,
           "sca": parse_trivy, "image": parse_trivy, "dast": parse_zap}


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
    except (KeyError, TypeError, IndexError, ValueError) as e:
        raise InputError(f"{stage}: unexpected format in {path} ({e!r})") from None


def dedup_key(f):
    # The same advisory on the same package version is one flaw, whether the
    # lockfile scan, the image scan, or both report it, and however many paths
    # it is installed at. App and base-image copies stay separate: they are fixed
    # in different places.
    if f["stage"] in DEPENDENCY_STAGES:
        return ("package", f["component"], f["title"])
    return (f["stage"], f["rule"], f["location"])


def group_key(f):
    # For listing: Semgrep often reports one line under two rules (e.g.
    # eval_nodejs and code-string-concat), which is one row to read.
    if f["stage"] in SAST_STAGES:
        return (f["stage"], f["location"])
    return dedup_key(f)


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


def sast_overlap(findings):
    """Locations (file:line) per SAST tool. Matched on the exact line only: the
    tools label the same flaw with different rules and CWEs."""
    at = {s: {} for s in SAST_STAGES}
    for f in findings:
        if f["stage"] in SAST_STAGES:
            at[f["stage"]].setdefault(f["location"], []).append(f)
    return at


def trivy_db_date(results_dir, artifact):
    try:
        info = json.loads((results_dir / artifact / "trivy-db.json").read_text())
        return info["VulnerabilityDB"]["UpdatedAt"]
    except (OSError, ValueError, KeyError):
        return None


def sbom_summary(results_dir, stage):
    """Component counts of a stage's SBOM by package type (npm, apk, ...), or None."""
    folder = STAGES[stage][2].split("/")[0]
    path = results_dir / folder / SBOM_FILES[stage]
    try:
        raw = json.loads(path.read_text())
        components = raw["components"]
        # "pkg:npm/express@4.17.1" -> "npm"; the OS and the scanned target have no purl.
        types = Counter(c["purl"].split(":", 1)[1].split("/", 1)[0]
                        for c in components if c.get("purl"))
        return {"file": SBOM_FILES[stage], "format": f"{raw['bomFormat']} {raw['specVersion']}",
                "components": sum(types.values()), "types": dict(types.most_common())}
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError):
        return None


def expected_files(stage):
    """Files a stage that ran must have produced, relative to the results folder."""
    main = STAGES[stage][2]
    if stage in SBOM_FILES:
        return [main, f"{main.split('/')[0]}/{SBOM_FILES[stage]}"]
    return [main]


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def evidence_files(results_dir, not_run):
    """Every file in the downloaded result folders, after checking the expected ones exist."""
    for stage in STAGES:
        if stage in not_run:
            continue
        for name in expected_files(stage):
            if not (results_dir / name).is_file():
                raise InputError(f"{stage}: {results_dir / name} not found")
    return sorted(p.relative_to(results_dir).as_posix()
                  for d in results_dir.iterdir() if d.is_dir() and d.name.endswith("-results")
                  for p in d.rglob("*") if p.is_file())


def write_manifest(results_dir, files, record):
    """Write the evidence manifest (JSON and sha256sum list); return the JSON's SHA-256."""
    entries = [{"path": name, "size": (results_dir / name).stat().st_size,
                "sha256": sha256(results_dir / name)} for name in files]
    manifest = dict(record, created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    files=entries)
    (results_dir / MANIFEST_JSON).write_text(json.dumps(manifest, indent=2) + "\n")
    digest = sha256(results_dir / MANIFEST_JSON)
    sums = [f"{e['sha256']}  {e['path']}" for e in entries] + [f"{digest}  {MANIFEST_JSON}"]
    (results_dir / MANIFEST_SUMS).write_text("\n".join(sums) + "\n")
    return entries, digest


def tool_version(results_dir, stage):
    # Provenance only: a missing version is reported as such, not an error.
    folder, name = STAGES[stage][2].split("/")
    try:
        if stage == "secrets":  # the report has none; the job saves `gitleaks version`
            return (results_dir / folder / "gitleaks-version.txt").read_text().strip().lstrip("v")
        raw = json.loads((results_dir / folder / name).read_text())
        return {"sast": lambda: raw["version"], "dast": lambda: raw["@version"],
                "codeql": lambda: raw["runs"][0]["tool"]["driver"]["semanticVersion"]}.get(
            stage, lambda: raw["Trivy"]["Version"])()
    except (OSError, ValueError, KeyError, TypeError):
        return None


def utc_minute(timestamp):
    # "2026-10-25T12:57:48.463991102Z" -> "25/10/2026 12:57 UTC"
    try:
        return datetime.strptime(timestamp[:16], "%Y-%m-%dT%H:%M").strftime("%d/%m/%Y %H:%M UTC")
    except ValueError:
        return timestamp


ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "⚪"}


def md(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def link(text, url):
    if not url:
        return md(text)
    text = md(text).replace("[", "\\[").replace("]", "\\]")
    return f"[{text}]({url.replace(' ', '%20').replace('(', '%28').replace(')', '%29')})"


def sev(level):
    return f"{ICON[level]} {level}"


def repo_url():
    env = os.environ
    if not env.get("GITHUB_REPOSITORY"):
        return None
    return f"{env.get('GITHUB_SERVER_URL', 'https://github.com')}/{env['GITHUB_REPOSITORY']}"


def title_md(f):
    # Link the advisory ID inside "CVE-... pkg@version", otherwise the whole title.
    if f.get("url") and f["title"].startswith(f["rule"] + " "):
        return link(f["rule"], f["url"]) + md(f["title"][len(f["rule"]):])
    return link(f["title"], f.get("url"))


def location_md(f):
    loc = f["location"]
    if f["stage"] == "dast":
        # "5 instance(s), e.g. http://web:4000/learn?url=..." -> path only, cut short
        count, _, uri = loc.partition(", e.g. ")
        path = re.sub(r"^https?://[^/]+", "", uri) or "/"
        return md(f"{count}, e.g. {path if len(path) <= 50 else path[:49] + '…'}")
    url = f.get("location_url")
    if not url and f["stage"] in SAST_STAGES and repo_url() and os.environ.get("GITHUB_SHA"):
        path, _, line = loc.rpartition(":")
        url = f"{repo_url()}/blob/{os.environ['GITHUB_SHA']}/{path}#L{line}"
    return link(loc, url)


def tool_severity(f):
    if f["stage"] == "dast":  # ZAP riskdesc is "risk (confidence)"
        m = re.fullmatch(r"(.+) \((.+)\)", f["raw_severity"])
        if m:
            return f"{m[1]}, confidence {m[2]}"
    return f["raw_severity"]


def cwe_md(ids):
    return ", ".join(link(c, CWE_URL.format(c[4:])) if c[4:].isdigit() else md(c) for c in ids)


def unique(values):
    return list(dict.fromkeys(v for v in values if v))


def identity(f):
    # Identifies a finding across runs. ZAP's instance count and example URL
    # change with what the spider happened to reach, so an alert type is
    # identified by its rule alone.
    if f["stage"] == "dast":
        return (f["stage"], f["rule"])
    if f["stage"] in DEPENDENCY_STAGES:
        return (f["stage"], f["component"], f["title"])
    return (f["stage"], f["rule"], f["location"])


def stages_run(previous):
    if "stages" in previous:
        return previous["stages"]
    # Older aggregated.json didn't list its stages; CodeQL wasn't one of them.
    return [s for s in STAGES if s != "codeql" and s not in previous["not_run"]]


def changes(findings, previous, not_run):
    """Compare with a previous run's aggregated.json, for stages run in both."""
    compared = [s for s in STAGES if s not in not_run and s in stages_run(previous)]
    now = {identity(f): f for f in findings if f["stage"] in compared}
    before = {identity(f): f for f in previous["findings"] if f["stage"] in compared}
    return {
        "compared": compared,
        "new": [now[k] for k in now.keys() - before.keys()],
        "resolved": [before[k] for k in before.keys() - now.keys()],
        "rerated": [(before[k], now[k]) for k in now.keys() & before.keys()
                    if now[k]["severity"] != before[k]["severity"]],
    }


def grouped(rows, key=group_key):
    """Merge findings with the same key into one row, most severe first."""
    groups = {}
    for f in rows:
        groups.setdefault(key(f), []).append(f)
    order = list(STAGES)
    return sorted(groups.values(), key=lambda g: (
        min(SCALE.index(f["severity"]) for f in g), order.index(g[0]["stage"])))


def finding_table(rows, with_stage=False, with_fixed=False, key=group_key):
    head = "| Severity | " + ("Stage | " if with_stage else "") + "Tool severity | Finding | " \
        "Location | " + ("Fixed in | " if with_fixed else "") + "CWE |"
    lines = [head, "|" + "---|" * (head.count("|") - 1)]
    for g in grouped(rows, key):
        level = min((f["severity"] for f in g), key=SCALE.index)
        locations = unique(f["location"] for f in g)
        first = next(f for f in g if f["location"] == locations[0])
        loc = location_md(first) + (f" (+{len(locations) - 1} more)" if len(locations) > 1 else "")
        cells = [sev(level)]
        if with_stage:
            cells.append(", ".join(unique(STAGES[f["stage"]][0] for f in g)))
        cells += [md(", ".join(unique(tool_severity(f) for f in g))),
                  ", ".join(unique(title_md(f) for f in g)), loc]
        if with_fixed:
            cells.append(md(", ".join(unique(f.get("fixed") for f in g))) or "–")
        cells.append(cwe_md(unique(c for f in g for c in f["cwe"])))
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def details(summary, body):
    return ["", f"<details><summary>{summary}</summary>", "", *body, "", "</details>"]


def fix_count(fs):
    """Unique advisories (as combine() counts them), and how many have a fixed version."""
    fixed = {}
    for f in fs:
        k = dedup_key(f)
        fixed[k] = fixed.get(k, False) or bool(f.get("fixed"))
    return sum(fixed.values()), len(fixed)


def provenance(results_dir, not_run):
    """Tool versions and Trivy DB dates of the stages that ran."""
    run = [s for s in STAGES if s not in not_run]
    tools = {s: tool_version(results_dir, s) for s in run}
    dbs = {s: trivy_db_date(results_dir, STAGES[s][2].split("/")[0])
           for s in DEPENDENCY_STAGES if s in run}
    return tools, {s: d for s, d in dbs.items() if d}


def run_line(tools, dbs):
    parts = []
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        url = f"{repo_url()}/commit/{sha}" if repo_url() else None
        parts.append(f"Commit {link(sha[:7], url)} (NodeGoat vendored in `app/`)")
    names = {}
    for s, v in tools.items():
        names.setdefault(STAGES[s][1].split()[0], v)
    for name, v in names.items():
        entry = f"{name} {v}" if v else f"{name} (version not recorded)"
        if name == "Trivy" and dbs:
            dates = unique(utc_minute(d) for d in dbs.values())
            entry += ", DB " + (dates[0] if len(dates) == 1 else ", ".join(
                f"{STAGES[s][0]} {utc_minute(d)}" for s, d in dbs.items()))
        parts.append(entry)
    return " · ".join(parts)


def report(results_dir, findings, not_run, passed, previous=None, evidence=None):
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
    tools, dbs = provenance(results_dir, not_run)
    lines += ["", run_line(tools, dbs)]

    lines += ["", "## Findings by stage", "",
              "| Stage | Tool | Gate | " + " | ".join(sev(s) for s in SCALE) + " | Total | Notes |",
              "|---|---|---|" + "--:|" * (len(SCALE) + 1) + "---|"]
    for stage, (label, tool, _) in STAGES.items():
        if stage in not_run:
            lines.append(f"| {label} | {tool} | ⏭️ not run |" + " – |" * (len(SCALE) + 1) + " |")
            continue
        fs = by_stage[stage]
        note = ""
        if stage in SAST_STAGES:
            note = f"{len({f['location'] for f in fs})} locations"
        if stage == "sast":
            rs = Counter(f["ruleset"] for f in fs)
            note += f"; standard {rs['standard']}, nodejsscan {rs['nodejsscan']}"
        elif stage == "sca":
            note = f"{len({f['package'] for f in fs})} package versions"
        elif stage == "image":
            comp = Counter(f["component"] for f in fs)
            note = f"app {comp['app']}, base-image npm {comp['base']}, OS {comp['os']}"
        elif stage == "dast":
            note = f"alert types; {sum(int(f['location'].split()[0]) for f in fs)} instances"
        if stage in DEPENDENCY_STAGES and fs:
            note += f"; fix available for {sum(1 for f in fs if f.get('fixed'))}"
        counts = Counter(f["severity"] for f in fs)
        gate = f"❌ {blocking[stage]}" if blocking[stage] else "✅"
        lines.append(f"| {label} | {tool} | {gate} | "
                     + " | ".join(str(counts[s]) for s in SCALE)
                     + f" | {len(fs)} | {note} |")
    combined = combine(findings)
    lines.append("| **Combined** | de-duplicated | | "
                 + " | ".join(str(combined[s]) for s in SCALE)
                 + f" | **{sum(combined.values())}** | package advisories counted once "
                 "per package version; SAST per tool |")

    if not passed:
        # Every blocking finding except High dependency advisories, which are
        # many and fixed the same way (upgrade); those are counted instead.
        groups = grouped(f for f in findings if f["severity"] in GATE_FAIL_ON)
        listed = [g for g in groups if any(
            f["stage"] not in DEPENDENCY_STAGES or f["severity"] == SCALE[0] for f in g)]
        shown = [f for g in listed for f in g]
        dep_high = [f for g in groups if g not in listed for f in g]
        lines += ["", "## What fails the gate", ""]
        lines += [f"{SCALE[0]} findings from any stage, and {' or '.join(GATE_FAIL_ON[1:])} "
                  "findings outside the dependency scans. Package advisories reported by both "
                  "SCA and the image are one row."] if len(GATE_FAIL_ON) > 1 else []
        if shown:
            lines += [""] + finding_table(shown, with_stage=True, with_fixed=True)
        if dep_high:
            n_fixed, n = fix_count(dep_high)
            lines += ["", f"Plus {n} {' or '.join(GATE_FAIL_ON[1:])} dependency advisories "
                      f"(de-duplicated; a fixed version exists for {n_fixed}), listed under "
                      "Details."]

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
                lines += details(f"🆕 New: {len(c['new'])}",
                                 finding_table(c["new"], True, key=identity))
            if c["resolved"]:
                lines += details(f"✔️ Resolved: {len(c['resolved'])}",
                                 finding_table(c["resolved"], True, key=identity))
            if c["rerated"]:
                rows = ["| Stage | Finding | Before | Now |", "|---|---|---|---|"]
                rows += [f"| {STAGES[f['stage']][0]} | {title_md(f)} | "
                         f"{sev(b['severity'])} | {sev(f['severity'])} |"
                         for b, f in c["rerated"]]
                lines += details(f"↕️ Re-rated: {len(c['rerated'])}", rows)
        if any(f["stage"] == "dast" for f in c["new"] + c["resolved"]):
            lines += ["", "> [!NOTE]", "> DAST changes can come from the spider reaching "
                      "different pages, not only from changes to the application."]

    if not set(DEPENDENCY_STAGES) & set(not_run):
        o = dependency_overlap(findings)
        n_fixed, n = fix_count(f for f in findings if f["stage"] in DEPENDENCY_STAGES)
        lines += ["", "## Dependencies", "",
                  "Unique advisory per package version: "
                  f"{o['both']} in both SCA and the image's app packages, "
                  f"{o['sca_only']} only in the lockfile (not installed in the image), "
                  f"{o['image_only']} only in the image's app packages. The image adds "
                  f"{o['image_base']} in the base image's bundled npm and {o['image_os']} "
                  "OS package findings, which the lockfile can't see.",
                  "", f"A fixed version exists for {n_fixed} of these {n} advisories."]

    if not set(SAST_STAGES) & set(not_run):
        at = sast_overlap(findings)
        semgrep, codeql = (set(at[s]) for s in SAST_STAGES)
        lines += ["", "## SAST tools compared", "",
                  f"Locations (file:line): {len(semgrep & codeql)} reported by both Semgrep "
                  f"and CodeQL, {len(semgrep - codeql)} by Semgrep only, "
                  f"{len(codeql - semgrep)} by CodeQL only. Matched on the exact line, "
                  "because the tools name the same flaw with different rules and CWEs."]

        def cell(fs):
            if not fs:
                return "–"
            level = min((f["severity"] for f in fs), key=SCALE.index)
            return f"{ICON[level]} " + ", ".join(unique(title_md(f) for f in fs))

        def by_line(loc):
            path, _, line = loc.rpartition(":")
            return path, int(line)

        rows = ["| Location | Semgrep | CodeQL |", "|---|---|---|"]
        for loc in sorted(semgrep | codeql, key=by_line):
            fs = at["sast"].get(loc) or at["codeql"][loc]
            rows.append(f"| {location_md(fs[0])} | {cell(at['sast'].get(loc))} | "
                        f"{cell(at['codeql'].get(loc))} |")
        lines += details(f"All {len(semgrep | codeql)} locations", rows)

    sboms = {s: sbom_summary(results_dir, s) for s in DEPENDENCY_STAGES if s not in not_run}
    if sboms:
        lines += ["", "## SBOM", "",
                  "Software bill of materials for each dependency stage, kept with the "
                  "results as evidence. Not a gate input.", "",
                  "| Stage | File | Format | Components | By package type |",
                  "|---|---|---|--:|---|"]
        for s, b in sboms.items():
            if b is None:
                lines.append(f"| {STAGES[s][0]} | {SBOM_FILES[s]} | – | – | not recorded |")
            else:
                lines.append(f"| {STAGES[s][0]} | `{b['file']}` | {b['format']} | "
                             f"{b['components']} | "
                             + ", ".join(f"{t} {n}" for t, n in b["types"].items()) + " |")

    lines += ["", "## Details"]
    for stage, (label, tool, _) in STAGES.items():
        fs = by_stage[stage]
        if not fs:
            continue
        # One row per finding, except SAST: one row per location.
        sast = stage in SAST_STAGES
        key = group_key if sast else id
        count = f"{len(fs)}" + (f" at {len(grouped(fs))} locations" if sast else "")
        name = label if tool in label else f"{label} ({tool})"
        lines += details(f"{name}: {count}",
                         finding_table(fs, with_fixed=stage in DEPENDENCY_STAGES, key=key))

    if evidence:
        entries, digest = evidence
        run = os.environ.get("GITHUB_RUN_ID")
        lines += ["", "## Evidence record", "",
                  (f"Run {link(run, run_url())} · " if run else "") + run_line(tools, dbs), "",
                  f"Manifest `{MANIFEST_JSON}`: SHA-256 `{digest}`. It lists the size and "
                  f"SHA-256 of all {len(entries)} files below; `{MANIFEST_SUMS}` holds the same "
                  "in `sha256sum -c` format. Both are in the `aggregate-results` artifact; "
                  "paths are relative to the downloaded results folder."]
        rows = ["| File | Size (bytes) | SHA-256 |", "|---|--:|---|"]
        rows += [f"| `{e['path']}` | {e['size']} | `{e['sha256']}` |" for e in entries]
        lines += details(f"{len(entries)} files", rows)
    return "\n".join(lines) + "\n"


def run_url():
    if "GITHUB_RUN_ID" not in os.environ or not repo_url():
        return None
    return f"{repo_url()}/actions/runs/{os.environ['GITHUB_RUN_ID']}"


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

    try:
        files = evidence_files(args.results_dir, args.not_run)
    except InputError as e:
        print(f"::error::aggregate: {e}", file=sys.stderr)
        return 2

    blocking = Counter(f["stage"] for f in findings if f["severity"] in GATE_FAIL_ON)
    passed = not blocking
    tools, dbs = provenance(args.results_dir, args.not_run)
    (args.results_dir / "aggregated.json").write_text(json.dumps({
        # Set in GitHub Actions; identifies this run when a later one compares.
        "run": os.environ.get("GITHUB_RUN_ID"),
        "commit": os.environ.get("GITHUB_SHA"),
        "url": run_url(),
        "gate": "pass" if passed else "fail",
        "fail_on": list(GATE_FAIL_ON),
        "not_run": args.not_run,
        "stages": [s for s in STAGES if s not in args.not_run],
        "tools": {STAGES[s][1]: v for s, v in tools.items()},
        "trivy_db": {STAGES[s][0]: d for s, d in dbs.items()},
        "sbom": {STAGES[s][0]: sbom_summary(args.results_dir, s)
                 for s in DEPENDENCY_STAGES if s not in args.not_run},
        "blocking": {STAGES[s][0]: n for s, n in blocking.items()},
        "findings": findings,
    }, indent=2) + "\n")
    # The evidence record covers the inputs and aggregated.json, so it comes last.
    evidence = write_manifest(args.results_dir, files + ["aggregated.json"], {
        "run": os.environ.get("GITHUB_RUN_ID"),
        "commit": os.environ.get("GITHUB_SHA"),
        "url": run_url(),
        "tools": {STAGES[s][1]: v for s, v in tools.items()},
        "trivy_db": {STAGES[s][0]: d for s, d in dbs.items()},
    })
    (args.results_dir / "aggregated-report.md").write_text(
        report(args.results_dir, findings, args.not_run, passed, previous, evidence))

    if passed:
        print("Gate PASSED: no " + "/".join(GATE_FAIL_ON) + " findings")
        return 0
    print("Gate FAILED: " + ", ".join(
        f"{STAGES[s][0]} {n}" for s, n in blocking.items()) + " Critical/High findings")
    return 0 if args.report_only else 1


if __name__ == "__main__":
    sys.exit(main())
