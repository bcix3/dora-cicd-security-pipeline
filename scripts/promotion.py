#!/usr/bin/env python3
"""Decide whether an image may be promoted to prod, and record the decision.

Usage:  promotion.py OUT_DIR

Reads its inputs from the environment (set by deploy-prod.yml's check job):
  IMAGE, DIGEST, COMMIT       the image being promoted (tag, registry digest, commit)
  GATE                        conclusion of the build run's "Security gate" job:
                              success / failure / anything else or empty = no result
  BUILD_RUN, BUILD_RUN_URL    the build run that scanned this exact digest
  AGGREGATED                  that run's aggregated.json (optional; verdict, counts)
  MANIFEST                    that run's evidence-manifest.json (optional)
  RISK_ACCEPTANCE             the operator's reason for promoting a failed image
  APPROVER, RUN_URL           github.actor and this deploy-prod run

Writes OUT_DIR/promotion-record.json and OUT_DIR/promotion-record.md (for the job
summary). Exit status: 0 = promote, 1 = refused.

Criteria (DORA Art. 24(5); RTS 2024/1774 Arts. 15(3)(g), 17): an image whose gate
passed is promoted. One whose gate failed is refused unless a risk acceptance of at
least MIN_REASON characters is given, which is then recorded with the approver. If no
gate result can be found for the image, it is refused (fail closed).
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

MIN_REASON = 20


def decide(gate, verdict, reason):
    """Return (promote, basis)."""
    reason = (reason or "").strip()
    if gate == "success":
        if verdict not in (None, "pass"):
            return False, f"refused: gate job succeeded but the report's verdict is {verdict!r}"
        return True, "gate passed"
    if gate == "failure":
        if verdict not in (None, "fail"):
            return False, f"refused: gate job failed but the report's verdict is {verdict!r}"
        if len(reason) >= MIN_REASON:
            return True, "gate failed; risk accepted"
        if reason:
            return False, (f"refused: gate failed and the risk acceptance is shorter than "
                           f"{MIN_REASON} characters")
        return False, "refused: gate failed and no risk acceptance was given"
    return False, "refused: no gate result found for this image"


def read_json(path):
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def sha256(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest() if path else None
    except OSError:
        return None


def md(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def summary(r):
    icon = "✅" if r["promote"] else "⛔"
    rows = [
        ("Decision", f"{icon} **{'PROMOTE' if r['promote'] else 'REFUSED'}**: {r['basis']}"),
        ("Image", f"`{r['image']}`"),
        ("Digest", f"`{r['digest']}`" if r["digest"] else "–"),
        ("Commit", f"`{r['commit']}`" if r["commit"] else "–"),
        ("Build run", f"[{r['build_run']}]({r['build_run_url']})"
         if r["build_run"] else "not found"),
        ("Security gate", r["gate"] or "no result"),
        ("Blocking findings", ", ".join(f"{k} {v}" for k, v in r["blocking"].items())
         if r["blocking"] else ("none" if r["verdict"] == "pass" else "–")),
        ("Evidence manifest SHA-256", f"`{r['evidence_manifest_sha256']}`"
         if r["evidence_manifest_sha256"] else "not available"),
        ("Risk acceptance", md(r["risk_acceptance"]) if r["risk_acceptance"] else "–"),
        ("Approver", f"`{r['approver']}`"),
        ("Time (UTC)", r["time"]),
    ]
    lines = ["# Promotion to prod", "", "| | |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in rows]
    if r["promote"] and r["gate"] == "failure":
        lines += ["", "> [!WARNING]", "> Promoted with failing security findings on the "
                  "approver's risk acceptance. The approver also built and tested this change, "
                  "so the acceptance is not independent (RTS 2024/1774 Art. 17(1)(b))."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__.split("\n")[2], file=sys.stderr)
        return 2
    out = Path(argv[0])
    out.mkdir(parents=True, exist_ok=True)
    env = os.environ
    aggregated = read_json(env.get("AGGREGATED")) or {}
    gate = env.get("GATE") or None
    reason = (env.get("RISK_ACCEPTANCE") or "").strip()
    promote, basis = decide(gate, aggregated.get("gate"), reason)
    record = {
        "promote": promote,
        "basis": basis,
        "image": env.get("IMAGE", ""),
        "digest": env.get("DIGEST") or None,
        "commit": env.get("COMMIT") or None,
        "build_run": env.get("BUILD_RUN") or None,
        "build_run_url": env.get("BUILD_RUN_URL") or None,
        "gate": gate,
        "verdict": aggregated.get("gate"),
        "blocking": aggregated.get("blocking", {}),
        "evidence_manifest_sha256": sha256(env.get("MANIFEST")),
        "risk_acceptance": reason or None,
        "approver": env.get("APPROVER", ""),
        "deploy_run_url": env.get("RUN_URL") or None,
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (out / "promotion-record.json").write_text(json.dumps(record, indent=2) + "\n")
    (out / "promotion-record.md").write_text(summary(record))
    print(("PROMOTE: " if promote else "REFUSED: ") + basis)
    return 0 if promote else 1


if __name__ == "__main__":
    sys.exit(main())
