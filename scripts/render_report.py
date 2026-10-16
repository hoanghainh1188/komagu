#!/usr/bin/env python3
"""Render OUT/report.md from findings.json, coverage.json and stack-profile.json.

Usage: render_report.py OUT [--project NAME]
Sections marked <!-- LLM: ... --> are filled by the reporter agent afterwards.
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import KIT_VERSION, read_json  # noqa: E402

SEV = ["critical", "high", "medium", "low", "info"]


def md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def render(out: Path, project: str) -> str:
    fj = read_json(out / "findings.json")
    cov = read_json(out / "coverage.json") if (out / "coverage.json").exists() else {}
    prof = read_json(out / "stack-profile.json") if (out / "stack-profile.json").exists() else {"stacks": []}
    s = fj["summary"]
    active = [f for f in fj["findings"] if f["status"] != "rejected"]
    rejected = [f for f in fj["findings"] if f["status"] == "rejected"]
    L = []
    L += [f"# Security Audit Report — {project}", "",
          "> **Classification: CONFIDENTIAL.** AI-assisted static review. All findings require human review "
          "(record decisions in `review-log.md`, created from `templates/review-log.md`) before they are shared outside the team.", "",
          "| Item | Value |", "|---|---|",
          f"| Date | {dt.date.today().isoformat()} |",
          f"| Kit version | {KIT_VERSION} |",
          f"| Scope | BOLA/IDOR; SQL/HQL/NoSQL queries built from input |",
          f"| Stacks | {', '.join(x['id'] for x in prof['stacks']) or '-'} |",
          f"| Endpoints inventoried | {cov.get('inventoried', '-')} (candidates: {cov.get('route_candidates', '-')}) |",
          f"| Endpoints audited for BOLA | {cov.get('bola_routes_to_audit', '-')} |",
          f"| Injection candidates reviewed | {cov.get('injection_candidates', '-')} |", ""]
    L += ["## 1. Executive summary", "", "<!-- LLM: reporter agent writes max 8 bullets here -->", ""]
    L += ["## 2. Findings overview", "",
          "| Severity | " + " | ".join(SEV) + " |", "|---|" + "---|" * len(SEV),
          "| Count | " + " | ".join(str(s["by_severity"].get(x, 0)) for x in SEV) + " |", "",
          "| Category | Count |", "|---|---|"]
    L += [f"| {c} | {n} |" for c, n in s["by_category"].items()]
    L += ["", f"Status: " + ", ".join(f"{k}={v}" for k, v in s["by_status"].items()), ""]
    L += ["## 3. Findings", "",
          "| ID | Sev | Conf | Status | Category | Endpoint | Location | Title |", "|---|---|---|---|---|---|---|---|"]
    for f in active:
        ep = f.get("endpoint") or {}
        L.append(f"| {f['finding_id']} | {f['severity']} | {f['confidence']} | {f['status']} | {f['category']} | "
                 f"{md_escape(ep.get('method', ''))} {md_escape(ep.get('path', ''))} | "
                 f"`{f['location']['file']}:{f['location']['start_line']}` | {md_escape(f['title'])} |")
    L.append("")
    for f in active:
        ep = f.get("endpoint") or {}
        L += [f"### {f['finding_id']} — {f['title']}", "",
              f"- **Severity / confidence:** {f['severity']} / {f['confidence']}  ",
              f"- **Status:** {f['status']}  ",
              f"- **Category:** {f['category']} ({f['subtype']}) — {', '.join(f.get('cwe', []))} {', '.join(f.get('owasp', []))}  ",
              f"- **Endpoint:** {ep.get('method', '-')} {ep.get('path', '-')}  ",
              f"- **Location:** `{f['location']['file']}:{f['location']['start_line']}`", ""]
        if f.get("attack_scenario"):
            L += [f"**Scenario.** {f['attack_scenario']}", ""]
        if f.get("impact"):
            L += [f"**Impact.** {f['impact']}", ""]
        L += ["**Evidence.**", ""]
        for e in f["evidence"]:
            code = (e.get("code") or "").replace("`", "'")
            L.append(f"- `{e['file']}:{e['line']}` — {e['why']}" + (f"  \n  `{code}`" if code else ""))
        L.append("")
        if f.get("data_flow"):
            L += ["**Data flow.** " + " → ".join(f["data_flow"]), ""]
        L += [f"**Recommendation.** {f['recommendation']}", ""]
        if f.get("fix_example"):
            L += ["```", f["fix_example"], "```", ""]
        v = f.get("verification") or {}
        if v:
            L += [f"*Verifier:* {v.get('verdict')} — checked: {', '.join(v.get('checked') or [])}. {v.get('notes') or ''}", ""]
    L += ["## 4. Systemic fixes", "", "<!-- LLM: reporter agent writes max 5 systemic fixes here -->", ""]
    L += ["## 5. Coverage and limitations", ""]
    for k in ("missing_from_inventory", "bola_routes_without_verdict", "injection_candidates_without_verdict", "findings_without_verification"):
        if k in cov:
            L.append(f"- {k.replace('_', ' ')}: {len(cov[k])}" + (f" ({', '.join(cov[k][:10])}{' …' if len(cov[k]) > 10 else ''})" if cov[k] else ""))
    L += ["", "<!-- LLM: reporter agent lists limitations here -->", ""]
    L += ["## Appendix A — Findings rejected by the verifier", ""]
    if rejected:
        L += ["| ID | Location | Reason |", "|---|---|---|"]
        for f in rejected:
            v = f.get("verification") or {}
            L.append(f"| {f['finding_id']} | `{f['location']['file']}:{f['location']['start_line']}` | {md_escape(v.get('notes') or '')} |")
    else:
        L.append("None.")
    L += ["", "## Appendix B — Method", "",
          "1. Deterministic pre-scan (stack detection, endpoint candidates, query-building candidates).",
          "2. AI agents: auth-model extraction, route inventory, BOLA audit, injection audit.",
          "3. Independent AI verifier tries to refute each finding.",
          "4. Human review and sign-off (`review-log.md`).", "",
          "This is not a penetration test. Absence of findings does not prove absence of vulnerabilities.", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out")
    ap.add_argument("--project")
    a = ap.parse_args()
    out = Path(a.out)
    project = a.project or out.resolve().name
    (out / "report.md").write_text(render(out, project), encoding="utf-8")
    print(f"wrote {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
