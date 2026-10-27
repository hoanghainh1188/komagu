#!/usr/bin/env python3
"""Self-test of the deterministic pre-scan against the fixture repositories.

Usage: python3 tests/run_tests.py [-v]

Checks, for every fixture under tests/fixtures/:
  1. every SQLI / NOSQL marker line is flagged by find_injection.py      (recall)
  2. no SAFE-SQL-NOFLAG marker line is flagged                           (precision on parameterized code)
  3. every BOLA / SAFE-BOLA marker line is covered by a route candidate  (endpoint coverage)
  4. the full pipeline (prescan -> merge -> SARIF -> report) runs on a sample agent output
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
sys.path.insert(0, str(KIT / "scripts"))
sys.path.insert(0, str(HERE))

from detect_stack import detect  # noqa: E402
from find_injection import find_injection  # noqa: E402
from lsa_common import load_config  # noqa: E402
from lsa_markers import read_markers  # noqa: E402
from map_routes import map_routes  # noqa: E402

VERBOSE = "-v" in sys.argv


def route_covers(routes, file, line):
    """A route covers a marker if its handler is that file (or the page whose code-behind it is) and starts before it."""
    best = None
    for r in routes:
        hf = r["handler"]["file"]
        if hf == file or file.startswith(hf.rsplit(".", 1)[0]) and file.endswith((".cs", ".vb")) and hf.endswith((".cs", ".vb")):
            if r["handler"]["line"] <= line and (best is None or r["handler"]["line"] > best["handler"]["line"]):
                best = r
    return best


def test_fixture(fx: Path, cfg) -> list:
    fails = []
    marks = read_markers(fx)
    prof = detect(fx, cfg)
    routes = map_routes(fx, cfg, {s["id"] for s in prof["stacks"]})["candidates"]
    inj = find_injection(fx, cfg)["candidates"]
    flagged = {(c["file"], c["line"]) for c in inj}
    n = {"sqli": 0, "sqli_hit": 0, "noflag": 0, "noflag_ok": 0, "bola": 0, "bola_hit": 0}
    for m in marks:
        key = (m["file"], m["line"])
        if m["label"] in ("SQLI", "NOSQL"):
            n["sqli"] += 1
            if key in flagged:
                n["sqli_hit"] += 1
            else:
                fails.append(f"MISSED {m['label']} {m['file']}:{m['line']}")
        elif m["label"] == "SAFE-SQL-NOFLAG":
            n["noflag"] += 1
            if key in flagged:
                fails.append(f"FALSE FLAG (parameterized) {m['file']}:{m['line']}")
            else:
                n["noflag_ok"] += 1
        elif m["label"] in ("BOLA", "SAFE-BOLA"):
            n["bola"] += 1
            r = route_covers(routes, m["file"], m["line"])
            if r:
                n["bola_hit"] += 1
                if VERBOSE:
                    ids = [p["name"] for p in r["id_params"]]
                    print(f"    route {r['route_id']} {r['method']} {r['path']} id_params={ids}")
            else:
                fails.append(f"NO ROUTE for {m['label']} marker {m['file']}:{m['line']}")
    stacks = ",".join(s["id"] for s in prof["stacks"])
    print(f"  {fx.name:<16} stacks=[{stacks}]  inj {n['sqli_hit']}/{n['sqli']}  noflag {n['noflag_ok']}/{n['noflag']}  "
          f"routes-for-bola {n['bola_hit']}/{n['bola']}  (candidates: {len(routes)} routes, {len(inj)} inj)")
    return fails


def test_pipeline(cfg) -> list:
    """Run run_prescan + merge + sarif + report on one fixture with a hand-written agent output."""
    fails = []
    fx = HERE / "fixtures" / "php-plain"
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out"
        r = subprocess.run([sys.executable, str(KIT / "scripts" / "run_prescan.py"), str(fx), str(out)], capture_output=True, text=True)
        if r.returncode != 0:
            return [f"run_prescan failed: {r.stderr}"]
        rc = json.loads((out / "routes.candidates.json").read_text())["candidates"]
        ic = json.loads((out / "injection.candidates.json").read_text())["candidates"]
        od = next(c for c in rc if c["handler"]["file"] == "order_detail.php")
        (out / "routes").mkdir()
        (out / "routes" / "routes-001.json").write_text(json.dumps({
            "batch_id": "routes-001",
            "routes": [{"route_id": od["route_id"], "method": ["GET"], "path": "/order_detail.php", "path_source": "file",
                        "handler": {"file": "order_detail.php", "line": 1, "symbol": None},
                        "id_inputs": [{"name": "id", "source": "query", "file": "order_detail.php", "line": 5}],
                        "guards": [{"type": "authn", "name": "inc/auth.php", "file": "order_detail.php", "line": 2}],
                        "data_ops": [{"op": "read", "target": "orders", "file": "order_detail.php", "line": 6}],
                        "needs_bola_audit": True, "notes": ""}],
            "rejected": [{"route_id": c["route_id"], "reason": "test"} for c in rc if c is not od]}))
        (out / "findings").mkdir()
        finding = {"finding_id": f"BOLA-{od['route_id']}-1", "category": "bola", "subtype": "missing_ownership_check",
                   "title": "Order readable by id", "route_id": od["route_id"],
                   "endpoint": {"method": "GET", "path": "/order_detail.php"},
                   "location": {"file": "order_detail.php", "start_line": 5, "end_line": 6},
                   "evidence": [{"file": "order_detail.php", "line": 6, "code": "SELECT * FROM orders WHERE id = ...", "why": "no owner"}],
                   "severity": "high", "confidence": "high", "cwe": ["CWE-639"], "owasp": ["API1:2023"],
                   "recommendation": "Bind user_id from session.", "status": "unverified"}
        (out / "findings" / "bola-routes-001.json").write_text("Notes...\n```json\n" + json.dumps({
            "batch_id": "routes-001", "route_verdicts": [{"route_id": od["route_id"], "verdict": "vulnerable"}],
            "findings": [finding]}) + "\n```\n")
        (out / "findings" / "inj-001.json").write_text(json.dumps({
            "batch_id": "injection-001", "candidate_verdicts": [{"candidate_id": c["candidate_id"], "verdict": "safe", "reason": "test"} for c in ic],
            "findings": []}))
        (out / "findings" / "verified-1.json").write_text(json.dumps({"verifications": [
            {"finding_id": finding["finding_id"], "verdict": "confirmed", "severity": "high", "confidence": "high",
             "checked": ["inc/auth.php"], "control_found": None, "notes": "ok"}]}))
        for script in ("merge_findings.py", "findings_to_sarif.py", "render_report.py"):
            r = subprocess.run([sys.executable, str(KIT / "scripts" / script), str(out)], capture_output=True, text=True)
            if r.returncode != 0:
                fails.append(f"{script} failed (rc={r.returncode}): {r.stdout[-400:]} {r.stderr[-400:]}")
        if not fails:
            fj = json.loads((out / "findings.json").read_text())
            if fj["summary"]["by_status"]["confirmed"] != 1:
                fails.append("merge: verification not applied")
            sarif = json.loads((out / "findings.sarif").read_text())
            try:
                import jsonschema  # noqa: F401
            except ImportError:
                pass
            if sarif["version"] != "2.1.0" or len(sarif["runs"][0]["results"]) != 1:
                fails.append("sarif: unexpected content")
            if "Order readable by id" not in (out / "report.md").read_text():
                fails.append("report: finding missing")
    print(f"  pipeline         {'OK' if not fails else 'FAIL'}")
    return fails


def main() -> int:
    cfg = load_config(None)
    cfg["scope"]["exclude"] = [e for e in cfg["scope"]["exclude"] if e not in ("test/", "tests/")]
    print("Pre-scan self-test")
    fails = []
    for fx in sorted((HERE / "fixtures").iterdir()):
        if fx.is_dir():
            fails += [f"[{fx.name}] {x}" for x in test_fixture(fx, cfg)]
    fails += test_pipeline(cfg)
    res = subprocess.run([sys.executable, str(HERE / "test_merge_and_security.py")], capture_output=True, text=True)
    if res.returncode != 0:
        fails.append(f"test_merge_and_security.py failed:\n{res.stdout}\n{res.stderr}")
    print(f"  merge & security {'OK' if res.returncode == 0 else 'FAIL'}")
    res_sarif = subprocess.run([sys.executable, str(HERE / "test_sarif_export.py")], capture_output=True, text=True)
    if res_sarif.returncode != 0:
        fails.append(f"test_sarif_export.py failed:\n{res_sarif.stdout}\n{res_sarif.stderr}")
    print(f"  sarif export     {'OK' if res_sarif.returncode == 0 else 'FAIL'}")
    res_mod = subprocess.run([sys.executable, str(HERE / "test_modern_stacks.py")], capture_output=True, text=True)
    if res_mod.returncode != 0:
        fails.append(f"test_modern_stacks.py failed:\n{res_mod.stdout}\n{res_mod.stderr}")
    print(f"  modern stacks    {'OK' if res_mod.returncode == 0 else 'FAIL'}")
    res_perf = subprocess.run([sys.executable, str(HERE / "test_performance.py")], capture_output=True, text=True)
    if res_perf.returncode != 0:
        fails.append(f"test_performance.py failed:\n{res_perf.stdout}\n{res_perf.stderr}")
    print(f"  scale benchmark  {'OK' if res_perf.returncode == 0 else 'FAIL'}")
    print()
    if fails:
        print(f"FAILED ({len(fails)})")
        for f in fails:
            print("  - " + f)
        return 1
    print("ALL PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
