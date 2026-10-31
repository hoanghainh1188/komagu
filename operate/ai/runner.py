"""Headless Cognitive Multi-Agent Runner (Tier 2 BYO-LLM Execution).

Drives the LSA Cognitive Multi-Agent Audit autonomously against an OpenAI-compatible
LLM endpoint (Ollama, vLLM, private OpenAI server):
1. Infers the application Auth Model (Stack & Auth Detector).
2. Maps routes and endpoint inventories (Route Mapper).
3. Audits candidate routes for BOLA / IDOR (BOLA Auditor).
4. Audits candidate queries for SQL/NoSQL Injection (Injection Auditor).
5. Adversarial Skeptic Verification (Finding Verifier Council).
6. Merges and schema-validates all findings; writes OUT/ai-run-stats.json.

Standard-library only (Python 3.8+ compatible).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from operate.ai.client import LLMClient

REPO_ROOT = Path(__file__).resolve().parents[2]
LSA_PROMPTS = REPO_ROOT / "assess" / "lsa" / "prompts"
DEFAULT_CWE = {"bola": ["CWE-284"], "bfla": ["CWE-285"], "mass_assignment": ["CWE-915"],
               "sql_injection": ["CWE-89"], "nosql_injection": ["CWE-943"]}
LSA_SCRIPTS = REPO_ROOT / "assess" / "lsa" / "scripts"
# Valid subtypes per category (finding.schema.json); the first one is used when a model writes an invalid value
CATEGORY_SUBTYPES = {"bfla": ["missing_role_check", "role_from_request", "client_side_role_check"],
                     "mass_assignment": ["whole_object_binding", "privileged_field_writable"]}
FINDING_STATUSES = {"unverified", "confirmed", "likely", "rejected", "needs_review"}


def _read_snippet(target_dir: Path, rel_file: str, line: int, radius: int = 15) -> str:
    """Read a window of code around target line from the audited repository."""
    full_path = target_dir / rel_file
    if not full_path.is_file():
        return f"[File not found: {rel_file}]"
    try:
        lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, line - radius - 1)
        end = min(len(lines), line + radius)
        numbered = [f"{i + 1:4d} | {lines[i]}" for i in range(start, end)]
        return "\n".join(numbered)
    except Exception as e:
        return f"[Error reading {rel_file}: {e}]"


# Server-side includes whose content a verifier must see to judge a control (PHP, Classic ASP, ColdFusion)
_INCLUDE_RE = re.compile(
    r"(?:require|include)(?:_once)?\s*\(?\s*['\"]([^'\"]+)['\"]"
    r"|<!--\s*#include\s+(?:file|virtual)\s*=\s*\"([^\"]+)\""
    r"|<cfinclude\s+template\s*=\s*\"([^\"]+)\"",
    re.IGNORECASE,
)
VERIFY_BATCH_SIZE = 5
AUTH_MODEL_LIMIT = 6000


def _included_files(target_dir: Path, rel_file: str) -> List[str]:
    """Repository-relative paths of files that rel_file includes, if they exist."""
    target_dir = target_dir.resolve()
    path = target_dir / rel_file
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    found: List[str] = []
    for m in _INCLUDE_RE.finditer(text):
        ref = next(g for g in m.groups() if g)
        candidate = (path.parent / ref).resolve()
        try:
            rel = str(candidate.relative_to(target_dir))
        except ValueError:
            continue
        if candidate.is_file() and rel not in found:
            found.append(rel)
    return found


def _verification_context(target_dir: Path, finding: Dict[str, Any]) -> Dict[str, Any]:
    """Code the verifier needs: the finding's site, its file header, evidence lines and included files."""
    loc = finding.get("location") or {}
    rel = str(loc.get("file") or "")
    line = int(loc.get("start_line") or 1)
    ctx: Dict[str, Any] = {"location": _read_snippet(target_dir, rel, line, radius=20)}
    if line > 40:
        ctx["file_header"] = _read_snippet(target_dir, rel, 13, radius=12)
    others = []
    for ev in finding.get("evidence") or []:
        if isinstance(ev, dict) and ev.get("file") and ev.get("file") != rel:
            others.append({"file": ev["file"], "code": _read_snippet(target_dir, str(ev["file"]), int(ev.get("line") or 1), radius=6)})
    if others:
        ctx["evidence"] = others[:3]
    includes = [{"file": inc, "code": _read_snippet(target_dir, inc, 30, radius=30)} for inc in _included_files(target_dir, rel)[:3]]
    if includes:
        ctx["included_files"] = includes
    return ctx


class HeadlessAIRunner:
    """Orchestrates multi-agent cognitive security audits via headless LLM API."""

    def __init__(
        self,
        target_dir: Path,
        out_dir: Path,
        client: LLMClient,
        step_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.target_dir = Path(target_dir).resolve()
        self.out_dir = Path(out_dir).resolve()
        self.client = client
        self.callback = step_callback or (lambda status, msg: None)
        # Per-phase replies that could not be parsed as JSON; written to ai-run-stats.json
        self.parse_failures: Dict[str, List[str]] = {}
        # Per-phase batches whose model call failed (timeout, HTTP error); the run continues without them
        self.call_errors: Dict[str, Dict[str, str]] = {}
        self.phase_stats: Dict[str, Dict[str, Any]] = {}

    def _log(self, status: str, msg: str) -> None:
        self.callback(status, msg)

    def _chat(self, phase: str, batch_id: str, messages: List[Dict[str, str]]) -> Optional[str]:
        """One batch call; a failed call is recorded and returns None instead of aborting the run."""
        try:
            return self.client.chat(messages, temperature=0.1)
        except Exception as e:
            self.call_errors.setdefault(phase, {})[batch_id] = str(e)[:300]
            self._log("warn", f"{phase}: model call failed for {batch_id} ({e}); batch left without verdicts")
            return None

    def _parse_failed(self, phase: str, batch_id: str, reply: Optional[str] = None) -> None:
        if batch_id in self.call_errors.get(phase, {}):
            return
        self.parse_failures.setdefault(phase, []).append(batch_id)
        if reply is not None:
            raw_dir = self.out_dir / "ai-raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            (raw_dir / f"{phase}-{batch_id}.txt").write_text(reply, encoding="utf-8")
        self._log("warn", f"{phase}: could not parse the model reply for {batch_id}; batch left without verdicts")

    def _usage(self) -> Dict[str, Any]:
        return dict(getattr(self.client, "usage", None) or {})

    def _timed(self, phase: str, fn: Callable[[], Any]) -> None:
        before, started = self._usage(), time.monotonic()
        fn()
        after = self._usage()
        self.phase_stats[phase] = {
            "seconds": round(time.monotonic() - started, 3),
            **{k: after.get(k, 0) - before.get(k, 0) for k in ("calls", "prompt_tokens", "completion_tokens")},
        }

    def write_run_stats(self) -> Path:
        """Write model, per-phase durations, token counts and parse failures to OUT/ai-run-stats.json."""
        stats = {
            "model": getattr(self.client, "model", None),
            "endpoint": getattr(self.client, "endpoint", None),
            "phases": self.phase_stats,
            "totals": self._usage(),
            "parse_failures": self.parse_failures,
            "call_errors": self.call_errors,
        }
        path = self.out_dir / "ai-run-stats.json"
        path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
        return path

    def run(self) -> Dict[str, Any]:
        """Execute all cognitive AI phases end-to-end."""
        self._log("step", "Starting Tier 2 Cognitive Multi-Agent Audit (Headless BYO-LLM)")

        # Phase 2: Stack & Auth Model Detector
        self._timed("2-stack-detector", self.infer_auth_model)

        # Phase 3: Route Inventory Mapping
        self._timed("3-route-mapper", self.map_routes_inventory)

        # Phase 4a: BOLA / IDOR Cognitive Audit
        self._timed("4a-bola-auditor", self.audit_bola_routes)

        # Phase 4b: SQL / NoSQL Injection Cognitive Audit
        self._timed("4b-injection-auditor", self.audit_injection_candidates)

        # Phase 4c: Privilege Audit (BFLA, mass assignment)
        self._timed("4c-privilege-auditor", self.audit_privilege)

        # Phase 5: Adversarial Skeptic Verifier
        self._timed("5-finding-verifier", self.verify_findings_skeptic)

        # Phase 6: Merge & Validate Outputs
        self.merge_and_validate()
        self.write_run_stats()

        self._log("ok", "Tier 2 Cognitive Multi-Agent Audit completed successfully")
        return {"status": "success", "out_dir": str(self.out_dir)}

    def infer_auth_model(self) -> Path:
        """Phase 2: Infer authentication and object-ownership model."""
        auth_model_file = self.out_dir / "auth-model.md"
        if auth_model_file.is_file() and auth_model_file.stat().st_size > 50:
            self._log("info", "Existing auth-model.md detected, skipping Phase 2 inference")
            return auth_model_file

        self._log("step", "Phase 2: Inferring application Auth Model with AI Agent")

        stack_file = self.out_dir / "stack-profile.json"
        stack_info = stack_file.read_text(encoding="utf-8") if stack_file.is_file() else "{}"

        # Discover security & controller entry files
        security_files = []
        for pat in ("*auth*", "*session*", "*user*", "*security*", "*filter*", "*middleware*"):
            for p in self.target_dir.rglob(pat):
                if p.is_file() and not any(part.startswith(".") for part in p.parts):
                    security_files.append(str(p.relative_to(self.target_dir)))
                    if len(security_files) >= 10:
                        break
            if len(security_files) >= 10:
                break

        detector_prompt_path = LSA_PROMPTS / "10-stack-detector.md"
        detector_prompt = detector_prompt_path.read_text(encoding="utf-8") if detector_prompt_path.is_file() else ""

        user_prompt = f"""Target Repository: {self.target_dir.name}
Pre-scan Stack Profile:
{stack_info}

Sample Security Entry Files Found in Codebase:
{json.dumps(security_files, indent=2)}

Task: Analyze the stack and identify how authentication, session management, and object-level ownership checks work.
Produce an Markdown document summarizing:
1. Authentication Model (Session, JWT, Cookie, or Anonymous).
2. Identity Helpers (how current user / tenant ID is retrieved on server).
3. Ownership Check Functions (e.g. checkOwner, isMyOrder, or direct SQL scoping).
4. Safe DAO or Query Scoping conventions.
Output MUST be Markdown format adhering to Komagu auth-model.md specification.
"""
        messages = [
            {"role": "system", "content": detector_prompt},
            {"role": "user", "content": user_prompt},
        ]

        auth_model_content = self.client.chat(messages, temperature=0.1)
        if not auth_model_content.strip():
            auth_model_content = "# Application Auth Model\n\n- Authentication: Session-based\n- Ownership checks: Not systematically enforced."

        auth_model_file.write_text(auth_model_content.strip() + "\n", encoding="utf-8")
        self._log("ok", "Generated auth-model.md")
        return auth_model_file

    def map_routes_inventory(self) -> None:
        """Phase 3: Refine route candidates into route inventories."""
        self._log("step", "Phase 3: Mapping route inventory for BOLA auditing")
        routes_dir = self.out_dir / "routes"
        routes_dir.mkdir(parents=True, exist_ok=True)

        batches_dir = self.out_dir / "batches"
        route_batches = sorted(batches_dir.glob("routes-*.json")) if batches_dir.is_dir() else []

        if not route_batches:
            # Create default empty inventory if no route candidates
            default_inv = {"routes": [], "rejected": []}
            (routes_dir / "routes-001.json").write_text(json.dumps(default_inv, indent=2), encoding="utf-8")
            return

        for b_path in route_batches:
            inv_file = routes_dir / b_path.name
            try:
                b_data = json.loads(b_path.read_text(encoding="utf-8"))
            except Exception:
                continue

            candidates = b_data.get("candidates", [])
            mapped_routes = []
            for c in candidates:
                route_id = c.get("route_id") or f"route-{c.get('line', 1)}"
                handler = c.get("handler", {})
                h_file = handler.get("file") or c.get("file", "")
                h_line = handler.get("line") or c.get("line", 1)
                
                # Format id_inputs according to route-inventory.schema.json
                id_inputs = c.get("id_inputs")
                if not id_inputs and "id_params" in c:
                    id_inputs = [
                        {"name": p.get("name", "id"), "source": p.get("source", "path")}
                        for p in c.get("id_params", [])
                    ]
                if not id_inputs:
                    id_inputs = [{"name": "id", "source": "path"}]

                mapped_routes.append({
                    "route_id": route_id,
                    "method": c.get("method") or c.get("methods", ["GET"]),
                    "path": c.get("path", "/"),
                    "path_source": "declared",
                    "handler": {
                        "file": h_file,
                        "line": h_line,
                    },
                    "id_inputs": id_inputs,
                    "guards": [],
                    "data_ops": [{"op": "read"}],
                    "needs_bola_audit": c.get("needs_audit_hint", True) or c.get("needs_bola_audit", True),
                })

            inv_doc = {"routes": mapped_routes, "rejected": []}
            inv_file.write_text(json.dumps(inv_doc, indent=2), encoding="utf-8")

        self._log("ok", f"Mapped {len(route_batches)} route inventories")

    @staticmethod
    def _sanitize_finding(f: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize finding fields to strictly comply with finding.schema.json."""
        if not isinstance(f, dict):
            return f
        # impact must be a string; small models often return a list of consequences
        if isinstance(f.get("impact"), list):
            f["impact"] = "; ".join(str(i) for i in f["impact"])

        # a verdict written into subtype belongs in status; fall back to the category's first subtype
        allowed = CATEGORY_SUBTYPES.get(f.get("category"))
        if allowed and f.get("subtype") not in allowed:
            if f.get("subtype") in FINDING_STATUSES:
                f["status"] = f["subtype"]
            f["subtype"] = allowed[0]

        if f.get("status") not in FINDING_STATUSES:
            f["status"] = "unverified"

        # recommendation must be a string
        rec = f.get("recommendation")
        if isinstance(rec, dict):
            f["recommendation"] = rec.get("summary") or str(rec)
        elif not isinstance(rec, str):
            f["recommendation"] = "Apply input validation and security checks."

        # evidence items require line, file, why
        loc = f.get("location", {})
        default_line = loc.get("start_line", 1)
        default_file = loc.get("file", "unknown")

        evidence = f.get("evidence", [])
        if not isinstance(evidence, list) or len(evidence) == 0:
            f["evidence"] = [{"file": default_file, "line": default_line, "why": "Vulnerability identified"}]
        else:
            for ev in evidence:
                if isinstance(ev, dict):
                    if not isinstance(ev.get("line"), int):
                        ev["line"] = ev.get("start_line") if isinstance(ev.get("start_line"), int) else default_line
                    if "file" not in ev:
                        ev["file"] = default_file
                    if "why" not in ev:
                        ev["why"] = "Vulnerable code path"

        # cwe must be array of strings matching ^CWE-[0-9]+$
        cwe_list = f.get("cwe", [])
        if not isinstance(cwe_list, list) or len(cwe_list) == 0:
            f["cwe"] = DEFAULT_CWE.get(f.get("category"), ["CWE-89"])
        else:
            normalized_cwe = []
            for c in cwe_list:
                c_str = str(c).strip().upper()
                if not c_str.startswith("CWE-"):
                    c_str = f"CWE-{c_str}"
                normalized_cwe.append(c_str)
            f["cwe"] = normalized_cwe

        return f

    def audit_bola_routes(self) -> None:
        """Phase 4a: BOLA / IDOR Auditor agent."""
        self._log("step", "Phase 4a: Executing BOLA/IDOR Cognitive Auditor Agent")
        findings_dir = self.out_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)

        routes_dir = self.out_dir / "routes"
        auth_model = (self.out_dir / "auth-model.md").read_text(encoding="utf-8", errors="replace") if (self.out_dir / "auth-model.md").is_file() else ""
        auditor_prompt = (LSA_PROMPTS / "30-bola-auditor.md").read_text(encoding="utf-8", errors="replace") if (LSA_PROMPTS / "30-bola-auditor.md").is_file() else ""

        for r_file in sorted(routes_dir.glob("*.json")):
            try:
                r_doc = json.loads(r_file.read_text(encoding="utf-8"))
            except Exception:
                continue

            routes_to_audit = [r for r in r_doc.get("routes", []) if r.get("needs_bola_audit", True)]
            if not routes_to_audit:
                continue

            # Assemble route code snippets
            snippets = []
            for r in routes_to_audit:
                handler = r.get("handler", {})
                f_path = handler.get("file", "")
                f_line = handler.get("line", 1)
                snip = _read_snippet(self.target_dir, f_path, f_line)
                snippets.append({
                    "route_id": r.get("route_id"),
                    "path": r.get("path"),
                    "method": r.get("method"),
                    "file": f_path,
                    "line": f_line,
                    "code_context": snip,
                })

            user_prompt = f"""Auth Model:
{auth_model}

Endpoint Routes to Audit for BOLA / IDOR:
{json.dumps(snippets, indent=2)}

Task:
For each route, decide if an authenticated caller can view or modify another tenant/user's resource by manipulating an object identifier (BOLA / IDOR).
Respond STRICTLY with a valid JSON object matching:
{{
  "batch_id": "{r_file.stem}",
  "findings": [
    {{
      "finding_id": "BOLA-<route_id>",
      "category": "bola",
      "subtype": "missing_ownership_check",
      "title": "BOLA in <method> <path>: missing owner verification",
      "route_id": "<route_id>",
      "endpoint": {{"method": "<method>", "path": "<path>"}},
      "location": {{"file": "<file>", "start_line": <line>}},
      "evidence": [{{"file": "<file>", "start_line": <line>, "code": "<vulnerable code>", "why": "<why it allows IDOR>"}}],
      "severity": "high",
      "confidence": "high",
      "cwe": ["CWE-284", "CWE-639"],
      "recommendation": {{"summary": "Bind query to current session user", "code_before": "...", "code_after": "..."}},
      "status": "unverified"
    }}
  ],
  "route_verdicts": [
    {{"route_id": "<route_id>", "verdict": "vulnerable|safe"}}
  ]
}}
"""
            messages = [
                {"role": "system", "content": auditor_prompt},
                {"role": "user", "content": user_prompt},
            ]

            reply = self._chat("4a-bola-auditor", r_file.stem, messages)
            try:
                parsed = self.client.extract_json(reply)
                raw_findings = parsed.get("findings", [])
                findings = [self._sanitize_finding(f) for f in raw_findings]
                route_verdicts = parsed.get("route_verdicts", [])
            except Exception:
                self._parse_failed("4a-bola-auditor", r_file.stem, reply)
                findings = []
                route_verdicts = []

            # Save batch findings
            out_findings_doc = {
                "batch_id": r_file.stem,
                "findings": findings,
                "route_verdicts": route_verdicts,
            }
            (findings_dir / f"bola-{r_file.stem}.json").write_text(json.dumps(out_findings_doc, indent=2), encoding="utf-8")

        self._log("ok", "Completed BOLA/IDOR auditing phase")

    def audit_injection_candidates(self) -> None:
        """Phase 4b: SQL / NoSQL Injection Auditor agent."""
        self._log("step", "Phase 4b: Executing SQL/NoSQL Injection Cognitive Auditor Agent")
        findings_dir = self.out_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)

        batches_dir = self.out_dir / "batches"
        inj_batches = sorted(batches_dir.glob("injection-*.json")) if batches_dir.is_dir() else []
        auditor_prompt = (LSA_PROMPTS / "40-injection-auditor.md").read_text(encoding="utf-8", errors="replace") if (LSA_PROMPTS / "40-injection-auditor.md").is_file() else ""

        for b_file in inj_batches:
            try:
                b_doc = json.loads(b_file.read_text(encoding="utf-8"))
            except Exception:
                continue

            candidates = b_doc.get("candidates", [])
            if not candidates:
                continue

            snippets = []
            for c in candidates:
                f_path = c.get("file") or c.get("location", {}).get("file", "")
                f_line = c.get("line") or c.get("location", {}).get("start_line", 1)
                snip = _read_snippet(self.target_dir, f_path, f_line)
                snippets.append({
                    "candidate_id": c.get("candidate_id"),
                    "file": f_path,
                    "line": f_line,
                    "code_context": snip,
                })

            user_prompt = f"""Candidate Query Sites:
{json.dumps(snippets, indent=2)}

Task:
Audit each candidate location to determine if dynamic query string concatenation or interpolation is vulnerable to SQL or NoSQL Injection.
Respond STRICTLY with a valid JSON object matching:
{{
  "batch_id": "{b_file.stem}",
  "findings": [
    {{
      "finding_id": "INJ-<candidate_id>",
      "category": "sql_injection",
      "subtype": "string_concatenation",
      "title": "SQL Injection in <file>:<line>",
      "candidate_id": "<candidate_id>",
      "location": {{"file": "<file>", "start_line": <line>}},
      "evidence": [{{"file": "<file>", "start_line": <line>, "code": "<code snippet>", "why": "Unsanitized input concatenated into query"}}],
      "severity": "critical",
      "confidence": "high",
      "cwe": ["CWE-89"],
      "recommendation": {{"summary": "Use parameterized queries", "code_before": "...", "code_after": "..."}},
      "status": "unverified"
    }}
  ],
  "candidate_verdicts": [
    {{"candidate_id": "<candidate_id>", "verdict": "vulnerable|safe"}}
  ]
}}
"""
            messages = [
                {"role": "system", "content": auditor_prompt},
                {"role": "user", "content": user_prompt},
            ]

            reply = self._chat("4b-injection-auditor", b_file.stem, messages)
            try:
                parsed = self.client.extract_json(reply)
                raw_findings = parsed.get("findings", [])
                findings = [self._sanitize_finding(f) for f in raw_findings]
                candidate_verdicts = parsed.get("candidate_verdicts", [])
            except Exception:
                self._parse_failed("4b-injection-auditor", b_file.stem, reply)
                findings = []
                candidate_verdicts = []

            out_doc = {
                "batch_id": b_file.stem,
                "findings": findings,
                "candidate_verdicts": candidate_verdicts,
            }
            (findings_dir / f"inj-{b_file.stem}.json").write_text(json.dumps(out_doc, indent=2), encoding="utf-8")

        self._log("ok", "Completed SQL/NoSQL injection auditing phase")

    def audit_privilege(self) -> None:
        """Phase 4c: Privilege auditor for BFLA and mass assignment."""
        self._log("step", "Phase 4c: Executing Privilege Auditor Agent (BFLA, mass assignment)")
        findings_dir = self.out_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        batches_dir = self.out_dir / "batches"
        priv_batches = sorted(batches_dir.glob("privilege-*.json")) if batches_dir.is_dir() else []
        prompt_path = LSA_PROMPTS / "35-privilege-auditor.md"
        auditor_prompt = prompt_path.read_text(encoding="utf-8", errors="replace") if prompt_path.is_file() else ""
        auth_model_file = self.out_dir / "auth-model.md"
        auth_model = auth_model_file.read_text(encoding="utf-8", errors="replace") if auth_model_file.is_file() else ""

        for b_file in priv_batches:
            try:
                b_doc = json.loads(b_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            routes = b_doc.get("routes", [])
            mass = b_doc.get("mass_candidates", [])
            if not routes and not mass:
                continue

            route_ctx = [{
                "route_id": r.get("route_id"),
                "method": r.get("method"),
                "path": r.get("path"),
                "privilege_reasons": r.get("privilege_reasons", []),
                "role_checks": r.get("role_checks", []),
                "bfla_signals": r.get("bfla_signals", []),
                "code_context": _read_snippet(self.target_dir, r["handler"]["file"], r["handler"].get("line") or 1, radius=25),
            } for r in routes]
            mass_ctx = [{
                "candidate_id": c.get("candidate_id"),
                "rule": c.get("rule"),
                "subtype": c.get("subtype"),
                "target": c.get("target"),
                "allowlist": c.get("allowlist"),
                "sensitive_fields": c.get("sensitive_fields", []),
                "code_context": _read_snippet(self.target_dir, c.get("file", ""), c.get("line") or 1),
            } for c in mass]

            user_prompt = f"""Auth Model:
{auth_model}

Privileged Route Candidates:
{json.dumps(route_ctx, indent=2)}

Mass Assignment Candidates:
{json.dumps(mass_ctx, indent=2)}

Task:
Judge every route for BFLA and every candidate for mass assignment as described in your role.
Respond STRICTLY with a valid JSON object matching:
{{
  "batch_id": "{b_file.stem}",
  "privilege_route_verdicts": [
    {{"route_id": "<route_id>", "verdict": "vulnerable|safe|needs_review"}}
  ],
  "candidate_verdicts": [
    {{"candidate_id": "<candidate_id>", "verdict": "vulnerable|safe|needs_review"}}
  ],
  "findings": [
    {{
      "finding_id": "BFLA-<route_id>-1 or MASS-<candidate_id>-1",
      "category": "bfla|mass_assignment",
      "subtype": "missing_role_check|role_from_request|client_side_role_check (bfla) or whole_object_binding|privileged_field_writable (mass_assignment)",
      "title": "<short title>",
      "route_id": "<route_id, bfla only>",
      "candidate_id": "<candidate_id, mass_assignment only>",
      "location": {{"file": "<file>", "start_line": <line>}},
      "evidence": [{{"file": "<file>", "line": <line>, "why": "<privileged action or binding, and the missing control>"}}],
      "impact": "<one string naming the privileged action or fields>",
      "severity": "critical|high|medium|low",
      "confidence": "high|medium|low",
      "cwe": ["CWE-285"],
      "recommendation": "<one string>",
      "status": "unverified|needs_review"
    }}
  ]
}}
Write one finding for every "vulnerable" or "needs_review" verdict. A "needs_review" verdict goes in
"status", never in "subtype".
"""
            messages = [
                {"role": "system", "content": auditor_prompt},
                {"role": "user", "content": user_prompt},
            ]
            reply = self._chat("4c-privilege-auditor", b_file.stem, messages)
            try:
                parsed = self.client.extract_json(reply)
                findings = [self._sanitize_finding(f) for f in parsed.get("findings", [])]
                route_verdicts = parsed.get("privilege_route_verdicts", [])
                candidate_verdicts = parsed.get("candidate_verdicts", [])
            except Exception:
                self._parse_failed("4c-privilege-auditor", b_file.stem, reply)
                findings, route_verdicts, candidate_verdicts = [], [], []

            out_doc = {
                "batch_id": b_file.stem,
                "findings": findings,
                "privilege_route_verdicts": route_verdicts,
                "candidate_verdicts": candidate_verdicts,
            }
            (findings_dir / f"priv-{b_file.stem}.json").write_text(json.dumps(out_doc, indent=2), encoding="utf-8")

        self._log("ok", f"Completed privilege auditing phase ({len(priv_batches)} batches)")

    def verify_findings_skeptic(self) -> None:
        """Phase 5: Finding Verifier (Skeptic) to refute false positives."""
        self._log("step", "Phase 5: Executing Skeptic Verifier (Multi-AI Consensus Council)")
        findings_dir = self.out_dir / "findings"
        if not findings_dir.is_dir():
            return

        all_findings = []
        for f_path in sorted(findings_dir.glob("*.json")):
            if f_path.name.startswith("verified-"):
                continue
            try:
                doc = json.loads(f_path.read_text(encoding="utf-8"))
                all_findings.extend(doc.get("findings", []))
            except Exception:
                pass

        if not all_findings:
            self._log("info", "No findings to verify, skipping Skeptic review")
            return

        verifier_prompt = (LSA_PROMPTS / "50-finding-verifier.md").read_text(encoding="utf-8", errors="replace") if (LSA_PROMPTS / "50-finding-verifier.md").is_file() else ""
        auth_model_path = self.out_dir / "auth-model.md"
        auth_model = auth_model_path.read_text(encoding="utf-8", errors="replace")[:AUTH_MODEL_LIMIT] if auth_model_path.is_file() else ""

        batch_size = VERIFY_BATCH_SIZE
        for idx in range(0, len(all_findings), batch_size):
            chunk = all_findings[idx : idx + batch_size]
            # The headless verifier cannot open files, so it gets the code it must judge (#286)
            to_verify = [{"finding": f, "code_context": _verification_context(self.target_dir, f)} for f in chunk]
            user_prompt = f"""Auth Model:
{auth_model}

Findings to Verify & Challenge (each with the code you may rely on):
{json.dumps(to_verify, indent=2)}

Task:
You are the skeptical security verifier. You cannot open files: judge only from the code_context given
with each finding and the Auth Model above.
For each finding:
1. Look for a compensating control (role or ownership check, global filter, integer cast, allow-list,
   parameter binding) in the code_context.
2. Only use reason_code "control_found" when the control is visible in the code_context; quote its
   file and line in "control_found". Never assume a control in a base class, include, config or
   middleware you were not shown.
3. If the code you would need is not shown, answer verdict "likely" with reason_code
   "code_not_visible" or "config_not_visible".
Verdicts: "confirmed" | "likely" | "rejected".
reason_code is one of: "traced", "code_not_visible", "config_not_visible", "data_ownership_unclear",
"control_found", "evidence_mismatch", "not_executed", "not_reachable", "not_attacker_controlled".
Respond STRICTLY with a valid JSON object matching verification.schema.json:
{{
  "batch_id": "verified-{(idx // batch_size) + 1}",
  "verifications": [
    {{
      "finding_id": "<finding_id>",
      "verdict": "confirmed|likely|rejected",
      "reason_code": "<one of the reason codes above>",
      "confidence": "high|medium|low",
      "checked": ["<what you checked in the code_context>"],
      "control_found": {{"file": "<file>", "line": <line>, "code": "<control>"}} or null,
      "notes": "<rationale for verdict>"
    }}
  ]
}}
"""
            messages = [
                {"role": "system", "content": verifier_prompt},
                {"role": "user", "content": user_prompt},
            ]

            reply = self._chat("5-finding-verifier", f"verified-{(idx // batch_size) + 1}", messages)
            try:
                parsed = self.client.extract_json(reply)
                verifs = parsed.get("verifications", [])
            except Exception:
                # No verdicts: merge_findings.py lists these findings under
                # coverage.findings_without_verification instead of confirming them
                self._parse_failed("5-finding-verifier", f"verified-{(idx // batch_size) + 1}", reply)
                verifs = []

            verif_doc = {
                "batch_id": f"verified-{(idx // batch_size) + 1}",
                "verifications": verifs,
            }
            (findings_dir / f"verified-{(idx // batch_size) + 1}.json").write_text(
                json.dumps(verif_doc, indent=2), encoding="utf-8"
            )

        self._log("ok", f"Skeptic verification completed on {len(all_findings)} findings")

    def merge_and_validate(self) -> None:
        """Phase 6: Merge findings and validate schemas via merge_findings.py."""
        self._log("step", "Phase 6: Merging and validating all cognitive findings")
        merge_script = LSA_SCRIPTS / "merge_findings.py"
        res = subprocess.run([sys.executable, str(merge_script), str(self.out_dir)], capture_output=True, text=True)
        if res.returncode != 0:
            self._log("warn", f"Merge findings validation note: {res.stderr.strip() or res.stdout.strip()}")
        else:
            self._log("ok", "Cognitive findings merged and validated against JSON Schemas")
