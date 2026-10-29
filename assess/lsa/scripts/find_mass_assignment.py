#!/usr/bin/env python3
"""Find mass assignment candidates (OWASP API3:2023, CWE-915) in a legacy repository (heuristic).

Usage: find_mass_assignment.py TARGET [--config audit-config.json] [--out mass-assignment.candidates.json]

Two subtypes:
  whole_object_binding       the request body (or every form field) is bound to a model,
                             entity or object without an allow-list
  privileged_field_writable  a privileged field (role, owner, tenant, price, status, ...)
                             is written from request input, or sits in a model's allow-list

Model facts come from the whole tree: Laravel $fillable / $guarded, JPA @Entity
classes and Entity Framework DbSet<T>. Explicit fields ($request->only, permit(...),
[Bind(Include=...)], DTOs, req.body.name) are not reported. The auditor agent
decides whether the bound object really holds fields the caller must not set.

Standard-library-only (Python 3.8+).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import KIT_VERSION, iter_source_files, load_config, read_text, redact, snippet, write_json  # noqa: E402

LANG_BY_EXT = {
    ".js": "js", ".mjs": "js", ".ts": "js",
    ".php": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".phtml": "php", ".inc": "php",
    ".py": "python", ".rb": "ruby",
    ".java": "java", ".kt": "java", ".groovy": "java",
    ".cs": "cs", ".asp": "asp", ".cfm": "cfml", ".cfc": "cfml", ".cfml": "cfml",
}

SENSITIVE = {
    "role", "roles", "isadmin", "admin", "isstaff", "issuperuser", "superuser", "ownerid", "userid", "tenantid",
    "accountid", "price", "amount", "balance", "credit", "credits", "status", "verified", "isverified",
    "approved", "isapproved", "permission", "permissions", "level", "usertype", "plan",
}

COMMENT_RE = re.compile(r"^\s*(?://|/\*|\*(?=\s|$)|#|'|<!---|--)")

REQ_INPUT = {
    "js": r"\breq\.(?:body|query|params|cookies|headers)\b",
    "php": r"\$_(?:GET|POST|REQUEST|COOKIE)\b|\$request->(?:input|get|post|all)\s*\(|\$this->input->(?:post|get)\s*\(|Input::get",
    "python": r"\brequest\.(?:json|form|args|values|data|POST|GET|get_json)\b",
    "ruby": r"\bparams\s*\[",
    "java": r"\brequest\.getParameter\s*\(",
    "cs": r"\bRequest(?:\.Form|\.QueryString)?\s*[\[(]",
    "asp": r"\bRequest(?:\.Form|\.QueryString)?\s*\(",
    "cfml": r"\b(?:form|url)\.\w+",
}
ASSIGN_RE = re.compile(r"(?:->|\.|\[\s*['\"])([A-Za-z_]\w*)['\"]?\s*\]?\s*=(?![=>])")

# (rule, regex, priority, target group or None)
WHOLE_RULES: Dict[str, List[Tuple[str, re.Pattern, str]]] = {
    "js": [
        ("js-model-call", re.compile(
            r"(?:\b([A-Z]\w*)\.(?:create|update\w*|find\w*AndUpdate|upsert|insert\w*|build|bulkCreate)\s*\("
            r"|\.(?:update\w*|set|merge|assign|extend|save)\s*\(|\bnew\s+([A-Z]\w*)\s*\(|Object\.assign\s*\(|_\.(?:extend|merge|assign)\s*\()"
            r"[^;]*?\breq\.body\b(?![\w.\[])"), "medium"),
        ("js-spread-body", re.compile(r"\.\.\.\s*req\.body\b(?![\w.\[])"), "medium"),
    ],
    "php": [
        ("php-extract", re.compile(r"\bextract\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)\s*\)"), "high"),
        ("php-foreach-input", re.compile(
            r"\bforeach\s*\(\s*(?:\$_(?:POST|GET|REQUEST)|\$request->all\(\s*\)|\$this->input->post\(\s*\))\s+as\s+\$\w+\s*=>"), "high"),
        ("php-ci-input-post", re.compile(r"->(?:insert|update|replace|set)\s*\([^;]*\$this->input->(?:post|get)\s*\(\s*(?:NULL|null|TRUE|true|,\s*)*\)"), "high"),
        ("php-eloquent-static", re.compile(
            r"\b([A-Z]\w*)::(?:create|forceCreate|firstOrCreate|updateOrCreate|insert)\s*\([^;]*?"
            r"(?:\$request->all\(\s*\)|\$request->input\(\s*\)|\$_(?:POST|REQUEST)\b(?!\s*\[)|Input::all\(\s*\))"), "medium"),
        ("php-eloquent-fill", re.compile(
            r"->(?:fill|forceFill|update)\s*\(\s*(?:\$request->all\(\s*\)|\$request->input\(\s*\)|\$_(?:POST|REQUEST)\b(?!\s*\[)|Input::all\(\s*\))"), "medium"),
    ],
    "python": [
        ("py-kwargs-request", re.compile(r"\*\*\s*request\.(?:json|form|args|values|data|POST|GET|get_json\s*\(\s*\))"), "medium"),
        ("py-dict-update", re.compile(r"\.__dict__\.update\s*\(\s*request\."), "high"),
        ("py-items-loop", re.compile(r"\bfor\s+\w+\s*,\s*\w+\s+in\s+request\.\w+(?:\(\s*\))?\.items\s*\(\s*\)"), "high"),
        ("py-modelform-all", re.compile(r"^\s*fields\s*=\s*['\"]__all__['\"]"), "medium"),
    ],
    "ruby": [
        ("rb-permit-all", re.compile(r"\.permit!"), "high"),
        ("rb-raw-params", re.compile(
            r"\.(?:new|create!?|update!?|update_attributes!?|assign_attributes)\s*\(?\s*params\[:\w+\]\s*\)?(?!\s*\.permit)"), "medium"),
    ],
    "java": [
        ("java-beanutils-populate", re.compile(r"\bBeanUtils\.populate\s*\([^;]*getParameterMap\s*\(\s*\)"), "high"),
        ("java-copy-properties", re.compile(r"\bBeanUtils\.copyProperties\s*\("), "medium"),
    ],
    "cs": [
        ("cs-update-model", re.compile(r"\b(?:Try)?UpdateModel(?:Async)?\s*\(\s*\w+\s*\)"), "high"),
    ],
    "asp": [
        ("asp-form-loop", re.compile(r"(?i)\bFor\s+Each\s+\w+\s+In\s+Request(?:\.Form|\.QueryString)?\s*$"), "high"),
    ],
    "cfml": [
        ("cf-struct-append", re.compile(r"(?i)\bStructAppend\s*\(\s*\w+\s*,\s*(?:form|url)\s*[,)]"), "high"),
        ("cf-loop-form", re.compile(r"(?i)<cfloop\b[^>]*collection\s*=\s*\"#(?:form|url)#\""), "high"),
    ],
}

ENTITY_RE = re.compile(r"@Entity\b[\s\S]{0,400}?\bclass\s+(\w+)")
DBSET_RE = re.compile(r"\bDbSet<\s*(\w+)\s*>")
LARAVEL_MODEL_RE = re.compile(r"\bclass\s+(\w+)\s+extends\s+\w*Model\b")
LARAVEL_PROP_RE = re.compile(r"\$(fillable|guarded)\s*=\s*\[([^\]]*)\]")
JAVA_PARAM_RE = re.compile(r"@(?:ModelAttribute|RequestBody)\b(?:\s*\([^)]*\))?\s+(?:@\w+(?:\([^)]*\))?\s+)*(?:final\s+)?(\w+)\s+\w+")
CS_ACTION_RE = re.compile(r"\bpublic\s+(?:async\s+)?(?:virtual\s+)?[\w<>]*Result>?\s+\w+\s*\(([^)]*)\)")


def _norm(name: str) -> str:
    return name.replace("_", "").lower()


def _quoted(items: str) -> List[str]:
    return re.findall(r"['\"]([^'\"]+)['\"]", items)


class Scanner:
    def __init__(self) -> None:
        self.items: List[Dict] = []
        self.meta: Dict[str, Any] = {"entities": [], "dbsets": [], "laravel": {}}

    def add(self, lang: str, rel: str, no: int, lines: List[str], rule: str, subtype: str, priority: str,
            target: Optional[str] = None, needs: Optional[Dict] = None, sensitive: Optional[List[str]] = None) -> None:
        self.items.append({
            "file": rel, "line": no, "language": lang, "rule": rule, "subtype": subtype,
            "target": target, "allowlist": "unknown", "priority": priority,
            "sensitive_fields": sensitive or [], "code": redact(snippet(lines, no)),
            **({"_needs": needs} if needs else {}),
        })

    def collect_meta(self, lang: str, text: str) -> None:
        if lang == "java":
            self.meta["entities"] += ENTITY_RE.findall(text)
        elif lang == "cs":
            self.meta["dbsets"] += DBSET_RE.findall(text)
        elif lang == "php":
            model = LARAVEL_MODEL_RE.search(text)
            if model:
                props = {k: _quoted(v) for k, v in LARAVEL_PROP_RE.findall(text)}
                self.meta["laravel"][model.group(1)] = props

    def scan(self, lang: str, rel: str, text: str) -> None:
        self.collect_meta(lang, text)
        lines = text.splitlines()
        req = re.compile(REQ_INPUT[lang], re.I if lang in ("cs", "asp", "cfml") else 0)
        for no, line in enumerate(lines, 1):
            if COMMENT_RE.match(line):
                continue
            if self._whole(lang, rel, no, lines, line):
                continue
            self._params(lang, rel, no, lines, line)
            assign = ASSIGN_RE.search(line)
            if assign and _norm(assign.group(1)) in SENSITIVE and req.search(line[assign.end():]):
                self.add(lang, rel, no, lines, f"{lang}-privileged-field", "privileged_field_writable", "high",
                         sensitive=[assign.group(1)])

    def _whole(self, lang: str, rel: str, no: int, lines: List[str], line: str) -> bool:
        for rule, rx, priority in WHOLE_RULES.get(lang, []):
            m = rx.search(line)
            if not m:
                continue
            target = next((g for g in m.groups() if g), None) if m.groups() else None
            needs = {"kind": "laravel", "model": target} if rule == "php-eloquent-static" else None
            self.add(lang, rel, no, lines, rule, "whole_object_binding", priority, target, needs)
            return True
        return False

    def _params(self, lang: str, rel: str, no: int, lines: List[str], line: str) -> None:
        if lang == "java":
            for m in JAVA_PARAM_RE.finditer(line):
                self.add(lang, rel, no, lines, "java-entity-binding", "whole_object_binding", "high",
                         m.group(1), {"kind": "entity", "type": m.group(1)})
        elif lang == "cs":
            action = CS_ACTION_RE.search(line)
            if not action:
                return
            for param in action.group(1).split(","):
                if re.search(r"\[\s*Bind\s*\(", param):
                    continue
                pm = re.match(r"\s*(?:\[[^\]]*\]\s*)*(\w+)\s+\w+\s*$", param)
                if pm:
                    self.add(lang, rel, no, lines, "cs-entity-binding", "whole_object_binding", "high",
                             pm.group(1), {"kind": "dbset", "type": pm.group(1)})


def _resolve(items: List[Dict], meta: Dict[str, Any]) -> List[Dict]:
    """Apply cross-file model facts: drop allow-listed or non-entity bindings, raise known-open ones."""
    out = []
    for it in items:
        needs = it.get("_needs")
        it = {k: v for k, v in it.items() if k != "_needs"}
        if needs and needs["kind"] == "entity":
            if needs["type"] not in meta["entities"]:
                continue
            it["allowlist"] = "none"
        elif needs and needs["kind"] == "dbset":
            if needs["type"] not in meta["dbsets"]:
                continue
            it["allowlist"] = "none"
        elif needs and needs["kind"] == "laravel":
            props = meta["laravel"].get(needs["model"])
            if props is not None:
                fillable, guarded = props.get("fillable"), props.get("guarded")
                if fillable:
                    risky = [f for f in fillable if _norm(f) in SENSITIVE]
                    if not risky:
                        continue
                    it.update(subtype="privileged_field_writable", priority="high", allowlist="seen", sensitive_fields=risky)
                elif guarded == [] or (guarded is None and fillable == []):
                    it.update(allowlist="none", priority="high")
                elif guarded:
                    continue
        out.append(it)
    return out


def _scan_files(files: List[Tuple[str, str]], config: Dict) -> Tuple[Dict[str, List[Dict]], Dict[str, Dict]]:
    enc = config["hints"]["file_encodings"]
    items: Dict[str, List[Dict]] = {}
    metas: Dict[str, Dict] = {}
    for p_str, rel in files:
        lang = LANG_BY_EXT.get(Path(p_str).suffix.lower())
        if not lang:
            continue
        s = Scanner()
        s.scan(lang, rel, read_text(Path(p_str), enc))
        items[rel], metas[rel] = s.items, s.meta
    return items, metas


def find_mass_assignment(target: Path, config: Dict, cache: Optional[Any] = None) -> Dict:
    """Scan in-scope files; model facts come from every in-scope file, even in diff mode."""
    scope = {k: v for k, v in config["scope"].items() if k != "only_files"}
    all_files = [(str(p), rel) for p, rel in iter_source_files(target, {**config, "scope": scope})
                 if p.suffix.lower() in LANG_BY_EXT]
    only = config["scope"].get("only_files")
    wanted = {rel for _, rel in all_files} if only is None else set(only)

    file_items: Dict[str, List[Dict]] = {}
    file_meta: Dict[str, Dict] = {}
    to_scan: List[Tuple[str, str]] = []
    use_cache = bool(cache and getattr(cache, "enabled", False))
    for p_str, rel in all_files:
        hit = cache.get_mass(rel, Path(p_str)) if use_cache else None
        if hit is not None:
            file_items[rel], file_meta[rel] = hit
        else:
            to_scan.append((p_str, rel))
    scanned_items, scanned_meta = _scan_files(to_scan, config)
    file_items.update(scanned_items)
    file_meta.update(scanned_meta)
    if use_cache:
        for p_str, rel in to_scan:
            cache.put_mass(rel, Path(p_str), file_items.get(rel, []), file_meta.get(rel, {}))

    meta: Dict[str, Any] = {"entities": set(), "dbsets": set(), "laravel": {}}
    for m in file_meta.values():
        meta["entities"].update(m.get("entities", []))
        meta["dbsets"].update(m.get("dbsets", []))
        meta["laravel"].update(m.get("laravel", {}))

    raw = [it for _, rel in all_files if rel in wanted for it in file_items.get(rel, [])]
    items = _resolve([dict(it) for it in raw], meta)
    for n, it in enumerate(items, 1):
        it["candidate_id"] = f"M-{n:04d}"

    by_rule: Dict[str, int] = {}
    by_subtype: Dict[str, int] = {}
    for it in items:
        by_rule[it["rule"]] = by_rule.get(it["rule"], 0) + 1
        by_subtype[it["subtype"]] = by_subtype.get(it["subtype"], 0) + 1
    return {
        "generated_by": f"lsa find_mass_assignment.py {KIT_VERSION}",
        "target": target.resolve().name,
        "summary": {
            "total": len(items),
            "high_priority": sum(1 for i in items if i["priority"] == "high"),
            "by_rule": by_rule,
            "by_subtype": by_subtype,
            "models": {"jpa_entities": len(meta["entities"]), "ef_dbsets": len(meta["dbsets"]),
                       "laravel_models": len(meta["laravel"])},
        },
        "candidates": items,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--config")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = find_mass_assignment(Path(a.target), load_config(a.config))
    if a.out:
        write_json(Path(a.out), res)
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
