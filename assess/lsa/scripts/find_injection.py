#!/usr/bin/env python3
"""Find hand-built SQL / HQL / NoSQL query candidates in a legacy repository (heuristic).

Usage: find_injection.py TARGET [--config audit-config.json] [--out injection.candidates.json]

Each candidate is a line where a query string is built dynamically, or a
NoSQL filter is taken from request data. The injection-auditor agent decides
whether the dynamic part is attacker-controlled and unsanitized.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import KIT_VERSION, iter_source_files, load_config, read_text, redact, snippet, write_json  # noqa: E402

LANG_BY_EXT = {
    ".php": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".phtml": "php", ".inc": "php", ".ctp": "php",
    ".java": "java", ".jsp": "java", ".jspf": "java", ".kt": "java", ".groovy": "java",
    ".cs": "cs", ".cshtml": "cs", ".vb": "vb", ".vbhtml": "vb", ".aspx": "aspx", ".ascx": "aspx", ".ashx": "cs", ".asmx": "cs",
    ".asp": "vb", ".asa": "vb",
    ".pl": "perl", ".pm": "perl", ".cgi": "perl",
    ".cfm": "cfml", ".cfc": "cfml", ".cfml": "cfml",
    ".js": "js", ".mjs": "js", ".ts": "js", ".py": "python", ".rb": "ruby",
    ".rs": "rust", ".go": "go",
    ".xml": "xml", ".sql": "sql",
}

STRONG_SQL = re.compile(
    r"(?i)(\bselect\b[\s\S]*?\bfrom\b|\bselect\s+[\w*]|\binsert\s+into\b|\bupdate\s+[\w\[\].`\"]+\s+set\b|\bupdate\s+[\w\[\].`\"]+\s*$"
    r"|\bdelete\s+from\b|\bwhere\b\s*[\w(`\[]|\border\s+by\b|\bgroup\s+by\b|\bvalues\s*\(|\bexec(ute)?\s+\w|\bunion\s+select\b"
    r"|\bfrom\s+[\w\[\].`\"]+\s+(where|order|group|inner|left|join)\b|\bhaving\b)")
WEAK_SQL = re.compile(r"(?i)\b(and|or|like|in|not|between|set|where|order\s+by|limit|offset|values|join|on)\b|=\s*['\"]?$|[(,=<>]\s*'?$")
SQL_IDENT = re.compile(r"(?i)\b(order\s+by|group\s+by|asc|desc|limit)\b")

REQ_RE = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b|\$HTTP_\w+_VARS|\$this->input->|\$this->request->|\$request->|Input::get"
    r"|getParameter|getQueryString|getHeader|@RequestParam|@PathVariable"
    r"|Request\.(QueryString|Form|Params|Cookies|ServerVariables)|Request\s*[\[(]\s*\"|\.Text\b|\.SelectedValue\b|\.Value\b"
    r"|req\.(query|body|params|cookies|headers)|request\.(GET|POST|args|form|values|json|cookies|data)|params\s*\["
    r"|\b(url|form|cookie|arguments|attributes)\.\w+|\bparam\s*\(|\$in\{|\$ENV\{", re.I)
SANITIZER_RE = re.compile(
    r"\(int\)|\bintval\s*\(|\bfloatval\s*\(|\bis_numeric\s*\(|\bctype_digit\s*\(|\babs\s*\(|Integer\.parseInt|Long\.parseLong|"
    r"Integer\.valueOf|Long\.valueOf|\bint\.Parse|\blong\.Parse|Convert\.ToInt\d+|\bCInt\s*\(|\bCLng\s*\(|\bIsNumeric\s*\(|\bint\s*\("
    r"|\.to_i\b|parseInt\s*\(|Number\s*\(|\bescape\w*\s*\(|real_escape_string|\bquote\s*\(|addslashes|Replace\s*\([^)]*\"'\"|"
    r"str_replace\s*\(\s*['\"]'['\"]|in_array\s*\(|allow|white_?list|preg_match\s*\(", re.I)

COMMENT_LINE = {
    "php": re.compile(r"^\s*(//|#|\*|/\*)"), "java": re.compile(r"^\s*(//|\*|/\*)"), "cs": re.compile(r"^\s*(//|\*|/\*)"),
    "js": re.compile(r"^\s*(//|\*|/\*)"), "vb": re.compile(r"^\s*('|REM\b)", re.I), "perl": re.compile(r"^\s*#"),
    "python": re.compile(r"^\s*#"), "ruby": re.compile(r"^\s*#"), "cfml": re.compile(r"^\s*(<!---|//)"),
    "rust": re.compile(r"^\s*(//|\*|/\*)"), "go": re.compile(r"^\s*(//|\*|/\*)"),
    "xml": re.compile(r"^\s*<!--"), "sql": re.compile(r"^\s*--"),
}
LOG_LINE = re.compile(r"(?i)\b(log(ger)?\.(debug|info|warn|error|trace)|console\.log|System\.out\.print|Debug\.Write|Trace\.Write|error_log|syslog)\s*\(")

LIT = {
    "c": re.compile(r"\"(?:\\.|[^\"\\])*\""),
    "cs": re.compile(r"@\"(?:\"\"|[^\"])*\"|\$@?\"(?:\{[^}]*\}|\\.|[^\"\\{])*\"|\"(?:\\.|[^\"\\])*\""),
    "both": re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'"),
    "js": re.compile(r"`(?:\\.|[^`\\])*`|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'"),
    "vb": re.compile(r"\"(?:\"\"|[^\"])*\""),
    "python": re.compile(r"[fFrRbBuU]{0,2}\"(?:\\.|[^\"\\])*\"|[fFrRbBuU]{0,2}'(?:\\.|[^'\\])*'"),
}
LIT_FOR = {"php": "both", "java": "c", "cs": "cs", "js": "js", "vb": "vb", "perl": "both", "python": "python",
           "ruby": "both", "cfml": "both", "aspx": "cs", "sql": "both", "xml": "both", "rust": "c", "go": "js"}
CONCAT_OP = {"php": r"\.", "perl": r"\.", "java": r"\+", "cs": r"\+", "js": r"\+", "python": r"\+", "ruby": r"\+",
             "vb": r"&|\+", "cfml": r"&", "sql": r"\+|\|\|", "rust": r"\+", "go": r"\+"}
INTERP = {
    "php": re.compile(r"\$[A-Za-z_]|\{\$"), "perl": re.compile(r"[$@][A-Za-z_{]"), "ruby": re.compile(r"#\{"),
    "js": re.compile(r"\$\{"), "cs": re.compile(r"\{[^}\d][^}]*\}"), "python": re.compile(r"\{[^}]*\}"),
    "java": re.compile(r"\$[A-Za-z_]|\$\{"), "rust": re.compile(r"\{[^}]*\}"),
}
FORMAT_CALL = re.compile(r"(?i)\b(String\.format|string\.Format|String\.Format|sprintf|MessageFormat\.format|AppendFormat|format!|fmt\.Sprintf)\s*\(")
PY_PERCENT = re.compile(r"[\"']\s*%\s*[\w(]")
PY_DOTFORMAT = re.compile(r"[\"']\s*\.format\s*\(")

NOSQL_RULES = [
    ("nosql-where", "js_injection", re.compile(r"['\"]?\$where['\"]?\s*[:=,]|\$where\s*=>|BasicDBObject\s*\(\s*\"\$where\"")),
    ("nosql-request-filter", "operator_injection", re.compile(
        r"(?:\.|->)(find|findOne|find_one|findOneAndUpdate|aggregate|update|updateOne|updateMany|deleteOne|deleteMany|remove|count|countDocuments)\s*\(\s*"
        r"(req\.(body|query|params)\b(?!\.)|\$_(GET|POST|REQUEST)\b(?!\s*\[)|request\.(args|json|form|get_json\(\))\b(?!\.get)|params\b(?!\s*\[))")),
    ("nosql-request-field", "operator_injection", re.compile(
        r"(?:\.|->)(find|findOne|find_one|update|updateOne|deleteOne|remove|count)\s*\(\s*(\{|array\s*\(|\[)[^;]{0,200}?"
        r"(req\.(body|query)\.\w+|req\.(body|query)\[|\$_(GET|POST|REQUEST)\s*\[)")),
    ("nosql-parse-request", "operator_injection", re.compile(
        r"(BasicDBObject\.parse|Document\.parse|JSON\.parse|json_decode|json\.loads)\s*\(\s*(request\.getParameter|req\.(query|body)|\$_(GET|POST|REQUEST)|request\.(args|form))")),
    ("nosql-regex", "operator_injection", re.compile(r"\$regex['\"]?\s*[:=>]+\s*(req\.|\$_(GET|POST|REQUEST)|request\.)|new\s+RegExp\s*\(\s*req\.")),
]
RAW_APIS = re.compile(r"\b(whereRaw|orWhereRaw|havingRaw|orderByRaw|selectRaw|DB::raw|DB::select|DB::statement|DB::unprepared|createQuery|"
                      r"createSQLQuery|createNativeQuery|sqlRestriction|find_by_sql|\.raw|\.extra|SqlQuery|ExecuteSqlCommand|"
                      r"FromSqlRaw|ExecuteQuery|queryForList|queryForObject|queryForMap|jdbcTemplate\.\w+|sqlx::query|sqlx::query_as|db\.Raw|db\.Exec)\s*\(")
ASSIGN = {
    "php": re.compile(r"(\$[\w\->\[\]'\"]+?)\s*(\.=|=)(?!=)"), "perl": re.compile(r"(\$\w+)\s*(\.=|=)(?!=)"),
    "java": re.compile(r"\b(\w+)\s*(\+=|=)(?!=)"), "cs": re.compile(r"\b([\w.]+)\s*(\+=|=)(?!=)"),
    "js": re.compile(r"\b(\w+)\s*(\+=|=)(?!=)"), "python": re.compile(r"\b(\w+)\s*(\+=|=)(?!=)"),
    "ruby": re.compile(r"\b(\w+)\s*(\+=|<<|=)(?!=)"), "vb": re.compile(r"\b([\w.]+)\s*(&=|\+=|=)(?!=)", re.I),
    "cfml": re.compile(r"\b([\w.]+)\s*(&=|=)(?!=)"),
    "rust": re.compile(r"\b(\w+)\s*(\+=|=)(?!=)"), "go": re.compile(r"\b(\w+)\s*(\+=|=)(?!=)"),
}
APPEND_CALL = re.compile(r"\b(\w+)\s*\.\s*(append|Append|AppendLine|concat)\s*\(")


def strip_literals(line: str, lit: re.Pattern) -> str:
    return lit.sub('""', line)


def literals(line: str, lit: re.Pattern) -> List[re.Match]:
    return list(lit.finditer(line))


CONST_OPERAND = re.compile(r"^(?:[A-Z][A-Z0-9_]+|(?:self|static|parent)::[A-Z][A-Z0-9_]*|[\w.]+\.[A-Z][A-Z0-9_]+|\d+(?:\.\d+)?|"
                           r"vbCrLf|vbNewLine|vbTab|Environment\.NewLine|PHP_EOL|System\.lineSeparator\(\))$")


def concat_kind(line: str, lang: str, lit: re.Pattern) -> Optional[str]:
    """Classify string concatenation on a line.

    Returns None (no literal joined with an operand), "const" (every joined operand looks like a
    constant, e.g. TABLE_NAME, self::T, 10) or "dynamic" (at least one variable / call / expression).
    """
    op = CONCAT_OP.get(lang)
    if not op:
        return None
    s = strip_literals(line, lit)
    chain = r"[$@]?[A-Za-z_][\w.:\->\[\]'\"$]*(?:\(\))?" if lang in ("php", "perl") else r"[A-Za-z_][\w.\[\]\"']*(?:\(\))?"
    after = re.compile(r'""\s*(?:' + op + r')\s*(?:_\s*\n?\s*)?(\(?\s*' + chain + r'|\(|\d+)')
    before = re.compile(r'(' + chain + r'|\)|\]|\d+)\s*(?:' + op + r')\s*(?:_\s*)?""')
    operands = [m.group(1).strip("( ") for m in after.finditer(s)] + [m.group(1) for m in before.finditer(s)]
    # line continuation: operand OP at the very end / start of the line next to a literal
    if not operands:
        return None
    if all(CONST_OPERAND.match(o) for o in operands if o not in (")", "]")) and not any(o in (")", "]") for o in operands):
        return "const"
    return "dynamic"


def has_dynamic_concat(line: str, lang: str, lit: re.Pattern) -> bool:
    return concat_kind(line, lang, lit) == "dynamic"


def has_interpolation(lit_text: str, lang: str) -> bool:
    if lang == "php" or lang == "perl":
        return lit_text.startswith('"') and bool(INTERP[lang].search(lit_text))
    if lang == "ruby":
        return lit_text.startswith('"') and bool(INTERP["ruby"].search(lit_text))
    if lang == "js":
        return lit_text.startswith("`") and bool(INTERP["js"].search(lit_text))
    if lang in ("cs", "aspx"):
        return lit_text.startswith("$") and bool(INTERP["cs"].search(lit_text))
    if lang == "python":
        return lit_text[:2].lower().replace("r", "").startswith("f") and bool(INTERP["python"].search(lit_text))
    if lang == "java":
        return lit_text.startswith('"') and bool(INTERP["java"].search(lit_text))
    if lang == "rust":
        return lit_text.startswith('"') and bool(INTERP["rust"].search(lit_text))
    return False


class Finder:
    def __init__(self, config: Dict):
        self.config = config
        self.items: List[Dict] = []
        self.seen = set()
        self.suppressed: List[Dict] = []

    def add(self, lang, rel, lineno, lines, rule, subtype, category, sql_var=None, file_has_input=False):
        key = (rel, lineno)
        if key in self.seen:
            return
        self.seen.add(key)
        line = lines[lineno - 1]
        ctx = "\n".join(lines[max(0, lineno - 4): lineno])
        on_line = bool(REQ_RE.search(line))
        near = bool(REQ_RE.search(ctx))
        hint = "request_input_on_line" if on_line else "request_input_nearby" if near else \
            "request_input_in_file" if file_has_input else "none"
        if subtype in ("string_concatenation", "string_interpolation", "format_string") and SQL_IDENT.search(line):
            subtype_hint = subtype + "|dynamic_identifier"
        else:
            subtype_hint = subtype
        self.items.append({
            "candidate_id": f"I-{len(self.items) + 1:04d}",
            "rule": rule, "category_hint": category, "subtype_hint": subtype_hint, "language": lang,
            "file": rel, "line": lineno, "snippet": redact(snippet(lines, lineno)),
            "sql_var": sql_var, "input_hint": hint,
            "sanitizer_hints": sorted(set(m.group(0)[:30] for m in SANITIZER_RE.finditer(ctx)))[:5],
            "priority": "high" if hint in ("request_input_on_line", "request_input_nearby") else "normal",
        })

    # ----------------------------------------------------------------------------------
    def scan_code(self, lang: str, rel: str, text: str) -> None:
        lit = LIT[LIT_FOR.get(lang, "both")]
        lines = text.splitlines()
        com = COMMENT_LINE.get(lang)
        file_has_input = bool(REQ_RE.search(text))
        sqlvars: Dict[str, int] = {}
        assign_rx = ASSIGN.get(lang)
        # pass 1 — register variables that hold SQL text
        for i, line in enumerate(lines, 1):
            if com and com.search(line):
                continue
            lits = literals(line, lit)
            if not any(STRONG_SQL.search(m.group(0)) for m in lits):
                continue
            if assign_rx:
                m = assign_rx.search(line)
                if m and (not lits or m.start() < lits[0].start()):
                    sqlvars.setdefault(m.group(1), i)
            am = APPEND_CALL.search(line)
            if am:
                sqlvars.setdefault(am.group(1), i)
        heredoc_end = None
        # pass 2 — flag dynamic building
        for i, line in enumerate(lines, 1):
            if com and com.search(line):
                continue
            if LOG_LINE.search(line):
                continue
            # PHP / Perl heredoc
            if lang in ("php", "perl"):
                if heredoc_end is None:
                    hm = re.search(r"<<<\s*['\"]?(\w+)['\"]?\s*$" if lang == "php" else r"<<\s*\"?(\w+)\"?\s*;?\s*$", line)
                    if hm and "'" + hm.group(1) not in line:
                        heredoc_end = hm.group(1)
                        heredoc_start, heredoc_sql = i, False
                        continue
                else:
                    if re.match(r"^\s*" + re.escape(heredoc_end) + r"\b", line):
                        heredoc_end = None
                        continue
                    if STRONG_SQL.search(line) or WEAK_SQL.search(line):
                        heredoc_sql = True
                    if heredoc_sql and INTERP[lang].search(line):
                        self.add(lang, rel, i, lines, "heredoc-interpolation", "string_interpolation", "sql", None, file_has_input)
                    continue
            lits = literals(line, lit)
            sql_lits = [m for m in lits if STRONG_SQL.search(m.group(0))]
            target_var = None
            if assign_rx:
                am = assign_rx.search(line)
                if am and am.group(1) in sqlvars:
                    target_var = am.group(1)
            ap = APPEND_CALL.search(line)
            if ap and ap.group(1) in sqlvars:
                target_var = ap.group(1)
            is_sqlish = bool(sql_lits) or target_var is not None
            if not is_sqlish:
                continue
            # interpolation inside a SQL literal (or SQL-variable literal)
            cand_lits = sql_lits or (lits if target_var else [])
            if any(has_interpolation(m.group(0), lang) for m in cand_lits):
                self.add(lang, rel, i, lines, "sql-interpolation", "string_interpolation", "sql", target_var, file_has_input)
                continue
            if FORMAT_CALL.search(line) and re.search(r"%[sd]|\{\d*\}", line):
                self.add(lang, rel, i, lines, "sql-format", "format_string", "sql", target_var, file_has_input)
                continue
            if lang == "python" and (PY_PERCENT.search(line) or PY_DOTFORMAT.search(line)):
                # note: cursor.execute("... %s", (x,)) uses a comma -> binding, not matched here
                self.add(lang, rel, i, lines, "sql-format", "format_string", "sql", target_var, file_has_input)
                continue
            kind = concat_kind(line, lang, lit)
            if kind == "dynamic":
                self.add(lang, rel, i, lines, "sql-concat" if sql_lits else "sql-append", "string_concatenation", "sql",
                         target_var, file_has_input)
                continue
            if kind == "const":
                self.suppressed.append({"file": rel, "line": i, "reason": "concatenation with constant-looking operands only",
                                        "snippet": redact(snippet(lines, i))})
                continue
            if target_var and re.search(r"\.\s*(append|Append|AppendLine|concat)\s*\(\s*(?![\"'@\s])", line):
                self.add(lang, rel, i, lines, "sql-append", "string_concatenation", "sql", target_var, file_has_input)
                continue
            # Laravel/Hibernate/etc. raw APIs fed by a SQL variable built elsewhere
        for i, line in enumerate(lines, 1):
            if com and com.search(line):
                continue
            rm = RAW_APIS.search(line)
            if rm:
                arg = line[rm.end():].strip()
                if arg and not arg.startswith(("\"", "'", "`", "@\"")) and re.match(r"[$\w]", arg):
                    var = re.match(r"[$\w.\->]+", arg).group(0)
                    if var in sqlvars or var.lstrip("$") in {k.lstrip("$") for k in sqlvars}:
                        continue  # building lines already flagged
                    if (rel, i) not in self.seen and has_dynamic_concat(line, lang, lit) is False:
                        self.add(lang, rel, i, lines, "raw-api-variable", "string_concatenation", "sql", var, file_has_input)
            for rule, subtype, rx in NOSQL_RULES:
                if rx.search(line):
                    self.add(lang, rel, i, lines, rule, subtype, "nosql", None, file_has_input)
                    break
            if lang == "java" and re.search(r"@(Select|Update|Delete|Insert)\s*\([^)]*\$\{", line):
                self.add(lang, rel, i, lines, "mybatis-annotation-dollar", "template_placeholder", "sql", None, file_has_input)

    def scan_xml(self, rel: str, text: str) -> None:
        if not re.search(r"<mapper\b|<sqlMap\b|<!DOCTYPE\s+(mapper|sqlMap)", text):
            return
        lines = text.splitlines()
        in_stmt = False
        for i, line in enumerate(lines, 1):
            if re.search(r"<(select|update|delete|insert|sql|statement|procedure)\b", line):
                in_stmt = True
            if in_stmt:
                if re.search(r"\$\{[^}]+\}", line):
                    self.add("xml", rel, i, lines, "mybatis-dollar", "template_placeholder", "sql")
                elif re.search(r"\$[\w.\[\]]+\$", line):
                    self.add("xml", rel, i, lines, "ibatis-dollar", "template_placeholder", "sql")
            if re.search(r"</(select|update|delete|insert|sql|statement|procedure)>", line):
                in_stmt = False

    def scan_cfml(self, rel: str, text: str) -> None:
        lines = text.splitlines()
        inq = False
        for i, line in enumerate(lines, 1):
            if re.search(r"<cfquery\b", line, re.I):
                inq = True
            if inq:
                body = re.sub(r"<cfqueryparam[^>]*>", "", line, flags=re.I)
                body = re.sub(r"<cfquery\b[^>]*>", "", body, flags=re.I)
                if re.search(r"#[^#]+#", body):
                    self.add("cfml", rel, i, lines, "cfquery-hash", "template_placeholder", "sql", None, True)
            if re.search(r"</cfquery>", line, re.I):
                inq = False
            if re.search(r"preserveSingleQuotes\s*\(", line, re.I):
                self.add("cfml", rel, i, lines, "cf-preserve-quotes", "template_placeholder", "sql", None, True)
        # cfscript parts
        self.scan_code("cfml", rel, text)

    def scan_sql(self, rel: str, text: str) -> None:
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if COMMENT_LINE["sql"].search(line):
                continue
            if re.search(r"(?i)\b(exec(ute)?\s*\(\s*@|exec(ute)?\s*\(\s*'|execute\s+immediate|sp_executesql)", line) or \
               (re.search(r"(?i)@\w*sql\w*\s*=\s*.*(\+|\|\|)\s*@", line) or re.search(r"(?i)(set|select)\s+@\w+\s*=\s*@\w+\s*\+", line)):
                self.add("sql", rel, i, lines, "proc-dynamic-sql", "stored_procedure_dynamic_sql", "sql")


def _scan_injection_file_batch(args: Tuple[List[Tuple[str, str]], Dict]) -> Tuple[List[Dict], List[Dict]]:
    file_batch, config = args
    enc = config["hints"]["file_encodings"]
    f = Finder(config)
    for p_str, rel in file_batch:
        p = Path(p_str)
        lang = LANG_BY_EXT.get(p.suffix.lower())
        if not lang:
            continue
        text = read_text(p, enc)
        if lang == "xml":
            f.scan_xml(rel, text)
        elif lang == "cfml":
            f.scan_cfml(rel, text)
        elif lang == "sql":
            f.scan_sql(rel, text)
        else:
            if lang == "aspx":
                lang = "vb" if re.search(r"<%@[^>]*Language\s*=\s*\"?VB", text, re.I) else "cs"
            if p.suffix.lower() in (".asp", ".asa") and re.search(r"LANGUAGE\s*=\s*\"?JScript", text, re.I):
                lang = "js"
            f.scan_code(lang, rel, text)
    return f.items, f.suppressed


def find_injection(target: Path, config: Dict, workers: int = 0, cache: Optional[Any] = None) -> Dict:
    files = [(str(p), rel) for p, rel in iter_source_files(target, config)]
    num_files = len(files)
    effective_workers = workers if workers > 0 else (os.cpu_count() or 1)

    file_items: Dict[str, List[Dict]] = {}
    file_suppressed: Dict[str, List[Dict]] = {}
    files_to_scan: List[Tuple[str, str]] = []

    if cache and getattr(cache, "enabled", False):
        for p_str, rel in files:
            hit = cache.get_injection(rel, Path(p_str))
            if hit is not None:
                inj_items, sup_items = hit
                file_items[rel] = inj_items
                file_suppressed[rel] = sup_items
            else:
                files_to_scan.append((p_str, rel))
    else:
        files_to_scan = files

    num_to_scan = len(files_to_scan)
    scanned_items: List[Dict] = []
    scanned_suppressed: List[Dict] = []

    if num_to_scan > 0:
        if effective_workers <= 1 or num_to_scan < 20:
            chunk_items, chunk_suppressed = _scan_injection_file_batch((files_to_scan, config))
            scanned_items = chunk_items
            scanned_suppressed = chunk_suppressed
        else:
            chunk_size = max(1, (num_to_scan + effective_workers - 1) // effective_workers)
            chunks = [
                (files_to_scan[i : i + chunk_size], config)
                for i in range(0, num_to_scan, chunk_size)
            ]
            with concurrent.futures.ProcessPoolExecutor(max_workers=effective_workers) as executor:
                for chunk_items, chunk_suppressed in executor.map(_scan_injection_file_batch, chunks):
                    scanned_items.extend(chunk_items)
                    scanned_suppressed.extend(chunk_suppressed)

        for it in scanned_items:
            file_items.setdefault(it["file"], []).append(it)
        for sup in scanned_suppressed:
            file_suppressed.setdefault(sup["file"], []).append(sup)

        if cache and getattr(cache, "enabled", False):
            for p_str, rel in files_to_scan:
                cache.put_injection(
                    rel=rel,
                    path=Path(p_str),
                    injection_items=file_items.get(rel, []),
                    injection_suppressed=file_suppressed.get(rel, []),
                )

    items: List[Dict] = []
    suppressed: List[Dict] = []
    for _, rel in files:
        if rel in file_items:
            items.extend(file_items[rel])
        if rel in file_suppressed:
            suppressed.extend(file_suppressed[rel])

    # Re-index candidate_ids deterministically across sequential, parallel, and cached runs
    for n, it in enumerate(items, 1):
        it["candidate_id"] = f"I-{n:04d}"

    by_rule: Dict[str, int] = {}
    for it in items:
        by_rule[it["rule"]] = by_rule.get(it["rule"], 0) + 1

    return {
        "generated_by": f"lsa find_injection.py {KIT_VERSION}",
        "target": target.resolve().name,
        "summary": {
            "total": len(items),
            "high_priority": sum(1 for i in items if i["priority"] == "high"),
            "suppressed_constant_only": len(suppressed),
            "by_rule": by_rule,
        },
        "candidates": items,
        "suppressed": suppressed,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--config")
    ap.add_argument("--out")
    ap.add_argument("--workers", "-j", type=int, default=0,
                    help="Number of worker processes for parallel scan (default: 0 = auto/cpu_count)")
    a = ap.parse_args()
    res = find_injection(Path(a.target), load_config(a.config), workers=a.workers)
    if a.out:
        write_json(Path(a.out), res)
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
