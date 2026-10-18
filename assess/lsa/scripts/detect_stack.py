#!/usr/bin/env python3
"""Detect the technology stacks of a legacy repository (heuristic).

Usage: detect_stack.py TARGET [--config audit-config.json] [--out stack-profile.json]
"""
from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lsa_common import KIT_VERSION, iter_source_files, load_config, read_text, write_json  # noqa: E402

# (stack id, language, knowledge file, list of (kind, pattern))
#   kind = "name"  -> regex on relative path
#   kind = "text"  -> regex on file content (files whose ext is in the 'exts' set)
RULES = [
    ("php", "php", "php.md", [("ext", {".php", ".php3", ".php4", ".php5", ".phtml"})]),
    ("php-codeigniter", "php", "php.md", [("name", r"(^|/)system/core/CodeIgniter\.php$"),
                                          ("name", r"(^|/)application/config/routes\.php$"),
                                          ("text", r"extends\s+CI_Controller")]),
    ("php-cakephp", "php", "php.md", [("name", r"(^|/)app/(Config|config)/routes\.php$"),
                                      ("name", r"(^|/)lib/Cake/|(^|/)cake/libs/"),
                                      ("text", r"extends\s+AppController")]),
    ("php-laravel", "php", "php.md", [("name", r"(^|/)artisan$"), ("text", r"Route::(get|post|put|delete|any|match|resource)\s*\(")]),
    ("php-zend1", "php", "php.md", [("text", r"extends\s+Zend_Controller_Action")]),
    ("java-servlet", "java", "java.md", [("name", r"(^|/)WEB-INF/web\.xml$"), ("text", r"extends\s+HttpServlet|@WebServlet")]),
    ("java-jsp", "java", "java.md", [("ext", {".jsp", ".jspf"})]),
    ("java-struts1", "java", "java.md", [("name", r"struts-config.*\.xml$"), ("text", r"extends\s+(Dispatch|LookupDispatch|MappingDispatch)?Action\b.*\{|org\.apache\.struts\.action")]),
    ("java-struts2", "java", "java.md", [("name", r"(^|/)struts\.xml$"), ("text", r"com\.opensymphony\.xwork2|org\.apache\.struts2")]),
    ("java-spring-mvc", "java", "java.md", [("text", r"@(Controller|RestController)\b|@RequestMapping|org\.springframework\.web\.servlet|org\.springframework\.web\.bind\.annotation")]),
    ("java-jaxrs", "java", "java.md", [("text", r"javax\.ws\.rs\.|jakarta\.ws\.rs\.")]),
    ("java-mybatis", "java", "java.md", [("text", r"<mapper\s+namespace=|org\.apache\.ibatis")]),
    ("java-ibatis", "java", "java.md", [("text", r"<sqlMap\b|com\.ibatis\.")]),
    ("java-hibernate", "java", "java.md", [("text", r"org\.hibernate\.|\.hbm\.xml|createQuery\s*\(")]),
    ("dotnet-webforms", "csharp/vbnet", "dotnet.md", [("ext", {".aspx", ".ascx"})]),
    ("dotnet-handlers", "csharp/vbnet", "dotnet.md", [("ext", {".ashx"})]),
    ("dotnet-asmx-wcf", "csharp/vbnet", "dotnet.md", [("ext", {".asmx", ".svc"})]),
    ("dotnet-mvc", "csharp/vbnet", "dotnet.md", [("text", r":\s*(ControllerBase|Controller)\b|Inherits\s+Controller\b|System\.Web\.Mvc|Microsoft\.AspNetCore\.Mvc")]),
    ("dotnet-webapi", "csharp/vbnet", "dotnet.md", [("text", r":\s*(ApiController|ControllerBase)\b|Inherits\s+ApiController\b|System\.Web\.Http|Microsoft\.AspNetCore\.Mvc")]),
    ("classic-asp", "vbscript", "classic-asp.md", [("ext", {".asp", ".asa"})]),
    ("perl-cgi", "perl", "perl-cgi.md", [("ext", {".cgi"}), ("text", r"use\s+CGI\b|CGI->new|use\s+DBI\b")]),
    ("coldfusion", "cfml", "coldfusion.md", [("ext", {".cfm", ".cfc", ".cfml"})]),
    ("node-express", "javascript", "node-python-ruby.md", [("text", r"require\(\s*['\"]express['\"]\s*\)|from\s+['\"]express['\"]")]),
    ("python-django", "python", "node-python-ruby.md", [("text", r"from\s+django\.|import\s+django")]),
    ("python-flask", "python", "node-python-ruby.md", [("text", r"from\s+flask\s+import|import\s+flask")]),
    ("sql-procedures", "sql", "", [("text", r"(?i)create\s+(or\s+replace\s+)?proc(edure)?\b")]),
    ("ruby-rails", "ruby", "node-python-ruby.md", [("name", r"(^|/)config/routes\.rb$"), ("text", r"<\s*(ApplicationController|ActionController::Base)")]),
]

DATA_ACCESS = [
    ("mysql_* (no binding)", r"\bmysql_query\s*\("),
    ("mysqli", r"\bmysqli_|new\s+mysqli\b"),
    ("PDO", r"new\s+PDO\s*\("),
    ("ADOdb/PEAR DB", r"ADONewConnection|DB::connect"),
    ("JDBC", r"java\.sql\.|DriverManager\.getConnection"),
    ("Spring JdbcTemplate", r"JdbcTemplate"),
    ("MyBatis/iBATIS", r"<mapper\s+namespace=|<sqlMap\b"),
    ("Hibernate/JPA", r"org\.hibernate\.|javax\.persistence\."),
    ("ADO.NET", r"SqlCommand|OleDbCommand|OdbcCommand|OracleCommand"),
    ("Entity Framework / LINQ to SQL", r"DbContext|DataContext|System\.Data\.Entity"),
    ("Classic ADO", r"ADODB\.(Connection|Recordset|Command)"),
    ("Perl DBI", r"DBI->connect"),
    ("ColdFusion cfquery", r"<cfquery"),
    ("MongoDB", r"MongoClient|MongoCollection|MongoDB\\|mongoose|pymongo|com\.mongodb"),
]

DB_HINTS = [
    ("MySQL", r"(?i)mysql"), ("PostgreSQL", r"(?i)\bpg_|postgres"), ("SQL Server", r"(?i)sqlclient|sqlsrv|mssql|Provider=SQLOLEDB"),
    ("Oracle", r"(?i)oracle|oci_|OracleCommand"), ("Access", r"(?i)Microsoft\.Jet|\.mdb\b|Microsoft\.ACE"),
    ("MongoDB", r"(?i)mongo"), ("SQLite", r"(?i)sqlite"),
]

TEXT_SAMPLE_EXTS = {".sql", ".php", ".inc", ".java", ".jsp", ".xml", ".cs", ".vb", ".aspx", ".asax", ".config", ".asp",
                    ".pl", ".pm", ".cgi", ".cfm", ".cfc", ".js", ".mjs", ".ts", ".py", ".rb", ".kt", ".kts"}


def detect(target: Path, config: dict) -> dict:
    enc = config["hints"]["file_encodings"]
    ext_counts = collections.Counter()
    evidence = collections.defaultdict(list)
    da_hits, db_hits = collections.Counter(), collections.Counter()
    files = list(iter_source_files(target, config))
    names = [rel for _, rel in files]
    for path, rel in files:
        ext_counts[path.suffix.lower()] += 1
    for sid, _lang, _kf, checks in RULES:
        for kind, pat in checks:
            if kind == "ext":
                n = sum(ext_counts[e] for e in pat)
                if n:
                    evidence[sid].append(f"{n} file(s) with extension {', '.join(sorted(pat))}")
            elif kind == "name":
                hit = next((r for r in names if re.search(pat, r)), None)
                if hit:
                    evidence[sid].append(f"marker file {hit}")
    text_rules = [(sid, re.compile(pat)) for sid, _l, _k, checks in RULES for kind, pat in checks if kind == "text"]
    da_rules = [(n, re.compile(p)) for n, p in DATA_ACCESS]
    db_rules = [(n, re.compile(p)) for n, p in DB_HINTS]
    seen_text = collections.defaultdict(int)
    for path, rel in files:
        if path.suffix.lower() not in TEXT_SAMPLE_EXTS:
            continue
        text = read_text(path, enc)
        for sid, rx in text_rules:
            if seen_text[sid] < 3 and rx.search(text):
                seen_text[sid] += 1
                evidence[sid].append(f"pattern /{rx.pattern[:40]}/ in {rel}")
        for n, rx in da_rules:
            if rx.search(text):
                da_hits[n] += 1
        for n, rx in db_rules:
            if rx.search(text):
                db_hits[n] += 1
    stacks, kfiles = [], []
    for sid, lang, kf, _ in RULES:
        if evidence.get(sid):
            stacks.append({"id": sid, "language": lang, "version_hint": None,
                           "evidence": evidence[sid][:6], "confirmed": False})
            if kf and kf not in kfiles:
                kfiles.append(kf)
    return {
        "repo": target.resolve().name,
        "generated_by": f"lsa detect_stack.py {KIT_VERSION}",
        "stacks": stacks,
        "data_access": [n for n, _ in da_hits.most_common()],
        "databases": [n for n, c in db_hits.most_common() if c >= 1],
        "file_counts": dict(sorted(ext_counts.items(), key=lambda kv: -kv[1])),
        "knowledge_files": ["knowledge/stacks/" + k for k in kfiles],
        "notes": "Heuristic result. The stack-detector agent must confirm each item.",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--config")
    ap.add_argument("--out")
    a = ap.parse_args()
    prof = detect(Path(a.target), load_config(a.config))
    if a.out:
        write_json(Path(a.out), prof)
    else:
        import json
        print(json.dumps(prof, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
