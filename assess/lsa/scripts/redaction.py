"""Secret redaction for code excerpts: Tier 1 snippets and every excerpt the headless agents send to a model (#350).

Pattern-based, so it cannot catch every secret: the pilot runbook also leaves key and environment config files
out of the source copy. Standard-library only (Python 3.8+ compatible).
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

MASK = "[REDACTED]"
# Longer lines (minified bundles, generated data) are dropped whole: they are not useful to an auditor and
# keep the regexes below from running on megabyte-long input
MAX_LINE_CHARS = 4000

# A secret-like key name; the lookahead keeps passwordPolicy, tokenizer and Passenger out
_KW = r"(?:password|passwd|passphrase|pwd|pw|pass|secret|credential|api[_-]?key|token)(?![a-z])"
_NAME_TAGS = r"(?:param-name|name|key)"
_VALUE_TAGS = r"(?:param-value|value)"


def _rx(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# (pattern, replacement); applied in order to each line
_RULES: Tuple[Tuple[re.Pattern[str], str], ...] = (
    # -----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY----- on one line
    (_rx(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----).*?(-----END [A-Z ]*PRIVATE KEY-----)", 0), r"\1" + MASK + r"\2"),
    # "password": "x", 'password' => 'x', pw = "x", keystorePass="x", setProperty("mail.smtp.password", "x")
    (_rx(r"(?<![\w.\-])((['\"]?)[\w.\-]*?" + _KW + r"\2\s*(?:=>|->|[=:,])\s*)(['\"])[^'\"]+\3"), r"\1\3" + MASK + r"\3"),
    # conn.setPassword("x"), setKeystorePass("x")
    (_rx(r"(\bset\w*?" + _KW + r"\s*\(\s*)(['\"])[^'\"]*\2"), r"\1\2" + MASK + r"\2"),
    # DriverManager.getConnection(url, "sa", "x")
    (_rx(r"(\bgetConnection\s*\([^,()]*,[^,()]*,\s*)(['\"])[^'\"]*\2"), r"\1\2" + MASK + r"\2"),
    # new PasswordAuthentication("u", "x".toCharArray())
    (_rx(r"(\bPasswordAuthentication\s*\([^,()]*,\s*)(['\"])[^'\"]*\2"), r"\1\2" + MASK + r"\2"),
    # <property name="jdbc.password" value="x"/>
    (_rx(r"(\bname\s*=\s*['\"][^'\"]*?" + _KW + r"[^'\"]*['\"][^>]*?\bvalue\s*=\s*)(['\"])[^'\"]*\2"),
     r"\1\2" + MASK + r"\2"),
    # <param-name>password</param-name><param-value>x</param-value>
    (_rx(r"(<" + _NAME_TAGS + r">[^<]*?" + _KW + r"[^<]*</" + _NAME_TAGS + r">\s*<" + _VALUE_TAGS + r">)[^<]+"),
     r"\1" + MASK),
    # <password>x</password>
    (_rx(r"(<([\w.\-:]*?" + _KW + r")\s*>)[^<]+(?=</\2\s*>)"), r"\1" + MASK),
    # jdbc:sqlserver://h;password=x  ?pwd=x&  password={a;b}
    (_rx(r"([;?&](?:password|passwd|pwd)=)(?:\{[^}]*\}|[^;\"'&\s]+)"), r"\1" + MASK),
    # scheme://user:pass@host
    (_rx(r"(?<![a-z0-9+.\-])([a-z][a-z0-9+.\-]*://[^/\s:@\"']+:)[^@\s\"'/]+@"), r"\1" + MASK + "@"),
    # jdbc:oracle:thin:user/pass@host
    (_rx(r"(\bjdbc:oracle:\w+:[^/\s:@\"']+/)[^@\s\"']+@"), r"\1" + MASK + "@"),
    # Authorization: Basic xxx / Bearer xxx
    (_rx(r"(\b(?:Basic|Bearer)\s+)[A-Za-z0-9._~+/=\-]{8,}"), r"\1" + MASK),
    # Well-known token formats (case-sensitive)
    (_rx(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{20,}|sk-[A-Za-z0-9_\-]{20,}"
         r"|AIza[0-9A-Za-z_\-]{35})\b", 0), MASK),
    # Unquoted config values (.properties, YAML, .env) on their own line; ${PLACEHOLDER} and code are kept
    (_rx(r"^(\s*[\w.\-]*?" + _KW + r"[\w.\-]*\s*[=:]\s*)(?![\"'$=\s])[^\s\"'(){}<>,;]+\s*(?:(?:#|//).*)?$"), r"\1" + MASK),
    # Dotted config keys inside comments or strings: <%-- db.password=x --%>
    (_rx(r"(?<![\w.\-])([\w\-]+\.[\w.\-]*?" + _KW + r"[\w\-]*\s*=\s*)(?![\"'$=\s])[^\s\"'(){}<>,;]+(?=\s|$|[\"'])"),
     r"\1" + MASK),
)

_PRIVATE_KEY_BEGIN = _rx(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", 0)
_PRIVATE_KEY_END = _rx(r"-----END [A-Z ]*PRIVATE KEY-----", 0)
# A secret name whose value follows on a later line: <property name="password"\n value="x"/>, web.xml params
_PENDING_NAME = _rx(r"\bname\s*=\s*['\"][^'\"]*?" + _KW + r"[^'\"]*['\"]|<" + _NAME_TAGS + r">[^<]*?" + _KW)
_PENDING_VALUE: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (_rx(r"(\bvalue\s*=\s*)(['\"])[^'\"]*\2"), r"\1\2" + MASK + r"\2"),
    (_rx(r"(<" + _VALUE_TAGS + r">)[^<]+"), r"\1" + MASK),
)
_PENDING_LINES = 2


def _too_long(s: str) -> Optional[str]:
    return f"[line of {len(s)} characters omitted]" if len(s) > MAX_LINE_CHARS else None


def redact(s: str) -> str:
    """Mask secrets in one line of code or config."""
    omitted = _too_long(s)
    if omitted:
        return omitted
    for pattern, repl in _RULES:
        s = pattern.sub(repl, s)
    return s


def _redact_pending(line: str) -> Tuple[str, bool]:
    for pattern, repl in _PENDING_VALUE:
        masked, n = pattern.subn(repl, line)
        if n:
            return masked, True
    return line, False


def redact_lines(lines: List[str]) -> List[str]:
    """Redact each line, blank out private key bodies and mask values split from their names.

    The line count stays the same, so line numbers in excerpts remain valid.
    """
    out: List[str] = []
    in_key, pending = False, 0
    for line in lines:
        if in_key:
            in_key = not _PRIVATE_KEY_END.search(line)
            out.append(MASK if in_key else line)
            continue
        masked = redact(line)
        if pending:
            masked, done = _redact_pending(masked)
            pending = 0 if done else pending - 1
        if _PENDING_NAME.search(line) and MASK not in masked:
            pending = _PENDING_LINES
        in_key = bool(_PRIVATE_KEY_BEGIN.search(line)) and not _PRIVATE_KEY_END.search(line)
        out.append(masked)
    return out
