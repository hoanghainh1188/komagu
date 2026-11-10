"""Post-run leak check for pilot outputs: ai-raw/, findings and reports (runbook §9).

Four independent detectors, because the output must be checked for what the redaction step missed:
client-provided canary strings, the redaction patterns, further token and credential patterns, and Shannon entropy.
Text is also checked after JSON/backslash and HTML unescaping, so "password": "x" stored inside a JSON string is
seen the way a reader would see it. Reported values are always masked. Standard-library only (Python 3.8+).

A clean result is not proof that no secret remains: the detectors are heuristics, so Person B still reviews.
"""

from __future__ import annotations

import base64
import html
import math
import os
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Pattern, Sequence, Set, Tuple
from urllib.parse import quote

from operate.ai.context import _load_redaction
from operate.devsecops.pipeline import SECRET_PATTERNS

_redaction = _load_redaction()
MASK: str = _redaction.MASK
MAX_LINE_CHARS: int = _redaction.MAX_LINE_CHARS
_CHUNK_OVERLAP = 200
MIN_CANARY_CHARS = 4
MIN_ALIGNED_BASE64_CHARS = 8

# (line number in the file, text); one physical line can become several entries after unescaping
Entry = Tuple[int, str]

_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_TOKEN_PATTERNS: Tuple[Tuple[Pattern[str], str], ...] = tuple(
    (re.compile(pattern), name) for pattern, name in SECRET_PATTERNS if "PRIVATE KEY" not in pattern
) + (
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+"), "JSON Web Token"),
    (re.compile(r"\bAccountKey=[A-Za-z0-9+/]{20,}=*"), "Azure Storage Account Key"),
    (re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}"), "Stripe Live Key"),
    # Japanese key names, which the English keyword patterns cannot see
    (re.compile(r"(?:パスワード|暗証番号|秘密鍵|認証キー)\s*[:：=＝]\s*(?!\[REDACTED)[!-~]{4,}"), "Japanese-labelled credential"),
)

_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_HEX_LIKE = re.compile(r"[0-9a-fA-F\-]+")
_SECRET_WORD = re.compile(r"(?:secret|token|passw|credential|api[_-]?key|private[_-]?key)", re.IGNORECASE)
_HASH_WORD = re.compile(r"(?:fingerprint|sha\d*|hash|digest|md5|checksum|integrity|commit|etag)", re.IGNORECASE)
_ENTROPY_RATIO = 0.85
_MIN_DIGIT_TRANSITIONS = 3
_DIGIT_TRANSITION_RATE = 0.12

_BACKSLASH_ESCAPE = re.compile(r"\\(u[0-9a-fA-F]{4}|[\"'\\/nrtbf])")
_BACKSLASH_MAP: Dict[str, str] = {"n": "\n", "r": "\n", "t": "\t", "b": " ", "f": " "}
_UNESCAPE_ROUNDS = 3


@dataclass(frozen=True)
class Hit:
    """One suspected leak. Never holds the value itself."""

    path: str
    line: int
    detector: str
    rule: str
    masked: str


@dataclass(frozen=True)
class ScanResult:
    hits: Tuple[Hit, ...]
    files_scanned: int
    unscanned: Tuple[Tuple[str, str], ...]
    canaries_loaded: int

    @property
    def exit_code(self) -> int:
        """1 on any hit; 2 when the scan is incomplete or saw nothing, so a bad path cannot pass as clean."""
        if self.hits:
            return 1
        return 2 if self.unscanned or not self.files_scanned else 0


class CanaryFileError(ValueError):
    """The canary file cannot be used, so the check must not report a clean result."""


def load_canaries(path: str) -> Tuple[str, ...]:
    """Read one canary per line. Every non-blank line counts: a "#" comment syntax could hide a real value."""
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            canaries = tuple(line.strip() for line in handle if line.strip())
    except (OSError, UnicodeDecodeError) as exc:
        raise CanaryFileError(f"cannot read canary file: {exc}") from exc
    if not canaries:
        raise CanaryFileError("canary file has no entries")
    short = [number for number, value in enumerate(canaries, 1) if len(value) < MIN_CANARY_CHARS]
    if short:
        raise CanaryFileError(f"canary entries shorter than {MIN_CANARY_CHARS} characters: {short}")
    return canaries


def _base64_forms(raw: bytes) -> Set[str]:
    """The canary's base64 at each byte alignment, so it is found inside a longer encoded payload too."""
    forms: Set[str] = set()
    for offset in range(3):
        encoded = base64.b64encode(b"\0" * offset + raw).decode().rstrip("=")
        # The first and last characters also carry bits of the neighbouring bytes
        form = encoded[math.ceil(offset * 4 / 3) :]
        form = form[:-1] if (offset + len(raw)) % 3 else form
        if offset == 0 or len(form) >= MIN_ALIGNED_BASE64_CHARS:
            forms.update((form, form.replace("+", "-").replace("/", "_")))
    return forms


def _compile_canaries(canaries: Sequence[str]) -> Tuple[Tuple[Pattern[str], str], ...]:
    """Each canary as typed, and as it appears once URL or HTML encoded (any case), or base64 encoded (exact)."""
    compiled: List[Tuple[Pattern[str], str]] = []
    for number, value in enumerate(canaries, 1):
        parts = [re.escape(form) for form in (value, html.escape(value), quote(value, safe=""))]
        rule = f"canary#{number}"
        compiled.append((re.compile("|".join(parts), re.IGNORECASE), rule))
        base64_forms = sorted(_base64_forms(value.encode("utf-8")))
        compiled.append((re.compile("|".join(re.escape(form) for form in base64_forms)), rule))
    return tuple(compiled)


def shannon_entropy(token: str) -> float:
    """Bits per character."""
    length = len(token)
    return -sum((count / length) * math.log2(count / length) for count in Counter(token).values())


def _is_random_token(token: str, line: str) -> bool:
    """Random-looking token that is not a hash, path or identifier."""
    if not any(ch.isdigit() for ch in token) or not any(ch.isalpha() for ch in token):
        return False
    if _HEX_LIKE.fullmatch(token):
        # Hashes fill audit output (fingerprints, checksums), so bare hex needs a secret word on the same line
        return bool(_SECRET_WORD.search(line)) and not _HASH_WORD.search(line)
    transitions = sum(1 for a, b in zip(token, token[1:]) if a.isdigit() != b.isdigit())
    if transitions < max(_MIN_DIGIT_TRANSITIONS, _DIGIT_TRANSITION_RATE * len(token)):
        return False
    return shannon_entropy(token) >= _ENTROPY_RATIO * math.log2(len(token))


def _masked(value: str) -> str:
    return f"[MASKED len={len(value)}]"


def _unescape_once(text: str) -> str:
    def replace(match: "re.Match[str]") -> str:
        escape = match.group(1)
        if escape.startswith("u"):
            return chr(int(escape[1:], 16))
        return _BACKSLASH_MAP.get(escape, escape)

    unescaped = html.unescape(_BACKSLASH_ESCAPE.sub(replace, text))
    # Full-width forms and zero-width characters read the same to a person
    normalized = unicodedata.normalize("NFKC", unescaped)
    return "".join(ch for ch in normalized if unicodedata.category(ch) != "Cf")


def _decoded_entries(lines: Sequence[str]) -> List[Entry]:
    """Lines that change when unescaped, split as a reader would see them; handles double-encoded JSON."""
    entries: List[Entry] = []
    for number, line in enumerate(lines, 1):
        current = line
        for _ in range(_UNESCAPE_ROUNDS):
            decoded = _unescape_once(current)
            if decoded == current:
                break
            current = decoded
        if current != line:
            entries.extend((number, part) for part in current.split("\n"))
    return entries


def _bounded(entries: Iterable[Entry]) -> List[Entry]:
    """Split very long lines into overlapping chunks: redact() would otherwise drop them whole."""
    bounded: List[Entry] = []
    step = MAX_LINE_CHARS - _CHUNK_OVERLAP
    for number, text in entries:
        if len(text) <= MAX_LINE_CHARS:
            bounded.append((number, text))
            continue
        bounded.extend((number, text[start : start + MAX_LINE_CHARS]) for start in range(0, len(text), step))
    return bounded


def _find_canaries(entries: Sequence[Entry], compiled: Sequence[Tuple[Pattern[str], str]]) -> Iterable[Tuple[int, str, str, str]]:
    for number, text in entries:
        for pattern, rule in compiled:
            for match in pattern.finditer(text):
                yield number, "canary", rule, _masked(match.group(0))


def _find_redaction_misses(entries: Sequence[Entry]) -> Iterable[Tuple[int, str, str, str]]:
    masked_lines = _redaction.redact_lines([text for _, text in entries])
    for (number, text), masked in zip(entries, masked_lines):
        if text != masked:
            yield number, "redaction-pattern", "value the redaction step would mask", "[MASKED]"


def _find_tokens(entries: Sequence[Entry]) -> Iterable[Tuple[int, str, str, str]]:
    for number, text in entries:
        for pattern, name in _TOKEN_PATTERNS:
            for match in pattern.finditer(text):
                yield number, "token-pattern", name, _masked(match.group(0))


def _find_private_keys(entries: Sequence[Entry]) -> Iterable[Tuple[int, str, str, str]]:
    """A key header counts unless its body was masked, either on the same line or on the next one."""
    for index, (number, text) in enumerate(entries):
        for match in _PRIVATE_KEY.finditer(text):
            rest = text[match.end() :].strip()
            following = entries[index + 1][1].strip() if index + 1 < len(entries) else ""
            if not (rest.startswith(MASK) or (not rest and following.startswith(MASK))):
                yield number, "token-pattern", "Private Key", _masked(match.group(0))


def _find_high_entropy(entries: Sequence[Entry]) -> Iterable[Tuple[int, str, str, str]]:
    for number, text in entries:
        for match in _TOKEN.finditer(text):
            if _is_random_token(match.group(0), text):
                yield number, "entropy", "high-entropy token", _masked(match.group(0))


_DETECTORS: Tuple[Callable[[Sequence[Entry]], Iterable[Tuple[int, str, str, str]]], ...] = (
    _find_redaction_misses,
    _find_tokens,
    _find_private_keys,
    _find_high_entropy,
)


def scan_text(path: str, text: str, compiled: Sequence[Tuple[Pattern[str], str]] = ()) -> List[Hit]:
    """Run every detector over the text as stored and as unescaped; repeated sightings are reported once."""
    lines = text.splitlines()
    streams = (
        [(number, line) for number, line in enumerate(lines, 1)],
        _decoded_entries(lines),
    )
    found: List[Tuple[int, str, str, str]] = []
    for entries in streams:
        found.extend(_find_canaries(entries, compiled))
        bounded = _bounded(entries)
        for detector in _DETECTORS:
            found.extend(detector(bounded))
    return [Hit(path, number, detector, rule, masked) for number, detector, rule, masked in sorted(set(found))]


def _decode(data: bytes) -> str:
    """Komagu writes UTF-8; copied source excerpts in Japanese systems are often Shift_JIS."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    for encoding in ("utf-8-sig", "cp932"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def _walk(paths: Sequence[str], errors: List[Tuple[str, str]]) -> Iterable[str]:
    """Every file below the paths, plus symlinked directories for _read to refuse. Hidden directories count."""

    def record(error: OSError) -> None:
        errors.append((str(error.filename), f"unreadable: {error.strerror}"))

    for root in paths:
        if not os.path.isdir(root) or os.path.islink(root):
            yield root
            continue
        for directory, subdirs, names in os.walk(root, onerror=record):
            subdirs.sort()
            links = [name for name in subdirs if os.path.islink(os.path.join(directory, name))]
            yield from (os.path.join(directory, name) for name in links + sorted(names))


def _read(path: str) -> Tuple[str, str]:
    """Return (text, "") or ("", reason not scanned)."""
    if os.path.islink(path):
        return "", "symbolic link"
    if not os.path.isfile(path):
        return "", "not found"
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        return "", f"unreadable: {exc.strerror}"
    if b"\0" in data[:8192] and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "", "binary file"
    text = _decode(data)
    return ("", "binary file") if "\0" in text else (text, "")


def scan_paths(paths: Sequence[str], canaries: Sequence[str] = ()) -> ScanResult:
    """Scan files and directories; anything that cannot be read is listed, never silently skipped."""
    compiled = _compile_canaries(canaries)
    hits: List[Hit] = []
    unscanned: List[Tuple[str, str]] = []
    files_scanned = 0
    for path in _walk(paths, unscanned):
        text, reason = _read(path)
        if reason:
            unscanned.append((path, reason))
            continue
        files_scanned += 1
        hits.extend(scan_text(path, text, compiled))
    return ScanResult(tuple(hits), files_scanned, tuple(unscanned), len(canaries))
