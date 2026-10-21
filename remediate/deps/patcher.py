"""Automated Dependency Manifest Patcher & CVE Advisory Catalog (CWE-1395).

Supports format-preserving dependency version upgrades across 5 ecosystems (7 manifest formats):
1. Node.js (npm): package.json
2. Python (PyPI): requirements.txt, pyproject.toml
3. .NET (NuGet): *.csproj
4. Java / Kotlin (Maven & Gradle): pom.xml, build.gradle, build.gradle.kts
5. Go (Golang): go.mod

Preserves existing version range prefixes (^, ~, ==, >=, ~=), file indentation,
comments, XML/JSON formatting, and line endings to minimize diff noise and
prevent breaking legacy builds.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class DependencyRewriteResult:
    """Represents the outcome of upgrading a vulnerable dependency in a manifest file."""

    package_name: str
    ecosystem: str
    previous_version: str
    fixed_version: str
    operator_preserved: str = ""
    changed: bool = False
    explanation: str = ""


@dataclass(frozen=True)
class CVEAdvisoryEntry:
    """Represents a known CVE security advisory for a package ecosystem."""

    cve_id: str
    ecosystem: str
    package_name: str
    fixed_version: str
    severity: str
    summary: str
    cwe: str = "CWE-1395"
    min_version: Optional[str] = None


def normalize_package_name(name: str, ecosystem: str) -> str:
    """Normalize package name according to ecosystem rules."""
    cleaned = name.strip()
    if ecosystem == "pypi":
        # PEP 503 normalized name
        return re.sub(r"[-_.]+", "-", cleaned).lower()
    if ecosystem in ("npm", "nuget"):
        return cleaned.lower()
    return cleaned


def parse_version_parts(version_str: str) -> List[int]:
    """Extract numeric version tuple from a version string for comparison."""
    clean = version_str.strip().lstrip("vV^~>=<!")
    # Take main release segment before pre-release/build metadata if numeric
    main_part = re.split(r"[-+]", clean, maxsplit=1)[0]
    nums: List[int] = []
    for token in main_part.split("."):
        m = re.match(r"^(\d+)", token)
        if m:
            nums.append(int(m.group(1)))
        else:
            nums.append(0)
    return nums


def is_version_older(current_version: str, target_version: str) -> bool:
    """Return True if current_version is strictly older than target_version."""
    cur_parts = parse_version_parts(current_version)
    tgt_parts = parse_version_parts(target_version)
    if not cur_parts or not tgt_parts:
        return False

    max_len = max(len(cur_parts), len(tgt_parts))
    cur_padded = cur_parts + [0] * (max_len - len(cur_parts))
    tgt_padded = tgt_parts + [0] * (max_len - len(tgt_parts))
    return cur_padded < tgt_padded


class CVEAdvisoryCatalog:
    """Built-in offline CVE advisory catalog with optional OSV.dev API integration."""

    # Curated catalog of high-impact CVEs across npm, PyPI, NuGet, Maven/Gradle, and Go
    BUILTIN_ADVISORIES: List[CVEAdvisoryEntry] = [
        # --- npm (Node.js) ---
        CVEAdvisoryEntry("CVE-2021-23337", "npm", "lodash", "4.17.21", "high", "Command Injection via template in lodash"),
        CVEAdvisoryEntry("CVE-2024-29041", "npm", "express", "4.19.2", "medium", "Open Redirect vulnerability in express"),
        CVEAdvisoryEntry("CVE-2023-45857", "npm", "axios", "1.6.0", "medium", "CSRF token leakage in axios"),
        CVEAdvisoryEntry("CVE-2022-23529", "npm", "jsonwebtoken", "9.0.0", "high", "Remote code execution via insecure key retrieval in jsonwebtoken"),
        CVEAdvisoryEntry("CVE-2021-44906", "npm", "minimist", "1.2.6", "critical", "Prototype Pollution in minimist"),
        CVEAdvisoryEntry("CVE-2024-37890", "npm", "ws", "8.17.1", "high", "DoS via uncaught TypeError in ws"),
        CVEAdvisoryEntry("CVE-2022-25883", "npm", "semver", "6.3.1", "high", "Regular Expression Denial of Service (ReDoS) in semver 6.x", min_version="6.0.0"),
        CVEAdvisoryEntry("CVE-2022-25883", "npm", "semver", "7.5.2", "high", "Regular Expression Denial of Service (ReDoS) in semver 7.x", min_version="7.0.0"),
        CVEAdvisoryEntry("CVE-2024-28863", "npm", "tar", "6.2.1", "medium", "Denial of Service via deep folder nesting in node-tar"),
        CVEAdvisoryEntry("CVE-2023-26136", "npm", "tough-cookie", "4.1.3", "critical", "Prototype Pollution in tough-cookie"),
        CVEAdvisoryEntry("CVE-2023-0842", "npm", "xml2js", "0.5.0", "medium", "Prototype Pollution in xml2js"),
        # --- PyPI (Python) ---
        CVEAdvisoryEntry("CVE-2024-35195", "pypi", "requests", "2.32.0", "medium", "Session verify=False persistence in requests"),
        CVEAdvisoryEntry("CVE-2023-45803", "pypi", "urllib3", "2.0.7", "medium", "Request body not stripped on redirect in urllib3"),
        CVEAdvisoryEntry("CVE-2024-26130", "pypi", "cryptography", "42.0.4", "high", "NULL pointer dereference in PKCS12 serialization in cryptography"),
        CVEAdvisoryEntry("CVE-2024-34069", "pypi", "werkzeug", "3.0.3", "high", "Debugger remote execution vulnerability in Werkzeug"),
        CVEAdvisoryEntry("CVE-2023-30861", "pypi", "flask", "2.3.2", "high", "Session cookie disclosure via caching in Flask"),
        CVEAdvisoryEntry("CVE-2024-27351", "pypi", "django", "4.2.11", "high", "Regular Expression Denial of Service in Django Truncator"),
        CVEAdvisoryEntry("CVE-2020-14343", "pypi", "pyyaml", "5.4", "critical", "Arbitrary code execution in PyYAML full_load"),
        CVEAdvisoryEntry("CVE-2024-22195", "pypi", "jinja2", "3.1.3", "medium", "Cross-Site Scripting via xmlattr filter in Jinja2"),
        CVEAdvisoryEntry("CVE-2024-28219", "pypi", "pillow", "10.3.0", "high", "Buffer overflow in _imagingcms in Pillow"),
        CVEAdvisoryEntry("CVE-2024-37891", "pypi", "certifi", "2024.7.4", "medium", "Removal of compromised GLOBALTRUST root certificates in certifi"),
        CVEAdvisoryEntry("CVE-2024-23334", "pypi", "aiohttp", "3.9.2", "high", "Directory traversal in static file resolution in aiohttp"),
        # --- NuGet (.NET) ---
        CVEAdvisoryEntry("CVE-2024-21907", "nuget", "Newtonsoft.Json", "13.0.1", "high", "StackOverflowException DoS via deeply nested JSON in Newtonsoft.Json"),
        CVEAdvisoryEntry("CVE-2024-30105", "nuget", "System.Text.Json", "8.0.4", "high", "Denial of Service in System.Text.Json source generator"),
        CVEAdvisoryEntry("CVE-2024-21319", "nuget", "Microsoft.Data.SqlClient", "5.1.4", "medium", "Information disclosure in Microsoft.Data.SqlClient"),
        CVEAdvisoryEntry("CVE-2024-29857", "nuget", "BouncyCastle.Cryptography", "2.3.1", "high", "Excessive CPU consumption during EC certificate import in BouncyCastle"),
        CVEAdvisoryEntry("CVE-2024-32655", "nuget", "Npgsql", "8.0.3", "high", "Protocol message injection in Npgsql"),
        # --- Maven / Gradle (Java & Kotlin) ---
        CVEAdvisoryEntry("CVE-2021-44228", "maven", "org.apache.logging.log4j:log4j-core", "2.17.1", "critical", "Remote Code Execution via JNDI lookup in Apache Log4j2 (Log4Shell)"),
        CVEAdvisoryEntry("CVE-2022-42003", "maven", "com.fasterxml.jackson.core:jackson-databind", "2.13.4.2", "high", "Resource exhaustion via deep wrapper array nesting in jackson-databind"),
        CVEAdvisoryEntry("CVE-2024-22243", "maven", "org.springframework:spring-webmvc", "6.0.17", "high", "Open Redirect and SSRF via UriComponentsBuilder in Spring Framework"),
        CVEAdvisoryEntry("CVE-2024-22259", "maven", "org.springframework.boot:spring-boot-starter-web", "3.2.4", "high", "UriComponentsBuilder URL parsing vulnerability in Spring Boot Web"),
        CVEAdvisoryEntry("CVE-2022-1471", "maven", "org.yaml:snakeyaml", "2.0", "critical", "Remote Code Execution via Constructor deserialization in SnakeYAML"),
        CVEAdvisoryEntry("CVE-2024-47554", "maven", "commons-io:commons-io", "2.14.0", "high", "Uncontrolled resource consumption in Apache Commons IO XmlStreamReader"),
        CVEAdvisoryEntry("CVE-2024-1597", "maven", "org.postgresql:postgresql", "42.7.2", "critical", "SQL Injection via PreferQueryMode=SIMPLE in pgjdbc"),
        # --- Go (Golang) ---
        CVEAdvisoryEntry("CVE-2023-45288", "golang", "golang.org/x/net", "v0.23.0", "high", "HTTP/2 CONTINUATION flood Denial of Service in golang.org/x/net"),
        CVEAdvisoryEntry("CVE-2023-48795", "golang", "golang.org/x/crypto", "v0.17.0", "medium", "Terrapin SSH prefix truncation vulnerability in golang.org/x/crypto"),
        CVEAdvisoryEntry("CVE-2023-29401", "golang", "github.com/gin-gonic/gin", "v1.9.1", "medium", "Filename header injection in Context.FileAttachment in Gin"),
        CVEAdvisoryEntry("CVE-2023-44487", "golang", "google.golang.org/grpc", "v1.58.3", "high", "HTTP/2 Rapid Reset Denial of Service in gRPC-Go"),
    ]

    def __init__(self, extra_advisories: Optional[List[CVEAdvisoryEntry]] = None) -> None:
        self.advisories: List[CVEAdvisoryEntry] = list(self.BUILTIN_ADVISORIES)
        if extra_advisories:
            self.advisories.extend(extra_advisories)

    def lookup_advisories(self, ecosystem: str, package_name: str, installed_version: str) -> List[CVEAdvisoryEntry]:
        """Find all matching advisories where installed_version is older than fixed_version."""
        if not installed_version or installed_version in ("unknown", "latest", "*"):
            return []

        norm_pkg = normalize_package_name(package_name, ecosystem)
        matches: List[CVEAdvisoryEntry] = []

        for adv in self.advisories:
            if adv.ecosystem != ecosystem:
                continue
            adv_norm = normalize_package_name(adv.package_name, ecosystem)
            # Match full group:artifact or artifact suffix for maven
            pkg_match = adv_norm == norm_pkg or (
                ecosystem == "maven" and ":" not in norm_pkg and adv_norm.endswith(f":{norm_pkg}")
            )
            if not pkg_match:
                continue
            if adv.min_version and is_version_older(installed_version, adv.min_version):
                continue
            if is_version_older(installed_version, adv.fixed_version):
                matches.append(adv)

        return matches

    def query_osv_api(
        self,
        ecosystem: str,
        package_name: str,
        installed_version: str,
        timeout: float = 3.0,
    ) -> List[CVEAdvisoryEntry]:
        """Optionally query the public OSV.dev API for additional vulnerability advisories."""
        osv_eco_map = {
            "npm": "npm",
            "pypi": "PyPI",
            "nuget": "NuGet",
            "maven": "Maven",
            "golang": "Go",
        }
        osv_eco = osv_eco_map.get(ecosystem)
        if not osv_eco or not installed_version or installed_version in ("unknown", "latest"):
            return []

        payload = json.dumps({
            "version": installed_version.lstrip("^~>=<"),
            "package": {"name": package_name, "ecosystem": osv_eco},
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        results: List[CVEAdvisoryEntry] = []
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for vuln in data.get("vulns", []):
                vuln_id = vuln.get("id", "OSV-UNKNOWN")
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                summary = vuln.get("summary") or f"Vulnerability {cve_id} in {package_name}"
                fixed_ver: Optional[str] = None
                for affected in vuln.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for ev in rng.get("events", []):
                            if "fixed" in ev:
                                fixed_ver = ev["fixed"]
                                break
                        if fixed_ver:
                            break
                    if fixed_ver:
                        break
                if fixed_ver:
                    if ecosystem == "golang" and not fixed_ver.startswith("v"):
                        fixed_ver = f"v{fixed_ver}"
                    results.append(
                        CVEAdvisoryEntry(
                            cve_id=cve_id,
                            ecosystem=ecosystem,
                            package_name=package_name,
                            fixed_version=fixed_ver,
                            severity="high",
                            summary=summary,
                        )
                    )
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            pass

        return results

    def scan_target(self, target_dir: Path | str, query_osv: bool = False) -> List[Dict[str, Any]]:
        """Scan all manifest files under target_dir and return actionable CVE findings."""
        root = Path(target_dir).resolve()
        findings: List[Dict[str, Any]] = []
        skip_dirs = {".git", "node_modules", "bin", "obj", "target", "build", "dist", "venv", ".komainu", ".komainu-devsecops"}

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in skip_dirs]
            for filename in sorted(filenames):
                abs_path = Path(dirpath) / filename
                rel_path = str(abs_path.relative_to(root)).replace("\\", "/")

                deps = self._extract_manifest_dependencies_with_lines(abs_path)
                for pkg_name, ver, ecosystem, line_no in deps:
                    matched = self.lookup_advisories(ecosystem, pkg_name, ver)
                    if query_osv:
                        osv_matches = self.query_osv_api(ecosystem, pkg_name, ver)
                        seen_ids = {m.cve_id for m in matched}
                        for om in osv_matches:
                            if om.cve_id not in seen_ids:
                                matched.append(om)

                    if not matched:
                        continue

                    # Pick the highest required fixed_version if multiple CVEs affect the same package
                    best_adv = matched[0]
                    for adv in matched[1:]:
                        if is_version_older(best_adv.fixed_version, adv.fixed_version):
                            best_adv = adv

                    cve_list = ", ".join(dict.fromkeys(m.cve_id for m in matched))
                    findings.append({
                        "finding_id": best_adv.cve_id,
                        "category": "dependency",
                        "cwe": best_adv.cwe,
                        "severity": best_adv.severity,
                        "title": f"{best_adv.summary} ({pkg_name} {ver} -> {best_adv.fixed_version})",
                        "package": pkg_name,
                        "ecosystem": ecosystem,
                        "installed_version": ver,
                        "fixed_version": best_adv.fixed_version,
                        "cves": [m.cve_id for m in matched],
                        "location": {
                            "file": rel_path,
                            "start_line": line_no,
                            "end_line": line_no,
                        },
                        "remediation": f"Upgrade {pkg_name} from {ver} to {best_adv.fixed_version} ({cve_list})",
                        "status": "confirmed",
                    })

        return findings

    def _extract_manifest_dependencies_with_lines(
        self, file_path: Path
    ) -> List[Tuple[str, str, str, int]]:
        """Return list of (package_name, version, ecosystem, line_number) for a manifest file."""
        name = file_path.name
        results: List[Tuple[str, str, str, int]] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return results

        lines = content.splitlines()

        if name == "package.json":
            in_deps_block = False
            brace_depth = 0
            for idx, line in enumerate(lines, start=1):
                if re.search(r'"(?:dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:\s*\{', line):
                    in_deps_block = True
                    brace_depth = 1
                    continue
                if in_deps_block:
                    brace_depth += line.count("{") - line.count("}")
                    if brace_depth <= 0:
                        in_deps_block = False
                        continue
                    m = re.search(r'"([^"]+)"\s*:\s*"[~^>=<]*([0-9][0-9a-zA-Z.\-+]*)"', line)
                    if m:
                        results.append((m.group(1), m.group(2), "npm", idx))

        elif name == "requirements.txt":
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                m = re.match(
                    r"^([a-zA-Z0-9_\-\.]+)(?:\[[^\]]+\])?\s*(?:==|>=|<=|~=|!=)\s*([0-9][0-9a-zA-Z.\-+]*)",
                    stripped,
                )
                if m:
                    results.append((m.group(1), m.group(2), "pypi", idx))

        elif name == "pyproject.toml":
            for idx, line in enumerate(lines, start=1):
                # PEP 621 style: "requests==2.31.0" or "requests>=2.31.0"
                m_pep = re.search(
                    r'["\']([a-zA-Z0-9_\-\.]+)(?:\[[^\]]+\])?\s*(?:==|>=|<=|~=|\^|~)\s*([0-9][0-9a-zA-Z.\-+]*)["\']',
                    line,
                )
                if m_pep:
                    results.append((m_pep.group(1), m_pep.group(2), "pypi", idx))
                    continue
                # Poetry style: requests = "^2.31.0" or requests = { version = "^2.31.0" }
                m_poetry = re.match(
                    r'^\s*([a-zA-Z0-9_\-\.]+)\s*=\s*(?:["\'][~^>=<]*([0-9][0-9a-zA-Z.\-+]*)["\']|\{[^}]*version\s*=\s*["\'][~^>=<]*([0-9][0-9a-zA-Z.\-+]*)["\'])',
                    line,
                )
                if m_poetry and m_poetry.group(1).lower() not in ("python", "version", "target-version"):
                    ver = m_poetry.group(2) or m_poetry.group(3)
                    if ver:
                        results.append((m_poetry.group(1), ver, "pypi", idx))

        elif name.endswith(".csproj"):
            for idx, line in enumerate(lines, start=1):
                m_inline = re.search(
                    r'<PackageReference\b[^>]*\b(?:Include|Update)\s*=\s*"([^"]+)"[^>]*\bVersion\s*=\s*"([^"]+)"',
                    line,
                    re.IGNORECASE,
                )
                if m_inline:
                    results.append((m_inline.group(1), m_inline.group(2), "nuget", idx))

        elif name == "pom.xml":
            # Parse properties map first in case versions use ${property}
            props: Dict[str, Tuple[str, int]] = {}
            for idx, line in enumerate(lines, start=1):
                m_prop = re.search(r"<([a-zA-Z0-9_.\-]+)>([0-9][0-9a-zA-Z.\-+]*)</\1>", line)
                if m_prop and m_prop.group(1) not in ("modelVersion", "version", "source", "target", "release"):
                    props[m_prop.group(1)] = (m_prop.group(2), idx)

            in_dep = False
            group_id = ""
            artifact_id = ""
            for idx, line in enumerate(lines, start=1):
                if "<dependency>" in line:
                    in_dep = True
                    group_id = ""
                    artifact_id = ""
                elif "</dependency>" in line:
                    in_dep = False
                elif in_dep:
                    mg = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", line)
                    if mg:
                        group_id = mg.group(1)
                    ma = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", line)
                    if ma:
                        artifact_id = ma.group(1)
                    mv = re.search(r"<version>\s*([^<\s]+)\s*</version>", line)
                    if mv and artifact_id:
                        ver_raw = mv.group(1)
                        full_pkg = f"{group_id}:{artifact_id}" if group_id else artifact_id
                        if ver_raw.startswith("${") and ver_raw.endswith("}"):
                            prop_name = ver_raw[2:-1]
                            if prop_name in props:
                                results.append((full_pkg, props[prop_name][0], "maven", props[prop_name][1]))
                        else:
                            results.append((full_pkg, ver_raw, "maven", idx))

        elif name in ("build.gradle", "build.gradle.kts"):
            for idx, line in enumerate(lines, start=1):
                m = re.search(
                    r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]\s*\)?",
                    line,
                )
                if m:
                    results.append((f"{m.group(1)}:{m.group(2)}", m.group(3), "maven", idx))

        elif name == "go.mod":
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue
                if stripped.startswith("require "):
                    stripped = stripped[len("require "):].strip()
                m = re.match(r"^([a-zA-Z0-9_\-\./]+)\s+(v[0-9][0-9a-zA-Z.\-+]*)", stripped)
                if m:
                    results.append((m.group(1), m.group(2), "golang", idx))

        elif name == "package-lock.json":
            seen_pkg_lock = set()
            current_pkg: Optional[str] = None
            for idx, line in enumerate(lines, start=1):
                # Match "node_modules/lodash": { or "lodash": {
                m_key = re.search(r'"(?:.*node_modules/)?(@?[a-zA-Z0-9_\-\./]+)"\s*:\s*\{', line)
                if m_key:
                    cand = m_key.group(1)
                    if cand not in ("dependencies", "devDependencies", "packages", "peerDependencies", "optionalDependencies"):
                        current_pkg = cand
                        continue
                if current_pkg:
                    m_ver = re.search(r'"version"\s*:\s*"([0-9][0-9a-zA-Z.\-+]*)"', line)
                    if m_ver:
                        ver = m_ver.group(1)
                        if (current_pkg, ver) not in seen_pkg_lock:
                            seen_pkg_lock.add((current_pkg, ver))
                            results.append((current_pkg, ver, "npm", idx))
                        current_pkg = None
                    elif "}" in line:
                        current_pkg = None

        elif name == "yarn.lock":
            seen_yarn = set()
            current_pkg = None
            for idx, line in enumerate(lines, start=1):
                if not line.startswith(" ") and not line.startswith("#") and "@" in line and line.rstrip().endswith(":"):
                    header = line.strip().rstrip(":").strip('"').strip("'")
                    first_spec = header.split(",")[0].strip().strip('"').strip("'")
                    at_pos = first_spec.rfind("@")
                    if at_pos > 0:
                        current_pkg = first_spec[:at_pos]
                    continue
                if current_pkg:
                    m_ver = re.search(r'^\s+version\s+(?:"([0-9][0-9a-zA-Z.\-+]*)"|:\s*([0-9][0-9a-zA-Z.\-+]*))', line)
                    if m_ver:
                        ver = m_ver.group(1) or m_ver.group(2)
                        if ver and (current_pkg, ver) not in seen_yarn:
                            seen_yarn.add((current_pkg, ver))
                            results.append((current_pkg, ver, "npm", idx))
                        current_pkg = None

        elif name == "Pipfile.lock":
            seen_pipfile = set()
            current_pkg = None
            for idx, line in enumerate(lines, start=1):
                m_key = re.search(r'^\s*"([a-zA-Z0-9_\-\.]+)"\s*:\s*\{', line)
                if m_key:
                    cand = m_key.group(1)
                    if cand not in ("_meta", "default", "develop", "hashes", "sources", "requires", "pipfile-spec"):
                        current_pkg = cand
                    continue
                if current_pkg:
                    m_ver = re.search(r'"version"\s*:\s*"==([0-9][0-9a-zA-Z.\-+]*)"', line)
                    if m_ver:
                        ver = m_ver.group(1)
                        if (current_pkg, ver) not in seen_pipfile:
                            seen_pipfile.add((current_pkg, ver))
                            results.append((current_pkg, ver, "pypi", idx))
                        current_pkg = None
                    elif "}" in line:
                        current_pkg = None

        elif name == "poetry.lock":
            seen_poetry = set()
            current_pkg = None
            for idx, line in enumerate(lines, start=1):
                if line.strip() == "[[package]]":
                    current_pkg = None
                    continue
                m_name = re.match(r'^\s*name\s*=\s*"([^"]+)"', line)
                if m_name:
                    current_pkg = m_name.group(1)
                    continue
                if current_pkg:
                    m_ver = re.match(r'^\s*version\s*=\s*"([0-9][0-9a-zA-Z.\-+]*)"', line)
                    if m_ver:
                        ver = m_ver.group(1)
                        if (current_pkg, ver) not in seen_poetry:
                            seen_poetry.add((current_pkg, ver))
                            results.append((current_pkg, ver, "pypi", idx))
                        current_pkg = None

        elif name == "packages.lock.json":
            seen_nuget_lock = set()
            current_pkg = None
            for idx, line in enumerate(lines, start=1):
                m_key = re.search(r'^\s*"([a-zA-Z0-9_\-\.]+)"\s*:\s*\{', line)
                if m_key:
                    cand = m_key.group(1)
                    if cand.lower() not in ("dependencies", "version") and not cand.startswith("net"):
                        current_pkg = cand
                    continue
                if current_pkg:
                    m_ver = re.search(r'"resolved"\s*:\s*"([0-9][0-9a-zA-Z.\-+]*)"', line)
                    if m_ver:
                        ver = m_ver.group(1)
                        if (current_pkg, ver) not in seen_nuget_lock:
                            seen_nuget_lock.add((current_pkg, ver))
                            results.append((current_pkg, ver, "nuget", idx))
                        current_pkg = None
                    elif "}" in line:
                        current_pkg = None

        elif name == "gradle.lockfile":
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("empty="):
                    continue
                m = re.match(r"^([^:#=]+:[^:#=]+):([0-9][0-9a-zA-Z.\-+]*)=.*$", stripped)
                if m:
                    results.append((m.group(1), m.group(2), "maven", idx))

        elif name == "go.sum":
            seen_gosum = set()
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                m = re.match(r"^([a-zA-Z0-9_\-\./]+)\s+(v[0-9][0-9a-zA-Z.\-+]*?)(?:/go\.mod)?\s+h1:", stripped)
                if m:
                    pkg_mod, ver_mod = m.group(1), m.group(2)
                    if (pkg_mod, ver_mod) not in seen_gosum:
                        seen_gosum.add((pkg_mod, ver_mod))
                        results.append((pkg_mod, ver_mod, "golang", idx))

        return results


class DependencyManifestPatcher:
    """Safely upgrades vulnerable package versions across manifest files while preserving formatting."""

    def __init__(self, catalog: Optional[CVEAdvisoryCatalog] = None) -> None:
        self.catalog = catalog or CVEAdvisoryCatalog()

    def detect_ecosystem(self, file_path: Path | str) -> str:
        """Infer package ecosystem from manifest or lockfile filename."""
        name = Path(file_path).name.lower()
        if name in ("package.json", "package-lock.json", "yarn.lock"):
            return "npm"
        if name in ("requirements.txt", "pyproject.toml", "pipfile.lock", "poetry.lock"):
            return "pypi"
        if name.endswith(".csproj") or name == "packages.lock.json":
            return "nuget"
        if name in ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"):
            return "maven"
        if name in ("go.mod", "go.sum"):
            return "golang"
        return "generic"

    def extract_target_metadata(
        self,
        finding: Dict[str, Any],
        ecosystem: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Extract (package_name, fixed_version) from structured finding fields or message text."""
        pkg = (
            finding.get("package")
            or finding.get("package_name")
            or finding.get("component")
            or finding.get("library")
        )
        fixed = (
            finding.get("fixed_version")
            or finding.get("patched_version")
            or finding.get("target_version")
        )

        # Check nested properties if loaded from SARIF
        props = finding.get("properties") or {}
        if not pkg:
            pkg = props.get("package") or props.get("package_name") or props.get("PkgName")
        if not fixed:
            fixed = props.get("fixed_version") or props.get("FixedVersion")

        # Parse from title, message, or remediation text if not explicitly set
        text_blobs = [
            str(finding.get("title") or ""),
            str(finding.get("remediation") or ""),
            str(finding.get("description") or ""),
        ]
        combined_text = "\n".join(text_blobs)

        if not pkg:
            # Pattern 1: "Package: <name>" (Trivy style)
            m_trivy_pkg = re.search(r"(?i)Package\s*:\s*([@\w\-\./:]+)", combined_text)
            if m_trivy_pkg:
                pkg = m_trivy_pkg.group(1)
            else:
                # Pattern 2: "Upgrade <name> from X to Y" or "(<name> 1.0 -> 1.1)"
                m_upg = re.search(r"(?i)(?:upgrade|update|bump)\s+([@\w\-\./:]+)\s+(?:from\s+[^\s]+\s+)?to\s+v?[0-9]", combined_text)
                if m_upg:
                    pkg = m_upg.group(1)
                else:
                    m_paren = re.search(r"\(([@\w\-\./:]+)\s+v?[0-9][^\s)]*\s*->\s*v?[0-9][^\s)]*\)", combined_text)
                    if m_paren:
                        pkg = m_paren.group(1)

        if not fixed:
            # Pattern 1: "Fixed Version: <ver>" (Trivy style)
            m_trivy_fix = re.search(r"(?i)Fixed\s+Version\s*:\s*(v?[0-9][0-9a-zA-Z.\-+]*)", combined_text)
            if m_trivy_fix:
                fixed = m_trivy_fix.group(1)
            else:
                # Pattern 2: "-> <ver>" or "to <ver>"
                m_arrow = re.search(r"->\s*(v?[0-9][0-9a-zA-Z.\-+]*)", combined_text)
                if m_arrow:
                    fixed = m_arrow.group(1)
                else:
                    m_to = re.search(r"(?i)\bto\s+(v?[0-9][0-9a-zA-Z.\-+]*)", combined_text)
                    if m_to:
                        fixed = m_to.group(1)

        # Fallback: look up CVE ID in built-in catalog
        finding_id = str(finding.get("finding_id") or "")
        if (not pkg or not fixed) and finding_id.startswith("CVE-"):
            for adv in self.catalog.advisories:
                if adv.cve_id == finding_id and (not ecosystem or adv.ecosystem == ecosystem):
                    pkg = pkg or adv.package_name
                    fixed = fixed or adv.fixed_version
                    break

        return pkg, fixed

    def patch_manifest(
        self,
        target_file: Path,
        content: str,
        finding: Dict[str, Any],
    ) -> Tuple[str, DependencyRewriteResult]:
        """Rewrite vulnerable dependency version in manifest content while preserving formatting."""
        fname = target_file.name
        fname_lower = fname.lower()
        ecosystem = finding.get("ecosystem") or self.detect_ecosystem(target_file)
        pkg_name, fixed_version = self.extract_target_metadata(finding, ecosystem)

        if not pkg_name or not fixed_version:
            return content, DependencyRewriteResult(
                package_name=pkg_name or "unknown",
                ecosystem=ecosystem,
                previous_version="",
                fixed_version=fixed_version or "",
                changed=False,
                explanation="Missing package name or fixed version in finding metadata; requires manual remediation.",
            )

        if fname_lower == "package.json":
            return self._patch_package_json(content, pkg_name, fixed_version)
        if fname_lower == "package-lock.json":
            return self._patch_package_lock_json(content, pkg_name, fixed_version)
        if fname_lower == "yarn.lock":
            return self._patch_yarn_lock(content, pkg_name, fixed_version)
        if fname_lower == "requirements.txt":
            return self._patch_requirements_txt(content, pkg_name, fixed_version)
        if fname_lower == "pyproject.toml":
            return self._patch_pyproject_toml(content, pkg_name, fixed_version)
        if fname_lower == "pipfile.lock":
            return self._patch_pipfile_lock(content, pkg_name, fixed_version)
        if fname_lower == "poetry.lock":
            return self._patch_poetry_lock(content, pkg_name, fixed_version)
        if fname_lower.endswith(".csproj"):
            return self._patch_csproj(content, pkg_name, fixed_version)
        if fname_lower == "packages.lock.json":
            return self._patch_packages_lock_json(content, pkg_name, fixed_version)
        if fname_lower == "pom.xml":
            return self._patch_pom_xml(content, pkg_name, fixed_version)
        if fname_lower in ("build.gradle", "build.gradle.kts"):
            return self._patch_build_gradle(content, pkg_name, fixed_version)
        if fname_lower == "gradle.lockfile":
            return self._patch_gradle_lockfile(content, pkg_name, fixed_version)
        if fname_lower == "go.mod":
            return self._patch_go_mod(content, pkg_name, fixed_version)
        if fname_lower == "go.sum":
            return self._patch_go_sum(content, pkg_name, fixed_version)

        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem=ecosystem,
            previous_version="",
            fixed_version=fixed_version,
            changed=False,
            explanation=f"Unsupported manifest file format '{fname}'; requires manual remediation.",
        )

    def _patch_package_json(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        pattern = re.compile(
            rf'("{re.escape(pkg_name)}"\s*:\s*")([~^>=<]*)([0-9][0-9a-zA-Z.\-+]*)(")'
        )
        previous_ver = ""
        preserved_op = ""
        already_safe = False

        def replacer(match: re.Match) -> str:
            nonlocal previous_ver, preserved_op, already_safe
            prefix_quote = match.group(1)
            operator = match.group(2)
            cur_ver = match.group(3)
            suffix_quote = match.group(4)

            if not is_version_older(cur_ver, clean_fixed):
                already_safe = True
                return match.group(0)

            previous_ver = cur_ver
            # Preserve range operator (^, ~, >=); convert < or <= to empty (exact)
            preserved_op = operator if operator in ("^", "~", ">=", "") else ""
            return f"{prefix_quote}{preserved_op}{clean_fixed}{suffix_quote}"

        patched, count = pattern.subn(replacer, content)
        if count > 0 and previous_ver:
            return patched, DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="npm",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                operator_preserved=preserved_op,
                changed=True,
                explanation=f"Upgraded npm package '{pkg_name}' from {preserved_op}{previous_ver} to {preserved_op}{clean_fixed} in package.json.",
            )

        reason = (
            f"Package '{pkg_name}' is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"Package '{pkg_name}' not found in package.json; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="npm",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_requirements_txt(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        norm_target = normalize_package_name(pkg_name, "pypi")
        lines = content.splitlines(keepends=True)
        previous_ver = ""
        preserved_op = ""
        changed = False
        already_safe = False

        req_pattern = re.compile(
            r"^(\s*([a-zA-Z0-9_\-\.]+)(?:\[[^\]]+\])?\s*)(==|>=|~=|<|<=)(\s*)([0-9][0-9a-zA-Z.\-+]*)(.*)$"
        )

        for idx, line in enumerate(lines):
            # Split line ending to preserve \r\n or \n
            line_body = line.rstrip("\r\n")
            line_ending = line[len(line_body):]
            if not line_body.strip() or line_body.lstrip().startswith("#"):
                continue

            m = req_pattern.match(line_body)
            if not m:
                continue

            found_pkg = m.group(2)
            if normalize_package_name(found_pkg, "pypi") != norm_target:
                continue

            prefix_part = m.group(1)
            operator = m.group(3)
            op_space = m.group(4)
            cur_ver = m.group(5)
            trailing = m.group(6)

            if not is_version_older(cur_ver, clean_fixed):
                already_safe = True
                continue

            previous_ver = cur_ver
            preserved_op = operator if operator in ("==", ">=", "~=") else "=="
            lines[idx] = f"{prefix_part}{preserved_op}{op_space}{clean_fixed}{trailing}{line_ending}"
            changed = True

        if changed:
            return "".join(lines), DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="pypi",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                operator_preserved=preserved_op,
                changed=True,
                explanation=f"Upgraded PyPI package '{pkg_name}' from {preserved_op}{previous_ver} to {preserved_op}{clean_fixed} in requirements.txt.",
            )

        reason = (
            f"Package '{pkg_name}' is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"Package '{pkg_name}' not found in requirements.txt; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="pypi",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_pyproject_toml(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        norm_target = normalize_package_name(pkg_name, "pypi")
        lines = content.splitlines(keepends=True)
        previous_ver = ""
        preserved_op = ""
        changed = False
        already_safe = False

        # Match PEP 621 string item e.g. "requests>=2.31.0" or 'requests==2.31.0'
        pep621_re = re.compile(
            r'(["\'])([a-zA-Z0-9_\-\.]+)((?:\[[^\]]+\])?\s*)(==|>=|~=|\^|~|<|<=)(\s*)([0-9][0-9a-zA-Z.\-+]*)(["\'])'
        )
        # Match Poetry key-value e.g. requests = "^2.31.0" or requests = { version = "^2.31.0" }
        poetry_re = re.compile(
            r'^(\s*([a-zA-Z0-9_\-\.]+)\s*=\s*(?:\{[^}]*version\s*=\s*)?["\'])([~^>=<=]*)([0-9][0-9a-zA-Z.\-+]*)(["\'].*)$'
        )

        for idx, line in enumerate(lines):
            line_body = line.rstrip("\r\n")
            line_ending = line[len(line_body):]

            # 1. Try PEP 621 match
            def pep_replacer(m: re.Match) -> str:
                nonlocal previous_ver, preserved_op, changed, already_safe
                q1, found_pkg, extras, op, sp, cur_ver, q2 = m.groups()
                if normalize_package_name(found_pkg, "pypi") != norm_target:
                    return m.group(0)
                if not is_version_older(cur_ver, clean_fixed):
                    already_safe = True
                    return m.group(0)
                previous_ver = cur_ver
                preserved_op = op if op in ("==", ">=", "~=", "^", "~") else ">="
                changed = True
                return f"{q1}{found_pkg}{extras}{preserved_op}{sp}{clean_fixed}{q2}"

            new_body = pep621_re.sub(pep_replacer, line_body)
            if new_body != line_body:
                lines[idx] = new_body + line_ending
                continue

            # 2. Try Poetry match
            m_poet = poetry_re.match(line_body)
            if m_poet and normalize_package_name(m_poet.group(2), "pypi") == norm_target:
                prefix, _, op, cur_ver, suffix = m_poet.groups()
                if not is_version_older(cur_ver, clean_fixed):
                    already_safe = True
                    continue
                previous_ver = cur_ver
                preserved_op = op if op in ("^", "~", "==", ">=", "~=", "") else "^"
                lines[idx] = f"{prefix}{preserved_op}{clean_fixed}{suffix}{line_ending}"
                changed = True

        if changed:
            return "".join(lines), DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="pypi",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                operator_preserved=preserved_op,
                changed=True,
                explanation=f"Upgraded PyPI package '{pkg_name}' from {preserved_op}{previous_ver} to {preserved_op}{clean_fixed} in pyproject.toml.",
            )

        reason = (
            f"Package '{pkg_name}' is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"Package '{pkg_name}' not found in pyproject.toml; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="pypi",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_csproj(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        previous_ver = ""
        already_safe = False

        # Pattern A: Inline attribute <PackageReference Include="Pkg" Version="1.0.0" />
        inline_pattern = re.compile(
            rf'(<PackageReference\b[^>]*\b(?:Include|Update)\s*=\s*"{re.escape(pkg_name)}"[^>]*\bVersion\s*=\s*")([^"]+)(")',
            re.IGNORECASE,
        )

        def inline_replacer(m: re.Match) -> str:
            nonlocal previous_ver, already_safe
            prefix, cur_ver, suffix = m.groups()
            if not is_version_older(cur_ver, clean_fixed):
                already_safe = True
                return m.group(0)
            previous_ver = cur_ver
            return f"{prefix}{clean_fixed}{suffix}"

        patched, count = inline_pattern.subn(inline_replacer, content)
        if count > 0 and previous_ver:
            return patched, DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="nuget",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                changed=True,
                explanation=f"Upgraded NuGet package '{pkg_name}' from {previous_ver} to {clean_fixed} in .csproj.",
            )

        # Pattern B: Child <Version> element inside <PackageReference Include="Pkg">...</PackageReference>
        nested_pattern = re.compile(
            rf'(<PackageReference\b[^>]*\b(?:Include|Update)\s*=\s*"{re.escape(pkg_name)}"[^>]*>.*?<Version>\s*)([^<\s]+)(\s*</Version>.*?</PackageReference>)',
            re.IGNORECASE | re.DOTALL,
        )

        def nested_replacer(m: re.Match) -> str:
            nonlocal previous_ver, already_safe
            prefix, cur_ver, suffix = m.groups()
            if not is_version_older(cur_ver, clean_fixed):
                already_safe = True
                return m.group(0)
            previous_ver = cur_ver
            return f"{prefix}{clean_fixed}{suffix}"

        patched_nested, count_nested = nested_pattern.subn(nested_replacer, content)
        if count_nested > 0 and previous_ver:
            return patched_nested, DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="nuget",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                changed=True,
                explanation=f"Upgraded NuGet package '{pkg_name}' from {previous_ver} to {clean_fixed} in .csproj.",
            )

        reason = (
            f"NuGet package '{pkg_name}' is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"NuGet package '{pkg_name}' not found in .csproj; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="nuget",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_pom_xml(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        if ":" in pkg_name:
            target_group, target_artifact = pkg_name.split(":", 1)
        else:
            target_group, target_artifact = "", pkg_name

        previous_ver = ""
        already_safe = False
        prop_to_update: Optional[str] = None

        dep_block_re = re.compile(r"(<dependency>.*?</dependency>)", re.DOTALL)

        def dep_replacer(m: re.Match) -> str:
            nonlocal previous_ver, already_safe, prop_to_update
            block = m.group(1)
            mg = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", block)
            ma = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", block)
            if not ma:
                return block
            found_group = mg.group(1) if mg else ""
            found_artifact = ma.group(1)

            if found_artifact != target_artifact:
                return block
            if target_group and found_group and found_group != target_group:
                return block

            mv = re.search(r"(<version>\s*)([^<\s]+)(\s*</version>)", block)
            if not mv:
                return block

            cur_ver = mv.group(2)
            if cur_ver.startswith("${") and cur_ver.endswith("}"):
                prop_to_update = cur_ver[2:-1]
                return block

            if not is_version_older(cur_ver, clean_fixed):
                already_safe = True
                return block

            previous_ver = cur_ver
            return block[:mv.start()] + f"{mv.group(1)}{clean_fixed}{mv.group(3)}" + block[mv.end():]

        patched = dep_block_re.sub(dep_replacer, content)

        # If the dependency version uses a Maven property ${prop.version}, update the property definition
        if prop_to_update and not previous_ver:
            prop_re = re.compile(rf"(<{re.escape(prop_to_update)}>\s*)([^<\s]+)(\s*</{re.escape(prop_to_update)}>)")

            def prop_replacer(m: re.Match) -> str:
                nonlocal previous_ver, already_safe
                cur_ver = m.group(2)
                if not is_version_older(cur_ver, clean_fixed):
                    already_safe = True
                    return m.group(0)
                previous_ver = cur_ver
                return f"{m.group(1)}{clean_fixed}{m.group(3)}"

            patched = prop_re.sub(prop_replacer, content)

        if previous_ver and patched != content:
            return patched, DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="maven",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                changed=True,
                explanation=f"Upgraded Maven dependency '{pkg_name}' from {previous_ver} to {clean_fixed} in pom.xml.",
            )

        reason = (
            f"Maven dependency '{pkg_name}' is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"Maven dependency '{pkg_name}' not found in pom.xml; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="maven",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_build_gradle(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        if ":" in pkg_name:
            group_part, artifact_part = pkg_name.split(":", 1)
            coord_prefix = rf"{re.escape(group_part)}:{re.escape(artifact_part)}"
        else:
            coord_prefix = rf"[^:'\"]+:{re.escape(pkg_name)}"

        pattern = re.compile(rf"(['\"](?:{coord_prefix}):)([0-9][0-9a-zA-Z.\-+]*)(['\"])")
        previous_ver = ""
        already_safe = False

        def replacer(m: re.Match) -> str:
            nonlocal previous_ver, already_safe
            prefix, cur_ver, suffix = m.groups()
            if not is_version_older(cur_ver, clean_fixed):
                already_safe = True
                return m.group(0)
            previous_ver = cur_ver
            return f"{prefix}{clean_fixed}{suffix}"

        patched, count = pattern.subn(replacer, content)
        if count > 0 and previous_ver:
            return patched, DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="maven",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                changed=True,
                explanation=f"Upgraded Gradle dependency '{pkg_name}' from {previous_ver} to {clean_fixed}.",
            )

        reason = (
            f"Gradle dependency '{pkg_name}' is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"Gradle dependency '{pkg_name}' not found in build.gradle; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="maven",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_go_mod(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        clean_num = fixed_version.lstrip("vV^~>=<")
        go_fixed = f"v{clean_num}"
        lines = content.splitlines(keepends=True)
        previous_ver = ""
        changed = False
        already_safe = False

        go_line_re = re.compile(
            rf"^(\s*(?:require\s+)?{re.escape(pkg_name)}\s+)(v[0-9][0-9a-zA-Z.\-+]*)(.*)$"
        )

        for idx, line in enumerate(lines):
            line_body = line.rstrip("\r\n")
            line_ending = line[len(line_body):]
            if line_body.lstrip().startswith("//"):
                continue

            m = go_line_re.match(line_body)
            if not m:
                continue

            prefix, cur_ver, suffix = m.groups()
            if not is_version_older(cur_ver, go_fixed):
                already_safe = True
                continue

            previous_ver = cur_ver
            lines[idx] = f"{prefix}{go_fixed}{suffix}{line_ending}"
            changed = True

        if changed:
            return "".join(lines), DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="golang",
                previous_version=previous_ver,
                fixed_version=go_fixed,
                operator_preserved="v",
                changed=True,
                explanation=f"Upgraded Go module '{pkg_name}' from {previous_ver} to {go_fixed} in go.mod.",
            )

        reason = (
            f"Go module '{pkg_name}' is already at or above fixed version {go_fixed}."
            if already_safe
            else f"Go module '{pkg_name}' not found in go.mod; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="golang",
            previous_version=previous_ver,
            fixed_version=go_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_package_lock_json(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        """Update package version and resolved tarball URL in package-lock.json (v1, v2, v3)."""
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        tar_basename = pkg_name.split("/")[-1]
        previous_ver = ""
        already_safe = False
        changed = False

        # 1. Update node_modules/<pkg> and legacy dependencies.<pkg> object blocks
        block_re = re.compile(
            rf'("(?:[^"]*node_modules/)?{re.escape(pkg_name)}"\s*:\s*\{{)(.*?)(\n\s*\}})',
            re.DOTALL,
        )

        def block_replacer(m: re.Match) -> str:
            nonlocal previous_ver, already_safe, changed
            header, body, footer = m.groups()
            ver_match = re.search(r'("version"\s*:\s*")([0-9][0-9a-zA-Z.\-+]*)(")', body)
            if not ver_match:
                return m.group(0)

            cur_ver = ver_match.group(2)
            if not is_version_older(cur_ver, clean_fixed):
                already_safe = True
                return m.group(0)

            previous_ver = cur_ver
            changed = True
            new_body = (
                body[:ver_match.start()]
                + f"{ver_match.group(1)}{clean_fixed}{ver_match.group(3)}"
                + body[ver_match.end():]
            )
            # Update tarball URL in "resolved": ".../<tar_basename>-<old>.tgz"
            new_body = re.sub(
                rf"(/{re.escape(tar_basename)}-)({re.escape(cur_ver)})(\.tgz)",
                rf"\g<1>{clean_fixed}\g<3>",
                new_body,
            )
            return f"{header}{new_body}{footer}"

        patched = block_re.sub(block_replacer, content)

        # 2. Also update root packages[""].dependencies / devDependencies range if present
        spec_re = re.compile(
            rf'("{re.escape(pkg_name)}"\s*:\s*")([~^>=<]*)([0-9][0-9a-zA-Z.\-+]*)(")'
        )

        def spec_replacer(m: re.Match) -> str:
            nonlocal previous_ver, already_safe, changed
            p_quote, op, cur_ver, s_quote = m.groups()
            if not is_version_older(cur_ver, clean_fixed):
                already_safe = True
                return m.group(0)
            if not previous_ver:
                previous_ver = cur_ver
            changed = True
            preserved = op if op in ("^", "~", ">=", "") else ""
            return f"{p_quote}{preserved}{clean_fixed}{s_quote}"

        patched = spec_re.sub(spec_replacer, patched)

        if changed and previous_ver:
            return patched, DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="npm",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                changed=True,
                explanation=f"Upgraded npm lockfile entry '{pkg_name}' from {previous_ver} to {clean_fixed} in package-lock.json.",
            )

        reason = (
            f"Package '{pkg_name}' in package-lock.json is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"Package '{pkg_name}' not found in package-lock.json; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="npm",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_yarn_lock(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        """Update resolved version and tarball URL in yarn.lock (v1 and Berry)."""
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        tar_basename = pkg_name.split("/")[-1]
        lines = content.splitlines(keepends=True)
        in_target_stanza = False
        previous_ver = ""
        already_safe = False
        changed = False

        for idx, line in enumerate(lines):
            line_body = line.rstrip("\r\n")
            line_ending = line[len(line_body):]

            if not line_body.startswith(" ") and not line_body.startswith("#") and line_body.endswith(":"):
                in_target_stanza = bool(
                    re.search(rf'(?:^|["\',\s]){re.escape(pkg_name)}@', line_body)
                )
                continue

            if in_target_stanza:
                m_ver = re.match(
                    r'^(\s+version(?:\s+"|\s*:\s*"?))([0-9][0-9a-zA-Z.\-+]*)(["\']?.*)$',
                    line_body,
                )
                if m_ver:
                    prefix, cur_ver, suffix = m_ver.groups()
                    if not is_version_older(cur_ver, clean_fixed):
                        already_safe = True
                        in_target_stanza = False
                        continue
                    previous_ver = cur_ver
                    lines[idx] = f"{prefix}{clean_fixed}{suffix}{line_ending}"
                    changed = True
                    continue

                if previous_ver and ("resolved " in line_body or "resolution:" in line_body):
                    updated_line = re.sub(
                        rf"({re.escape(tar_basename)}-|@{re.escape(pkg_name)}@npm:)({re.escape(previous_ver)})",
                        rf"\g<1>{clean_fixed}",
                        line_body,
                    )
                    if updated_line != line_body:
                        lines[idx] = updated_line + line_ending

        if changed and previous_ver:
            return "".join(lines), DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="npm",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                changed=True,
                explanation=f"Upgraded Yarn lockfile entry '{pkg_name}' from {previous_ver} to {clean_fixed} in yarn.lock.",
            )

        reason = (
            f"Package '{pkg_name}' in yarn.lock is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"Package '{pkg_name}' not found in yarn.lock; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="npm",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_pipfile_lock(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        """Update pinned ==version in Pipfile.lock."""
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        norm_target = normalize_package_name(pkg_name, "pypi")
        lines = content.splitlines(keepends=True)
        current_pkg: Optional[str] = None
        previous_ver = ""
        already_safe = False
        changed = False

        for idx, line in enumerate(lines):
            line_body = line.rstrip("\r\n")
            line_ending = line[len(line_body):]

            m_key = re.search(r'^\s*"([a-zA-Z0-9_\-\.]+)"\s*:\s*\{', line_body)
            if m_key:
                cand = m_key.group(1)
                if cand not in ("_meta", "default", "develop", "hashes", "sources", "requires", "pipfile-spec"):
                    current_pkg = cand
                continue

            if current_pkg and normalize_package_name(current_pkg, "pypi") == norm_target:
                m_ver = re.search(r'^(\s*"version"\s*:\s*"==)([0-9][0-9a-zA-Z.\-+]+)(".*)$', line_body)
                if m_ver:
                    prefix, cur_ver, suffix = m_ver.groups()
                    if not is_version_older(cur_ver, clean_fixed):
                        already_safe = True
                    else:
                        previous_ver = cur_ver
                        lines[idx] = f"{prefix}{clean_fixed}{suffix}{line_ending}"
                        changed = True
                    current_pkg = None
                elif "}" in line_body:
                    current_pkg = None

        if changed and previous_ver:
            return "".join(lines), DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="pypi",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                operator_preserved="==",
                changed=True,
                explanation=f"Upgraded Pipfile.lock entry '{pkg_name}' from =={previous_ver} to =={clean_fixed}.",
            )

        reason = (
            f"Package '{pkg_name}' in Pipfile.lock is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"Package '{pkg_name}' not found in Pipfile.lock; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="pypi",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_poetry_lock(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        """Update package version inside [[package]] stanza in poetry.lock."""
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        norm_target = normalize_package_name(pkg_name, "pypi")
        lines = content.splitlines(keepends=True)
        in_target_pkg = False
        previous_ver = ""
        already_safe = False
        changed = False

        for idx, line in enumerate(lines):
            line_body = line.rstrip("\r\n")
            line_ending = line[len(line_body):]

            if line_body.strip().startswith("[["):
                in_target_pkg = False
                continue

            m_name = re.match(r'^\s*name\s*=\s*"([^"]+)"', line_body)
            if m_name:
                in_target_pkg = normalize_package_name(m_name.group(1), "pypi") == norm_target
                continue

            if in_target_pkg:
                m_ver = re.match(r'^(\s*version\s*=\s*")([0-9][0-9a-zA-Z.\-+]+)(".*)$', line_body)
                if m_ver:
                    prefix, cur_ver, suffix = m_ver.groups()
                    if not is_version_older(cur_ver, clean_fixed):
                        already_safe = True
                    else:
                        previous_ver = cur_ver
                        lines[idx] = f"{prefix}{clean_fixed}{suffix}{line_ending}"
                        changed = True
                    in_target_pkg = False

        if changed and previous_ver:
            return "".join(lines), DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="pypi",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                changed=True,
                explanation=f"Upgraded poetry.lock entry '{pkg_name}' from {previous_ver} to {clean_fixed}.",
            )

        reason = (
            f"Package '{pkg_name}' in poetry.lock is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"Package '{pkg_name}' not found in poetry.lock; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="pypi",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_packages_lock_json(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        """Update resolved and requested versions in NuGet packages.lock.json."""
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        block_re = re.compile(
            rf'("{re.escape(pkg_name)}"\s*:\s*\{{)(.*?)(\n\s*\}})',
            re.IGNORECASE | re.DOTALL,
        )
        previous_ver = ""
        already_safe = False
        changed = False

        def replacer(m: re.Match) -> str:
            nonlocal previous_ver, already_safe, changed
            header, body, footer = m.groups()
            res_match = re.search(r'("resolved"\s*:\s*")([0-9][0-9a-zA-Z.\-+]*)(")', body)
            if not res_match:
                return m.group(0)

            cur_ver = res_match.group(2)
            if not is_version_older(cur_ver, clean_fixed):
                already_safe = True
                return m.group(0)

            previous_ver = cur_ver
            changed = True
            new_body = (
                body[:res_match.start()]
                + f"{res_match.group(1)}{clean_fixed}{res_match.group(3)}"
                + body[res_match.end():]
            )
            new_body = re.sub(
                rf'("requested"\s*:\s*"\[?){re.escape(cur_ver)}',
                rf"\g<1>{clean_fixed}",
                new_body,
            )
            return f"{header}{new_body}{footer}"

        patched = block_re.sub(replacer, content)
        if changed and previous_ver:
            return patched, DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="nuget",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                changed=True,
                explanation=f"Upgraded NuGet lockfile entry '{pkg_name}' from {previous_ver} to {clean_fixed} in packages.lock.json.",
            )

        reason = (
            f"NuGet package '{pkg_name}' in packages.lock.json is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"NuGet package '{pkg_name}' not found in packages.lock.json; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="nuget",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_gradle_lockfile(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        """Update locked coordinate version in gradle.lockfile."""
        clean_fixed = fixed_version.lstrip("vV^~>=<")
        if ":" in pkg_name:
            group_part, artifact_part = pkg_name.split(":", 1)
            coord_prefix = rf"{re.escape(group_part)}:{re.escape(artifact_part)}"
        else:
            coord_prefix = rf"[^:#=]+:{re.escape(pkg_name)}"

        lines = content.splitlines(keepends=True)
        line_re = re.compile(rf"^({coord_prefix}:)([0-9][0-9a-zA-Z.\-+]*)(=.*)$")
        previous_ver = ""
        already_safe = False
        changed = False

        for idx, line in enumerate(lines):
            line_body = line.rstrip("\r\n")
            line_ending = line[len(line_body):]
            m = line_re.match(line_body)
            if not m:
                continue
            prefix, cur_ver, suffix = m.groups()
            if not is_version_older(cur_ver, clean_fixed):
                already_safe = True
                continue
            previous_ver = cur_ver
            lines[idx] = f"{prefix}{clean_fixed}{suffix}{line_ending}"
            changed = True

        if changed and previous_ver:
            return "".join(lines), DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="maven",
                previous_version=previous_ver,
                fixed_version=clean_fixed,
                changed=True,
                explanation=f"Upgraded Gradle lockfile entry '{pkg_name}' from {previous_ver} to {clean_fixed} in gradle.lockfile.",
            )

        reason = (
            f"Gradle lockfile entry '{pkg_name}' is already at or above fixed version {clean_fixed}."
            if already_safe
            else f"Gradle lockfile entry '{pkg_name}' not found in gradle.lockfile; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="maven",
            previous_version=previous_ver,
            fixed_version=clean_fixed,
            changed=False,
            explanation=reason,
        )

    def _patch_go_sum(
        self, content: str, pkg_name: str, fixed_version: str
    ) -> Tuple[str, DependencyRewriteResult]:
        """Update Go module version entries (including /go.mod lines) in go.sum."""
        clean_num = fixed_version.lstrip("vV^~>=<")
        go_fixed = f"v{clean_num}"
        lines = content.splitlines(keepends=True)
        gosum_re = re.compile(
            rf"^(\s*{re.escape(pkg_name)}\s+)(v[0-9][0-9a-zA-Z.\-+]*?)((?:/go\.mod)?\s+h1:.*)$"
        )
        previous_ver = ""
        already_safe = False
        changed = False

        for idx, line in enumerate(lines):
            line_body = line.rstrip("\r\n")
            line_ending = line[len(line_body):]
            m = gosum_re.match(line_body)
            if not m:
                continue
            prefix, cur_ver, suffix = m.groups()
            if not is_version_older(cur_ver, go_fixed):
                already_safe = True
                continue
            previous_ver = cur_ver
            lines[idx] = f"{prefix}{go_fixed}{suffix}{line_ending}"
            changed = True

        if changed and previous_ver:
            return "".join(lines), DependencyRewriteResult(
                package_name=pkg_name,
                ecosystem="golang",
                previous_version=previous_ver,
                fixed_version=go_fixed,
                operator_preserved="v",
                changed=True,
                explanation=f"Upgraded Go checksum entry '{pkg_name}' from {previous_ver} to {go_fixed} in go.sum.",
            )

        reason = (
            f"Go module '{pkg_name}' in go.sum is already at or above fixed version {go_fixed}."
            if already_safe
            else f"Go module '{pkg_name}' not found in go.sum; requires manual remediation."
        )
        return content, DependencyRewriteResult(
            package_name=pkg_name,
            ecosystem="golang",
            previous_version=previous_ver,
            fixed_version=go_fixed,
            changed=False,
            explanation=reason,
        )
