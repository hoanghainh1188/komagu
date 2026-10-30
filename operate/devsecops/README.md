# Komagu DevSecOps, SCA & SBOM Supply Chain Security Pipeline (Boilerplate 5)

## 1. Overview
Boilerplate 5 delivers an automated **DevSecOps, SCA & Software Bill of Materials (SBOM)** pipeline designed to prevent vulnerable open-source dependencies, leaked credentials, insecure containers, and compliance violations from reaching production unnoticed.

### Core Capabilities
1. **SAST (Static Application Security Testing)**: Orchestrates Semgrep rulesets with fallback to Komagu native AST analyzers.
2. **Secret Detection**: High-entropy token and credential scanning integrating Gitleaks and native regex detection (AWS keys, GitHub tokens, Slack tokens, private keys).
3. **SCA (Software Composition Analysis)**: Automated dependency vulnerability scanning with Trivy and native manifest parsing.
4. **SBOM Compliance**: Generates compliant SBOM documents according to **CycloneDX v1.5 JSON** (OWASP) and **SPDX v2.3 JSON** (ISO/IEC 5962:2021) across 5 major language ecosystems.
5. **Container Image & Dockerfile Scanning**: Detects root user execution, unpinned `:latest` tags, and insecure remote downloads.
6. **Unified OASIS SARIF v2.1.0 Aggregation**: Merges and deduplicates multi-tool findings into a single SARIF document directly uploaded to GitHub Security Tab or GitLab Security Dashboard.

---

## 2. CLI Usage

### A. Run Full DevSecOps Pipeline
```bash
# Scan repository and generate SARIF + SBOMs in .komagu-devsecops/
komagu devsecops run .

# Specify custom output directory and application metadata
komagu devsecops run ./my-app -o ./security-reports --app-name "PaymentPortal" --app-version "2.4.0"
```

### B. Generate SBOM
```bash
# CycloneDX v1.5 JSON
komagu devsecops sbom . --format cyclonedx -o ./cyclonedx-sbom.json

# SPDX v2.3 JSON
komagu devsecops sbom . --format spdx -o ./spdx-sbom.json
```

### C. Merge Multi-Source SARIF Reports
```bash
komagu devsecops merge-sarif --inputs sast.sarif secrets.sarif sca.sarif -o unified-gate.sarif
```

---

## 3. CI/CD Integration

### GitHub Actions
Reference the reusable workflow from your repository workflows:
```yaml
name: Security Gate
on: [pull_request, push]

jobs:
  devsecops:
    uses: hoanghainh1188/komagu/.github/workflows/reusable-devsecops.yml@main
    with:
      target-path: "."
      app-name: "EnterpriseService"
      enable-sast: true
      enable-secrets: true
      enable-sca: true
      enable-sbom: true
```

### GitLab CI
Include the template in `.gitlab-ci.yml`:
```yaml
include:
  - local: 'operate/ci/gitlab/devsecops-pipeline.gitlab-ci.yml'
```
