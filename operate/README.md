# Komainu Operate: Continuous Security Verification Pipeline

Part of Boilerplate 1 (Deliverable B1-D5).

This directory provides CI/CD components for automated security verification, preventing BOLA/IDOR and injection regressions from entering production.

---

## Capabilities

1. **Cross-User Authorization Test Runner (`cross-user-tester/runner.py`)**:
   - Executes multi-method security tests (`GET`, `PUT`, `DELETE`) simulating cross-user access attempts (Persona B accessing Persona A's resources).
   - Invariant: Endpoints protected by Komainu D1 return **HTTP 404 Not Found**. Any `2xx` response is flagged as a BOLA breach (CWE-639 / CWE-284) and fails the pipeline (exit code 1).
   - Standard library only (Python 3.8+).

2. **LSA-to-SARIF Converter (`lsa-sarif/lsa_to_sarif.py`)**:
   - Converts LSA audit output (`findings.json`) into OASIS SARIF v2.1.0 format.
   - Uploadable to GitHub Code Scanning and GitLab Security Dashboard for inline PR/MR annotations.

3. **CI/CD Templates (`ci/`)**:
   - `github/cross-user-authz.yml`: Reusable GitHub Actions workflow.
   - `gitlab/cross-user-authz.gitlab-ci.yml`: GitLab CI security template.

---

## Usage

### 1. Run Cross-User Tests Locally

```bash
# Start mock or actual application server
python3 operate/cross-user-tester/mock_test_server.py 8089 &

# Auto-test 3 CRUD operations on a resource
python3 operate/cross-user-tester/runner.py \
  --base-url http://127.0.0.1:8089 \
  --auto-crud-path "/api/orders/{id}" \
  --resource-id "1" \
  --attacker-token "token-user-b"
```

### 2. Run Test Suite from Config

```bash
python3 operate/cross-user-tester/runner.py \
  --base-url http://127.0.0.1:8089 \
  --config operate/tests/test_suite.json \
  --output test-report.json
```

### 3. Convert LSA Findings to SARIF

```bash
python3 operate/lsa-sarif/lsa_to_sarif.py \
  --input findings.json \
  --output komainu-lsa.sarif
```
