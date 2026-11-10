# Delivery Assets

Internal delivery playbooks, report templates, pilot configuration profiles, and timesheet tracking metrics.

| Path | Description |
|---|---|
| [`pilot/timesheet-template.csv`](pilot/timesheet-template.csv) | Standardized CSV timesheet tracking template using the 4 workstream tags defined in ADR-0005 (`[PILOT-LSA]`, `[PILOT-GATEWAY]`, `[PILOT-REMEDIATE]`, `[PILOT-TEST-CI]`). |
| [`pilot/pilot-config.sample.json`](pilot/pilot-config.sample.json) | AMS pilot profile (Java legacy): filtered source copy, approval and deletion-report status, hosting options A (on-prem) and B (Japan-region cloud), headless-only execution, ADR-0005 baseline formula. Steps: [`docs/pilot-execution-runbook.md`](../docs/pilot-execution-runbook.md). |
| [`pilot/ams-exclude.sample.txt`](pilot/ams-exclude.sample.txt) | Starting exclude list for the filtered source copy of a Java system (runbook W9-2). Copy it outside the repository and agree the final list with the client. |
| [`pilot/data-deletion-report.template.md`](pilot/data-deletion-report.template.md) | Bilingual JA/EN deletion record for approval letter §3-6 and runbook W12-3. |

## Real pilot data

This repository is public. Real client configuration, source file lists, canary strings and outputs stay in the secure pilot directory (runbook W9-1). `pilot/pilot-config.json`, `pilot/audit-out/` and `pilot/timesheet-pilot.csv` are records of the internal fallback pilot only.

`.gitignore` covers the usual working file names, and `.githooks/pre-push` blocks real configuration or outputs on the way out. A deliberate edit of those fallback records needs `KOMAGU_ALLOW_FALLBACK_EDIT=1` for that push. Enable the hook once per clone: `git config core.hooksPath .githooks`. Run `komagu leak-check` on outputs before they leave the team (runbook §9).
