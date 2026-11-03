# Delivery Assets

Internal delivery playbooks, report templates, pilot configuration profiles, and timesheet tracking metrics.

| Path | Description |
|---|---|
| [`pilot/timesheet-template.csv`](pilot/timesheet-template.csv) | Standardized CSV timesheet tracking template using the 4 workstream tags defined in ADR-0005 (`[PILOT-LSA]`, `[PILOT-GATEWAY]`, `[PILOT-REMEDIATE]`, `[PILOT-TEST-CI]`). |
| [`pilot/pilot-config.sample.json`](pilot/pilot-config.sample.json) | AMS pilot profile (Java legacy): filtered source copy, approval and deletion-report status, hosting options A (on-prem) and B (Japan-region cloud), headless-only execution, ADR-0005 baseline formula. Steps: [`docs/pilot-execution-runbook.md`](../docs/pilot-execution-runbook.md). |
