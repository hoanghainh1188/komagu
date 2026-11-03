# Pilot audit output (archived, 2026-10-18)

This folder is the signed-off LSA audit of the D6 Member Portal pilot
([#76](https://github.com/hoanghainh1188/komagu/issues/76)). It was produced by
LSA kit 0.2.1, before the project was renamed from Komainu to Komagu
([ADR-0007](../../../docs/adr/0007-rename-to-komagu.md)).

The files are kept exactly as they were generated and reviewed. They still use
the old name in these places:

- the product name in report titles and the review log ("Komainu LSA Kit"),
- source paths of the scanned code at that time
  (`backend-spring/src/main/kotlin/io/komainu/portal/...`, now `io/komagu/portal`),
- class names in finding evidence (`KomainuSecurityManager`, now `KomaguSecurityManager`).

Why they are not renamed or regenerated:

- **Evidence integrity.** Person B signed off these 8 findings in
  [`review-log.md`](review-log.md). If the text is edited afterwards, the archive
  no longer matches what was reviewed. Rewritten source paths would also point at
  line numbers in code that has changed since then.
- **Regeneration does not reproduce the numbers.** A Tier 1 run today
  (`./bin/komagu scan examples/member-portal`) reports 0 findings. The code is
  remediated, and the original findings came from the Tier 2 AI audit plus human
  review. A new run would replace the 8 accepted findings quoted in
  [`pilot-final-report.md`](../pilot-final-report.md) and
  [`remediation-verification.md`](../remediation-verification.md).

To get a current scan, write it to a new folder. Do not overwrite this one.
