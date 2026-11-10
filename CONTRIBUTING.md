# Contributing to Komagu

Thank you for helping improve Komagu. This repository is public, so never include client names, client code, credentials, or other confidential details in issues, commits, pull requests, or test fixtures.

## Start from an issue

All work is tracked in [`hoanghainh1188/komagu`](https://github.com/hoanghainh1188/komagu/issues) and on Project Board #6. Open an issue, or comment on an existing one, before you start.

## Branches

Create a branch from `main` named `<issue-number>-<short-kebab-description>`, for example `365-pilot-claims-and-contributing`. External contributors can use the same naming in a fork.

Direct pushes to `main` are blocked on the server. To get the same check locally, run:

```bash
git config core.hooksPath .githooks
```

## Pull requests

- Target `main` and include `Closes #N` in the description.
- Use a conventional commit style title, such as `fix(pilot): ...` or `docs: ...`. Pull requests are squash-merged.
- All 6 CI status checks must pass before merging.
- Maintainers move the Project #6 item through *In progress*, *In review*, and *Done*.

## Tests

Run the suites that match your change.

LSA self-tests:

```bash
python3 assess/lsa/tests/run_tests.py
```

Operate tests (CLI, cross-user tester, npm package):

```bash
python3 -m unittest discover -s operate/tests -p "test_*.py"
```

```bash
npm test
```

Remediate modules, when you touch that language:

```bash
dotnet test remediate/authz/dotnet/tests/Komagu.Security.Authorization.Tests/Komagu.Security.Authorization.Tests.csproj
```

```bash
(cd remediate/authz/golang && go test ./...)
```

```bash
(cd remediate/authz/spring && gradle test)
```

## Project rules

- Keep LSA prompts runtime-neutral and LSA scripts Python 3.8+ standard-library-only.
- Keep `contracts/` changes schema-compliant.
- The LSA version is in `assess/lsa/VERSION`. The CLI and npm package version is in `package.json`.
- Mark effort and ROI figures as a target, a modeled estimate, or an internal result. Only a pilot on a real system may supply numbers shown to clients.

## License

Komagu is licensed under the [Apache License 2.0](LICENSE). Unless you state otherwise, any contribution you intentionally submit for inclusion is licensed under Apache-2.0 without additional terms or conditions, as described in section 5 of the license. Submit only work you have the right to contribute.
