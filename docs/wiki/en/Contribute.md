# Contribute

[Home](EN-Home) · [YARA Channel](EN-YARA-Channel) · [Limits](EN-YARA-Limits) · [Glossary](EN-Glossary)

## In 30 seconds

You can help by running the tests, proposing a change as a pull request, or reporting a bug as an issue. Two things are **not** in place yet and this page does not pretend otherwise: the repository has no license file, and the security reporting channel is planned (to be defined by the maintainer). Never post the technical details of a vulnerability in a public issue. {{ev:EV-YC-82}} {{ev:EV-YC-81}}

## Check it yourself: run the tests

Only commands that exist in the repository today:

```
python3 -m unittest discover -s tests
python3 -m unittest tests.test_tlog
```

- The first line is the Python suite that CI runs on every pull request. CI installs the `yara` engine first and `cosign`, because `tests/test_verify_public_release.py` verifies the real published release (network access and a GitHub token are involved). Without them some tests will fail or be unable to run; that is an environment gap, not a result to ignore {{ev:EV-YC-88}}.
- The second line runs one test module; it is a quick way to work on one area. `tests.test_tlog` passed when this page was written; the number of tests changes with the code, so none is quoted.
- The review-service tests also run in CI with Node 24; their commands are in that service's `package.json`. {{ev:EV-YC-88}}
- `scripts/web_check.sh [site-dir] [mode]` checks the public pages in headless Chrome and needs a built site. The README also mentions `tests/tui_pty_check.py` and the Xcode scheme `DMGTrustAuditor`; they were not run for this page.

## Propose a change

1. Fork or branch, make one focused change and open a **pull request** against `main`. Do not push to `main` directly.
2. CI (`ci.yml`) runs on pull requests: the Python suite and the review-service tests. Run them first.
3. `.github/CODEOWNERS` names `@MacGuard` as owner of the sensitive paths (workflows, `config/`, `scripts/`, `tests/`, the review-service code, the sources docs) {{ev:EV-YC-86}}.
4. For wiki pages, follow the process in [docs/wiki/README.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs/wiki/README.md): the pages are generated from `docs/wiki/`, and nothing is published automatically.

**About branch protection.** Hardening of `main` (review rules before merging) is planned. {{ev:EV-YC-84}}

## Report a bug or ask for a feature

Open an [issue](https://github.com/MacGuard/macguard-yara-channel/issues). Issue templates are **not yet in the repository** {{ev:EV-YC-83}}. Until then, say what you did, what you expected, what happened, and the commit or release tag. Do not paste secrets, tokens or private data.

## Report a vulnerability

Security reporting channel: **planned**. The way to report a vulnerability will be defined by the maintainer, and no address or form is offered here. **Do not post technical details of a vulnerability in a public issue or pull request.** {{ev:EV-YC-82}}

## Licenses and attributions

- **This repository has no LICENSE file today.** This wiki therefore grants no permission to reuse the code {{ev:EV-YC-81}}.
- **The YARA rules come from third parties** (`Neo23x0/signature-base` and `Yara-Rules/rules`) under their own licenses, which stay with each source. `config/policy.json` records what the project expects (Detection Rule License for the first, GPL-2.0 for the second) and `scripts/licensing.py` compares it with what GitHub reports and the LICENSE text on every run; a mismatch quarantines every file of that source. That is an internal check, not legal advice: read each source's license and do not assume the rules are reusable. This project does not claim copyright over downloaded rules, and the conditions for redistributing them are pending legal review {{ev:EV-YC-85}}.
- The vendored Mermaid library keeps its own notice in `web/vendor/mermaid-LICENSE.txt` {{ev:EV-YC-87}}.
- **Wiki text and diagrams:** license pending the owner's decision.

## Limits

This page describes the repository as it was read, not what the owner may decide next. The test commands were checked to exist; only `tests.test_tlog` and `tests.test_licensing` were run for this page, not the whole suite.

## State

| Capability | State |
|---|---|
| Pull requests with CI (Python suite, review-service tests) | operational {{ev:EV-YC-88}} |
| Branch protection hardening for `main` | planned {{ev:EV-YC-84}} |
| Issue templates | planned (not in the repository) {{ev:EV-YC-83}} |
| Security reporting channel | planned {{ev:EV-YC-82}} |
| Repository license file | absent {{ev:EV-YC-81}} |
