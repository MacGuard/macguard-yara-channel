# Contribute

[Home](EN-Home) · [YARA Channel](EN-YARA-Channel) · [Limits](EN-YARA-Limits) · [Glossary](EN-Glossary)

## In 30 seconds

You can help by running the tests, proposing a change as a pull request, or reporting a bug as an issue. Two things are **not** in place yet and this page does not pretend otherwise: there is no private channel for reporting vulnerabilities, and the repository has no licence file. Never post a vulnerability in a public issue. {{ev:EV-YC-82}} {{ev:EV-YC-81}}

## Check it yourself: run the tests

Only commands that exist in the repository today:

```
python3 -m unittest discover -s tests
python3 -m unittest tests.test_tlog
cd admin/worker
npm ci --no-audit --no-fund
npm test
npm run test:runtime
```

- The first line is the Python suite that CI runs on every pull request. CI installs the `yara` engine first and `cosign`, because `tests/test_verify_public_release.py` verifies the real published release (network access and a GitHub token are involved). Without them some tests will fail or be unable to run; that is an environment gap, not a result to ignore {{ev:EV-YC-88}}.
- The second line runs one test module; it is a quick way to work on one area. `tests.test_tlog` ran with all 16 tests passing when this page was written.
- The `admin/worker` lines are the review service tests that CI runs with Node 24: `npm test` (service tests) and `npm run test:runtime` (the service on workerd with a real D1, GitHub faked). `npm run test:ui` also exists in `package.json`; CI does not run it {{ev:EV-YC-88}}.
- `scripts/web_check.sh [site-dir] [mode]` checks the public pages in headless Chrome and needs a built site. The README also mentions `tests/tui_pty_check.py` and the Xcode scheme `DMGTrustAuditor`; they were not run for this page.

## Propose a change

1. Fork or branch, make one focused change and open a **pull request** against `main`. Do not push to `main` directly.
2. CI (`ci.yml`) runs on pull requests: the Python suite and the review-service tests. Run them first.
3. `.github/CODEOWNERS` names `@MacGuard` for the sensitive paths (workflows, `config/`, `scripts/`, `tests/`, the Worker code and migrations, the sources docs). It takes effect only if a repository ruleset requires code-owner review {{ev:EV-YC-86}}.
4. For wiki pages, follow the process in [docs/wiki/README.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs/wiki/README.md): the pages are generated from `docs/wiki/`, and nothing is published automatically.

**About branch protection.** `main` is meant to be protected. A proposal for it exists in [docs/audit/repo-hardening](https://github.com/MacGuard/macguard-yara-channel/tree/main/docs/audit/repo-hardening) (rulesets plus an owner runbook); its runbook states that nothing in it had been run. This page does not claim the protection is applied: check the repository settings before relying on it {{ev:EV-YC-84}}.

## Report a bug or ask for a feature

Open an [issue](https://github.com/MacGuard/macguard-yara-channel/issues). Issue templates are being prepared in another work item and are **not yet in the repository** {{ev:EV-YC-83}}. Until then, say what you did, what you expected, what happened, and the commit or release tag. Do not paste secrets, tokens or private data.

## Report a vulnerability

The repository has no `SECURITY.md`, and GitHub's private vulnerability reporting is currently disabled. A private channel is therefore **PENDING**: no address or form is offered here and none will be invented. **Do not post a vulnerability in a public issue or pull request.** Until the channel exists, an issue may say only that you have a security matter to report, without technical detail, so the owner can arrange a private route {{ev:EV-YC-82}}.

## Licences and attributions

- **This repository has no LICENSE file today.** This wiki therefore grants no permission to reuse the code {{ev:EV-YC-81}}.
- **The YARA rules come from third parties** (`Neo23x0/signature-base` and `Yara-Rules/rules`) under their own licences, which stay with each source. `config/policy.json` records what the project expects (Detection Rule License for the first, GPL-2.0 for the second) and `scripts/licensing.py` compares it with what GitHub reports and the LICENSE text on every run; a mismatch quarantines every file of that source. That is an internal check, not legal advice: read each source's licence and do not assume the rules are reusable {{ev:EV-YC-85}}.
- The vendored Mermaid library keeps its own notice in `web/vendor/mermaid-LICENSE.txt` {{ev:EV-YC-87}}.
- **Wiki text and diagrams:** licence pending the owner's decision.

## Limits

This page describes the repository as it was read, not what the owner may decide next. The test commands were checked to exist; only `tests.test_tlog` and `tests.test_licensing` were run for this page, not the whole suite.

## State

| Capability | State |
|---|---|
| Pull requests with CI (Python suite, review-service tests) | operational {{ev:EV-YC-88}} |
| Protection of `main` by rulesets | planned (proposal in `docs/audit/repo-hardening`) {{ev:EV-YC-84}} |
| Issue templates | planned (not in the repository) {{ev:EV-YC-83}} |
| Private vulnerability reporting channel | planned (pending; reporting disabled, no `SECURITY.md`) {{ev:EV-YC-82}} |
| Repository licence file | absent {{ev:EV-YC-81}} |
