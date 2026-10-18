# macguard-audit

One engine (`Core/`) serves the GUI, this CLI and the TUI. Build: `xcodegen generate && xcodebuild -scheme macguard-audit build`.

| Command | Purpose |
|---|---|
| `scan <path> [--format text\|json] [--sha256 H] [--team ID] [--bundle ID] [--name T] [--recursive]` | Audit one item |
| `formats` | Supported formats and depth |
| `update-rules [--yes] [--format json]` | Download, verify, install signed rules |
| `verify-rules [--format json]` | Re-verify installed rules |
| `rules-status [--format json]` | Installed rules, verifier, trust state |
| `hash`, `signature`, `identity`, `explain` | Small helpers |
| `tui` | Interactive explorer (needs a terminal) |

Exit codes: 0 no confirmed failure (not a safety guarantee) · 2 a check failed · 3 bad arguments/path · 4 evidence or capability unavailable.

## JSON schema (schemaVersion 1)
`scan`: `{schemaVersion, tool, version, results:[{schemaVersion, kind, sha256, coverage, file, timestamp, findings:[{title, detail, state, weight}], score, blockers, evidenceURL, assessmentNote}]}`
`state` is one of `passed|warning|failed|unknown`. `unknown` never means safe. Finding order and titles are stable within a schema version; new fields may be added, existing ones are not renamed or removed without bumping `schemaVersion`.
`verify-rules`: `{schemaVersion, ok, files, rulesRoot, logSize, error}`. `update-rules`: `{schemaVersion, ok, updated, message}`.
`rules-status`: `{schemaVersion, installedFiles, verifiedRelease, rulesRoot, logSize, trustedLogSize, sigstoreVerifier, sigstoreDetail, yaraEngine, note}`.
