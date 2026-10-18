---
title: Overview
summary: What the MacGuard YARA rules channel is, what it guarantees and what it does not.
---
## What it is

The channel collects public YARA rules, validates them, signs a **complete** rule set with Sigstore (no stored key), publishes it as a GitHub Release, records every step in a Merkle transparency log and serves the catalog on GitHub Pages (with Cloudflare Pages as a mirror). The MacGuard apps (GUI, TUI and CLI) install only releases they can verify.

It is an independent project: it is not affiliated with Nextron Systems, VirusTotal or the YARA rules community, and those sources neither sign nor endorse these releases.

## The latest release

Tag [`{{release.tag}}`]({{release.url}}), published {{release.date}}: {{release.files}} rule files and {{release.yara_rules}} YARA rules. Package of {{release.package_bytes}} bytes with SHA-256 `{{release.package_sha256}}`. Merkle root of the rules (`rules_root`): `{{release.rules_root}}`.

These figures are read from the real release files when this documentation is built; if they change, the page is regenerated.

## What it guarantees

- Everything published passed static classification and the dynamic test before being signed.
- Every release is the full current set: it installs on its own, without earlier releases.
- The manifest and the log checkpoint are signed with the identity of the `publish.yml` workflow on the `main` branch of this repository.
- Anyone can check it without trusting this site: see [Verification](page:verification).

## What it does not guarantee

- "Validated" means the YARA compiler accepted the file and it passed the tests described; it does not mean it detects well.
- There are no SLSA or in-toto attestations: only Sigstore signatures of blobs (`manifest.json` and the checkpoint).
- Licence review of upstream rules is not automated beyond checking the expected licence marker.
- There is no download telemetry: charts show what the pipeline observed, not users.

> **NOTE** Every statement in this documentation is marked **CURRENT** (exists and has been tested) or **PROPOSED** (designed, not implemented). Known defects are in [Limits and pending work](page:limits).
