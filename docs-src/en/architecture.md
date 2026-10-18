---
title: Architecture
summary: The components of the channel and how they connect end to end.
---
## Overview

The flow has two halves: a private pipeline that decides what is published and a signed public chain anyone can verify. The decision point is `decide.py`: nothing reaches signing without going through it.

{{diagram:architecture}}

## Components

| Component | What it does | Where |
|---|---|---|
| `daily.yml` | Daily 03:17 UTC or manual run: collects, classifies, measures, decides and requests publication. | `.github/workflows/daily.yml` |
| `publish.yml` | Signs and publishes the release; environment `stable-signing-auto` when `AUTO_PUBLISH=true`, otherwise `stable-signing` with a human approver. | `.github/workflows/publish.yml` |
| `site.yml` | Builds and verifies the site, deploys it and checks the public URL. | `.github/workflows/site.yml` |
| Servicio de cuarentena | Private store and review panel (Cloudflare Worker + D1). | `admin/worker/` |
| MacGuard | GUI, TUI and CLI sharing one engine. | `DMGTrustAuditor/DMGTrustAuditor/Core/` |

> **CURRENT** The quarantine service is implemented and tested against a local development server, but it is **not deployed** in production: Cloudflare Workers/D1 credentials and a GitHub OAuth app are missing. Meanwhile quarantine is applied inside the pipeline and only what passes every automatic check is published.

## Trust boundaries

{{diagram:trust-boundaries}}

Sources are untrusted input. Details about unpublished rules (names, findings, content) never leave the private job except towards the private service; public artifacts, logs and the site carry counts only.
