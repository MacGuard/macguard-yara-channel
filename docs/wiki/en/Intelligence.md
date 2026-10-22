# Security Intelligence: sources, alerts and subscriptions

[Home](EN-Home) · [Global roadmap](EN-Roadmap) · [YARA Sources](EN-YARA-Sources) · [YARA Channel](EN-YARA-Channel)

## In 30 seconds

Security Intelligence is the part of MacGuard that gathers public information about vulnerabilities and rule updates, checks it, and lets people **subscribe** to the parts that matter to them by country, sector, technology and severity. Today most of it is **built and tested but not published**: the code works against the real feeds of CISA, ENISA and CERT-EU, yet nothing from those sources is redistributed until their reuse terms are cleared and the owner confirms {{ev:EV-SI-01}}.

## An everyday example

It is like a newsstand that reads many newspapers every morning, checks each cutting, and keeps a card per story that says which newspapers reported it and what each one said. A customer asks for "only stories about Windows, serious, from Europe" and the stand slips in a note saying why each cutting was chosen. The stand does not resell a newspaper whose publisher has not said it is allowed.

## What exists today

- **Real sources, experimental:** CISA KEV, the ENISA European Vulnerability Database, its exploited list and CERT-EU advisories are downloaded and validated; on 2026-10-22 the adapters accepted 1,754, 2,928, 1,770 and 10 records and the merge found no identifier conflicts {{ev:EV-SI-02}}.
- **Alerts engine:** one alert per vulnerability keeps what every source said, with the evidence it came from; updates are new versions of the same alert, and only material changes notify anyone {{ev:EV-SI-03}}.
- **Filters:** a closed language with 26 fields (region, sector, technology, version, system, exposure, severity, exploitation, dates, source and more), never code, evaluated identically on the server and in the browser {{ev:EV-SI-04}}.
- **Delivery:** public and private RSS feeds, e-mail with double confirmation, and signed webhooks protected against requests to internal addresses {{ev:EV-SI-05}}.
- **Organisations and roles:** tenants, units, device groups, an MSP relationship, explicit roles and an audit log with a hash chain {{ev:EV-SI-06}}.
- **Web section:** eight pages in Spanish and English, checked in a real browser for WCAG 2.2 AA {{ev:EV-SI-07}}.

## Where the alerts come from and what may be published

| Source | State |
|---|---|
| MacGuard's own YARA release log | active: three alerts, published as static files {{ev:EV-SI-08}} |
| CISA KEV, ENISA EUVD and its exploited list, CERT-EU | implemented and tested with real data, not published: owner confirmation or reuse terms missing |
| INCIBE-CERT, CCN-CERT, abuse.ch feeds | blocked by their terms or access |
| NVD, OSV, Debian, Ubuntu, Red Hat, Sigma | pending: no adapter yet |

"Active" requires an adapter, a recent import and data. A source that only exists in a list is shown as pending.

## How it keeps itself honest

- A critical score is **severity**, never proof of exploitation: exploitation is only what a source states in a structured field, and each source keeps its own statement.
- The country of an alert is the scope of the **source**, not where a vulnerability is exploited.
- A Linux package is never called vulnerable from the upstream version alone, because distributions backport fixes; only the distribution's own data can say.
- What is unknown stays unknown: no stated fix means "unknown", not "no fix".

## What is missing

- No hosted service: accounts, subscriptions and private feeds run in a reference server that is not deployed. There is no mail relay and no identity provider {{ev:EV-SI-07}}.
- Correlating alerts with a customer's own equipment needs MacGuard Cloud, which does not exist; only the contract and a reference matcher are written {{ev:EV-SI-09}}.
- Third-party data in the public feeds waits for the owner's decisions on licences and on a signing workflow.

## How to check it yourself

Run `python3 scripts/gen_alerts_site.py --check` to confirm the published files are what the repository produces, and read `docs/alerts/ARCHITECTURE.md` for the status of each phase {{ev:EV-SI-07}}.

## Limits

- Everything marked "experimental" is code and tests, not a deployed service.
- Reuse conditions are evidence read from public pages, not legal advice.
- No dates are promised; see the [Global roadmap](EN-Roadmap).

## State

| Capability | State |
|---|---|
| Alerts engine, filters, delivery, tenancy | implemented in the repository, not deployed {{ev:EV-SI-03}} |
| Public alerts from third-party sources | blocked: licences and owner confirmation {{ev:EV-SI-01}} |
| Inventory-based correlation (Cloud) | planned {{ev:EV-SI-09}} |
