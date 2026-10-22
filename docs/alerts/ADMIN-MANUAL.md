# Administrator manual (reference backend)

## Run it
```
python3 -m alerts ingest --db alerts.db --vuln-channel ROOT/vulns/1 ... --yara-log logs/log.jsonl     # builds alerts, warms views
python3 -m alerts match  --db alerts.db --outbox outbox --public-url https://…                          # match, digests, deliver (.eml files)
python3 -m alerts status --db alerts.db                                                                 # sources, freshness, counts, latencies, audit chain
python3 -m alerts feeds  --db alerts.db --out web                                                       # public feeds + Explore data (only cleared sources)
python3 -m alerts serve  --db alerts.db --site web --public-url https://…                              # API + site on 127.0.0.1
python3 -m alerts purge  --db alerts.db                                                                 # retention policy
python3 scripts/gen_alerts_site.py [--check]    # the committed static data (first-party releases only)
python3 scripts/bench_alerts.py                 # measures on synthetic data
```
Run `ingest` and `match` from a scheduler (cron, launchd). Use `--registry FILE` to try a different clearance locally: **never commit such a file or publish its output**.

## Decisions that belong to the owner
1. `owner_confirmed` per source in `config/intel/sources.registry.json` (CISA KEV, CERT-EU, then EUVD once terms are confirmed). Until then public feeds and the Explore page carry no third-party vulnerability data. The first-party YARA-release source is set to confirmed by the author of this change: review or revert it.
2. A mail relay (`SmtpTransport`: host, STARTTLS, credentials in the environment, never in the repository) and the public URL for links.
3. A TLS front and a process supervisor, a secret store for webhook keys, an identity provider (OIDC) for organisations.
4. Whether merging to `main` is acceptable: `site.yml` deploys `web/**` on merge.

## Operating roles
Per organisation: owner, administrator, security manager, auditor, operator, viewer (and MSP administrator in an MSP organisation). Organisation administration needs a session with the second factor (`--no-mfa-for-admin` exists for local development only). Audit: `GET /api/v1/orgs/{id}/audit` (hash chain checked), `python3 -m alerts status`.
