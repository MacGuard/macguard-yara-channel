# Subscriptions and Alerts: security and privacy

*Resumen: controles implementados y probados en el servidor de referencia, y lo que NO existe (despliegue, relé de correo, proveedor de identidad). Cada control tiene al menos una prueba que falla si se rompe.*

## 1. Threats and controls

| Threat | Control (code) | Test |
|---|---|---|
| A tenant reads or changes another's data | the principal is loaded from the database per request; every operation checks scope and permission; reads of foreign objects are 404; candidate rows are narrowed in SQL then re-checked per row (`subs.list_visible`) | `test_alerts_tenancy.IsolationTests`, `ScopeTests`, `test_alerts_api.OrgApiTests` |
| The client chooses the tenant or role | a request only names ids; extra fields (`owner_user_id`, `tenant`) are ignored; a personal scope naming an organisation is refused | `test_one_tenant_cannot_touch_the_other_through_any_endpoint` |
| Privilege escalation inside an organisation | explicit role lists; only an owner grants/removes owners; last owner protected; unit memberships confined; MSP delegation excludes members, organisation management and audit | `RoleTests`, `MspTests` |
| CSRF | CSRF token header per session, same-origin `Origin`, JSON content type required, SameSite=Lax HttpOnly cookie (`__Host-` and Secure unless local dev) | `SessionTests` |
| Session theft / fixation | random 256-bit token, only its SHA-256 stored, 12 h expiry, logout and MFA enrolment close sessions | `IdentityTests`, `SessionTests` |
| Password guessing | scrypt (n=2^15), 12–256 characters, common passwords refused, lock-out after 5 failures, per-IP and per-account rate limits, uniform error, same work for unknown accounts | `IdentityTests`, `SessionTests` |
| Account enumeration | registration answers identically for new and existing addresses | `test_registration_does_not_reveal_whether_an_address_exists` |
| Admin account takeover | TOTP (RFC 6238, vector-tested) required for organisation administration | `MfaTests` |
| Feed token leakage or guessing | 256 random bits, hash only, revoke/rotate/expire, per-token and per-IP limits, failed guesses throttled harder, `Cache-Control: private, no-store`, `X-Robots-Tag: noindex`, `Referrer-Policy: no-referrer`, tokens redacted from access logs, token never in listings, audit or exports | `FeedTokenTests` |
| SSRF through webhooks | https only; public host **name** (no IP literal in any notation, no internal suffix); port 443/8443; every resolved address must be global; connection **pinned** to the validated address; re-validated at every send; redirects never followed; body limits | `WebhookSecurityTests`, `test_the_connection_goes_to_the_validated_address_over_tls` |
| Forged or replayed webhooks | HMAC-SHA256 over `timestamp.body`, rotating keys (several `v1=`), 5-minute window, stable event id | `test_signatures_verify_and_reject_tampering_replays_and_rotation` |
| Mail abuse / spam | double opt-in by POST (a link scanner cannot confirm), per-recipient hourly/daily limits, one-click unsubscribe with forgery-proof token, bounce handling, header-injection neutralised | `EmailTests`, `test_one_click_unsubscribe` |
| Leaking a third party's data | every output uses the **publish view** (only cleared sources); the check is re-done at send time | `DistributionTests`, `test_the_public_api_never_shows_a_source_that_is_not_cleared` |
| Hostile content in alerts | RSS built with an XML library, control characters removed, URLs restricted to http(s), pages insert text only, CSP forbids inline script and forms | `FeedTests`, `test_alerts_web.Csp` |
| Parser abuse | DTD/entity declarations refused in feeds, size limits, filter depth/size limits, no regular expression from input | `CertEuTests`, `ValidationTests` |
| Tampered audit log | hash chain verified on read | `test_the_whole_batch_is_one_transaction_and_the_audit_chain_holds` |
| Internal errors disclosed | generic 500, no stack traces | `test_headers_methods_and_internal_errors` |

## 2. Privacy

* Personal data stored: e-mail (lower case), optional display name, e-mail channel addresses, webhook URLs, the names people give subscriptions, delivery history. No tracking, no third-party requests from the pages, no analytics.
* The audit log stores **ids and states only**, never an address, a token or a secret, so it can stay append-only after an erasure.
* Export (`GET /api/v1/me/export`) and erasure (`POST /api/v1/me/erase`): erasure removes channels, addresses, webhook keys, subscriptions and credentials, revokes tokens and anonymises the account; an only-owner of an organisation must transfer ownership first.
* Retention (`alerts/privacy.py`, `python3 -m alerts purge`): matches and deliveries 400 days, metrics 90 days, expired sessions at once, revoked tokens 30 days. Audit entries are kept (ids only).
* Consent and communication preferences: nothing is sent before the address is confirmed; frequency, immediate-critical and the kinds of change are per subscription; unsubscribe is one click.
* Public feeds never contain inventories, internal names, private addresses or server data: they carry the publish view of alerts only. P3 (assets) is not implemented, so no inventory exists to leak.

## 3. What is not covered

No TLS termination in the reference server (put it behind a TLS proxy; the Secure/`__Host-` cookie behaviour is the default and tested), no WAF, no distributed rate limiter (the limiter is in memory, with the interface a shared one would implement), no hardware-backed key custody for webhook secrets (they are stored in the 0600 database file because signing needs them; a hosted deployment must use a secret store), no external penetration test. The webhook secret and the e-mail transport credentials are operator configuration and are never committed.
