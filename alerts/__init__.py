"""MacGuard alerts and subscriptions: a common alert model, a closed filter language, an incremental matching engine, delivery channels
(web, public and private RSS, email, webhook) and a multi-tenant store with roles.

Standard library only. State: EXPERIMENTAL reference backend. Nothing here is deployed; there is no hosted service, no identity provider and no
mail relay. See docs/alerts/ARCHITECTURE.md for what exists and what does not.
"""
VERSION = "0.1.0"
SCHEMA_ALERT = "macguard.intelligence-alert/1"
SCHEMA_FILTER = "macguard.subscription-filter/1"
SCHEMA_EXPOSURE_MATCH = "macguard.asset-exposure-match/1"
