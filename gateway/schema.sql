-- MacGuard gateway (Premium + API/MCP). D1 (SQLite). Money is INTEGER micro-units of the plan currency: no floating point anywhere.
CREATE TABLE tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','suspended','closed')),
  plan TEXT NOT NULL DEFAULT 'community' CHECK (plan IN ('community','intelligence','business')),
  stripe_customer_id TEXT UNIQUE,
  monthly_budget_micros INTEGER NOT NULL DEFAULT 0 CHECK (monthly_budget_micros >= 0),
  created_at TEXT NOT NULL
);
CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,                       -- the public part of the key (16 hex), never the secret
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  secret_hash TEXT NOT NULL,                 -- HMAC-SHA256(KEY_PEPPER, secret); the secret itself is shown once and never stored
  scopes TEXT NOT NULL,                      -- JSON array
  label TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  last_used_at TEXT,
  actor_kind TEXT NOT NULL DEFAULT 'api_key_client' CHECK (actor_kind IN ('authenticated_service','api_key_client','device_identity'))   -- no key is ever counted as a human
);
CREATE INDEX api_keys_tenant ON api_keys(tenant_id);
CREATE TABLE subscriptions (
  stripe_subscription_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  plan TEXT NOT NULL,
  status TEXT NOT NULL,
  current_period_end INTEGER,
  past_due_since INTEGER,
  updated_at TEXT NOT NULL
);
CREATE TABLE stripe_events (                 -- one row per event id: duplicate deliveries are no-ops. Order is NOT inferred from `created`.
  event_id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  received_at TEXT NOT NULL,
  outcome TEXT NOT NULL
);
CREATE TABLE usage_events (
  usage_event_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  customer_id TEXT,
  api_key_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  pricing_version TEXT NOT NULL,
  units INTEGER NOT NULL,
  unit_price_micros INTEGER NOT NULL,
  billable_micros INTEGER NOT NULL,            -- what is actually CHARGED (0 during FREE_LAUNCH, before acceptance, or for included operations)
  theoretical_micros INTEGER NOT NULL DEFAULT 0, -- what the example prices WOULD charge: for analysing future prices; never billed, never reported to Stripe
  commercial_mode TEXT NOT NULL,                -- the effective mode applied to this request
  policy_version INTEGER NOT NULL,
  currency TEXT NOT NULL,
  request_status TEXT NOT NULL CHECK (request_status IN ('received','authorized','processed','completed','failed')),
  billing_status TEXT NOT NULL CHECK (billing_status IN ('none','included','pending','billed','not_billable','refunded')),
  idem_key TEXT NOT NULL,
  result TEXT,
  stripe_reported INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  completed_at TEXT,
  UNIQUE (tenant_id, idem_key)
);
CREATE INDEX usage_tenant_time ON usage_events(tenant_id, created_at);
CREATE TABLE counters (tenant_id TEXT NOT NULL, scope TEXT NOT NULL, window TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (tenant_id, scope, window));
CREATE TABLE budget (tenant_id TEXT NOT NULL, month TEXT NOT NULL, spent_micros INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (tenant_id, month));
CREATE TABLE releases (
  id TEXT PRIMARY KEY,
  edition TEXT NOT NULL CHECK (edition IN ('community','premium')),
  published_at TEXT NOT NULL,
  object_key TEXT,                           -- private bucket key; community rows have none (their files stay on the public site)
  size INTEGER,
  sha256 TEXT,
  manifest_sha256 TEXT,
  rules_root TEXT,
  source_ids TEXT NOT NULL DEFAULT '[]',        -- every source whose content is in the bundle: each must be approved for Premium in intel_sources at download time
  status TEXT NOT NULL CHECK (status IN ('published','withdrawn'))
);
CREATE TABLE downloads (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  api_key_id TEXT NOT NULL,
  release_id TEXT NOT NULL REFERENCES releases(id),
  state TEXT NOT NULL CHECK (state IN ('authorized','in_progress','completed','expired')),
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  uses INTEGER NOT NULL DEFAULT 0,
  max_uses INTEGER NOT NULL,
  bytes INTEGER NOT NULL DEFAULT 0,
  usage_event_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT,
  ranges TEXT NOT NULL DEFAULT '[]',          -- merged [start,end) byte intervals actually delivered; COMPLETED only when they cover the whole file
  started_at TEXT,
  last_activity_at TEXT,
  failed_at TEXT,
  fail_code TEXT
);
CREATE TABLE intel_sources (source_id TEXT PRIMARY KEY, status TEXT NOT NULL, approved_products TEXT NOT NULL, owner_confirmed INTEGER NOT NULL, attribution TEXT);
CREATE TABLE intel_records (
  kind TEXT NOT NULL CHECK (kind IN ('hash','cve','ioc')),
  key TEXT NOT NULL,
  source_id TEXT NOT NULL REFERENCES intel_sources(source_id),
  doc TEXT NOT NULL,                         -- JSON
  expires_at TEXT,
  PRIMARY KEY (kind, key, source_id)
);
CREATE TABLE audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  tenant_id TEXT,
  action TEXT NOT NULL,
  detail TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;

-- Commercial policy: immutable, hash-chained versions + one pointer moved by compare-and-set. Every Worker reads the same pointer, so there is one effective policy at a time.
CREATE TABLE policy_versions (
  version INTEGER PRIMARY KEY,
  doc TEXT NOT NULL,
  doc_sha256 TEXT NOT NULL,
  prev_sha256 TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  reason TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('seed','change','rollback'))
);
CREATE TRIGGER policy_versions_no_update BEFORE UPDATE ON policy_versions BEGIN SELECT RAISE(ABORT, 'policy versions are immutable'); END;
CREATE TRIGGER policy_versions_no_delete BEFORE DELETE ON policy_versions BEGIN SELECT RAISE(ABORT, 'policy versions are immutable'); END;
CREATE TABLE policy_pointer (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL REFERENCES policy_versions(version));
CREATE TABLE policy_proposals (
  id TEXT PRIMARY KEY, base_version INTEGER NOT NULL, doc TEXT NOT NULL, reason TEXT NOT NULL, proposed_by TEXT NOT NULL, created_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open','applied','stale'))
);
CREATE TABLE policy_approvals (proposal_id TEXT NOT NULL REFERENCES policy_proposals(id), admin_id TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY (proposal_id, admin_id));
CREATE TABLE admins (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT NOT NULL,
  totp_sealed TEXT NOT NULL,                  -- the TOTP seed sealed with TOTP_SEAL_KEY (AES-GCM through WebCrypto); never stored in clear
  last_totp_step INTEGER NOT NULL DEFAULT 0,  -- a code is accepted once: replay protection
  disabled_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE terms_acceptances (
  tenant_id TEXT NOT NULL REFERENCES tenants(id), pricing_version TEXT NOT NULL, terms_version TEXT NOT NULL, accepted_at TEXT NOT NULL, accepted_by_key TEXT NOT NULL,
  PRIMARY KEY (tenant_id, pricing_version)
);

-- ============================ Analytics (additive; nothing above is altered) ============================
-- GitHub Releases: cumulative download counters observed by an incremental collector. A row in gh_observations exists only when the counter CHANGED (or on the first sight / a
-- discontinuity); the interval it closes is [prev_observed_at, observed_at]. Nothing is back-filled: before first_observed_at the history is simply unknown.
CREATE TABLE gh_releases (
  release_id INTEGER PRIMARY KEY, repo TEXT NOT NULL, tag TEXT NOT NULL, name TEXT, draft INTEGER NOT NULL DEFAULT 0, prerelease INTEGER NOT NULL DEFAULT 0,
  created_at TEXT, published_at TEXT, first_observed_at TEXT NOT NULL, last_observed_at TEXT NOT NULL, deleted_at TEXT
);
CREATE TABLE gh_assets (
  asset_id INTEGER PRIMARY KEY, release_id INTEGER NOT NULL REFERENCES gh_releases(release_id), name TEXT NOT NULL, kind TEXT NOT NULL, size INTEGER NOT NULL, content_type TEXT,
  first_observed_at TEXT NOT NULL, last_observed_at TEXT NOT NULL, last_count INTEGER NOT NULL, supersedes_asset_id INTEGER, deleted_at TEXT
);
CREATE INDEX gh_assets_release ON gh_assets(release_id);
CREATE TABLE gh_observations (
  asset_id INTEGER NOT NULL REFERENCES gh_assets(asset_id), observed_at TEXT NOT NULL, download_count INTEGER NOT NULL,
  prev_observed_at TEXT, prev_count INTEGER,
  kind TEXT NOT NULL CHECK (kind IN ('baseline','delta','discontinuity')),   -- baseline: first sight (no interval); delta: counter grew; discontinuity: counter fell (reset/replacement), nothing counted
  PRIMARY KEY (asset_id, observed_at)
);
CREATE TABLE gh_sync (
  id INTEGER PRIMARY KEY CHECK (id = 1), last_attempt_at TEXT, last_success_at TEXT, last_status TEXT, last_error TEXT, consecutive_failures INTEGER NOT NULL DEFAULT 0,
  first_success_at TEXT, rate_remaining INTEGER, rate_reset_at TEXT,
  authenticated INTEGER NOT NULL DEFAULT 0            -- 1 when the last attempt carried a GitHub token (a token lifts the per-IP limit that shared Cloudflare egress addresses hit)
);
CREATE TABLE gh_sync_log (observed_at TEXT PRIMARY KEY, releases INTEGER NOT NULL, assets INTEGER NOT NULL, status TEXT NOT NULL);

-- Incremental aggregates: ONE upsert per request. Histogram buckets (ms): <=5, <=10, <=25, <=50, <=100, <=250, <=500, <=1000, <=2500, >2500 (percentiles are estimates from these).
CREATE TABLE analytics_daily (
  day TEXT NOT NULL, tenant_id TEXT NOT NULL, channel TEXT NOT NULL CHECK (channel IN ('rest','mcp','x402','download')), product TEXT NOT NULL, operation TEXT NOT NULL,
  status_class TEXT NOT NULL CHECK (status_class IN ('2xx','3xx','4xx','5xx','tool_error')), commercial_mode TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0, units INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0, duration_ms_sum INTEGER NOT NULL DEFAULT 0,
  b0 INTEGER NOT NULL DEFAULT 0, b1 INTEGER NOT NULL DEFAULT 0, b2 INTEGER NOT NULL DEFAULT 0, b3 INTEGER NOT NULL DEFAULT 0, b4 INTEGER NOT NULL DEFAULT 0,
  b5 INTEGER NOT NULL DEFAULT 0, b6 INTEGER NOT NULL DEFAULT 0, b7 INTEGER NOT NULL DEFAULT 0, b8 INTEGER NOT NULL DEFAULT 0, b9 INTEGER NOT NULL DEFAULT 0,
  billable_micros INTEGER NOT NULL DEFAULT 0, theoretical_micros INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, tenant_id, channel, product, operation, status_class, commercial_mode)
);
-- Who was active on which day (an actor is a KEYED HASH of the key id: never an IP, a fingerprint or a raw identifier). INSERT OR IGNORE: free after the first request of the day.
CREATE TABLE activity_daily (day TEXT NOT NULL, tenant_id TEXT NOT NULL, actor_kind TEXT NOT NULL, actor_hash TEXT NOT NULL, premium INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, tenant_id, actor_kind, actor_hash));
CREATE TABLE actor_first_seen (tenant_id TEXT NOT NULL, actor_kind TEXT NOT NULL, actor_hash TEXT NOT NULL, first_day TEXT NOT NULL, PRIMARY KEY (tenant_id, actor_kind, actor_hash));
CREATE TABLE tenant_first_seen (tenant_id TEXT PRIMARY KEY, first_day TEXT NOT NULL, first_premium_day TEXT);
-- Community downloads through the optional redirect route. A redirect is a REQUEST that was AUTHORISED to go to GitHub; completion is not observable and is never claimed.
CREATE TABLE community_requests_daily (day TEXT NOT NULL, release_tag TEXT NOT NULL, asset_name TEXT NOT NULL, actor_kind TEXT NOT NULL, redirected INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, release_tag, asset_name, actor_kind));

-- Rows of telemetry that are known test traffic (for example the checks made when a deployment was verified). They are NOT deleted: they are identified here, by exact key and content digest, and the
-- commercial panels skip them. Unauthenticated traffic (tenant_id '-') is excluded from commercial KPIs by rule and needs no entry.
CREATE TABLE telemetry_exclusions (source TEXT NOT NULL CHECK (source IN ('community_requests_daily')), row_key TEXT NOT NULL, row_digest TEXT NOT NULL, reason TEXT NOT NULL, marked_by TEXT NOT NULL, marked_at TEXT NOT NULL, PRIMARY KEY (source, row_key));

-- Durable outbox of operational events for GuardOps (contract macguard.event/1). Idempotent by event_id; retried with backoff; dead-lettered after repeated failure. Contains ids and counters only.
CREATE TABLE guardops_outbox (event_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, envelope TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('pending','sent','dead')), attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL, last_error TEXT, sent_at TEXT);
CREATE INDEX guardops_outbox_due ON guardops_outbox(state, next_attempt_at);

-- Cost intelligence: nothing here is invented. `estimated` rows come from owner-supplied rates x measured quantities; `confirmed` rows come from invoices (CSV import or an official API).
CREATE TABLE cost_entries (
  entry_id TEXT PRIMARY KEY, provider TEXT NOT NULL, service TEXT NOT NULL, billing_period TEXT NOT NULL CHECK (billing_period GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]'),
  kind TEXT NOT NULL CHECK (kind IN ('estimated','confirmed')), amount_micros INTEGER NOT NULL, currency TEXT NOT NULL CHECK (length(currency) = 3),
  tenant_id TEXT, product TEXT, usage_unit TEXT, usage_quantity INTEGER, source TEXT NOT NULL CHECK (source IN ('manual','csv','api','rates')), invoice_ref TEXT, import_batch TEXT, imported_at TEXT NOT NULL
);
CREATE INDEX cost_period ON cost_entries(billing_period, provider, service);
CREATE TABLE cost_rates (provider TEXT NOT NULL, service TEXT NOT NULL, usage_unit TEXT NOT NULL, micros_per_unit INTEGER NOT NULL, currency TEXT NOT NULL, source_url TEXT NOT NULL, as_of TEXT NOT NULL, PRIMARY KEY (provider, service, usage_unit, as_of));

-- Commercial interest: only what a person or an authorised form records. Nothing is inferred from traffic.
CREATE TABLE leads (
  lead_id TEXT PRIMARY KEY, org_name TEXT NOT NULL, tenant_id TEXT, state TEXT NOT NULL CHECK (state IN ('NEW_LEAD','CONTACTED','QUALIFIED','DEMO_REQUESTED','PILOT','PROPOSAL','NEGOTIATION','WON','LOST')),
  source TEXT NOT NULL CHECK (source IN ('manual','form')), contact TEXT, notes TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, created_by TEXT NOT NULL
);
CREATE TABLE lead_events (lead_id TEXT NOT NULL REFERENCES leads(lead_id), at TEXT NOT NULL, from_state TEXT, to_state TEXT NOT NULL, by_admin TEXT NOT NULL);
