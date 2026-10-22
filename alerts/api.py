"""The HTTP API as a pure function: Request -> Response. No sockets here (server.py adapts it), so every rule is testable without a network.

Security model (each item has tests):
  * Sessions: random 256-bit token in an HttpOnly, SameSite=Lax cookie (`__Host-` prefixed and Secure unless explicitly running over plain http for local
    development); the server keeps only its SHA-256. Every state-changing request needs the session's CSRF token in `X-CSRF-Token`, a JSON content type
    and, when the browser sends one, a same-origin `Origin`.
  * The caller's organisations and roles are loaded from the database for each request. Nothing in a request can set them.
  * Rate limits: login, registration, public search and private feeds, each with its own bucket and a `Retry-After`.
  * Errors never carry internals; unknown objects and objects of other tenants are both 404.
  * Private feed tokens never appear in access logs (`redact`), feeds are `no-store, private`, `noindex`, `no-referrer`.
  * Public endpoints expose only the publish view of alerts.
"""
from __future__ import annotations
import hashlib
import json
import mimetypes
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from html import escape
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlsplit

from intel import registry as reg
from intel.vulns import ids as idmod

from . import authz, delivery, engine, filters, identity, mail, matching, model, privacy, rss, sources, store, subs, taxonomy, tenancy, webhook
from . import VERSION

MAX_BODY = 64 * 1024
COOKIE = "mg_session"
PUBLIC_FEEDS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "alerts", "public-feeds.json")


class Request:
    def __init__(self, method: str, path: str, query: Optional[Dict[str, List[str]]] = None, headers: Optional[Dict[str, str]] = None, body: bytes = b"", client_ip: str = "0.0.0.0"):
        self.method, self.path, self.query = method.upper(), path, query or {}
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body, self.client_ip = body, client_ip

    def q(self, name: str, default: Optional[str] = None) -> Optional[str]:
        v = self.query.get(name)
        return v[0] if v else default


class Response:
    def __init__(self, status: int, body: Any = b"", headers: Optional[Dict[str, str]] = None, content_type: str = "application/json; charset=utf-8"):
        self.status = status
        self.headers = {"Content-Type": content_type}
        self.headers.update(headers or {})
        if isinstance(body, (dict, list)):
            body = json.dumps(body, sort_keys=True, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.body = body

    def json(self) -> Any:
        return json.loads(self.body)


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: Optional[Dict[str, str]] = None):
        super().__init__(message)
        self.status, self.code, self.message, self.headers = status, code, message, headers or {}


class RateLimiter:
    """Sliding window per key. In memory: a hosted service would share it (Redis or the edge); the interface is the same."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self.clock, self.hits = clock, defaultdict(deque)

    def check(self, key: str, limit: int, window: float) -> Optional[int]:
        """None if allowed (and counts the hit); otherwise seconds to wait."""
        now = self.clock()
        q = self.hits[key]
        while q and q[0] <= now - window:
            q.popleft()
        if len(q) >= limit:
            return max(1, int(q[0] + window - now) + 1)
        q.append(now)
        if len(self.hits) > 50000:                       # bound memory: drop idle keys
            for k in [k for k, v in self.hits.items() if not v or v[-1] < now - window][:10000]:
                self.hits.pop(k, None)
        return None


_TOKEN_IN_PATH = re.compile(r"(/feeds/private/)[^/.?]+")
_TOKEN_IN_QUERY = re.compile(r"([?&](?:token|t)=)[^&]+")


def redact(path_and_query: str) -> str:
    """What may be written to a log: tokens are replaced. Applied to every access-log line."""
    return _TOKEN_IN_QUERY.sub(r"\1<redacted>", _TOKEN_IN_PATH.sub(r"\1<redacted>", path_and_query))


def _need(cond: bool, status: int, code: str, msg: str) -> None:
    if not cond:
        raise ApiError(status, code, msg)


def filter_from_query(req: Request) -> Dict[str, Any]:
    """The public GET search: a closed vocabulary of query parameters turned into a validated filter. Nothing else is read."""
    expr: List[Dict[str, Any]] = []

    def lst(name):
        v = req.q(name)
        return [x for x in (v or "").split(",") if x.strip()] if v else None
    for param, fld in (("region", "region"), ("sector", "sector"), ("vendor", "vendor"), ("product", "product"), ("os", "os"), ("source", "source"), ("id", "id"), ("exposure", "exposure"), ("type", "alert_type"),
                       ("category", "technology_category"), ("family", "threat_family")):
        v = lst(param)
        if v:
            expr.append({"field": fld, "op": "in", "value": v})
    if req.q("severity"):
        expr.append({"field": "severity", "op": "gte", "value": req.q("severity")})
    for p, f, op in (("cvss_min", "cvss", "gte"), ("cvss_max", "cvss", "lte"), ("epss_min", "epss", "gte")):
        if req.q(p) is not None:
            try:
                expr.append({"field": f, "op": op, "value": float(req.q(p))})
            except ValueError:
                raise ApiError(400, "bad_filter", f"{p} must be a number")
    for p, f in (("exploited", "exploited"), ("has_fix", "has_fix"), ("has_mitigation", "has_mitigation")):
        if req.q(p) is not None:
            _need(req.q(p) in ("true", "false"), 400, "bad_filter", f"{p} must be true or false")
            expr.append({"field": f, "op": "is", "value": req.q(p) == "true"})
    for p, f, op in (("published_after", "published", "gte"), ("published_before", "published", "lte"), ("updated_after", "updated", "gte")):
        if req.q(p):
            expr.append({"field": f, "op": op, "value": req.q(p)})
    if req.q("new_within_days") is not None:
        try:
            expr.append({"field": "ingested_within_days", "op": "lte", "value": int(req.q("new_within_days"))})
        except ValueError:
            raise ApiError(400, "bad_filter", "new_within_days must be an integer")
    spec = {"schema": "macguard.subscription-filter/1", "version": 1, "expr": {"all": expr}}
    errs = filters.validate(spec)
    if errs:
        raise ApiError(400, "bad_filter", "; ".join(errs[:3]))
    return spec


class App:
    def __init__(self, db_path: str, registry: Optional[Dict[str, Dict[str, Any]]] = None, cfg: Optional[delivery.Config] = None, *, clock: Optional[Callable[[], datetime]] = None,
                 site_dir: Optional[str] = None, public_url: Optional[str] = None, secure_cookies: bool = True, require_mfa_for_org_admin: bool = True, scrypt_params: Optional[Dict[str, int]] = None,
                 rate_clock: Callable[[], float] = time.time):
        self.db_path = db_path
        self.registry = registry if registry is not None else reg.load()
        self.cfg = cfg or delivery.Config()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.site_dir = os.path.abspath(site_dir) if site_dir else None
        self.public_url = public_url.rstrip("/") if public_url else None
        self.secure_cookies = secure_cookies
        self.require_mfa = require_mfa_for_org_admin
        self.scrypt = scrypt_params or identity.SCRYPT
        self.rl = RateLimiter(rate_clock)
        self.access_log: List[str] = []
        with open(PUBLIC_FEEDS_FILE, encoding="utf-8") as fh:
            self.feeds = json.load(fh)["feeds"]
        self.cookie_name = ("__Host-" + COOKIE) if secure_cookies else COOKIE
        self.cfg.base_url = self.cfg.base_url or self.public_url
        store.connect(db_path).close()
        self.routes = self._routes()

    # ---- plumbing -------------------------------------------------------------------------------------------------------------------
    def now(self) -> datetime:
        return self.clock()

    def handle(self, req: Request) -> Response:
        t0 = time.perf_counter()
        try:
            resp = self._dispatch(req)
        except ApiError as e:
            resp = Response(e.status, {"error": {"code": e.code, "message": e.message}}, e.headers)
        except tenancy.Denied:
            resp = Response(403, {"error": {"code": "forbidden", "message": "you are not allowed to do this"}})
        except tenancy.NotFound:
            resp = Response(404, {"error": {"code": "not_found", "message": "not found"}})
        except (tenancy.Invalid, filters.FilterError) as e:
            resp = Response(400, {"error": {"code": "invalid", "message": str(e)[:300]}})
        except identity.AuthError as e:
            resp = Response({"invalid_credentials": 401, "locked": 429, "mfa_required": 401, "email_taken": 409}.get(e.code, 400), {"error": {"code": e.code, "message": str(e)}})
        except ValueError as e:
            resp = Response(400, {"error": {"code": "invalid", "message": str(e)[:300]}})
        except Exception:                                    # noqa: BLE001  never leak internals; the operator reads the server log
            resp = Response(500, {"error": {"code": "internal", "message": "internal error"}})
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        if resp.headers.get("Content-Type", "").startswith("application/json"):
            resp.headers.setdefault("Cache-Control", "no-store")
        self.access_log.append(f"{req.method} {redact(req.path + ('?' + '&'.join(k + '=' + v[0] for k, v in req.query.items()) if req.query else ''))} {resp.status} {int((time.perf_counter() - t0) * 1000)}ms")
        del self.access_log[:-2000]
        return resp

    def _dispatch(self, req: Request) -> Response:
        if len(req.body) > MAX_BODY:
            raise ApiError(413, "too_large", "request body too large")
        for method, pattern, handler, mode in self.routes:
            m = pattern.match(req.path)
            if m and method == req.method:
                db = store.connect(self.db_path)
                try:
                    ctx = {"db": db, "now": self.now(), "match": m.groups()}
                    if mode in ("user", "user-nocsrf"):
                        self._authenticate(req, ctx, csrf=(mode == "user" and req.method not in ("GET", "HEAD")))
                    return handler(self, req, ctx)
                finally:
                    db.close()
        if req.method in ("GET", "HEAD") and self.site_dir:
            return self._static(req.path)               # dynamic routes were tried first; whatever they do not serve may be a static file (intelligence/alerts/data/*.json, feeds/*)
        if any(p.match(req.path) for _m, p, _h, _mode in self.routes):
            raise ApiError(405, "method_not_allowed", "method not allowed")
        raise ApiError(404, "not_found", "not found")

    def _static(self, path: str) -> Response:
        rel = os.path.normpath(path.lstrip("/") or "index.html")
        if rel.startswith("..") or os.path.isabs(rel) or any(part.startswith(".") for part in rel.split(os.sep)):
            raise ApiError(404, "not_found", "not found")
        full = os.path.join(self.site_dir, rel)
        if os.path.isdir(full):
            full = os.path.join(full, "index.html")
        real = os.path.realpath(full)
        if not real.startswith(os.path.realpath(self.site_dir) + os.sep) or not os.path.isfile(real):
            raise ApiError(404, "not_found", "not found")
        ctype = mimetypes.guess_type(real)[0] or "application/octet-stream"
        with open(real, "rb") as f:
            data = f.read()
        return Response(200, data, {"Cache-Control": "no-cache"}, ctype + ("; charset=utf-8" if ctype.startswith("text/") or ctype in ("application/javascript", "application/json") else ""))

    def _json(self, req: Request, required: bool = True) -> Dict[str, Any]:
        if not req.body:
            _need(not required, 400, "bad_request", "a JSON body is required")
            return {}
        _need(req.headers.get("content-type", "").split(";")[0].strip() == "application/json", 415, "unsupported_media_type", "send application/json")
        try:
            d = json.loads(req.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "bad_json", "the body is not valid JSON")
        _need(isinstance(d, dict), 400, "bad_json", "the body must be a JSON object")
        return d

    def _limit(self, key: str, limit: int, window: float) -> None:
        wait = self.rl.check(key, limit, window)
        if wait is not None:
            raise ApiError(429, "rate_limited", "too many requests", {"Retry-After": str(wait)})

    def _cookie(self, req: Request) -> Optional[str]:
        for part in req.headers.get("cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == self.cookie_name:
                return v
        return None

    def _same_origin(self, req: Request) -> bool:
        origin = req.headers.get("origin")
        if not origin:
            return True                                               # not a browser cross-origin request
        host = req.headers.get("host", "")
        o = urlsplit(origin)
        if self.public_url:
            return origin.rstrip("/") == self.public_url
        return o.netloc == host

    def _authenticate(self, req: Request, ctx: Dict[str, Any], csrf: bool) -> None:
        s = identity.session(ctx["db"], self._cookie(req), ctx["now"])
        if s is None:
            raise ApiError(401, "unauthenticated", "sign in first")
        if csrf:
            _need(self._same_origin(req), 403, "bad_origin", "cross-origin request refused")
            _need(secrets.compare_digest(req.headers.get("x-csrf-token", ""), s["csrf"]), 403, "csrf", "missing or wrong CSRF token")
        ctx["session"] = s
        ctx["p"] = authz.load_principal(ctx["db"], s["user_id"], bool(s["mfa_verified"]))

    def _mfa(self, ctx: Dict[str, Any]) -> None:
        if self.require_mfa and not ctx["p"].mfa_verified:
            raise ApiError(403, "mfa_required", "this action needs a session with the second factor: enable it in your account and sign in with it")

    def _set_cookie(self, token: Optional[str]) -> Dict[str, str]:
        base = f"{self.cookie_name}={token or ''}; Path=/; HttpOnly; SameSite=Lax" + ("; Secure" if self.secure_cookies else "")
        return {"Set-Cookie": base + (f"; Max-Age={identity.SESSION_HOURS * 3600}" if token else "; Max-Age=0")}

    def _now_t(self, ctx) -> str:
        return store.utc(ctx["now"])

    # ---- public -----------------------------------------------------------------------------------------------------------------------
    def health(self, req, ctx):
        return Response(200, {"ok": True, "version": VERSION, "time_utc": self._now_t(ctx), "note": "reference backend (not a hosted service)"})

    def taxonomies(self, req, ctx):
        return Response(200, {n: {"version": taxonomy.load(n)["version"], "sha256": taxonomy.load(n)["sha256"], "items": taxonomy.load(n).get("items", taxonomy.load(n).get("rules"))} for n in
                              ("sectors", "regions", "os-families", "exposure", "severity")} | {"technology-map": {"version": taxonomy.load("technology-map")["version"], "note": taxonomy.load("technology-map")["note"]}},
                        {"Cache-Control": "public, max-age=3600"})

    def sources_(self, req, ctx):
        st = engine.source_status(ctx["db"], self.registry, ctx["now"])
        return Response(200, {"generated_utc": self._now_t(ctx), "sources": sources.source_catalog(self.registry, st),
                              "note": "pending and blocked sources are listed on purpose: only 'active' sources feed alerts"})

    def _query(self, req, ctx, spec) -> Dict[str, Any]:
        st = engine.source_status(ctx["db"], self.registry, ctx["now"])
        try:
            limit = int(req.q("limit", "50"))
        except ValueError:
            raise ApiError(400, "bad_request", "limit must be an integer")
        out = engine.query(ctx["db"], self.registry, spec, ctx["now"], limit=limit, cursor=req.q("cursor"), stale=engine.stale_sources(st))
        return {"items": out["items"], "next_cursor": out["next_cursor"], "filter": spec, "source_freshness": {s: v["state"] for s, v in st.items() if v["alerts"] or v["state"] != "never-imported"},
                "note": "match_reasons explain, per condition, why each alert matches"}

    def alerts_get(self, req, ctx):
        self._limit("pub:" + req.client_ip, 120, 60)
        return Response(200, self._query(req, ctx, filter_from_query(req)))

    def alerts_search(self, req, ctx):
        self._limit("pub:" + req.client_ip, 120, 60)
        body = self._json(req)
        spec = body.get("filter")
        filters.parse(spec)
        req.query = dict(req.query)
        if "limit" in body:
            req.query["limit"] = [str(body["limit"])]
        if "cursor" in body and body["cursor"]:
            req.query["cursor"] = [str(body["cursor"])]
        return Response(200, self._query(req, ctx, spec))

    def alert_get(self, req, ctx):
        self._limit("pub:" + req.client_ip, 120, 60)
        a = engine.load_alert(ctx["db"], ctx["match"][0])
        v = model.publish_view(a, self.registry) if a else None
        if v is None:
            raise ApiError(404, "not_found", "not found")
        versions_ = [{"record_version": r["record_version"], "record_hash": r["record_hash"], "at": r["at"]} for r in ctx["db"].execute("SELECT record_version, record_hash, at FROM alert_versions WHERE alert_id=? ORDER BY record_version", (a["alert_id"],))]
        return Response(200, {"alert": v, "versions": versions_})

    # ---- feeds ------------------------------------------------------------------------------------------------------------------------
    def _feed_response(self, req: Request, xml: bytes, private: bool) -> Response:
        etag = '"' + hashlib.sha256(xml).hexdigest()[:32] + '"'
        h = {"ETag": etag}
        if private:
            h.update({"Cache-Control": "private, no-store", "X-Robots-Tag": "noindex, nofollow", "Referrer-Policy": "no-referrer", "Vary": "Cookie"})
        else:
            h["Cache-Control"] = "public, max-age=300"
        if not private and req.headers.get("if-none-match") == etag:
            return Response(304, b"", h, "application/rss+xml; charset=utf-8")
        return Response(200, xml, h, "application/rss+xml; charset=utf-8")

    def _public_feed_defs(self, ctx) -> List[Dict[str, Any]]:
        defs = [dict(f) for f in self.feeds]
        for sid in ("cisa-kev", "enisa-euvd", "enisa-euvd-exploited", "cert-eu-advisories", "macguard-yara-releases"):
            if sid in self.registry:
                defs.append({"id": "source-" + sid, "es": f"Alertas de la fuente {sid}", "en": f"Alerts from source {sid}", "filter": {"all": [{"field": "source", "op": "in", "value": [sid]}]}})
        return defs

    def render_public_feed(self, ctx, feed_id: str, lang: str) -> Optional[bytes]:
        fd = next((f for f in self._public_feed_defs(ctx) if f["id"] == feed_id), None)
        if fd is None:
            return None
        spec = {"schema": "macguard.subscription-filter/1", "version": 1, "expr": fd["filter"]}
        st = engine.source_status(ctx["db"], self.registry, ctx["now"])
        res = engine.query(ctx["db"], self.registry, spec, ctx["now"], limit=50, stale=engine.stale_sources(st))
        base = self.public_url or rss.DEFAULT_BASE
        items = [rss.public_item(v, base, lang) for v in res["items"]]
        return rss.render_feed("MacGuard: " + fd[lang], fd[lang] + (" · " + {"es": "solo fuentes con redistribución autorizada", "en": "only sources cleared for redistribution"}[lang]),
                               base.rstrip("/") + "/intelligence/alerts/index.html", (self.public_url + f"/feeds/public/{feed_id}.xml") if self.public_url else None, items, ctx["now"], lang=lang)

    def feed_public(self, req, ctx):
        self._limit("pub:" + req.client_ip, 120, 60)
        lang = req.q("lang", "es")
        _need(lang in ("es", "en"), 400, "bad_request", "lang must be es or en")
        xml = self.render_public_feed(ctx, ctx["match"][0], lang)
        if xml is None:
            raise ApiError(404, "not_found", "no such feed")
        return self._feed_response(req, xml, False)

    def feeds_index(self, req, ctx):
        self._limit("pub:" + req.client_ip, 120, 60)
        out = []
        for f in self._public_feed_defs(ctx):
            xml = self.render_public_feed(ctx, f["id"], "es")
            items = len(re.findall(rb"<item>", xml or b""))
            out.append({"id": f["id"], "title": {"es": f["es"], "en": f["en"]}, "url": f"/feeds/public/{f['id']}.xml", "items": items, "sha256": hashlib.sha256(xml).hexdigest(), "filter": f["filter"],
                        "empty_reason": None if items else "no alert matches, or no source feeding it is cleared for redistribution (see /api/v1/sources)"})
        return Response(200, {"generated_utc": self._now_t(ctx), "feeds": out, "how_to_verify": "fetch the feed, compute SHA-256 of the body, compare with this index; validate the XML with scripts/validate_rss.py"}, {"Cache-Control": "public, max-age=300"})

    def feed_private(self, req, ctx):
        self._limit("feedip:" + req.client_ip, 60, 60)
        token = ctx["match"][0]
        row = subs.resolve_rss_token(ctx["db"], token, self._now_t(ctx))
        if row is None:
            self._limit("feedbad:" + req.client_ip, 20, 300)             # guessing is throttled much harder than normal use
            raise ApiError(404, "not_found", "no such feed")
        self._limit("feedtok:" + row["token_id"], 60, 60)
        u = ctx["db"].execute("SELECT state, locale FROM users WHERE user_id=?", (row["owner_user_id"],)).fetchone()
        if u is None or u["state"] != "active":
            raise ApiError(404, "not_found", "no such feed")
        p = authz.load_principal(ctx["db"], row["owner_user_id"])
        lang = req.q("lang") if req.q("lang") in ("es", "en") else u["locale"]
        try:
            if row["sub_id"]:
                sub_ids = [subs.get(ctx["db"], p, row["sub_id"])["sub_id"]]
            elif row["org_id"]:
                _need(authz.can(p, "alerts.read", row["org_id"]), 404, "not_found", "no such feed")
                sub_ids = [s["sub_id"] for s in subs.list_visible(ctx["db"], p) if s["org_id"] == row["org_id"] or s["customer_org_id"] == row["org_id"]]
            else:
                sub_ids = [s["sub_id"] for s in subs.list_visible(ctx["db"], p) if s["scope"] == "PERSONAL"]
        except tenancy.NotFound:
            raise ApiError(404, "not_found", "no such feed")
        items = []
        if sub_ids:
            ph = ",".join("?" * len(sub_ids))
            for m in ctx["db"].execute(f"SELECT * FROM alert_matches WHERE sub_id IN ({ph}) ORDER BY created_utc DESC, match_id DESC LIMIT 100", sub_ids):
                a = engine.load_alert(ctx["db"], m["alert_id"])
                v = model.publish_view(a, self.registry) if a else None
                if v is not None:
                    items.append(rss.match_item(v, {"match_id": m["match_id"], "kind": m["kind"], "created_utc": m["created_utc"], "reasons": json.loads(m["reasons_json"]), "changes": json.loads(m["changes_json"])},
                                                self.public_url or rss.DEFAULT_BASE, lang))
        title = {"es": "MacGuard: tus alertas", "en": "MacGuard: your alerts"}[lang]
        xml = rss.render_feed(title, {"es": "Alertas que coinciden con tus suscripciones. Feed privado: no lo compartas.", "en": "Alerts matching your subscriptions. Private feed: do not share it."}[lang],
                              (self.public_url or rss.DEFAULT_BASE).rstrip("/") + "/intelligence/alerts/index.html", None, items[:50], ctx["now"], lang=lang, ttl_minutes=30)
        return self._feed_response(req, xml, True)

    # ---- one-click pages (GET shows a form; only POST changes anything, so link scanners cannot confirm or unsubscribe for you) -------------------
    def _form_page(self, title: str, text: str, action: str, token: str, button: str) -> Response:
        html = (f'<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)}</title>'
                f'<body style="font-family:system-ui;max-width:32rem;margin:3rem auto;padding:0 1rem"><h1>{escape(title)}</h1><p>{escape(text)}</p>'
                f'<form method="post" action="{escape(action)}"><input type="hidden" name="token" value="{escape(token)}"><button type="submit" style="font-size:1rem;padding:.6rem 1rem">{escape(button)}</button></form></body></html>')
        return Response(200, html, {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'", "Cache-Control": "no-store"}, "text/html; charset=utf-8")

    def _token_from(self, req: Request) -> str:
        if req.method == "POST" and req.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            t = (parse_qs(req.body.decode("utf-8", "replace")).get("token") or [""])[0]
            if t:
                return t
        return req.q("token") or ""                                      # RFC 8058 one-click posts to the List-Unsubscribe URL itself, the token is in its query

    def channel_confirm_page(self, req, ctx):
        return self._form_page("Confirmar dirección / Confirm address", "Pulsa para confirmar que quieres recibir alertas de MacGuard en esta dirección. / Press to confirm that you want MacGuard alerts at this address.",
                               "/api/v1/channels/confirm", req.q("token") or "", "Confirmar / Confirm")

    def channel_confirm(self, req, ctx):
        self._limit("confirm:" + req.client_ip, 30, 3600)
        ok = subs.confirm_channel(ctx["db"], self._token_from(req), self._now_t(ctx))
        _need(ok is not None, 400, "invalid_token", "the link is invalid or has expired")
        return Response(200, "<!doctype html><meta charset=utf-8><p>OK: confirmado / confirmed.</p>", {"Content-Security-Policy": "default-src 'none'"}, "text/html; charset=utf-8")

    def unsubscribe_page(self, req, ctx):
        return self._form_page("Darse de baja / Unsubscribe", "Pulsa para dejar de recibir estos mensajes. / Press to stop receiving these messages.", "/api/v1/channels/unsubscribe", req.q("token") or "", "Darme de baja / Unsubscribe")

    def unsubscribe(self, req, ctx):
        self._limit("unsub:" + req.client_ip, 30, 3600)
        ok = subs.unsubscribe(ctx["db"], self._token_from(req), self._now_t(ctx))
        _need(ok, 400, "invalid_token", "the link is invalid")
        return Response(200, "<!doctype html><meta charset=utf-8><p>OK: baja realizada / unsubscribed.</p>", {"Content-Security-Policy": "default-src 'none'"}, "text/html; charset=utf-8")

    # ---- accounts -----------------------------------------------------------------------------------------------------------------------
    def register(self, req, ctx):
        self._limit("reg:" + req.client_ip, 5, 3600)
        b = self._json(req)
        try:
            identity.register(ctx["db"], b.get("email"), b.get("password"), self._now_t(ctx), display_name=b.get("display_name"), locale=b.get("locale", "es"), params=self.scrypt)
        except identity.AuthError as e:
            if e.code != "email_taken":
                raise
        return Response(201, {"ok": True, "message": "if the address is new, the account exists now"})           # the same answer either way: no account enumeration

    def login(self, req, ctx):
        b = self._json(req)
        email = str(b.get("email", "")).strip().lower()[:200]
        self._limit("login:ip:" + req.client_ip, 20, 900)
        self._limit("login:em:" + hashlib.sha256(email.encode()).hexdigest(), 8, 900)
        token, csrf, mfa = identity.login(ctx["db"], b.get("email"), b.get("password"), ctx["now"], b.get("totp"))
        return Response(200, {"csrf": csrf, "mfa_verified": mfa}, self._set_cookie(token))

    def logout(self, req, ctx):
        identity.logout(ctx["db"], self._cookie(req) or "", self._now_t(ctx))
        return Response(200, {"ok": True}, self._set_cookie(None))

    def session_(self, req, ctx):
        """Like /me, but answers 200 {authenticated:false} when nobody is signed in, so the page can ask without producing an error."""
        s = identity.session(ctx["db"], self._cookie(req), ctx["now"])
        if s is None:
            return Response(200, {"authenticated": False})
        ctx["session"] = s
        ctx["p"] = authz.load_principal(ctx["db"], s["user_id"], bool(s["mfa_verified"]))
        r = self.me(req, ctx)
        return Response(200, dict(r.json(), authenticated=True))

    def me(self, req, ctx):
        p, s = ctx["p"], ctx["session"]
        orgs = []
        for m in p.memberships:
            o = ctx["db"].execute("SELECT name, kind FROM organizations WHERE org_id=?", (m.org_id,)).fetchone()
            orgs.append({"org_id": m.org_id, "name": o["name"], "kind": o["kind"], "role": m.role, "unit_limited": m.unit_ids is not None,
                         "permissions": sorted(authz.perms_in(p, m.org_id)) if m.unit_ids is None else sorted(authz.ROLES[m.role])})
        mfa_on = bool(ctx["db"].execute("SELECT totp_confirmed FROM credentials WHERE user_id=?", (s["user_id"],)).fetchone()["totp_confirmed"])
        return Response(200, {"user": {"user_id": s["user_id"], "email": s["email"], "locale": s["locale"]}, "csrf": s["csrf"], "mfa_enabled": mfa_on, "mfa_verified": p.mfa_verified, "organizations": orgs,
                              "personal_permissions": sorted(authz.PERSONAL_PERMS)})

    def me_patch(self, req, ctx):
        b = self._json(req)
        loc = b.get("locale")
        _need(loc in (None, "es", "en"), 400, "invalid", "locale must be es or en")
        if loc:
            ctx["db"].execute("UPDATE users SET locale=? WHERE user_id=?", (loc, ctx["session"]["user_id"]))
        return Response(200, {"ok": True})

    def me_export(self, req, ctx):
        return Response(200, privacy.export_user(ctx["db"], ctx["session"]["user_id"]), {"Content-Disposition": 'attachment; filename="macguard-export.json"'})

    def me_erase(self, req, ctx):
        b = self._json(req)
        _need(b.get("confirm") == "erase my account", 400, "invalid", 'send {"confirm": "erase my account"}')
        privacy.erase_user(ctx["db"], ctx["session"]["user_id"], self._now_t(ctx))
        return Response(200, {"ok": True}, self._set_cookie(None))

    def mfa_enroll(self, req, ctx):
        secret = identity.totp_enroll(ctx["db"], ctx["session"]["user_id"], self._now_t(ctx))
        return Response(200, {"secret": secret, "otpauth_uri": f"otpauth://totp/MacGuard:{quote(ctx['session']['email'])}?secret={secret}&issuer=MacGuard"})

    def mfa_confirm(self, req, ctx):
        ok = identity.totp_confirm(ctx["db"], ctx["session"]["user_id"], str(self._json(req).get("code", "")), ctx["now"])
        _need(ok, 400, "invalid_code", "the code is wrong")
        identity.revoke_all_sessions(ctx["db"], ctx["session"]["user_id"])
        return Response(200, {"ok": True, "note": "all sessions were closed: sign in again with your second factor"}, self._set_cookie(None))

    # ---- subscriptions --------------------------------------------------------------------------------------------------------------------
    def subs_list(self, req, ctx):
        return Response(200, {"subscriptions": subs.list_visible(ctx["db"], ctx["p"])})

    def subs_create(self, req, ctx):
        b = self._json(req)
        scope = b.get("scope", "PERSONAL")
        s = subs.create(ctx["db"], ctx["p"], self._now_t(ctx), name=b.get("name"), scope=scope, spec=b.get("filter"), org_id=b.get("org_id"), unit_id=b.get("unit_id"), group_id=b.get("group_id"),
                        customer_org_id=b.get("customer_org_id"), frequency=b.get("frequency", "immediate"), notify_on=b.get("notify_on"), critical_immediate=b.get("critical_immediate", True),
                        channel_ids=b.get("channel_ids") or [], state=b.get("state", "active"))
        return Response(201, s)

    def sub_get(self, req, ctx):
        return Response(200, subs.get(ctx["db"], ctx["p"], ctx["match"][0]))

    def sub_patch(self, req, ctx):
        b = self._json(req)
        s = subs.update(ctx["db"], ctx["p"], ctx["match"][0], self._now_t(ctx), name=b.get("name"), spec=b.get("filter"), frequency=b.get("frequency"), notify_on=b.get("notify_on"),
                        critical_immediate=b.get("critical_immediate"))
        if "channel_ids" in b:
            s = subs.set_recipients(ctx["db"], ctx["p"], ctx["match"][0], b["channel_ids"], self._now_t(ctx))
        return Response(200, s)

    def sub_delete(self, req, ctx):
        subs.delete(ctx["db"], ctx["p"], ctx["match"][0], self._now_t(ctx))
        return Response(200, {"ok": True})

    def sub_action(self, req, ctx):
        sid, action = ctx["match"]
        if action in ("suspend", "resume"):
            return Response(200, subs.set_state(ctx["db"], ctx["p"], sid, "suspended" if action == "suspend" else "active", self._now_t(ctx)))
        if action == "duplicate":
            return Response(201, subs.duplicate(ctx["db"], ctx["p"], sid, self._now_t(ctx)))
        if action == "test":
            sub = subs.get(ctx["db"], ctx["p"], sid)
            out = []
            for cid in sub["channel_ids"]:
                out.append(dict(channel_id=cid, **delivery.send_test(ctx["db"], self.registry, cid, sid, ctx["now"], self.cfg)))
            return Response(200, {"results": out, "note": "test messages are labelled as tests and are never counted as alerts"})
        raise ApiError(404, "not_found", "not found")

    def matches_list(self, req, ctx):
        try:
            return Response(200, subs.list_matches(ctx["db"], ctx["p"], sub_id=req.q("sub_id"), limit=int(req.q("limit", "50")), before=req.q("before"), unread_only=req.q("unread") == "true"))
        except ValueError:
            raise ApiError(400, "bad_request", "limit must be an integer")

    def match_mark(self, req, ctx):
        subs.mark_match(ctx["db"], ctx["p"], ctx["match"][0], self._now_t(ctx), acknowledge=ctx["match"][1] == "ack")
        return Response(200, {"ok": True})

    def deliveries_list(self, req, ctx):
        return Response(200, {"deliveries": subs.delivery_history(ctx["db"], ctx["p"], sub_id=req.q("sub_id"))})

    # ---- channels, feed tokens -------------------------------------------------------------------------------------------------------------
    def channels_list(self, req, ctx):
        return Response(200, {"channels": subs.list_channels(ctx["db"], ctx["p"])})

    def channels_create(self, req, ctx):
        b = self._json(req)
        kind, org_id = b.get("kind"), b.get("org_id")
        if kind == "email":
            c = subs.add_email_channel(ctx["db"], ctx["p"], b.get("address"), self._now_t(ctx), label=b.get("label"), locale=b.get("locale", "es"), org_id=org_id)
            msg = mail.render_confirmation(c["address"], c["confirm_token"], b.get("locale", "es"), self.cfg.base_url, self.cfg.from_addr, c["channel_id"], ctx["now"])
            kind_, detail = self.cfg.email_transport.send(msg) if self.cfg.email_transport else ("temporary", "no mail transport configured")
            return Response(201, {"channel_id": c["channel_id"], "state": "pending", "confirmation_sent": kind_ == "ok", "note": "the confirmation link is sent to the address; it is never returned here"})
        if kind == "webhook":
            w = subs.add_webhook_channel(ctx["db"], ctx["p"], b.get("url"), self._now_t(ctx), label=b.get("label"), org_id=org_id)
            return Response(201, {"channel_id": w["channel_id"], "key_id": w["key_id"], "secret": w["secret"], "note": "the secret is shown only now; verify X-MacGuard-Signature with it"})
        raise ApiError(400, "invalid", "kind must be email or webhook")

    def channel_delete(self, req, ctx):
        subs.delete_channel(ctx["db"], ctx["p"], ctx["match"][0], self._now_t(ctx))
        return Response(200, {"ok": True})

    def channel_action(self, req, ctx):
        cid, action = ctx["match"]
        if action == "rotate-key":
            return Response(200, subs.rotate_webhook_key(ctx["db"], ctx["p"], cid, self._now_t(ctx), int(self._json(req, False).get("overlap_hours", 24))))
        if action == "test":
            subs._own_channel(ctx["db"], ctx["p"], cid, "notifications.manage")
            return Response(200, delivery.send_test(ctx["db"], self.registry, cid, "", ctx["now"], self.cfg))
        raise ApiError(404, "not_found", "not found")

    def tokens_list(self, req, ctx):
        return Response(200, {"tokens": subs.list_rss_tokens(ctx["db"], ctx["p"])})

    def tokens_create(self, req, ctx):
        b = self._json(req)
        t = subs.create_rss_token(ctx["db"], ctx["p"], self._now_t(ctx), label=b.get("label"), sub_id=b.get("sub_id"), org_id=b.get("org_id"), expires_days=b.get("expires_days", 90))
        base = self.public_url or ""
        return Response(201, {"token_id": t["token_id"], "expires_utc": t["expires_utc"], "feed_url": f"{base}/feeds/private/{t['token']}.xml",
                              "note": "this URL is the secret: it is shown only now. Anyone who has it can read the feed until you revoke it. Put it only in your feed reader."})

    def token_action(self, req, ctx):
        tid, action = ctx["match"]
        if action == "revoke":
            subs.revoke_rss_token(ctx["db"], ctx["p"], tid, self._now_t(ctx))
            return Response(200, {"ok": True})
        t = subs.rotate_rss_token(ctx["db"], ctx["p"], tid, self._now_t(ctx), int(self._json(req, False).get("grace_minutes", 0)))
        return Response(201, {"token_id": t["token_id"], "feed_url": f"{self.public_url or ''}/feeds/private/{t['token']}.xml"})

    # ---- organisations --------------------------------------------------------------------------------------------------------------------------
    def org_create(self, req, ctx):
        b = self._json(req)
        oid = tenancy.create_org(ctx["db"], ctx["session"]["user_id"], b.get("name"), self._now_t(ctx), kind=b.get("kind", "organization"))
        return Response(201, {"org_id": oid})

    def org_members(self, req, ctx):
        if req.method == "GET":
            return Response(200, {"members": tenancy.list_members(ctx["db"], ctx["p"], ctx["match"][0])})
        self._mfa(ctx)
        b = self._json(req)
        mid = tenancy.add_member(ctx["db"], ctx["p"], ctx["match"][0], b.get("email"), b.get("role"), self._now_t(ctx), unit_id=b.get("unit_id"))
        return Response(201, {"membership_id": mid})

    def org_member_item(self, req, ctx):
        self._mfa(ctx)
        oid, mid = ctx["match"]
        if req.method == "PATCH":
            tenancy.change_role(ctx["db"], ctx["p"], oid, mid, self._json(req).get("role"), self._now_t(ctx))
        else:
            tenancy.remove_member(ctx["db"], ctx["p"], oid, mid, self._now_t(ctx))
        return Response(200, {"ok": True})

    def org_units(self, req, ctx):
        oid = ctx["match"][0]
        if req.method == "GET":
            return Response(200, {"units": tenancy.list_units(ctx["db"], ctx["p"], oid), "device_groups": tenancy.list_device_groups(ctx["db"], ctx["p"], oid)})
        self._mfa(ctx)
        b = self._json(req)
        if b.get("type") == "device_group":
            return Response(201, {"group_id": tenancy.add_device_group(ctx["db"], ctx["p"], oid, b.get("name"), self._now_t(ctx), unit_id=b.get("unit_id"))})
        return Response(201, {"unit_id": tenancy.add_unit(ctx["db"], ctx["p"], oid, b.get("name"), self._now_t(ctx), parent_unit_id=b.get("parent_unit_id"))})

    def org_audit(self, req, ctx):
        self._mfa(ctx)
        try:
            before = int(req.q("before")) if req.q("before") else None
            limit = int(req.q("limit", "100"))
        except ValueError:
            raise ApiError(400, "bad_request", "before and limit must be integers")
        return Response(200, {"entries": tenancy.read_audit(ctx["db"], ctx["p"], ctx["match"][0], limit=limit, before_seq=before), "chain": store.verify_audit(ctx["db"])["ok"]})

    def msp_links(self, req, ctx):
        self._mfa(ctx)
        b = self._json(req)
        act = ctx["match"][0]
        if act == "propose":
            return Response(201, {"link_id": tenancy.propose_msp_link(ctx["db"], ctx["p"], b.get("msp_org_id"), b.get("customer_org_id"), b.get("delegated_role"), self._now_t(ctx))})
        if act == "accept":
            tenancy.accept_msp_link(ctx["db"], ctx["p"], b.get("customer_org_id"), b.get("link_id"), self._now_t(ctx))
        else:
            tenancy.end_msp_link(ctx["db"], ctx["p"], b.get("link_id"), self._now_t(ctx))
        return Response(200, {"ok": True})

    # ---- routing table -----------------------------------------------------------------------------------------------------------------------
    def _routes(self):
        R: List[Tuple[str, re.Pattern, Callable, str]] = []

        def add(method, pattern, handler, mode="public"):
            R.append((method, re.compile("^" + pattern + "$"), handler, mode))
        sid, tid, cid = r"([A-Za-z0-9_]{3,40})", r"([A-Za-z0-9_]{3,40})", r"([A-Za-z0-9_]{3,40})"
        add("GET", "/api/v1/health", App.health)
        add("GET", "/api/v1/taxonomies", App.taxonomies)
        add("GET", "/api/v1/sources", App.sources_)
        add("GET", "/api/v1/alerts", App.alerts_get)
        add("POST", "/api/v1/alerts/search", App.alerts_search)
        add("GET", r"/api/v1/alerts/(MGA-[0-9a-f]{20})", App.alert_get)
        add("GET", r"/feeds/public/([a-z0-9-]{1,60})\.xml", App.feed_public)
        add("GET", "/feeds/index.json", App.feeds_index)
        add("GET", r"/feeds/private/([A-Za-z0-9_-]{20,100})\.xml", App.feed_private)
        add("GET", "/api/v1/channels/confirm", App.channel_confirm_page)
        add("POST", "/api/v1/channels/confirm", App.channel_confirm)
        add("GET", "/api/v1/channels/unsubscribe", App.unsubscribe_page)
        add("POST", "/api/v1/channels/unsubscribe", App.unsubscribe)
        add("POST", "/api/v1/auth/register", App.register)
        add("POST", "/api/v1/auth/login", App.login)
        add("POST", "/api/v1/auth/logout", App.logout, "user")
        add("GET", "/api/v1/session", App.session_)
        add("GET", "/api/v1/me", App.me, "user")
        add("PATCH", "/api/v1/me", App.me_patch, "user")
        add("GET", "/api/v1/me/export", App.me_export, "user")
        add("POST", "/api/v1/me/erase", App.me_erase, "user")
        add("POST", "/api/v1/auth/mfa/enroll", App.mfa_enroll, "user")
        add("POST", "/api/v1/auth/mfa/confirm", App.mfa_confirm, "user")
        add("GET", "/api/v1/subscriptions", App.subs_list, "user")
        add("POST", "/api/v1/subscriptions", App.subs_create, "user")
        add("GET", f"/api/v1/subscriptions/{sid}", App.sub_get, "user")
        add("PATCH", f"/api/v1/subscriptions/{sid}", App.sub_patch, "user")
        add("DELETE", f"/api/v1/subscriptions/{sid}", App.sub_delete, "user")
        add("POST", f"/api/v1/subscriptions/{sid}/(suspend|resume|duplicate|test)", App.sub_action, "user")
        add("GET", "/api/v1/matches", App.matches_list, "user")
        add("POST", r"/api/v1/matches/([A-Za-z0-9_]{3,40})/(read|ack)", App.match_mark, "user")
        add("GET", "/api/v1/deliveries", App.deliveries_list, "user")
        add("GET", "/api/v1/channels", App.channels_list, "user")
        add("POST", "/api/v1/channels", App.channels_create, "user")
        add("DELETE", f"/api/v1/channels/{cid}", App.channel_delete, "user")
        add("POST", f"/api/v1/channels/{cid}/(rotate-key|test)", App.channel_action, "user")
        add("GET", "/api/v1/feed-tokens", App.tokens_list, "user")
        add("POST", "/api/v1/feed-tokens", App.tokens_create, "user")
        add("POST", f"/api/v1/feed-tokens/{tid}/(revoke|rotate)", App.token_action, "user")
        add("POST", "/api/v1/orgs", App.org_create, "user")
        add("GET", r"/api/v1/orgs/([A-Za-z0-9_]{3,40})/members", App.org_members, "user")
        add("POST", r"/api/v1/orgs/([A-Za-z0-9_]{3,40})/members", App.org_members, "user")
        add("PATCH", r"/api/v1/orgs/([A-Za-z0-9_]{3,40})/members/([A-Za-z0-9_]{3,40})", App.org_member_item, "user")
        add("DELETE", r"/api/v1/orgs/([A-Za-z0-9_]{3,40})/members/([A-Za-z0-9_]{3,40})", App.org_member_item, "user")
        add("GET", r"/api/v1/orgs/([A-Za-z0-9_]{3,40})/units", App.org_units, "user")
        add("POST", r"/api/v1/orgs/([A-Za-z0-9_]{3,40})/units", App.org_units, "user")
        add("GET", r"/api/v1/orgs/([A-Za-z0-9_]{3,40})/audit", App.org_audit, "user")
        add("POST", r"/api/v1/msp-links/(propose|accept|end)", App.msp_links, "user")
        return R
