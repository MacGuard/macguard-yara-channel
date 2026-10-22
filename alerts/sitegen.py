"""Writes the static part of the site from an alert store: public feeds (ES and EN), the feed index with SHA-256 of every file, and the data the Explore page reads
(intelligence/alerts/data/snapshot.json, sources.json, feeds.json). Only the PUBLISH VIEW of alerts is written; with the real registry that is first-party data only.
Every feed is validated before it is written."""
from __future__ import annotations
import hashlib
import json
import os
from datetime import datetime
from typing import Any, Dict, Tuple

from . import api, engine, rss, sources, store


class InvalidFeed(Exception):
    pass


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def generate(db_path: str, registry: Dict[str, Dict[str, Any]], out: str, now: datetime, public_url: str = None) -> Tuple[int, int]:
    app = api.App(db_path, registry, clock=lambda: now, public_url=public_url)
    db = store.connect(db_path)
    try:
        ctx = {"db": db, "now": now}
        index = []
        for f in app._public_feed_defs(ctx):
            for lang in ("es", "en"):
                xml = app.render_public_feed(ctx, f["id"], lang)
                name = f"{f['id']}.xml" if lang == "es" else f"{f['id']}.en.xml"
                problems = rss.validate_rss(xml)
                if problems:
                    raise InvalidFeed(f"{name}: {problems}")
                _write(os.path.join(out, "feeds", "public", name), xml)
                index.append({"id": f["id"], "lang": lang, "file": "feeds/public/" + name, "items": xml.count(b"<item>"), "sha256": hashlib.sha256(xml).hexdigest(),
                              "title": f[lang], "empty_reason": None if xml.count(b"<item>") else "no alert matches, or no source feeding it is cleared for redistribution (see intelligence/alerts/data/sources.json)"})
        st = engine.source_status(db, registry, now)
        res = engine.query(db, registry, {"schema": "macguard.subscription-filter/1", "version": 1, "expr": {"all": []}}, now, limit=200, stale=engine.stale_sources(st))
        snap = {"schema": "macguard.alerts-snapshot/1", "generated_at": store.utc(now), "data_origin": "alert store, publish views only: sources cleared by the registry and confirmed by the owner",
                "what_is_real": "Real alerts built from sources that may be redistributed. Empty or small when few sources are cleared; never padded with examples.", "count": len(res["items"]),
                "truncated": res["next_cursor"] is not None, "taxonomies": {n: v["version"] for n, v in __import__("alerts.taxonomy", fromlist=["x"]).versions().items()},
                "alerts": [{k: v for k, v in x.items() if k != "match_reasons"} for x in res["items"]]}
        cat = {"generated_at": store.utc(now), "sources": sources.source_catalog(registry, st)}
        for rel, doc in (("intelligence/alerts/data/snapshot.json", snap), ("intelligence/alerts/data/sources.json", cat), ("intelligence/alerts/data/feeds.json", {"generated_at": store.utc(now), "feeds": index})):
            _write(os.path.join(out, rel), (json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode())
        _write(os.path.join(out, "feeds", "index.json"), (json.dumps({"generated_utc": store.utc(now), "feeds": index,
                                                                      "how_to_verify": "fetch the feed, compute SHA-256 of the body, compare with this index; validate the XML with scripts/validate_rss.py"},
                                                                     indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode())
        return len(index), len(res["items"])
    finally:
        db.close()
