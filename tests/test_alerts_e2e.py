"""End to end, across the real boundaries: a real browser (Playwright/Chromium) drives the real pages, which call the real reference server over HTTP, which writes a real
SQLite database and real .eml files. The matcher and the delivery worker run between two browser phases, exactly as the operator would run them.

Needs node and Playwright + axe-core (found in this checkout's admin/worker/node_modules, or in the primary checkout's, or in $ALERTS_NODE_MODULES). Without them the class is
SKIPPED and says so: a skip is not a pass. All data here is synthetic and exists only inside the test."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from datetime import datetime, timezone

from alerts_helpers import ROOT, aff, contents_from, test_registry, vrec  # noqa: F401
from alerts import delivery, engine, mail, matching, store

PW = "correct horse battery staple"


def node_modules():
    cands = [os.environ.get("ALERTS_NODE_MODULES"), os.path.join(ROOT, "admin", "worker", "node_modules")]
    try:
        common = subprocess.run(["git", "rev-parse", "--git-common-dir"], cwd=ROOT, capture_output=True, text=True, timeout=20).stdout.strip()
        if common:
            cands.append(os.path.join(os.path.dirname(os.path.abspath(os.path.join(ROOT, common))), "admin", "worker", "node_modules"))
    except (OSError, subprocess.SubprocessError):
        pass
    for c in cands:
        if c and os.path.isdir(os.path.join(c, "playwright")) and os.path.isfile(os.path.join(c, "axe-core", "axe.min.js")):
            return c
    return None


NM = node_modules()
NODE = shutil.which("node")


@unittest.skipUnless(NODE and NM, "node, Playwright and axe-core are not available: the browser end-to-end test was NOT run (a skip is not a pass)")
class AlertsEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="alerts-e2e-")
        cls.registry = test_registry()
        reg_path = os.path.join(cls.dir, "registry.json")
        with open(reg_path, "w") as f:
            json.dump({"schema": "macguard.source-registry/1", "sources": list(cls.registry.values())}, f)
        cls.db_path = os.path.join(cls.dir, "a.db")
        cls.db = store.connect(cls.db_path)
        recs = []
        for i in range(1, 9):
            win = i % 2 == 1
            recs.append(vrec("enisa-euvd", f"EUVD-2026-{i:04d}", cve=[f"CVE-2026-{i:04d}"], euvd=[f"EUVD-2026-{i:04d}"], score="8.1" if i <= 4 else "5.0", vector="CVSS:3.1/AV:N/AC:L",
                             summary=f"Synthetic test alert {i}", affected=[aff("Microsoft", "Windows 11", "1 <2") if win else aff("Debian", "OpenSSL", "1 <2")]))
        recs.append(vrec("cisa-kev", "CVE-2026-0002", cve=["CVE-2026-0002"], asserted=True, since="2026-10-10", title="Synthetic KEV item", summary="Synthetic KEV item"))
        cls.now = datetime.now(timezone.utc)
        engine.ingest(cls.db, contents_from(recs, cls.registry), store.utc(cls.now))
        views = [v for v in (engine.view_of(cls.db, r["alert_id"], r["record_version"], cls.registry, engine.clearance_key(cls.registry)) for r in cls.db.execute("SELECT alert_id, record_version FROM alerts")) if v]
        cls.total = len(views)
        cls.windows_high = len([v for v in views if v["severity"]["band"] in ("high", "critical") and any("windows" in a["os"] for a in v["affected"])])
        cls.alert_id = views[0]["alert_id"]
        cls.outbox = os.path.join(cls.dir, "outbox")
        site = os.path.join(cls.dir, "site")
        shutil.copytree(os.path.join(ROOT, "web"), site, ignore=shutil.ignore_patterns("vendor"))
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "csp.py"), "inject", site], check=True, capture_output=True)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        cls.base = f"http://127.0.0.1:{port}"
        cls.server = subprocess.Popen([sys.executable, "-m", "alerts", "serve", "--db", cls.db_path, "--registry", reg_path, "--site", site, "--port", str(port), "--insecure-cookies",
                                       "--no-mfa-for-admin", "--outbox", cls.outbox, "--public-url", cls.base], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
        for _ in range(100):
            try:
                urllib.request.urlopen(cls.base + "/api/v1/health", timeout=1).read()
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("the reference server did not start")
        cls.state = {"email": "e2e@example.org", "password": PW, "second_email": "second@example.org", "outbox": cls.outbox, "alerts_total": cls.total, "windows_high": cls.windows_high,
                     "new_key": "CVE-2026-0900", "alert_id": cls.alert_id}
        cls.state_file = os.path.join(cls.dir, "state.json")
        cls.write_state()
        req = urllib.request.Request(cls.base + "/api/v1/auth/register", data=json.dumps({"email": cls.state["second_email"], "password": PW}).encode(), headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=10).read()

    @classmethod
    def write_state(cls):
        with open(cls.state_file, "w") as f:
            json.dump(cls.state, f)

    @classmethod
    def tearDownClass(cls):
        try:
            import signal
            os.killpg(cls.server.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        cls.server.wait(timeout=20)
        cls.db.close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def node(self, phase, timeout=600):
        r = subprocess.run([NODE, os.path.join(ROOT, "tests", "alerts_e2e.mjs"), phase, self.base, self.state_file, NM], capture_output=True, text=True, timeout=timeout)
        line = (r.stdout.strip().splitlines() or ["[]"])[-1]
        if not line.startswith("["):
            line = "[]"
        try:
            res = json.loads(line)
        except ValueError:
            self.fail(f"the browser script produced no result\n{r.stdout[-1500:]}\n{r.stderr[-1500:]}")
        if r.returncode != 0 and not res:
            self.fail(f"the browser script crashed\n{r.stdout[-1500:]}\n{r.stderr[-2500:]}")
        failed = [x for x in res if not x["ok"]]
        self.assertEqual(failed, [], json.dumps(failed, indent=1)[:4000] + "\n" + r.stderr[-800:])
        self.assertGreater(len(res), 3)
        return res

    def pipeline(self, recs):
        engine.ingest(self.db, contents_from(recs, self.registry), store.utc(datetime.now(timezone.utc)))
        now = datetime.now(timezone.utc)
        matching.match_pending(self.db, self.registry, now)
        return delivery.run_due(self.db, self.registry, now, delivery.Config(base_url=self.base, email_transport=mail.FileTransport(self.outbox)))

    def test_1_the_user_journey_in_a_real_browser(self):
        self.node("a")
        self.assertEqual(len([f for f in os.listdir(self.outbox) if f.endswith(".eml")]) >= 2, True)         # the confirmation e-mail and the test message
        new = [vrec("enisa-euvd", "EUVD-2026-0900", cve=["CVE-2026-0900"], euvd=["EUVD-2026-0900"], score="8.8", vector="CVSS:3.1/AV:N/AC:L", summary="Synthetic new alert",
                    affected=[aff("Microsoft", "Windows 11", "1 <2")])]
        before = len(os.listdir(self.outbox))
        res = self.pipeline(new)
        dbg = {"subs": [dict(r) for r in self.db.execute("SELECT sub_id, state, activated_after_seq, frequency FROM subscriptions")], "channels": [dict(r) for r in self.db.execute("SELECT channel_id, state, kind FROM notification_channels")],
               "recipients": [dict(r) for r in self.db.execute("SELECT * FROM subscription_recipients")], "matches": self.db.execute("SELECT COUNT(*) n FROM alert_matches").fetchone()["n"],
               "deliveries": [dict(r) for r in self.db.execute("SELECT state, mode, last_error FROM notification_deliveries")], "max_seq": self.db.execute("SELECT MAX(seq) m FROM alert_events").fetchone()["m"]}
        self.assertEqual(res["sent"], 1, json.dumps(dbg))
        self.assertEqual(len(os.listdir(self.outbox)), before + 1)
        res = self.pipeline(new + [vrec("cisa-kev", "CVE-2026-0900", cve=["CVE-2026-0900"], asserted=True, since="2026-10-22", title="Synthetic KEV 900", summary="Synthetic KEV 900")])
        self.assertEqual(res["sent"], 1)                                                                          # the exploitation news is a notification of its own
        self.assertEqual(self.pipeline(new + [vrec("cisa-kev", "CVE-2026-0900", cve=["CVE-2026-0900"], asserted=True, since="2026-10-22", title="Synthetic KEV 900", summary="Synthetic KEV 900")])["sent"], 0)
        self.node("b")

    def test_2_accessibility_wcag_22_aa_and_no_horizontal_scroll(self):
        # needs the account created by the journey; run it again here if this test is selected alone
        try:
            urllib.request.urlopen(urllib.request.Request(self.base + "/api/v1/auth/register", data=json.dumps({"email": self.state["email"], "password": PW}).encode(),
                                                          headers={"Content-Type": "application/json"}, method="POST"), timeout=10).read()
        except OSError:
            pass
        res = self.node("axe", timeout=900)
        self.assertGreaterEqual(len(res), 8 * 2 * 2 * 2 * 2)


if __name__ == "__main__":
    unittest.main()
