"""Accounts, roles, scopes, tenant isolation, subscriptions CRUD, channels, private RSS tokens and the audit trail."""
import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from alerts_helpers import NOW, NOWT, DbCase, leaf, spec, SPEC_ALL  # noqa: F401
from alerts import authz, identity, store, subs, tenancy, webhook
from alerts.tenancy import Denied, Invalid, NotFound

PW = "correct horse battery staple"
PUBLIC = lambda host, port, **kw: [(2, 1, 6, "", ("93.184.216.34", port))]       # noqa: E731  a resolver that answers one public address


def T(minutes=0):
    return store.utc(NOW + timedelta(minutes=minutes))


class IdentityTests(DbCase):
    def test_passwords_are_hashed_and_rules_are_enforced(self):
        uid = self.user("a@example.org")
        c = self.db.execute("SELECT * FROM credentials WHERE user_id=?", (uid,)).fetchone()
        self.assertNotIn(PW.encode(), bytes(c["hash"]) + bytes(c["salt"]))
        self.assertEqual(c["scheme"], "scrypt")
        for bad in ("short", "a" * 300, "password12345", "aaaaaaaaaaaaaa"):
            with self.assertRaises(identity.AuthError):
                identity.register(self.db, "b@example.org", bad, NOWT, params=identity.SCRYPT_TEST)
        with self.assertRaises(identity.AuthError):
            identity.register(self.db, "not an address", PW, NOWT, params=identity.SCRYPT_TEST)
        with self.assertRaises(identity.AuthError) as cm:
            identity.register(self.db, "A@Example.org", PW, NOWT, params=identity.SCRYPT_TEST)         # same address, any case
        self.assertEqual(cm.exception.code, "email_taken")

    def test_login_gives_the_same_error_for_every_failure_and_stores_only_a_hash(self):
        self.user("a@example.org")
        for email, pw in (("a@example.org", "wrong password here"), ("nobody@example.org", PW), ("garbage", PW)):
            with self.assertRaises(identity.AuthError) as cm:
                identity.login(self.db, email, pw, NOW)
            self.assertEqual(cm.exception.code, "invalid_credentials")
        tok, csrf, mfa = identity.login(self.db, "A@example.org", PW, NOW)
        self.assertFalse(mfa)
        stored = [r["session_hash"] for r in self.db.execute("SELECT session_hash FROM sessions")]
        self.assertNotIn(tok, stored)
        self.assertEqual(identity.session(self.db, tok, NOW)["email"], "a@example.org")
        self.assertIsNone(identity.session(self.db, tok + "x", NOW))
        self.assertIsNone(identity.session(self.db, tok, NOW + timedelta(hours=13)))              # expired
        identity.logout(self.db, tok, NOWT)
        self.assertIsNone(identity.session(self.db, tok, NOW))

    def test_lock_out_after_repeated_failures_and_recovery(self):
        self.user("a@example.org")
        for _ in range(identity.LOCK_AFTER):
            with self.assertRaises(identity.AuthError):
                identity.login(self.db, "a@example.org", "wrong password here", NOW)
        with self.assertRaises(identity.AuthError) as cm:
            identity.login(self.db, "a@example.org", PW, NOW)                               # even the right password is refused while locked
        self.assertEqual(cm.exception.code, "locked")
        identity.login(self.db, "a@example.org", PW, NOW + timedelta(minutes=identity.LOCK_MINUTES + 1))

    def test_totp_second_factor(self):
        uid = self.user("a@example.org")
        secret = identity.totp_enroll(self.db, uid, NOWT)
        self.assertFalse(identity.totp_confirm(self.db, uid, "000000", NOW))
        code = identity.totp_code(secret, int(NOW.timestamp()))
        self.assertTrue(identity.totp_confirm(self.db, uid, code, NOW))
        with self.assertRaises(identity.AuthError) as cm:
            identity.login(self.db, "a@example.org", PW, NOW)
        self.assertEqual(cm.exception.code, "mfa_required")
        with self.assertRaises(identity.AuthError):
            identity.login(self.db, "a@example.org", PW, NOW, "123456")
        _t, _c, mfa = identity.login(self.db, "a@example.org", PW, NOW, identity.totp_code(secret, int(NOW.timestamp())))
        self.assertTrue(mfa)

    def test_totp_matches_the_rfc_6238_test_vector(self):
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(identity.totp_code(secret, 59), "287082")
        self.assertEqual(identity.totp_code(secret, 1111111109), "081804")
        self.assertEqual(identity.totp_code(secret, 20000000000), "353130")


class RoleTests(DbCase):
    def test_role_matrix(self):
        R = authz.ROLES
        self.assertEqual(R["owner"], frozenset(authz.PERMISSIONS))
        self.assertNotIn("organization.manage", R["administrator"])
        self.assertIn("subscriptions.manage_organization", R["security_manager"])
        for role in ("auditor", "operator", "viewer"):
            self.assertNotIn("subscriptions.manage_organization", R[role], role)
        self.assertEqual(R["viewer"], frozenset({"subscriptions.read", "alerts.read"}))
        self.assertIn("audit_logs.read", R["auditor"])
        self.assertNotIn("subscriptions.create", R["auditor"])
        self.assertNotIn("audit_logs.read", R["security_manager"])
        self.assertNotIn("webhooks.manage", R["operator"])
        for role, perms in R.items():
            for p in perms:
                self.assertIn(p, authz.PERMISSIONS)
        with self.assertRaises(ValueError):
            authz.can(authz.Principal("u"), "everything", "o")

    def test_owner_and_membership_rules(self):
        a, b, c = self.user(), self.user("b@example.org"), self.user("c@example.org")
        oid = tenancy.create_org(self.db, a, "Acme", NOWT)
        pa = self.principal(a)
        self.assertTrue(authz.can(pa, "organization.manage", oid))
        tenancy.add_member(self.db, pa, oid, "b@example.org", "administrator", NOWT)
        pb = self.principal(b)
        with self.assertRaises(Denied):
            tenancy.add_member(self.db, pb, oid, "c@example.org", "owner", NOWT)                  # an administrator cannot make an owner
        mid = tenancy.add_member(self.db, pb, oid, "c@example.org", "viewer", NOWT)
        with self.assertRaises(Denied):
            tenancy.add_member(self.db, self.principal(c), oid, "a@example.org", "viewer", NOWT)  # a viewer manages nobody
        with self.assertRaises(Invalid):
            tenancy.add_member(self.db, pb, oid, "c@example.org", "viewer", NOWT)                # already a member
        with self.assertRaises(NotFound):
            tenancy.add_member(self.db, pb, oid, "ghost@example.org", "viewer", NOWT)
        owner_m = [m for m in tenancy.list_members(self.db, pa, oid) if m["role"] == "owner"][0]["membership_id"]
        with self.assertRaises(Invalid):
            tenancy.change_role(self.db, pa, oid, owner_m, "viewer", NOWT)                        # the last owner stays
        with self.assertRaises(Invalid):
            tenancy.remove_member(self.db, pa, oid, owner_m, NOWT)
        with self.assertRaises(Denied):
            tenancy.remove_member(self.db, pb, oid, owner_m, NOWT)                                # not by an administrator
        tenancy.change_role(self.db, pa, oid, mid, "operator", NOWT)
        self.assertTrue(authz.can(self.principal(c), "subscriptions.create", oid))
        tenancy.remove_member(self.db, pa, oid, mid, NOWT)
        self.assertFalse(authz.can(self.principal(c), "subscriptions.read", oid))

    def test_a_unit_membership_grants_nothing_outside_its_unit(self):
        a, b = self.user(), self.user("b@example.org")
        oid = tenancy.create_org(self.db, a, "Acme", NOWT)
        pa = self.principal(a)
        u1, u2 = tenancy.add_unit(self.db, pa, oid, "Finance", NOWT), tenancy.add_unit(self.db, pa, oid, "Ops", NOWT)
        child = tenancy.add_unit(self.db, pa, oid, "Ops-EU", NOWT, parent_unit_id=u2)
        tenancy.add_member(self.db, pa, oid, "b@example.org", "operator", NOWT, unit_id=u2)
        pb = self.principal(b)
        self.assertTrue(authz.can(pb, "subscriptions.create", oid, u2))
        self.assertTrue(authz.can(pb, "subscriptions.create", oid, child))                        # sub-units are included
        self.assertFalse(authz.can(pb, "subscriptions.create", oid, u1))
        self.assertFalse(authz.can(pb, "subscriptions.read", oid))                                # nothing organisation-wide
        with self.assertRaises(Invalid):
            tenancy.add_member(self.db, pa, oid, "b@example.org", "administrator", NOWT, unit_id=u1)
        with self.assertRaises(NotFound):
            tenancy.add_unit(self.db, pa, oid, "x", NOWT, parent_unit_id="ou_nonexistent")


class IsolationTests(DbCase):
    """Two organisations, each with an owner, a viewer and subscriptions: nothing crosses."""

    def setUp(self):
        super().setUp()
        self.a_owner, self.b_owner = self.user("ao@example.org"), self.user("bo@example.org")
        self.a_view, self.b_view = self.user("av@example.org"), self.user("bv@example.org")
        self.oa = tenancy.create_org(self.db, self.a_owner, "Org A", NOWT)
        self.ob = tenancy.create_org(self.db, self.b_owner, "Org B", NOWT)
        tenancy.add_member(self.db, self.principal(self.a_owner), self.oa, "av@example.org", "viewer", NOWT)
        tenancy.add_member(self.db, self.principal(self.b_owner), self.ob, "bv@example.org", "viewer", NOWT)
        self.pa, self.pb = self.principal(self.a_owner), self.principal(self.b_owner)
        self.sub_a = subs.create(self.db, self.pa, NOWT, name="A all", scope="ORGANIZATION", org_id=self.oa, spec=SPEC_ALL)
        self.sub_b = subs.create(self.db, self.pb, NOWT, name="B all", scope="ORGANIZATION", org_id=self.ob, spec=SPEC_ALL)
        self.personal_a = subs.create(self.db, self.pa, NOWT, name="A personal", scope="PERSONAL", spec=SPEC_ALL)

    def test_listing_shows_only_what_the_caller_may_read(self):
        names = lambda p: sorted(s["name"] for s in subs.list_visible(self.db, p))                  # noqa: E731
        self.assertEqual(names(self.pa), ["A all", "A personal"])
        self.assertEqual(names(self.pb), ["B all"])
        self.assertEqual(names(self.principal(self.a_view)), ["A all"])                              # a viewer reads the organisation's, not the owner's personal one
        self.assertEqual(names(self.principal(self.b_view)), ["B all"])

    def test_objects_of_another_tenant_are_not_found_for_every_action(self):
        for action in (lambda: subs.get(self.db, self.pb, self.sub_a["sub_id"]), lambda: subs.update(self.db, self.pb, self.sub_a["sub_id"], NOWT, name="x"),
                       lambda: subs.set_state(self.db, self.pb, self.sub_a["sub_id"], "suspended", NOWT), lambda: subs.delete(self.db, self.pb, self.sub_a["sub_id"], NOWT),
                       lambda: subs.duplicate(self.db, self.pb, self.sub_a["sub_id"], NOWT), lambda: subs.list_matches(self.db, self.pb, sub_id=self.sub_a["sub_id"]),
                       lambda: subs.get(self.db, self.pb, self.personal_a["sub_id"]), lambda: subs.create_rss_token(self.db, self.pb, NOWT, label="x", sub_id=self.sub_a["sub_id"])):
            with self.assertRaises(NotFound):
                action()
        self.assertEqual(subs.get(self.db, self.pa, self.sub_a["sub_id"])["name"], "A all")        # nothing changed

    def test_naming_another_tenant_when_creating_is_refused(self):
        for kw in (dict(scope="ORGANIZATION", org_id=self.oa), dict(scope="ORGANIZATION_UNIT", org_id=self.oa, unit_id="ou_x"), dict(scope="DEVICE_GROUP", org_id=self.oa, group_id="dg_x"),
                   dict(scope="ORGANIZATION", org_id="o_doesnotexist")):
            with self.assertRaises((Denied, Invalid)):
                subs.create(self.db, self.pb, NOWT, name="x", spec=SPEC_ALL, **kw)

    def test_a_unit_or_group_of_another_organisation_cannot_be_attached(self):
        unit_b = tenancy.add_unit(self.db, self.pb, self.ob, "Ops", NOWT)
        group_b = tenancy.add_device_group(self.db, self.pb, self.ob, "Servers", NOWT)
        with self.assertRaises(Denied):
            subs.create(self.db, self.pa, NOWT, name="x", scope="ORGANIZATION_UNIT", org_id=self.oa, unit_id=unit_b, spec=SPEC_ALL)     # B's unit under A's organisation id
        with self.assertRaises(Denied):
            subs.create(self.db, self.pa, NOWT, name="x", scope="DEVICE_GROUP", org_id=self.oa, group_id=group_b, spec=SPEC_ALL)
        with self.assertRaises(Denied):
            subs.create(self.db, self.pa, NOWT, name="x", scope="ORGANIZATION_UNIT", org_id=self.ob, unit_id=unit_b, spec=SPEC_ALL)     # B's organisation outright

    def test_channels_and_tokens_do_not_cross(self):
        ch = subs.add_email_channel(self.db, self.pb, "b@example.org", NOWT, org_id=self.ob)
        subs.confirm_channel(self.db, ch["confirm_token"], NOWT)
        with self.assertRaises((NotFound, Denied, Invalid)):
            subs.set_recipients(self.db, self.pa, self.sub_a["sub_id"], [ch["channel_id"]], NOWT)
        with self.assertRaises(NotFound):
            subs.delete_channel(self.db, self.pa, ch["channel_id"], NOWT)
        self.assertEqual([c["channel_id"] for c in subs.list_channels(self.db, self.pa)], [])
        tk = subs.create_rss_token(self.db, self.pb, NOWT, label="b", org_id=self.ob)
        with self.assertRaises(NotFound):
            subs.revoke_rss_token(self.db, self.pa, tk["token_id"], NOWT)
        with self.assertRaises(Denied):
            subs.create_rss_token(self.db, self.pa, NOWT, label="x", org_id=self.ob)

    def test_removed_members_lose_access_and_their_subscriptions_stop(self):
        mem = [m for m in tenancy.list_members(self.db, self.pa, self.oa) if m["user_id"] == self.a_view][0]["membership_id"]
        op = self.user("op@example.org")
        tenancy.add_member(self.db, self.pa, self.oa, "op@example.org", "operator", NOWT)
        s = subs.create(self.db, self.principal(op), NOWT, name="op's", scope="ORGANIZATION_UNIT", org_id=self.oa, unit_id=tenancy.add_unit(self.db, self.pa, self.oa, "U", NOWT), spec=SPEC_ALL)
        opm = [m for m in tenancy.list_members(self.db, self.pa, self.oa) if m["user_id"] == op][0]["membership_id"]
        tenancy.remove_member(self.db, self.pa, self.oa, opm, NOWT)
        self.assertEqual(subs.list_visible(self.db, self.principal(op)), [])
        self.assertEqual(self.db.execute("SELECT state FROM subscriptions WHERE sub_id=?", (s["sub_id"],)).fetchone()["state"], "suspended")
        tenancy.remove_member(self.db, self.pa, self.oa, mem, NOWT)
        self.assertEqual(subs.list_visible(self.db, self.principal(self.a_view)), [])

    def test_a_tampered_principal_cannot_exceed_what_the_database_says(self):
        # the principal is rebuilt from the database on every request; the only thing a request can name is an id
        fake = authz.Principal(self.b_owner, [authz.Membership(self.oa, "owner", None)])        # what a forged client claim would look like
        self.assertNotEqual(self.principal(self.b_owner).orgs(), fake.orgs())
        self.assertEqual(self.principal(self.b_owner).orgs(), {self.ob})


class ScopeTests(DbCase):
    def setUp(self):
        super().setUp()
        self.owner = self.user("o@example.org")
        self.org = tenancy.create_org(self.db, self.owner, "Org", NOWT)
        self.po = self.principal(self.owner)
        self.u1, self.u2 = tenancy.add_unit(self.db, self.po, self.org, "One", NOWT), tenancy.add_unit(self.db, self.po, self.org, "Two", NOWT)
        self.g1 = tenancy.add_device_group(self.db, self.po, self.org, "G1", NOWT, unit_id=self.u1)
        self.users = {}
        for role in ("security_manager", "operator", "viewer", "auditor"):
            self.users[role] = self.user(f"{role}@example.org")
            tenancy.add_member(self.db, self.po, self.org, f"{role}@example.org", role, NOWT)
        self.op_unit = self.user("opunit@example.org")
        tenancy.add_member(self.db, self.po, self.org, "opunit@example.org", "operator", NOWT, unit_id=self.u1)

    def p(self, role):
        return self.principal(self.users[role])

    def make(self, p, scope, **kw):
        ids = dict(org=dict(org_id=self.org), unit=dict(org_id=self.org, unit_id=self.u1), group=dict(org_id=self.org, group_id=self.g1))
        extra = {"ORGANIZATION": ids["org"], "ORGANIZATION_UNIT": ids["unit"], "DEVICE_GROUP": ids["group"], "PERSONAL": {}}[scope]
        extra.update(kw)
        return subs.create(self.db, p, NOWT, name="s", scope=scope, spec=SPEC_ALL, **extra)

    def test_who_may_create_at_which_scope(self):
        self.make(self.p("security_manager"), "ORGANIZATION")
        self.make(self.po, "ORGANIZATION")
        for role in ("operator", "viewer", "auditor"):
            with self.assertRaises(Denied, msg=role):
                self.make(self.p(role), "ORGANIZATION")                                           # organisation-wide needs manage_organization
        self.make(self.p("operator"), "ORGANIZATION_UNIT")
        self.make(self.principal(self.op_unit), "ORGANIZATION_UNIT")                              # a unit-limited operator, in its own unit
        with self.assertRaises(Denied):
            self.make(self.principal(self.op_unit), "ORGANIZATION_UNIT", unit_id=self.u2)         # not in another unit
        with self.assertRaises(Denied):
            self.make(self.principal(self.op_unit), "ORGANIZATION")
        for role in ("viewer", "auditor"):
            with self.assertRaises(Denied):
                self.make(self.p(role), "ORGANIZATION_UNIT")
        self.make(self.p("security_manager"), "DEVICE_GROUP")
        self.make(self.p("operator"), "DEVICE_GROUP")
        self.make(self.principal(self.op_unit), "DEVICE_GROUP")                                   # the group sits in unit One
        with self.assertRaises(Denied):
            self.make(self.p("viewer"), "DEVICE_GROUP")
        for role in ("viewer", "auditor", "operator", "security_manager"):
            self.make(self.p(role), "PERSONAL")                                                   # everybody has a personal scope

    def test_reading_follows_the_same_scopes(self):
        s_org = self.make(self.po, "ORGANIZATION")
        s_unit = self.make(self.po, "ORGANIZATION_UNIT")
        for role in ("viewer", "auditor", "operator", "security_manager"):
            ids = {s["sub_id"] for s in subs.list_visible(self.db, self.p(role))}
            self.assertEqual(ids, {s_org["sub_id"], s_unit["sub_id"]}, role)
        ids = {s["sub_id"] for s in subs.list_visible(self.db, self.principal(self.op_unit))}
        self.assertEqual(ids, {s_unit["sub_id"]})                                                 # only its own unit's
        with self.assertRaises(NotFound):
            subs.get(self.db, self.principal(self.op_unit), s_org["sub_id"])

    def test_updating_and_deleting_need_their_own_permissions(self):
        s = self.make(self.po, "ORGANIZATION")
        for role in ("viewer", "auditor", "operator"):
            with self.assertRaises(NotFound, msg=role):
                subs.update(self.db, self.p(role), s["sub_id"], NOWT, name="x")
            with self.assertRaises(NotFound, msg=role):
                subs.delete(self.db, self.p(role), s["sub_id"], NOWT)
        subs.update(self.db, self.p("security_manager"), s["sub_id"], NOWT, name="renamed")
        subs.delete(self.db, self.p("security_manager"), s["sub_id"], NOWT)
        self.assertEqual([x for x in subs.list_visible(self.db, self.po) if x["sub_id"] == s["sub_id"]], [])

    def test_personal_subscriptions_belong_to_one_person(self):
        s = self.make(self.p("viewer"), "PERSONAL")
        self.assertEqual(len(subs.list_visible(self.db, self.po)), 0)                           # even the owner of the organisation cannot see it
        with self.assertRaises(NotFound):
            subs.get(self.db, self.po, s["sub_id"])
        with self.assertRaises(Invalid):
            self.make(self.p("viewer"), "PERSONAL", org_id=self.org)                            # a personal scope names no organisation

    def test_filters_versions_state_changes_and_duplicates(self):
        s = self.make(self.po, "ORGANIZATION")
        self.assertEqual(s["filter_version"], 1)
        s2 = subs.update(self.db, self.po, s["sub_id"], NOWT, spec=spec(leaf("os", "in", ["linux"])))
        self.assertEqual(s2["filter_version"], 2)
        self.assertEqual(subs.update(self.db, self.po, s["sub_id"], NOWT, spec=spec(leaf("os", "in", ["linux"])))["filter_version"], 2)       # same filter: no new version
        self.assertEqual(self.db.execute("SELECT COUNT(*) n FROM subscription_filters WHERE sub_id=?", (s["sub_id"],)).fetchone()["n"], 2)
        with self.assertRaises(Exception):
            subs.update(self.db, self.po, s["sub_id"], NOWT, spec={"schema": "x"})
        with self.assertRaises(Invalid):
            subs.update(self.db, self.po, s["sub_id"], NOWT, frequency="hourly")
        susp = subs.set_state(self.db, self.po, s["sub_id"], "suspended", NOWT)
        self.assertEqual(susp["state"], "suspended")
        d = subs.duplicate(self.db, self.po, s["sub_id"], NOWT)
        self.assertEqual((d["state"], d["filter"]), ("draft", s2["filter"]))
        self.assertNotEqual(d["sub_id"], s["sub_id"])
        with self.assertRaises(Invalid):
            subs.set_state(self.db, self.po, s["sub_id"], "deleted", NOWT)

    def test_limits(self):
        for i in range(subs.MAX_SUBS_PER_USER):
            self.make(self.p("viewer"), "PERSONAL")
        with self.assertRaises(Invalid):
            self.make(self.p("viewer"), "PERSONAL")

    def test_audit_records_who_did_what_and_never_a_secret(self):
        s = self.make(self.po, "ORGANIZATION")
        subs.set_state(self.db, self.po, s["sub_id"], "suspended", NOWT)
        subs.delete(self.db, self.po, s["sub_id"], NOWT)
        rows = tenancy.read_audit(self.db, self.po, self.org)
        acts = [r["action"] for r in rows]
        for a in ("subscription.create", "subscription.suspend", "subscription.delete", "unit.create", "member.add", "device_group.create"):
            self.assertIn(a, acts)
        self.assertTrue(all(r["actor_user_id"] for r in rows if r["action"].startswith("subscription.")))
        with self.assertRaises(Denied):
            tenancy.read_audit(self.db, self.p("security_manager"), self.org)                  # not part of that role
        self.assertEqual(len(tenancy.read_audit(self.db, self.p("auditor"), self.org)), len(rows))
        self.assertTrue(store.verify_audit(self.db)["ok"])


class MspTests(DbCase):
    def setUp(self):
        super().setUp()
        self.msp_admin, self.cust_owner, self.other = self.user("msp@example.org"), self.user("cust@example.org"), self.user("other@example.org")
        self.msp = tenancy.create_org(self.db, self.msp_admin, "MSP Ltd", NOWT, kind="msp")
        self.cust = tenancy.create_org(self.db, self.cust_owner, "Customer", NOWT)
        self.other_org = tenancy.create_org(self.db, self.other, "Other customer", NOWT)

    def test_a_link_needs_both_sides_and_delegates_only_what_the_customer_allows(self):
        pm = self.principal(self.msp_admin)
        with self.assertRaises(Denied):
            subs.create(self.db, pm, NOWT, name="x", scope="MSP_CUSTOMER", org_id=self.msp, customer_org_id=self.cust, spec=SPEC_ALL)               # no link yet
        with self.assertRaises(Invalid):
            tenancy.propose_msp_link(self.db, pm, self.msp, self.cust, "owner", NOWT)                                                             # owner cannot be delegated
        lid = tenancy.propose_msp_link(self.db, pm, self.msp, self.cust, "security_manager", NOWT)
        pm = self.principal(self.msp_admin)
        with self.assertRaises(Denied):
            subs.create(self.db, pm, NOWT, name="x", scope="MSP_CUSTOMER", org_id=self.msp, customer_org_id=self.cust, spec=SPEC_ALL)               # pending is not enough
        with self.assertRaises(Denied):
            tenancy.accept_msp_link(self.db, pm, self.cust, lid, NOWT)                                                                             # the MSP cannot accept for the customer
        with self.assertRaises(Denied):
            tenancy.accept_msp_link(self.db, self.principal(self.other), self.cust, lid, NOWT)
        tenancy.accept_msp_link(self.db, self.principal(self.cust_owner), self.cust, lid, NOWT)
        pm = self.principal(self.msp_admin)
        s = subs.create(self.db, pm, NOWT, name="for customer", scope="MSP_CUSTOMER", org_id=self.msp, customer_org_id=self.cust, spec=SPEC_ALL)
        self.assertEqual(s["customer_org_id"], self.cust)
        self.assertEqual([x["name"] for x in subs.list_visible(self.db, pm)], ["for customer"])
        self.assertFalse(authz.can(pm, "organization.manage_members", self.cust))                 # delegation never includes membership management
        self.assertFalse(authz.can(pm, "audit_logs.read", self.cust))
        with self.assertRaises(Denied):
            subs.create(self.db, pm, NOWT, name="x", scope="MSP_CUSTOMER", org_id=self.msp, customer_org_id=self.other_org, spec=SPEC_ALL)       # another customer: no link
        self.assertEqual(subs.list_visible(self.db, self.principal(self.cust_owner))[0]["name"], "for customer")                                   # the customer sees it

    def test_ending_the_link_stops_the_msp_at_once(self):
        pm = self.principal(self.msp_admin)
        lid = tenancy.propose_msp_link(self.db, pm, self.msp, self.cust, "security_manager", NOWT)
        tenancy.accept_msp_link(self.db, self.principal(self.cust_owner), self.cust, lid, NOWT)
        s = subs.create(self.db, self.principal(self.msp_admin), NOWT, name="x", scope="MSP_CUSTOMER", org_id=self.msp, customer_org_id=self.cust, spec=SPEC_ALL)
        with self.assertRaises(NotFound):
            tenancy.end_msp_link(self.db, self.principal(self.other), lid, NOWT)                 # a stranger learns nothing
        tenancy.end_msp_link(self.db, self.principal(self.cust_owner), lid, NOWT)
        self.assertEqual(self.db.execute("SELECT state FROM subscriptions WHERE sub_id=?", (s["sub_id"],)).fetchone()["state"], "suspended")
        self.assertEqual(subs.list_visible(self.db, self.principal(self.msp_admin)), [])
        with self.assertRaises(Denied):
            subs.create(self.db, self.principal(self.msp_admin), NOWT, name="y", scope="MSP_CUSTOMER", org_id=self.msp, customer_org_id=self.cust, spec=SPEC_ALL)

    def test_a_viewer_delegation_cannot_create(self):
        lid = tenancy.propose_msp_link(self.db, self.principal(self.msp_admin), self.msp, self.cust, "viewer", NOWT)
        tenancy.accept_msp_link(self.db, self.principal(self.cust_owner), self.cust, lid, NOWT)
        with self.assertRaises(Denied):
            subs.create(self.db, self.principal(self.msp_admin), NOWT, name="x", scope="MSP_CUSTOMER", org_id=self.msp, customer_org_id=self.cust, spec=SPEC_ALL)

    def test_only_an_msp_organisation_may_propose(self):
        with self.assertRaises(Denied):
            tenancy.propose_msp_link(self.db, self.principal(self.cust_owner), self.cust, self.other_org, "viewer", NOWT)


class ChannelTests(DbCase):
    def setUp(self):
        super().setUp()
        self.uid = self.user("me@example.org")
        self.p = self.principal(self.uid)

    def test_email_needs_confirmation_and_the_token_is_stored_only_as_a_hash(self):
        c = subs.add_email_channel(self.db, self.p, "Me@Example.org", NOWT, locale="en")
        row = self.db.execute("SELECT * FROM notification_channels WHERE channel_id=?", (c["channel_id"],)).fetchone()
        self.assertEqual((row["state"], row["address"]), ("pending", "me@example.org"))
        self.assertNotEqual(row["confirm_hash"], c["confirm_token"])
        self.assertIsNone(subs.confirm_channel(self.db, "x" * 43, NOWT))
        self.assertIsNone(subs.confirm_channel(self.db, c["confirm_token"], T(60 * 49)))          # expired
        self.assertEqual(subs.confirm_channel(self.db, c["confirm_token"], T(5)), c["channel_id"])
        self.assertIsNone(subs.confirm_channel(self.db, c["confirm_token"], T(6)))                # used once
        self.assertEqual(self.db.execute("SELECT state FROM notification_channels WHERE channel_id=?", (c["channel_id"],)).fetchone()["state"], "active")
        self.assertEqual(subs.list_channels(self.db, self.p)[0]["address"], "m***@example.org")    # masked in listings
        self.assertNotIn("me@example.org", json.dumps([dict(r) for r in self.db.execute("SELECT detail_json FROM audit_log")]))

    def test_unsubscribe_links_work_without_a_login_and_cannot_be_forged(self):
        c = subs.add_email_channel(self.db, self.p, "me@example.org", NOWT)
        subs.confirm_channel(self.db, c["confirm_token"], NOWT)
        tok = subs.unsubscribe_token(self.db, c["channel_id"])
        self.assertFalse(subs.unsubscribe(self.db, c["channel_id"] + ".deadbeef", NOWT))
        self.assertFalse(subs.unsubscribe(self.db, "nonsense", NOWT))
        self.assertTrue(subs.unsubscribe(self.db, tok, NOWT))
        self.assertEqual(self.db.execute("SELECT state FROM notification_channels WHERE channel_id=?", (c["channel_id"],)).fetchone()["state"], "unsubscribed")

    def test_webhook_destinations_are_validated_and_the_secret_is_shown_once(self):
        for bad in ("http://hooks.example.com/x", "https://127.0.0.1/x", "https://localhost/x", "https://169.254.169.254/latest/meta-data", "https://user:pw@hooks.example.com/x",
                    "https://hooks.example.com:22/x", "file:///etc/passwd", "https://[::1]/x", "https://0x7f.1/x", "https://2130706433/x", "https://intranet/x"):
            with self.assertRaises(Invalid, msg=bad):
                subs.add_webhook_channel(self.db, self.p, bad, NOWT, resolver=PUBLIC)
        w = subs.add_webhook_channel(self.db, self.p, "https://hooks.example.com/in", NOWT, resolver=PUBLIC)
        self.assertEqual(len(w["secret"]), 64)
        listed = json.dumps(subs.list_channels(self.db, self.p))
        self.assertNotIn(w["secret"], listed)
        self.assertNotIn(w["secret"], json.dumps([dict(r) for r in self.db.execute("SELECT detail_json FROM audit_log")]))
        w2 = subs.rotate_webhook_key(self.db, self.p, w["channel_id"], NOWT, overlap_hours=2)
        self.assertEqual(set(subs.active_webhook_secrets(self.db, w["channel_id"], T(60))), {w["secret"], w2["secret"]})       # both valid during the overlap
        self.assertEqual(subs.active_webhook_secrets(self.db, w["channel_id"], T(180)), [w2["secret"]])                        # then only the new one

    def test_a_name_that_resolves_to_a_private_address_is_refused(self):
        private = lambda host, port, **kw: [(2, 1, 6, "", ("10.0.0.5", port))]                    # noqa: E731
        with self.assertRaises(Invalid):
            subs.add_webhook_channel(self.db, self.p, "https://evil.example.com/x", NOWT, resolver=private)
        mixed = lambda host, port, **kw: [(2, 1, 6, "", ("93.184.216.34", port)), (2, 1, 6, "", ("192.168.1.1", port))]       # noqa: E731
        with self.assertRaises(Invalid):
            subs.add_webhook_channel(self.db, self.p, "https://evil.example.com/x", NOWT, resolver=mixed)                       # ONE bad address is enough

    def test_deleting_a_channel_erases_the_address(self):
        c = subs.add_email_channel(self.db, self.p, "me@example.org", NOWT)
        subs.delete_channel(self.db, self.p, c["channel_id"], NOWT)
        r = self.db.execute("SELECT * FROM notification_channels WHERE channel_id=?", (c["channel_id"],)).fetchone()
        self.assertEqual((r["state"], r["address"], r["confirm_hash"]), ("deleted", None, None))
        self.assertEqual(subs.list_channels(self.db, self.p), [])

    def test_a_personal_subscription_uses_only_your_own_channels(self):
        other = self.user("other@example.org")
        c = subs.add_email_channel(self.db, self.principal(other), "other@example.org", NOWT)
        subs.confirm_channel(self.db, c["confirm_token"], NOWT)
        s = subs.create(self.db, self.p, NOWT, name="s", scope="PERSONAL", spec=SPEC_ALL)
        with self.assertRaises((NotFound, Invalid)):
            subs.set_recipients(self.db, self.p, s["sub_id"], [c["channel_id"]], NOWT)

    def test_channel_limit(self):
        for i in range(subs.MAX_CHANNELS_PER_USER):
            subs.add_email_channel(self.db, self.p, f"m{i}@example.org", NOWT)
        with self.assertRaises(Invalid):
            subs.add_email_channel(self.db, self.p, "one-more@example.org", NOWT)


class RssTokenTests(DbCase):
    def setUp(self):
        super().setUp()
        self.uid = self.user("me@example.org")
        self.p = self.principal(self.uid)

    def test_tokens_are_random_stored_only_as_a_hash_and_resolve(self):
        t1, t2 = subs.create_rss_token(self.db, self.p, NOWT, label="a"), subs.create_rss_token(self.db, self.p, NOWT, label="b")
        self.assertNotEqual(t1["token"], t2["token"])
        self.assertGreaterEqual(len(t1["token"]), 43)                                              # 256 bits, url-safe base64
        dump = "".join(str(tuple(r)) for r in self.db.execute("SELECT * FROM rss_tokens")) + "".join(str(tuple(r)) for r in self.db.execute("SELECT * FROM audit_log"))
        self.assertNotIn(t1["token"], dump)
        self.assertNotIn(self.uid[2:], t1["token"])                                                # nothing derived from the user id
        self.assertEqual(subs.resolve_rss_token(self.db, t1["token"], T(1))["token_id"], t1["token_id"])
        self.assertEqual(subs.list_rss_tokens(self.db, self.p)[0]["use_count"] + subs.list_rss_tokens(self.db, self.p)[1]["use_count"], 1)
        for bad in (None, "", "short", "x" * 200, t1["token"] + "!", t1["token"][:-1] + ("A" if t1["token"][-1] != "A" else "B"), "../etc/passwd" + "a" * 30):
            self.assertIsNone(subs.resolve_rss_token(self.db, bad, T(1)), repr(bad))

    def test_revocation_expiry_and_rotation_with_a_grace_period(self):
        t = subs.create_rss_token(self.db, self.p, NOWT, label="a", expires_days=1)
        self.assertIsNotNone(subs.resolve_rss_token(self.db, t["token"], T(60)))
        self.assertIsNone(subs.resolve_rss_token(self.db, t["token"], T(60 * 25)))                 # expired
        t = subs.create_rss_token(self.db, self.p, NOWT, label="b", expires_days=None)
        subs.revoke_rss_token(self.db, self.p, t["token_id"], T(10))
        self.assertIsNotNone(subs.resolve_rss_token(self.db, t["token"], T(9)))                    # before the revocation
        self.assertIsNone(subs.resolve_rss_token(self.db, t["token"], T(10)))
        old = subs.create_rss_token(self.db, self.p, NOWT, label="c")
        new = subs.rotate_rss_token(self.db, self.p, old["token_id"], T(20), grace_minutes=30)
        self.assertNotEqual(new["token"], old["token"])
        self.assertIsNotNone(subs.resolve_rss_token(self.db, old["token"], T(40)))                 # still valid during the grace period
        self.assertIsNone(subs.resolve_rss_token(self.db, old["token"], T(51)))
        self.assertIsNotNone(subs.resolve_rss_token(self.db, new["token"], T(51)))
        for bad in (0, 731, "7", True):
            with self.assertRaises(Invalid):
                subs.create_rss_token(self.db, self.p, NOWT, label="x", expires_days=bad)

    def test_deleting_a_subscription_revokes_its_feed_token(self):
        s = subs.create(self.db, self.p, NOWT, name="s", scope="PERSONAL", spec=SPEC_ALL)
        t = subs.create_rss_token(self.db, self.p, NOWT, label="a", sub_id=s["sub_id"])
        subs.delete(self.db, self.p, s["sub_id"], T(5))
        self.assertIsNone(subs.resolve_rss_token(self.db, t["token"], T(6)))

    def test_token_limit(self):
        for i in range(subs.MAX_TOKENS_PER_USER):
            subs.create_rss_token(self.db, self.p, NOWT, label=f"t{i}")
        with self.assertRaises(Invalid):
            subs.create_rss_token(self.db, self.p, NOWT, label="more")


if __name__ == "__main__":
    unittest.main()
