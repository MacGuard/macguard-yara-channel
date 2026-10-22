"""Organisations, units, device groups, memberships and MSP links. Every function takes the acting Principal and checks the permission itself; none of
them trusts an organisation id because it was sent. Every change is written to the audit log with who did it.

Guard rails: the last owner of an organisation cannot be removed or demoted; only an owner may grant or remove the owner role; a unit or device group
must belong to the organisation it is attached to (checked in the query); an MSP link needs both sides to act (the MSP proposes, the customer's
administrator accepts) and can be ended by either.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from . import authz, store
from .authz import Principal


class Denied(Exception):
    """The caller may not do this. The API maps it to 403 for actions and to 404 for reads of a named object (existence is not leaked)."""


class NotFound(Exception):
    pass


class Invalid(ValueError):
    pass


def _require(p: Principal, perm: str, org_id: str, unit_id: Optional[str] = None) -> None:
    if not authz.can(p, perm, org_id, unit_id):
        raise Denied(perm)


def create_org(db, user_id: str, name: str, now: str, kind: str = "organization") -> str:
    name = (name or "").strip()
    if not 2 <= len(name) <= 120 or kind not in ("organization", "msp"):
        raise Invalid("an organisation needs a name of 2 to 120 characters")
    oid = store.new_id("o")
    with store.tx(db):
        db.execute("INSERT INTO organizations(org_id, name, kind, created_by, created_utc) VALUES(?,?,?,?,?)", (oid, name, kind, user_id, now))
        db.execute("INSERT INTO memberships(membership_id, org_id, user_id, role, unit_id, created_utc, created_by) VALUES(?,?,?,?,?,?,?)",
                   (store.new_id("m"), oid, user_id, "msp_administrator" if kind == "msp" else "owner", None, now, user_id))
        store.audit(db, now, user_id, oid, "org.create", oid, {"kind": kind})
    return oid


def add_unit(db, p: Principal, org_id: str, name: str, now: str, parent_unit_id: Optional[str] = None) -> str:
    _require(p, "organization.manage", org_id)
    name = (name or "").strip()
    if not 1 <= len(name) <= 120:
        raise Invalid("a unit needs a name of 1 to 120 characters")
    if parent_unit_id and not db.execute("SELECT 1 FROM org_units WHERE unit_id=? AND org_id=?", (parent_unit_id, org_id)).fetchone():
        raise NotFound("parent unit")
    uid = store.new_id("ou")
    with store.tx(db):
        db.execute("INSERT INTO org_units(unit_id, org_id, name, parent_unit_id, created_utc) VALUES(?,?,?,?,?)", (uid, org_id, name, parent_unit_id, now))
        store.audit(db, now, p.user_id, org_id, "unit.create", uid, {})
    return uid


def add_device_group(db, p: Principal, org_id: str, name: str, now: str, unit_id: Optional[str] = None) -> str:
    _require(p, "organization.manage", org_id)
    if unit_id and not db.execute("SELECT 1 FROM org_units WHERE unit_id=? AND org_id=?", (unit_id, org_id)).fetchone():
        raise NotFound("unit")
    name = (name or "").strip()
    if not 1 <= len(name) <= 120:
        raise Invalid("a device group needs a name of 1 to 120 characters")
    gid = store.new_id("dg")
    with store.tx(db):
        db.execute("INSERT INTO device_groups(group_id, org_id, unit_id, name, created_utc) VALUES(?,?,?,?,?)", (gid, org_id, unit_id, name, now))
        store.audit(db, now, p.user_id, org_id, "device_group.create", gid, {})
    return gid


def list_units(db, p: Principal, org_id: str) -> List[Dict[str, Any]]:
    if not any(m.org_id == org_id for m in p.memberships) and not any(c == org_id for links in p.msp.values() for c, _r in links):
        raise NotFound("organization")
    out = []
    for r in db.execute("SELECT unit_id, name, parent_unit_id FROM org_units WHERE org_id=? ORDER BY name", (org_id,)):
        if authz.can(p, "subscriptions.read", org_id, r["unit_id"]) or authz.can(p, "subscriptions.read", org_id):
            out.append(dict(r))
    return out


def list_device_groups(db, p: Principal, org_id: str) -> List[Dict[str, Any]]:
    out = []
    for r in db.execute("SELECT group_id, name, unit_id FROM device_groups WHERE org_id=? ORDER BY name", (org_id,)):
        if authz.can(p, "device_groups.read", org_id, r["unit_id"]):
            out.append(dict(r))
    return out


def _owner_count(db, org_id: str) -> int:
    return db.execute("SELECT COUNT(*) n FROM memberships WHERE org_id=? AND role='owner' AND state='active' AND unit_id IS NULL", (org_id,)).fetchone()["n"]


def add_member(db, p: Principal, org_id: str, email: str, role: str, now: str, unit_id: Optional[str] = None) -> str:
    _require(p, "organization.manage_members", org_id)
    if role not in authz.ROLES or role == "msp_administrator":
        raise Invalid("unknown role")
    if role == "owner" and not any(m.org_id == org_id and m.role == "owner" and m.unit_ids is None for m in p.memberships):
        raise Denied("only an owner may grant the owner role")
    if unit_id and not db.execute("SELECT 1 FROM org_units WHERE unit_id=? AND org_id=?", (unit_id, org_id)).fetchone():
        raise NotFound("unit")
    if unit_id and role in authz.ADMIN_ROLES:
        raise Invalid("owner and administrator apply to the whole organisation, not to a unit")
    u = db.execute("SELECT user_id FROM users WHERE email=? AND state='active'", ((email or "").strip().lower(),)).fetchone()
    if u is None:
        raise NotFound("user")
    mid = store.new_id("m")
    with store.tx(db):
        if db.execute("SELECT 1 FROM memberships WHERE org_id=? AND user_id=? AND COALESCE(unit_id,'')=COALESCE(?, '') AND state='active'", (org_id, u["user_id"], unit_id)).fetchone():
            raise Invalid("already a member")
        db.execute("INSERT INTO memberships(membership_id, org_id, user_id, role, unit_id, created_utc, created_by) VALUES(?,?,?,?,?,?,?)", (mid, org_id, u["user_id"], role, unit_id, now, p.user_id))
        store.audit(db, now, p.user_id, org_id, "member.add", mid, {"user_id": u["user_id"], "role": role, "unit_id": unit_id})
    return mid


def _membership(db, org_id: str, membership_id: str):
    r = db.execute("SELECT * FROM memberships WHERE membership_id=? AND org_id=? AND state='active'", (membership_id, org_id)).fetchone()
    if r is None:
        raise NotFound("membership")
    return r


def change_role(db, p: Principal, org_id: str, membership_id: str, role: str, now: str) -> None:
    _require(p, "organization.manage_members", org_id)
    m = _membership(db, org_id, membership_id)
    if role not in authz.ROLES or role == "msp_administrator":
        raise Invalid("unknown role")
    owner_p = any(x.org_id == org_id and x.role == "owner" and x.unit_ids is None for x in p.memberships)
    if (role == "owner" or m["role"] == "owner") and not owner_p:
        raise Denied("only an owner may grant or change the owner role")
    if m["role"] == "owner" and role != "owner" and _owner_count(db, org_id) <= 1:
        raise Invalid("the last owner cannot be demoted")
    with store.tx(db):
        db.execute("UPDATE memberships SET role=? WHERE membership_id=?", (role, membership_id))
        store.audit(db, now, p.user_id, org_id, "member.role_change", membership_id, {"from": m["role"], "to": role})


def remove_member(db, p: Principal, org_id: str, membership_id: str, now: str) -> None:
    _require(p, "organization.manage_members", org_id)
    m = _membership(db, org_id, membership_id)
    owner_p = any(x.org_id == org_id and x.role == "owner" and x.unit_ids is None for x in p.memberships)
    if m["role"] == "owner" and not owner_p:
        raise Denied("only an owner may remove an owner")
    if m["role"] == "owner" and m["unit_id"] is None and _owner_count(db, org_id) <= 1:
        raise Invalid("the last owner cannot be removed")
    with store.tx(db):
        db.execute("UPDATE memberships SET state='removed' WHERE membership_id=?", (membership_id,))
        # what that person owned in this organisation stops notifying: their subscriptions here are suspended, not deleted (an admin decides)
        db.execute("UPDATE subscriptions SET state='suspended', updated_utc=? WHERE owner_user_id=? AND org_id=? AND state='active'", (now, m["user_id"], org_id))
        store.audit(db, now, p.user_id, org_id, "member.remove", membership_id, {"user_id": m["user_id"]})


def list_members(db, p: Principal, org_id: str) -> List[Dict[str, Any]]:
    _require(p, "organization.manage_members", org_id)
    return [dict(r) for r in db.execute("SELECT m.membership_id, m.user_id, u.email, m.role, m.unit_id, m.created_utc FROM memberships m JOIN users u ON u.user_id=m.user_id WHERE m.org_id=? AND m.state='active' ORDER BY m.created_utc", (org_id,))]


# ---- MSP -----------------------------------------------------------------------------------------------------------------------
def propose_msp_link(db, p: Principal, msp_org_id: str, customer_org_id: str, delegated_role: str, now: str) -> str:
    if not any(m.org_id == msp_org_id and m.role == "msp_administrator" and m.unit_ids is None for m in p.memberships):
        raise Denied("only an MSP administrator of the MSP organisation may propose a link")
    if delegated_role not in authz.DELEGABLE_ROLES:
        raise Invalid(f"a customer may delegate only {list(authz.DELEGABLE_ROLES)}")
    if msp_org_id == customer_org_id or not db.execute("SELECT 1 FROM organizations WHERE org_id=? AND kind='msp'", (msp_org_id,)).fetchone():
        raise Invalid("not an MSP organisation")
    if not db.execute("SELECT 1 FROM organizations WHERE org_id=? AND state='active'", (customer_org_id,)).fetchone():
        raise NotFound("customer organisation")
    lid = store.new_id("ml")
    with store.tx(db):
        if db.execute("SELECT 1 FROM msp_links WHERE msp_org_id=? AND customer_org_id=?", (msp_org_id, customer_org_id)).fetchone():
            raise Invalid("a link already exists")
        db.execute("INSERT INTO msp_links(link_id, msp_org_id, customer_org_id, delegated_role, state, created_utc) VALUES(?,?,?,?,?,?)", (lid, msp_org_id, customer_org_id, delegated_role, "pending", now))
        store.audit(db, now, p.user_id, customer_org_id, "msp_link.propose", lid, {"msp_org_id": msp_org_id, "delegated_role": delegated_role})
    return lid


def accept_msp_link(db, p: Principal, customer_org_id: str, link_id: str, now: str) -> None:
    if not authz.is_admin(p, customer_org_id):
        raise Denied("only an owner or administrator of the customer organisation may accept")
    r = db.execute("SELECT * FROM msp_links WHERE link_id=? AND customer_org_id=? AND state='pending'", (link_id, customer_org_id)).fetchone()
    if r is None:
        raise NotFound("link")
    with store.tx(db):
        db.execute("UPDATE msp_links SET state='active', accepted_by=? WHERE link_id=?", (p.user_id, link_id))
        store.audit(db, now, p.user_id, customer_org_id, "msp_link.accept", link_id, {"msp_org_id": r["msp_org_id"], "delegated_role": r["delegated_role"]})


def end_msp_link(db, p: Principal, link_id: str, now: str) -> None:
    r = db.execute("SELECT * FROM msp_links WHERE link_id=? AND state IN ('pending','active')", (link_id,)).fetchone()
    if r is None or not (authz.is_admin(p, r["customer_org_id"]) or any(m.org_id == r["msp_org_id"] and m.role == "msp_administrator" for m in p.memberships)):
        raise NotFound("link")            # a stranger learns nothing about the link
    with store.tx(db):
        db.execute("UPDATE msp_links SET state='ended' WHERE link_id=?", (link_id,))
        # subscriptions the MSP kept for that customer stop at once
        db.execute("UPDATE subscriptions SET state='suspended', updated_utc=? WHERE scope='MSP_CUSTOMER' AND org_id=? AND customer_org_id=? AND state='active'", (now, r["msp_org_id"], r["customer_org_id"]))
        store.audit(db, now, p.user_id, r["customer_org_id"], "msp_link.end", link_id, {"msp_org_id": r["msp_org_id"]})


def read_audit(db, p: Principal, org_id: str, limit: int = 100, before_seq: Optional[int] = None) -> List[Dict[str, Any]]:
    _require(p, "audit_logs.read", org_id)
    q = "SELECT seq, at, actor_user_id, action, target, detail_json FROM audit_log WHERE org_id=?"
    args: List[Any] = [org_id]
    if before_seq:
        q += " AND seq<?"
        args.append(int(before_seq))
    q += " ORDER BY seq DESC LIMIT ?"
    args.append(max(1, min(int(limit), 500)))
    return [dict(r) for r in db.execute(q, args)]
