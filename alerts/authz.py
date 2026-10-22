"""Roles, permissions and the question 'may this person do this here?'.

Rules that hold everywhere:
  * The Principal is built on the SERVER from the session's user id and the database (memberships, units, MSP links). A request never says which
    organisation or role the caller has; it may only NAME an organisation, and naming one the caller has no right in is refused.
  * Least privilege: a role grants exactly the permissions listed here. No wildcard, no implicit inheritance between roles.
  * Membership may be limited to one organisation unit (and its sub-units); such a membership grants nothing outside it.
  * An MSP administrator acts in a customer organisation only through an ACTIVE link that the customer accepted, with the role the link delegates;
    delegated roles never include membership or audit management.
  * Existence is not leaked: reading an object the caller may not see answers 'not found', not 'forbidden'.
"""
from __future__ import annotations
import sqlite3
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

PERMISSIONS = (
    "subscriptions.read", "subscriptions.create", "subscriptions.update", "subscriptions.delete", "subscriptions.manage_organization",
    "alerts.read", "alerts.export", "notifications.manage", "webhooks.manage", "device_groups.read", "audit_logs.read",
    # needed to administer an organisation itself (not part of the eleven listed in the brief; documented in SECURITY.md)
    "organization.manage_members", "organization.manage",
)

_SUBS_RW = ("subscriptions.read", "subscriptions.create", "subscriptions.update", "subscriptions.delete")
ROLES: Dict[str, FrozenSet[str]] = {
    "owner": frozenset(PERMISSIONS),
    "administrator": frozenset(set(PERMISSIONS) - {"organization.manage"}),
    "security_manager": frozenset(_SUBS_RW + ("subscriptions.manage_organization", "alerts.read", "alerts.export", "notifications.manage", "webhooks.manage", "device_groups.read")),
    "auditor": frozenset(("subscriptions.read", "alerts.read", "alerts.export", "device_groups.read", "audit_logs.read")),
    "operator": frozenset(("subscriptions.read", "subscriptions.create", "subscriptions.update", "alerts.read", "device_groups.read")),
    "viewer": frozenset(("subscriptions.read", "alerts.read")),
    "msp_administrator": frozenset(_SUBS_RW + ("subscriptions.manage_organization", "alerts.read", "alerts.export", "notifications.manage", "webhooks.manage", "device_groups.read")),
}
# what an MSP may be delegated in a customer organisation: never membership, audit or organisation management
DELEGABLE_ROLES = ("security_manager", "operator", "viewer", "auditor")
ADMIN_ROLES = ("owner", "administrator")
PERSONAL_PERMS = frozenset(_SUBS_RW + ("alerts.read", "alerts.export", "notifications.manage"))

SCOPES = ("PERSONAL", "ORGANIZATION", "ORGANIZATION_UNIT", "DEVICE_GROUP", "MSP_CUSTOMER")


@dataclass(frozen=True)
class Membership:
    org_id: str
    role: str
    unit_ids: Optional[FrozenSet[str]]          # None = the whole organisation; otherwise the unit and every sub-unit it contains


@dataclass
class Principal:
    user_id: str
    memberships: List[Membership] = field(default_factory=list)
    msp: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)     # msp_org_id -> [(customer_org_id, delegated_role)] for ACTIVE links, only for MSP administrators
    mfa_verified: bool = False

    def orgs(self) -> Set[str]:
        return {m.org_id for m in self.memberships}


def unit_subtree(db: sqlite3.Connection, unit_id: str) -> FrozenSet[str]:
    out, todo = set(), [unit_id]
    while todo:
        u = todo.pop()
        if u in out:
            continue
        out.add(u)
        todo += [r["unit_id"] for r in db.execute("SELECT unit_id FROM org_units WHERE parent_unit_id=?", (u,))]
    return frozenset(out)


def load_principal(db: sqlite3.Connection, user_id: str, mfa_verified: bool = False) -> Principal:
    p = Principal(user_id=user_id, mfa_verified=mfa_verified)
    for r in db.execute("SELECT m.org_id, m.role, m.unit_id FROM memberships m JOIN organizations o ON o.org_id=m.org_id WHERE m.user_id=? AND m.state='active' AND o.state='active'", (user_id,)):
        p.memberships.append(Membership(r["org_id"], r["role"], None if r["unit_id"] is None else unit_subtree(db, r["unit_id"])))
        if r["role"] == "msp_administrator" and r["unit_id"] is None:
            p.msp.setdefault(r["org_id"], [])
    for msp_org in list(p.msp):
        for l in db.execute("SELECT customer_org_id, delegated_role FROM msp_links WHERE msp_org_id=? AND state='active'", (msp_org,)):
            p.msp[msp_org].append((l["customer_org_id"], l["delegated_role"]))
    return p


def perms_in(p: Principal, org_id: str, unit_id: Optional[str] = None) -> FrozenSet[str]:
    """Permissions the principal holds in (org, unit). With unit_id None the question is about the organisation as a whole: only org-wide
    memberships (and MSP delegation) count; a unit-limited membership grants nothing at organisation level."""
    got: Set[str] = set()
    for m in p.memberships:
        if m.org_id != org_id or m.role == "msp_administrator":
            continue
        if m.unit_ids is None or (unit_id is not None and unit_id in m.unit_ids):
            got |= ROLES[m.role]
    for _msp, links in p.msp.items():
        for cust, role in links:
            if cust == org_id and role in DELEGABLE_ROLES:
                got |= ROLES[role] - {"organization.manage_members", "organization.manage", "audit_logs.read"}
    return frozenset(got)


def can(p: Principal, perm: str, org_id: str, unit_id: Optional[str] = None) -> bool:
    if perm not in PERMISSIONS:
        raise ValueError(f"unknown permission {perm}")
    return perm in perms_in(p, org_id, unit_id)


def is_admin(p: Principal, org_id: str) -> bool:
    return any(m.org_id == org_id and m.unit_ids is None and m.role in ADMIN_ROLES for m in p.memberships)


def is_msp_admin_of(p: Principal, msp_org_id: str, customer_org_id: str) -> Optional[str]:
    for cust, role in p.msp.get(msp_org_id, []):
        if cust == customer_org_id:
            return role
    return None
