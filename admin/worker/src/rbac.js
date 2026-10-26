// Role-based access control with EXPLICIT permissions: five roles, a closed list of permissions, a grant list per role (no rank, no inheritance), and one route table that every authenticated API call
// goes through. Anything that is not in the route table is refused (default deny), and so is any role or permission this file does not know.
//
// How a person gets roles: GitHub repository permission maps ONLY to the two roles that already existed (admin -> ADMIN, maintain/write -> REVIEWER; unchanged, so nobody gains or loses anything);
// PUBLISHER and SECURITY_ADMIN exist ONLY as explicit grants by an ADMIN to a verified GitHub account. The effective permission set of a person is the UNION of the grants of the roles they hold.
export const ROLES = ['VIEWER', 'REVIEWER', 'PUBLISHER', 'SECURITY_ADMIN', 'ADMIN'];
export const GITHUB_DERIVED_ROLES = ['REVIEWER', 'ADMIN'];             // the only roles GitHub permission can confer
export const GRANTABLE_ROLES = ['VIEWER', 'REVIEWER', 'PUBLISHER', 'SECURITY_ADMIN', 'ADMIN'];
const DISPLAY_ORDER = ['ADMIN', 'SECURITY_ADMIN', 'PUBLISHER', 'REVIEWER', 'VIEWER'];   // only to pick the label shown next to a name and written to audit rows; it grants nothing

/** Every permission: module, what it allows, whether the operation is critical (fresh GitHub check, recent sign-in) and whether policy requires a second, different identity (enforced by the module that owns the operation). */
export const PERMISSIONS = {
  'dashboard.read': { module: 'dashboard', desc: 'Panel, statistics and pipeline activity' },
  'quarantine.read': { module: 'quarantine', desc: 'List and open quarantined YARA candidates' },
  'quarantine.decide': { module: 'quarantine', desc: 'Approve, reject or hold a candidate (YARA review)' },
  'quarantine.retest': { module: 'quarantine', desc: 'Ask for a candidate to be tested again' },
  'quarantine.authorise_new_source': { module: 'quarantine', desc: 'Approve a candidate that introduces a new source', critical: true },
  'publication.read': { module: 'publications', desc: 'Published inventory, rule sheet, withdrawal policies (read)' },
  'publication.adopt': { module: 'publications', desc: 'Register a published file the panel never saw so it can be managed', critical: true },
  'publication.withdraw.request': { module: 'publications', desc: 'Request the withdrawal of a published rule (standard criticality)', critical: true },
  'publication.revoke.request': { module: 'publications', desc: 'Request a critical revocation (by content) of a published rule', critical: true },
  'publication.lift.request': { module: 'publications', desc: 'Request to lift a withdrawal', critical: true },
  'publication.lift.authorize': { module: 'publications', desc: 'Authorise a lift as a SECOND, different identity', critical: true, dual: true },
  'publication.lift.breakglass': { module: 'publications', desc: 'Execute an emergency lift after its delay', critical: true },
  'publication.lift.review': { module: 'publications', desc: 'Review an emergency lift afterwards (not the person who executed it)', critical: true, dual: true },
  'publication.reconcile': { module: 'publications', desc: 'Re-read the public release and confirm pending withdrawals' },
  'yara.inspect': { module: 'yara', desc: 'Read the original content of YARA rules and their evidence' },
  'suricata.inspect': { module: 'suricata', desc: 'Read Suricata rules, verdicts and evidence' },
  'sigma.inspect': { module: 'sigma', desc: 'Read Sigma rules, verdicts and evidence' },
  'ioc.inspect': { module: 'ioc', desc: 'Read indicators of compromise' },
  'hashes.inspect': { module: 'hashes', desc: 'Read hash records' },
  'vulns.inspect': { module: 'vulnerabilities', desc: 'Read CVE, KEV, EPSS, advisories and ATT&CK records' },
  'intel.sources.read': { module: 'intelligence', desc: 'Sources, runs and statistics of the intelligence store' },
  'logs.read': { module: 'logs', desc: 'Structured operational logs' },
  'sources.read': { module: 'sources', desc: 'Upstream sources and proposals (read)' },
  'sources.propose': { module: 'sources', desc: 'Propose a new upstream source' },
  'sources.review': { module: 'sources', desc: 'Verify, approve, reject or retire a source proposal', critical: true },
  'audit.read': { module: 'audit', desc: 'Read the audit trail' },
  'audit.verify': { module: 'audit', desc: 'Verify the audit hash chain' },
  'audit.export': { module: 'audit', desc: 'Export authorised audit evidence', planned: true },
  'incidents.manage': { module: 'security', desc: 'Open and manage security incidents', planned: true },
  'alerts.manage': { module: 'security', desc: 'Manage alerts, silences and escalation', planned: true },
  'backups.read': { module: 'backups', desc: 'Backup and recovery status' },
  'restore.guide': { module: 'restores', desc: 'Recovery procedures and the guided assistant' },
  'restore.drill.record': { module: 'restores', desc: 'Record steps of a recovery drill' },
  'restore.real.record': { module: 'restores', desc: 'Record steps of a real, protected recovery', critical: true },
  'restore.real.authorize': { module: 'restores', desc: 'Co-authorise a real recovery (never alone)', critical: true, dual: true, planned: true },
  'admin.members.read': { module: 'administration', desc: 'List users, roles and their history' },
  'admin.members.manage': { module: 'administration', desc: 'Grant or revoke roles to verified GitHub identities', critical: true },
  'admin.permissions.read': { module: 'administration', desc: 'See the permission matrix' },
};

const READ = ['dashboard.read', 'quarantine.read', 'publication.read', 'sources.read'];
const INTEL = ['yara.inspect', 'suricata.inspect', 'sigma.inspect', 'ioc.inspect', 'hashes.inspect', 'vulns.inspect', 'intel.sources.read', 'logs.read'];
/** Explicit grants. A role never receives anything because another role has it: every line below is intentional and reviewed. */
export const GRANTS = {
  VIEWER: [...READ],
  REVIEWER: [...READ, ...INTEL, 'quarantine.decide', 'quarantine.retest', 'sources.propose', 'audit.read', 'backups.read', 'restore.guide', 'restore.drill.record'],
  PUBLISHER: [...READ, ...INTEL, 'publication.adopt', 'publication.withdraw.request', 'publication.revoke.request', 'publication.lift.request', 'publication.reconcile'],
  SECURITY_ADMIN: [...READ, ...INTEL, 'audit.read', 'audit.verify', 'audit.export', 'incidents.manage', 'alerts.manage', 'backups.read', 'restore.guide', 'restore.drill.record', 'restore.real.authorize', 'publication.revoke.request', 'publication.lift.authorize', 'publication.lift.review'],
  // ADMIN keeps everything the previous ADMIN could do (no existing privilege is removed) and adds user administration. Nothing else is implied.
  ADMIN: [...READ, ...INTEL, 'quarantine.decide', 'quarantine.retest', 'quarantine.authorise_new_source', 'publication.adopt', 'publication.withdraw.request', 'publication.revoke.request', 'publication.lift.request', 'publication.lift.authorize',
    'publication.lift.breakglass', 'publication.lift.review', 'publication.reconcile', 'sources.propose', 'sources.review', 'audit.read', 'audit.verify', 'backups.read', 'restore.guide', 'restore.drill.record', 'restore.real.record', 'restore.real.authorize',
    'admin.members.read', 'admin.members.manage', 'admin.permissions.read'],
};

const known = new Set(Object.keys(PERMISSIONS)), roleSet = new Set(ROLES);
for (const [r, list] of Object.entries(GRANTS)) for (const p of list) if (!known.has(p)) throw new Error(`role ${r} grants an unknown permission ${p}`);

/** `roles` is a role name or a list of them. Unknown roles, unknown permissions and an empty set all answer false. */
export function can(roles, permission) {
  if (!known.has(permission)) return false;
  const list = Array.isArray(roles) ? roles : [roles];
  return list.some((r) => roleSet.has(r) && GRANTS[r].includes(permission));
}
export const permissionsOf = (roles) => [...new Set((Array.isArray(roles) ? roles : [roles]).filter((r) => roleSet.has(r)).flatMap((r) => GRANTS[r]))].sort();
export const primaryRole = (roles) => DISPLAY_ORDER.find((r) => (roles || []).includes(r)) || null;
export const isCritical = (permission) => !!(PERMISSIONS[permission] && PERMISSIONS[permission].critical);

/** What GitHub may confer, and what an explicit grant adds: the person's role set. */
export function rolesFor({ repoRole, manualRole }) {
  const out = new Set();
  if (repoRole && GITHUB_DERIVED_ROLES.includes(repoRole)) out.add(repoRole);
  if (manualRole && roleSet.has(manualRole)) out.add(manualRole);
  return [...out];
}

// ---- the route table: method + path pattern -> permission. First match wins; no match means the request is refused (404 for the unknown, never "allowed by default"). ----
const ID = '[0-9a-f-]{8,64}';
export const ROUTES = [
  ['GET', /^\/api\/stats$/, 'dashboard.read'], ['GET', /^\/api\/ops\/overview$/, 'dashboard.read'],
  ['GET', /^\/api\/candidates$/, 'quarantine.read'], ['GET', new RegExp(`^/api/candidates/${ID}$`), 'quarantine.read'],
  ['POST', /^\/api\/decisions$/, 'quarantine.decide'], ['POST', new RegExp(`^/api/candidates/${ID}/retest$`), 'quarantine.retest'],
  ['GET', /^\/api\/published$/, 'publication.read'], ['GET', /^\/api\/published\/file$/, 'publication.read'], ['POST', /^\/api\/published\/adopt$/, 'publication.adopt'],
  ['GET', /^\/api\/policies$/, 'publication.read'], ['GET', new RegExp(`^/api/policies/${ID}$`), 'publication.read'], ['GET', /^\/api\/policies\/preview$/, 'publication.withdraw.request'],
  ['POST', /^\/api\/policies\/withdrawals$/, 'publication.withdraw.request'], ['POST', /^\/api\/policies\/reconcile$/, 'publication.reconcile'], ['POST', new RegExp(`^/api/policies/${ID}/lifts$`), 'publication.lift.request'],
  ['POST', /^\/api\/policies\/lifts\/[A-Za-z0-9-]{8,64}\/authorize$/, 'publication.lift.authorize'], ['POST', /^\/api\/policies\/lifts\/[A-Za-z0-9-]{8,64}\/execute$/, 'publication.lift.breakglass'],
  ['POST', /^\/api\/policies\/lifts\/[A-Za-z0-9-]{8,64}\/cancel$/, 'publication.lift.request'], ['POST', /^\/api\/policies\/lifts\/[A-Za-z0-9-]{8,64}\/review$/, 'publication.lift.review'],
  ['GET', /^\/api\/intel\/families$/, 'intel.sources.read'], ['GET', /^\/api\/intel\/(sources|runs|stats)$/, 'intel.sources.read'], ['GET', /^\/api\/intel\/events$/, 'logs.read'],
  ['GET', /^\/api\/intel\/records$/, 'INTEL_BY_FAMILY'], ['GET', /^\/api\/intel\/records\/.+$/, 'INTEL_BY_FAMILY'],
  ['GET', /^\/api\/audit$/, 'audit.read'], ['GET', /^\/api\/audit\/verify$/, 'audit.verify'],
  ['GET', /^\/api\/restore\/status$/, 'backups.read'], ['GET', /^\/api\/restore\/procedures$/, 'restore.guide'], ['POST', /^\/api\/restore\/event$/, 'restore.drill.record'],
  ['GET', /^\/api\/source-proposals$/, 'sources.read'], ['GET', /^\/api\/source-proposals\/.+$/, 'sources.read'], ['POST', /^\/api\/source-proposals$/, 'sources.propose'], ['POST', /^\/api\/source-proposals\/[0-9a-f-]{8,64}\/verify$/, 'sources.propose'], ['POST', /^\/api\/source-proposals\/.+$/, 'sources.review'],
  ['GET', /^\/api\/members$/, 'admin.members.read'], ['GET', /^\/api\/members\/lookup$/, 'admin.members.read'], ['GET', /^\/api\/members\/\d{1,12}\/history$/, 'admin.members.read'], ['POST', /^\/api\/members$/, 'admin.members.manage'],
  ['GET', /^\/api\/permissions$/, 'admin.permissions.read'],
];
// /api/me and /api/logout are answered before any role exists and are not in this table on purpose.

const FAMILY_PERM = { yara: 'yara.inspect', suricata: 'suricata.inspect', sigma: 'sigma.inspect', ioc: 'ioc.inspect', hash: 'hashes.inspect', cve: 'vulns.inspect', kev: 'vulns.inspect', advisory: 'vulns.inspect', attack: 'vulns.inspect', epss: 'vulns.inspect' };
export const familyPermission = (family) => FAMILY_PERM[family] || null;

/** The permission a request needs, or null when the route is unknown (the caller answers 404 and never falls through to a handler). */
export function permissionFor(method, path) {
  for (const [m, re, perm] of ROUTES) if (m === method && re.test(path)) return perm;
  return null;
}

/** The full matrix as plain data (for the administration screen and the generated document). */
export function matrix() {
  const mods = {}; for (const [p, d] of Object.entries(PERMISSIONS)) (mods[d.module] ||= []).push(p);
  return { roles: ROLES, github_derived: GITHUB_DERIVED_ROLES, modules: mods, permissions: Object.fromEntries(Object.entries(PERMISSIONS).map(([p, d]) => [p, { ...d, roles: ROLES.filter((r) => GRANTS[r].includes(p)) }])) };
}
