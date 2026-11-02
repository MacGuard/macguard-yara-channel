// Shared helpers for tests on an INTEL database built from migrations 0001-0005 + 0007 (correlation assurance). Synthetic data only; local node:sqlite only.
import { readFileSync } from 'node:fs';
import { newDb } from './d1shim.js';
import { reviewerBootstrapSql, syncSourceApprovals } from '../src/intel_assurance.js';

export const M5 = ['0001_intel.sql', '0002_decisions.sql', '0003_effective_state.sql', '0004_canonical_graph.sql', '0005_vulnerability_model.sql'].map((f) => `../migrations-intel/${f}`);
export const M7 = [...M5, '../migrations-intel/0007_correlation_assurance.sql'];
export const REGISTRY_TEXT = readFileSync(new URL('../../../config/intel/sources.registry.json', import.meta.url), 'utf8');
export const newDb7 = () => newDb(M7);
/** The registry with extra sources marked APPROVED_PUBLIC (test-only; the real registry is never edited). */
export function registryWith(ids) {
  const reg = JSON.parse(REGISTRY_TEXT);
  for (const id of ids) { const s = reg.sources.find((x) => x.id === id); if (s) s.approval_state = 'APPROVED_PUBLIC'; else reg.sources.push({ id, approval_state: 'APPROVED_PUBLIC' }); }
  return JSON.stringify(reg, null, 1);
}
/** Emulates an owner-authored bootstrap migration (the only way to add the first reviewers). */
export async function bootstrapReviewers(db, reviewers = [['user:rev-a', 1001], ['user:rev-b', 1002], ['user:rev-c', 1003]], at = '2026-11-02T00:00:00.000Z') {
  const sql = await reviewerBootstrapSql(reviewers.map(([actor_id, github_user_id]) => ({ actor_id, github_user_id })), { migration: 'migration:9999_test_bootstrap', approval_record: 'owner-approval:test-fixture', at });
  db.raw.exec(sql);
  return sql;
}
/** A scratch INTEL database at 0007 with the real registry synced and (optionally) three bootstrap reviewers. */
export async function assuranceDb({ reviewers = true, registry = REGISTRY_TEXT, now = '2026-11-02T00:00:00.000Z' } = {}) {
  const db = newDb7();
  await syncSourceApprovals(db, registry, now);
  if (reviewers) await bootstrapReviewers(db);
  return db;
}
