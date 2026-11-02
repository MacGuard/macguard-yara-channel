-- 0004 (INTEL): canonical entities and evidence-backed relationships. Requires 0001. Additive: nothing in intel_records/intel_decisions is altered; an entity MAY point to the record it was derived from.
-- Principles enforced HERE (not only in the Worker), so that no writer can bypass them:
--   * stable identity: an entity is (type, namespace, key) with a normalised key; its id is '<type>:<namespace>:<key>'; identity columns never change.
--   * a relationship joins two existing entities with an ALLOWED (type, from_type, to_type) triple; its identity never changes and it is never deleted.
--   * confidence is assessed in an APPEND-ONLY log. CONFIRMED needs strong evidence (a test run, a human review, a signature or a content match) recorded beforehand;
--     REPORTED needs a source statement; an automatic correlation stays INFERRED until such evidence exists. Nothing is confirmed by default: a new relationship is UNKNOWN.
--   * evidence is append-only. Revoking a relationship is a new assessment (DISPUTED or UNKNOWN), never an edit or a deletion.
--   * reads are bounded: indexes per endpoint and type; the current state is kept in a one-row-per-relationship table (as 0003 does for decisions) so no screen scans the log.
-- Triggers are on ONE line each.
CREATE TABLE IF NOT EXISTS intel_entity_types (type TEXT PRIMARY KEY, grp TEXT NOT NULL) WITHOUT ROWID;
INSERT OR IGNORE INTO intel_entity_types (type, grp) VALUES
  ('source','provenance'),('source_version','provenance'),
  ('rule','detections'),('rule_revision','detections'),
  ('indicator','indicators'),('sample','indicators'),('malware_family','indicators'),('campaign','indicators'),
  ('vulnerability','vulnerabilities'),('advisory','vulnerabilities'),('product','vulnerabilities'),('version_range','vulnerabilities'),('poc_reference','vulnerabilities'),
  ('technique','context'),
  ('test_run','quality'),('test_evidence','quality'),('quarantine_decision','quality'),('publication_decision','quality'),
  ('artifact','distribution'),('release','distribution'),('attestation','distribution'),('revocation','distribution');

CREATE TABLE IF NOT EXISTS intel_entities (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL REFERENCES intel_entity_types(type),
  namespace TEXT NOT NULL CHECK (namespace GLOB '[a-z0-9]*' AND namespace NOT GLOB '*[^a-z0-9._-]*' AND length(namespace) BETWEEN 1 AND 64),
  key TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 512),
  display TEXT,
  record_id TEXT,
  attrs TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs)),
  source_id TEXT,
  first_seen TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (id = type || ':' || namespace || ':' || key),
  UNIQUE (type, namespace, key)
);
CREATE INDEX IF NOT EXISTS intel_entities_type ON intel_entities (type, namespace, key);
CREATE INDEX IF NOT EXISTS intel_entities_record ON intel_entities (record_id) WHERE record_id IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS intel_entities_identity BEFORE UPDATE ON intel_entities WHEN NEW.id IS NOT OLD.id OR NEW.type IS NOT OLD.type OR NEW.namespace IS NOT OLD.namespace OR NEW.key IS NOT OLD.key OR NEW.first_seen IS NOT OLD.first_seen BEGIN SELECT RAISE(ABORT, 'entity identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS intel_entities_no_delete BEFORE DELETE ON intel_entities WHEN EXISTS (SELECT 1 FROM intel_relationships r WHERE r.from_id = OLD.id OR r.to_id = OLD.id) BEGIN SELECT RAISE(ABORT, 'an entity with relationships cannot be deleted'); END;

CREATE TABLE IF NOT EXISTS intel_relationship_types (type TEXT PRIMARY KEY, from_type TEXT NOT NULL REFERENCES intel_entity_types(type), to_type TEXT NOT NULL REFERENCES intel_entity_types(type), note TEXT) WITHOUT ROWID;
INSERT OR IGNORE INTO intel_relationship_types (type, from_type, to_type, note) VALUES
  ('RULE_DETECTS_INDICATOR','rule','indicator',NULL),
  ('RULE_ASSOCIATED_WITH_CVE','rule','vulnerability','association only: it does NOT mean the rule detects exploitation'),
  ('RULE_REFERENCES_SAMPLE','rule','sample',NULL),
  ('RULE_DETECTS_TECHNIQUE','rule','technique',NULL),
  ('RULE_REFERENCES_ADVISORY','rule','advisory',NULL),
  ('RULE_DERIVED_FROM_SOURCE','rule','source',NULL),
  ('RULE_VALIDATED_BY_TEST','rule','test_run',NULL),
  ('IOC_OBSERVED_IN_CAMPAIGN','indicator','campaign',NULL),
  ('HASH_IDENTIFIES_SAMPLE','indicator','sample','the indicator must be a file hash'),
  ('SAMPLE_ASSOCIATED_WITH_FAMILY','sample','malware_family','a shared name is not a causal link'),
  ('CVE_AFFECTS_PRODUCT','vulnerability','product',NULL),
  ('CVE_HAS_ADVISORY','vulnerability','advisory',NULL),
  ('CVE_HAS_POC_REFERENCE','vulnerability','poc_reference','a documentary reference, never a confirmed exploitation'),
  ('ARTIFACT_CONTAINS_RULE','artifact','rule',NULL),
  ('ARTIFACT_SIGNED_BY','artifact','attestation','signature bundle of the artifact digest'),
  ('ARTIFACT_ATTESTED_BY','artifact','attestation',NULL),
  ('ARTIFACT_REVOKED_BY','artifact','revocation',NULL);

CREATE TABLE IF NOT EXISTS intel_relationships (
  id TEXT PRIMARY KEY CHECK (length(id) = 64),
  type TEXT NOT NULL REFERENCES intel_relationship_types(type),
  from_id TEXT NOT NULL REFERENCES intel_entities(id),
  to_id TEXT NOT NULL REFERENCES intel_entities(id),
  source_id TEXT NOT NULL,
  method TEXT NOT NULL CHECK (method IN ('asserted_by_source','derived_from_content','correlated','manual','test')),
  version TEXT,
  exposure TEXT NOT NULL DEFAULT 'internal' CHECK (exposure IN ('public','internal','restricted')),
  observed_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (from_id <> to_id),
  UNIQUE (type, from_id, to_id, source_id, method)
);
CREATE INDEX IF NOT EXISTS intel_rel_from ON intel_relationships (from_id, type, id);
CREATE INDEX IF NOT EXISTS intel_rel_to ON intel_relationships (to_id, type, id);
CREATE TRIGGER IF NOT EXISTS intel_rel_endpoints BEFORE INSERT ON intel_relationships WHEN NOT EXISTS (SELECT 1 FROM intel_relationship_types t JOIN intel_entities f ON f.id = NEW.from_id JOIN intel_entities x ON x.id = NEW.to_id WHERE t.type = NEW.type AND t.from_type = f.type AND t.to_type = x.type) BEGIN SELECT RAISE(ABORT, 'relationship type does not allow these endpoint types (or an endpoint does not exist)'); END;
CREATE TRIGGER IF NOT EXISTS intel_rel_hash_endpoint BEFORE INSERT ON intel_relationships WHEN NEW.type = 'HASH_IDENTIFIES_SAMPLE' AND (SELECT namespace FROM intel_entities WHERE id = NEW.from_id) NOT IN ('sha256','sha512','sha1','md5') BEGIN SELECT RAISE(ABORT, 'HASH_IDENTIFIES_SAMPLE needs a file-hash indicator'); END;
CREATE TRIGGER IF NOT EXISTS intel_rel_immutable BEFORE UPDATE ON intel_relationships BEGIN SELECT RAISE(ABORT, 'relationships are immutable: record a new assessment instead'); END;
CREATE TRIGGER IF NOT EXISTS intel_rel_no_delete BEFORE DELETE ON intel_relationships BEGIN SELECT RAISE(ABORT, 'relationships are never deleted: record a DISPUTED or UNKNOWN assessment'); END;

CREATE TABLE IF NOT EXISTS intel_relationship_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  relationship_id TEXT NOT NULL REFERENCES intel_relationships(id),
  kind TEXT NOT NULL CHECK (kind IN ('source_statement','content_match','test_run','human_review','signature','document')),
  ref TEXT NOT NULL CHECK (length(ref) BETWEEN 1 AND 1024),
  sha256 TEXT CHECK (sha256 IS NULL OR (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*')),
  source_id TEXT,
  observed_at TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  note TEXT
);
CREATE INDEX IF NOT EXISTS intel_rel_evidence_rel ON intel_relationship_evidence (relationship_id, kind, id);
CREATE TRIGGER IF NOT EXISTS intel_rel_evidence_no_update BEFORE UPDATE ON intel_relationship_evidence BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS intel_rel_evidence_no_delete BEFORE DELETE ON intel_relationship_evidence BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;

CREATE TABLE IF NOT EXISTS intel_relationship_assessments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  relationship_id TEXT NOT NULL REFERENCES intel_relationships(id),
  confidence TEXT NOT NULL CHECK (confidence IN ('CONFIRMED','REPORTED','INFERRED','DISPUTED','UNKNOWN')),
  verification TEXT NOT NULL CHECK (verification IN ('VERIFIED','UNVERIFIED','FAILED')),
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 5 AND 2000),
  actor TEXT NOT NULL,
  at TEXT NOT NULL,
  CHECK (verification <> 'VERIFIED' OR confidence = 'CONFIRMED')
);
CREATE INDEX IF NOT EXISTS intel_rel_assess_rel ON intel_relationship_assessments (relationship_id, id DESC);
CREATE TRIGGER IF NOT EXISTS intel_rel_assess_confirmed BEFORE INSERT ON intel_relationship_assessments WHEN NEW.confidence = 'CONFIRMED' AND NOT EXISTS (SELECT 1 FROM intel_relationship_evidence e WHERE e.relationship_id = NEW.relationship_id AND e.kind IN ('test_run','human_review','signature','content_match')) BEGIN SELECT RAISE(ABORT, 'CONFIRMED needs a test run, human review, signature or content match as evidence'); END;
CREATE TRIGGER IF NOT EXISTS intel_rel_assess_reported BEFORE INSERT ON intel_relationship_assessments WHEN NEW.confidence = 'REPORTED' AND NOT EXISTS (SELECT 1 FROM intel_relationship_evidence e WHERE e.relationship_id = NEW.relationship_id AND e.kind IN ('source_statement','document')) BEGIN SELECT RAISE(ABORT, 'REPORTED needs a source statement or document as evidence'); END;
CREATE TRIGGER IF NOT EXISTS intel_rel_assess_poc BEFORE INSERT ON intel_relationship_assessments WHEN NEW.confidence = 'CONFIRMED' AND (SELECT type FROM intel_relationships WHERE id = NEW.relationship_id) = 'CVE_HAS_POC_REFERENCE' AND NOT EXISTS (SELECT 1 FROM intel_relationship_evidence e WHERE e.relationship_id = NEW.relationship_id AND e.kind = 'human_review') BEGIN SELECT RAISE(ABORT, 'a PoC reference is confirmed only by a human review of the document, never automatically'); END;
CREATE TRIGGER IF NOT EXISTS intel_rel_assess_no_update BEFORE UPDATE ON intel_relationship_assessments BEGIN SELECT RAISE(ABORT, 'assessments are append-only'); END;
CREATE TRIGGER IF NOT EXISTS intel_rel_assess_no_delete BEFORE DELETE ON intel_relationship_assessments BEGIN SELECT RAISE(ABORT, 'assessments are append-only'); END;

-- Current state: one row per relationship, kept in step by triggers; a relationship without an assessment is UNKNOWN/UNVERIFIED (inserted on creation).
CREATE TABLE IF NOT EXISTS intel_relationship_state (relationship_id TEXT PRIMARY KEY, confidence TEXT NOT NULL, verification TEXT NOT NULL, assessment_id INTEGER, evidence_count INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS intel_rel_state_init AFTER INSERT ON intel_relationships BEGIN INSERT INTO intel_relationship_state (relationship_id, confidence, verification, assessment_id, evidence_count) VALUES (NEW.id, 'UNKNOWN', 'UNVERIFIED', NULL, 0); END;
CREATE TRIGGER IF NOT EXISTS intel_rel_state_assess AFTER INSERT ON intel_relationship_assessments BEGIN UPDATE intel_relationship_state SET confidence = NEW.confidence, verification = NEW.verification, assessment_id = NEW.id WHERE relationship_id = NEW.relationship_id; END;
CREATE TRIGGER IF NOT EXISTS intel_rel_state_evidence AFTER INSERT ON intel_relationship_evidence BEGIN UPDATE intel_relationship_state SET evidence_count = evidence_count + 1 WHERE relationship_id = NEW.relationship_id; END;
-- The state table cannot be used to bypass the log: it only accepts values that equal the LATEST assessment and the real evidence count.
CREATE TRIGGER IF NOT EXISTS intel_rel_state_guard_insert BEFORE INSERT ON intel_relationship_state WHEN NEW.confidence <> 'UNKNOWN' OR NEW.verification <> 'UNVERIFIED' OR NEW.assessment_id IS NOT NULL OR NEW.evidence_count <> 0 BEGIN SELECT RAISE(ABORT, 'relationship state starts UNKNOWN and changes only through assessments and evidence'); END;
CREATE TRIGGER IF NOT EXISTS intel_rel_state_guard_update BEFORE UPDATE ON intel_relationship_state WHEN NEW.relationship_id IS NOT OLD.relationship_id OR NEW.evidence_count <> (SELECT COUNT(*) FROM intel_relationship_evidence e WHERE e.relationship_id = NEW.relationship_id) OR NOT ((NEW.assessment_id IS NULL AND NEW.confidence = 'UNKNOWN' AND NEW.verification = 'UNVERIFIED') OR EXISTS (SELECT 1 FROM intel_relationship_assessments a WHERE a.id = NEW.assessment_id AND a.relationship_id = NEW.relationship_id AND a.confidence = NEW.confidence AND a.verification = NEW.verification AND a.id = (SELECT MAX(x.id) FROM intel_relationship_assessments x WHERE x.relationship_id = NEW.relationship_id))) BEGIN SELECT RAISE(ABORT, 'relationship state must equal its latest assessment and evidence count'); END;
CREATE TRIGGER IF NOT EXISTS intel_rel_state_no_delete BEFORE DELETE ON intel_relationship_state BEGIN SELECT RAISE(ABORT, 'relationship state is not deleted'); END;
