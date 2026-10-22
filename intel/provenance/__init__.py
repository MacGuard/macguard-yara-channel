"""Per-file software provenance engine (design: docs/intelligence/PROVENANCE-DESIGN.md, schema: docs/intelligence/schemas/file-provenance.schema.json).

Read-only and offline. Standard library only (Python 3.9+). The six facts (content origin, installation method, package ownership,
integrity status, provenance confidence, detection status) are separate fields; UNKNOWN is a first-class result and is never "safe".

Layout: runner (injectable subprocess runner) / fileid (path validation, TOCTOU-safe hashing) / model (evidence book, Finding) /
collectors (brew, cask, macos pkgutil+xattr+codesign, dpkg, pip, manual) / combiner (pure policy 1.0.0) / engine (assembly) / cli.
"""
VERSION = "0.1.0"
POLICY_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"
ENGINE_NAME = "macguard-provenance"
