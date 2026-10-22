"""MacGuard Security Intelligence: separately versioned channels, a signed global catalog and the IOC channel (P0/P1).

Standard library only. Nothing here uses the network: fetching sources is a separate, licence-gated step that does not exist yet.
The legacy YARA channel (scripts/, workflows, releases) is NOT changed by this package; the catalog only references it.
"""
VERSION = "0.1.0"
SCHEMA_CHANNEL = "macguard.channel-manifest/1"
SCHEMA_CATALOG = "macguard.catalog/1"
SCHEMA_IOC = "macguard.ioc-record/1"
FAMILIES = ("yara", "yara-x", "sigma", "ioc", "clamav", "heuristics", "behavior", "ml", "sandbox")
