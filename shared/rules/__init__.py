"""Detection and correlation engine (see ``docs/detection-engine.md``).

Rules are data (JSON rule packs), evaluated over an assessment, optionally with the snapshot
comparison and history of earlier assessments. The package never reads a host.
"""

RULES_ENGINE_NAME = "blueops-rules"
RULES_ENGINE_VERSION = "0.5.0"
# Version line of the rule-pack, detection-results, detection-comparison and case-event documents.
RULES_SCHEMA_VERSION = "0.1.0"
