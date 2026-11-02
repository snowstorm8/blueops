"""BlueOps assessment engine: module registry, execution, and assessment documents.

See ``docs/assessment-engine.md``. The engine orchestrates the existing platform collectors
(Bash, PowerShell) and any plugin modules; it never inspects the host itself.
"""

ENGINE_NAME = "blueops-engine"
ENGINE_VERSION = "0.4.0"
# Version line shared by the documents introduced with the engine: assessment, snapshot
# comparison and module manifests. The audit-report schema keeps its own line (0.2.0).
ASSESSMENT_SCHEMA_VERSION = "0.1.0"
