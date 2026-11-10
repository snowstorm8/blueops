"""BlueOps validation lab and detection quality framework.

See ``docs/validation-lab.md``. Scenarios describe controlled endpoint conditions and the
observations/detections BlueOps is expected to report; the framework evaluates the real telemetry
ingestion and detection engine against them and measures detection quality. Synthetic datasets are
evaluated anywhere; live execution is confined to a verified disposable lab.
"""
