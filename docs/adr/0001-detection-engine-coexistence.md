# ADR 0001: The legacy detection tool and the detection engine coexist

* Status: accepted
* Scope: `shared.reporting.detection` / `detect` (legacy, `BO-*` rules) and `shared.rules` (the
  detection engine, `DR-*` rules).
* Evidence: [detection-migration.md](../detection-migration.md) and `tests/shared/test_detection_parity.py`
  (run both systems on the same synthetic scenarios).

## Context

BlueOps has two detection implementations. The legacy tool reads a baseline diff of two audit
reports and reports *changes*. The engine reads an assessment (plus history and telemetry) and
mostly reports *standing state*. Measured on the legacy suite's own scenarios, the engine fires on
4 of 49 alert scenarios and 2 of 14 benign ones, severities differ on identical data, and only the
legacy tool can accept a reviewed change (`--accepted`). 1 of 31 legacy rules has a
predicate-equivalent in the engine, 19 overlap partly, 11 have nothing.

## Decision

1. **The legacy detection tool remains supported.** Its flags, exit codes, output fields and file
   layout follow the normal deprecation rules in `CLAUDE.md`; nothing is removed or renamed by this
   decision.
2. **The detection engine remains under active development** and keeps its own rule ids,
   output schema and state. It is not described as a replacement anywhere in the documentation.
3. **No replacement happens until rule parity is demonstrated.** "Parity" means the parity tests
   show, rule by rule, that the engine reports the same condition for the same data, or that a
   difference is recorded as intended in `docs/detection-migration.md`. The 11 rules with no
   engine counterpart and the 19 partial ones are the work list.
4. **Accepted-change allowlisting must exist in the engine before any migration.** Today
   `test_the_engine_has_no_accepted_change_allowlist` pins its absence and is meant to fail the day
   one is added, forcing this record to be revisited.
5. **A future migration must preserve output semantics or document each change.** That covers
   what triggers a detection (change vs. state), severity per scenario, indeterminate handling, ids
   and the exit codes. A semantic change ships with a CHANGELOG entry, an updated migration table
   and, if outputs change shape, a schema version bump. A compatibility shim that makes the
   engine *look* like the legacy tool is not a substitute for any of this.

## Consequences

* Users may run both. Their results are not interchangeable: a legacy `BO-*` detection and an
  engine `DR-*` detection of "the same thing" can differ in trigger, severity and wording.
* Work on the engine does not need to reproduce the legacy rules, and work on the legacy tool does
  not need to anticipate the engine.
* Reviewers can hold any proposal to retire the legacy tool to points 3-5 above.

## Revisit when

* An engine allowlist is implemented (point 4).
* The parity tests show no `none` and no unexplained `partial` rows.
* A third detection source is proposed (it would need its own record).
