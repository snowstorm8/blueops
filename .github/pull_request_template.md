## Summary

<!-- What and why. -->

## Category

- [ ] audit (read-only)
- [ ] persistence (read-only)
- [ ] incident (evidence / containment)
- [ ] hardening (state-changing)
- [ ] shared / docs / CI

## Checklist

- [ ] Follows [CLAUDE.md](../CLAUDE.md) conventions
- [ ] Read-only by default; state changes have confirmation, `--dry-run`, and rollback
- [ ] Protects service availability (dependencies / protected services considered)
- [ ] Output conforms to `shared/schemas/` (if applicable)
- [ ] Tests added/updated; I ran: <!-- list the exact commands and results -->
- [ ] Docs and `CHANGELOG.md` updated
- [ ] No secrets, real hostnames/IPs, or collected evidence included
- [ ] No new dependencies (or justified above)
