## Problem and resulting behavior

What changed, why, and what should a reviewer observe before/after?

## Validation

List checks actually run and their results. State skipped checks and limitations.
Use synthetic data; do not attach private reports, credentials or production logs.

## Review checklist

- [ ] Security impact assessed, including authorization and credential handling.
- [ ] Any new provider permissions are documented with their purpose and scope.
- [ ] Any new metadata fields and retention behavior are documented.
- [ ] OWASP mapping reviewed if affected; no unsupported coverage claims.
- [ ] Backward compatibility, stable identity IDs and evidence provenance reviewed.
- [ ] Relevant tests/docs updated; incomplete evidence keeps an honest outcome.

For a database change, describe migration, backup and rollback compatibility.
For a rule/connector, include positive, negative and incomplete-evidence cases.
