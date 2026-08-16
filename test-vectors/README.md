# Test vectors

This directory contains deterministic fixtures consumed by the repository's
tests. Each consumer must rederive the vector's named application property from
an independent implementation path where one exists.

A passing vector proves only its named test property. No retained vector is an
accepted proof, suite-activation record, current security certificate,
production-authority capability, or supported-phone result.

## Maintenance

- Regenerate a changed vector in full through its owning command. Never patch a
  derived field or status in isolation.
- Bind source inputs, canonical parameters, and deterministic seeds needed by
  the consumer; do not store producer-supplied readiness or assurance claims.
- Keep obsolete backend vectors deleted. Historical records cannot become a
  fallback evidence authority.
- A consumer that reads its expected authority from the same vector establishes
  canonical self-consistency, not independent authority freshness.
- Keep exact runtime and proof evidence in the owning run diagnostics rather
  than copying measurements into fixture documentation.

## Current exclusions

`selected-lattice-security-estimator-evidence.json` describes a superseded
candidate and is ineligible for suite selection until regenerated from the
final production parameters and bytes. The tracked collective-setup record is
development bookkeeping until its authority, reduction premises, and packet
chronology are independently derived and consumed by a production capability
path.
