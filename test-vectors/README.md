# Test vectors

This directory contains deterministic fixtures consumed by the repository's tests. Each consumer must rederive the vector's named application property from an independent implementation path where one exists.

A passing vector proves only its named test property. Fixtures cannot authorize protocol state or establish production readiness or supported-phone qualification.

## Maintenance

- Regenerate a changed vector in full through its owning command. Never patch a derived field or status in isolation.
- Bind source inputs, canonical parameters, and deterministic seeds needed by the consumer; do not store producer-supplied readiness or assurance claims.
- Remove a fixture when its construction is retired. Preserve executed historical results in run diagnostics, not in a selectable fixture.
- Expected authority must come from an independent source; reading it from the same vector tests only self-consistency.
- Enforce fixture eligibility in the authoritative source and tests. Do not maintain a prose snapshot of selectable files.
- Keep exact runtime and cryptographic evidence in the owning run diagnostics rather than copying measurements into fixture documentation.
