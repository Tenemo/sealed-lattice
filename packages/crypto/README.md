# Crypto package

This private package owns the current domain-separated cryptographic wrappers
used by the election foundation.

The current release implements the transcript-core `Hash512` SHAKE256 framing,
protocol digest derivation, canonical JSON normalization, ML-DSA-65 fixture key
generation, ML-DSA signature profile construction, canonical signed-root
fixture signing, and signed-root verification.

It is not a public API surface. The published `sealed-lattice` package vendors
the required runtime internally and does not export raw hash, signing, or
provider controls.
