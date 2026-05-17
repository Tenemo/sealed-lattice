# sealed-lattice

WORK IN PROGRESS - protocol-facing APIs remain under implementation and are not suitable for production or real elections.

---

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice)

---

[![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=passing%20tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml)
[![Tests coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/sealed-lattice/coverage-badge.json)](https://tenemo.github.io/sealed-lattice/coverage-summary.json)
[![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml)

---

[![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

---

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold
homomorphic voting library workspace.

The repository uses a private Turborepo workspace with one published package
and five private internal packages:

- `sealed-lattice`
- `@sealed-lattice/types`
- `@sealed-lattice/protocol`
- `@sealed-lattice/crypto`
- `@sealed-lattice/wasm`
- `@sealed-lattice/testkit`

The workspace also contains `crates/sealed-lattice-kernel`, the Rust transcript
core used by the native test and WASM loading path. The internal WASM command
surface covers transcript fixture verification, protocol digest derivation, and
the current `GF(65537)` interpolation/comparison checks used to keep the
TypeScript reference path pinned to the kernel behavior.

## Current public boundary

The published `sealed-lattice` package currently exposes a safe transcript core
fixture verifier plus the threshold, lifecycle, poll specification, capability,
board/finality, roster-manifest, cast receipt, close record, validated ordering,
and recovery-epoch election foundation helpers.

This keeps packaging, documentation, smoke checks, transcript fixtures, and
release flow stable while the broader voting API remains future implementation.

Internal PVSS ballot-algebra helpers are deterministic test infrastructure only:
they are not exported by the public package and must not be used for real ballot
confidentiality.
The internal ballot privacy plan targets ballot-level encoded score shares:
scalar score coordinates plus hidden one-hot score-bucket coordinates. Those
encoded aggregates feed TargetBasisData and a packed bit-sliced BGV evaluator.
The current scalar PVSS helpers remain fixture/oracle infrastructure only.
Claim-bearing ballot proof generation and verification, the encoded
TargetBasisData bridge, and the bit-sliced evaluator are not implemented yet.

The internal LaZer-style proof verifier work uses upstream LaZer only as an
offline deterministic oracle. Generated public vectors record upstream
provenance and accept/reject outcomes, while the Rust/WASM port independently
decodes canonical proof bytes, checks bounds, rebuilds the ABDLOP/tbox and
many-quadratic verifier path, and recomputes the final challenge for the demo
and receiver-key linear proof-vector profiles plus the compiler-derived
encoded-score field-row proof-vector profile. The verifier now records the
target coefficient representation explicitly: the demo and receiver-key oracle
targets recover LaZer's centered signed internal target coefficients from
positive JSON representatives, while the encoded-score field-row target uses
canonical unsigned `GF(65537)` representatives. The receiver-key profile still
carries an upstream `protocol-not-complete` warning, and the encoded-score
profile covers only the compiler-emitted field-row projection, so this is
compatibility evidence for the selected internal proof slice, not production
ballot-proof availability.

The encoded ballot relation now lowers the score layout into a deterministic
sparse linear-relation statement: one scalar score coordinate plus ten hidden
one-hot bucket coordinates per option, plus a concrete internal backend
statement with explicit signed sparse field rows and digest-expanded algebraic
row batches for share commitments, receiver-payload plaintext binding,
receiver-payload encryption, and receiver-key binding. Public vectors cover a
mini relation, the mandatory 20 option by 20 receiver shape, digest-changing
public target mutations, malformed backend statements, and hostile compiler
mutations. Rust/WASM verifies those vector shapes, backend statement digests,
row-batch continuity, variable columns, bounds, and statement digests.
Receiver-key proof records are generated only after the local key witness
equation and norm checks pass, and can now carry proof-byte metadata bound to a
canonical digest-expanded backend statement, a concrete public linear statement
for `A * secret + error - public_key = 0 mod 12289`, proof encoding, and public
randomness. Public
receiver-key vectors cover valid context binding, digest-changing manifest
input, malformed backend statements, mutated linear statement matrix/target
coefficients, proof-root mutation, substituted matrix seed, wrong key material,
and hostile witness-construction refusals. Rust/WASM verifies those vector
shapes, recomputes the receiver-key linear statement matrix from the frozen
seed/profile, derives the public key-material digest from the target vector,
and recomputes the backend statement, linear statement, and proof roots. The
internal Rust/WASM receiver-key proof command now accepts a proof-byte-bearing
receiver-key record when its supplied public linear statement and proof bytes
verify through the ported linear proof backend, and rejects target and proof-byte
mutations. Ballot proof records now carry the lowered relation statement digest
into their challenge binding and can also carry complete linear-backend proof
metadata: backend statement digest, concrete linear statement digest, statement
matrix digest, target vector digest, proof encoding digest, proof parameter-set
digest, public randomness digest, proof bytes digest, and proof size. The
internal Rust/WASM ballot-proof command now accepts a proof-byte-bearing ballot
record when all public verifier inputs are supplied together and the proof bytes
verify through the ported linear proof backend. The same command also verifies
the encoded-score field-row proof-vector profile through native and WASM paths.
This is still backend-record plumbing; claim-bearing ballot closure waits for
proof bytes covering the full encoded-score ballot relation, including
digest-expanded share-commitment, receiver-payload encryption, and receiver-key
binding rows.

- workspace layout and package boundaries
- packaging and tarball smoke checks
- TypeScript, ESLint, browser, and Node verification
- Astro documentation and TypeDoc generation
- transcript core test vector manifest verification
- election foundation board/finality, roster-manifest, ML-DSA-65 signed-root, cast receipt, close record, validated ordering, and recovery-epoch checks
- the Rust-to-WASM transcript core toolchain

## Documentation

- Hosted documentation site: [tenemo.github.io/sealed-lattice](https://tenemo.github.io/sealed-lattice/)
- Guides index: [tenemo.github.io/sealed-lattice/guides](https://tenemo.github.io/sealed-lattice/guides/)
- Protocol spec: [tenemo.github.io/sealed-lattice/spec](https://tenemo.github.io/sealed-lattice/spec/)
- API reference: [tenemo.github.io/sealed-lattice/api](https://tenemo.github.io/sealed-lattice/api/)

## Workspace layout

```text
sealed-lattice/
  docs/
  implementation-documentation/
  packages/
    sdk/
    protocol/
    crypto/
    wasm/
    testkit/
  crates/
    sealed-lattice-kernel/
  tools/
  typedoc/
```

## Installation

```bash
pnpm add sealed-lattice
```

The package exports the current transcript core fixture verifier and safe
election foundation helpers. It is not a usable voting library yet.

## Development

```bash
pnpm install
pnpm run check
pnpm run vectors
pnpm exec playwright install chromium firefox webkit
pnpm run test
pnpm run verify:docs
pnpm run docs:build:site
pnpm run smoke:pack
pnpm run smoke:pack:npm
pnpm run build
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
