# Lattigo oracle boundary

This directory holds a development-only Lattigo oracle used to cross-check sealed-lattice BGV-RNS ring arithmetic. It is a developer sanity tool, not a verified artifact.

Pinned reference material is kept under `temp/lattigo/` only. The downloaded archive and extracted checkout are fully ignored by git, are not runtime code, are not public SDK inputs, and are not protocol evidence. The Docker oracle extracts the verified archive from `temp/lattigo/` as its build input. The sealed-lattice verification path accepts only sealed-lattice Rust/WASM canonical BGV objects.

The oracle compares against Lattigo at a fixed upstream commit:

- Repository: `https://github.com/tuneinsight/lattigo`
- Commit: `5dbffbdea05394de2ca3a432ed5318aa832e3f40`

The archive SHA-256 integrity check, the Go toolchain, and the base image digest all live in `Dockerfile`, which verifies the downloaded archive with `sha256sum -c` and resolves Go modules with `go mod verify` before building. That is the single source of truth; there is no separate metadata manifest to keep in sync.

The oracle may compare behavior that is actually comparable across all selected BGV-RNS moduli, such as selected ring construction, coefficient-domain addition, subtraction, Barrett multiplication, and NTT/INTT round trips. It must not accept Lattigo serialization, keys, default parameters, Docker output, or oracle roots as transcript objects. Coefficient ordering and NTT root direction are reviewed for parity; automorphism direction, key-switch decomposition, ciphertext component order, slot ordering, and plaintext encoding convention are out of scope and are never treated as protocol evidence.

## Running it

Place the upstream archive at the git-ignored path `temp/lattigo/lattigo-5dbffbdea05394de2ca3a432ed5318aa832e3f40.zip`, then run `pnpm run test:lattigo-oracle` (requires Docker). It builds the oracle image and runs the comparison against the committed fixtures in `sealed-lattice-canonical-rns-fixtures.json`.
