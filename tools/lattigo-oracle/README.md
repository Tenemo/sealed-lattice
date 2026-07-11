# Lattigo oracle boundary

This directory holds a development-only Lattigo oracle used to cross-check sealed-lattice BGV-RNS ring arithmetic. It is a developer sanity tool, not a verified artifact. Its build, output, and any roots it prints are not runtime code, public SDK inputs, or protocol evidence; the sealed-lattice verification path accepts only sealed-lattice Rust/WASM canonical BGV objects.

The oracle compares against Lattigo at a fixed upstream commit:

- Repository: `https://github.com/tuneinsight/lattigo`
- Commit: `5dbffbdea05394de2ca3a432ed5318aa832e3f40`

The commit is pinned as an ordinary Go module dependency: `go.mod` records the commit pseudo-version and `go.sum` records its cryptographic module checksum, so `go mod download` and `go mod verify` fetch and integrity-check the exact upstream source directly. The Go toolchain and base image digest are pinned in `Dockerfile`. There is no separate metadata manifest to keep in sync.

The oracle may compare behavior that is actually comparable across all selected BGV-RNS moduli, such as selected ring construction, coefficient-domain addition, subtraction, Barrett multiplication, and NTT/INTT round trips. It must not accept Lattigo serialization, keys, default parameters, Docker output, or oracle roots as transcript objects. Coefficient ordering and NTT root direction are reviewed for parity; automorphism direction, key-switch decomposition, ciphertext component order, slot ordering, and plaintext encoding convention are out of scope and are never treated as protocol evidence.

## Running it

Run `pnpm run test:lattigo-oracle` (requires Docker and network access to fetch the pinned module). It builds the oracle image and runs the comparison against the committed fixtures in `sealed-lattice-canonical-rns-fixtures.json`.

To move to a different upstream commit, run `go get github.com/tuneinsight/lattigo/v6@<commit>` in this directory (updates `go.mod` and `go.sum`), then re-run the oracle.
