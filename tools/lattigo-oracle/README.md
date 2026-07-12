# Lattigo oracle boundary

This directory holds a development-only Lattigo oracle used to cross-check sealed-lattice BGV-RNS ring arithmetic. It is a developer sanity tool, not a verified artifact. Its build, output, and any roots it prints are not runtime code, public SDK inputs, or protocol evidence; the sealed-lattice verification path accepts only sealed-lattice Rust/WASM canonical BGV objects.

The oracle compares against a fixed Lattigo module release:

- Repository: `https://github.com/tuneinsight/lattigo`
- Module version: `v6.0.0`

`go.mod` records the module version and `go.sum` records its cryptographic module checksums, so `go mod download` and `go mod verify` fetch and integrity-check the selected upstream source directly. The Go toolchain and base image digest are pinned in `Dockerfile`. There is no separate metadata manifest to keep in sync.

The oracle may compare behavior that is actually comparable across all selected BGV-RNS moduli, such as selected ring construction, coefficient-domain addition, subtraction, Barrett multiplication, and NTT/INTT round trips. It must not accept Lattigo serialization, keys, default parameters, Docker output, or oracle roots as transcript objects. Coefficient ordering and NTT root direction are reviewed for parity; automorphism direction, key-switch decomposition, ciphertext component order, slot ordering, and plaintext encoding convention are out of scope and are never treated as protocol evidence.

## Running it

Run `pnpm run test:lattigo-oracle` (requires Docker and network access to fetch the pinned module). It sends only this directory as the Docker build context. The final scratch image contains a static oracle executable and the committed fixture, runs under a numeric non-root user, and has no Go toolchain. The container runs without a network or writable root filesystem, with all capabilities dropped, no privilege escalation, at most 128 processes, and a 2 GiB memory and swap ceiling.

To move to a different upstream release or commit, run `go get github.com/tuneinsight/lattigo/v6@<version-or-commit>` in this directory (updates `go.mod` and `go.sum`), then re-run the oracle.
