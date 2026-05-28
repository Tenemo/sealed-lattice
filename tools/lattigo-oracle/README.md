# Lattigo oracle boundary

This directory owns the development-only Lattigo reference metadata and oracle tooling used by the M7 comparison lane.

Pinned reference material is kept under `temp/lattigo/` only. The downloaded archive and extracted checkout are fully ignored by git, are not runtime code, are not public SDK inputs, and are not protocol evidence. The Docker oracle extracts the verified archive from `temp/lattigo/` as its build input. The sealed-lattice claim path accepts only sealed-lattice Rust/WASM canonical BGV objects.

Pinned reference:

- Repository: `https://github.com/tuneinsight/lattigo`
- Commit: `5dbffbdea05394de2ca3a432ed5318aa832e3f40`
- Commit date: `2026-05-07T10:30:53Z`
- Archive SHA-256: `33c9049ea3c3eb0189b55619766a5bd07457de1c2c68565778a1253d9039d680`
- Required Go toolchain for the oracle container: `go1.25.0`
- Container base image hash: `sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a`

The oracle may compare behavior that is actually comparable across all selected M7 moduli, such as selected ring construction, coefficient-domain addition, subtraction, Barrett multiplication, and NTT/INTT round trips. It must not accept Lattigo serialization, keys, default parameters, Docker output, or oracle roots as transcript objects.
