# Lattigo reference boundary

This directory pins the development-only Lattigo reference used by the M7 oracle tooling.

The checkout under `reference-projects/lattigo/upstream/` and the downloaded archive are ignored by git. They are not runtime code, not public SDK inputs, and not protocol evidence. The sealed-lattice claim path accepts only sealed-lattice Rust/WASM canonical BGV objects.

Pinned reference:

- Repository: `https://github.com/tuneinsight/lattigo`
- Commit: `5dbffbdea05394de2ca3a432ed5318aa832e3f40`
- Commit date: `2026-05-07T10:30:53Z`
- Archive SHA-256: `33c9049ea3c3eb0189b55619766a5bd07457de1c2c68565778a1253d9039d680`
- Required Go toolchain for the oracle container: `go1.25.0`
- Container base image digest: `sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a`
- Oracle command digest: `da8d56e61b61e4da9b30357a00bf6b7e0058694c27a1e57ddd6aa40593118372`
- Oracle Dockerfile digest: `9045a4402372359f14cb3baea7e8177b2f12c41059faf66d5ccf203301e45f28`

The oracle tooling in `tools/lattigo-oracle/` may compare behavior that is actually comparable across all selected M7 moduli, such as selected ring construction, coefficient-domain addition, subtraction, Barrett multiplication, and NTT/INTT round trips. It must not accept Lattigo serialization, keys, default parameters, Docker output, or oracle roots as transcript objects.
