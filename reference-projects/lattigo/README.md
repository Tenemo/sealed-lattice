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
- Oracle command digest: `63d1b1c2b60c96e4654b584e2288945e1cdc6bf65f2a9f00077f083757e588c3`
- Oracle Dockerfile digest: `92b8ed9aacc8fada0cdd59cd49488c1ae1c056487c1cf18ec58a6db9f948bf86`

The oracle tooling in `tools/lattigo-oracle/` may compare behavior that is actually comparable, such as selected ring construction, coefficient-domain arithmetic, and NTT/INTT round trips. It must not accept Lattigo serialization, keys, default parameters, Docker output, or oracle roots as transcript objects.
