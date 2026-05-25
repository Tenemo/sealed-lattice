# Lattigo reference boundary

This directory pins the development-only Lattigo reference used by the M7 oracle tooling.

The checkout under `reference-projects/lattigo/upstream/` and the downloaded archive are ignored by git. The Docker oracle extracts the verified archive as its build input; the local checkout is reference material only. They are not runtime code, not public SDK inputs, and not protocol evidence. The sealed-lattice claim path accepts only sealed-lattice Rust/WASM canonical BGV objects.

Pinned reference:

- Repository: `https://github.com/tuneinsight/lattigo`
- Commit: `5dbffbdea05394de2ca3a432ed5318aa832e3f40`
- Commit date: `2026-05-07T10:30:53Z`
- Archive SHA-256: `33c9049ea3c3eb0189b55619766a5bd07457de1c2c68565778a1253d9039d680`
- Required Go toolchain for the oracle container: `go1.25.0`
- Container base image digest: `sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a`
- Oracle command digest: `117a46f4a02dbc9eaf738b2d1431777c2510da56b681c3de1d78773cf3617c6a`
- Oracle Dockerfile digest: `eb996b12ca2ccbf0ca524d38ecfa9f0c0535a8424b9c0d337b486fb5f0692470`

The oracle tooling in `tools/lattigo-oracle/` may compare behavior that is actually comparable across all selected M7 moduli, such as selected ring construction, coefficient-domain addition, subtraction, Barrett multiplication, and NTT/INTT round trips. It must not accept Lattigo serialization, keys, default parameters, Docker output, or oracle roots as transcript objects.
