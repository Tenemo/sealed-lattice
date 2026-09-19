# Protocol research workspace

research direction

This workspace versions the executable threshold-FHE research construction. It is separate from the published SDK and is not enabled by its foundation API. End-to-end post-quantum security is unestablished. Use synthetic data only.

The current native case uses ten participants, ten options and all ten result identifiers. It generates fresh original credentials, proves and verifies setup, classifies signed sources, evaluates the encrypted ranking, certifies its target, proves original-key releases and checks reconstruction. The empty case verifies a certified no-result target. These cases retain volatile native private state; they do not establish browser custody, durable terminal publication or a complete participant workflow. Subset reconstruction is not evidence of participants departing before release generation.

## Build and run

Prerequisites are Node.js satisfying the repository's engine requirement, the pinned pnpm version, Rust 1.95.0 with rustfmt, Clippy and the `wasm32-unknown-unknown` target, and Protocol Buffers compiler 36.1. Install protoc from the official Protocol Buffers release and put it on `PATH`, or set `PROTOC` to that executable. The runner checks both compiler versions and records the native executable digest; it does not search an ignored checkout. Cargo's lockfile pins registry dependency versions and checksums. Before an offline run, populate the Cargo cache with:

```text
cargo +1.95.0 fetch --locked --manifest-path crates/protocol-research/Cargo.toml
pnpm run research:protocol -- check
pnpm run research:protocol -- native-result
pnpm run research:protocol -- native-empty
```

The runner refuses unknown or empty selectors, serializes heavy runs, derives the corpus bound before generation, checks available memory, contains the process tree and records diagnostics under `logs/`. Native process memory, runtime and public storage measurements remain distinct from unmeasured browser, recovery, network-transfer and participant-visit costs. Failed diagnostics are preserved.

All sources, parameters, toolchain selection and third-party code needed by this workspace are tracked. `temp/` contains only run-owned scratch. No prior log, private participant profile, generated target directory or reference checkout is an input to the native generation case. Source paths are captured in each run; moving code changes the build identity and never authorizes private-state import.

The public verifier and scalar bridge are library consumers of the same owning Rust verifiers. Target certification alone does not establish archive availability. The complete reduction argument, independent adversarial review, supported-profile coverage, resource qualification and physical qualification remain outstanding.

## Third-party sources

`vendor/fhe-rs` contains the used arithmetic, utility and trait crates from `tlepoint/fhe.rs` at `e248cd288c754e5cca9a54d4b7df505058a539ed`, plus the previously verified scalar execution and dependency-pin changes. The imported local revision is `877151d0f2484aef379c2253fb5bb0d380eb528a`. Its MIT license is retained. The existing Protobuf schema and build remain unchanged.

`vendor/keccak` contains RustCrypto keccak 0.2.2 with the existing scalar backend delegation to keccak 0.1.6. Its MIT and Apache-2.0 licenses are retained. Unused registry test/benchmark manifest entries are removed because those sources were not part of the imported dependency. This is a pinned local dependency, not a claim of an unmodified upstream release.
