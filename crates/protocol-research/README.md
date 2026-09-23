# Protocol research workspace

research direction

This workspace versions the executable threshold-FHE research construction. It is separate from the published SDK and is not enabled by its foundation API. End-to-end post-quantum security is unestablished. Use synthetic data only.

The current native case uses ten participants, ten options and all ten result identifiers. Five honest participants cast ballots, which meets the minimum turnout of `f+2` accepted ballots, and two corrupt participants submit authenticated invalid ballots. It generates fresh original credentials, proves and verifies setup, classifies signed sources, evaluates the encrypted ranking, certifies its target, proves original-key releases and checks reconstruction. A target with fewer accepted ballots than the minimum turnout takes the no-result branch. The no-result cases cover all-empty sources and one authenticated invalid ballot with the remaining sources empty. The latter preserves a valid body header and consumes the classification operands before rejecting its malformed proof. These cases retain volatile native private state; they do not establish browser custody, durable terminal publication or a complete participant workflow. Subset reconstruction is not evidence of participants departing before release generation.

Ballots pack a comparison window for every rank, whatever result length the poll requests. The evaluator and terminal decoder support every requested result length for the ten-participant, ten-option profile. The encrypted computation clears omitted ranks; the decoder rejects a plaintext containing them. The complete-ordering program keeps its existing bytes. This arithmetic profile supports no other participant or option count: poll creation refuses other option counts, and a roster proposal refuses other sizes.

## Build and run

Prerequisites are Node.js satisfying the repository's engine requirement, the pinned pnpm version, Rust 1.95.0 with rustfmt, Clippy and the `wasm32-unknown-unknown` target, and Protocol Buffers compiler 36.1. Install protoc from the official Protocol Buffers release and put it on `PATH`, or set `PROTOC` to that executable. The runner checks both compiler versions and records the native executable digest; it does not search an ignored checkout. Cargo's lockfile pins registry dependency versions and checksums. Before an offline run, populate the Cargo cache with:

```text
cargo +1.95.0 fetch --locked --manifest-path crates/protocol-research/Cargo.toml
pnpm run research:protocol -- check
pnpm run research:protocol -- native-result
pnpm run research:protocol -- native-empty
pnpm run research:protocol -- native-invalid-only
```

The focused numerical case checks complete and shorter output prefixes using the same deterministic BFV ciphertext inputs:

```text
pnpm run research:protocol -- native-prefix
```

It exercises the coefficient-selection gates and checks every decrypted coefficient with a test-only secret and an independent interpolation oracle. Because these numerical probes decrypt synthetic test ciphertexts, they compile only with the `numerical-probes` feature, which this case enables; evaluation modules neither contain nor export them. It creates no participants, ballots, certificate or protocol terminal.

For focused retrieval checks, an existing passed public completion run can supply archived public fixtures:

```text
pnpm run research:protocol:public -- available-records <public-completion-run>
```

This case supplies a nonconsecutive quorum of votes and a nonconsecutive release subset, leaves other files absent, and injects corrupt extras. It recomputes setup and evaluation before consuming completion records. This is a retrieval test after generation; it does not demonstrate participants disappearing before their later actions.

An independently verified public target can also be checked against a directory containing actual participant messages:

```text
pnpm run research:protocol:public -- certificate-records <public-target-run> <public-record-directory>
pnpm run research:protocol:public -- release-records <public-target-run> <public-record-directory>
pnpm run research:protocol:public -- terminal-records <public-target-run> <public-record-directory>
```

All three modes recompute setup, classification and the target. The certificate mode needs only a valid quorum of target votes and does not request release messages. The release mode additionally verifies one available release message and runs wrong-target, incomplete-proof, altered-proof and duplicate controls at its actual author; it requires an encrypted target and emits no result identifiers. The terminal mode verifies sufficient release shares when the target is encrypted. These checks do not establish durable publication by themselves.

The public reader retains the accepted target-vote packets in its output's `certificate-records/` directory, using each authenticated author's position. The run report identifies that directory for archive construction. Candidate file positions are transport labels and need not match the author encoded in a vote; archive extraction must use the retained packets. Retrieval still requires the owning certificate verifier.

The runner refuses unknown or empty selectors, serializes heavy runs, derives the corpus bound before generation, checks available memory, contains the process tree and records diagnostics under `logs/`. Native process memory, runtime and public storage measurements remain distinct from unmeasured browser, recovery, network-transfer and participant-visit costs. Failed diagnostics are preserved.

All sources, parameters, toolchain selection and third-party code needed by the native generation case are tracked. That case uses `temp/` only for run-owned scratch. No prior log, private participant profile, generated target directory or reference checkout is an input to native generation. Source paths are captured in each run; moving code changes the build identity and never authorizes private-state import.

The public verifier and scalar bridge are library consumers of the same owning Rust verifiers. Target certification alone does not establish archive availability. The complete reduction argument, independent adversarial review, supported-profile coverage, resource qualification and physical qualification remain outstanding.

The original participant bridge also exposes target signing and certified release in the same scalar instance. New release work requires the actual certificate-derived context and original recipient key; an unsigned retained body passes the owning verifier before signing. Completed-message restoration verifies its original signature and exact body digest and restores consumed authority only. A restored credential signs nothing new until the authenticated participant root unlocks the purposes its records show unused. The experimental worker connects encrypted journal and root transitions, but its complete target/release browser fault gate remains open. These interfaces are not exported by the published SDK.

The worker authenticates release-journal records before staging them in the scalar byte buffer. Consumed records are retired inside the existing memory limit; the buffer supplies no release authority. The numerical proof verifier uses a dedicated workload role; actual certified messages must pass the public release-records case above.

## Third-party sources

`vendor/fhe-rs` contains the used arithmetic, utility and trait crates from `tlepoint/fhe.rs` at `e248cd288c754e5cca9a54d4b7df505058a539ed`, plus the previously verified scalar execution and dependency-pin changes. The imported local revision is `877151d0f2484aef379c2253fb5bb0d380eb528a`. Its MIT license is retained. The existing Protobuf schema and build remain unchanged.

`vendor/keccak` contains RustCrypto keccak 0.2.2 with the existing scalar backend delegation to keccak 0.1.6. Its MIT and Apache-2.0 licenses are retained. Unused registry test/benchmark manifest entries are removed because those sources were not part of the imported dependency. This is a pinned local dependency, not a claim of an unmodified upstream release.
