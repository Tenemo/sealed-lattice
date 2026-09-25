# Protocol research workspace

research direction

This workspace versions the executable threshold-FHE research construction. It is separate from the published SDK and is not enabled by its foundation API. End-to-end post-quantum security is unestablished. Use synthetic data only.

The native cases take a participant count from 3 to 20 and an option count from 2 to 20, ten of each by default, and request every result identifier. Their roles follow from the threshold completion rules, with at most `f=floor((n-1)/3)` corrupt participants. Positions one to `f` are corrupt and withhold their target signatures. The first `f+2` honest positions cast accepted ballots, which meets the minimum turnout. The last corrupt position signs two on-time envelopes, which make its slot conflicting, and a late one that every verifier refuses; the two corrupt positions before it, where present, submit authenticated invalid ballots. When `f` is positive and another honest position remains, the relay delivers the last position's ballot only to the last `f` positions, so the organizer's proposal of `n-f` close responses omits it within the bound of `f`. That voter still signs the target, and its ballot does not reach the result. Before the organizer answers, the case checks that no other participant takes a response, that a participant refuses a new envelope for a slot with two known ones and, after its intent lock, a late envelope, and that the organizer refuses a response delivered with an envelope it already knows or that the response does not list. After the proposal, each participant's ordered log of accepted close inputs, replayed into a fresh close state, must reproduce its response and the organizer's proposal. At three participants `f` is zero, so no participant is corrupt and no ballot is omitted. The case generates fresh original credentials, proves and verifies setup, closes through signed close responses, classifies the usable slots, evaluates the encrypted ranking, certifies its target, proves original-key releases and checks reconstruction from every release subset and from the honest shares that remain after every departure of at most `f` participants. When either kind has more than 256 sets, it checks a deterministic sample of 256. A target with fewer accepted ballots than the minimum turnout takes the no-result branch. The no-result cases cover a close with no ballot and one whose only listed submission is an authenticated invalid ballot. The latter preserves a valid body header and consumes the classification operands before rejecting its malformed proof. These cases retain volatile native private state; they do not establish browser custody, durable terminal publication or a complete participant workflow. Subset reconstruction is not evidence of participants departing before release generation.

Ballots pack a comparison window for every rank, whatever result length the poll requests. The evaluator and terminal decoder support every requested result length of every profile of 3 to 20 participants and 2 to 20 options. The encrypted computation clears omitted ranks; the decoder rejects a plaintext containing them. The complete-ordering program of ten participants and ten options keeps its existing bytes. Poll creation refuses only option counts outside that range, and a roster proposal refuses only sizes outside it.

The `supported-profile` crate derives each profile's thresholds, interpolation points and relation layouts in closed form. Its tracked `profiles.bin` table carries the searched parameters: both moduli with their primality witnesses, the sharing and release widths, the common sampling width and the share lifting limb and carry widths. The repository's protocol tests compare that table with the independent TypeScript profile model. After a model change, regenerate it with:

```text
pnpm run research:profiles -- --output crates/protocol-research/supported-profile/profiles.bin
```

## Build and run

Prerequisites are Node.js satisfying the repository's engine requirement, the pinned pnpm version, Rust 1.95.0 with rustfmt, Clippy and the `wasm32-unknown-unknown` target, and Protocol Buffers compiler 36.1. Install protoc from the official Protocol Buffers release and put it on `PATH`, or set `PROTOC` to that executable. The runner checks both compiler versions and records the native executable digest; it does not search an ignored checkout. Cargo's lockfile pins registry dependency versions and checksums. Before an offline run, populate the Cargo cache with:

```text
cargo +1.95.0 fetch --locked --manifest-path crates/protocol-research/Cargo.toml
pnpm run research:protocol -- check
pnpm run research:protocol -- native-result
pnpm run research:protocol -- native-empty
pnpm run research:protocol -- native-invalid-only
```

Each native ceremony case optionally takes its participant and option counts:

```text
pnpm run research:protocol -- native-result 3 2
```

The runner derives the expected roles, ranking and checked set counts from the independent TypeScript threshold and ranking models, not from the ceremony, and scales its deadline with the participant count.

The focused numerical case checks complete and shorter output prefixes at the smallest, the ten-participant and the largest profile, each prefix from the same deterministic BFV ciphertext inputs as its complete ordering:

```text
pnpm run research:protocol -- native-prefix
```

It exercises the coefficient-selection gates and checks every decrypted coefficient with a test-only secret and an independent interpolation oracle. Because these numerical probes decrypt synthetic test ciphertexts, they compile only with the `numerical-probes` feature, which this case enables; evaluation modules neither contain nor export them. It creates no participants, ballots, certificate or protocol terminal.

For focused retrieval checks, a passed native result run supplies its public ceremony records:

```text
pnpm run research:protocol:public -- available-records <native-result-run>
```

This case supplies the certificate's votes and a nonconsecutive release subset, leaves other files absent, and injects corrupt extras. It recomputes setup, the close barrier and evaluation before consuming completion records. This is a retrieval test after generation; it does not demonstrate participants disappearing before their later actions.

The records a passed native run's verified result depends on can also travel through the maintained public archive:

```text
pnpm run build
pnpm run research:protocol:public -- archived-records <native-run>
```

The reader first verifies the native records and lists every public input its accepted result depends on: setup, the close intent, proposal and named responses, their listed envelopes, the usable bodies and the accepted votes and release shares. The case publishes exactly those files as one archive closure bound to the poll identity to three local replicas with the built SDK client. After the source and one acknowledging replica are gone, a fresh reader retrieves the closure, rebuilds the reader input only from authenticated records and must reach the same target and terminal while depending on exactly the retrieved files. A reader bound to another poll and a closure without one usable body are refused. A roster whose public records exceed the archive client's maximum retrieval bytes cannot be archived as one closure. Local replicas on one host are not independent fault domains, and no browser reader or departure chronology is exercised.

The public setup and close records of a passed native run can also be checked against a directory containing actual participant messages:

```text
pnpm run research:protocol:public -- certificate-records <native-run> <public-record-directory>
pnpm run research:protocol:public -- release-records <native-run> <public-record-directory>
pnpm run research:protocol:public -- terminal-records <native-run> <public-record-directory>
```

All three modes recompute setup, the close barrier from the archived intent, responses, proposal and listed envelopes, the classification of each usable slot and the target. Only usable slots' bodies are read. The certificate mode needs only a valid quorum of target votes and does not request release messages. The release mode additionally verifies one available release message and runs wrong-target, incomplete-proof, altered-proof and duplicate controls at its actual author; it requires an encrypted target and emits no result identifiers. The terminal mode verifies sufficient release shares when the target is encrypted. These checks do not establish durable publication by themselves.

The public reader retains the accepted target-vote packets in its output's `certificate-records/` directory, using each authenticated author's position. The run report identifies that directory for archive construction. Candidate file positions are transport labels and need not match the author encoded in a vote; archive extraction must use the retained packets. Retrieval still requires the owning certificate verifier.

The maintained participant runtime runs registration, roster agreement, setup contribution, setup verification, signed ballots, close responses and target votes in external desktop Chrome:

```text
pnpm run research:participant -- 3 2
```

The runner builds the scalar participant module and the bundled worker from tracked sources, checks that the module contains no vector instructions and declares exactly its bounded memory, and derives every bound the worker enforces from the profile's models. The page runs the worker only after checking its hash, and before any operation the worker checks the module's hash and recomputes the runtime identity over the sources, module, worker and descriptor. Each participant uses its own disk-backed Chrome profile under `temp/`, which the run removes when it ends, and each Chrome process tree runs under a memory guard. The organizer creates the poll and registers, the other participants join, and every participant verifies all registration records before the organizer signs the roster proposal or another participant accepts it. Each participant then generates its contribution in two one-shot steps around a sealed checkpoint and signs its confirmation. It signs its opening only after every confirmation is published, so an earlier request stays pending. Every participant then verifies the complete setup from the public records in its own module, which alone emits the retained setup reference; a ballot is refused before it. Each participant then locks its scores and ballot time and appends a journal of original random bytes, one encrypted record per transition, before the module encrypts and proves the ballot from that journal alone. An interrupted attempt replays the same journal and must reproduce its retained envelope. A signed ballot refuses other scores and is only delivered again. Each participant then collects published ballots into an encrypted close log, one event and its records per accepted delivery. The organizer's close time is the second-latest ballot time, so locking its intent retires a strictly later ballot wherever it was held. Every participant responds with the on-time ballots it holds, and the organizer takes the other responses, fetches the one body they list that it lacks, and proposes. Each participant then verifies the close barrier from the public close records in its own module, classifies every usable ballot, evaluates the public target, and retains the exact target body with fresh signing coins before it signs its target vote. Each root transition commits under a fresh key only after its exact predecessor authenticates. Release and later protocol stages are not exercised, and a desktop result is development evidence, not supported-phone qualification.

The runner refuses unknown or empty selectors, serializes heavy runs, derives the corpus bound before generation, checks available memory, contains the process tree and records diagnostics under `logs/`. Native process memory, runtime and public storage measurements remain distinct from unmeasured browser, recovery, network-transfer and participant-visit costs. Failed diagnostics are preserved.

All sources, parameters, toolchain selection and third-party code needed by the native generation case are tracked. That case uses `temp/` only for run-owned scratch. No prior log, private participant profile, generated target directory or reference checkout is an input to native generation. Source paths are captured in each run; moving code changes the build identity and never authorizes private-state import.

The public verifier and scalar bridge are library consumers of the same owning Rust verifiers. Target certification alone does not establish archive availability. The complete reduction argument, independent adversarial review, resource qualification of every supported profile and physical qualification remain outstanding.

The original participant bridge also exposes target signing and certified release in the same scalar instance. New release work requires the actual certificate-derived context and original recipient key; an unsigned retained body passes the owning verifier before signing. Completed-message restoration verifies its original signature and exact body digest and restores consumed authority only. A restored credential signs nothing new until the authenticated participant root unlocks the purposes its records show unused. The experimental worker connects encrypted journal and root transitions, but its complete target/release browser fault gate remains open. These interfaces are not exported by the published SDK.

The worker authenticates release-journal records before staging them in the scalar byte buffer. Consumed records are retired inside the existing memory limit; the buffer supplies no release authority. The numerical proof workload binds only its dedicated workload role when proving and verifying, so it cannot produce or accept a proof bound to a protocol role; actual certified messages must pass the public release-records case above.

## Third-party sources

`vendor/fhe-rs` contains the used arithmetic, utility and trait crates from `tlepoint/fhe.rs` at `e248cd288c754e5cca9a54d4b7df505058a539ed`, plus the previously verified scalar execution and dependency-pin changes. The imported local revision is `877151d0f2484aef379c2253fb5bb0d380eb528a`. Only its tests enable rand's operating-system generator: the browser modules build for `wasm32-unknown-unknown`, where that generator has no backend, and receive randomness from their host. The `check` case builds the browser participant module for that target. Its MIT license is retained. The existing Protobuf schema and build remain unchanged.

`vendor/keccak` contains RustCrypto keccak 0.2.2 with the existing scalar backend delegation to keccak 0.1.6. Its MIT and Apache-2.0 licenses are retained. Unused registry test/benchmark manifest entries are removed because those sources were not part of the imported dependency. This is a pinned local dependency, not a claim of an unmodified upstream release.
