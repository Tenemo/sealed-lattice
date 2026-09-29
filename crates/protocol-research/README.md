# Protocol research workspace

research direction

This workspace versions the executable threshold-FHE research construction. It is separate from the published SDK and is not enabled by its foundation API. End-to-end post-quantum security is unestablished. Use synthetic data only.

The native cases take a participant count from 3 to 20 and an option count from 2 to 20, ten of each by default, and request every result identifier. Their roles follow from the threshold completion rules, with at most `f=floor((n-1)/3)` corrupt participants. Positions one to `f` are corrupt and withhold their target signatures. The first `f+2` honest positions cast accepted ballots, which meets the minimum turnout. The last corrupt position signs two on-time envelopes, which make its slot conflicting, and a late one that every verifier refuses; the two corrupt positions before it, where present, submit authenticated invalid ballots. When `f` is positive and another honest position remains, the relay delivers the last position's ballot only to the last `f` positions, so the organizer's proposal of `n-f` close responses omits it within the bound of `f`. That voter still signs the target, and its ballot does not reach the result. Before the organizer answers, the case checks that no other participant takes a response, that a participant refuses a new envelope for a slot with two known ones and, after its intent lock, a late envelope, and that the organizer refuses a response delivered with an envelope it already knows or that the response does not list. After the proposal, each participant's ordered log of accepted close inputs, replayed into a fresh close state, must reproduce its response and the organizer's proposal. At three participants `f` is zero, so no participant is corrupt and no ballot is omitted. The case generates fresh original credentials, has every participant confirm the roster and only the first `max(f+1,2)` positions contribute, proves and verifies setup, closes through signed close responses, classifies the usable slots, evaluates the encrypted ranking, certifies its target, proves original-key releases and checks reconstruction from every release subset and from the honest shares that remain after every departure of at most `f` participants. When either kind has more than 256 sets, it checks a deterministic sample of 256. A target with fewer accepted ballots than the minimum turnout takes the no-result branch. The no-result cases cover a close with no ballot and one whose only listed submission is an authenticated invalid ballot. The latter preserves a valid body header and consumes the classification operands before rejecting its malformed proof. These cases retain volatile native private state; they do not establish browser custody, durable terminal publication or a complete participant workflow. Subset reconstruction is not evidence of participants departing before release generation.

Ballots pack a comparison window for every rank, whatever result length the poll requests. The evaluator and terminal decoder support every requested result length of every profile of 3 to 20 participants and 2 to 20 options. The encrypted computation clears omitted ranks; the decoder rejects a plaintext containing them. The complete-ordering program of ten participants and ten options keeps its existing bytes. Poll creation refuses only option counts outside that range, and a roster proposal refuses only sizes outside it.

The `supported-profile` crate derives each profile's thresholds, interpolation points and relation layouts in closed form. Its tracked `profiles.bin` table carries the searched parameters: both moduli with their primality witnesses, the sharing and release widths, the common sampling width and the share lifting limb and carry widths. The repository's protocol tests compare that table with the independent TypeScript profile model. After a model change, regenerate it with:

```text
pnpm run research:profiles -- --output crates/protocol-research/supported-profile/profiles.bin
```

## Build and run

Prerequisites are Node.js satisfying the repository's engine requirement, the pinned pnpm version, and Rust 1.95.0 with rustfmt, Clippy and the `wasm32-unknown-unknown` target. The runner checks the compiler version and records the native executable digest. Cargo's lockfile pins registry dependency versions and checksums. Before an offline run, populate the Cargo cache with:

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

The browser participant's worker may hand independent jobs to helper workers, and the Rust sources that run there also build natively. An executing case can run every job on one to eight native threads that stand in for those helpers, each holding its jobs' state as a helper instance does; the run records the count:

```text
pnpm run research:protocol -- native-invalid-only 3 2 --simulated-helpers 3
```

Every case runs the unit tests alone and then with three simulated helpers, the proof crates' also with eight, whose proof rows hold two residue classes of each coset, and the vendored arithmetic crate's own tests, which check its WebAssembly word products natively.

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

The records a passed native run's or browser participant run's verified result depends on can also travel through the maintained public archive:

```text
pnpm run build
pnpm run research:protocol:public -- archived-records <native-or-participant-run>
```

A participant run's relayed records are first laid out as the native reader takes them: registrations in roster order under the poll and runtime identities the reader is given, and an index of the published envelopes. The reader first verifies the records and lists every public input its accepted result depends on: setup, the close intent, proposal and named responses, their listed envelopes, the usable bodies and the accepted votes and release shares. The case publishes exactly those files, bound to the poll identity, to three local replicas with the built SDK client: consecutive parts that one retrieval each carries, then an index that lists them and carries the target. After the source and one acknowledging replica are gone, a fresh reader retrieves the index and each part it lists, rebuilds the reader input only from authenticated records and must reach the same target and terminal while depending on exactly the retrieved files. A reader bound to another poll and a closure without one usable body are refused. Local replicas on one host are not independent fault domains, and no browser reader is exercised; only a participant run's own departures precede its archive.

The public setup and close records of a passed native run can also be checked against a directory containing actual participant messages:

```text
pnpm run research:protocol:public -- certificate-records <native-run> <public-record-directory>
pnpm run research:protocol:public -- release-records <native-run> <public-record-directory>
pnpm run research:protocol:public -- terminal-records <native-run> <public-record-directory>
```

All three modes recompute setup, the close barrier from the archived intent, responses, proposal and listed envelopes, the classification of each usable slot and the target. Only usable slots' bodies are read. The certificate mode needs only a valid quorum of target votes and does not request release messages. The release mode additionally verifies one available release message and runs wrong-target, incomplete-proof, altered-proof and duplicate controls at its actual author; it requires an encrypted target and emits no result identifiers. The terminal mode verifies sufficient release shares when the target is encrypted. These checks do not establish durable publication by themselves.

The public reader retains the accepted target-vote packets in its output's `certificate-records/` directory, using each authenticated author's position. The run report identifies that directory for archive construction. Candidate file positions are transport labels and need not match the author encoded in a vote; archive extraction must use the retained packets. Retrieval still requires the owning certificate verifier.

The browser cohort also retains the actual participant-published certified closure and terminal transcript, retrieved from the replicas after one replica is lost. These cases authenticate those archived records, lay out only their public files and run a fresh native verifier with no participant verification cache or source-relay fallback:

```text
pnpm run research:protocol:public -- participant-closure <participant-run>
pnpm run research:protocol:public -- participant-transcript <participant-run>
```

The closure case verifies the complete setup, close, recomputed target and certificate without requiring release shares. The transcript case additionally verifies the terminal. Their input must be a passed cohort that retained these archives; an older cohort's relay files do not substitute for them. The layout preserves missing ballot bodies so the owning close verifier requires bodies only for usable slots and still rejects a missing usable body.

The maintained participant runtime runs registration, roster agreement, setup contribution, setup verification, signed ballots, close responses, target votes, release shares and the result in external desktop Chrome:

```text
pnpm run research:participant -- 3 2
```

The archive is configured before setup verification. That verification records its complete public input closure and retains the archive index in the participant's authenticated root; later recording visits can reuse those exact dependencies while the owning setup verifier restores its own result. A missing aggregate still requires full setup verification. `--prepopulate-archive` has the local relay copy its already public files to the replicas before participants archive them. It performs no participant verification, and complete-closure acknowledgements remain required. Service transfer and elapsed time are recorded separately in the run diagnostics; the sequential operation span includes the service intervals between participant operations.

For a bounded storage experiment over complete public files from a passed participant run, use `pnpm exec tsx tools/ci/measure-archive-transfer.ts upload <participant-run>`, with `prepopulate` for service copying or `reuse` for a second publication from its prior exact index. The experiment records the first publication separately, compares unchanged transcript identities, checks fresh retrieval after replica loss, and does not measure protocol verification or a complete participant workflow.

The script first builds the workspace packages, whose SDK build produces the scalar participant module, the bundled worker and their source manifest and checks that the module contains no vector instructions, declares exactly its bounded memory and imports only what the worker supplies. The runner serves those packaged files, refuses to run when a listed source differs from the working tree, checks the published records against the sizes the profile's models derive, and checks that every ballot and release a visit generates draws exactly the proof randomness those models derive. Each honest participant's page runs its operations through the SDK's participant API, which carries the worker's source, and before any operation the worker checks the module's hash and recomputes the runtime identity over the sources, module and worker. The worker takes every size it enforces from the module, for the participant count of the retained roster and the option count of the poll the module verified. Each participant uses its own disk-backed Chrome profile under `temp/`, which the run removes when it ends, and each Chrome process tree runs under a memory guard. The organizer creates the poll, whose result lists one option fewer than the complete ranking, and registers; the other participants join, and every participant verifies all registration records before the organizer signs the roster proposal or another participant accepts it. One more registrant joins, and the organizer leaves it out of the roster: shown the roster, it stays pending with its registration intact. Each setup contributor, at one of the first `max(f+1,2)` roster positions, then generates its contribution in two one-shot steps around a sealed checkpoint and signs its confirmation, and every other participant signs a confirmation that names its own registration. A contributor signs its opening only after every participant's confirmation is published, so an earlier request stays pending. Every participant then verifies the complete setup from the public records in its own module, which alone emits the retained setup reference; a ballot is refused before it. Each participant then locks its scores and ballot time and retains a seed, from which alone the module expands all the ballot's encryption and proof randomness, and retains the envelope and every encrypted body record with one root that retires the seed. An interrupted attempt draws the same bytes from the retained seed again. A signed ballot refuses other scores and is only delivered again. Each participant then collects published ballots into an encrypted close log, one event and its records per accepted delivery. Every ballot but the last is on time: a late ballot starts later, and the organizer's close time is the latest on-time ballot time, so locking its intent retires every later ballot wherever it was held. When the profile tolerates a corrupt participant, as in `pnpm run research:participant -- 4 2`, every ballot is instead on time and the last corrupt position equivocates: two copies of its private state sign two more ballots at its origin, the second one late. The relay stores each submission under its author and envelope identity and names the late ballot to the last participant, whose intent lock retires it, and the other copy's ballot to the organizer, which then lists both of that author's on-time envelopes. The slot is conflicting, so none of its ballots counts, and every participant retrieves both listed envelopes by their identities. Every participant responds with the on-time ballots it holds, and the organizer takes the other responses, fetches the one body they list that it lacks, and proposes. Each participant then verifies the close barrier from the public close records in its own module, classifies every usable ballot, evaluates the public target, and retains the exact target body with fresh signing coins before it signs its target vote. When the certificate quorum is smaller than the roster, as in `pnpm run research:participant -- 4 2`, the participants after the organizer beyond it sign no target vote. Once every target vote is published, the organizer departs: its browser closes and its private state is deleted before any release exists. Three local archive replicas and a fourth that never answers, with fault bound one, then start. Each remaining participant evaluates the target again, certifies it from the published votes, archives the certified target closure it read to the replicas, retains a seed, and generates its release share from the randomness the module expands from that seed alone; the body and envelope are retained before the signing coins, and the coins before the signature. A participant that signed no target releases from its completed close once the certificate verifies and can no longer sign one. The last remaining participant, which the relay then serves no public record, finds an archived closure among the archive's hints and releases from the replicas alone. One voter's browser closes while it generates its release share, and its next visit generates the share again from the retained seed. A remaining participant finally combines the published shares into the requested prefix of the ranking in its own module, without the departed organizer's share. It then archives the transcript of its verified outcome to the same replicas, and after one of the three stops, another remaining participant that the relay serves no public record finds the transcript among the archive's hints and reaches the same outcome from the replicas alone. Meanwhile a malicious relay shows each other remaining honest participant forged records in its own view, and each view would complete that participant's work only if a forgery counted, so each stays pending. One view hides a voter's vote behind the last voter's vote relabeled with that voter's position and replays the last voter's vote in every non-voter's slot. Another replays the combining participant's share in the departed organizer's slot, alters another participant's release body, and relabels that share for every other slot until one share fewer than the release threshold remains. Others, one at a time, alter or withhold the body of the participant's own counted ballot, replace that ballot's submission with another counted author's authentic one, or alter its signature; the result visit verifies the close barrier again from the public records, so no view withdraws or replaces the accepted ballot. Last, one honest participant's first retained data record is altered from its own page: its next visit stops it, and it stays stopped after the exact bytes are restored. Each root transition commits under a fresh key only after its exact predecessor authenticates. A desktop result is development evidence, not supported-phone qualification.

Honest browsers also crash during roster agreement and setup and at every durable boundary after setup. For each crash at a durable boundary the runner serves that participant a copy of the runtime's worker that stops once its participant commits the chosen generation; like a corrupt client, the copy claims the honest runtime, and its page names the copy's digest. The runner then ends that browser's process tree without Chrome's shutdown, and the next visit runs the runtime's own worker from the retained state. The organizer crashes with its roster proposal intent and the last honest participant right after it retains the accepted roster. The last honest setup contributor's browser also ends during its contribution generation and continuation once each stored records ahead of the next root, and it crashes with its retained checkpoint and with its confirmation and opening intents, as does the last honest participant outside the setup contributors with its confirmation intent. An honest participant's browser ends while it verifies the setup, once the relay delivered it the last contributor's opening, and it crashes right after it retains the verified setup. Each next visit discards what an interrupted operation stored and continues from its retained seed or state. After setup the first three honest ballot authors crash after the attempt lock, with the seed retained, with the body retained, with the signature intent and with the signed ballot, which the next visit only delivers again. The organizer crashes with its close intent before signing it, the first two other honest participants after locking the intent and with their response intent, and the organizer again with its signed response and retained proposal intent and with its signed proposal, whose next visit restores the completed close without replaying its log. The first other honest voter crashes with its target intent and the organizer with its signed vote, and the combining participant at each release generation after its target lock, the last with its signed release before delivery, which its next visit only delivers.

A no-result run closes with one valid on-time ballot fewer than the minimum turnout, from the honest positions just before the last:

```text
pnpm run research:participant -- 3 2 no-result
```

When the profile tolerates a corrupt participant, as in `pnpm run research:participant -- 4 2 no-result`, the last corrupt position also casts an authentic invalid ballot on time, which alone would meet the turnout. Its client claims the honest runtime: its worker fetches and hashes the honest module, then compiles a module built with the `invalid-ballot` feature, which proves a ballot statement with one ciphertext coefficient changed and signs it. The other participants hold its body by its identity, find its slot usable and its ballot invalid, and count one valid ballot fewer than the turnout. The participants certify a no-result target, their releases create nothing, and the combining participant finds no result, while the forged-vote view still leaves its participant pending.

An empty run casts no ballot:

```text
pnpm run research:participant -- 3 2 empty
```

The organizer closes at the current time, every response lists nothing, a participant that locked the intent is refused a ballot, and the participants certify a no-result target whose releases create nothing. Its browsers crash only at the close and target boundaries.

A rosters run has a corrupt organizer complete two rosters of one poll:

```text
pnpm run research:participant -- 4 2 rosters
```

The organizer's private state is copied after its registration, before it proposes a roster, and the copy proposes a second roster of the same poll to other registrants. The copy acts under its own path of the organizer's origin, and the relay serves each roster only its own records, showing the second roster the poll definition and the organizer's registration. The profile must tolerate a corrupt participant, so the organizer is each roster's only corrupt member. Both rosters then complete roster agreement, setup, ballots, the close, target votes, releases and their results in parallel. A relay view then serves a member of each roster the other roster's registrations, contributions, close records, target votes or release shares, one family at a time, under its own roster's names: each view leaves it pending, the other roster's valid registrations of the same poll refused only as a roster, and with the relay's own records it reaches its roster's outcome.

A plain run carries one roster of honest participants through each stage once, including certified-target archiving before release and final transcript publication, with no crash, forgery or other roster:

```text
pnpm run research:participant -- 3 2 plain
pnpm run research:participant -- 10 10 plain --sequential
```

With `--sequential`, only one participant's browser runs at a time; the ordinary workflow report rejects overlapping operations and records actual sequential wall time separately from summed active work. Its stage totals charge every operation, including both kinds of archiving, and its combined memory includes the worker, helpers and shared arena. Payload counters cover the relay and archive exchanges without browser network-body capture; HTTP headers and link overhead are not measured, and incomplete exchanges or unknown upload lengths remain explicit. Runs without this flag do not report sequential completion time.

With `--profile`, Chrome records the CPU samples of every participant operation, and the run directory keeps a summary for each operation of the functions that spent the most time at the top of a sampled stack and anywhere on it. With `--memory-pressure`, the second setup contributor first contributes in a browser that caps each WebAssembly memory below what its contribution needs; that visit ends pending with the worker's exhausted memory bound rather than stopping the participant, and the next visit completes the contribution. This fault run does not supply an ordinary-workflow total. Failed runs retain their private browser checkpoints in place, bound to the archived runtime and original origins; they never import them into another action or build.

Every run records, with each sample of a participant's process memory, the JavaScript heap use that its page and each of its workers and helpers last reported; a worker busy in a module call reports only when it returns to its event loop.

The runner refuses unknown or empty selectors, serializes heavy runs, derives the corpus bound before generation, checks available memory, contains the process tree and records diagnostics under `logs/`. The ceremony's records, the relay's records, the public reader's output and the runtime copies are the run's artifacts, which it writes under `temp/run-artifacts/` with the same date and run name as its diagnostics; a run named as the source of another reads them from there. Native process memory, runtime and public storage measurements remain distinct from unmeasured browser, recovery, network-transfer and participant-visit costs. Failed diagnostics are preserved.

All sources, parameters, toolchain selection and third-party code needed by the native generation case are tracked. That case uses `temp/` only for run-owned scratch and the run's artifacts. No prior log, private participant profile, generated target directory or reference checkout is an input to native generation. Source paths are captured in each run; moving code changes the build identity and never authorizes private-state import.

The public verifier and scalar bridge are library consumers of the same owning Rust verifiers. Target certification alone does not establish archive availability. The complete reduction argument, independent adversarial review, resource qualification of every supported profile and physical qualification remain outstanding.

The original participant bridge also exposes target signing and certified release in the same scalar instance. New release work requires the actual certificate-derived context and original recipient key; an unsigned retained body passes the owning verifier before signing. Completed-message restoration verifies its original signature and exact body digest and restores consumed authority only. A restored credential signs nothing new until the authenticated participant root unlocks the purposes its records show unused. The maintained worker connects the retained seed, body and signature to root transitions, but its complete target/release browser fault gate remains open. These interfaces are not exported by the published SDK.

The module refuses a release unless the worker installed the retained seed and nothing was drawn from it, and it expands the release's randomness from that seed alone; the seed supplies no release authority. The numerical proof workload binds only its dedicated workload role when proving and verifying, so it cannot produce or accept a proof bound to a protocol role; actual certified messages must pass the public release-records case above.

## Third-party sources

`vendor/fhe-rs` contains the used arithmetic, utility and trait crates from `tlepoint/fhe.rs` at `e248cd288c754e5cca9a54d4b7df505058a539ed`, plus the previously verified scalar execution and dependency-pin changes. The imported local revision is `877151d0f2484aef379c2253fb5bb0d380eb528a`. On WebAssembly, which has no widening multiplication, its modular multiplication forms each double-word product and Barrett quotient from 32-bit partial products instead of calling the library routine for a 128-bit product, with the same results. Its negacyclic transform keeps only the forward twiddles and their Shoup companions, and its backward transform reads each inverse twiddle as the negation of a forward one, so each prime's plan holds two tables instead of four with the same results. Only its tests enable rand's operating-system generator: the browser modules build for `wasm32-unknown-unknown`, where that generator has no backend, and receive randomness from their host. The `check` case builds the browser participant module for that target. Its MIT license is retained. Its Protobuf schema is unchanged, and the Rust code that prost-build 0.14.4 generated from it with protoc 36.1 is committed in place of the build script, so no build needs a Protocol Buffers compiler.

`vendor/keccak` contains RustCrypto keccak 0.2.2 with the existing scalar backend delegation to keccak 0.1.6. Its MIT and Apache-2.0 licenses are retained. Unused registry test/benchmark manifest entries are removed because those sources were not part of the imported dependency. This is a pinned local dependency, not a claim of an unmodified upstream release.
