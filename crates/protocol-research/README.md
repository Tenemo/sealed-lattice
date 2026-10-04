# Protocol research workspace

research direction

This workspace versions the executable threshold-FHE research construction. The published SDK's participant module is built from its crates. End-to-end post-quantum security is unestablished. Use synthetic data only.

The current setup uses signed clear contribution offers and a quorum-certified selection. The fixed eligible pool contains the first `d+f` original positions, where `d=max(f+1,2)`; the organizer selects `d` complete verified offers, and `n-f` matching endorsements certify that selection. Each member confirms the roster locally before acting, and any original member can accept the winning certificate after verifying its inputs. There is no all-participant confirmation inventory or separate contribution-opening operation. The complete security argument, asynchronous adversarial cases and browser lifecycle still require their corresponding checks; one departure case does not establish the full availability guarantee.

The ordinary native ceremony cases take a participant count from 3 to 20 and an option count from 2 to 20, ten of each by default, and request every result identifier. Their roles follow from the threshold completion rules, with at most `f=floor((n-1)/3)` corrupt participants. Positions one to `f` are corrupt and withhold their target signatures. The first `f+2` honest positions cast accepted ballots, which meets the minimum turnout. The last corrupt position signs two on-time envelopes, which make its slot conflicting, and a late one that every verifier refuses; the two corrupt positions before it, where present, submit authenticated invalid ballots. When `f` is positive and another honest position remains, the relay delivers the last position's ballot only to the last `f` positions, so the organizer's proposal of `n-f` close responses omits it within the bound of `f`. That voter still signs the target, and its ballot does not reach the result. Before the organizer answers, the case checks that no other participant takes a response, that a participant refuses a new envelope for a slot with two known ones and, after its intent lock, a late envelope, and that the organizer refuses a response delivered with an envelope it already knows or that the response does not list. After the proposal, each participant's ordered log of accepted close inputs, replayed into a fresh close state, must reproduce its response and the organizer's proposal. At three participants `f` is zero, so no participant is corrupt and no ballot is omitted. The case generates fresh original credentials, has each active participant confirm its roster locally and each available eligible position publish a signed clear offer, verifies the selected contributions and certifies their aggregate, closes through signed close responses, classifies the usable slots, evaluates the encrypted ranking, certifies its target, proves original-key releases and checks reconstruction from every release subset and from the honest shares that remain after every departure of at most `f` participants. When either kind has more than 256 sets, it checks a deterministic sample of 256. A target with fewer accepted ballots than the minimum turnout takes the no-result branch. The no-result cases cover a close with no ballot and one whose only listed submission is an authenticated invalid ballot. The latter preserves a valid body header and consumes the classification operands before rejecting its malformed proof. These cases retain volatile native private state; they do not establish browser custody, durable terminal publication or a complete participant workflow. Subset reconstruction is not evidence of participants departing before release generation.

Ballots pack a comparison window for every rank, whatever result length the poll requests. The evaluator and terminal decoder support every requested result length of every profile of 3 to 20 participants and 2 to 20 options. The encrypted computation clears omitted ranks; the decoder rejects a plaintext containing them. The complete-ordering program of ten participants and ten options keeps its existing bytes. Poll creation refuses only option counts outside that range, and a roster proposal refuses only sizes outside it.

The `supported-profile` crate derives each profile's thresholds, interpolation points and relation layouts in closed form. Its tracked `profiles.bin` table carries the searched parameters: both moduli with their primality witnesses, the sharing and release widths, the common sampling width and the share lifting limb and carry widths. The repository's protocol tests compare that table with the independent TypeScript profile model. After a model change, regenerate it with:

```text
pnpm run research:profiles -- --output crates/protocol-research/supported-profile/profiles.bin
```

## Build and run

The FHE key source screen generates the first public encryption coordinate from a fixed synthetic source, discards working state, reconstructs the source and checks the coordinate emitted by the first contribution gadget. It checks selected coefficients with direct integer convolution and compares identical public report bytes across native, scalar Node and external Chrome. It creates no registration, proof, authenticated checkpoint or setup capability. It does not establish the clear-offer selection or its departure behavior.

```text
pnpm run research:protocol -- native-fhe-key-source
pnpm run research:protocol -- scalar-fhe-key-source <passed-native-run>
pnpm run research:protocol -- browser-fhe-key-source <passed-native-run>
```

Prerequisites are Node.js satisfying the repository's engine requirement, the pinned pnpm version, and Rust 1.95.0 with rustfmt, Clippy and the `wasm32-unknown-unknown` target. The runner checks the compiler version and records the native executable digest. Cargo's lockfile pins registry dependency versions and checksums. Before an offline run, populate the Cargo cache with:

```text
cargo +1.95.0 fetch --locked --manifest-path crates/protocol-research/Cargo.toml
pnpm run research:protocol -- check
pnpm run research:protocol -- native-result
pnpm run research:protocol -- native-empty
pnpm run research:protocol -- native-invalid-only
```

The ordinary native ceremony cases optionally take their participant and option counts:

```text
pnpm run research:protocol -- native-result 3 2
```

Two fixed four-participant, two-option cases exercise different preparation boundaries and accept no profile or helper overrides:

```text
pnpm run research:protocol -- native-setup-departure
pnpm run research:protocol -- native-selection-fork
```

The departure case drops honest eligible position 1's original enrollment immediately after the roster is fixed, before confirmation or contribution. Position 2 is corrupt but supplies the required valid actions; positions 0 and 2 are selected, and original positions 0, 2 and 3 endorse, cast ballots, close, certify the target and release the result. The absent participant supplies no later private operation. The original roster and thresholds are unchanged.

The selection-fork case has corrupt organizer 0 sign two selections for the same roster. Honest position 1 endorses the losing selection of positions 0 and 1, then refuses to endorse the winning selection of positions 0 and 2. The winner obtains its quorum from positions 0, 2 and 3; position 1 subsequently accepts that certified setup and participates in the result without changing its endorsement. A retained verification result for the losing list cannot certify the winner. Both fixed cases also compare a distinct valid certificate carrier for the same selection and require identical setup identity and aggregate; carrier bytes are not setup meaning. These are native development cases, separate from browser persistence and a general malicious-scheduling proof.

Public offer records use `contribution-<position>/<body-identity>/` with `offer.bin`, `offer-signature.bin`, `body-header.bin`, `proof.bin` and the polynomial files. Discovery uses append-only untrusted announcements: `POST /offers/<position>` appends one body identity idempotently, and `GET /offers/<position>?offset=<entry-index>` returns a little-endian `u64` total, a little-endian `u32` count and at most 64 identities in insertion order. Any origin may announce; no hint replaces an earlier one or occupies a selected slot before its actual signed body verifies. The selector considers one candidate per unresolved author per round within each author's initial finite snapshot. A later call starts from the beginning, retrying previously unavailable bodies and seeing newly appended hints. Announcement storage is separate from immutable public-record paths. The selection is published as `selection.bin` and `selection-signature.bin`, endorsements as `selection-endorsement-<position>.bin`, and the certified result as `setup-certificate.bin` and `setup-identity.bin`. A native carrier comparison additionally writes `setup-certificate-alternative.bin`. Public consumers reconstruct and verify the named records; filenames and discovery announcements grant no capability.

The browser participant's worker may hand independent jobs to helper workers, and the Rust sources that run there also build natively. An executing case can run every job on one to eight native threads that stand in for those helpers, each holding its jobs' state as a helper instance does; the run records the count:

```text
pnpm run research:protocol -- native-invalid-only 3 2 --simulated-helpers 3
```

The build check, ceremony cases and requested-output probe run the workspace unit tests alone and then with three simulated helpers, and the proof crates' also with eight, whose proof rows hold two residue classes of each coset.

For a ceremony, the runner derives the expected roles, ranking and checked set counts from the independent TypeScript threshold and ranking models, not from the ceremony, and scales its deadline with the participant count.

The seed-sharing, opening-share and public-operator cases below are isolated research comparisons; the current clear-offer preparation does not use them to establish setup authority. The isolated seed-sharing proof case uses the four-participant, two-option parameter profile with a reduced 256-coefficient ring and four synthetic seed bits, while retaining the word-proof engine's full verification domain:

```text
pnpm run research:protocol -- native-seed-sharing
pnpm run research:protocol -- native-seed-sharing --compare-reference <historical-native-run>
```

This fixed scalar case accepts no profile counts or simulated-helper option. Its runner checks formatting, Clippy and the library unit tests of the isolated `seed-sharing-proof` crate, then builds its explicit `native-fixture` binary and runs one valid proof, one freshly generated proof from an inconsistent seed witness and one freshly generated proof for a provably unsatisfiable ciphertext statement, together with hostile verification controls. Both fresh negative proofs must fail the relation check; a false supplied witness alone is not evidence that the public statement has no satisfying witness. The fixture feature enables deterministic test randomness only for this native research executable; the participant runtime does not consume it. Source snapshots, the executable digest, model-derived resource inputs, stage output and measured process-tree memory remain in the run diagnostics. Proof files and the runtime digest are written only to the corresponding run-artifact directory. The same research lock, available-memory preflight, 1 GiB process-tree guard and process containment govern this case; a planning estimate does not raise that guard. This experiment creates no participant, accepted setup, recovery protocol, ballot, certificate or terminal, and supplies no complete-protocol security or browser qualification.

The explicit reference option pins a completed historical native run before execution and compares all three freshly generated proof files byte for byte using bounded reads. It records proof lengths and hashes in the new run and checks that the historical files and diagnostics remain unchanged. The historical archive supplies deterministic comparison bytes; a consumer of changed shared proof sources must use a fresh native baseline.

The native opening-share case consumes a fresh seed-sharing baseline:

```text
pnpm run research:protocol -- native-opening-share <fresh-native-seed-run>
pnpm run research:protocol -- native-opening-share <fresh-native-seed-run> --compare-reference <historical-native-opening-run>
```

It requires the baseline's exact compiler and recorded compiled shared inputs, while pinning the new opening crate separately. The same guarded runner copies the three source proofs and verifies their identities before and after execution. The Rust fixture verifies the original positive outer record, generates and verifies a second distinct outer record, and uses those verifier-created records to construct one recipient's batched opening statement. It accepts an honest proof and rejects a freshly generated proof for an unsatisfiable shifted share, together with hostile predecessor, context and framing controls. Its six new statement/proof files have independently modeled bounds and recorded identities. The externally fixed selection descriptor is a fixture input; it grants no broadcast, registration, opening-release or sealed-body authority. This case does not execute participant recovery or a complete setup.

The matching native opening archive also supplies the scalar worker cases:

```text
pnpm run research:protocol -- scalar-opening-share <fresh-native-opening-run>
pnpm run research:protocol -- browser-opening-share <fresh-native-opening-run>
pnpm run research:protocol -- scalar-opening-share-generation <fresh-native-opening-run>
pnpm run research:protocol -- browser-opening-share-generation <fresh-native-opening-run>
```

These reuse the bounded Node and external Chrome harnesses. Every fresh worker streams both outer proofs through the owning verifier before it may verify or generate an opening proof. Incomplete, reordered, duplicated and damaged predecessors retain their refusal; the genuine shifted-share proof is checked against its own statement. Generation uses the fixed native fixture randomness inside Rust and waits for a durable sink acknowledgment after each bounded output span. Its positive proof must match the native file literally before the normal verifier controls run. Shared compiled inputs and the compiler must match the native baseline; the separately identified scalar adapter must match its recorded source bytes. A changed shared source requires a fresh native run, whose reference option checks all statement and proof files against the earlier archive.

Scalar and browser seed-sharing cases require a native baseline with recorded compiled inputs and the same compiler. Shared source files and manifests must match that compiled inventory; the target-only browser adapters are separately checked against the baseline snapshot. Historical archives remain usable for deterministic comparison after shared code changes, but do not authorize scalar execution of that changed code.

The public operator screen exercises both factored operators at the full physical ring without constructing witnesses or proofs:

```text
pnpm run research:protocol -- native-public-operator
pnpm run research:protocol -- scalar-public-operator <passed-native-operator-run>
pnpm run research:protocol -- browser-public-operator <passed-native-operator-run>
```

Each case streams a fixed synthetic public polynomial recipe, checks selected coefficients against original equation sums, and evaluates the actual operator on the complete paired query inventory. It hashes the combined operator one column at a time and compares query values through the existing interpolation kernel. Small canonical reports contain the target, lookup weight, selected values and the digests of the complete operator and query outputs; Node and Chrome must reproduce the native report bytes exactly. The same source, bounded-memory, process-containment and output-acknowledgment rules apply. Native and Node cases wait for initial and final process observations. Timings distinguish recipe and operator construction, actual query evaluation, and reference/digest instrumentation; they do not measure participant completion or qualify a phone.

The same pinned native proof files can also be checked in a dedicated worker in the installed external desktop Chrome:

```text
pnpm run research:protocol -- browser-seed-sharing <passed-native-run>
```

This case reuses the scalar source validation, module build and import admission, native verification of identical bytes, source and artifact identity checks, and research lock. Its owned local server serves only the verifier files and bounded proof chunks on an ephemeral loopback port. The browser authenticates each chunk with WebCrypto SHA-512 against hashes computed from the pinned inputs, retaining one chunk and one bounded read buffer. Every case runs in a fresh dedicated worker, which ends before the next case; the harness records the Chrome version and sampled process-tree memory without network-body capture. The honest proof, false witness, false statement and context, truncation, trailing-byte and changed-proof cases exercise the same verifier loop as Node. This is desktop development evidence and does not qualify a phone, generate a proof in a browser or create a protocol capability.

The bounded generation screen creates the reduced fixture's honest proof through scalar WebAssembly, either in a Node worker or a dedicated external Chrome worker:

```text
pnpm run research:protocol -- scalar-seed-sharing-generation <passed-native-run>
pnpm run research:protocol -- browser-seed-sharing-generation <passed-native-run>
```

The original native run remains unchanged. Each generation run writes a fresh proof artifact and requires its exact length and SHA-512 identity to match the pinned deterministic native fixture before independent native and scalar verification. Generation uses bounded prover steps and records their call costs and live linear memory. The Chrome worker sends one bounded output chunk at a time to its owned local sink, waits for that chunk's completed write and matching hash/coordinate receipt before acknowledging the output to Rust, and keeps only the latest progress snapshot for diagnostic sampling. The sink rejects out-of-order or overlapping writes and never overwrites an existing artifact. The existing process-tree memory guard and experiment deadline remain enforced. This is a reduced synthetic proof-generation screen, not a participant setup, durable private-state workflow, complete resource bound or phone qualification.

The focused numerical case checks complete and shorter output prefixes at the smallest, the ten-participant and the largest profile, each prefix from the same deterministic BFV ciphertext inputs as its complete ordering:

```text
pnpm run research:protocol -- native-prefix
```

It exercises the coefficient-selection gates and checks every decrypted coefficient with a test-only secret and an independent interpolation oracle. Because these numerical probes decrypt synthetic test ciphertexts, they compile only with the `numerical-probes` feature, which this case enables; evaluation modules neither contain nor export them. It creates no participants, ballots, certificate or protocol terminal.

For focused retrieval checks, a passed native result, setup-departure or selection-fork run supplies its public ceremony records:

```text
pnpm run research:protocol:public -- available-records <native-completion-run>
```

This case supplies the certificate's votes and a nonconsecutive release subset, leaves other files absent, and injects corrupt extras. It recomputes setup, the close barrier and evaluation before consuming completion records. This is a retrieval test after generation; it does not demonstrate participants disappearing before their later actions.

The public setup and close records of a passed native run can also be checked against a directory containing actual participant messages:

```text
pnpm run research:protocol:public -- certificate-records <native-run> <public-record-directory>
pnpm run research:protocol:public -- release-records <native-run> <public-record-directory>
pnpm run research:protocol:public -- terminal-records <native-run> <public-record-directory>
```

All three modes recompute setup, the close barrier from the published intent, responses, proposal and listed envelopes, the classification of each usable slot and the target. Only usable slots' bodies are read. The certificate mode needs only a valid quorum of target votes and does not request release messages. The release mode additionally verifies one available release message and runs wrong-target, incomplete-proof, altered-proof and duplicate controls at its actual author; it requires an encrypted target and emits no result identifiers. The terminal mode verifies sufficient release shares when the target is encrypted. These checks do not establish durable publication by themselves.

The maintained participant runtime runs registration, local roster confirmation, clear contribution offers, quorum setup selection, setup verification, signed ballots, close responses, target votes, release shares and the result in external desktop Chrome:

```text
pnpm run research:participant -- 3 2
```

The script first builds the workspace packages, whose SDK build produces the scalar participant module, the bundled worker and their source manifest and checks that the module contains no vector instructions, declares exactly its bounded memory and imports only what the worker supplies. The runner serves those packaged files, refuses to run when a listed source differs from the working tree, checks the published records against the sizes the profile's models derive, and checks that every ballot and release a visit generates draws exactly the proof randomness those models derive. Each honest participant's page runs its operations through the SDK's participant API, which carries the worker's source, and before any operation the worker checks the module's hash and recomputes the runtime identity over the sources, module and worker. The worker takes every size it enforces from the module, for the participant count of the retained roster and the option count of the poll the module verified. Each participant uses its own disk-backed Chrome profile under `temp/`, and each Chrome process tree runs under a memory guard. Successful runs remove their profiles; failed runs preserve them for original-state diagnosis. The organizer creates the poll, whose result lists one option fewer than the complete ranking, and registers; the other participants join, and every participant verifies all registration records before the organizer signs the roster proposal or another participant accepts it. One more registrant joins, and the organizer leaves it out of the roster: shown the roster, it stays pending with its registration intact. Every active participant uses `confirm` to lock the displayed roster locally. Eligible positions may call `contribute`, which resumes original generation around its sealed checkpoint, signs the complete offer and publishes it under its body identity. The organizer calls `select-setup`; active members call `endorse-setup` after complete verification of the selected offers. Any original member calls `verify-setup` to accept a matching quorum certificate and retain the verified aggregate; a ballot is refused before that activation. Own contribution work and selection-signing intents occupy independent preparation-journal fields, so an unused own contribution is not a prerequisite for endorsement or activation. Activation retires private preparation state, while its public records remain available. Each participant then locks its scores and ballot time and retains a seed, from which alone the module expands all the ballot's encryption and proof randomness, and retains the envelope and every encrypted body record with one root that retires the seed. An interrupted attempt draws the same bytes from the retained seed again. A signed ballot refuses other scores and is only delivered again. Each participant then collects published ballots into an encrypted close log, one event and its records per accepted delivery. Every ballot but the last is on time: a late ballot starts later, and the organizer's close time is the latest on-time ballot time, so locking its intent retires every later ballot wherever it was held. When the profile tolerates a corrupt participant, as in `pnpm run research:participant -- 4 2`, every ballot is instead on time and the last corrupt position equivocates: two copies of its private state sign two more ballots at its origin, the second one late. The relay stores each submission under its author and envelope identity and names the late ballot to the last participant, whose intent lock retires it, and the other copy's ballot to the organizer, which then lists both of that author's on-time envelopes. The slot is conflicting, so none of its ballots counts, and every participant retrieves both listed envelopes by their identities. Every participant responds with the on-time ballots it holds, and the organizer takes the other responses, fetches the one body they list that it lacks, and proposes. Each participant then verifies the close barrier from the public close records in its own module, classifies every usable ballot, evaluates the public target, and retains the exact target body with fresh signing coins before it signs its target vote. When the certificate quorum is smaller than the roster, as in `pnpm run research:participant -- 4 2`, the participants after the organizer beyond it sign no target vote. Once every target vote is published, the organizer departs: its browser closes and its private state is deleted before any release exists. Each remaining participant evaluates the target again, certifies it from the published votes, retains a seed, and generates its release share from the randomness the module expands from that seed alone; the body and envelope are retained before the signing coins, and the coins before the signature. A participant that signed no target releases from its completed close once the certificate verifies and can no longer sign one. One voter's browser closes while it generates its release share, and its next visit generates the share again from the retained seed. The last remaining participant halts at every step after its target lock, the last with its signed release before delivery, which its next visit only delivers. A remaining participant finally combines the published shares into the requested prefix of the ranking in its own module, without the departed organizer's share. Meanwhile a malicious relay shows each other remaining honest participant forged records in its own view, and each view would complete that participant's work only if a forgery counted, so each stays pending. One view hides a voter's vote behind the last voter's vote relabeled with that voter's position and replays the last voter's vote in every non-voter's slot. Another replays the combining participant's share in the departed organizer's slot, alters another participant's release body, and relabels that share for every other slot until one share fewer than the release threshold remains. Others, one at a time, alter or withhold the body of the participant's own counted ballot, replace that ballot's submission with another counted author's authentic one, or alter its signature; the result visit verifies the close barrier again from the public records, so no view withdraws or replaces the accepted ballot. Last, one honest participant's first retained data record is altered from its own page: its next visit stops it, and it stays stopped after the exact bytes are restored. That participant and the registrant left out of the roster then each verify the same outcome with the SDK's standalone verifier from the poll's identity and the relay alone. Each root transition commits under a fresh key only after its exact predecessor authenticates. A desktop result is development evidence, not supported-phone qualification.

The fault cohort also interrupts roster agreement and preparation. For a durable cut, the runner serves a copy of the runtime worker that pauses after successful root commit and readback; its page authenticates that copy's digest. It then crashes the browser process tree, and the next visit runs the ordinary worker against the same retained state. Because preparation stays at one root generation while its independent journal fields advance, the preparation hooks inspect the committed own-contribution phase or selection/endorsement signature intent rather than infer progress from generation alone. The cases interrupt generation and proof continuation with staged records, the retained checkpoint, the offer-signing intent, the organizer's selection intent and an endorsement intent. The first endorsement is also interrupted while reading an actual selected offer, before its verification result is retained; setup activation has its own committed-root interruption. Each next visit discards what an interrupted operation stored and continues from its retained seed or state. After setup the first three honest ballot authors crash after the attempt lock, with the seed retained, with the body retained, with the signature intent and with the signed ballot, which the next visit only delivers again. The organizer crashes with its close intent before signing it, the first two other honest participants after locking the intent and with their response intent, and the organizer again with its signed response and retained proposal intent and with its signed proposal, whose next visit restores the completed close without replaying its log. The first other honest voter crashes with its target intent and the organizer with its signed vote, and the combining participant at each release generation after its target lock, the last with its signed release before delivery, which its next visit only delivers.

For a bounded clear-preparation and private-storage check that stops before ballots, use:

```text
pnpm run research:participant -- 3 2 preparation --scalar
```

The preparation case reuses the guarded fault prefix through actual setup activation. Its original contributor resumes the same retained continuation after harness-only pauses following a stored slot containing padding after proof output ends and the final planned slot before the completed-body root commit. Private replay diagnostics record the original and instrumented worker digests, charged instrumentation time, per-slot plaintext proof hashes and whether the cuts coincide. Isolated profile copies are taken at the complete unsigned-body phase: missing padding or authenticated nonzero padding must stop `contribute` before any relay publication. The healthy original then signs and publishes the offer, and the cohort completes selection, endorsement and setup activation, publishing only the logical proof prefix. A separate copy taken at the retained checkpoint phase loses a required checkpoint record; generic `publish` must stop without attempting a relay publication. Cold recovery checks that original credential and setup authority survive retirement of private preparation records. This instrumented development case does not exercise an early departure, ballots or an outcome, and does not qualify a phone.

A no-result run closes with one valid on-time ballot fewer than the minimum turnout, from the honest positions just before the last:

```text
pnpm run research:participant -- 3 2 no-result
```

When the profile tolerates a corrupt participant, as in `pnpm run research:participant -- 4 2 no-result`, the last corrupt position also casts an authentic invalid ballot on time, which alone would meet the turnout. Its client claims the honest runtime: its worker fetches and hashes the honest module, then compiles a module built with the `invalid-ballot` feature, which proves a ballot statement with one ciphertext coefficient changed and signs it. The other participants hold its body by its identity, find its slot usable and its ballot invalid, and count one valid ballot fewer than the turnout. The participants certify a no-result target, their releases create nothing, and the combining participant finds no result, while the forged-vote view still leaves its participant pending.

An empty run casts no ballot:

```text
pnpm run research:participant -- 3 2 empty
```

The organizer closes at the current time, every response lists nothing, a participant that locked the intent is refused a ballot, and the participants certify a no-result target whose releases create nothing. It retains the preparation interruption checks and exercises the close and target boundaries without ballot or encrypted-release generation.

A rosters run has a corrupt organizer complete two rosters of one poll:

```text
pnpm run research:participant -- 4 2 rosters
```

The organizer's private state is copied after its registration, before it proposes a roster, and the copy proposes a second roster of the same poll to other registrants. The copy acts under its own path of the organizer's origin, and the relay serves each roster only its own records, showing the second roster the poll definition and the organizer's registration. The profile must tolerate a corrupt participant, so the organizer is each roster's only corrupt member. Both rosters then complete roster agreement, setup, ballots, the close, target votes, releases and their results in parallel. A relay view then serves a member of each roster the other roster's registrations, contributions, close records, target votes or release shares, one family at a time, under its own roster's names: a consumed wrong-context family leaves it pending, while a family that retained result recovery does not read leaves its outcome unchanged. The other roster's valid registrations of the same poll are refused against the original roster, and the relay's own records restore the expected outcome.

A plain run carries one roster of honest participants through each stage once, with no crash, forgery or other roster:

```text
pnpm run research:participant -- 3 2 plain
pnpm run research:participant -- 10 10 plain --sequential
```

Use `--scalar` to run the full cohort without cross-origin isolation or helper workers. The runner checks the actual browser isolation state and requires zero helper and shared-arena memory. Use `--top-count=<count>` to select any result length from one through the option count, including both endpoints:

```text
pnpm run research:participant -- 3 2 plain --scalar --top-count=2
```

The explicit early-departure browser case uses the same fixed scenario as the native departure selector:

```text
pnpm run research:participant -- 4 2 --setup-departure --scalar
```

It deletes honest eligible position 1's Chrome profile immediately after roster publication, before that participant accepts or confirms the roster. Cooperative corrupt position 2 runs every required valid operation. Before position 2 publishes its valid offer, it announces an invalid body identity after position 0's valid offer is available. Selection must remain pending without consuming its intent; the later valid announcement must remain discoverable behind the invalid hint. The original positions 0, 2 and 3 then finish setup, voting, closing and release; the harness independently checks the selected positions, endorsement positions and public outcome. This flag cannot combine with another scenario, a foreign poll, sequential mode or memory pressure. It leaves the ordinary three-participant baseline available and checks the stated invalid-first discovery strategy, without establishing a general adversarial-scheduling guarantee. These switches select development evidence; they do not qualify a physical phone.

With `--sequential`, only one participant's browser runs at a time; the ordinary workflow report rejects overlapping operations and records actual sequential wall time separately from summed active work. Its stage totals charge every operation, and its combined memory includes the worker, helpers and shared arena. Payload counters cover the relay exchanges without browser network-body capture; HTTP headers and link overhead are not measured, and incomplete exchanges or unknown upload lengths remain explicit. Runs without this flag do not report sequential completion time.

With `--profile`, Chrome records the CPU samples of every participant operation, and the run directory keeps a summary for each operation of the functions that spent the most time at the top of a sampled stack and anywhere on it. With `--memory-pressure`, the second setup contributor first contributes in a browser that caps each WebAssembly memory below what its contribution needs; that visit ends pending with the worker's exhausted memory bound rather than stopping the participant, and the next visit completes the contribution. This fault run does not supply an ordinary-workflow total. Failed runs retain their private browser checkpoints in place, bound to the archived runtime and original origins; they never import them into another action or build.

Every run records, with each sample of a participant's process memory, the JavaScript heap use that its page and each of its workers and helpers last reported; a worker busy in a module call reports only when it returns to its event loop.

The local relay serializes writes per record path. It accepts identical stored spans from another origin but permits only the original publisher to append; simultaneous distinct certificate carriers cannot concatenate or overwrite each other. The runner refuses unknown or empty selectors, serializes heavy runs, derives the corpus bound before generation, checks available memory, contains the process tree and records diagnostics under `logs/`. The ceremony's records, the relay's records, the public reader's output and the runtime copies are the run's artifacts, which it writes under `temp/run-artifacts/` with the same date and run name as its diagnostics; a run named as the source of another reads them from there. Native process memory, runtime and public storage measurements remain distinct from unmeasured browser, recovery, network-transfer and participant-visit costs. Failed diagnostics are preserved.

All sources, parameters and toolchain selection needed by the native generation case are tracked, and the tracked lockfile pins each third-party crate's version and checksum. That case uses `temp/` only for run-owned scratch and the run's artifacts. No prior log, private participant profile, generated target directory or reference checkout is an input to native generation. Source paths are captured in each run; moving code changes the build identity and never authorizes private-state import.

The SDK's standalone outcome verifier runs the same participant module and worker as a participant, and so the same owning Rust verifiers. Target certification alone does not establish that the published records remain retrievable. The complete reduction argument, independent adversarial review, resource qualification of every supported profile and physical qualification remain outstanding.

The participant module also signs targets and generates certified releases in the same scalar instance. New release work requires the actual certificate-derived context and original recipient key; an unsigned retained body passes the owning verifier before signing. Completed-message restoration verifies its original signature and exact body digest and restores consumed authority only. A restored credential signs nothing new until the authenticated participant root unlocks the purposes its records show unused. The worker connects the retained seed, body and signature to root transitions.

The module refuses a release unless the worker installed the retained seed and nothing was drawn from it, and it expands the release's randomness from that seed alone; the seed supplies no release authority.
