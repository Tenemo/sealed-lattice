# Protocol research workspace

research direction

This workspace versions the executable threshold-FHE research construction. The published SDK's participant module is built from its crates. End-to-end post-quantum security is unestablished. Use synthetic data only.

The current setup uses signed contribution offers and a quorum-certified selection. The fixed eligible pool contains the first `d+f` original positions, where `d=max(f+1,2)`; the organizer selects `d` complete verified offers, and `n-f` matching endorsements certify that selection. Each member confirms the roster locally before acting, and any original member can accept the winning certificate after verifying its inputs. There is no all-participant confirmation inventory or separate contribution-opening operation. The complete security argument, asynchronous adversarial cases and browser lifecycle still require their corresponding checks; one departure case does not establish the full availability guarantee.

The ordinary native ceremony cases take a participant count from 3 to 20 and an option count from 2 to 20, ten of each by default, and request every result identifier. Their roles follow from the threshold completion rules, with at most `f=floor((n-1)/3)` corrupt participants. Positions one to `f` are corrupt and withhold their target votes. The first `f+2` honest positions cast accepted ballots, which meets the minimum turnout. The last corrupt position signs two on-time envelopes, which make its slot conflicting, and a late one that every verifier refuses; the two corrupt positions before it, where present, submit authenticated invalid ballots. When `f` is positive and another honest position remains, the relay delivers the last position's ballot only to the last `f` positions, so the organizer's proposal of `n-f` close responses omits it within the bound of `f`. That voter still signs the target, and its ballot does not reach the result. Before the organizer answers, the case checks that no other participant takes a response, that a participant refuses a new envelope for a slot with two known ones and, after its intent lock, a late envelope, and that the organizer refuses a response delivered with an envelope it already knows or that the response does not list. After the proposal, each participant's ordered log of accepted close inputs, replayed into a fresh close state, must reproduce its response and the organizer's proposal. At three participants `f` is zero, so no participant is corrupt and no ballot is omitted. The case generates fresh original credentials, has each active participant confirm its roster locally and each available eligible position publish a signed contribution offer, verifies the selected contributions and certifies their aggregate, closes through signed close responses, classifies the usable slots, evaluates the encrypted ranking, certifies its target, proves original-key releases and checks reconstruction from every release subset and from the honest shares that remain after every departure of at most `f` participants. When either kind has more than 256 sets, it checks a deterministic sample of 256. A target with fewer accepted ballots than the minimum turnout takes the no-result branch. The no-result cases cover a close with no ballot and one whose only listed submission is an authenticated invalid ballot. The latter preserves a valid body header and consumes the classification operands before rejecting its malformed proof. These cases retain volatile native private state; they do not establish browser custody, durable terminal publication or a complete participant workflow. Subset reconstruction is not evidence of participants departing before release generation.

Ballots pack a comparison window for every rank, whatever result length the poll requests. The evaluator and terminal decoder support every requested result length of every profile of 3 to 20 participants and 2 to 20 options. The encrypted computation clears omitted ranks; the decoder rejects a plaintext containing them. The complete-ordering program of ten participants and ten options keeps its existing bytes. Poll creation refuses only option counts outside that range, and a roster proposal refuses only sizes outside it.

The `supported-profile` crate derives each profile's thresholds, interpolation points and relation layouts in closed form. Its tracked `profiles.bin` table carries the searched parameters: both moduli with their primality witnesses, the sharing and release widths, the common sampling width and the share lifting limb and carry widths. The repository's protocol tests compare that table with the independent TypeScript profile model. After a model change, regenerate it with:

```text
pnpm run research:profiles -- --output crates/protocol-research/supported-profile/profiles.bin
```

## Build and run

The FHE key source screen generates the first public encryption coordinate from a fixed synthetic source, discards working state, reconstructs the source and checks the coordinate emitted by the first contribution gadget. It checks selected coefficients with direct integer convolution and compares identical public report bytes across native, scalar Node and external Chrome. Both scalar hosts acknowledge each bounded output span to Rust only after the run's local sink has durably written it and returned a receipt for that exact span; the sink refuses out-of-order, overlapping or excess output and never overwrites an existing artifact. It creates no registration, proof, authenticated checkpoint or setup capability. It does not establish the clear-offer selection or its departure behavior.

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

The selection-fork case has corrupt organizer 0 sign two selections for the same roster. Honest position 1 endorses the losing selection of positions 0 and 1, then refuses to endorse the winning selection of positions 0 and 2. The winner obtains its quorum from positions 0, 2 and 3; position 1 subsequently accepts that certified setup and participates in the result without changing its endorsement. A retained verification result for the losing selection cannot certify the winner. In both fixed cases exactly the quorum endorses, and the declared corrupt participant's forked signing state must replay its original endorsement, so those positions carry no second certificate. An ordinary case with more endorsements than the quorum compares the certificate of a different endorser subset for the same selection and requires identical setup identity and aggregate; carrier bytes are not setup meaning. These are native development cases, separate from browser persistence and a general malicious-scheduling proof.

Public offer records use `contribution-<position>/<body-identity>/` with `offer.bin`, `offer-signature.bin`, `body-header.bin`, `proof.bin` and the polynomial files. Discovery uses append-only untrusted announcements: `POST /offers/<position>` appends one body identity idempotently, and `GET /offers/<position>?offset=<entry-index>` returns a little-endian `u64` total, a little-endian `u32` count and at most 64 identities in insertion order. Any origin may announce; no hint replaces an earlier one or occupies a selected slot before its actual signed body verifies. The selector considers one candidate per unresolved author per round within each author's initial finite snapshot. A later call starts from the beginning, retrying previously unavailable bodies and seeing newly appended hints. Announcement storage is separate from immutable public-record paths. The selection is published as `selection.bin` and `selection-signature.bin`, endorsements as `selection-endorsement-<position>.bin`, and the setup certificate as `setup-certificate.bin` and `setup-identity.bin`. A native carrier comparison additionally writes `setup-certificate-alternative.bin`. Public consumers reconstruct and verify the named records; filenames and discovery announcements grant no capability.

The browser participant's worker may hand independent jobs to helper workers, and the Rust sources that run there also build natively. An executing case can run every job on one to eight native threads that stand in for those helpers, each holding its jobs' state as a helper instance does; the run records the count:

```text
pnpm run research:protocol -- native-invalid-only 3 2 --simulated-helpers 3
```

The build check, ceremony cases and requested-output probe run the workspace unit tests alone and then with three simulated helpers, and the proof crates' also with eight, whose proof rows hold two residue classes of each coset.

For a ceremony, the runner derives the expected roles, ranking and checked set counts from the independent TypeScript threshold and ranking models, not from the ceremony, and scales its deadline with the participant count.

The focused numerical case checks complete and shorter output prefixes at the smallest, the ten-participant and the largest profile, each prefix from the same deterministic BFV ciphertext inputs as its complete ordering:

```text
pnpm run research:protocol -- native-requested-output
```

It exercises the coefficient-selection gates and checks every decrypted coefficient with a test-only secret and an independent interpolation oracle. Because these numerical probes decrypt synthetic test ciphertexts, they compile only with the `numerical-probes` feature, which this case enables; evaluation modules neither contain nor export them. It creates no participants, ballots, certificate or protocol terminal.

For focused retrieval checks, a passed native result, setup-departure or selection-fork run supplies its public ceremony records:

```text
pnpm run research:protocol:public-records -- available-records <native-completion-run>
```

This case supplies the certificate's votes and a nonconsecutive release subset, leaves other files absent, and injects corrupt extras. It recomputes setup, the close barrier and evaluation before consuming completion records. This is a retrieval test after generation; it does not demonstrate participants disappearing before their later actions.

The public setup and close records of a passed native run can also be checked against a directory containing actual participant messages:

```text
pnpm run research:protocol:public-records -- certificate-records <native-run> <public-record-directory>
pnpm run research:protocol:public-records -- release-records <native-run> <public-record-directory>
pnpm run research:protocol:public-records -- terminal-records <native-run> <public-record-directory>
```

All three modes recompute setup, the close barrier from the published intent, responses, proposal and listed envelopes, the classification of each usable slot and the target. Only usable slots' bodies are read. The certificate mode needs only a valid quorum of target votes and does not request release shares. The release mode additionally verifies one available release share and runs wrong-target, incomplete-proof, altered-proof and duplicate controls at its actual author; it requires an encrypted target and emits no result identifiers. The terminal mode verifies sufficient release shares when the target is encrypted. These checks do not establish durable publication by themselves.

The maintained participant runtime runs registration, local roster confirmation, contribution offers, quorum setup selection, setup verification, signed ballots, close responses, target votes, release shares and the result in external desktop Chrome:

```text
pnpm run research:participant -- 3 2
```

The script first builds the workspace packages, whose SDK build produces the scalar participant module, the bundled worker and their source manifest and checks that the module contains no vector instructions, declares exactly its bounded memory and imports only what the worker supplies. The runner serves those packaged files, refuses to run when a listed source differs from the working tree, checks the published records against the sizes the profile's models derive, and checks that every ballot and release an operation generates draws exactly the proof randomness those models derive. Each honest participant's page runs its operations through the SDK's participant API, which carries the worker's source, and before any operation the worker checks the module's hash and recomputes the runtime identity over the sources, module and worker. The worker takes every size it enforces from the module, for the participant count of the retained proposal and the option count of the poll the module verified. Each participant uses its own disk-backed Chrome profile under `temp/`, and each Chrome process tree runs under a memory guard. Successful runs remove their profiles; failed runs preserve them for original-state diagnosis. The organizer creates the poll, whose result lists one option fewer than the complete ranking, and registers; the other participants join, and every participant verifies all registration records before the organizer signs the roster proposal or another participant accepts it. One more registrant joins, and the organizer leaves it out of the roster: shown the roster, it stays pending with its registration intact. Every active participant uses `confirm` to lock the displayed roster locally. Eligible positions may call `contribute`, which resumes original generation around its sealed checkpoint, signs the complete offer and publishes it under its body identity. The organizer calls `select-setup`, which publishes and authenticates readback of its exact proposal before endorsing it in the same worker; other active members call `endorse-setup` after complete verification of the selected offers. Any original member calls `verify-setup` to accept a matching setup certificate and retain the verified aggregate; a ballot is refused before that activation. Own contribution work and selection-signing intents occupy independent preparation-journal fields, so an unused own contribution is not a prerequisite for endorsement or activation. Activation retires private preparation state, while its public records remain available. Each participant then locks its scores and ballot time and retains a seed, from which alone the module expands all the ballot's encryption and proof randomness, and retains the envelope and every encrypted body record with one root that retires the seed. An interrupted attempt draws the same bytes from the retained seed again. A signed ballot refuses other scores and is only delivered again. Each participant then collects published ballots into an encrypted close log, one event and its records per accepted delivery. Every ballot but the last is on time: a late ballot starts later, and the organizer's close time is the latest on-time ballot time, so locking its intent retires every later ballot wherever it was held. When the profile tolerates a corrupt participant, as in `pnpm run research:participant -- 4 2`, every ballot is instead on time and the last corrupt position equivocates: two copies of its private state sign two more ballots at its origin, the second one late. The relay stores each submission under its author and envelope identity and names the late ballot to the last participant, whose intent lock retires it, and the other copy's ballot to the organizer, which then lists both of that author's on-time envelopes. The slot is conflicting, so none of its ballots counts, and every participant retrieves both listed envelopes by their identities. Every participant responds with the on-time ballots it holds, and the organizer takes the other responses, fetches the one body they list that it lacks, and proposes. Each participant then verifies the close barrier from the public close records in its own module, classifies every usable ballot, evaluates the public target, and retains the exact target body with fresh signing coins before it signs its target vote. When the certificate quorum is smaller than the roster, as in `pnpm run research:participant -- 4 2`, the participants after the organizer beyond it sign no target vote. Once every target vote is published, the organizer departs: its browser closes and its private state is deleted before any release exists. Each remaining participant evaluates the target again, certifies it from the published votes, retains a seed, and generates its release share from the randomness the module expands from that seed alone; the body and envelope are retained before the signing coins, and the coins before the signature. A participant that signed no target releases from its completed close once the certificate verifies and can no longer sign one. One voter's browser closes while it generates its release share, and its next session generates the share again from the retained seed. The last remaining participant halts at every step after its target lock, the last with its signed release before delivery, which its next session only delivers. A remaining participant finally combines the published shares into the requested prefix of the ranking in its own module, without the departed organizer's share. Meanwhile a malicious relay shows each other remaining honest participant forged records in its own view, and each view would complete that participant's work only if a forgery counted, so each stays pending. One view hides a voter's vote behind the last voter's vote relabeled with that voter's position and replays the last voter's vote in every non-voter's slot. Another replays the combining participant's share in the departed organizer's slot, alters another participant's release body, and relabels that share for every other slot until one share fewer than the release threshold remains. Others, one at a time, alter or withhold the body of the participant's own counted ballot, replace that ballot's submission with another counted author's authentic one, or alter its signature; the result operation verifies the close barrier again from the public records, so no view withdraws or replaces the accepted ballot. Last, one honest participant's first retained data record is altered from its own page: its next session stops it, and it stays stopped after the exact bytes are restored. That participant and the registrant left out of the roster then each verify the same outcome with the SDK's outcome verifier from the poll's identity and the relay alone. Each root transition commits under a fresh key only after its exact predecessor authenticates. A desktop result is development evidence, not supported-phone qualification.

The fault cohort also interrupts roster agreement and preparation. For a durable cut, the runner serves a copy of the runtime worker that pauses after successful root commit and readback; its page authenticates that copy's digest. It then crashes the browser process tree, and the next session runs the ordinary worker against the same retained state. Because preparation stays at one root generation while its independent journal fields advance, the preparation hooks inspect the committed own-contribution phase or selection/endorsement signature intent rather than infer progress from generation alone. The cases interrupt generation and proof continuation with staged records, the retained checkpoint, the offer-signing intent, both organizer selection commits, authenticated proposal readback before endorsement, and independent endorsement intent and signed commits. Missing or changed proposal readback preserves the signed selection and creates no endorsement intent. The first endorsement is also interrupted while reading an actual selected offer, before its verification result is retained; setup activation has its own committed-root interruption. The bounded preparation case corrupts the last selected proof after observing replacement aggregate chunks, requires the failed attempt to clear the complete public scratch cache without changing private authority or publishing an endorsement, then completes with the original bytes. Each next session discards what an interrupted operation stored and continues from its retained seed or state. After setup the first three honest ballot authors crash after the attempt lock, with the seed retained, with the body retained, with the signature intent and with the signed ballot, which the next session only delivers again. The organizer crashes with its close intent before signing it, the first two other honest participants after locking the intent and with their response intent, and the organizer again with its signed response and retained proposal intent and with its signed proposal, whose next session restores the completed close without replaying its log. The first other honest voter crashes with its target intent and the organizer with its signed vote, and the combining participant at each release generation after its target lock, the last with its signed release before delivery, which its next session only delivers.

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

Use `--publication-faults` with a plain cohort to put empty and corrupted candidates before genuine publications, refuse the organizer's first signed-ballot publication, and verify the outcome with a fresh outcome verifier after every original participant has left. This is a separate fault schedule and reports no ordinary-workflow visit total:

```text
pnpm run research:participant -- 3 2 plain --scalar --publication-faults
pnpm run research:participant -- 4 2 plain --scalar --publication-faults
```

When the selected profile permits a corrupt participant, this case also withholds that participant's ballot publication, sends its real signed close response and envelopes without body references, and removes its private state. The organizer must collect a ready quorum beyond that authenticated but incomplete response. The remaining original participants complete and a fresh reader retrieves the result.

Use `--selection-fork` for the fixed four-participant case in which the corrupt organizer signs competing selections. An honest participant endorses the losing selection, refuses to endorse again and then accepts the certified winner and completes the result. The run also checks a fresh outcome verifier:

```text
pnpm run research:participant -- 4 2 --scalar --selection-fork
```

The explicit early-departure browser case uses the same fixed scenario as the native departure selector:

```text
pnpm run research:participant -- 4 2 --setup-departure --scalar
pnpm run research:participant -- 7 2 --setup-departure --scalar
```

The seven-participant variant combines two departures in the same execution: one original member leaves before confirmation, and another loses its complete profile after publishing an offer but before selection. The surviving quorum uses the departed author's original public contribution, completes the result, and a fresh outcome verifier retrieves it.

The four-participant variant deletes honest eligible position 1's Chrome profile immediately after roster publication, before that participant accepts or confirms the roster. Cooperative corrupt position 2 runs every required valid operation. Before position 2 publishes its valid offer, it announces an invalid body identity after position 0's valid offer is available. Selection must remain pending without consuming its intent; the later valid announcement must remain discoverable behind the invalid hint. The original positions 0, 2 and 3 then finish setup, voting, closing and release; the harness independently checks the selected positions, endorsement positions and public outcome. This flag cannot combine with another scenario, a foreign poll, sequential mode or memory pressure. It leaves the ordinary three-participant baseline available and checks the stated invalid-first discovery strategy, without establishing a general adversarial-scheduling guarantee. These switches select development evidence; they are not supported-phone qualification.

To exercise activation while an eligible participant's own contribution remains unfinished, use:

```text
pnpm run research:participant -- 4 2 --unselected-checkpoint --scalar
```

All four original participants remain available, with position 2 acting as the cooperative corrupt participant. Position 1 halts after retaining a genuine first-oracle checkpoint; positions 0 and 2 complete the selected offers. Position 1 endorses that selection without finishing its own offer. Browser-only diagnostics authenticate its original state and compare opaque nested-journal and encrypted-record identities across endorsement. An isolated copy with a damaged required checkpoint record must stop before activation or publication. The healthy original retains its checkpoint until certified setup activation, then retires the unused private records and participates in voting and release. This fixed case cannot combine with another scenario, a foreign poll, sequential mode or memory pressure. It is a development lifecycle check, not supported-phone qualification or a general failure-tolerance claim.

With `--sequential`, only one participant's browser runs at a time. The ordinary workflow records explicit stage and browser-session membership, checks the completed-message frontiers between stages, and includes target and outcome verification for every original member. Every attempted invocation contributes once to cumulative active work, including pending, refused and interrupted work; valid-state continuation stays in its original stage. The organizer's final close call crosses response collection and proposal, so its complete duration contributes to both adjacent visit upper bounds but only once to participant and cohort totals. These are conservative per-visit bounds, not an exact division inside that call or a minimum visit claim. Earlier accounting-group reports retain their original interpretation.

The report preserves invocation-only active totals and separately records each browser session's bootstrap from launch through navigation and SDK initialization, after the pool makes room. It charges that bootstrap once to cumulative active upper bounds and the first invocation's visit bounds, including pending first attempts and cold restarts within one stage. Worker and helper creation, Blob-source parsing and module fetch/compilation already occur inside invocation time and are not added again. Every session must have one bootstrap and a measured invocation; missing, duplicate, mismatched or overlapping intervals fail the summary. Sequential wall time begins at the first bootstrap, while pool waiting and human delay remain outside active bounds. Combined module memory includes the worker, helpers and shared arena. Payload counters cover relay exchanges without browser network-body capture; HTTP headers and link overhead are not measured, and incomplete exchanges or unknown upload lengths remain explicit. Runs without `--sequential` do not report sequential completion time. Fault and departure schedules keep their separate recovery evidence and do not claim an ordinary measured visit traversal.

With `--profile`, Chrome records the CPU samples of every participant operation, and the run directory keeps a summary for each operation of the functions that spent the most time at the top of a sampled stack and anywhere on it. With `--memory-pressure`, the second setup contributor first contributes in a browser that caps each WebAssembly memory below what its contribution needs; that session ends pending with the worker's exhausted memory bound rather than stopping the participant, and the next session completes the contribution. This fault run does not supply an ordinary-workflow total. With `--recovery`, a plain run crashes the organizer's browser once each at a durable cut of its contribution, ballot, target vote and release, and records each following session as a recovery. With `--departures`, a concurrent plain run of a profile that tolerates a fault loses that many members for good, spread from the roster's publication to the target vote, and the remaining members complete every later quorum and the result alone. With `--foreign-poll=<run directory>`, a relay view serves one participant another passed cohort's records of the same profile as this poll's. With `--base-port=<port>`, the origins start at that port instead of 43600, so a run of another checkout can run beside this one. `--help` lists every option. Failed runs retain their private browser checkpoints in place, bound to the archived runtime and original origins; they never import them into another action or build.

Every run records, with each sample of a participant's process memory, the JavaScript heap use that its page and each of its workers and helpers last reported; a worker busy in a module call reports only when it returns to its event loop.

The local relay gives each uploaded chunk an immutable opaque locator and appends complete correlated manifests to discovery lists. Earlier junk cannot reserve a logical publication key. The worker checks named chunk, manifest and discovery readback; owning verifiers authenticate the actual protocol bytes. Forwarding can reuse chunk locations only after comparing their complete contents with authenticated retained records. The harness also writes diagnostic record copies for inspection; the protocol reads the manifest and chunk store. The runner refuses unknown or empty selectors, serializes heavy runs, derives the corpus bound before generation, checks available memory, contains the process tree and records diagnostics under `logs/`. The ceremony's records, the relay's records, the public-record check's output and the runtime copies are the run's artifacts, which it writes under `temp/run-artifacts/` with the same date and run name as its diagnostics; a run named as the source of another reads them from there. Native process memory, runtime and public storage measurements remain distinct from unmeasured browser, recovery, network-transfer and participant-visit costs. Failed diagnostics are preserved.

All sources, parameters and toolchain selection needed by the native generation case are tracked, and the tracked lockfile pins each third-party crate's version and checksum. That case uses `temp/` only for run-owned scratch and the run's artifacts. No prior log, private participant profile, generated target directory or reference checkout is an input to native generation. Source paths are captured in each run; moving code changes the build identity and never authorizes private-state import.

The SDK's outcome verifier runs the same participant module and worker as a participant, and so the same owning Rust verifiers. Target certification alone does not establish that the published records remain retrievable. The complete reduction argument, resource qualification of every supported profile and supported-phone qualification remain outstanding.

The participant module also signs targets and generates certified releases in the same scalar instance. New release work requires the actual certificate-derived context and original recipient key; an unsigned retained body passes the owning verifier before signing. Completed-message restoration verifies its original signature and exact body digest and restores consumed authority only. A restored credential signs nothing new until the authenticated participant root unlocks the purposes its records show unused. The worker connects the retained seed, body and signature to root transitions.

The module refuses a release unless the worker installed the retained seed and nothing was drawn from it, and it expands the release's randomness from that seed alone; the seed supplies no release authority.
