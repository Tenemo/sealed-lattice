# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WASM prototype for threshold homomorphic polling. It implements configuration and transcript checks, collective BGV setup records and proof checks, a bounded direct-ballot path, encrypted evaluator replay, and target-bound threshold result release.

The repository is development software. It has not been independently audited, certified, or approved for production elections, and it must not be used with real ballots or secret material. The implementation summary below records what exists now; fixtures, local runs, and component tests do not expand the security boundary in [SECURITY.md](SECURITY.md).

## Current implementation ledger

### Configuration and foundation

The TypeScript protocol layer and published package provide:

- poll validation, canonical poll hashes, threshold derivation, and frozen-roster parameter derivation;
- roster-manifest transcript checks and externally anchored roster acceptance;
- lifecycle-transition, action-capability, recovery-epoch, and deterministic first-valid ordering checks;
- foundation-transcript and append-only board-consistency checks; and
- cast-receipt, close-record, and target-finality shells.

These helpers validate their stated inputs and return structured refusals. They do not create an election authority or decide whether caller-supplied policy, signer, witness, or roster keys are trustworthy. In particular, the target-finality helper is not an authorization decision because its witness keys are not yet bound to an accepted roster (`SEC-013`).

### Collective setup, VSS, and evaluation keys

The repository implements the following collective BGV setup path:

- common-randomness commit and reveal records;
- per-coefficient committed-material VSS commitments, private mailbox delivery, local share checks, acceptance records, and complaint records;
- VSS share-linkage and aggregate-threshold proofs, plus a full-source same-secret bridge between the accepted BDLOP constant commitments and target committed material;
- public-key share records, collective public-key construction, evaluator-key schedules, relinearization and Galois-key share records, and trustee evaluation-key proof material;
- chunked binary transport for large public material and proof bytes;
- encrypted local trustee setup state with explicit retained-material and deletion boundaries; and
- setup phase records, transport certificates, package assembly, and Rust/WASM package acceptance against externally supplied manifest and roster hashes.

VSS commitment records bind collision-resistant committed-material roots. Recipient shares and aggregate threshold shares are tied to those roots by proof relations; the aggregate is not accepted from a producer-supplied sum. The same-secret bridge opens the complete accepted BDLOP constant-commitment set and the target committed-material commitments to one ternary secret. Public-key share proofs bind to that bridge, while evaluation-key atom proofs open the exact canonical limb-zero source constant commitment. Legacy projection and opaque same-secret-anchor artifacts do not contribute to acceptance (`SEC-012`).

The implemented setup proofs remain development evidence. They do not establish complete 128-bit quantum soundness or zero knowledge (`SEC-004`, `SEC-005`), and secret-dependent evaluation-key material retains the construction's KDM or circular-security assumption (`SEC-011`).

### Direct ballots

The Rust kernel contains a bounded direct encrypted-ballot command. The current profile accepts one to twenty ballots, exactly twenty score options, and integer scores from 1 through 10. It validates the setup handoff and disjoint randomness, encrypts each ballot, creates and checks a ballot-relation proof, transports proof bytes in chunks, and aggregates the ciphertexts.

This path is a kernel development path driven by a private setup witness. It is not exposed as a complete public cast, collection, receipt, and accepted-ballot workflow. The TypeScript plaintext oracle is test support for checking the bounded ranking and sparse-target semantics; it is not a voting or tallying API (`SEC-007`).

### Aggregation and evaluator replay

The kernel implements homomorphic addition of accepted direct-ballot ciphertexts and a deterministic packed BGV top-k evaluator for the bounded score domain. The evaluator performs encrypted comparisons, rank accumulation, and sparse target projection, and emits a target proposal and evaluator-replay record bound to the setup, aggregate, layout, and target context.

The evaluator currently provides component and end-to-end development evidence. It does not by itself accept the target, prove the complete evaluation, or authorize result release. Existing estimator output, fixtures, and component tests do not establish complete ballot confidentiality or evaluation correctness (`SEC-006`).

### Target finality and decryption

The target-decryption kernel binds an accepted setup package, accepted target record, target ciphertext pair, target basis, and target share profile. Its staged result-release path:

1. derives the release context from the accepted setup package;
2. starts a release session for one target binding;
3. checks each distinct trustee's target-bound share proof and accumulates exactly the required quorum; and
4. interpolates only the selected target fields and consumes that target binding in process.

Development-only commands can derive share statements and create target-bound shares and proof material from a trustee's local witness. The published package exposes the staged result check, not a proofless raw-share interface.

The one-shot consumption registry is process-local and is not persistent across restarts. Target release therefore remains development-only and must not be treated as a durable authorization boundary (`SEC-002`). Retry safety for setup, key switching, and decryption under reused secret material is also open (`SEC-003`).

### Package and API surface

The published `sealed-lattice` package is an ESM package that loads the Rust kernel through the bundled WebAssembly bridge. Public consumers must import from the package root; workspace packages, fixtures, or deep source paths are not public API.

The package root currently exports these runtime functions:

- Poll and roster helpers: `validatePollSpec`, `derivePollSpecHash`, `deriveThresholdParameters`, `deriveThresholdParametersHash`, `deriveFrozenRosterParameters`, and `deriveCollectiveBgvSetupRosterHash`.
- Lifecycle and transcript helpers: `isValidLifecycleTransition`, `evaluateActionCapability`, `verifyFoundationTranscript`, `verifyBoardConsistency`, `verifyCastReceiptShell`, `verifyCloseRecordShell`, `deriveValidatedFirstValidOrder`, `verifyRosterExternalAcceptance`, `verifyRosterManifestTranscript`, `isActionCurrentForRecoveryEpoch`, and `verifyRecoveryEpochUpdate`.
- Setup and kernel helpers: `verifyPrivateVssShare`, `createSetupPackageVerificationInput`, `verifySetupPackage`, `verifyTargetFinality`, `verifyTargetDecryptionResult`, and `verifyTranscriptCoreFixture`.

TypeScript input, result, protocol-object, setup-transport, and verification types are exported from the same package root. `packages/sdk/api-surface-summary.json` is a generated review aid for intentional public API changes; package policy and packed-package smoke tests cover runtime exports and published behavior.

### Runtime verification paths

| Runtime path             | Evidence that exists now                                                                                                                                                                                                                                      | Current limit                                                                                                              |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Native Rust              | Kernel unit and integration tests cover setup commitments and proofs, direct ballots, evaluator operations, target-bound shares, and result release.                                                                                                          | Native execution is development evidence only and is not the participant-facing product runtime.                           |
| Node.js with WebAssembly | Fast and heavy kernel suites exercise the built WebAssembly bridge, accepted setup packages, direct ballots, evaluator replay, and target decryption. TypeScript package suites cover foundation, setup construction, transport, and public package behavior. | Node.js evidence does not establish browser or supported-phone execution.                                                  |
| Desktop browser          | Browser suites load the WebAssembly kernel, execute a canonical hashing command, exercise foundation package exports, and check the plaintext-oracle semantics without native helpers.                                                                        | The current browser suite does not run the full ceremony or its proof workloads. There is no browser proof benchmark lane. |
| Supported phone          | No physical-device runtime evidence is recorded.                                                                                                                                                                                                              | Native, Node.js, desktop-browser, and emulated runs cannot substitute for supported-phone evidence (`SEC-008`).            |

Participant mobile browsers remain the required verification path: acceptance must not depend on a trusted tally server, external prover, dedicated auditor, or native-only verifier. Heavy trustee evaluation-key proving may currently require a participant-owned desktop device, but it is not an accepted native-only end state. Closing that runtime gap requires proof-size and runtime work plus evidence from the exact supported physical-device and build combination.

## Public security and runtime boundaries

The authoritative wording and correct-use consequences are in [SECURITY.md](SECURITY.md). In summary:

- `SEC-001` and `SEC-009`: this is development software without production approval, independent audit, certification, or production hardening. Use only synthetic data.
- `SEC-002`: target decryption does not yet provide a persistent one-shot release boundary.
- `SEC-003`: repeated participation with reused setup, key-switching, or decryption secret material is not covered by an established retry-safety argument.
- `SEC-004` and `SEC-005`: the complete setup-proof system does not carry conventional 128-bit quantum soundness or full 128-bit zero-knowledge claims.
- `SEC-006`: homomorphic-encryption evidence covers components, not complete end-to-end ballot confidentiality, evaluator correctness, and target release.
- `SEC-007`: the public encrypted-ballot creation, proof, transport, aggregation, and accepted-result workflow is incomplete.
- `SEC-008`: there is no supported-phone runtime evidence.
- `SEC-010`: accepting a roster size or derived parameter set does not certify a cryptographic or runtime profile.
- `SEC-011`: evaluation-key material depends on the selected construction's KDM or circular-security assumptions.
- `SEC-012`: legacy VSS projection and opaque anchor artifacts do not contribute to acceptance; committed-material roots, the full-source bridge proof, and canonical BDLOP source commitments carry the current binding.
- `SEC-013`: target-finality witness keys are caller supplied and are not bound to an accepted roster.
- `SEC-014`: hash-critical non-ASCII text can diverge with ambient Unicode data; callers should independently enforce one canonical representation or keep those identifiers and labels ASCII.

Do not expose VSS shares, trustee secret shares, encryption randomness, proof witnesses, decryption witnesses, or local secret state. Untrusted transcript and private-mailbox services may relay bytes, but acceptance must come from recomputed canonical encodings, hashes, roots, signatures, proof relations, and externally anchored prerequisites.

## Installation

```bash
npm install sealed-lattice
```

or:

```bash
pnpm add sealed-lattice
```

The package requires Node.js 24.14.1 or later when used in Node.js.

## Usage

```typescript
import { deriveThresholdParameters, validatePollSpec } from "sealed-lattice";

const pollValidation = validatePollSpec({
    pollId: "board-election-2026",
    question: "Which proposal should be adopted?",
    options: Array.from(
        { length: 20 },
        (_unused, optionIndex) => `Proposal ${optionIndex + 1}`,
    ),
    topOptionCount: 5,
});

if (!pollValidation.isValid) {
    throw new Error(
        pollValidation.errors[0]?.message ?? "Invalid poll specification.",
    );
}

const thresholdParameters = deriveThresholdParameters({ rosterSize: 10 });

console.log(pollValidation.normalized, thresholdParameters);
```

`pollValidation.normalized` contains the validated poll with defaults applied. Threshold derivation returns protocol parameters and warnings; it is not a security certificate.

## Development

The repository uses Node.js 24.14.1 and pnpm 10.33.0.

```bash
pnpm install --frozen-lockfile
pnpm run check
```

Useful full verification commands are:

```bash
pnpm run tsc
pnpm run build
pnpm run test:node
pnpm run test:browser
pnpm run smoke:pack:npm
```

Kernel proof changes also use the Rust lanes:

```bash
pnpm run test:rust:kernel
pnpm run test:rust:kernel:accepted-setup
```

Generate the public SDK review summary after an intentional API change:

```bash
pnpm run api-surface:generate
```

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
