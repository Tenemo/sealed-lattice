# sealed-lattice

`sealed-lattice` provides browser-oriented TypeScript and Rust/WASM helpers for validating poll configuration, deriving threshold parameters, and verifying protocol transcripts and setup artifacts. It is development software and is not approved for production elections or real ballots.

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

## API

Import public functions and types only from `sealed-lattice`. Internal workspace package paths are not public API.

The package root currently exports these runtime functions:

- Poll and roster helpers: `validatePollSpec`, `derivePollSpecHash`, `deriveThresholdParameters`, `deriveThresholdParametersHash`, `deriveFrozenRosterParameters`, and `deriveCollectiveBgvSetupRosterHash`.
- Lifecycle and transcript helpers: `isValidLifecycleTransition`, `evaluateActionCapability`, `verifyFoundationTranscript`, `verifyBoardConsistency`, `verifyCastReceiptShell`, `verifyCloseRecordShell`, `deriveValidatedFirstValidOrder`, `verifyRosterExternalAcceptance`, `verifyRosterManifestTranscript`, `isActionCurrentForRecoveryEpoch`, and `verifyRecoveryEpochUpdate`.
- Setup and kernel helpers: `verifyPrivateVssShare`, `createSetupPackageVerificationInput`, `verifySetupPackage`, `verifyTargetFinality`, `verifyTargetDecryptionResult`, and `verifyTranscriptCoreFixture`.

TypeScript input, result, protocol-object, setup-transport, and verification types are exported from the same package root.

## Security

This package is development software, not a production voting system. Read the current trust boundary and safe-use requirements in [SECURITY.md](SECURITY.md) before relying on a verification result.

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

Generate the public SDK review summary after an intentional API change:

```bash
pnpm run api-surface:generate
```

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
