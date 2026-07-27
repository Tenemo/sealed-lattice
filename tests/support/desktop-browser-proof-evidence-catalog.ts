import type { DesktopBrowserProofExecutionKind } from './desktop-browser-proof-measurement.js';

export type DesktopBrowserProofEvidenceOwnershipRole =
    | 'generation'
    | 'verification';

export const desktopBrowserProofEvidenceCaseExecutionKinds = Object.freeze({
    'aggregate-threshold-share-generation': 'fresh-generation',
    'aggregate-threshold-share-verification': 'verification',
    'ballot-validity-generation': 'fresh-generation',
    'ballot-validity-verification': 'verification',
    'evaluator-key-aggregate-generation': 'fresh-generation',
    'evaluator-key-aggregate-verification': 'verification',
    'evaluator-replay-maximum-stream': 'replay',
    'galois-key-share-batch-generation-fresh': 'fresh-generation',
    'galois-key-share-batch-generation-resumed': 'resumed-generation',
    'galois-key-share-batch-verification': 'verification',
    'relinearization-round-two-generation': 'fresh-generation',
    'relinearization-round-two-verification': 'verification',
    'same-secret-generation-after-cancellation': 'worker-reuse-generation',
    'same-secret-generation-after-refusal': 'worker-reuse-generation',
    'same-secret-generation-cancellation': 'cancelled-generation',
    'same-secret-generation-refusal': 'refused-generation',
    'same-secret-generation': 'fresh-generation',
    'same-secret-native-wasm-deterministic-parity': 'deterministic-parity',
    'same-secret-verification': 'verification',
    'vss-share-linkage-generation-fresh': 'fresh-generation',
    'vss-share-linkage-generation-resumed': 'resumed-generation',
    'vss-share-linkage-verification': 'verification',
} satisfies Readonly<Record<string, DesktopBrowserProofExecutionKind>>);

export type DesktopBrowserProofEvidenceCaseIdentifier =
    keyof typeof desktopBrowserProofEvidenceCaseExecutionKinds;

export const desktopBrowserProofEvidenceCaseIdentifiers = Object.freeze(
    Object.keys(
        desktopBrowserProofEvidenceCaseExecutionKinds,
    ) as readonly DesktopBrowserProofEvidenceCaseIdentifier[],
);

const desktopBrowserProofEvidenceCaseIdentifierSet: ReadonlySet<string> =
    new Set(desktopBrowserProofEvidenceCaseIdentifiers);

export const isDesktopBrowserProofEvidenceCaseIdentifier = (
    value: string,
): value is DesktopBrowserProofEvidenceCaseIdentifier =>
    desktopBrowserProofEvidenceCaseIdentifierSet.has(value);

export const desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole =
    Object.freeze({
        generation: Object.freeze(
            desktopBrowserProofEvidenceCaseIdentifiers.filter(
                (caseIdentifier) =>
                    desktopBrowserProofEvidenceCaseExecutionKinds[
                        caseIdentifier
                    ] !== 'verification',
            ),
        ),
        verification: Object.freeze(
            desktopBrowserProofEvidenceCaseIdentifiers.filter(
                (caseIdentifier) =>
                    desktopBrowserProofEvidenceCaseExecutionKinds[
                        caseIdentifier
                    ] === 'verification',
            ),
        ),
    } satisfies Readonly<
        Record<
            DesktopBrowserProofEvidenceOwnershipRole,
            readonly DesktopBrowserProofEvidenceCaseIdentifier[]
        >
    >);

export const desktopBrowserProofGenerationRepetitionRequirement = Object.freeze(
    {
        caseIdentifier: 'same-secret-generation',
        minimumColdRunCount: 2,
        minimumWarmRunCount: 2,
    } as const,
);

export const desktopBrowserProofCancellationCoverageRequirement = Object.freeze(
    {
        cancellationCaseIdentifier: 'same-secret-generation-cancellation',
        declarationCaseIdentifier: 'same-secret-generation',
        reuseCaseIdentifier: 'same-secret-generation-after-cancellation',
    } as const,
);

export const desktopBrowserProofRefusalReuseRequirement = Object.freeze({
    refusalCaseIdentifier: 'same-secret-generation-refusal',
    reuseCaseIdentifier: 'same-secret-generation-after-refusal',
} as const);

export const desktopBrowserProofDeterministicParityCaseIdentifier =
    'same-secret-native-wasm-deterministic-parity' as const;

export const desktopBrowserProofTransportCasePairs = Object.freeze([
    [
        'aggregate-threshold-share-generation',
        'aggregate-threshold-share-verification',
    ],
    ['ballot-validity-generation', 'ballot-validity-verification'],
    [
        'evaluator-key-aggregate-generation',
        'evaluator-key-aggregate-verification',
    ],
    [
        'galois-key-share-batch-generation-fresh',
        'galois-key-share-batch-verification',
    ],
    [
        'relinearization-round-two-generation',
        'relinearization-round-two-verification',
    ],
    ['same-secret-generation', 'same-secret-verification'],
    ['vss-share-linkage-generation-fresh', 'vss-share-linkage-verification'],
] as const);

export type DesktopBrowserProofTransportGenerationCaseIdentifier =
    (typeof desktopBrowserProofTransportCasePairs)[number][0];
export type DesktopBrowserProofTransportVerificationCaseIdentifier =
    (typeof desktopBrowserProofTransportCasePairs)[number][1];

export const desktopBrowserProofTransportGenerationCaseIdentifiers =
    Object.freeze(
        desktopBrowserProofTransportCasePairs.map(
            ([generationCaseIdentifier]) => generationCaseIdentifier,
        ),
    );

export const resolveDesktopBrowserProofTransportVerificationCaseIdentifier = (
    generationCaseIdentifier: string,
): DesktopBrowserProofTransportVerificationCaseIdentifier | undefined =>
    desktopBrowserProofTransportCasePairs.find(
        ([candidateGenerationCaseIdentifier]) =>
            candidateGenerationCaseIdentifier === generationCaseIdentifier,
    )?.[1];
