import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { deriveProtocolHash } from '#packages/crypto/src/index';
import type { AggregateDerivationWitnessInput } from '#packages/protocol/src/ballot-privacy/index';
import type {
    AggregateContribution,
    AggregateDerivationComponent,
    ProtocolHash,
} from '#packages/types/src/index';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

export type TranscriptCoreKernel = Awaited<
    ReturnType<typeof loadTranscriptCoreKernel>
>;

export type MatrixMode = 'full' | 'representative';

export type Variant = {
    readonly optionCount: number;
    readonly rosterSize: number;
};

export type MatrixRow = {
    readonly aggregateCoordinateCount: number;
    readonly aggregateReadyVerificationTime: number;
    readonly claimTier: string;
    readonly ciphertextShape: Record<string, unknown>;
    readonly failureReason: string | null;
    readonly optionCount: number;
    readonly proofByteLength: number;
    readonly proverTime: number;
    readonly publicArtifactWitnessCleanResult: boolean;
    readonly rosterSize: number;
    readonly selectedContributionCount: number;
    readonly shareVectorWidth: number;
    readonly status: 'passed' | 'failed';
    readonly thresholdProfileHash: ProtocolHash;
    readonly trusteeAggregateThreshold: number;
    readonly verifierTime: number;
};

export type NegativeCheck = {
    readonly check: string;
    readonly expectedFailureObserved: boolean;
    readonly failureReason: string | null;
    readonly optionCount: number;
    readonly rosterSize: number;
    readonly suite: 'cheap' | 'sentinel';
};

export type ShapeConfigRow = {
    readonly aggregateInputLayoutHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
    readonly bridgeProofTargetContractHash: ProtocolHash;
    readonly claimTier: string;
    readonly failureReason: string | null;
    readonly optionCount: number;
    readonly rosterSize: number;
    readonly selectedContributionCount: number;
    readonly shareVectorWidth: number;
    readonly statementDimensionHash: ProtocolHash;
    readonly status: 'passed' | 'failed';
    readonly thresholdProfileHash: ProtocolHash;
    readonly trusteeAggregateThreshold: number;
};

export type ContributionBuild = {
    readonly aggregateContribution: AggregateContribution;
    readonly aggregateDerivationComponent: AggregateDerivationComponent;
    readonly aggregateWitness: AggregateDerivationWitnessInput;
    readonly bridgeEncryption: Record<string, unknown>;
    readonly bridgeVerification: Record<string, unknown>;
    readonly proofByteLength: number;
    readonly proverTime: number;
    readonly verifierTime: number;
};

export type VariantBuildResult = {
    readonly aggregateReadyRow: MatrixRow;
    readonly benchmarkRow: MatrixRow | null;
    readonly negativeChecks: readonly NegativeCheck[];
    readonly privateRelationRow: MatrixRow;
    readonly proofRow: MatrixRow;
};

export type IndexedVariantBuildResult = VariantBuildResult & {
    readonly variantIndex: number;
};

export const outputDirectory = path.join(
    process.cwd(),
    'temp',
    'aggregate-bridge',
);

export const workerOutputPrefix = 'SEALED_LATTICE_BRIDGE_ROW_RESULT=';

const forbiddenPublicArtifactFieldNames = new Set([
    'aggregateInputPlaintext',
    'aggregateIntegerShareVector',
    'aggregateOpeningRandomness',
    'aggregateScore',
    'aggregateScoreBits',
    'aggregateShareWitness',
    'aggregateWitness',
    'bgvPlaintext',
    'comparisonInputs',
    'encryptionError',
    'encryptionNoise',
    'encryptionRandomizer',
    'encryptionRandomness',
    'layoutPlaintextWitness',
    'noiseWitness',
    'plaintextComparisonInputs',
    'plaintextScoreBitInputs',
    'quotientWitness',
    'rankWitness',
    'rawAggregateWitness',
    'receiverPlaintext',
    'sourceWitnessCoefficients',
    'tPvss',
    't_pvss',
]);

export const publicArtifactIsWitnessClean = (value: unknown): boolean => {
    if (Array.isArray(value)) {
        return value.every(publicArtifactIsWitnessClean);
    }
    if (typeof value !== 'object' || value === null) {
        return true;
    }

    return Object.entries(value).every(
        ([fieldName, fieldValue]) =>
            !forbiddenPublicArtifactFieldNames.has(fieldName) &&
            publicArtifactIsWitnessClean(fieldValue),
    );
};

export const sentinelVariants = new Set([
    '3:2',
    '3:20',
    '4:2',
    '9:20',
    '10:2',
    '10:20',
    '16:2',
    '16:20',
    '20:2',
    '20:20',
]);

export const benchmarkVariantKeys = new Set([
    '20:20',
    '20:10',
    '3:2',
    '3:10',
    '9:20',
]);

export const lowerHexHash = (label: string): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        label,
        purpose: 'encrypted-aggregate-bridge-matrix',
    });

export const variantKey = (variant: Variant): string =>
    `${variant.rosterSize}:${variant.optionCount}`;

export const parseVariantKey = (key: string): Variant => {
    const [rosterSizeText, optionCountText] = key.split(':');
    const rosterSize = Number(rosterSizeText);
    const optionCount = Number(optionCountText);
    if (
        !Number.isInteger(rosterSize) ||
        !Number.isInteger(optionCount) ||
        rosterSize < 3 ||
        rosterSize > 20 ||
        optionCount < 2 ||
        optionCount > 20
    ) {
        throw new Error(
            `Invalid encrypted aggregate bridge variant key: ${key}`,
        );
    }

    return { optionCount, rosterSize };
};

export const argumentValue = (name: string): string | null => {
    const argumentIndex = process.argv.indexOf(name);
    if (argumentIndex < 0) {
        return null;
    }
    const value = process.argv[argumentIndex + 1];
    if (value === undefined || value.startsWith('--')) {
        throw new Error(`Missing value for ${name}.`);
    }

    return value;
};

export const matrixMode = (): MatrixMode => {
    for (const removedArgument of ['--prototype', '--axes', '--workers']) {
        if (process.argv.includes(removedArgument)) {
            throw new Error(
                `Unsupported encrypted aggregate bridge matrix argument: ${removedArgument}`,
            );
        }
    }
    if (process.argv.includes('--representative')) {
        return 'representative';
    }

    return 'full';
};

export const variantsForMode = (mode: MatrixMode): readonly Variant[] => {
    const variants = Array.from({ length: 18 }, (_unusedRoster, rosterIndex) =>
        Array.from({ length: 19 }, (_unusedOption, optionIndex) => ({
            optionCount: optionIndex + 2,
            rosterSize: rosterIndex + 3,
        })),
    ).flat();
    if (mode === 'representative') {
        return variants.filter((variant) =>
            sentinelVariants.has(variantKey(variant)),
        );
    }

    return variants;
};

const fullMatrixWorkerCount = 8;
const representativeMatrixWorkerCount = 4;

export const requestedWorkerCount = (mode: MatrixMode): number => {
    return mode === 'representative'
        ? representativeMatrixWorkerCount
        : fullMatrixWorkerCount;
};

export const claimTierForRosterSize = (rosterSize: number): string =>
    rosterSize < 10 ? 'micro-roster-outside-claim' : 'claim-candidate';

export const measure = <Result>(
    action: () => Result,
): {
    readonly elapsedMilliseconds: number;
    readonly result: Result;
} => {
    const startedAt = performance.now();
    const result = action();

    return {
        elapsedMilliseconds: performance.now() - startedAt,
        result,
    };
};

export const roundedMilliseconds = (milliseconds: number): number =>
    Math.round(milliseconds);
