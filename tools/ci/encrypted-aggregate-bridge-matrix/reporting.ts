import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
    claimTierForRosterSize,
    lowerHexDigest,
    outputDirectory,
    variantKey,
    type MatrixRow,
    type NegativeCheck,
    type Variant,
    type VariantBuildResult,
} from './shared.js';

import { deriveThresholdProfile } from '#packages/protocol/src/lifecycle/thresholds';

export const failedRow = (
    variant: Variant,
    failureReason: unknown,
): MatrixRow => {
    const thresholdProfile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: variant.rosterSize < 10,
        rosterSize: variant.rosterSize,
    });

    return {
        aggregateCoordinateCount: variant.optionCount * 11,
        aggregateReadyVerificationTime: 0,
        claimTier: claimTierForRosterSize(variant.rosterSize),
        ciphertextShape: {},
        failureReason:
            failureReason instanceof Error
                ? failureReason.message
                : String(failureReason),
        optionCount: variant.optionCount,
        proofByteLength: 0,
        proverTime: 0,
        publicArtifactWitnessCleanResult: false,
        rosterSize: variant.rosterSize,
        selectedContributionCount: thresholdProfile.pvssThreshold,
        shareVectorWidth: variant.optionCount * 11,
        status: 'failed',
        thresholdProfileHash: lowerHexDigest(
            `failed-threshold-${variantKey(variant)}`,
        ),
        trusteeAggregateThreshold: thresholdProfile.pvssThreshold,
        verifierTime: 0,
    };
};

export const matrixMarkdown = (input: {
    readonly title: string;
    readonly rows: readonly MatrixRow[];
}): string => {
    const lines = [
        `# ${input.title}`,
        '',
        '| n | m | claim tier | t_pvss | selected | shareVectorWidth | aggregate coordinates | proof bytes | prover ms | verifier ms | aggregate-ready verifier ms | witness-clean | status | failure reason |',
        '| -: | -: | - | -: | -: | -: | -: | -: | -: | -: | -: | - | - | - |',
        ...input.rows.map((row) =>
            [
                row.rosterSize,
                row.optionCount,
                row.claimTier,
                row.trusteeAggregateThreshold,
                row.selectedContributionCount,
                row.shareVectorWidth,
                row.aggregateCoordinateCount,
                row.proofByteLength,
                row.proverTime.toFixed(1),
                row.verifierTime.toFixed(1),
                row.aggregateReadyVerificationTime.toFixed(1),
                row.publicArtifactWitnessCleanResult ? 'passed' : 'failed',
                row.status,
                row.failureReason ?? '',
            ].join(' | '),
        ),
    ];

    return `${lines.join('\n')}\n`;
};

export const negativeMarkdown = (checks: readonly NegativeCheck[]): string => {
    const lines = [
        '# Encrypted aggregate bridge negative fixture report',
        '',
        '| n | m | suite | check | expected failure observed | failure reason |',
        '| -: | -: | - | - | - | - |',
        ...checks.map((check) =>
            [
                check.rosterSize,
                check.optionCount,
                check.suite,
                check.check,
                check.expectedFailureObserved ? 'yes' : 'no',
                check.failureReason ?? '',
            ].join(' | '),
        ),
    ];

    return `${lines.join('\n')}\n`;
};

export const writeArtifact = async (
    fileName: string,
    content: string,
): Promise<void> => {
    await writeFile(path.join(outputDirectory, fileName), content, 'utf8');
};

export const appendVariantResult = (input: {
    readonly aggregateReadyRows: MatrixRow[];
    readonly benchmarkRows: MatrixRow[];
    readonly negativeChecks: NegativeCheck[];
    readonly privateRows: MatrixRow[];
    readonly proofRows: MatrixRow[];
    readonly result: VariantBuildResult;
}): void => {
    input.privateRows.push(input.result.privateRelationRow);
    input.proofRows.push(input.result.proofRow);
    input.aggregateReadyRows.push(input.result.aggregateReadyRow);
    input.negativeChecks.push(...input.result.negativeChecks);
    if (input.result.benchmarkRow !== null) {
        input.benchmarkRows.push(input.result.benchmarkRow);
    }
};

export const failedVariantResult = (
    variant: Variant,
    failureReason: unknown,
): VariantBuildResult => {
    const row = failedRow(variant, failureReason);

    return {
        aggregateReadyRow: row,
        benchmarkRow: null,
        negativeChecks: [],
        privateRelationRow: row,
        proofRow: row,
    };
};
