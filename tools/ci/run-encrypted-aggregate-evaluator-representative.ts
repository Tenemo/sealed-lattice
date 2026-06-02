import { Buffer } from 'node:buffer';
import path from 'node:path';

import {
    readJsonFile,
    writeJsonFileAtomic,
} from './aggregate-derivation-kernel/checkpoints.js';

import { canonicalJson } from '#packages/crypto/src/index';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import type {
    BgvPassiveSetupPackage,
    TopKEvaluatorEncryptedAggregateEvaluationSweep,
    TopKEvaluatorEncryptedAggregateInput,
} from '#packages/wasm/src/transcript-core-bridge/kernel-types';
import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

type RepresentativeEvaluatorRequestBase = {
    readonly aggregateReadyRecord: unknown;
    readonly canonicalBallotSetHash: string;
    readonly encryptedAggregateInputs: readonly TopKEvaluatorEncryptedAggregateInput[];
    readonly evaluatorSignature: string;
    readonly objectType: 'EncryptedAggregateTopKEvaluationRequestBase';
    readonly objectVersion: 1;
    readonly preTargetBoardHead: string;
    readonly scoreDomainMax: number;
    readonly setupPackage: BgvPassiveSetupPackage;
    readonly topCount: number;
};

type RunnerConfig = {
    readonly checkpointDir: string;
    readonly requestBasePath: string;
    readonly setupSeed: string;
    readonly topCounts: readonly number[];
};

const usageText = `Usage:
  pnpm run test:encrypted-aggregate-evaluator:representative
  pnpm run test:encrypted-aggregate-evaluator:representative -- --top-count 1
  pnpm run test:encrypted-aggregate-evaluator:representative -- --top-counts 1,10,20
  pnpm run test:encrypted-aggregate-evaluator:representative -- --top-counts all

Flags:
  --checkpoint-dir <path> (default: temp/test-checkpoints)
  --request-base <path> (default: aggregate-derivation-kernel-last-evaluator-request-base.json under checkpoint dir)
  --setup-seed <seed> (default: accepted-encrypted-aggregate-evaluator-test-seed)
  --top-count <count> (default: 1)
  --top-counts <comma-separated-counts|all> (overrides --top-count)

This runner consumes the fast aggregate-derivation request-base artifact,
prepares in-process public evaluation-key material from the setup private
witness without serializing key-switch coefficients as JSON, runs the accepted
encrypted aggregate evaluator sweep, and writes the public result under the
checkpoint directory. It does not run the bridge matrix.
`;

const removePackageManagerSeparator = (
    argumentsList: readonly string[],
): readonly string[] => argumentsList.filter((argument) => argument !== '--');

const requiredNestedString = (
    value: unknown,
    pathSegments: readonly string[],
): string => {
    let currentValue = value;
    for (const pathSegment of pathSegments) {
        if (
            currentValue === null ||
            typeof currentValue !== 'object' ||
            !(pathSegment in currentValue)
        ) {
            throw new Error(
                `Missing required field ${pathSegments.join('.')}.`,
            );
        }
        currentValue = (currentValue as Record<string, unknown>)[pathSegment];
    }
    if (typeof currentValue !== 'string') {
        throw new Error(
            `Required field ${pathSegments.join('.')} must be a string.`,
        );
    }

    return currentValue;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const nestedValue = (
    value: unknown,
    pathSegments: readonly string[],
): unknown => {
    let currentValue = value;
    for (const pathSegment of pathSegments) {
        if (!isRecord(currentValue) || !(pathSegment in currentValue)) {
            return undefined;
        }
        currentValue = currentValue[pathSegment];
    }

    return currentValue;
};

const optionalNestedNumber = (
    value: unknown,
    pathSegments: readonly string[],
): number | null => {
    const nested = nestedValue(value, pathSegments);

    return typeof nested === 'number' && Number.isFinite(nested)
        ? nested
        : null;
};

const optionalNestedString = (
    value: unknown,
    pathSegments: readonly string[],
): string | null => {
    const nested = nestedValue(value, pathSegments);

    return typeof nested === 'string' ? nested : null;
};

export const canonicalJsonByteLength = (value: unknown): number =>
    Buffer.byteLength(canonicalJson(value), 'utf8');

export const canonicalCiphertextByteLength = (
    artifact: unknown,
): number | null => {
    const canonicalBytesHex = optionalNestedString(artifact, [
        'canonicalBytesHex',
    ]);
    if (canonicalBytesHex === null || canonicalBytesHex.length % 2 !== 0) {
        return null;
    }

    return canonicalBytesHex.length / 2;
};

const argumentValue = (
    argumentsList: readonly string[],
    flag: string,
): string | null => {
    const index = argumentsList.indexOf(flag);
    if (index < 0) {
        return null;
    }
    const value = argumentsList[index + 1];
    if (value === undefined || value.startsWith('--')) {
        throw new Error(`Missing value for ${flag}.`);
    }

    return value;
};

const positiveIntegerFlag = (
    argumentsList: readonly string[],
    flag: string,
    fallback: number,
): number => {
    const rawValue = argumentValue(argumentsList, flag);
    if (rawValue === null) {
        return fallback;
    }
    const value = Number(rawValue);
    if (!Number.isInteger(value) || value < 1) {
        throw new Error(`${flag} must be a positive integer.`);
    }

    return value;
};

const parseTopCounts = (rawValue: string): readonly number[] => {
    if (rawValue === 'all') {
        return Array.from({ length: 20 }, (_, index) => index + 1);
    }
    const counts = rawValue.split(',').map((value) => value.trim());
    if (counts.length === 0 || counts.some((value) => value.length === 0)) {
        throw new Error('--top-counts must contain one or more integers.');
    }

    return counts.map((value) => {
        const topCount = Number(value);
        if (!Number.isInteger(topCount) || topCount < 1) {
            throw new Error(
                '--top-counts must contain positive integer values.',
            );
        }

        return topCount;
    });
};

const parseConfig = (rawArguments: readonly string[]): RunnerConfig => {
    const argumentsList = removePackageManagerSeparator(rawArguments);
    const checkpointDir = path.resolve(
        process.cwd(),
        argumentValue(argumentsList, '--checkpoint-dir') ??
            path.join('temp', 'test-checkpoints'),
    );
    const requestBasePath = path.resolve(
        process.cwd(),
        argumentValue(argumentsList, '--request-base') ??
            path.join(
                checkpointDir,
                'aggregate-derivation-kernel-last-evaluator-request-base.json',
            ),
    );

    const topCountsFlag = argumentValue(argumentsList, '--top-counts');
    const topCounts =
        topCountsFlag === null
            ? [positiveIntegerFlag(argumentsList, '--top-count', 1)]
            : parseTopCounts(topCountsFlag);

    return {
        checkpointDir,
        requestBasePath,
        setupSeed:
            argumentValue(argumentsList, '--setup-seed') ??
            'accepted-encrypted-aggregate-evaluator-test-seed',
        topCounts,
    };
};

const topCountLabel = (topCounts: readonly number[]): string =>
    topCounts.length === 20 &&
    topCounts.every((value, index) => value === index + 1)
        ? 'all'
        : topCounts.join('-');

const outputPathForTopCounts = (
    checkpointDir: string,
    topCounts: readonly number[],
): string =>
    path.join(
        checkpointDir,
        `encrypted-aggregate-evaluator-representative-top-counts-${topCountLabel(
            topCounts,
        )}.json`,
    );

const summaryPathForTopCounts = (
    checkpointDir: string,
    topCounts: readonly number[],
): string =>
    path.join(
        checkpointDir,
        `encrypted-aggregate-evaluator-representative-top-counts-${topCountLabel(
            topCounts,
        )}-summary.json`,
    );

export const summarizeEvaluations = (
    sweep: TopKEvaluatorEncryptedAggregateEvaluationSweep,
): readonly Record<string, unknown>[] =>
    sweep.evaluations.map((evaluation, index) => {
        const operationCounts = nestedValue(evaluation, [
            'evaluationNoiseCertificate',
            'operationCounts',
        ]);
        const encryptedSparseTarget = nestedValue(evaluation, [
            'encryptedSparseTarget',
        ]);

        return {
            appendixDPublicInputStatementJsonByteLength:
                canonicalJsonByteLength(
                    evaluation.appendixDPublicInputStatement,
                ),
            comparisonInputLevelDropCount: optionalNestedNumber(
                operationCounts,
                ['comparisonInputLevelDropCount'],
            ),
            comparisonInputPolynomialCiphertextMultiplicationEstimate:
                optionalNestedNumber(operationCounts, [
                    'comparisonInputPolynomialCiphertextMultiplicationEstimate',
                ]),
            evaluationNoiseCertHash: optionalNestedString(evaluation, [
                'evaluationNoiseCertificate',
                'evaluationNoiseCertHash',
            ]),
            fullCiphertextByteEstimate: optionalNestedNumber(evaluation, [
                'evaluationNoiseCertificate',
                'fullCiphertextByteEstimate',
            ]),
            statusLabels: evaluation.statusLabels,
            targetCiphertextHash: String(
                evaluation.topKEvaluationRecord.targetCiphertextHash,
            ),
            targetIdCiphertextByteLength: canonicalCiphertextByteLength(
                nestedValue(encryptedSparseTarget, ['targetIdCiphertext']),
            ),
            targetOrderCiphertextByteLength: canonicalCiphertextByteLength(
                nestedValue(encryptedSparseTarget, ['targetOrderCiphertext']),
            ),
            targetProposalHash: evaluation.targetProposalHash,
            topCount: sweep.topCounts[index],
            topKEvaluationRecordJsonByteLength: canonicalJsonByteLength(
                evaluation.topKEvaluationRecord,
            ),
            topKCiphertextHash: String(
                evaluation.topKEvaluationRecord.topKCiphertextHash,
            ),
        };
    });

export const summarizeSetupKeyMetrics = (
    setupPackage: BgvPassiveSetupPackage,
): Record<string, unknown> => ({
    acceptedHeSecurityStatus: optionalNestedString(setupPackage, [
        'certificates',
        'setupParameterCertificate',
        'finalSecurityStatus',
    ]),
    evaluationKeySizeProfileHash: optionalNestedString(setupPackage, [
        'certificates',
        'evaluationKeySizeProfileHash',
    ]),
    keySwitchKeyByteEstimate: optionalNestedNumber(setupPackage, [
        'certificates',
        'evaluationKeySizeCertificate',
        'keySwitchKeyByteEstimate',
    ]),
    largestExposedModulusBits: optionalNestedNumber(setupPackage, [
        'certificates',
        'setupParameterCertificate',
        'largestExposedModulusBits',
    ]),
    relinearizationKeyByteEstimate: optionalNestedNumber(setupPackage, [
        'certificates',
        'evaluationKeySizeCertificate',
        'relinearizationKeyByteEstimate',
    ]),
    rotationKeyByteEstimate: optionalNestedNumber(setupPackage, [
        'certificates',
        'evaluationKeySizeCertificate',
        'rotationKeyByteEstimate',
    ]),
    rotationKeyCount: optionalNestedNumber(setupPackage, [
        'certificates',
        'evaluationKeySizeCertificate',
        'rotationKeyCount',
    ]),
    totalEvaluationKeyByteEstimate: optionalNestedNumber(setupPackage, [
        'certificates',
        'evaluationKeySizeCertificate',
        'totalEvaluationKeyByteEstimate',
    ]),
});

export const summarizePublicArtifactMetrics = (input: {
    readonly requestBase: RepresentativeEvaluatorRequestBase;
    readonly sweep: TopKEvaluatorEncryptedAggregateEvaluationSweep;
}): Record<string, unknown> => ({
    aggregateReadyRecordJsonByteLength: canonicalJsonByteLength(
        input.requestBase.aggregateReadyRecord,
    ),
    evaluatorSweepOutputJsonByteLength: canonicalJsonByteLength(input.sweep),
    requestBaseJsonByteLength: canonicalJsonByteLength(input.requestBase),
    selectedEncryptedAggregateInputsJsonByteLength: canonicalJsonByteLength(
        input.requestBase.encryptedAggregateInputs,
    ),
    setupPackageJsonByteLength: canonicalJsonByteLength(
        input.requestBase.setupPackage,
    ),
    sharedEncryptedRankBundleJsonByteLength: canonicalJsonByteLength(
        input.sweep.sharedEncryptedRankBundle,
    ),
    sharedPackedRankCiphertextByteLength: canonicalCiphertextByteLength(
        nestedValue(input.sweep.sharedEncryptedRankBundle, [
            'packedRankCiphertext',
        ]),
    ),
});

const main = async (): Promise<void> => {
    if (process.argv.includes('--help')) {
        console.log(usageText);

        return;
    }
    const config = parseConfig(process.argv.slice(2));
    const startedAt = Date.now();
    console.log(`reading evaluator request base: ${config.requestBasePath}`);
    const requestBase = await readJsonFile<RepresentativeEvaluatorRequestBase>(
        config.requestBasePath,
    );
    if (
        requestBase.objectType !==
            'EncryptedAggregateTopKEvaluationRequestBase' ||
        requestBase.objectVersion !== 1
    ) {
        throw new Error(
            `Unsupported evaluator request base: ${config.requestBasePath}`,
        );
    }
    console.log('loading transcript-core kernel');
    const kernel = await loadTranscriptCoreKernel();
    console.log('preparing public evaluation-key material handle');
    const preparedEvaluationKeyMaterial =
        kernel.prepareBgvEvaluationKeyMaterial({
            setupPackage: requestBase.setupPackage,
            setupPrivateWitness: {
                setupSeed: config.setupSeed,
            },
        });
    const preparedEvaluationKeyMaterialHandle =
        preparedEvaluationKeyMaterial.preparedEvaluationKeyMaterialHandle;
    if (typeof preparedEvaluationKeyMaterialHandle !== 'string') {
        throw new Error('Prepared evaluation-key material handle is missing.');
    }
    console.log(
        `running encrypted aggregate evaluator sweep for topCounts=${config.topCounts.join(
            ',',
        )}`,
    );
    const sweep = kernel.runEncryptedAggregateTopKEvaluationSweep({
        aggregateReadyRecord: requestBase.aggregateReadyRecord,
        canonicalBallotSetHash: requestBase.canonicalBallotSetHash,
        encryptedAggregateInputs: requestBase.encryptedAggregateInputs,
        evaluatorSignature: requestBase.evaluatorSignature,
        preTargetBoardHead: requestBase.preTargetBoardHead,
        preparedEvaluationKeyMaterialHandle,
        scoreDomainMax: requestBase.scoreDomainMax,
        setupPackage: requestBase.setupPackage,
        topCounts: config.topCounts,
    });
    const outputPath = outputPathForTopCounts(
        config.checkpointDir,
        config.topCounts,
    );
    await writeJsonFileAtomic(outputPath, sweep);
    const summary = {
        aggregateReadyRecordHash: requiredNestedString(
            requestBase.aggregateReadyRecord,
            ['aggregateReadyRecordHash'],
        ),
        durationMilliseconds: Date.now() - startedAt,
        evaluations: summarizeEvaluations(sweep),
        evidenceScope: {
            executionEnvironment: 'node-wasm-transcript-core-kernel',
            topCountCoverage: topCountLabel(sweep.topCounts),
            memoryPeakStatus: 'not-measured-by-this-runner',
            bridgeMatrixStatus: 'not-run-by-this-runner',
            browserParityStatus: 'not-run-by-this-runner',
        },
        inputBindingStatus: sweep.inputBindingStatus,
        objectType: 'EncryptedAggregateEvaluatorRepresentativeRunSummary',
        objectVersion: 1,
        outputPath,
        preparedEvaluationKeyMaterialHandle,
        publicArtifactMetrics: summarizePublicArtifactMetrics({
            requestBase,
            sweep,
        }),
        requestBasePath: config.requestBasePath,
        setupKeyMetrics: summarizeSetupKeyMetrics(requestBase.setupPackage),
        statusLabels: sweep.statusLabels,
        topCounts: sweep.topCounts,
    };
    const summaryPath = summaryPathForTopCounts(
        config.checkpointDir,
        config.topCounts,
    );
    await writeJsonFileAtomic(summaryPath, summary);
    console.log(
        `encrypted aggregate evaluator representative summary: ${canonicalJson(
            summary,
        )}`,
    );
    console.log(`summary written: ${summaryPath}`);
};

if (isDirectlyInvokedModule(import.meta.url)) {
    main().catch((error: unknown) => {
        console.error(error);
        process.exitCode = 1;
    });
}
