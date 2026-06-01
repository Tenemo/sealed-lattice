import path from 'node:path';

import {
    readJsonFile,
    writeJsonFileAtomic,
} from './aggregate-derivation-kernel/checkpoints.js';

import { canonicalJson } from '#packages/crypto/src/index';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import type {
    BgvPassiveSetupPackage,
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
    readonly topCount: number;
};

const usageText = `Usage:
  pnpm run test:encrypted-aggregate-evaluator:representative
  pnpm run test:encrypted-aggregate-evaluator:representative -- --top-count 1

Flags:
  --checkpoint-dir <path> (default: temp/test-checkpoints)
  --request-base <path> (default: aggregate-derivation-kernel-last-evaluator-request-base.json under checkpoint dir)
  --setup-seed <seed> (default: accepted-encrypted-aggregate-evaluator-test-seed)
  --top-count <count> (default: 1)

This runner consumes the fast aggregate-derivation request-base artifact,
prepares in-process public evaluation-key material from the setup private
witness without serializing key-switch coefficients as JSON, runs one
representative encrypted aggregate evaluator slice, and writes the public result
under the checkpoint directory. It does not run the bridge matrix or an
all-top-count evaluator sweep.
`;

const removePackageManagerSeparator = (
    argumentsList: readonly string[],
): readonly string[] => argumentsList.filter((argument) => argument !== '--');

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

    return {
        checkpointDir,
        requestBasePath,
        setupSeed:
            argumentValue(argumentsList, '--setup-seed') ??
            'accepted-encrypted-aggregate-evaluator-test-seed',
        topCount: positiveIntegerFlag(argumentsList, '--top-count', 1),
    };
};

const outputPathForTopCount = (
    checkpointDir: string,
    topCount: number,
): string =>
    path.join(
        checkpointDir,
        `encrypted-aggregate-evaluator-representative-top-count-${topCount}.json`,
    );

const summaryPathForTopCount = (
    checkpointDir: string,
    topCount: number,
): string =>
    path.join(
        checkpointDir,
        `encrypted-aggregate-evaluator-representative-top-count-${topCount}-summary.json`,
    );

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
        `running encrypted aggregate evaluator for topCount=${config.topCount}`,
    );
    const evaluation = kernel.runEncryptedAggregateTopKEvaluation({
        aggregateReadyRecord: requestBase.aggregateReadyRecord,
        canonicalBallotSetHash: requestBase.canonicalBallotSetHash,
        encryptedAggregateInputs: requestBase.encryptedAggregateInputs,
        evaluatorSignature: requestBase.evaluatorSignature,
        preTargetBoardHead: requestBase.preTargetBoardHead,
        preparedEvaluationKeyMaterialHandle,
        scoreDomainMax: requestBase.scoreDomainMax,
        setupPackage: requestBase.setupPackage,
        topCount: config.topCount,
    });
    const outputPath = outputPathForTopCount(
        config.checkpointDir,
        config.topCount,
    );
    await writeJsonFileAtomic(outputPath, evaluation);
    const summary = {
        aggregateReadyRecordHash: String(
            evaluation.topKEvaluationRecord.aggregateReadyRecordHash,
        ),
        durationMilliseconds: Date.now() - startedAt,
        inputBindingStatus: evaluation.inputBindingStatus,
        objectType: 'EncryptedAggregateEvaluatorRepresentativeRunSummary',
        objectVersion: 1,
        outputPath,
        preparedEvaluationKeyMaterialHandle,
        requestBasePath: config.requestBasePath,
        statusLabels: evaluation.statusLabels,
        targetCiphertextHash: String(
            evaluation.topKEvaluationRecord.targetCiphertextHash,
        ),
        targetProposalHash: evaluation.targetProposalHash,
        topCount: config.topCount,
        topKCiphertextHash: String(
            evaluation.topKEvaluationRecord.topKCiphertextHash,
        ),
    };
    const summaryPath = summaryPathForTopCount(
        config.checkpointDir,
        config.topCount,
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
