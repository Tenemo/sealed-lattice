import { createHash, randomUUID } from 'node:crypto';
import { mkdir, open, readFile } from 'node:fs/promises';
import path from 'node:path';

import { normalizeTranscriptCoreKernelBytesForHash } from '../../packages/wasm/src/transcript-core-bridge.js';
import {
    parseProofStorageWidthBrowserMeasurement,
    parseProofStorageWidthBrowserNativeBinding,
    proofStorageWidthBrowserEvidenceProfile,
    requireProofStorageWidthBrowserNativeMatch,
    type ProofStorageWidthBrowserMeasurement,
    type ProofStorageWidthBrowserNativeBinding,
} from '../../tests/support/proof-storage-width-browser-evidence.js';

import {
    proofStorageWidthBrowserEvidenceProjectName,
    proofStorageWidthBrowserEvidenceTestGlobs,
} from './browser-test-project-selection.js';
import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import {
    extractProofStorageWidthOperationMemory,
    type ValidatedProofStorageWidthResult,
    type ValidatedProofStorageWidthStaticPreflightPoint,
} from './proof-storage-width-evidence.js';
import {
    appendProofStorageWidthOfficialReservationOutcome,
    buildProofStorageWidthBrowserReservationIdentity,
    createProofStorageWidthBrowserSampleReservation,
    defaultProofStorageWidthOfficialReservationRootPath,
} from './proof-storage-width-official-reservation.js';
import {
    createPackageManagerCommand,
    runCommandAndCaptureOutput,
    type CapturedCommandResult,
    type CommandInvocation,
} from './run-command.js';
import { validateProofStorageWidthEvidenceArtifacts } from './run-proof-storage-width-evidence.js';

const laneLabel = 'Proof-storage width release WebAssembly evidence';
const scriptName = 'test:browser:proof-storage-width-evidence';
const browserOfficialSampleOwner = scriptName;
const testProjectLabel = 'proof-storage-width-browser-evidence';
const testProjectName = proofStorageWidthBrowserEvidenceProjectName;
const browserTestFile = proofStorageWidthBrowserEvidenceTestGlobs[0];
const browserEvidenceCargoFeature = 'proof-storage-width-browser-evidence';
const wasmEvidenceFeatureEnvironmentVariable =
    'SEALED_LATTICE_WASM_CARGO_FEATURES';
const expectedWasmHashEnvironmentVariable =
    'VITE_SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_EXPECTED_WASM_SHA256_HEX';
const nativeBindingEnvironmentVariable =
    'VITE_SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_NATIVE_BINDING';
const databaseNameEnvironmentVariable =
    'VITE_SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_DATABASE_NAME';
const resourceSampleIntervalMilliseconds = 100;
const maximumOperationWindowGapMilliseconds = 500;
const plausibleBrowserProjectionNanoseconds = 120n * 60n * 1_000_000_000n;
const setupContributionPlanningTargetNanoseconds = 20n * 60n * 1_000_000_000n;
const terabyteScaleByteLength = 1_099_511_627_776n;
const billionTransactions = 1_000_000_000n;
const exactCommitHashPattern = /^[0-9a-f]{40}$/u;
const exactSha256HexPattern = /^[0-9a-f]{64}$/u;
const processedWasmKernelPath = path.resolve(
    'packages',
    'wasm',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const publicSdkWasmKernelPath = path.resolve(
    'packages',
    'sdk',
    'dist',
    'sealed-lattice-kernel.wasm',
);

export const proofStorageWidthBrowserEvidenceVitestArguments = Object.freeze([
    'exec',
    'vitest',
    '--project',
    testProjectName,
    '--run',
    browserTestFile,
    '--retry=0',
] as const);

type JsonObject = Readonly<Record<string, unknown>>;

type RepositoryState = Readonly<{
    commitHash: string;
    treeDirty: boolean;
}>;

type RepositoryCheckpoint = 'after' | 'before' | 'closure-after' | 'initial';

type CommandExecutor = (
    invocation: CommandInvocation,
    runLog: ActiveLocalRunLog,
) => Promise<CapturedCommandResult>;

type ProcessedWasmBinding = Readonly<{
    byteLength: bigint;
    normalizedSha256Hex: string;
    rawSha256Hex: string;
}>;

type NativeWidthEvidenceLoader = (
    evidencePath: string,
    options?: Readonly<{ officialReservationRootPath?: string }>,
) => Promise<NativeWidthEvidence>;

export type NativeWidthEvidence = Readonly<{
    evidencePath: string;
    evidenceSha256Hex: string;
    fullWidthResult: ValidatedProofStorageWidthResult;
    fullWidthStaticPoint: ValidatedProofStorageWidthStaticPreflightPoint;
    nativeBinding: ProofStorageWidthBrowserNativeBinding;
    nativeBindingRecord: JsonObject;
    officialSampleReservationIdentitySha256Hex: string;
    repositoryCommitHash: string;
    representativeResult: ValidatedProofStorageWidthResult;
    representativeStaticPoint: ValidatedProofStorageWidthStaticPreflightPoint;
}>;

export type ProofStorageWidthBrowserProjection = Readonly<{
    arithmeticNanoseconds: bigint;
    coordinatorNanoseconds: bigint;
    externalStorageWaitNanoseconds: bigint;
    operationNanoseconds: bigint;
    planningTargetNanoseconds: bigint;
    planningTargetRatio: Readonly<{
        denominator: bigint;
        numerator: bigint;
    }>;
    projectedCopiedBufferPeakByteLength: bigint;
    projectedWasmLinearMemoryPeakByteLength: bigint;
    representativeCopiedBufferPeakByteLength: bigint;
    representativeWasmLinearMemoryEndByteLength: bigint;
    representativeWasmLinearMemoryPeakByteLength: bigint;
    representativeWasmLinearMemoryStartByteLength: bigint;
    staticWasmMemoryCeilingGrowth: Readonly<{
        deltaByteLength: bigint;
        fullWidthByteLength: bigint;
        representativeByteLength: bigint;
    }>;
    workerYieldNanoseconds: bigint;
}>;

export type ProofStorageWidthBrowserProjectionPoint = Pick<
    ValidatedProofStorageWidthResult,
    | 'elapsedNanoseconds'
    | 'externalCommittedTransactionCount'
    | 'externalIoByteLength'
    | 'ldeTransformCount'
    | 'publicBaseLeafColumnCount'
>;

export type ProofStorageWidthBrowserStaticProjectionPoint = Pick<
    ValidatedProofStorageWidthStaticPreflightPoint,
    'publicBaseLeafColumnCount' | 'wasmMemoryByteLengthCeiling'
>;

export type ProofStorageWidthBrowserEvidenceDependencies = Readonly<{
    deriveProcessedWasmBinding?: () => Promise<ProcessedWasmBinding>;
    executeCommand?: CommandExecutor;
    loadNativeWidthEvidence?: NativeWidthEvidenceLoader;
    officialReservationRootPath?: string;
    processMemoryGuard?: ProcessMemoryGuard;
    processedWasmKernelPath?: string;
    publicSdkWasmKernelPath?: string;
    readRepositoryState?: (
        checkpoint: RepositoryCheckpoint,
        runLog: ActiveLocalRunLog,
    ) => Promise<RepositoryState>;
}>;

const requireJsonObject = (value: unknown, fieldName: string): JsonObject => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${fieldName} must be a JSON object.`);
    }
    return value as JsonObject;
};

const parseJson = (serialized: string, fieldName: string): unknown => {
    try {
        return JSON.parse(serialized) as unknown;
    } catch (error) {
        throw Object.assign(new Error(`${fieldName} is not valid JSON.`), {
            cause: error,
        });
    }
};

const requireString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string') {
        throw new Error(`${fieldName} must be a string.`);
    }
    return value;
};

const requireSha256Hex = (value: unknown, fieldName: string): string => {
    const digest = requireString(value, fieldName);
    if (!exactSha256HexPattern.test(digest)) {
        throw new Error(`${fieldName} must be a lowercase SHA-256 digest.`);
    }
    return digest;
};

const normalizeJsonValue = (value: unknown): unknown => {
    if (typeof value === 'bigint') {
        return value.toString();
    }
    if (Array.isArray(value)) {
        return value.map(normalizeJsonValue);
    }
    if (typeof value === 'object' && value !== null) {
        return Object.fromEntries(
            Object.entries(value)
                .sort(([leftFieldName], [rightFieldName]) =>
                    leftFieldName.localeCompare(rightFieldName),
                )
                .map(([fieldName, nestedValue]) => [
                    fieldName,
                    normalizeJsonValue(nestedValue),
                ]),
        );
    }
    return value;
};

const normalizedJsonEquals = (left: unknown, right: unknown): boolean =>
    JSON.stringify(normalizeJsonValue(left)) ===
    JSON.stringify(normalizeJsonValue(right));

const sha256Hex = (value: string | Uint8Array): string =>
    createHash('sha256').update(value).digest('hex');

const canonicalRelativePath = (rootPath: string, filePath: string): string =>
    path.relative(rootPath, filePath).split(path.sep).join('/');

const requireExactRelativeArtifactPath = (input: {
    readonly actual: unknown;
    readonly expected: string;
    readonly fieldName: string;
    readonly rootPath: string;
}): string => {
    const actual = requireString(input.actual, input.fieldName);
    if (actual !== input.expected || path.isAbsolute(actual)) {
        throw new Error(
            `${input.fieldName} must be the exact artifact path ${input.expected}.`,
        );
    }
    const resolvedPath = path.resolve(input.rootPath, actual);
    const relativePath = path.relative(input.rootPath, resolvedPath);
    if (
        relativePath.startsWith(`..${path.sep}`) ||
        relativePath === '..' ||
        path.isAbsolute(relativePath)
    ) {
        throw new Error(`${input.fieldName} escapes its artifact root.`);
    }
    return resolvedPath;
};

const requireArtifactDigest = (input: {
    readonly expectedSha256Hex: unknown;
    readonly fieldName: string;
    readonly value: string | Uint8Array;
}): string => {
    const expectedSha256Hex = requireSha256Hex(
        input.expectedSha256Hex,
        `${input.fieldName} digest`,
    );
    if (sha256Hex(input.value) !== expectedSha256Hex) {
        throw new Error(`${input.fieldName} does not match its bound digest.`);
    }
    return expectedSha256Hex;
};

export const loadNativeWidthEvidence = async (
    evidencePath: string,
    options: Readonly<{ officialReservationRootPath?: string }> = {},
): Promise<NativeWidthEvidence> => {
    const serializedEvidenceBeforeValidation = await readFile(evidencePath);
    const evidence = await validateProofStorageWidthEvidenceArtifacts(
        evidencePath,
        options,
    );
    const serializedEvidenceAfterValidation = await readFile(evidencePath);
    if (
        !serializedEvidenceBeforeValidation.equals(
            serializedEvidenceAfterValidation,
        )
    ) {
        throw new Error(
            'The native width evidence changed while its artifacts were being validated.',
        );
    }
    const representativeStaticPoint = evidence.staticPreflight.points.find(
        (point) =>
            point.publicBaseLeafColumnCount ===
            proofStorageWidthBrowserEvidenceProfile.representativeWidth,
    );
    const fullWidthStaticPoint = evidence.staticPreflight.points.find(
        (point) => point.publicBaseLeafColumnCount === 3_451,
    );
    if (
        representativeStaticPoint === undefined ||
        fullWidthStaticPoint === undefined
    ) {
        throw new Error(
            'Validated native width evidence omitted a required static projection point.',
        );
    }
    return Object.freeze({
        evidencePath: path.resolve(evidencePath),
        evidenceSha256Hex: createHash('sha256')
            .update(serializedEvidenceAfterValidation)
            .digest('hex'),
        fullWidthResult: evidence.fullWidthPoint.result,
        fullWidthStaticPoint,
        nativeBinding: parseProofStorageWidthBrowserNativeBinding(
            evidence.representativePoint.resultRecord,
        ),
        nativeBindingRecord: evidence.representativePoint.resultRecord,
        officialSampleReservationIdentitySha256Hex:
            evidence.officialSampleReservationIdentitySha256Hex,
        repositoryCommitHash: evidence.repositoryCommitHash,
        representativeResult: evidence.representativePoint.result,
        representativeStaticPoint,
    });
};

const scaledCeiling = (
    value: bigint,
    numerator: bigint,
    denominator: bigint,
    fieldName: string,
): bigint => {
    if (denominator === 0n) {
        throw new Error(`${fieldName} has a zero scaling denominator.`);
    }
    return (value * numerator + denominator - 1n) / denominator;
};

const maximumBigInt = (values: readonly bigint[]): bigint => {
    const first = values[0];
    if (first === undefined) {
        throw new Error('Cannot derive a maximum from an empty collection.');
    }
    return values
        .slice(1)
        .reduce((maximum, value) => (value > maximum ? value : maximum), first);
};

const maximumUnsigned64 = (1n << 64n) - 1n;

const checkedNonnegativeDifference = (input: {
    readonly fieldName: string;
    readonly minuend: bigint;
    readonly subtrahend: bigint;
}): bigint => {
    if (input.minuend < 0n || input.subtrahend < 0n) {
        throw new Error(`${input.fieldName} requires nonnegative operands.`);
    }
    if (input.minuend < input.subtrahend) {
        throw new Error(`${input.fieldName} would be negative.`);
    }
    return input.minuend - input.subtrahend;
};

const checkedNonnegativeUnsigned64Sum = (input: {
    readonly fieldName: string;
    readonly left: bigint;
    readonly right: bigint;
}): bigint => {
    if (input.left < 0n || input.right < 0n) {
        throw new Error(`${input.fieldName} requires nonnegative operands.`);
    }
    const sum = input.left + input.right;
    if (sum > maximumUnsigned64) {
        throw new Error(`${input.fieldName} exceeds u64.`);
    }
    return sum;
};

export const deriveProofStorageWidthBrowserProjection = (input: {
    readonly fullWidthResult: ProofStorageWidthBrowserProjectionPoint;
    readonly fullWidthStaticPoint: ProofStorageWidthBrowserStaticProjectionPoint;
    readonly measurement: ProofStorageWidthBrowserMeasurement;
    readonly representativeResult: ProofStorageWidthBrowserProjectionPoint;
    readonly representativeStaticPoint: ProofStorageWidthBrowserStaticProjectionPoint;
}): ProofStorageWidthBrowserProjection => {
    if (
        input.representativeResult.publicBaseLeafColumnCount !==
            proofStorageWidthBrowserEvidenceProfile.representativeWidth ||
        input.fullWidthResult.publicBaseLeafColumnCount !== 3_451 ||
        input.representativeStaticPoint.publicBaseLeafColumnCount !==
            proofStorageWidthBrowserEvidenceProfile.representativeWidth ||
        input.fullWidthStaticPoint.publicBaseLeafColumnCount !== 3_451
    ) {
        throw new Error(
            'The browser projection requires the fixed width-512 and width-3451 points.',
        );
    }
    const staticWasmMemoryCeilingDeltaByteLength = checkedNonnegativeDifference(
        {
            fieldName: 'Static WebAssembly memory ceiling growth',
            minuend: input.fullWidthStaticPoint.wasmMemoryByteLengthCeiling,
            subtrahend:
                input.representativeStaticPoint.wasmMemoryByteLengthCeiling,
        },
    );
    const staticWasmMemoryCeilingGrowth = Object.freeze({
        deltaByteLength: staticWasmMemoryCeilingDeltaByteLength,
        fullWidthByteLength:
            input.fullWidthStaticPoint.wasmMemoryByteLengthCeiling,
        representativeByteLength:
            input.representativeStaticPoint.wasmMemoryByteLengthCeiling,
    });
    const representativeExternalIo =
        input.representativeResult.externalIoByteLength;
    const fullExternalIo = input.fullWidthResult.externalIoByteLength;
    const arithmeticNanoseconds = scaledCeiling(
        input.measurement.arithmeticNanoseconds,
        input.fullWidthResult.elapsedNanoseconds,
        input.representativeResult.elapsedNanoseconds,
        'arithmetic projection',
    );
    const storageScaleNumerators = [
        scaledCeiling(
            fullExternalIo,
            1_000_000_000n,
            representativeExternalIo,
            'external-I/O projection ratio',
        ),
        scaledCeiling(
            input.fullWidthResult.externalCommittedTransactionCount,
            1_000_000_000n,
            input.representativeResult.externalCommittedTransactionCount,
            'transaction projection ratio',
        ),
    ];
    const storageScaleNumerator = maximumBigInt(storageScaleNumerators);
    const externalStorageWaitNanoseconds = scaledCeiling(
        input.measurement.externalStorageWaitNanoseconds,
        storageScaleNumerator,
        1_000_000_000n,
        'external-storage wait projection',
    );
    const yieldScaleNumerator = maximumBigInt([
        storageScaleNumerator,
        scaledCeiling(
            input.fullWidthResult.ldeTransformCount,
            1_000_000_000n,
            input.representativeResult.ldeTransformCount,
            'worker-yield transform ratio',
        ),
    ]);
    const workerYieldNanoseconds = scaledCeiling(
        input.measurement.workerYieldNanoseconds,
        yieldScaleNumerator,
        1_000_000_000n,
        'worker-yield projection',
    );
    const coordinatorNanoseconds = scaledCeiling(
        input.measurement.coordinatorNanoseconds,
        maximumBigInt([
            yieldScaleNumerator,
            scaledCeiling(
                BigInt(input.fullWidthResult.publicBaseLeafColumnCount),
                1_000_000_000n,
                BigInt(input.representativeResult.publicBaseLeafColumnCount),
                'coordinator width ratio',
            ),
        ]),
        1_000_000_000n,
        'coordinator projection',
    );
    const operationNanoseconds =
        arithmeticNanoseconds +
        externalStorageWaitNanoseconds +
        workerYieldNanoseconds +
        coordinatorNanoseconds;
    return Object.freeze({
        arithmeticNanoseconds,
        coordinatorNanoseconds,
        externalStorageWaitNanoseconds,
        operationNanoseconds,
        planningTargetNanoseconds: setupContributionPlanningTargetNanoseconds,
        planningTargetRatio: Object.freeze({
            denominator: setupContributionPlanningTargetNanoseconds,
            numerator: operationNanoseconds,
        }),
        projectedCopiedBufferPeakByteLength:
            input.measurement.copiedBufferPeakByteLength,
        projectedWasmLinearMemoryPeakByteLength:
            checkedNonnegativeUnsigned64Sum({
                fieldName:
                    'Projected full-width WebAssembly linear-memory peak',
                left: input.measurement.wasmLinearMemoryPeakByteLength,
                right: staticWasmMemoryCeilingDeltaByteLength,
            }),
        representativeCopiedBufferPeakByteLength:
            input.measurement.copiedBufferPeakByteLength,
        representativeWasmLinearMemoryEndByteLength:
            input.measurement.wasmLinearMemoryEndByteLength,
        representativeWasmLinearMemoryPeakByteLength:
            input.measurement.wasmLinearMemoryPeakByteLength,
        representativeWasmLinearMemoryStartByteLength:
            input.measurement.wasmLinearMemoryStartByteLength,
        staticWasmMemoryCeilingGrowth,
        workerYieldNanoseconds,
    });
};

export const requireProofStorageWidthBrowserProjectionEligibility = (input: {
    readonly fullWidthResult: ProofStorageWidthBrowserProjectionPoint;
    readonly projection: ProofStorageWidthBrowserProjection;
}): void => {
    if (
        input.projection.projectedCopiedBufferPeakByteLength >
        proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength
    ) {
        throw new Error(
            'The full-width browser projection exceeds the copied-buffer cap.',
        );
    }
    if (
        input.projection.projectedWasmLinearMemoryPeakByteLength >
        proofStorageWidthBrowserEvidenceProfile.maximumWasmLinearMemoryByteLength
    ) {
        throw new Error(
            'The full-width browser projection exceeds the WebAssembly linear-memory cap.',
        );
    }
    if (input.fullWidthResult.externalIoByteLength >= terabyteScaleByteLength) {
        throw new Error(
            'The full-width browser projection requires terabyte-scale external I/O.',
        );
    }
    if (
        input.fullWidthResult.externalCommittedTransactionCount >=
        billionTransactions
    ) {
        throw new Error(
            'The full-width browser projection requires at least one billion transactions.',
        );
    }
    if (
        input.projection.operationNanoseconds >
        plausibleBrowserProjectionNanoseconds
    ) {
        throw new Error(
            'The full-width release-browser projection exceeds 120 minutes.',
        );
    }
};

const executeRequiredCommand = async (input: {
    readonly command: CommandInvocation;
    readonly executeCommand: CommandExecutor;
    readonly runLog: ActiveLocalRunLog;
}): Promise<CapturedCommandResult> => {
    const result = await input.executeCommand(input.command, input.runLog);
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw new Error(
            `${input.command.description} failed with exit code ${String(result.exitCode)}${
                result.terminationSignal === null
                    ? ''
                    : ` and signal ${result.terminationSignal}`
            }. The browser evidence run is not retried.`,
        );
    }
    return result;
};

const defaultCommandExecutor: CommandExecutor = (invocation, runLog) =>
    runCommandAndCaptureOutput(invocation, {
        echoOutput: true,
        runLog,
    });

const readRepositoryStateWithCommands = async (input: {
    readonly checkpoint: RepositoryCheckpoint;
    readonly executeCommand: CommandExecutor;
    readonly runLog: ActiveLocalRunLog;
}): Promise<RepositoryState> => {
    const commitResult = await executeRequiredCommand({
        command: {
            args: ['rev-parse', '--verify', 'HEAD^{commit}'],
            command: 'git',
            description: `read the ${input.checkpoint} browser width-evidence commit`,
            logFileSlug: `git-browser-width-${input.checkpoint}-commit`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    const commitHash = commitResult.stdout.trim();
    if (!exactCommitHashPattern.test(commitHash)) {
        throw new Error(
            `The ${input.checkpoint} browser width-evidence commit is malformed.`,
        );
    }
    const statusResult = await executeRequiredCommand({
        command: {
            args: [
                'status',
                '--porcelain=v1',
                '--untracked-files=all',
                '--ignore-submodules=none',
            ],
            command: 'git',
            description: `read the ${input.checkpoint} browser width-evidence status`,
            logFileSlug: `git-browser-width-${input.checkpoint}-status`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    return Object.freeze({
        commitHash,
        treeDirty: statusResult.stdout.length !== 0,
    });
};

const requireCleanPinnedRepository = (
    actual: RepositoryState,
    expectedCommitHash: string,
    checkpoint: string,
): void => {
    if (actual.treeDirty || actual.commitHash !== expectedCommitHash) {
        throw new Error(
            `The browser width-evidence ${checkpoint} checkpoint is not the exact clean native-evidence commit.`,
        );
    }
};

const deriveProcessedWasmBinding = async (input: {
    readonly processedWasmKernelPath: string;
    readonly publicSdkWasmKernelPath: string;
}): Promise<ProcessedWasmBinding> => {
    const [producerBytes, publicSdkBytes] = await Promise.all([
        readFile(input.processedWasmKernelPath),
        readFile(input.publicSdkWasmKernelPath),
    ]);
    if (!producerBytes.equals(publicSdkBytes)) {
        throw new Error(
            'The public SDK WebAssembly bytes differ from the processed producer artifact.',
        );
    }
    const byteLength = BigInt(producerBytes.byteLength);
    if (
        byteLength >
        proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength
    ) {
        throw new Error(
            'The processed release WebAssembly module exceeds the absolute copied-buffer bound.',
        );
    }
    return Object.freeze({
        byteLength,
        normalizedSha256Hex: createHash('sha256')
            .update(normalizeTranscriptCoreKernelBytesForHash(producerBytes))
            .digest('hex'),
        rawSha256Hex: createHash('sha256').update(producerBytes).digest('hex'),
    });
};

export const parseProofStorageWidthBrowserMeasurementEvents = (input: {
    readonly expectedWasmSha256Hex: string;
    readonly serializedEvents: string;
}): ProofStorageWidthBrowserMeasurement => {
    const records = input.serializedEvents
        .split(/\r?\n/u)
        .filter((line) => line.length !== 0)
        .map((line, lineIndex) =>
            requireJsonObject(
                parseJson(
                    line,
                    `Browser test event line ${String(lineIndex + 1)}`,
                ),
                `Browser test event line ${String(lineIndex + 1)}`,
            ),
        );
    if (
        records.length !== 1 ||
        records[0]?.event !== 'proof-storage-width-browser-evidence'
    ) {
        throw new Error(
            'The browser width-evidence JSONL must contain exactly one measurement record and no unrelated records.',
        );
    }
    const event = records[0];
    if (event?.browser !== true) {
        throw new Error(
            'The proof-storage width measurement was not emitted by a browser.',
        );
    }
    const measurement = parseProofStorageWidthBrowserMeasurement(event);
    if (measurement.wasmSha256Hex !== input.expectedWasmSha256Hex) {
        throw new Error(
            'The browser width-evidence measurement used the wrong release WebAssembly module.',
        );
    }
    return measurement;
};

const requireArtifactAbsent = async (
    filePath: string,
    fieldName: string,
): Promise<void> => {
    try {
        await readFile(filePath);
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'ENOENT'
        ) {
            return;
        }
        throw error;
    }
    throw new Error(`${fieldName} already exists before the one-shot sample.`);
};

const errorName = (error: unknown): string =>
    error instanceof Error ? error.name : 'NonErrorFailure';

const combineAttemptAndRepositoryFailure = (input: {
    readonly attemptError: unknown;
    readonly repositoryError: unknown;
}): Error =>
    Object.assign(
        new Error(
            'The browser width-evidence repository changed or could not be checked after the attempted one-shot sample.',
        ),
        {
            attemptCause: input.attemptError,
            cause: input.repositoryError,
        },
    );

const validateBrowserOfficialReservationArtifact = (input: {
    readonly identitySha256Hex: string;
    readonly nativeAggregateSha256Hex: string;
    readonly officialOwner: string;
    readonly rawWasmSha256Hex: string;
    readonly serialized: string;
    readonly sourceCommitHash: string;
}): void => {
    const records = input.serialized
        .split(/\r?\n/u)
        .filter((line) => line.length !== 0)
        .map((line, lineIndex) =>
            requireJsonObject(
                parseJson(
                    line,
                    `Browser reservation line ${String(lineIndex + 1)}`,
                ),
                `Browser reservation line ${String(lineIndex + 1)}`,
            ),
        );
    if (records.length !== 2) {
        throw new Error(
            'The browser official reservation must contain exactly one start and one outcome record.',
        );
    }
    const start = records[0];
    const outcome = records[1];
    const startTimestamp = start?.recordedAtUnixMilliseconds;
    const outcomeTimestamp = outcome?.recordedAtUnixMilliseconds;
    if (
        start?.eventType !== 'official-browser-width-sample-started' ||
        start.identitySha256Hex !== input.identitySha256Hex ||
        start.nativeAggregateSha256Hex !== input.nativeAggregateSha256Hex ||
        start.officialOwner !== input.officialOwner ||
        start.rawWasmSha256Hex !== input.rawWasmSha256Hex ||
        start.sourceCommitHash !== input.sourceCommitHash ||
        typeof startTimestamp !== 'number' ||
        !Number.isSafeInteger(startTimestamp) ||
        startTimestamp < 0 ||
        start.width !==
            proofStorageWidthBrowserEvidenceProfile.representativeWidth
    ) {
        throw new Error(
            'The browser official reservation start record changed its canonical binding.',
        );
    }
    if (
        outcome?.eventType !== 'official-sample-outcome' ||
        outcome.outcome !== 'validated' ||
        typeof outcomeTimestamp !== 'number' ||
        !Number.isSafeInteger(outcomeTimestamp) ||
        outcomeTimestamp < startTimestamp
    ) {
        throw new Error(
            'The browser official reservation lacks one validated terminal outcome.',
        );
    }
};

const requireGuardMemoryLimitBinding = (input: {
    readonly expectedMemoryLimitBytes: number;
    readonly serializedGuard: string;
}): void => {
    if (
        !Number.isSafeInteger(input.expectedMemoryLimitBytes) ||
        input.expectedMemoryLimitBytes <= 0
    ) {
        throw new Error(
            'The browser process-memory limit must be a positive safe integer.',
        );
    }
    const firstLine = input.serializedGuard
        .split(/\r?\n/u)
        .find((line) => line.length !== 0);
    if (firstLine === undefined) {
        throw new Error('The browser process-memory guard artifact is empty.');
    }
    const guardStarted = requireJsonObject(
        parseJson(firstLine, 'Browser process-memory guard start record'),
        'Browser process-memory guard start record',
    );
    if (
        guardStarted.eventType !== 'guard-started' ||
        guardStarted.memoryLimitBytes !== input.expectedMemoryLimitBytes
    ) {
        throw new Error(
            'The browser process-memory guard does not bind the exact enforced memory limit.',
        );
    }
};

const writeJsonExclusively = async (
    filePath: string,
    value: unknown,
): Promise<void> => {
    await mkdir(path.dirname(filePath), { recursive: true });
    const file = await open(filePath, 'wx');
    try {
        await file.writeFile(
            `${JSON.stringify(normalizeJsonValue(value), null, 2)}\n`,
            'utf8',
        );
        await file.sync();
    } finally {
        await file.close();
    }
};

const requirePinnedRepositoryRecord = (input: {
    readonly expectedCommitHash: string;
    readonly fieldName: string;
    readonly value: unknown;
}): void => {
    const record = requireJsonObject(input.value, input.fieldName);
    if (
        record.commitHash !== input.expectedCommitHash ||
        record.treeDirty !== false
    ) {
        throw new Error(
            `${input.fieldName} must bind the exact clean evidence commit.`,
        );
    }
};

export const validateProofStorageWidthBrowserEvidenceArtifacts = async (
    attachmentPath: string,
    options: Readonly<{
        loadNativeWidthEvidence?: NativeWidthEvidenceLoader;
        officialReservationRootPath?: string;
        processedWasmKernelPath?: string;
        publicSdkWasmKernelPath?: string;
    }> = {},
): Promise<void> => {
    if (!path.isAbsolute(attachmentPath)) {
        throw new Error(
            'The proof-storage width browser evidence path must be absolute.',
        );
    }
    const resolvedAttachmentPath = path.resolve(attachmentPath);
    const runDirectoryPath = path.resolve(
        path.dirname(resolvedAttachmentPath),
        '..',
    );
    const expectedAttachmentPath = path.resolve(
        runDirectoryPath,
        'attachments',
        'proof-storage-width-browser-evidence.json',
    );
    if (resolvedAttachmentPath !== expectedAttachmentPath) {
        throw new Error(
            'The browser evidence file is outside its exact run attachment location.',
        );
    }
    const configuredReservationRootPath =
        options.officialReservationRootPath ??
        defaultProofStorageWidthOfficialReservationRootPath;
    if (!path.isAbsolute(configuredReservationRootPath)) {
        throw new Error(
            'The official browser reservation root path must be absolute.',
        );
    }
    const reservationRootPath = path.resolve(configuredReservationRootPath);
    const reservationRelativeToRun = path.relative(
        runDirectoryPath,
        reservationRootPath,
    );
    if (
        reservationRelativeToRun.length === 0 ||
        (!reservationRelativeToRun.startsWith(`..${path.sep}`) &&
            reservationRelativeToRun !== '..' &&
            !path.isAbsolute(reservationRelativeToRun))
    ) {
        throw new Error(
            'The official browser reservation root must stay outside the run directory.',
        );
    }
    const evidence = requireJsonObject(
        parseJson(
            await readFile(resolvedAttachmentPath, 'utf8'),
            'Proof-storage width browser evidence',
        ),
        'Proof-storage width browser evidence',
    );
    if (evidence.formatVersion !== 3) {
        throw new Error(
            'Proof-storage width browser evidence must use integrity format version three.',
        );
    }
    const repository = requireJsonObject(evidence.repository, 'repository');
    const initialRepository = requireJsonObject(
        repository.initial,
        'repository.initial',
    );
    const repositoryCommitHash = requireString(
        initialRepository.commitHash,
        'repository.initial.commitHash',
    );
    if (!exactCommitHashPattern.test(repositoryCommitHash)) {
        throw new Error(
            'repository.initial.commitHash must be an exact lowercase commit hash.',
        );
    }
    for (const checkpoint of ['initial', 'before', 'after'] as const) {
        requirePinnedRepositoryRecord({
            expectedCommitHash: repositoryCommitHash,
            fieldName: `repository.${checkpoint}`,
            value: repository[checkpoint],
        });
    }

    const artifacts = requireJsonObject(evidence.artifacts, 'artifacts');
    const nativeAggregate = requireJsonObject(
        artifacts.nativeAggregate,
        'artifacts.nativeAggregate',
    );
    const nativeAggregatePath = requireString(
        nativeAggregate.path,
        'artifacts.nativeAggregate.path',
    );
    if (
        !path.isAbsolute(nativeAggregatePath) ||
        nativeAggregatePath !== path.resolve(nativeAggregatePath)
    ) {
        throw new Error(
            'The bound native aggregate path must be absolute and canonical.',
        );
    }
    const serializedNativeAggregate = await readFile(nativeAggregatePath);
    const nativeAggregateSha256Hex = requireArtifactDigest({
        expectedSha256Hex: nativeAggregate.sha256Hex,
        fieldName: 'Native aggregate artifact',
        value: serializedNativeAggregate,
    });
    const nativeEvidence = await (
        options.loadNativeWidthEvidence ?? loadNativeWidthEvidence
    )(nativeAggregatePath, {
        officialReservationRootPath: reservationRootPath,
    });
    if (
        nativeEvidence.evidenceSha256Hex !== nativeAggregateSha256Hex ||
        nativeEvidence.evidencePath !== nativeAggregatePath ||
        nativeEvidence.repositoryCommitHash !== repositoryCommitHash
    ) {
        throw new Error(
            'The reopened native aggregate does not match its browser closure binding.',
        );
    }
    const embeddedNativeEvidence = requireJsonObject(
        evidence.nativeEvidence,
        'nativeEvidence',
    );
    const expectedEmbeddedNativeEvidence = {
        fullWidthResult: nativeEvidence.fullWidthResult,
        fullWidthStaticPoint: nativeEvidence.fullWidthStaticPoint,
        officialSampleReservationIdentitySha256Hex:
            nativeEvidence.officialSampleReservationIdentitySha256Hex,
        repositoryCommitHash: nativeEvidence.repositoryCommitHash,
        representativeResult: nativeEvidence.representativeResult,
        representativeStaticPoint: nativeEvidence.representativeStaticPoint,
    };
    if (
        !normalizedJsonEquals(
            embeddedNativeEvidence,
            expectedEmbeddedNativeEvidence,
        )
    ) {
        throw new Error(
            'The browser closure native summary does not match the reopened native aggregate.',
        );
    }

    const guardArtifact = requireJsonObject(artifacts.guard, 'artifacts.guard');
    const guardPath = requireExactRelativeArtifactPath({
        actual: guardArtifact.path,
        expected:
            'resources/process-memory-guard-proof-storage-width-browser.jsonl',
        fieldName: 'artifacts.guard.path',
        rootPath: runDirectoryPath,
    });
    const browserEventsArtifact = requireJsonObject(
        artifacts.browserEvents,
        'artifacts.browserEvents',
    );
    const browserEventsPath = requireExactRelativeArtifactPath({
        actual: browserEventsArtifact.path,
        expected: `tests/${testProjectLabel}.jsonl`,
        fieldName: 'artifacts.browserEvents.path',
        rootPath: runDirectoryPath,
    });
    const [serializedGuard, serializedEvents] = await Promise.all([
        readFile(guardPath, 'utf8'),
        readFile(browserEventsPath, 'utf8'),
    ]);
    requireArtifactDigest({
        expectedSha256Hex: guardArtifact.sha256Hex,
        fieldName: 'Browser process-memory guard artifact',
        value: serializedGuard,
    });
    requireArtifactDigest({
        expectedSha256Hex: browserEventsArtifact.sha256Hex,
        fieldName: 'Raw browser event artifact',
        value: serializedEvents,
    });

    const wasm = requireJsonObject(evidence.wasm, 'wasm');
    const expectedProcessedWasmKernelPath = path.resolve(
        options.processedWasmKernelPath ?? processedWasmKernelPath,
    );
    const expectedPublicSdkWasmKernelPath = path.resolve(
        options.publicSdkWasmKernelPath ?? publicSdkWasmKernelPath,
    );
    if (
        wasm.cargoFeature !== browserEvidenceCargoFeature ||
        wasm.producerPath !== expectedProcessedWasmKernelPath ||
        wasm.publicSdkPath !== expectedPublicSdkWasmKernelPath
    ) {
        throw new Error(
            'The browser closure changed its release WebAssembly feature or artifact paths.',
        );
    }
    const rawWasmSha256Hex = requireSha256Hex(
        wasm.rawSha256Hex,
        'wasm.rawSha256Hex',
    );
    const normalizedWasmSha256Hex = requireSha256Hex(
        wasm.normalizedSha256Hex,
        'wasm.normalizedSha256Hex',
    );
    const [producerBytes, publicSdkBytes] = await Promise.all([
        readFile(expectedProcessedWasmKernelPath),
        readFile(expectedPublicSdkWasmKernelPath),
    ]);
    if (!producerBytes.equals(publicSdkBytes)) {
        throw new Error(
            'The reopened producer and public SDK WebAssembly artifacts differ.',
        );
    }
    if (
        sha256Hex(producerBytes) !== rawWasmSha256Hex ||
        sha256Hex(normalizeTranscriptCoreKernelBytesForHash(producerBytes)) !==
            normalizedWasmSha256Hex ||
        wasm.processedByteLength !== String(producerBytes.byteLength)
    ) {
        throw new Error(
            'The reopened release WebAssembly bytes do not match the raw, normalized, or length binding.',
        );
    }
    if (
        BigInt(producerBytes.byteLength) >
        proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength
    ) {
        throw new Error(
            'The reopened release WebAssembly module exceeds the absolute copied-buffer bound.',
        );
    }

    const measurement = parseProofStorageWidthBrowserMeasurementEvents({
        expectedWasmSha256Hex: normalizedWasmSha256Hex,
        serializedEvents,
    });
    requireProofStorageWidthBrowserNativeMatch(
        measurement,
        nativeEvidence.nativeBinding,
    );
    if (!normalizedJsonEquals(evidence.measurement, measurement)) {
        throw new Error(
            'The browser closure measurement does not match its raw event artifact.',
        );
    }
    const operationMemory = extractProofStorageWidthOperationMemory({
        guardJsonLines: serializedGuard,
        operationFinishedAtUnixMilliseconds:
            measurement.operationFinishedAtUnixMilliseconds,
        operationStartedAtUnixMilliseconds:
            measurement.operationStartedAtUnixMilliseconds,
    });
    const guard = requireJsonObject(evidence.guard, 'guard');
    if (
        typeof guard.memoryLimitBytes !== 'number' ||
        !Number.isSafeInteger(guard.memoryLimitBytes) ||
        guard.memoryLimitBytes <= 0
    ) {
        throw new Error(
            'guard.memoryLimitBytes must be a positive safe integer.',
        );
    }
    requireGuardMemoryLimitBinding({
        expectedMemoryLimitBytes: guard.memoryLimitBytes,
        serializedGuard,
    });
    if (
        guard.maximumOperationWindowGapMilliseconds !==
            maximumOperationWindowGapMilliseconds ||
        guard.resourceSampleIntervalMilliseconds !==
            resourceSampleIntervalMilliseconds ||
        !normalizedJsonEquals(guard.operationMemory, operationMemory)
    ) {
        throw new Error(
            'The browser closure guard summary does not match its raw telemetry.',
        );
    }
    const projection = deriveProofStorageWidthBrowserProjection({
        fullWidthResult: nativeEvidence.fullWidthResult,
        fullWidthStaticPoint: nativeEvidence.fullWidthStaticPoint,
        measurement,
        representativeResult: nativeEvidence.representativeResult,
        representativeStaticPoint: nativeEvidence.representativeStaticPoint,
    });
    requireProofStorageWidthBrowserProjectionEligibility({
        fullWidthResult: nativeEvidence.fullWidthResult,
        projection,
    });
    if (!normalizedJsonEquals(evidence.projection, projection)) {
        throw new Error(
            'The browser closure projection does not match the reopened native and browser artifacts.',
        );
    }

    const invocation = requireJsonObject(evidence.invocation, 'invocation');
    const expectedInvocation = {
        retryCount: 0,
        semanticArguments: proofStorageWidthBrowserEvidenceVitestArguments,
        testFile: browserTestFile,
        testProjectName,
    };
    if (!normalizedJsonEquals(invocation, expectedInvocation)) {
        throw new Error(
            'The browser closure must bind the exact project, test file, and zero-retry invocation.',
        );
    }

    const officialReservation = requireJsonObject(
        evidence.officialSampleReservation,
        'officialSampleReservation',
    );
    const officialReservationIdentity =
        buildProofStorageWidthBrowserReservationIdentity({
            nativeAggregateSha256Hex,
            nativeReservationIdentitySha256Hex:
                nativeEvidence.officialSampleReservationIdentitySha256Hex,
            officialOwner: browserOfficialSampleOwner,
            rawWasmSha256Hex,
            sourceCommitHash: repositoryCommitHash,
        });
    const officialReservationIdentitySha256Hex = requireSha256Hex(
        officialReservation.identitySha256Hex,
        'officialSampleReservation.identitySha256Hex',
    );
    if (
        officialReservationIdentitySha256Hex !==
            officialReservationIdentity.identitySha256Hex ||
        officialReservation.officialOwner !== browserOfficialSampleOwner ||
        officialReservation.schemaVersion !== 1
    ) {
        throw new Error(
            'The browser official reservation identity, owner, or schema changed.',
        );
    }
    const reservationPath = requireExactRelativeArtifactPath({
        actual: officialReservation.path,
        expected: `browser/${officialReservationIdentitySha256Hex}/browser-started.json`,
        fieldName: 'officialSampleReservation.path',
        rootPath: reservationRootPath,
    });
    const serializedReservation = await readFile(reservationPath, 'utf8');
    requireArtifactDigest({
        expectedSha256Hex: officialReservation.sha256Hex,
        fieldName: 'Browser official reservation artifact',
        value: serializedReservation,
    });
    validateBrowserOfficialReservationArtifact({
        identitySha256Hex: officialReservationIdentitySha256Hex,
        nativeAggregateSha256Hex,
        officialOwner: browserOfficialSampleOwner,
        rawWasmSha256Hex,
        serialized: serializedReservation,
        sourceCommitHash: repositoryCommitHash,
    });
};

const executeProofStorageWidthBrowserEvidenceAttempt = async (input: {
    readonly dependencies?: ProofStorageWidthBrowserEvidenceDependencies;
    readonly nativeEvidencePath: string;
    readonly runLog: ActiveLocalRunLog;
}) => {
    if (!path.isAbsolute(input.nativeEvidencePath)) {
        throw new Error('The native width-evidence path must be absolute.');
    }
    const executeCommand =
        input.dependencies?.executeCommand ?? defaultCommandExecutor;
    const processMemoryGuard =
        input.dependencies?.processMemoryGuard ??
        createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription:
                'Proof-storage width release WebAssembly evidence',
        });
    const readRepositoryState =
        input.dependencies?.readRepositoryState ??
        ((checkpoint, runLog) =>
            readRepositoryStateWithCommands({
                checkpoint,
                executeCommand,
                runLog,
            }));
    const configuredOfficialReservationRootPath =
        input.dependencies?.officialReservationRootPath ??
        defaultProofStorageWidthOfficialReservationRootPath;
    if (!path.isAbsolute(configuredOfficialReservationRootPath)) {
        throw new Error(
            'The official browser reservation root path must be absolute.',
        );
    }
    const officialReservationRootPath = path.resolve(
        configuredOfficialReservationRootPath,
    );
    const loadNativeEvidence =
        input.dependencies?.loadNativeWidthEvidence ?? loadNativeWidthEvidence;
    const nativeEvidence = await loadNativeEvidence(input.nativeEvidencePath, {
        officialReservationRootPath,
    });
    const initialRepositoryState = await readRepositoryState(
        'initial',
        input.runLog,
    );
    requireCleanPinnedRepository(
        initialRepositoryState,
        nativeEvidence.repositoryCommitHash,
        'initial',
    );
    const packageManagerRunner = resolvePackageManagerRunner();
    const commandEnvironment: NodeJS.ProcessEnv = {
        ...process.env,
        SEALED_LATTICE_TEST_PROJECT_LABEL: testProjectLabel,
        [wasmEvidenceFeatureEnvironmentVariable]: browserEvidenceCargoFeature,
    };
    await executeRequiredCommand({
        command: createPackageManagerCommand(
            'build the release WebAssembly width-evidence feature',
            ['run', 'build'],
            {
                env: commandEnvironment,
                logFileSlug: 'build-proof-storage-width-browser-evidence',
                packageManagerRunner,
            },
        ),
        executeCommand,
        runLog: input.runLog,
    });
    const evidenceProcessedWasmKernelPath = path.resolve(
        input.dependencies?.processedWasmKernelPath ?? processedWasmKernelPath,
    );
    const evidencePublicSdkWasmKernelPath = path.resolve(
        input.dependencies?.publicSdkWasmKernelPath ?? publicSdkWasmKernelPath,
    );
    const wasmBinding = await (
        input.dependencies?.deriveProcessedWasmBinding ??
        (() =>
            deriveProcessedWasmBinding({
                processedWasmKernelPath: evidenceProcessedWasmKernelPath,
                publicSdkWasmKernelPath: evidencePublicSdkWasmKernelPath,
            }))
    )();
    const beforeRepositoryState = await readRepositoryState(
        'before',
        input.runLog,
    );
    requireCleanPinnedRepository(
        beforeRepositoryState,
        nativeEvidence.repositoryCommitHash,
        'before',
    );
    commandEnvironment[expectedWasmHashEnvironmentVariable] =
        wasmBinding.normalizedSha256Hex;
    commandEnvironment[nativeBindingEnvironmentVariable] = JSON.stringify(
        nativeEvidence.nativeBindingRecord,
    );
    commandEnvironment[databaseNameEnvironmentVariable] = [
        'sealed-lattice-proof-storage-width',
        nativeEvidence.repositoryCommitHash.slice(0, 12),
        randomUUID(),
    ].join('-');
    await executeRequiredCommand({
        command: processMemoryGuard.buildVerificationCommand(),
        executeCommand,
        runLog: input.runLog,
    });
    const guardPath = path.join(
        input.runLog.runDirectoryPath,
        'resources',
        'process-memory-guard-proof-storage-width-browser.jsonl',
    );
    const eventPath = path.join(
        input.runLog.runDirectoryPath,
        'tests',
        `${testProjectLabel}.jsonl`,
    );
    await mkdir(path.dirname(guardPath), { recursive: true });
    await Promise.all([
        requireArtifactAbsent(guardPath, 'Browser guard artifact'),
        requireArtifactAbsent(eventPath, 'Browser event artifact'),
    ]);
    const browserCommand = createPackageManagerCommand(
        'run the fixed width-512 release WebAssembly evidence',
        proofStorageWidthBrowserEvidenceVitestArguments,
        {
            env: commandEnvironment,
            logFileSlug: 'vitest-proof-storage-width-browser-evidence',
            packageManagerRunner,
        },
    );
    const officialReservationIdentity =
        buildProofStorageWidthBrowserReservationIdentity({
            nativeAggregateSha256Hex: nativeEvidence.evidenceSha256Hex,
            nativeReservationIdentitySha256Hex:
                nativeEvidence.officialSampleReservationIdentitySha256Hex,
            officialOwner: browserOfficialSampleOwner,
            rawWasmSha256Hex: wasmBinding.rawSha256Hex,
            sourceCommitHash: nativeEvidence.repositoryCommitHash,
        });
    const reservationPath =
        await createProofStorageWidthBrowserSampleReservation({
            identitySha256Hex: officialReservationIdentity.identitySha256Hex,
            nativeAggregateSha256Hex: nativeEvidence.evidenceSha256Hex,
            officialOwner: browserOfficialSampleOwner,
            rawWasmSha256Hex: wasmBinding.rawSha256Hex,
            reservationRootPath: officialReservationRootPath,
            runDirectoryPath: input.runLog.runDirectoryPath,
            sourceCommitHash: nativeEvidence.repositoryCommitHash,
        });
    let attemptError: unknown;
    try {
        await executeRequiredCommand({
            command: processMemoryGuard.guardCommand(browserCommand, {
                diagnosticsPath: guardPath,
                resourceSampleIntervalMilliseconds,
            }),
            executeCommand,
            runLog: input.runLog,
        });
    } catch (error) {
        attemptError = error;
    }
    let afterRepositoryState: RepositoryState | undefined;
    try {
        afterRepositoryState = await readRepositoryState('after', input.runLog);
        requireCleanPinnedRepository(
            afterRepositoryState,
            nativeEvidence.repositoryCommitHash,
            'after',
        );
    } catch (repositoryError) {
        attemptError =
            attemptError === undefined
                ? repositoryError
                : combineAttemptAndRepositoryFailure({
                      attemptError,
                      repositoryError,
                  });
    }
    let serializedEvents: string | undefined;
    let guardJsonLines: string | undefined;
    let measurement: ProofStorageWidthBrowserMeasurement | undefined;
    let operationMemory:
        | ReturnType<typeof extractProofStorageWidthOperationMemory>
        | undefined;
    let projection: ProofStorageWidthBrowserProjection | undefined;
    if (attemptError === undefined) {
        try {
            [serializedEvents, guardJsonLines] = await Promise.all([
                readFile(eventPath, 'utf8'),
                readFile(guardPath, 'utf8'),
            ]);
            measurement = parseProofStorageWidthBrowserMeasurementEvents({
                expectedWasmSha256Hex: wasmBinding.normalizedSha256Hex,
                serializedEvents,
            });
            requireProofStorageWidthBrowserNativeMatch(
                measurement,
                nativeEvidence.nativeBinding,
            );
            operationMemory = extractProofStorageWidthOperationMemory({
                guardJsonLines,
                operationFinishedAtUnixMilliseconds:
                    measurement.operationFinishedAtUnixMilliseconds,
                operationStartedAtUnixMilliseconds:
                    measurement.operationStartedAtUnixMilliseconds,
            });
            requireGuardMemoryLimitBinding({
                expectedMemoryLimitBytes: processMemoryGuard.memoryLimitBytes,
                serializedGuard: guardJsonLines,
            });
            if (
                operationMemory.resourceSampleIntervalMilliseconds !==
                    BigInt(resourceSampleIntervalMilliseconds) ||
                operationMemory.inWindowSampleCount === 0
            ) {
                throw new Error(
                    'The browser width-evidence operation lacks guarded in-window samples.',
                );
            }
            projection = deriveProofStorageWidthBrowserProjection({
                fullWidthResult: nativeEvidence.fullWidthResult,
                fullWidthStaticPoint: nativeEvidence.fullWidthStaticPoint,
                measurement,
                representativeResult: nativeEvidence.representativeResult,
                representativeStaticPoint:
                    nativeEvidence.representativeStaticPoint,
            });
            requireProofStorageWidthBrowserProjectionEligibility({
                fullWidthResult: nativeEvidence.fullWidthResult,
                projection,
            });
        } catch (error) {
            attemptError = error;
        }
    }
    try {
        await appendProofStorageWidthOfficialReservationOutcome({
            ...(attemptError === undefined
                ? {}
                : { failureName: errorName(attemptError) }),
            outcome: attemptError === undefined ? 'validated' : 'failed',
            reservationPath,
        });
    } catch (outcomeError) {
        throw Object.assign(
            new Error(
                'The durable browser reservation outcome could not be appended; the started marker still prohibits a replacement sample.',
            ),
            { attemptCause: attemptError, cause: outcomeError },
        );
    }
    if (attemptError !== undefined) {
        throw attemptError instanceof Error
            ? attemptError
            : Object.assign(new Error('The browser sample failed.'), {
                  cause: attemptError,
              });
    }
    if (
        serializedEvents === undefined ||
        guardJsonLines === undefined ||
        measurement === undefined ||
        operationMemory === undefined ||
        projection === undefined ||
        afterRepositoryState === undefined
    ) {
        throw new Error(
            'The validated browser sample omitted a required closure artifact.',
        );
    }
    const serializedReservation = await readFile(reservationPath, 'utf8');
    validateBrowserOfficialReservationArtifact({
        identitySha256Hex: officialReservationIdentity.identitySha256Hex,
        nativeAggregateSha256Hex: nativeEvidence.evidenceSha256Hex,
        officialOwner: browserOfficialSampleOwner,
        rawWasmSha256Hex: wasmBinding.rawSha256Hex,
        serialized: serializedReservation,
        sourceCommitHash: nativeEvidence.repositoryCommitHash,
    });
    const attachmentPath = path.join(
        input.runLog.runDirectoryPath,
        'attachments',
        'proof-storage-width-browser-evidence.json',
    );
    await writeJsonExclusively(attachmentPath, {
        artifacts: {
            browserEvents: {
                path: canonicalRelativePath(
                    input.runLog.runDirectoryPath,
                    eventPath,
                ),
                sha256Hex: sha256Hex(serializedEvents),
            },
            guard: {
                path: canonicalRelativePath(
                    input.runLog.runDirectoryPath,
                    guardPath,
                ),
                sha256Hex: sha256Hex(guardJsonLines),
            },
            nativeAggregate: {
                path: nativeEvidence.evidencePath,
                sha256Hex: nativeEvidence.evidenceSha256Hex,
            },
        },
        formatVersion: 3,
        guard: {
            memoryLimitBytes: processMemoryGuard.memoryLimitBytes,
            maximumOperationWindowGapMilliseconds,
            operationMemory,
            resourceSampleIntervalMilliseconds,
        },
        measurement,
        invocation: {
            retryCount: 0,
            semanticArguments: proofStorageWidthBrowserEvidenceVitestArguments,
            testFile: browserTestFile,
            testProjectName,
        },
        nativeEvidence: {
            officialSampleReservationIdentitySha256Hex:
                nativeEvidence.officialSampleReservationIdentitySha256Hex,
            repositoryCommitHash: nativeEvidence.repositoryCommitHash,
            representativeResult: nativeEvidence.representativeResult,
            representativeStaticPoint: nativeEvidence.representativeStaticPoint,
            fullWidthResult: nativeEvidence.fullWidthResult,
            fullWidthStaticPoint: nativeEvidence.fullWidthStaticPoint,
        },
        officialSampleReservation: {
            identitySha256Hex: officialReservationIdentity.identitySha256Hex,
            officialOwner: browserOfficialSampleOwner,
            path: canonicalRelativePath(
                officialReservationRootPath,
                reservationPath,
            ),
            schemaVersion: 1,
            sha256Hex: sha256Hex(serializedReservation),
        },
        projection,
        repository: {
            after: afterRepositoryState,
            before: beforeRepositoryState,
            initial: initialRepositoryState,
        },
        wasm: {
            cargoFeature: browserEvidenceCargoFeature,
            processedByteLength: wasmBinding.byteLength,
            normalizedSha256Hex: wasmBinding.normalizedSha256Hex,
            producerPath: evidenceProcessedWasmKernelPath,
            publicSdkPath: evidencePublicSdkWasmKernelPath,
            rawSha256Hex: wasmBinding.rawSha256Hex,
        },
    });
    await validateProofStorageWidthBrowserEvidenceArtifacts(attachmentPath, {
        loadNativeWidthEvidence: loadNativeEvidence,
        officialReservationRootPath,
        processedWasmKernelPath: evidenceProcessedWasmKernelPath,
        publicSdkWasmKernelPath: evidencePublicSdkWasmKernelPath,
    });
    return {
        attachmentPath,
        completionEventDetails: {
            attachmentPath,
            projectedFullWidthNanoseconds:
                projection.operationNanoseconds.toString(),
            projectedWasmLinearMemoryPeakByteLength:
                projection.projectedWasmLinearMemoryPeakByteLength.toString(),
            repositoryCommitHash: nativeEvidence.repositoryCommitHash,
            staticWasmMemoryCeilingDeltaByteLength:
                projection.staticWasmMemoryCeilingGrowth.deltaByteLength.toString(),
            rawWasmSha256Hex: wasmBinding.rawSha256Hex,
            wasmSha256Hex: wasmBinding.normalizedSha256Hex,
        },
    };
};

export const executeProofStorageWidthBrowserEvidence = async (input: {
    readonly dependencies?: ProofStorageWidthBrowserEvidenceDependencies;
    readonly nativeEvidencePath: string;
    readonly runLog: ActiveLocalRunLog;
}): Promise<void> => {
    const executeCommand =
        input.dependencies?.executeCommand ?? defaultCommandExecutor;
    const processMemoryGuard =
        input.dependencies?.processMemoryGuard ??
        createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription:
                'Proof-storage width release WebAssembly evidence',
        });
    const readRepositoryState =
        input.dependencies?.readRepositoryState ??
        ((checkpoint: RepositoryCheckpoint, runLog: ActiveLocalRunLog) =>
            readRepositoryStateWithCommands({
                checkpoint,
                executeCommand,
                runLog,
            }));
    let initialCommitHash: string | undefined;
    const readTrackedRepositoryState = async (
        checkpoint: RepositoryCheckpoint,
        runLog: ActiveLocalRunLog,
    ): Promise<RepositoryState> => {
        const repositoryState = await readRepositoryState(checkpoint, runLog);
        if (checkpoint === 'initial') {
            initialCommitHash = repositoryState.commitHash;
        }
        return repositoryState;
    };

    let attemptError: unknown;
    let result:
        | Awaited<
              ReturnType<typeof executeProofStorageWidthBrowserEvidenceAttempt>
          >
        | undefined;
    try {
        result = await executeProofStorageWidthBrowserEvidenceAttempt({
            dependencies: {
                ...(input.dependencies ?? {}),
                executeCommand,
                processMemoryGuard,
                readRepositoryState: readTrackedRepositoryState,
            },
            nativeEvidencePath: input.nativeEvidencePath,
            runLog: input.runLog,
        });
    } catch (error) {
        attemptError = error;
    }

    let closureRepositoryError: unknown;
    if (initialCommitHash !== undefined) {
        try {
            const closureRepositoryState = await readRepositoryState(
                'closure-after',
                input.runLog,
            );
            requireCleanPinnedRepository(
                closureRepositoryState,
                initialCommitHash,
                'closure-after',
            );
        } catch (error) {
            closureRepositoryError = error;
        }
    }

    if (attemptError !== undefined && closureRepositoryError !== undefined) {
        throw Object.assign(
            new Error(
                'The browser width-evidence attempt failed and its final repository closure check also failed.',
            ),
            {
                attemptCause: attemptError,
                cause: closureRepositoryError,
            },
        );
    }
    if (attemptError !== undefined) {
        if (attemptError instanceof Error) {
            throw attemptError;
        }
        throw Object.assign(
            new Error(
                'The browser width-evidence attempt failed with a non-Error rejection value.',
            ),
            { cause: attemptError },
        );
    }
    if (closureRepositoryError !== undefined) {
        if (closureRepositoryError instanceof Error) {
            throw closureRepositoryError;
        }
        throw Object.assign(
            new Error(
                'The browser width-evidence final repository closure check failed with a non-Error rejection value.',
            ),
            { cause: closureRepositoryError },
        );
    }
    if (result === undefined) {
        throw new Error(
            'The browser width-evidence attempt completed without a result.',
        );
    }

    const message = `Proof-storage width browser evidence: ${result.attachmentPath}\n`;
    process.stdout.write(message);
    input.runLog.writeCombinedOutput(message);
    input.runLog.writeEvent({
        details: result.completionEventDetails,
        eventType: 'proof-storage-width-browser-evidence-complete',
    });
};

export const parseProofStorageWidthBrowserEvidenceArguments = (
    rawArguments: readonly string[],
): string => {
    const effectiveArguments = rawArguments.filter(
        (argument) => argument !== '--',
    );
    if (
        effectiveArguments.length !== 2 ||
        effectiveArguments[0] !== '--native-evidence' ||
        effectiveArguments[1] === undefined ||
        !path.isAbsolute(effectiveArguments[1])
    ) {
        throw new Error(
            'The browser width-evidence runner requires --native-evidence followed by one absolute evidence path.',
        );
    }
    return effectiveArguments[1];
};

export const runProofStorageWidthBrowserEvidence = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const nativeEvidencePath =
        parseProofStorageWidthBrowserEvidenceArguments(rawArguments);
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: [laneLabel],
            resourceSampleIntervalMilliseconds,
            scriptName,
        },
        async (runLog) => {
            await withLocalHeavyLaneLease({
                action: () =>
                    executeProofStorageWidthBrowserEvidence({
                        nativeEvidencePath,
                        runLog,
                    }),
                laneLabel,
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    void runProofStorageWidthBrowserEvidence();
}
