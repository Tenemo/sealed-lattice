import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import {
    link,
    lstat,
    mkdir,
    mkdtemp,
    readFile,
    readdir,
    rename,
    rm,
    symlink,
    writeFile,
} from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    parseProofStorageWidthBrowserMeasurement,
    type ProofStorageWidthBrowserNativeBinding,
} from '#tests/support/proof-storage-width-browser-evidence';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log';
import type { ProcessMemoryGuard } from '#tools/ci/process-memory-guard';
import {
    deriveProofStorageWidthGeometry,
    proofStorageWidthProfile,
} from '#tools/ci/proof-storage-width-evidence';
import type {
    CapturedCommandResult,
    CommandInvocation,
} from '#tools/ci/run-command';
import {
    dryRunProofStorageWidthBrowserRecoveryChain,
    executeProofStorageWidthBrowserEvidence,
    immutableFailedRunMetadataInvocationEquals,
    parseProofStorageWidthBrowserEvidenceArguments,
    parseProofStorageWidthBrowserMeasurementEvents,
    parseProofStorageWidthBrowserStaticPreflightOutput,
    proofStorageWidthBrowserEvidenceVitestArguments,
    proofStorageWidthBrowserEvidenceStaticPreflightArguments,
    runProofStorageWidthBrowserEvidence,
    validateProofStorageWidthBrowserEvidenceArtifacts,
    type NativeWidthEvidence,
    type ProofStorageWidthBrowserEvidenceDependencies,
    type ProofStorageWidthBrowserChainedRecoveryProfile,
    type ProofStorageWidthBrowserPreOperationRecoveryProfile,
    type ProofStorageWidthBrowserThirdRecoveryProfile,
} from '#tools/ci/run-proof-storage-width-browser-evidence';

const commitHash = '9a'.repeat(20);
const firstHarnessRepairCommitHash = '618c55d352d5a2f87db09b446f7e05857831c4dd';
const validatorRepairCommitHash = 'b7398ce150044fc4d3579136989753ddcaad3faa';
const recoveryHarnessCommitHash = '6d'.repeat(20);
const thirdRecoveryIssuanceCommitHash =
    '17d0b2b15027e0914f55105c27931f2d6e1c5824';
const thirdRecoveryFinalHarnessCommitHash = '7e'.repeat(20);
const officialNativeReservationIdentitySha256Hex = '34'.repeat(32);
const testMemoryLimitBytes = 8_589_934_592;
const expectedWasmHashEnvironmentVariable =
    'VITE_SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_EXPECTED_WASM_SHA256_HEX';
const browserEvidenceTestFile =
    'packages/wasm/tests/browser/proof-storage-width-evidence.manual.browser.test.ts';
const browserEvidenceStaticPreflightOutput = `[chromium-proof-storage-width-evidence] ${browserEvidenceTestFile}\n`;

const successfulCommandResult = (): CapturedCommandResult => ({
    exitCode: 0,
    stderr: '',
    stdout: '',
    terminationSignal: null,
});

const failedCommandResult = (): CapturedCommandResult => ({
    exitCode: 1,
    stderr: 'intentional browser sample failure',
    stdout: '',
    terminationSignal: null,
});

const createRunLog = (
    runDirectoryPath: string,
    input: Readonly<{
        writeCombinedOutput?: (output: string) => void;
        writeEvent?: ActiveLocalRunLog['writeEvent'];
    }> = {},
): ActiveLocalRunLog => ({
    createCommandLogFiles: ({ preferredSlug }) => ({
        combinedPath: path.join(
            runDirectoryPath,
            `${preferredSlug ?? 'command'}.log`,
        ),
        commandId: preferredSlug ?? 'command',
    }),
    finish: () => Promise.resolve(),
    runDirectoryPath,
    writeCombinedOutput: input.writeCombinedOutput ?? (() => undefined),
    writeCommandOutput: () => undefined,
    writeEvent: input.writeEvent ?? (() => undefined),
});

const createProcessMemoryGuard = (): ProcessMemoryGuard => ({
    buildVerificationCommand: () => ({
        args: ['verify'],
        command: 'test-process-memory-guard-verification',
        description: 'verify test process-memory guard',
    }),
    guardCommand: (command, options = {}) => ({
        ...command,
        args: [
            '--diagnostics-path',
            options.diagnosticsPath ?? '',
            '--resource-sample-interval-milliseconds',
            String(options.resourceSampleIntervalMilliseconds ?? ''),
            '--',
            command.command,
            ...command.args,
        ],
        command: 'test-process-memory-guard',
        description: `guarded ${command.description}`,
    }),
    memoryLimitBytes: testMemoryLimitBytes,
    memoryLimitGigabytes: 8,
});

const createMeasurementRecord = (
    wasmSha256Hex: string,
): Readonly<Record<string, unknown>> => {
    const geometry = deriveProofStorageWidthGeometry(512);
    return {
        absorbedLeafValueCountDecimal:
            geometry.absorbedLeafValueCount.toString(),
        activeColumnLdeScratchByteLengthDecimal:
            geometry.activeColumnLdeScratchByteLength.toString(),
        arithmeticNanosecondsDecimal: '100',
        artifactShake256Hex: 'ab'.repeat(64),
        backendProfileIdentifier:
            proofStorageWidthProfile.backendProfileIdentifier,
        baseLeafObjectReadByteLengthDecimal: '0',
        baseLeafObjectWrittenByteLengthDecimal: '0',
        baseRootShake256Hex: 'cd'.repeat(64),
        canonicalArtifactByteLengthDecimal: '1700000',
        canonicalArtifactNonleafRangeChunkCountDecimal: '5',
        canonicalArtifactPostleafRangeChunkCountDecimal: '3',
        canonicalArtifactPreleafRangeChunkCountDecimal: '2',
        coordinatorNanosecondsDecimal: '10',
        copiedBufferPeakByteLengthDecimal:
            proofStorageWidthProfile.externalMemoryCopiedBufferByteLengthCeiling.toString(),
        custodyCleanupCompleted: true,
        custodyModel: 'bounded-external-storage-replay',
        custodySchemaIdentifier:
            proofStorageWidthProfile.custodySchemaIdentifier,
        exactCandidate: {
            firstDataModulus: proofStorageWidthProfile.firstDataModulus,
            materialRadix: proofStorageWidthProfile.materialRadix,
            plaintextModulus: 257,
            ringDimension: 32_768,
            rosterSize: 10,
        },
        externalCommittedCreateTransactionCountDecimal: '513',
        externalCommittedDeleteTransactionCountDecimal: '513',
        externalCommittedReadTransactionCountDecimal: '9404',
        externalCommittedSealTransactionCountDecimal: '513',
        externalCommittedTransactionCountDecimal: '12667',
        externalCommittedWriteTransactionCountDecimal: '1724',
        externalReadByteLengthDecimal: '404353184',
        externalStorageWaitNanosecondsDecimal: '200',
        externalWrittenByteLengthDecimal: '68808864',
        formatVersion: 1,
        frozenInputIdentityHashDomain:
            proofStorageWidthProfile.frozenInputIdentityHashDomain,
        frozenInputIdentityShake256Hex:
            proofStorageWidthProfile.frozenInputIdentityShake256Hex,
        frozenInputRecipeIdentifier:
            proofStorageWidthProfile.frozenInputRecipeIdentifier,
        inputIdentityShake256Hex: 'ef'.repeat(64),
        intendedReleaseRuntime: proofStorageWidthProfile.intendedReleaseRuntime,
        ldeTransformCountDecimal: geometry.ldeTransformCount.toString(),
        localRecordSealInvocationCountDecimal: '0',
        manifestIdentityShake256Hex: '56'.repeat(64),
        maximumArithmeticSliceNanosecondsDecimal: '50',
        maximumTransactionPayloadByteLengthDecimal: '49152',
        measurementRuntime: 'desktop-browser-wasm',
        openedLeafElementByteLengthDecimal:
            geometry.openedLeafElementByteLength.toString(),
        openedLeafRangeChunkCountDecimal:
            geometry.openedLeafRangeChunkCount.toString(),
        openedValueCountDecimal: geometry.openedValueCount.toString(),
        operationElapsedNanosecondsDecimal: '610',
        operationFinishedAtUnixMilliseconds: '1200',
        operationStartedAtUnixMilliseconds: '1000',
        persistedBaseLeafByteLengthDecimal: '0',
        persistedLdeByteLengthDecimal: '0',
        physicalObjectPeakDecimal: geometry.physicalObjectPeak.toString(),
        proofByteLengthDecimal: '1700000',
        proofObjectSealTransactionCountDecimal: '1',
        proofPhysicalObjectCountDecimal: '1',
        providerCleanupInspectionTransactionCountDecimal: '2',
        providerDataRecordPeakDecimal: '1724',
        providerMetadataRecordPeakDecimal: '513',
        providerMetadataWrittenByteLengthDecimal: '110000',
        providerMutationTransactionCountDecimal: '3263',
        providerReadTransactionCountDecimal: '18808',
        providerRecordPeakDecimal: '2237',
        providerTransactionCountDecimal: '22073',
        publicBaseLeafByteLengthDecimal:
            geometry.publicBaseLeafByteLength.toString(),
        publicBaseLeafColumnCount: 512,
        publicColumnDerivationAlgorithm:
            proofStorageWidthProfile.publicColumnDerivationAlgorithm,
        publicColumnInputDomain:
            proofStorageWidthProfile.publicColumnInputDomain,
        publicColumnSeedHex: proofStorageWidthProfile.publicColumnSeedHex,
        queriedLeafPayloadByteLengthDecimal:
            geometry.queriedLeafPayloadByteLength.toString(),
        recomputedCanonicalArtifactByteLengthDecimal: '1700000',
        releaseProfileIdentifier:
            proofStorageWidthProfile.releaseProfileIdentifier,
        sealedSecretPlaintextByteLengthDecimal: '0',
        sourceCommittedTransactionCountDecimal: '12288',
        sourceObjectSealTransactionCountDecimal: '512',
        sourcePhysicalObjectCountDecimal: '512',
        sourceReplayByteLengthDecimal:
            geometry.sourceReplayByteLength.toString(),
        storedScratchPeakByteLengthDecimal: '68808864',
        wasmLinearMemoryEndByteLengthDecimal: '134217728',
        wasmLinearMemoryPeakByteLengthDecimal: '201326592',
        wasmLinearMemoryStartByteLengthDecimal: '134217728',
        wasmSha256Hex,
        workerYieldCountDecimal: '4',
        workerYieldNanosecondsDecimal: '300',
        widthDependentQueriedBaseOpeningByteLengthDecimal:
            geometry.widthDependentQueriedBaseOpeningByteLength.toString(),
        widthInputIdentityHashDomain:
            proofStorageWidthProfile.widthInputIdentityHashDomain,
    };
};

const buildGuardJsonLines = (): string =>
    [
        {
            aggregateProcessTreeMemoryLimit: true,
            elapsedMilliseconds: 0,
            eventType: 'guard-started',
            memoryLimitBytes: testMemoryLimitBytes,
            recordedAtUnixMilliseconds: 800,
            resourceSampleIntervalMilliseconds: 100,
            sequence: 0,
        },
        {
            elapsedMilliseconds: 50,
            eventType: 'child-started',
            recordedAtUnixMilliseconds: 850,
            sequence: 1,
        },
        ...[900, 1_050, 1_150, 1_250].map(
            (recordedAtUnixMilliseconds, sampleIndex) => ({
                confirmedMemoryLimitViolation: false,
                elapsedMilliseconds: 100 + sampleIndex * 100,
                eventType: 'resource-sample',
                processTreeResidentMemoryBytes: 100_000_000 + sampleIndex,
                recordedAtUnixMilliseconds,
                sampleError: null,
                sequence: sampleIndex + 2,
            }),
        ),
        {
            elapsedMilliseconds: 600,
            eventType: 'child-exited',
            exitCode: 0,
            memoryEvidence: 'completed',
            recordedAtUnixMilliseconds: 1_300,
            sequence: 6,
            terminationClassification: 'completed',
        },
    ]
        .map((record) => JSON.stringify(record))
        .join('\n') + '\n';

const sha256Hex = (value: string | Uint8Array): string =>
    createHash('sha256').update(value).digest('hex');

const recoveryRepairFilePaths = [
    'tests/node/tools/browser-test-project-selection.test.ts',
    'tests/node/tools/proof-storage-width-browser-evidence-runner.test.ts',
    'tools/ci/browser-test-project-selection.ts',
    'tools/ci/run-proof-storage-width-browser-evidence.ts',
    'vitest.config.ts',
] as const;
const validatorRepairFilePaths = [
    'tests/node/tools/proof-storage-width-browser-evidence-runner.test.ts',
    'tools/ci/run-proof-storage-width-browser-evidence.ts',
] as const;

const createNativeEvidence = async (input: {
    readonly evidencePath?: string;
    readonly fullWidthExternalIoByteLength?: bigint;
    readonly measurementRecord: Readonly<Record<string, unknown>>;
    readonly nativeEvidencePath: string;
}): Promise<NativeWidthEvidence> => {
    const measurement = parseProofStorageWidthBrowserMeasurement(
        input.measurementRecord,
    );
    const nativeEvidenceBytes = await readFile(input.nativeEvidencePath);
    const representativeResult = {
        elapsedNanoseconds: 1_000n,
        externalCommittedTransactionCount:
            measurement.externalCommittedTransactionCount,
        externalIoByteLength:
            measurement.externalReadByteLength +
            measurement.externalWrittenByteLength,
        ldeTransformCount: measurement.ldeTransformCount,
        publicBaseLeafColumnCount: 512,
    } as unknown as NativeWidthEvidence['representativeResult'];
    const fullWidthResult = {
        elapsedNanoseconds: 7_000n,
        externalCommittedTransactionCount:
            measurement.externalCommittedTransactionCount * 7n,
        externalIoByteLength:
            input.fullWidthExternalIoByteLength ??
            (measurement.externalReadByteLength +
                measurement.externalWrittenByteLength) *
                7n,
        ldeTransformCount:
            deriveProofStorageWidthGeometry(3_451).ldeTransformCount,
        publicBaseLeafColumnCount: 3_451,
    } as unknown as NativeWidthEvidence['fullWidthResult'];
    return {
        evidencePath:
            input.evidencePath ?? path.resolve(input.nativeEvidencePath),
        evidenceSha256Hex: sha256Hex(nativeEvidenceBytes),
        fullWidthResult,
        fullWidthStaticPoint: {
            publicBaseLeafColumnCount: 3_451,
            wasmMemoryByteLengthCeiling: 450_000_000n,
        } as NativeWidthEvidence['fullWidthStaticPoint'],
        nativeBinding:
            measurement as unknown as ProofStorageWidthBrowserNativeBinding,
        nativeBindingRecord: input.measurementRecord,
        officialSampleReservationIdentitySha256Hex:
            officialNativeReservationIdentitySha256Hex,
        repositoryCommitHash: commitHash,
        representativeResult,
        representativeStaticPoint: {
            publicBaseLeafColumnCount: 512,
            wasmMemoryByteLengthCeiling: 300_000_000n,
        } as NativeWidthEvidence['representativeStaticPoint'],
    };
};

const withTemporaryFixture = async <Result>(
    action: (fixture: {
        readonly nativeEvidencePath: string;
        readonly processedWasmKernelPath: string;
        readonly publicSdkWasmKernelPath: string;
        readonly reservationRootPath: string;
        readonly runDirectoryPath: string;
    }) => Promise<Result>,
): Promise<Result> => {
    const temporaryParentPath = path.resolve('temp');
    await mkdir(temporaryParentPath, { recursive: true });
    const temporaryRootPath = await mkdtemp(
        path.join(temporaryParentPath, 'sealed-lattice-width-browser-runner-'),
    );
    const runDirectoryPath = path.join(temporaryRootPath, 'run');
    const reservationRootPath = path.join(
        temporaryRootPath,
        'official-reservations',
    );
    const nativeEvidencePath = path.join(
        temporaryRootPath,
        'native-evidence.json',
    );
    const processedWasmKernelPath = path.join(
        temporaryRootPath,
        'producer.wasm',
    );
    const publicSdkWasmKernelPath = path.join(temporaryRootPath, 'public.wasm');
    await mkdir(runDirectoryPath);
    await writeFile(nativeEvidencePath, '{"native":true}\n', 'utf8');
    const minimalWasmBytes = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]);
    await Promise.all([
        writeFile(processedWasmKernelPath, minimalWasmBytes),
        writeFile(publicSdkWasmKernelPath, minimalWasmBytes),
    ]);
    try {
        return await action({
            nativeEvidencePath,
            processedWasmKernelPath,
            publicSdkWasmKernelPath,
            reservationRootPath,
            runDirectoryPath,
        });
    } finally {
        await rm(temporaryRootPath, { force: true, recursive: true });
    }
};

type TestRecoveryProfile = ProofStorageWidthBrowserPreOperationRecoveryProfile &
    Readonly<{
        chainedRecoveryProfile: ProofStorageWidthBrowserChainedRecoveryProfile;
    }>;

type TestThirdRecoveryProfile = TestRecoveryProfile &
    Readonly<{
        thirdRecoveryProfile: ProofStorageWidthBrowserThirdRecoveryProfile;
    }>;

type RecordedInvocationPathSerializer = (
    canonicalPath: string,
    pathArgumentIndex: 1 | 3 | 5,
) => string;

type BrowserRecoveryMarkerFaultInjection = NonNullable<
    ProofStorageWidthBrowserEvidenceDependencies['browserRecoveryMarkerFaultInjection']
>;

const exactRecordedInvocationPath: RecordedInvocationPathSerializer = (
    canonicalPath,
) => canonicalPath;

const doubledWindowsRecordedInvocationPath: RecordedInvocationPathSerializer = (
    canonicalPath,
) => {
    if (process.platform !== 'win32') {
        return canonicalPath;
    }
    const parsedPath = path.win32.parse(canonicalPath);
    return `${parsedPath.root}${canonicalPath
        .slice(parsedPath.root.length)
        .split(/[\\/]+/u)
        .join('\\\\')}`;
};

const mixedWindowsRecordedInvocationPath: RecordedInvocationPathSerializer = (
    canonicalPath,
) => {
    if (process.platform !== 'win32') {
        return canonicalPath;
    }
    const parsedPath = path.win32.parse(canonicalPath);
    return `${parsedPath.root}${canonicalPath
        .slice(parsedPath.root.length)
        .split(/[\\/]+/u)
        .map((segment, segmentIndex) =>
            segmentIndex === 0
                ? segment
                : `${segmentIndex % 2 === 0 ? '\\\\' : '/'}${segment}`,
        )
        .join('')}`;
};

const normalizeTestJsonValue = (value: unknown): unknown => {
    if (Array.isArray(value)) {
        return value.map(normalizeTestJsonValue);
    }
    if (typeof value !== 'object' || value === null) {
        return value;
    }
    return Object.fromEntries(
        Object.entries(value)
            .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey))
            .map(([key, nestedValue]) => [
                key,
                normalizeTestJsonValue(nestedValue),
            ]),
    );
};

const createPreOperationRecoveryProfile = async (input: {
    readonly failedRecoveryInvocationPathSerializer?: RecordedInvocationPathSerializer;
    readonly failedRecoveryRunDirectoryPathSerializer?: RecordedInvocationPathSerializer;
    readonly nativeEvidencePath: string;
    readonly nativeEvidenceBindingPath?: string;
    readonly processedWasmKernelPath: string;
    readonly reservationRootPath: string;
    readonly runDirectoryPath: string;
}): Promise<TestRecoveryProfile> => {
    const failedRunDirectoryPath = path.join(
        path.dirname(input.runDirectoryPath),
        'failed-run',
    );
    const emptyDirectoryNames = [
        'attachments',
        'diagnostic-reports',
        'tests',
        'vitest-results',
    ];
    await Promise.all([
        mkdir(path.join(failedRunDirectoryPath, 'resources'), {
            recursive: true,
        }),
        ...emptyDirectoryNames.map((directoryName) =>
            mkdir(path.join(failedRunDirectoryPath, directoryName), {
                recursive: true,
            }),
        ),
        mkdir(
            path.join(
                failedRunDirectoryPath,
                'attachments',
                'proof-storage-width-browser-evidence',
            ),
            { recursive: true },
        ),
        mkdir(
            path.join(
                failedRunDirectoryPath,
                'diagnostic-reports',
                'proof-storage-width-browser-evidence',
            ),
            { recursive: true },
        ),
    ]);
    const summary = `${JSON.stringify({
        exitCode: 1,
        failedCommandId: 'vitest-proof-storage-width-browser-evidence',
        repositoryCommitHash: commitHash,
        repositoryTreeDirty: false,
        resultClassification: 'runner-failure',
    })}\n`;
    const output =
        'Startup Error: The project name "chromium-proof-storage-width-evidence" was already defined.\n';
    const diagnostics = 'Fixture predecessor diagnostic.\n';
    const events = `${JSON.stringify({
        commandId: 'vitest-proof-storage-width-browser-evidence',
        eventType: 'command-finished',
    })}\n`;
    const metadata = `${JSON.stringify({ fixture: 'predecessor-metadata' })}\n`;
    const resources = `${JSON.stringify({
        eventType: 'resource-sample',
        processTreeResidentMemoryBytes: 1,
    })}\n`;
    const processGuard = [
        {
            eventType: 'guard-started',
            ioReadBytes: 0,
            ioWriteBytes: 0,
        },
        {
            eventType: 'resource-sample',
            ioReadBytes: 0,
            ioWriteBytes: 0,
        },
        {
            durationMilliseconds: 608,
            eventType: 'child-exited',
            exitCode: 1,
        },
    ]
        .map((record) => JSON.stringify(record))
        .join('\n');
    const processGuardWithTerminator = `${processGuard}\n`;
    const failedArtifacts = {
        diagnostics: {
            relativePath: 'diagnostics.txt',
            sha256Hex: sha256Hex(diagnostics),
        },
        events: {
            relativePath: 'events.jsonl',
            sha256Hex: sha256Hex(events),
        },
        metadata: {
            relativePath: 'metadata.json',
            sha256Hex: sha256Hex(metadata),
        },
        output: {
            relativePath: 'output.log',
            sha256Hex: sha256Hex(output),
        },
        processGuard: {
            relativePath:
                'resources/process-memory-guard-proof-storage-width-browser.jsonl',
            sha256Hex: sha256Hex(processGuardWithTerminator),
        },
        resources: {
            relativePath: 'resources.jsonl',
            sha256Hex: sha256Hex(resources),
        },
        summary: {
            relativePath: 'summary.json',
            sha256Hex: sha256Hex(summary),
        },
    } as const;
    await Promise.all([
        writeFile(
            path.join(
                failedRunDirectoryPath,
                failedArtifacts.diagnostics.relativePath,
            ),
            diagnostics,
            'utf8',
        ),
        writeFile(
            path.join(
                failedRunDirectoryPath,
                failedArtifacts.summary.relativePath,
            ),
            summary,
            'utf8',
        ),
        writeFile(
            path.join(
                failedRunDirectoryPath,
                failedArtifacts.output.relativePath,
            ),
            output,
            'utf8',
        ),
        writeFile(
            path.join(
                failedRunDirectoryPath,
                failedArtifacts.events.relativePath,
            ),
            events,
            'utf8',
        ),
        writeFile(
            path.join(
                failedRunDirectoryPath,
                failedArtifacts.metadata.relativePath,
            ),
            metadata,
            'utf8',
        ),
        writeFile(
            path.join(
                failedRunDirectoryPath,
                failedArtifacts.processGuard.relativePath,
            ),
            processGuardWithTerminator,
            'utf8',
        ),
        writeFile(
            path.join(
                failedRunDirectoryPath,
                failedArtifacts.resources.relativePath,
            ),
            resources,
            'utf8',
        ),
    ]);
    const failedReservationIdentitySha256Hex = '71'.repeat(32);
    const failedReservationRelativePath = `browser/${failedReservationIdentitySha256Hex}/browser-started.json`;
    const rawWasmSha256Hex = sha256Hex(
        await readFile(input.processedWasmKernelPath),
    );
    const nativeAggregateSha256Hex = sha256Hex(
        await readFile(input.nativeEvidencePath),
    );
    const failedReservation = [
        {
            eventType: 'official-browser-width-sample-started',
            identitySha256Hex: failedReservationIdentitySha256Hex,
            nativeAggregateSha256Hex,
            officialOwner: 'test:browser:proof-storage-width-evidence',
            rawWasmSha256Hex,
            recordedAtUnixMilliseconds: 100,
            sourceCommitHash: commitHash,
            width: 512,
        },
        {
            eventType: 'official-sample-outcome',
            failureName: 'Error',
            outcome: 'failed',
            recordedAtUnixMilliseconds: 200,
        },
    ]
        .map((record) => JSON.stringify(record))
        .join('\n');
    const failedReservationWithTerminator = `${failedReservation}\n`;
    const failedReservationPath = path.join(
        input.reservationRootPath,
        failedReservationRelativePath,
    );
    await mkdir(path.dirname(failedReservationPath), { recursive: true });
    await writeFile(
        failedReservationPath,
        failedReservationWithTerminator,
        'utf8',
    );
    const preOperationRecoveryProfile = {
        failedArtifacts,
        failedReservation: {
            identitySha256Hex: failedReservationIdentitySha256Hex,
            relativePath: failedReservationRelativePath,
            sha256Hex: sha256Hex(failedReservationWithTerminator),
        },
        failedRunDirectoryPath,
        nativeAggregateSha256Hex,
        nativeSourceCommitHash: commitHash,
        rawWasmSha256Hex,
        recoveryOrdinal: 1,
    } satisfies ProofStorageWidthBrowserPreOperationRecoveryProfile;
    const chainedRecoveryProfile = await createChainedRecoveryProfile({
        invocationPathSerializer: input.failedRecoveryInvocationPathSerializer,
        runDirectoryPathSerializer:
            input.failedRecoveryRunDirectoryPathSerializer,
        nativeEvidencePath: input.nativeEvidencePath,
        nativeEvidenceBindingPath: input.nativeEvidenceBindingPath,
        preOperationRecoveryProfile,
        reservationRootPath: input.reservationRootPath,
        runDirectoryPath: input.runDirectoryPath,
    });
    return Object.freeze({
        ...preOperationRecoveryProfile,
        chainedRecoveryProfile,
    });
};

const createChainedRecoveryProfile = async (input: {
    readonly invocationPathSerializer?: RecordedInvocationPathSerializer;
    readonly nativeEvidencePath: string;
    readonly nativeEvidenceBindingPath?: string;
    readonly preOperationRecoveryProfile: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    readonly reservationRootPath: string;
    readonly runDirectoryPathSerializer?: RecordedInvocationPathSerializer;
    readonly runDirectoryPath: string;
}): Promise<ProofStorageWidthBrowserChainedRecoveryProfile> => {
    const failedRecoveryRunDirectoryPath = path.join(
        path.dirname(input.runDirectoryPath),
        'failed-recovery-attempt',
    );
    await mkdir(failedRecoveryRunDirectoryPath);
    const diagnostics = 'Result: runner-failure\n';
    const events = [
        { eventType: 'run-started' },
        { eventType: 'run-heartbeat' },
        { eventType: 'heavy-lane-lease-acquired' },
        { eventType: 'heavy-lane-lease-released' },
        { eventType: 'run-finished' },
    ]
        .map((record) => JSON.stringify(record))
        .join('\n');
    const eventsWithTerminator = `${events}\n`;
    const metadata = `${JSON.stringify({
        commandLineArguments: [
            '--native-evidence',
            (input.invocationPathSerializer ?? exactRecordedInvocationPath)(
                input.nativeEvidenceBindingPath ??
                    path.resolve(input.nativeEvidencePath),
                1,
            ),
            '--pre-operation-recovery',
            (input.invocationPathSerializer ?? exactRecordedInvocationPath)(
                path.resolve(
                    input.preOperationRecoveryProfile.failedRunDirectoryPath,
                ),
                3,
            ),
        ],
        runDirectoryPath: (
            input.runDirectoryPathSerializer ?? exactRecordedInvocationPath
        )(path.resolve(failedRecoveryRunDirectoryPath), 1),
        scriptName: 'test:browser:proof-storage-width-evidence',
    })}\n`;
    const output = [
        'Acquired local guarded heavy-lane lease for Proof-storage width release WebAssembly evidence.',
        'Released local guarded heavy-lane lease for Proof-storage width release WebAssembly evidence.',
        '',
    ].join('\n');
    const resources = `${JSON.stringify({
        activeCommandIds: [],
        resourceScope: 'orchestration-process-and-host',
    })}\n`;
    const summary = `${JSON.stringify({
        error: {
            message:
                'Failed browser attachments directory must contain no prior operation artifact.',
            name: 'Error',
        },
        exitCode: 1,
        repositoryCommitHash: firstHarnessRepairCommitHash,
        repositoryTreeDirty: false,
        resultClassification: 'runner-failure',
    })}\n`;
    const failedRecoveryArtifacts = {
        diagnostics: {
            relativePath: 'diagnostics.txt',
            sha256Hex: sha256Hex(diagnostics),
        },
        events: {
            relativePath: 'events.jsonl',
            sha256Hex: sha256Hex(eventsWithTerminator),
        },
        metadata: {
            relativePath: 'metadata.json',
            sha256Hex: sha256Hex(metadata),
        },
        output: {
            relativePath: 'output.log',
            sha256Hex: sha256Hex(output),
        },
        resources: {
            relativePath: 'resources.jsonl',
            sha256Hex: sha256Hex(resources),
        },
        summary: {
            relativePath: 'summary.json',
            sha256Hex: sha256Hex(summary),
        },
    } as const;
    await Promise.all(
        [
            [failedRecoveryArtifacts.diagnostics.relativePath, diagnostics],
            [failedRecoveryArtifacts.events.relativePath, eventsWithTerminator],
            [failedRecoveryArtifacts.metadata.relativePath, metadata],
            [failedRecoveryArtifacts.output.relativePath, output],
            [failedRecoveryArtifacts.resources.relativePath, resources],
            [failedRecoveryArtifacts.summary.relativePath, summary],
        ].map(([relativePath, contents]) =>
            writeFile(
                path.join(failedRecoveryRunDirectoryPath, relativePath ?? ''),
                contents ?? '',
                'utf8',
            ),
        ),
    );
    const previousAuthorizationKeySha256Hex = sha256Hex(
        JSON.stringify({
            failedReservationIdentitySha256Hex:
                input.preOperationRecoveryProfile.failedReservation
                    .identitySha256Hex,
            formatVersion: 1,
            nativeAggregateSha256Hex:
                input.preOperationRecoveryProfile.nativeAggregateSha256Hex,
            nativeSourceCommitHash:
                input.preOperationRecoveryProfile.nativeSourceCommitHash,
            recoveryOrdinal: input.preOperationRecoveryProfile.recoveryOrdinal,
        }),
    );
    const previousPreflightAttemptRelativePath = path.join(
        'browser-recovery-preflight',
        previousAuthorizationKeySha256Hex,
        'preflight-attempted.json',
    );
    const previousPreflightAttempt = [
        {
            authorizationKeySha256Hex: previousAuthorizationKeySha256Hex,
            eventType: 'official-browser-width-recovery-preflight-attempted',
            failedReservationIdentitySha256Hex:
                input.preOperationRecoveryProfile.failedReservation
                    .identitySha256Hex,
            recordedAtUnixMilliseconds: 300,
            recoveryOrdinal: 1,
        },
        {
            eventType: 'official-sample-outcome',
            failureName: 'Error',
            outcome: 'failed',
            recordedAtUnixMilliseconds: 400,
        },
    ]
        .map((record) => JSON.stringify(record))
        .join('\n');
    const previousPreflightAttemptWithTerminator = `${previousPreflightAttempt}\n`;
    const previousPreflightAttemptPath = path.join(
        input.reservationRootPath,
        previousPreflightAttemptRelativePath,
    );
    await mkdir(path.dirname(previousPreflightAttemptPath), {
        recursive: true,
    });
    await writeFile(
        previousPreflightAttemptPath,
        previousPreflightAttemptWithTerminator,
        'utf8',
    );
    return {
        failedRecoveryArtifacts,
        failedRecoveryRunDirectoryPath: path.resolve(
            failedRecoveryRunDirectoryPath,
        ),
        failedRecoveryRunRelativePath: path
            .relative(path.resolve('.'), failedRecoveryRunDirectoryPath)
            .split(path.sep)
            .join('/'),
        firstHarnessRepairCommitHash,
        previousAuthorizationKeySha256Hex,
        previousPreflightAttempt: {
            relativePath: previousPreflightAttemptRelativePath
                .split(path.sep)
                .join('/'),
            sha256Hex: sha256Hex(previousPreflightAttemptWithTerminator),
        },
        recoveryOrdinal: 2,
        validatorRepairCommitHash,
    };
};

const createThirdRecoveryFixtureProfile = async (input: {
    readonly failedChainedRecoveryInvocationPathSerializer?: RecordedInvocationPathSerializer;
    readonly failedRecoveryInvocationPathSerializer?: RecordedInvocationPathSerializer;
    readonly failedChainedRecoveryRunDirectoryPathSerializer?: RecordedInvocationPathSerializer;
    readonly failedRecoveryRunDirectoryPathSerializer?: RecordedInvocationPathSerializer;
    readonly nativeEvidenceBindingPath?: string;
    readonly nativeEvidencePath: string;
    readonly processedWasmKernelPath: string;
    readonly reservationRootPath: string;
    readonly runDirectoryPath: string;
}): Promise<TestThirdRecoveryProfile> => {
    const preOperationRecoveryProfile = await createPreOperationRecoveryProfile(
        {
            failedRecoveryInvocationPathSerializer:
                input.failedRecoveryInvocationPathSerializer,
            failedRecoveryRunDirectoryPathSerializer:
                input.failedRecoveryRunDirectoryPathSerializer,
            nativeEvidencePath: input.nativeEvidencePath,
            nativeEvidenceBindingPath: input.nativeEvidenceBindingPath,
            processedWasmKernelPath: input.processedWasmKernelPath,
            reservationRootPath: input.reservationRootPath,
            runDirectoryPath: input.runDirectoryPath,
        },
    );
    const failedChainedRecoveryRunDirectoryPath = path.join(
        path.dirname(input.runDirectoryPath),
        'failed-chained-recovery-attempt',
    );
    await mkdir(failedChainedRecoveryRunDirectoryPath);
    const diagnostics = 'Result: runner-failure\n';
    const events = [
        { eventType: 'run-started' },
        { eventType: 'heavy-lane-lease-waiting' },
        { eventType: 'run-heartbeat' },
        { eventType: 'heavy-lane-lease-acquired' },
        { eventType: 'heavy-lane-lease-released' },
        { eventType: 'run-finished' },
    ]
        .map((record) => JSON.stringify(record))
        .join('\n');
    const eventsWithTerminator = `${events}\n`;
    const invocationPathSerializer =
        input.failedChainedRecoveryInvocationPathSerializer ??
        exactRecordedInvocationPath;
    const metadata = `${JSON.stringify({
        commandLineArguments: [
            '--native-evidence',
            invocationPathSerializer(
                input.nativeEvidenceBindingPath ??
                    path.resolve(input.nativeEvidencePath),
                1,
            ),
            '--pre-operation-recovery',
            invocationPathSerializer(
                path.resolve(
                    preOperationRecoveryProfile.failedRunDirectoryPath,
                ),
                3,
            ),
            '--failed-recovery-attempt',
            invocationPathSerializer(
                path.resolve(
                    preOperationRecoveryProfile.chainedRecoveryProfile
                        .failedRecoveryRunDirectoryPath,
                ),
                5,
            ),
        ],
        runDirectoryPath: (
            input.failedChainedRecoveryRunDirectoryPathSerializer ??
            exactRecordedInvocationPath
        )(path.resolve(failedChainedRecoveryRunDirectoryPath), 1),
        scriptName: 'test:browser:proof-storage-width-evidence',
    })}\n`;
    const output = [
        'Waiting for local guarded heavy-lane lease for Proof-storage width release WebAssembly evidence.',
        'Acquired local guarded heavy-lane lease for Proof-storage width release WebAssembly evidence.',
        'Released local guarded heavy-lane lease for Proof-storage width release WebAssembly evidence.',
        '',
    ].join('\n');
    const resources = `${JSON.stringify({
        activeCommandIds: [],
        resourceScope: 'orchestration-process-and-host',
    })}\n`;
    const summary = `${JSON.stringify({
        error: {
            message:
                'The failed recovery metadata changed its exact predecessor invocation.',
            name: 'Error',
        },
        exitCode: 1,
        repositoryCommitHash: thirdRecoveryIssuanceCommitHash,
        repositoryTreeDirty: false,
        resultClassification: 'runner-failure',
    })}\n`;
    const failedChainedRecoveryArtifacts = {
        diagnostics: {
            relativePath: 'diagnostics.txt',
            sha256Hex: sha256Hex(diagnostics),
        },
        events: {
            relativePath: 'events.jsonl',
            sha256Hex: sha256Hex(eventsWithTerminator),
        },
        metadata: {
            relativePath: 'metadata.json',
            sha256Hex: sha256Hex(metadata),
        },
        output: {
            relativePath: 'output.log',
            sha256Hex: sha256Hex(output),
        },
        resources: {
            relativePath: 'resources.jsonl',
            sha256Hex: sha256Hex(resources),
        },
        summary: {
            relativePath: 'summary.json',
            sha256Hex: sha256Hex(summary),
        },
    } as const;
    await Promise.all(
        [
            [
                failedChainedRecoveryArtifacts.diagnostics.relativePath,
                diagnostics,
            ],
            [
                failedChainedRecoveryArtifacts.events.relativePath,
                eventsWithTerminator,
            ],
            [failedChainedRecoveryArtifacts.metadata.relativePath, metadata],
            [failedChainedRecoveryArtifacts.output.relativePath, output],
            [failedChainedRecoveryArtifacts.resources.relativePath, resources],
            [failedChainedRecoveryArtifacts.summary.relativePath, summary],
        ].map(([relativePath, contents]) =>
            writeFile(
                path.join(
                    failedChainedRecoveryRunDirectoryPath,
                    relativePath ?? '',
                ),
                contents ?? '',
                'utf8',
            ),
        ),
    );
    const chainedRecoveryProfile =
        preOperationRecoveryProfile.chainedRecoveryProfile;
    const previousChainedAuthorizationKeySha256Hex = sha256Hex(
        JSON.stringify(
            normalizeTestJsonValue({
                failedRecoveryArtifacts:
                    chainedRecoveryProfile.failedRecoveryArtifacts,
                failedRecoveryRunRelativePath:
                    chainedRecoveryProfile.failedRecoveryRunRelativePath,
                formatVersion: 2,
                nativeAggregateSha256Hex:
                    preOperationRecoveryProfile.nativeAggregateSha256Hex,
                nativeSourceCommitHash:
                    preOperationRecoveryProfile.nativeSourceCommitHash,
                previousAuthorizationKeySha256Hex:
                    chainedRecoveryProfile.previousAuthorizationKeySha256Hex,
                previousPreflightAttemptSha256Hex:
                    chainedRecoveryProfile.previousPreflightAttempt.sha256Hex,
                recoveryOrdinal: chainedRecoveryProfile.recoveryOrdinal,
                validatorRepairCommitHash:
                    chainedRecoveryProfile.validatorRepairCommitHash,
                width: 512,
            }),
        ),
    );
    const previousChainedPreflightAttemptRelativePath = path.join(
        'browser-recovery-preflight-2',
        previousChainedAuthorizationKeySha256Hex,
        'preflight-attempted.json',
    );
    const previousChainedPreflightAttempt = [
        {
            authorizationKeySha256Hex: previousChainedAuthorizationKeySha256Hex,
            eventType: 'official-browser-width-recovery-preflight-attempted',
            failedReservationIdentitySha256Hex:
                preOperationRecoveryProfile.failedReservation.identitySha256Hex,
            previousAuthorizationKeySha256Hex:
                chainedRecoveryProfile.previousAuthorizationKeySha256Hex,
            previousPreflightAttemptSha256Hex:
                chainedRecoveryProfile.previousPreflightAttempt.sha256Hex,
            recordedAtUnixMilliseconds: 500,
            recoveryOrdinal: 2,
        },
        {
            eventType: 'official-sample-outcome',
            failureName: 'Error',
            outcome: 'failed',
            recordedAtUnixMilliseconds: 600,
        },
    ]
        .map((record) => JSON.stringify(record))
        .join('\n');
    const previousChainedPreflightAttemptWithTerminator = `${previousChainedPreflightAttempt}\n`;
    const previousChainedPreflightAttemptPath = path.join(
        input.reservationRootPath,
        previousChainedPreflightAttemptRelativePath,
    );
    await mkdir(path.dirname(previousChainedPreflightAttemptPath), {
        recursive: true,
    });
    await writeFile(
        previousChainedPreflightAttemptPath,
        previousChainedPreflightAttemptWithTerminator,
        'utf8',
    );
    const thirdRecoveryProfile = {
        failedChainedRecoveryArtifacts,
        failedChainedRecoveryRunDirectoryPath: path.resolve(
            failedChainedRecoveryRunDirectoryPath,
        ),
        failedChainedRecoveryRunRelativePath: path
            .relative(path.resolve('.'), failedChainedRecoveryRunDirectoryPath)
            .split(path.sep)
            .join('/'),
        issuanceCommitHash: thirdRecoveryIssuanceCommitHash,
        previousChainedAuthorizationKeySha256Hex,
        previousChainedPreflightAttempt: {
            relativePath: previousChainedPreflightAttemptRelativePath
                .split(path.sep)
                .join('/'),
            sha256Hex: sha256Hex(previousChainedPreflightAttemptWithTerminator),
        },
        recoveryOrdinal: 3,
    } satisfies ProofStorageWidthBrowserThirdRecoveryProfile;
    return Object.freeze({
        ...preOperationRecoveryProfile,
        thirdRecoveryProfile,
    });
};

const recoveryExecutionPaths = (
    profile: TestRecoveryProfile,
): Readonly<{
    failedRecoveryAttemptRunDirectoryPath: string;
    preOperationRecoveryRunDirectoryPath: string;
}> => ({
    failedRecoveryAttemptRunDirectoryPath:
        profile.chainedRecoveryProfile.failedRecoveryRunDirectoryPath,
    preOperationRecoveryRunDirectoryPath: profile.failedRunDirectoryPath,
});

const thirdRecoveryExecutionPaths = (
    profile: TestThirdRecoveryProfile,
): Readonly<{
    failedChainedRecoveryAttemptRunDirectoryPath: string;
    failedRecoveryAttemptRunDirectoryPath: string;
    preOperationRecoveryRunDirectoryPath: string;
}> => ({
    failedChainedRecoveryAttemptRunDirectoryPath:
        profile.thirdRecoveryProfile.failedChainedRecoveryRunDirectoryPath,
    failedRecoveryAttemptRunDirectoryPath:
        profile.chainedRecoveryProfile.failedRecoveryRunDirectoryPath,
    preOperationRecoveryRunDirectoryPath: profile.failedRunDirectoryPath,
});

const createDependencies = (input: {
    readonly allInvocations?: CommandInvocation[];
    readonly browserRecoveryMarkerFaultInjection?: ProofStorageWidthBrowserEvidenceDependencies['browserRecoveryMarkerFaultInjection'];
    readonly chainedRecoveryProfile?: ProofStorageWidthBrowserChainedRecoveryProfile;
    readonly driftNativeEvidenceAtLoadCount?: number;
    readonly driftNativeEvidenceDuringAttachmentValidation?: boolean;
    readonly failGuardedSample?: boolean;
    readonly fixture: {
        readonly nativeEvidencePath: string;
        readonly processedWasmKernelPath: string;
        readonly publicSdkWasmKernelPath: string;
        readonly reservationRootPath: string;
        readonly runDirectoryPath: string;
    };
    readonly fullWidthExternalIoByteLength?: bigint;
    readonly nativeEvidenceBindingPath?: string;
    readonly nativeEvidenceLoadCounts?: number[];
    readonly repositoryStateForCheckpoint?: (
        checkpoint:
            | 'after'
            | 'before'
            | 'closure-after'
            | 'initial'
            | 'pre-operation',
    ) => Readonly<{ commitHash: string; treeDirty: boolean }>;
    readonly sampleInvocations: CommandInvocation[];
    readonly preOperationRecoveryProfile?: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    readonly staticPreflightStderr?: string;
    readonly staticPreflightStdout?: string;
    readonly transitionChangedFilePaths?: readonly string[];
    readonly transitionChangedFileStatuses?: readonly string[];
    readonly transitionCommitObject?: string;
    readonly transitionOverrideCommitHash?: string;
    readonly thirdRecoveryProfile?: ProofStorageWidthBrowserThirdRecoveryProfile;
}): ProofStorageWidthBrowserEvidenceDependencies => {
    let nativeEvidence: NativeWidthEvidence | undefined;
    let nativeEvidenceLoadCount = 0;
    return {
        ...(input.browserRecoveryMarkerFaultInjection === undefined
            ? {}
            : {
                  browserRecoveryMarkerFaultInjection:
                      input.browserRecoveryMarkerFaultInjection,
              }),
        executeCommand: async (invocation) => {
            input.allInvocations?.push(invocation);
            if (
                invocation.command === 'git' &&
                invocation.args.length === 3 &&
                invocation.args[0] === 'rev-parse' &&
                invocation.args[1] === '--verify' &&
                invocation.args[2] === 'HEAD^{commit}'
            ) {
                return {
                    ...successfulCommandResult(),
                    stdout: `${
                        input.repositoryStateForCheckpoint?.('initial')
                            .commitHash ?? commitHash
                    }\n`,
                };
            }
            if (
                invocation.command === 'git' &&
                invocation.args.length === 4 &&
                invocation.args[0] === 'status' &&
                invocation.args[1] === '--porcelain=v1' &&
                invocation.args[2] === '--untracked-files=all' &&
                invocation.args[3] === '--ignore-submodules=none'
            ) {
                return {
                    ...successfulCommandResult(),
                    stdout:
                        input.repositoryStateForCheckpoint?.('initial')
                            .treeDirty === true
                            ? ' M synthetic-dirty-path\n'
                            : '',
                };
            }
            if (invocation.args.includes('cat-file')) {
                const childCommitHash =
                    invocation.args[invocation.args.length - 1];
                const parentCommitHash =
                    childCommitHash === firstHarnessRepairCommitHash
                        ? commitHash
                        : childCommitHash === validatorRepairCommitHash
                          ? firstHarnessRepairCommitHash
                          : childCommitHash ===
                              thirdRecoveryFinalHarnessCommitHash
                            ? thirdRecoveryIssuanceCommitHash
                            : validatorRepairCommitHash;
                const commitObject =
                    childCommitHash ===
                        (input.transitionOverrideCommitHash ??
                            recoveryHarnessCommitHash) &&
                    input.transitionCommitObject !== undefined
                        ? input.transitionCommitObject
                        : [
                              `tree ${'7a'.repeat(20)}`,
                              `parent ${parentCommitHash}`,
                              'author Test Author <test@example.invalid> 1 +0000',
                              'committer Test Author <test@example.invalid> 1 +0000',
                              '',
                              'test repair commit',
                              '',
                          ].join('\n');
                return {
                    ...successfulCommandResult(),
                    stdout: commitObject,
                };
            }
            if (invocation.args.includes('diff')) {
                const childTree = invocation.args[invocation.args.length - 2];
                const childCommitHash = childTree?.endsWith('^{tree}')
                    ? childTree.slice(0, -'^{tree}'.length)
                    : childTree;
                const changedFilePaths =
                    childCommitHash ===
                    (input.transitionOverrideCommitHash ??
                        recoveryHarnessCommitHash)
                        ? (input.transitionChangedFilePaths ??
                          (childCommitHash === firstHarnessRepairCommitHash
                              ? recoveryRepairFilePaths
                              : validatorRepairFilePaths))
                        : childCommitHash === firstHarnessRepairCommitHash
                          ? recoveryRepairFilePaths
                          : childCommitHash === validatorRepairCommitHash
                            ? validatorRepairFilePaths
                            : (input.transitionChangedFilePaths ??
                              validatorRepairFilePaths);
                const changedFileStatuses =
                    childCommitHash ===
                        (input.transitionOverrideCommitHash ??
                            recoveryHarnessCommitHash) &&
                    input.transitionChangedFileStatuses !== undefined
                        ? input.transitionChangedFileStatuses
                        : changedFilePaths.map(() => 'M');
                return {
                    ...successfulCommandResult(),
                    stdout: `${changedFilePaths
                        .flatMap((filePath, fileIndex) => [
                            changedFileStatuses[fileIndex] ?? 'M',
                            filePath,
                        ])
                        .join('\0')}\0`,
                };
            }
            if (
                invocation.args.some((argument) => argument === 'list') &&
                invocation.args.some((argument) => argument === '--staticParse')
            ) {
                return {
                    ...successfulCommandResult(),
                    stderr: input.staticPreflightStderr ?? '',
                    stdout:
                        input.staticPreflightStdout ??
                        browserEvidenceStaticPreflightOutput,
                };
            }
            if (invocation.command === 'test-process-memory-guard') {
                input.sampleInvocations.push(invocation);
                const diagnosticsArgumentIndex =
                    invocation.args.indexOf('--diagnostics-path');
                const diagnosticsPath =
                    invocation.args[diagnosticsArgumentIndex + 1];
                if (diagnosticsPath === undefined) {
                    throw new Error('The guarded sample omitted diagnostics.');
                }
                const wasmSha256Hex =
                    invocation.env?.[expectedWasmHashEnvironmentVariable];
                if (wasmSha256Hex === undefined) {
                    throw new Error(
                        'The guarded sample omitted its WASM hash.',
                    );
                }
                const eventPath = path.join(
                    input.fixture.runDirectoryPath,
                    'tests',
                    'proof-storage-width-browser-evidence.jsonl',
                );
                await Promise.all([
                    mkdir(path.dirname(diagnosticsPath), { recursive: true }),
                    mkdir(path.dirname(eventPath), { recursive: true }),
                ]);
                await Promise.all([
                    writeFile(diagnosticsPath, buildGuardJsonLines(), 'utf8'),
                    writeFile(
                        eventPath,
                        `${JSON.stringify({
                            event: 'proof-storage-width-browser-evidence',
                            ...createMeasurementRecord(wasmSha256Hex),
                            browser: true,
                        })}\n`,
                        'utf8',
                    ),
                ]);
                if (input.failGuardedSample === true) {
                    return failedCommandResult();
                }
            }
            return successfulCommandResult();
        },
        loadNativeWidthEvidence: async () => {
            nativeEvidenceLoadCount += 1;
            input.nativeEvidenceLoadCounts?.push(nativeEvidenceLoadCount);
            nativeEvidence ??= await createNativeEvidence({
                ...(input.fullWidthExternalIoByteLength === undefined
                    ? {}
                    : {
                          fullWidthExternalIoByteLength:
                              input.fullWidthExternalIoByteLength,
                      }),
                measurementRecord: createMeasurementRecord(
                    sha256Hex(
                        await readFile(input.fixture.processedWasmKernelPath),
                    ),
                ),
                ...(input.nativeEvidenceBindingPath === undefined
                    ? {}
                    : { evidencePath: input.nativeEvidenceBindingPath }),
                nativeEvidencePath: input.fixture.nativeEvidencePath,
            });
            return (input.driftNativeEvidenceDuringAttachmentValidation ===
                true &&
                nativeEvidenceLoadCount > 1) ||
                nativeEvidenceLoadCount === input.driftNativeEvidenceAtLoadCount
                ? {
                      ...nativeEvidence,
                      evidenceSha256Hex: '5c'.repeat(32),
                  }
                : nativeEvidence;
        },
        ...((input.chainedRecoveryProfile ??
            (input.preOperationRecoveryProfile !== undefined &&
            'chainedRecoveryProfile' in input.preOperationRecoveryProfile
                ? input.preOperationRecoveryProfile.chainedRecoveryProfile
                : undefined)) === undefined
            ? {}
            : {
                  chainedRecoveryProfile:
                      input.chainedRecoveryProfile ??
                      (input.preOperationRecoveryProfile as TestRecoveryProfile)
                          .chainedRecoveryProfile,
              }),
        ...((input.thirdRecoveryProfile ??
            (input.preOperationRecoveryProfile !== undefined &&
            'thirdRecoveryProfile' in input.preOperationRecoveryProfile
                ? input.preOperationRecoveryProfile.thirdRecoveryProfile
                : undefined)) === undefined
            ? {}
            : {
                  thirdRecoveryProfile:
                      input.thirdRecoveryProfile ??
                      (
                          input.preOperationRecoveryProfile as TestThirdRecoveryProfile
                      ).thirdRecoveryProfile,
              }),
        officialReservationRootPath: input.fixture.reservationRootPath,
        ...(input.preOperationRecoveryProfile === undefined
            ? {}
            : {
                  preOperationRecoveryProfile:
                      input.preOperationRecoveryProfile,
              }),
        processMemoryGuard: createProcessMemoryGuard(),
        processedWasmKernelPath: input.fixture.processedWasmKernelPath,
        publicSdkWasmKernelPath: input.fixture.publicSdkWasmKernelPath,
        readRepositoryState: (checkpoint) =>
            Promise.resolve(
                input.repositoryStateForCheckpoint?.(checkpoint) ?? {
                    commitHash,
                    treeDirty: false,
                },
            ),
    };
};

const snapshotDirectoryCustody = async (
    rootPath: string,
): Promise<readonly string[]> => {
    const records: string[] = [];
    const visit = async (
        directoryPath: string,
        relativeDirectoryPath: string,
    ): Promise<void> => {
        const entries = await readdir(directoryPath, { withFileTypes: true });
        for (const entry of entries.sort((left, right) =>
            left.name.localeCompare(right.name),
        )) {
            const entryPath = path.join(directoryPath, entry.name);
            const relativeEntryPath = path
                .join(relativeDirectoryPath, entry.name)
                .split(path.sep)
                .join('/');
            if (entry.isDirectory()) {
                records.push(`directory:${relativeEntryPath}`);
                await visit(entryPath, relativeEntryPath);
            } else if (entry.isFile()) {
                const bytes = await readFile(entryPath);
                records.push(
                    `file:${relativeEntryPath}:${bytes.byteLength}:${sha256Hex(bytes)}`,
                );
            } else {
                records.push(`other:${relativeEntryPath}`);
            }
        }
    };
    try {
        await visit(rootPath, '');
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'ENOENT'
        ) {
            return Object.freeze(['absent']);
        }
        throw error;
    }
    return Object.freeze(records);
};

const resolveOnlyThirdRecoveryKeyDirectoryPath = async (
    reservationRootPath: string,
): Promise<string> => {
    const preflightRootPath = path.join(
        reservationRootPath,
        'browser-recovery-preflight-3',
    );
    const entries = await readdir(preflightRootPath, { withFileTypes: true });
    const keyDirectories = entries.filter(
        (entry) => entry.isDirectory() && /^[0-9a-f]{64}$/u.test(entry.name),
    );
    if (keyDirectories.length !== 1) {
        throw new Error(
            `Expected one third-recovery key directory, observed ${keyDirectories.length}.`,
        );
    }
    return path.join(preflightRootPath, keyDirectories[0]?.name ?? '');
};

const expectNoUnpublishedRecoveryRecordEntries = async (
    preflightRootPath: string,
    assertionLabel: string,
): Promise<void> => {
    const custody = await snapshotDirectoryCustody(preflightRootPath);
    expect(
        custody.filter((entry) =>
            entry.includes('.unpublished-recovery-record-'),
        ),
        assertionLabel,
    ).toEqual([]);
};

const readRecoveryMarker = (
    reservationRootPath: string,
    relativePath: string,
): Promise<Buffer> => readFile(path.join(reservationRootPath, relativePath));

const readThirdRecoveryMarkerForTest = async (
    reservationRootPath: string,
): Promise<
    Readonly<{
        authorizationKeySha256Hex: string;
        records: readonly Record<string, unknown>[];
        rootPath: string;
        serialized: string;
        terminalDirectoryPath?: string;
        terminalRecordBytes?: Buffer;
    }>
> => {
    const preflightRootPath = path.join(
        reservationRootPath,
        'browser-recovery-preflight-3',
    );
    const authorizationDirectories = await readdir(preflightRootPath);
    expect(authorizationDirectories).toHaveLength(1);
    const authorizationKeySha256Hex = authorizationDirectories[0] ?? '';
    const rootPath = path.join(preflightRootPath, authorizationKeySha256Hex);
    const attemptedBytes = await readFile(
        path.join(rootPath, 'preflight-attempted', 'record.json'),
    );
    const staticRecordPath = path.join(
        rootPath,
        'static-preflight-observed',
        'record.json',
    );
    const terminalDirectoryPath = path.join(rootPath, 'terminal-outcome');
    const terminalRecordPath = path.join(terminalDirectoryPath, 'record.json');
    const readOptional = (filePath: string): Promise<Buffer | undefined> =>
        readFile(filePath).catch((error: unknown) => {
            if (
                typeof error === 'object' &&
                error !== null &&
                'code' in error &&
                error.code === 'ENOENT'
            ) {
                return undefined;
            }
            throw error;
        });
    const [staticBytes, terminalRecordBytes] = await Promise.all([
        readOptional(staticRecordPath),
        readOptional(terminalRecordPath),
    ]);
    const serialized = Buffer.concat([
        attemptedBytes,
        ...(staticBytes === undefined ? [] : [staticBytes]),
        ...(terminalRecordBytes === undefined ? [] : [terminalRecordBytes]),
    ]).toString('utf8');
    return Object.freeze({
        authorizationKeySha256Hex,
        records: Object.freeze(
            serialized
                .trim()
                .split('\n')
                .map((line) => JSON.parse(line) as Record<string, unknown>),
        ),
        rootPath,
        serialized,
        ...(terminalRecordBytes === undefined
            ? {}
            : { terminalDirectoryPath, terminalRecordBytes }),
    });
};

describe('Proof-storage width browser evidence runner', () => {
    it('pins a nonmeasurement static list and preserves the child selector for the zero-retry operation', () => {
        expect(
            proofStorageWidthBrowserEvidenceStaticPreflightArguments,
        ).toEqual([
            'exec',
            'vitest',
            'list',
            '--staticParse',
            '--filesOnly',
            '--project',
            'chromium-proof-storage-width-evidence',
            browserEvidenceTestFile,
        ]);
        expect(
            proofStorageWidthBrowserEvidenceStaticPreflightArguments,
        ).not.toContain('--run');
        expect(proofStorageWidthBrowserEvidenceVitestArguments).toEqual([
            'exec',
            'vitest',
            '--project',
            'chromium-proof-storage-width-evidence',
            '--run',
            browserEvidenceTestFile,
            '--retry=0',
        ]);
        expect(
            parseProofStorageWidthBrowserStaticPreflightOutput(
                browserEvidenceStaticPreflightOutput,
            ),
        ).toBe(browserEvidenceTestFile);
        for (const invalidOutput of [
            '',
            'tests/node/unrelated.test.ts\n',
            `[browser-proof-storage-width-evidence] ${browserEvidenceTestFile}\n`,
            `${browserEvidenceStaticPreflightOutput}${browserEvidenceStaticPreflightOutput}`,
        ]) {
            expect(() =>
                parseProofStorageWidthBrowserStaticPreflightOutput(
                    invalidOutput,
                ),
            ).toThrow(/exactly the fixed evidence test file/u);
        }
    });

    it('parses only the absolute native path and both chained-recovery predecessors', () => {
        const nativeEvidencePath = path.resolve('native-evidence.json');
        const failedRunDirectoryPath = path.resolve('failed-run');
        const failedRecoveryAttemptRunDirectoryPath = path.resolve(
            'failed-recovery-attempt',
        );
        const failedChainedRecoveryAttemptRunDirectoryPath = path.resolve(
            'failed-chained-recovery-attempt',
        );
        expect(
            parseProofStorageWidthBrowserEvidenceArguments([
                '--native-evidence',
                nativeEvidencePath,
            ]),
        ).toEqual({ nativeEvidencePath });
        expect(
            parseProofStorageWidthBrowserEvidenceArguments([
                '--native-evidence',
                nativeEvidencePath,
                '--pre-operation-recovery',
                failedRunDirectoryPath,
            ]),
        ).toEqual({
            nativeEvidencePath,
            preOperationRecoveryRunDirectoryPath: failedRunDirectoryPath,
        });
        expect(
            parseProofStorageWidthBrowserEvidenceArguments([
                '--native-evidence',
                nativeEvidencePath,
                '--pre-operation-recovery',
                failedRunDirectoryPath,
                '--failed-recovery-attempt',
                failedRecoveryAttemptRunDirectoryPath,
            ]),
        ).toEqual({
            failedRecoveryAttemptRunDirectoryPath,
            nativeEvidencePath,
            preOperationRecoveryRunDirectoryPath: failedRunDirectoryPath,
        });
        const ordinalThreeArguments = [
            '--native-evidence',
            nativeEvidencePath,
            '--pre-operation-recovery',
            failedRunDirectoryPath,
            '--failed-recovery-attempt',
            failedRecoveryAttemptRunDirectoryPath,
            '--failed-chained-recovery-attempt',
            failedChainedRecoveryAttemptRunDirectoryPath,
        ];
        expect(
            parseProofStorageWidthBrowserEvidenceArguments(
                ordinalThreeArguments,
            ),
        ).toEqual({
            failedChainedRecoveryAttemptRunDirectoryPath,
            failedRecoveryAttemptRunDirectoryPath,
            nativeEvidencePath,
            preOperationRecoveryRunDirectoryPath: failedRunDirectoryPath,
        });
        expect(
            parseProofStorageWidthBrowserEvidenceArguments([
                ...ordinalThreeArguments,
                '--recovery-chain-dry-run',
            ]),
        ).toEqual({
            failedChainedRecoveryAttemptRunDirectoryPath,
            failedRecoveryAttemptRunDirectoryPath,
            nativeEvidencePath,
            preOperationRecoveryRunDirectoryPath: failedRunDirectoryPath,
            recoveryChainDryRun: true,
        });
        for (const invalidArguments of [
            ['--native-evidence', 'relative.json'],
            [
                '--native-evidence',
                nativeEvidencePath,
                '--pre-operation-recovery',
                'relative-run',
                '--failed-recovery-attempt',
                failedRecoveryAttemptRunDirectoryPath,
            ],
            [
                '--native-evidence',
                nativeEvidencePath,
                '--failed-recovery-attempt',
                failedRecoveryAttemptRunDirectoryPath,
            ],
            [
                '--pre-operation-recovery',
                failedRunDirectoryPath,
                '--native-evidence',
                nativeEvidencePath,
            ],
            [
                '--native-evidence',
                nativeEvidencePath,
                '--pre-operation-recovery',
                failedRunDirectoryPath,
                '--failed-chained-recovery-attempt',
                failedChainedRecoveryAttemptRunDirectoryPath,
            ],
            [...ordinalThreeArguments, '--recovery-chain-dry-run', 'extra'],
            [
                ...ordinalThreeArguments.slice(0, 2),
                '--recovery-chain-dry-run',
                ...ordinalThreeArguments.slice(2),
            ],
            [
                ...ordinalThreeArguments,
                '--recovery-chain-dry-run',
                '--recovery-chain-dry-run',
            ],
        ]) {
            expect(() =>
                parseProofStorageWidthBrowserEvidenceArguments(
                    invalidArguments,
                ),
            ).toThrow(/every path must be absolute/u);
        }
    });

    it('compares the complete immutable predecessor invocation without weakening flags, roots, or lexical custody', () => {
        const failedRunDirectoryPath = 'C:\\custody\\metadata-run';
        const metadataForInvocation = (
            commandLineArguments: readonly string[],
        ): Readonly<Record<string, unknown>> => ({
            commandLineArguments,
            runDirectoryPath: failedRunDirectoryPath,
            scriptName: 'test:browser:proof-storage-width-evidence',
        });
        const acceptedPairs = [
            ['C:\\custody\\failed-run', 'C:\\\\custody//failed-run'],
            [
                '\\\\server\\share\\custody\\failed-run',
                '//server/share//custody\\\\failed-run',
            ],
            [
                '\\\\?\\C:\\custody\\failed-run',
                '\\\\?\\C:\\custody\\failed-run',
            ],
            [
                '\\\\.\\C:\\custody\\failed-run',
                '\\\\.\\C:\\custody\\failed-run',
            ],
        ] as const;
        for (const pathArgumentIndex of [1, 3, 5] as const) {
            for (const [expectedPath, observedPath] of acceptedPairs) {
                const expected = [
                    '--native-evidence',
                    expectedPath,
                    '--pre-operation-recovery',
                    expectedPath,
                    '--failed-recovery-attempt',
                    expectedPath,
                ];
                const observed = [...expected];
                observed[pathArgumentIndex] = observedPath;
                expect(
                    immutableFailedRunMetadataInvocationEquals({
                        observed: metadataForInvocation(observed),
                        profile: {
                            failedRecoveryAttemptRunDirectoryPath: expectedPath,
                            failedRunDirectoryPath,
                            nativeEvidencePath: expectedPath,
                            preOperationRecoveryRunDirectoryPath: expectedPath,
                            recoveryOrdinal: 2,
                        },
                    }),
                    `accepted argument ${pathArgumentIndex}: ${observedPath}`,
                ).toBe(true);
            }
        }
        const rejectedPairs = [
            ['C:\\custody\\failed-run', 'D:\\custody\\failed-run'],
            ['C:\\custody\\failed-run', 'c:\\Custody\\failed-run'],
            ['C:\\custody\\failed-run', 'C:\\custody\\.\\failed-run'],
            ['C:\\custody\\failed-run', 'C:\\custody\\..\\failed-run'],
            ['C:\\custody\\failed-run', 'C:\\custody\\failed-run\\'],
            ['C:\\custody\\failed-run', 'C:\\custody\\failed-run:stream'],
            ['C:\\custody\\failed-run', 'C:\\custody\\failed-rún'],
            ['C:\\custody\\failed-run', 'C:\\custody\\failed-run '],
            [
                '\\\\server\\share\\custody\\failed-run',
                '\\\\server\\other-share\\custody\\failed-run',
            ],
            [
                '\\\\server\\share\\custody\\failed-run',
                '\\\\\\server\\share\\custody\\failed-run',
            ],
            [
                '\\\\?\\C:\\custody\\failed-run',
                '\\\\?\\C:\\\\custody\\failed-run',
            ],
            ['\\\\.\\C:\\custody\\failed-run', '\\\\.\\C:/custody\\failed-run'],
        ] as const;
        for (const pathArgumentIndex of [1, 3, 5] as const) {
            for (const [expectedPath, observedPath] of rejectedPairs) {
                const expected = [
                    '--native-evidence',
                    expectedPath,
                    '--pre-operation-recovery',
                    expectedPath,
                    '--failed-recovery-attempt',
                    expectedPath,
                ];
                const observed = [...expected];
                observed[pathArgumentIndex] = observedPath;
                expect(
                    immutableFailedRunMetadataInvocationEquals({
                        observed: metadataForInvocation(observed),
                        profile: {
                            failedRecoveryAttemptRunDirectoryPath: expectedPath,
                            failedRunDirectoryPath,
                            nativeEvidencePath: expectedPath,
                            preOperationRecoveryRunDirectoryPath: expectedPath,
                            recoveryOrdinal: 2,
                        },
                    }),
                    `rejected argument ${pathArgumentIndex}: ${observedPath}`,
                ).toBe(false);
            }
        }
        const exactInvocation = [
            '--native-evidence',
            'C:\\custody\\native.json',
            '--pre-operation-recovery',
            'C:\\custody\\failed-run',
            '--failed-recovery-attempt',
            'C:\\custody\\failed-recovery',
        ];
        for (const observed of [
            exactInvocation.slice(0, -1),
            [...exactInvocation, 'extra'],
            [
                '--pre-operation-recovery',
                exactInvocation[1],
                '--native-evidence',
                exactInvocation[3],
                '--failed-recovery-attempt',
                exactInvocation[5],
            ],
            ['--native', ...exactInvocation.slice(1)],
        ]) {
            expect(
                immutableFailedRunMetadataInvocationEquals({
                    observed: metadataForInvocation(observed),
                    profile: {
                        failedRecoveryAttemptRunDirectoryPath:
                            exactInvocation[5] ?? '',
                        failedRunDirectoryPath,
                        nativeEvidencePath: exactInvocation[1] ?? '',
                        preOperationRecoveryRunDirectoryPath:
                            exactInvocation[3] ?? '',
                        recoveryOrdinal: 2,
                    },
                }),
            ).toBe(false);
        }
    });

    it('accepts complete failed-launch records with every drive path separator doubled or mixed at once', () => {
        const canonicalPaths = [
            'C:\\custody\\native-evidence.json',
            'C:\\custody\\failed-run',
            'C:\\custody\\failed-recovery-attempt',
        ] as const;
        const serializeAllPaths = (
            invocation: readonly string[],
            style: 'doubled' | 'mixed',
        ): readonly string[] =>
            invocation.map((argument, argumentIndex) => {
                if (![1, 3, 5].includes(argumentIndex)) {
                    return argument;
                }
                const [driveRoot, ...segments] = argument.split('\\');
                return `${driveRoot}${
                    style === 'doubled' ? '\\\\' : '//'
                }${segments
                    .map((segment, segmentIndex) =>
                        segmentIndex === 0
                            ? segment
                            : `${
                                  style === 'doubled'
                                      ? '\\\\'
                                      : segmentIndex % 2 === 0
                                        ? '//'
                                        : '\\\\'
                              }${segment}`,
                    )
                    .join('')}`;
            });
        const ordinalOneInvocation = [
            '--native-evidence',
            canonicalPaths[0],
            '--pre-operation-recovery',
            canonicalPaths[1],
        ];
        const ordinalTwoInvocation = [
            ...ordinalOneInvocation,
            '--failed-recovery-attempt',
            canonicalPaths[2],
        ];
        const failedRunDirectoryPath = 'C:\\custody\\metadata-run';
        const metadataForInvocation = (
            commandLineArguments: readonly string[],
        ): Readonly<Record<string, unknown>> => ({
            commandLineArguments,
            runDirectoryPath: failedRunDirectoryPath,
            scriptName: 'test:browser:proof-storage-width-evidence',
        });
        for (const style of ['doubled', 'mixed'] as const) {
            expect(
                immutableFailedRunMetadataInvocationEquals({
                    observed: metadataForInvocation(
                        serializeAllPaths(ordinalOneInvocation, style),
                    ),
                    profile: {
                        failedRunDirectoryPath,
                        nativeEvidencePath: canonicalPaths[0],
                        preOperationRecoveryRunDirectoryPath: canonicalPaths[1],
                        recoveryOrdinal: 1,
                    },
                }),
                `ordinal one ${style}`,
            ).toBe(true);
            expect(
                immutableFailedRunMetadataInvocationEquals({
                    observed: metadataForInvocation(
                        serializeAllPaths(ordinalTwoInvocation, style),
                    ),
                    profile: {
                        failedRecoveryAttemptRunDirectoryPath:
                            canonicalPaths[2],
                        failedRunDirectoryPath,
                        nativeEvidencePath: canonicalPaths[0],
                        preOperationRecoveryRunDirectoryPath: canonicalPaths[1],
                        recoveryOrdinal: 2,
                    },
                }),
                `ordinal two ${style}`,
            ).toBe(true);
        }
    });

    it('accepts independently doubled or mixed predecessor metadata in the real recovery topology', async () => {
        for (const invocationPathSerializer of [
            doubledWindowsRecordedInvocationPath,
            mixedWindowsRecordedInvocationPath,
        ]) {
            for (const metadataPosition of [
                'ordinal-one-native',
                'ordinal-one-predecessor',
                'ordinal-two-native',
                'ordinal-two-predecessor',
                'ordinal-two-failed-recovery',
            ] as const) {
                await withTemporaryFixture(async (fixture) => {
                    const selectOrdinalOnePath: RecordedInvocationPathSerializer =
                        (canonicalPath, pathArgumentIndex) =>
                            (metadataPosition === 'ordinal-one-native' &&
                                pathArgumentIndex === 1) ||
                            (metadataPosition === 'ordinal-one-predecessor' &&
                                pathArgumentIndex === 3)
                                ? invocationPathSerializer(
                                      canonicalPath,
                                      pathArgumentIndex,
                                  )
                                : canonicalPath;
                    const selectOrdinalTwoPath: RecordedInvocationPathSerializer =
                        (canonicalPath, pathArgumentIndex) => {
                            const selectedIndex =
                                metadataPosition === 'ordinal-two-native'
                                    ? 1
                                    : metadataPosition ===
                                        'ordinal-two-predecessor'
                                      ? 3
                                      : metadataPosition ===
                                          'ordinal-two-failed-recovery'
                                        ? 5
                                        : undefined;
                            return selectedIndex === pathArgumentIndex
                                ? invocationPathSerializer(
                                      canonicalPath,
                                      pathArgumentIndex,
                                  )
                                : canonicalPath;
                        };
                    const recoveryProfile =
                        await createThirdRecoveryFixtureProfile({
                            ...fixture,
                            failedChainedRecoveryInvocationPathSerializer:
                                selectOrdinalTwoPath,
                            failedRecoveryInvocationPathSerializer:
                                selectOrdinalOnePath,
                        });
                    await expect(
                        dryRunProofStorageWidthBrowserRecoveryChain({
                            dependencies: createDependencies({
                                fixture,
                                preOperationRecoveryProfile: recoveryProfile,
                                repositoryStateForCheckpoint: () => ({
                                    commitHash:
                                        thirdRecoveryFinalHarnessCommitHash,
                                    treeDirty: false,
                                }),
                                sampleInvocations: [],
                            }),
                            nativeEvidencePath: fixture.nativeEvidencePath,
                            ...thirdRecoveryExecutionPaths(recoveryProfile),
                        }),
                    ).resolves.toMatchObject({ recoveryOrdinal: 3 });
                });
            }
        }
    });

    it('keeps failed-run metadata run-directory custody exact', async () => {
        const doubleEverySeparator: RecordedInvocationPathSerializer = (
            canonicalPath,
        ) => canonicalPath.replace(/([\\/])/gu, '$1$1');
        for (const changedRunDirectory of [
            'ordinal-one',
            'ordinal-two',
        ] as const) {
            await withTemporaryFixture(async (fixture) => {
                const recoveryProfile = await createThirdRecoveryFixtureProfile(
                    {
                        ...fixture,
                        failedChainedRecoveryRunDirectoryPathSerializer:
                            changedRunDirectory === 'ordinal-two'
                                ? doubleEverySeparator
                                : exactRecordedInvocationPath,
                        failedRecoveryRunDirectoryPathSerializer:
                            changedRunDirectory === 'ordinal-one'
                                ? doubleEverySeparator
                                : exactRecordedInvocationPath,
                    },
                );
                await expect(
                    dryRunProofStorageWidthBrowserRecoveryChain({
                        dependencies: createDependencies({
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: thirdRecoveryFinalHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations: [],
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...thirdRecoveryExecutionPaths(recoveryProfile),
                    }),
                ).rejects.toThrow(
                    /metadata changed its exact predecessor invocation/u,
                );
                await expect(
                    readdir(
                        path.join(
                            fixture.reservationRootPath,
                            'browser-recovery-preflight-3',
                        ),
                    ),
                ).rejects.toMatchObject({ code: 'ENOENT' });
            });
        }
    });

    it('keeps sequential and concurrent ordinal-three dry-runs byte-read-only', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const allInvocations: CommandInvocation[] = [];
            const sampleInvocations: CommandInvocation[] = [];
            const dependencies = createDependencies({
                allInvocations,
                fixture,
                preOperationRecoveryProfile: recoveryProfile,
                repositoryStateForCheckpoint: () => ({
                    commitHash: thirdRecoveryFinalHarnessCommitHash,
                    treeDirty: false,
                }),
                sampleInvocations,
            });
            const dryRunInput = {
                dependencies,
                nativeEvidencePath: fixture.nativeEvidencePath,
                ...thirdRecoveryExecutionPaths(recoveryProfile),
            };
            const reservationBefore = await snapshotDirectoryCustody(
                fixture.reservationRootPath,
            );
            const fixtureBefore = await snapshotDirectoryCustody(
                path.dirname(fixture.runDirectoryPath),
            );
            const runBefore = await snapshotDirectoryCustody(
                fixture.runDirectoryPath,
            );
            const firstMarkerBefore = await readRecoveryMarker(
                fixture.reservationRootPath,
                recoveryProfile.chainedRecoveryProfile.previousPreflightAttempt
                    .relativePath,
            );
            const secondMarkerBefore = await readRecoveryMarker(
                fixture.reservationRootPath,
                recoveryProfile.thirdRecoveryProfile
                    .previousChainedPreflightAttempt.relativePath,
            );
            const firstResult =
                await dryRunProofStorageWidthBrowserRecoveryChain(dryRunInput);
            const secondResult =
                await dryRunProofStorageWidthBrowserRecoveryChain(dryRunInput);
            const concurrentResults = await Promise.all([
                dryRunProofStorageWidthBrowserRecoveryChain(dryRunInput),
                dryRunProofStorageWidthBrowserRecoveryChain(dryRunInput),
            ]);
            expect(secondResult).toEqual(firstResult);
            expect(concurrentResults).toEqual([firstResult, firstResult]);
            expect(firstResult).toMatchObject({
                finalHarnessCommitHash: thirdRecoveryFinalHarnessCommitHash,
                recoveryOrdinal: 3,
            });
            expect(firstResult.authorizationKeySha256Hex).not.toBe(
                recoveryProfile.thirdRecoveryProfile
                    .previousChainedAuthorizationKeySha256Hex,
            );
            expect(firstResult.authorizationKeySha256Hex).not.toBe(
                recoveryProfile.chainedRecoveryProfile
                    .previousAuthorizationKeySha256Hex,
            );
            expect(
                await snapshotDirectoryCustody(fixture.reservationRootPath),
            ).toEqual(reservationBefore);
            expect(
                await snapshotDirectoryCustody(fixture.runDirectoryPath),
            ).toEqual(runBefore);
            expect(
                await snapshotDirectoryCustody(
                    path.dirname(fixture.runDirectoryPath),
                ),
            ).toEqual(fixtureBefore);
            expect(
                await readRecoveryMarker(
                    fixture.reservationRootPath,
                    recoveryProfile.chainedRecoveryProfile
                        .previousPreflightAttempt.relativePath,
                ),
            ).toEqual(firstMarkerBefore);
            expect(
                await readRecoveryMarker(
                    fixture.reservationRootPath,
                    recoveryProfile.thirdRecoveryProfile
                        .previousChainedPreflightAttempt.relativePath,
                ),
            ).toEqual(secondMarkerBefore);
            await expect(
                readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-3',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            await expect(
                readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-3',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            expect(sampleInvocations).toHaveLength(0);
            expect(allInvocations.length).toBeGreaterThan(0);
            for (const invocation of allInvocations) {
                expect(invocation.command).toBe('git');
                expect(invocation.env).toMatchObject({
                    GIT_NO_REPLACE_OBJECTS: '1',
                    GIT_OPTIONAL_LOCKS: '0',
                });
                expect(invocation.args).not.toContain('list');
                expect(invocation.args).not.toContain('build');
                expect(invocation.args).not.toContain('vitest');
            }
        }));

    it('dispatches the public dry-run mode before local run custody, lease, build, browser, or measurement work', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const allInvocations: CommandInvocation[] = [];
            const sampleInvocations: CommandInvocation[] = [];
            let runLogWrapperInvocationCount = 0;
            let heavyLaneLeaseWrapperInvocationCount = 0;
            const dependencies = {
                ...createDependencies({
                    allInvocations,
                    fixture,
                    preOperationRecoveryProfile: recoveryProfile,
                    repositoryStateForCheckpoint: () => ({
                        commitHash: thirdRecoveryFinalHarnessCommitHash,
                        treeDirty: false,
                    }),
                    sampleInvocations,
                }),
                runWithLocalRunLog: () => {
                    runLogWrapperInvocationCount += 1;
                    return Promise.reject(
                        new Error(
                            'Public dry-run dispatch entered local run-log custody.',
                        ),
                    );
                },
                withLocalHeavyLaneLease: () => {
                    heavyLaneLeaseWrapperInvocationCount += 1;
                    return Promise.reject(
                        new Error(
                            'Public dry-run dispatch entered the heavy-lane lease.',
                        ),
                    );
                },
            } satisfies ProofStorageWidthBrowserEvidenceDependencies;
            Object.defineProperty(dependencies, 'processMemoryGuard', {
                configurable: true,
                get: () => {
                    throw new Error(
                        'Public dry-run dispatch constructed the measurement guard.',
                    );
                },
            });
            const fixtureBefore = await snapshotDirectoryCustody(
                path.dirname(fixture.runDirectoryPath),
            );
            await expect(
                runProofStorageWidthBrowserEvidence(
                    [
                        '--native-evidence',
                        fixture.nativeEvidencePath,
                        '--pre-operation-recovery',
                        recoveryProfile.failedRunDirectoryPath,
                        '--failed-recovery-attempt',
                        recoveryProfile.chainedRecoveryProfile
                            .failedRecoveryRunDirectoryPath,
                        '--failed-chained-recovery-attempt',
                        recoveryProfile.thirdRecoveryProfile
                            .failedChainedRecoveryRunDirectoryPath,
                        '--recovery-chain-dry-run',
                    ],
                    dependencies,
                ),
            ).resolves.toBeUndefined();
            expect(runLogWrapperInvocationCount).toBe(0);
            expect(heavyLaneLeaseWrapperInvocationCount).toBe(0);
            expect(
                await snapshotDirectoryCustody(
                    path.dirname(fixture.runDirectoryPath),
                ),
            ).toEqual(fixtureBefore);
            expect(sampleInvocations).toHaveLength(0);
            expect(allInvocations.length).toBeGreaterThan(0);
            for (const invocation of allInvocations) {
                expect(invocation.command).toBe('git');
                expect(invocation.args).not.toContain('build');
                expect(invocation.args).not.toContain('vitest');
            }
            await expect(
                readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-3',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        }));

    it('refuses empty and hostile preexisting ordinal-three key directories without consuming dry-run state', async () => {
        for (const keyDirectoryKind of ['empty', 'hostile'] as const) {
            await withTemporaryFixture(async (fixture) => {
                const recoveryProfile =
                    await createThirdRecoveryFixtureProfile(fixture);
                const dryRunInput = {
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                };
                const derived =
                    await dryRunProofStorageWidthBrowserRecoveryChain({
                        ...dryRunInput,
                        dependencies: createDependencies({
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: thirdRecoveryFinalHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations: [],
                        }),
                    });
                const keyDirectoryPath = path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-3',
                    derived.authorizationKeySha256Hex,
                );
                await mkdir(keyDirectoryPath, { recursive: true });
                if (keyDirectoryKind === 'hostile') {
                    const hostileDirectoryPath = path.join(
                        keyDirectoryPath,
                        'unexpected',
                    );
                    await mkdir(hostileDirectoryPath);
                    await writeFile(
                        path.join(hostileDirectoryPath, 'artifact.json'),
                        '{}\n',
                        'utf8',
                    );
                }
                const custodyBefore =
                    await snapshotDirectoryCustody(keyDirectoryPath);
                const allInvocations: CommandInvocation[] = [];
                const sampleInvocations: CommandInvocation[] = [];
                await expect(
                    dryRunProofStorageWidthBrowserRecoveryChain({
                        ...dryRunInput,
                        dependencies: createDependencies({
                            allInvocations,
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: thirdRecoveryFinalHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations,
                        }),
                    }),
                    keyDirectoryKind,
                ).rejects.toThrow(/singleton key directory already exists/u);
                expect(allInvocations, keyDirectoryKind).toHaveLength(0);
                expect(sampleInvocations, keyDirectoryKind).toHaveLength(0);
                expect(
                    await snapshotDirectoryCustody(keyDirectoryPath),
                    keyDirectoryKind,
                ).toEqual(custodyBefore);
                await expect(
                    readdir(
                        path.join(
                            fixture.reservationRootPath,
                            'browser-recovery-3',
                        ),
                    ),
                    keyDirectoryKind,
                ).rejects.toMatchObject({ code: 'ENOENT' });
            });
        }
    });

    it('keeps adversarial ordinal-three predecessor dry-runs non-consuming and command-free', async () => {
        for (const mutationKind of [
            'artifact-bytes',
            'nested-entry',
            'reparse-alias',
            'ordinal-two-marker',
            'ordinal-two-operation',
        ] as const) {
            await withTemporaryFixture(async (fixture) => {
                const recoveryProfile =
                    await createThirdRecoveryFixtureProfile(fixture);
                if (mutationKind === 'artifact-bytes') {
                    const summaryPath = path.join(
                        recoveryProfile.thirdRecoveryProfile
                            .failedChainedRecoveryRunDirectoryPath,
                        recoveryProfile.thirdRecoveryProfile
                            .failedChainedRecoveryArtifacts.summary
                            .relativePath,
                    );
                    await writeFile(
                        summaryPath,
                        Buffer.concat([
                            await readFile(summaryPath),
                            Buffer.from('changed'),
                        ]),
                    );
                } else if (mutationKind === 'nested-entry') {
                    const nestedDirectoryPath = path.join(
                        recoveryProfile.thirdRecoveryProfile
                            .failedChainedRecoveryRunDirectoryPath,
                        'hostile-nested-entry',
                    );
                    await mkdir(nestedDirectoryPath);
                    await writeFile(
                        path.join(nestedDirectoryPath, 'unexpected.txt'),
                        'unexpected',
                        'utf8',
                    );
                } else if (mutationKind === 'reparse-alias') {
                    const aliasTargetPath = path.join(
                        path.dirname(fixture.runDirectoryPath),
                        'hostile-alias-target',
                    );
                    await mkdir(aliasTargetPath);
                    await symlink(
                        aliasTargetPath,
                        path.join(
                            recoveryProfile.thirdRecoveryProfile
                                .failedChainedRecoveryRunDirectoryPath,
                            'hostile-alias',
                        ),
                        process.platform === 'win32' ? 'junction' : 'dir',
                    );
                } else if (mutationKind === 'ordinal-two-marker') {
                    const markerPath = path.join(
                        fixture.reservationRootPath,
                        recoveryProfile.thirdRecoveryProfile
                            .previousChainedPreflightAttempt.relativePath,
                    );
                    await writeFile(
                        markerPath,
                        Buffer.concat([
                            await readFile(markerPath),
                            Buffer.from('changed'),
                        ]),
                    );
                } else {
                    const operationPath = path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-2',
                        recoveryProfile.thirdRecoveryProfile
                            .previousChainedAuthorizationKeySha256Hex,
                        'browser-recovery-started.json',
                    );
                    await mkdir(path.dirname(operationPath), {
                        recursive: true,
                    });
                    await writeFile(operationPath, '{}\n', 'utf8');
                }
                const reservationBefore = await snapshotDirectoryCustody(
                    fixture.reservationRootPath,
                );
                const runBefore = await snapshotDirectoryCustody(
                    fixture.runDirectoryPath,
                );
                const allInvocations: CommandInvocation[] = [];
                const sampleInvocations: CommandInvocation[] = [];
                await expect(
                    dryRunProofStorageWidthBrowserRecoveryChain({
                        dependencies: createDependencies({
                            allInvocations,
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: thirdRecoveryFinalHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations,
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...thirdRecoveryExecutionPaths(recoveryProfile),
                    }),
                    mutationKind,
                ).rejects.toThrow();
                expect(allInvocations, mutationKind).toHaveLength(0);
                expect(sampleInvocations, mutationKind).toHaveLength(0);
                expect(
                    await snapshotDirectoryCustody(fixture.reservationRootPath),
                    mutationKind,
                ).toEqual(reservationBefore);
                expect(
                    await snapshotDirectoryCustody(fixture.runDirectoryPath),
                    mutationKind,
                ).toEqual(runBefore);
                await expect(
                    readdir(
                        path.join(
                            fixture.reservationRootPath,
                            'browser-recovery-preflight-3',
                        ),
                    ),
                    mutationKind,
                ).rejects.toMatchObject({ code: 'ENOENT' });
                await expect(
                    readdir(
                        path.join(
                            fixture.reservationRootPath,
                            'browser-recovery-3',
                        ),
                    ),
                    mutationKind,
                ).rejects.toMatchObject({ code: 'ENOENT' });
            });
        }
    });

    it('consumes exactly one ordinal-three singleton on failure and refuses replay before commands', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const firstMarkerBefore = await readRecoveryMarker(
                fixture.reservationRootPath,
                recoveryProfile.chainedRecoveryProfile.previousPreflightAttempt
                    .relativePath,
            );
            const secondMarkerBefore = await readRecoveryMarker(
                fixture.reservationRootPath,
                recoveryProfile.thirdRecoveryProfile
                    .previousChainedPreflightAttempt.relativePath,
            );
            const firstInvocations: CommandInvocation[] = [];
            const firstSampleInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations: firstInvocations,
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: (checkpoint) => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: checkpoint === 'initial',
                        }),
                        sampleInvocations: firstSampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/initial checkpoint/u);
            expect(firstInvocations).toHaveLength(0);
            expect(firstSampleInvocations).toHaveLength(0);
            const marker = await readThirdRecoveryMarkerForTest(
                fixture.reservationRootPath,
            );
            const authorizationKeySha256Hex = marker.authorizationKeySha256Hex;
            const markerBeforeReplay = await snapshotDirectoryCustody(
                marker.rootPath,
            );
            const markerRecords = marker.records;
            expect(markerRecords).toHaveLength(2);
            expect(markerRecords[0]).toMatchObject({
                authorizationKeySha256Hex,
                eventType:
                    'official-browser-width-recovery-preflight-attempted',
                failedReservationIdentitySha256Hex:
                    recoveryProfile.failedReservation.identitySha256Hex,
                firstAuthorizationKeySha256Hex:
                    recoveryProfile.chainedRecoveryProfile
                        .previousAuthorizationKeySha256Hex,
                firstPreflightAttemptSha256Hex:
                    recoveryProfile.chainedRecoveryProfile
                        .previousPreflightAttempt.sha256Hex,
                previousAuthorizationKeySha256Hex:
                    recoveryProfile.thirdRecoveryProfile
                        .previousChainedAuthorizationKeySha256Hex,
                previousPreflightAttemptSha256Hex:
                    recoveryProfile.thirdRecoveryProfile
                        .previousChainedPreflightAttempt.sha256Hex,
                recoveryOrdinal: 3,
            });
            expect(markerRecords[1]).toMatchObject({
                eventType: 'official-sample-outcome',
                failureName: 'Error',
                outcome: 'failed',
            });
            await expect(
                readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-3',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            expect(
                await readRecoveryMarker(
                    fixture.reservationRootPath,
                    recoveryProfile.chainedRecoveryProfile
                        .previousPreflightAttempt.relativePath,
                ),
            ).toEqual(firstMarkerBefore);
            expect(
                await readRecoveryMarker(
                    fixture.reservationRootPath,
                    recoveryProfile.thirdRecoveryProfile
                        .previousChainedPreflightAttempt.relativePath,
                ),
            ).toEqual(secondMarkerBefore);

            const replayRunDirectoryPath = path.join(
                path.dirname(fixture.runDirectoryPath),
                'ordinal-three-replay',
            );
            await mkdir(replayRunDirectoryPath);
            const replayInvocations: CommandInvocation[] = [];
            const replaySampleInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations: replayInvocations,
                        fixture: {
                            ...fixture,
                            runDirectoryPath: replayRunDirectoryPath,
                        },
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: replaySampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(replayRunDirectoryPath),
                }),
            ).rejects.toThrow(/already claimed its singleton key directory/u);
            expect(replayInvocations).toHaveLength(0);
            expect(replaySampleInvocations).toHaveLength(0);
            expect(await snapshotDirectoryCustody(marker.rootPath)).toEqual(
                markerBeforeReplay,
            );
        }));

    it('keeps a preflight staging fault as one consumed empty singleton with no evidence work', async () => {
        for (const faultStage of [
            'before-staged-write',
            'after-staged-close-before-validation',
        ] as const) {
            await withTemporaryFixture(async (fixture) => {
                const recoveryProfile =
                    await createThirdRecoveryFixtureProfile(fixture);
                let injected = false;
                const faultInjection: BrowserRecoveryMarkerFaultInjection = (
                    event,
                ) => {
                    if (
                        !injected &&
                        event.recordKind === 'preflight-attempt' &&
                        event.stage === faultStage
                    ) {
                        injected = true;
                        if (faultStage === 'before-staged-write') {
                            return { maximumWriteByteLength: 1 };
                        }
                        throw new Error(
                            'Injected staged-close preflight failure.',
                        );
                    }
                    return undefined;
                };
                const allInvocations: CommandInvocation[] = [];
                const sampleInvocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            allInvocations,
                            browserRecoveryMarkerFaultInjection: faultInjection,
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: thirdRecoveryFinalHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations,
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...thirdRecoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(fixture.runDirectoryPath),
                    }),
                    faultStage,
                ).rejects.toThrow();
                expect(injected, faultStage).toBe(true);
                expect(allInvocations, faultStage).toHaveLength(0);
                expect(sampleInvocations, faultStage).toHaveLength(0);
                const preflightRootEntries = await readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-3',
                    ),
                );
                expect(preflightRootEntries, faultStage).toHaveLength(1);
                await expectNoUnpublishedRecoveryRecordEntries(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-3',
                    ),
                    faultStage,
                );
                const keyDirectoryPath = path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-3',
                    preflightRootEntries[0] ?? '',
                );
                expect(await readdir(keyDirectoryPath), faultStage).toEqual([]);
                const consumedSingletonBeforeReplay =
                    await snapshotDirectoryCustody(keyDirectoryPath);

                const replayInvocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            allInvocations: replayInvocations,
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: thirdRecoveryFinalHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations: [],
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...thirdRecoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(fixture.runDirectoryPath),
                    }),
                    faultStage,
                ).rejects.toThrow(
                    /already claimed its singleton key directory/u,
                );
                expect(replayInvocations, faultStage).toHaveLength(0);
                expect(
                    await snapshotDirectoryCustody(keyDirectoryPath),
                    faultStage,
                ).toEqual(consumedSingletonBeforeReplay);
                await expect(
                    readdir(
                        path.join(
                            fixture.reservationRootPath,
                            'browser-recovery-3',
                        ),
                    ),
                    faultStage,
                ).rejects.toMatchObject({ code: 'ENOENT' });
            });
        }
    });

    it('never accepts reopenable bytes after a preflight publication durability failure', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            let injected = false;
            const allInvocations: CommandInvocation[] = [];
            const sampleInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations,
                        browserRecoveryMarkerFaultInjection: (event) => {
                            if (
                                !injected &&
                                event.recordKind === 'preflight-attempt' &&
                                event.stage === 'after-link-before-durability'
                            ) {
                                injected = true;
                                throw new Error(
                                    'Injected preflight publication durability failure.',
                                );
                            }
                            return undefined;
                        },
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/preflight-attempt atomic publication failed/u);
            expect(injected).toBe(true);
            expect(allInvocations).toHaveLength(0);
            expect(sampleInvocations).toHaveLength(0);
            const preflightRootPath = path.join(
                fixture.reservationRootPath,
                'browser-recovery-preflight-3',
            );
            const preflightRootEntries = await readdir(preflightRootPath);
            expect(preflightRootEntries).toHaveLength(1);
            const keyDirectoryPath = path.join(
                preflightRootPath,
                preflightRootEntries[0] ?? '',
            );
            expect(await readdir(keyDirectoryPath)).toEqual([]);
            await expectNoUnpublishedRecoveryRecordEntries(
                preflightRootPath,
                'durability-failed preflight cleanup',
            );
            const markerBeforeReplay =
                await snapshotDirectoryCustody(keyDirectoryPath);

            const replayInvocations: CommandInvocation[] = [];
            const replaySampleInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations: replayInvocations,
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: replaySampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/already claimed its singleton key directory/u);
            expect(replayInvocations).toHaveLength(0);
            expect(replaySampleInvocations).toHaveLength(0);
            expect(await snapshotDirectoryCustody(keyDirectoryPath)).toEqual(
                markerBeforeReplay,
            );
            await expect(
                readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-3',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        }));

    it('refuses a claimed ordinal-three key-directory identity replacement before attempted-record publication', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            let reportAttemptStagingReached: (() => void) | undefined;
            const attemptStagingReached = new Promise<void>((resolve) => {
                reportAttemptStagingReached = resolve;
            });
            let releaseAttemptStaging: (() => void) | undefined;
            const attemptStagingBarrier = new Promise<void>((resolve) => {
                releaseAttemptStaging = resolve;
            });
            let attemptStagingArrivalCount = 0;
            const allInvocations: CommandInvocation[] = [];
            const sampleInvocations: CommandInvocation[] = [];
            const announcements: string[] = [];
            const executionResult = executeProofStorageWidthBrowserEvidence({
                dependencies: createDependencies({
                    allInvocations,
                    browserRecoveryMarkerFaultInjection: async (event) => {
                        if (
                            event.recordKind === 'preflight-attempt' &&
                            event.stage === 'before-staged-write'
                        ) {
                            attemptStagingArrivalCount += 1;
                            if (attemptStagingArrivalCount > 1) {
                                throw new Error(
                                    'The attempted-record staging barrier was entered more than once.',
                                );
                            }
                            reportAttemptStagingReached?.();
                            await attemptStagingBarrier;
                        }
                        return undefined;
                    },
                    fixture,
                    preOperationRecoveryProfile: recoveryProfile,
                    repositoryStateForCheckpoint: () => ({
                        commitHash: thirdRecoveryFinalHarnessCommitHash,
                        treeDirty: false,
                    }),
                    sampleInvocations,
                }),
                nativeEvidencePath: fixture.nativeEvidencePath,
                ...thirdRecoveryExecutionPaths(recoveryProfile),
                runLog: createRunLog(fixture.runDirectoryPath, {
                    writeCombinedOutput: (output) => announcements.push(output),
                    writeEvent: ({ eventType }) =>
                        announcements.push(eventType),
                }),
            }).then(
                () => ({ status: 'fulfilled' as const }),
                (reason: unknown) => ({ reason, status: 'rejected' as const }),
            );
            const stageOrCompletion = await Promise.race([
                attemptStagingReached.then(() => 'staging' as const),
                executionResult.then(() => 'completed' as const),
            ]);
            if (stageOrCompletion !== 'staging') {
                throw new Error(
                    'The ordinal-three attempt completed before its controlled staging barrier.',
                );
            }

            const claimedKeyDirectoryPath =
                await resolveOnlyThirdRecoveryKeyDirectoryPath(
                    fixture.reservationRootPath,
                );
            const displacedClaimedKeyDirectoryPath = `${claimedKeyDirectoryPath}.displaced-claim`;
            const claimedIdentity = await lstat(claimedKeyDirectoryPath, {
                bigint: true,
            });
            await rename(
                claimedKeyDirectoryPath,
                displacedClaimedKeyDirectoryPath,
            );
            await mkdir(claimedKeyDirectoryPath);
            const replacementSentinelBytes = Buffer.from(
                'hostile replacement custody\n',
                'utf8',
            );
            await writeFile(
                path.join(claimedKeyDirectoryPath, 'replacement-sentinel.bin'),
                replacementSentinelBytes,
            );
            const replacementIdentity = await lstat(claimedKeyDirectoryPath, {
                bigint: true,
            });
            const displacedIdentity = await lstat(
                displacedClaimedKeyDirectoryPath,
                { bigint: true },
            );
            expect({
                device: displacedIdentity.dev,
                inode: displacedIdentity.ino,
            }).toEqual({
                device: claimedIdentity.dev,
                inode: claimedIdentity.ino,
            });
            expect({
                device: replacementIdentity.dev,
                inode: replacementIdentity.ino,
            }).not.toEqual({
                device: claimedIdentity.dev,
                inode: claimedIdentity.ino,
            });
            const displacedCustodyBeforeRefusal =
                await snapshotDirectoryCustody(
                    displacedClaimedKeyDirectoryPath,
                );
            const replacementCustodyBeforeRefusal =
                await snapshotDirectoryCustody(claimedKeyDirectoryPath);
            releaseAttemptStaging?.();

            const result = await executionResult;
            expect(result.status).toBe('rejected');
            if (result.status !== 'rejected') {
                throw new Error(
                    'The replaced ordinal-three key directory was accepted.',
                );
            }
            expect(result.reason).toBeInstanceOf(Error);
            const identityRefusalCause = (
                result.reason as Readonly<{ cause?: unknown }>
            ).cause;
            expect(identityRefusalCause).toBeInstanceOf(Error);
            if (!(identityRefusalCause instanceof Error)) {
                throw new Error(
                    'The identity-replacement refusal omitted its Error cause.',
                );
            }
            expect(identityRefusalCause.message).toMatch(
                /filesystem identity/u,
            );
            expect(attemptStagingArrivalCount).toBe(1);
            expect(allInvocations).toHaveLength(0);
            expect(sampleInvocations).toHaveLength(0);
            expect(announcements).toHaveLength(0);
            expect(
                await snapshotDirectoryCustody(
                    displacedClaimedKeyDirectoryPath,
                ),
            ).toEqual(displacedCustodyBeforeRefusal);
            expect(
                await snapshotDirectoryCustody(claimedKeyDirectoryPath),
            ).toEqual(replacementCustodyBeforeRefusal);
            const preflightRootPath = path.dirname(claimedKeyDirectoryPath);
            await expectNoUnpublishedRecoveryRecordEntries(
                preflightRootPath,
                'identity replacement staging cleanup',
            );
            await expect(
                readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-3',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });

            const replayRunDirectoryPath = path.join(
                path.dirname(fixture.runDirectoryPath),
                'identity-replacement-replay',
            );
            await mkdir(replayRunDirectoryPath);
            const replayInvocations: CommandInvocation[] = [];
            const replaySampleInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations: replayInvocations,
                        fixture: {
                            ...fixture,
                            runDirectoryPath: replayRunDirectoryPath,
                        },
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: replaySampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(replayRunDirectoryPath),
                }),
            ).rejects.toThrow(/exact record inventory/u);
            expect(replayInvocations).toHaveLength(0);
            expect(replaySampleInvocations).toHaveLength(0);
            expect(
                await snapshotDirectoryCustody(
                    displacedClaimedKeyDirectoryPath,
                ),
            ).toEqual(displacedCustodyBeforeRefusal);
            expect(
                await snapshotDirectoryCustody(claimedKeyDirectoryPath),
            ).toEqual(replacementCustodyBeforeRefusal);
        }));

    it('terminalizes a one-shot post-publication preflight fault before commands', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            let injected = false;
            const allInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations,
                        browserRecoveryMarkerFaultInjection: (event) => {
                            if (
                                !injected &&
                                event.recordKind === 'preflight-attempt' &&
                                event.stage ===
                                    'after-publication-before-reopen'
                            ) {
                                injected = true;
                                throw new Error(
                                    'Injected post-publication preflight failure.',
                                );
                            }
                            return undefined;
                        },
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: [],
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/preflight-attempt atomic publication failed/u);
            expect(injected).toBe(true);
            expect(allInvocations).toHaveLength(0);
            const marker = await readThirdRecoveryMarkerForTest(
                fixture.reservationRootPath,
            );
            expect(marker.records).toHaveLength(2);
            expect(marker.records[1]).toMatchObject({
                eventType: 'official-sample-outcome',
                failureName: 'Error',
                outcome: 'failed',
            });
            await expectNoUnpublishedRecoveryRecordEntries(
                path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-3',
                ),
                'post-publication preflight cleanup',
            );
        }));

    it('reports exact custody failure when the failed terminal record cannot be staged', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const allInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations,
                        browserRecoveryMarkerFaultInjection: (event) => {
                            if (
                                event.recordKind === 'preflight-attempt' &&
                                event.stage ===
                                    'after-publication-before-reopen'
                            ) {
                                throw new Error(
                                    'Injected acquisition publication failure.',
                                );
                            }
                            return event.recordKind === 'failure-outcome' &&
                                event.stage === 'before-staged-write'
                                ? { maximumWriteByteLength: 1 }
                                : undefined;
                        },
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: [],
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/failure-outcome atomic publication failed/u);
            expect(allInvocations).toHaveLength(0);
            const marker = await readThirdRecoveryMarkerForTest(
                fixture.reservationRootPath,
            );
            expect(marker.records).toHaveLength(1);
            await expectNoUnpublishedRecoveryRecordEntries(
                path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-3',
                ),
                'failed-terminal staging cleanup',
            );
        }));

    it('never overwrites a colliding fixed ordinal-three child directory', async () => {
        for (const collision of [
            {
                directoryName: 'static-preflight-observed',
                recordKind: 'static-observation',
            },
            {
                directoryName: 'terminal-outcome',
                recordKind: 'failure-outcome',
            },
        ] as const) {
            for (const collisionInventory of ['empty', 'hostile'] as const) {
                await withTemporaryFixture(async (fixture) => {
                    const recoveryProfile =
                        await createThirdRecoveryFixtureProfile(fixture);
                    const allInvocations: CommandInvocation[] = [];
                    const sampleInvocations: CommandInvocation[] = [];
                    const announcements: string[] = [];
                    let collisionInjected = false;
                    let collidingDirectoryPath: string | undefined;
                    let collidingCustodyBeforeRefusal:
                        | readonly string[]
                        | undefined;
                    const hostileRecordBytes = Buffer.from(
                        `hostile ${collision.recordKind} record\n`,
                        'utf8',
                    );
                    await expect(
                        executeProofStorageWidthBrowserEvidence({
                            dependencies: createDependencies({
                                allInvocations,
                                browserRecoveryMarkerFaultInjection: async (
                                    event,
                                ) => {
                                    if (
                                        !collisionInjected &&
                                        event.recordKind ===
                                            collision.recordKind &&
                                        event.stage === 'before-staged-write'
                                    ) {
                                        const keyDirectoryPath =
                                            await resolveOnlyThirdRecoveryKeyDirectoryPath(
                                                fixture.reservationRootPath,
                                            );
                                        collidingDirectoryPath = path.join(
                                            keyDirectoryPath,
                                            collision.directoryName,
                                        );
                                        await mkdir(collidingDirectoryPath);
                                        if (collisionInventory === 'hostile') {
                                            await writeFile(
                                                path.join(
                                                    collidingDirectoryPath,
                                                    'record.json',
                                                ),
                                                hostileRecordBytes,
                                            );
                                            const nestedHostileDirectoryPath =
                                                path.join(
                                                    collidingDirectoryPath,
                                                    'nested-hostile-custody',
                                                );
                                            await mkdir(
                                                nestedHostileDirectoryPath,
                                            );
                                            await writeFile(
                                                path.join(
                                                    nestedHostileDirectoryPath,
                                                    'artifact.bin',
                                                ),
                                                Buffer.from([
                                                    0x00, 0x7f, 0x80, 0xff,
                                                ]),
                                            );
                                        }
                                        collidingCustodyBeforeRefusal =
                                            await snapshotDirectoryCustody(
                                                collidingDirectoryPath,
                                            );
                                        collisionInjected = true;
                                    }
                                    return undefined;
                                },
                                fixture,
                                preOperationRecoveryProfile: recoveryProfile,
                                repositoryStateForCheckpoint: (checkpoint) => ({
                                    commitHash:
                                        thirdRecoveryFinalHarnessCommitHash,
                                    treeDirty:
                                        collision.recordKind ===
                                            'failure-outcome' &&
                                        checkpoint === 'initial',
                                }),
                                sampleInvocations,
                            }),
                            nativeEvidencePath: fixture.nativeEvidencePath,
                            ...thirdRecoveryExecutionPaths(recoveryProfile),
                            runLog: createRunLog(fixture.runDirectoryPath, {
                                writeCombinedOutput: (output) =>
                                    announcements.push(output),
                                writeEvent: ({ eventType }) =>
                                    announcements.push(eventType),
                            }),
                        }),
                        `${collision.recordKind}:${collisionInventory}`,
                    ).rejects.toThrow();
                    expect(
                        collisionInjected,
                        `${collision.recordKind}:${collisionInventory}`,
                    ).toBe(true);
                    expect(
                        collidingDirectoryPath,
                        `${collision.recordKind}:${collisionInventory}`,
                    ).toBeDefined();
                    expect(
                        collidingCustodyBeforeRefusal,
                        `${collision.recordKind}:${collisionInventory}`,
                    ).toBeDefined();
                    expect(
                        sampleInvocations,
                        `${collision.recordKind}:${collisionInventory}`,
                    ).toHaveLength(0);
                    expect(
                        announcements,
                        `${collision.recordKind}:${collisionInventory}`,
                    ).toHaveLength(0);
                    expect(
                        await snapshotDirectoryCustody(
                            collidingDirectoryPath ?? '',
                        ),
                        `${collision.recordKind}:${collisionInventory}`,
                    ).toEqual(collidingCustodyBeforeRefusal);
                    const retainedHostileRecordBytes =
                        collisionInventory === 'hostile'
                            ? await readFile(
                                  path.join(
                                      collidingDirectoryPath ?? '',
                                      'record.json',
                                  ),
                              )
                            : undefined;
                    expect(retainedHostileRecordBytes).toEqual(
                        collisionInventory === 'hostile'
                            ? hostileRecordBytes
                            : undefined,
                    );
                    const keyDirectoryPath = path.dirname(
                        collidingDirectoryPath ?? '',
                    );
                    const keyCustodyBeforeReplay =
                        await snapshotDirectoryCustody(keyDirectoryPath);
                    await expectNoUnpublishedRecoveryRecordEntries(
                        path.dirname(keyDirectoryPath),
                        `${collision.recordKind}:${collisionInventory}`,
                    );
                    await expect(
                        readdir(
                            path.join(
                                fixture.reservationRootPath,
                                'browser-recovery-3',
                            ),
                        ),
                        `${collision.recordKind}:${collisionInventory}`,
                    ).rejects.toMatchObject({ code: 'ENOENT' });

                    const replayRunDirectoryPath = path.join(
                        path.dirname(fixture.runDirectoryPath),
                        `fixed-child-collision-${collision.recordKind}-${collisionInventory}`,
                    );
                    await mkdir(replayRunDirectoryPath);
                    const replayInvocations: CommandInvocation[] = [];
                    const replaySampleInvocations: CommandInvocation[] = [];
                    await expect(
                        executeProofStorageWidthBrowserEvidence({
                            dependencies: createDependencies({
                                allInvocations: replayInvocations,
                                fixture: {
                                    ...fixture,
                                    runDirectoryPath: replayRunDirectoryPath,
                                },
                                preOperationRecoveryProfile: recoveryProfile,
                                repositoryStateForCheckpoint: () => ({
                                    commitHash:
                                        thirdRecoveryFinalHarnessCommitHash,
                                    treeDirty: false,
                                }),
                                sampleInvocations: replaySampleInvocations,
                            }),
                            nativeEvidencePath: fixture.nativeEvidencePath,
                            ...thirdRecoveryExecutionPaths(recoveryProfile),
                            runLog: createRunLog(replayRunDirectoryPath),
                        }),
                        `${collision.recordKind}:${collisionInventory}`,
                    ).rejects.toThrow(/exact one-file inventory/u);
                    expect(
                        replayInvocations,
                        `${collision.recordKind}:${collisionInventory}`,
                    ).toHaveLength(0);
                    expect(
                        replaySampleInvocations,
                        `${collision.recordKind}:${collisionInventory}`,
                    ).toHaveLength(0);
                    expect(
                        await snapshotDirectoryCustody(keyDirectoryPath),
                        `${collision.recordKind}:${collisionInventory}`,
                    ).toEqual(keyCustodyBeforeReplay);
                });
            }
        }
    });

    it('rolls back a short static observation and terminalizes the attempt', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const allInvocations: CommandInvocation[] = [];
            const sampleInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations,
                        browserRecoveryMarkerFaultInjection: (event) =>
                            event.recordKind === 'static-observation' &&
                            event.stage === 'before-staged-write'
                                ? { maximumWriteByteLength: 1 }
                                : undefined,
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/static-observation atomic publication failed/u);
            expect(allInvocations.length).toBeGreaterThan(0);
            expect(sampleInvocations).toHaveLength(0);
            const marker = await readThirdRecoveryMarkerForTest(
                fixture.reservationRootPath,
            );
            expect(marker.records).toHaveLength(2);
            expect(marker.records[1]).toMatchObject({
                eventType: 'official-sample-outcome',
                outcome: 'failed',
            });
            await expect(
                readdir(
                    path.join(marker.rootPath, 'static-preflight-observed'),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            await expectNoUnpublishedRecoveryRecordEntries(
                path.dirname(marker.rootPath),
                'short static-observation cleanup',
            );
        }));

    it('rolls back a short validated outcome, records failure, and never announces closure', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const announcements: string[] = [];
            const sampleInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        browserRecoveryMarkerFaultInjection: (event) =>
                            event.recordKind === 'validated-outcome' &&
                            event.stage === 'before-staged-write'
                                ? { maximumWriteByteLength: 1 }
                                : undefined,
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath, {
                        writeCombinedOutput: (output) => {
                            if (
                                output.startsWith(
                                    'Proof-storage width browser evidence:',
                                )
                            ) {
                                announcements.push(output);
                            }
                        },
                        writeEvent: ({ eventType }) => {
                            if (
                                eventType ===
                                    'proof-storage-width-browser-evidence-complete' ||
                                eventType ===
                                    'proof-storage-width-browser-evidence-decisive-negative'
                            ) {
                                announcements.push(eventType);
                            }
                        },
                    }),
                }),
            ).rejects.toThrow(/validated-outcome atomic publication failed/u);
            expect(sampleInvocations).toHaveLength(1);
            expect(announcements).toHaveLength(0);
            const marker = await readThirdRecoveryMarkerForTest(
                fixture.reservationRootPath,
            );
            expect(marker.records).toHaveLength(3);
            expect(marker.records[1]?.eventType).toBe(
                'official-browser-width-recovery-static-preflight-observed',
            );
            expect(marker.records[2]).toMatchObject({
                eventType: 'official-sample-outcome',
                outcome: 'failed',
            });
            await expectNoUnpublishedRecoveryRecordEntries(
                path.dirname(marker.rootPath),
                'short validated-outcome cleanup',
            );
        }));

    it('never announces closure from reopenable validated bytes whose durability barrier failed', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const announcements: string[] = [];
            const sampleInvocations: CommandInvocation[] = [];
            let injected = false;
            const dependencies = createDependencies({
                browserRecoveryMarkerFaultInjection: (event) => {
                    if (
                        !injected &&
                        event.recordKind === 'validated-outcome' &&
                        event.stage === 'after-link-before-durability'
                    ) {
                        injected = true;
                        throw new Error(
                            'Injected validated publication durability failure.',
                        );
                    }
                    return undefined;
                },
                fixture,
                preOperationRecoveryProfile: recoveryProfile,
                repositoryStateForCheckpoint: () => ({
                    commitHash: thirdRecoveryFinalHarnessCommitHash,
                    treeDirty: false,
                }),
                sampleInvocations,
            });
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies,
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath, {
                        writeCombinedOutput: (output) => {
                            if (
                                output.startsWith(
                                    'Proof-storage width browser evidence:',
                                )
                            ) {
                                announcements.push(output);
                            }
                        },
                        writeEvent: ({ eventType }) => {
                            if (
                                eventType ===
                                    'proof-storage-width-browser-evidence-complete' ||
                                eventType ===
                                    'proof-storage-width-browser-evidence-decisive-negative'
                            ) {
                                announcements.push(eventType);
                            }
                        },
                    }),
                }),
            ).rejects.toThrow(/validated-outcome atomic publication failed/u);
            expect(injected).toBe(true);
            expect(sampleInvocations).toHaveLength(1);
            expect(announcements).toHaveLength(0);
            const marker = await readThirdRecoveryMarkerForTest(
                fixture.reservationRootPath,
            );
            expect(marker.records).toHaveLength(3);
            expect(marker.records[2]).toMatchObject({
                eventType: 'official-sample-outcome',
                outcome: 'failed',
            });
            const attachmentPath = path.join(
                fixture.runDirectoryPath,
                'attachments',
                'proof-storage-width-browser-evidence.json',
            );
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        chainedRecoveryProfile:
                            recoveryProfile.chainedRecoveryProfile,
                        preOperationRecoveryProfile: recoveryProfile,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                        thirdRecoveryProfile:
                            recoveryProfile.thirdRecoveryProfile,
                    },
                ),
            ).rejects.toThrow(/lacks its one validated terminal outcome/u);
            await expectNoUnpublishedRecoveryRecordEntries(
                path.dirname(marker.rootPath),
                'durability-failed validated-outcome cleanup',
            );
        }));

    it('keeps a failed canonical rollback multiply linked so exported validation refuses it', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const announcements: string[] = [];
            const sampleInvocations: CommandInvocation[] = [];
            let publicationFaultInjected = false;
            let rollbackFaultInjected = false;
            const dependencies = createDependencies({
                browserRecoveryMarkerFaultInjection: (event) => {
                    if (
                        !publicationFaultInjected &&
                        event.recordKind === 'validated-outcome' &&
                        event.stage === 'after-link-before-durability'
                    ) {
                        publicationFaultInjected = true;
                        throw new Error(
                            'Injected validated publication durability failure.',
                        );
                    }
                    if (
                        !rollbackFaultInjected &&
                        event.recordKind === 'validated-outcome' &&
                        event.stage === 'before-incomplete-canonical-unlink'
                    ) {
                        rollbackFaultInjected = true;
                        throw new Error(
                            'Injected canonical rollback unlink failure.',
                        );
                    }
                    return undefined;
                },
                fixture,
                preOperationRecoveryProfile: recoveryProfile,
                repositoryStateForCheckpoint: () => ({
                    commitHash: thirdRecoveryFinalHarnessCommitHash,
                    treeDirty: false,
                }),
                sampleInvocations,
            });
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies,
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath, {
                        writeCombinedOutput: (output) => {
                            if (
                                output.startsWith(
                                    'Proof-storage width browser evidence:',
                                )
                            ) {
                                announcements.push(output);
                            }
                        },
                        writeEvent: ({ eventType }) => {
                            if (
                                eventType ===
                                    'proof-storage-width-browser-evidence-complete' ||
                                eventType ===
                                    'proof-storage-width-browser-evidence-decisive-negative'
                            ) {
                                announcements.push(eventType);
                            }
                        },
                    }),
                }),
            ).rejects.toThrow(/finalization failed/u);
            expect(publicationFaultInjected).toBe(true);
            expect(rollbackFaultInjected).toBe(true);
            expect(sampleInvocations).toHaveLength(1);
            expect(announcements).toHaveLength(0);
            const preflightRootPath = path.join(
                fixture.reservationRootPath,
                'browser-recovery-preflight-3',
            );
            const preflightRootEntries = await readdir(preflightRootPath);
            const authorizationDirectoryName = preflightRootEntries.find(
                (entryName) => /^[0-9a-f]{64}$/u.test(entryName),
            );
            expect(authorizationDirectoryName).toBeDefined();
            const keyDirectoryPath = path.join(
                preflightRootPath,
                authorizationDirectoryName ?? '',
            );
            const terminalDirectoryPath = path.join(
                keyDirectoryPath,
                'terminal-outcome',
            );
            const canonicalRecordPath = path.join(
                terminalDirectoryPath,
                'record.json',
            );
            const terminalRecord = JSON.parse(
                await readFile(canonicalRecordPath, 'utf8'),
            ) as Record<string, unknown>;
            expect(terminalRecord).toMatchObject({
                eventType: 'official-sample-outcome',
                outcome: 'validated',
            });
            const stagingDirectoryNames = preflightRootEntries.filter(
                (entryName) =>
                    entryName.startsWith('.unpublished-recovery-record-'),
            );
            expect(stagingDirectoryNames).toHaveLength(1);
            const stagedRecordPath = path.join(
                preflightRootPath,
                stagingDirectoryNames[0] ?? '',
                'record.json',
            );
            const [canonicalStatistics, stagedStatistics] = await Promise.all([
                lstat(canonicalRecordPath),
                lstat(stagedRecordPath),
            ]);
            expect(canonicalStatistics.nlink).toBe(2);
            expect(stagedStatistics.nlink).toBe(2);
            expect(canonicalStatistics.dev).toBe(stagedStatistics.dev);
            expect(canonicalStatistics.ino).toBe(stagedStatistics.ino);
            expect(await readFile(canonicalRecordPath)).toEqual(
                await readFile(stagedRecordPath),
            );
            const attachmentPath = path.join(
                fixture.runDirectoryPath,
                'attachments',
                'proof-storage-width-browser-evidence.json',
            );
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        chainedRecoveryProfile:
                            recoveryProfile.chainedRecoveryProfile,
                        preOperationRecoveryProfile: recoveryProfile,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                        thirdRecoveryProfile:
                            recoveryProfile.thirdRecoveryProfile,
                    },
                ),
            ).rejects.toThrow(/singly linked regular file/u);
        }));

    it('detects same-size validated-terminal mutation after publication and never announces closure', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const announcements: string[] = [];
            const sampleInvocations: CommandInvocation[] = [];
            let mutated = false;
            let mutationByteLengthPreserved = false;
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        browserRecoveryMarkerFaultInjection: async (event) => {
                            if (
                                !mutated &&
                                event.recordKind === 'validated-outcome' &&
                                event.stage ===
                                    'after-publication-before-reopen'
                            ) {
                                const originalBytes = await readFile(
                                    event.markerPath,
                                );
                                const mutatedRecord = originalBytes
                                    .toString('utf8')
                                    .replace(
                                        '"outcome":"validated"',
                                        '"outcome":"validateD"',
                                    );
                                mutationByteLengthPreserved =
                                    Buffer.byteLength(mutatedRecord, 'utf8') ===
                                    originalBytes.byteLength;
                                await writeFile(
                                    event.markerPath,
                                    mutatedRecord,
                                    'utf8',
                                );
                                mutated = true;
                            }
                            return undefined;
                        },
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath, {
                        writeCombinedOutput: (output) => {
                            if (
                                output.startsWith(
                                    'Proof-storage width browser evidence:',
                                )
                            ) {
                                announcements.push(output);
                            }
                        },
                        writeEvent: ({ eventType }) => {
                            if (
                                eventType ===
                                    'proof-storage-width-browser-evidence-complete' ||
                                eventType ===
                                    'proof-storage-width-browser-evidence-decisive-negative'
                            ) {
                                announcements.push(eventType);
                            }
                        },
                    }),
                }),
            ).rejects.toThrow(
                /chained browser recovery finalization failed and its pending singleton could not record the failure/u,
            );
            expect(mutated).toBe(true);
            expect(mutationByteLengthPreserved).toBe(true);
            expect(sampleInvocations).toHaveLength(1);
            expect(announcements).toHaveLength(0);
            const marker = await readThirdRecoveryMarkerForTest(
                fixture.reservationRootPath,
            );
            expect(marker.records).toHaveLength(3);
            expect(marker.records[2]).toMatchObject({
                eventType: 'official-sample-outcome',
                outcome: 'validateD',
            });
        }));

    it('refuses an unexpected entry in the published ordinal-three marker before commands', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const allInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations,
                        browserRecoveryMarkerFaultInjection: async (event) => {
                            if (
                                event.recordKind === 'preflight-attempt' &&
                                event.stage ===
                                    'after-publication-before-reopen'
                            ) {
                                await writeFile(
                                    path.join(
                                        path.dirname(event.markerPath),
                                        'unexpected-marker-entry.txt',
                                    ),
                                    'unexpected',
                                    'utf8',
                                );
                            }
                            return undefined;
                        },
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: [],
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/could not be reopened safely/u);
            expect(allInvocations).toHaveLength(0);
            await expect(
                readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-3',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        }));

    it('allows exactly one ordinal-three measured invocation across an acquisition race', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const secondRunDirectoryPath = path.join(
                path.dirname(fixture.runDirectoryPath),
                'ordinal-three-race-second-run',
            );
            await mkdir(secondRunDirectoryPath);
            let preflightArrivalCount = 0;
            let reportFirstPreflightArrival: (() => void) | undefined;
            const firstPreflightArrival = new Promise<void>((resolve) => {
                reportFirstPreflightArrival = resolve;
            });
            let releasePreflightBarrier: (() => void) | undefined;
            const preflightBarrier = new Promise<void>((resolve) => {
                releasePreflightBarrier = resolve;
            });
            const raceFaultInjection: BrowserRecoveryMarkerFaultInjection =
                async (event) => {
                    if (
                        event.recordKind === 'preflight-attempt' &&
                        event.stage === 'before-staged-write'
                    ) {
                        preflightArrivalCount += 1;
                        if (preflightArrivalCount > 1) {
                            throw new Error(
                                'A second racer passed the exclusive singleton claim.',
                            );
                        }
                        reportFirstPreflightArrival?.();
                        await preflightBarrier;
                    }
                    return undefined;
                };
            const sampleInvocations: CommandInvocation[] = [];
            const executeRacer = (runDirectoryPath: string): Promise<void> =>
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        browserRecoveryMarkerFaultInjection: raceFaultInjection,
                        fixture: { ...fixture, runDirectoryPath },
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: thirdRecoveryFinalHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...thirdRecoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(runDirectoryPath),
                });
            const firstRacer = executeRacer(fixture.runDirectoryPath);
            await firstPreflightArrival;
            const secondRacerResult = await executeRacer(
                secondRunDirectoryPath,
            ).then(
                () => ({ status: 'fulfilled' as const }),
                (reason: unknown) => ({ reason, status: 'rejected' as const }),
            );
            releasePreflightBarrier?.();
            const firstRacerResult = await firstRacer.then(
                () => ({ status: 'fulfilled' as const }),
                (reason: unknown) => ({ reason, status: 'rejected' as const }),
            );
            const results = [firstRacerResult, secondRacerResult];
            expect(preflightArrivalCount).toBe(1);
            expect(
                results.filter((result) => result.status === 'fulfilled'),
            ).toHaveLength(1);
            expect(
                results.filter((result) => result.status === 'rejected'),
            ).toHaveLength(1);
            expect(sampleInvocations).toHaveLength(1);
            const marker = await readThirdRecoveryMarkerForTest(
                fixture.reservationRootPath,
            );
            expect(marker.records).toHaveLength(3);
            expect(marker.records[2]).toMatchObject({
                eventType: 'official-sample-outcome',
                outcome: 'validated',
            });
            const preflightRootEntries = await readdir(
                path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-3',
                ),
            );
            expect(preflightRootEntries).toEqual([
                marker.authorizationKeySha256Hex,
            ]);
            expect(
                await readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-3',
                    ),
                ),
            ).toEqual([marker.authorizationKeySha256Hex]);
        }));

    it('closes successful ordinal-three evidence as format seven before announcement', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createThirdRecoveryFixtureProfile(fixture);
            const sampleInvocations: CommandInvocation[] = [];
            const dependencies = createDependencies({
                fixture,
                preOperationRecoveryProfile: recoveryProfile,
                repositoryStateForCheckpoint: () => ({
                    commitHash: thirdRecoveryFinalHarnessCommitHash,
                    treeDirty: false,
                }),
                sampleInvocations,
            });
            let announcementCount = 0;
            const assertTerminalMarker = (): void => {
                const singletonDirectories = readdirSync(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-3',
                    ),
                );
                expect(singletonDirectories).toHaveLength(1);
                const markerRootPath = path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-3',
                    singletonDirectories[0] ?? '',
                );
                const records = [
                    readFileSync(
                        path.join(
                            markerRootPath,
                            'preflight-attempted',
                            'record.json',
                        ),
                        'utf8',
                    ),
                    readFileSync(
                        path.join(
                            markerRootPath,
                            'static-preflight-observed',
                            'record.json',
                        ),
                        'utf8',
                    ),
                    readFileSync(
                        path.join(
                            markerRootPath,
                            'terminal-outcome',
                            'record.json',
                        ),
                        'utf8',
                    ),
                ]
                    .join('')
                    .trim()
                    .split('\n')
                    .map((line) => JSON.parse(line) as Record<string, unknown>);
                expect(records).toHaveLength(3);
                expect(records[2]).toMatchObject({
                    eventType: 'official-sample-outcome',
                    outcome: 'validated',
                });
                announcementCount += 1;
            };
            await executeProofStorageWidthBrowserEvidence({
                dependencies,
                nativeEvidencePath: fixture.nativeEvidencePath,
                ...thirdRecoveryExecutionPaths(recoveryProfile),
                runLog: createRunLog(fixture.runDirectoryPath, {
                    writeCombinedOutput: (output) => {
                        if (
                            output.startsWith(
                                'Proof-storage width browser evidence:',
                            )
                        ) {
                            assertTerminalMarker();
                        }
                    },
                    writeEvent: ({ eventType }) => {
                        if (
                            eventType ===
                            'proof-storage-width-browser-evidence-complete'
                        ) {
                            assertTerminalMarker();
                        }
                    },
                }),
            });
            expect(announcementCount).toBe(2);
            expect(sampleInvocations).toHaveLength(1);
            const attachmentPath = path.join(
                fixture.runDirectoryPath,
                'attachments',
                'proof-storage-width-browser-evidence.json',
            );
            const evidence = JSON.parse(
                await readFile(attachmentPath, 'utf8'),
            ) as {
                readonly formatVersion: number;
                readonly officialSampleReservation: {
                    readonly schemaVersion: string;
                };
                readonly recovery: {
                    readonly recoveryOrdinal: number;
                    readonly thirdRecoveryHarness: {
                        readonly harnessCommitHash: string;
                        readonly nativeSourceCommitHash: string;
                    };
                };
            };
            expect(evidence).toMatchObject({
                formatVersion: 7,
                officialSampleReservation: {
                    schemaVersion: 'browser-recovery-3',
                },
                recovery: {
                    recoveryOrdinal: 3,
                    thirdRecoveryHarness: {
                        harnessCommitHash: thirdRecoveryFinalHarnessCommitHash,
                        nativeSourceCommitHash: thirdRecoveryIssuanceCommitHash,
                    },
                },
            });
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        chainedRecoveryProfile:
                            recoveryProfile.chainedRecoveryProfile,
                        preOperationRecoveryProfile: recoveryProfile,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                        thirdRecoveryProfile:
                            recoveryProfile.thirdRecoveryProfile,
                    },
                ),
            ).resolves.toBeUndefined();
            const terminalMarker = await readThirdRecoveryMarkerForTest(
                fixture.reservationRootPath,
            );
            expect(terminalMarker.records).toHaveLength(3);
            expect(terminalMarker.terminalDirectoryPath).toBeDefined();
            expect(terminalMarker.terminalRecordBytes).toBeDefined();
            await rm(terminalMarker.terminalDirectoryPath ?? '', {
                recursive: true,
            });
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        chainedRecoveryProfile:
                            recoveryProfile.chainedRecoveryProfile,
                        preOperationRecoveryProfile: recoveryProfile,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                        thirdRecoveryProfile:
                            recoveryProfile.thirdRecoveryProfile,
                    },
                ),
            ).rejects.toThrow(/requires its validated terminal marker/u);
            await mkdir(terminalMarker.terminalDirectoryPath ?? '');
            await writeFile(
                path.join(
                    terminalMarker.terminalDirectoryPath ?? '',
                    'record.json',
                ),
                terminalMarker.terminalRecordBytes ?? Buffer.alloc(0),
            );
        }));

    it('requires one raw measurement record and refuses unrelated or duplicate JSONL records', () => {
        const wasmSha256Hex = '12'.repeat(32);
        const event = JSON.stringify({
            event: 'proof-storage-width-browser-evidence',
            ...createMeasurementRecord(wasmSha256Hex),
            browser: true,
        });
        expect(() =>
            parseProofStorageWidthBrowserMeasurementEvents({
                expectedWasmSha256Hex: wasmSha256Hex,
                serializedEvents: `${event}\n`,
            }),
        ).not.toThrow();
        for (const serializedEvents of [
            `${JSON.stringify({ event: 'unrelated' })}\n${event}\n`,
            `${event}\n${event}\n`,
            `${JSON.stringify({ event: 'unrelated' })}\n`,
        ]) {
            expect(() =>
                parseProofStorageWidthBrowserMeasurementEvents({
                    expectedWasmSha256Hex: wasmSha256Hex,
                    serializedEvents,
                }),
            ).toThrow(/exactly one measurement record/u);
        }
    });

    it('pins one zero-retry invocation and reopens every bound artifact', () =>
        withTemporaryFixture(async (fixture) => {
            const sampleInvocations: CommandInvocation[] = [];
            const lifecycle: string[] = [];
            const dependencies = createDependencies({
                fixture,
                repositoryStateForCheckpoint: (checkpoint) => {
                    lifecycle.push(`repository:${checkpoint}`);
                    return { commitHash, treeDirty: false };
                },
                sampleInvocations,
            });
            await executeProofStorageWidthBrowserEvidence({
                dependencies,
                nativeEvidencePath: fixture.nativeEvidencePath,
                runLog: createRunLog(fixture.runDirectoryPath, {
                    writeCombinedOutput: () => lifecycle.push('output'),
                    writeEvent: (event) => {
                        if (
                            event.eventType ===
                            'proof-storage-width-browser-evidence-complete'
                        ) {
                            lifecycle.push('completion-event');
                        }
                    },
                }),
            });
            expect(lifecycle).toEqual([
                'repository:initial',
                'repository:before',
                'repository:pre-operation',
                'repository:after',
                'repository:closure-after',
                'output',
                'completion-event',
            ]);
            expect(sampleInvocations).toHaveLength(1);
            expect(sampleInvocations[0]?.args).toEqual(
                expect.arrayContaining([
                    ...proofStorageWidthBrowserEvidenceVitestArguments,
                ]),
            );
            expect(sampleInvocations[0]?.args).toContain('--retry=0');
            expect(
                sampleInvocations[0]?.args.some((argument) =>
                    /^--retry=(?!0$)/u.test(argument),
                ),
            ).toBe(false);

            const attachmentPath = path.join(
                fixture.runDirectoryPath,
                'attachments',
                'proof-storage-width-browser-evidence.json',
            );
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                    },
                ),
            ).resolves.toBeUndefined();

            const evidence = JSON.parse(
                await readFile(attachmentPath, 'utf8'),
            ) as {
                readonly artifacts: {
                    readonly browserEvents: { readonly path: string };
                    readonly guard: { readonly path: string };
                    readonly nativeAggregate: { readonly path: string };
                };
                readonly officialSampleReservation: {
                    readonly path: string;
                };
            };
            const tamperPaths = [
                path.resolve(
                    fixture.runDirectoryPath,
                    evidence.artifacts.browserEvents.path,
                ),
                path.resolve(
                    fixture.runDirectoryPath,
                    evidence.artifacts.guard.path,
                ),
                evidence.artifacts.nativeAggregate.path,
                fixture.processedWasmKernelPath,
                path.resolve(
                    fixture.reservationRootPath,
                    evidence.officialSampleReservation.path,
                ),
            ];
            for (const tamperPath of tamperPaths) {
                const originalBytes = await readFile(tamperPath);
                await writeFile(
                    tamperPath,
                    Buffer.concat([originalBytes, Buffer.from([1])]),
                );
                await expect(
                    validateProofStorageWidthBrowserEvidenceArtifacts(
                        attachmentPath,
                        {
                            loadNativeWidthEvidence:
                                dependencies.loadNativeWidthEvidence,
                            officialReservationRootPath:
                                fixture.reservationRootPath,
                            processedWasmKernelPath:
                                fixture.processedWasmKernelPath,
                            publicSdkWasmKernelPath:
                                fixture.publicSdkWasmKernelPath,
                        },
                    ),
                ).rejects.toThrow();
                await writeFile(tamperPath, originalBytes);
            }

            const secondRunDirectoryPath = path.join(
                path.dirname(fixture.runDirectoryPath),
                'second-run',
            );
            await mkdir(secondRunDirectoryPath);
            const replacementInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        fixture: {
                            ...fixture,
                            runDirectoryPath: secondRunDirectoryPath,
                        },
                        sampleInvocations: replacementInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    runLog: createRunLog(secondRunDirectoryPath),
                }),
            ).rejects.toThrow(/durable started reservation/u);
            expect(replacementInvocations).toHaveLength(0);
        }));

    it('preserves the ordinal-one recovery closure and immutable singleton', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            await rm(
                path.join(
                    fixture.reservationRootPath,
                    recoveryProfile.chainedRecoveryProfile
                        .previousPreflightAttempt.relativePath,
                ),
            );
            const sampleInvocations: CommandInvocation[] = [];
            const dependencies = createDependencies({
                fixture,
                preOperationRecoveryProfile: recoveryProfile,
                repositoryStateForCheckpoint: () => ({
                    commitHash: firstHarnessRepairCommitHash,
                    treeDirty: false,
                }),
                sampleInvocations,
            });
            await executeProofStorageWidthBrowserEvidence({
                dependencies,
                nativeEvidencePath: fixture.nativeEvidencePath,
                preOperationRecoveryRunDirectoryPath:
                    recoveryProfile.failedRunDirectoryPath,
                runLog: createRunLog(fixture.runDirectoryPath),
            });
            expect(sampleInvocations).toHaveLength(1);
            const attachmentPath = path.join(
                fixture.runDirectoryPath,
                'attachments',
                'proof-storage-width-browser-evidence.json',
            );
            const evidence = JSON.parse(
                await readFile(attachmentPath, 'utf8'),
            ) as {
                readonly formatVersion: number;
                readonly officialSampleReservation: {
                    readonly authorizationKeySha256Hex: string;
                    readonly path: string;
                    readonly schemaVersion: string;
                };
                readonly recovery: {
                    readonly changedFilePaths: readonly string[];
                    readonly harnessCommitHash: string;
                    readonly recoveryOrdinal: number;
                    readonly staticPreflight: {
                        readonly attempt: {
                            readonly path: string;
                            readonly sha256Hex: string;
                        };
                    };
                };
            };
            expect(evidence).toMatchObject({
                formatVersion: 5,
                officialSampleReservation: {
                    schemaVersion: 'browser-recovery-1',
                },
                recovery: {
                    changedFilePaths: recoveryRepairFilePaths,
                    harnessCommitHash: firstHarnessRepairCommitHash,
                    recoveryOrdinal: 1,
                },
            });
            expect(evidence.officialSampleReservation.path).toMatch(
                /^browser-recovery\/[0-9a-f]{64}\/browser-recovery-started\.json$/u,
            );
            const preflightPath = path.join(
                fixture.reservationRootPath,
                evidence.recovery.staticPreflight.attempt.path,
            );
            const serializedPreflight = await readFile(preflightPath, 'utf8');
            expect(sha256Hex(serializedPreflight)).toBe(
                evidence.recovery.staticPreflight.attempt.sha256Hex,
            );
            const records = serializedPreflight
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as { outcome?: string });
            expect(records).toHaveLength(3);
            expect(records[2]?.outcome).toBe('validated');
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        preOperationRecoveryProfile: recoveryProfile,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                    },
                ),
            ).resolves.toBeUndefined();
        }));

    it('preserves the ordinal-one failed singleton and blocks a second invocation before commands', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            await rm(
                path.join(
                    fixture.reservationRootPath,
                    recoveryProfile.chainedRecoveryProfile
                        .previousPreflightAttempt.relativePath,
                ),
            );
            const firstInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: firstHarnessRepairCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: firstInvocations,
                        staticPreflightStderr: 'unexpected diagnostic\n',
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    preOperationRecoveryRunDirectoryPath:
                        recoveryProfile.failedRunDirectoryPath,
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/no standard-error diagnostics/u);
            expect(firstInvocations).toHaveLength(0);
            const singletonDirectories = await readdir(
                path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight',
                ),
            );
            expect(singletonDirectories).toHaveLength(1);
            const currentAuthorizationKey = singletonDirectories[0];
            expect(currentAuthorizationKey).toBeDefined();
            const singletonRecords = (
                await readFile(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight',
                        currentAuthorizationKey ?? '',
                        'preflight-attempted.json',
                    ),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as { outcome?: string });
            expect(singletonRecords).toHaveLength(2);
            expect(singletonRecords[1]?.outcome).toBe('failed');

            const secondRunDirectoryPath = path.join(
                path.dirname(fixture.runDirectoryPath),
                'ordinal-one-second-invocation',
            );
            await mkdir(secondRunDirectoryPath);
            const secondInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations: secondInvocations,
                        fixture: {
                            ...fixture,
                            runDirectoryPath: secondRunDirectoryPath,
                        },
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: firstHarnessRepairCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: [],
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    preOperationRecoveryRunDirectoryPath:
                        recoveryProfile.failedRunDirectoryPath,
                    runLog: createRunLog(secondRunDirectoryPath),
                }),
            ).rejects.toThrow(/already attempted its static preflight/u);
            expect(secondInvocations).toHaveLength(0);
        }));

    it('chains one recovery through both failures and three clean commit transitions', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            const sampleInvocations: CommandInvocation[] = [];
            const allInvocations: CommandInvocation[] = [];
            const nativeEvidenceLoadCounts: number[] = [];
            let terminalBeforeAnnouncementAssertionCount = 0;
            const assertValidatedTerminalBeforeAnnouncement = (): void => {
                const singletonRootPath = path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-2',
                );
                const singletonDirectories = readdirSync(singletonRootPath);
                expect(singletonDirectories).toHaveLength(1);
                const markerRecords = readFileSync(
                    path.join(
                        singletonRootPath,
                        singletonDirectories[0] ?? '',
                        'preflight-attempted.json',
                    ),
                    'utf8',
                )
                    .trim()
                    .split('\n')
                    .map((line) => JSON.parse(line) as Record<string, unknown>);
                expect(markerRecords).toHaveLength(3);
                expect(markerRecords[2]).toMatchObject({
                    eventType: 'official-sample-outcome',
                    outcome: 'validated',
                });
                expect(
                    nativeEvidenceLoadCounts[
                        nativeEvidenceLoadCounts.length - 1
                    ],
                ).toBeGreaterThanOrEqual(3);
                terminalBeforeAnnouncementAssertionCount += 1;
            };
            const dependencies = createDependencies({
                allInvocations,
                fixture,
                nativeEvidenceLoadCounts,
                preOperationRecoveryProfile: recoveryProfile,
                repositoryStateForCheckpoint: () => ({
                    commitHash: recoveryHarnessCommitHash,
                    treeDirty: false,
                }),
                sampleInvocations,
            });
            const failedReservationPath = path.join(
                fixture.reservationRootPath,
                recoveryProfile.failedReservation.relativePath,
            );
            const failedReservationBefore = await readFile(
                failedReservationPath,
            );
            const previousPreflightAttemptPath = path.join(
                fixture.reservationRootPath,
                recoveryProfile.chainedRecoveryProfile.previousPreflightAttempt
                    .relativePath,
            );
            const previousPreflightAttemptBefore = await readFile(
                previousPreflightAttemptPath,
            );
            await executeProofStorageWidthBrowserEvidence({
                dependencies,
                nativeEvidencePath: fixture.nativeEvidencePath,
                ...recoveryExecutionPaths(recoveryProfile),
                runLog: createRunLog(fixture.runDirectoryPath, {
                    writeCombinedOutput: (output) => {
                        if (
                            output.startsWith(
                                'Proof-storage width browser evidence:',
                            )
                        ) {
                            assertValidatedTerminalBeforeAnnouncement();
                        }
                    },
                    writeEvent: ({ eventType }) => {
                        if (
                            eventType ===
                            'proof-storage-width-browser-evidence-complete'
                        ) {
                            assertValidatedTerminalBeforeAnnouncement();
                        }
                    },
                }),
            });
            expect(terminalBeforeAnnouncementAssertionCount).toBe(2);
            expect(sampleInvocations).toHaveLength(1);
            const semanticArgumentStartIndex =
                sampleInvocations[0]?.args.indexOf('exec') ?? -1;
            expect(semanticArgumentStartIndex).toBeGreaterThanOrEqual(0);
            expect(
                sampleInvocations[0]?.args.slice(semanticArgumentStartIndex),
            ).toEqual(proofStorageWidthBrowserEvidenceVitestArguments);
            const rawCommitInvocations = allInvocations.filter((invocation) =>
                invocation.args.includes('cat-file'),
            );
            const rawTreeDiffInvocations = allInvocations.filter((invocation) =>
                invocation.args.includes('diff'),
            );
            expect(rawCommitInvocations.length).toBeGreaterThanOrEqual(3);
            expect(rawTreeDiffInvocations.length).toBeGreaterThanOrEqual(3);
            for (const invocation of [
                ...rawCommitInvocations,
                ...rawTreeDiffInvocations,
            ]) {
                expect(invocation.args[0]).toBe('--no-replace-objects');
                expect(invocation.env?.GIT_NO_REPLACE_OBJECTS).toBe('1');
            }
            for (const invocation of rawCommitInvocations) {
                expect(invocation.args.slice(0, 3)).toEqual([
                    '--no-replace-objects',
                    'cat-file',
                    'commit',
                ]);
            }
            for (const invocation of rawTreeDiffInvocations) {
                expect(invocation.args.slice(0, 5)).toEqual([
                    '--no-replace-objects',
                    'diff',
                    '--name-status',
                    '-z',
                    '--no-renames',
                ]);
                expect(invocation.args[invocation.args.length - 1]).toBe('--');
            }
            expect(await readFile(failedReservationPath)).toEqual(
                failedReservationBefore,
            );
            expect(await readFile(previousPreflightAttemptPath)).toEqual(
                previousPreflightAttemptBefore,
            );

            const attachmentPath = path.join(
                fixture.runDirectoryPath,
                'attachments',
                'proof-storage-width-browser-evidence.json',
            );
            const evidence = JSON.parse(
                await readFile(attachmentPath, 'utf8'),
            ) as {
                readonly formatVersion: number;
                readonly officialSampleReservation: {
                    readonly authorizationKeySha256Hex: string;
                    readonly path: string;
                    readonly schemaVersion: string;
                    readonly sha256Hex: string;
                };
                readonly recovery: {
                    readonly firstHarnessRepair: {
                        readonly changedFilePaths: readonly string[];
                        readonly harnessCommitHash: string;
                        readonly nativeSourceCommitHash: string;
                    };
                    readonly nativeSourceCommitHash: string;
                    readonly recoveryHarnessRepair: {
                        readonly changedFilePaths: readonly string[];
                        readonly harnessCommitHash: string;
                        readonly nativeSourceCommitHash: string;
                    };
                    readonly recoveryOrdinal: number;
                    readonly staticPreflight: {
                        readonly attempt: {
                            readonly path: string;
                            readonly prefixByteLength: number;
                            readonly prefixSha256Hex: string;
                        };
                        readonly outputSha256Hex: string;
                    };
                    readonly validatorRepair: {
                        readonly changedFilePaths: readonly string[];
                        readonly harnessCommitHash: string;
                        readonly nativeSourceCommitHash: string;
                    };
                };
            };
            expect(evidence).toMatchObject({
                formatVersion: 6,
                officialSampleReservation: {
                    schemaVersion: 'browser-recovery-2',
                },
                recovery: {
                    firstHarnessRepair: {
                        changedFilePaths: recoveryRepairFilePaths,
                        harnessCommitHash: firstHarnessRepairCommitHash,
                        nativeSourceCommitHash: commitHash,
                    },
                    nativeSourceCommitHash: commitHash,
                    recoveryHarnessRepair: {
                        changedFilePaths: validatorRepairFilePaths,
                        harnessCommitHash: recoveryHarnessCommitHash,
                        nativeSourceCommitHash: validatorRepairCommitHash,
                    },
                    recoveryOrdinal: 2,
                    validatorRepair: {
                        changedFilePaths: validatorRepairFilePaths,
                        harnessCommitHash: validatorRepairCommitHash,
                        nativeSourceCommitHash: firstHarnessRepairCommitHash,
                    },
                },
            });
            expect(evidence.officialSampleReservation.path).toMatch(
                /^browser-recovery-2\/[0-9a-f]{64}\/browser-recovery-started\.json$/u,
            );
            expect(evidence.recovery.staticPreflight.attempt.path).toBe(
                `browser-recovery-preflight-2/${evidence.officialSampleReservation.authorizationKeySha256Hex}/preflight-attempted.json`,
            );
            const preflightMarkerPath = path.join(
                fixture.reservationRootPath,
                evidence.recovery.staticPreflight.attempt.path,
            );
            const serializedPreflightMarker = await readFile(
                preflightMarkerPath,
                'utf8',
            );
            const preflightRecords = serializedPreflightMarker
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(preflightRecords).toHaveLength(3);
            expect(preflightRecords[1]).toMatchObject({
                eventType:
                    'official-browser-width-recovery-static-preflight-observed',
                staticListStderr: '',
                staticListStderrSha256Hex: sha256Hex(''),
                staticListStdout: browserEvidenceStaticPreflightOutput,
                staticListStdoutSha256Hex:
                    evidence.recovery.staticPreflight.outputSha256Hex,
            });
            const preflightPrefix = `${serializedPreflightMarker
                .trim()
                .split(/\r?\n/u)
                .slice(0, 2)
                .join('\n')}\n`;
            expect(evidence.recovery.staticPreflight.attempt).toMatchObject({
                prefixByteLength: Buffer.byteLength(preflightPrefix, 'utf8'),
                prefixSha256Hex: sha256Hex(preflightPrefix),
            });
            expect(preflightRecords[2]).toMatchObject({
                attachmentPath,
                attachmentSha256Hex: sha256Hex(await readFile(attachmentPath)),
                decisionOutcome: 'eligible',
                eventType: 'official-sample-outcome',
                identitySha256Hex: preflightRecords[1]?.identitySha256Hex,
                markerPrefixByteLength: Buffer.byteLength(
                    preflightPrefix,
                    'utf8',
                ),
                markerPrefixSha256Hex: sha256Hex(preflightPrefix),
                outcome: 'validated',
                operationReservationPath:
                    evidence.officialSampleReservation.path,
                operationReservationSha256Hex:
                    evidence.officialSampleReservation.sha256Hex,
            });
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        chainedRecoveryProfile:
                            recoveryProfile.chainedRecoveryProfile,
                        preOperationRecoveryProfile: recoveryProfile,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                    },
                ),
            ).resolves.toBeUndefined();

            const originalAttachmentBytes = await readFile(attachmentPath);
            const originalPreflightMarkerBytes =
                await readFile(preflightMarkerPath);
            const originalPreflightMarker =
                originalPreflightMarkerBytes.toString('utf8');
            await writeFile(preflightMarkerPath, preflightPrefix, 'utf8');
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        chainedRecoveryProfile:
                            recoveryProfile.chainedRecoveryProfile,
                        preOperationRecoveryProfile: recoveryProfile,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                    },
                ),
            ).rejects.toThrow(/requires its validated terminal marker/u);
            const truncatedTerminal = `${preflightPrefix}${JSON.stringify(
                preflightRecords[2],
            ).slice(0, -8)}`;
            await writeFile(preflightMarkerPath, truncatedTerminal, 'utf8');
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        chainedRecoveryProfile:
                            recoveryProfile.chainedRecoveryProfile,
                        preOperationRecoveryProfile: recoveryProfile,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                    },
                ),
            ).rejects.toThrow(/LF-terminated JSONL/u);
            await writeFile(preflightMarkerPath, originalPreflightMarkerBytes);
            for (const tamperedMarker of [
                originalPreflightMarker.replace('\n', '\n\n'),
                originalPreflightMarker.replace('\n', '\r\n'),
            ]) {
                await writeFile(preflightMarkerPath, tamperedMarker, 'utf8');
                await expect(
                    validateProofStorageWidthBrowserEvidenceArtifacts(
                        attachmentPath,
                        {
                            loadNativeWidthEvidence:
                                dependencies.loadNativeWidthEvidence,
                            officialReservationRootPath:
                                fixture.reservationRootPath,
                            chainedRecoveryProfile:
                                recoveryProfile.chainedRecoveryProfile,
                            preOperationRecoveryProfile: recoveryProfile,
                            processedWasmKernelPath:
                                fixture.processedWasmKernelPath,
                            publicSdkWasmKernelPath:
                                fixture.publicSdkWasmKernelPath,
                        },
                    ),
                ).rejects.toThrow(
                    /LF-terminated JSONL|no blank JSONL records/u,
                );
            }
            await writeFile(preflightMarkerPath, originalPreflightMarkerBytes);
            const unrelatedStaticListOutput =
                '[chromium-proof-storage-width-evidence] tests/node/unrelated.test.ts\n';
            const tamperedPreflightRecords = [
                preflightRecords[0],
                {
                    ...preflightRecords[1],
                    staticListStdout: unrelatedStaticListOutput,
                    staticListStdoutSha256Hex: sha256Hex(
                        unrelatedStaticListOutput,
                    ),
                },
            ];
            const tamperedPreflightPrefix = `${tamperedPreflightRecords
                .map((record) => JSON.stringify(record))
                .join('\n')}\n`;
            const tamperedEvidence = {
                ...evidence,
                recovery: {
                    ...evidence.recovery,
                    staticPreflight: {
                        ...evidence.recovery.staticPreflight,
                        attempt: {
                            ...evidence.recovery.staticPreflight.attempt,
                            prefixByteLength: Buffer.byteLength(
                                tamperedPreflightPrefix,
                                'utf8',
                            ),
                            prefixSha256Hex: sha256Hex(tamperedPreflightPrefix),
                        },
                        outputSha256Hex: sha256Hex(unrelatedStaticListOutput),
                    },
                },
            };
            const serializedTamperedEvidence = `${JSON.stringify(
                tamperedEvidence,
                null,
                2,
            )}\n`;
            const tamperedPreflightMarker = `${tamperedPreflightPrefix}${JSON.stringify(
                {
                    ...preflightRecords[2],
                    attachmentSha256Hex: sha256Hex(serializedTamperedEvidence),
                    markerPrefixByteLength: Buffer.byteLength(
                        tamperedPreflightPrefix,
                        'utf8',
                    ),
                    markerPrefixSha256Hex: sha256Hex(tamperedPreflightPrefix),
                },
            )}\n`;
            await Promise.all([
                writeFile(preflightMarkerPath, tamperedPreflightMarker, 'utf8'),
                writeFile(attachmentPath, serializedTamperedEvidence, 'utf8'),
            ]);
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        chainedRecoveryProfile:
                            recoveryProfile.chainedRecoveryProfile,
                        preOperationRecoveryProfile: recoveryProfile,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                    },
                ),
            ).rejects.toThrow(/exactly the fixed evidence test file/u);
            await Promise.all([
                writeFile(preflightMarkerPath, originalPreflightMarkerBytes),
                writeFile(attachmentPath, originalAttachmentBytes),
            ]);

            const secondHarnessCommitHash = '5e'.repeat(20);
            const secondRunDirectoryPath = path.join(
                path.dirname(fixture.runDirectoryPath),
                'alternate-harness-run',
            );
            await mkdir(secondRunDirectoryPath);
            const alternateHarnessInvocations: CommandInvocation[] = [];
            const failedRecoveryArtifacts =
                recoveryProfile.chainedRecoveryProfile.failedRecoveryArtifacts;
            const reorderedChainedRecoveryProfile = {
                ...recoveryProfile.chainedRecoveryProfile,
                failedRecoveryArtifacts: {
                    summary: failedRecoveryArtifacts.summary,
                    resources: failedRecoveryArtifacts.resources,
                    output: failedRecoveryArtifacts.output,
                    metadata: failedRecoveryArtifacts.metadata,
                    events: failedRecoveryArtifacts.events,
                    diagnostics: failedRecoveryArtifacts.diagnostics,
                },
            } satisfies ProofStorageWidthBrowserChainedRecoveryProfile;
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        chainedRecoveryProfile: reorderedChainedRecoveryProfile,
                        fixture: {
                            ...fixture,
                            runDirectoryPath: secondRunDirectoryPath,
                        },
                        allInvocations: alternateHarnessInvocations,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: secondHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: [],
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(secondRunDirectoryPath),
                }),
            ).rejects.toThrow(/already attempted its static preflight/u);
            expect(alternateHarnessInvocations).toHaveLength(0);
            for (const reservationKind of [
                'browser-recovery-preflight-2',
                'browser-recovery-2',
            ]) {
                expect(
                    await readdir(
                        path.join(fixture.reservationRootPath, reservationKind),
                    ),
                ).toEqual([
                    evidence.officialSampleReservation
                        .authorizationKeySha256Hex,
                ]);
            }
        }));

    it('consumes the ordinal-two singleton on every recognized pre-operation gate failure', async () => {
        for (const failure of [
            {
                expectedPattern: /exactly the fixed evidence test file/u,
                label: 'unexpected-list-output',
                staticPreflightStdout: `${browserEvidenceStaticPreflightOutput}[node] tests/node/unrelated.test.ts\n`,
            },
            {
                expectedPattern: /no standard-error diagnostics/u,
                label: 'static-list-diagnostic',
                staticPreflightStderr: 'unexpected static-list diagnostic\n',
            },
            {
                expectedPattern: /authorized harness files/u,
                label: 'changed-file-set',
                transitionChangedFilePaths: [
                    ...validatorRepairFilePaths,
                    'packages/wasm/src/unrelated.ts',
                ],
            },
            {
                expectedPattern: /sole direct child/u,
                label: 'non-direct-child',
                transitionCommitObject: [
                    `tree ${'7a'.repeat(20)}`,
                    `parent ${validatorRepairCommitHash}`,
                    `parent ${'4f'.repeat(20)}`,
                    'author Test Author <test@example.invalid> 1 +0000',
                    'committer Test Author <test@example.invalid> 1 +0000',
                    '',
                    'merge repair commit',
                    '',
                ].join('\n'),
            },
            {
                dirtyInitialRepository: true,
                expectedPattern: /initial checkpoint/u,
                label: 'dirty-initial-repository',
            },
        ] as const) {
            await withTemporaryFixture(async (fixture) => {
                const recoveryProfile =
                    await createPreOperationRecoveryProfile(fixture);
                const sampleInvocations: CommandInvocation[] = [];
                let observedFailure: unknown;
                try {
                    await executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: (checkpoint) => ({
                                commitHash: recoveryHarnessCommitHash,
                                treeDirty:
                                    'dirtyInitialRepository' in failure &&
                                    failure.dirtyInitialRepository === true &&
                                    checkpoint === 'initial',
                            }),
                            sampleInvocations,
                            ...('staticPreflightStderr' in failure
                                ? {
                                      staticPreflightStderr:
                                          failure.staticPreflightStderr,
                                  }
                                : {}),
                            ...('staticPreflightStdout' in failure
                                ? {
                                      staticPreflightStdout:
                                          failure.staticPreflightStdout,
                                  }
                                : {}),
                            ...('transitionChangedFilePaths' in failure
                                ? {
                                      transitionChangedFilePaths:
                                          failure.transitionChangedFilePaths,
                                  }
                                : {}),
                            ...('transitionCommitObject' in failure
                                ? {
                                      transitionCommitObject:
                                          failure.transitionCommitObject,
                                  }
                                : {}),
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...recoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(fixture.runDirectoryPath),
                    });
                } catch (error) {
                    observedFailure = error;
                }
                expect(observedFailure, failure.label).toBeInstanceOf(Error);
                expect(
                    (observedFailure as Error).message,
                    failure.label,
                ).toMatch(failure.expectedPattern);
                expect(sampleInvocations).toHaveLength(0);
                await expect(
                    readdir(
                        path.join(
                            fixture.reservationRootPath,
                            'browser-recovery-2',
                        ),
                    ),
                ).rejects.toMatchObject({ code: 'ENOENT' });
                const singletonDirectories = await readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-2',
                    ),
                );
                expect(singletonDirectories).toHaveLength(1);
                const singletonRecords = (
                    await readFile(
                        path.join(
                            fixture.reservationRootPath,
                            'browser-recovery-preflight-2',
                            singletonDirectories[0] ?? '',
                            'preflight-attempted.json',
                        ),
                        'utf8',
                    )
                )
                    .trim()
                    .split(/\r?\n/u)
                    .map((line) => JSON.parse(line) as { outcome?: string });
                expect(singletonRecords).toHaveLength(2);
                expect(singletonRecords[1]?.outcome).toBe('failed');

                const correctedRunDirectoryPath = path.join(
                    path.dirname(fixture.runDirectoryPath),
                    `corrected-${failure.label}`,
                );
                await mkdir(correctedRunDirectoryPath);
                const correctedAllInvocations: CommandInvocation[] = [];
                const correctedSampleInvocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            allInvocations: correctedAllInvocations,
                            fixture: {
                                ...fixture,
                                runDirectoryPath: correctedRunDirectoryPath,
                            },
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: recoveryHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations: correctedSampleInvocations,
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...recoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(correctedRunDirectoryPath),
                    }),
                ).rejects.toThrow(/already attempted its static preflight/u);
                expect(correctedAllInvocations).toHaveLength(0);
                expect(correctedSampleInvocations).toHaveLength(0);
            });
        }
    });

    it('refuses wrong raw parent, status, and file custody on every chained commit edge', async () => {
        const transitionCommitHashes = [
            firstHarnessRepairCommitHash,
            validatorRepairCommitHash,
            recoveryHarnessCommitHash,
        ] as const;
        for (const transitionCommitHash of transitionCommitHashes) {
            for (const mutation of [
                {
                    expectedPattern: /sole direct child/u,
                    label: 'wrong-parent',
                    transitionCommitObject: [
                        `tree ${'7a'.repeat(20)}`,
                        `parent ${'4f'.repeat(20)}`,
                        'author Test Author <test@example.invalid> 1 +0000',
                        'committer Test Author <test@example.invalid> 1 +0000',
                        '',
                        'wrong parent repair',
                        '',
                    ].join('\n'),
                },
                {
                    expectedPattern: /authorized harness files/u,
                    label: 'wrong-status',
                    transitionChangedFileStatuses: ['A'],
                },
                {
                    expectedPattern: /authorized harness files/u,
                    label: 'wrong-file',
                    transitionChangedFilePaths: [
                        ...(transitionCommitHash ===
                        firstHarnessRepairCommitHash
                            ? recoveryRepairFilePaths
                            : validatorRepairFilePaths),
                        'tools/ci/unrelated.ts',
                    ],
                },
            ] as const) {
                await withTemporaryFixture(async (fixture) => {
                    const recoveryProfile =
                        await createPreOperationRecoveryProfile(fixture);
                    const allInvocations: CommandInvocation[] = [];
                    await expect(
                        executeProofStorageWidthBrowserEvidence({
                            dependencies: createDependencies({
                                allInvocations,
                                fixture,
                                preOperationRecoveryProfile: recoveryProfile,
                                repositoryStateForCheckpoint: () => ({
                                    commitHash: recoveryHarnessCommitHash,
                                    treeDirty: false,
                                }),
                                sampleInvocations: [],
                                transitionOverrideCommitHash:
                                    transitionCommitHash,
                                ...('transitionCommitObject' in mutation
                                    ? {
                                          transitionCommitObject:
                                              mutation.transitionCommitObject,
                                      }
                                    : {}),
                                ...('transitionChangedFileStatuses' in mutation
                                    ? {
                                          transitionChangedFileStatuses:
                                              mutation.transitionChangedFileStatuses,
                                      }
                                    : {}),
                                ...('transitionChangedFilePaths' in mutation
                                    ? {
                                          transitionChangedFilePaths:
                                              mutation.transitionChangedFilePaths,
                                      }
                                    : {}),
                            }),
                            nativeEvidencePath: fixture.nativeEvidencePath,
                            ...recoveryExecutionPaths(recoveryProfile),
                            runLog: createRunLog(fixture.runDirectoryPath),
                        }),
                        `${transitionCommitHash}-${mutation.label}`,
                    ).rejects.toThrow(mutation.expectedPattern);
                    expect(
                        allInvocations.every(
                            (invocation) => invocation.command === 'git',
                        ),
                    ).toBe(true);
                    const singletonDirectories = await readdir(
                        path.join(
                            fixture.reservationRootPath,
                            'browser-recovery-preflight-2',
                        ),
                    );
                    const singletonRecords = (
                        await readFile(
                            path.join(
                                fixture.reservationRootPath,
                                'browser-recovery-preflight-2',
                                singletonDirectories[0] ?? '',
                                'preflight-attempted.json',
                            ),
                            'utf8',
                        )
                    )
                        .trim()
                        .split('\n')
                        .map(
                            (line) =>
                                JSON.parse(line) as Record<string, unknown>,
                        );
                    expect(
                        singletonRecords[singletonRecords.length - 1],
                    ).toMatchObject({ outcome: 'failed' });

                    const replayInvocations: CommandInvocation[] = [];
                    await expect(
                        executeProofStorageWidthBrowserEvidence({
                            dependencies: createDependencies({
                                allInvocations: replayInvocations,
                                fixture,
                                preOperationRecoveryProfile: recoveryProfile,
                                repositoryStateForCheckpoint: () => ({
                                    commitHash: recoveryHarnessCommitHash,
                                    treeDirty: false,
                                }),
                                sampleInvocations: [],
                            }),
                            nativeEvidencePath: fixture.nativeEvidencePath,
                            ...recoveryExecutionPaths(recoveryProfile),
                            runLog: createRunLog(fixture.runDirectoryPath),
                        }),
                    ).rejects.toThrow(
                        /already attempted its static preflight/u,
                    );
                    expect(replayInvocations).toHaveLength(0);
                });
            }
        }
    });

    it('pins every ordinal-two failed-recovery artifact and the consumed ordinal-one marker', async () => {
        const failedRecoveryArtifactNames = [
            'diagnostics',
            'events',
            'metadata',
            'output',
            'resources',
            'summary',
        ] as const;
        for (const [
            artifactIndex,
            artifactName,
        ] of failedRecoveryArtifactNames.entries()) {
            await withTemporaryFixture(async (fixture) => {
                const recoveryProfile =
                    await createPreOperationRecoveryProfile(fixture);
                const artifactPath = path.join(
                    recoveryProfile.chainedRecoveryProfile
                        .failedRecoveryRunDirectoryPath,
                    recoveryProfile.chainedRecoveryProfile
                        .failedRecoveryArtifacts[artifactName].relativePath,
                );
                await writeFile(
                    artifactPath,
                    Buffer.concat([
                        await readFile(artifactPath),
                        Buffer.from([artifactIndex + 1]),
                    ]),
                );
                const allInvocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            allInvocations,
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: recoveryHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations: [],
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...recoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(fixture.runDirectoryPath),
                    }),
                ).rejects.toThrow(/failed recovery.*changed/u);
                expect(allInvocations).toHaveLength(0);
            });
        }

        for (const inventoryMutation of [
            {
                label: 'extra-direct-file',
                mutate: async (runDirectoryPath: string) =>
                    writeFile(
                        path.join(runDirectoryPath, 'unexpected.json'),
                        '{}\n',
                        'utf8',
                    ),
            },
            {
                label: 'nested-artifact',
                mutate: async (runDirectoryPath: string) => {
                    const nestedDirectoryPath = path.join(
                        runDirectoryPath,
                        'nested',
                    );
                    await mkdir(nestedDirectoryPath);
                    await writeFile(
                        path.join(nestedDirectoryPath, 'artifact.json'),
                        '{}\n',
                        'utf8',
                    );
                },
            },
        ] as const) {
            await withTemporaryFixture(async (fixture) => {
                const recoveryProfile =
                    await createPreOperationRecoveryProfile(fixture);
                await inventoryMutation.mutate(
                    recoveryProfile.chainedRecoveryProfile
                        .failedRecoveryRunDirectoryPath,
                );
                const allInvocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            allInvocations,
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: recoveryHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations: [],
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...recoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(fixture.runDirectoryPath),
                    }),
                    inventoryMutation.label,
                ).rejects.toThrow(
                    /exact direct regular files|exact six-file inventory/u,
                );
                expect(allInvocations, inventoryMutation.label).toHaveLength(0);
            });
        }

        await withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            const summaryArtifactPath = path.join(
                recoveryProfile.chainedRecoveryProfile
                    .failedRecoveryRunDirectoryPath,
                recoveryProfile.chainedRecoveryProfile.failedRecoveryArtifacts
                    .summary.relativePath,
            );
            const externalHardlinkTargetPath = path.join(
                path.dirname(
                    recoveryProfile.chainedRecoveryProfile
                        .failedRecoveryRunDirectoryPath,
                ),
                'external-hardlink-target.json',
            );
            await writeFile(
                externalHardlinkTargetPath,
                await readFile(summaryArtifactPath),
            );
            await rm(summaryArtifactPath);
            await link(externalHardlinkTargetPath, summaryArtifactPath);
            const allInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations,
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: recoveryHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: [],
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/multiply linked regular files/u);
            expect(allInvocations).toHaveLength(0);
            const singletonDirectories = await readdir(
                path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-2',
                ),
            );
            const singletonRecords = (
                await readFile(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-2',
                        singletonDirectories[0] ?? '',
                        'preflight-attempted.json',
                    ),
                    'utf8',
                )
            )
                .trim()
                .split('\n')
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(singletonRecords).toHaveLength(2);
            expect(singletonRecords[1]).toMatchObject({ outcome: 'failed' });
        });

        await withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            const previousMarkerPath = path.join(
                fixture.reservationRootPath,
                recoveryProfile.chainedRecoveryProfile.previousPreflightAttempt
                    .relativePath,
            );
            await writeFile(
                previousMarkerPath,
                Buffer.concat([
                    await readFile(previousMarkerPath),
                    Buffer.from([1]),
                ]),
            );
            const mutatedPreviousMarkerBytes =
                await readFile(previousMarkerPath);
            const allInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations,
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: recoveryHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: [],
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/consumed browser recovery marker changed/u);
            expect(allInvocations).toHaveLength(0);
            expect(await readFile(previousMarkerPath)).toEqual(
                mutatedPreviousMarkerBytes,
            );
            const singletonDirectories = await readdir(
                path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-2',
                ),
            );
            const singletonRecords = (
                await readFile(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-2',
                        singletonDirectories[0] ?? '',
                        'preflight-attempted.json',
                    ),
                    'utf8',
                )
            )
                .trim()
                .split('\n')
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(singletonRecords).toHaveLength(2);
            expect(singletonRecords[1]).toMatchObject({ outcome: 'failed' });
        });
    });

    it('refuses a reparse alias in the ordinal-two failed-recovery inventory', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            const escapedDirectoryPath = path.join(
                path.dirname(
                    recoveryProfile.chainedRecoveryProfile
                        .failedRecoveryRunDirectoryPath,
                ),
                'failed-recovery-alias-target',
            );
            const aliasPath = path.join(
                recoveryProfile.chainedRecoveryProfile
                    .failedRecoveryRunDirectoryPath,
                recoveryProfile.chainedRecoveryProfile.failedRecoveryArtifacts
                    .summary.relativePath,
            );
            await mkdir(escapedDirectoryPath);
            await rm(aliasPath);
            await symlink(
                escapedDirectoryPath,
                aliasPath,
                process.platform === 'win32' ? 'junction' : 'dir',
            );
            const allInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations,
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: recoveryHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: [],
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/exact direct regular files/u);
            expect(allInvocations).toHaveLength(0);
        }));

    it('records a terminal ordinal-two failure after browser, attachment, or outer closure failure', async () => {
        for (const failureStage of [
            'browser-operation',
            'attachment-validation',
            'outer-repository-closure',
        ] as const) {
            await withTemporaryFixture(async (fixture) => {
                const recoveryProfile =
                    await createPreOperationRecoveryProfile(fixture);
                const previousMarkerPath = path.join(
                    fixture.reservationRootPath,
                    recoveryProfile.chainedRecoveryProfile
                        .previousPreflightAttempt.relativePath,
                );
                const previousMarkerBytes = await readFile(previousMarkerPath);
                const sampleInvocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            driftNativeEvidenceDuringAttachmentValidation:
                                failureStage === 'attachment-validation',
                            failGuardedSample:
                                failureStage === 'browser-operation',
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: (checkpoint) => ({
                                commitHash: recoveryHarnessCommitHash,
                                treeDirty:
                                    failureStage ===
                                        'outer-repository-closure' &&
                                    checkpoint === 'closure-after',
                            }),
                            sampleInvocations,
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...recoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(fixture.runDirectoryPath),
                    }),
                    failureStage,
                ).rejects.toThrow();
                expect(sampleInvocations, failureStage).toHaveLength(1);
                expect(
                    await readFile(previousMarkerPath),
                    failureStage,
                ).toEqual(previousMarkerBytes);
                const authorizationDirectories = await readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-2',
                    ),
                );
                expect(authorizationDirectories, failureStage).toHaveLength(1);
                const markerRecords = (
                    await readFile(
                        path.join(
                            fixture.reservationRootPath,
                            'browser-recovery-preflight-2',
                            authorizationDirectories[0] ?? '',
                            'preflight-attempted.json',
                        ),
                        'utf8',
                    )
                )
                    .trim()
                    .split(/\r?\n/u)
                    .map(
                        (line) =>
                            JSON.parse(line) as {
                                outcome?: string;
                            },
                    );
                expect(markerRecords, failureStage).toHaveLength(3);
                expect(markerRecords[2]?.outcome, failureStage).toBe('failed');

                const operationAuthorizationDirectories = await readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-2',
                    ),
                );
                expect(
                    operationAuthorizationDirectories,
                    failureStage,
                ).toHaveLength(1);
                const operationRecords = (
                    await readFile(
                        path.join(
                            fixture.reservationRootPath,
                            'browser-recovery-2',
                            operationAuthorizationDirectories[0] ?? '',
                            'browser-recovery-started.json',
                        ),
                        'utf8',
                    )
                )
                    .trim()
                    .split(/\r?\n/u)
                    .map(
                        (line) =>
                            JSON.parse(line) as {
                                outcome?: string;
                            },
                    );
                expect(operationRecords, failureStage).toHaveLength(2);
                expect(operationRecords[1]?.outcome, failureStage).toBe(
                    failureStage === 'browser-operation'
                        ? 'failed'
                        : 'validated',
                );
                const attachmentPath = path.join(
                    fixture.runDirectoryPath,
                    'attachments',
                    'proof-storage-width-browser-evidence.json',
                );
                const attachmentState = await readFile(attachmentPath).then(
                    () => 'present' as const,
                    (error: unknown) => {
                        if (
                            typeof error === 'object' &&
                            error !== null &&
                            'code' in error &&
                            error.code === 'ENOENT'
                        ) {
                            return 'absent' as const;
                        }
                        throw error;
                    },
                );
                expect(attachmentState, failureStage).toBe(
                    failureStage === 'browser-operation' ? 'absent' : 'present',
                );
            });
        }
    });

    it('fails closed when finalization reopens a changed attachment or operation reservation', async () => {
        for (const changedArtifact of [
            'attachment',
            'operation-reservation',
        ] as const) {
            await withTemporaryFixture(async (fixture) => {
                const recoveryProfile =
                    await createPreOperationRecoveryProfile(fixture);
                const sampleInvocations: CommandInvocation[] = [];
                const announcements: string[] = [];
                let artifactChanged = false;
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: (checkpoint) => {
                                if (
                                    checkpoint === 'closure-after' &&
                                    !artifactChanged
                                ) {
                                    const artifactPath =
                                        changedArtifact === 'attachment'
                                            ? path.join(
                                                  fixture.runDirectoryPath,
                                                  'attachments',
                                                  'proof-storage-width-browser-evidence.json',
                                              )
                                            : path.join(
                                                  fixture.reservationRootPath,
                                                  'browser-recovery-2',
                                                  readdirSync(
                                                      path.join(
                                                          fixture.reservationRootPath,
                                                          'browser-recovery-2',
                                                      ),
                                                  )[0] ?? '',
                                                  'browser-recovery-started.json',
                                              );
                                    writeFileSync(
                                        artifactPath,
                                        Buffer.concat([
                                            readFileSync(artifactPath),
                                            Buffer.from(
                                                '\nchanged-after-provisional-validation',
                                            ),
                                        ]),
                                    );
                                    artifactChanged = true;
                                }
                                return {
                                    commitHash: recoveryHarnessCommitHash,
                                    treeDirty: false,
                                };
                            },
                            sampleInvocations,
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...recoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(fixture.runDirectoryPath, {
                            writeCombinedOutput: (output) => {
                                if (
                                    output.startsWith(
                                        'Proof-storage width browser evidence:',
                                    )
                                ) {
                                    announcements.push(output);
                                }
                            },
                            writeEvent: ({ eventType }) => {
                                if (
                                    eventType ===
                                        'proof-storage-width-browser-evidence-complete' ||
                                    eventType ===
                                        'proof-storage-width-browser-evidence-decisive-negative'
                                ) {
                                    announcements.push(eventType);
                                }
                            },
                        }),
                    }),
                    changedArtifact,
                ).rejects.toThrow(
                    /not valid JSON|changed before finalization|bound digest/u,
                );
                expect(sampleInvocations, changedArtifact).toHaveLength(1);
                expect(announcements, changedArtifact).toHaveLength(0);
                const singletonDirectories = readdirSync(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-2',
                    ),
                );
                const markerRecords = readFileSync(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-2',
                        singletonDirectories[0] ?? '',
                        'preflight-attempted.json',
                    ),
                    'utf8',
                )
                    .trim()
                    .split('\n')
                    .map((line) => JSON.parse(line) as Record<string, unknown>);
                expect(markerRecords, changedArtifact).toHaveLength(3);
                expect(markerRecords[2], changedArtifact).toMatchObject({
                    outcome: 'failed',
                });

                const replayInvocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            allInvocations: replayInvocations,
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: recoveryHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations: [],
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...recoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(fixture.runDirectoryPath),
                    }),
                ).rejects.toThrow(/already attempted its static preflight/u);
                expect(replayInvocations, changedArtifact).toHaveLength(0);
            });
        }
    });

    it('records failure when the final full closure reopen fails before terminalization', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            const sampleInvocations: CommandInvocation[] = [];
            const announcements: string[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        driftNativeEvidenceAtLoadCount: 3,
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: recoveryHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath, {
                        writeCombinedOutput: (output) =>
                            announcements.push(output),
                        writeEvent: ({ eventType }) =>
                            announcements.push(eventType),
                    }),
                }),
            ).rejects.toThrow(/reopened native aggregate/u);
            expect(sampleInvocations).toHaveLength(1);
            expect(announcements).toHaveLength(0);
            const singletonDirectories = await readdir(
                path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-2',
                ),
            );
            const markerRecords = (
                await readFile(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-2',
                        singletonDirectories[0] ?? '',
                        'preflight-attempted.json',
                    ),
                    'utf8',
                )
            )
                .trim()
                .split('\n')
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(markerRecords).toHaveLength(3);
            expect(markerRecords[2]).toMatchObject({ outcome: 'failed' });

            const replayInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        allInvocations: replayInvocations,
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: recoveryHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: [],
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/already attempted its static preflight/u);
            expect(replayInvocations).toHaveLength(0);
        }));

    it('records an ordinal-two ineligible closure as validated before throwing the decisive negative', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            const sampleInvocations: CommandInvocation[] = [];
            const dependencies = createDependencies({
                fixture,
                fullWidthExternalIoByteLength: 1_099_511_627_776n,
                preOperationRecoveryProfile: recoveryProfile,
                repositoryStateForCheckpoint: () => ({
                    commitHash: recoveryHarnessCommitHash,
                    treeDirty: false,
                }),
                sampleInvocations,
            });
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies,
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/decisive negative terabyte-scale-external-io/u);
            expect(sampleInvocations).toHaveLength(1);
            const authorizationDirectories = await readdir(
                path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-2',
                ),
            );
            const markerRecords = (
                await readFile(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-2',
                        authorizationDirectories[0] ?? '',
                        'preflight-attempted.json',
                    ),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(markerRecords).toHaveLength(3);
            expect(markerRecords[2]).toMatchObject({
                decisionOutcome: 'ineligible',
                outcome: 'validated',
            });
            const attachmentPath = path.join(
                fixture.runDirectoryPath,
                'attachments',
                'proof-storage-width-browser-evidence.json',
            );
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        chainedRecoveryProfile:
                            recoveryProfile.chainedRecoveryProfile,
                        preOperationRecoveryProfile: recoveryProfile,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                    },
                ),
            ).resolves.toBeUndefined();
        }));

    it('rechecks the clean harness head after static listing and before operation reservation', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            const sampleInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: (checkpoint) => ({
                            commitHash: recoveryHarnessCommitHash,
                            treeDirty: checkpoint === 'pre-operation',
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/pre-operation checkpoint/u);
            expect(sampleInvocations).toHaveLength(0);
            await expect(
                readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-2',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            const singletonDirectoryNames = await readdir(
                path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight-2',
                ),
            );
            const singletonRecords = (
                await readFile(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight-2',
                        singletonDirectoryNames[0] ?? '',
                        'preflight-attempted.json',
                    ),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as { outcome?: string });
            expect(singletonRecords).toHaveLength(3);
            expect(singletonRecords[1]).toMatchObject({
                eventType:
                    'official-browser-width-recovery-static-preflight-observed',
                staticListStderr: '',
                staticListStdout: browserEvidenceStaticPreflightOutput,
            });
            expect(singletonRecords[2]?.outcome).toBe('failed');
        }));

    it('pins the exact predecessor inventory and consumes early drift attempts', async () => {
        const predecessorArtifactNames = [
            'diagnostics',
            'events',
            'metadata',
            'output',
            'processGuard',
            'resources',
            'summary',
        ] as const;
        for (const [
            artifactIndex,
            artifactName,
        ] of predecessorArtifactNames.entries()) {
            await withTemporaryFixture(async (fixture) => {
                const recoveryProfile =
                    await createPreOperationRecoveryProfile(fixture);
                const artifactPath = path.join(
                    recoveryProfile.failedRunDirectoryPath,
                    recoveryProfile.failedArtifacts[artifactName].relativePath,
                );
                const originalBytes = await readFile(artifactPath);
                await writeFile(
                    artifactPath,
                    Buffer.concat([
                        originalBytes,
                        Buffer.from([artifactIndex]),
                    ]),
                );
                const sampleInvocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: recoveryHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations,
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...recoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(fixture.runDirectoryPath),
                    }),
                ).rejects.toThrow(/changed/u);
                expect(sampleInvocations).toHaveLength(0);
                await writeFile(artifactPath, originalBytes);

                const correctedInvocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: recoveryHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations: correctedInvocations,
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...recoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(fixture.runDirectoryPath),
                    }),
                ).rejects.toThrow(/already attempted its static preflight/u);
                expect(correctedInvocations).toHaveLength(0);
            });
        }

        for (const priorOperationArtifactRelativePath of [
            '.hidden-prior-operation.json',
            path.join(
                'attachments',
                'proof-storage-width-browser-evidence',
                '.hidden-prior-operation.json',
            ),
        ]) {
            await withTemporaryFixture(async (fixture) => {
                const recoveryProfile =
                    await createPreOperationRecoveryProfile(fixture);
                await writeFile(
                    path.join(
                        recoveryProfile.failedRunDirectoryPath,
                        priorOperationArtifactRelativePath,
                    ),
                    '{}\n',
                    'utf8',
                );
                const sampleInvocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            fixture,
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: recoveryHarnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations,
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        ...recoveryExecutionPaths(recoveryProfile),
                        runLog: createRunLog(fixture.runDirectoryPath),
                    }),
                ).rejects.toThrow(/recursive file inventory changed/u);
                expect(sampleInvocations).toHaveLength(0);
            });
        }

        await withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            const producerBytes = await readFile(
                fixture.processedWasmKernelPath,
            );
            const driftedBytes = Buffer.concat([
                producerBytes,
                // A valid empty custom section changes the raw bytes without
                // making the test module malformed.
                Buffer.from([0, 1, 0]),
            ]);
            await Promise.all([
                writeFile(fixture.processedWasmKernelPath, driftedBytes),
                writeFile(fixture.publicSdkWasmKernelPath, driftedBytes),
            ]);
            const sampleInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: recoveryHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/WebAssembly bytes drifted/u);
            expect(sampleInvocations).toHaveLength(0);
            await Promise.all([
                writeFile(fixture.processedWasmKernelPath, producerBytes),
                writeFile(fixture.publicSdkWasmKernelPath, producerBytes),
            ]);
            const correctedInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: recoveryHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: correctedInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/already attempted its static preflight/u);
            expect(correctedInvocations).toHaveLength(0);
        });
    });

    it('refuses predecessor custody through a symbolic-link or junction ancestor', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            const originalResourcesDirectoryPath = path.join(
                recoveryProfile.failedRunDirectoryPath,
                'resources',
            );
            const escapedResourcesDirectoryPath = path.join(
                path.dirname(recoveryProfile.failedRunDirectoryPath),
                'escaped-resources',
            );
            await mkdir(escapedResourcesDirectoryPath);
            const processGuardProfile =
                recoveryProfile.failedArtifacts.processGuard;
            await writeFile(
                path.join(
                    escapedResourcesDirectoryPath,
                    path.basename(processGuardProfile.relativePath),
                ),
                await readFile(
                    path.join(
                        recoveryProfile.failedRunDirectoryPath,
                        processGuardProfile.relativePath,
                    ),
                ),
            );
            await rm(originalResourcesDirectoryPath, {
                force: true,
                recursive: true,
            });
            let linkCreated = false;
            try {
                await symlink(
                    escapedResourcesDirectoryPath,
                    originalResourcesDirectoryPath,
                    process.platform === 'win32' ? 'junction' : 'dir',
                );
                linkCreated = true;
            } catch (error) {
                if (
                    typeof error !== 'object' ||
                    error === null ||
                    !('code' in error) ||
                    !['EACCES', 'ENOTSUP', 'EPERM'].includes(String(error.code))
                ) {
                    throw error;
                }
            }
            const sampleInvocations: CommandInvocation[] = [];
            let observedFailure: unknown;
            try {
                await executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: recoveryHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                });
            } catch (error) {
                observedFailure = error;
            }
            expect(observedFailure).toBeInstanceOf(Error);
            expect((observedFailure as Error).message).toMatch(
                linkCreated ? /symbolic link or junction/u : /.+/u,
            );
            expect(sampleInvocations).toHaveLength(0);
            await expect(
                readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-2',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        }));

    it('refuses an alias inside otherwise empty predecessor scaffolding', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            const escapedEmptyDirectoryPath = path.join(
                path.dirname(recoveryProfile.failedRunDirectoryPath),
                'escaped-empty-scaffolding',
            );
            const scaffoldAliasPath = path.join(
                recoveryProfile.failedRunDirectoryPath,
                'attachments',
                'proof-storage-width-browser-evidence',
                'redirected-empty-scaffolding',
            );
            await mkdir(escapedEmptyDirectoryPath);
            let linkCreated = false;
            try {
                await symlink(
                    escapedEmptyDirectoryPath,
                    scaffoldAliasPath,
                    process.platform === 'win32' ? 'junction' : 'dir',
                );
                linkCreated = true;
            } catch (error) {
                if (
                    typeof error !== 'object' ||
                    error === null ||
                    !('code' in error) ||
                    !['EACCES', 'ENOTSUP', 'EPERM'].includes(String(error.code))
                ) {
                    throw error;
                }
            }
            const sampleInvocations: CommandInvocation[] = [];
            let observedFailure: unknown;
            try {
                await executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        fixture,
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: recoveryHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    ...recoveryExecutionPaths(recoveryProfile),
                    runLog: createRunLog(fixture.runDirectoryPath),
                });
            } catch (error) {
                observedFailure = error;
            }
            expect(observedFailure).toBeInstanceOf(Error);
            expect((observedFailure as Error).message).toMatch(
                linkCreated
                    ? /symbolic link or junction|unsupported non-file entry|canonical custody path/u
                    : /.+/u,
            );
            expect(sampleInvocations).toHaveLength(0);
            await expect(
                readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-2',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        }));

    it('refuses native aggregate and WebAssembly custody through link ancestors', async () => {
        for (const targetKind of ['native-aggregate', 'wasm'] as const) {
            await withTemporaryFixture(async (fixture) => {
                const escapedDirectoryPath = path.join(
                    path.dirname(fixture.runDirectoryPath),
                    `escaped-${targetKind}`,
                );
                const linkedDirectoryPath = path.join(
                    path.dirname(fixture.runDirectoryPath),
                    `linked-${targetKind}`,
                );
                await mkdir(escapedDirectoryPath);
                const sourcePath =
                    targetKind === 'native-aggregate'
                        ? fixture.nativeEvidencePath
                        : fixture.processedWasmKernelPath;
                const escapedFilePath = path.join(
                    escapedDirectoryPath,
                    path.basename(sourcePath),
                );
                await writeFile(escapedFilePath, await readFile(sourcePath));
                let linkCreated = false;
                try {
                    await symlink(
                        escapedDirectoryPath,
                        linkedDirectoryPath,
                        process.platform === 'win32' ? 'junction' : 'dir',
                    );
                    linkCreated = true;
                } catch (error) {
                    if (
                        typeof error !== 'object' ||
                        error === null ||
                        !('code' in error) ||
                        !['EACCES', 'ENOTSUP', 'EPERM'].includes(
                            String(error.code),
                        )
                    ) {
                        throw error;
                    }
                }
                const linkedFilePath = path.join(
                    linkedDirectoryPath,
                    path.basename(sourcePath),
                );
                const custodyFixture = {
                    ...fixture,
                    ...(targetKind === 'native-aggregate'
                        ? { nativeEvidencePath: linkedFilePath }
                        : { processedWasmKernelPath: linkedFilePath }),
                };
                const sampleInvocations: CommandInvocation[] = [];
                let observedFailure: unknown;
                try {
                    await executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            fixture: custodyFixture,
                            sampleInvocations,
                        }),
                        nativeEvidencePath: custodyFixture.nativeEvidencePath,
                        runLog: createRunLog(fixture.runDirectoryPath),
                    });
                } catch (error) {
                    observedFailure = error;
                }
                expect(observedFailure).toBeInstanceOf(Error);
                expect((observedFailure as Error).message).toMatch(
                    linkCreated ? /symbolic link or junction/u : /.+/u,
                );
                expect(sampleInvocations).toHaveLength(0);
            });
        }
    });

    it('closes one canonical decisive-negative projection before failing the command', () =>
        withTemporaryFixture(async (fixture) => {
            const sampleInvocations: CommandInvocation[] = [];
            const lifecycle: string[] = [];
            const completionEvents: string[] = [];
            const decisiveNegativeDetails: Array<
                Readonly<Record<string, unknown>>
            > = [];
            const dependencies = createDependencies({
                fixture,
                fullWidthExternalIoByteLength: 1_099_511_627_776n,
                repositoryStateForCheckpoint: (checkpoint) => {
                    lifecycle.push(`repository:${checkpoint}`);
                    return { commitHash, treeDirty: false };
                },
                sampleInvocations,
            });
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies,
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    runLog: createRunLog(fixture.runDirectoryPath, {
                        writeCombinedOutput: (output) => {
                            lifecycle.push('output');
                            expect(output).toContain(
                                'proof-storage-width-browser-evidence.json',
                            );
                        },
                        writeEvent: (event) => {
                            completionEvents.push(event.eventType);
                            if (
                                event.eventType ===
                                'proof-storage-width-browser-evidence-decisive-negative'
                            ) {
                                lifecycle.push('decisive-negative-event');
                                if (event.details === undefined) {
                                    throw new Error(
                                        'The decisive-negative event omitted its evidence details.',
                                    );
                                }
                                decisiveNegativeDetails.push(event.details);
                            }
                        },
                    }),
                }),
            ).rejects.toThrow(
                /decisive negative terabyte-scale-external-io after canonical evidence closure/u,
            );
            expect(sampleInvocations).toHaveLength(1);
            expect(lifecycle).toEqual([
                'repository:initial',
                'repository:before',
                'repository:pre-operation',
                'repository:after',
                'repository:closure-after',
                'output',
                'decisive-negative-event',
            ]);
            expect(completionEvents).not.toContain(
                'proof-storage-width-browser-evidence-complete',
            );

            const attachmentPath = path.join(
                fixture.runDirectoryPath,
                'attachments',
                'proof-storage-width-browser-evidence.json',
            );
            const serializedEvidence = await readFile(attachmentPath, 'utf8');
            const evidence = JSON.parse(serializedEvidence) as {
                readonly decision: {
                    readonly outcome: string;
                    readonly violations: readonly string[];
                };
                readonly formatVersion: number;
            };
            expect(evidence).toMatchObject({
                decision: {
                    outcome: 'ineligible',
                    violations: ['terabyte-scale-external-io'],
                },
                formatVersion: 4,
            });
            expect(decisiveNegativeDetails).toEqual([
                expect.objectContaining({
                    attachmentPath,
                    attachmentSha256Hex: sha256Hex(serializedEvidence),
                    decisionOutcome: 'ineligible',
                    decisionViolations: ['terabyte-scale-external-io'],
                }),
            ]);
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                    },
                ),
            ).resolves.toBeUndefined();

            await writeFile(
                attachmentPath,
                `${JSON.stringify(
                    {
                        ...evidence,
                        decision: { outcome: 'eligible', violations: [] },
                    },
                    null,
                    2,
                )}\n`,
                'utf8',
            );
            await expect(
                validateProofStorageWidthBrowserEvidenceArtifacts(
                    attachmentPath,
                    {
                        loadNativeWidthEvidence:
                            dependencies.loadNativeWidthEvidence,
                        officialReservationRootPath:
                            fixture.reservationRootPath,
                        processedWasmKernelPath:
                            fixture.processedWasmKernelPath,
                        publicSdkWasmKernelPath:
                            fixture.publicSdkWasmKernelPath,
                    },
                ),
            ).rejects.toThrow(/decision does not match/u);
            await writeFile(attachmentPath, serializedEvidence, 'utf8');

            const reservationIdentityDirectories = await readdir(
                path.join(fixture.reservationRootPath, 'browser'),
            );
            expect(reservationIdentityDirectories).toHaveLength(1);
            const reservationRecords = (
                await readFile(
                    path.join(
                        fixture.reservationRootPath,
                        'browser',
                        reservationIdentityDirectories[0] ?? '',
                        'browser-started.json',
                    ),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as { outcome?: string });
            expect(reservationRecords).toHaveLength(2);
            expect(reservationRecords[1]?.outcome).toBe('validated');
        }));

    it('runs closure after a post-start sample failure and records exactly one failed outcome', () =>
        withTemporaryFixture(async (fixture) => {
            const sampleInvocations: CommandInvocation[] = [];
            const checkpoints: string[] = [];
            const completionEvents: string[] = [];
            const combinedOutputs: string[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        failGuardedSample: true,
                        fixture,
                        repositoryStateForCheckpoint: (checkpoint) => {
                            checkpoints.push(checkpoint);
                            return { commitHash, treeDirty: false };
                        },
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    runLog: createRunLog(fixture.runDirectoryPath, {
                        writeCombinedOutput: (output) =>
                            combinedOutputs.push(output),
                        writeEvent: (event) =>
                            completionEvents.push(event.eventType),
                    }),
                }),
            ).rejects.toThrow(/fixed width-512.*failed with exit code 1/u);
            expect(sampleInvocations).toHaveLength(1);
            expect(checkpoints).toEqual([
                'initial',
                'before',
                'pre-operation',
                'after',
                'closure-after',
            ]);
            expect(combinedOutputs).toEqual([]);
            expect(completionEvents).not.toContain(
                'proof-storage-width-browser-evidence-complete',
            );
            await expect(
                readFile(
                    path.join(
                        fixture.runDirectoryPath,
                        'attachments',
                        'proof-storage-width-browser-evidence.json',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            const reservationIdentityDirectories = await readdir(
                path.join(fixture.reservationRootPath, 'browser'),
            );
            expect(reservationIdentityDirectories).toHaveLength(1);
            const reservationRecords = (
                await readFile(
                    path.join(
                        fixture.reservationRootPath,
                        'browser',
                        reservationIdentityDirectories[0] ?? '',
                        'browser-started.json',
                    ),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as { outcome?: string });
            expect(reservationRecords).toHaveLength(2);
            expect(reservationRecords[1]?.outcome).toBe('failed');
        }));

    it('refuses closure drift after a validated attempt without announcing completion or appending another outcome', () =>
        withTemporaryFixture(async (fixture) => {
            const sampleInvocations: CommandInvocation[] = [];
            const checkpoints: string[] = [];
            const completionEvents: string[] = [];
            const combinedOutputs: string[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        fixture,
                        repositoryStateForCheckpoint: (checkpoint) => {
                            checkpoints.push(checkpoint);
                            return checkpoint === 'closure-after'
                                ? {
                                      commitHash: '8b'.repeat(20),
                                      treeDirty: false,
                                  }
                                : { commitHash, treeDirty: false };
                        },
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    runLog: createRunLog(fixture.runDirectoryPath, {
                        writeCombinedOutput: (output) =>
                            combinedOutputs.push(output),
                        writeEvent: (event) =>
                            completionEvents.push(event.eventType),
                    }),
                }),
            ).rejects.toThrow(/closure-after checkpoint/u);
            expect(sampleInvocations).toHaveLength(1);
            expect(checkpoints).toEqual([
                'initial',
                'before',
                'pre-operation',
                'after',
                'closure-after',
            ]);
            expect(combinedOutputs).toEqual([]);
            expect(completionEvents).not.toContain(
                'proof-storage-width-browser-evidence-complete',
            );
            const reservationIdentityDirectories = await readdir(
                path.join(fixture.reservationRootPath, 'browser'),
            );
            const reservationRecords = (
                await readFile(
                    path.join(
                        fixture.reservationRootPath,
                        'browser',
                        reservationIdentityDirectories[0] ?? '',
                        'browser-started.json',
                    ),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as { outcome?: string });
            expect(reservationRecords).toHaveLength(2);
            expect(reservationRecords[1]?.outcome).toBe('validated');
            await expect(
                readFile(
                    path.join(
                        fixture.runDirectoryPath,
                        'attachments',
                        'proof-storage-width-browser-evidence.json',
                    ),
                ),
            ).resolves.toBeInstanceOf(Buffer);
        }));

    it('preserves both a post-start attempt failure and closure drift', () =>
        withTemporaryFixture(async (fixture) => {
            const sampleInvocations: CommandInvocation[] = [];
            let observedError: unknown;
            try {
                await executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        failGuardedSample: true,
                        fixture,
                        repositoryStateForCheckpoint: (checkpoint) =>
                            checkpoint === 'closure-after'
                                ? { commitHash, treeDirty: true }
                                : { commitHash, treeDirty: false },
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    runLog: createRunLog(fixture.runDirectoryPath),
                });
            } catch (error) {
                observedError = error;
            }
            expect(observedError).toBeInstanceOf(Error);
            if (!(observedError instanceof Error)) {
                throw new Error('The combined failure was not an Error.');
            }
            const combinedError = observedError as Error & {
                readonly attemptCause?: unknown;
                readonly cause?: unknown;
            };
            expect(combinedError.message).toMatch(
                /attempt failed and its final repository closure check also failed/u,
            );
            expect(combinedError.attemptCause).toBeInstanceOf(Error);
            expect(combinedError.cause).toBeInstanceOf(Error);
            expect(sampleInvocations).toHaveLength(1);
            const reservationIdentityDirectories = await readdir(
                path.join(fixture.reservationRootPath, 'browser'),
            );
            const reservationRecords = (
                await readFile(
                    path.join(
                        fixture.reservationRootPath,
                        'browser',
                        reservationIdentityDirectories[0] ?? '',
                        'browser-started.json',
                    ),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as { outcome?: string });
            expect(reservationRecords).toHaveLength(2);
            expect(reservationRecords[1]?.outcome).toBe('failed');
        }));

    it('checks the repository after a drifted attempted sample and records failure', () =>
        withTemporaryFixture(async (fixture) => {
            const sampleInvocations: CommandInvocation[] = [];
            const checkpoints: string[] = [];
            const dependencies = createDependencies({
                fixture,
                repositoryStateForCheckpoint: (checkpoint) => {
                    checkpoints.push(checkpoint);
                    return checkpoint === 'after'
                        ? { commitHash: '8b'.repeat(20), treeDirty: false }
                        : { commitHash, treeDirty: false };
                },
                sampleInvocations,
            });
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies,
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/after checkpoint/u);
            expect(sampleInvocations).toHaveLength(1);
            expect(checkpoints).toEqual([
                'initial',
                'before',
                'pre-operation',
                'after',
                'closure-after',
            ]);
            await expect(
                readFile(
                    path.join(
                        fixture.runDirectoryPath,
                        'attachments',
                        'proof-storage-width-browser-evidence.json',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            const reservationIdentityDirectories = await readdir(
                path.join(fixture.reservationRootPath, 'browser'),
            );
            expect(reservationIdentityDirectories).toHaveLength(1);
            const reservationPath = path.join(
                fixture.reservationRootPath,
                'browser',
                reservationIdentityDirectories[0] ?? '',
                'browser-started.json',
            );
            const reservationRecords = (await readFile(reservationPath, 'utf8'))
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as { outcome?: string });
            expect(reservationRecords).toHaveLength(2);
            expect(reservationRecords[1]?.outcome).toBe('failed');
        }));
});
