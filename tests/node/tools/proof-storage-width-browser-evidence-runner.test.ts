import { createHash } from 'node:crypto';
import {
    mkdir,
    mkdtemp,
    readFile,
    readdir,
    rm,
    symlink,
    writeFile,
} from 'node:fs/promises';
import os from 'node:os';
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
    executeProofStorageWidthBrowserEvidence,
    parseProofStorageWidthBrowserEvidenceArguments,
    parseProofStorageWidthBrowserMeasurementEvents,
    parseProofStorageWidthBrowserStaticPreflightOutput,
    proofStorageWidthBrowserEvidenceVitestArguments,
    proofStorageWidthBrowserEvidenceStaticPreflightArguments,
    validateProofStorageWidthBrowserEvidenceArtifacts,
    type NativeWidthEvidence,
    type ProofStorageWidthBrowserEvidenceDependencies,
    type ProofStorageWidthBrowserPreOperationRecoveryProfile,
} from '#tools/ci/run-proof-storage-width-browser-evidence';

const commitHash = '9a'.repeat(20);
const harnessCommitHash = '8b'.repeat(20);
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

const createNativeEvidence = async (input: {
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
        evidencePath: path.resolve(input.nativeEvidencePath),
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
    const temporaryRootPath = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-width-browser-runner-'),
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

const createPreOperationRecoveryProfile = async (input: {
    readonly nativeEvidencePath: string;
    readonly processedWasmKernelPath: string;
    readonly reservationRootPath: string;
    readonly runDirectoryPath: string;
}): Promise<ProofStorageWidthBrowserPreOperationRecoveryProfile> => {
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
    return {
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
    };
};

const createDependencies = (input: {
    readonly failGuardedSample?: boolean;
    readonly fixture: {
        readonly nativeEvidencePath: string;
        readonly processedWasmKernelPath: string;
        readonly publicSdkWasmKernelPath: string;
        readonly reservationRootPath: string;
        readonly runDirectoryPath: string;
    };
    readonly fullWidthExternalIoByteLength?: bigint;
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
    readonly transitionParentLine?: string;
}): ProofStorageWidthBrowserEvidenceDependencies => {
    let nativeEvidence: NativeWidthEvidence | undefined;
    return {
        executeCommand: async (invocation) => {
            if (invocation.args[0] === 'rev-list') {
                return {
                    ...successfulCommandResult(),
                    stdout:
                        input.transitionParentLine ??
                        `${harnessCommitHash} ${commitHash}\n`,
                };
            }
            if (invocation.args[0] === 'diff') {
                return {
                    ...successfulCommandResult(),
                    stdout: `${(
                        input.transitionChangedFilePaths ??
                        recoveryRepairFilePaths
                    ).join('\n')}\n`,
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
                nativeEvidencePath: input.fixture.nativeEvidencePath,
            });
            return nativeEvidence;
        },
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

    it('parses only the absolute native path and optional absolute pre-operation predecessor', () => {
        const nativeEvidencePath = path.resolve('native-evidence.json');
        const failedRunDirectoryPath = path.resolve('failed-run');
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
        for (const invalidArguments of [
            ['--native-evidence', 'relative.json'],
            [
                '--native-evidence',
                nativeEvidencePath,
                '--pre-operation-recovery',
                'relative-run',
            ],
            [
                '--pre-operation-recovery',
                failedRunDirectoryPath,
                '--native-evidence',
                nativeEvidencePath,
            ],
        ]) {
            expect(() =>
                parseProofStorageWidthBrowserEvidenceArguments(
                    invalidArguments,
                ),
            ).toThrow(/optionally --pre-operation-recovery/u);
        }
    });

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

    it('chains one recovery to the immutable predecessor and both clean commits', () =>
        withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            const sampleInvocations: CommandInvocation[] = [];
            const dependencies = createDependencies({
                fixture,
                preOperationRecoveryProfile: recoveryProfile,
                repositoryStateForCheckpoint: () => ({
                    commitHash: harnessCommitHash,
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
            await executeProofStorageWidthBrowserEvidence({
                dependencies,
                nativeEvidencePath: fixture.nativeEvidencePath,
                preOperationRecoveryRunDirectoryPath:
                    recoveryProfile.failedRunDirectoryPath,
                runLog: createRunLog(fixture.runDirectoryPath),
            });
            expect(sampleInvocations).toHaveLength(1);
            const semanticArgumentStartIndex =
                sampleInvocations[0]?.args.indexOf('exec') ?? -1;
            expect(semanticArgumentStartIndex).toBeGreaterThanOrEqual(0);
            expect(
                sampleInvocations[0]?.args.slice(semanticArgumentStartIndex),
            ).toEqual(proofStorageWidthBrowserEvidenceVitestArguments);
            expect(await readFile(failedReservationPath)).toEqual(
                failedReservationBefore,
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
                };
                readonly recovery: {
                    readonly changedFilePaths: readonly string[];
                    readonly harnessCommitHash: string;
                    readonly nativeSourceCommitHash: string;
                    readonly recoveryOrdinal: number;
                    readonly staticPreflight: {
                        readonly attempt: {
                            readonly path: string;
                            readonly sha256Hex: string;
                        };
                        readonly outputSha256Hex: string;
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
                    harnessCommitHash,
                    nativeSourceCommitHash: commitHash,
                    recoveryOrdinal: 1,
                },
            });
            expect(evidence.officialSampleReservation.path).toMatch(
                /^browser-recovery\/[0-9a-f]{64}\/browser-recovery-started\.json$/u,
            );
            expect(evidence.recovery.staticPreflight.attempt.path).toBe(
                `browser-recovery-preflight/${evidence.officialSampleReservation.authorizationKeySha256Hex}/preflight-attempted.json`,
            );
            const preflightMarkerPath = path.join(
                fixture.reservationRootPath,
                evidence.recovery.staticPreflight.attempt.path,
            );
            const preflightRecords = (
                await readFile(preflightMarkerPath, 'utf8')
            )
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
            expect(preflightRecords[2]).toMatchObject({
                eventType: 'official-sample-outcome',
                outcome: 'validated',
            });
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

            const originalAttachmentBytes = await readFile(attachmentPath);
            const originalPreflightMarkerBytes =
                await readFile(preflightMarkerPath);
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
                preflightRecords[2],
            ];
            const tamperedPreflightMarker = `${tamperedPreflightRecords
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
                            sha256Hex: sha256Hex(tamperedPreflightMarker),
                        },
                        outputSha256Hex: sha256Hex(unrelatedStaticListOutput),
                    },
                },
            };
            await Promise.all([
                writeFile(preflightMarkerPath, tamperedPreflightMarker, 'utf8'),
                writeFile(
                    attachmentPath,
                    `${JSON.stringify(tamperedEvidence, null, 2)}\n`,
                    'utf8',
                ),
            ]);
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
            ).rejects.toThrow(/exactly the fixed evidence test file/u);
            await Promise.all([
                writeFile(preflightMarkerPath, originalPreflightMarkerBytes),
                writeFile(attachmentPath, originalAttachmentBytes),
            ]);

            const secondHarnessCommitHash = '6d'.repeat(20);
            const secondRunDirectoryPath = path.join(
                path.dirname(fixture.runDirectoryPath),
                'alternate-harness-run',
            );
            await mkdir(secondRunDirectoryPath);
            const alternateHarnessInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthBrowserEvidence({
                    dependencies: createDependencies({
                        fixture: {
                            ...fixture,
                            runDirectoryPath: secondRunDirectoryPath,
                        },
                        preOperationRecoveryProfile: recoveryProfile,
                        repositoryStateForCheckpoint: () => ({
                            commitHash: secondHarnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: alternateHarnessInvocations,
                        transitionParentLine: `${secondHarnessCommitHash} ${commitHash}\n`,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    preOperationRecoveryRunDirectoryPath:
                        recoveryProfile.failedRunDirectoryPath,
                    runLog: createRunLog(secondRunDirectoryPath),
                }),
            ).rejects.toThrow(/already attempted its static preflight/u);
            expect(alternateHarnessInvocations).toHaveLength(0);
            for (const reservationKind of [
                'browser-recovery-preflight',
                'browser-recovery',
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

    it('consumes the singleton on every recognized pre-operation gate failure', async () => {
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
                expectedPattern: /five authorized harness files/u,
                label: 'changed-file-set',
                transitionChangedFilePaths: [
                    ...recoveryRepairFilePaths,
                    'packages/wasm/src/unrelated.ts',
                ],
            },
            {
                expectedPattern: /sole direct child/u,
                label: 'non-direct-child',
                transitionParentLine: `${harnessCommitHash} ${commitHash} ${'7c'.repeat(20)}\n`,
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
                                commitHash: harnessCommitHash,
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
                            ...('transitionParentLine' in failure
                                ? {
                                      transitionParentLine:
                                          failure.transitionParentLine,
                                  }
                                : {}),
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        preOperationRecoveryRunDirectoryPath:
                            recoveryProfile.failedRunDirectoryPath,
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
                            'browser-recovery',
                        ),
                    ),
                ).rejects.toMatchObject({ code: 'ENOENT' });
                const singletonDirectories = await readdir(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight',
                    ),
                );
                expect(singletonDirectories).toHaveLength(1);
                const singletonRecords = (
                    await readFile(
                        path.join(
                            fixture.reservationRootPath,
                            'browser-recovery-preflight',
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
                const correctedSampleInvocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthBrowserEvidence({
                        dependencies: createDependencies({
                            fixture: {
                                ...fixture,
                                runDirectoryPath: correctedRunDirectoryPath,
                            },
                            preOperationRecoveryProfile: recoveryProfile,
                            repositoryStateForCheckpoint: () => ({
                                commitHash: harnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations: correctedSampleInvocations,
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        preOperationRecoveryRunDirectoryPath:
                            recoveryProfile.failedRunDirectoryPath,
                        runLog: createRunLog(correctedRunDirectoryPath),
                    }),
                ).rejects.toThrow(/already attempted its static preflight/u);
                expect(correctedSampleInvocations).toHaveLength(0);
            });
        }
    });

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
                            commitHash: harnessCommitHash,
                            treeDirty: checkpoint === 'pre-operation',
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    preOperationRecoveryRunDirectoryPath:
                        recoveryProfile.failedRunDirectoryPath,
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/pre-operation checkpoint/u);
            expect(sampleInvocations).toHaveLength(0);
            await expect(
                readdir(
                    path.join(fixture.reservationRootPath, 'browser-recovery'),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            const singletonDirectoryNames = await readdir(
                path.join(
                    fixture.reservationRootPath,
                    'browser-recovery-preflight',
                ),
            );
            const singletonRecords = (
                await readFile(
                    path.join(
                        fixture.reservationRootPath,
                        'browser-recovery-preflight',
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
                                commitHash: harnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations,
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        preOperationRecoveryRunDirectoryPath:
                            recoveryProfile.failedRunDirectoryPath,
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
                                commitHash: harnessCommitHash,
                                treeDirty: false,
                            }),
                            sampleInvocations: correctedInvocations,
                        }),
                        nativeEvidencePath: fixture.nativeEvidencePath,
                        preOperationRecoveryRunDirectoryPath:
                            recoveryProfile.failedRunDirectoryPath,
                        runLog: createRunLog(fixture.runDirectoryPath),
                    }),
                ).rejects.toThrow(/already attempted its static preflight/u);
                expect(correctedInvocations).toHaveLength(0);
            });
        }

        await withTemporaryFixture(async (fixture) => {
            const recoveryProfile =
                await createPreOperationRecoveryProfile(fixture);
            await writeFile(
                path.join(
                    recoveryProfile.failedRunDirectoryPath,
                    '.hidden-prior-operation.json',
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
                            commitHash: harnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    preOperationRecoveryRunDirectoryPath:
                        recoveryProfile.failedRunDirectoryPath,
                    runLog: createRunLog(fixture.runDirectoryPath),
                }),
            ).rejects.toThrow(/recursive file inventory changed/u);
            expect(sampleInvocations).toHaveLength(0);
        });

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
                            commitHash: harnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    preOperationRecoveryRunDirectoryPath:
                        recoveryProfile.failedRunDirectoryPath,
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
                            commitHash: harnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations: correctedInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    preOperationRecoveryRunDirectoryPath:
                        recoveryProfile.failedRunDirectoryPath,
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
                            commitHash: harnessCommitHash,
                            treeDirty: false,
                        }),
                        sampleInvocations,
                    }),
                    nativeEvidencePath: fixture.nativeEvidencePath,
                    preOperationRecoveryRunDirectoryPath:
                        recoveryProfile.failedRunDirectoryPath,
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
                    path.join(fixture.reservationRootPath, 'browser-recovery'),
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
