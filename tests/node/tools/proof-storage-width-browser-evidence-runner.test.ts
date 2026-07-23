import { createHash } from 'node:crypto';
import {
    mkdir,
    mkdtemp,
    readFile,
    readdir,
    rm,
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
    parseProofStorageWidthBrowserMeasurementEvents,
    proofStorageWidthBrowserEvidenceVitestArguments,
    validateProofStorageWidthBrowserEvidenceArtifacts,
    type NativeWidthEvidence,
    type ProofStorageWidthBrowserEvidenceDependencies,
} from '#tools/ci/run-proof-storage-width-browser-evidence';

const commitHash = '9a'.repeat(20);
const officialNativeReservationIdentitySha256Hex = '34'.repeat(32);
const testMemoryLimitBytes = 8_589_934_592;
const expectedWasmHashEnvironmentVariable =
    'VITE_SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_EXPECTED_WASM_SHA256_HEX';

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
        checkpoint: 'after' | 'before' | 'closure-after' | 'initial',
    ) => Readonly<{ commitHash: string; treeDirty: boolean }>;
    readonly sampleInvocations: CommandInvocation[];
}): ProofStorageWidthBrowserEvidenceDependencies => {
    let nativeEvidence: NativeWidthEvidence | undefined;
    return {
        executeCommand: async (invocation) => {
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
