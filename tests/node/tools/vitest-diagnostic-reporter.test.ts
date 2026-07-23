import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import type { TestCase } from 'vitest/node';

import { desktopBrowserProofMeasurementConsolePrefix } from '#tests/support/desktop-browser-proof-measurement';
import {
    proofStorageWidthBrowserEvidenceConsolePrefix,
    proofStorageWidthBrowserEvidenceProjectLabel,
} from '#tests/support/proof-storage-width-browser-evidence';
import {
    deriveProofStorageWidthGeometry,
    proofStorageWidthProfile,
} from '#tools/ci/proof-storage-width-evidence';
import { testDiagnosticEnvironmentVariables } from '#tools/ci/test-diagnostic-environment';
import { VitestDiagnosticReporter } from '#tools/ci/vitest-diagnostic-reporter';

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const createTemporaryDirectory = async (): Promise<string> => {
    return mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-vitest-diagnostics-'),
    );
};

const createProofStorageWidthBrowserMeasurementRecord = (): Readonly<
    Record<string, unknown>
> => {
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
        manifestIdentityShake256Hex: '34'.repeat(64),
        measurementRuntime: 'desktop-browser-wasm',
        maximumArithmeticSliceNanosecondsDecimal: '50',
        maximumTransactionPayloadByteLengthDecimal: '49152',
        openedLeafElementByteLengthDecimal:
            geometry.openedLeafElementByteLength.toString(),
        openedLeafRangeChunkCountDecimal:
            geometry.openedLeafRangeChunkCount.toString(),
        openedValueCountDecimal: geometry.openedValueCount.toString(),
        operationElapsedNanosecondsDecimal: '610',
        operationFinishedAtUnixMilliseconds: '1001',
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
        publicColumnDerivationAlgorithm:
            proofStorageWidthProfile.publicColumnDerivationAlgorithm,
        publicColumnInputDomain:
            proofStorageWidthProfile.publicColumnInputDomain,
        publicColumnSeedHex: proofStorageWidthProfile.publicColumnSeedHex,
        publicBaseLeafByteLengthDecimal:
            geometry.publicBaseLeafByteLength.toString(),
        publicBaseLeafColumnCount: 512,
        queriedLeafPayloadByteLengthDecimal:
            geometry.queriedLeafPayloadByteLength.toString(),
        recomputedCanonicalArtifactByteLengthDecimal: '1700000',
        sourceReplayByteLengthDecimal:
            geometry.sourceReplayByteLength.toString(),
        sealedSecretPlaintextByteLengthDecimal: '0',
        sourceCommittedTransactionCountDecimal: '12288',
        sourceObjectSealTransactionCountDecimal: '512',
        sourcePhysicalObjectCountDecimal: '512',
        storedScratchPeakByteLengthDecimal: '68808864',
        releaseProfileIdentifier:
            proofStorageWidthProfile.releaseProfileIdentifier,
        wasmLinearMemoryEndByteLengthDecimal: '134217728',
        wasmLinearMemoryPeakByteLengthDecimal: '201326592',
        wasmLinearMemoryStartByteLengthDecimal: '134217728',
        wasmSha256Hex: '12'.repeat(32),
        workerYieldCountDecimal: '4',
        workerYieldNanosecondsDecimal: '300',
        widthDependentQueriedBaseOpeningByteLengthDecimal:
            geometry.widthDependentQueriedBaseOpeningByteLength.toString(),
        widthInputIdentityHashDomain:
            proofStorageWidthProfile.widthInputIdentityHashDomain,
    };
};

const createProofStorageWidthReporter = (
    runDirectoryPath: string,
): VitestDiagnosticReporter =>
    new VitestDiagnosticReporter({
        [testDiagnosticEnvironmentVariables.projectLabel]:
            proofStorageWidthBrowserEvidenceProjectLabel,
        [testDiagnosticEnvironmentVariables.runDirectory]: runDirectoryPath,
    });

describe('Vitest diagnostics', () => {
    it('persists useful failure diagnostics without leaking hostile secrets', async () => {
        const runDirectoryPath = await createTemporaryDirectory();
        try {
            const eventFilePath = path.join(
                runDirectoryPath,
                'tests',
                'node-fast.jsonl',
            );
            const reporter = new VitestDiagnosticReporter({
                [testDiagnosticEnvironmentVariables.projectLabel]: 'node-fast',
                [testDiagnosticEnvironmentVariables.runDirectory]:
                    runDirectoryPath,
            });
            const testCase = {
                diagnostic: () => ({
                    duration: 1_234,
                    heap: 4096,
                    retryCount: 0,
                    slow: true,
                    startTime: 0,
                }),
                fullName: 'suite > rejects malformed input',
                id: 'test-id',
                location: { column: 3, line: 12 },
                module: { relativeModuleId: 'tests/example.test.ts' },
                options: { timeout: 5_000 },
                project: { name: 'node-fast' },
                result: () => ({
                    errors: [
                        {
                            cause: new Error('token=underlying-secret'),
                            message: 'assertion failed password=hunter2',
                            name: 'AssertionError',
                            stack: 'Authorization: Bearer stack-secret\n at test',
                        },
                    ],
                    state: 'failed',
                }),
            } as unknown as TestCase;

            reporter.onTestCaseReady?.(testCase);
            reporter.onTestCaseResult?.(testCase);
            reporter.onUserConsoleLog?.({
                content: 'stderr credential=console-secret',
                taskId: 'test-id',
                type: 'stderr',
            });
            reporter.onTestRunEnd?.([], [], 'failed');

            const eventText = await readFile(eventFilePath, 'utf8');
            const events = eventText
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(events.map((event) => event.event)).toEqual([
                'test-started',
                'test-finished',
                'test-stderr',
                'test-run-finished',
            ]);
            expect(events[1]).toMatchObject({
                durationMilliseconds: 1_234,
                heapBytes: 4096,
                result: 'failed',
            });
            const errors = events[1]?.errors;
            if (!Array.isArray(errors) || !isRecord(errors[0])) {
                throw new Error('Expected one serialized test error.');
            }
            expect(errors[0].message).toContain('[redacted]');
            expect(errors[0].stack).toContain('[redacted]');
            if (!isRecord(errors[0].cause)) {
                throw new Error('Expected a serialized test error cause.');
            }
            expect(errors[0].cause.message).toContain('[redacted]');
            expect(events[2]?.content).toContain('[redacted]');
            expect(eventText).not.toMatch(
                /underlying-secret|hunter2|stack-secret|console-secret/u,
            );
        } finally {
            await rm(runDirectoryPath, { force: true, recursive: true });
        }
    });

    it('persists validated desktop-browser proof measurements as structured events', async () => {
        const runDirectoryPath = await createTemporaryDirectory();
        try {
            const eventFilePath = path.join(
                runDirectoryPath,
                'tests',
                'desktop-proof.jsonl',
            );
            const reporter = new VitestDiagnosticReporter({
                [testDiagnosticEnvironmentVariables.projectLabel]:
                    'desktop-proof',
                [testDiagnosticEnvironmentVariables.runDirectory]:
                    runDirectoryPath,
            });
            const measurement = {
                canonicalInputByteLength: 11,
                canonicalInputSha512Hex: '12'.repeat(64),
                canonicalOutputByteLength: 17,
                caseIdentifier: 'ballot-validity-verification',
                copiedBufferPeakByteLength: 1024,
                durationMilliseconds: 12.5,
                executionKind: 'verification',
                externalScratchPeakByteLength: 2048,
                externalScratchReadByteLength: 4096,
                externalScratchTransactionCount: 2,
                externalScratchWriteByteLength: 2048,
                finishedAtUnixMilliseconds: 1_020,
                fullBufferCopiedByteLength: 2048,
                fullBufferCopyCount: 2,
                observedHostAllocationVolumeByteLength: 4096,
                outputSha512Hex: 'ab'.repeat(64),
                retainedResidentPeakByteLength: 4096,
                runOrdinal: 1,
                suiteId: 'cd'.repeat(64),
                startedAtUnixMilliseconds: 1_000,
                wasmSha256Hex: 'ef'.repeat(32),
                wasmLinearMemoryEndByteLength: 196_608,
                wasmLinearMemoryPeakByteLength: 262_144,
                wasmLinearMemoryStartByteLength: 131_072,
            };

            reporter.onUserConsoleLog?.({
                browser: true,
                content: `${desktopBrowserProofMeasurementConsolePrefix}${JSON.stringify(measurement)}\n`,
                origin: 'proof evidence',
                taskId: 'test-id',
                type: 'stdout',
            });

            const events = (await readFile(eventFilePath, 'utf8'))
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(events).toHaveLength(1);
            expect(events[0]).toMatchObject({
                ...measurement,
                browser: true,
                event: 'desktop-browser-proof-measurement',
                testIdentifier: 'test-id',
            });
        } finally {
            await rm(runDirectoryPath, { force: true, recursive: true });
        }
    });

    it('persists exactly one validated proof-storage width browser evidence event', async () => {
        const runDirectoryPath = await createTemporaryDirectory();
        try {
            const reporter = createProofStorageWidthReporter(runDirectoryPath);
            const measurement =
                createProofStorageWidthBrowserMeasurementRecord();
            reporter.onUserConsoleLog({
                browser: true,
                content: `${proofStorageWidthBrowserEvidenceConsolePrefix}${JSON.stringify(measurement)}\n`,
                origin: 'proof-storage width evidence',
                taskId: 'proof-storage-width-test',
                type: 'stdout',
            });
            reporter.onTestRunEnd([], [], 'passed');

            const eventFilePath = path.join(
                runDirectoryPath,
                'tests',
                `${proofStorageWidthBrowserEvidenceProjectLabel}.jsonl`,
            );
            const events = (await readFile(eventFilePath, 'utf8'))
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(
                events.filter(
                    (event) =>
                        event.event === 'proof-storage-width-browser-evidence',
                ),
            ).toHaveLength(1);
            expect(events[0]).toMatchObject({
                browser: true,
                event: 'proof-storage-width-browser-evidence',
                publicBaseLeafColumnCount: 512,
                testIdentifier: 'proof-storage-width-test',
            });
        } finally {
            await rm(runDirectoryPath, { force: true, recursive: true });
        }
    });

    it('refuses malformed proof-storage width browser evidence', async () => {
        const runDirectoryPath = await createTemporaryDirectory();
        try {
            const reporter = createProofStorageWidthReporter(runDirectoryPath);
            expect(() =>
                reporter.onUserConsoleLog({
                    browser: true,
                    content: `${proofStorageWidthBrowserEvidenceConsolePrefix}{`,
                    type: 'stdout',
                }),
            ).toThrow(/not valid JSON/u);
        } finally {
            await rm(runDirectoryPath, { force: true, recursive: true });
        }
    });

    it('refuses duplicate proof-storage width browser evidence', async () => {
        const runDirectoryPath = await createTemporaryDirectory();
        try {
            const reporter = createProofStorageWidthReporter(runDirectoryPath);
            const content = `${proofStorageWidthBrowserEvidenceConsolePrefix}${JSON.stringify(createProofStorageWidthBrowserMeasurementRecord())}`;
            reporter.onUserConsoleLog({
                browser: true,
                content,
                type: 'stdout',
            });
            expect(() =>
                reporter.onUserConsoleLog({
                    browser: true,
                    content,
                    type: 'stdout',
                }),
            ).toThrow(/duplicate evidence records/u);
        } finally {
            await rm(runDirectoryPath, { force: true, recursive: true });
        }
    });

    it('refuses a proof-storage width browser run with missing evidence', async () => {
        const runDirectoryPath = await createTemporaryDirectory();
        try {
            const reporter = createProofStorageWidthReporter(runDirectoryPath);
            expect(() => reporter.onTestRunEnd([], [], 'passed')).toThrow(
                /0 evidence records instead of exactly one/u,
            );
        } finally {
            await rm(runDirectoryPath, { force: true, recursive: true });
        }
    });
});
