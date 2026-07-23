import { createHash } from 'node:crypto';
import {
    access,
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

import type { ActiveLocalRunLog } from '#tools/ci/local-run-log';
import type { ProcessMemoryGuard } from '#tools/ci/process-memory-guard';
import {
    deriveProofStorageWidthGeometry,
    deriveProofStorageWidthExternalMemoryFramingGeometry,
    deriveProofStorageWidthNativeCustodyMetadataByteLengthCeiling,
    deriveProofStorageWidthOpeningWorkspaceGeometry,
    proofStorageWidthProfile,
    proofStorageWidthSchedule,
    type ProofStorageWidth,
} from '#tools/ci/proof-storage-width-evidence';
import {
    appendProofStorageWidthOfficialReservationOutcome,
    buildProofStorageWidthNativeReservationIdentity,
} from '#tools/ci/proof-storage-width-official-reservation';
import type {
    CapturedCommandResult,
    CommandInvocation,
} from '#tools/ci/run-command';
import {
    proofBackendBakeoffFeatureTestNames,
    proofBackendBakeoffIgnoredTestNames,
} from '#tools/ci/run-proof-backend-bakeoff-preflight';
import { loadNativeWidthEvidence } from '#tools/ci/run-proof-storage-width-browser-evidence';
import {
    buildProofStorageWidthCustodyDirectoryPath,
    buildProofStorageWidthEnvironment,
    buildProofStorageWidthFeatureListCommand,
    buildProofStorageWidthListCommand,
    buildProofStorageWidthPrecompileCommand,
    buildProofStorageWidthSampleCommand,
    buildProofStorageWidthStaticPreflightCommand,
    executeProofStorageWidthEvidenceSequence,
    parseProofStorageWidthFeatureInventory,
    parseProofStorageWidthTestInventory,
    proofStorageWidthFeatureTestNames,
    proofStorageWidthCustodyDirectoryEnvironmentVariable,
    proofStorageWidthMeasurementTestName,
    ProofStorageWidthLeftoverCustodyError,
    validateProofStorageWidthEvidenceArtifacts,
    validateProofStorageWidthObservedEvidenceArtifacts,
    type ProofStorageWidthEvidenceRunnerDependencies,
} from '#tools/ci/run-proof-storage-width-evidence';

const exactTestName =
    'bgv::proof_suite::proof_storage_width_evidence::tests::proof_storage_width_evidence_records_incumbent_curve';
const commitHash = '9a'.repeat(20);
const testMemoryLimitBytes = 8_589_934_592;

const canonicalArtifactByteLengthForTest = (width: ProofStorageWidth): bigint =>
    720_000n + 3_000n * BigInt(width) + 64n * (BigInt(width) % 97n);

const browserOperationRegistryByteLengthCeilingForTest = 64_552n;

const canonicalArtifactNonleafRangeChunkCountForTest = (
    width: ProofStorageWidth,
): bigint => 10n + (BigInt(width) % 3n);

const canonicalArtifactPreleafRangeChunkCountForTest = (
    width: ProofStorageWidth,
): bigint => 4n + (BigInt(width) % 3n);

const inputIdentityForTest = (width: ProofStorageWidth): string =>
    BigInt(width).toString(16).padStart(128, '0');

const profileBinding = {
    absoluteCapTableIdentifier:
        proofStorageWidthProfile.absoluteCapTableIdentifier,
    backend: proofStorageWidthProfile.backend,
    backendProfileIdentifier: proofStorageWidthProfile.backendProfileIdentifier,
    custodyModel: 'bounded-external-storage-replay',
    custodySchemaIdentifier: proofStorageWidthProfile.custodySchemaIdentifier,
    custodySchemaVersion: 1,
    evaluationDomainSize: 131_072,
    frozenInputIdentityHashDomain:
        proofStorageWidthProfile.frozenInputIdentityHashDomain,
    frozenInputIdentityShake256Hex:
        proofStorageWidthProfile.frozenInputIdentityShake256Hex,
    frozenInputRecipeIdentifier:
        proofStorageWidthProfile.frozenInputRecipeIdentifier,
    intendedReleaseRuntime: proofStorageWidthProfile.intendedReleaseRuntime,
    maximumNativeCustodyPathByteLength:
        proofStorageWidthProfile.maximumNativeCustodyPathByteLength,
    measurementRuntime: proofStorageWidthProfile.measurementRuntime,
    publicColumnDerivationAlgorithm:
        proofStorageWidthProfile.publicColumnDerivationAlgorithm,
    publicColumnInputDomain: proofStorageWidthProfile.publicColumnInputDomain,
    publicColumnSeedHex: proofStorageWidthProfile.publicColumnSeedHex,
    releaseProfileIdentifier: proofStorageWidthProfile.releaseProfileIdentifier,
    representativeBrowserWidth: 512,
    traceRowCount: 16_384,
    widthInputIdentityHashDomain:
        proofStorageWidthProfile.widthInputIdentityHashDomain,
} as const;

const withTemporaryDirectory = async <Result>(
    action: (directoryPath: string) => Promise<Result>,
): Promise<Result> => {
    const temporaryRootPath = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-proof-storage-width-'),
    );
    const directoryPath = path.join(temporaryRootPath, 'run');
    await mkdir(directoryPath);
    try {
        return await action(directoryPath);
    } finally {
        await rm(temporaryRootPath, { force: true, recursive: true });
    }
};

const officialReservationRootPathForRun = (runDirectoryPath: string): string =>
    path.join(path.dirname(runDirectoryPath), 'official-reservations');

const successfulCommandResult = (
    standardOutput = '',
): CapturedCommandResult => ({
    exitCode: 0,
    stderr: '',
    stdout: standardOutput,
    terminationSignal: null,
});

const failedCommandResult = (): CapturedCommandResult => ({
    exitCode: 1,
    stderr: 'preflight failed',
    stdout: '',
    terminationSignal: null,
});

const guardKilledCommandResult = (): CapturedCommandResult => ({
    exitCode: 1,
    stderr: 'guard terminated the process tree',
    stdout: '',
    terminationSignal: 'SIGKILL',
});

const createRunLog = (
    runDirectoryPath: string,
    writeEvent: ActiveLocalRunLog['writeEvent'] = () => undefined,
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
    writeCombinedOutput: () => undefined,
    writeCommandOutput: () => undefined,
    writeEvent,
});

const createProcessMemoryGuard = (): ProcessMemoryGuard => ({
    buildVerificationCommand: () => ({
        args: ['verify'],
        command: 'test-process-memory-guard-verification',
        description: 'verify test process memory guard',
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

const requiredEnvironmentValue = (
    environment: NodeJS.ProcessEnv | undefined,
    name: string,
): string => {
    const value = environment?.[name];
    if (value === undefined) {
        throw new Error(`Missing test environment value ${name}.`);
    }
    return value;
};

const buildResult = (input: {
    readonly elapsedNanoseconds: bigint;
    readonly manifestIdentityShake256Hex: string;
    readonly physicalObjectPeak?: bigint;
    readonly width: ProofStorageWidth;
}): Readonly<Record<string, unknown>> => {
    const geometry = deriveProofStorageWidthGeometry(input.width);
    const canonicalArtifactByteLength = canonicalArtifactByteLengthForTest(
        input.width,
    );
    const canonicalArtifactNonleafRangeChunkCount =
        canonicalArtifactNonleafRangeChunkCountForTest(input.width);
    return {
        ...profileBinding,
        absorbedLeafValueCountDecimal:
            geometry.absorbedLeafValueCount.toString(),
        activeColumnLdeScratchByteLengthDecimal:
            geometry.activeColumnLdeScratchByteLength.toString(),
        algebraicBaseColumnCount: 8,
        artifactShake256Hex: '12'.repeat(64),
        baseLeafObjectReadByteLengthDecimal: '0',
        baseLeafObjectWrittenByteLengthDecimal: '0',
        baseRootShake256Hex: '34'.repeat(64),
        batchingFunctionCount: 18,
        canonicalArtifactNonleafRangeChunkCountDecimal:
            canonicalArtifactNonleafRangeChunkCount.toString(),
        canonicalArtifactPostleafRangeChunkCountDecimal: '6',
        canonicalArtifactPreleafRangeChunkCountDecimal:
            canonicalArtifactPreleafRangeChunkCountForTest(
                input.width,
            ).toString(),
        canonicalArtifactByteLengthDecimal:
            canonicalArtifactByteLength.toString(),
        custodyCleanupCompleted: true,
        elapsedNanosecondsDecimal: input.elapsedNanoseconds.toString(),
        exactCandidate: {
            firstDataModulus: 1_953_759_233,
            materialRadix: 129_140_163,
            plaintextModulus: 257,
            ringDimension: 32_768,
            rosterSize: 10,
        },
        externalCommittedTransactionCountDecimal: (
            24n * BigInt(input.width) +
            3n +
            2n *
                (geometry.openedLeafRangeChunkCount +
                    canonicalArtifactNonleafRangeChunkCount)
        ).toString(),
        externalReadByteLengthDecimal: (
            6n * geometry.sourceReplayByteLength +
            canonicalArtifactByteLength
        ).toString(),
        externalWrittenByteLengthDecimal: (
            geometry.sourceReplayByteLength + canonicalArtifactByteLength
        ).toString(),
        formatVersion: 1,
        inputIdentityShake256Hex: inputIdentityForTest(input.width),
        ldeTransformCountDecimal: geometry.ldeTransformCount.toString(),
        localRecordSealInvocationCountDecimal:
            geometry.localRecordSealInvocationCount.toString(),
        manifestIdentityShake256Hex: input.manifestIdentityShake256Hex,
        maximumTransactionPayloadByteLengthDecimal: '49152',
        openedLeafElementByteLengthDecimal:
            geometry.openedLeafElementByteLength.toString(),
        openedLeafRangeChunkCountDecimal:
            geometry.openedLeafRangeChunkCount.toString(),
        openedValueCountDecimal: geometry.openedValueCount.toString(),
        operationFinishedAtUnixMilliseconds: 1_300,
        operationStartedAtUnixMilliseconds: 1_000,
        persistedBaseLeafByteLengthDecimal: '0',
        persistedLdeByteLengthDecimal: '0',
        physicalObjectPeakDecimal: (
            input.physicalObjectPeak ?? geometry.physicalObjectPeak
        ).toString(),
        proofByteLengthDecimal: canonicalArtifactByteLength.toString(),
        proofObjectSealTransactionCountDecimal: '1',
        proofPhysicalObjectCountDecimal: '1',
        publicBaseLeafByteLengthDecimal:
            geometry.publicBaseLeafByteLength.toString(),
        publicBaseLeafColumnCount: input.width,
        queriedLeafPayloadByteLengthDecimal:
            geometry.queriedLeafPayloadByteLength.toString(),
        recomputedCanonicalArtifactByteLengthDecimal:
            canonicalArtifactByteLength.toString(),
        sealedSecretPlaintextByteLengthDecimal: '0',
        sourceCommittedTransactionCountDecimal: (
            24n * BigInt(input.width)
        ).toString(),
        sourceObjectSealTransactionCountDecimal: BigInt(input.width).toString(),
        sourceOpeningClaimCount: 9,
        sourcePhysicalObjectCountDecimal: BigInt(input.width).toString(),
        sourceReplayByteLengthDecimal:
            geometry.sourceReplayByteLength.toString(),
        storedScratchPeakByteLengthDecimal: (
            geometry.sourceReplayByteLength + canonicalArtifactByteLength
        ).toString(),
        widthDependentQueriedBaseOpeningByteLengthDecimal:
            geometry.widthDependentQueriedBaseOpeningByteLength.toString(),
        width: input.width,
    };
};

const buildStaticPreflightResult = (): Readonly<Record<string, unknown>> => ({
    ...profileBinding,
    absoluteCaps: {
        maximumCommonProofByteLengthDecimal:
            proofStorageWidthProfile.maximumCommonProofByteLength.toString(),
        maximumCopiedBufferByteLengthDecimal:
            proofStorageWidthProfile.maximumCopiedBufferByteLength.toString(),
        maximumLocalRecordSealInvocationCountDecimal:
            proofStorageWidthProfile.maximumLocalRecordSealInvocationCount.toString(),
        maximumLocalRecordSealedPlaintextByteLengthDecimal:
            proofStorageWidthProfile.maximumLocalRecordSealedPlaintextByteLength.toString(),
        maximumPhysicalObjectCountDecimal:
            proofStorageWidthProfile.maximumPhysicalObjectCount.toString(),
        maximumStoredScratchByteLengthDecimal:
            proofStorageWidthProfile.maximumStoredScratchByteLength.toString(),
        maximumTransportByteLengthDecimal:
            proofStorageWidthProfile.maximumTransportByteLength.toString(),
        maximumWasmMemoryByteLengthDecimal:
            proofStorageWidthProfile.maximumWasmMemoryByteLength.toString(),
    },
    algebraicBaseColumnCount: 8,
    batchingFunctionCount: 18,
    exactCandidate: {
        firstDataModulus: 1_953_759_233,
        materialRadix: 129_140_163,
        plaintextModulus: 257,
        ringDimension: 32_768,
        rosterSize: 10,
    },
    formatVersion: 1,
    points: proofStorageWidthSchedule.map((width) => {
        const geometry = deriveProofStorageWidthGeometry(width);
        const canonicalProofByteLengthCeiling =
            1_000_000n + 4_000n * BigInt(width);
        const canonicalArtifactNonleafRangeChunkCountCeiling =
            (canonicalProofByteLengthCeiling + 49_151n) / 49_152n + 1n;
        const externalReadByteLengthCeiling =
            6n * geometry.sourceReplayByteLength +
            canonicalProofByteLengthCeiling;
        const externalWrittenByteLengthCeiling =
            geometry.sourceReplayByteLength + canonicalProofByteLengthCeiling;
        const digestStateByteLengthCeiling = 33_554_432n;
        const digestStateContainerByteLengthCeiling =
            proofStorageWidthProfile.vectorHeaderByteLengthNative64 +
            proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength;
        const frozenFixtureAndContainerByteLengthCeiling = 2_000_000n;
        const canonicalArtifactContainerByteLengthCeiling =
            3n *
            (proofStorageWidthProfile.vectorHeaderByteLengthNative64 +
                proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength);
        const externalMemoryFramingGeometry =
            deriveProofStorageWidthExternalMemoryFramingGeometry();
        const openingWorkspaceGeometry =
            deriveProofStorageWidthOpeningWorkspaceGeometry(width);
        return {
            absorbedLeafValueCountDecimal:
                geometry.absorbedLeafValueCount.toString(),
            activeColumnLdeScratchByteLengthDecimal:
                geometry.activeColumnLdeScratchByteLength.toString(),
            baseLeafObjectReadByteLengthDecimal: '0',
            baseLeafObjectWrittenByteLengthDecimal: '0',
            canonicalArtifactNonleafRangeChunkCountCeilingDecimal:
                canonicalArtifactNonleafRangeChunkCountCeiling.toString(),
            canonicalProofByteLengthCeilingDecimal:
                canonicalProofByteLengthCeiling.toString(),
            committedTransactionCountCeilingDecimal: (
                24n * BigInt(width) +
                3n +
                2n *
                    (geometry.openedLeafRangeChunkCount +
                        canonicalArtifactNonleafRangeChunkCountCeiling)
            ).toString(),
            copiedBufferByteLengthCeilingDecimal:
                proofStorageWidthProfile.externalMemoryCopiedBufferByteLengthCeiling.toString(),
            digestStateByteLengthCeilingDecimal:
                digestStateByteLengthCeiling.toString(),
            digestStateContainerByteLengthCeilingDecimal:
                digestStateContainerByteLengthCeiling.toString(),
            frozenFixtureAndContainerByteLengthCeilingDecimal:
                frozenFixtureAndContainerByteLengthCeiling.toString(),
            retainedAlgebraicCoefficientByteLengthCeilingDecimal:
                proofStorageWidthProfile.retainedAlgebraicCoefficientByteLength.toString(),
            extensionDomainWorkingByteLengthCeilingDecimal:
                proofStorageWidthProfile.extensionDomainWorkingByteLength.toString(),
            inputIdentityShake256Hex: inputIdentityForTest(width),
            canonicalArtifactLiveCopyByteLengthCeilingDecimal: (
                2n * canonicalProofByteLengthCeiling
            ).toString(),
            canonicalArtifactContainerByteLengthCeilingDecimal:
                canonicalArtifactContainerByteLengthCeiling.toString(),
            openingArtifactAndTranscriptByteLengthCeilingDecimal:
                canonicalProofByteLengthCeiling.toString(),
            proverPublicOpeningWorkspaceByteLengthCeilingDecimal:
                openingWorkspaceGeometry.proverPublicOpeningWorkspaceByteLengthCeiling.toString(),
            freshVerifierPublicOpeningWorkspaceByteLengthCeilingDecimal:
                openingWorkspaceGeometry.freshVerifierPublicOpeningWorkspaceByteLengthCeiling.toString(),
            freshVerifierOuterVectorContainerByteLengthCeilingDecimal:
                openingWorkspaceGeometry.freshVerifierOuterVectorContainerByteLengthCeiling.toString(),
            boundaryTransferByteLengthCeilingDecimal:
                proofStorageWidthProfile.externalMemoryBoundaryTransferLiveByteLengthCeiling.toString(),
            browserOperationRegistryByteLengthCeilingDecimal:
                browserOperationRegistryByteLengthCeilingForTest.toString(),
            rawAbiRequestCopyWorkspaceByteLengthCeilingDecimal:
                externalMemoryFramingGeometry.rawAbiRequestCopyWorkspaceByteLengthCeiling.toString(),
            rawAbiResponseDecodeWorkspaceByteLengthCeilingDecimal:
                externalMemoryFramingGeometry.rawAbiResponseDecodeWorkspaceByteLengthCeiling.toString(),
            rawAbiTransferWorkspaceByteLengthCeilingDecimal:
                externalMemoryFramingGeometry.rawAbiTransferWorkspaceByteLengthCeiling.toString(),
            nativeCustodyMetadataByteLengthCeilingDecimal:
                deriveProofStorageWidthNativeCustodyMetadataByteLengthCeiling(
                    width,
                ).toString(),
            externalIoByteLengthCeilingDecimal: (
                externalReadByteLengthCeiling + externalWrittenByteLengthCeiling
            ).toString(),
            externalReadByteLengthCeilingDecimal:
                externalReadByteLengthCeiling.toString(),
            externalWrittenByteLengthCeilingDecimal:
                externalWrittenByteLengthCeiling.toString(),
            ldeTransformCountDecimal: geometry.ldeTransformCount.toString(),
            legacyBaseLeafObjectByteLengthDecimal:
                geometry.legacyBaseLeafObjectByteLength.toString(),
            localRecordSealInvocationCountDecimal: '0',
            maximumTransactionPayloadByteLengthDecimal: '49152',
            openedLeafElementByteLengthDecimal:
                geometry.openedLeafElementByteLength.toString(),
            openedLeafRangeChunkCountDecimal:
                geometry.openedLeafRangeChunkCount.toString(),
            openedValueCountDecimal: geometry.openedValueCount.toString(),
            persistedLdeByteLengthDecimal: '0',
            physicalObjectPeakDecimal: geometry.physicalObjectPeak.toString(),
            proofObjectSealTransactionCountDecimal: '1',
            proofPhysicalObjectCountDecimal: '1',
            publicBaseLeafByteLengthDecimal:
                geometry.publicBaseLeafByteLength.toString(),
            publicBaseLeafColumnCount: width,
            queriedLeafPayloadByteLengthDecimal:
                geometry.queriedLeafPayloadByteLength.toString(),
            sealedSecretPlaintextByteLengthDecimal: '0',
            sourceCommittedTransactionCountDecimal: (
                24n * BigInt(width)
            ).toString(),
            sourceObjectSealTransactionCountDecimal: BigInt(width).toString(),
            sourcePhysicalObjectCountDecimal: BigInt(width).toString(),
            sourceReplayByteLengthDecimal:
                geometry.sourceReplayByteLength.toString(),
            storedScratchPeakByteLengthCeilingDecimal: (
                geometry.sourceReplayByteLength +
                canonicalProofByteLengthCeiling
            ).toString(),
            transportByteLengthCeilingDecimal:
                canonicalProofByteLengthCeiling.toString(),
            wasmMemoryByteLengthCeilingDecimal: (
                digestStateByteLengthCeiling +
                digestStateContainerByteLengthCeiling +
                frozenFixtureAndContainerByteLengthCeiling +
                geometry.activeColumnLdeScratchByteLength +
                proofStorageWidthProfile.retainedAlgebraicCoefficientByteLength +
                proofStorageWidthProfile.extensionDomainWorkingByteLength +
                3n * canonicalProofByteLengthCeiling +
                canonicalArtifactContainerByteLengthCeiling +
                openingWorkspaceGeometry.proverPublicOpeningWorkspaceByteLengthCeiling +
                openingWorkspaceGeometry.freshVerifierPublicOpeningWorkspaceByteLengthCeiling +
                openingWorkspaceGeometry.freshVerifierOuterVectorContainerByteLengthCeiling +
                externalMemoryFramingGeometry.rawAbiTransferWorkspaceByteLengthCeiling +
                browserOperationRegistryByteLengthCeilingForTest
            ).toString(),
            widthDependentQueriedBaseOpeningByteLengthDecimal:
                geometry.widthDependentQueriedBaseOpeningByteLength.toString(),
        };
    }),
    sourceOpeningClaimCount: 9,
    widths: proofStorageWidthSchedule,
});

const buildGuardJsonLines = (includeBaseline: boolean): string =>
    [
        {
            aggregateProcessTreeMemoryLimit: true,
            elapsedMilliseconds: 0,
            eventType: 'guard-started',
            memoryLimitBytes: testMemoryLimitBytes,
            recordedAtUnixMilliseconds: 700,
            resourceSampleIntervalMilliseconds: 100,
            sequence: 0,
        },
        {
            elapsedMilliseconds: 50,
            eventType: 'child-started',
            recordedAtUnixMilliseconds: 750,
            sequence: 1,
        },
        ...(includeBaseline
            ? [
                  {
                      confirmedMemoryLimitViolation: false,
                      elapsedMilliseconds: 200,
                      eventType: 'resource-sample',
                      processTreeResidentMemoryBytes: 100_000_000,
                      recordedAtUnixMilliseconds: 900,
                      sampleError: null,
                      sequence: 2,
                  },
              ]
            : []),
        {
            confirmedMemoryLimitViolation: false,
            elapsedMilliseconds: 400,
            eventType: 'resource-sample',
            processTreeResidentMemoryBytes: 200_000_000,
            recordedAtUnixMilliseconds: 1_100,
            sampleError: null,
            sequence: includeBaseline ? 3 : 2,
        },
        {
            confirmedMemoryLimitViolation: false,
            elapsedMilliseconds: 600,
            eventType: 'resource-sample',
            processTreeResidentMemoryBytes: 150_000_000,
            recordedAtUnixMilliseconds: 1_300,
            sampleError: null,
            sequence: includeBaseline ? 4 : 3,
        },
        {
            elapsedMilliseconds: 700,
            eventType: 'child-exited',
            exitCode: 0,
            memoryEvidence: 'completed',
            recordedAtUnixMilliseconds: 1_400,
            sequence: includeBaseline ? 5 : 4,
            terminationClassification: 'completed',
        },
    ]
        .map((record) => JSON.stringify(record))
        .join('\n');

const createSequenceDependencies = (input: {
    readonly capFailureWidth?: ProofStorageWidth;
    readonly failPreflightFeaturePhase?: boolean;
    readonly failWidthStaticPreflightPhase?: boolean;
    readonly includeBaseline?: boolean;
    readonly invalidWidthStaticPreflightGuardTelemetry?: boolean;
    readonly invocations: CommandInvocation[];
    readonly leaveCustodyOnFailedWidth?: ProofStorageWidth;
    readonly repositoryCheckpoints?: string[];
    readonly repositoryStates?: readonly RepositoryState[];
    readonly runDirectoryPath: string;
    readonly superlinearWidth?: ProofStorageWidth;
}): ProofStorageWidthEvidenceRunnerDependencies => {
    let repositoryStateIndex = 0;
    return {
        executeCommand: async (invocation) => {
            input.invocations.push(invocation);
            if (
                invocation.description ===
                'list the proof backend bakeoff feature tests'
            ) {
                return successfulCommandResult(
                    `${proofBackendBakeoffFeatureTestNames
                        .map((testName) => `${testName}: test`)
                        .join('\n')}\n`,
                );
            }
            if (
                invocation.description ===
                'list the proof backend bakeoff ignored owners'
            ) {
                return successfulCommandResult(
                    `${proofBackendBakeoffIgnoredTestNames
                        .map((testName) => `${testName}: test`)
                        .join('\n')}\n`,
                );
            }
            if (
                invocation.description ===
                'list every proof-storage width feature test'
            ) {
                return successfulCommandResult(
                    `${proofStorageWidthFeatureTestNames
                        .map((testName) => `${testName}: test`)
                        .join('\n')}\n`,
                );
            }
            if (
                invocation.description ===
                'list the release proof-storage width owner'
            ) {
                return successfulCommandResult(`${exactTestName}: test\n`);
            }
            if (invocation.command !== 'test-process-memory-guard') {
                return successfulCommandResult();
            }
            const staticPreflightResultPath =
                invocation.env?.[
                    'SEALED_LATTICE_PROOF_STORAGE_WIDTH_STATIC_PREFLIGHT_RESULT_PATH'
                ];
            if (staticPreflightResultPath !== undefined) {
                if (
                    input.failWidthStaticPreflightPhase === true &&
                    invocation.description ===
                        'guarded run the proof-storage width non-ignored static feature tests'
                ) {
                    return failedCommandResult();
                }
                const diagnosticsPathIndex =
                    invocation.args.indexOf('--diagnostics-path');
                const diagnosticsPath =
                    invocation.args[diagnosticsPathIndex + 1];
                if (diagnosticsPath === undefined) {
                    throw new Error(
                        'Missing static-preflight guard diagnostics path.',
                    );
                }
                await Promise.all([
                    writeFile(
                        staticPreflightResultPath,
                        `${JSON.stringify(buildStaticPreflightResult(), null, 2)}\n`,
                        { encoding: 'utf8', flag: 'wx' },
                    ),
                    writeFile(
                        diagnosticsPath,
                        `${
                            input.invalidWidthStaticPreflightGuardTelemetry ===
                                true &&
                            invocation.description ===
                                'guarded run the proof-storage width non-ignored static feature tests'
                                ? buildGuardJsonLines(true).replace(
                                      '"sampleError":null',
                                      '"sampleError":"intentional static guard failure"',
                                  )
                                : buildGuardJsonLines(true)
                        }\n`,
                        { encoding: 'utf8', flag: 'wx' },
                    ),
                ]);
                return successfulCommandResult();
            }
            if (
                invocation.env?.SEALED_LATTICE_PROOF_STORAGE_WIDTH === undefined
            ) {
                if (
                    input.failPreflightFeaturePhase === true &&
                    invocation.description.includes('non-ignored feature tests')
                ) {
                    return failedCommandResult();
                }
                const diagnosticsPathIndex =
                    invocation.args.indexOf('--diagnostics-path');
                const diagnosticsPath =
                    invocation.args[diagnosticsPathIndex + 1];
                if (diagnosticsPath === undefined) {
                    throw new Error(
                        'Missing preflight guard diagnostics path.',
                    );
                }
                await writeFile(
                    diagnosticsPath,
                    `${buildGuardJsonLines(true)}\n`,
                    { encoding: 'utf8', flag: 'wx' },
                );
                return successfulCommandResult();
            }
            const width = Number.parseInt(
                requiredEnvironmentValue(
                    invocation.env,
                    'SEALED_LATTICE_PROOF_STORAGE_WIDTH',
                ),
                10,
            ) as ProofStorageWidth;
            const resultPath = requiredEnvironmentValue(
                invocation.env,
                'SEALED_LATTICE_PROOF_STORAGE_WIDTH_RESULT_PATH',
            );
            const diagnosticsPathIndex =
                invocation.args.indexOf('--diagnostics-path');
            const diagnosticsPath = invocation.args[diagnosticsPathIndex + 1];
            if (diagnosticsPath === undefined) {
                throw new Error('Missing test guard diagnostics path.');
            }
            if (input.leaveCustodyOnFailedWidth === width) {
                const custodyPath = requiredEnvironmentValue(
                    invocation.env,
                    proofStorageWidthCustodyDirectoryEnvironmentVariable,
                );
                await mkdir(custodyPath);
                await writeFile(
                    path.join(custodyPath, 'public-column-0000.bin'),
                    'partial custody',
                    'utf8',
                );
                return guardKilledCommandResult();
            }
            await Promise.all([
                writeFile(
                    resultPath,
                    `${JSON.stringify(
                        buildResult({
                            elapsedNanoseconds:
                                input.superlinearWidth === width
                                    ? 1_000_000_000n
                                    : 1_000_000n + BigInt(width) * 1_000n,
                            manifestIdentityShake256Hex:
                                requiredEnvironmentValue(
                                    invocation.env,
                                    'SEALED_LATTICE_PROOF_STORAGE_WIDTH_MANIFEST_IDENTITY_SHAKE256_HEX',
                                ),
                            physicalObjectPeak:
                                input.capFailureWidth === width
                                    ? proofStorageWidthProfile.maximumPhysicalObjectCount +
                                      1n
                                    : deriveProofStorageWidthGeometry(width)
                                          .physicalObjectPeak,
                            width,
                        }),
                        null,
                        2,
                    )}\n`,
                    { encoding: 'utf8', flag: 'wx' },
                ),
                writeFile(
                    diagnosticsPath,
                    `${buildGuardJsonLines(input.includeBaseline ?? true)}\n`,
                    { encoding: 'utf8', flag: 'wx' },
                ),
            ]);
            return successfulCommandResult();
        },
        officialReservationRootPath: officialReservationRootPathForRun(
            input.runDirectoryPath,
        ),
        processMemoryGuard: createProcessMemoryGuard(),
        readRepositoryState: (checkpoint) => {
            input.repositoryCheckpoints?.push(checkpoint);
            const state = input.repositoryStates?.[repositoryStateIndex] ?? {
                commitHash,
                treeDirty: false,
            };
            repositoryStateIndex += 1;
            return Promise.resolve(state);
        },
    };
};

type RepositoryState = Readonly<{
    commitHash: string;
    treeDirty: boolean;
}>;

type MutableAggregateEvidence = {
    decision: Record<string, unknown>;
    mandatoryPreflight: { attachmentPath: string };
    manifestPath: string;
    sampleArtifacts: Array<{
        guardPath: string;
        guardSha256Hex: string;
        reservationPath: string;
        reservationSha256Hex: string;
        resultPath: string;
        resultSha256Hex: string;
    }>;
    staticPreflight: {
        attachmentPath: string;
        guardPath: string;
    };
};

describe('Proof-storage width evidence runner', () => {
    it('never creates a missing reservation while appending an outcome', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const missingReservationPath = path.join(
                officialReservationRootPathForRun(runDirectoryPath),
                'missing-started.json',
            );
            await expect(
                appendProofStorageWidthOfficialReservationOutcome({
                    outcome: 'failed',
                    reservationPath: missingReservationPath,
                }),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            await expect(access(missingReservationPath)).rejects.toMatchObject({
                code: 'ENOENT',
            });
        }));

    it('derives stable reservation keys and separates genuinely different source or guard identities', () => {
        const baseIdentity = buildProofStorageWidthNativeReservationIdentity({
            memoryLimitBytes: testMemoryLimitBytes,
            officialOwner: proofStorageWidthMeasurementTestName,
            sourceCommitHash: commitHash,
        });
        expect(
            buildProofStorageWidthNativeReservationIdentity({
                memoryLimitBytes: testMemoryLimitBytes,
                officialOwner: proofStorageWidthMeasurementTestName,
                sourceCommitHash: commitHash,
            }),
        ).toEqual(baseIdentity);
        expect(
            buildProofStorageWidthNativeReservationIdentity({
                memoryLimitBytes: testMemoryLimitBytes,
                officialOwner: proofStorageWidthMeasurementTestName,
                sourceCommitHash: 'ab'.repeat(20),
            }).identitySha256Hex,
        ).not.toBe(baseIdentity.identitySha256Hex);
        expect(
            buildProofStorageWidthNativeReservationIdentity({
                memoryLimitBytes: testMemoryLimitBytes / 2,
                officialOwner: proofStorageWidthMeasurementTestName,
                sourceCommitHash: commitHash,
            }).identitySha256Hex,
        ).not.toBe(baseIdentity.identitySha256Hex);
    });

    it('pins the release feature, exact ignored owner, isolated width, and result path', () => {
        const environment = buildProofStorageWidthEnvironment({
            baseEnvironment: {
                CARGO_TARGET_DIR: 'inherited-target',
                SEALED_LATTICE_PROOF_STORAGE_WIDTH: '999',
                SEALED_LATTICE_PROOF_STORAGE_WIDTH_RESULT_PATH:
                    'inherited-result',
                SEALED_LATTICE_PROOF_STORAGE_WIDTH_MANIFEST_IDENTITY_SHAKE256_HEX:
                    'inherited-manifest',
                SEALED_LATTICE_PROOF_STORAGE_WIDTH_CUSTODY_DIRECTORY_PATH:
                    'inherited-custody',
                SEALED_LATTICE_PROOF_STORAGE_WIDTH_STATIC_PREFLIGHT_RESULT_PATH:
                    'inherited-static-result',
                SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
            },
            targetDirectoryPath: 'dedicated-target',
        });
        expect(environment).toMatchObject({
            CARGO_BUILD_JOBS: '1',
            CARGO_INCREMENTAL: '0',
            CARGO_TARGET_DIR: 'dedicated-target',
            RAYON_NUM_THREADS: '1',
            RUST_TEST_THREADS: '1',
        });
        expect(environment.SEALED_LATTICE_PROOF_STORAGE_WIDTH).toBeUndefined();
        expect(
            environment.SEALED_LATTICE_PROOF_STORAGE_WIDTH_MANIFEST_IDENTITY_SHAKE256_HEX,
        ).toBeUndefined();
        expect(
            environment.SEALED_LATTICE_PROOF_STORAGE_WIDTH_STATIC_PREFLIGHT_RESULT_PATH,
        ).toBeUndefined();
        expect(
            environment.SEALED_LATTICE_PROOF_STORAGE_WIDTH_CUSTODY_DIRECTORY_PATH,
        ).toBeUndefined();
        expect(
            environment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS,
        ).toBeUndefined();

        expect(
            buildProofStorageWidthPrecompileCommand(environment).args,
        ).toEqual(
            expect.arrayContaining([
                '--locked',
                '--release',
                '--features',
                'proof-storage-width-evidence',
                '--lib',
                '--no-run',
            ]),
        );
        const listCommand = buildProofStorageWidthListCommand(environment);
        expect(listCommand.args).toContain('--ignored');
        expect(listCommand.args).toContain('--list');
        const featureListCommand =
            buildProofStorageWidthFeatureListCommand(environment);
        expect(featureListCommand.args).toContain('--list');
        expect(featureListCommand.args).not.toContain('--ignored');
        const staticPreflightCommand =
            buildProofStorageWidthStaticPreflightCommand({
                baseEnvironment: environment,
                resultPath: path.resolve('static-width-result.json'),
            });
        expect(staticPreflightCommand.args).not.toContain('--ignored');
        expect(staticPreflightCommand.env).toMatchObject({
            SEALED_LATTICE_PROOF_STORAGE_WIDTH_STATIC_PREFLIGHT_RESULT_PATH:
                path.resolve('static-width-result.json'),
        });
        const resultPath = path.resolve('width-result.json');
        const custodyDirectoryPath = buildProofStorageWidthCustodyDirectoryPath(
            {
                resultPath,
                uniqueIdentifier: '12345678-1234-4123-8123-123456789abc',
            },
        );
        const sampleCommand = buildProofStorageWidthSampleCommand({
            baseEnvironment: environment,
            custodyDirectoryPath,
            exactTestName,
            manifestIdentityShake256Hex: 'ab'.repeat(64),
            resultPath,
            width: 512,
        });
        expect(sampleCommand.args).toContain('--exact');
        expect(sampleCommand.args).toContain('--ignored');
        expect(sampleCommand.env).toMatchObject({
            SEALED_LATTICE_PROOF_STORAGE_WIDTH_MANIFEST_IDENTITY_SHAKE256_HEX:
                'ab'.repeat(64),
            SEALED_LATTICE_PROOF_STORAGE_WIDTH: '512',
            SEALED_LATTICE_PROOF_STORAGE_WIDTH_CUSTODY_DIRECTORY_PATH:
                custodyDirectoryPath,
        });
        expect(() =>
            buildProofStorageWidthSampleCommand({
                baseEnvironment: environment,
                custodyDirectoryPath,
                exactTestName,
                manifestIdentityShake256Hex: 'ab'.repeat(64),
                resultPath: 'relative.json',
                width: 8,
            }),
        ).toThrow(/must be absolute/u);
        expect(() =>
            buildProofStorageWidthSampleCommand({
                baseEnvironment: environment,
                custodyDirectoryPath: 'relative-custody',
                exactTestName,
                manifestIdentityShake256Hex: 'ab'.repeat(64),
                resultPath,
                width: 8,
            }),
        ).toThrow(/custody directory path must be absolute/u);
        expect(() =>
            buildProofStorageWidthSampleCommand({
                baseEnvironment: environment,
                custodyDirectoryPath: path.resolve(
                    'other-sample-directory',
                    '.width-result.json.12345678-1234-4123-8123-123456789abc.bounded-custody',
                ),
                exactTestName,
                manifestIdentityShake256Hex: 'ab'.repeat(64),
                resultPath,
                width: 8,
            }),
        ).toThrow(/immediate child of the result directory/u);
        expect(() =>
            buildProofStorageWidthSampleCommand({
                baseEnvironment: environment,
                custodyDirectoryPath: path.join(
                    path.dirname(resultPath),
                    '.wrong-result.json.12345678-1234-4123-8123-123456789abc.bounded-custody',
                ),
                exactTestName,
                manifestIdentityShake256Hex: 'ab'.repeat(64),
                resultPath,
                width: 8,
            }),
        ).toThrow(/name is not bound to the result file/u);
        expect(() =>
            buildProofStorageWidthSampleCommand({
                baseEnvironment: environment,
                custodyDirectoryPath: path.join(
                    path.dirname(resultPath),
                    '.width-result.json.not-a-uuid.bounded-custody',
                ),
                exactTestName,
                manifestIdentityShake256Hex: 'ab'.repeat(64),
                resultPath,
                width: 8,
            }),
        ).toThrow(/canonical UUID/u);
    });

    it('requires exactly one matching ignored test owner', () => {
        expect(
            parseProofStorageWidthTestInventory(`${exactTestName}: test\n`),
        ).toBe(exactTestName);
        expect(() => parseProofStorageWidthTestInventory('')).toThrow(
            /exactly one ignored owner/u,
        );
        expect(() =>
            parseProofStorageWidthTestInventory(
                `${exactTestName}: test\nother::${exactTestName}: test\n`,
            ),
        ).toThrow(/listed 2/u);
        expect(() =>
            parseProofStorageWidthTestInventory('other::owner: test\n'),
        ).toThrow(/unexpected test/u);
    });

    it('requires the exact complete width-feature inventory', () => {
        const inventory = `${proofStorageWidthFeatureTestNames
            .map((testName) => `${testName}: test`)
            .join('\n')}\n`;
        expect(parseProofStorageWidthFeatureInventory(inventory)).toEqual(
            proofStorageWidthFeatureTestNames,
        );
        expect(() =>
            parseProofStorageWidthFeatureInventory(
                `${inventory}other::unowned: test\n`,
            ),
        ).toThrow(/exact registry.*Extra/u);
    });

    it('runs each precommitted width once in order and writes pinned append-only progress', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            const result = await executeProofStorageWidthEvidenceSequence({
                dependencies: createSequenceDependencies({
                    invocations,
                    runDirectoryPath,
                }),
                runLog: createRunLog(runDirectoryPath),
            });
            const guardedWidths = invocations
                .filter(
                    (invocation) =>
                        invocation.command === 'test-process-memory-guard' &&
                        invocation.env?.SEALED_LATTICE_PROOF_STORAGE_WIDTH !==
                            undefined,
                )
                .map(
                    (invocation) =>
                        invocation.env?.['SEALED_LATTICE_PROOF_STORAGE_WIDTH'],
                );
            const staticPreflightInvocationIndex = invocations.findIndex(
                (invocation) =>
                    invocation.env?.[
                        'SEALED_LATTICE_PROOF_STORAGE_WIDTH_STATIC_PREFLIGHT_RESULT_PATH'
                    ] !== undefined,
            );
            const firstWidthInvocationIndex = invocations.findIndex(
                (invocation) =>
                    invocation.env?.SEALED_LATTICE_PROOF_STORAGE_WIDTH !==
                    undefined,
            );
            expect(staticPreflightInvocationIndex).toBeGreaterThanOrEqual(0);
            expect(firstWidthInvocationIndex).toBeGreaterThan(
                staticPreflightInvocationIndex,
            );
            expect(guardedWidths).toEqual([
                '8',
                '32',
                '128',
                '512',
                '1024',
                '2048',
                '3451',
            ]);
            expect(result.decision.outcome).toBe('full-width-complete');
            const evidence = JSON.parse(
                await readFile(result.attachmentPath, 'utf8'),
            ) as {
                readonly formatVersion: number;
                readonly manifestIdentityShake256Hex: string;
                readonly manifestSha256Hex: string;
                readonly mandatoryPreflight: {
                    readonly evidenceSha256Hex: string;
                    readonly repositoryCommitHash: string;
                };
                readonly officialSampleReservation: {
                    readonly identitySha256Hex: string;
                    readonly officialOwner: string;
                    readonly schemaVersion: number;
                };
                readonly points: readonly unknown[];
                readonly repository: Record<string, RepositoryState>;
                readonly sampleArtifacts: readonly {
                    readonly guardSha256Hex: string;
                    readonly reservationPath: string;
                    readonly reservationSha256Hex: string;
                    readonly repositoryAfter: RepositoryState;
                    readonly repositoryBefore: RepositoryState;
                    readonly resultSha256Hex: string;
                }[];
                readonly staticPreflight: {
                    readonly attachmentPath: string;
                    readonly evidenceSha256Hex: string;
                    readonly guardSha256Hex: string;
                };
            };
            expect(evidence.manifestIdentityShake256Hex).toMatch(
                /^[0-9a-f]{128}$/u,
            );
            expect(evidence.formatVersion).toBe(3);
            expect(evidence.manifestSha256Hex).toMatch(/^[0-9a-f]{64}$/u);
            expect(evidence.mandatoryPreflight.evidenceSha256Hex).toMatch(
                /^[0-9a-f]{64}$/u,
            );
            expect(evidence.mandatoryPreflight.repositoryCommitHash).toBe(
                commitHash,
            );
            expect(evidence.points).toHaveLength(7);
            expect(evidence.sampleArtifacts).toHaveLength(7);
            expect(evidence.officialSampleReservation).toMatchObject({
                officialOwner: proofStorageWidthMeasurementTestName,
                schemaVersion: 1,
            });
            expect(
                evidence.officialSampleReservation.identitySha256Hex,
            ).toMatch(/^[0-9a-f]{64}$/u);
            expect(
                evidence.sampleArtifacts.every(
                    ({
                        guardSha256Hex,
                        reservationPath,
                        reservationSha256Hex,
                        repositoryAfter,
                        repositoryBefore,
                        resultSha256Hex,
                    }) =>
                        /^[0-9a-f]{64}$/u.test(guardSha256Hex) &&
                        /^[0-9a-f]{64}$/u.test(reservationSha256Hex) &&
                        reservationPath.startsWith('native/') &&
                        /^[0-9a-f]{64}$/u.test(resultSha256Hex) &&
                        repositoryAfter.commitHash === commitHash &&
                        repositoryAfter.treeDirty === false &&
                        repositoryBefore.commitHash === commitHash &&
                        repositoryBefore.treeDirty === false,
                ),
            ).toBe(true);
            expect(evidence.staticPreflight.attachmentPath).toMatch(
                /proof-storage-width-static-preflight\.json$/u,
            );
            expect(evidence.staticPreflight.evidenceSha256Hex).toMatch(
                /^[0-9a-f]{64}$/u,
            );
            expect(evidence.staticPreflight.guardSha256Hex).toMatch(
                /^[0-9a-f]{64}$/u,
            );
            expect(evidence.repository).toEqual({
                after: { commitHash, treeDirty: false },
                before: { commitHash, treeDirty: false },
                initial: { commitHash, treeDirty: false },
            });
            const attachmentNames = await readdir(
                path.join(
                    runDirectoryPath,
                    'attachments',
                    'proof-storage-width',
                ),
            );
            expect(
                attachmentNames.filter((name) =>
                    name.startsWith('progress-after-width-'),
                ),
            ).toHaveLength(7);
            expect(
                await readdir(
                    path.join(
                        runDirectoryPath,
                        'attachments',
                        'proof-storage-width',
                        'samples',
                    ),
                ),
            ).toHaveLength(7);
            const manifestEnvelope = JSON.parse(
                await readFile(
                    path.join(
                        runDirectoryPath,
                        'attachments',
                        'proof-storage-width',
                        'proof-storage-width-manifest.json',
                    ),
                    'utf8',
                ),
            ) as {
                readonly manifest: {
                    readonly absoluteCapTable: {
                        readonly applicableAbsoluteCaps: readonly {
                            readonly cap: string;
                            readonly enforcedBy: readonly string[];
                        }[];
                        readonly identifier: string;
                        readonly identityShake256Hex: string;
                    };
                    readonly absoluteCaps: Readonly<Record<string, string>>;
                    readonly backendProfile: {
                        readonly backend: string;
                        readonly identifier: string;
                    };
                    readonly custodySchema: {
                        readonly identifier: string;
                        readonly version: number;
                    };
                    readonly deterministicPublicColumnInput: {
                        readonly algorithm: string;
                        readonly domain: string;
                        readonly frozenInputIdentityHashDomain: string;
                        readonly frozenInputIdentityShake256Hex: string;
                        readonly frozenInputRecipeIdentifier: string;
                        readonly ordering: string;
                        readonly seedHex: string;
                        readonly widthInputIdentityHashDomain: string;
                    };
                    readonly intendedReleaseProfile: {
                        readonly identifier: string;
                        readonly representativeBrowserWidth: number;
                        readonly runtime: string;
                    };
                    readonly measurementProfile: {
                        readonly runtime: string;
                    };
                    readonly queryDependentMeasurementBoundary: Readonly<
                        Record<string, boolean>
                    >;
                    readonly staticPreflight: {
                        readonly evidenceSha256Hex: string;
                        readonly points: readonly unknown[];
                    };
                };
            };
            expect(manifestEnvelope.manifest.absoluteCaps).toEqual({
                maximumCommonProofByteLength: '268435456',
                maximumCopiedBufferByteLength: '8388608',
                maximumLocalRecordSealInvocationCount: '1073741824',
                maximumLocalRecordSealedPlaintextByteLength: '1099511627776',
                maximumPhysicalObjectCount: '4096',
                maximumStoredScratchByteLength: '1073741824',
                maximumTransportByteLength: '4294967291',
                maximumWasmMemoryByteLength: '671088640',
            });
            expect(manifestEnvelope.manifest.absoluteCapTable.identifier).toBe(
                'sealed-lattice/absolute-resource-caps/v1',
            );
            expect(
                manifestEnvelope.manifest.absoluteCapTable.identityShake256Hex,
            ).toMatch(/^[0-9a-f]{128}$/u);
            expect(
                manifestEnvelope.manifest.absoluteCapTable.applicableAbsoluteCaps.map(
                    ({ cap }) => cap,
                ),
            ).toEqual(
                expect.arrayContaining([
                    'copied-buffer-byte-length',
                    'wasm-memory-byte-length',
                ]),
            );
            expect(
                manifestEnvelope.manifest.absoluteCapTable
                    .applicableAbsoluteCaps,
            ).toHaveLength(8);
            expect(manifestEnvelope.manifest.backendProfile.identifier).toBe(
                proofStorageWidthProfile.backendProfileIdentifier,
            );
            expect(manifestEnvelope.manifest.backendProfile.backend).toBe(
                proofStorageWidthProfile.backend,
            );
            expect(manifestEnvelope.manifest.custodySchema).toMatchObject({
                identifier: proofStorageWidthProfile.custodySchemaIdentifier,
                version: 1,
            });
            expect(
                manifestEnvelope.manifest.deterministicPublicColumnInput,
            ).toEqual({
                algorithm:
                    proofStorageWidthProfile.publicColumnDerivationAlgorithm,
                domain: proofStorageWidthProfile.publicColumnInputDomain,
                frozenInputIdentityHashDomain:
                    proofStorageWidthProfile.frozenInputIdentityHashDomain,
                frozenInputIdentityShake256Hex:
                    proofStorageWidthProfile.frozenInputIdentityShake256Hex,
                frozenInputRecipeIdentifier:
                    proofStorageWidthProfile.frozenInputRecipeIdentifier,
                ordering: 'column-major-row-major-canonical-le-u64',
                seedHex: proofStorageWidthProfile.publicColumnSeedHex,
                widthInputIdentityHashDomain:
                    proofStorageWidthProfile.widthInputIdentityHashDomain,
            });
            expect(
                manifestEnvelope.manifest.intendedReleaseProfile,
            ).toMatchObject({
                identifier: proofStorageWidthProfile.releaseProfileIdentifier,
                representativeBrowserWidth: 512,
                runtime: 'desktop-browser-wasm',
            });
            expect(manifestEnvelope.manifest.measurementProfile).toEqual({
                cargoProfile: 'release',
                conservativeLayoutParameters: {
                    btreeEntryStorageMultiplier: '16',
                    heapAllocationOverheadByteLength: '64',
                    proofTreeCount: '7',
                    queryRepresentativeCount: '183',
                },
                native64LayoutByteLengths: {
                    authenticatedMapEntry: '56',
                    authenticatedTreeOpeningHeader: '32',
                    btreeMapHeader: '24',
                    nativeCustodyPathHeader: '32',
                    proofChallengeExtensionElement: '40',
                    proofTreeValue: '48',
                    vectorHeader: '24',
                },
                runtime: 'native-rust',
            });
            expect(
                manifestEnvelope.manifest.queryDependentMeasurementBoundary,
            ).toEqual({
                actualRootBoundQueryLayoutRunsOnlyInOfficialWidthSample: true,
                duplicateWidthWorkloadProhibited: true,
                frozenQueryVectorProhibited: true,
                paddedCanonicalProofProhibited: true,
                staticGateUsesConservativeCanonicalCeilings: true,
                totalProofAffineProjectionProhibited: true,
            });
            expect(
                manifestEnvelope.manifest.staticPreflight.points,
            ).toHaveLength(7);
            expect(
                manifestEnvelope.manifest.staticPreflight.evidenceSha256Hex,
            ).toBe(evidence.staticPreflight.evidenceSha256Hex);
        }));

    it('durably refuses a second observed width attempt for the same canonical key', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const reservationRootPath =
                officialReservationRootPathForRun(runDirectoryPath);
            await executeProofStorageWidthEvidenceSequence({
                dependencies: createSequenceDependencies({
                    invocations: [],
                    runDirectoryPath,
                }),
                runLog: createRunLog(runDirectoryPath),
            });

            const secondRunDirectoryPath = path.join(
                path.dirname(runDirectoryPath),
                'second-run',
            );
            await mkdir(secondRunDirectoryPath);
            const secondRunInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthEvidenceSequence({
                    dependencies: createSequenceDependencies({
                        invocations: secondRunInvocations,
                        runDirectoryPath: secondRunDirectoryPath,
                    }),
                    runLog: createRunLog(secondRunDirectoryPath),
                }),
            ).rejects.toThrow(/already has a durable started reservation/u);
            expect(
                secondRunInvocations.filter(
                    (invocation) =>
                        invocation.env?.SEALED_LATTICE_PROOF_STORAGE_WIDTH !==
                        undefined,
                ),
            ).toHaveLength(0);

            const reservationIdentity =
                buildProofStorageWidthNativeReservationIdentity({
                    memoryLimitBytes:
                        createProcessMemoryGuard().memoryLimitBytes,
                    officialOwner: proofStorageWidthMeasurementTestName,
                    sourceCommitHash: commitHash,
                });
            const widthEightReservationPath = path.join(
                reservationRootPath,
                'native',
                reservationIdentity.identitySha256Hex,
                'width-1-started.json',
            );
            const reservationRecords = (
                await readFile(widthEightReservationPath, 'utf8')
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(reservationRecords).toHaveLength(2);
            expect(reservationRecords[0]).toMatchObject({
                eventType: 'official-native-width-sample-started',
                identitySha256Hex: reservationIdentity.identitySha256Hex,
                scheduleOrdinal: 1,
                sourceCommitHash: commitHash,
                width: 8,
            });
            expect(reservationRecords[1]).toMatchObject({
                eventType: 'official-sample-outcome',
                outcome: 'validated',
            });
        }));

    it('reopens every bound artifact and refuses tampering, artifact mix-up, and self-asserted decisions', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const result = await executeProofStorageWidthEvidenceSequence({
                dependencies: createSequenceDependencies({
                    invocations: [],
                    runDirectoryPath,
                }),
                runLog: createRunLog(runDirectoryPath),
            });
            await expect(
                validateProofStorageWidthEvidenceArtifacts(
                    result.attachmentPath,
                    {
                        officialReservationRootPath:
                            officialReservationRootPathForRun(runDirectoryPath),
                    },
                ),
            ).resolves.toMatchObject({
                fullWidthPoint: {
                    result: { publicBaseLeafColumnCount: 3_451 },
                },
                repositoryCommitHash: commitHash,
            });
            const loadedNativeEvidence = await loadNativeWidthEvidence(
                result.attachmentPath,
                {
                    officialReservationRootPath:
                        officialReservationRootPathForRun(runDirectoryPath),
                },
            );
            expect(
                loadedNativeEvidence.representativeStaticPoint
                    .publicBaseLeafColumnCount,
            ).toBe(512);
            expect(
                loadedNativeEvidence.fullWidthStaticPoint
                    .publicBaseLeafColumnCount,
            ).toBe(3_451);
            expect(
                loadedNativeEvidence.fullWidthStaticPoint
                    .wasmMemoryByteLengthCeiling,
            ).toBeGreaterThan(
                loadedNativeEvidence.representativeStaticPoint
                    .wasmMemoryByteLengthCeiling,
            );
            const originalAggregateEvidence = await readFile(
                result.attachmentPath,
                'utf8',
            );
            const evidence = JSON.parse(
                originalAggregateEvidence,
            ) as MutableAggregateEvidence;
            const preflightEvidence = JSON.parse(
                await readFile(
                    path.resolve(
                        runDirectoryPath,
                        evidence.mandatoryPreflight.attachmentPath,
                    ),
                    'utf8',
                ),
            ) as {
                readonly completedFeatureTestPhase: {
                    readonly diagnosticsPath: string;
                };
                readonly completedTests: readonly {
                    readonly diagnosticsPath: string;
                }[];
            };
            const boundArtifactRelativePaths = [
                evidence.manifestPath,
                evidence.mandatoryPreflight.attachmentPath,
                evidence.staticPreflight.attachmentPath,
                evidence.staticPreflight.guardPath,
                preflightEvidence.completedFeatureTestPhase.diagnosticsPath,
                ...preflightEvidence.completedTests.map(
                    (completedTest) => completedTest.diagnosticsPath,
                ),
                ...evidence.sampleArtifacts.flatMap((artifact) => [
                    artifact.resultPath,
                    artifact.guardPath,
                ]),
            ];
            expect(boundArtifactRelativePaths).toHaveLength(22);
            for (const relativeArtifactPath of boundArtifactRelativePaths) {
                const artifactPath = path.resolve(
                    runDirectoryPath,
                    relativeArtifactPath,
                );
                const originalArtifact = await readFile(artifactPath, 'utf8');
                try {
                    await writeFile(
                        artifactPath,
                        `${originalArtifact} `,
                        'utf8',
                    );
                    await expect(
                        validateProofStorageWidthEvidenceArtifacts(
                            result.attachmentPath,
                            {
                                officialReservationRootPath:
                                    officialReservationRootPathForRun(
                                        runDirectoryPath,
                                    ),
                            },
                        ),
                    ).rejects.toThrow(/SHA-256 digest/u);
                } finally {
                    await writeFile(artifactPath, originalArtifact, 'utf8');
                }
            }
            const reservationRootPath =
                officialReservationRootPathForRun(runDirectoryPath);
            const boundReservationRelativePaths = evidence.sampleArtifacts.map(
                (artifact) => artifact.reservationPath,
            );
            expect(boundReservationRelativePaths).toHaveLength(7);
            for (const relativeReservationPath of boundReservationRelativePaths) {
                const reservationPath = path.resolve(
                    reservationRootPath,
                    relativeReservationPath,
                );
                const originalReservation = await readFile(
                    reservationPath,
                    'utf8',
                );
                try {
                    await writeFile(
                        reservationPath,
                        `${originalReservation} `,
                        'utf8',
                    );
                    await expect(
                        validateProofStorageWidthEvidenceArtifacts(
                            result.attachmentPath,
                            {
                                officialReservationRootPath:
                                    reservationRootPath,
                            },
                        ),
                    ).rejects.toThrow(/SHA-256 digest/u);
                } finally {
                    await writeFile(
                        reservationPath,
                        originalReservation,
                        'utf8',
                    );
                }
            }

            const memoryLimitMutationEvidence = JSON.parse(
                originalAggregateEvidence,
            ) as MutableAggregateEvidence;
            const memoryLimitMutationSample =
                memoryLimitMutationEvidence.sampleArtifacts[0];
            if (memoryLimitMutationSample === undefined) {
                throw new Error('Aggregate test fixture omitted width 8.');
            }
            const memoryLimitMutationGuardPath = path.resolve(
                runDirectoryPath,
                memoryLimitMutationSample.guardPath,
            );
            const originalMemoryLimitGuard = await readFile(
                memoryLimitMutationGuardPath,
                'utf8',
            );
            const mutatedMemoryLimitGuard = originalMemoryLimitGuard.replace(
                `"memoryLimitBytes":${testMemoryLimitBytes}`,
                `"memoryLimitBytes":${testMemoryLimitBytes - 1}`,
            );
            expect(mutatedMemoryLimitGuard).not.toBe(originalMemoryLimitGuard);
            memoryLimitMutationSample.guardSha256Hex = createHash('sha256')
                .update(mutatedMemoryLimitGuard)
                .digest('hex');
            try {
                await Promise.all([
                    writeFile(
                        memoryLimitMutationGuardPath,
                        mutatedMemoryLimitGuard,
                        'utf8',
                    ),
                    writeFile(
                        result.attachmentPath,
                        `${JSON.stringify(memoryLimitMutationEvidence, null, 2)}\n`,
                        'utf8',
                    ),
                ]);
                await expect(
                    validateProofStorageWidthEvidenceArtifacts(
                        result.attachmentPath,
                        { officialReservationRootPath: reservationRootPath },
                    ),
                ).rejects.toThrow(/expected memory limit/u);
            } finally {
                await Promise.all([
                    writeFile(
                        memoryLimitMutationGuardPath,
                        originalMemoryLimitGuard,
                        'utf8',
                    ),
                    writeFile(
                        result.attachmentPath,
                        originalAggregateEvidence,
                        'utf8',
                    ),
                ]);
            }

            const mixedEvidence = JSON.parse(
                originalAggregateEvidence,
            ) as MutableAggregateEvidence;
            const firstSample = mixedEvidence.sampleArtifacts[0];
            const secondSample = mixedEvidence.sampleArtifacts[1];
            if (firstSample === undefined || secondSample === undefined) {
                throw new Error(
                    'Aggregate test fixture omitted sample bindings.',
                );
            }
            firstSample.resultPath = secondSample.resultPath;
            try {
                await writeFile(
                    result.attachmentPath,
                    `${JSON.stringify(mixedEvidence, null, 2)}\n`,
                    'utf8',
                );
                await expect(
                    validateProofStorageWidthEvidenceArtifacts(
                        result.attachmentPath,
                        {
                            officialReservationRootPath:
                                officialReservationRootPathForRun(
                                    runDirectoryPath,
                                ),
                        },
                    ),
                ).rejects.toThrow(
                    /sampleArtifacts\[0\]\.resultPath must be the exact/u,
                );
            } finally {
                await writeFile(
                    result.attachmentPath,
                    originalAggregateEvidence,
                    'utf8',
                );
            }

            const selfAssertedDecisionEvidence = JSON.parse(
                originalAggregateEvidence,
            ) as MutableAggregateEvidence;
            selfAssertedDecisionEvidence.decision = {
                ...selfAssertedDecisionEvidence.decision,
                outcome: 'continue',
            };
            try {
                await writeFile(
                    result.attachmentPath,
                    `${JSON.stringify(selfAssertedDecisionEvidence, null, 2)}\n`,
                    'utf8',
                );
                await expect(
                    validateProofStorageWidthEvidenceArtifacts(
                        result.attachmentPath,
                        {
                            officialReservationRootPath:
                                officialReservationRootPathForRun(
                                    runDirectoryPath,
                                ),
                        },
                    ),
                ).rejects.toThrow(/self-asserted/u);
            } finally {
                await writeFile(
                    result.attachmentPath,
                    originalAggregateEvidence,
                    'utf8',
                );
            }

            const originalFirstSample = evidence.sampleArtifacts[0];
            if (originalFirstSample === undefined) {
                throw new Error('Aggregate test fixture omitted width 8.');
            }
            const originalFirstResultPath = path.resolve(
                runDirectoryPath,
                originalFirstSample.resultPath,
            );
            const originalFirstResult = await readFile(
                originalFirstResultPath,
                'utf8',
            );
            const expectReboundRawMutationRefused = async (input: {
                readonly expectedError: RegExp;
                readonly mutate: (record: Record<string, unknown>) => void;
            }): Promise<void> => {
                const rawResult = JSON.parse(originalFirstResult) as Record<
                    string,
                    unknown
                >;
                input.mutate(rawResult);
                const mutatedRawResult = `${JSON.stringify(rawResult, null, 2)}\n`;
                const reboundEvidence = JSON.parse(
                    originalAggregateEvidence,
                ) as MutableAggregateEvidence;
                const reboundFirstSample = reboundEvidence.sampleArtifacts[0];
                if (reboundFirstSample === undefined) {
                    throw new Error('Aggregate test fixture omitted width 8.');
                }
                reboundFirstSample.resultSha256Hex = createHash('sha256')
                    .update(mutatedRawResult)
                    .digest('hex');
                try {
                    await Promise.all([
                        writeFile(
                            originalFirstResultPath,
                            mutatedRawResult,
                            'utf8',
                        ),
                        writeFile(
                            result.attachmentPath,
                            `${JSON.stringify(reboundEvidence, null, 2)}\n`,
                            'utf8',
                        ),
                    ]);
                    await expect(
                        validateProofStorageWidthEvidenceArtifacts(
                            result.attachmentPath,
                            {
                                officialReservationRootPath:
                                    officialReservationRootPathForRun(
                                        runDirectoryPath,
                                    ),
                            },
                        ),
                    ).rejects.toThrow(input.expectedError);
                } finally {
                    await Promise.all([
                        writeFile(
                            originalFirstResultPath,
                            originalFirstResult,
                            'utf8',
                        ),
                        writeFile(
                            result.attachmentPath,
                            originalAggregateEvidence,
                            'utf8',
                        ),
                    ]);
                }
            };
            await expectReboundRawMutationRefused({
                expectedError: /input identity.*static core-and-recipe/u,
                mutate: (rawResult) => {
                    rawResult.inputIdentityShake256Hex = 'ff'.repeat(64);
                },
            });
            await expectReboundRawMutationRefused({
                expectedError: /exactCandidate\.materialRadix/u,
                mutate: (rawResult) => {
                    rawResult.exactCandidate = {
                        ...(rawResult.exactCandidate as Record<
                            string,
                            unknown
                        >),
                        materialRadix: 129_140_164,
                    };
                },
            });
        }));

    it('stops at the first cap or superlinear result without replacement or later widths', async () => {
        for (const [
            dependenciesInput,
            expectedPattern,
            expectedWidths,
            writesAggregateEvidence,
        ] of [
            [
                { capFailureWidth: 128 as const },
                /physicalObjectPeakDecimal must be 129/u,
                ['8', '32', '128'],
                false,
            ],
            [
                { superlinearWidth: 128 as const },
                /unexplained superlinear scaling/u,
                ['8', '32', '128'],
                true,
            ],
        ] as const) {
            await withTemporaryDirectory(async (runDirectoryPath) => {
                const invocations: CommandInvocation[] = [];
                await expect(
                    executeProofStorageWidthEvidenceSequence({
                        dependencies: createSequenceDependencies({
                            ...dependenciesInput,
                            invocations,
                            runDirectoryPath,
                        }),
                        runLog: createRunLog(runDirectoryPath),
                    }),
                ).rejects.toThrow(expectedPattern);
                expect(
                    invocations
                        .filter(
                            (invocation) =>
                                invocation.command ===
                                    'test-process-memory-guard' &&
                                invocation.env
                                    ?.SEALED_LATTICE_PROOF_STORAGE_WIDTH !==
                                    undefined,
                        )
                        .map(
                            (invocation) =>
                                invocation.env?.[
                                    'SEALED_LATTICE_PROOF_STORAGE_WIDTH'
                                ],
                        ),
                ).toEqual(expectedWidths);
                const aggregateEvidencePath = path.join(
                    runDirectoryPath,
                    'attachments',
                    'proof-storage-width',
                    'proof-storage-width-evidence.json',
                );
                const serializedAggregateEvidence = await readFile(
                    aggregateEvidencePath,
                    'utf8',
                ).catch((error: unknown) => {
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
                const aggregatePointCount =
                    serializedAggregateEvidence === undefined
                        ? undefined
                        : (
                              JSON.parse(serializedAggregateEvidence) as {
                                  readonly points: readonly unknown[];
                              }
                          ).points.length;
                expect(aggregatePointCount).toBe(
                    writesAggregateEvidence ? 3 : undefined,
                );
                const officialReservationRootPath =
                    officialReservationRootPathForRun(runDirectoryPath);
                const validatedObservedEvidence =
                    serializedAggregateEvidence === undefined
                        ? undefined
                        : await validateProofStorageWidthObservedEvidenceArtifacts(
                              aggregateEvidencePath,
                              { officialReservationRootPath },
                          );
                const fullWidthValidationError =
                    serializedAggregateEvidence === undefined
                        ? undefined
                        : await validateProofStorageWidthEvidenceArtifacts(
                              aggregateEvidencePath,
                              { officialReservationRootPath },
                          ).then(
                              () => undefined,
                              (error: unknown) => error,
                          );
                expect(validatedObservedEvidence?.points.length).toBe(
                    writesAggregateEvidence ? 3 : undefined,
                );
                expect(validatedObservedEvidence?.decision.outcome).toBe(
                    writesAggregateEvidence
                        ? 'unexplained-superlinear-scaling'
                        : undefined,
                );
                expect(
                    fullWidthValidationError instanceof Error
                        ? fullWidthValidationError.message
                        : undefined,
                ).toBe(
                    writesAggregateEvidence
                        ? 'Recomputed proof-storage width decision is unexplained-superlinear-scaling; serialized full-width eligibility is refused.'
                        : undefined,
                );
            });
        }
    });

    it('refuses dirty or changed source and missing baseline without retrying a width', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const dirtyInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthEvidenceSequence({
                    dependencies: createSequenceDependencies({
                        invocations: dirtyInvocations,
                        repositoryStates: [{ commitHash, treeDirty: true }],
                        runDirectoryPath,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/clean repository tree/u);
            expect(dirtyInvocations).toHaveLength(0);

            const missingBaselineInvocations: CommandInvocation[] = [];
            const missingBaselineRunDirectoryPath = path.join(
                runDirectoryPath,
                'missing-baseline',
                'run',
            );
            await expect(
                executeProofStorageWidthEvidenceSequence({
                    dependencies: createSequenceDependencies({
                        includeBaseline: false,
                        invocations: missingBaselineInvocations,
                        runDirectoryPath: missingBaselineRunDirectoryPath,
                    }),
                    runLog: createRunLog(missingBaselineRunDirectoryPath),
                }),
            ).rejects.toThrow(/pre-operation resident baseline/u);
            expect(
                missingBaselineInvocations.filter(
                    (invocation) =>
                        invocation.command === 'test-process-memory-guard' &&
                        invocation.env?.SEALED_LATTICE_PROOF_STORAGE_WIDTH !==
                            undefined,
                ),
            ).toHaveLength(1);

            const changedCommitHash = 'bc'.repeat(20);
            const changedCommitRunDirectoryPath = path.join(
                runDirectoryPath,
                'changed-commit',
                'run',
            );
            const changedCommitInvocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthEvidenceSequence({
                    dependencies: createSequenceDependencies({
                        invocations: changedCommitInvocations,
                        repositoryStates: [
                            ...Array.from({ length: 6 }, () => ({
                                commitHash,
                                treeDirty: false,
                            })),
                            {
                                commitHash: changedCommitHash,
                                treeDirty: false,
                            },
                        ],
                        runDirectoryPath: changedCommitRunDirectoryPath,
                    }),
                    runLog: createRunLog(changedCommitRunDirectoryPath),
                }),
            ).rejects.toThrow(/state could not be pinned after.*width 8/u);
            expect(
                changedCommitInvocations.filter(
                    (invocation) =>
                        invocation.env?.SEALED_LATTICE_PROOF_STORAGE_WIDTH !==
                        undefined,
                ),
            ).toHaveLength(1);

            const changedCommitReservationIdentity =
                buildProofStorageWidthNativeReservationIdentity({
                    memoryLimitBytes:
                        createProcessMemoryGuard().memoryLimitBytes,
                    officialOwner: proofStorageWidthMeasurementTestName,
                    sourceCommitHash: commitHash,
                });
            const changedCommitReservationPath = path.join(
                officialReservationRootPathForRun(
                    changedCommitRunDirectoryPath,
                ),
                'native',
                changedCommitReservationIdentity.identitySha256Hex,
                'width-1-started.json',
            );
            const changedCommitReservationRecords = (
                await readFile(changedCommitReservationPath, 'utf8')
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(changedCommitReservationRecords).toHaveLength(2);
            expect(changedCommitReservationRecords[1]).toMatchObject({
                eventType: 'official-sample-outcome',
                outcome: 'failed',
            });
        }));

    it('does not start width 8 when the mandatory non-ignored feature phase fails', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthEvidenceSequence({
                    dependencies: createSequenceDependencies({
                        failPreflightFeaturePhase: true,
                        invocations,
                        runDirectoryPath,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/non-ignored feature tests.*failed/u);
            expect(
                invocations.filter(
                    (invocation) =>
                        invocation.env?.SEALED_LATTICE_PROOF_STORAGE_WIDTH !==
                        undefined,
                ),
            ).toHaveLength(0);
            await expect(
                access(officialReservationRootPathForRun(runDirectoryPath)),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        }));

    it('does not start width 8 when the width-specific static gate fails', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthEvidenceSequence({
                    dependencies: createSequenceDependencies({
                        failWidthStaticPreflightPhase: true,
                        invocations,
                        runDirectoryPath,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/non-ignored static feature tests failed/u);
            expect(
                invocations.filter(
                    (invocation) =>
                        invocation.env?.SEALED_LATTICE_PROOF_STORAGE_WIDTH !==
                        undefined,
                ),
            ).toHaveLength(0);
            await expect(
                access(officialReservationRootPathForRun(runDirectoryPath)),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        }));

    it('validates the complete width-static guard lifecycle before manifest creation or width 8', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofStorageWidthEvidenceSequence({
                    dependencies: createSequenceDependencies({
                        invalidWidthStaticPreflightGuardTelemetry: true,
                        invocations,
                        runDirectoryPath,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/sampling error/u);
            expect(
                invocations.filter(
                    (invocation) =>
                        invocation.env?.SEALED_LATTICE_PROOF_STORAGE_WIDTH !==
                        undefined,
                ),
            ).toHaveLength(0);
            await expect(
                access(officialReservationRootPathForRun(runDirectoryPath)),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            await expect(
                access(
                    path.join(
                        runDirectoryPath,
                        'attachments',
                        'proof-storage-width',
                        'proof-storage-width-manifest.json',
                    ),
                ),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        }));

    it('preserves a postwrite failure together with the final repository-check failure', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            const repositoryCheckpoints: string[] = [];
            const baseDependencies = createSequenceDependencies({
                invocations,
                repositoryCheckpoints,
                runDirectoryPath,
            });
            const baseReadRepositoryState =
                baseDependencies.readRepositoryState;
            if (baseReadRepositoryState === undefined) {
                throw new Error('Test repository-state reader is missing.');
            }
            const dependencies: ProofStorageWidthEvidenceRunnerDependencies = {
                ...baseDependencies,
                readRepositoryState: async (checkpoint, runLog) => {
                    const state = await baseReadRepositoryState(
                        checkpoint,
                        runLog,
                    );
                    return checkpoint === 'closure-after'
                        ? { ...state, treeDirty: true }
                        : state;
                },
            };
            let thrownError: unknown;
            try {
                await executeProofStorageWidthEvidenceSequence({
                    dependencies,
                    runLog: createRunLog(runDirectoryPath, (event) => {
                        if (
                            event.eventType ===
                            'proof-storage-width-point-validated'
                        ) {
                            throw new Error(
                                'Injected postwrite serialization failure.',
                            );
                        }
                    }),
                });
            } catch (error) {
                thrownError = error;
            }
            expect(thrownError).toBeInstanceOf(Error);
            expect((thrownError as Error).message).toMatch(
                /attempt failed.*closure check also failed/u,
            );
            expect(
                (thrownError as { readonly attemptCause?: unknown })
                    .attemptCause,
            ).toMatchObject({
                message: 'Injected postwrite serialization failure.',
            });
            const closureRepositoryCause = (
                thrownError as { readonly cause?: unknown }
            ).cause;
            expect(closureRepositoryCause).toBeInstanceOf(Error);
            expect((closureRepositoryCause as Error).message).toMatch(
                /clean repository tree/u,
            );
            expect(
                repositoryCheckpoints[repositoryCheckpoints.length - 1],
            ).toBe('closure-after');
        }));

    it('removes and refuses the one precommitted custody directory after a guard kill', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            const repositoryCheckpoints: string[] = [];
            let thrownError: unknown;
            try {
                await executeProofStorageWidthEvidenceSequence({
                    dependencies: createSequenceDependencies({
                        invocations,
                        leaveCustodyOnFailedWidth: 8,
                        repositoryCheckpoints,
                        runDirectoryPath,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                });
            } catch (error) {
                thrownError = error;
            }
            expect(thrownError).toBeInstanceOf(
                ProofStorageWidthLeftoverCustodyError,
            );
            const custodyError =
                thrownError as ProofStorageWidthLeftoverCustodyError;
            expect(custodyError.code).toBe(
                'PROOF_STORAGE_WIDTH_LEFTOVER_CUSTODY',
            );
            expect(custodyError.cleanupCompleted).toBe(true);
            expect(custodyError.originalCause).toBeInstanceOf(Error);
            if (!(custodyError.originalCause instanceof Error)) {
                throw new Error('Guard-kill cause lost its Error type.');
            }
            expect(custodyError.originalCause.message).toContain('SIGKILL');
            expect(custodyError.custodyPaths).toHaveLength(1);
            expect(repositoryCheckpoints).toContain('width-8-after');
            expect(
                repositoryCheckpoints[repositoryCheckpoints.length - 1],
            ).toBe('closure-after');
            const [custodyDirectoryPath] = custodyError.custodyPaths;
            expect(custodyDirectoryPath).toMatch(
                /\.width-0008-result\.json\.[0-9a-f-]+\.bounded-custody$/u,
            );
            await expect(
                access(custodyDirectoryPath ?? ''),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            expect(
                invocations
                    .filter(
                        (invocation) =>
                            invocation.command ===
                                'test-process-memory-guard' &&
                            invocation.env
                                ?.SEALED_LATTICE_PROOF_STORAGE_WIDTH !==
                                undefined,
                    )
                    .map(
                        (invocation) =>
                            invocation.env?.[
                                'SEALED_LATTICE_PROOF_STORAGE_WIDTH'
                            ],
                    ),
            ).toEqual(['8']);
        }));
});
