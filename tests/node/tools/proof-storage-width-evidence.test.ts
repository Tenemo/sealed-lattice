import { describe, expect, it } from 'vitest';

import {
    deriveProofStorageWidthExternalMemoryFramingGeometry,
    deriveProofStorageWidthGeometry,
    deriveProofStorageWidthNativeCustodyMetadataByteLengthCeiling,
    deriveProofStorageWidthOpeningWorkspaceGeometry,
    evaluateProofStorageWidthCurve,
    proofStorageWidthProfile,
    proofStorageWidthSchedule,
    validateProofStorageWidthPoint,
    validateProofStorageWidthResult,
    validateProofStorageWidthStaticPreflightResult,
    type ProofStorageWidth,
    type ValidatedProofStorageWidthPoint,
} from '#tools/ci/proof-storage-width-evidence';

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

const buildResult = (
    width: ProofStorageWidth,
    input: Readonly<{
        elapsedNanoseconds?: bigint;
        externalCommittedTransactionCount?: bigint;
        physicalObjectPeak?: bigint;
        storedScratchPeakByteLength?: bigint;
    }> = {},
): Readonly<Record<string, unknown>> => {
    const geometry = deriveProofStorageWidthGeometry(width);
    const canonicalArtifactByteLength =
        canonicalArtifactByteLengthForTest(width);
    const canonicalArtifactNonleafRangeChunkCount =
        canonicalArtifactNonleafRangeChunkCountForTest(width);
    const externalReadByteLength =
        6n * geometry.sourceReplayByteLength + canonicalArtifactByteLength;
    const externalWrittenByteLength =
        geometry.sourceReplayByteLength + canonicalArtifactByteLength;
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
            canonicalArtifactPreleafRangeChunkCountForTest(width).toString(),
        canonicalArtifactByteLengthDecimal:
            canonicalArtifactByteLength.toString(),
        custodyCleanupCompleted: true,
        elapsedNanosecondsDecimal: (
            input.elapsedNanoseconds ?? 1_000_000n + BigInt(width) * 1_000n
        ).toString(),
        exactCandidate: {
            firstDataModulus: 1_953_759_233,
            materialRadix: 129_140_163,
            plaintextModulus: 257,
            ringDimension: 32_768,
            rosterSize: 10,
        },
        externalCommittedTransactionCountDecimal: (
            input.externalCommittedTransactionCount ??
            24n * BigInt(width) +
                3n +
                2n *
                    (geometry.openedLeafRangeChunkCount +
                        canonicalArtifactNonleafRangeChunkCount)
        ).toString(),
        externalReadByteLengthDecimal: externalReadByteLength.toString(),
        externalWrittenByteLengthDecimal: externalWrittenByteLength.toString(),
        formatVersion: 1,
        inputIdentityShake256Hex: inputIdentityForTest(width),
        ldeTransformCountDecimal: geometry.ldeTransformCount.toString(),
        localRecordSealInvocationCountDecimal:
            geometry.localRecordSealInvocationCount.toString(),
        manifestIdentityShake256Hex: 'ab'.repeat(64),
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
        publicBaseLeafColumnCount: width,
        queriedLeafPayloadByteLengthDecimal:
            geometry.queriedLeafPayloadByteLength.toString(),
        recomputedCanonicalArtifactByteLengthDecimal:
            canonicalArtifactByteLength.toString(),
        sealedSecretPlaintextByteLengthDecimal: '0',
        sourceOpeningClaimCount: 9,
        sourceCommittedTransactionCountDecimal: (
            24n * BigInt(width)
        ).toString(),
        sourceObjectSealTransactionCountDecimal: BigInt(width).toString(),
        sourcePhysicalObjectCountDecimal: BigInt(width).toString(),
        sourceReplayByteLengthDecimal:
            geometry.sourceReplayByteLength.toString(),
        storedScratchPeakByteLengthDecimal: (
            input.storedScratchPeakByteLength ??
            geometry.sourceReplayByteLength + canonicalArtifactByteLength
        ).toString(),
        widthDependentQueriedBaseOpeningByteLengthDecimal:
            geometry.widthDependentQueriedBaseOpeningByteLength.toString(),
        width,
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

const buildGuardJsonLines = (peakResidentByteLength = 200_000_000): string =>
    [
        {
            aggregateProcessTreeMemoryLimit: true,
            elapsedMilliseconds: 0,
            eventType: 'guard-started',
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
        {
            confirmedMemoryLimitViolation: false,
            elapsedMilliseconds: 200,
            eventType: 'resource-sample',
            processTreeResidentMemoryBytes: 100_000_000,
            recordedAtUnixMilliseconds: 900,
            sampleError: null,
            sequence: 2,
        },
        {
            confirmedMemoryLimitViolation: false,
            elapsedMilliseconds: 400,
            eventType: 'resource-sample',
            processTreeResidentMemoryBytes: peakResidentByteLength,
            recordedAtUnixMilliseconds: 1_100,
            sampleError: null,
            sequence: 3,
        },
        {
            confirmedMemoryLimitViolation: false,
            elapsedMilliseconds: 600,
            eventType: 'resource-sample',
            processTreeResidentMemoryBytes: 150_000_000,
            recordedAtUnixMilliseconds: 1_300,
            sampleError: null,
            sequence: 4,
        },
        {
            elapsedMilliseconds: 700,
            eventType: 'child-exited',
            exitCode: 0,
            memoryEvidence: 'completed',
            recordedAtUnixMilliseconds: 1_400,
            sequence: 5,
            terminationClassification: 'completed',
        },
    ]
        .map((record) => JSON.stringify(record))
        .join('\n');

const buildPoint = (
    scheduleIndex: number,
    input: Parameters<typeof buildResult>[1] = {},
): ValidatedProofStorageWidthPoint => {
    const width = proofStorageWidthSchedule[scheduleIndex];
    if (width === undefined) {
        throw new Error('Test schedule index is outside the width schedule.');
    }
    return validateProofStorageWidthPoint({
        expectedScheduleOrdinal: scheduleIndex + 1,
        guardJsonLines: buildGuardJsonLines(),
        result: buildResult(width, input),
    });
};

describe('Proof-storage width evidence', () => {
    it('derives distinct payload, encoded-copy, and simultaneous boundary ceilings', () => {
        expect(deriveProofStorageWidthExternalMemoryFramingGeometry()).toEqual({
            appendResponseDecodeWorkspaceByteLengthCeiling: 345_704n,
            appendRequestByteLengthCeiling: 49_340n,
            boundaryTransferLiveByteLengthCeiling: 49_508n,
            copiedBufferByteLengthCeiling: 49_340n,
            emptyResponseByteLength: 80n,
            rawAbiRequestCopyWorkspaceByteLengthCeiling: 345_680n,
            rawAbiResponseDecodeWorkspaceByteLengthCeiling: 345_704n,
            rawAbiTransferWorkspaceByteLengthCeiling: 345_704n,
            readRequestByteLength: 188n,
            readResponseDecodeWorkspaceByteLengthCeiling: 345_704n,
            readResponseByteLengthCeiling: 49_320n,
        });
        expect(proofStorageWidthProfile.externalMemoryChunkByteLength).toBe(
            49_152n,
        );
        const firstPoint = validateProofStorageWidthStaticPreflightResult(
            buildStaticPreflightResult(),
        ).points[0];
        expect(firstPoint).toMatchObject({
            boundaryTransferByteLengthCeiling: 49_508n,
            browserOperationRegistryByteLengthCeiling: 64_552n,
            copiedBufferByteLengthCeiling: 49_340n,
            maximumTransactionPayloadByteLength: 49_152n,
        });
    });

    it('derives every precommitted width and the full-width static geometry exactly', () => {
        expect(proofStorageWidthSchedule).toEqual([
            8, 32, 128, 512, 1_024, 2_048, 3_451,
        ]);
        expect(deriveProofStorageWidthGeometry(3_451)).toMatchObject({
            absorbedLeafValueCount: 1_356_988_416n,
            ldeTransformCount: 20_706n,
            legacyBaseLeafObjectByteLength: 3_626_762_240n,
            openedLeafRangeChunkCount: 366n,
            openedValueCount: 1_263_066n,
            publicBaseLeafByteLength: 55_340n,
            queriedLeafPayloadByteLength: 10_127_220n,
            sourceReplayByteLength: 452_329_472n,
            widthDependentQueriedBaseOpeningByteLength: 10_104_528n,
        });
        expect(deriveProofStorageWidthOpeningWorkspaceGeometry(3_451)).toEqual({
            freshVerifierOuterVectorContainerByteLengthCeiling: 8_960n,
            freshVerifierPublicOpeningWorkspaceByteLengthCeiling: 102_726_432n,
            proverPublicOpeningWorkspaceByteLengthCeiling: 60_659_552n,
        });
        for (
            let index = 1;
            index < proofStorageWidthSchedule.length;
            index += 1
        ) {
            const previousWidth = proofStorageWidthSchedule[index - 1];
            const currentWidth = proofStorageWidthSchedule[index];
            if (previousWidth === undefined || currentWidth === undefined) {
                throw new Error('Width schedule unexpectedly became sparse.');
            }
            const previous = deriveProofStorageWidthGeometry(previousWidth);
            const current = deriveProofStorageWidthGeometry(currentWidth);
            expect(
                (current.widthDependentQueriedBaseOpeningByteLength -
                    previous.widthDependentQueriedBaseOpeningByteLength) /
                    BigInt(currentWidth - previousWidth),
            ).toBe(2_928n);
        }
    });

    it('validates every static width before sampling and refuses formula or cap drift', () => {
        expect(
            validateProofStorageWidthStaticPreflightResult(
                buildStaticPreflightResult(),
            ).points,
        ).toHaveLength(7);
        const exact = buildStaticPreflightResult();
        const points = exact.points as readonly Record<string, unknown>[];
        const firstPoint = points[0];
        if (firstPoint === undefined) {
            throw new Error('Static test fixture has no first point.');
        }
        expect(() =>
            validateProofStorageWidthStaticPreflightResult({
                ...exact,
                points: [
                    {
                        ...firstPoint,
                        sourceCommittedTransactionCountDecimal: '191',
                    },
                    ...points.slice(1),
                ],
            }),
        ).toThrow(/sourceCommittedTransactionCountDecimal/u);
        for (const [fieldName, stalePayloadOnlyValue] of [
            ['copiedBufferByteLengthCeilingDecimal', '49152'],
            ['boundaryTransferByteLengthCeilingDecimal', '49340'],
        ] as const) {
            expect(() =>
                validateProofStorageWidthStaticPreflightResult({
                    ...exact,
                    points: [
                        {
                            ...firstPoint,
                            [fieldName]: stalePayloadOnlyValue,
                        },
                        ...points.slice(1),
                    ],
                }),
            ).toThrow(new RegExp(fieldName, 'u'));
        }
        expect(() =>
            validateProofStorageWidthStaticPreflightResult({
                ...exact,
                points: [
                    {
                        ...firstPoint,
                        browserOperationRegistryByteLengthCeilingDecimal:
                            '64553',
                    },
                    ...points.slice(1),
                ],
            }),
        ).toThrow(/wasmMemoryByteLengthCeilingDecimal/u);
        const overCapDigestStateByteLength = 700_000_000n;
        const overCapWasmMemoryByteLength =
            BigInt(firstPoint.wasmMemoryByteLengthCeilingDecimal as string) +
            overCapDigestStateByteLength -
            33_554_432n;
        expect(() =>
            validateProofStorageWidthStaticPreflightResult({
                ...exact,
                points: [
                    {
                        ...firstPoint,
                        digestStateByteLengthCeilingDecimal:
                            overCapDigestStateByteLength.toString(),
                        wasmMemoryByteLengthCeilingDecimal:
                            overCapWasmMemoryByteLength.toString(),
                    },
                    ...points.slice(1),
                ],
            }),
        ).toThrow(/WASM memory bytes.*exceeds cap/u);
    });

    it('accepts one exact result and refuses ledger, persistence, counter, and schedule mutations', () => {
        expect(validateProofStorageWidthResult(buildResult(32))).toMatchObject({
            publicBaseLeafColumnCount: 32,
            persistedLdeByteLength: 0n,
            baseLeafObjectReadByteLength: 0n,
            baseLeafObjectWrittenByteLength: 0n,
        });
        const exact = buildResult(32);
        for (const [fieldName, invalidValue, expectedPattern] of [
            [
                'absoluteCapTableIdentifier',
                'wrong',
                /absoluteCapTableIdentifier/u,
            ],
            ['backendProfileIdentifier', 'wrong', /backendProfileIdentifier/u],
            ['custodySchemaVersion', 2, /custodySchemaVersion/u],
            ['publicColumnSeedHex', '00', /publicColumnSeedHex/u],
            [
                'representativeBrowserWidth',
                1_024,
                /representativeBrowserWidth/u,
            ],
            ['sourceOpeningClaimCount', 10, /sourceOpeningClaimCount/u],
            ['batchingFunctionCount', 17, /batchingFunctionCount/u],
            ['persistedLdeByteLengthDecimal', '1', /must be 0/u],
            ['baseLeafObjectReadByteLengthDecimal', '1', /must be 0/u],
            ['ldeTransformCountDecimal', '191', /must be 192/u],
            ['openedLeafRangeChunkCountDecimal', '184', /must be 183/u],
            [
                'canonicalArtifactByteLengthDecimal',
                '1',
                /canonicalArtifactByteLengthDecimal/u,
            ],
            [
                'recomputedCanonicalArtifactByteLengthDecimal',
                '1',
                /canonicalArtifactByteLengthDecimal/u,
            ],
            [
                'externalCommittedTransactionCountDecimal',
                '1',
                /externalCommittedTransactionCountDecimal/u,
            ],
        ] as const) {
            expect(() =>
                validateProofStorageWidthResult({
                    ...exact,
                    [fieldName]: invalidValue,
                }),
            ).toThrow(expectedPattern);
        }
        expect(() =>
            validateProofStorageWidthPoint({
                expectedScheduleOrdinal: 2,
                guardJsonLines: buildGuardJsonLines(),
                result: buildResult(128),
            }),
        ).toThrow(/requires width 32/u);
    });

    it('requires complete 100 ms guard telemetry with baseline and in-window coverage', () => {
        const withoutBaseline = buildGuardJsonLines()
            .split('\n')
            .filter(
                (line) => !line.includes('"recordedAtUnixMilliseconds":900'),
            )
            .map((line, index) => {
                const record = JSON.parse(line) as Record<string, unknown>;
                return JSON.stringify({ ...record, sequence: index });
            })
            .join('\n');
        expect(() =>
            validateProofStorageWidthPoint({
                expectedScheduleOrdinal: 1,
                guardJsonLines: withoutBaseline,
                result: buildResult(8),
            }),
        ).toThrow(/pre-operation resident baseline/u);

        const withSamplingError = buildGuardJsonLines().replace(
            '"sampleError":null',
            '"sampleError":"unavailable"',
        );
        expect(() =>
            validateProofStorageWidthPoint({
                expectedScheduleOrdinal: 1,
                guardJsonLines: withSamplingError,
                result: buildResult(8),
            }),
        ).toThrow(/no sampling error/u);
    });

    it('stops on either hard cap and accepts values exactly at both caps', () => {
        const baseline = buildPoint(0);
        const width32 = buildPoint(1);
        expect(
            evaluateProofStorageWidthCurve([
                baseline,
                {
                    ...width32,
                    result: {
                        ...width32.result,
                        physicalObjectPeak:
                            proofStorageWidthProfile.maximumPhysicalObjectCount +
                            1n,
                    },
                },
            ]),
        ).toMatchObject({
            capViolations: ['physical-external-object-count'],
            outcome: 'absolute-cap-violation',
        });
        expect(
            evaluateProofStorageWidthCurve([
                baseline,
                {
                    ...width32,
                    result: {
                        ...width32.result,
                        storedScratchPeakByteLength:
                            proofStorageWidthProfile.maximumStoredScratchByteLength +
                            1n,
                    },
                },
            ]),
        ).toMatchObject({
            capViolations: ['stored-scratch-byte-length'],
            outcome: 'absolute-cap-violation',
        });
        const exactBoundary = {
            ...baseline,
            result: {
                ...baseline.result,
                physicalObjectPeak:
                    proofStorageWidthProfile.maximumPhysicalObjectCount,
                storedScratchPeakByteLength:
                    proofStorageWidthProfile.maximumStoredScratchByteLength,
            },
        };
        expect(evaluateProofStorageWidthCurve([exactBoundary])).toMatchObject({
            outcome: 'continue',
            pendingReleaseDesktopBrowserCaps: [
                'copied-buffer-byte-length',
                'wasm-memory-byte-length',
            ],
        });
    });

    it('uses width 8 to 32 as the fixed-term-adjusted elapsed anchor for adjacent and global envelopes', () => {
        const baseline = buildPoint(0, { elapsedNanoseconds: 1_000n });
        const anchor = buildPoint(1, { elapsedNanoseconds: 1_240n });
        const linearWidth128 = buildPoint(2, {
            elapsedNanoseconds: 2_200n,
        });
        expect(
            evaluateProofStorageWidthCurve([baseline, anchor, linearWidth128])
                .outcome,
        ).toBe('continue');

        const adjacentBreak = buildPoint(3, {
            elapsedNanoseconds: 15_000n,
        });
        const brokenCurve = evaluateProofStorageWidthCurve([
            baseline,
            anchor,
            linearWidth128,
            adjacentBreak,
        ]);
        expect(brokenCurve.outcome).toBe('unexplained-superlinear-scaling');
        expect(brokenCurve.superlinearViolations).toContain(
            'elapsed-time-adjacent',
        );
        expect(brokenCurve.superlinearViolations).toContain(
            'elapsed-time-global',
        );
    });

    it('exempts only the exact per-leaf transaction chunk transition at full width', () => {
        const points = proofStorageWidthSchedule.map((width, index) =>
            buildPoint(index, {
                elapsedNanoseconds: 1_000n + 10n * BigInt(width),
            }),
        );
        expect(evaluateProofStorageWidthCurve(points)).toEqual({
            capViolations: [],
            outcome: 'full-width-complete',
            pendingReleaseDesktopBrowserCaps: [
                'copied-buffer-byte-length',
                'wasm-memory-byte-length',
            ],
            superlinearViolations: [],
            transactionChunkBoundaryExempted: true,
        });

        const arbitraryFullWidthJump = points.map((point, index) =>
            index === points.length - 1
                ? {
                      ...point,
                      result: {
                          ...point.result,
                          externalCommittedTransactionCount: 1_000_000n,
                      },
                  }
                : point,
        );
        expect(
            evaluateProofStorageWidthCurve(arbitraryFullWidthJump),
        ).toMatchObject({
            outcome: 'unexplained-superlinear-scaling',
            superlinearViolations: ['external-transactions-adjacent'],
            transactionChunkBoundaryExempted: true,
        });

        const earlyTransactionBreak = points.slice(0, 4).map((point, index) =>
            index === 3
                ? {
                      ...point,
                      result: {
                          ...point.result,
                          externalCommittedTransactionCount: 1_000_000n,
                      },
                  }
                : point,
        );
        expect(
            evaluateProofStorageWidthCurve(earlyTransactionBreak),
        ).toMatchObject({
            outcome: 'unexplained-superlinear-scaling',
            superlinearViolations: ['external-transactions-adjacent'],
            transactionChunkBoundaryExempted: false,
        });
    });
});
