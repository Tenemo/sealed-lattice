import {
    deriveProofStorageWidthExternalMemoryFramingGeometry,
    deriveProofStorageWidthGeometry,
    deriveProofStorageWidthNativeCustodyMetadataByteLengthCeiling,
    deriveProofStorageWidthOpeningWorkspaceGeometry,
    proofStorageWidthProfile,
    proofStorageWidthSchedule,
    type ProofStorageWidth,
} from '#tools/ci/proof-storage-width-evidence';

const browserOperationRegistryByteLengthCeiling = 64_552n;

const inputIdentityForWidth = (width: ProofStorageWidth): string =>
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

export const buildProofStorageWidthStaticPreflightFixture = (): Readonly<
    Record<string, unknown>
> => ({
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
            boundaryTransferByteLengthCeilingDecimal:
                proofStorageWidthProfile.externalMemoryBoundaryTransferLiveByteLengthCeiling.toString(),
            browserOperationRegistryByteLengthCeilingDecimal:
                browserOperationRegistryByteLengthCeiling.toString(),
            canonicalArtifactContainerByteLengthCeilingDecimal:
                canonicalArtifactContainerByteLengthCeiling.toString(),
            canonicalArtifactLiveCopyByteLengthCeilingDecimal: (
                2n * canonicalProofByteLengthCeiling
            ).toString(),
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
            extensionDomainWorkingByteLengthCeilingDecimal:
                proofStorageWidthProfile.extensionDomainWorkingByteLength.toString(),
            externalIoByteLengthCeilingDecimal: (
                externalReadByteLengthCeiling + externalWrittenByteLengthCeiling
            ).toString(),
            externalReadByteLengthCeilingDecimal:
                externalReadByteLengthCeiling.toString(),
            externalWrittenByteLengthCeilingDecimal:
                externalWrittenByteLengthCeiling.toString(),
            freshVerifierOuterVectorContainerByteLengthCeilingDecimal:
                openingWorkspaceGeometry.freshVerifierOuterVectorContainerByteLengthCeiling.toString(),
            freshVerifierPublicOpeningWorkspaceByteLengthCeilingDecimal:
                openingWorkspaceGeometry.freshVerifierPublicOpeningWorkspaceByteLengthCeiling.toString(),
            frozenFixtureAndContainerByteLengthCeilingDecimal:
                frozenFixtureAndContainerByteLengthCeiling.toString(),
            inputIdentityShake256Hex: inputIdentityForWidth(width),
            ldeTransformCountDecimal: geometry.ldeTransformCount.toString(),
            legacyBaseLeafObjectByteLengthDecimal:
                geometry.legacyBaseLeafObjectByteLength.toString(),
            localRecordSealInvocationCountDecimal: '0',
            maximumTransactionPayloadByteLengthDecimal: '49152',
            nativeCustodyMetadataByteLengthCeilingDecimal:
                deriveProofStorageWidthNativeCustodyMetadataByteLengthCeiling(
                    width,
                ).toString(),
            openedLeafElementByteLengthDecimal:
                geometry.openedLeafElementByteLength.toString(),
            openedLeafRangeChunkCountDecimal:
                geometry.openedLeafRangeChunkCount.toString(),
            openedValueCountDecimal: geometry.openedValueCount.toString(),
            openingArtifactAndTranscriptByteLengthCeilingDecimal:
                canonicalProofByteLengthCeiling.toString(),
            persistedLdeByteLengthDecimal: '0',
            physicalObjectPeakDecimal: geometry.physicalObjectPeak.toString(),
            proofObjectSealTransactionCountDecimal: '1',
            proofPhysicalObjectCountDecimal: '1',
            proverPublicOpeningWorkspaceByteLengthCeilingDecimal:
                openingWorkspaceGeometry.proverPublicOpeningWorkspaceByteLengthCeiling.toString(),
            publicBaseLeafByteLengthDecimal:
                geometry.publicBaseLeafByteLength.toString(),
            publicBaseLeafColumnCount: width,
            queriedLeafPayloadByteLengthDecimal:
                geometry.queriedLeafPayloadByteLength.toString(),
            rawAbiRequestCopyWorkspaceByteLengthCeilingDecimal:
                externalMemoryFramingGeometry.rawAbiRequestCopyWorkspaceByteLengthCeiling.toString(),
            rawAbiResponseDecodeWorkspaceByteLengthCeilingDecimal:
                externalMemoryFramingGeometry.rawAbiResponseDecodeWorkspaceByteLengthCeiling.toString(),
            rawAbiTransferWorkspaceByteLengthCeilingDecimal:
                externalMemoryFramingGeometry.rawAbiTransferWorkspaceByteLengthCeiling.toString(),
            retainedAlgebraicCoefficientByteLengthCeilingDecimal:
                proofStorageWidthProfile.retainedAlgebraicCoefficientByteLength.toString(),
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
                browserOperationRegistryByteLengthCeiling
            ).toString(),
            widthDependentQueriedBaseOpeningByteLengthDecimal:
                geometry.widthDependentQueriedBaseOpeningByteLength.toString(),
        };
    }),
    sourceOpeningClaimCount: 9,
    widths: proofStorageWidthSchedule,
});
