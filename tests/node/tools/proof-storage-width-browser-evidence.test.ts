import { describe, expect, it } from 'vitest';

import {
    parseProofStorageWidthBrowserMeasurement,
    proofStorageWidthBrowserEvidenceProfile,
    serializeProofStorageWidthBrowserMeasurement,
} from '#tests/support/proof-storage-width-browser-evidence';
import {
    deriveProofStorageWidthGeometry,
    proofStorageWidthProfile,
} from '#tools/ci/proof-storage-width-evidence';
import {
    deriveProofStorageWidthBrowserProjection,
    requireProofStorageWidthBrowserProjectionEligibility,
    type ProofStorageWidthBrowserProjectionPoint,
    type ProofStorageWidthBrowserStaticProjectionPoint,
} from '#tools/ci/run-proof-storage-width-browser-evidence';

const createMeasurementRecord = (): Readonly<Record<string, unknown>> => {
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
        wasmSha256Hex: '12'.repeat(32),
        workerYieldCountDecimal: '4',
        workerYieldNanosecondsDecimal: '300',
        widthDependentQueriedBaseOpeningByteLengthDecimal:
            geometry.widthDependentQueriedBaseOpeningByteLength.toString(),
        widthInputIdentityHashDomain:
            proofStorageWidthProfile.widthInputIdentityHashDomain,
    };
};

const representativePoint: ProofStorageWidthBrowserProjectionPoint = {
    elapsedNanoseconds: 1_000n,
    externalCommittedTransactionCount: 10n,
    externalIoByteLength: 1_000n,
    ldeTransformCount: deriveProofStorageWidthGeometry(512).ldeTransformCount,
    publicBaseLeafColumnCount: 512,
};

const fullWidthPoint: ProofStorageWidthBrowserProjectionPoint = {
    elapsedNanoseconds: 9_000n,
    externalCommittedTransactionCount: 80n,
    externalIoByteLength: 7_000n,
    ldeTransformCount: deriveProofStorageWidthGeometry(3_451).ldeTransformCount,
    publicBaseLeafColumnCount: 3_451,
};

const representativeStaticPoint: ProofStorageWidthBrowserStaticProjectionPoint =
    {
        publicBaseLeafColumnCount: 512,
        wasmMemoryByteLengthCeiling: 300_000_000n,
    };

const fullWidthStaticPoint: ProofStorageWidthBrowserStaticProjectionPoint = {
    publicBaseLeafColumnCount: 3_451,
    wasmMemoryByteLengthCeiling: 450_000_000n,
};

describe('Proof-storage width browser evidence', () => {
    it('round-trips the canonical browser measurement and refuses cap drift', () => {
        const record = createMeasurementRecord();
        const measurement = parseProofStorageWidthBrowserMeasurement(record);
        expect(
            parseProofStorageWidthBrowserMeasurement(
                serializeProofStorageWidthBrowserMeasurement(measurement),
            ),
        ).toEqual(measurement);
        expect(() =>
            parseProofStorageWidthBrowserMeasurement({
                ...record,
                copiedBufferPeakByteLengthDecimal: (
                    proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength +
                    1n
                ).toString(),
            }),
        ).toThrow(/copied-buffer bound/u);
        expect(() =>
            parseProofStorageWidthBrowserMeasurement({
                ...record,
                copiedBufferPeakByteLengthDecimal: '49152',
            }),
        ).toThrow(/copiedBufferPeakByteLengthDecimal/u);
        expect(() =>
            parseProofStorageWidthBrowserMeasurement({
                ...record,
                maximumTransactionPayloadByteLengthDecimal: '49340',
            }),
        ).toThrow(/maximumTransactionPayloadByteLengthDecimal/u);
        expect(() =>
            parseProofStorageWidthBrowserMeasurement({
                ...record,
                custodySchemaIdentifier: 'unbounded-memory-v1',
            }),
        ).toThrow(/custodySchemaIdentifier/u);
    });

    it('refuses browser evidence identity and runtime metadata drift', () => {
        const record = createMeasurementRecord();
        for (const fieldName of [
            'frozenInputIdentityHashDomain',
            'frozenInputRecipeIdentifier',
            'intendedReleaseRuntime',
            'measurementRuntime',
            'widthInputIdentityHashDomain',
        ] as const) {
            expect(() =>
                parseProofStorageWidthBrowserMeasurement({
                    ...record,
                    [fieldName]: 'stale-metadata-v0',
                }),
            ).toThrow(new RegExp(fieldName, 'u'));
        }
        expect(() =>
            parseProofStorageWidthBrowserMeasurement({
                ...record,
                exactCandidate: {
                    ...(record.exactCandidate as Readonly<
                        Record<string, unknown>
                    >),
                    firstDataModulus: 257,
                },
            }),
        ).toThrow(/exactCandidate\.firstDataModulus/u);
    });

    it('projects the exact validated static WebAssembly ceiling delta', () => {
        const measurement = parseProofStorageWidthBrowserMeasurement(
            createMeasurementRecord(),
        );
        const projection = deriveProofStorageWidthBrowserProjection({
            fullWidthResult: fullWidthPoint,
            fullWidthStaticPoint,
            measurement,
            representativeResult: representativePoint,
            representativeStaticPoint,
        });
        expect(projection).toMatchObject({
            arithmeticNanoseconds: 900n,
            coordinatorNanoseconds: 80n,
            externalStorageWaitNanoseconds: 1_600n,
            operationNanoseconds: 4_980n,
            projectedCopiedBufferPeakByteLength: 49_340n,
            projectedWasmLinearMemoryPeakByteLength: 351_326_592n,
            staticWasmMemoryCeilingGrowth: {
                deltaByteLength: 150_000_000n,
                fullWidthByteLength: 450_000_000n,
                representativeByteLength: 300_000_000n,
            },
            workerYieldNanoseconds: 2_400n,
        });
        expect(() =>
            requireProofStorageWidthBrowserProjectionEligibility({
                fullWidthResult: fullWidthPoint,
                projection,
            }),
        ).not.toThrow();
    });

    it('refuses every full-width browser projection cap boundary', () => {
        const projection = deriveProofStorageWidthBrowserProjection({
            fullWidthResult: fullWidthPoint,
            fullWidthStaticPoint,
            measurement: parseProofStorageWidthBrowserMeasurement(
                createMeasurementRecord(),
            ),
            representativeResult: representativePoint,
            representativeStaticPoint,
        });
        expect(() =>
            requireProofStorageWidthBrowserProjectionEligibility({
                fullWidthResult: fullWidthPoint,
                projection: {
                    ...projection,
                    projectedCopiedBufferPeakByteLength: 65_536n,
                },
            }),
        ).not.toThrow();
        expect(() =>
            requireProofStorageWidthBrowserProjectionEligibility({
                fullWidthResult: fullWidthPoint,
                projection: {
                    ...projection,
                    projectedCopiedBufferPeakByteLength:
                        proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength +
                        1n,
                },
            }),
        ).toThrow(/copied-buffer cap/u);
        expect(() =>
            requireProofStorageWidthBrowserProjectionEligibility({
                fullWidthResult: fullWidthPoint,
                projection: {
                    ...projection,
                    projectedWasmLinearMemoryPeakByteLength:
                        proofStorageWidthBrowserEvidenceProfile.maximumWasmLinearMemoryByteLength +
                        1n,
                },
            }),
        ).toThrow(/linear-memory cap/u);
        expect(() =>
            requireProofStorageWidthBrowserProjectionEligibility({
                fullWidthResult: fullWidthPoint,
                projection: {
                    ...projection,
                    operationNanoseconds: 121n * 60n * 1_000_000_000n,
                },
            }),
        ).toThrow(/120 minutes/u);
        expect(() =>
            requireProofStorageWidthBrowserProjectionEligibility({
                fullWidthResult: {
                    ...fullWidthPoint,
                    externalIoByteLength: 1_099_511_627_776n,
                },
                projection,
            }),
        ).toThrow(/terabyte-scale/u);
        expect(() =>
            requireProofStorageWidthBrowserProjectionEligibility({
                fullWidthResult: {
                    ...fullWidthPoint,
                    externalCommittedTransactionCount: 1_000_000_000n,
                },
                projection,
            }),
        ).toThrow(/one billion/u);
    });

    it('refuses tampered static points, negative deltas, and overflowing sums', () => {
        const measurement = parseProofStorageWidthBrowserMeasurement(
            createMeasurementRecord(),
        );
        const derive = (input: {
            readonly fullWidthStaticPoint: ProofStorageWidthBrowserStaticProjectionPoint;
            readonly representativeStaticPoint: ProofStorageWidthBrowserStaticProjectionPoint;
        }) =>
            deriveProofStorageWidthBrowserProjection({
                fullWidthResult: fullWidthPoint,
                fullWidthStaticPoint: input.fullWidthStaticPoint,
                measurement,
                representativeResult: representativePoint,
                representativeStaticPoint: input.representativeStaticPoint,
            });
        expect(() =>
            derive({
                fullWidthStaticPoint: {
                    ...fullWidthStaticPoint,
                    publicBaseLeafColumnCount: 2_048,
                },
                representativeStaticPoint,
            }),
        ).toThrow(/fixed width-512 and width-3451 points/u);
        expect(() =>
            derive({
                fullWidthStaticPoint: {
                    ...fullWidthStaticPoint,
                    wasmMemoryByteLengthCeiling: 299_999_999n,
                },
                representativeStaticPoint,
            }),
        ).toThrow(/would be negative/u);
        expect(() =>
            derive({
                fullWidthStaticPoint,
                representativeStaticPoint: {
                    ...representativeStaticPoint,
                    wasmMemoryByteLengthCeiling: -1n,
                },
            }),
        ).toThrow(/requires nonnegative operands/u);
        expect(() =>
            derive({
                fullWidthStaticPoint: {
                    ...fullWidthStaticPoint,
                    wasmMemoryByteLengthCeiling: (1n << 64n) - 1n,
                },
                representativeStaticPoint: {
                    ...representativeStaticPoint,
                    wasmMemoryByteLengthCeiling: 0n,
                },
            }),
        ).toThrow(/exceeds u64/u);
    });
});
