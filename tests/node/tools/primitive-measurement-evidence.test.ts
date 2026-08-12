import { describe, expect, it } from 'vitest';

import { deriveDesktopBrowserAuthenticatedStorageConfiguration } from '#tools/ci/desktop-browser-primitive-measurement-page';
import {
    desktopBrowserBoundaryCopyIterationCount,
    parseReleaseNativePrimitiveMeasurementOutput,
    primitiveMeasurementCaseCatalog,
    requireCompletePrimitiveMeasurementCatalog,
    selectedAuthenticatedScratchRecordByteLength,
    validateDesktopBrowserAuthenticatedStorageMeasurement,
    validateDesktopBrowserBoundaryCopyMeasurement,
    validateDesktopBrowserFocusedPrimitiveMeasurementBundle,
    validateDesktopBrowserFocusedPrimitiveMeasurementEvidence,
    validateDesktopBrowserPrimitiveMeasurementBundle,
    validateDesktopBrowserPrimitiveMeasurementEvidence,
    validatePrimitiveMeasurementRecord,
    validateReleaseNativePrimitiveMeasurementEvidence,
    vssFusedRadix51ProjectionOwnerCaseIdentifiers,
    type PrimitiveMeasurementRecord,
} from '#tools/ci/primitive-measurement-evidence';
import { parseDesktopBrowserPrimitiveMeasurementArguments } from '#tools/ci/run-desktop-browser-primitive-measurements';
import {
    deriveVssBaseMaterializationProjection,
    deriveVssFusedRadix51OwnerProjection,
} from '#tools/ci/vss-base-materialization-projection';

const recordFor = (
    caseIdentifier: number,
    executionTarget: PrimitiveMeasurementRecord['executionTarget'] = 'wasm32-unknown-unknown',
): Record<string, unknown> => {
    const catalogEntry = primitiveMeasurementCaseCatalog.find(
        (candidate) => candidate.caseIdentifier === caseIdentifier,
    );
    if (catalogEntry === undefined) {
        throw new Error('Test primitive-measurement case is absent.');
    }
    const dimensions: Array<{ name: string; value: number }> = Object.entries(
        catalogEntry.requiredDimensions,
    ).map(([name, value]) => ({ name, value }));
    if (caseIdentifier === 1) {
        dimensions.push({ name: 'pollCount', value: 41 });
    }
    if (caseIdentifier === 5) {
        const materializationPassCount = 2;
        const rowCount = 1_128;
        const laneCount = 32;
        const logicalChunkCountPerLane = 9_009;
        const sourceReplayCount =
            logicalChunkCountPerLane * laneCount * materializationPassCount;
        const laneDftCount = rowCount * laneCount * materializationPassCount;
        const fullDomainSize = 16_777_216;
        const leafHashQueryCount = fullDomainSize * materializationPassCount;
        dimensions.push(
            { name: 'columnOrdinal', value: 17 },
            { name: 'nonzeroSourceCoefficientCount', value: 1_024 },
            { name: 'retainedInputByteLength', value: 2_097_152 },
            {
                name: 'basePhaseSourceReplayCount',
                value: sourceReplayCount,
            },
            {
                name: 'basePhaseProverSourceReplayCount',
                value: sourceReplayCount,
            },
            { name: 'basePhaseLaneDftCount', value: laneDftCount },
            {
                name: 'basePhaseButterflyCount',
                value: laneDftCount * 4_980_736,
            },
            {
                name: 'basePhaseCosetMultiplicationCount',
                value: laneDftCount * 524_288,
            },
            {
                name: 'basePhaseColumnValueDeliveryCount',
                value: rowCount * fullDomainSize * materializationPassCount,
            },
            {
                name: 'basePhaseTransportedValueByteLength',
                value: rowCount * fullDomainSize * materializationPassCount * 8,
            },
            {
                name: 'basePhaseLeafHashQueryCount',
                value: leafHashQueryCount,
            },
            {
                name: 'basePhaseSaltedLeafKeccakPermutationCount',
                value: leafHashQueryCount * 68,
            },
            {
                name: 'basePhaseMerkleParentHashQueryCount',
                value: (fullDomainSize - 1) * materializationPassCount,
            },
            {
                name: 'basePhasePrivateLeafSaltDerivationCount',
                value: leafHashQueryCount,
            },
            {
                name: 'modeledCandidateQuotientConstructionIdentityByteLength',
                value: 749_188,
            },
            {
                name: 'modeledCandidateQuotientPhaseOrderCount',
                value: 2,
            },
            {
                name: 'modeledCandidateQuotientTranscriptOperationCount',
                value: 2_625,
            },
            {
                name: 'modeledCandidateQuotientOpeningBatchCount',
                value: 923,
            },
            {
                name: 'modeledCandidateQuotientProofSectionCount',
                value: 121,
            },
            {
                name: 'modeledCandidateQuotientCheckpointCount',
                value: 11,
            },
            {
                name: 'modeledCandidateQuotientMaximumTranscriptHashQueryCount',
                value: 329_471,
            },
            {
                name: 'modeledCandidateQuotientLogicalVerifierMessageCount',
                value: 2_158,
            },
        );
    }
    if (caseIdentifier === 7) {
        dimensions.push(
            { name: 'pollCount', value: 1_024 },
            { name: 'lowerScheduleHeapByteLength', value: 100_000 },
            { name: 'higherScheduleHeapByteLength', value: 110_000 },
        );
    }
    if (caseIdentifier === 8) {
        dimensions.push({ name: 'retainedInputByteLength', value: 2_097_152 });
    }
    if (caseIdentifier === 9 || caseIdentifier === 11) {
        dimensions.push(
            { name: 'retainedInputByteLength', value: 2_097_152 },
            {
                name: 'retainedGroupHeaderByteLength',
                value: executionTarget === 'release-native' ? 1_536 : 768,
            },
        );
    }
    if (caseIdentifier === 10 || caseIdentifier === 12) {
        const retainedInputByteLength = 2_097_152;
        const retainedGroupHeaderByteLength =
            executionTarget === 'release-native' ? 1_536 : 768;
        const retainedGroupContainerByteLength =
            executionTarget === 'release-native' ? 32 : 24;
        const ownedFixedStateByteLength =
            executionTarget === 'release-native' ? 256 : 192;
        const retainedCoefficientPayloadByteLength = dimensions.find(
            (dimension) =>
                dimension.name === 'retainedCoefficientPayloadByteLength',
        )!.value;
        const replayBufferByteLength = dimensions.find(
            (dimension) => dimension.name === 'replayBufferByteLength',
        )!.value;
        const rowWorkingBufferByteLength = dimensions.find(
            (dimension) => dimension.name === 'rowWorkingBufferByteLength',
        )!.value;
        dimensions.push(
            { name: 'pollCount', value: 10_000 },
            { name: 'retainedInputByteLength', value: retainedInputByteLength },
            {
                name: 'retainedGroupHeaderByteLength',
                value: retainedGroupHeaderByteLength,
            },
            {
                name: 'retainedGroupContainerByteLength',
                value: retainedGroupContainerByteLength,
            },
            {
                name: 'ownedFixedStateByteLength',
                value: ownedFixedStateByteLength,
            },
            {
                name: 'materializationPeakLiveByteLength',
                value:
                    retainedInputByteLength +
                    retainedCoefficientPayloadByteLength +
                    replayBufferByteLength +
                    retainedGroupHeaderByteLength +
                    retainedGroupContainerByteLength,
            },
            {
                name: 'stripePeakLiveByteLength',
                value:
                    retainedInputByteLength +
                    retainedCoefficientPayloadByteLength +
                    retainedGroupHeaderByteLength +
                    rowWorkingBufferByteLength +
                    ownedFixedStateByteLength,
            },
        );
    }
    const retainedInputByteLength = dimensions.find(
        (dimension) => dimension.name === 'retainedInputByteLength',
    )?.value;
    const traceValueCount = dimensions.find(
        (dimension) => dimension.name === 'traceValueCount',
    )?.value;
    const retainedCoefficientPayloadByteLength = dimensions.find(
        (dimension) =>
            dimension.name === 'retainedCoefficientPayloadByteLength',
    )?.value;
    const retainedGroupHeaderByteLength = dimensions.find(
        (dimension) => dimension.name === 'retainedGroupHeaderByteLength',
    )?.value;
    const materializationPeakLiveByteLength = dimensions.find(
        (dimension) => dimension.name === 'materializationPeakLiveByteLength',
    )?.value;
    const stripePeakLiveByteLength = dimensions.find(
        (dimension) => dimension.name === 'stripePeakLiveByteLength',
    )?.value;
    return {
        caseIdentifier,
        caseName: catalogEntry.caseName,
        checksumHex: '0123456789abcdef',
        dimensions,
        elapsedNanoseconds: 123_456,
        executionTarget,
        iterationCount: catalogEntry.expectedIterationCount,
        modeledPeakLiveByteLength:
            caseIdentifier === 5 || caseIdentifier === 8
                ? retainedInputByteLength! + traceValueCount! * 8
                : caseIdentifier === 9 || caseIdentifier === 11
                  ? retainedInputByteLength! +
                    retainedCoefficientPayloadByteLength! +
                    dimensions.find(
                        (dimension) =>
                            dimension.name === 'replayBufferByteLength',
                    )!.value +
                    retainedGroupHeaderByteLength!
                  : caseIdentifier === 10 || caseIdentifier === 12
                    ? Math.max(
                          materializationPeakLiveByteLength!,
                          stripePeakLiveByteLength!,
                      )
                    : caseIdentifier === 13
                      ? (dimensions.find(
                            (dimension) =>
                                dimension.name === 'planFieldElementCount',
                        )!.value +
                            dimensions.find(
                                (dimension) =>
                                    dimension.name ===
                                    'retainedFieldElementCount',
                            )!.value) *
                        dimensions.find(
                            (dimension) =>
                                dimension.name === 'fieldElementByteLength',
                        )!.value
                      : caseIdentifier === 14
                        ? dimensions.find(
                              (dimension) =>
                                  dimension.name === 'inverseChunkElementCount',
                          )!.value *
                          dimensions.find(
                              (dimension) =>
                                  dimension.name ===
                                  'extensionElementByteLength',
                          )!.value *
                          2
                        : caseIdentifier === 15
                          ? (dimensions.find(
                                (dimension) =>
                                    dimension.name === 'encodedElementCount',
                            )!.value +
                                dimensions.find(
                                    (dimension) =>
                                        dimension.name ===
                                        'twiddleFieldElementCount',
                                )!.value) *
                            8
                          : caseIdentifier === 16
                            ? 1_568
                            : caseIdentifier === 17
                              ? dimensions.find(
                                    (dimension) =>
                                        dimension.name ===
                                        'batchMatrixByteLength',
                                )!.value +
                                dimensions.find(
                                    (dimension) =>
                                        dimension.name ===
                                        'replayColumnByteLength',
                                )!.value +
                                dimensions.find(
                                    (dimension) =>
                                        dimension.name ===
                                        'hashStateByteLength',
                                )!.value +
                                dimensions.find(
                                    (dimension) =>
                                        dimension.name === 'twiddleByteLength',
                                )!.value
                              : caseIdentifier === 18
                                ? dimensions.find(
                                      (dimension) =>
                                          dimension.name ===
                                          'retainedInputByteLength',
                                  )!.value +
                                  dimensions.find(
                                      (dimension) =>
                                          dimension.name ===
                                          'maximumReconstructionRetainedByteLength',
                                  )!.value +
                                  dimensions.find(
                                      (dimension) =>
                                          dimension.name ===
                                          'outputResidueByteLength',
                                  )!.value
                                : caseIdentifier === 19 || caseIdentifier === 20
                                  ? dimensions.find(
                                        (dimension) =>
                                            dimension.name ===
                                            'batchMatrixByteLength',
                                    )!.value +
                                    dimensions.find(
                                        (dimension) =>
                                            dimension.name ===
                                            'replayBaseCoordinateByteLength',
                                    )!.value +
                                    dimensions.find(
                                        (dimension) =>
                                            dimension.name ===
                                            'hashStateByteLength',
                                    )!.value +
                                    dimensions.find(
                                        (dimension) =>
                                            dimension.name ===
                                            'twiddleByteLength',
                                    )!.value
                                  : 4_194_304,
        schemaVersion: 2,
    };
};

describe('Primitive measurement evidence', () => {
    it('accepts one exact ordered record for every production primitive owner', () => {
        const records = primitiveMeasurementCaseCatalog.map((entry) =>
            validatePrimitiveMeasurementRecord(
                recordFor(entry.caseIdentifier),
                'wasm32-unknown-unknown',
            ),
        );

        expect(() =>
            requireCompletePrimitiveMeasurementCatalog(records),
        ).not.toThrow();
        expect(records.map((record) => record.caseName)).toEqual(
            primitiveMeasurementCaseCatalog.map((entry) => entry.caseName),
        );
    });

    it('refuses stale geometry, identity, target, and canonical framing', () => {
        const wrongGeometry = recordFor(1);
        const dimensions = wrongGeometry.dimensions as Array<{
            name: string;
            value: number;
        }>;
        const butterflyCount = dimensions.find(
            (dimension) => dimension.name === 'butterflyCount',
        );
        if (butterflyCount === undefined) {
            throw new Error('Test butterfly dimension is absent.');
        }
        butterflyCount.value -= 1;
        expect(() => validatePrimitiveMeasurementRecord(wrongGeometry)).toThrow(
            /production geometry/u,
        );

        const wrongIdentity = recordFor(2);
        wrongIdentity.caseName = 'salted-phase-column-leaves';
        expect(() => validatePrimitiveMeasurementRecord(wrongIdentity)).toThrow(
            /identity/u,
        );

        expect(() =>
            validatePrimitiveMeasurementRecord(
                recordFor(3, 'release-native'),
                'wasm32-unknown-unknown',
            ),
        ).toThrow(/target/u);

        const oversizedEnvelope = recordFor(6);
        const envelopeDimension = (
            oversizedEnvelope.dimensions as Array<{
                name: string;
                value: number;
            }>
        ).find((dimension) => dimension.name === 'canonicalEnvelopeByteLength');
        if (envelopeDimension === undefined) {
            throw new Error('Test envelope dimension is absent.');
        }
        envelopeDimension.value += 1;
        expect(() =>
            validatePrimitiveMeasurementRecord(oversizedEnvelope),
        ).toThrow(/production geometry/u);

        for (const [dimensionName, wrongValue] of [
            ['basePhaseOpeningQueryCount', 393],
            ['aggregateWidePadQueryCount', 387],
            ['modeledCandidateRowCount', 107],
            ['modeledCandidateTracePackingFactor', 8],
            ['modeledCandidateOpeningPointCount', 23],
            ['modeledCandidateAggregateColumnRoleCount', 24],
            ['modeledCandidateQuotientSourceDegreeBoundExclusive', 4_194_303],
            ['modeledCandidateQuotientQueryCount', 393],
            ['modeledCandidateQuotientAgreementCeiling', 4_194_325],
            ['modeledCandidateQuotientBoundOpeningBatchCount', 535],
            ['singleAggregateCandidateRowCount', 330],
            [
                'singleAggregateCandidateBasePhaseAlgorithmLiveSetByteLength',
                289_406_975,
            ],
        ] as const) {
            const staleVssGeometry = recordFor(5);
            const staleDimension = (
                staleVssGeometry.dimensions as Array<{
                    name: string;
                    value: number;
                }>
            ).find((dimension) => dimension.name === dimensionName);
            if (staleDimension === undefined) {
                throw new Error(`Test ${dimensionName} dimension is absent.`);
            }
            staleDimension.value = wrongValue;
            expect(() =>
                validatePrimitiveMeasurementRecord(staleVssGeometry),
            ).toThrow(/production geometry/u);
        }

        for (const [caseIdentifier, dimensionName, wrongValue] of [
            [11, 'rangeDigitRadix', 50],
            [11, 'completeSourceMaterializationCount', 5_253],
            [12, 'completePhaseRowCount', 51],
            [12, 'completeLaneDftCount', 3_327],
            [12, 'completeSaltedLeafKeccakPermutationCount', 201_326_591],
        ] as const) {
            const staleFusedCandidate = recordFor(caseIdentifier);
            const staleDimension = (
                staleFusedCandidate.dimensions as Array<{
                    name: string;
                    value: number;
                }>
            ).find((dimension) => dimension.name === dimensionName);
            if (staleDimension === undefined) {
                throw new Error(`Test ${dimensionName} dimension is absent.`);
            }
            staleDimension.value = wrongValue;
            expect(() =>
                validatePrimitiveMeasurementRecord(staleFusedCandidate),
            ).toThrow(/production geometry|inconsistent/u);
        }

        for (const [dimensionName, wrongValue] of [
            ['modeledCandidateQuotientOpeningBatchCount', 922],
            ['modeledCandidateQuotientConstructionIdentityByteLength', 0],
            ['modeledCandidateQuotientMaximumTranscriptHashQueryCount', 2_158],
        ] as const) {
            const inconsistentQuotientConstruction = recordFor(5);
            const staleDimension = (
                inconsistentQuotientConstruction.dimensions as Array<{
                    name: string;
                    value: number;
                }>
            ).find((dimension) => dimension.name === dimensionName);
            if (staleDimension === undefined) {
                throw new Error(`Test ${dimensionName} dimension is absent.`);
            }
            staleDimension.value = wrongValue;
            expect(() =>
                validatePrimitiveMeasurementRecord(
                    inconsistentQuotientConstruction,
                ),
            ).toThrow(/inconsistent|unsigned integer/u);
        }
    });

    it('refuses duplicate dimensions, unknown fields, and catalog reordering', () => {
        const duplicateDimension = recordFor(4);
        const dimensions = duplicateDimension.dimensions as Array<{
            name: string;
            value: number;
        }>;
        dimensions.push({ ...dimensions[0] });
        expect(() =>
            validatePrimitiveMeasurementRecord(duplicateDimension),
        ).toThrow(/duplicated/u);

        const unknownField = recordFor(5);
        unknownField.producerValidity = true;
        expect(() => validatePrimitiveMeasurementRecord(unknownField)).toThrow(
            /noncanonical fields/u,
        );

        const records = primitiveMeasurementCaseCatalog.map((entry) =>
            validatePrimitiveMeasurementRecord(recordFor(entry.caseIdentifier)),
        );
        expect(() =>
            requireCompletePrimitiveMeasurementCatalog([
                records[1],
                records[0],
                ...records.slice(2),
            ]),
        ).toThrow(/reordered/u);
        expect(() =>
            requireCompletePrimitiveMeasurementCatalog(records.slice(0, -1)),
        ).toThrow(/incomplete/u);
    });

    it('extracts one canonical native catalog and refuses missing, duplicate, or stale output', () => {
        const serializedRecords = primitiveMeasurementCaseCatalog
            .map((entry) =>
                JSON.stringify(
                    recordFor(entry.caseIdentifier, 'release-native'),
                ),
            )
            .map(
                (record, recordIndex) =>
                    `test primitive_${recordIndex} ... primitive measurement: ${record}`,
            )
            .join('\n');

        expect(
            parseReleaseNativePrimitiveMeasurementOutput(
                serializedRecords,
                true,
            ).primitiveCases.map((record) => record.caseIdentifier),
        ).toEqual(
            primitiveMeasurementCaseCatalog.map(
                (entry) => entry.caseIdentifier,
            ),
        );
        expect(() =>
            parseReleaseNativePrimitiveMeasurementOutput('no record', true),
        ).toThrow(/no measurement record/u);
        expect(() =>
            parseReleaseNativePrimitiveMeasurementOutput(
                `${serializedRecords}\n${serializedRecords.split('\n')[0]}`,
                true,
            ),
        ).toThrow(/duplicates/u);

        const staleRecord = recordFor(5, 'release-native');
        (staleRecord.dimensions as Array<{ name: string; value: number }>).find(
            (dimension) =>
                dimension.name === 'basePhaseLogicalChunkCountPerLane',
        )!.value += 1;
        expect(() =>
            parseReleaseNativePrimitiveMeasurementOutput(
                `primitive measurement: ${JSON.stringify(staleRecord)}`,
                false,
            ),
        ).toThrow(/production geometry/u);
        const reversedFocusedOutput = [12, 11]
            .map(
                (caseIdentifier) =>
                    `primitive measurement: ${JSON.stringify(
                        recordFor(caseIdentifier, 'release-native'),
                    )}`,
            )
            .join('\n');
        expect(
            parseReleaseNativePrimitiveMeasurementOutput(
                reversedFocusedOutput,
                false,
                [11, 12],
            ).primitiveCases.map((record) => record.caseIdentifier),
        ).toEqual([11, 12]);
        expect(() =>
            parseReleaseNativePrimitiveMeasurementOutput(
                reversedFocusedOutput,
                false,
                [11],
            ),
        ).toThrow(/expected case set/u);
        expect(() =>
            parseReleaseNativePrimitiveMeasurementOutput(
                reversedFocusedOutput,
                false,
                [11, 11],
            ),
        ).toThrow(/expected case set/u);
        expect(() =>
            parseReleaseNativePrimitiveMeasurementOutput(
                serializedRecords,
                true,
                [11, 12],
            ),
        ).toThrow(/cannot declare focused cases/u);

        const exactEvidence = {
            primitiveCases: primitiveMeasurementCaseCatalog.map((entry) =>
                recordFor(entry.caseIdentifier, 'release-native'),
            ),
            schemaVersion: 1,
        };
        expect(
            validateReleaseNativePrimitiveMeasurementEvidence(
                exactEvidence,
                true,
            ).primitiveCases.map((record) => record.caseIdentifier),
        ).toEqual(
            primitiveMeasurementCaseCatalog.map(
                (entry) => entry.caseIdentifier,
            ),
        );
        const reorderedEvidence = structuredClone(exactEvidence);
        [
            reorderedEvidence.primitiveCases[0],
            reorderedEvidence.primitiveCases[1],
        ] = [
            reorderedEvidence.primitiveCases[1],
            reorderedEvidence.primitiveCases[0],
        ];
        expect(() =>
            validateReleaseNativePrimitiveMeasurementEvidence(
                reorderedEvidence,
                true,
            ),
        ).toThrow(/reordered/u);
        expect(() =>
            validateReleaseNativePrimitiveMeasurementEvidence(
                {
                    ...exactEvidence,
                    primitiveCases: [exactEvidence.primitiveCases[0]],
                },
                true,
            ),
        ).toThrow(/incomplete/u);
    });

    it('binds browser memory, boundary copies, and authenticated storage to the codec extent', () => {
        const primitiveCases = primitiveMeasurementCaseCatalog.map((entry) => ({
            record: recordFor(entry.caseIdentifier),
            wallElapsedMilliseconds: 1.25,
            wasmMemoryByteLengthAfter: 8_388_608,
            wasmMemoryByteLengthBefore: 1_048_576,
        }));
        const recordByteLength = selectedAuthenticatedScratchRecordByteLength;
        const physicalAccounting = {
            deletedByteLength: recordByteLength * 4,
            deletionCount: 4,
            deletionDurationMilliseconds: 2,
            physicalReadByteLength: recordByteLength * 8,
            physicalReadCallCount: 32,
            physicalQuotaByteLength: 1_073_741_824,
            physicalQuotaHeadroomByteLength: 1_000_000_000,
            physicalQuotaReservedByteLength: 8_000_000,
            physicalStoredEndByteLength: 2_048,
            physicalStoredPeakByteLength: recordByteLength * 4,
            physicalStoredStartByteLength: 1_024,
            physicalWriteByteLength: recordByteLength * 4,
            physicalWriteCallCount: 20,
            repairHashCallCount: 20,
            repairHashedByteLength: 50_000,
            storageRequestCount: 80,
            storageTransactionCount: 24,
        };
        const evidence = {
            boundaryCopies: {
                byteLengthPerCopy: recordByteLength,
                checksumHex: '1234abcd',
                copyFromWasmElapsedMilliseconds: 1,
                copyIntoWasmElapsedMilliseconds: 1,
                iterationCount: desktopBrowserBoundaryCopyIterationCount,
                wasmMemoryByteLengthAfter: 4_194_304,
                wasmMemoryByteLengthBefore: 1_048_576,
            },
            browserEngine: 'chromium',
            browserUserAgent: 'test browser',
            primitiveCases,
            schemaVersion: 1,
            storage: {
                cleanupElapsedMilliseconds: 1,
                iterationCount: 4,
                physicalAccounting,
                readElapsedMilliseconds: 2,
                readPassCount: 2,
                recordByteLength,
                storageEstimateAfter: { quota: 1_073_741_824, usage: 2_048 },
                storageEstimateBefore: { quota: 1_073_741_824, usage: 0 },
                writeElapsedMilliseconds: 3,
            },
        };

        expect(
            validateDesktopBrowserPrimitiveMeasurementEvidence(
                evidence,
                'chromium',
            ).storage.recordByteLength,
        ).toBe(recordByteLength);

        const shortenedRead = structuredClone(evidence);
        shortenedRead.storage.physicalAccounting.physicalReadByteLength -= 1;
        expect(() =>
            validateDesktopBrowserPrimitiveMeasurementEvidence(shortenedRead),
        ).toThrow(/exact scratch-record geometry/u);

        const changedExtent = structuredClone(evidence);
        changedExtent.boundaryCopies.byteLengthPerCopy -= 1;
        expect(() =>
            validateDesktopBrowserPrimitiveMeasurementEvidence(changedExtent),
        ).toThrow(/boundary-copy geometry/u);

        expect(
            validateDesktopBrowserBoundaryCopyMeasurement(
                evidence.boundaryCopies,
                selectedAuthenticatedScratchRecordByteLength,
            ).iterationCount,
        ).toBe(desktopBrowserBoundaryCopyIterationCount);

        expect(
            validateDesktopBrowserAuthenticatedStorageMeasurement(
                evidence.storage,
                selectedAuthenticatedScratchRecordByteLength,
            ).physicalAccounting.physicalStoredPeakByteLength,
        ).toBe(recordByteLength * 4);

        const nativeEvidence = {
            primitiveCases: primitiveMeasurementCaseCatalog.map((entry) =>
                validatePrimitiveMeasurementRecord(
                    recordFor(entry.caseIdentifier, 'release-native'),
                    'release-native',
                ),
            ),
            schemaVersion: 1 as const,
        };
        const chromiumEvidence =
            validateDesktopBrowserPrimitiveMeasurementEvidence(
                evidence,
                'chromium',
            );
        const measurementWasm = {
            byteLength: 1_000_000,
            normalizedSha256Hex: 'a'.repeat(64),
            rawSha256Hex: 'b'.repeat(64),
        };
        const singleBuildBundle =
            validateDesktopBrowserPrimitiveMeasurementBundle({
                browserEvidence: [evidence],
                measurementWasm,
                schemaVersion: 1,
            });
        expect(singleBuildBundle.browserEvidence).toHaveLength(1);
        expect(
            singleBuildBundle.browserEvidence[0]?.primitiveCases.map(
                (measurement) => measurement.record.caseIdentifier,
            ),
        ).toEqual(
            primitiveMeasurementCaseCatalog.map(
                (entry) => entry.caseIdentifier,
            ),
        );

        const incompleteBrowserEvidence = structuredClone(evidence);
        incompleteBrowserEvidence.primitiveCases.pop();
        expect(() =>
            validateDesktopBrowserPrimitiveMeasurementBundle({
                browserEvidence: [incompleteBrowserEvidence],
                measurementWasm,
                schemaVersion: 1,
            }),
        ).toThrow(/incomplete/u);

        const reorderedBrowserEvidence = structuredClone(evidence);
        const firstCase = reorderedBrowserEvidence.primitiveCases[0];
        const secondCase = reorderedBrowserEvidence.primitiveCases[1];
        if (firstCase === undefined || secondCase === undefined) {
            throw new Error('Test browser cases are absent.');
        }
        [
            reorderedBrowserEvidence.primitiveCases[0],
            reorderedBrowserEvidence.primitiveCases[1],
        ] = [secondCase, firstCase];
        expect(() =>
            validateDesktopBrowserPrimitiveMeasurementBundle({
                browserEvidence: [reorderedBrowserEvidence],
                measurementWasm,
                schemaVersion: 1,
            }),
        ).toThrow(/reordered/u);
        const projection = deriveVssBaseMaterializationProjection({
            browserEvidence: [chromiumEvidence],
            nativeEvidence,
        });
        const modeledCheckpoint = projection.checkpointCandidates.find(
            (candidate) => candidate.modeled === true,
        );
        expect(projection.schemaVersion).toBe(3);
        expect(projection.currentTwoPass.sourceReplayCount).toBe(576_576);
        expect(projection.fusedRadix51Candidate).toMatchObject({
            basePhaseRowCount: 42,
            completePhaseRowCount: 52,
            physicalRowWidth: 64,
            productionRecipeCount: 2_627,
            proverColumnDegreeBoundExclusive: 18_432,
            quotientPhaseRowCount: 10,
            rangeDigitRadix: 51,
            relationTraceValueCount: 16_384,
            retainedCoefficientGroupByteLength: 9_437_184,
            tracePackingFactor: 1,
            transportedValueByteLength: 13_958_643_712,
        });
        const fusedCandidateTargetProjections = projection.fusedRadix51Candidate
            .targetProjections as
            | Array<{
                  currentOwnerTotalNanoseconds: number;
                  fusedOwnerTotalNanoseconds: number;
                  ownerReductionFactor: number;
                  owners: {
                      rowLaneOwnerCaseIdentifier: number;
                      totalNanoseconds: number;
                  };
              }>
            | undefined;
        expect(fusedCandidateTargetProjections).toHaveLength(2);
        expect(
            fusedCandidateTargetProjections?.every(
                (target) =>
                    target.owners.rowLaneOwnerCaseIdentifier === 12 &&
                    target.owners.totalNanoseconds ===
                        target.fusedOwnerTotalNanoseconds &&
                    target.ownerReductionFactor > 1 &&
                    target.fusedOwnerTotalNanoseconds <
                        target.currentOwnerTotalNanoseconds,
            ),
        ).toBe(true);
        expect(projection.modeledRelationReplayCandidate).toMatchObject({
            coefficientChunkCountPerSource: 9,
            logicalRowChunkByteLength: 16_777_216,
            maximumRangeConstraintNumeratorDegree: 792_573,
            openingDegreeBoundExclusive: 2_097_152,
            physicalRowWidth: 64,
            proverColumnCount: 753,
            proverColumnDegreeBoundExclusive: 264_192,
            relationTraceValueCount: 262_144,
            retainedCoefficientGroupByteLength: 135_266_304,
            rowCodeInverseRate: 4,
            rowCount: 108,
            sourceTraceValueGenerationCount: 394_788_864,
            tracePackingFactor: 16,
            transportedValueByteLength: 28_991_029_248,
        });
        const modeledCandidateTargetProjections = projection
            .modeledRelationReplayCandidate.targetProjections as
            | Array<{
                  currentOwnerTotalNanoseconds: number;
                  modeledOwners: {
                      rowLaneOwnerCaseIdentifier: number;
                      totalNanoseconds: number;
                  };
              }>
            | undefined;
        expect(modeledCandidateTargetProjections).toHaveLength(2);
        expect(
            modeledCandidateTargetProjections?.every(
                (target) =>
                    target.modeledOwners.rowLaneOwnerCaseIdentifier === 10 &&
                    target.modeledOwners.totalNanoseconds <
                        target.currentOwnerTotalNanoseconds,
            ),
        ).toBe(true);
        expect(modeledCheckpoint).toMatchObject({
            checkpointLevel: 2,
            checkpointNodeCount: 4_194_304,
            checkpointPlaintextByteLength: 268_435_456,
            engineeringReviewRequired: false,
            maximumRecomputedLeafCount: 1_548,
            persistedScratchByteLength: 268_576_000,
            scratchRecordCount: 256,
            selectiveEvaluationBenchmarkRequired: false,
            reusableStrategyMaximumRecomputedLeafCount: 1_572,
            withinAutomaticScratchBound: true,
            withinHardScratchBound: true,
        });
        expect(
            (
                modeledCheckpoint?.optimizedWork as
                    | { sourceReplayCount: number }
                    | undefined
            )?.sourceReplayCount,
        ).toBe(297_297);

        const targetSizedChromiumEvidence = structuredClone(evidence);
        const targetSizedVssRecord = targetSizedChromiumEvidence
            .primitiveCases[4].record as {
            dimensions: Array<{ name: string; value: number }>;
            modeledPeakLiveByteLength: number;
        };
        const targetSizedRetainedInput = targetSizedVssRecord.dimensions.find(
            (dimension) => dimension.name === 'retainedInputByteLength',
        );
        const targetSizedTraceValueCount = targetSizedVssRecord.dimensions.find(
            (dimension) => dimension.name === 'traceValueCount',
        );
        if (
            targetSizedRetainedInput === undefined ||
            targetSizedTraceValueCount === undefined
        ) {
            throw new Error(
                'Test target-sized VSS memory dimensions are absent.',
            );
        }
        targetSizedRetainedInput.value -= 240_976;
        targetSizedVssRecord.modeledPeakLiveByteLength =
            targetSizedRetainedInput.value +
            targetSizedTraceValueCount.value * 8;
        expect(() =>
            deriveVssBaseMaterializationProjection({
                browserEvidence: [
                    validateDesktopBrowserPrimitiveMeasurementEvidence(
                        targetSizedChromiumEvidence,
                        'chromium',
                    ),
                ],
                nativeEvidence,
            }),
        ).not.toThrow();

        const wrongBrowserChecksum = structuredClone(evidence);
        wrongBrowserChecksum.primitiveCases[4].record.checksumHex =
            'fedcba9876543210';
        expect(() =>
            deriveVssBaseMaterializationProjection({
                browserEvidence: [
                    validateDesktopBrowserPrimitiveMeasurementEvidence(
                        wrongBrowserChecksum,
                        'chromium',
                    ),
                ],
                nativeEvidence,
            }),
        ).toThrow(/differs across native and WASM/u);
    });

    it('selects Chromium primitive-measurement components and cases', () => {
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([]).browserEngines,
        ).toEqual(['chromium']);
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'authenticated-storage',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            measurementComponent: 'authenticated-storage',
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'boundary-copies',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            measurementComponent: 'boundary-copies',
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'reuse-wasm',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            reuseMeasurementWasm: true,
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-5',
                'reuse-wasm',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [5],
            reuseMeasurementWasm: true,
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-6',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [6],
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-8',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [8],
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-8',
                'reuse-wasm',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [8],
            reuseMeasurementWasm: true,
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-9',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [9],
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-10',
                'reuse-wasm',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [10],
            reuseMeasurementWasm: true,
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-11',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [11],
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-12',
                'reuse-wasm',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [12],
            reuseMeasurementWasm: true,
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-13',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [13],
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-14',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [14],
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-15',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [15],
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-16',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [16],
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-17',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [17],
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-18',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [18],
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-19',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [19],
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-20',
                'reuse-wasm',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [20],
            reuseMeasurementWasm: true,
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'compact-lookup-projection-owners',
                'reuse-wasm',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [14, 17],
            reuseMeasurementWasm: true,
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'fused-radix-51-projection-owners',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifiers: [1, 2, 3, 4, 5, 8, 11, 12],
        });
        expect(() =>
            parseDesktopBrowserPrimitiveMeasurementArguments(['other-browser']),
        ).toThrow(/only chromium/u);
        expect(() =>
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'other-browser',
            ]),
        ).toThrow(/accepts chromium/u);
        expect(() =>
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'unknown-component',
            ]),
        ).toThrow(/authenticated-storage/u);
        expect(() =>
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-7',
            ]),
        ).toThrow(/authenticated-storage/u);
        expect(() =>
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-8',
                'boundary-copies',
            ]),
        ).toThrow(/optional reuse-wasm/u);
    });

    it('binds focused browser evidence to one exact catalog case and WASM identity', () => {
        const focusedEvidence = {
            browserEngine: 'chromium',
            browserUserAgent: 'focused browser',
            primitiveCase: {
                record: recordFor(8),
                wallElapsedMilliseconds: 10,
                wasmMemoryByteLengthAfter: 33_554_432,
                wasmMemoryByteLengthBefore: 1_048_576,
            },
            schemaVersion: 1,
        };
        expect(
            validateDesktopBrowserFocusedPrimitiveMeasurementEvidence(
                focusedEvidence,
                'chromium',
                8,
            ).primitiveCase.record.caseIdentifier,
        ).toBe(8);
        expect(
            validateDesktopBrowserFocusedPrimitiveMeasurementBundle(
                {
                    focusedPrimitiveEvidence: [focusedEvidence],
                    measurementWasm: {
                        byteLength: 1_000_000,
                        normalizedSha256Hex: 'a'.repeat(64),
                        rawSha256Hex: 'b'.repeat(64),
                    },
                    schemaVersion: 1,
                },
                8,
            ).focusedPrimitiveEvidence,
        ).toHaveLength(1);
        const projectionOwnerEvidence =
            vssFusedRadix51ProjectionOwnerCaseIdentifiers.map(
                (caseIdentifier) => ({
                    ...focusedEvidence,
                    primitiveCase: {
                        ...focusedEvidence.primitiveCase,
                        record: recordFor(caseIdentifier),
                    },
                }),
            );
        expect(
            validateDesktopBrowserFocusedPrimitiveMeasurementBundle(
                {
                    focusedPrimitiveEvidence: projectionOwnerEvidence,
                    measurementWasm: {
                        byteLength: 1_000_000,
                        normalizedSha256Hex: 'a'.repeat(64),
                        rawSha256Hex: 'b'.repeat(64),
                    },
                    schemaVersion: 1,
                },
                vssFusedRadix51ProjectionOwnerCaseIdentifiers,
            ).focusedPrimitiveEvidence.map(
                (evidence) => evidence.primitiveCase.record.caseIdentifier,
            ),
        ).toEqual(vssFusedRadix51ProjectionOwnerCaseIdentifiers);
        expect(() =>
            validateDesktopBrowserFocusedPrimitiveMeasurementBundle(
                {
                    focusedPrimitiveEvidence: projectionOwnerEvidence.slice(
                        0,
                        -1,
                    ),
                    measurementWasm: {
                        byteLength: 1_000_000,
                        normalizedSha256Hex: 'a'.repeat(64),
                        rawSha256Hex: 'b'.repeat(64),
                    },
                    schemaVersion: 1,
                },
                vssFusedRadix51ProjectionOwnerCaseIdentifiers,
            ),
        ).toThrow(/exact canonical case set/u);
        expect(() =>
            validateDesktopBrowserFocusedPrimitiveMeasurementBundle(
                {
                    focusedPrimitiveEvidence: projectionOwnerEvidence,
                    measurementWasm: {
                        byteLength: 1_000_000,
                        normalizedSha256Hex: 'a'.repeat(64),
                        rawSha256Hex: 'b'.repeat(64),
                    },
                    schemaVersion: 1,
                },
                [2, 1],
            ),
        ).toThrow(/noncanonical/u);

        expect(() =>
            validateDesktopBrowserFocusedPrimitiveMeasurementEvidence(
                { ...focusedEvidence, browserEngine: 'other-browser' },
                undefined,
                8,
            ),
        ).toThrow(/engine or user agent/u);
        expect(() =>
            validateDesktopBrowserFocusedPrimitiveMeasurementEvidence(
                focusedEvidence,
                'chromium',
                7,
            ),
        ).toThrow(/instead of case 7/u);

        const shrinkingMemory = structuredClone(focusedEvidence);
        shrinkingMemory.primitiveCase.wasmMemoryByteLengthAfter = 1;
        expect(() =>
            validateDesktopBrowserFocusedPrimitiveMeasurementEvidence(
                shrinkingMemory,
                'chromium',
                8,
            ),
        ).toThrow(/memory shrank/u);

        const unknownField = {
            ...structuredClone(focusedEvidence),
            producerValidity: true,
        };
        expect(() =>
            validateDesktopBrowserFocusedPrimitiveMeasurementEvidence(
                unknownField,
                'chromium',
                8,
            ),
        ).toThrow(/noncanonical fields/u);
    });

    it('derives the fused radix-51 comparison only from exact native and browser owner sets', () => {
        const nativeEvidence =
            validateReleaseNativePrimitiveMeasurementEvidence(
                {
                    primitiveCases:
                        vssFusedRadix51ProjectionOwnerCaseIdentifiers.map(
                            (caseIdentifier) =>
                                recordFor(caseIdentifier, 'release-native'),
                        ),
                    schemaVersion: 1,
                },
                false,
                vssFusedRadix51ProjectionOwnerCaseIdentifiers,
            );
        const browserEvidence =
            vssFusedRadix51ProjectionOwnerCaseIdentifiers.map(
                (caseIdentifier) =>
                    validateDesktopBrowserFocusedPrimitiveMeasurementEvidence(
                        {
                            browserEngine: 'chromium',
                            browserUserAgent: 'chromium test',
                            primitiveCase: {
                                record: recordFor(caseIdentifier),
                                wallElapsedMilliseconds: caseIdentifier,
                                wasmMemoryByteLengthAfter: 67_108_864,
                                wasmMemoryByteLengthBefore: 16_777_216,
                            },
                            schemaVersion: 1,
                        },
                        'chromium',
                        caseIdentifier,
                    ),
            );
        const projection = deriveVssFusedRadix51OwnerProjection({
            browserEvidence,
            nativeEvidence,
        });
        expect(projection).toMatchObject({
            candidateWork: {
                laneDftCount: 3_328,
                sourceReplayCount: 5_254,
            },
            schemaVersion: 1,
            selectedWork: {
                laneDftCount: 72_192,
                sourceReplayCount: 576_576,
            },
        });
        expect(projection.targetProjections).toHaveLength(2);
        expect(
            projection.targetProjections.map((target) =>
                Number(target.ownerReductionFactor),
            ),
        ).toEqual(
            expect.arrayContaining([expect.any(Number), expect.any(Number)]),
        );

        expect(() =>
            deriveVssFusedRadix51OwnerProjection({
                browserEvidence: [
                    browserEvidence[1],
                    browserEvidence[0],
                    ...browserEvidence.slice(2),
                ],
                nativeEvidence,
            }),
        ).toThrow(/noncanonical/u);
        const changedChecksumEvidence = browserEvidence.map(
            (evidence, evidenceIndex) =>
                evidenceIndex === 0
                    ? {
                          ...evidence,
                          primitiveCase: {
                              ...evidence.primitiveCase,
                              record: {
                                  ...evidence.primitiveCase.record,
                                  checksumHex: '0'.repeat(16),
                              },
                          },
                      }
                    : evidence,
        );
        expect(() =>
            deriveVssFusedRadix51OwnerProjection({
                browserEvidence: changedChecksumEvidence,
                nativeEvidence,
            }),
        ).toThrow(/differs across native and WASM/u);
    });

    it('makes cleanup batches admissible under the authenticated storage transaction limits', () => {
        const configuration =
            deriveDesktopBrowserAuthenticatedStorageConfiguration(
                selectedAuthenticatedScratchRecordByteLength,
            );

        expect(
            configuration.storeLimits.maximumLeaseCountPerTransaction,
        ).toBeGreaterThanOrEqual(
            configuration.reservation.maximumDeletionBatchRecordCount,
        );
        expect(
            configuration.storeLimits.maximumTransactionByteLength,
        ).toBeGreaterThanOrEqual(selectedAuthenticatedScratchRecordByteLength);
        expect(
            configuration.reservation.maximumAdditionalStoredValueByteLength,
        ).toBeGreaterThan(selectedAuthenticatedScratchRecordByteLength * 4);
    });
});
