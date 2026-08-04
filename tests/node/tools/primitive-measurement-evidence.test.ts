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
    type PrimitiveMeasurementRecord,
} from '#tools/ci/primitive-measurement-evidence';
import { parseDesktopBrowserPrimitiveMeasurementArguments } from '#tools/ci/run-desktop-browser-primitive-measurements';
import { deriveVssBaseMaterializationProjection } from '#tools/ci/vss-base-materialization-projection';

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
    if (caseIdentifier === 9) {
        dimensions.push(
            { name: 'retainedInputByteLength', value: 2_097_152 },
            {
                name: 'retainedGroupHeaderByteLength',
                value: executionTarget === 'release-native' ? 1_536 : 768,
            },
        );
    }
    if (caseIdentifier === 10) {
        const retainedInputByteLength = 2_097_152;
        const retainedGroupHeaderByteLength =
            executionTarget === 'release-native' ? 1_536 : 768;
        const retainedGroupContainerByteLength =
            executionTarget === 'release-native' ? 32 : 24;
        const ownedFixedStateByteLength =
            executionTarget === 'release-native' ? 256 : 192;
        const retainedCoefficientPayloadByteLength = 135_266_304;
        const replayBufferByteLength = 2_097_152;
        const rowWorkingBufferByteLength = 33_554_432;
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
                : caseIdentifier === 9
                  ? retainedInputByteLength! +
                    retainedCoefficientPayloadByteLength! +
                    dimensions.find(
                        (dimension) =>
                            dimension.name === 'replayBufferByteLength',
                    )!.value +
                    retainedGroupHeaderByteLength!
                  : caseIdentifier === 10
                    ? Math.max(
                          materializationPeakLiveByteLength!,
                          stripePeakLiveByteLength!,
                      )
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
        const firefoxEvidence =
            validateDesktopBrowserPrimitiveMeasurementEvidence(
                { ...structuredClone(evidence), browserEngine: 'firefox' },
                'firefox',
            );
        const measurementWasm = {
            byteLength: 1_000_000,
            normalizedSha256Hex: 'a'.repeat(64),
            rawSha256Hex: 'b'.repeat(64),
        };
        const singleBuildBundle =
            validateDesktopBrowserPrimitiveMeasurementBundle({
                browserEvidence: [
                    evidence,
                    {
                        ...structuredClone(evidence),
                        browserEngine: 'firefox',
                    },
                ],
                measurementWasm,
                schemaVersion: 1,
            });
        expect(singleBuildBundle.browserEvidence).toHaveLength(2);
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
            browserEvidence: [chromiumEvidence, firefoxEvidence],
            nativeEvidence,
        });
        const modeledCheckpoint = projection.checkpointCandidates.find(
            (candidate) => candidate.modeled === true,
        );
        expect(projection.schemaVersion).toBe(2);
        expect(projection.currentTwoPass.sourceReplayCount).toBe(576_576);
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
        expect(modeledCandidateTargetProjections).toHaveLength(3);
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

        const targetSizedFirefoxEvidence = structuredClone(evidence);
        targetSizedFirefoxEvidence.browserEngine = 'firefox';
        const targetSizedVssRecord = targetSizedFirefoxEvidence
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
                    chromiumEvidence,
                    validateDesktopBrowserPrimitiveMeasurementEvidence(
                        targetSizedFirefoxEvidence,
                        'firefox',
                    ),
                ],
                nativeEvidence,
            }),
        ).not.toThrow();

        const wrongBrowserChecksum = structuredClone(evidence);
        wrongBrowserChecksum.browserEngine = 'firefox';
        wrongBrowserChecksum.primitiveCases[4].record.checksumHex =
            'fedcba9876543210';
        expect(() =>
            deriveVssBaseMaterializationProjection({
                browserEvidence: [
                    chromiumEvidence,
                    validateDesktopBrowserPrimitiveMeasurementEvidence(
                        wrongBrowserChecksum,
                        'firefox',
                    ),
                ],
                nativeEvidence,
            }),
        ).toThrow(/differs across native and WASM/u);
    });

    it('selects one focused browser engine or the complete two-engine lane', () => {
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([]).browserEngines,
        ).toEqual(['chromium', 'firefox']);
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments(['--', 'firefox'])
                .browserEngines,
        ).toEqual(['firefox']);
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
                'firefox',
                'boundary-copies',
            ]),
        ).toEqual({
            browserEngines: ['firefox'],
            measurementComponent: 'boundary-copies',
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'firefox',
                'reuse-wasm',
            ]),
        ).toEqual({
            browserEngines: ['firefox'],
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
            focusedCaseIdentifier: 5,
            reuseMeasurementWasm: true,
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-8',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifier: 8,
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'firefox',
                'case-8',
                'reuse-wasm',
            ]),
        ).toEqual({
            browserEngines: ['firefox'],
            focusedCaseIdentifier: 8,
            reuseMeasurementWasm: true,
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'case-9',
            ]),
        ).toEqual({
            browserEngines: ['chromium'],
            focusedCaseIdentifier: 9,
        });
        expect(
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'firefox',
                'case-10',
                'reuse-wasm',
            ]),
        ).toEqual({
            browserEngines: ['firefox'],
            focusedCaseIdentifier: 10,
            reuseMeasurementWasm: true,
        });
        expect(() =>
            parseDesktopBrowserPrimitiveMeasurementArguments(['webkit']),
        ).toThrow(/chromium or firefox/u);
        expect(() =>
            parseDesktopBrowserPrimitiveMeasurementArguments([
                'chromium',
                'firefox',
            ]),
        ).toThrow(/accepts chromium or firefox/u);
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

        expect(() =>
            validateDesktopBrowserFocusedPrimitiveMeasurementEvidence(
                focusedEvidence,
                'firefox',
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
