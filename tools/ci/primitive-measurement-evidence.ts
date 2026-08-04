export type PrimitiveMeasurementDimension = Readonly<{
    name: string;
    value: number;
}>;

export type PrimitiveMeasurementRecord = Readonly<{
    caseIdentifier: number;
    caseName: string;
    checksumHex: string;
    dimensions: readonly PrimitiveMeasurementDimension[];
    elapsedNanoseconds: number;
    executionTarget: 'release-native' | 'wasm32-unknown-unknown';
    iterationCount: number;
    modeledPeakLiveByteLength: number;
    schemaVersion: 2;
}>;

export type DesktopBrowserPrimitiveCaseMeasurement = Readonly<{
    record: PrimitiveMeasurementRecord;
    wallElapsedMilliseconds: number;
    wasmMemoryByteLengthAfter: number;
    wasmMemoryByteLengthBefore: number;
}>;

export type DesktopBrowserFocusedPrimitiveMeasurementEvidence = Readonly<{
    browserEngine: 'chromium' | 'firefox';
    browserUserAgent: string;
    primitiveCase: DesktopBrowserPrimitiveCaseMeasurement;
    schemaVersion: 1;
}>;

export type DesktopBrowserBoundaryCopyMeasurement = Readonly<{
    byteLengthPerCopy: number;
    checksumHex: string;
    copyFromWasmElapsedMilliseconds: number;
    copyIntoWasmElapsedMilliseconds: number;
    iterationCount: number;
    wasmMemoryByteLengthAfter: number;
    wasmMemoryByteLengthBefore: number;
}>;

export type PrimitiveStoragePhysicalAccounting = Readonly<{
    deletedByteLength: number;
    deletionCount: number;
    deletionDurationMilliseconds: number;
    physicalReadByteLength: number;
    physicalReadCallCount: number;
    physicalQuotaByteLength: number;
    physicalQuotaHeadroomByteLength: number;
    physicalQuotaReservedByteLength: number;
    physicalStoredEndByteLength: number;
    physicalStoredPeakByteLength: number;
    physicalStoredStartByteLength: number;
    physicalWriteByteLength: number;
    physicalWriteCallCount: number;
    repairHashCallCount: number;
    repairHashedByteLength: number;
    storageRequestCount: number;
    storageTransactionCount: number;
}>;

export type DesktopBrowserAuthenticatedStorageMeasurement = Readonly<{
    cleanupElapsedMilliseconds: number;
    iterationCount: number;
    physicalAccounting: PrimitiveStoragePhysicalAccounting;
    readElapsedMilliseconds: number;
    readPassCount: number;
    recordByteLength: number;
    storageEstimateAfter: Readonly<{
        quota?: number;
        usage?: number;
    }>;
    storageEstimateBefore: Readonly<{
        quota?: number;
        usage?: number;
    }>;
    writeElapsedMilliseconds: number;
}>;

export type DesktopBrowserPrimitiveMeasurementEvidence = Readonly<{
    boundaryCopies: DesktopBrowserBoundaryCopyMeasurement;
    browserEngine: 'chromium' | 'firefox';
    browserUserAgent: string;
    primitiveCases: readonly DesktopBrowserPrimitiveCaseMeasurement[];
    schemaVersion: 1;
    storage: DesktopBrowserAuthenticatedStorageMeasurement;
}>;

export type ReleaseNativePrimitiveMeasurementEvidence = Readonly<{
    primitiveCases: readonly PrimitiveMeasurementRecord[];
    schemaVersion: 1;
}>;

export type DesktopBrowserPrimitiveMeasurementBundle = Readonly<{
    browserEvidence: readonly DesktopBrowserPrimitiveMeasurementEvidence[];
    measurementWasm: Readonly<{
        byteLength: number;
        normalizedSha256Hex: string;
        rawSha256Hex: string;
    }>;
    schemaVersion: 1;
}>;

export type DesktopBrowserFocusedPrimitiveMeasurementBundle = Readonly<{
    focusedPrimitiveEvidence: readonly DesktopBrowserFocusedPrimitiveMeasurementEvidence[];
    measurementWasm: DesktopBrowserPrimitiveMeasurementBundle['measurementWasm'];
    schemaVersion: 1;
}>;

export const selectedAuthenticatedScratchRecordByteLength = 1_049_125;
export const desktopBrowserBoundaryCopyIterationCount = 256;
export const vssFusedRadix51ProjectionOwnerCaseIdentifiers = Object.freeze([
    1, 2, 3, 4, 5, 8, 11, 12,
] as const);

export const primitiveMeasurementCaseCatalog = Object.freeze([
    Object.freeze({
        caseIdentifier: 1,
        caseName: 'bounded-phase-lane-dft',
        expectedIterationCount: 1,
        requiredDimensions: Object.freeze({
            butterflyCount: 4_980_736,
            fullDomainSize: 16_777_216,
            laneColumnCount: 524_288,
        }),
    }),
    Object.freeze({
        caseIdentifier: 2,
        caseName: 'salted-phase-column-leaf',
        expectedIterationCount: 512,
        requiredDimensions: Object.freeze({
            keccakPermutationCount: 34_816,
            logicalLeafWidth: 1_128,
            saltByteLength: 128,
        }),
    }),
    Object.freeze({
        caseIdentifier: 3,
        caseName: 'private-leaf-salt-kmac',
        expectedIterationCount: 4_096,
        requiredDimensions: Object.freeze({
            leafCount: 16_777_216,
            logicalLeafWidth: 1_128,
            saltByteLength: 128,
        }),
    }),
    Object.freeze({
        caseIdentifier: 4,
        caseName: 'five-level-digest-carry',
        expectedIterationCount: 32_768,
        requiredDimensions: Object.freeze({
            merkleParentHashCount: 163_840,
        }),
    }),
    Object.freeze({
        caseIdentifier: 5,
        caseName: 'selected-vss-source-replay',
        expectedIterationCount: 4,
        requiredDimensions: Object.freeze({
            basePhaseBoundSourceReplayCount: 0,
            basePhaseCoefficientChunkCountPerSource: 3,
            basePhaseDirectSourceColumnCountPerLane: 3_003,
            basePhaseDirectSourceChunkCountPerLane: 9_009,
            basePhaseLaneCount: 32,
            basePhaseLogicalPolynomialCoefficientCount: 32_768,
            basePhaseLogicalChunkCountPerLane: 9_009,
            basePhaseMaterializationPassCount: 2,
            basePhaseMaximumRangeConstraintNumeratorDegree: 202_749,
            basePhaseOpeningQueryCount: 387,
            basePhasePhysicalRowWidth: 8,
            basePhaseProverColumnDegreeBoundExclusive: 67_584,
            basePhaseReversedPolynomialReconstructionCount: 0,
            basePhaseReversedSourceChunkCountPerLane: 0,
            basePhaseRowCount: 1_128,
            basePhaseTraceMaskDegreeBoundExclusive: 2_048,
            basePhaseTracePackingFactor: 4,
            aggregateWidePadQueryCount: 393,
            logicalRootCount: 112,
            modeledCandidateButterflyCount: 34_426_847_232,
            modeledCandidateCoefficientFoldCount: 25_367_150_592,
            modeledCandidateCoefficientChunkCountPerSource: 9,
            modeledCandidateColumnValueDeliveryCount: 3_623_878_656,
            modeledCandidateCosetMultiplicationCount: 3_623_878_656,
            modeledCandidateLaneDftCount: 6_912,
            modeledCandidateLeafHashQueryCount: 33_554_432,
            modeledCandidateLogicalRowChunkByteLength: 16_777_216,
            modeledCandidateMaterialGroupCount: 8,
            modeledCandidateMaterialProverColumnCount: 720,
            modeledCandidateMaximumRangeConstraintNumeratorDegree: 792_573,
            modeledCandidateMerkleParentHashQueryCount: 33_554_430,
            modeledCandidateOpeningDegreeBoundExclusive: 2_097_152,
            modeledCandidateOpeningPointCount: 24,
            modeledCandidateBoundReductionAggregateColumnCount: 1,
            modeledCandidateAggregateColumnRoleCount: 25,
            modeledCandidateAggregateTableWidth: 4,
            modeledCandidateDirectAggregateColumnRoleCount: 25,
            modeledCandidateQuotientAggregateColumnRoleCount: 2,
            modeledCandidateQuotientSourceDegreeBoundExclusive: 4_194_304,
            modeledCandidateQuotientOpeningClaimCount: 24,
            modeledCandidateBatchedQuotientDegreeBoundExclusive: 4_194_303,
            modeledCandidateQuotientDiscrepancyNumeratorDegreeBoundInclusive: 4_194_326,
            modeledCandidateQuotientQueryDomainSize: 16_777_216,
            modeledCandidateQuotientQueryCount: 387,
            modeledCandidateQuotientAgreementCeiling: 4_194_326,
            modeledCandidateQuotientConstructionIdentityHashByteLength: 64,
            modeledCandidateQuotientOracleEquationCatalogHashByteLength: 64,
            modeledCandidateQuotientPhysicalRowWitnessVariableCount: 21,
            modeledCandidateQuotientTableVariableCount: 22,
            modeledCandidateQuotientPolynomialCommitmentVariableCount: 24,
            modeledCandidateQuotientRowCodeLogInverseRate: 2,
            modeledCandidateQuotientAggregateLogicalColumnCount: 2,
            modeledCandidateQuotientAggregateTableWidth: 4,
            modeledCandidateQuotientOuterOpeningBatchCount: 387,
            modeledCandidateQuotientBoundReductionBlockCount: 1,
            modeledCandidateQuotientBoundQueryCount: 266,
            modeledCandidateQuotientBoundDegreeTestCount: 4,
            modeledCandidateQuotientBoundOpeningBatchCount: 536,
            modeledCandidatePhysicalRowWidth: 64,
            modeledCandidatePrivateHighHalfValueGenerationCount: 14_495_514_624,
            modeledCandidatePrivateLeafSaltDerivationCount: 33_554_432,
            modeledCandidateProverColumnCount: 753,
            modeledCandidateProverColumnDegreeBoundExclusive: 264_192,
            modeledCandidateQuotientGroupCount: 10,
            modeledCandidateQuotientProverColumnCount: 30,
            modeledCandidateRelationTraceValueCount: 262_144,
            modeledCandidateRetainedCoefficientGroupByteLength: 135_266_304,
            modeledCandidateRetainedSourceMaterializationCount: 1_506,
            modeledCandidateRowCodeInverseRate: 4,
            modeledCandidateRowCount: 108,
            modeledCandidateSaltedLeafKeccakPermutationCount: 268_435_456,
            modeledCandidateShiftSelectorColumnCount: 3,
            modeledCandidateSourceTraceValueGenerationCount: 394_788_864,
            modeledCandidateTracePackingFactor: 16,
            modeledCandidateTransportedValueByteLength: 28_991_029_248,
            singleAggregateCandidateAggregateColumnRoleCount: 6,
            singleAggregateCandidateAggregateTableWidth: 8,
            singleAggregateCandidateBasePhaseAlgorithmLiveSetByteLength: 289_406_976,
            singleAggregateCandidateBasePhaseDigestPlaneByteLength: 167_772_160,
            singleAggregateCandidateBasePhaseHashStateByteLength: 104_857_600,
            singleAggregateCandidateBasePhaseWorkingBufferByteLength: 16_777_216,
            singleAggregateCandidateCheckpointCount: 11,
            singleAggregateCandidateConstructionIdentityByteLength: 2_239_344,
            singleAggregateCandidateConstructionIdentityHashByteLength: 64,
            singleAggregateCandidateLaneDftCount: 21_184,
            singleAggregateCandidateLogicalVerifierMessageCount: 12_487,
            singleAggregateCandidateMaximumTranscriptHashQueryCount: 1_672_271,
            singleAggregateCandidateOpeningBatchCount: 928,
            singleAggregateCandidateOpeningDegreeBoundExclusive: 1_048_576,
            singleAggregateCandidateOracleEquationCatalogHashByteLength: 64,
            singleAggregateCandidatePhaseOrderCount: 2,
            singleAggregateCandidatePhysicalRowWidth: 32,
            singleAggregateCandidatePhysicalRowWitnessVariableCount: 20,
            singleAggregateCandidatePolynomialCommitmentVariableCount: 24,
            singleAggregateCandidateProofSectionCount: 121,
            singleAggregateCandidateRowCodeLogInverseRate: 3,
            singleAggregateCandidateRowCount: 331,
            singleAggregateCandidateSaltedLeafKeccakPermutationCount: 704_643_072,
            singleAggregateCandidateTableVariableCount: 21,
            singleAggregateCandidateTracePackingFactor: 1,
            singleAggregateCandidateTranscriptOperationCount: 2_802,
            traceValueCount: 65_536,
        }),
    }),
    Object.freeze({
        caseIdentifier: 6,
        caseName: 'authenticated-scratch-record-codec',
        expectedIterationCount: 8,
        requiredDimensions: Object.freeze({
            canonicalEnvelopeByteLength:
                selectedAuthenticatedScratchRecordByteLength,
            plaintextByteLength: 1_048_576,
            roundTripCount: 8,
        }),
    }),
    Object.freeze({
        caseIdentifier: 7,
        caseName: 'selected-vss-checkpoint-opening-lane-dfts',
        expectedIterationCount: 32,
        requiredDimensions: Object.freeze({
            checkpointLeafCount: 4,
            checkpointLevel: 2,
            executedButterflyCount: 63_011_316,
            fullButterflyCount: 159_383_552,
            fullDomainSize: 16_777_216,
            higherOutputLaneCount: 12,
            higherSelectedOutputCount: 49,
            laneColumnCount: 524_288,
            laneCount: 32,
            lowerOutputLaneCount: 20,
            lowerSelectedOutputCount: 48,
            maximumRecomputedLeafCount: 1_548,
            scheduleConstructionWorkspaceByteLength: 163_840,
            selectedValueCount: 1_548,
        }),
    }),
    Object.freeze({
        caseIdentifier: 8,
        caseName: 'selected-vss-production-weighted-source-replay',
        expectedIterationCount: 1,
        requiredDimensions: Object.freeze({
            basePhaseCoefficientChunkCountPerSource: 3,
            basePhaseCurrentTwoPassSourceCatalogPassCount: 192,
            basePhaseDirectSourceColumnCountPerLane: 3_003,
            basePhaseDirectSourceChunkCountPerLane: 9_009,
            basePhaseReversedSourceChunkCountPerLane: 0,
            basePhaseRootPassSourceCatalogPassCount: 96,
            logicalRootCount: 112,
            productionRecipeCount: 3_003,
            traceValueCount: 65_536,
        }),
    }),
    Object.freeze({
        caseIdentifier: 9,
        caseName: 'vss-relation-replay-candidate-retained-group',
        expectedIterationCount: 1,
        requiredDimensions: Object.freeze({
            logicalRowChunkByteLength: 16_777_216,
            physicalRowWidth: 64,
            productionRecipeCount: 753,
            proverColumnDegreeBoundExclusive: 264_192,
            relationPlanHashByteLength: 64,
            replayBufferByteLength: 2_097_152,
            retainedCoefficientPayloadByteLength: 135_266_304,
            retainedRecipeCount: 64,
            tracePackingFactor: 16,
            traceValueCount: 262_144,
        }),
    }),
    Object.freeze({
        caseIdentifier: 10,
        caseName: 'vss-relation-replay-candidate-row-lane-stripe',
        expectedIterationCount: 9,
        requiredDimensions: Object.freeze({
            butterflyCountPerLane: 4_980_736,
            coefficientChunkCount: 9,
            coefficientFoldCountPerLane: 3_670_016,
            copiedCoefficientValueCount: 16_908_288,
            fullDomainSize: 16_777_216,
            laneColumnCount: 524_288,
            laneCount: 32,
            laneOrdinal: 0,
            logicalPolynomialCoefficientCount: 32_768,
            paddedCoefficientCount: 4_194_304,
            physicalRowCount: 108,
            physicalRowWidth: 64,
            productionRecipeCount: 753,
            proverColumnDegreeBoundExclusive: 264_192,
            relationPlanHashByteLength: 64,
            replayBufferByteLength: 2_097_152,
            retainedCoefficientPayloadByteLength: 135_266_304,
            retainedRecipeCount: 64,
            rowWorkingBufferByteLength: 33_554_432,
            stripeButterflyCount: 44_826_624,
            stripeCoefficientFoldCount: 33_030_144,
            stripeCosetMultiplicationCount: 4_718_592,
            stripePrivateHighHalfValueCount: 18_874_368,
            tracePackingFactor: 16,
            traceValueCount: 262_144,
            witnessValueCount: 2_097_152,
        }),
    }),
    Object.freeze({
        caseIdentifier: 11,
        caseName: 'vss-fused-radix-51-retained-group',
        expectedIterationCount: 1,
        requiredDimensions: Object.freeze({
            basePhaseRowCount: 42,
            completeSourceMaterializationCount: 5_254,
            completeSourceTraceValueGenerationCount: 86_081_536,
            logicalRowChunkByteLength: 16_777_216,
            phaseMaterializationPassCount: 2,
            physicalRowWidth: 64,
            productionRecipeCount: 2_627,
            proverColumnDegreeBoundExclusive: 18_432,
            rangeDigitRadix: 51,
            relationPlanHashByteLength: 64,
            replayBufferByteLength: 131_072,
            retainedCoefficientPayloadByteLength: 9_437_184,
            retainedRecipeCount: 64,
            tracePackingFactor: 1,
            traceValueCount: 16_384,
        }),
    }),
    Object.freeze({
        caseIdentifier: 12,
        caseName: 'vss-fused-radix-51-row-lane-stripe',
        expectedIterationCount: 1,
        requiredDimensions: Object.freeze({
            basePhaseRowCount: 42,
            butterflyCountPerLane: 4_980_736,
            coefficientChunkCount: 1,
            coefficientFoldCountPerLane: 3_670_016,
            completeButterflyCount: 16_575_889_408,
            completeCoefficientFoldCount: 12_213_813_248,
            completeColumnValueDeliveryCount: 1_744_830_464,
            completeCosetMultiplicationCount: 1_744_830_464,
            completeLaneDftCount: 3_328,
            completeLeafHashQueryCount: 67_108_864,
            completeMerkleParentHashQueryCount: 67_108_860,
            completePhaseRowCount: 52,
            completePrivateHighHalfValueGenerationCount: 218_103_808,
            completePrivateLeafSaltDerivationCount: 67_108_864,
            completeSaltedLeafKeccakPermutationCount: 201_326_592,
            completeSourceMaterializationCount: 5_254,
            completeSourceTraceValueGenerationCount: 86_081_536,
            completeTransportedValueByteLength: 13_958_643_712,
            copiedCoefficientValueCount: 1_179_648,
            fullDomainSize: 16_777_216,
            laneColumnCount: 524_288,
            laneCount: 32,
            laneOrdinal: 0,
            logicalPolynomialCoefficientCount: 32_768,
            paddedCoefficientCount: 4_194_304,
            phaseGeometryCount: 2,
            phaseMaterializationPassCount: 2,
            physicalRowWidth: 64,
            productionRecipeCount: 2_627,
            proverColumnDegreeBoundExclusive: 18_432,
            quotientPhaseRowCount: 10,
            rangeDigitRadix: 51,
            relationPlanHashByteLength: 64,
            replayBufferByteLength: 131_072,
            retainedCoefficientPayloadByteLength: 9_437_184,
            retainedRecipeCount: 64,
            rowWorkingBufferByteLength: 33_554_432,
            stripeButterflyCount: 4_980_736,
            stripeCoefficientFoldCount: 3_670_016,
            stripeCosetMultiplicationCount: 524_288,
            stripePrivateHighHalfValueCount: 2_097_152,
            tracePackingFactor: 1,
            traceValueCount: 16_384,
            witnessValueCount: 2_097_152,
        }),
    }),
] as const);

type JsonObject = Record<string, unknown>;

const isJsonObject = (value: unknown): value is JsonObject =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const requireSafeUnsignedInteger = (
    value: unknown,
    label: string,
    allowZero = false,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < (allowZero ? 0 : 1)
    ) {
        throw new Error(`${label} is not a safe unsigned integer.`);
    }
    return value;
};

const requireExactKeys = (
    value: JsonObject,
    expectedKeys: readonly string[],
    label: string,
): void => {
    const actualKeys = Object.keys(value).sort();
    const sortedExpectedKeys = [...expectedKeys].sort();
    if (
        actualKeys.length !== sortedExpectedKeys.length ||
        actualKeys.some((key, keyIndex) => key !== sortedExpectedKeys[keyIndex])
    ) {
        throw new Error(`${label} has noncanonical fields.`);
    }
};

const saltedPhaseColumnLeafKeccakPermutationCount = (
    logicalLeafWidth: number,
): number => Math.floor((7 + 128 / 8 + logicalLeafWidth) / 17) + 1;

export const validatePrimitiveMeasurementRecord = (
    value: unknown,
    expectedExecutionTarget?: PrimitiveMeasurementRecord['executionTarget'],
): PrimitiveMeasurementRecord => {
    if (!isJsonObject(value)) {
        throw new Error('Primitive measurement is not an object.');
    }
    requireExactKeys(
        value,
        [
            'caseIdentifier',
            'caseName',
            'checksumHex',
            'dimensions',
            'elapsedNanoseconds',
            'executionTarget',
            'iterationCount',
            'modeledPeakLiveByteLength',
            'schemaVersion',
        ],
        'Primitive measurement',
    );
    if (value.schemaVersion !== 2) {
        throw new Error('Primitive measurement schema version is unsupported.');
    }
    const caseIdentifier = requireSafeUnsignedInteger(
        value.caseIdentifier,
        'Primitive measurement case identifier',
    );
    const catalogEntry = primitiveMeasurementCaseCatalog.find(
        (candidate) => candidate.caseIdentifier === caseIdentifier,
    );
    if (
        catalogEntry === undefined ||
        value.caseName !== catalogEntry.caseName
    ) {
        throw new Error('Primitive measurement case identity is unsupported.');
    }
    if (!/^[0-9a-f]{16}$/u.test(String(value.checksumHex))) {
        throw new Error(
            'Primitive measurement checksum is not canonical hexadecimal.',
        );
    }
    if (
        value.executionTarget !== 'release-native' &&
        value.executionTarget !== 'wasm32-unknown-unknown'
    ) {
        throw new Error(
            'Primitive measurement execution target is unsupported.',
        );
    }
    if (
        expectedExecutionTarget !== undefined &&
        value.executionTarget !== expectedExecutionTarget
    ) {
        throw new Error(
            'Primitive measurement execution target is unexpected.',
        );
    }
    if (!Array.isArray(value.dimensions) || value.dimensions.length === 0) {
        throw new Error('Primitive measurement dimensions are absent.');
    }
    const dimensionNames = new Set<string>();
    const dimensions = value.dimensions.map((rawDimension) => {
        if (!isJsonObject(rawDimension)) {
            throw new Error(
                'Primitive measurement dimension is not an object.',
            );
        }
        requireExactKeys(
            rawDimension,
            ['name', 'value'],
            'Primitive measurement dimension',
        );
        if (
            typeof rawDimension.name !== 'string' ||
            !/^[a-z][A-Za-z0-9]*$/u.test(rawDimension.name) ||
            dimensionNames.has(rawDimension.name)
        ) {
            throw new Error(
                'Primitive measurement dimension name is noncanonical or duplicated.',
            );
        }
        dimensionNames.add(rawDimension.name);
        return Object.freeze({
            name: rawDimension.name,
            value: requireSafeUnsignedInteger(
                rawDimension.value,
                `Primitive measurement dimension ${rawDimension.name}`,
                true,
            ),
        });
    });
    const dimensionsByName = new Map(
        dimensions.map((dimension) => [dimension.name, dimension.value]),
    );
    const modeledPeakLiveByteLength = requireSafeUnsignedInteger(
        value.modeledPeakLiveByteLength,
        'Primitive measurement modeled peak live byte length',
    );
    for (const [dimensionName, expectedValue] of Object.entries(
        catalogEntry.requiredDimensions,
    )) {
        if (dimensionsByName.get(dimensionName) !== expectedValue) {
            throw new Error(
                `Primitive measurement dimension ${dimensionName} differs from production geometry.`,
            );
        }
    }
    if (caseIdentifier === 1) {
        requireSafeUnsignedInteger(
            dimensionsByName.get('pollCount'),
            'Primitive measurement DFT poll count',
        );
    }
    if (caseIdentifier === 5) {
        for (const dimensionName of [
            'traceValueCount',
            'nonzeroSourceCoefficientCount',
            'retainedInputByteLength',
            'basePhaseSourceReplayCount',
            'basePhaseProverSourceReplayCount',
            'basePhaseLaneDftCount',
            'basePhaseButterflyCount',
            'basePhaseCosetMultiplicationCount',
            'basePhaseColumnValueDeliveryCount',
            'basePhaseTransportedValueByteLength',
            'basePhaseLeafHashQueryCount',
            'basePhaseSaltedLeafKeccakPermutationCount',
            'basePhaseMerkleParentHashQueryCount',
            'basePhasePrivateLeafSaltDerivationCount',
            'modeledCandidateQuotientConstructionIdentityByteLength',
            'modeledCandidateQuotientPhaseOrderCount',
            'modeledCandidateQuotientTranscriptOperationCount',
            'modeledCandidateQuotientOpeningBatchCount',
            'modeledCandidateQuotientProofSectionCount',
            'modeledCandidateQuotientCheckpointCount',
            'modeledCandidateQuotientMaximumTranscriptHashQueryCount',
            'modeledCandidateQuotientLogicalVerifierMessageCount',
        ]) {
            requireSafeUnsignedInteger(
                dimensionsByName.get(dimensionName),
                `Primitive measurement ${dimensionName}`,
            );
        }
        requireSafeUnsignedInteger(
            dimensionsByName.get('basePhaseBoundSourceReplayCount'),
            'Primitive measurement basePhaseBoundSourceReplayCount',
            true,
        );
        requireSafeUnsignedInteger(
            dimensionsByName.get(
                'basePhaseReversedPolynomialReconstructionCount',
            ),
            'Primitive measurement basePhaseReversedPolynomialReconstructionCount',
            true,
        );
        const materializationPassCount = dimensionsByName.get(
            'basePhaseMaterializationPassCount',
        )!;
        const physicalRowWidth = dimensionsByName.get(
            'basePhasePhysicalRowWidth',
        )!;
        const logicalPolynomialCoefficientCount = dimensionsByName.get(
            'basePhaseLogicalPolynomialCoefficientCount',
        )!;
        const tracePackingFactor = dimensionsByName.get(
            'basePhaseTracePackingFactor',
        )!;
        const traceMaskDegreeBoundExclusive = dimensionsByName.get(
            'basePhaseTraceMaskDegreeBoundExclusive',
        )!;
        const proverColumnDegreeBoundExclusive = dimensionsByName.get(
            'basePhaseProverColumnDegreeBoundExclusive',
        )!;
        const rowCount = dimensionsByName.get('basePhaseRowCount')!;
        const laneCount = dimensionsByName.get('basePhaseLaneCount')!;
        const logicalChunkCountPerLane = dimensionsByName.get(
            'basePhaseLogicalChunkCountPerLane',
        )!;
        const sourceReplayCount = dimensionsByName.get(
            'basePhaseSourceReplayCount',
        )!;
        const directSourceChunkCountPerLane = dimensionsByName.get(
            'basePhaseDirectSourceChunkCountPerLane',
        )!;
        const directSourceColumnCountPerLane = dimensionsByName.get(
            'basePhaseDirectSourceColumnCountPerLane',
        )!;
        const coefficientChunkCountPerSource = dimensionsByName.get(
            'basePhaseCoefficientChunkCountPerSource',
        )!;
        const reversedSourceChunkCountPerLane = dimensionsByName.get(
            'basePhaseReversedSourceChunkCountPerLane',
        )!;
        const boundSourceReplayCount = dimensionsByName.get(
            'basePhaseBoundSourceReplayCount',
        )!;
        const proverSourceReplayCount = dimensionsByName.get(
            'basePhaseProverSourceReplayCount',
        )!;
        const laneDftCount = dimensionsByName.get('basePhaseLaneDftCount')!;
        const traceValueCount = dimensionsByName.get('traceValueCount')!;
        const retainedInputByteLength = dimensionsByName.get(
            'retainedInputByteLength',
        )!;
        const fullDomainSize =
            primitiveMeasurementCaseCatalog[0].requiredDimensions
                .fullDomainSize;
        const laneColumnCount =
            primitiveMeasurementCaseCatalog[0].requiredDimensions
                .laneColumnCount;
        const butterflyCountPerLaneDft =
            primitiveMeasurementCaseCatalog[0].requiredDimensions
                .butterflyCount;
        const modeledCandidateTracePackingFactor = dimensionsByName.get(
            'modeledCandidateTracePackingFactor',
        )!;
        const modeledCandidatePhysicalRowWidth = dimensionsByName.get(
            'modeledCandidatePhysicalRowWidth',
        )!;
        const modeledCandidateRelationTraceValueCount = dimensionsByName.get(
            'modeledCandidateRelationTraceValueCount',
        )!;
        const modeledCandidateProverColumnCount = dimensionsByName.get(
            'modeledCandidateProverColumnCount',
        )!;
        const modeledCandidateProverColumnDegreeBoundExclusive =
            dimensionsByName.get(
                'modeledCandidateProverColumnDegreeBoundExclusive',
            )!;
        const modeledCandidateOpeningDegreeBoundExclusive =
            dimensionsByName.get(
                'modeledCandidateOpeningDegreeBoundExclusive',
            )!;
        const modeledCandidateCoefficientChunkCountPerSource =
            dimensionsByName.get(
                'modeledCandidateCoefficientChunkCountPerSource',
            )!;
        const modeledCandidateRowCount = dimensionsByName.get(
            'modeledCandidateRowCount',
        )!;
        const modeledCandidateLeafHashQueryCount = dimensionsByName.get(
            'modeledCandidateLeafHashQueryCount',
        )!;
        const modeledCandidateOpeningPointCount = dimensionsByName.get(
            'modeledCandidateOpeningPointCount',
        )!;
        const modeledCandidateBoundReductionAggregateColumnCount =
            dimensionsByName.get(
                'modeledCandidateBoundReductionAggregateColumnCount',
            )!;
        const modeledCandidateAggregateColumnRoleCount = dimensionsByName.get(
            'modeledCandidateAggregateColumnRoleCount',
        )!;
        const modeledCandidateAggregateTableWidth = dimensionsByName.get(
            'modeledCandidateAggregateTableWidth',
        )!;
        const modeledCandidateDirectAggregateColumnRoleCount =
            dimensionsByName.get(
                'modeledCandidateDirectAggregateColumnRoleCount',
            )!;
        const modeledCandidateQuotientAggregateColumnRoleCount =
            dimensionsByName.get(
                'modeledCandidateQuotientAggregateColumnRoleCount',
            )!;
        const modeledCandidateQuotientSourceDegreeBoundExclusive =
            dimensionsByName.get(
                'modeledCandidateQuotientSourceDegreeBoundExclusive',
            )!;
        const modeledCandidateQuotientOpeningClaimCount = dimensionsByName.get(
            'modeledCandidateQuotientOpeningClaimCount',
        )!;
        const modeledCandidateBatchedQuotientDegreeBoundExclusive =
            dimensionsByName.get(
                'modeledCandidateBatchedQuotientDegreeBoundExclusive',
            )!;
        const modeledCandidateQuotientDiscrepancyDegreeBound =
            dimensionsByName.get(
                'modeledCandidateQuotientDiscrepancyNumeratorDegreeBoundInclusive',
            )!;
        const modeledCandidateQuotientQueryDomainSize = dimensionsByName.get(
            'modeledCandidateQuotientQueryDomainSize',
        )!;
        const modeledCandidateQuotientQueryCount = dimensionsByName.get(
            'modeledCandidateQuotientQueryCount',
        )!;
        const modeledCandidateQuotientAgreementCeiling = dimensionsByName.get(
            'modeledCandidateQuotientAgreementCeiling',
        )!;
        const modeledCandidateQuotientPhysicalRowWitnessVariableCount =
            dimensionsByName.get(
                'modeledCandidateQuotientPhysicalRowWitnessVariableCount',
            )!;
        const modeledCandidateQuotientTableVariableCount = dimensionsByName.get(
            'modeledCandidateQuotientTableVariableCount',
        )!;
        const modeledCandidateQuotientPolynomialCommitmentVariableCount =
            dimensionsByName.get(
                'modeledCandidateQuotientPolynomialCommitmentVariableCount',
            )!;
        const modeledCandidateQuotientRowCodeLogInverseRate =
            dimensionsByName.get(
                'modeledCandidateQuotientRowCodeLogInverseRate',
            )!;
        const modeledCandidateQuotientAggregateLogicalColumnCount =
            dimensionsByName.get(
                'modeledCandidateQuotientAggregateLogicalColumnCount',
            )!;
        const modeledCandidateQuotientAggregateTableWidth =
            dimensionsByName.get(
                'modeledCandidateQuotientAggregateTableWidth',
            )!;
        const modeledCandidateQuotientOuterOpeningBatchCount =
            dimensionsByName.get(
                'modeledCandidateQuotientOuterOpeningBatchCount',
            )!;
        const modeledCandidateQuotientBoundQueryCount = dimensionsByName.get(
            'modeledCandidateQuotientBoundQueryCount',
        )!;
        const modeledCandidateQuotientBoundDegreeTestCount =
            dimensionsByName.get(
                'modeledCandidateQuotientBoundDegreeTestCount',
            )!;
        const modeledCandidateQuotientBoundOpeningBatchCount =
            dimensionsByName.get(
                'modeledCandidateQuotientBoundOpeningBatchCount',
            )!;
        const modeledCandidateQuotientOpeningBatchCount = dimensionsByName.get(
            'modeledCandidateQuotientOpeningBatchCount',
        )!;
        const singleAggregateCandidateTracePackingFactor = dimensionsByName.get(
            'singleAggregateCandidateTracePackingFactor',
        )!;
        const singleAggregateCandidatePhysicalRowWidth = dimensionsByName.get(
            'singleAggregateCandidatePhysicalRowWidth',
        )!;
        const singleAggregateCandidateRowCount = dimensionsByName.get(
            'singleAggregateCandidateRowCount',
        )!;
        const singleAggregateCandidateLaneDftCount = dimensionsByName.get(
            'singleAggregateCandidateLaneDftCount',
        )!;
        const singleAggregateCandidateAggregateColumnRoleCount =
            dimensionsByName.get(
                'singleAggregateCandidateAggregateColumnRoleCount',
            )!;
        const singleAggregateCandidateAggregateTableWidth =
            dimensionsByName.get(
                'singleAggregateCandidateAggregateTableWidth',
            )!;
        const singleAggregateCandidateWorkingBufferByteLength =
            dimensionsByName.get(
                'singleAggregateCandidateBasePhaseWorkingBufferByteLength',
            )!;
        const singleAggregateCandidateHashStateByteLength =
            dimensionsByName.get(
                'singleAggregateCandidateBasePhaseHashStateByteLength',
            )!;
        const singleAggregateCandidateDigestPlaneByteLength =
            dimensionsByName.get(
                'singleAggregateCandidateBasePhaseDigestPlaneByteLength',
            )!;
        const singleAggregateCandidateAlgorithmLiveSetByteLength =
            dimensionsByName.get(
                'singleAggregateCandidateBasePhaseAlgorithmLiveSetByteLength',
            )!;
        const messageTraceValueCount = traceValueCount / tracePackingFactor;
        const deriveVssOpeningPointCount = (
            candidateTracePackingFactor: number,
        ): number => {
            const ringDegree = 32_768;
            const messageTraceDomainSize = ringDegree / 2;
            const twiceRingDegree = ringDegree * 2;
            const paddedParticipantCount = 16;
            const participantCount = 10;
            const threshold = 4;
            const pointStride = twiceRingDegree / paddedParticipantCount;
            const packedRotations = new Set<number>();
            for (
                let packedLaneOrdinal = 0;
                packedLaneOrdinal < candidateTracePackingFactor;
                packedLaneOrdinal += 1
            ) {
                packedRotations.add(packedLaneOrdinal);
            }
            let hasShiftSelector = false;
            for (
                let recipientOrdinal = 0;
                recipientOrdinal < participantCount;
                recipientOrdinal += 1
            ) {
                for (
                    let coefficientOrdinal = 0;
                    coefficientOrdinal < threshold;
                    coefficientOrdinal += 1
                ) {
                    const exponent =
                        recipientOrdinal * coefficientOrdinal * pointStride;
                    const reducedExponent = exponent % twiceRingDegree;
                    const sourceRowOffset =
                        (reducedExponent % ringDegree) % messageTraceDomainSize;
                    const rotationMagnitude =
                        sourceRowOffset === 0
                            ? 0
                            : messageTraceDomainSize - sourceRowOffset;
                    const coefficientPackedLaneOrdinal =
                        coefficientOrdinal % candidateTracePackingFactor;
                    packedRotations.add(
                        rotationMagnitude * candidateTracePackingFactor +
                            coefficientPackedLaneOrdinal,
                    );
                    hasShiftSelector ||= rotationMagnitude !== 0;
                }
            }
            if (hasShiftSelector) {
                packedRotations.add(candidateTracePackingFactor);
            }
            return packedRotations.size;
        };
        const sharingLimbCount = 8;
        const rootsPerSharingLimb = 14;
        const materialColumnsPerGroup = 90;
        const quotientValueCount = 160;
        const quotientColumnsPerGroup = 3;
        const shiftSelectorColumnCount = 3;
        const singleAggregateCandidateMaterialGroupCount =
            sharingLimbCount *
            Math.ceil(
                rootsPerSharingLimb /
                    singleAggregateCandidateTracePackingFactor,
            );
        const singleAggregateCandidateProverColumnCount =
            singleAggregateCandidateMaterialGroupCount *
                materialColumnsPerGroup +
            Math.ceil(
                quotientValueCount / singleAggregateCandidateTracePackingFactor,
            ) *
                quotientColumnsPerGroup +
            shiftSelectorColumnCount;
        const singleAggregateCandidateSourceDegreeBoundExclusive =
            messageTraceValueCount *
                singleAggregateCandidateTracePackingFactor +
            traceMaskDegreeBoundExclusive;
        const singleAggregateCandidateCoefficientChunkCount = Math.ceil(
            singleAggregateCandidateSourceDegreeBoundExclusive /
                logicalPolynomialCoefficientCount,
        );
        const independentlyDerivedSingleAggregateCandidateRowCount =
            Math.ceil(
                singleAggregateCandidateProverColumnCount /
                    singleAggregateCandidatePhysicalRowWidth,
            ) * singleAggregateCandidateCoefficientChunkCount;
        const singleAggregateCandidateOpeningPointCount =
            deriveVssOpeningPointCount(
                singleAggregateCandidateTracePackingFactor,
            );
        const independentlyDerivedSingleAggregateCandidates: Array<{
            aggregateColumnRoleCount: number;
            aggregateTableWidth: number;
            physicalRowWidth: number;
            rowCount: number;
            tracePackingFactor: number;
        }> = [];
        for (const candidateTracePackingFactor of [1, 2, 4, 8, 16, 32, 64]) {
            const candidateRelationTraceValueCount =
                messageTraceValueCount * candidateTracePackingFactor;
            const candidateSourceDegreeBoundExclusive =
                candidateRelationTraceValueCount +
                traceMaskDegreeBoundExclusive;
            const candidateMaximumRangeConstraintNumeratorDegree =
                (candidateSourceDegreeBoundExclusive - 1) * 3;
            const candidateMaterialGroupCount =
                sharingLimbCount *
                Math.ceil(rootsPerSharingLimb / candidateTracePackingFactor);
            const candidateProverColumnCount =
                candidateMaterialGroupCount * materialColumnsPerGroup +
                Math.ceil(quotientValueCount / candidateTracePackingFactor) *
                    quotientColumnsPerGroup +
                shiftSelectorColumnCount;
            const candidateOpeningPointCount = deriveVssOpeningPointCount(
                candidateTracePackingFactor,
            );
            const candidateAggregateColumnRoleCount =
                candidateOpeningPointCount + 1;
            for (const candidatePhysicalRowWidth of [8, 16, 32, 64]) {
                const candidateOpeningDegreeBoundExclusive =
                    logicalPolynomialCoefficientCount *
                    candidatePhysicalRowWidth;
                const candidateAggregateTableWidth =
                    fullDomainSize / (candidateOpeningDegreeBoundExclusive * 2);
                if (
                    candidateSourceDegreeBoundExclusive >
                        candidateOpeningDegreeBoundExclusive ||
                    candidateMaximumRangeConstraintNumeratorDegree >=
                        candidateOpeningDegreeBoundExclusive ||
                    !Number.isInteger(candidateAggregateTableWidth) ||
                    candidateAggregateTableWidth < 4 ||
                    !Number.isInteger(
                        Math.log2(candidateAggregateTableWidth),
                    ) ||
                    candidateAggregateColumnRoleCount >
                        candidateAggregateTableWidth
                ) {
                    continue;
                }
                const candidateCoefficientChunkCount = Math.ceil(
                    candidateSourceDegreeBoundExclusive /
                        logicalPolynomialCoefficientCount,
                );
                independentlyDerivedSingleAggregateCandidates.push({
                    aggregateColumnRoleCount: candidateAggregateColumnRoleCount,
                    aggregateTableWidth: candidateAggregateTableWidth,
                    physicalRowWidth: candidatePhysicalRowWidth,
                    rowCount:
                        Math.ceil(
                            candidateProverColumnCount /
                                candidatePhysicalRowWidth,
                        ) * candidateCoefficientChunkCount,
                    tracePackingFactor: candidateTracePackingFactor,
                });
            }
        }
        independentlyDerivedSingleAggregateCandidates.sort(
            (left, right) =>
                left.rowCount - right.rowCount ||
                left.tracePackingFactor - right.tracePackingFactor ||
                left.physicalRowWidth - right.physicalRowWidth,
        );
        const independentlySelectedSingleAggregateCandidate =
            independentlyDerivedSingleAggregateCandidates[0];
        const independentlyDerivedModeledRelationTraceValueCount =
            messageTraceValueCount * modeledCandidateTracePackingFactor;
        const independentlyDerivedModeledSourceDegreeBoundExclusive =
            modeledCandidateRelationTraceValueCount +
            traceMaskDegreeBoundExclusive;
        const independentlyDerivedModeledOpeningDegreeBoundExclusive =
            logicalPolynomialCoefficientCount *
            modeledCandidatePhysicalRowWidth;
        const independentlyDerivedModeledCoefficientChunkCount = Math.ceil(
            modeledCandidateProverColumnDegreeBoundExclusive /
                logicalPolynomialCoefficientCount,
        );
        const independentlyDerivedModeledRowCount =
            Math.ceil(
                modeledCandidateProverColumnCount /
                    modeledCandidatePhysicalRowWidth,
            ) * modeledCandidateCoefficientChunkCountPerSource;
        const independentlyDerivedModeledLaneDftCount =
            modeledCandidateRowCount * laneCount * materializationPassCount;
        const independentlyDerivedModeledColumnValueDeliveryCount =
            modeledCandidateRowCount *
            fullDomainSize *
            materializationPassCount;
        const independentlyDerivedModeledSourceMaterializationCount =
            modeledCandidateProverColumnCount * materializationPassCount;
        const independentlyDerivedQuotientSourceDegreeBoundExclusive =
            2 ** modeledCandidateQuotientTableVariableCount;
        const independentlyDerivedQuotientDiscrepancyDegreeBound =
            independentlyDerivedQuotientSourceDegreeBoundExclusive +
            modeledCandidateOpeningPointCount -
            2;
        const independentlyDerivedQuotientBoundOpeningBatchCount =
            modeledCandidateQuotientBoundQueryCount * 2 +
            modeledCandidateQuotientBoundDegreeTestCount;
        const identitiesHold =
            Number.isInteger(messageTraceValueCount) &&
            physicalRowWidth * logicalPolynomialCoefficientCount >
                dimensionsByName.get(
                    'basePhaseMaximumRangeConstraintNumeratorDegree',
                )! &&
            proverColumnDegreeBoundExclusive ===
                traceValueCount + traceMaskDegreeBoundExclusive &&
            dimensionsByName.get(
                'basePhaseMaximumRangeConstraintNumeratorDegree',
            ) ===
                (proverColumnDegreeBoundExclusive - 1) * 3 &&
            logicalChunkCountPerLane <= rowCount * physicalRowWidth &&
            directSourceChunkCountPerLane + reversedSourceChunkCountPerLane ===
                logicalChunkCountPerLane &&
            directSourceColumnCountPerLane * coefficientChunkCountPerSource ===
                directSourceChunkCountPerLane &&
            sourceReplayCount ===
                logicalChunkCountPerLane *
                    laneCount *
                    materializationPassCount &&
            sourceReplayCount ===
                boundSourceReplayCount + proverSourceReplayCount &&
            dimensionsByName.get(
                'basePhaseReversedPolynomialReconstructionCount',
            ) ===
                reversedSourceChunkCountPerLane *
                    laneCount *
                    materializationPassCount &&
            laneDftCount === rowCount * laneCount * materializationPassCount &&
            dimensionsByName.get('basePhaseButterflyCount') ===
                laneDftCount * butterflyCountPerLaneDft &&
            dimensionsByName.get('basePhaseCosetMultiplicationCount') ===
                laneDftCount * laneColumnCount &&
            dimensionsByName.get('basePhaseColumnValueDeliveryCount') ===
                rowCount * fullDomainSize * materializationPassCount &&
            dimensionsByName.get('basePhaseTransportedValueByteLength') ===
                rowCount * fullDomainSize * materializationPassCount * 8 &&
            dimensionsByName.get('basePhaseLeafHashQueryCount') ===
                fullDomainSize * materializationPassCount &&
            dimensionsByName.get('basePhaseMerkleParentHashQueryCount') ===
                (fullDomainSize - 1) * materializationPassCount &&
            dimensionsByName.get('basePhasePrivateLeafSaltDerivationCount') ===
                fullDomainSize * materializationPassCount &&
            dimensionsByName.get(
                'basePhaseSaltedLeafKeccakPermutationCount',
            ) ===
                dimensionsByName.get('basePhaseLeafHashQueryCount')! *
                    saltedPhaseColumnLeafKeccakPermutationCount(rowCount) &&
            modeledCandidateRelationTraceValueCount ===
                independentlyDerivedModeledRelationTraceValueCount &&
            modeledCandidateProverColumnDegreeBoundExclusive ===
                independentlyDerivedModeledSourceDegreeBoundExclusive &&
            dimensionsByName.get(
                'modeledCandidateMaximumRangeConstraintNumeratorDegree',
            ) ===
                (modeledCandidateProverColumnDegreeBoundExclusive - 1) * 3 &&
            modeledCandidateOpeningDegreeBoundExclusive ===
                independentlyDerivedModeledOpeningDegreeBoundExclusive &&
            modeledCandidateOpeningDegreeBoundExclusive >
                dimensionsByName.get(
                    'modeledCandidateMaximumRangeConstraintNumeratorDegree',
                )! &&
            dimensionsByName.get('modeledCandidateRowCodeInverseRate') ===
                fullDomainSize /
                    (modeledCandidateOpeningDegreeBoundExclusive * 2) &&
            modeledCandidateCoefficientChunkCountPerSource ===
                independentlyDerivedModeledCoefficientChunkCount &&
            modeledCandidateRowCount === independentlyDerivedModeledRowCount &&
            dimensionsByName.get('modeledCandidateMaterialProverColumnCount')! +
                dimensionsByName.get(
                    'modeledCandidateQuotientProverColumnCount',
                )! +
                dimensionsByName.get(
                    'modeledCandidateShiftSelectorColumnCount',
                )! ===
                modeledCandidateProverColumnCount &&
            dimensionsByName.get('modeledCandidateLaneDftCount') ===
                independentlyDerivedModeledLaneDftCount &&
            dimensionsByName.get('modeledCandidateButterflyCount') ===
                independentlyDerivedModeledLaneDftCount *
                    butterflyCountPerLaneDft &&
            dimensionsByName.get('modeledCandidateColumnValueDeliveryCount') ===
                independentlyDerivedModeledColumnValueDeliveryCount &&
            dimensionsByName.get(
                'modeledCandidateTransportedValueByteLength',
            ) ===
                independentlyDerivedModeledColumnValueDeliveryCount * 8 &&
            modeledCandidateLeafHashQueryCount ===
                fullDomainSize * materializationPassCount &&
            dimensionsByName.get(
                'modeledCandidateSaltedLeafKeccakPermutationCount',
            ) ===
                modeledCandidateLeafHashQueryCount *
                    saltedPhaseColumnLeafKeccakPermutationCount(
                        modeledCandidateRowCount,
                    ) &&
            dimensionsByName.get(
                'modeledCandidateMerkleParentHashQueryCount',
            ) ===
                (fullDomainSize - 1) * materializationPassCount &&
            dimensionsByName.get(
                'modeledCandidatePrivateLeafSaltDerivationCount',
            ) === modeledCandidateLeafHashQueryCount &&
            dimensionsByName.get(
                'modeledCandidateRetainedSourceMaterializationCount',
            ) === independentlyDerivedModeledSourceMaterializationCount &&
            dimensionsByName.get(
                'modeledCandidateSourceTraceValueGenerationCount',
            ) ===
                independentlyDerivedModeledSourceMaterializationCount *
                    modeledCandidateRelationTraceValueCount &&
            dimensionsByName.get(
                'modeledCandidateRetainedCoefficientGroupByteLength',
            ) ===
                Math.min(
                    modeledCandidateProverColumnCount,
                    modeledCandidatePhysicalRowWidth,
                ) *
                    modeledCandidateProverColumnDegreeBoundExclusive *
                    8 &&
            dimensionsByName.get(
                'modeledCandidateLogicalRowChunkByteLength',
            ) ===
                modeledCandidateOpeningDegreeBoundExclusive * 8 &&
            modeledCandidateOpeningPointCount ===
                deriveVssOpeningPointCount(
                    modeledCandidateTracePackingFactor,
                ) &&
            modeledCandidateBoundReductionAggregateColumnCount === 1 &&
            modeledCandidateAggregateColumnRoleCount ===
                modeledCandidateOpeningPointCount +
                    modeledCandidateBoundReductionAggregateColumnCount &&
            modeledCandidateAggregateTableWidth ===
                dimensionsByName.get('modeledCandidateRowCodeInverseRate') &&
            modeledCandidateAggregateColumnRoleCount >
                modeledCandidateAggregateTableWidth &&
            modeledCandidateDirectAggregateColumnRoleCount ===
                modeledCandidateAggregateColumnRoleCount &&
            modeledCandidateQuotientAggregateColumnRoleCount ===
                1 + modeledCandidateBoundReductionAggregateColumnCount &&
            modeledCandidateQuotientSourceDegreeBoundExclusive ===
                independentlyDerivedQuotientSourceDegreeBoundExclusive &&
            modeledCandidateQuotientOpeningClaimCount ===
                modeledCandidateOpeningPointCount &&
            modeledCandidateBatchedQuotientDegreeBoundExclusive ===
                modeledCandidateQuotientSourceDegreeBoundExclusive - 1 &&
            modeledCandidateQuotientDiscrepancyDegreeBound ===
                independentlyDerivedQuotientDiscrepancyDegreeBound &&
            modeledCandidateQuotientAgreementCeiling ===
                independentlyDerivedQuotientDiscrepancyDegreeBound &&
            modeledCandidateQuotientQueryDomainSize === fullDomainSize &&
            modeledCandidateQuotientQueryCount ===
                dimensionsByName.get('basePhaseOpeningQueryCount') &&
            modeledCandidateQuotientPhysicalRowWitnessVariableCount ===
                Math.log2(modeledCandidateOpeningDegreeBoundExclusive) &&
            modeledCandidateQuotientTableVariableCount ===
                modeledCandidateQuotientPhysicalRowWitnessVariableCount + 1 &&
            modeledCandidateQuotientPolynomialCommitmentVariableCount ===
                Math.log2(fullDomainSize) &&
            modeledCandidateQuotientRowCodeLogInverseRate ===
                modeledCandidateQuotientPolynomialCommitmentVariableCount -
                    modeledCandidateQuotientTableVariableCount &&
            modeledCandidateQuotientAggregateLogicalColumnCount ===
                modeledCandidateQuotientAggregateColumnRoleCount &&
            modeledCandidateQuotientAggregateTableWidth ===
                2 ** modeledCandidateQuotientRowCodeLogInverseRate &&
            modeledCandidateQuotientAggregateLogicalColumnCount <=
                modeledCandidateQuotientAggregateTableWidth &&
            modeledCandidateQuotientOuterOpeningBatchCount ===
                modeledCandidateQuotientQueryCount &&
            dimensionsByName.get(
                'modeledCandidateQuotientBoundReductionBlockCount',
            ) === 1 &&
            modeledCandidateQuotientBoundOpeningBatchCount ===
                independentlyDerivedQuotientBoundOpeningBatchCount &&
            modeledCandidateQuotientOpeningBatchCount ===
                modeledCandidateQuotientOuterOpeningBatchCount +
                    modeledCandidateQuotientBoundOpeningBatchCount &&
            dimensionsByName.get(
                'modeledCandidateQuotientConstructionIdentityHashByteLength',
            ) === 64 &&
            dimensionsByName.get(
                'modeledCandidateQuotientOracleEquationCatalogHashByteLength',
            ) === 64 &&
            dimensionsByName.get(
                'modeledCandidateQuotientConstructionIdentityByteLength',
            )! > 0 &&
            dimensionsByName.get('modeledCandidateQuotientPhaseOrderCount') ===
                2 &&
            dimensionsByName.get(
                'modeledCandidateQuotientTranscriptOperationCount',
            )! >
                dimensionsByName.get(
                    'modeledCandidateQuotientLogicalVerifierMessageCount',
                )! &&
            dimensionsByName.get('modeledCandidateQuotientProofSectionCount')! >
                0 &&
            dimensionsByName.get('modeledCandidateQuotientCheckpointCount')! >
                0 &&
            dimensionsByName.get(
                'modeledCandidateQuotientMaximumTranscriptHashQueryCount',
            )! >
                dimensionsByName.get(
                    'modeledCandidateQuotientLogicalVerifierMessageCount',
                )! &&
            independentlySelectedSingleAggregateCandidate !== undefined &&
            singleAggregateCandidateTracePackingFactor ===
                independentlySelectedSingleAggregateCandidate.tracePackingFactor &&
            singleAggregateCandidatePhysicalRowWidth ===
                independentlySelectedSingleAggregateCandidate.physicalRowWidth &&
            singleAggregateCandidateRowCount ===
                independentlySelectedSingleAggregateCandidate.rowCount &&
            singleAggregateCandidateRowCount ===
                independentlyDerivedSingleAggregateCandidateRowCount &&
            singleAggregateCandidateAggregateColumnRoleCount ===
                independentlySelectedSingleAggregateCandidate.aggregateColumnRoleCount &&
            singleAggregateCandidateAggregateColumnRoleCount ===
                singleAggregateCandidateOpeningPointCount + 1 &&
            singleAggregateCandidateAggregateTableWidth ===
                independentlySelectedSingleAggregateCandidate.aggregateTableWidth &&
            singleAggregateCandidateAggregateColumnRoleCount <=
                singleAggregateCandidateAggregateTableWidth &&
            dimensionsByName.get(
                'singleAggregateCandidateOpeningDegreeBoundExclusive',
            ) ===
                logicalPolynomialCoefficientCount *
                    singleAggregateCandidatePhysicalRowWidth &&
            singleAggregateCandidateLaneDftCount ===
                singleAggregateCandidateRowCount *
                    laneCount *
                    materializationPassCount &&
            dimensionsByName.get(
                'singleAggregateCandidateSaltedLeafKeccakPermutationCount',
            ) ===
                fullDomainSize *
                    materializationPassCount *
                    saltedPhaseColumnLeafKeccakPermutationCount(
                        singleAggregateCandidateRowCount,
                    ) &&
            rowCount < singleAggregateCandidateRowCount * 10 &&
            dimensionsByName.get(
                'singleAggregateCandidatePhysicalRowWitnessVariableCount',
            ) ===
                Math.log2(
                    logicalPolynomialCoefficientCount *
                        singleAggregateCandidatePhysicalRowWidth,
                ) &&
            dimensionsByName.get(
                'singleAggregateCandidateTableVariableCount',
            ) ===
                dimensionsByName.get(
                    'singleAggregateCandidatePhysicalRowWitnessVariableCount',
                )! +
                    1 &&
            dimensionsByName.get(
                'singleAggregateCandidatePolynomialCommitmentVariableCount',
            ) === Math.log2(fullDomainSize) &&
            dimensionsByName.get(
                'singleAggregateCandidateRowCodeLogInverseRate',
            ) === Math.log2(singleAggregateCandidateAggregateTableWidth) &&
            dimensionsByName.get(
                'singleAggregateCandidateConstructionIdentityHashByteLength',
            ) === 64 &&
            dimensionsByName.get(
                'singleAggregateCandidateOracleEquationCatalogHashByteLength',
            ) === 64 &&
            dimensionsByName.get(
                'singleAggregateCandidateConstructionIdentityByteLength',
            )! > 0 &&
            singleAggregateCandidateAlgorithmLiveSetByteLength ===
                singleAggregateCandidateWorkingBufferByteLength +
                    singleAggregateCandidateHashStateByteLength +
                    singleAggregateCandidateDigestPlaneByteLength &&
            dimensionsByName.get(
                'singleAggregateCandidateMaximumTranscriptHashQueryCount',
            )! >
                dimensionsByName.get(
                    'singleAggregateCandidateLogicalVerifierMessageCount',
                )! &&
            independentlyDerivedModeledLaneDftCount * 10 <= laneDftCount &&
            modeledPeakLiveByteLength ===
                retainedInputByteLength + traceValueCount * 8;
        if (!identitiesHold) {
            throw new Error(
                'Primitive measurement selected VSS work-ledger identities are inconsistent.',
            );
        }
    }
    if (caseIdentifier === 6) {
        const plaintextByteLength = dimensionsByName.get('plaintextByteLength');
        const canonicalEnvelopeByteLength = requireSafeUnsignedInteger(
            dimensionsByName.get('canonicalEnvelopeByteLength'),
            'Primitive measurement canonical envelope byte length',
        );
        if (
            plaintextByteLength === undefined ||
            canonicalEnvelopeByteLength <= plaintextByteLength ||
            canonicalEnvelopeByteLength > plaintextByteLength + 968
        ) {
            throw new Error(
                'Primitive measurement canonical envelope length exceeds the exact secret-record overhead.',
            );
        }
    }
    if (caseIdentifier === 7) {
        for (const dimensionName of [
            'pollCount',
            'lowerScheduleHeapByteLength',
            'higherScheduleHeapByteLength',
        ]) {
            requireSafeUnsignedInteger(
                dimensionsByName.get(dimensionName),
                `Primitive measurement ${dimensionName}`,
            );
        }
        const laneColumnCount = dimensionsByName.get('laneColumnCount')!;
        const laneCount = dimensionsByName.get('laneCount')!;
        const higherOutputLaneCount = dimensionsByName.get(
            'higherOutputLaneCount',
        )!;
        const higherSelectedOutputCount = dimensionsByName.get(
            'higherSelectedOutputCount',
        )!;
        const lowerOutputLaneCount = dimensionsByName.get(
            'lowerOutputLaneCount',
        )!;
        const lowerSelectedOutputCount = dimensionsByName.get(
            'lowerSelectedOutputCount',
        )!;
        const selectedValueCount = dimensionsByName.get('selectedValueCount')!;
        const butterflyBound = (selectedOutputCount: number): number =>
            Array.from(
                { length: Math.log2(laneColumnCount) },
                (_, dependencyDepth) =>
                    Math.min(
                        laneColumnCount / 2,
                        selectedOutputCount * 2 ** dependencyDepth,
                    ),
            ).reduce((total, count) => total + count, 0);
        const independentlyDerivedButterflyCount =
            higherOutputLaneCount * butterflyBound(higherSelectedOutputCount) +
            lowerOutputLaneCount * butterflyBound(lowerSelectedOutputCount);
        if (
            !Number.isInteger(Math.log2(laneColumnCount)) ||
            higherOutputLaneCount + lowerOutputLaneCount !== laneCount ||
            higherOutputLaneCount * higherSelectedOutputCount +
                lowerOutputLaneCount * lowerSelectedOutputCount !==
                selectedValueCount ||
            dimensionsByName.get('maximumRecomputedLeafCount') !==
                selectedValueCount ||
            dimensionsByName.get('checkpointLeafCount') !==
                2 ** dimensionsByName.get('checkpointLevel')! ||
            dimensionsByName.get('executedButterflyCount') !==
                independentlyDerivedButterflyCount ||
            dimensionsByName.get('fullButterflyCount') !==
                laneCount *
                    (laneColumnCount / 2) *
                    Math.log2(laneColumnCount) ||
            modeledPeakLiveByteLength >= 671_088_640
        ) {
            throw new Error(
                'Primitive measurement modeled checkpoint DFT identities are inconsistent.',
            );
        }
    }
    if (caseIdentifier === 8) {
        const retainedInputByteLength = requireSafeUnsignedInteger(
            dimensionsByName.get('retainedInputByteLength'),
            'Primitive measurement retainedInputByteLength',
        );
        const traceValueCount = dimensionsByName.get('traceValueCount')!;
        const productionRecipeCount = dimensionsByName.get(
            'productionRecipeCount',
        )!;
        const directSourceChunkCountPerLane = dimensionsByName.get(
            'basePhaseDirectSourceChunkCountPerLane',
        )!;
        const directSourceColumnCountPerLane = dimensionsByName.get(
            'basePhaseDirectSourceColumnCountPerLane',
        )!;
        const coefficientChunkCountPerSource = dimensionsByName.get(
            'basePhaseCoefficientChunkCountPerSource',
        )!;
        const rootPassCount = dimensionsByName.get(
            'basePhaseRootPassSourceCatalogPassCount',
        )!;
        if (
            productionRecipeCount !== directSourceColumnCountPerLane ||
            productionRecipeCount * coefficientChunkCountPerSource !==
                directSourceChunkCountPerLane ||
            dimensionsByName.get('basePhaseReversedSourceChunkCountPerLane') !==
                0 ||
            dimensionsByName.get(
                'basePhaseCurrentTwoPassSourceCatalogPassCount',
            ) !==
                rootPassCount * 2 ||
            rootPassCount !== 32 * coefficientChunkCountPerSource ||
            modeledPeakLiveByteLength !==
                retainedInputByteLength + traceValueCount * 8
        ) {
            throw new Error(
                'Primitive measurement production-weighted source-replay identities are inconsistent.',
            );
        }
    }
    if (caseIdentifier === 9 || caseIdentifier === 11) {
        const retainedInputByteLength = requireSafeUnsignedInteger(
            dimensionsByName.get('retainedInputByteLength'),
            'Primitive measurement retainedInputByteLength',
        );
        const retainedGroupHeaderByteLength = requireSafeUnsignedInteger(
            dimensionsByName.get('retainedGroupHeaderByteLength'),
            'Primitive measurement retainedGroupHeaderByteLength',
        );
        const traceValueCount = dimensionsByName.get('traceValueCount')!;
        const degreeBound = dimensionsByName.get(
            'proverColumnDegreeBoundExclusive',
        )!;
        const retainedRecipeCount = dimensionsByName.get(
            'retainedRecipeCount',
        )!;
        const physicalRowWidth = dimensionsByName.get('physicalRowWidth')!;
        const replayBufferByteLength = dimensionsByName.get(
            'replayBufferByteLength',
        )!;
        const retainedCoefficientPayloadByteLength = dimensionsByName.get(
            'retainedCoefficientPayloadByteLength',
        )!;
        if (
            retainedRecipeCount !== physicalRowWidth ||
            replayBufferByteLength !== traceValueCount * 8 ||
            retainedCoefficientPayloadByteLength !==
                retainedRecipeCount * degreeBound * 8 ||
            dimensionsByName.get('logicalRowChunkByteLength') !==
                physicalRowWidth * 32_768 * 8 ||
            modeledPeakLiveByteLength !==
                retainedInputByteLength +
                    retainedCoefficientPayloadByteLength +
                    replayBufferByteLength +
                    retainedGroupHeaderByteLength ||
            modeledPeakLiveByteLength >= 671_088_640
        ) {
            throw new Error(
                'Primitive measurement VSS retained-group identities are inconsistent.',
            );
        }
    }
    if (caseIdentifier === 11) {
        const productionRecipeCount = dimensionsByName.get(
            'productionRecipeCount',
        )!;
        const physicalRowWidth = dimensionsByName.get('physicalRowWidth')!;
        const materializationPassCount = dimensionsByName.get(
            'phaseMaterializationPassCount',
        )!;
        const completeSourceMaterializationCount = dimensionsByName.get(
            'completeSourceMaterializationCount',
        )!;
        if (
            dimensionsByName.get('basePhaseRowCount') !==
                Math.ceil(productionRecipeCount / physicalRowWidth) ||
            completeSourceMaterializationCount !==
                productionRecipeCount * materializationPassCount ||
            dimensionsByName.get('completeSourceTraceValueGenerationCount') !==
                completeSourceMaterializationCount *
                    dimensionsByName.get('traceValueCount')!
        ) {
            throw new Error(
                'Primitive measurement fused VSS retained-group work identities are inconsistent.',
            );
        }
    }
    if (caseIdentifier === 10 || caseIdentifier === 12) {
        const retainedInputByteLength = requireSafeUnsignedInteger(
            dimensionsByName.get('retainedInputByteLength'),
            'Primitive measurement retainedInputByteLength',
        );
        const retainedGroupHeaderByteLength = requireSafeUnsignedInteger(
            dimensionsByName.get('retainedGroupHeaderByteLength'),
            'Primitive measurement retainedGroupHeaderByteLength',
        );
        const retainedGroupContainerByteLength = requireSafeUnsignedInteger(
            dimensionsByName.get('retainedGroupContainerByteLength'),
            'Primitive measurement retainedGroupContainerByteLength',
        );
        const ownedFixedStateByteLength = requireSafeUnsignedInteger(
            dimensionsByName.get('ownedFixedStateByteLength'),
            'Primitive measurement ownedFixedStateByteLength',
        );
        const materializationPeakLiveByteLength = requireSafeUnsignedInteger(
            dimensionsByName.get('materializationPeakLiveByteLength'),
            'Primitive measurement materializationPeakLiveByteLength',
        );
        const stripePeakLiveByteLength = requireSafeUnsignedInteger(
            dimensionsByName.get('stripePeakLiveByteLength'),
            'Primitive measurement stripePeakLiveByteLength',
        );
        requireSafeUnsignedInteger(
            dimensionsByName.get('pollCount'),
            'Primitive measurement VSS row-lane poll count',
        );
        const traceValueCount = dimensionsByName.get('traceValueCount')!;
        const physicalRowWidth = dimensionsByName.get('physicalRowWidth')!;
        const productionRecipeCount = dimensionsByName.get(
            'productionRecipeCount',
        )!;
        const degreeBound = dimensionsByName.get(
            'proverColumnDegreeBoundExclusive',
        )!;
        const logicalPolynomialCoefficientCount = dimensionsByName.get(
            'logicalPolynomialCoefficientCount',
        )!;
        const coefficientChunkCount = dimensionsByName.get(
            'coefficientChunkCount',
        )!;
        const witnessValueCount = dimensionsByName.get('witnessValueCount')!;
        const paddedCoefficientCount = dimensionsByName.get(
            'paddedCoefficientCount',
        )!;
        const fullDomainSize = dimensionsByName.get('fullDomainSize')!;
        const laneColumnCount = dimensionsByName.get('laneColumnCount')!;
        const laneCount = dimensionsByName.get('laneCount')!;
        const retainedCoefficientPayloadByteLength = dimensionsByName.get(
            'retainedCoefficientPayloadByteLength',
        )!;
        const replayBufferByteLength = dimensionsByName.get(
            'replayBufferByteLength',
        )!;
        const rowWorkingBufferByteLength = dimensionsByName.get(
            'rowWorkingBufferByteLength',
        )!;
        const coefficientFoldCountPerLane = dimensionsByName.get(
            'coefficientFoldCountPerLane',
        )!;
        if (
            dimensionsByName.get('retainedRecipeCount') !== physicalRowWidth ||
            witnessValueCount !==
                physicalRowWidth * logicalPolynomialCoefficientCount ||
            paddedCoefficientCount !== witnessValueCount * 2 ||
            fullDomainSize !== paddedCoefficientCount * 4 ||
            fullDomainSize !== laneCount * laneColumnCount ||
            dimensionsByName.get('laneOrdinal')! >= laneCount ||
            coefficientChunkCount !==
                Math.ceil(degreeBound / logicalPolynomialCoefficientCount) ||
            dimensionsByName.get(
                caseIdentifier === 10
                    ? 'physicalRowCount'
                    : 'basePhaseRowCount',
            ) !==
                Math.ceil(productionRecipeCount / physicalRowWidth) *
                    coefficientChunkCount ||
            coefficientFoldCountPerLane !==
                paddedCoefficientCount - laneColumnCount ||
            dimensionsByName.get('stripeCoefficientFoldCount') !==
                coefficientFoldCountPerLane * coefficientChunkCount ||
            dimensionsByName.get('stripeButterflyCount') !==
                dimensionsByName.get('butterflyCountPerLane')! *
                    coefficientChunkCount ||
            dimensionsByName.get('stripeCosetMultiplicationCount') !==
                laneColumnCount * coefficientChunkCount ||
            dimensionsByName.get('copiedCoefficientValueCount') !==
                physicalRowWidth * degreeBound ||
            dimensionsByName.get('stripePrivateHighHalfValueCount') !==
                witnessValueCount * coefficientChunkCount ||
            retainedCoefficientPayloadByteLength !==
                physicalRowWidth * degreeBound * 8 ||
            replayBufferByteLength !== traceValueCount * 8 ||
            rowWorkingBufferByteLength !== paddedCoefficientCount * 8 ||
            ownedFixedStateByteLength <=
                retainedGroupContainerByteLength + 64 ||
            materializationPeakLiveByteLength !==
                retainedInputByteLength +
                    retainedCoefficientPayloadByteLength +
                    replayBufferByteLength +
                    retainedGroupHeaderByteLength +
                    retainedGroupContainerByteLength ||
            stripePeakLiveByteLength !==
                retainedInputByteLength +
                    retainedCoefficientPayloadByteLength +
                    retainedGroupHeaderByteLength +
                    rowWorkingBufferByteLength +
                    ownedFixedStateByteLength ||
            modeledPeakLiveByteLength !==
                Math.max(
                    materializationPeakLiveByteLength,
                    stripePeakLiveByteLength,
                ) ||
            modeledPeakLiveByteLength >= 671_088_640
        ) {
            throw new Error(
                'Primitive measurement VSS row-lane stripe identities are inconsistent.',
            );
        }
    }
    if (caseIdentifier === 12) {
        const basePhaseRowCount = dimensionsByName.get('basePhaseRowCount')!;
        const quotientPhaseRowCount = dimensionsByName.get(
            'quotientPhaseRowCount',
        )!;
        const completePhaseRowCount = dimensionsByName.get(
            'completePhaseRowCount',
        )!;
        const phaseGeometryCount = dimensionsByName.get('phaseGeometryCount')!;
        const materializationPassCount = dimensionsByName.get(
            'phaseMaterializationPassCount',
        )!;
        const laneCount = dimensionsByName.get('laneCount')!;
        const fullDomainSize = dimensionsByName.get('fullDomainSize')!;
        const witnessValueCount = dimensionsByName.get('witnessValueCount')!;
        const completeLaneDftCount = dimensionsByName.get(
            'completeLaneDftCount',
        )!;
        const completeLeafHashQueryCount = dimensionsByName.get(
            'completeLeafHashQueryCount',
        )!;
        const productionRecipeCount = dimensionsByName.get(
            'productionRecipeCount',
        )!;
        const completeSourceMaterializationCount = dimensionsByName.get(
            'completeSourceMaterializationCount',
        )!;
        if (
            completePhaseRowCount !==
                basePhaseRowCount + quotientPhaseRowCount ||
            completeLaneDftCount !==
                completePhaseRowCount * laneCount * materializationPassCount ||
            dimensionsByName.get('completeButterflyCount') !==
                completeLaneDftCount *
                    dimensionsByName.get('butterflyCountPerLane')! ||
            dimensionsByName.get('completeCoefficientFoldCount') !==
                completeLaneDftCount *
                    dimensionsByName.get('coefficientFoldCountPerLane')! ||
            dimensionsByName.get('completeCosetMultiplicationCount') !==
                completeLaneDftCount *
                    dimensionsByName.get('laneColumnCount')! ||
            dimensionsByName.get('completeColumnValueDeliveryCount') !==
                completePhaseRowCount *
                    fullDomainSize *
                    materializationPassCount ||
            dimensionsByName.get('completeTransportedValueByteLength') !==
                dimensionsByName.get('completeColumnValueDeliveryCount')! * 8 ||
            dimensionsByName.get(
                'completePrivateHighHalfValueGenerationCount',
            ) !==
                completePhaseRowCount *
                    witnessValueCount *
                    materializationPassCount ||
            completeLeafHashQueryCount !==
                phaseGeometryCount *
                    fullDomainSize *
                    materializationPassCount ||
            dimensionsByName.get('completeMerkleParentHashQueryCount') !==
                phaseGeometryCount *
                    (fullDomainSize - 1) *
                    materializationPassCount ||
            dimensionsByName.get('completePrivateLeafSaltDerivationCount') !==
                completeLeafHashQueryCount ||
            dimensionsByName.get('completeSaltedLeafKeccakPermutationCount') !==
                fullDomainSize *
                    materializationPassCount *
                    (saltedPhaseColumnLeafKeccakPermutationCount(
                        basePhaseRowCount,
                    ) +
                        saltedPhaseColumnLeafKeccakPermutationCount(
                            quotientPhaseRowCount,
                        )) ||
            completeSourceMaterializationCount !==
                productionRecipeCount * materializationPassCount ||
            dimensionsByName.get('completeSourceTraceValueGenerationCount') !==
                completeSourceMaterializationCount *
                    dimensionsByName.get('traceValueCount')!
        ) {
            throw new Error(
                'Primitive measurement fused VSS complete-work identities are inconsistent.',
            );
        }
    }

    const iterationCount = requireSafeUnsignedInteger(
        value.iterationCount,
        'Primitive measurement iteration count',
    );
    if (iterationCount !== catalogEntry.expectedIterationCount) {
        throw new Error(
            'Primitive measurement iteration count differs from the bounded case.',
        );
    }

    return Object.freeze({
        caseIdentifier,
        caseName: catalogEntry.caseName,
        checksumHex: value.checksumHex as string,
        dimensions: Object.freeze(dimensions),
        elapsedNanoseconds: requireSafeUnsignedInteger(
            value.elapsedNanoseconds,
            'Primitive measurement elapsed nanoseconds',
        ),
        executionTarget: value.executionTarget,
        iterationCount,
        modeledPeakLiveByteLength,
        schemaVersion: 2,
    });
};

export const requireCompletePrimitiveMeasurementCatalog = (
    records: readonly PrimitiveMeasurementRecord[],
): void => {
    if (records.length !== primitiveMeasurementCaseCatalog.length) {
        throw new Error('Primitive measurement catalog is incomplete.');
    }
    const observedIdentifiers = records.map((record) => record.caseIdentifier);
    if (
        primitiveMeasurementCaseCatalog.some(
            (entry, entryIndex) =>
                observedIdentifiers[entryIndex] !== entry.caseIdentifier,
        )
    ) {
        throw new Error(
            'Primitive measurement catalog is duplicated, omitted, or reordered.',
        );
    }
    const saltedLeafRecord = records[1];
    const selectedVssRecord = records[4];
    const modeledCheckpointDftRecord = records[6];
    const productionWeightedSourceReplayRecord = records[7];
    const retainedGroupCandidateRecord = records[8];
    const rowLaneCandidateRecord = records[9];
    const fusedRetainedGroupCandidateRecord = records[10];
    const fusedRowLaneCandidateRecord = records[11];
    if (
        saltedLeafRecord === undefined ||
        selectedVssRecord === undefined ||
        modeledCheckpointDftRecord === undefined ||
        productionWeightedSourceReplayRecord === undefined ||
        retainedGroupCandidateRecord === undefined ||
        rowLaneCandidateRecord === undefined ||
        fusedRetainedGroupCandidateRecord === undefined ||
        fusedRowLaneCandidateRecord === undefined
    ) {
        throw new Error('Primitive measurement catalog work ledger is absent.');
    }
    const saltedLeafDimensions = new Map(
        saltedLeafRecord.dimensions.map((dimension) => [
            dimension.name,
            dimension.value,
        ]),
    );
    const selectedVssDimensions = new Map(
        selectedVssRecord.dimensions.map((dimension) => [
            dimension.name,
            dimension.value,
        ]),
    );
    const modeledCheckpointDftDimensions = new Map(
        modeledCheckpointDftRecord.dimensions.map((dimension) => [
            dimension.name,
            dimension.value,
        ]),
    );
    const productionWeightedSourceReplayDimensions = new Map(
        productionWeightedSourceReplayRecord.dimensions.map((dimension) => [
            dimension.name,
            dimension.value,
        ]),
    );
    const retainedGroupCandidateDimensions = new Map(
        retainedGroupCandidateRecord.dimensions.map((dimension) => [
            dimension.name,
            dimension.value,
        ]),
    );
    const rowLaneCandidateDimensions = new Map(
        rowLaneCandidateRecord.dimensions.map((dimension) => [
            dimension.name,
            dimension.value,
        ]),
    );
    const fusedRetainedGroupCandidateDimensions = new Map(
        fusedRetainedGroupCandidateRecord.dimensions.map((dimension) => [
            dimension.name,
            dimension.value,
        ]),
    );
    const fusedRowLaneCandidateDimensions = new Map(
        fusedRowLaneCandidateRecord.dimensions.map((dimension) => [
            dimension.name,
            dimension.value,
        ]),
    );
    const measuredPermutationCount = saltedLeafDimensions.get(
        'keccakPermutationCount',
    );
    const projectedPermutationCount = selectedVssDimensions.get(
        'basePhaseSaltedLeafKeccakPermutationCount',
    );
    const projectedLeafCount = selectedVssDimensions.get(
        'basePhaseLeafHashQueryCount',
    );
    if (
        measuredPermutationCount === undefined ||
        projectedPermutationCount === undefined ||
        projectedLeafCount === undefined ||
        measuredPermutationCount % saltedLeafRecord.iterationCount !== 0 ||
        projectedPermutationCount !==
            projectedLeafCount *
                (measuredPermutationCount / saltedLeafRecord.iterationCount)
    ) {
        throw new Error(
            'Primitive measurement salted-leaf projection is inconsistent.',
        );
    }
    if (
        modeledCheckpointDftDimensions.get('laneCount') !==
            selectedVssDimensions.get('basePhaseLaneCount') ||
        modeledCheckpointDftDimensions.get('maximumRecomputedLeafCount') !==
            selectedVssDimensions.get('basePhaseOpeningQueryCount')! *
                modeledCheckpointDftDimensions.get('checkpointLeafCount')!
    ) {
        throw new Error(
            'Primitive measurement modeled checkpoint projection is inconsistent.',
        );
    }
    if (
        productionWeightedSourceReplayDimensions.get(
            'productionRecipeCount',
        ) !==
            selectedVssDimensions.get(
                'basePhaseDirectSourceColumnCountPerLane',
            ) ||
        productionWeightedSourceReplayDimensions.get(
            'basePhaseCoefficientChunkCountPerSource',
        ) !==
            selectedVssDimensions.get(
                'basePhaseCoefficientChunkCountPerSource',
            ) ||
        productionWeightedSourceReplayDimensions.get(
            'basePhaseReversedSourceChunkCountPerLane',
        ) !==
            selectedVssDimensions.get(
                'basePhaseReversedSourceChunkCountPerLane',
            )
    ) {
        throw new Error(
            'Primitive measurement source-replay catalogs are inconsistent.',
        );
    }
    for (const [modeledDimensionName, measuredDimensionName] of [
        ['modeledCandidateTracePackingFactor', 'tracePackingFactor'],
        ['modeledCandidatePhysicalRowWidth', 'physicalRowWidth'],
        ['modeledCandidateRelationTraceValueCount', 'traceValueCount'],
        ['modeledCandidateProverColumnCount', 'productionRecipeCount'],
        [
            'modeledCandidateProverColumnDegreeBoundExclusive',
            'proverColumnDegreeBoundExclusive',
        ],
        [
            'modeledCandidateRetainedCoefficientGroupByteLength',
            'retainedCoefficientPayloadByteLength',
        ],
        [
            'modeledCandidateLogicalRowChunkByteLength',
            'logicalRowChunkByteLength',
        ],
    ] as const) {
        if (
            selectedVssDimensions.get(modeledDimensionName) !==
            retainedGroupCandidateDimensions.get(measuredDimensionName)
        ) {
            throw new Error(
                'Primitive measurement retained-group candidate disagrees with the modeled relation geometry.',
            );
        }
    }
    for (const [modeledDimensionName, measuredDimensionName] of [
        ['modeledCandidateTracePackingFactor', 'tracePackingFactor'],
        ['modeledCandidatePhysicalRowWidth', 'physicalRowWidth'],
        ['modeledCandidateRelationTraceValueCount', 'traceValueCount'],
        ['modeledCandidateProverColumnCount', 'productionRecipeCount'],
        [
            'modeledCandidateProverColumnDegreeBoundExclusive',
            'proverColumnDegreeBoundExclusive',
        ],
        [
            'modeledCandidateCoefficientChunkCountPerSource',
            'coefficientChunkCount',
        ],
        ['modeledCandidateRowCount', 'physicalRowCount'],
        [
            'modeledCandidateRetainedCoefficientGroupByteLength',
            'retainedCoefficientPayloadByteLength',
        ],
    ] as const) {
        if (
            selectedVssDimensions.get(modeledDimensionName) !==
            rowLaneCandidateDimensions.get(measuredDimensionName)
        ) {
            throw new Error(
                'Primitive measurement row-lane candidate disagrees with the modeled relation geometry.',
            );
        }
    }
    const candidateLaneDftCount = selectedVssDimensions.get(
        'modeledCandidateLaneDftCount',
    )!;
    const candidateCoefficientChunkCount = rowLaneCandidateDimensions.get(
        'coefficientChunkCount',
    )!;
    const candidateStripeCount =
        candidateLaneDftCount / candidateCoefficientChunkCount;
    if (
        !Number.isSafeInteger(candidateStripeCount) ||
        candidateLaneDftCount !==
            rowLaneCandidateDimensions.get('physicalRowCount')! *
                rowLaneCandidateDimensions.get('laneCount')! *
                selectedVssDimensions.get(
                    'basePhaseMaterializationPassCount',
                )! ||
        selectedVssDimensions.get('modeledCandidateButterflyCount') !==
            rowLaneCandidateDimensions.get('stripeButterflyCount')! *
                candidateStripeCount ||
        selectedVssDimensions.get('modeledCandidateCoefficientFoldCount') !==
            rowLaneCandidateDimensions.get('stripeCoefficientFoldCount')! *
                candidateStripeCount ||
        selectedVssDimensions.get(
            'modeledCandidateCosetMultiplicationCount',
        ) !==
            rowLaneCandidateDimensions.get('stripeCosetMultiplicationCount')! *
                candidateStripeCount ||
        selectedVssDimensions.get(
            'modeledCandidatePrivateHighHalfValueGenerationCount',
        ) !==
            rowLaneCandidateDimensions.get('stripePrivateHighHalfValueCount')! *
                candidateStripeCount
    ) {
        throw new Error(
            'Primitive measurement row-lane workload does not reconcile to the modeled candidate.',
        );
    }
    for (const dimensionName of [
        'rangeDigitRadix',
        'tracePackingFactor',
        'traceValueCount',
        'physicalRowWidth',
        'basePhaseRowCount',
        'productionRecipeCount',
        'proverColumnDegreeBoundExclusive',
        'retainedRecipeCount',
        'retainedCoefficientPayloadByteLength',
        'replayBufferByteLength',
        'phaseMaterializationPassCount',
        'completeSourceMaterializationCount',
        'completeSourceTraceValueGenerationCount',
        'relationPlanHashByteLength',
    ] as const) {
        if (
            fusedRetainedGroupCandidateDimensions.get(dimensionName) !==
            fusedRowLaneCandidateDimensions.get(dimensionName)
        ) {
            throw new Error(
                'Primitive measurement fused VSS candidate records disagree.',
            );
        }
    }
    if (
        fusedRowLaneCandidateDimensions.get('completeLaneDftCount')! * 10 >
            selectedVssDimensions.get('basePhaseLaneDftCount')! ||
        fusedRowLaneCandidateDimensions.get('completeButterflyCount')! * 10 >
            selectedVssDimensions.get('basePhaseButterflyCount')! ||
        fusedRowLaneCandidateDimensions.get(
            'completeColumnValueDeliveryCount',
        )! *
            10 >
            selectedVssDimensions.get('basePhaseColumnValueDeliveryCount')! ||
        fusedRowLaneCandidateDimensions.get(
            'completeSaltedLeafKeccakPermutationCount',
        )! *
            10 >
            selectedVssDimensions.get(
                'basePhaseSaltedLeafKeccakPermutationCount',
            )! ||
        fusedRowLaneCandidateDimensions.get(
            'completeSourceTraceValueGenerationCount',
        )! *
            10 >
            selectedVssDimensions.get('basePhaseSourceReplayCount')! *
                selectedVssDimensions.get('traceValueCount')!
    ) {
        throw new Error(
            'Primitive measurement fused VSS candidate fails its tenfold static work gate.',
        );
    }
};

export const parseReleaseNativePrimitiveMeasurementOutput = (
    output: string,
    requireCompleteCatalog: boolean,
    expectedFocusedCaseIdentifiers?: readonly number[],
): ReleaseNativePrimitiveMeasurementEvidence => {
    const outputMarker = 'primitive measurement: ';
    const primitiveCases: PrimitiveMeasurementRecord[] = [];
    for (const outputLine of output.split(/\r?\n/u)) {
        const markerIndex = outputLine.indexOf(outputMarker);
        if (markerIndex < 0) {
            continue;
        }
        const serializedRecord = outputLine
            .slice(markerIndex + outputMarker.length)
            .trim();
        let decodedRecord: unknown;
        try {
            decodedRecord = JSON.parse(serializedRecord) as unknown;
        } catch {
            throw new Error(
                'Release-native primitive measurement output is not canonical JSON.',
            );
        }
        primitiveCases.push(
            validatePrimitiveMeasurementRecord(decodedRecord, 'release-native'),
        );
    }
    if (primitiveCases.length === 0) {
        throw new Error(
            'Release-native primitive measurement output has no measurement record.',
        );
    }
    const identifiers = primitiveCases.map((record) => record.caseIdentifier);
    if (new Set(identifiers).size !== identifiers.length) {
        throw new Error(
            'Release-native primitive measurement output duplicates a case.',
        );
    }
    if (requireCompleteCatalog) {
        if (expectedFocusedCaseIdentifiers !== undefined) {
            throw new Error(
                'Complete release-native primitive measurement output cannot declare focused cases.',
            );
        }
        requireCompletePrimitiveMeasurementCatalog(primitiveCases);
    } else if (expectedFocusedCaseIdentifiers === undefined) {
        if (primitiveCases.length !== 1) {
            throw new Error(
                'Focused release-native primitive measurement output must contain one case.',
            );
        }
    } else {
        if (
            expectedFocusedCaseIdentifiers.length === 0 ||
            new Set(expectedFocusedCaseIdentifiers).size !==
                expectedFocusedCaseIdentifiers.length ||
            expectedFocusedCaseIdentifiers.some(
                (caseIdentifier) =>
                    !Number.isSafeInteger(caseIdentifier) ||
                    caseIdentifier <= 0,
            ) ||
            primitiveCases.length !== expectedFocusedCaseIdentifiers.length ||
            expectedFocusedCaseIdentifiers.some(
                (caseIdentifier) => !identifiers.includes(caseIdentifier),
            )
        ) {
            throw new Error(
                'Focused release-native primitive measurement output differs from its expected case set.',
            );
        }
        primitiveCases.sort(
            (left, right) =>
                expectedFocusedCaseIdentifiers.indexOf(left.caseIdentifier) -
                expectedFocusedCaseIdentifiers.indexOf(right.caseIdentifier),
        );
    }
    return Object.freeze({
        primitiveCases: Object.freeze(primitiveCases),
        schemaVersion: 1,
    });
};

export const validateReleaseNativePrimitiveMeasurementEvidence = (
    value: unknown,
    requireCompleteCatalog: boolean,
    expectedFocusedCaseIdentifiers?: readonly number[],
): ReleaseNativePrimitiveMeasurementEvidence => {
    if (!isJsonObject(value)) {
        throw new Error(
            'Release-native primitive measurement evidence is not an object.',
        );
    }
    requireExactKeys(
        value,
        ['primitiveCases', 'schemaVersion'],
        'Release-native primitive measurement evidence',
    );
    if (value.schemaVersion !== 1 || !Array.isArray(value.primitiveCases)) {
        throw new Error(
            'Release-native primitive measurement evidence schema is invalid.',
        );
    }
    const primitiveCases = value.primitiveCases.map((record) =>
        validatePrimitiveMeasurementRecord(record, 'release-native'),
    );
    const identifiers = primitiveCases.map((record) => record.caseIdentifier);
    if (new Set(identifiers).size !== identifiers.length) {
        throw new Error(
            'Release-native primitive measurement evidence duplicates a case.',
        );
    }
    if (requireCompleteCatalog) {
        if (expectedFocusedCaseIdentifiers !== undefined) {
            throw new Error(
                'Complete release-native primitive measurement evidence cannot declare focused cases.',
            );
        }
        requireCompletePrimitiveMeasurementCatalog(primitiveCases);
    } else if (expectedFocusedCaseIdentifiers === undefined) {
        if (primitiveCases.length !== 1) {
            throw new Error(
                'Focused release-native primitive measurement evidence must contain one case.',
            );
        }
    } else if (
        expectedFocusedCaseIdentifiers.length === 0 ||
        new Set(expectedFocusedCaseIdentifiers).size !==
            expectedFocusedCaseIdentifiers.length ||
        primitiveCases.length !== expectedFocusedCaseIdentifiers.length ||
        primitiveCases.some(
            (record, recordIndex) =>
                record.caseIdentifier !==
                expectedFocusedCaseIdentifiers[recordIndex],
        )
    ) {
        throw new Error(
            'Focused release-native primitive measurement evidence differs from its expected canonical case set.',
        );
    }
    return Object.freeze({
        primitiveCases: Object.freeze(primitiveCases),
        schemaVersion: 1,
    });
};

const requireFiniteNonnegativeNumber = (
    value: unknown,
    label: string,
    allowZero = true,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isFinite(value) ||
        value < 0 ||
        (!allowZero && value === 0)
    ) {
        throw new Error(`${label} is not a finite nonnegative number.`);
    }
    return value;
};

const physicalAccountingKeys = [
    'deletedByteLength',
    'deletionCount',
    'deletionDurationMilliseconds',
    'physicalReadByteLength',
    'physicalReadCallCount',
    'physicalQuotaByteLength',
    'physicalQuotaHeadroomByteLength',
    'physicalQuotaReservedByteLength',
    'physicalStoredEndByteLength',
    'physicalStoredPeakByteLength',
    'physicalStoredStartByteLength',
    'physicalWriteByteLength',
    'physicalWriteCallCount',
    'repairHashCallCount',
    'repairHashedByteLength',
    'storageRequestCount',
    'storageTransactionCount',
] as const satisfies readonly (keyof PrimitiveStoragePhysicalAccounting)[];

const validateStorageEstimate = (
    value: unknown,
    label: string,
): Readonly<{ quota?: number; usage?: number }> => {
    if (!isJsonObject(value)) {
        throw new Error(`${label} is not an object.`);
    }
    const keys = Object.keys(value);
    if (
        keys.some((key) => key !== 'quota' && key !== 'usage') ||
        keys.length === 0
    ) {
        throw new Error(`${label} has noncanonical fields.`);
    }
    const quota =
        value.quota === undefined
            ? undefined
            : requireFiniteNonnegativeNumber(value.quota, `${label} quota`);
    const usage =
        value.usage === undefined
            ? undefined
            : requireFiniteNonnegativeNumber(value.usage, `${label} usage`);
    return Object.freeze({
        ...(quota === undefined ? {} : { quota }),
        ...(usage === undefined ? {} : { usage }),
    });
};

export const validateDesktopBrowserAuthenticatedStorageMeasurement = (
    value: unknown,
    expectedRecordByteLength: number,
): DesktopBrowserAuthenticatedStorageMeasurement => {
    if (!isJsonObject(value)) {
        throw new Error(
            'Desktop-browser authenticated storage evidence is absent.',
        );
    }
    requireExactKeys(
        value,
        [
            'cleanupElapsedMilliseconds',
            'iterationCount',
            'physicalAccounting',
            'readElapsedMilliseconds',
            'readPassCount',
            'recordByteLength',
            'storageEstimateAfter',
            'storageEstimateBefore',
            'writeElapsedMilliseconds',
        ],
        'Desktop-browser authenticated storage evidence',
    );
    if (!isJsonObject(value.physicalAccounting)) {
        throw new Error(
            'Desktop-browser storage physical accounting is absent.',
        );
    }
    requireExactKeys(
        value.physicalAccounting,
        physicalAccountingKeys,
        'Desktop-browser storage physical accounting',
    );
    const rawPhysicalAccounting = value.physicalAccounting;
    const physicalAccountingEntries = physicalAccountingKeys.map(
        (key) =>
            [
                key,
                requireFiniteNonnegativeNumber(
                    rawPhysicalAccounting[key],
                    `Desktop-browser storage ${key}`,
                ),
            ] as const,
    );
    const physicalAccounting = Object.freeze(
        Object.fromEntries(
            physicalAccountingEntries,
        ) as PrimitiveStoragePhysicalAccounting,
    );
    const storage = Object.freeze({
        cleanupElapsedMilliseconds: requireFiniteNonnegativeNumber(
            value.cleanupElapsedMilliseconds,
            'Desktop-browser storage cleanup duration',
            false,
        ),
        iterationCount: requireSafeUnsignedInteger(
            value.iterationCount,
            'Desktop-browser storage iteration count',
        ),
        physicalAccounting,
        readElapsedMilliseconds: requireFiniteNonnegativeNumber(
            value.readElapsedMilliseconds,
            'Desktop-browser storage read duration',
            false,
        ),
        readPassCount: requireSafeUnsignedInteger(
            value.readPassCount,
            'Desktop-browser storage read-pass count',
        ),
        recordByteLength: requireSafeUnsignedInteger(
            value.recordByteLength,
            'Desktop-browser storage record byte length',
        ),
        storageEstimateAfter: validateStorageEstimate(
            value.storageEstimateAfter,
            'Desktop-browser storage estimate after',
        ),
        storageEstimateBefore: validateStorageEstimate(
            value.storageEstimateBefore,
            'Desktop-browser storage estimate before',
        ),
        writeElapsedMilliseconds: requireFiniteNonnegativeNumber(
            value.writeElapsedMilliseconds,
            'Desktop-browser storage write duration',
            false,
        ),
    });
    if (
        storage.iterationCount !== 4 ||
        storage.readPassCount !== 2 ||
        storage.recordByteLength !== expectedRecordByteLength ||
        physicalAccounting.physicalWriteByteLength <
            storage.recordByteLength * storage.iterationCount ||
        physicalAccounting.physicalReadByteLength <
            storage.recordByteLength *
                storage.iterationCount *
                storage.readPassCount ||
        physicalAccounting.physicalStoredPeakByteLength <
            storage.recordByteLength
    ) {
        throw new Error(
            'Desktop-browser authenticated storage evidence does not cover the exact scratch-record geometry.',
        );
    }
    return storage;
};

export const validateDesktopBrowserBoundaryCopyMeasurement = (
    value: unknown,
    expectedByteLength: number,
): DesktopBrowserBoundaryCopyMeasurement => {
    if (!isJsonObject(value)) {
        throw new Error('Desktop-browser boundary-copy evidence is absent.');
    }
    requireExactKeys(
        value,
        [
            'byteLengthPerCopy',
            'checksumHex',
            'copyFromWasmElapsedMilliseconds',
            'copyIntoWasmElapsedMilliseconds',
            'iterationCount',
            'wasmMemoryByteLengthAfter',
            'wasmMemoryByteLengthBefore',
        ],
        'Desktop-browser boundary-copy evidence',
    );
    const wasmMemoryByteLengthBefore = requireSafeUnsignedInteger(
        value.wasmMemoryByteLengthBefore,
        'Boundary-copy initial WASM memory',
    );
    const wasmMemoryByteLengthAfter = requireSafeUnsignedInteger(
        value.wasmMemoryByteLengthAfter,
        'Boundary-copy final WASM memory',
    );
    const measurement = Object.freeze({
        byteLengthPerCopy: requireSafeUnsignedInteger(
            value.byteLengthPerCopy,
            'Boundary-copy byte length',
        ),
        checksumHex: String(value.checksumHex),
        copyFromWasmElapsedMilliseconds: requireFiniteNonnegativeNumber(
            value.copyFromWasmElapsedMilliseconds,
            'Boundary-copy read duration',
            false,
        ),
        copyIntoWasmElapsedMilliseconds: requireFiniteNonnegativeNumber(
            value.copyIntoWasmElapsedMilliseconds,
            'Boundary-copy write duration',
            false,
        ),
        iterationCount: requireSafeUnsignedInteger(
            value.iterationCount,
            'Boundary-copy iteration count',
        ),
        wasmMemoryByteLengthAfter,
        wasmMemoryByteLengthBefore,
    });
    if (
        !/^[0-9a-f]{8}$/u.test(measurement.checksumHex) ||
        measurement.byteLengthPerCopy !== expectedByteLength ||
        measurement.iterationCount !==
            desktopBrowserBoundaryCopyIterationCount ||
        wasmMemoryByteLengthAfter < wasmMemoryByteLengthBefore
    ) {
        throw new Error(
            'Desktop-browser boundary-copy geometry or checksum is invalid.',
        );
    }
    return measurement;
};

export const validateDesktopBrowserPrimitiveCaseMeasurement = (
    value: unknown,
): DesktopBrowserPrimitiveCaseMeasurement => {
    if (!isJsonObject(value)) {
        throw new Error('Desktop-browser primitive case is not an object.');
    }
    requireExactKeys(
        value,
        [
            'record',
            'wallElapsedMilliseconds',
            'wasmMemoryByteLengthAfter',
            'wasmMemoryByteLengthBefore',
        ],
        'Desktop-browser primitive case',
    );
    const record = validatePrimitiveMeasurementRecord(
        value.record,
        'wasm32-unknown-unknown',
    );
    const wasmMemoryByteLengthBefore = requireSafeUnsignedInteger(
        value.wasmMemoryByteLengthBefore,
        'Primitive case initial WASM memory',
    );
    const wasmMemoryByteLengthAfter = requireSafeUnsignedInteger(
        value.wasmMemoryByteLengthAfter,
        'Primitive case final WASM memory',
    );
    if (wasmMemoryByteLengthAfter < wasmMemoryByteLengthBefore) {
        throw new Error('Primitive case WASM memory shrank unexpectedly.');
    }
    return Object.freeze({
        record,
        wallElapsedMilliseconds: requireFiniteNonnegativeNumber(
            value.wallElapsedMilliseconds,
            'Primitive case wall duration',
            false,
        ),
        wasmMemoryByteLengthAfter,
        wasmMemoryByteLengthBefore,
    });
};

const validateBrowserIdentity = (
    value: Readonly<Record<string, unknown>>,
    expectedBrowserEngine?: 'chromium' | 'firefox',
): Readonly<{
    browserEngine: 'chromium' | 'firefox';
    browserUserAgent: string;
}> => {
    if (
        (value.browserEngine !== 'chromium' &&
            value.browserEngine !== 'firefox') ||
        (expectedBrowserEngine !== undefined &&
            value.browserEngine !== expectedBrowserEngine) ||
        typeof value.browserUserAgent !== 'string' ||
        value.browserUserAgent.length === 0 ||
        value.browserUserAgent.length > 1_024
    ) {
        throw new Error(
            'Desktop-browser primitive evidence has an invalid engine or user agent.',
        );
    }
    return Object.freeze({
        browserEngine: value.browserEngine,
        browserUserAgent: value.browserUserAgent,
    });
};

export const validateDesktopBrowserFocusedPrimitiveMeasurementEvidence = (
    value: unknown,
    expectedBrowserEngine?: 'chromium' | 'firefox',
    expectedCaseIdentifier?: number,
): DesktopBrowserFocusedPrimitiveMeasurementEvidence => {
    if (!isJsonObject(value)) {
        throw new Error(
            'Focused desktop-browser primitive evidence is not an object.',
        );
    }
    requireExactKeys(
        value,
        ['browserEngine', 'browserUserAgent', 'primitiveCase', 'schemaVersion'],
        'Focused desktop-browser primitive evidence',
    );
    if (value.schemaVersion !== 1) {
        throw new Error(
            'Focused desktop-browser primitive evidence has an invalid version.',
        );
    }
    const browserIdentity = validateBrowserIdentity(
        value,
        expectedBrowserEngine,
    );
    const primitiveCase = validateDesktopBrowserPrimitiveCaseMeasurement(
        value.primitiveCase,
    );
    if (
        expectedCaseIdentifier !== undefined &&
        primitiveCase.record.caseIdentifier !== expectedCaseIdentifier
    ) {
        throw new Error(
            `Focused desktop-browser primitive evidence contains case ${String(primitiveCase.record.caseIdentifier)} instead of case ${String(expectedCaseIdentifier)}.`,
        );
    }
    return Object.freeze({
        ...browserIdentity,
        primitiveCase,
        schemaVersion: 1,
    });
};

export const validateDesktopBrowserPrimitiveMeasurementEvidence = (
    value: unknown,
    expectedBrowserEngine?: 'chromium' | 'firefox',
): DesktopBrowserPrimitiveMeasurementEvidence => {
    if (!isJsonObject(value)) {
        throw new Error('Desktop-browser primitive evidence is not an object.');
    }
    requireExactKeys(
        value,
        [
            'boundaryCopies',
            'browserEngine',
            'browserUserAgent',
            'primitiveCases',
            'schemaVersion',
            'storage',
        ],
        'Desktop-browser primitive evidence',
    );
    if (value.schemaVersion !== 1) {
        throw new Error(
            'Desktop-browser primitive evidence has an invalid version.',
        );
    }
    const browserIdentity = validateBrowserIdentity(
        value,
        expectedBrowserEngine,
    );
    if (!Array.isArray(value.primitiveCases)) {
        throw new Error('Desktop-browser primitive cases are absent.');
    }
    const primitiveCases = value.primitiveCases.map((rawCase) =>
        validateDesktopBrowserPrimitiveCaseMeasurement(rawCase),
    );
    requireCompletePrimitiveMeasurementCatalog(
        primitiveCases.map((measurement) => measurement.record),
    );

    const scratchCodec = primitiveCases.find(
        (measurement) => measurement.record.caseIdentifier === 6,
    );
    const expectedRecordByteLength = scratchCodec?.record.dimensions.find(
        (dimension) => dimension.name === 'canonicalEnvelopeByteLength',
    )?.value;
    if (expectedRecordByteLength === undefined) {
        throw new Error(
            'Desktop-browser scratch-record extent is absent from the codec measurement.',
        );
    }
    const storage = validateDesktopBrowserAuthenticatedStorageMeasurement(
        value.storage,
        expectedRecordByteLength,
    );
    const boundaryCopies = validateDesktopBrowserBoundaryCopyMeasurement(
        value.boundaryCopies,
        expectedRecordByteLength,
    );

    return Object.freeze({
        boundaryCopies,
        ...browserIdentity,
        primitiveCases: Object.freeze(primitiveCases),
        schemaVersion: 1,
        storage,
    });
};

const validateMeasurementWasmIdentity = (
    value: unknown,
): DesktopBrowserPrimitiveMeasurementBundle['measurementWasm'] => {
    if (!isJsonObject(value)) {
        throw new Error(
            'Desktop-browser primitive-measurement WASM identity is absent.',
        );
    }
    requireExactKeys(
        value,
        ['byteLength', 'normalizedSha256Hex', 'rawSha256Hex'],
        'Desktop-browser primitive-measurement WASM identity',
    );
    const measurementWasm = Object.freeze({
        byteLength: requireSafeUnsignedInteger(
            value.byteLength,
            'Primitive-measurement WASM byte length',
        ),
        normalizedSha256Hex: String(value.normalizedSha256Hex),
        rawSha256Hex: String(value.rawSha256Hex),
    });
    if (
        !/^[0-9a-f]{64}$/u.test(measurementWasm.normalizedSha256Hex) ||
        !/^[0-9a-f]{64}$/u.test(measurementWasm.rawSha256Hex)
    ) {
        throw new Error(
            'Desktop-browser primitive-measurement WASM hash is noncanonical.',
        );
    }
    return measurementWasm;
};

const requireCanonicalBrowserEngineOrder = (
    browserEngines: readonly ('chromium' | 'firefox')[],
): void => {
    if (
        browserEngines.length === 0 ||
        browserEngines.length > 2 ||
        new Set(browserEngines).size !== browserEngines.length ||
        (browserEngines.length === 2 &&
            (browserEngines[0] !== 'chromium' ||
                browserEngines[1] !== 'firefox'))
    ) {
        throw new Error(
            'Desktop-browser primitive-measurement bundle engines are duplicated or noncanonical.',
        );
    }
};

export const validateDesktopBrowserPrimitiveMeasurementBundle = (
    value: unknown,
): DesktopBrowserPrimitiveMeasurementBundle => {
    if (!isJsonObject(value)) {
        throw new Error(
            'Desktop-browser primitive-measurement bundle is not an object.',
        );
    }
    requireExactKeys(
        value,
        ['browserEvidence', 'measurementWasm', 'schemaVersion'],
        'Desktop-browser primitive-measurement bundle',
    );
    if (value.schemaVersion !== 1 || !Array.isArray(value.browserEvidence)) {
        throw new Error(
            'Desktop-browser primitive-measurement bundle has an invalid schema.',
        );
    }
    const browserEvidence = value.browserEvidence.map((evidence) =>
        validateDesktopBrowserPrimitiveMeasurementEvidence(evidence),
    );
    requireCanonicalBrowserEngineOrder(
        browserEvidence.map((evidence) => evidence.browserEngine),
    );
    const measurementWasm = validateMeasurementWasmIdentity(
        value.measurementWasm,
    );
    return Object.freeze({
        browserEvidence: Object.freeze(browserEvidence),
        measurementWasm,
        schemaVersion: 1,
    });
};

export const validateDesktopBrowserFocusedPrimitiveMeasurementBundle = (
    value: unknown,
    expectedCaseIdentifiers?: number | readonly number[],
): DesktopBrowserFocusedPrimitiveMeasurementBundle => {
    if (!isJsonObject(value)) {
        throw new Error(
            'Focused desktop-browser primitive-measurement bundle is not an object.',
        );
    }
    requireExactKeys(
        value,
        ['focusedPrimitiveEvidence', 'measurementWasm', 'schemaVersion'],
        'Focused desktop-browser primitive-measurement bundle',
    );
    if (
        value.schemaVersion !== 1 ||
        !Array.isArray(value.focusedPrimitiveEvidence)
    ) {
        throw new Error(
            'Focused desktop-browser primitive-measurement bundle has an invalid schema.',
        );
    }
    const focusedPrimitiveEvidence = value.focusedPrimitiveEvidence.map(
        (evidence) =>
            validateDesktopBrowserFocusedPrimitiveMeasurementEvidence(evidence),
    );
    const normalizedExpectedCaseIdentifiers =
        expectedCaseIdentifiers === undefined
            ? undefined
            : typeof expectedCaseIdentifiers === 'number'
              ? [expectedCaseIdentifiers]
              : [...expectedCaseIdentifiers];
    if (
        normalizedExpectedCaseIdentifiers !== undefined &&
        (normalizedExpectedCaseIdentifiers.length === 0 ||
            new Set(normalizedExpectedCaseIdentifiers).size !==
                normalizedExpectedCaseIdentifiers.length ||
            normalizedExpectedCaseIdentifiers.some(
                (caseIdentifier, caseIndex) =>
                    !Number.isSafeInteger(caseIdentifier) ||
                    caseIdentifier <= 0 ||
                    primitiveMeasurementCaseCatalog.findIndex(
                        (entry) => entry.caseIdentifier === caseIdentifier,
                    ) <
                        (caseIndex === 0
                            ? 0
                            : primitiveMeasurementCaseCatalog.findIndex(
                                  (entry) =>
                                      entry.caseIdentifier ===
                                      normalizedExpectedCaseIdentifiers[
                                          caseIndex - 1
                                      ],
                              ) + 1),
            ))
    ) {
        throw new Error(
            'Focused desktop-browser primitive-measurement bundle expected case identifiers are empty, duplicated, unsupported, or noncanonical.',
        );
    }
    const browserGroups: Array<{
        browserEngine: 'chromium' | 'firefox';
        caseIdentifiers: number[];
    }> = [];
    for (const evidence of focusedPrimitiveEvidence) {
        let currentGroup = browserGroups[browserGroups.length - 1];
        if (currentGroup?.browserEngine !== evidence.browserEngine) {
            if (
                browserGroups.some(
                    (group) => group.browserEngine === evidence.browserEngine,
                )
            ) {
                throw new Error(
                    'Focused desktop-browser primitive-measurement bundle has noncontiguous browser groups.',
                );
            }
            currentGroup = {
                browserEngine: evidence.browserEngine,
                caseIdentifiers: [],
            };
            browserGroups.push(currentGroup);
        }
        currentGroup.caseIdentifiers.push(
            evidence.primitiveCase.record.caseIdentifier,
        );
    }
    requireCanonicalBrowserEngineOrder(
        browserGroups.map((group) => group.browserEngine),
    );
    const canonicalCaseIdentifiers =
        normalizedExpectedCaseIdentifiers ??
        (browserGroups[0]?.caseIdentifiers.length === 1
            ? browserGroups[0].caseIdentifiers
            : undefined);
    if (
        canonicalCaseIdentifiers === undefined ||
        browserGroups.some(
            (group) =>
                group.caseIdentifiers.length !==
                    canonicalCaseIdentifiers.length ||
                group.caseIdentifiers.some(
                    (caseIdentifier, caseIndex) =>
                        caseIdentifier !== canonicalCaseIdentifiers[caseIndex],
                ),
        )
    ) {
        throw new Error(
            'Focused desktop-browser primitive-measurement bundle differs from its exact canonical case set.',
        );
    }
    return Object.freeze({
        focusedPrimitiveEvidence: Object.freeze(focusedPrimitiveEvidence),
        measurementWasm: validateMeasurementWasmIdentity(value.measurementWasm),
        schemaVersion: 1,
    });
};
