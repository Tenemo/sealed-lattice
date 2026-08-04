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
            modeledCandidateCoefficientChunkCountPerSource: 9,
            modeledCandidateColumnValueDeliveryCount: 3_623_878_656,
            modeledCandidateLaneDftCount: 6_912,
            modeledCandidateLeafHashQueryCount: 33_554_432,
            modeledCandidateLogicalRowChunkByteLength: 16_777_216,
            modeledCandidateMaterialGroupCount: 8,
            modeledCandidateMaterialProverColumnCount: 720,
            modeledCandidateMaximumRangeConstraintNumeratorDegree: 792_573,
            modeledCandidateMerkleParentHashQueryCount: 33_554_430,
            modeledCandidateOpeningDegreeBoundExclusive: 2_097_152,
            modeledCandidatePhysicalRowWidth: 64,
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
        const phaseLeafPermutationCount = (logicalLeafWidth: number): number =>
            Math.floor((7 + 128 / 8 + logicalLeafWidth) / 17) + 1;
        const messageTraceValueCount = traceValueCount / tracePackingFactor;
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
                    phaseLeafPermutationCount(rowCount) &&
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
                    phaseLeafPermutationCount(modeledCandidateRowCount) &&
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
    if (caseIdentifier === 9) {
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
    if (
        saltedLeafRecord === undefined ||
        selectedVssRecord === undefined ||
        modeledCheckpointDftRecord === undefined ||
        productionWeightedSourceReplayRecord === undefined ||
        retainedGroupCandidateRecord === undefined
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
};

export const parseReleaseNativePrimitiveMeasurementOutput = (
    output: string,
    requireCompleteCatalog: boolean,
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
        requireCompletePrimitiveMeasurementCatalog(primitiveCases);
    } else if (primitiveCases.length !== 1) {
        throw new Error(
            'Focused release-native primitive measurement output must contain one case.',
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
        requireCompletePrimitiveMeasurementCatalog(primitiveCases);
    } else if (primitiveCases.length !== 1) {
        throw new Error(
            'Focused release-native primitive measurement evidence must contain one case.',
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
    expectedCaseIdentifier?: number,
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
            validateDesktopBrowserFocusedPrimitiveMeasurementEvidence(
                evidence,
                undefined,
                expectedCaseIdentifier,
            ),
    );
    requireCanonicalBrowserEngineOrder(
        focusedPrimitiveEvidence.map((evidence) => evidence.browserEngine),
    );
    const caseIdentifiers = new Set(
        focusedPrimitiveEvidence.map(
            (evidence) => evidence.primitiveCase.record.caseIdentifier,
        ),
    );
    if (caseIdentifiers.size !== 1) {
        throw new Error(
            'Focused desktop-browser primitive-measurement bundle mixes case identifiers.',
        );
    }
    return Object.freeze({
        focusedPrimitiveEvidence: Object.freeze(focusedPrimitiveEvidence),
        measurementWasm: validateMeasurementWasmIdentity(value.measurementWasm),
        schemaVersion: 1,
    });
};
