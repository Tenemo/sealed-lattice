import {
    requireCompletePrimitiveMeasurementCatalog,
    type DesktopBrowserPrimitiveMeasurementEvidence,
    type PrimitiveMeasurementRecord,
    type ReleaseNativePrimitiveMeasurementEvidence,
} from './primitive-measurement-evidence.js';

const merkleDigestByteLength = 64;
const scratchRecordPlaintextByteLength = 1_048_576;
const nominalScratchByteLength = 268_435_456;
const automaticScratchByteLength = 402_653_184;
const maximumScratchByteLength = 1_073_741_824;
const selectedCheckpointLevel = 2;

type ProjectionTarget = Readonly<{
    browserEngine?: 'chromium' | 'firefox';
    primitiveCases: readonly PrimitiveMeasurementRecord[];
    storage?: DesktopBrowserPrimitiveMeasurementEvidence['storage'];
    boundaryCopies?: DesktopBrowserPrimitiveMeasurementEvidence['boundaryCopies'];
    target: 'release-native' | 'wasm32-unknown-unknown';
}>;

type WorkCounts = Readonly<{
    laneDftCount: number;
    leafHashQueryCount: number;
    merkleParentHashQueryCount: number;
    privateLeafSaltDerivationCount: number;
    sourceReplayCount: number;
}>;

export type VssBaseMaterializationProjection = Readonly<{
    checkpointCandidates: readonly Readonly<Record<string, unknown>>[];
    currentTwoPass: Readonly<{
        columnValueDeliveryCount: number;
        laneDftCount: number;
        leafHashQueryCount: number;
        merkleParentHashQueryCount: number;
        privateLeafSaltDerivationCount: number;
        saltedLeafKeccakPermutationCount: number;
        sourceReplayCount: number;
        transportedValueByteLength: number;
    }>;
    ledgerIdentity: Readonly<{
        basePhaseLaneCount: number;
        basePhaseLogicalChunkCountPerLane: number;
        basePhaseMaterializationPassCount: number;
        basePhaseOpeningQueryCount: number;
        basePhaseRowCount: number;
        aggregateWidePadQueryCount: number;
    }>;
    schemaVersion: 1;
    selectedCheckpointLevel: 2;
    targetProjections: readonly Readonly<Record<string, unknown>>[];
}>;

const dimensionsByName = (
    record: PrimitiveMeasurementRecord,
): ReadonlyMap<string, number> =>
    new Map(
        record.dimensions.map((dimension) => [dimension.name, dimension.value]),
    );

const requireDimension = (
    record: PrimitiveMeasurementRecord,
    dimensionName: string,
): number => {
    const value = dimensionsByName(record).get(dimensionName);
    if (value === undefined) {
        throw new Error(
            `Primitive measurement ${record.caseName} lacks ${dimensionName}.`,
        );
    }
    return value;
};

const requireCase = (
    records: readonly PrimitiveMeasurementRecord[],
    caseIdentifier: number,
): PrimitiveMeasurementRecord => {
    const record = records.find(
        (candidate) => candidate.caseIdentifier === caseIdentifier,
    );
    if (record === undefined) {
        throw new Error(
            `Primitive measurement case ${caseIdentifier} is absent.`,
        );
    }
    return record;
};

const scaleElapsedNanoseconds = (
    elapsedNanoseconds: number,
    projectedOperationCount: number,
    measuredOperationCount: number,
): number => {
    const numerator =
        BigInt(elapsedNanoseconds) * BigInt(projectedOperationCount);
    const denominator = BigInt(measuredOperationCount);
    const rounded = (numerator + denominator / 2n) / denominator;
    const projected = Number(rounded);
    if (!Number.isSafeInteger(projected) || projected <= 0) {
        throw new Error(
            'Primitive duration projection exceeds a safe integer.',
        );
    }
    return projected;
};

const projectPrimitiveOwners = (
    primitiveCases: readonly PrimitiveMeasurementRecord[],
    work: WorkCounts,
): Readonly<{
    laneDftNanoseconds: number;
    leafHashNanoseconds: number;
    merkleParentHashNanoseconds: number;
    privateLeafSaltNanoseconds: number;
    sourceReplayNanoseconds: number;
    totalNanoseconds: number;
}> => {
    const laneDft = requireCase(primitiveCases, 1);
    const leafHash = requireCase(primitiveCases, 2);
    const privateLeafSalt = requireCase(primitiveCases, 3);
    const merkleParentHash = requireCase(primitiveCases, 4);
    const sourceReplay = requireCase(primitiveCases, 8);
    const laneDftNanoseconds = scaleElapsedNanoseconds(
        laneDft.elapsedNanoseconds,
        work.laneDftCount,
        laneDft.iterationCount,
    );
    const leafHashNanoseconds = scaleElapsedNanoseconds(
        leafHash.elapsedNanoseconds,
        work.leafHashQueryCount,
        leafHash.iterationCount,
    );
    const privateLeafSaltNanoseconds = scaleElapsedNanoseconds(
        privateLeafSalt.elapsedNanoseconds,
        work.privateLeafSaltDerivationCount,
        privateLeafSalt.iterationCount,
    );
    const merkleParentHashNanoseconds = scaleElapsedNanoseconds(
        merkleParentHash.elapsedNanoseconds,
        work.merkleParentHashQueryCount,
        requireDimension(merkleParentHash, 'merkleParentHashCount'),
    );
    const productionRecipeCount = requireDimension(
        sourceReplay,
        'productionRecipeCount',
    );
    if (!Number.isSafeInteger(work.sourceReplayCount / productionRecipeCount)) {
        throw new Error(
            'VSS source-replay count is not an integral production-catalog pass count.',
        );
    }
    const sourceCatalogPassCount =
        work.sourceReplayCount / productionRecipeCount;
    const sourceReplayNanoseconds = scaleElapsedNanoseconds(
        sourceReplay.elapsedNanoseconds,
        sourceCatalogPassCount,
        sourceReplay.iterationCount,
    );
    const totalNanoseconds = [
        laneDftNanoseconds,
        leafHashNanoseconds,
        privateLeafSaltNanoseconds,
        merkleParentHashNanoseconds,
        sourceReplayNanoseconds,
    ].reduce((total, value) => total + value, 0);
    if (!Number.isSafeInteger(totalNanoseconds)) {
        throw new Error('Primitive owner total exceeds a safe integer.');
    }
    return Object.freeze({
        laneDftNanoseconds,
        leafHashNanoseconds,
        merkleParentHashNanoseconds,
        privateLeafSaltNanoseconds,
        sourceReplayNanoseconds,
        totalNanoseconds,
    });
};

const assertCatalogCorrespondence = (
    nativeCases: readonly PrimitiveMeasurementRecord[],
    browserCases: readonly PrimitiveMeasurementRecord[],
): void => {
    requireCompletePrimitiveMeasurementCatalog(nativeCases);
    requireCompletePrimitiveMeasurementCatalog(browserCases);
    for (const nativeRecord of nativeCases) {
        const browserRecord = requireCase(
            browserCases,
            nativeRecord.caseIdentifier,
        );
        const targetDependentDimensionNames = new Set(
            nativeRecord.caseIdentifier === 5 ||
                nativeRecord.caseIdentifier === 8
                ? ['retainedInputByteLength']
                : nativeRecord.caseIdentifier === 7
                  ? [
                        'lowerScheduleHeapByteLength',
                        'higherScheduleHeapByteLength',
                    ]
                  : [],
        );
        const dimensionsCorrespond =
            nativeRecord.dimensions.length ===
                browserRecord.dimensions.length &&
            nativeRecord.dimensions.every((nativeDimension, dimensionIndex) => {
                const browserDimension =
                    browserRecord.dimensions[dimensionIndex];
                return (
                    browserDimension?.name === nativeDimension.name &&
                    (targetDependentDimensionNames.has(nativeDimension.name) ||
                        browserDimension.value === nativeDimension.value)
                );
            });
        if (
            nativeRecord.caseName !== browserRecord.caseName ||
            nativeRecord.checksumHex !== browserRecord.checksumHex ||
            !dimensionsCorrespond
        ) {
            throw new Error(
                `Primitive measurement ${nativeRecord.caseName} differs across native and WASM targets.`,
            );
        }
    }
};

const projectCheckpointStorage = (
    target: ProjectionTarget,
    recordCount: number,
): Readonly<Record<string, number>> | undefined => {
    if (target.storage === undefined || target.boundaryCopies === undefined) {
        return undefined;
    }
    const scratchCodec = requireCase(target.primitiveCases, 6);
    const codecNanoseconds = scaleElapsedNanoseconds(
        scratchCodec.elapsedNanoseconds,
        recordCount,
        scratchCodec.iterationCount,
    );
    const storageWriteMilliseconds =
        (target.storage.writeElapsedMilliseconds /
            target.storage.iterationCount) *
        recordCount;
    const storageReadMilliseconds =
        (target.storage.readElapsedMilliseconds /
            (target.storage.iterationCount * target.storage.readPassCount)) *
        recordCount;
    const storageCleanupMilliseconds =
        (target.storage.cleanupElapsedMilliseconds /
            target.storage.iterationCount) *
        recordCount;
    const boundaryCopyIntoWasmMilliseconds =
        (target.boundaryCopies.copyIntoWasmElapsedMilliseconds /
            target.boundaryCopies.iterationCount) *
        recordCount;
    const boundaryCopyFromWasmMilliseconds =
        (target.boundaryCopies.copyFromWasmElapsedMilliseconds /
            target.boundaryCopies.iterationCount) *
        recordCount;
    return Object.freeze({
        boundaryCopyFromWasmMilliseconds,
        boundaryCopyIntoWasmMilliseconds,
        codecNanoseconds,
        storageCleanupMilliseconds,
        storageReadMilliseconds,
        storageWriteMilliseconds,
    });
};

export const deriveVssBaseMaterializationProjection = (input: {
    readonly browserEvidence: readonly DesktopBrowserPrimitiveMeasurementEvidence[];
    readonly nativeEvidence: ReleaseNativePrimitiveMeasurementEvidence;
}): VssBaseMaterializationProjection => {
    const nativeCases = input.nativeEvidence.primitiveCases;
    requireCompletePrimitiveMeasurementCatalog(nativeCases);
    if (
        input.browserEvidence.length !== 2 ||
        input.browserEvidence[0]?.browserEngine !== 'chromium' ||
        input.browserEvidence[1]?.browserEngine !== 'firefox'
    ) {
        throw new Error(
            'VSS materialization projection requires Chromium and Firefox evidence in canonical order.',
        );
    }
    for (const browserEvidence of input.browserEvidence) {
        assertCatalogCorrespondence(
            nativeCases,
            browserEvidence.primitiveCases.map(
                (measurement) => measurement.record,
            ),
        );
    }
    const ledgerRecord = requireCase(nativeCases, 5);
    const ledger = dimensionsByName(ledgerRecord);
    const materializationPassCount = requireDimension(
        ledgerRecord,
        'basePhaseMaterializationPassCount',
    );
    const rowCount = requireDimension(ledgerRecord, 'basePhaseRowCount');
    const laneCount = requireDimension(ledgerRecord, 'basePhaseLaneCount');
    const logicalChunkCountPerLane = requireDimension(
        ledgerRecord,
        'basePhaseLogicalChunkCountPerLane',
    );
    const openingQueryCount = requireDimension(
        ledgerRecord,
        'basePhaseOpeningQueryCount',
    );
    const aggregateWidePadQueryCount = requireDimension(
        ledgerRecord,
        'aggregateWidePadQueryCount',
    );
    const currentWork: WorkCounts = Object.freeze({
        laneDftCount: requireDimension(ledgerRecord, 'basePhaseLaneDftCount'),
        leafHashQueryCount: requireDimension(
            ledgerRecord,
            'basePhaseLeafHashQueryCount',
        ),
        merkleParentHashQueryCount: requireDimension(
            ledgerRecord,
            'basePhaseMerkleParentHashQueryCount',
        ),
        privateLeafSaltDerivationCount: requireDimension(
            ledgerRecord,
            'basePhasePrivateLeafSaltDerivationCount',
        ),
        sourceReplayCount: requireDimension(
            ledgerRecord,
            'basePhaseSourceReplayCount',
        ),
    });
    const leafCountPerPass =
        currentWork.leafHashQueryCount / materializationPassCount;
    if (
        !Number.isSafeInteger(leafCountPerPass) ||
        !Number.isSafeInteger(
            currentWork.laneDftCount / materializationPassCount,
        ) ||
        ledger.get('basePhaseBoundSourceReplayCount') !== 0 ||
        ledger.get('basePhaseProverSourceReplayCount') !==
            currentWork.sourceReplayCount
    ) {
        throw new Error(
            'Selected VSS base materialization ledger has an unsupported replay class or pass partition.',
        );
    }

    const targets: ProjectionTarget[] = [
        Object.freeze({
            primitiveCases: nativeCases,
            target: 'release-native' as const,
        }),
        ...input.browserEvidence.map((evidence) =>
            Object.freeze({
                boundaryCopies: evidence.boundaryCopies,
                browserEngine: evidence.browserEngine,
                primitiveCases: evidence.primitiveCases.map(
                    (measurement) => measurement.record,
                ),
                storage: evidence.storage,
                target: 'wasm32-unknown-unknown' as const,
            }),
        ),
    ];
    const currentTargetProjections = targets.map((target) =>
        Object.freeze({
            ...(target.browserEngine === undefined
                ? {}
                : { browserEngine: target.browserEngine }),
            currentTwoPassOwners: projectPrimitiveOwners(
                target.primitiveCases,
                currentWork,
            ),
            target: target.target,
        }),
    );

    const scratchCodecRecord = requireCase(nativeCases, 6);
    const scratchRecordByteLength = requireDimension(
        scratchCodecRecord,
        'canonicalEnvelopeByteLength',
    );
    const checkpointCandidates = [1, 2, 3, 4, 5].map((checkpointLevel) => {
        const leavesPerCheckpoint = 2 ** checkpointLevel;
        const checkpointNodeCount = leafCountPerPass / leavesPerCheckpoint;
        const checkpointPlaintextByteLength =
            checkpointNodeCount * merkleDigestByteLength;
        const scratchRecordCount =
            checkpointPlaintextByteLength / scratchRecordPlaintextByteLength;
        const persistedScratchByteLength =
            scratchRecordCount * scratchRecordByteLength;
        const maximumRecomputedLeafCount =
            openingQueryCount * leavesPerCheckpoint;
        const reusableStrategyMaximumRecomputedLeafCount =
            Math.max(openingQueryCount, aggregateWidePadQueryCount) *
            leavesPerCheckpoint;
        const optimizedWork: WorkCounts = Object.freeze({
            laneDftCount: currentWork.laneDftCount / materializationPassCount,
            leafHashQueryCount: leafCountPerPass + maximumRecomputedLeafCount,
            merkleParentHashQueryCount:
                leafCountPerPass -
                1 +
                (checkpointNodeCount - 1) +
                openingQueryCount * (leavesPerCheckpoint - 1),
            privateLeafSaltDerivationCount:
                leafCountPerPass + maximumRecomputedLeafCount,
            sourceReplayCount:
                currentWork.sourceReplayCount / materializationPassCount +
                logicalChunkCountPerLane,
        });
        const targetFixedOwnerProjections = targets.map((target) => {
            const fixedOwners = projectPrimitiveOwners(
                target.primitiveCases,
                optimizedWork,
            );
            const selectedCheckpointOpeningLaneDftNanoseconds =
                checkpointLevel === selectedCheckpointLevel
                    ? scaleElapsedNanoseconds(
                          requireCase(target.primitiveCases, 7)
                              .elapsedNanoseconds,
                          rowCount,
                          1,
                      )
                    : undefined;
            const completeOwnersTotalNanoseconds =
                selectedCheckpointOpeningLaneDftNanoseconds === undefined
                    ? undefined
                    : fixedOwners.totalNanoseconds +
                      selectedCheckpointOpeningLaneDftNanoseconds;
            if (
                completeOwnersTotalNanoseconds !== undefined &&
                !Number.isSafeInteger(completeOwnersTotalNanoseconds)
            ) {
                throw new Error(
                    'Selected checkpoint complete-owner projection exceeds a safe integer.',
                );
            }
            return Object.freeze({
                ...(target.browserEngine === undefined
                    ? {}
                    : { browserEngine: target.browserEngine }),
                ...(completeOwnersTotalNanoseconds === undefined ||
                selectedCheckpointOpeningLaneDftNanoseconds === undefined
                    ? {}
                    : {
                          completeOwnersTotalNanoseconds,
                          selectedCheckpointOpeningLaneDftNanoseconds,
                      }),
                fixedOwners,
                ...(projectCheckpointStorage(target, scratchRecordCount) ===
                undefined
                    ? {}
                    : {
                          checkpointStorage: projectCheckpointStorage(
                              target,
                              scratchRecordCount,
                          ),
                      }),
                target: target.target,
            });
        });
        return Object.freeze({
            checkpointLevel,
            checkpointNodeCount,
            checkpointPlaintextByteLength,
            engineeringReviewRequired:
                persistedScratchByteLength > automaticScratchByteLength,
            hardScratchHeadroomByteLength:
                maximumScratchByteLength - persistedScratchByteLength,
            leavesPerCheckpoint,
            maximumRecomputedLeafCount,
            reusableStrategyMaximumRecomputedLeafCount,
            nominalScratchVarianceByteLength:
                persistedScratchByteLength - nominalScratchByteLength,
            optimizedColumnValueDeliveryCount:
                requireDimension(
                    ledgerRecord,
                    'basePhaseColumnValueDeliveryCount',
                ) /
                    materializationPassCount +
                maximumRecomputedLeafCount * rowCount,
            optimizedWork,
            persistedScratchByteLength,
            proofByteLengthDelta: 0,
            rootAndTranscriptGeometryChanged: false,
            scratchRecordCount,
            selected: checkpointLevel === selectedCheckpointLevel,
            selectiveEvaluationBenchmarkRequired:
                checkpointLevel !== selectedCheckpointLevel,
            targetFixedOwnerProjections,
            withinAutomaticScratchBound:
                persistedScratchByteLength <= automaticScratchByteLength,
            withinHardScratchBound:
                persistedScratchByteLength <= maximumScratchByteLength,
        });
    });
    const selectedCandidate = checkpointCandidates.find(
        (candidate) => candidate.selected,
    );
    if (
        selectedCandidate === undefined ||
        !selectedCandidate.withinAutomaticScratchBound ||
        checkpointCandidates[0]?.withinAutomaticScratchBound
    ) {
        throw new Error(
            'Selected VSS checkpoint level is not the smallest automatic-bound candidate.',
        );
    }

    return Object.freeze({
        checkpointCandidates: Object.freeze(checkpointCandidates),
        currentTwoPass: Object.freeze({
            columnValueDeliveryCount: requireDimension(
                ledgerRecord,
                'basePhaseColumnValueDeliveryCount',
            ),
            laneDftCount: currentWork.laneDftCount,
            leafHashQueryCount: currentWork.leafHashQueryCount,
            merkleParentHashQueryCount: currentWork.merkleParentHashQueryCount,
            privateLeafSaltDerivationCount:
                currentWork.privateLeafSaltDerivationCount,
            saltedLeafKeccakPermutationCount: requireDimension(
                ledgerRecord,
                'basePhaseSaltedLeafKeccakPermutationCount',
            ),
            sourceReplayCount: currentWork.sourceReplayCount,
            transportedValueByteLength: requireDimension(
                ledgerRecord,
                'basePhaseTransportedValueByteLength',
            ),
        }),
        ledgerIdentity: Object.freeze({
            basePhaseLaneCount: laneCount,
            basePhaseLogicalChunkCountPerLane: logicalChunkCountPerLane,
            basePhaseMaterializationPassCount: materializationPassCount,
            basePhaseOpeningQueryCount: openingQueryCount,
            basePhaseRowCount: rowCount,
            aggregateWidePadQueryCount,
        }),
        schemaVersion: 1,
        selectedCheckpointLevel,
        targetProjections: Object.freeze(currentTargetProjections),
    });
};
