import {
    requireCompletePrimitiveMeasurementCatalog,
    vssFusedRadix51ProjectionOwnerCaseIdentifiers,
    type DesktopBrowserFocusedPrimitiveMeasurementEvidence,
    type DesktopBrowserPrimitiveMeasurementEvidence,
    type PrimitiveMeasurementRecord,
    type ReleaseNativePrimitiveMeasurementEvidence,
} from './primitive-measurement-evidence.js';

const merkleDigestByteLength = 64;
const scratchRecordPlaintextByteLength = 1_048_576;
const nominalScratchByteLength = 268_435_456;
const automaticScratchByteLength = 402_653_184;
const maximumScratchByteLength = 1_073_741_824;
const modeledCheckpointLevel = 2;

type ProjectionTarget = Readonly<{
    browserEngine?: 'chromium' | 'firefox';
    primitiveCases: readonly PrimitiveMeasurementRecord[];
    storage?: DesktopBrowserPrimitiveMeasurementEvidence['storage'];
    boundaryCopies?: DesktopBrowserPrimitiveMeasurementEvidence['boundaryCopies'];
    target: 'release-native' | 'wasm32-unknown-unknown';
}>;

type WorkCounts = Readonly<{
    laneDftCount: number;
    leafHashKeccakPermutationCount: number;
    leafHashQueryCount: number;
    merkleParentHashQueryCount: number;
    privateLeafSaltDerivationCount: number;
    sourceReplayCount: number;
    sourceTraceValueGenerationCount: number;
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
        basePhasePhysicalRowWidth: number;
        basePhaseRowCount: number;
        aggregateWidePadQueryCount: number;
    }>;
    fusedRadix51Candidate: Readonly<Record<string, unknown>>;
    modeledRelationReplayCandidate: Readonly<Record<string, unknown>>;
    schemaVersion: 3;
    modeledCheckpointLevel: 2;
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
    sourceReplayCaseIdentifier: 8 | 9 | 11,
    rowLaneCaseIdentifier: 1 | 10 | 12,
): Readonly<{
    leafHashNanoseconds: number;
    merkleParentHashNanoseconds: number;
    privateLeafSaltNanoseconds: number;
    rowLaneNanoseconds: number;
    rowLaneOwnerCaseIdentifier: 1 | 10 | 12;
    sourceReplayNanoseconds: number;
    totalNanoseconds: number;
}> => {
    const rowLane = requireCase(primitiveCases, rowLaneCaseIdentifier);
    const leafHash = requireCase(primitiveCases, 2);
    const privateLeafSalt = requireCase(primitiveCases, 3);
    const merkleParentHash = requireCase(primitiveCases, 4);
    const sourceReplay = requireCase(
        primitiveCases,
        sourceReplayCaseIdentifier,
    );
    const rowLaneNanoseconds = scaleElapsedNanoseconds(
        rowLane.elapsedNanoseconds,
        work.laneDftCount,
        rowLane.iterationCount,
    );
    const leafHashNanoseconds = scaleElapsedNanoseconds(
        leafHash.elapsedNanoseconds,
        work.leafHashKeccakPermutationCount,
        requireDimension(leafHash, 'keccakPermutationCount'),
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
    const sourceReplayNanoseconds =
        sourceReplayCaseIdentifier === 8
            ? scaleElapsedNanoseconds(
                  sourceReplay.elapsedNanoseconds,
                  work.sourceTraceValueGenerationCount,
                  requireDimension(sourceReplay, 'productionRecipeCount') *
                      requireDimension(sourceReplay, 'traceValueCount'),
              )
            : scaleElapsedNanoseconds(
                  sourceReplay.elapsedNanoseconds,
                  work.sourceReplayCount,
                  requireDimension(sourceReplay, 'retainedRecipeCount'),
              );
    const totalNanoseconds = [
        rowLaneNanoseconds,
        leafHashNanoseconds,
        privateLeafSaltNanoseconds,
        merkleParentHashNanoseconds,
        sourceReplayNanoseconds,
    ].reduce((total, value) => total + value, 0);
    if (!Number.isSafeInteger(totalNanoseconds)) {
        throw new Error('Primitive owner total exceeds a safe integer.');
    }
    return Object.freeze({
        leafHashNanoseconds,
        merkleParentHashNanoseconds,
        privateLeafSaltNanoseconds,
        rowLaneNanoseconds,
        rowLaneOwnerCaseIdentifier: rowLaneCaseIdentifier,
        sourceReplayNanoseconds,
        totalNanoseconds,
    });
};

const deriveSelectedVssWork = (
    primitiveCases: readonly PrimitiveMeasurementRecord[],
): WorkCounts => {
    const ledgerRecord = requireCase(primitiveCases, 5);
    const sourceReplayCount = requireDimension(
        ledgerRecord,
        'basePhaseSourceReplayCount',
    );
    return Object.freeze({
        laneDftCount: requireDimension(ledgerRecord, 'basePhaseLaneDftCount'),
        leafHashKeccakPermutationCount: requireDimension(
            ledgerRecord,
            'basePhaseSaltedLeafKeccakPermutationCount',
        ),
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
        sourceReplayCount,
        sourceTraceValueGenerationCount:
            sourceReplayCount *
            requireDimension(ledgerRecord, 'traceValueCount'),
    });
};

const deriveFusedRadix51Work = (
    primitiveCases: readonly PrimitiveMeasurementRecord[],
): WorkCounts => {
    const retainedGroupRecord = requireCase(primitiveCases, 11);
    const rowLaneRecord = requireCase(primitiveCases, 12);
    return Object.freeze({
        laneDftCount: requireDimension(rowLaneRecord, 'completeLaneDftCount'),
        leafHashKeccakPermutationCount: requireDimension(
            rowLaneRecord,
            'completeSaltedLeafKeccakPermutationCount',
        ),
        leafHashQueryCount: requireDimension(
            rowLaneRecord,
            'completeLeafHashQueryCount',
        ),
        merkleParentHashQueryCount: requireDimension(
            rowLaneRecord,
            'completeMerkleParentHashQueryCount',
        ),
        privateLeafSaltDerivationCount: requireDimension(
            rowLaneRecord,
            'completePrivateLeafSaltDerivationCount',
        ),
        sourceReplayCount: requireDimension(
            retainedGroupRecord,
            'completeSourceMaterializationCount',
        ),
        sourceTraceValueGenerationCount: requireDimension(
            retainedGroupRecord,
            'completeSourceTraceValueGenerationCount',
        ),
    });
};

const assertMeasurementCorrespondence = (
    nativeCases: readonly PrimitiveMeasurementRecord[],
    browserCases: readonly PrimitiveMeasurementRecord[],
): void => {
    for (const nativeRecord of nativeCases) {
        const browserRecord = requireCase(
            browserCases,
            nativeRecord.caseIdentifier,
        );
        const targetDependentDimensionNames = new Set(
            nativeRecord.caseIdentifier === 5 ||
                nativeRecord.caseIdentifier === 8
                ? ['retainedInputByteLength']
                : nativeRecord.caseIdentifier === 9 ||
                    nativeRecord.caseIdentifier === 11
                  ? ['retainedInputByteLength', 'retainedGroupHeaderByteLength']
                  : nativeRecord.caseIdentifier === 10 ||
                      nativeRecord.caseIdentifier === 12
                    ? [
                          'retainedInputByteLength',
                          'retainedGroupHeaderByteLength',
                          'retainedGroupContainerByteLength',
                          'ownedFixedStateByteLength',
                          'materializationPeakLiveByteLength',
                          'stripePeakLiveByteLength',
                      ]
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

const assertCatalogCorrespondence = (
    nativeCases: readonly PrimitiveMeasurementRecord[],
    browserCases: readonly PrimitiveMeasurementRecord[],
): void => {
    requireCompletePrimitiveMeasurementCatalog(nativeCases);
    requireCompletePrimitiveMeasurementCatalog(browserCases);
    assertMeasurementCorrespondence(nativeCases, browserCases);
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

const requireFusedRadix51ProjectionOwnerCaseSet = (
    primitiveCases: readonly PrimitiveMeasurementRecord[],
    expectedExecutionTarget: PrimitiveMeasurementRecord['executionTarget'],
): void => {
    if (
        primitiveCases.length !==
            vssFusedRadix51ProjectionOwnerCaseIdentifiers.length ||
        primitiveCases.some(
            (record, recordIndex) =>
                record.caseIdentifier !==
                    vssFusedRadix51ProjectionOwnerCaseIdentifiers[
                        recordIndex
                    ] || record.executionTarget !== expectedExecutionTarget,
        )
    ) {
        throw new Error(
            'VSS fused radix-51 projection owner evidence differs from its exact canonical case set or execution target.',
        );
    }
};

export type VssFusedRadix51OwnerProjection = Readonly<{
    candidateWork: WorkCounts;
    schemaVersion: 1;
    selectedWork: WorkCounts;
    targetProjections: readonly Readonly<Record<string, unknown>>[];
}>;

export const deriveVssFusedRadix51OwnerProjection = (input: {
    readonly browserEvidence: readonly DesktopBrowserFocusedPrimitiveMeasurementEvidence[];
    readonly nativeEvidence: ReleaseNativePrimitiveMeasurementEvidence;
}): VssFusedRadix51OwnerProjection => {
    const nativeCases = input.nativeEvidence.primitiveCases;
    requireFusedRadix51ProjectionOwnerCaseSet(nativeCases, 'release-native');
    const expectedBrowserEvidenceCount =
        vssFusedRadix51ProjectionOwnerCaseIdentifiers.length * 2;
    if (input.browserEvidence.length !== expectedBrowserEvidenceCount) {
        throw new Error(
            'VSS fused radix-51 projection requires exact Chromium and Firefox owner sets.',
        );
    }
    const browserTargets = (['chromium', 'firefox'] as const).map(
        (browserEngine, browserIndex) => {
            const firstEvidenceIndex =
                browserIndex *
                vssFusedRadix51ProjectionOwnerCaseIdentifiers.length;
            const evidence = input.browserEvidence.slice(
                firstEvidenceIndex,
                firstEvidenceIndex +
                    vssFusedRadix51ProjectionOwnerCaseIdentifiers.length,
            );
            if (
                evidence.some(
                    (entry, entryIndex) =>
                        entry.browserEngine !== browserEngine ||
                        entry.primitiveCase.record.caseIdentifier !==
                            vssFusedRadix51ProjectionOwnerCaseIdentifiers[
                                entryIndex
                            ],
                )
            ) {
                throw new Error(
                    'VSS fused radix-51 projection browser owner sets are duplicated or noncanonical.',
                );
            }
            const primitiveCases = evidence.map(
                (entry) => entry.primitiveCase.record,
            );
            requireFusedRadix51ProjectionOwnerCaseSet(
                primitiveCases,
                'wasm32-unknown-unknown',
            );
            assertMeasurementCorrespondence(nativeCases, primitiveCases);
            return Object.freeze({
                browserEngine,
                evidence,
                primitiveCases,
            });
        },
    );
    const selectedWork = deriveSelectedVssWork(nativeCases);
    const candidateWork = deriveFusedRadix51Work(nativeCases);
    const targets = [
        Object.freeze({
            primitiveCases: nativeCases,
            target: 'release-native' as const,
        }),
        ...browserTargets.map((browserTarget) =>
            Object.freeze({
                browserEngine: browserTarget.browserEngine,
                evidence: browserTarget.evidence,
                primitiveCases: browserTarget.primitiveCases,
                target: 'wasm32-unknown-unknown' as const,
            }),
        ),
    ];
    const targetProjections = targets.map((target) => {
        const selectedOwners = projectPrimitiveOwners(
            target.primitiveCases,
            selectedWork,
            8,
            1,
        );
        const candidateOwners = projectPrimitiveOwners(
            target.primitiveCases,
            candidateWork,
            11,
            12,
        );
        return Object.freeze({
            ...('browserEngine' in target
                ? { browserEngine: target.browserEngine }
                : {}),
            candidateOwners,
            maximumModeledPrimitiveLiveByteLength: Math.max(
                ...target.primitiveCases.map(
                    (record) => record.modeledPeakLiveByteLength,
                ),
            ),
            ...('evidence' in target
                ? {
                      maximumWasmMemoryByteLength: Math.max(
                          ...target.evidence.map(
                              (entry) =>
                                  entry.primitiveCase.wasmMemoryByteLengthAfter,
                          ),
                      ),
                      measuredOwnerWallElapsedMilliseconds:
                          target.evidence.reduce(
                              (total, entry) =>
                                  total +
                                  entry.primitiveCase.wallElapsedMilliseconds,
                              0,
                          ),
                  }
                : {}),
            ownerReductionFactor:
                selectedOwners.totalNanoseconds /
                candidateOwners.totalNanoseconds,
            selectedOwners,
            target: target.target,
        });
    });
    return Object.freeze({
        candidateWork,
        schemaVersion: 1,
        selectedWork,
        targetProjections: Object.freeze(targetProjections),
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
    const currentWork = deriveSelectedVssWork(nativeCases);
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
                8,
                1,
            ),
            target: target.target,
        }),
    );
    const modeledCandidateWork: WorkCounts = Object.freeze({
        laneDftCount: requireDimension(
            ledgerRecord,
            'modeledCandidateLaneDftCount',
        ),
        leafHashKeccakPermutationCount: requireDimension(
            ledgerRecord,
            'modeledCandidateSaltedLeafKeccakPermutationCount',
        ),
        leafHashQueryCount: requireDimension(
            ledgerRecord,
            'modeledCandidateLeafHashQueryCount',
        ),
        merkleParentHashQueryCount: requireDimension(
            ledgerRecord,
            'modeledCandidateMerkleParentHashQueryCount',
        ),
        privateLeafSaltDerivationCount: requireDimension(
            ledgerRecord,
            'modeledCandidatePrivateLeafSaltDerivationCount',
        ),
        sourceReplayCount: requireDimension(
            ledgerRecord,
            'modeledCandidateRetainedSourceMaterializationCount',
        ),
        sourceTraceValueGenerationCount: requireDimension(
            ledgerRecord,
            'modeledCandidateSourceTraceValueGenerationCount',
        ),
    });
    const modeledCandidateTargetProjections = targets.map(
        (target, targetIndex) => {
            const owners = projectPrimitiveOwners(
                target.primitiveCases,
                modeledCandidateWork,
                9,
                10,
            );
            const currentProjection = currentTargetProjections[targetIndex];
            const currentOwners = currentProjection?.currentTwoPassOwners;
            if (
                currentOwners === undefined ||
                currentOwners.totalNanoseconds <= owners.totalNanoseconds
            ) {
                throw new Error(
                    'Modeled VSS relation-replay candidate does not reduce every target owner total.',
                );
            }
            return Object.freeze({
                ...(target.browserEngine === undefined
                    ? {}
                    : { browserEngine: target.browserEngine }),
                currentOwnerTotalNanoseconds: currentOwners.totalNanoseconds,
                modeledOwners: owners,
                target: target.target,
            });
        },
    );
    const fusedCandidateRetainedGroupRecord = requireCase(nativeCases, 11);
    const fusedCandidateRowLaneRecord = requireCase(nativeCases, 12);
    const fusedCandidateWork = deriveFusedRadix51Work(nativeCases);
    const fusedCandidateTargetProjections = targets.map(
        (target, targetIndex) => {
            const owners = projectPrimitiveOwners(
                target.primitiveCases,
                fusedCandidateWork,
                11,
                12,
            );
            const currentProjection = currentTargetProjections[targetIndex];
            const currentOwners = currentProjection?.currentTwoPassOwners;
            if (
                currentOwners === undefined ||
                currentOwners.totalNanoseconds <= owners.totalNanoseconds
            ) {
                throw new Error(
                    'Fused radix-51 VSS candidate does not reduce every target owner total.',
                );
            }
            return Object.freeze({
                ...(target.browserEngine === undefined
                    ? {}
                    : { browserEngine: target.browserEngine }),
                currentOwnerTotalNanoseconds: currentOwners.totalNanoseconds,
                fusedOwnerTotalNanoseconds: owners.totalNanoseconds,
                ownerReductionFactor:
                    currentOwners.totalNanoseconds / owners.totalNanoseconds,
                owners,
                target: target.target,
            });
        },
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
        const leafHashKeccakPermutationCountPerQuery =
            currentWork.leafHashKeccakPermutationCount /
            currentWork.leafHashQueryCount;
        const optimizedSourceReplayCount =
            currentWork.sourceReplayCount / materializationPassCount +
            logicalChunkCountPerLane;
        const optimizedWork: WorkCounts = Object.freeze({
            laneDftCount: currentWork.laneDftCount / materializationPassCount,
            leafHashKeccakPermutationCount:
                (leafCountPerPass + maximumRecomputedLeafCount) *
                leafHashKeccakPermutationCountPerQuery,
            leafHashQueryCount: leafCountPerPass + maximumRecomputedLeafCount,
            merkleParentHashQueryCount:
                leafCountPerPass -
                1 +
                (checkpointNodeCount - 1) +
                openingQueryCount * (leavesPerCheckpoint - 1),
            privateLeafSaltDerivationCount:
                leafCountPerPass + maximumRecomputedLeafCount,
            sourceReplayCount: optimizedSourceReplayCount,
            sourceTraceValueGenerationCount:
                optimizedSourceReplayCount *
                requireDimension(ledgerRecord, 'traceValueCount'),
        });
        const targetFixedOwnerProjections = targets.map((target) => {
            const fixedOwners = projectPrimitiveOwners(
                target.primitiveCases,
                optimizedWork,
                8,
                1,
            );
            const modeledCheckpointOpeningLaneDftNanoseconds =
                checkpointLevel === modeledCheckpointLevel
                    ? scaleElapsedNanoseconds(
                          requireCase(target.primitiveCases, 7)
                              .elapsedNanoseconds,
                          rowCount,
                          1,
                      )
                    : undefined;
            const completeOwnersTotalNanoseconds =
                modeledCheckpointOpeningLaneDftNanoseconds === undefined
                    ? undefined
                    : fixedOwners.totalNanoseconds +
                      modeledCheckpointOpeningLaneDftNanoseconds;
            if (
                completeOwnersTotalNanoseconds !== undefined &&
                !Number.isSafeInteger(completeOwnersTotalNanoseconds)
            ) {
                throw new Error(
                    'Modeled checkpoint complete-owner projection exceeds a safe integer.',
                );
            }
            return Object.freeze({
                ...(target.browserEngine === undefined
                    ? {}
                    : { browserEngine: target.browserEngine }),
                ...(completeOwnersTotalNanoseconds === undefined ||
                modeledCheckpointOpeningLaneDftNanoseconds === undefined
                    ? {}
                    : {
                          completeOwnersTotalNanoseconds,
                          modeledCheckpointOpeningLaneDftNanoseconds,
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
            scratchRecordCount,
            modeled: checkpointLevel === modeledCheckpointLevel,
            selectiveEvaluationBenchmarkRequired:
                checkpointLevel !== modeledCheckpointLevel,
            targetFixedOwnerProjections,
            withinAutomaticScratchBound:
                persistedScratchByteLength <= automaticScratchByteLength,
            withinHardScratchBound:
                persistedScratchByteLength <= maximumScratchByteLength,
        });
    });
    const modeledCandidate = checkpointCandidates.find(
        (candidate) => candidate.modeled,
    );
    if (
        modeledCandidate === undefined ||
        !modeledCandidate.withinAutomaticScratchBound ||
        checkpointCandidates[0]?.withinAutomaticScratchBound
    ) {
        throw new Error(
            'Modeled VSS checkpoint level is not the smallest automatic-bound candidate.',
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
            basePhasePhysicalRowWidth: requireDimension(
                ledgerRecord,
                'basePhasePhysicalRowWidth',
            ),
            basePhaseRowCount: rowCount,
            aggregateWidePadQueryCount,
        }),
        fusedRadix51Candidate: Object.freeze({
            basePhaseRowCount: requireDimension(
                fusedCandidateRowLaneRecord,
                'basePhaseRowCount',
            ),
            completePhaseRowCount: requireDimension(
                fusedCandidateRowLaneRecord,
                'completePhaseRowCount',
            ),
            completeWork: Object.freeze({
                butterflyCount: requireDimension(
                    fusedCandidateRowLaneRecord,
                    'completeButterflyCount',
                ),
                coefficientFoldCount: requireDimension(
                    fusedCandidateRowLaneRecord,
                    'completeCoefficientFoldCount',
                ),
                columnValueDeliveryCount: requireDimension(
                    fusedCandidateRowLaneRecord,
                    'completeColumnValueDeliveryCount',
                ),
                cosetMultiplicationCount: requireDimension(
                    fusedCandidateRowLaneRecord,
                    'completeCosetMultiplicationCount',
                ),
                laneDftCount: fusedCandidateWork.laneDftCount,
                leafHashQueryCount: fusedCandidateWork.leafHashQueryCount,
                merkleParentHashQueryCount:
                    fusedCandidateWork.merkleParentHashQueryCount,
                privateLeafSaltDerivationCount:
                    fusedCandidateWork.privateLeafSaltDerivationCount,
                saltedLeafKeccakPermutationCount:
                    fusedCandidateWork.leafHashKeccakPermutationCount,
                sourceMaterializationCount:
                    fusedCandidateWork.sourceReplayCount,
                sourceTraceValueGenerationCount:
                    fusedCandidateWork.sourceTraceValueGenerationCount,
            }),
            physicalRowWidth: requireDimension(
                fusedCandidateRowLaneRecord,
                'physicalRowWidth',
            ),
            productionRecipeCount: requireDimension(
                fusedCandidateRowLaneRecord,
                'productionRecipeCount',
            ),
            proverColumnDegreeBoundExclusive: requireDimension(
                fusedCandidateRowLaneRecord,
                'proverColumnDegreeBoundExclusive',
            ),
            quotientPhaseRowCount: requireDimension(
                fusedCandidateRowLaneRecord,
                'quotientPhaseRowCount',
            ),
            rangeDigitRadix: requireDimension(
                fusedCandidateRowLaneRecord,
                'rangeDigitRadix',
            ),
            relationTraceValueCount: requireDimension(
                fusedCandidateRowLaneRecord,
                'traceValueCount',
            ),
            retainedCoefficientGroupByteLength: requireDimension(
                fusedCandidateRetainedGroupRecord,
                'retainedCoefficientPayloadByteLength',
            ),
            targetProjections: Object.freeze(fusedCandidateTargetProjections),
            tracePackingFactor: requireDimension(
                fusedCandidateRowLaneRecord,
                'tracePackingFactor',
            ),
            transportedValueByteLength: requireDimension(
                fusedCandidateRowLaneRecord,
                'completeTransportedValueByteLength',
            ),
        }),
        modeledRelationReplayCandidate: Object.freeze({
            coefficientChunkCountPerSource: requireDimension(
                ledgerRecord,
                'modeledCandidateCoefficientChunkCountPerSource',
            ),
            columnValueDeliveryCount: requireDimension(
                ledgerRecord,
                'modeledCandidateColumnValueDeliveryCount',
            ),
            logicalRowChunkByteLength: requireDimension(
                ledgerRecord,
                'modeledCandidateLogicalRowChunkByteLength',
            ),
            maximumRangeConstraintNumeratorDegree: requireDimension(
                ledgerRecord,
                'modeledCandidateMaximumRangeConstraintNumeratorDegree',
            ),
            openingDegreeBoundExclusive: requireDimension(
                ledgerRecord,
                'modeledCandidateOpeningDegreeBoundExclusive',
            ),
            physicalRowWidth: requireDimension(
                ledgerRecord,
                'modeledCandidatePhysicalRowWidth',
            ),
            proverColumnCount: requireDimension(
                ledgerRecord,
                'modeledCandidateProverColumnCount',
            ),
            proverColumnDegreeBoundExclusive: requireDimension(
                ledgerRecord,
                'modeledCandidateProverColumnDegreeBoundExclusive',
            ),
            relationTraceValueCount: requireDimension(
                ledgerRecord,
                'modeledCandidateRelationTraceValueCount',
            ),
            retainedCoefficientGroupByteLength: requireDimension(
                ledgerRecord,
                'modeledCandidateRetainedCoefficientGroupByteLength',
            ),
            rowCodeInverseRate: requireDimension(
                ledgerRecord,
                'modeledCandidateRowCodeInverseRate',
            ),
            rowCount: requireDimension(
                ledgerRecord,
                'modeledCandidateRowCount',
            ),
            sourceTraceValueGenerationCount:
                modeledCandidateWork.sourceTraceValueGenerationCount,
            targetProjections: Object.freeze(modeledCandidateTargetProjections),
            tracePackingFactor: requireDimension(
                ledgerRecord,
                'modeledCandidateTracePackingFactor',
            ),
            transportedValueByteLength: requireDimension(
                ledgerRecord,
                'modeledCandidateTransportedValueByteLength',
            ),
        }),
        schemaVersion: 3,
        modeledCheckpointLevel,
        targetProjections: Object.freeze(currentTargetProjections),
    });
};
