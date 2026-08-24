import {
    validateDesktopBrowserPrimitiveCaseMeasurement,
    type DesktopBrowserPrimitiveCaseMeasurement,
} from './primitive-measurement-evidence.js';

export type CompactCfwStorageDiagnosticRound = Readonly<{
    appendChunkCountPerMatrix: number;
    outputElementCount: number;
    outputObjectByteLength: number;
    precedingReadChunkCountPerMatrix: number;
    roundOrdinal: number;
}>;

export type CompactCfwStorageDiagnosticSchedule = Readonly<{
    appendTransactionCount: number;
    createTransactionCount: number;
    deleteTransactionCount: number;
    deterministicSafeBoundaryCount: number;
    extensionElementByteLength: number;
    matrixCount: number;
    maximumActiveObjectCount: number;
    objectLifecycleCount: number;
    peakStoredByteLength: number;
    readTransactionCount: number;
    r1csRowCount: number;
    roundCount: number;
    rounds: readonly CompactCfwStorageDiagnosticRound[];
    schemaVersion: 1;
    sealTransactionCount: number;
    secretSealInvocationCount: number;
    secretSealedPlaintextByteLength: number;
    stepCount: number;
    streamChunkByteLength: number;
    streamChunkElementCount: number;
    totalReadByteLength: number;
    totalTransactionCount: number;
    totalWrittenByteLength: number;
    witnessElementCount: number;
}>;

export type CompactCfwTransactionKind =
    | 'append'
    | 'create'
    | 'delete'
    | 'read'
    | 'seal';

export type CompactCfwCommitLatencyDistribution = Readonly<{
    count: number;
    maximumMilliseconds: number;
    meanMilliseconds: number;
    minimumMilliseconds: number;
    percentile50Milliseconds: number;
    percentile90Milliseconds: number;
    percentile95Milliseconds: number;
    percentile99Milliseconds: number;
    totalMilliseconds: number;
}>;

export type CompactCfwStorageEstimate = Readonly<{
    quota?: number;
    usage?: number;
}>;

export type CompactCfwBrowserMemorySample = Readonly<{
    javascriptHeapByteLength?: number;
    sampleLabel: string;
    storageEstimate: CompactCfwStorageEstimate;
}>;

export type CompactCfwPhysicalStorageAccounting = Readonly<{
    ciphertextReadByteLength: number;
    ciphertextReadCallCount: number;
    ciphertextWriteByteLength: number;
    ciphertextWriteCallCount: number;
    cleanupCompleted: boolean;
    cleanupDurationMilliseconds: number;
    commitReadbackByteLength: number;
    commitReadbackCallCount: number;
    deterministicRegeneratedByteLength: number;
    deterministicRegenerationCallCount: number;
    deletedByteLength: number;
    deletionCount: number;
    deletionDurationMilliseconds: number;
    openCallCount: number;
    openCiphertextByteLength: number;
    openPlaintextByteLength: number;
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
    plaintextReadByteLength: number;
    plaintextReadCallCount: number;
    plaintextWriteByteLength: number;
    plaintextWriteCallCount: number;
    sealCallCount: number;
    sealCiphertextByteLength: number;
    sealPlaintextByteLength: number;
    repairHashCallCount: number;
    repairHashedByteLength: number;
    storageRequestCount: number;
    storageTransactionCount: number;
}>;

export type DesktopBrowserCompactCfwStorageDiagnosticEvidence = Readonly<{
    browserEngine: 'chromium';
    browserUserAgent: string;
    commitLatencyByTransactionKind: Readonly<
        Record<CompactCfwTransactionKind, CompactCfwCommitLatencyDistribution>
    >;
    evidenceScope: 'nonqualifying-desktop-chromium-development-diagnostic';
    memoryAndStorageSamples: readonly CompactCfwBrowserMemorySample[];
    observedReadByteLength: number;
    observedReadChecksumHex: string;
    observedTransactionCount: number;
    observedWrittenByteLength: number;
    physicalStorageAccountingAfterCleanup: CompactCfwPhysicalStorageAccounting;
    physicalStorageAccountingBeforeCleanup: CompactCfwPhysicalStorageAccounting;
    primitiveCases: readonly [
        DesktopBrowserPrimitiveCaseMeasurement,
        DesktopBrowserPrimitiveCaseMeasurement,
    ];
    schedule: CompactCfwStorageDiagnosticSchedule;
    schemaVersion: 1;
    totalElapsedMilliseconds: number;
}>;

const expectedSelectedSchedule = Object.freeze({
    appendTransactionCount: 1_575,
    createTransactionCount: 69,
    deleteTransactionCount: 69,
    deterministicSafeBoundaryCount: 2_657,
    extensionElementByteLength: 40,
    matrixCount: 3,
    maximumActiveObjectCount: 4,
    objectLifecycleCount: 69,
    peakStoredByteLength: 587_202_560,
    readTransactionCount: 3_144,
    r1csRowCount: 8_388_608,
    roundCount: 23,
    sealTransactionCount: 69,
    secretSealInvocationCount: 1_713,
    secretSealedPlaintextByteLength: 1_006_633_461,
    stepCount: 70,
    streamChunkByteLength: 655_360,
    streamChunkElementCount: 16_384,
    totalReadByteLength: 2_013_265_440,
    totalTransactionCount: 4_926,
    totalWrittenByteLength: 1_006_632_840,
    witnessElementCount: 4_194_304,
} as const);
const expectedSelectedReadChecksumHex = '51d46ff8bc9dd585';

const scheduleFieldNames = Object.freeze([
    'appendTransactionCount',
    'createTransactionCount',
    'deleteTransactionCount',
    'deterministicSafeBoundaryCount',
    'extensionElementByteLength',
    'matrixCount',
    'maximumActiveObjectCount',
    'objectLifecycleCount',
    'peakStoredByteLength',
    'readTransactionCount',
    'r1csRowCount',
    'roundCount',
    'sealTransactionCount',
    'secretSealInvocationCount',
    'secretSealedPlaintextByteLength',
    'stepCount',
    'streamChunkByteLength',
    'streamChunkElementCount',
    'totalReadByteLength',
    'totalTransactionCount',
    'totalWrittenByteLength',
    'witnessElementCount',
] as const);

const requireObject = (
    value: unknown,
    label: string,
): Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${label} is not an object.`);
    }
    return value as Record<string, unknown>;
};

const requireExactKeys = (
    value: Record<string, unknown>,
    expectedKeys: readonly string[],
    label: string,
): void => {
    const actualKeys = Object.keys(value).sort();
    const sortedExpectedKeys = [...expectedKeys].sort();
    if (
        actualKeys.length !== sortedExpectedKeys.length ||
        actualKeys.some((key, keyIndex) => key !== sortedExpectedKeys[keyIndex])
    ) {
        throw new Error(`${label} has unknown or missing fields.`);
    }
};

const requireSafeUnsignedInteger = (value: unknown, label: string): number => {
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
        throw new Error(`${label} is not a safe unsigned integer.`);
    }
    return value as number;
};

export const validateCompactCfwStorageDiagnosticSchedule = (
    value: unknown,
): CompactCfwStorageDiagnosticSchedule => {
    const schedule = requireObject(
        value,
        'Compact CFW storage diagnostic schedule',
    );
    requireExactKeys(
        schedule,
        [...scheduleFieldNames, 'rounds', 'schemaVersion'],
        'Compact CFW storage diagnostic schedule',
    );
    if (schedule.schemaVersion !== 1 || !Array.isArray(schedule.rounds)) {
        throw new Error(
            'Compact CFW storage diagnostic schedule has an unsupported schema.',
        );
    }
    const numericFields = Object.fromEntries(
        scheduleFieldNames.map((fieldName) => [
            fieldName,
            requireSafeUnsignedInteger(
                schedule[fieldName],
                `Compact CFW schedule ${fieldName}`,
            ),
        ]),
    ) as Record<(typeof scheduleFieldNames)[number], number>;
    for (const fieldName of scheduleFieldNames) {
        if (numericFields[fieldName] !== expectedSelectedSchedule[fieldName]) {
            throw new Error(
                `Compact CFW schedule ${fieldName} differs from the selected production owner.`,
            );
        }
    }

    if (schedule.rounds.length !== numericFields.roundCount) {
        throw new Error('Compact CFW schedule has the wrong round count.');
    }
    let expectedOutputElementCount = numericFields.r1csRowCount / 2;
    let precedingOutputElementCount = 0;
    let derivedAppendTransactionCount = 0;
    let derivedReadTransactionCount = 0;
    let derivedWrittenByteLength = 0;
    let derivedReadByteLength = 0;
    let storedRoundChunkGroupCount = 0;
    const rounds = schedule.rounds.map((roundValue, roundIndex) => {
        const round = requireObject(
            roundValue,
            `Compact CFW diagnostic round ${String(roundIndex)}`,
        );
        requireExactKeys(
            round,
            [
                'appendChunkCountPerMatrix',
                'outputElementCount',
                'outputObjectByteLength',
                'precedingReadChunkCountPerMatrix',
                'roundOrdinal',
            ],
            `Compact CFW diagnostic round ${String(roundIndex)}`,
        );
        const roundOrdinal = requireSafeUnsignedInteger(
            round.roundOrdinal,
            'Compact CFW round ordinal',
        );
        const outputElementCount = requireSafeUnsignedInteger(
            round.outputElementCount,
            'Compact CFW round output element count',
        );
        const outputObjectByteLength = requireSafeUnsignedInteger(
            round.outputObjectByteLength,
            'Compact CFW round output byte length',
        );
        const appendChunkCountPerMatrix = requireSafeUnsignedInteger(
            round.appendChunkCountPerMatrix,
            'Compact CFW round append chunk count',
        );
        const precedingReadChunkCountPerMatrix = requireSafeUnsignedInteger(
            round.precedingReadChunkCountPerMatrix,
            'Compact CFW round preceding read chunk count',
        );
        const expectedAppendChunkCount = Math.ceil(
            expectedOutputElementCount / numericFields.streamChunkElementCount,
        );
        const expectedPrecedingReadChunkCount =
            roundIndex === 0
                ? 0
                : Math.ceil(
                      precedingOutputElementCount /
                          numericFields.streamChunkElementCount,
                  );
        if (
            roundOrdinal !== roundIndex ||
            outputElementCount !== expectedOutputElementCount ||
            outputObjectByteLength !==
                outputElementCount * numericFields.extensionElementByteLength ||
            appendChunkCountPerMatrix !== expectedAppendChunkCount ||
            precedingReadChunkCountPerMatrix !== expectedPrecedingReadChunkCount
        ) {
            throw new Error(
                `Compact CFW diagnostic round ${String(roundIndex)} differs from the recursively derived geometry.`,
            );
        }
        derivedAppendTransactionCount +=
            appendChunkCountPerMatrix * numericFields.matrixCount;
        derivedWrittenByteLength +=
            outputObjectByteLength * numericFields.matrixCount;
        if (roundIndex !== 0) {
            storedRoundChunkGroupCount += precedingReadChunkCountPerMatrix;
            derivedReadTransactionCount +=
                precedingReadChunkCountPerMatrix *
                numericFields.matrixCount *
                2;
            derivedReadByteLength +=
                precedingOutputElementCount *
                numericFields.extensionElementByteLength *
                numericFields.matrixCount *
                2;
        }
        precedingOutputElementCount = outputElementCount;
        expectedOutputElementCount /= 2;
        return Object.freeze({
            appendChunkCountPerMatrix,
            outputElementCount,
            outputObjectByteLength,
            precedingReadChunkCountPerMatrix,
            roundOrdinal,
        });
    });

    const derivedObjectLifecycleCount =
        numericFields.roundCount * numericFields.matrixCount;
    const derivedTotalTransactionCount =
        derivedObjectLifecycleCount * 3 +
        derivedAppendTransactionCount +
        derivedReadTransactionCount;
    const derivedSecretSealInvocationCount =
        derivedObjectLifecycleCount * 2 + derivedAppendTransactionCount;
    const derivedSecretSealedPlaintextByteLength =
        derivedWrittenByteLength + derivedObjectLifecycleCount * 9;
    const derivedSafeBoundaryCount =
        Math.ceil(
            numericFields.r1csRowCount / numericFields.streamChunkElementCount,
        ) +
        derivedAppendTransactionCount +
        storedRoundChunkGroupCount +
        numericFields.roundCount * 2;
    const firstRoundObjectByteLength = rounds[0]?.outputObjectByteLength ?? 0;
    const secondRoundObjectByteLength = rounds[1]?.outputObjectByteLength ?? 0;
    if (
        expectedOutputElementCount !== 0.5 ||
        rounds[rounds.length - 1]?.outputElementCount !== 1 ||
        derivedObjectLifecycleCount !== numericFields.objectLifecycleCount ||
        derivedAppendTransactionCount !==
            numericFields.appendTransactionCount ||
        derivedReadTransactionCount !== numericFields.readTransactionCount ||
        derivedWrittenByteLength !== numericFields.totalWrittenByteLength ||
        derivedReadByteLength !== numericFields.totalReadByteLength ||
        derivedTotalTransactionCount !== numericFields.totalTransactionCount ||
        derivedSecretSealInvocationCount !==
            numericFields.secretSealInvocationCount ||
        derivedSecretSealedPlaintextByteLength !==
            numericFields.secretSealedPlaintextByteLength ||
        derivedSafeBoundaryCount !==
            numericFields.deterministicSafeBoundaryCount ||
        firstRoundObjectByteLength * numericFields.matrixCount +
            secondRoundObjectByteLength !==
            numericFields.peakStoredByteLength
    ) {
        throw new Error(
            'Compact CFW storage schedule does not reconcile its derived census.',
        );
    }

    return Object.freeze({
        ...numericFields,
        rounds: Object.freeze(rounds),
        schemaVersion: 1,
    });
};

const requireFiniteNonnegativeNumber = (
    value: unknown,
    label: string,
): number => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new Error(`${label} is not a finite nonnegative number.`);
    }
    return value;
};

const transactionKinds = Object.freeze([
    'append',
    'create',
    'delete',
    'read',
    'seal',
] as const);

const expectedTransactionCountByKind = Object.freeze({
    append: expectedSelectedSchedule.appendTransactionCount,
    create: expectedSelectedSchedule.createTransactionCount,
    delete: expectedSelectedSchedule.deleteTransactionCount,
    read: expectedSelectedSchedule.readTransactionCount,
    seal: expectedSelectedSchedule.sealTransactionCount,
});

const validateLatencyDistribution = (
    value: unknown,
    transactionKind: CompactCfwTransactionKind,
): CompactCfwCommitLatencyDistribution => {
    const distribution = requireObject(
        value,
        `Compact CFW ${transactionKind} latency distribution`,
    );
    const fieldNames = [
        'count',
        'maximumMilliseconds',
        'meanMilliseconds',
        'minimumMilliseconds',
        'percentile50Milliseconds',
        'percentile90Milliseconds',
        'percentile95Milliseconds',
        'percentile99Milliseconds',
        'totalMilliseconds',
    ] as const;
    requireExactKeys(
        distribution,
        fieldNames,
        `Compact CFW ${transactionKind} latency distribution`,
    );
    const count = requireSafeUnsignedInteger(
        distribution.count,
        `Compact CFW ${transactionKind} latency count`,
    );
    const numeric = Object.fromEntries(
        fieldNames
            .filter((fieldName) => fieldName !== 'count')
            .map((fieldName) => [
                fieldName,
                requireFiniteNonnegativeNumber(
                    distribution[fieldName],
                    `Compact CFW ${transactionKind} ${fieldName}`,
                ),
            ]),
    ) as Omit<CompactCfwCommitLatencyDistribution, 'count'>;
    if (
        count !== expectedTransactionCountByKind[transactionKind] ||
        numeric.minimumMilliseconds > numeric.percentile50Milliseconds ||
        numeric.percentile50Milliseconds > numeric.percentile90Milliseconds ||
        numeric.percentile90Milliseconds > numeric.percentile95Milliseconds ||
        numeric.percentile95Milliseconds > numeric.percentile99Milliseconds ||
        numeric.percentile99Milliseconds > numeric.maximumMilliseconds ||
        Math.abs(numeric.meanMilliseconds * count - numeric.totalMilliseconds) >
            Math.max(0.001, numeric.totalMilliseconds * 1e-9)
    ) {
        throw new Error(
            `Compact CFW ${transactionKind} latency distribution is inconsistent.`,
        );
    }
    return Object.freeze({ count, ...numeric });
};

const physicalAccountingFieldNames = Object.freeze([
    'ciphertextReadByteLength',
    'ciphertextReadCallCount',
    'ciphertextWriteByteLength',
    'ciphertextWriteCallCount',
    'cleanupDurationMilliseconds',
    'commitReadbackByteLength',
    'commitReadbackCallCount',
    'deterministicRegeneratedByteLength',
    'deterministicRegenerationCallCount',
    'deletedByteLength',
    'deletionCount',
    'deletionDurationMilliseconds',
    'openCallCount',
    'openCiphertextByteLength',
    'openPlaintextByteLength',
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
    'plaintextReadByteLength',
    'plaintextReadCallCount',
    'plaintextWriteByteLength',
    'plaintextWriteCallCount',
    'sealCallCount',
    'sealCiphertextByteLength',
    'sealPlaintextByteLength',
    'repairHashCallCount',
    'repairHashedByteLength',
    'storageRequestCount',
    'storageTransactionCount',
] as const);

const validatePhysicalAccounting = (
    value: unknown,
    expectedCleanupCompleted: boolean,
): CompactCfwPhysicalStorageAccounting => {
    const accounting = requireObject(value, 'Compact CFW physical accounting');
    requireExactKeys(
        accounting,
        [...physicalAccountingFieldNames, 'cleanupCompleted'],
        'Compact CFW physical accounting',
    );
    if (accounting.cleanupCompleted !== expectedCleanupCompleted) {
        throw new Error(
            'Compact CFW physical accounting has the wrong cleanup state.',
        );
    }
    const numeric = Object.fromEntries(
        physicalAccountingFieldNames.map((fieldName) => [
            fieldName,
            requireFiniteNonnegativeNumber(
                accounting[fieldName],
                `Compact CFW physical accounting ${fieldName}`,
            ),
        ]),
    ) as Omit<CompactCfwPhysicalStorageAccounting, 'cleanupCompleted'>;
    return Object.freeze({
        cleanupCompleted: expectedCleanupCompleted,
        ...numeric,
    });
};

const validateStorageEstimate = (value: unknown): CompactCfwStorageEstimate => {
    const estimate = requireObject(value, 'Compact CFW storage estimate');
    requireExactKeys(
        estimate,
        Object.keys(estimate).filter(
            (fieldName) => fieldName === 'quota' || fieldName === 'usage',
        ),
        'Compact CFW storage estimate',
    );
    if (
        Object.keys(estimate).some((key) => key !== 'quota' && key !== 'usage')
    ) {
        throw new Error('Compact CFW storage estimate has unknown fields.');
    }
    return Object.freeze({
        ...(estimate.quota === undefined
            ? {}
            : {
                  quota: requireFiniteNonnegativeNumber(
                      estimate.quota,
                      'Compact CFW storage quota',
                  ),
              }),
        ...(estimate.usage === undefined
            ? {}
            : {
                  usage: requireFiniteNonnegativeNumber(
                      estimate.usage,
                      'Compact CFW storage usage',
                  ),
              }),
    });
};

export const validateDesktopBrowserCompactCfwStorageDiagnosticEvidence = (
    value: unknown,
): DesktopBrowserCompactCfwStorageDiagnosticEvidence => {
    const evidence = requireObject(value, 'Compact CFW browser diagnostic');
    requireExactKeys(
        evidence,
        [
            'browserEngine',
            'browserUserAgent',
            'commitLatencyByTransactionKind',
            'evidenceScope',
            'memoryAndStorageSamples',
            'observedReadByteLength',
            'observedReadChecksumHex',
            'observedTransactionCount',
            'observedWrittenByteLength',
            'physicalStorageAccountingAfterCleanup',
            'physicalStorageAccountingBeforeCleanup',
            'primitiveCases',
            'schedule',
            'schemaVersion',
            'totalElapsedMilliseconds',
        ],
        'Compact CFW browser diagnostic',
    );
    if (
        evidence.schemaVersion !== 1 ||
        evidence.browserEngine !== 'chromium' ||
        evidence.evidenceScope !==
            'nonqualifying-desktop-chromium-development-diagnostic' ||
        typeof evidence.browserUserAgent !== 'string' ||
        evidence.browserUserAgent.length === 0 ||
        evidence.browserUserAgent.length > 1_024 ||
        !Array.isArray(evidence.primitiveCases) ||
        evidence.primitiveCases.length !== 2 ||
        !Array.isArray(evidence.memoryAndStorageSamples) ||
        evidence.memoryAndStorageSamples.length < 3
    ) {
        throw new Error('Compact CFW browser diagnostic framing is invalid.');
    }
    const schedule = validateCompactCfwStorageDiagnosticSchedule(
        evidence.schedule,
    );
    const latencies = requireObject(
        evidence.commitLatencyByTransactionKind,
        'Compact CFW latency catalog',
    );
    requireExactKeys(
        latencies,
        transactionKinds,
        'Compact CFW latency catalog',
    );
    const commitLatencyByTransactionKind = Object.freeze(
        Object.fromEntries(
            transactionKinds.map((transactionKind) => [
                transactionKind,
                validateLatencyDistribution(
                    latencies[transactionKind],
                    transactionKind,
                ),
            ]),
        ),
    ) as Readonly<
        Record<CompactCfwTransactionKind, CompactCfwCommitLatencyDistribution>
    >;
    const primitiveCases = evidence.primitiveCases.map((primitiveCase) =>
        validateDesktopBrowserPrimitiveCaseMeasurement(primitiveCase),
    );
    if (
        primitiveCases[0]?.record.caseIdentifier !== 1 ||
        primitiveCases[1]?.record.caseIdentifier !== 2
    ) {
        throw new Error(
            'Compact CFW browser diagnostic lacks the scalar butterfly or salted-leaf primitive.',
        );
    }
    const memoryAndStorageSamples = evidence.memoryAndStorageSamples.map(
        (sampleValue) => {
            const sample = requireObject(
                sampleValue,
                'Compact CFW memory and storage sample',
            );
            requireExactKeys(
                sample,
                [
                    ...(sample.javascriptHeapByteLength === undefined
                        ? []
                        : ['javascriptHeapByteLength']),
                    'sampleLabel',
                    'storageEstimate',
                ],
                'Compact CFW memory and storage sample',
            );
            if (
                typeof sample.sampleLabel !== 'string' ||
                sample.sampleLabel.length === 0 ||
                sample.sampleLabel.length > 128
            ) {
                throw new Error('Compact CFW sample label is invalid.');
            }
            return Object.freeze({
                ...(sample.javascriptHeapByteLength === undefined
                    ? {}
                    : {
                          javascriptHeapByteLength:
                              requireFiniteNonnegativeNumber(
                                  sample.javascriptHeapByteLength,
                                  'Compact CFW JavaScript heap size',
                              ),
                      }),
                sampleLabel: sample.sampleLabel,
                storageEstimate: validateStorageEstimate(
                    sample.storageEstimate,
                ),
            });
        },
    );
    const expectedSampleLabels = [
        'before-open',
        'after-open',
        ...Array.from(
            { length: schedule.roundCount },
            (_unused, roundOrdinal) => `after-round-${String(roundOrdinal)}`,
        ),
        'after-final-deletes',
        'after-custody-cleanup',
    ];
    if (
        memoryAndStorageSamples.length !== expectedSampleLabels.length ||
        memoryAndStorageSamples.some(
            (sample, sampleOrdinal) =>
                sample.sampleLabel !== expectedSampleLabels[sampleOrdinal],
        )
    ) {
        throw new Error(
            'Compact CFW browser diagnostic lacks the exact storage-overlap sample sequence.',
        );
    }
    const observedTransactionCount = requireSafeUnsignedInteger(
        evidence.observedTransactionCount,
        'Compact CFW observed transaction count',
    );
    const observedWrittenByteLength = requireSafeUnsignedInteger(
        evidence.observedWrittenByteLength,
        'Compact CFW observed written byte length',
    );
    const observedReadByteLength = requireSafeUnsignedInteger(
        evidence.observedReadByteLength,
        'Compact CFW observed read byte length',
    );
    if (
        observedTransactionCount !== schedule.totalTransactionCount ||
        observedWrittenByteLength !== schedule.totalWrittenByteLength ||
        observedReadByteLength !== schedule.totalReadByteLength ||
        evidence.observedReadChecksumHex !== expectedSelectedReadChecksumHex
    ) {
        throw new Error(
            'Compact CFW browser diagnostic does not match its compiler-derived schedule.',
        );
    }
    const beforeCleanup = validatePhysicalAccounting(
        evidence.physicalStorageAccountingBeforeCleanup,
        false,
    );
    const afterCleanup = validatePhysicalAccounting(
        evidence.physicalStorageAccountingAfterCleanup,
        true,
    );
    if (
        beforeCleanup.sealCallCount !== schedule.secretSealInvocationCount ||
        beforeCleanup.sealPlaintextByteLength !==
            schedule.secretSealedPlaintextByteLength ||
        beforeCleanup.plaintextWriteCallCount !==
            schedule.secretSealInvocationCount ||
        beforeCleanup.plaintextWriteByteLength !==
            schedule.secretSealedPlaintextByteLength ||
        beforeCleanup.openCallCount !== schedule.readTransactionCount ||
        beforeCleanup.plaintextReadCallCount !==
            schedule.readTransactionCount ||
        beforeCleanup.openPlaintextByteLength !==
            schedule.totalReadByteLength ||
        beforeCleanup.plaintextReadByteLength !==
            schedule.totalReadByteLength ||
        beforeCleanup.commitReadbackCallCount !==
            schedule.secretSealInvocationCount ||
        beforeCleanup.commitReadbackByteLength !==
            beforeCleanup.sealCiphertextByteLength ||
        beforeCleanup.physicalWriteByteLength <
            beforeCleanup.sealCiphertextByteLength ||
        beforeCleanup.physicalReadByteLength <
            beforeCleanup.openCiphertextByteLength ||
        beforeCleanup.physicalStoredPeakByteLength <
            schedule.peakStoredByteLength ||
        beforeCleanup.physicalStoredPeakByteLength >
            beforeCleanup.physicalQuotaReservedByteLength ||
        beforeCleanup.physicalQuotaReservedByteLength +
            beforeCleanup.physicalQuotaHeadroomByteLength !==
            beforeCleanup.physicalQuotaByteLength ||
        afterCleanup.sealCallCount !== beforeCleanup.sealCallCount ||
        afterCleanup.openCallCount !== beforeCleanup.openCallCount ||
        afterCleanup.physicalWriteByteLength !==
            beforeCleanup.physicalWriteByteLength ||
        afterCleanup.physicalReadByteLength <
            beforeCleanup.physicalReadByteLength ||
        afterCleanup.storageTransactionCount <
            beforeCleanup.storageTransactionCount ||
        afterCleanup.physicalStoredPeakByteLength !==
            beforeCleanup.physicalStoredPeakByteLength ||
        afterCleanup.physicalStoredEndByteLength !==
            afterCleanup.physicalStoredStartByteLength
    ) {
        throw new Error(
            'Compact CFW browser diagnostic physical custody does not reconcile.',
        );
    }
    const totalElapsedMilliseconds = requireFiniteNonnegativeNumber(
        evidence.totalElapsedMilliseconds,
        'Compact CFW total elapsed time',
    );
    const totalCommitLatencyMilliseconds = transactionKinds.reduce(
        (total, transactionKind) =>
            total +
            commitLatencyByTransactionKind[transactionKind].totalMilliseconds,
        0,
    );
    if (totalElapsedMilliseconds < totalCommitLatencyMilliseconds) {
        throw new Error(
            'Compact CFW total duration is shorter than its sequential commit latency.',
        );
    }
    return Object.freeze({
        browserEngine: 'chromium',
        browserUserAgent: evidence.browserUserAgent,
        commitLatencyByTransactionKind,
        evidenceScope: 'nonqualifying-desktop-chromium-development-diagnostic',
        memoryAndStorageSamples: Object.freeze(memoryAndStorageSamples),
        observedReadByteLength,
        observedReadChecksumHex: evidence.observedReadChecksumHex,
        observedTransactionCount,
        observedWrittenByteLength,
        physicalStorageAccountingAfterCleanup: afterCleanup,
        physicalStorageAccountingBeforeCleanup: beforeCleanup,
        primitiveCases: Object.freeze(primitiveCases) as readonly [
            DesktopBrowserPrimitiveCaseMeasurement,
            DesktopBrowserPrimitiveCaseMeasurement,
        ],
        schedule,
        schemaVersion: 1,
        totalElapsedMilliseconds,
    });
};
