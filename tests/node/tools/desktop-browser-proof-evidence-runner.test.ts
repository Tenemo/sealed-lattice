import { describe, expect, it } from 'vitest';

import {
    desktopBrowserProofEvidenceCaseExecutionKinds as exactCaseExecutionKinds,
    desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole,
    desktopBrowserProofTransportCasePairs as transportedProofCasePairs,
    type DesktopBrowserProofEvidenceCaseIdentifier,
} from '#tests/support/desktop-browser-proof-evidence-catalog';
import {
    emptyCanonicalByteSequenceSha512Hex,
    type DesktopBrowserProofResourceAccounting,
} from '#tests/support/desktop-browser-proof-measurement';
import { desktopBrowserProofEvidenceSessionDefinitions } from '#tools/ci/browser-test-project-selection';
import {
    desktopBrowserCheckpointLedgerEvent,
    desktopBrowserCheckpointLedgerSchemaIdentifier,
    desktopBrowserMeasuredWorkLedgerEvent,
    desktopBrowserMeasuredWorkLedgerSchemaIdentifier,
    desktopBrowserProtocolCarrierLedgerEvent,
    desktopBrowserProtocolCarrierLedgerSchemaIdentifier,
    desktopBrowserProductionNetworkAccountingAuthorityEvent,
    desktopBrowserProductionNetworkAccountingAuthoritySchemaIdentifier,
} from '#tools/ci/desktop-browser-network-projection';
import {
    deriveDesktopBrowserProofCancellationBoundaryCatalogSha512Hex,
    projectDesktopBrowserProofEvidenceNetworkSessions,
    validateDesktopBrowserProofEvidenceOwnershipMatrix,
    validateDesktopBrowserProofMeasurementEvents,
} from '#tools/ci/run-desktop-browser-proof-evidence';

const cancellationBoundaries = Object.freeze([
    Object.freeze({
        boundaryIdentifier: 'store-phase-oracle',
        boundaryKind: 'storage-yield',
        boundaryOrdinal: 1,
    }),
    Object.freeze({
        boundaryIdentifier: 'read-phase-oracle',
        boundaryKind: 'storage-yield',
        boundaryOrdinal: 2,
    }),
    Object.freeze({
        boundaryIdentifier: 'commit-phase-root',
        boundaryKind: 'safe-boundary',
        boundaryOrdinal: 1,
    }),
] as const);

const cancellationBoundaryCatalogSha512Hex =
    deriveDesktopBrowserProofCancellationBoundaryCatalogSha512Hex(
        cancellationBoundaries,
    );

const completeResourceAccounting = (
    overrides: Partial<DesktopBrowserProofResourceAccounting> = {},
): DesktopBrowserProofResourceAccounting => ({
    cleanupCompleted: true,
    cleanupDeletedByteLength: 2_048,
    cleanupDeletionCount: 1,
    cleanupDurationMilliseconds: 2,
    commitReadbackByteLength: 1_024,
    commitReadbackCallCount: 1,
    ciphertextReadByteLength: 4_096,
    ciphertextReadCallCount: 2,
    ciphertextWriteByteLength: 2_048,
    ciphertextWriteCallCount: 1,
    deletionDurationMilliseconds: 1,
    deterministicRegeneratedByteLength: 1_024,
    deterministicRegenerationCallCount: 1,
    indexedDbRequestCount: 4,
    indexedDbTransactionCount: 2,
    javascriptToWasmCopyByteLength: 2_048,
    javascriptToWasmCopyCount: 2,
    kernelStorageRequestCount: 2,
    openCallCount: 1,
    openCiphertextByteLength: 2_048,
    openPlaintextByteLength: 2_000,
    physicalQuotaByteLength: 100_000,
    physicalQuotaHeadroomByteLength: 20_000,
    physicalQuotaReservedByteLength: 50_000,
    physicalStoredEndByteLength: 10_000,
    physicalStoredPeakByteLength: 40_000,
    plaintextReadByteLength: 2_000,
    plaintextReadCallCount: 2,
    plaintextWriteByteLength: 2_000,
    plaintextWriteCallCount: 2,
    repairHashCallCount: 1,
    repairHashedByteLength: 1_024,
    sealCallCount: 1,
    sealCiphertextByteLength: 2_048,
    sealPlaintextByteLength: 2_000,
    simultaneousLiveBufferPeakByteLength: 1_048_576,
    simultaneousLiveBufferPeakCount: 2,
    wasmToJavascriptCopyByteLength: 2_048,
    wasmToJavascriptCopyCount: 2,
    workerTransferByteLength: 2_048,
    workerTransferCount: 2,
    ...overrides,
});

const createMeasurementEvent = (
    caseIdentifier: DesktopBrowserProofEvidenceCaseIdentifier,
    overrides: Readonly<Record<string, unknown>> = {},
) => {
    const executionKind = exactCaseExecutionKinds[caseIdentifier];
    const emitsProof = ![
        'cancelled-generation',
        'refused-generation',
        'verification',
    ].includes(executionKind);
    return {
        browser: true,
        browserCacheState: 'cold',
        browserProcessResidentMemoryEndByteLength: 1_050_000,
        browserProcessResidentMemoryPeakByteLength: 1_100_000,
        browserProcessResidentMemoryStartByteLength: 1_000_000,
        canonicalInputByteLength: 11,
        canonicalInputSha512Hex: '12'.repeat(64),
        canonicalOutputByteLength: emitsProof ? 17 : 0,
        caseIdentifier,
        copiedBufferPeakByteLength: 1_024,
        durationMilliseconds: 12.5,
        event: 'desktop-browser-proof-measurement',
        executionKind,
        externalScratchPeakByteLength: 2_048,
        externalScratchReadByteLength: 4_096,
        externalScratchTransactionCount: 2,
        externalScratchWriteByteLength: 2_048,
        finishedAtUnixMilliseconds: 1_020,
        fullBufferCopiedByteLength: 2_048,
        fullBufferCopyCount: 2,
        javascriptHeapEndByteLength: 12_000,
        javascriptHeapPeakByteLength: 15_000,
        javascriptHeapStartByteLength: 10_000,
        observedHostAllocationVolumeByteLength: 4_096,
        outputSha512Hex: emitsProof
            ? 'ab'.repeat(64)
            : emptyCanonicalByteSequenceSha512Hex,
        resourceAccounting: completeResourceAccounting(),
        retainedResidentPeakByteLength: 4_096,
        runOrdinal: 1,
        startedAtUnixMilliseconds: 1_000,
        suiteId: 'cd'.repeat(64),
        wasmLinearMemoryEndByteLength: 196_608,
        wasmLinearMemoryEndPageCount: 3,
        wasmLinearMemoryPeakByteLength: 262_144,
        wasmLinearMemoryPeakPageCount: 4,
        wasmLinearMemoryStartByteLength: 131_072,
        wasmLinearMemoryStartPageCount: 2,
        wasmSha256Hex: 'ef'.repeat(32),
        workerInstanceIdentifier: `worker-${caseIdentifier}`,
        workerOperationOrdinal: 1,
        ...overrides,
    };
};

const generationCaseByVerificationCase: ReadonlyMap<string, string> = new Map(
    transportedProofCasePairs.map(
        ([generationCaseIdentifier, verificationCaseIdentifier]) => [
            verificationCaseIdentifier,
            generationCaseIdentifier,
        ],
    ),
);

const generationProofStream = (
    generationCaseIdentifier: string,
    browserEngine: 'chromium' | 'firefox',
    runOrdinal = 1,
) => {
    const caseIndex = transportedProofCasePairs.findIndex(
        ([candidateCaseIdentifier]) =>
            candidateCaseIdentifier === generationCaseIdentifier,
    );
    if (caseIndex < 0) {
        throw new Error(
            `No transported proof stream owns ${generationCaseIdentifier}.`,
        );
    }
    const browserOffset = browserEngine === 'chromium' ? 1 : 129;
    const digestByte = (browserOffset + caseIndex + runOrdinal - 1)
        .toString(16)
        .padStart(2, '0');
    return {
        byteLength: 100 + caseIndex + runOrdinal - 1,
        sha512Hex: digestByte.repeat(64),
    };
};

const cancellationDeclaration = Object.freeze({
    cancellationBoundaryCatalogSha512Hex,
    declaredSafeBoundaryCount: 1,
    declaredStorageYieldBoundaryCount: 2,
});

const createGenerationEvents = (browserEngine: 'chromium' | 'firefox') =>
    desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole.generation.flatMap(
        (caseIdentifier) => {
            if (caseIdentifier === 'same-secret-generation') {
                return Array.from({ length: 4 }, (_, runIndex) => {
                    const runOrdinal = runIndex + 1;
                    const transportedProof = generationProofStream(
                        caseIdentifier,
                        browserEngine,
                        runOrdinal,
                    );
                    return createMeasurementEvent(caseIdentifier, {
                        ...cancellationDeclaration,
                        browserCacheState: runOrdinal <= 2 ? 'cold' : 'warm',
                        canonicalOutputByteLength: transportedProof.byteLength,
                        finishedAtUnixMilliseconds: 1_020 + runIndex * 20,
                        outputSha512Hex: transportedProof.sha512Hex,
                        runOrdinal,
                        startedAtUnixMilliseconds: 1_000 + runIndex * 20,
                        workerInstanceIdentifier: `${browserEngine}-same-secret-run-${String(runOrdinal)}`,
                    });
                });
            }
            if (caseIdentifier === 'same-secret-generation-cancellation') {
                return cancellationBoundaries.map((boundary, boundaryIndex) =>
                    createMeasurementEvent(caseIdentifier, {
                        ...cancellationDeclaration,
                        cancellationBoundaryIdentifier:
                            boundary.boundaryIdentifier,
                        cancellationBoundaryKind: boundary.boundaryKind,
                        cancellationBoundaryOrdinal: boundary.boundaryOrdinal,
                        runOrdinal: boundaryIndex + 1,
                        workerInstanceIdentifier: `${browserEngine}-cancel-worker-${String(boundaryIndex + 1)}`,
                    }),
                );
            }
            if (
                caseIdentifier === 'same-secret-generation-after-cancellation'
            ) {
                return [
                    createMeasurementEvent(caseIdentifier, {
                        workerInstanceIdentifier: `${browserEngine}-cancel-worker-1`,
                        workerOperationOrdinal: 2,
                    }),
                ];
            }
            if (caseIdentifier === 'same-secret-generation-refusal') {
                return [
                    createMeasurementEvent(caseIdentifier, {
                        refusalReasonIdentifier: 'malformed-proof-source',
                        workerInstanceIdentifier: `${browserEngine}-refusal-worker`,
                        workerOperationOrdinal: 3,
                    }),
                ];
            }
            if (caseIdentifier === 'same-secret-generation-after-refusal') {
                return [
                    createMeasurementEvent(caseIdentifier, {
                        workerInstanceIdentifier: `${browserEngine}-refusal-worker`,
                        workerOperationOrdinal: 4,
                    }),
                ];
            }
            if (
                caseIdentifier ===
                'same-secret-native-wasm-deterministic-parity'
            ) {
                return [
                    createMeasurementEvent(caseIdentifier, {
                        canonicalOutputByteLength: 256,
                        deterministicCoinBindingSha512Hex: '77'.repeat(64),
                        nativeReferenceByteLength: 256,
                        nativeReferenceSha512Hex: '99'.repeat(64),
                        outputSha512Hex: '99'.repeat(64),
                    }),
                ];
            }
            const transportedProof = transportedProofCasePairs.some(
                ([generationCaseIdentifier]) =>
                    generationCaseIdentifier === caseIdentifier,
            )
                ? generationProofStream(caseIdentifier, browserEngine)
                : undefined;
            return [
                createMeasurementEvent(
                    caseIdentifier,
                    transportedProof === undefined
                        ? {}
                        : {
                              canonicalOutputByteLength:
                                  transportedProof.byteLength,
                              outputSha512Hex: transportedProof.sha512Hex,
                          },
                ),
            ];
        },
    );

const createVerificationEvents = (
    verificationBrowserEngine: 'chromium' | 'firefox' | 'webkit',
) =>
    desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole.verification.flatMap(
        (verificationCaseIdentifier) => {
            const generationCaseIdentifier =
                generationCaseByVerificationCase.get(
                    verificationCaseIdentifier,
                );
            if (generationCaseIdentifier === undefined) {
                throw new Error(
                    `No generation case owns ${verificationCaseIdentifier}.`,
                );
            }
            let verificationRunOrdinal = 0;
            return (['chromium', 'firefox'] as const).flatMap(
                (generationBrowserEngine) => {
                    const runCount =
                        generationCaseIdentifier === 'same-secret-generation'
                            ? 4
                            : 1;
                    return Array.from({ length: runCount }, (_, runIndex) => {
                        const generationRunOrdinal = runIndex + 1;
                        verificationRunOrdinal += 1;
                        const transportedProof = generationProofStream(
                            generationCaseIdentifier,
                            generationBrowserEngine,
                            generationRunOrdinal,
                        );
                        return createMeasurementEvent(
                            verificationCaseIdentifier,
                            {
                                canonicalInputByteLength:
                                    transportedProof.byteLength,
                                canonicalInputSha512Hex:
                                    transportedProof.sha512Hex,
                                runOrdinal: verificationRunOrdinal,
                                workerInstanceIdentifier: `${verificationBrowserEngine}-${verificationCaseIdentifier}-${generationBrowserEngine}-run-${String(generationRunOrdinal)}`,
                            },
                        );
                    });
                },
            );
        },
    );

const createOwnershipSessionEventSets = () =>
    desktopBrowserProofEvidenceSessionDefinitions.map((session) => ({
        sessionIdentifier: session.sessionIdentifier,
        testEvents:
            session.ownershipRole === 'generation'
                ? createGenerationEvents(session.browserEngine)
                : createVerificationEvents(session.browserEngine),
    }));

const networkEvidenceIdentity = Object.freeze({
    buildSha512Hex: '34'.repeat(64),
    sourceSha512Hex: '56'.repeat(64),
    suiteId: 'cd'.repeat(64),
    wasmSha256Hex: 'ef'.repeat(32),
});

const createSyntheticNetworkAccountingAuthority = (
    uploadByteLength: number,
) => ({
    canonicalChunkByteLength: 64,
    derivationErrors: [],
    event: desktopBrowserProductionNetworkAccountingAuthorityEvent,
    identity: networkEvidenceIdentity,
    orderedPhases: [
        {
            measurementCaseIdentifier: 'same-secret-generation',
            orderedCheckpoints: [
                {
                    checkpointIdentifier: 'resume-complete-generation',
                    resumeDirectionalMaterialRows: [
                        {
                            carrierIdentifier: 'synthetic-resume-input',
                            downloadByteLengthPerInstance: 5,
                            downloadChunkCountPerInstance: 1,
                            materialFamilyIdentifier:
                                'synthetic-generation-input',
                            multiplicity: 1,
                            protocolRoundTripCount: 1,
                            uploadByteLengthPerInstance: 0,
                            uploadChunkCountPerInstance: 0,
                        },
                    ],
                },
            ],
            orderedDirectionalMaterialRows: [
                {
                    carrierIdentifier: 'synthetic-generation-carrier',
                    downloadByteLengthPerInstance: 11,
                    downloadChunkCountPerInstance: 1,
                    materialFamilyIdentifier: 'synthetic-common-proof',
                    multiplicity: 1,
                    protocolRoundTripCount: 1,
                    uploadByteLengthPerInstance: uploadByteLength,
                    uploadChunkCountPerInstance: 1,
                },
            ],
            phaseIdentifier: 'complete-generation',
            proofFamilyApplications: [
                {
                    applicationStatementSchemaIdentifier: 0x1201,
                    logicalEntryCount: 1,
                    physicalProofCount: 1,
                },
            ],
        },
    ],
    orderedProofFamilies: [
        {
            applicationStatementSchemaIdentifier: 0x1201,
            logicalEntryCount: 1,
            physicalProofCount: 1,
        },
    ],
    productionAccountingBuildShake256Hex: '45'.repeat(64),
    productionAccountingCandidateInputShake256Hex: '67'.repeat(64),
    productionAccountingRecordByteLength: 1_234,
    productionAccountingRecordKind: 'synthetic-test-only-accounting',
    productionAccountingRecordShake256Hex: '89'.repeat(64),
    productionAccountingRecordVersion: 1,
    productionAccountingSourceShake256Hex: 'ab'.repeat(64),
    schemaIdentifier:
        desktopBrowserProductionNetworkAccountingAuthoritySchemaIdentifier,
    totalLogicalEntryCount: 1,
    totalPhysicalProofCount: 1,
});

const createNetworkLedgerEvents = (uploadByteLength = 17) => [
    createSyntheticNetworkAccountingAuthority(uploadByteLength),
    {
        canonicalChunkByteLength: 64,
        event: desktopBrowserProtocolCarrierLedgerEvent,
        identity: networkEvidenceIdentity,
        phases: [
            {
                downloadByteLength: 11,
                downloadChunkCount: 1,
                phaseIdentifier: 'complete-generation',
                protocolRoundTripCount: 1,
                uploadByteLength,
                uploadChunkCount: 1,
            },
        ],
        schemaIdentifier: desktopBrowserProtocolCarrierLedgerSchemaIdentifier,
    },
    {
        event: desktopBrowserCheckpointLedgerEvent,
        identity: networkEvidenceIdentity,
        phases: [
            {
                checkpoints: [
                    {
                        checkpointIdentifier: 'resume-complete-generation',
                        resumeArithmeticDurationMilliseconds: 1,
                        resumeDownloadByteLength: 5,
                        resumeDownloadChunkCount: 1,
                        resumeHashingDurationMilliseconds: 1,
                        resumeProtocolRoundTripCount: 1,
                        resumeQuorumWaitDurationMilliseconds: 2,
                        resumeResourceAccounting: completeResourceAccounting(),
                        resumeStorageDurationMilliseconds: 1,
                        resumeUploadByteLength: 0,
                        resumeUploadChunkCount: 0,
                    },
                ],
                phaseIdentifier: 'complete-generation',
            },
        ],
        schemaIdentifier: desktopBrowserCheckpointLedgerSchemaIdentifier,
    },
    {
        event: desktopBrowserMeasuredWorkLedgerEvent,
        identity: networkEvidenceIdentity,
        phases: [
            {
                arithmeticDurationMilliseconds: 7,
                hashingDurationMilliseconds: 2,
                measurementCaseIdentifier: 'same-secret-generation',
                measurementRunOrdinal: 1,
                ordersOfMagnitudeVarianceExplanation: null,
                phaseIdentifier: 'complete-generation',
                planningReferenceDurationMilliseconds: 12.5,
                quorumWaitDurationMilliseconds: 3,
                storageDurationMilliseconds: 3.5,
            },
        ],
        schemaIdentifier: desktopBrowserMeasuredWorkLedgerSchemaIdentifier,
    },
];

const createOwnershipSessionEventSetsWithNetworkLedgers = (
    firefoxUploadByteLength = 17,
) =>
    createOwnershipSessionEventSets().map((sessionEventSet) => {
        const session = desktopBrowserProofEvidenceSessionDefinitions.find(
            ({ sessionIdentifier }) =>
                sessionIdentifier === sessionEventSet.sessionIdentifier,
        );
        if (session === undefined) {
            throw new Error('The test fixture lost an ownership session.');
        }
        return session.ownershipRole === 'generation'
            ? {
                  ...sessionEventSet,
                  testEvents: [
                      ...sessionEventSet.testEvents,
                      ...createNetworkLedgerEvents(
                          session.browserEngine === 'firefox'
                              ? firefoxUploadByteLength
                              : 17,
                      ),
                  ],
              }
            : sessionEventSet;
    });

const createExactMeasurementEvents = () => [
    ...createGenerationEvents('chromium'),
    ...createVerificationEvents('chromium'),
];

describe('Desktop-browser proof-evidence runner', () => {
    it('owns generation and verification in independent browser sessions', () => {
        expect(
            desktopBrowserProofEvidenceSessionDefinitions.map(
                ({ browserEngine, ownershipRole }) => ({
                    browserEngine,
                    ownershipRole,
                }),
            ),
        ).toEqual([
            { browserEngine: 'chromium', ownershipRole: 'generation' },
            { browserEngine: 'firefox', ownershipRole: 'generation' },
            { browserEngine: 'chromium', ownershipRole: 'verification' },
            { browserEngine: 'firefox', ownershipRole: 'verification' },
            { browserEngine: 'webkit', ownershipRole: 'verification' },
        ]);
    });

    it('accepts complete lifecycle evidence and fresh cross-process verification', () => {
        expect(
            validateDesktopBrowserProofEvidenceOwnershipMatrix(
                createOwnershipSessionEventSets(),
                { wasmSha256Hex: 'ef'.repeat(32) },
            ),
        ).toHaveLength(desktopBrowserProofEvidenceSessionDefinitions.length);
        expect(
            validateDesktopBrowserProofMeasurementEvents(
                createExactMeasurementEvents(),
            ),
        ).not.toHaveLength(0);
    });

    it('projects canonical network ledgers through the evidence report owner', () => {
        const projections = projectDesktopBrowserProofEvidenceNetworkSessions(
            createOwnershipSessionEventSetsWithNetworkLedgers(),
            { wasmSha256Hex: 'ef'.repeat(32) },
        );
        expect(projections.map(({ browserEngine }) => browserEngine)).toEqual([
            'chromium',
            'firefox',
        ]);
        expect(
            projections.map(
                ({ projection }) => projection.durableCheckpointCount,
            ),
        ).toEqual([1, 1]);
        expect(
            projections.map(({ projection }) =>
                projection.projections.map(
                    ({ computeSlowdownMultiplier }) =>
                        computeSlowdownMultiplier,
                ),
            ),
        ).toEqual([
            [2, 4, 8],
            [2, 4, 8],
        ]);
    });

    it('rejects cross-engine network carrier drift', () => {
        expect(() =>
            projectDesktopBrowserProofEvidenceNetworkSessions(
                createOwnershipSessionEventSetsWithNetworkLedgers(18),
            ),
        ).toThrow(/did not use one source, build, suite/u);
    });

    it('rejects incomplete, role-mixed, or untransported ownership evidence', () => {
        const exactSessionEventSets = createOwnershipSessionEventSets();
        expect(() =>
            validateDesktopBrowserProofEvidenceOwnershipMatrix(
                exactSessionEventSets.slice(1),
            ),
        ).toThrow(/omitted required ownership sessions/u);
        expect(() =>
            validateDesktopBrowserProofEvidenceOwnershipMatrix([
                ...exactSessionEventSets,
                exactSessionEventSets[0],
            ]),
        ).toThrow(/repeated ownership session/u);
        expect(() =>
            validateDesktopBrowserProofEvidenceOwnershipMatrix(
                exactSessionEventSets.map((sessionEventSet, sessionIndex) =>
                    sessionIndex === 0
                        ? {
                              ...sessionEventSet,
                              testEvents: [
                                  ...sessionEventSet.testEvents,
                                  createMeasurementEvent(
                                      'same-secret-verification',
                                  ),
                              ],
                          }
                        : sessionEventSet,
                ),
            ),
        ).toThrow(/unexpected case/u);
        expect(() =>
            validateDesktopBrowserProofEvidenceOwnershipMatrix(
                exactSessionEventSets.map((sessionEventSet) =>
                    sessionEventSet.sessionIdentifier === 'webkit-verification'
                        ? {
                              ...sessionEventSet,
                              testEvents: sessionEventSet.testEvents.map(
                                  (event, eventIndex) =>
                                      eventIndex === 0
                                          ? {
                                                ...event,
                                                canonicalInputSha512Hex:
                                                    '44'.repeat(64),
                                            }
                                          : event,
                              ),
                          }
                        : sessionEventSet,
                ),
            ),
        ).toThrow(/did not freshly verify exactly the transported bytes/u);
    });

    it('rejects missing cancellation coverage and broken cancellation reuse', () => {
        const exactSessionEventSets = createOwnershipSessionEventSets();
        const chromiumGeneration = exactSessionEventSets[0];
        expect(chromiumGeneration).toBeDefined();
        const removeOneCancellationBoundary = exactSessionEventSets.map(
            (sessionEventSet) =>
                sessionEventSet === chromiumGeneration
                    ? {
                          ...sessionEventSet,
                          testEvents: sessionEventSet.testEvents.filter(
                              (event) =>
                                  !(
                                      event.caseIdentifier ===
                                          'same-secret-generation-cancellation' &&
                                      event.runOrdinal === 3
                                  ),
                          ),
                      }
                    : sessionEventSet,
        );
        expect(() =>
            validateDesktopBrowserProofEvidenceOwnershipMatrix(
                removeOneCancellationBoundary,
            ),
        ).toThrow(/did not cancel at every declared/u);

        const breakReuse = exactSessionEventSets.map((sessionEventSet) =>
            sessionEventSet === chromiumGeneration
                ? {
                      ...sessionEventSet,
                      testEvents: sessionEventSet.testEvents.map((event) =>
                          event.caseIdentifier ===
                          'same-secret-generation-after-cancellation'
                              ? {
                                    ...event,
                                    workerOperationOrdinal: 9,
                                }
                              : event,
                      ),
                  }
                : sessionEventSet,
        );
        expect(() =>
            validateDesktopBrowserProofEvidenceOwnershipMatrix(breakReuse),
        ).toThrow(/immediately after cancellation/u);
    });

    it('rejects insufficient cache repetitions and native/WASM parity drift', () => {
        const exactSessionEventSets = createOwnershipSessionEventSets();
        const chromiumGeneration = exactSessionEventSets[0];
        expect(chromiumGeneration).toBeDefined();
        expect(() =>
            validateDesktopBrowserProofEvidenceOwnershipMatrix(
                exactSessionEventSets.map((sessionEventSet) =>
                    sessionEventSet === chromiumGeneration
                        ? {
                              ...sessionEventSet,
                              testEvents: sessionEventSet.testEvents.filter(
                                  (event) =>
                                      !(
                                          event.caseIdentifier ===
                                              'same-secret-generation' &&
                                          event.runOrdinal === 4
                                      ),
                              ),
                          }
                        : sessionEventSet,
                ),
            ),
        ).toThrow(/at least 2 cold and 2 warm/u);
        expect(() =>
            validateDesktopBrowserProofEvidenceOwnershipMatrix(
                exactSessionEventSets.map((sessionEventSet) =>
                    sessionEventSet === chromiumGeneration
                        ? {
                              ...sessionEventSet,
                              testEvents: sessionEventSet.testEvents.map(
                                  (event) =>
                                      event.caseIdentifier ===
                                      'same-secret-native-wasm-deterministic-parity'
                                          ? {
                                                ...event,
                                                nativeReferenceSha512Hex:
                                                    '98'.repeat(64),
                                            }
                                          : event,
                              ),
                          }
                        : sessionEventSet,
                ),
            ),
        ).toThrow(/not identical/u);
    });

    it('rejects verifier worker reuse and cross-session suite drift', () => {
        const exactSessionEventSets = createOwnershipSessionEventSets();
        const webkitVerification = exactSessionEventSets.find(
            ({ sessionIdentifier }) =>
                sessionIdentifier === 'webkit-verification',
        );
        expect(webkitVerification).toBeDefined();
        expect(() =>
            validateDesktopBrowserProofEvidenceOwnershipMatrix(
                exactSessionEventSets.map((sessionEventSet) =>
                    sessionEventSet === webkitVerification
                        ? {
                              ...sessionEventSet,
                              testEvents: sessionEventSet.testEvents.map(
                                  (event, eventIndex) =>
                                      eventIndex === 1
                                          ? {
                                                ...event,
                                                workerInstanceIdentifier:
                                                    sessionEventSet
                                                        .testEvents[0]
                                                        ?.workerInstanceIdentifier,
                                            }
                                          : event,
                              ),
                          }
                        : sessionEventSet,
                ),
            ),
        ).toThrow(/fresh worker instance/u);
        expect(() =>
            validateDesktopBrowserProofEvidenceOwnershipMatrix(
                exactSessionEventSets.map((sessionEventSet) =>
                    sessionEventSet === webkitVerification
                        ? {
                              ...sessionEventSet,
                              testEvents: sessionEventSet.testEvents.map(
                                  (event) => ({
                                      ...event,
                                      suiteId: '12'.repeat(64),
                                  }),
                              ),
                          }
                        : sessionEventSet,
                ),
            ),
        ).toThrow(/ownership sessions did not use one exact suite/u);
    });

    it('rejects missing physical accounting and absolute-bound overruns', () => {
        const exactEvents = createExactMeasurementEvents();
        const firstEvent = exactEvents[0];
        expect(firstEvent).toBeDefined();
        const {
            indexedDbRequestCount: _omitted,
            ...incompleteResourceAccounting
        } = firstEvent.resourceAccounting;
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                exactEvents.map((event, eventIndex) =>
                    eventIndex === 0
                        ? {
                              ...event,
                              resourceAccounting: incompleteResourceAccounting,
                          }
                        : event,
                ),
            ),
        ).toThrow(/exact fields/u);
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                exactEvents.map((event, eventIndex) =>
                    eventIndex === 0
                        ? {
                              ...event,
                              resourceAccounting: completeResourceAccounting({
                                  simultaneousLiveBufferPeakByteLength: 2_097_153,
                              }),
                          }
                        : event,
                ),
            ),
        ).toThrow(/absolute simultaneous live-buffer peak/u);
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                exactEvents.map((event, eventIndex) =>
                    eventIndex === 0
                        ? {
                              ...event,
                              wasmLinearMemoryPeakByteLength: 671_088_640,
                              wasmLinearMemoryPeakPageCount: 10_240,
                          }
                        : event,
                ),
            ),
        ).not.toThrow();
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                exactEvents.map((event, eventIndex) =>
                    eventIndex === 0
                        ? {
                              ...event,
                              wasmLinearMemoryPeakByteLength: 671_154_176,
                              wasmLinearMemoryPeakPageCount: 10_241,
                          }
                        : event,
                ),
            ),
        ).toThrow(/absolute WebAssembly linear-memory peak/u);
    });

    it('accepts a selected proof exactly at the evidence-selection bound', () => {
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                createExactMeasurementEvents().map((event) =>
                    event.caseIdentifier === 'same-secret-generation' &&
                    event.runOrdinal === 1
                        ? {
                              ...event,
                              canonicalOutputByteLength: 5_242_880,
                          }
                        : event,
                ),
            ),
        ).not.toThrow();
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                createExactMeasurementEvents().map((event) =>
                    event.caseIdentifier === 'same-secret-verification' &&
                    event.runOrdinal === 1
                        ? {
                              ...event,
                              canonicalInputByteLength: 5_242_880,
                          }
                        : event,
                ),
            ),
        ).not.toThrow();
    });

    it('rejects a selected proof one byte above the evidence-selection bound', () => {
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                createExactMeasurementEvents().map((event) =>
                    event.caseIdentifier === 'same-secret-generation' &&
                    event.runOrdinal === 1
                        ? {
                              ...event,
                              canonicalOutputByteLength: 5_242_881,
                          }
                        : event,
                ),
            ),
        ).toThrow(
            /selected proof evidence-selection bound.*5242881 > 5242880 bytes/u,
        );
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                createExactMeasurementEvents().map((event) =>
                    event.caseIdentifier === 'same-secret-verification' &&
                    event.runOrdinal === 1
                        ? {
                              ...event,
                              canonicalInputByteLength: 5_242_881,
                          }
                        : event,
                ),
            ),
        ).toThrow(
            /selected proof evidence-selection bound.*5242881 > 5242880 bytes/u,
        );
    });
});
