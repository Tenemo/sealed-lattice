import { describe, expect, it } from 'vitest';

import type {
    DesktopBrowserProofMeasurementRecord,
    DesktopBrowserProofResourceAccounting,
} from '#tests/support/desktop-browser-proof-measurement';
import {
    desktopBrowserCheckpointLedgerEvent,
    desktopBrowserCheckpointLedgerSchemaIdentifier,
    desktopBrowserMeasuredWorkLedgerEvent,
    desktopBrowserMeasuredWorkLedgerSchemaIdentifier,
    desktopBrowserProtocolCarrierLedgerEvent,
    desktopBrowserProtocolCarrierLedgerSchemaIdentifier,
    desktopBrowserProductionNetworkAccountingAuthorityEvent,
    desktopBrowserProductionNetworkAccountingAuthoritySchemaIdentifier,
    projectDesktopBrowserNetworkEvidence,
    type DesktopBrowserCheckpointLedger,
    type DesktopBrowserMeasuredWorkLedger,
    type DesktopBrowserNetworkEvidenceIdentity,
    type DesktopBrowserProtocolCarrierLedger,
    type DesktopBrowserProductionNetworkAccountingAuthority,
} from '#tools/ci/desktop-browser-network-projection';

const identity: DesktopBrowserNetworkEvidenceIdentity = Object.freeze({
    buildSha512Hex: '22'.repeat(64),
    sourceSha512Hex: '11'.repeat(64),
    suiteId: '33'.repeat(64),
    wasmSha256Hex: '44'.repeat(32),
});

const syntheticProductionAccountingAuthority =
    (): DesktopBrowserProductionNetworkAccountingAuthority => ({
        canonicalChunkByteLength: 1_000,
        derivationErrors: [],
        event: desktopBrowserProductionNetworkAccountingAuthorityEvent,
        identity,
        orderedPhases: [
            {
                measurementCaseIdentifier: 'same-secret-generation',
                orderedCheckpoints: [
                    {
                        checkpointIdentifier: 'generated-proof',
                        resumeDirectionalMaterialRows: [
                            {
                                carrierIdentifier:
                                    'synthetic-resume-source-read',
                                downloadByteLengthPerInstance: 1_000,
                                downloadChunkCountPerInstance: 1,
                                materialFamilyIdentifier:
                                    'synthetic-proof-source',
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
                        carrierIdentifier: 'synthetic-small-input',
                        downloadByteLengthPerInstance: 200,
                        downloadChunkCountPerInstance: 1,
                        materialFamilyIdentifier: 'synthetic-proof-input',
                        multiplicity: 2,
                        protocolRoundTripCount: 0,
                        uploadByteLengthPerInstance: 0,
                        uploadChunkCountPerInstance: 0,
                    },
                    {
                        carrierIdentifier: 'synthetic-proof-carrier',
                        downloadByteLengthPerInstance: 2_100,
                        downloadChunkCountPerInstance: 3,
                        materialFamilyIdentifier: 'synthetic-common-proof',
                        multiplicity: 1,
                        protocolRoundTripCount: 1,
                        uploadByteLengthPerInstance: 2_000,
                        uploadChunkCountPerInstance: 2,
                    },
                ],
                phaseIdentifier: 'generate-proof',
                proofFamilyApplications: [
                    {
                        applicationStatementSchemaIdentifier: 0x1201,
                        logicalEntryCount: 3,
                        physicalProofCount: 2,
                    },
                ],
            },
            {
                measurementCaseIdentifier: 'ballot-validity-generation',
                orderedCheckpoints: [],
                orderedDirectionalMaterialRows: [
                    {
                        carrierIdentifier: 'synthetic-proof-publication',
                        downloadByteLengthPerInstance: 0,
                        downloadChunkCountPerInstance: 0,
                        materialFamilyIdentifier: 'synthetic-published-proof',
                        multiplicity: 1,
                        protocolRoundTripCount: 1,
                        uploadByteLengthPerInstance: 1_000,
                        uploadChunkCountPerInstance: 1,
                    },
                ],
                phaseIdentifier: 'publish-proof',
                proofFamilyApplications: [
                    {
                        applicationStatementSchemaIdentifier: 0x1217,
                        logicalEntryCount: 6,
                        physicalProofCount: 1,
                    },
                ],
            },
        ],
        orderedProofFamilies: [
            {
                applicationStatementSchemaIdentifier: 0x1201,
                logicalEntryCount: 3,
                physicalProofCount: 2,
            },
            {
                applicationStatementSchemaIdentifier: 0x1217,
                logicalEntryCount: 6,
                physicalProofCount: 1,
            },
        ],
        productionAccountingBuildShake256Hex: '88'.repeat(64),
        productionAccountingCandidateInputShake256Hex: '99'.repeat(64),
        productionAccountingRecordByteLength: 12_345,
        productionAccountingRecordKind: 'synthetic-test-only-accounting',
        productionAccountingRecordShake256Hex: 'aa'.repeat(64),
        productionAccountingRecordVersion: 1,
        productionAccountingSourceShake256Hex: 'bb'.repeat(64),
        schemaIdentifier:
            desktopBrowserProductionNetworkAccountingAuthoritySchemaIdentifier,
        totalLogicalEntryCount: 9,
        totalPhysicalProofCount: 3,
    });

const resourceAccounting = (): DesktopBrowserProofResourceAccounting => ({
    cleanupCompleted: true,
    cleanupDeletedByteLength: 1_000,
    cleanupDeletionCount: 1,
    cleanupDurationMilliseconds: 2,
    commitReadbackByteLength: 1_000,
    commitReadbackCallCount: 1,
    ciphertextReadByteLength: 2_000,
    ciphertextReadCallCount: 2,
    ciphertextWriteByteLength: 2_000,
    ciphertextWriteCallCount: 2,
    deletionDurationMilliseconds: 1,
    deterministicRegeneratedByteLength: 1_000,
    deterministicRegenerationCallCount: 1,
    indexedDbRequestCount: 4,
    indexedDbTransactionCount: 2,
    javascriptToWasmCopyByteLength: 1_000,
    javascriptToWasmCopyCount: 1,
    kernelStorageRequestCount: 2,
    openCallCount: 1,
    openCiphertextByteLength: 1_024,
    openPlaintextByteLength: 1_000,
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
    repairHashedByteLength: 1_000,
    sealCallCount: 1,
    sealCiphertextByteLength: 1_024,
    sealPlaintextByteLength: 1_000,
    simultaneousLiveBufferPeakByteLength: 2_000,
    simultaneousLiveBufferPeakCount: 2,
    wasmToJavascriptCopyByteLength: 1_000,
    wasmToJavascriptCopyCount: 1,
    workerTransferByteLength: 1_000,
    workerTransferCount: 1,
});

const measurement = (
    caseIdentifier: string,
    durationMilliseconds: number,
): DesktopBrowserProofMeasurementRecord => ({
    browserCacheState: 'warm',
    browserProcessResidentMemoryEndByteLength: 1_100_000,
    browserProcessResidentMemoryPeakByteLength: 1_200_000,
    browserProcessResidentMemoryStartByteLength: 1_000_000,
    canonicalInputByteLength: 1_000,
    canonicalInputSha512Hex: '55'.repeat(64),
    canonicalOutputByteLength: 2_000,
    caseIdentifier,
    copiedBufferPeakByteLength: 1_000,
    durationMilliseconds,
    executionKind: 'fresh-generation',
    externalScratchPeakByteLength: 2_000,
    externalScratchReadByteLength: 2_000,
    externalScratchTransactionCount: 2,
    externalScratchWriteByteLength: 2_000,
    finishedAtUnixMilliseconds: 1_000 + durationMilliseconds,
    fullBufferCopiedByteLength: 2_000,
    fullBufferCopyCount: 2,
    javascriptHeapEndByteLength: 11_000,
    javascriptHeapPeakByteLength: 12_000,
    javascriptHeapStartByteLength: 10_000,
    observedHostAllocationVolumeByteLength: 2_000,
    outputSha512Hex: '66'.repeat(64),
    resourceAccounting: resourceAccounting(),
    retainedResidentPeakByteLength: 2_000,
    runOrdinal: 1,
    startedAtUnixMilliseconds: 1_000,
    suiteId: identity.suiteId,
    wasmLinearMemoryEndByteLength: 131_072,
    wasmLinearMemoryEndPageCount: 2,
    wasmLinearMemoryPeakByteLength: 196_608,
    wasmLinearMemoryPeakPageCount: 3,
    wasmLinearMemoryStartByteLength: 65_536,
    wasmLinearMemoryStartPageCount: 1,
    wasmSha256Hex: identity.wasmSha256Hex,
    workerInstanceIdentifier: `worker-${caseIdentifier}`,
    workerOperationOrdinal: 1,
});

const carrierLedger = (): DesktopBrowserProtocolCarrierLedger => ({
    canonicalChunkByteLength: 1_000,
    event: desktopBrowserProtocolCarrierLedgerEvent,
    identity,
    phases: [
        {
            downloadByteLength: 2_500,
            downloadChunkCount: 5,
            phaseIdentifier: 'generate-proof',
            protocolRoundTripCount: 1,
            uploadByteLength: 2_000,
            uploadChunkCount: 2,
        },
        {
            downloadByteLength: 0,
            downloadChunkCount: 0,
            phaseIdentifier: 'publish-proof',
            protocolRoundTripCount: 1,
            uploadByteLength: 1_000,
            uploadChunkCount: 1,
        },
    ],
    schemaIdentifier: desktopBrowserProtocolCarrierLedgerSchemaIdentifier,
});

const checkpointLedger = (): DesktopBrowserCheckpointLedger => ({
    event: desktopBrowserCheckpointLedgerEvent,
    identity,
    phases: [
        {
            checkpoints: [
                {
                    checkpointIdentifier: 'generated-proof',
                    resumeArithmeticDurationMilliseconds: 10,
                    resumeDownloadByteLength: 1_000,
                    resumeDownloadChunkCount: 1,
                    resumeHashingDurationMilliseconds: 5,
                    resumeProtocolRoundTripCount: 1,
                    resumeQuorumWaitDurationMilliseconds: 30,
                    resumeResourceAccounting: resourceAccounting(),
                    resumeStorageDurationMilliseconds: 20,
                    resumeUploadByteLength: 0,
                    resumeUploadChunkCount: 0,
                },
            ],
            phaseIdentifier: 'generate-proof',
        },
        {
            checkpoints: [],
            phaseIdentifier: 'publish-proof',
        },
    ],
    schemaIdentifier: desktopBrowserCheckpointLedgerSchemaIdentifier,
});

const workLedger = (): DesktopBrowserMeasuredWorkLedger => ({
    event: desktopBrowserMeasuredWorkLedgerEvent,
    identity,
    phases: [
        {
            arithmeticDurationMilliseconds: 60,
            hashingDurationMilliseconds: 20,
            measurementCaseIdentifier: 'same-secret-generation',
            measurementRunOrdinal: 1,
            ordersOfMagnitudeVarianceExplanation: null,
            phaseIdentifier: 'generate-proof',
            planningReferenceDurationMilliseconds: 100,
            quorumWaitDurationMilliseconds: 40,
            storageDurationMilliseconds: 20,
        },
        {
            arithmeticDurationMilliseconds: 20,
            hashingDurationMilliseconds: 10,
            measurementCaseIdentifier: 'ballot-validity-generation',
            measurementRunOrdinal: 1,
            ordersOfMagnitudeVarianceExplanation: null,
            phaseIdentifier: 'publish-proof',
            planningReferenceDurationMilliseconds: 50,
            quorumWaitDurationMilliseconds: 30,
            storageDurationMilliseconds: 20,
        },
    ],
    schemaIdentifier: desktopBrowserMeasuredWorkLedgerSchemaIdentifier,
});

const exactEvidence = () => ({
    evidenceEvents: [carrierLedger(), checkpointLedger(), workLedger()],
    measurements: [
        measurement('same-secret-generation', 100),
        measurement('ballot-validity-generation', 50),
    ],
    productionAccountingAuthority: syntheticProductionAccountingAuthority(),
});

describe('Desktop-browser network projection', () => {
    it('projects pipelined relay traffic, every checkpoint interruption, and compute slowdowns', () => {
        const projection =
            projectDesktopBrowserNetworkEvidence(exactEvidence());

        expect(projection.durableCheckpointCount).toBe(1);
        expect(projection.orderedPhaseIdentifiers).toEqual([
            'generate-proof',
            'publish-proof',
        ]);
        expect(projection.localIndexedDbTraffic).toMatchObject({
            indexedDbRequestCount: 12,
            indexedDbTransactionCount: 6,
            kernelStorageRequestCount: 6,
            minimumPhysicalQuotaHeadroomByteLength: 20_000,
        });
        const twoTimes = projection.projections[0];
        expect(twoTimes).toBeDefined();
        expect(twoTimes?.computeSlowdownMultiplier).toBe(2);
        expect(twoTimes?.protocolRelayTransport).toMatchObject({
            downloadByteLength: 3_500,
            downloadChunkCount: 6,
            pipelinedChunks: true,
            protocolRoundTripCount: 3,
            uploadByteLength: 3_000,
            uploadChunkCount: 3,
        });
        expect(
            twoTimes?.protocolRelayTransport.totalDurationMilliseconds,
        ).toBeCloseTo(303.52);
        expect(twoTimes?.arithmeticDurationMilliseconds).toBe(180);
        expect(twoTimes?.hashingDurationMilliseconds).toBe(70);
        expect(twoTimes?.storageDurationMilliseconds).toBe(60);
        expect(twoTimes?.quorumWaitDurationMilliseconds).toBe(100);
        expect(twoTimes?.totalDurationMilliseconds).toBeCloseTo(713.52);
        expect(
            projection.projections[2]?.totalDurationMilliseconds,
        ).toBeCloseTo(1_463.52);
        expect(projection.productionAccounting).toMatchObject({
            directionalMaterialRowCount: 4,
            productionAccountingRecordKind: 'synthetic-test-only-accounting',
            totalLogicalEntryCount: 9,
            totalPhysicalProofCount: 3,
        });
    });

    it('rejects absent or duplicate canonical ledgers', () => {
        const exact = exactEvidence();
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                evidenceEvents: exact.evidenceEvents.slice(0, 2),
            }),
        ).toThrow(/exactly one.*measured-work-ledger/u);
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                evidenceEvents: [
                    ...exact.evidenceEvents,
                    exact.evidenceEvents[0],
                ],
            }),
        ).toThrow(/exactly one.*protocol-carrier-ledger/u);
    });

    it('refuses missing or incomplete production accounting authority before projection', () => {
        const exact = exactEvidence();
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                productionAccountingAuthority: undefined as never,
            }),
        ).toThrow(/productionAccountingAuthority must be an object/u);

        const authority = syntheticProductionAccountingAuthority();
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                productionAccountingAuthority: {
                    ...authority,
                    derivationErrors: [
                        {
                            dimension: 'directional-ceremony-traffic',
                            reasonCode:
                                'remaining-directional-traffic-carriers-absent',
                            requiredCarrier:
                                'Production-derived participant upload and download routes.',
                        },
                    ],
                },
            }),
        ).toThrow(/refuses incomplete production accounting/u);
    });

    it('rejects production multiplicity and durable-checkpoint drift', () => {
        const exact = exactEvidence();
        const authority = syntheticProductionAccountingAuthority();
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                productionAccountingAuthority: {
                    ...authority,
                    totalPhysicalProofCount: 4,
                },
            }),
        ).toThrow(/complete-action proof multiplicities/u);

        const checkpointDrift = checkpointLedger();
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                evidenceEvents: [
                    carrierLedger(),
                    {
                        ...checkpointDrift,
                        phases: [
                            {
                                ...checkpointDrift.phases[0],
                                checkpoints: [
                                    {
                                        ...checkpointDrift.phases[0]
                                            ?.checkpoints[0],
                                        checkpointIdentifier:
                                            'wrong-generated-proof',
                                    },
                                ],
                            },
                            checkpointDrift.phases[1],
                        ],
                    },
                    workLedger(),
                ],
            }),
        ).toThrow(/production-authoritative durable checkpoint catalog/u);
    });

    it('rejects missing, duplicate, or reordered phases and measurements', () => {
        const exact = exactEvidence();
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                evidenceEvents: [
                    carrierLedger(),
                    {
                        ...checkpointLedger(),
                        phases: checkpointLedger().phases.slice(1),
                    },
                    workLedger(),
                ],
            }),
        ).toThrow(/production-authoritative phase catalog/u);
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                measurements: exact.measurements.slice(1),
            }),
        ).toThrow(/missing or duplicate measurement binding/u);
        const duplicateMeasurementWorkLedger = workLedger();
        const duplicateMeasurementAuthority =
            syntheticProductionAccountingAuthority();
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                evidenceEvents: [
                    carrierLedger(),
                    checkpointLedger(),
                    {
                        ...duplicateMeasurementWorkLedger,
                        phases: [
                            duplicateMeasurementWorkLedger.phases[0],
                            {
                                ...duplicateMeasurementWorkLedger.phases[1],
                                measurementCaseIdentifier:
                                    'same-secret-generation',
                            },
                        ],
                    },
                ],
                productionAccountingAuthority: {
                    ...duplicateMeasurementAuthority,
                    orderedPhases: [
                        duplicateMeasurementAuthority.orderedPhases[0],
                        {
                            ...duplicateMeasurementAuthority.orderedPhases[1],
                            measurementCaseIdentifier: 'same-secret-generation',
                        },
                    ],
                },
            }),
        ).toThrow(/missing or duplicate measurement binding/u);
    });

    it('rejects identity drift, unaccounted time, and noncanonical chunks', () => {
        const exact = exactEvidence();
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                evidenceEvents: [
                    carrierLedger(),
                    {
                        ...checkpointLedger(),
                        identity: {
                            ...identity,
                            sourceSha512Hex: '77'.repeat(64),
                        },
                    },
                    workLedger(),
                ],
            }),
        ).toThrow(/different source, build, suite, or WebAssembly/u);
        const unaccountedWork = workLedger();
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                evidenceEvents: [
                    carrierLedger(),
                    checkpointLedger(),
                    {
                        ...unaccountedWork,
                        phases: [
                            {
                                ...unaccountedWork.phases[0],
                                arithmeticDurationMilliseconds: 1,
                            },
                            unaccountedWork.phases[1],
                        ],
                    },
                ],
            }),
        ).toThrow(/does not reconcile/u);
        const noncanonicalCarrierLedger = carrierLedger();
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                evidenceEvents: [
                    {
                        ...noncanonicalCarrierLedger,
                        phases: [
                            {
                                ...noncanonicalCarrierLedger.phases[0],
                                downloadChunkCount: 2,
                            },
                            noncanonicalCarrierLedger.phases[1],
                        ],
                    },
                    checkpointLedger(),
                    workLedger(),
                ],
            }),
        ).toThrow(/production-derived directional material accounting/u);
    });

    it('fails unexplained orders-of-magnitude variance and preserves explanations', () => {
        const exact = exactEvidence();
        const highVarianceWorkLedger = workLedger();
        const highVariancePhases = [
            {
                ...highVarianceWorkLedger.phases[0],
                planningReferenceDurationMilliseconds: 0.5,
            },
            highVarianceWorkLedger.phases[1],
        ] as const;
        expect(() =>
            projectDesktopBrowserNetworkEvidence({
                ...exact,
                evidenceEvents: [
                    carrierLedger(),
                    checkpointLedger(),
                    { ...highVarianceWorkLedger, phases: highVariancePhases },
                ],
            }),
        ).toThrow(/unexplained orders-of-magnitude variance/u);

        const explainedProjection = projectDesktopBrowserNetworkEvidence({
            ...exact,
            evidenceEvents: [
                carrierLedger(),
                checkpointLedger(),
                {
                    ...highVarianceWorkLedger,
                    phases: [
                        {
                            ...highVariancePhases[0],
                            ordersOfMagnitudeVarianceExplanation:
                                'Measured production geometry exceeds the earlier compact planning geometry.',
                        },
                        highVariancePhases[1],
                    ],
                },
            ],
        });
        expect(
            explainedProjection.ordersOfMagnitudeVarianceExplanations,
        ).toEqual([
            {
                explanation:
                    'Measured production geometry exceeds the earlier compact planning geometry.',
                observedToPlanningRatio: 200,
                phaseIdentifier: 'generate-proof',
            },
        ]);
    });
});
