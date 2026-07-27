import { createHash } from 'node:crypto';

import {
    isDesktopBrowserProofEvidenceCaseIdentifier,
    type DesktopBrowserProofEvidenceCaseIdentifier,
} from '../../tests/support/desktop-browser-proof-evidence-catalog.js';
import {
    parseDesktopBrowserProofResourceAccounting,
    type DesktopBrowserProofMeasurementRecord,
    type DesktopBrowserProofResourceAccounting,
} from '../../tests/support/desktop-browser-proof-measurement.js';

export const desktopBrowserProtocolCarrierLedgerEvent =
    'desktop-browser-proof-protocol-carrier-ledger';
export const desktopBrowserCheckpointLedgerEvent =
    'desktop-browser-proof-checkpoint-ledger';
export const desktopBrowserMeasuredWorkLedgerEvent =
    'desktop-browser-proof-measured-work-ledger';
export const desktopBrowserProductionNetworkAccountingAuthorityEvent =
    'desktop-browser-production-network-accounting-authority';

const protocolCarrierLedgerSchemaIdentifier =
    'sealed-lattice/desktop-browser-protocol-carrier-ledger/v1';
const checkpointLedgerSchemaIdentifier =
    'sealed-lattice/desktop-browser-checkpoint-ledger/v1';
const measuredWorkLedgerSchemaIdentifier =
    'sealed-lattice/desktop-browser-measured-work-ledger/v1';
const productionNetworkAccountingAuthoritySchemaIdentifier =
    'sealed-lattice/desktop-browser-production-network-accounting-authority/v1';
const sha256HexPattern = /^[0-9a-f]{64}$/u;
const sha512HexPattern = /^[0-9a-f]{128}$/u;
const identifierPattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const ordersOfMagnitudeVarianceRatio = 100;
const durationReconciliationFraction = 0.01;
const durationReconciliationMinimumMilliseconds = 1;

export const desktopBrowserNetworkProjectionProfile = Object.freeze({
    downloadBitsPerSecond: 25_000_000,
    protocolRoundTripMilliseconds: 100,
    uploadBitsPerSecond: 10_000_000,
} as const);

export const desktopBrowserComputeSlowdownMultipliers = Object.freeze([
    2, 4, 8,
] as const);

type EvidenceIdentity = Readonly<{
    buildSha512Hex: string;
    sourceSha512Hex: string;
    suiteId: string;
    wasmSha256Hex: string;
}>;

type ProtocolCarrierPhase = Readonly<{
    downloadByteLength: number;
    downloadChunkCount: number;
    phaseIdentifier: string;
    protocolRoundTripCount: number;
    uploadByteLength: number;
    uploadChunkCount: number;
}>;

type ProtocolCarrierLedger = Readonly<{
    canonicalChunkByteLength: number;
    event: typeof desktopBrowserProtocolCarrierLedgerEvent;
    identity: EvidenceIdentity;
    phases: readonly ProtocolCarrierPhase[];
    schemaIdentifier: typeof protocolCarrierLedgerSchemaIdentifier;
}>;

type CheckpointResume = Readonly<{
    checkpointIdentifier: string;
    resumeArithmeticDurationMilliseconds: number;
    resumeDownloadByteLength: number;
    resumeDownloadChunkCount: number;
    resumeHashingDurationMilliseconds: number;
    resumeProtocolRoundTripCount: number;
    resumeQuorumWaitDurationMilliseconds: number;
    resumeResourceAccounting: DesktopBrowserProofResourceAccounting;
    resumeStorageDurationMilliseconds: number;
    resumeUploadByteLength: number;
    resumeUploadChunkCount: number;
}>;

type CheckpointPhase = Readonly<{
    checkpoints: readonly CheckpointResume[];
    phaseIdentifier: string;
}>;

type CheckpointLedger = Readonly<{
    event: typeof desktopBrowserCheckpointLedgerEvent;
    identity: EvidenceIdentity;
    phases: readonly CheckpointPhase[];
    schemaIdentifier: typeof checkpointLedgerSchemaIdentifier;
}>;

type MeasuredWorkPhase = Readonly<{
    arithmeticDurationMilliseconds: number;
    hashingDurationMilliseconds: number;
    measurementCaseIdentifier: string;
    measurementRunOrdinal: number;
    ordersOfMagnitudeVarianceExplanation: string | null;
    phaseIdentifier: string;
    planningReferenceDurationMilliseconds: number;
    quorumWaitDurationMilliseconds: number;
    storageDurationMilliseconds: number;
}>;

type MeasuredWorkLedger = Readonly<{
    event: typeof desktopBrowserMeasuredWorkLedgerEvent;
    identity: EvidenceIdentity;
    phases: readonly MeasuredWorkPhase[];
    schemaIdentifier: typeof measuredWorkLedgerSchemaIdentifier;
}>;

type ProductionProofFamilyMultiplicity = Readonly<{
    applicationStatementSchemaIdentifier: number;
    logicalEntryCount: number;
    physicalProofCount: number;
}>;

type ProductionDirectionalMaterialRow = Readonly<{
    carrierIdentifier: string;
    downloadByteLengthPerInstance: number;
    downloadChunkCountPerInstance: number;
    materialFamilyIdentifier: string;
    multiplicity: number;
    protocolRoundTripCount: number;
    uploadByteLengthPerInstance: number;
    uploadChunkCountPerInstance: number;
}>;

type ProductionCheckpointAccounting = Readonly<{
    checkpointIdentifier: string;
    resumeDirectionalMaterialRows: readonly ProductionDirectionalMaterialRow[];
}>;

type ProductionPhaseAccounting = Readonly<{
    measurementCaseIdentifier: DesktopBrowserProofEvidenceCaseIdentifier;
    orderedCheckpoints: readonly ProductionCheckpointAccounting[];
    orderedDirectionalMaterialRows: readonly ProductionDirectionalMaterialRow[];
    phaseIdentifier: string;
    proofFamilyApplications: readonly ProductionProofFamilyMultiplicity[];
}>;

type ProductionAccountingDerivationError = Readonly<{
    dimension: string;
    reasonCode: string;
    requiredCarrier: string;
}>;

type ProductionNetworkAccountingAuthority = Readonly<{
    canonicalChunkByteLength: number;
    derivationErrors: readonly ProductionAccountingDerivationError[];
    event: typeof desktopBrowserProductionNetworkAccountingAuthorityEvent;
    identity: EvidenceIdentity;
    orderedPhases: readonly ProductionPhaseAccounting[];
    orderedProofFamilies: readonly ProductionProofFamilyMultiplicity[];
    productionAccountingBuildShake256Hex: string;
    productionAccountingCandidateInputShake256Hex: string;
    productionAccountingRecordByteLength: number;
    productionAccountingRecordKind: string;
    productionAccountingRecordShake256Hex: string;
    productionAccountingRecordVersion: number;
    productionAccountingSourceShake256Hex: string;
    schemaIdentifier: typeof productionNetworkAccountingAuthoritySchemaIdentifier;
    totalLogicalEntryCount: number;
    totalPhysicalProofCount: number;
}>;

export const desktopBrowserProtocolCarrierLedgerSchemaIdentifier =
    protocolCarrierLedgerSchemaIdentifier;
export const desktopBrowserCheckpointLedgerSchemaIdentifier =
    checkpointLedgerSchemaIdentifier;
export const desktopBrowserMeasuredWorkLedgerSchemaIdentifier =
    measuredWorkLedgerSchemaIdentifier;
export const desktopBrowserProductionNetworkAccountingAuthoritySchemaIdentifier =
    productionNetworkAccountingAuthoritySchemaIdentifier;
export type DesktopBrowserNetworkEvidenceIdentity = EvidenceIdentity;
export type DesktopBrowserProtocolCarrierLedger = ProtocolCarrierLedger;
export type DesktopBrowserCheckpointLedger = CheckpointLedger;
export type DesktopBrowserMeasuredWorkLedger = MeasuredWorkLedger;
export type DesktopBrowserProductionNetworkAccountingAuthority =
    ProductionNetworkAccountingAuthority;

type LocalIndexedDbTraffic = Readonly<{
    ciphertextReadByteLength: number;
    ciphertextReadCallCount: number;
    ciphertextWriteByteLength: number;
    ciphertextWriteCallCount: number;
    cleanupDeletedByteLength: number;
    cleanupDeletionCount: number;
    cleanupDurationMilliseconds: number;
    commitReadbackByteLength: number;
    commitReadbackCallCount: number;
    deletionDurationMilliseconds: number;
    deterministicRegeneratedByteLength: number;
    deterministicRegenerationCallCount: number;
    indexedDbRequestCount: number;
    indexedDbTransactionCount: number;
    javascriptToWasmCopyByteLength: number;
    javascriptToWasmCopyCount: number;
    kernelStorageRequestCount: number;
    minimumPhysicalQuotaHeadroomByteLength: number;
    openCallCount: number;
    openCiphertextByteLength: number;
    openPlaintextByteLength: number;
    physicalStoredPeakByteLength: number;
    plaintextReadByteLength: number;
    plaintextReadCallCount: number;
    plaintextWriteByteLength: number;
    plaintextWriteCallCount: number;
    repairHashCallCount: number;
    repairHashedByteLength: number;
    sealCallCount: number;
    sealCiphertextByteLength: number;
    sealPlaintextByteLength: number;
    wasmToJavascriptCopyByteLength: number;
    wasmToJavascriptCopyCount: number;
    workerTransferByteLength: number;
    workerTransferCount: number;
}>;

type ProtocolRelayTransportProjection = Readonly<{
    downloadByteLength: number;
    downloadChunkCount: number;
    downloadDurationMilliseconds: number;
    pipelinedChunks: true;
    protocolRoundTripCount: number;
    protocolRoundTripDurationMilliseconds: number;
    totalDurationMilliseconds: number;
    uploadByteLength: number;
    uploadChunkCount: number;
    uploadDurationMilliseconds: number;
}>;

type PhaseDurationProjection = Readonly<{
    arithmeticDurationMilliseconds: number;
    hashingDurationMilliseconds: number;
    phaseIdentifier: string;
    protocolRelayTransportDurationMilliseconds: number;
    quorumWaitDurationMilliseconds: number;
    storageDurationMilliseconds: number;
    totalDurationMilliseconds: number;
}>;

export type DesktopBrowserNetworkProjection = Readonly<{
    canonicalLedgerSha512Hex: Readonly<{
        checkpoint: string;
        measuredWork: string;
        productionAccountingAuthority: string;
        protocolCarrier: string;
    }>;
    durableCheckpointCatalogSha512Hex: string;
    durableCheckpointCount: number;
    identity: EvidenceIdentity;
    interruptionAtEveryDurableCheckpoint: true;
    localIndexedDbTraffic: LocalIndexedDbTraffic;
    networkProfile: typeof desktopBrowserNetworkProjectionProfile;
    orderedPhaseIdentifiers: readonly string[];
    ordersOfMagnitudeVarianceExplanations: readonly Readonly<{
        explanation: string;
        observedToPlanningRatio: number;
        phaseIdentifier: string;
    }>[];
    productionAccounting: Readonly<{
        directionalMaterialRowCount: number;
        orderedProofFamilies: readonly ProductionProofFamilyMultiplicity[];
        productionAccountingBuildShake256Hex: string;
        productionAccountingCandidateInputShake256Hex: string;
        productionAccountingRecordByteLength: number;
        productionAccountingRecordKind: string;
        productionAccountingRecordShake256Hex: string;
        productionAccountingRecordVersion: number;
        productionAccountingSourceShake256Hex: string;
        totalLogicalEntryCount: number;
        totalPhysicalProofCount: number;
    }>;
    projections: readonly Readonly<{
        arithmeticDurationMilliseconds: number;
        computeSlowdownMultiplier: (typeof desktopBrowserComputeSlowdownMultipliers)[number];
        hashingDurationMilliseconds: number;
        phaseProjections: readonly PhaseDurationProjection[];
        protocolRelayTransport: ProtocolRelayTransportProjection;
        quorumWaitDurationMilliseconds: number;
        storageDurationMilliseconds: number;
        totalDurationMilliseconds: number;
    }>[];
}>;

type UnknownRecord = Readonly<Record<string, unknown>>;

const requireRecord = (value: unknown, fieldName: string): UnknownRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }
    return value as UnknownRecord;
};

const requireExactKeys = (
    record: UnknownRecord,
    expectedKeys: readonly string[],
    fieldName: string,
): void => {
    const actualKeys = Object.keys(record).sort();
    const canonicalExpectedKeys = [...expectedKeys].sort();
    if (
        actualKeys.length !== canonicalExpectedKeys.length ||
        actualKeys.some(
            (actualKey, keyIndex) =>
                actualKey !== canonicalExpectedKeys[keyIndex],
        )
    ) {
        throw new TypeError(`${fieldName} does not contain its exact fields.`);
    }
};

const requireArray = (
    value: unknown,
    fieldName: string,
): readonly unknown[] => {
    if (!Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an array.`);
    }
    return value;
};

const requireNonnegativeSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (!Number.isSafeInteger(value) || Number(value) < 0) {
        throw new TypeError(`${fieldName} must be a nonnegative safe integer.`);
    }
    return Number(value);
};

const requirePositiveSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    const number = requireNonnegativeSafeInteger(value, fieldName);
    if (number === 0) {
        throw new TypeError(`${fieldName} must be positive.`);
    }
    return number;
};

const requireNonemptyString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || value.trim().length === 0) {
        throw new TypeError(`${fieldName} must be a nonempty string.`);
    }
    return value;
};

const requireNonnegativeDuration = (
    value: unknown,
    fieldName: string,
): number => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a nonnegative finite duration.`,
        );
    }
    return value;
};

const requirePositiveDuration = (value: unknown, fieldName: string): number => {
    const duration = requireNonnegativeDuration(value, fieldName);
    if (duration === 0) {
        throw new TypeError(`${fieldName} must be positive.`);
    }
    return duration;
};

const requireIdentifier = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !identifierPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a kebab-case identifier.`);
    }
    return value;
};

const requireSha512Hex = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !sha512HexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a lowercase SHA-512 digest.`);
    }
    return value;
};

const requireShake256Hex = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !sha512HexPattern.test(value)) {
        throw new TypeError(
            `${fieldName} must be a lowercase 512-bit SHAKE256 digest.`,
        );
    }
    return value;
};

const requireSha256Hex = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !sha256HexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a lowercase SHA-256 digest.`);
    }
    return value;
};

const parseIdentity = (value: unknown, fieldName: string): EvidenceIdentity => {
    const record = requireRecord(value, fieldName);
    requireExactKeys(
        record,
        ['buildSha512Hex', 'sourceSha512Hex', 'suiteId', 'wasmSha256Hex'],
        fieldName,
    );
    return Object.freeze({
        buildSha512Hex: requireSha512Hex(
            record.buildSha512Hex,
            `${fieldName}.buildSha512Hex`,
        ),
        sourceSha512Hex: requireSha512Hex(
            record.sourceSha512Hex,
            `${fieldName}.sourceSha512Hex`,
        ),
        suiteId: requireSha512Hex(record.suiteId, `${fieldName}.suiteId`),
        wasmSha256Hex: requireSha256Hex(
            record.wasmSha256Hex,
            `${fieldName}.wasmSha256Hex`,
        ),
    });
};

const addSafeInteger = (
    left: number,
    right: number,
    fieldName: string,
): number => {
    const result = left + right;
    if (!Number.isSafeInteger(result)) {
        throw new RangeError(`${fieldName} exceeds the safe integer range.`);
    }
    return result;
};

const multiplySafeIntegers = (
    left: number,
    right: number,
    fieldName: string,
): number => {
    const result = left * right;
    if (!Number.isSafeInteger(result)) {
        throw new RangeError(`${fieldName} exceeds the safe integer range.`);
    }
    return result;
};

const requireApplicationStatementSchemaIdentifier = (
    value: unknown,
    fieldName: string,
): number => {
    const identifier = requirePositiveSafeInteger(value, fieldName);
    if (identifier > 0xffff) {
        throw new TypeError(`${fieldName} must fit an unsigned 16-bit value.`);
    }
    return identifier;
};

const parseProductionProofFamilyMultiplicity = (
    value: unknown,
    fieldName: string,
): ProductionProofFamilyMultiplicity => {
    const record = requireRecord(value, fieldName);
    requireExactKeys(
        record,
        [
            'applicationStatementSchemaIdentifier',
            'logicalEntryCount',
            'physicalProofCount',
        ],
        fieldName,
    );
    return Object.freeze({
        applicationStatementSchemaIdentifier:
            requireApplicationStatementSchemaIdentifier(
                record.applicationStatementSchemaIdentifier,
                `${fieldName}.applicationStatementSchemaIdentifier`,
            ),
        logicalEntryCount: requirePositiveSafeInteger(
            record.logicalEntryCount,
            `${fieldName}.logicalEntryCount`,
        ),
        physicalProofCount: requirePositiveSafeInteger(
            record.physicalProofCount,
            `${fieldName}.physicalProofCount`,
        ),
    });
};

const parseProductionDirectionalMaterialRow = (
    value: unknown,
    canonicalChunkByteLength: number,
    fieldName: string,
): ProductionDirectionalMaterialRow => {
    const record = requireRecord(value, fieldName);
    requireExactKeys(
        record,
        [
            'carrierIdentifier',
            'downloadByteLengthPerInstance',
            'downloadChunkCountPerInstance',
            'materialFamilyIdentifier',
            'multiplicity',
            'protocolRoundTripCount',
            'uploadByteLengthPerInstance',
            'uploadChunkCountPerInstance',
        ],
        fieldName,
    );
    const downloadByteLengthPerInstance = requireNonnegativeSafeInteger(
        record.downloadByteLengthPerInstance,
        `${fieldName}.downloadByteLengthPerInstance`,
    );
    const downloadChunkCountPerInstance = requireNonnegativeSafeInteger(
        record.downloadChunkCountPerInstance,
        `${fieldName}.downloadChunkCountPerInstance`,
    );
    const uploadByteLengthPerInstance = requireNonnegativeSafeInteger(
        record.uploadByteLengthPerInstance,
        `${fieldName}.uploadByteLengthPerInstance`,
    );
    const uploadChunkCountPerInstance = requireNonnegativeSafeInteger(
        record.uploadChunkCountPerInstance,
        `${fieldName}.uploadChunkCountPerInstance`,
    );
    requireCanonicalChunkCount(
        downloadByteLengthPerInstance,
        downloadChunkCountPerInstance,
        canonicalChunkByteLength,
        `${fieldName}.downloadChunkCountPerInstance`,
    );
    requireCanonicalChunkCount(
        uploadByteLengthPerInstance,
        uploadChunkCountPerInstance,
        canonicalChunkByteLength,
        `${fieldName}.uploadChunkCountPerInstance`,
    );
    const protocolRoundTripCount = requireNonnegativeSafeInteger(
        record.protocolRoundTripCount,
        `${fieldName}.protocolRoundTripCount`,
    );
    if (
        downloadByteLengthPerInstance === 0 &&
        uploadByteLengthPerInstance === 0 &&
        protocolRoundTripCount === 0
    ) {
        throw new TypeError(`${fieldName} is an empty directional row.`);
    }
    return Object.freeze({
        carrierIdentifier: requireIdentifier(
            record.carrierIdentifier,
            `${fieldName}.carrierIdentifier`,
        ),
        downloadByteLengthPerInstance,
        downloadChunkCountPerInstance,
        materialFamilyIdentifier: requireIdentifier(
            record.materialFamilyIdentifier,
            `${fieldName}.materialFamilyIdentifier`,
        ),
        multiplicity: requirePositiveSafeInteger(
            record.multiplicity,
            `${fieldName}.multiplicity`,
        ),
        protocolRoundTripCount,
        uploadByteLengthPerInstance,
        uploadChunkCountPerInstance,
    });
};

const parseProductionCheckpointAccounting = (
    value: unknown,
    canonicalChunkByteLength: number,
    phaseIndex: number,
    checkpointIndex: number,
): ProductionCheckpointAccounting => {
    const fieldName = `productionAccountingAuthority.orderedPhases[${String(phaseIndex)}].orderedCheckpoints[${String(checkpointIndex)}]`;
    const record = requireRecord(value, fieldName);
    requireExactKeys(
        record,
        ['checkpointIdentifier', 'resumeDirectionalMaterialRows'],
        fieldName,
    );
    return Object.freeze({
        checkpointIdentifier: requireIdentifier(
            record.checkpointIdentifier,
            `${fieldName}.checkpointIdentifier`,
        ),
        resumeDirectionalMaterialRows: Object.freeze(
            requireArray(
                record.resumeDirectionalMaterialRows,
                `${fieldName}.resumeDirectionalMaterialRows`,
            ).map((row, rowIndex) =>
                parseProductionDirectionalMaterialRow(
                    row,
                    canonicalChunkByteLength,
                    `${fieldName}.resumeDirectionalMaterialRows[${String(rowIndex)}]`,
                ),
            ),
        ),
    });
};

const parseProductionPhaseAccounting = (
    value: unknown,
    canonicalChunkByteLength: number,
    phaseIndex: number,
): ProductionPhaseAccounting => {
    const fieldName = `productionAccountingAuthority.orderedPhases[${String(phaseIndex)}]`;
    const record = requireRecord(value, fieldName);
    requireExactKeys(
        record,
        [
            'measurementCaseIdentifier',
            'orderedCheckpoints',
            'orderedDirectionalMaterialRows',
            'phaseIdentifier',
            'proofFamilyApplications',
        ],
        fieldName,
    );
    const proofFamilyApplications = requireArray(
        record.proofFamilyApplications,
        `${fieldName}.proofFamilyApplications`,
    ).map((family, familyIndex) =>
        parseProductionProofFamilyMultiplicity(
            family,
            `${fieldName}.proofFamilyApplications[${String(familyIndex)}]`,
        ),
    );
    if (
        new Set(
            proofFamilyApplications.map(
                ({ applicationStatementSchemaIdentifier }) =>
                    applicationStatementSchemaIdentifier,
            ),
        ).size !== proofFamilyApplications.length
    ) {
        throw new TypeError(
            `${fieldName}.proofFamilyApplications repeats a proof family.`,
        );
    }
    const measurementCaseIdentifier = requireIdentifier(
        record.measurementCaseIdentifier,
        `${fieldName}.measurementCaseIdentifier`,
    );
    if (
        !isDesktopBrowserProofEvidenceCaseIdentifier(measurementCaseIdentifier)
    ) {
        throw new TypeError(
            `${fieldName}.measurementCaseIdentifier is not a production evidence case.`,
        );
    }
    return Object.freeze({
        measurementCaseIdentifier,
        orderedCheckpoints: Object.freeze(
            requireArray(
                record.orderedCheckpoints,
                `${fieldName}.orderedCheckpoints`,
            ).map((checkpoint, checkpointIndex) =>
                parseProductionCheckpointAccounting(
                    checkpoint,
                    canonicalChunkByteLength,
                    phaseIndex,
                    checkpointIndex,
                ),
            ),
        ),
        orderedDirectionalMaterialRows: Object.freeze(
            requireArray(
                record.orderedDirectionalMaterialRows,
                `${fieldName}.orderedDirectionalMaterialRows`,
            ).map((row, rowIndex) =>
                parseProductionDirectionalMaterialRow(
                    row,
                    canonicalChunkByteLength,
                    `${fieldName}.orderedDirectionalMaterialRows[${String(rowIndex)}]`,
                ),
            ),
        ),
        phaseIdentifier: requireIdentifier(
            record.phaseIdentifier,
            `${fieldName}.phaseIdentifier`,
        ),
        proofFamilyApplications: Object.freeze(proofFamilyApplications),
    });
};

const requireProductionAccountingAuthorityTopology = (
    authority: ProductionNetworkAccountingAuthority,
): void => {
    requireUniquePhaseIdentifiers(
        authority.orderedPhases,
        'production accounting authority',
    );
    const proofFamilyIdentifiers = authority.orderedProofFamilies.map(
        ({ applicationStatementSchemaIdentifier }) =>
            applicationStatementSchemaIdentifier,
    );
    if (
        proofFamilyIdentifiers.length === 0 ||
        new Set(proofFamilyIdentifiers).size !== proofFamilyIdentifiers.length
    ) {
        throw new TypeError(
            'The production accounting authority must contain a nonempty unique proof-family catalog.',
        );
    }

    let totalPhysicalProofCount = 0;
    let totalLogicalEntryCount = 0;
    const applicationTotals = new Map<
        number,
        { logicalEntryCount: number; physicalProofCount: number }
    >();
    const checkpointIdentifiers = new Set<string>();
    const carrierIdentifiers = new Set<string>();
    let checkpointCount = 0;
    let directionalMaterialRowCount = 0;
    for (const phase of authority.orderedPhases) {
        for (const family of phase.proofFamilyApplications) {
            const totals = applicationTotals.get(
                family.applicationStatementSchemaIdentifier,
            ) ?? { logicalEntryCount: 0, physicalProofCount: 0 };
            totals.logicalEntryCount = addSafeInteger(
                totals.logicalEntryCount,
                family.logicalEntryCount,
                'production proof-family logical entry count',
            );
            totals.physicalProofCount = addSafeInteger(
                totals.physicalProofCount,
                family.physicalProofCount,
                'production proof-family physical proof count',
            );
            applicationTotals.set(
                family.applicationStatementSchemaIdentifier,
                totals,
            );
        }
        for (const checkpoint of phase.orderedCheckpoints) {
            checkpointCount += 1;
            if (checkpointIdentifiers.has(checkpoint.checkpointIdentifier)) {
                throw new TypeError(
                    'The production accounting authority repeats a durable checkpoint identifier.',
                );
            }
            checkpointIdentifiers.add(checkpoint.checkpointIdentifier);
            for (const row of checkpoint.resumeDirectionalMaterialRows) {
                directionalMaterialRowCount += 1;
                if (carrierIdentifiers.has(row.carrierIdentifier)) {
                    throw new TypeError(
                        'The production accounting authority repeats a directional carrier identifier.',
                    );
                }
                carrierIdentifiers.add(row.carrierIdentifier);
            }
        }
        for (const row of phase.orderedDirectionalMaterialRows) {
            directionalMaterialRowCount += 1;
            if (carrierIdentifiers.has(row.carrierIdentifier)) {
                throw new TypeError(
                    'The production accounting authority repeats a directional carrier identifier.',
                );
            }
            carrierIdentifiers.add(row.carrierIdentifier);
        }
    }
    if (checkpointCount === 0 || directionalMaterialRowCount === 0) {
        throw new TypeError(
            'The production accounting authority must contain durable checkpoints and directional material rows.',
        );
    }
    for (const family of authority.orderedProofFamilies) {
        totalPhysicalProofCount = addSafeInteger(
            totalPhysicalProofCount,
            family.physicalProofCount,
            'production total physical proof count',
        );
        totalLogicalEntryCount = addSafeInteger(
            totalLogicalEntryCount,
            family.logicalEntryCount,
            'production total logical entry count',
        );
        const observed = applicationTotals.get(
            family.applicationStatementSchemaIdentifier,
        );
        if (
            observed?.physicalProofCount !== family.physicalProofCount ||
            observed.logicalEntryCount !== family.logicalEntryCount
        ) {
            throw new TypeError(
                `The production accounting authority does not reconcile proof-family multiplicity 0x${family.applicationStatementSchemaIdentifier.toString(16).padStart(4, '0')}.`,
            );
        }
        applicationTotals.delete(family.applicationStatementSchemaIdentifier);
    }
    if (
        applicationTotals.size !== 0 ||
        totalPhysicalProofCount !== authority.totalPhysicalProofCount ||
        totalLogicalEntryCount !== authority.totalLogicalEntryCount
    ) {
        throw new TypeError(
            'The production accounting authority does not reconcile its complete-action proof multiplicities.',
        );
    }
};

export const parseDesktopBrowserProductionNetworkAccountingAuthority = (
    value: unknown,
): DesktopBrowserProductionNetworkAccountingAuthority => {
    const fieldName = 'productionAccountingAuthority';
    const record = requireRecord(value, fieldName);
    requireExactKeys(
        record,
        [
            'canonicalChunkByteLength',
            'derivationErrors',
            'event',
            'identity',
            'orderedPhases',
            'orderedProofFamilies',
            'productionAccountingBuildShake256Hex',
            'productionAccountingCandidateInputShake256Hex',
            'productionAccountingRecordByteLength',
            'productionAccountingRecordKind',
            'productionAccountingRecordShake256Hex',
            'productionAccountingRecordVersion',
            'productionAccountingSourceShake256Hex',
            'schemaIdentifier',
            'totalLogicalEntryCount',
            'totalPhysicalProofCount',
        ],
        fieldName,
    );
    if (
        record.event !==
            desktopBrowserProductionNetworkAccountingAuthorityEvent ||
        record.schemaIdentifier !==
            productionNetworkAccountingAuthoritySchemaIdentifier
    ) {
        throw new TypeError(
            'The production accounting authority has the wrong event or schema.',
        );
    }
    const derivationErrors = requireArray(
        record.derivationErrors,
        `${fieldName}.derivationErrors`,
    ).map((error, errorIndex) => {
        const errorFieldName = `${fieldName}.derivationErrors[${String(errorIndex)}]`;
        const errorRecord = requireRecord(error, errorFieldName);
        requireExactKeys(
            errorRecord,
            ['dimension', 'reasonCode', 'requiredCarrier'],
            errorFieldName,
        );
        return Object.freeze({
            dimension: requireIdentifier(
                errorRecord.dimension,
                `${errorFieldName}.dimension`,
            ),
            reasonCode: requireIdentifier(
                errorRecord.reasonCode,
                `${errorFieldName}.reasonCode`,
            ),
            requiredCarrier: requireNonemptyString(
                errorRecord.requiredCarrier,
                `${errorFieldName}.requiredCarrier`,
            ),
        });
    });
    if (derivationErrors.length !== 0) {
        throw new Error(
            `Desktop-browser network projection refuses incomplete production accounting: ${derivationErrors.map(({ dimension }) => dimension).join(', ')}.`,
        );
    }
    const canonicalChunkByteLength = requirePositiveSafeInteger(
        record.canonicalChunkByteLength,
        `${fieldName}.canonicalChunkByteLength`,
    );
    const orderedProofFamilies = requireArray(
        record.orderedProofFamilies,
        `${fieldName}.orderedProofFamilies`,
    ).map((family, familyIndex) =>
        parseProductionProofFamilyMultiplicity(
            family,
            `${fieldName}.orderedProofFamilies[${String(familyIndex)}]`,
        ),
    );
    const authority = Object.freeze({
        canonicalChunkByteLength,
        derivationErrors: Object.freeze(derivationErrors),
        event: desktopBrowserProductionNetworkAccountingAuthorityEvent,
        identity: parseIdentity(record.identity, `${fieldName}.identity`),
        orderedPhases: Object.freeze(
            requireArray(
                record.orderedPhases,
                `${fieldName}.orderedPhases`,
            ).map((phase, phaseIndex) =>
                parseProductionPhaseAccounting(
                    phase,
                    canonicalChunkByteLength,
                    phaseIndex,
                ),
            ),
        ),
        orderedProofFamilies: Object.freeze(orderedProofFamilies),
        productionAccountingBuildShake256Hex: requireShake256Hex(
            record.productionAccountingBuildShake256Hex,
            `${fieldName}.productionAccountingBuildShake256Hex`,
        ),
        productionAccountingCandidateInputShake256Hex: requireShake256Hex(
            record.productionAccountingCandidateInputShake256Hex,
            `${fieldName}.productionAccountingCandidateInputShake256Hex`,
        ),
        productionAccountingRecordByteLength: requirePositiveSafeInteger(
            record.productionAccountingRecordByteLength,
            `${fieldName}.productionAccountingRecordByteLength`,
        ),
        productionAccountingRecordKind: requireIdentifier(
            record.productionAccountingRecordKind,
            `${fieldName}.productionAccountingRecordKind`,
        ),
        productionAccountingRecordShake256Hex: requireShake256Hex(
            record.productionAccountingRecordShake256Hex,
            `${fieldName}.productionAccountingRecordShake256Hex`,
        ),
        productionAccountingRecordVersion: requirePositiveSafeInteger(
            record.productionAccountingRecordVersion,
            `${fieldName}.productionAccountingRecordVersion`,
        ),
        productionAccountingSourceShake256Hex: requireShake256Hex(
            record.productionAccountingSourceShake256Hex,
            `${fieldName}.productionAccountingSourceShake256Hex`,
        ),
        schemaIdentifier: productionNetworkAccountingAuthoritySchemaIdentifier,
        totalLogicalEntryCount: requirePositiveSafeInteger(
            record.totalLogicalEntryCount,
            `${fieldName}.totalLogicalEntryCount`,
        ),
        totalPhysicalProofCount: requirePositiveSafeInteger(
            record.totalPhysicalProofCount,
            `${fieldName}.totalPhysicalProofCount`,
        ),
    } satisfies ProductionNetworkAccountingAuthority);
    requireProductionAccountingAuthorityTopology(authority);
    return authority;
};

const requireCanonicalChunkCount = (
    byteLength: number,
    chunkCount: number,
    canonicalChunkByteLength: number,
    fieldName: string,
): void => {
    const expectedChunkCount =
        byteLength === 0 ? 0 : Math.ceil(byteLength / canonicalChunkByteLength);
    if (chunkCount !== expectedChunkCount) {
        throw new TypeError(
            `${fieldName} does not match the canonical pipelined chunk count.`,
        );
    }
};

const parseProtocolCarrierPhase = (
    value: unknown,
    phaseIndex: number,
): ProtocolCarrierPhase => {
    const fieldName = `protocolCarrierLedger.phases[${String(phaseIndex)}]`;
    const record = requireRecord(value, fieldName);
    requireExactKeys(
        record,
        [
            'downloadByteLength',
            'downloadChunkCount',
            'phaseIdentifier',
            'protocolRoundTripCount',
            'uploadByteLength',
            'uploadChunkCount',
        ],
        fieldName,
    );
    const downloadByteLength = requireNonnegativeSafeInteger(
        record.downloadByteLength,
        `${fieldName}.downloadByteLength`,
    );
    const downloadChunkCount = requireNonnegativeSafeInteger(
        record.downloadChunkCount,
        `${fieldName}.downloadChunkCount`,
    );
    const uploadByteLength = requireNonnegativeSafeInteger(
        record.uploadByteLength,
        `${fieldName}.uploadByteLength`,
    );
    const uploadChunkCount = requireNonnegativeSafeInteger(
        record.uploadChunkCount,
        `${fieldName}.uploadChunkCount`,
    );
    return Object.freeze({
        downloadByteLength,
        downloadChunkCount,
        phaseIdentifier: requireIdentifier(
            record.phaseIdentifier,
            `${fieldName}.phaseIdentifier`,
        ),
        protocolRoundTripCount: requireNonnegativeSafeInteger(
            record.protocolRoundTripCount,
            `${fieldName}.protocolRoundTripCount`,
        ),
        uploadByteLength,
        uploadChunkCount,
    });
};

const parseProtocolCarrierLedger = (value: unknown): ProtocolCarrierLedger => {
    const record = requireRecord(value, 'protocolCarrierLedger');
    requireExactKeys(
        record,
        [
            'canonicalChunkByteLength',
            'event',
            'identity',
            'phases',
            'schemaIdentifier',
        ],
        'protocolCarrierLedger',
    );
    if (
        record.event !== desktopBrowserProtocolCarrierLedgerEvent ||
        record.schemaIdentifier !== protocolCarrierLedgerSchemaIdentifier
    ) {
        throw new TypeError(
            'The protocol carrier ledger has the wrong event or schema.',
        );
    }
    const canonicalChunkByteLength = requirePositiveSafeInteger(
        record.canonicalChunkByteLength,
        'protocolCarrierLedger.canonicalChunkByteLength',
    );
    const phases = requireArray(
        record.phases,
        'protocolCarrierLedger.phases',
    ).map((phase, phaseIndex) => parseProtocolCarrierPhase(phase, phaseIndex));
    requireUniquePhaseIdentifiers(phases, 'protocol carrier ledger');
    return Object.freeze({
        canonicalChunkByteLength,
        event: desktopBrowserProtocolCarrierLedgerEvent,
        identity: parseIdentity(
            record.identity,
            'protocolCarrierLedger.identity',
        ),
        phases: Object.freeze(phases),
        schemaIdentifier: protocolCarrierLedgerSchemaIdentifier,
    });
};

const parseCheckpointResume = (
    value: unknown,
    phaseIndex: number,
    checkpointIndex: number,
): CheckpointResume => {
    const fieldName = `checkpointLedger.phases[${String(phaseIndex)}].checkpoints[${String(checkpointIndex)}]`;
    const record = requireRecord(value, fieldName);
    requireExactKeys(
        record,
        [
            'checkpointIdentifier',
            'resumeArithmeticDurationMilliseconds',
            'resumeDownloadByteLength',
            'resumeDownloadChunkCount',
            'resumeHashingDurationMilliseconds',
            'resumeProtocolRoundTripCount',
            'resumeQuorumWaitDurationMilliseconds',
            'resumeResourceAccounting',
            'resumeStorageDurationMilliseconds',
            'resumeUploadByteLength',
            'resumeUploadChunkCount',
        ],
        fieldName,
    );
    return Object.freeze({
        checkpointIdentifier: requireIdentifier(
            record.checkpointIdentifier,
            `${fieldName}.checkpointIdentifier`,
        ),
        resumeArithmeticDurationMilliseconds: requireNonnegativeDuration(
            record.resumeArithmeticDurationMilliseconds,
            `${fieldName}.resumeArithmeticDurationMilliseconds`,
        ),
        resumeDownloadByteLength: requireNonnegativeSafeInteger(
            record.resumeDownloadByteLength,
            `${fieldName}.resumeDownloadByteLength`,
        ),
        resumeDownloadChunkCount: requireNonnegativeSafeInteger(
            record.resumeDownloadChunkCount,
            `${fieldName}.resumeDownloadChunkCount`,
        ),
        resumeHashingDurationMilliseconds: requireNonnegativeDuration(
            record.resumeHashingDurationMilliseconds,
            `${fieldName}.resumeHashingDurationMilliseconds`,
        ),
        resumeProtocolRoundTripCount: requireNonnegativeSafeInteger(
            record.resumeProtocolRoundTripCount,
            `${fieldName}.resumeProtocolRoundTripCount`,
        ),
        resumeQuorumWaitDurationMilliseconds: requireNonnegativeDuration(
            record.resumeQuorumWaitDurationMilliseconds,
            `${fieldName}.resumeQuorumWaitDurationMilliseconds`,
        ),
        resumeResourceAccounting: parseDesktopBrowserProofResourceAccounting(
            record.resumeResourceAccounting,
        ),
        resumeStorageDurationMilliseconds: requireNonnegativeDuration(
            record.resumeStorageDurationMilliseconds,
            `${fieldName}.resumeStorageDurationMilliseconds`,
        ),
        resumeUploadByteLength: requireNonnegativeSafeInteger(
            record.resumeUploadByteLength,
            `${fieldName}.resumeUploadByteLength`,
        ),
        resumeUploadChunkCount: requireNonnegativeSafeInteger(
            record.resumeUploadChunkCount,
            `${fieldName}.resumeUploadChunkCount`,
        ),
    });
};

const parseCheckpointLedger = (value: unknown): CheckpointLedger => {
    const record = requireRecord(value, 'checkpointLedger');
    requireExactKeys(
        record,
        ['event', 'identity', 'phases', 'schemaIdentifier'],
        'checkpointLedger',
    );
    if (
        record.event !== desktopBrowserCheckpointLedgerEvent ||
        record.schemaIdentifier !== checkpointLedgerSchemaIdentifier
    ) {
        throw new TypeError(
            'The checkpoint ledger has the wrong event or schema.',
        );
    }
    const phases = requireArray(record.phases, 'checkpointLedger.phases').map(
        (phase, phaseIndex) => {
            const fieldName = `checkpointLedger.phases[${String(phaseIndex)}]`;
            const phaseRecord = requireRecord(phase, fieldName);
            requireExactKeys(
                phaseRecord,
                ['checkpoints', 'phaseIdentifier'],
                fieldName,
            );
            return Object.freeze({
                checkpoints: Object.freeze(
                    requireArray(
                        phaseRecord.checkpoints,
                        `${fieldName}.checkpoints`,
                    ).map((checkpoint, checkpointIndex) =>
                        parseCheckpointResume(
                            checkpoint,
                            phaseIndex,
                            checkpointIndex,
                        ),
                    ),
                ),
                phaseIdentifier: requireIdentifier(
                    phaseRecord.phaseIdentifier,
                    `${fieldName}.phaseIdentifier`,
                ),
            });
        },
    );
    requireUniquePhaseIdentifiers(phases, 'checkpoint ledger');
    const checkpointIdentifiers = phases.flatMap(({ checkpoints }) =>
        checkpoints.map(({ checkpointIdentifier }) => checkpointIdentifier),
    );
    if (new Set(checkpointIdentifiers).size !== checkpointIdentifiers.length) {
        throw new TypeError(
            'The checkpoint ledger repeats a durable checkpoint identifier.',
        );
    }
    return Object.freeze({
        event: desktopBrowserCheckpointLedgerEvent,
        identity: parseIdentity(record.identity, 'checkpointLedger.identity'),
        phases: Object.freeze(phases),
        schemaIdentifier: checkpointLedgerSchemaIdentifier,
    });
};

const parseMeasuredWorkLedger = (value: unknown): MeasuredWorkLedger => {
    const record = requireRecord(value, 'measuredWorkLedger');
    requireExactKeys(
        record,
        ['event', 'identity', 'phases', 'schemaIdentifier'],
        'measuredWorkLedger',
    );
    if (
        record.event !== desktopBrowserMeasuredWorkLedgerEvent ||
        record.schemaIdentifier !== measuredWorkLedgerSchemaIdentifier
    ) {
        throw new TypeError(
            'The measured work ledger has the wrong event or schema.',
        );
    }
    const phases = requireArray(record.phases, 'measuredWorkLedger.phases').map(
        (phase, phaseIndex) => {
            const fieldName = `measuredWorkLedger.phases[${String(phaseIndex)}]`;
            const phaseRecord = requireRecord(phase, fieldName);
            requireExactKeys(
                phaseRecord,
                [
                    'arithmeticDurationMilliseconds',
                    'hashingDurationMilliseconds',
                    'measurementCaseIdentifier',
                    'measurementRunOrdinal',
                    'ordersOfMagnitudeVarianceExplanation',
                    'phaseIdentifier',
                    'planningReferenceDurationMilliseconds',
                    'quorumWaitDurationMilliseconds',
                    'storageDurationMilliseconds',
                ],
                fieldName,
            );
            const explanation =
                phaseRecord.ordersOfMagnitudeVarianceExplanation;
            if (
                explanation !== null &&
                (typeof explanation !== 'string' ||
                    explanation.trim().length === 0)
            ) {
                throw new TypeError(
                    `${fieldName}.ordersOfMagnitudeVarianceExplanation must be null or nonempty prose.`,
                );
            }
            return Object.freeze({
                arithmeticDurationMilliseconds: requireNonnegativeDuration(
                    phaseRecord.arithmeticDurationMilliseconds,
                    `${fieldName}.arithmeticDurationMilliseconds`,
                ),
                hashingDurationMilliseconds: requireNonnegativeDuration(
                    phaseRecord.hashingDurationMilliseconds,
                    `${fieldName}.hashingDurationMilliseconds`,
                ),
                measurementCaseIdentifier: requireIdentifier(
                    phaseRecord.measurementCaseIdentifier,
                    `${fieldName}.measurementCaseIdentifier`,
                ),
                measurementRunOrdinal: requirePositiveSafeInteger(
                    phaseRecord.measurementRunOrdinal,
                    `${fieldName}.measurementRunOrdinal`,
                ),
                ordersOfMagnitudeVarianceExplanation: explanation,
                phaseIdentifier: requireIdentifier(
                    phaseRecord.phaseIdentifier,
                    `${fieldName}.phaseIdentifier`,
                ),
                planningReferenceDurationMilliseconds: requirePositiveDuration(
                    phaseRecord.planningReferenceDurationMilliseconds,
                    `${fieldName}.planningReferenceDurationMilliseconds`,
                ),
                quorumWaitDurationMilliseconds: requireNonnegativeDuration(
                    phaseRecord.quorumWaitDurationMilliseconds,
                    `${fieldName}.quorumWaitDurationMilliseconds`,
                ),
                storageDurationMilliseconds: requireNonnegativeDuration(
                    phaseRecord.storageDurationMilliseconds,
                    `${fieldName}.storageDurationMilliseconds`,
                ),
            });
        },
    );
    requireUniquePhaseIdentifiers(phases, 'measured work ledger');
    return Object.freeze({
        event: desktopBrowserMeasuredWorkLedgerEvent,
        identity: parseIdentity(record.identity, 'measuredWorkLedger.identity'),
        phases: Object.freeze(phases),
        schemaIdentifier: measuredWorkLedgerSchemaIdentifier,
    });
};

const requireUniquePhaseIdentifiers = (
    phases: readonly Readonly<{ phaseIdentifier: string }>[],
    ledgerName: string,
): void => {
    if (
        phases.length === 0 ||
        new Set(phases.map(({ phaseIdentifier }) => phaseIdentifier)).size !==
            phases.length
    ) {
        throw new TypeError(
            `The ${ledgerName} must contain a nonempty unique phase catalog.`,
        );
    }
};

const requireOneLedgerEvent = (
    evidenceEvents: readonly unknown[],
    eventName: string,
): unknown => {
    const matchingEvents = evidenceEvents.filter(
        (event) =>
            typeof event === 'object' &&
            event !== null &&
            !Array.isArray(event) &&
            (event as UnknownRecord).event === eventName,
    );
    if (matchingEvents.length !== 1) {
        throw new Error(
            `Desktop-browser network projection requires exactly one ${eventName} record.`,
        );
    }
    return matchingEvents[0];
};

const identitiesEqual = (
    left: EvidenceIdentity,
    right: EvidenceIdentity,
): boolean =>
    left.buildSha512Hex === right.buildSha512Hex &&
    left.sourceSha512Hex === right.sourceSha512Hex &&
    left.suiteId === right.suiteId &&
    left.wasmSha256Hex === right.wasmSha256Hex;

const requireMatchingPhaseCatalogs = (
    authority: ProductionNetworkAccountingAuthority,
    carrierLedger: ProtocolCarrierLedger,
    checkpointLedger: CheckpointLedger,
    workLedger: MeasuredWorkLedger,
): readonly string[] => {
    const authorityPhases = authority.orderedPhases.map(
        ({ phaseIdentifier }) => phaseIdentifier,
    );
    const carrierPhases = carrierLedger.phases.map(
        ({ phaseIdentifier }) => phaseIdentifier,
    );
    const checkpointPhases = checkpointLedger.phases.map(
        ({ phaseIdentifier }) => phaseIdentifier,
    );
    const workPhases = workLedger.phases.map(
        ({ phaseIdentifier }) => phaseIdentifier,
    );
    if (
        authorityPhases.length !== carrierPhases.length ||
        carrierPhases.length !== checkpointPhases.length ||
        carrierPhases.length !== workPhases.length ||
        authorityPhases.some(
            (phaseIdentifier, phaseIndex) =>
                phaseIdentifier !== carrierPhases[phaseIndex] ||
                phaseIdentifier !== checkpointPhases[phaseIndex] ||
                phaseIdentifier !== workPhases[phaseIndex] ||
                authority.orderedPhases[phaseIndex]
                    ?.measurementCaseIdentifier !==
                    workLedger.phases[phaseIndex]?.measurementCaseIdentifier,
        )
    ) {
        throw new Error(
            'Desktop-browser network ledgers differ from the production-authoritative phase catalog.',
        );
    }
    return Object.freeze(authorityPhases);
};

const canonicalLedgerSha512Hex = (ledger: unknown): string =>
    createHash('sha512').update(JSON.stringify(ledger)).digest('hex');

const measurementKey = (caseIdentifier: string, runOrdinal: number): string =>
    `${caseIdentifier}:${String(runOrdinal)}`;

const safeSum = (values: readonly number[], fieldName: string): number => {
    let total = 0;
    for (const value of values) {
        total += value;
        if (!Number.isSafeInteger(total) && Number.isInteger(value)) {
            throw new RangeError(
                `${fieldName} exceeds the safe integer range.`,
            );
        }
        if (!Number.isFinite(total)) {
            throw new RangeError(`${fieldName} is not finite.`);
        }
    }
    return total;
};

type DirectionalTransportTotals = Readonly<{
    downloadByteLength: number;
    downloadChunkCount: number;
    protocolRoundTripCount: number;
    uploadByteLength: number;
    uploadChunkCount: number;
}>;

const deriveDirectionalTransportTotals = (
    rows: readonly ProductionDirectionalMaterialRow[],
    fieldName: string,
): DirectionalTransportTotals => {
    let downloadByteLength = 0;
    let downloadChunkCount = 0;
    let protocolRoundTripCount = 0;
    let uploadByteLength = 0;
    let uploadChunkCount = 0;
    for (const row of rows) {
        downloadByteLength = addSafeInteger(
            downloadByteLength,
            multiplySafeIntegers(
                row.downloadByteLengthPerInstance,
                row.multiplicity,
                `${fieldName}.downloadByteLength`,
            ),
            `${fieldName}.downloadByteLength`,
        );
        downloadChunkCount = addSafeInteger(
            downloadChunkCount,
            multiplySafeIntegers(
                row.downloadChunkCountPerInstance,
                row.multiplicity,
                `${fieldName}.downloadChunkCount`,
            ),
            `${fieldName}.downloadChunkCount`,
        );
        protocolRoundTripCount = addSafeInteger(
            protocolRoundTripCount,
            row.protocolRoundTripCount,
            `${fieldName}.protocolRoundTripCount`,
        );
        uploadByteLength = addSafeInteger(
            uploadByteLength,
            multiplySafeIntegers(
                row.uploadByteLengthPerInstance,
                row.multiplicity,
                `${fieldName}.uploadByteLength`,
            ),
            `${fieldName}.uploadByteLength`,
        );
        uploadChunkCount = addSafeInteger(
            uploadChunkCount,
            multiplySafeIntegers(
                row.uploadChunkCountPerInstance,
                row.multiplicity,
                `${fieldName}.uploadChunkCount`,
            ),
            `${fieldName}.uploadChunkCount`,
        );
    }
    return Object.freeze({
        downloadByteLength,
        downloadChunkCount,
        protocolRoundTripCount,
        uploadByteLength,
        uploadChunkCount,
    });
};

const requireMatchingDirectionalTransport = (
    observed: DirectionalTransportTotals,
    expected: DirectionalTransportTotals,
    fieldName: string,
): void => {
    if (
        observed.downloadByteLength !== expected.downloadByteLength ||
        observed.downloadChunkCount !== expected.downloadChunkCount ||
        observed.protocolRoundTripCount !== expected.protocolRoundTripCount ||
        observed.uploadByteLength !== expected.uploadByteLength ||
        observed.uploadChunkCount !== expected.uploadChunkCount
    ) {
        throw new Error(
            `${fieldName} differs from production-derived directional material accounting.`,
        );
    }
};

const requireProductionAuthorityLedgerReconciliation = (
    authority: ProductionNetworkAccountingAuthority,
    carrierLedger: ProtocolCarrierLedger,
    checkpointLedger: CheckpointLedger,
): void => {
    if (
        carrierLedger.canonicalChunkByteLength !==
        authority.canonicalChunkByteLength
    ) {
        throw new Error(
            'The protocol carrier ledger uses a different canonical chunk length than production accounting.',
        );
    }
    for (const [
        phaseIndex,
        authorityPhase,
    ] of authority.orderedPhases.entries()) {
        const carrierPhase = carrierLedger.phases[phaseIndex];
        const checkpointPhase = checkpointLedger.phases[phaseIndex];
        if (carrierPhase === undefined || checkpointPhase === undefined) {
            throw new Error(
                'Desktop-browser network projection lost a production-authoritative phase.',
            );
        }
        requireMatchingDirectionalTransport(
            carrierPhase,
            deriveDirectionalTransportTotals(
                authorityPhase.orderedDirectionalMaterialRows,
                `${authorityPhase.phaseIdentifier}.directionalMaterialRows`,
            ),
            `Protocol phase ${authorityPhase.phaseIdentifier}`,
        );
        if (
            checkpointPhase.checkpoints.length !==
            authorityPhase.orderedCheckpoints.length
        ) {
            throw new Error(
                `Protocol phase ${authorityPhase.phaseIdentifier} differs from the production-authoritative durable checkpoint catalog.`,
            );
        }
        for (const [
            checkpointIndex,
            authorityCheckpoint,
        ] of authorityPhase.orderedCheckpoints.entries()) {
            const checkpoint = checkpointPhase.checkpoints[checkpointIndex];
            if (
                checkpoint === undefined ||
                checkpoint.checkpointIdentifier !==
                    authorityCheckpoint.checkpointIdentifier
            ) {
                throw new Error(
                    `Protocol phase ${authorityPhase.phaseIdentifier} differs from the production-authoritative durable checkpoint catalog.`,
                );
            }
            requireMatchingDirectionalTransport(
                {
                    downloadByteLength: checkpoint.resumeDownloadByteLength,
                    downloadChunkCount: checkpoint.resumeDownloadChunkCount,
                    protocolRoundTripCount:
                        checkpoint.resumeProtocolRoundTripCount,
                    uploadByteLength: checkpoint.resumeUploadByteLength,
                    uploadChunkCount: checkpoint.resumeUploadChunkCount,
                },
                deriveDirectionalTransportTotals(
                    authorityCheckpoint.resumeDirectionalMaterialRows,
                    `${authorityCheckpoint.checkpointIdentifier}.resumeDirectionalMaterialRows`,
                ),
                `Checkpoint ${authorityCheckpoint.checkpointIdentifier}`,
            );
        }
    }
};

const addResourceAccounting = (
    resources: readonly DesktopBrowserProofResourceAccounting[],
): LocalIndexedDbTraffic => {
    const sum = (fieldName: keyof DesktopBrowserProofResourceAccounting) =>
        safeSum(
            resources.map((resource) => Number(resource[fieldName])),
            String(fieldName),
        );
    return Object.freeze({
        ciphertextReadByteLength: sum('ciphertextReadByteLength'),
        ciphertextReadCallCount: sum('ciphertextReadCallCount'),
        ciphertextWriteByteLength: sum('ciphertextWriteByteLength'),
        ciphertextWriteCallCount: sum('ciphertextWriteCallCount'),
        cleanupDeletedByteLength: sum('cleanupDeletedByteLength'),
        cleanupDeletionCount: sum('cleanupDeletionCount'),
        cleanupDurationMilliseconds: sum('cleanupDurationMilliseconds'),
        commitReadbackByteLength: sum('commitReadbackByteLength'),
        commitReadbackCallCount: sum('commitReadbackCallCount'),
        deletionDurationMilliseconds: sum('deletionDurationMilliseconds'),
        deterministicRegeneratedByteLength: sum(
            'deterministicRegeneratedByteLength',
        ),
        deterministicRegenerationCallCount: sum(
            'deterministicRegenerationCallCount',
        ),
        indexedDbRequestCount: sum('indexedDbRequestCount'),
        indexedDbTransactionCount: sum('indexedDbTransactionCount'),
        javascriptToWasmCopyByteLength: sum('javascriptToWasmCopyByteLength'),
        javascriptToWasmCopyCount: sum('javascriptToWasmCopyCount'),
        kernelStorageRequestCount: sum('kernelStorageRequestCount'),
        minimumPhysicalQuotaHeadroomByteLength: Math.min(
            ...resources.map(
                ({ physicalQuotaHeadroomByteLength }) =>
                    physicalQuotaHeadroomByteLength,
            ),
        ),
        openCallCount: sum('openCallCount'),
        openCiphertextByteLength: sum('openCiphertextByteLength'),
        openPlaintextByteLength: sum('openPlaintextByteLength'),
        physicalStoredPeakByteLength: Math.max(
            ...resources.map(
                ({ physicalStoredPeakByteLength }) =>
                    physicalStoredPeakByteLength,
            ),
        ),
        plaintextReadByteLength: sum('plaintextReadByteLength'),
        plaintextReadCallCount: sum('plaintextReadCallCount'),
        plaintextWriteByteLength: sum('plaintextWriteByteLength'),
        plaintextWriteCallCount: sum('plaintextWriteCallCount'),
        repairHashCallCount: sum('repairHashCallCount'),
        repairHashedByteLength: sum('repairHashedByteLength'),
        sealCallCount: sum('sealCallCount'),
        sealCiphertextByteLength: sum('sealCiphertextByteLength'),
        sealPlaintextByteLength: sum('sealPlaintextByteLength'),
        wasmToJavascriptCopyByteLength: sum('wasmToJavascriptCopyByteLength'),
        wasmToJavascriptCopyCount: sum('wasmToJavascriptCopyCount'),
        workerTransferByteLength: sum('workerTransferByteLength'),
        workerTransferCount: sum('workerTransferCount'),
    });
};

const transportProjection = (input: {
    downloadByteLength: number;
    downloadChunkCount: number;
    protocolRoundTripCount: number;
    uploadByteLength: number;
    uploadChunkCount: number;
}): ProtocolRelayTransportProjection => {
    const downloadDurationMilliseconds =
        (input.downloadByteLength * 8 * 1_000) /
        desktopBrowserNetworkProjectionProfile.downloadBitsPerSecond;
    const uploadDurationMilliseconds =
        (input.uploadByteLength * 8 * 1_000) /
        desktopBrowserNetworkProjectionProfile.uploadBitsPerSecond;
    const protocolRoundTripDurationMilliseconds =
        input.protocolRoundTripCount *
        desktopBrowserNetworkProjectionProfile.protocolRoundTripMilliseconds;
    return Object.freeze({
        downloadByteLength: input.downloadByteLength,
        downloadChunkCount: input.downloadChunkCount,
        downloadDurationMilliseconds,
        pipelinedChunks: true,
        protocolRoundTripCount: input.protocolRoundTripCount,
        protocolRoundTripDurationMilliseconds,
        totalDurationMilliseconds:
            downloadDurationMilliseconds +
            uploadDurationMilliseconds +
            protocolRoundTripDurationMilliseconds,
        uploadByteLength: input.uploadByteLength,
        uploadChunkCount: input.uploadChunkCount,
        uploadDurationMilliseconds,
    });
};

export const projectDesktopBrowserNetworkEvidence = (input: {
    evidenceEvents: readonly unknown[];
    measurements: readonly DesktopBrowserProofMeasurementRecord[];
    productionAccountingAuthority: DesktopBrowserProductionNetworkAccountingAuthority;
}): DesktopBrowserNetworkProjection => {
    const productionAccountingAuthority =
        parseDesktopBrowserProductionNetworkAccountingAuthority(
            input.productionAccountingAuthority,
        );
    const carrierLedger = parseProtocolCarrierLedger(
        requireOneLedgerEvent(
            input.evidenceEvents,
            desktopBrowserProtocolCarrierLedgerEvent,
        ),
    );
    const checkpointLedger = parseCheckpointLedger(
        requireOneLedgerEvent(
            input.evidenceEvents,
            desktopBrowserCheckpointLedgerEvent,
        ),
    );
    const workLedger = parseMeasuredWorkLedger(
        requireOneLedgerEvent(
            input.evidenceEvents,
            desktopBrowserMeasuredWorkLedgerEvent,
        ),
    );
    if (
        !identitiesEqual(carrierLedger.identity, checkpointLedger.identity) ||
        !identitiesEqual(carrierLedger.identity, workLedger.identity) ||
        !identitiesEqual(
            carrierLedger.identity,
            productionAccountingAuthority.identity,
        )
    ) {
        throw new Error(
            'Desktop-browser network ledgers are bound to different source, build, suite, or WebAssembly identities.',
        );
    }
    const orderedPhaseIdentifiers = requireMatchingPhaseCatalogs(
        productionAccountingAuthority,
        carrierLedger,
        checkpointLedger,
        workLedger,
    );
    requireProductionAuthorityLedgerReconciliation(
        productionAccountingAuthority,
        carrierLedger,
        checkpointLedger,
    );

    const measurementsByKey = new Map<
        string,
        DesktopBrowserProofMeasurementRecord
    >();
    for (const measurement of input.measurements) {
        const key = measurementKey(
            measurement.caseIdentifier,
            measurement.runOrdinal,
        );
        if (measurementsByKey.has(key)) {
            throw new Error(
                `Desktop-browser network projection received duplicate measurement ${key}.`,
            );
        }
        measurementsByKey.set(key, measurement);
    }

    const usedMeasurementKeys = new Set<string>();
    const varianceExplanations: Array<{
        explanation: string;
        observedToPlanningRatio: number;
        phaseIdentifier: string;
    }> = [];
    const phaseInputs = workLedger.phases.map((workPhase, phaseIndex) => {
        const key = measurementKey(
            workPhase.measurementCaseIdentifier,
            workPhase.measurementRunOrdinal,
        );
        const measurement = measurementsByKey.get(key);
        if (measurement === undefined || usedMeasurementKeys.has(key)) {
            throw new Error(
                `Desktop-browser measured work phase ${workPhase.phaseIdentifier} has a missing or duplicate measurement binding.`,
            );
        }
        usedMeasurementKeys.add(key);
        if (
            measurement.suiteId !== carrierLedger.identity.suiteId ||
            measurement.wasmSha256Hex !== carrierLedger.identity.wasmSha256Hex
        ) {
            throw new Error(
                `Desktop-browser measurement ${key} has the wrong suite or WebAssembly binding.`,
            );
        }
        const classifiedMeasuredDurationMilliseconds =
            workPhase.arithmeticDurationMilliseconds +
            workPhase.hashingDurationMilliseconds +
            workPhase.storageDurationMilliseconds;
        const durationDifferenceMilliseconds = Math.abs(
            classifiedMeasuredDurationMilliseconds -
                measurement.durationMilliseconds,
        );
        const permittedDurationDifferenceMilliseconds = Math.max(
            durationReconciliationMinimumMilliseconds,
            measurement.durationMilliseconds * durationReconciliationFraction,
        );
        if (
            durationDifferenceMilliseconds >
            permittedDurationDifferenceMilliseconds
        ) {
            throw new Error(
                `Desktop-browser measured work phase ${workPhase.phaseIdentifier} does not reconcile arithmetic, hashing, and storage with its browser measurement.`,
            );
        }
        const observedToPlanningRatio =
            measurement.durationMilliseconds /
            workPhase.planningReferenceDurationMilliseconds;
        if (
            observedToPlanningRatio >= ordersOfMagnitudeVarianceRatio &&
            workPhase.ordersOfMagnitudeVarianceExplanation === null
        ) {
            throw new Error(
                `Desktop-browser measured work phase ${workPhase.phaseIdentifier} has an unexplained orders-of-magnitude variance.`,
            );
        }
        if (workPhase.ordersOfMagnitudeVarianceExplanation !== null) {
            varianceExplanations.push({
                explanation: workPhase.ordersOfMagnitudeVarianceExplanation,
                observedToPlanningRatio,
                phaseIdentifier: workPhase.phaseIdentifier,
            });
        }
        const carrierPhase = carrierLedger.phases[phaseIndex];
        const checkpointPhase = checkpointLedger.phases[phaseIndex];
        if (carrierPhase === undefined || checkpointPhase === undefined) {
            throw new Error(
                'Desktop-browser network projection lost a checked phase.',
            );
        }
        const checkpointResources = checkpointPhase.checkpoints.map(
            ({ resumeResourceAccounting }) => resumeResourceAccounting,
        );
        return Object.freeze({
            arithmeticDurationMilliseconds:
                workPhase.arithmeticDurationMilliseconds +
                safeSum(
                    checkpointPhase.checkpoints.map(
                        ({ resumeArithmeticDurationMilliseconds }) =>
                            resumeArithmeticDurationMilliseconds,
                    ),
                    `${workPhase.phaseIdentifier}.arithmeticDurationMilliseconds`,
                ),
            carrierPhase,
            checkpointPhase,
            hashingDurationMilliseconds:
                workPhase.hashingDurationMilliseconds +
                safeSum(
                    checkpointPhase.checkpoints.map(
                        ({ resumeHashingDurationMilliseconds }) =>
                            resumeHashingDurationMilliseconds,
                    ),
                    `${workPhase.phaseIdentifier}.hashingDurationMilliseconds`,
                ),
            localResources: [
                measurement.resourceAccounting,
                ...checkpointResources,
            ],
            phaseIdentifier: workPhase.phaseIdentifier,
            quorumWaitDurationMilliseconds:
                workPhase.quorumWaitDurationMilliseconds +
                safeSum(
                    checkpointPhase.checkpoints.map(
                        ({ resumeQuorumWaitDurationMilliseconds }) =>
                            resumeQuorumWaitDurationMilliseconds,
                    ),
                    `${workPhase.phaseIdentifier}.quorumWaitDurationMilliseconds`,
                ),
            storageDurationMilliseconds:
                workPhase.storageDurationMilliseconds +
                safeSum(
                    checkpointPhase.checkpoints.map(
                        ({ resumeStorageDurationMilliseconds }) =>
                            resumeStorageDurationMilliseconds,
                    ),
                    `${workPhase.phaseIdentifier}.storageDurationMilliseconds`,
                ),
        });
    });

    const totalTransport = transportProjection({
        downloadByteLength: safeSum(
            phaseInputs.flatMap(({ carrierPhase, checkpointPhase }) => [
                carrierPhase.downloadByteLength,
                ...checkpointPhase.checkpoints.map(
                    ({ resumeDownloadByteLength }) => resumeDownloadByteLength,
                ),
            ]),
            'downloadByteLength',
        ),
        downloadChunkCount: safeSum(
            phaseInputs.flatMap(({ carrierPhase, checkpointPhase }) => [
                carrierPhase.downloadChunkCount,
                ...checkpointPhase.checkpoints.map(
                    ({ resumeDownloadChunkCount }) => resumeDownloadChunkCount,
                ),
            ]),
            'downloadChunkCount',
        ),
        protocolRoundTripCount: safeSum(
            phaseInputs.flatMap(({ carrierPhase, checkpointPhase }) => [
                carrierPhase.protocolRoundTripCount,
                ...checkpointPhase.checkpoints.map(
                    ({ resumeProtocolRoundTripCount }) =>
                        resumeProtocolRoundTripCount,
                ),
            ]),
            'protocolRoundTripCount',
        ),
        uploadByteLength: safeSum(
            phaseInputs.flatMap(({ carrierPhase, checkpointPhase }) => [
                carrierPhase.uploadByteLength,
                ...checkpointPhase.checkpoints.map(
                    ({ resumeUploadByteLength }) => resumeUploadByteLength,
                ),
            ]),
            'uploadByteLength',
        ),
        uploadChunkCount: safeSum(
            phaseInputs.flatMap(({ carrierPhase, checkpointPhase }) => [
                carrierPhase.uploadChunkCount,
                ...checkpointPhase.checkpoints.map(
                    ({ resumeUploadChunkCount }) => resumeUploadChunkCount,
                ),
            ]),
            'uploadChunkCount',
        ),
    });

    const projections = desktopBrowserComputeSlowdownMultipliers.map(
        (computeSlowdownMultiplier) => {
            const phaseProjections = phaseInputs.map((phaseInput) => {
                const phaseTransport = transportProjection({
                    downloadByteLength:
                        phaseInput.carrierPhase.downloadByteLength +
                        safeSum(
                            phaseInput.checkpointPhase.checkpoints.map(
                                ({ resumeDownloadByteLength }) =>
                                    resumeDownloadByteLength,
                            ),
                            `${phaseInput.phaseIdentifier}.downloadByteLength`,
                        ),
                    downloadChunkCount:
                        phaseInput.carrierPhase.downloadChunkCount +
                        safeSum(
                            phaseInput.checkpointPhase.checkpoints.map(
                                ({ resumeDownloadChunkCount }) =>
                                    resumeDownloadChunkCount,
                            ),
                            `${phaseInput.phaseIdentifier}.downloadChunkCount`,
                        ),
                    protocolRoundTripCount:
                        phaseInput.carrierPhase.protocolRoundTripCount +
                        safeSum(
                            phaseInput.checkpointPhase.checkpoints.map(
                                ({ resumeProtocolRoundTripCount }) =>
                                    resumeProtocolRoundTripCount,
                            ),
                            `${phaseInput.phaseIdentifier}.protocolRoundTripCount`,
                        ),
                    uploadByteLength:
                        phaseInput.carrierPhase.uploadByteLength +
                        safeSum(
                            phaseInput.checkpointPhase.checkpoints.map(
                                ({ resumeUploadByteLength }) =>
                                    resumeUploadByteLength,
                            ),
                            `${phaseInput.phaseIdentifier}.uploadByteLength`,
                        ),
                    uploadChunkCount:
                        phaseInput.carrierPhase.uploadChunkCount +
                        safeSum(
                            phaseInput.checkpointPhase.checkpoints.map(
                                ({ resumeUploadChunkCount }) =>
                                    resumeUploadChunkCount,
                            ),
                            `${phaseInput.phaseIdentifier}.uploadChunkCount`,
                        ),
                });
                const arithmeticDurationMilliseconds =
                    phaseInput.arithmeticDurationMilliseconds *
                    computeSlowdownMultiplier;
                const hashingDurationMilliseconds =
                    phaseInput.hashingDurationMilliseconds *
                    computeSlowdownMultiplier;
                const totalDurationMilliseconds =
                    arithmeticDurationMilliseconds +
                    hashingDurationMilliseconds +
                    phaseInput.storageDurationMilliseconds +
                    phaseInput.quorumWaitDurationMilliseconds +
                    phaseTransport.totalDurationMilliseconds;
                return Object.freeze({
                    arithmeticDurationMilliseconds,
                    hashingDurationMilliseconds,
                    phaseIdentifier: phaseInput.phaseIdentifier,
                    protocolRelayTransportDurationMilliseconds:
                        phaseTransport.totalDurationMilliseconds,
                    quorumWaitDurationMilliseconds:
                        phaseInput.quorumWaitDurationMilliseconds,
                    storageDurationMilliseconds:
                        phaseInput.storageDurationMilliseconds,
                    totalDurationMilliseconds,
                });
            });
            const arithmeticDurationMilliseconds = safeSum(
                phaseProjections.map(
                    (phase) => phase.arithmeticDurationMilliseconds,
                ),
                'arithmeticDurationMilliseconds',
            );
            const hashingDurationMilliseconds = safeSum(
                phaseProjections.map(
                    (phase) => phase.hashingDurationMilliseconds,
                ),
                'hashingDurationMilliseconds',
            );
            const quorumWaitDurationMilliseconds = safeSum(
                phaseProjections.map(
                    (phase) => phase.quorumWaitDurationMilliseconds,
                ),
                'quorumWaitDurationMilliseconds',
            );
            const storageDurationMilliseconds = safeSum(
                phaseProjections.map(
                    (phase) => phase.storageDurationMilliseconds,
                ),
                'storageDurationMilliseconds',
            );
            return Object.freeze({
                arithmeticDurationMilliseconds,
                computeSlowdownMultiplier,
                hashingDurationMilliseconds,
                phaseProjections: Object.freeze(phaseProjections),
                protocolRelayTransport: totalTransport,
                quorumWaitDurationMilliseconds,
                storageDurationMilliseconds,
                totalDurationMilliseconds:
                    arithmeticDurationMilliseconds +
                    hashingDurationMilliseconds +
                    storageDurationMilliseconds +
                    quorumWaitDurationMilliseconds +
                    totalTransport.totalDurationMilliseconds,
            });
        },
    );

    return Object.freeze({
        canonicalLedgerSha512Hex: Object.freeze({
            checkpoint: canonicalLedgerSha512Hex(checkpointLedger),
            measuredWork: canonicalLedgerSha512Hex(workLedger),
            productionAccountingAuthority: canonicalLedgerSha512Hex(
                productionAccountingAuthority,
            ),
            protocolCarrier: canonicalLedgerSha512Hex(carrierLedger),
        }),
        durableCheckpointCatalogSha512Hex: canonicalLedgerSha512Hex(
            checkpointLedger.phases.map(({ checkpoints, phaseIdentifier }) => ({
                checkpointIdentifiers: checkpoints.map(
                    ({ checkpointIdentifier }) => checkpointIdentifier,
                ),
                phaseIdentifier,
            })),
        ),
        durableCheckpointCount: checkpointLedger.phases.reduce(
            (count, phase) => count + phase.checkpoints.length,
            0,
        ),
        identity: carrierLedger.identity,
        interruptionAtEveryDurableCheckpoint: true,
        localIndexedDbTraffic: addResourceAccounting(
            phaseInputs.flatMap(({ localResources }) => localResources),
        ),
        networkProfile: desktopBrowserNetworkProjectionProfile,
        orderedPhaseIdentifiers,
        ordersOfMagnitudeVarianceExplanations: Object.freeze(
            varianceExplanations.map((explanation) =>
                Object.freeze(explanation),
            ),
        ),
        productionAccounting: Object.freeze({
            directionalMaterialRowCount:
                productionAccountingAuthority.orderedPhases.reduce(
                    (rowCount, phase) =>
                        rowCount +
                        phase.orderedDirectionalMaterialRows.length +
                        phase.orderedCheckpoints.reduce(
                            (checkpointRowCount, checkpoint) =>
                                checkpointRowCount +
                                checkpoint.resumeDirectionalMaterialRows.length,
                            0,
                        ),
                    0,
                ),
            orderedProofFamilies:
                productionAccountingAuthority.orderedProofFamilies,
            productionAccountingBuildShake256Hex:
                productionAccountingAuthority.productionAccountingBuildShake256Hex,
            productionAccountingCandidateInputShake256Hex:
                productionAccountingAuthority.productionAccountingCandidateInputShake256Hex,
            productionAccountingRecordByteLength:
                productionAccountingAuthority.productionAccountingRecordByteLength,
            productionAccountingRecordKind:
                productionAccountingAuthority.productionAccountingRecordKind,
            productionAccountingRecordShake256Hex:
                productionAccountingAuthority.productionAccountingRecordShake256Hex,
            productionAccountingRecordVersion:
                productionAccountingAuthority.productionAccountingRecordVersion,
            productionAccountingSourceShake256Hex:
                productionAccountingAuthority.productionAccountingSourceShake256Hex,
            totalLogicalEntryCount:
                productionAccountingAuthority.totalLogicalEntryCount,
            totalPhysicalProofCount:
                productionAccountingAuthority.totalPhysicalProofCount,
        }),
        projections: Object.freeze(projections),
    });
};
