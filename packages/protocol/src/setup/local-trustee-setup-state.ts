import {
    decryptLocalTrusteeState,
    deriveProtocolHash,
    encryptLocalTrusteeSetupSealedMaterial,
    encryptLocalTrusteeState,
    type EncryptedLocalTrusteeSetupState,
    type LocalTrusteeSetupStateSealedPayload,
    type LocalTrusteeStateStorageDecryptionResult,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type {
    CollectiveBgvSetupContext,
    PrivateVssEnvelopeVerificationReference,
} from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export const localTrusteeSetupStateExportPolicy =
    'roots-only-no-raw-share-or-opening-export';
export const localTrusteeSetupStateStorageProfile =
    'encrypted-local-device-state-required';
export const localTrusteeSetupStateDeletionBoundary =
    'after-private-vss-aggregation';

export const deletedLocalTrusteeSetupMaterialClasses = [
    'raw-per-dealer-vss-shares',
    'raw-per-dealer-vss-openings',
    'private-vss-envelope-payloads-after-aggregation',
] as const;

export const retainedLocalTrusteeSetupMaterialClasses = [
    'aggregate-threshold-share-sealed',
    'aggregate-threshold-opening-sealed',
    'issued-vss-acceptance-roots',
    'issued-vss-complaint-roots',
    'setup-context',
] as const;

export type LocalTrusteeSetupStateCommitmentInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
    readonly aggregateThresholdShareRoot: ProtocolHash;
    readonly aggregateOpeningRoot: ProtocolHash;
    readonly issuedVssAcceptanceRoot: ProtocolHash;
    readonly issuedVssComplaintRoots: readonly ProtocolHash[];
};

export type LocalTrusteeSetupStateEncryptionInput =
    LocalTrusteeSetupStateCommitmentInput & {
        readonly localStatePlaintext: LocalTrusteeSetupStateSealedPayload;
        readonly storageKeyBytesHex: string;
        readonly aeadNonceBytesHex?: string;
    };

export type LocalTrusteeSetupStateEncryptionResult = Readonly<{
    readonly localStateCommitment: LocalTrusteeSetupStateCommitment;
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly localStatePlaintextHash: ProtocolHash;
    readonly storageAadHash: ProtocolHash;
}>;

export type GeneratedLocalTrusteeSetupStateInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly deviceEpoch: number;
    readonly thresholdShareCommitments: unknown;
    readonly privateVssEnvelopeCommitments: unknown;
    readonly verifiedPrivateVssShareEnvelopes: readonly unknown[];
    readonly vssShareAcceptances: unknown;
    readonly vssComplaints?: unknown;
    readonly storageKeyBytesHex: string;
    readonly localStateAeadNonceBytesHex?: string;
    readonly sealedAggregateThresholdShareAeadNonceBytesHex?: string;
    readonly sealedAggregateOpeningAeadNonceBytesHex?: string;
}>;

export type GeneratedLocalTrusteeSetupStateResult =
    LocalTrusteeSetupStateEncryptionResult &
        Readonly<{
            readonly localStatePlaintext: LocalTrusteeSetupStateSealedPayload;
        }>;

export type LocalTrusteeSetupStateDecryptionInput = Readonly<{
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly expectedLocalStateRoot: ProtocolHash;
    readonly setupContext: CollectiveBgvSetupContext;
    readonly storageKeyBytesHex: string;
}>;

export type LocalTrusteeSetupStateDeletionReceipt = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateDeletionReceipt';
        readonly objectVersion: 1;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly trusteePoint: number;
        readonly deletionBoundary: typeof localTrusteeSetupStateDeletionBoundary;
        readonly deletedMaterialClasses: typeof deletedLocalTrusteeSetupMaterialClasses;
        readonly retainedMaterialClasses: typeof retainedLocalTrusteeSetupMaterialClasses;
        readonly deletionReceiptRoot: ProtocolHash;
    }
>;

export type LocalTrusteeSetupStateCommitment = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateCommitment';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly trusteePoint: number;
        readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
        readonly aggregateThresholdShareRoot: ProtocolHash;
        readonly aggregateOpeningRoot: ProtocolHash;
        readonly issuedVssAcceptanceRoot: ProtocolHash;
        readonly issuedVssComplaintRoots: readonly ProtocolHash[];
        readonly deletionReceiptRoot: ProtocolHash;
        readonly deletionReceipt: LocalTrusteeSetupStateDeletionReceipt;
        readonly exportPolicy: typeof localTrusteeSetupStateExportPolicy;
        readonly storageProfile: typeof localTrusteeSetupStateStorageProfile;
        readonly localStateRoot: ProtocolHash;
    }
>;

const protocolHashPattern = /^[0-9a-f]{128}$/u;

const contextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

const forbiddenLocalStateFieldNames = new Set([
    'rawSecret',
    'rawSecretShare',
    'rawAggregateThresholdShare',
    'rawVssOpening',
    'rawShamirShare',
    'rawShamirShares',
    'rawShare',
    'rawShares',
    'proofWitness',
    'proofWitnesses',
    'setupSeed',
    'setupPrivateWitness',
    'privateSetupSeedHash',
    'decryptionShareWitness',
    'coefficientMessage',
    'randomnessByColumn',
    'shareValues',
    'carryWitnessesDecimal',
    'privateEnvelope',
    'privateEnvelopes',
]);

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const isJsonRecord = (value: unknown): value is JsonRecord =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const jsonRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (!isJsonRecord(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value;
};

const jsonRecordArray = (
    value: unknown,
    fieldName: string,
): readonly JsonRecord[] => {
    if (!Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an array.`);
    }

    return value.map((entry, entryIndex) =>
        jsonRecord(entry, `${fieldName}.${String(entryIndex)}`),
    );
};

const objectField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): JsonRecord => jsonRecord(value[fieldName], `${objectPath}.${fieldName}`);

const stringField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): string => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'string') {
        throw new TypeError(`${objectPath}.${fieldName} must be a string.`);
    }

    return fieldValue;
};

const numberField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'number') {
        throw new TypeError(`${objectPath}.${fieldName} must be a number.`);
    }

    return fieldValue;
};

const protocolHashField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): ProtocolHash => {
    const fieldValue = stringField(value, fieldName, objectPath);
    assertProtocolHash(fieldValue, `${objectPath}.${fieldName}`);

    return fieldValue;
};

const nonNegativeIntegerField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = numberField(value, fieldName, objectPath);
    assertNonNegativeSafeInteger(fieldValue, `${objectPath}.${fieldName}`);

    return fieldValue;
};

const arrayField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): readonly unknown[] => {
    const fieldValue = value[fieldName];
    if (!Array.isArray(fieldValue)) {
        throw new TypeError(`${objectPath}.${fieldName} must be an array.`);
    }

    return fieldValue;
};

const assertSetupContextBinding = (
    setupContext: CollectiveBgvSetupContext,
    value: JsonRecord,
    objectPath: string,
): void => {
    for (const fieldName of contextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${objectPath}.${fieldName} must match setupContext.${fieldName}.`,
            );
        }
    }
};

export const collectForbiddenLocalTrusteeSetupStateFieldPaths = (
    value: unknown,
    objectPath = 'localStateCommitment',
): string[] => {
    if (Array.isArray(value)) {
        return value.flatMap((item, itemIndex) =>
            collectForbiddenLocalTrusteeSetupStateFieldPaths(
                item,
                `${objectPath}.${String(itemIndex)}`,
            ),
        );
    }
    if (typeof value !== 'object' || value === null) {
        return [];
    }

    return Object.entries(value).flatMap(([fieldName, fieldValue]) => {
        const fieldPath = `${objectPath}.${fieldName}`;
        if (forbiddenLocalStateFieldNames.has(fieldName)) {
            return [fieldPath];
        }

        return collectForbiddenLocalTrusteeSetupStateFieldPaths(
            fieldValue,
            fieldPath,
        );
    });
};

const setupContextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<CollectiveBgvSetupContext, (typeof contextFieldNames)[number]> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const validateInput = (input: LocalTrusteeSetupStateCommitmentInput): void => {
    assertNonEmptyString(
        input.setupContext.ceremonyId,
        'setupContext.ceremonyId',
    );
    assertNonEmptyString(
        input.setupContext.setupEpoch,
        'setupContext.setupEpoch',
    );
    for (const fieldName of contextFieldNames) {
        if (fieldName !== 'ceremonyId' && fieldName !== 'setupEpoch') {
            assertProtocolHash(
                input.setupContext[fieldName],
                `setupContext.${fieldName}`,
            );
        }
    }
    assertNonEmptyString(input.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(
        input.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    assertProtocolHash(
        input.thresholdShareCommitmentRecipientRoot,
        'thresholdShareCommitmentRecipientRoot',
    );
    assertProtocolHash(
        input.aggregateThresholdShareRoot,
        'aggregateThresholdShareRoot',
    );
    assertProtocolHash(input.aggregateOpeningRoot, 'aggregateOpeningRoot');
    assertProtocolHash(
        input.issuedVssAcceptanceRoot,
        'issuedVssAcceptanceRoot',
    );
    input.issuedVssComplaintRoots.forEach((complaintRoot, complaintRootIndex) =>
        assertProtocolHash(
            complaintRoot,
            `issuedVssComplaintRoots.${String(complaintRootIndex)}`,
        ),
    );
};

export const createLocalTrusteeSetupStateCommitment = (
    input: LocalTrusteeSetupStateCommitmentInput,
): LocalTrusteeSetupStateCommitment => {
    validateInput(input);

    const trusteePoint = input.trusteeRosterPosition + 1;
    const deletionReceiptWithoutRoot = {
        objectType: 'LocalTrusteeSetupStateDeletionReceipt',
        objectVersion: 1,
        ...setupContextFields(input.setupContext),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        trusteePoint,
        deletionBoundary: localTrusteeSetupStateDeletionBoundary,
        deletedMaterialClasses: deletedLocalTrusteeSetupMaterialClasses,
        retainedMaterialClasses: retainedLocalTrusteeSetupMaterialClasses,
    } as const satisfies JsonRecord;
    const deletionReceipt = {
        ...deletionReceiptWithoutRoot,
        deletionReceiptRoot: deriveProtocolHash(
            'LocalTrusteeDeletionReceiptRoot',
            deletionReceiptWithoutRoot,
        ),
    } satisfies LocalTrusteeSetupStateDeletionReceipt;
    const localStateWithoutRoot = {
        objectType: 'LocalTrusteeSetupStateCommitment',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ...setupContextFields(input.setupContext),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        trusteePoint,
        thresholdShareCommitmentRecipientRoot:
            input.thresholdShareCommitmentRecipientRoot,
        aggregateThresholdShareRoot: input.aggregateThresholdShareRoot,
        aggregateOpeningRoot: input.aggregateOpeningRoot,
        issuedVssAcceptanceRoot: input.issuedVssAcceptanceRoot,
        issuedVssComplaintRoots: input.issuedVssComplaintRoots,
        deletionReceiptRoot: deletionReceipt.deletionReceiptRoot,
        deletionReceipt,
        exportPolicy: localTrusteeSetupStateExportPolicy,
        storageProfile: localTrusteeSetupStateStorageProfile,
    } as const satisfies JsonRecord;
    const forbiddenFieldPaths =
        collectForbiddenLocalTrusteeSetupStateFieldPaths(localStateWithoutRoot);
    if (forbiddenFieldPaths.length > 0) {
        throw new Error(
            `localStateCommitment includes forbidden raw local state fields: ${forbiddenFieldPaths.join(', ')}`,
        );
    }

    return {
        ...localStateWithoutRoot,
        localStateRoot: deriveProtocolHash(
            'LocalTrusteeSetupStateRoot',
            localStateWithoutRoot,
        ),
    } satisfies LocalTrusteeSetupStateCommitment;
};

const thresholdShareCommitmentRecipientRoot = (
    input: GeneratedLocalTrusteeSetupStateInput,
): ProtocolHash => {
    const thresholdShareCommitments = jsonRecord(
        input.thresholdShareCommitments,
        'thresholdShareCommitments',
    );
    assertSetupContextBinding(
        input.setupContext,
        thresholdShareCommitments,
        'thresholdShareCommitments',
    );
    const recipientRecords = jsonRecordArray(
        thresholdShareCommitments.recipientRecords,
        'thresholdShareCommitments.recipientRecords',
    ).filter(
        (record) =>
            record.recipientRosterPosition === input.trusteeRosterPosition,
    );
    if (recipientRecords.length !== 1) {
        throw new Error(
            'thresholdShareCommitments must contain exactly one recipient record for the trustee.',
        );
    }
    const recipientRecord = recipientRecords[0];
    if (recipientRecord.recipientIdentity !== input.trusteeIdentity) {
        throw new Error(
            'thresholdShareCommitments recipient identity must match the trustee identity.',
        );
    }

    return protocolHashField(
        recipientRecord,
        'recipientCommitmentRoot',
        'thresholdShareCommitments.recipientRecords',
    );
};

const recipientEnvelopeReferences = (
    input: GeneratedLocalTrusteeSetupStateInput,
): readonly PrivateVssEnvelopeVerificationReference[] => {
    const privateVssEnvelopeCommitments = jsonRecord(
        input.privateVssEnvelopeCommitments,
        'privateVssEnvelopeCommitments',
    );
    assertSetupContextBinding(
        input.setupContext,
        privateVssEnvelopeCommitments,
        'privateVssEnvelopeCommitments',
    );
    const participantCount = nonNegativeIntegerField(
        privateVssEnvelopeCommitments,
        'participantCount',
        'privateVssEnvelopeCommitments',
    );
    if (participantCount === 0) {
        throw new Error(
            'privateVssEnvelopeCommitments.participantCount must be positive.',
        );
    }
    const envelopeReferences = jsonRecordArray(
        privateVssEnvelopeCommitments.envelopeReferences,
        'privateVssEnvelopeCommitments.envelopeReferences',
    )
        .filter(
            (reference) =>
                reference.recipientRosterPosition ===
                input.trusteeRosterPosition,
        )
        .sort(
            (left, right) =>
                Number(left.dealerRosterPosition) -
                Number(right.dealerRosterPosition),
        );
    if (envelopeReferences.length !== participantCount) {
        throw new Error(
            'privateVssEnvelopeCommitments must include one envelope reference from every dealer for the trustee.',
        );
    }
    envelopeReferences.forEach((reference, referenceIndex) => {
        const objectPath = `privateVssEnvelopeCommitments.envelopeReferences.${String(referenceIndex)}`;
        assertSetupContextBinding(input.setupContext, reference, objectPath);
        if (reference.dealerRosterPosition !== referenceIndex) {
            throw new Error(
                'private VSS envelope references for a trustee must cover contiguous dealer roster positions.',
            );
        }
        if (reference.recipientIdentity !== input.trusteeIdentity) {
            throw new Error(
                `${objectPath}.recipientIdentity must match the trustee identity.`,
            );
        }
        if (reference.recipientRosterPosition !== input.trusteeRosterPosition) {
            throw new Error(
                `${objectPath}.recipientRosterPosition must match the trustee roster position.`,
            );
        }
        protocolHashField(reference, 'privateEnvelopeHash', objectPath);
        protocolHashField(reference, 'localVerificationRoot', objectPath);
        protocolHashField(reference, 'dealerCommitmentRoot', objectPath);
    });

    return envelopeReferences as unknown as readonly PrivateVssEnvelopeVerificationReference[];
};

const issuedVssAcceptanceRoot = (
    input: GeneratedLocalTrusteeSetupStateInput,
    privateVssEnvelopeCommitmentRoot: ProtocolHash,
    expectedAcceptanceCount: number,
): ProtocolHash => {
    const vssShareAcceptances = jsonRecord(
        input.vssShareAcceptances,
        'vssShareAcceptances',
    );
    assertSetupContextBinding(
        input.setupContext,
        vssShareAcceptances,
        'vssShareAcceptances',
    );
    const acceptanceRoots = jsonRecordArray(
        vssShareAcceptances.acceptanceRecords,
        'vssShareAcceptances.acceptanceRecords',
    )
        .filter(
            (record) =>
                record.recipientRosterPosition === input.trusteeRosterPosition,
        )
        .sort(
            (left, right) =>
                Number(left.dealerRosterPosition) -
                Number(right.dealerRosterPosition),
        )
        .map((record, recordIndex) => {
            const objectPath = `vssShareAcceptances.acceptanceRecords.${String(recordIndex)}`;
            assertSetupContextBinding(input.setupContext, record, objectPath);
            if (record.recipientIdentity !== input.trusteeIdentity) {
                throw new Error(
                    `${objectPath}.recipientIdentity must match the trustee identity.`,
                );
            }
            if (
                record.privateVssEnvelopeCommitmentRoot !==
                privateVssEnvelopeCommitmentRoot
            ) {
                throw new Error(
                    `${objectPath}.privateVssEnvelopeCommitmentRoot must match the local private VSS envelope commitment set.`,
                );
            }

            return protocolHashField(record, 'acceptanceRoot', objectPath);
        });
    if (acceptanceRoots.length !== expectedAcceptanceCount) {
        throw new Error(
            'vssShareAcceptances must contain one acceptance issued by the trustee for every dealer.',
        );
    }

    return deriveProtocolHash('VssShareAcceptanceRoot', {
        objectType: 'LocalTrusteeIssuedVssAcceptanceSet',
        objectVersion: 1,
        ...setupContextFields(input.setupContext),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        privateVssEnvelopeCommitmentRoot,
        acceptanceRoots,
    });
};

const issuedVssComplaintRoots = (
    input: GeneratedLocalTrusteeSetupStateInput,
    privateVssEnvelopeCommitmentRoot: ProtocolHash,
): readonly ProtocolHash[] => {
    if (input.vssComplaints === undefined) {
        return [];
    }
    const vssComplaints = jsonRecord(input.vssComplaints, 'vssComplaints');
    assertSetupContextBinding(
        input.setupContext,
        vssComplaints,
        'vssComplaints',
    );

    return jsonRecordArray(
        vssComplaints.complaintRecords,
        'vssComplaints.complaintRecords',
    )
        .filter(
            (record) =>
                record.recipientRosterPosition === input.trusteeRosterPosition,
        )
        .sort(
            (left, right) =>
                Number(left.dealerRosterPosition) -
                Number(right.dealerRosterPosition),
        )
        .map((record, recordIndex) => {
            const objectPath = `vssComplaints.complaintRecords.${String(recordIndex)}`;
            assertSetupContextBinding(input.setupContext, record, objectPath);
            if (record.recipientIdentity !== input.trusteeIdentity) {
                throw new Error(
                    `${objectPath}.recipientIdentity must match the trustee identity.`,
                );
            }
            if (
                record.privateVssEnvelopeCommitmentRoot !==
                privateVssEnvelopeCommitmentRoot
            ) {
                throw new Error(
                    `${objectPath}.privateVssEnvelopeCommitmentRoot must match the local private VSS envelope commitment set.`,
                );
            }

            return protocolHashField(record, 'complaintRoot', objectPath);
        });
};

type AggregateLimbAccumulator = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    shareValues: bigint[];
    aggregateOpeningColumns: bigint[][];
};

const sourcePrivateEnvelopeReferences = (
    envelopeReferences: readonly PrivateVssEnvelopeVerificationReference[],
): readonly JsonRecord[] =>
    envelopeReferences.map((reference) => ({
        objectType: 'LocalTrusteePrivateVssEnvelopeReference',
        objectVersion: 1,
        dealerIdentity: reference.dealerIdentity,
        dealerRosterPosition: reference.dealerRosterPosition,
        dealerCommitmentRoot: reference.dealerCommitmentRoot,
        privateEnvelopeHash: reference.privateEnvelopeHash,
        localVerificationRoot: reference.localVerificationRoot,
    }));

const numericVector = (
    value: unknown,
    objectPath: string,
): readonly number[] => {
    if (!Array.isArray(value)) {
        throw new TypeError(`${objectPath} must be an array.`);
    }

    return value.map((entry, entryIndex) => {
        if (!Number.isSafeInteger(entry)) {
            throw new TypeError(
                `${objectPath}.${String(entryIndex)} must be a safe integer.`,
            );
        }

        return Number(entry);
    });
};

const assertPrivateEnvelopeMatchesReference = (
    setupContext: CollectiveBgvSetupContext,
    privateEnvelope: JsonRecord,
    privateEnvelopeHash: ProtocolHash,
    envelopeReference: PrivateVssEnvelopeVerificationReference,
): void => {
    assertSetupContextBinding(setupContext, privateEnvelope, 'privateEnvelope');
    if (privateEnvelopeHash !== envelopeReference.privateEnvelopeHash) {
        throw new Error(
            'verified private VSS envelope hash must match the public envelope reference.',
        );
    }
    for (const fieldName of [
        'dealerIdentity',
        'dealerRosterPosition',
        'recipientIdentity',
        'recipientRosterPosition',
        'dealerCommitmentRoot',
    ] as const) {
        if (privateEnvelope[fieldName] !== envelopeReference[fieldName]) {
            throw new Error(
                `privateEnvelope.${fieldName} must match the public envelope reference.`,
            );
        }
    }
};

const aggregateVerifiedPrivateVssMaterial = (
    input: GeneratedLocalTrusteeSetupStateInput,
    thresholdShareCommitmentRecipientRootValue: ProtocolHash,
    envelopeReferences: readonly PrivateVssEnvelopeVerificationReference[],
): Readonly<{
    readonly aggregateThresholdShareMaterial: JsonRecord;
    readonly aggregateOpeningMaterial: JsonRecord;
}> => {
    const privateEnvelopeByHash = new Map<ProtocolHash, JsonRecord>();
    for (const privateEnvelopeValue of input.verifiedPrivateVssShareEnvelopes) {
        const privateEnvelope = jsonRecord(
            privateEnvelopeValue,
            'verifiedPrivateVssShareEnvelopes',
        );
        const privateEnvelopeHash = deriveProtocolHash(
            'PrivateVssShareEnvelopeHash',
            privateEnvelope,
        );
        if (privateEnvelopeByHash.has(privateEnvelopeHash)) {
            throw new Error(
                'verifiedPrivateVssShareEnvelopes must not contain duplicate private envelope hashes.',
            );
        }
        privateEnvelopeByHash.set(privateEnvelopeHash, privateEnvelope);
    }

    const aggregateByLimb = new Map<number, AggregateLimbAccumulator>();
    for (const envelopeReference of envelopeReferences) {
        const privateEnvelope = privateEnvelopeByHash.get(
            envelopeReference.privateEnvelopeHash,
        );
        if (privateEnvelope === undefined) {
            throw new Error(
                'verifiedPrivateVssShareEnvelopes must include the private envelope referenced by each public envelope commitment.',
            );
        }
        assertPrivateEnvelopeMatchesReference(
            input.setupContext,
            privateEnvelope,
            envelopeReference.privateEnvelopeHash,
            envelopeReference,
        );
        const rnsShareOpenings = jsonRecordArray(
            privateEnvelope.rnsShareOpenings,
            'privateEnvelope.rnsShareOpenings',
        );
        for (const limbOpening of rnsShareOpenings) {
            const rnsLimbIndex = nonNegativeIntegerField(
                limbOpening,
                'rnsLimbIndex',
                'privateEnvelope.rnsShareOpenings',
            );
            const rnsPrime = nonNegativeIntegerField(
                limbOpening,
                'rnsPrime',
                'privateEnvelope.rnsShareOpenings',
            );
            if (rnsPrime === 0) {
                throw new Error('private VSS share rnsPrime must be positive.');
            }
            const shareValues = numericVector(
                limbOpening.shareValues,
                'privateEnvelope.rnsShareOpenings.shareValues',
            );
            shareValues.forEach((shareValue, shareValueIndex) => {
                if (shareValue < 0 || shareValue >= rnsPrime) {
                    throw new TypeError(
                        `privateEnvelope.rnsShareOpenings.shareValues.${String(shareValueIndex)} must be a residue below rnsPrime.`,
                    );
                }
            });
            const aggregateOpening = objectField(
                limbOpening,
                'aggregateOpening',
                'privateEnvelope.rnsShareOpenings',
            );
            const openingColumns = jsonRecordArray(
                arrayField(
                    aggregateOpening,
                    'openingColumns',
                    'privateEnvelope.rnsShareOpenings.aggregateOpening',
                ).map((openingColumn) => ({ openingColumn })),
                'privateEnvelope.rnsShareOpenings.aggregateOpening.openingColumns',
            ).map((openingColumnRecord, openingColumnIndex) =>
                numericVector(
                    openingColumnRecord.openingColumn,
                    `privateEnvelope.rnsShareOpenings.aggregateOpening.openingColumns.${String(openingColumnIndex)}`,
                ),
            );
            const existingAccumulator = aggregateByLimb.get(rnsLimbIndex);
            if (existingAccumulator === undefined) {
                aggregateByLimb.set(rnsLimbIndex, {
                    rnsLimbIndex,
                    rnsPrime,
                    shareValues: shareValues.map((shareValue) =>
                        BigInt(shareValue),
                    ),
                    aggregateOpeningColumns: openingColumns.map(
                        (openingColumn) =>
                            openingColumn.map((openingValue) =>
                                BigInt(openingValue),
                            ),
                    ),
                });
                continue;
            }
            if (existingAccumulator.rnsPrime !== rnsPrime) {
                throw new Error(
                    'private VSS share openings must use one rnsPrime per limb.',
                );
            }
            if (existingAccumulator.shareValues.length !== shareValues.length) {
                throw new Error(
                    'private VSS share vectors for the same limb must have equal length.',
                );
            }
            if (
                existingAccumulator.aggregateOpeningColumns.length !==
                openingColumns.length
            ) {
                throw new Error(
                    'private VSS aggregate openings for the same limb must have equal column count.',
                );
            }
            const rnsPrimeWide = BigInt(rnsPrime);
            shareValues.forEach((shareValue, shareValueIndex) => {
                existingAccumulator.shareValues[shareValueIndex] =
                    ((existingAccumulator.shareValues[shareValueIndex] ?? 0n) +
                        BigInt(shareValue)) %
                    rnsPrimeWide;
            });
            openingColumns.forEach((openingColumn, openingColumnIndex) => {
                const existingColumn =
                    existingAccumulator.aggregateOpeningColumns[
                        openingColumnIndex
                    ];
                if (existingColumn?.length !== openingColumn.length) {
                    throw new Error(
                        'private VSS aggregate opening column lengths must match.',
                    );
                }
                openingColumn.forEach((openingValue, openingValueIndex) => {
                    existingColumn[openingValueIndex] =
                        (existingColumn[openingValueIndex] ?? 0n) +
                        BigInt(openingValue);
                });
            });
        }
    }

    const orderedAggregates = [...aggregateByLimb.values()].sort(
        (left, right) => left.rnsLimbIndex - right.rnsLimbIndex,
    );
    const localEnvelopeReferences =
        sourcePrivateEnvelopeReferences(envelopeReferences);
    const materialCommonFields = {
        setupProfileId: 'CollectiveBgvSetup-v1',
        ...setupContextFields(input.setupContext),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        thresholdShareCommitmentRecipientRoot:
            thresholdShareCommitmentRecipientRootValue,
        sourcePrivateEnvelopeReferences: localEnvelopeReferences,
    } as const satisfies JsonRecord;

    return {
        aggregateThresholdShareMaterial: {
            objectType: 'LocalTrusteeAggregateThresholdShareMaterial',
            objectVersion: 1,
            ...materialCommonFields,
            materialDerivation: 'sum-of-verified-private-vss-share-values-v1',
            aggregateShareByRnsLimb: orderedAggregates.map((aggregate) => ({
                objectType: 'LocalTrusteeAggregateThresholdShareLimb',
                objectVersion: 1,
                rnsLimbIndex: aggregate.rnsLimbIndex,
                rnsPrime: aggregate.rnsPrime,
                shareValues: aggregate.shareValues.map((shareValue) =>
                    Number(shareValue),
                ),
            })),
        },
        aggregateOpeningMaterial: {
            objectType: 'LocalTrusteeAggregateThresholdOpeningMaterial',
            objectVersion: 1,
            ...materialCommonFields,
            materialDerivation:
                'sum-of-verified-private-vss-aggregate-openings-v1',
            aggregateOpeningByRnsLimb: orderedAggregates.map((aggregate) => ({
                objectType: 'LocalTrusteeAggregateThresholdOpeningLimb',
                objectVersion: 1,
                rnsLimbIndex: aggregate.rnsLimbIndex,
                rnsPrime: aggregate.rnsPrime,
                openingColumnsDecimal: aggregate.aggregateOpeningColumns.map(
                    (openingColumn) =>
                        openingColumn.map((openingValue) =>
                            openingValue.toString(),
                        ),
                ),
            })),
        },
    };
};

export async function encryptLocalTrusteeSetupState(
    input: LocalTrusteeSetupStateEncryptionInput,
): Promise<LocalTrusteeSetupStateEncryptionResult> {
    const localStateCommitment = createLocalTrusteeSetupStateCommitment(input);
    const encryptedState = await encryptLocalTrusteeState({
        localStatePlaintext: input.localStatePlaintext,
        localStateCommitment,
        setupContext: input.setupContext,
        storageKeyBytesHex: input.storageKeyBytesHex,
        aeadNonceBytesHex: input.aeadNonceBytesHex,
    });

    return {
        localStateCommitment,
        encryptedLocalState: encryptedState.encryptedLocalState,
        localStatePlaintextHash: encryptedState.localStatePlaintextHash,
        storageAadHash: encryptedState.storageAadHash,
    };
}

export const createEncryptedLocalTrusteeSetupStateFromVerifiedShares = async (
    input: GeneratedLocalTrusteeSetupStateInput,
): Promise<GeneratedLocalTrusteeSetupStateResult> => {
    assertNonEmptyString(input.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(
        input.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    assertNonNegativeSafeInteger(input.deviceEpoch, 'deviceEpoch');
    const thresholdShareCommitmentRecipientRootValue =
        thresholdShareCommitmentRecipientRoot(input);
    const envelopeReferences = recipientEnvelopeReferences(input);
    const privateVssEnvelopeCommitmentRoot = protocolHashField(
        jsonRecord(
            input.privateVssEnvelopeCommitments,
            'privateVssEnvelopeCommitments',
        ),
        'privateVssEnvelopeCommitmentRoot',
        'privateVssEnvelopeCommitments',
    );
    const materialPlaintexts = aggregateVerifiedPrivateVssMaterial(
        input,
        thresholdShareCommitmentRecipientRootValue,
        envelopeReferences,
    );
    const sealedAggregateThresholdShare =
        await encryptLocalTrusteeSetupSealedMaterial({
            materialClass: 'aggregate-threshold-share-sealed',
            materialPlaintext:
                materialPlaintexts.aggregateThresholdShareMaterial,
            setupContext: input.setupContext,
            trusteeIdentity: input.trusteeIdentity,
            trusteeRosterPosition: input.trusteeRosterPosition,
            thresholdShareCommitmentRecipientRoot:
                thresholdShareCommitmentRecipientRootValue,
            storageKeyBytesHex: input.storageKeyBytesHex,
            aeadNonceBytesHex:
                input.sealedAggregateThresholdShareAeadNonceBytesHex,
        });
    const sealedAggregateOpening = await encryptLocalTrusteeSetupSealedMaterial(
        {
            materialClass: 'aggregate-threshold-opening-sealed',
            materialPlaintext: materialPlaintexts.aggregateOpeningMaterial,
            setupContext: input.setupContext,
            trusteeIdentity: input.trusteeIdentity,
            trusteeRosterPosition: input.trusteeRosterPosition,
            thresholdShareCommitmentRecipientRoot:
                thresholdShareCommitmentRecipientRootValue,
            storageKeyBytesHex: input.storageKeyBytesHex,
            aeadNonceBytesHex: input.sealedAggregateOpeningAeadNonceBytesHex,
        },
    );
    const acceptanceRoot = issuedVssAcceptanceRoot(
        input,
        privateVssEnvelopeCommitmentRoot,
        envelopeReferences.length,
    );
    const complaintRoots = issuedVssComplaintRoots(
        input,
        privateVssEnvelopeCommitmentRoot,
    );
    const localStatePlaintext = {
        objectType: 'LocalTrusteeSetupStateSealedPayload',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupEpoch: input.setupContext.setupEpoch,
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        deviceEpoch: input.deviceEpoch,
        thresholdShareCommitmentRecipientRoot:
            thresholdShareCommitmentRecipientRootValue,
        sealedAggregateThresholdShare:
            sealedAggregateThresholdShare.sealedMaterial,
        sealedAggregateOpening: sealedAggregateOpening.sealedMaterial,
        issuedVssAcceptanceRoots: [acceptanceRoot],
        issuedVssComplaintRoots: complaintRoots,
    } satisfies LocalTrusteeSetupStateSealedPayload;
    const encryptedLocalState = await encryptLocalTrusteeSetupState({
        setupContext: input.setupContext,
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        thresholdShareCommitmentRecipientRoot:
            thresholdShareCommitmentRecipientRootValue,
        aggregateThresholdShareRoot: sealedAggregateThresholdShare.materialRoot,
        aggregateOpeningRoot: sealedAggregateOpening.materialRoot,
        issuedVssAcceptanceRoot: acceptanceRoot,
        issuedVssComplaintRoots: complaintRoots,
        localStatePlaintext,
        storageKeyBytesHex: input.storageKeyBytesHex,
        aeadNonceBytesHex: input.localStateAeadNonceBytesHex,
    });

    return {
        ...encryptedLocalState,
        localStatePlaintext,
    };
};

export const decryptLocalTrusteeSetupState = async (
    input: LocalTrusteeSetupStateDecryptionInput,
): Promise<LocalTrusteeStateStorageDecryptionResult> =>
    decryptLocalTrusteeState(input);
