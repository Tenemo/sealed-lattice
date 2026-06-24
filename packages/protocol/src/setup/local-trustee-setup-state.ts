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

import {
    computeCompactVssCommitmentFromOpening,
    verifyCompactVssAggregateThresholdCommitmentSet,
    verifyCompactVssShareLinkageStatement,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssAggregateThresholdOpeningCredential,
    type CompactVssCoefficientCommitmentSet,
    type CompactVssRecipientShareOpeningCredential,
    type CompactVssRecipientShareCommitmentSet,
    type CompactVssShareLinkageStatement,
} from './compact-vss-commitments.js';
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
    'raw-per-source-trustee-vss-shares',
    'raw-per-source-trustee-vss-openings',
    'private-vss-envelope-payloads-after-aggregation',
] as const;

export const retainedLocalTrusteeSetupMaterialClasses = [
    'aggregate-threshold-share-sealed',
    'target-decryption-proof-witness-sealed',
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
    readonly targetDecryptionProofWitnessRoot: ProtocolHash;
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

export type GeneratedCompactVssTargetProofWitnessInput = Readonly<{
    readonly coefficientCommitmentSet?: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet?: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
    readonly aggregateThresholdOpeningCredentials?: readonly CompactVssAggregateThresholdOpeningCredential[];
    readonly recipientShareOpeningCredentials?: readonly CompactVssRecipientShareOpeningCredential[];
    readonly shareLinkageStatement: CompactVssShareLinkageStatement;
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
    readonly sealedTargetDecryptionProofWitnessAeadNonceBytesHex?: string;
    readonly compactVssTargetProofWitness?: GeneratedCompactVssTargetProofWitnessInput;
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
        readonly targetDecryptionProofWitnessRoot: ProtocolHash;
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
    assertProtocolHash(
        input.targetDecryptionProofWitnessRoot,
        'targetDecryptionProofWitnessRoot',
    );
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
        targetDecryptionProofWitnessRoot:
            input.targetDecryptionProofWitnessRoot,
        issuedVssAcceptanceRoot: input.issuedVssAcceptanceRoot,
        issuedVssComplaintRoots: input.issuedVssComplaintRoots,
        deletionReceiptRoot: deletionReceipt.deletionReceiptRoot,
        deletionReceipt,
        exportPolicy: localTrusteeSetupStateExportPolicy,
        storageProfile: localTrusteeSetupStateStorageProfile,
    } as const satisfies JsonRecord;

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
                Number(left.sourceTrusteeRosterPosition) -
                Number(right.sourceTrusteeRosterPosition),
        );
    if (envelopeReferences.length !== participantCount) {
        throw new Error(
            'privateVssEnvelopeCommitments must include one envelope reference from every source trustee for the trustee.',
        );
    }
    envelopeReferences.forEach((reference, referenceIndex) => {
        const objectPath = `privateVssEnvelopeCommitments.envelopeReferences.${String(referenceIndex)}`;
        assertSetupContextBinding(input.setupContext, reference, objectPath);
        if (reference.sourceTrusteeRosterPosition !== referenceIndex) {
            throw new Error(
                'private VSS envelope references for a trustee must cover contiguous source trustee roster positions.',
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
        protocolHashField(reference, 'sourceTrusteeCommitmentRoot', objectPath);
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
                Number(left.sourceTrusteeRosterPosition) -
                Number(right.sourceTrusteeRosterPosition),
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
            'vssShareAcceptances must contain one acceptance issued by the trustee for every source trustee.',
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
                Number(left.sourceTrusteeRosterPosition) -
                Number(right.sourceTrusteeRosterPosition),
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
};

const sourcePrivateEnvelopeReferences = (
    envelopeReferences: readonly PrivateVssEnvelopeVerificationReference[],
): readonly JsonRecord[] =>
    envelopeReferences.map((reference) => ({
        objectType: 'LocalTrusteePrivateVssEnvelopeReference',
        objectVersion: 1,
        sourceTrusteeIdentity: reference.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: reference.sourceTrusteeRosterPosition,
        sourceTrusteeCommitmentRoot: reference.sourceTrusteeCommitmentRoot,
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
        'sourceTrusteeIdentity',
        'sourceTrusteeRosterPosition',
        'recipientIdentity',
        'recipientRosterPosition',
        'sourceTrusteeCommitmentRoot',
    ] as const) {
        if (privateEnvelope[fieldName] !== envelopeReference[fieldName]) {
            throw new Error(
                `privateEnvelope.${fieldName} must match the public envelope reference.`,
            );
        }
    }
};

const assertSameShareValues = (
    leftValues: readonly number[],
    rightValues: readonly number[],
    objectPath: string,
    expectedDescription = 'the aggregate threshold share material',
): void => {
    if (leftValues.length !== rightValues.length) {
        throw new Error(`${objectPath} length must match.`);
    }
    leftValues.forEach((leftValue, valueIndex) => {
        if (leftValue !== rightValues[valueIndex]) {
            throw new Error(
                `${objectPath}.${String(valueIndex)} must match ${expectedDescription}.`,
            );
        }
    });
};

const aggregateVerifiedPrivateVssMaterial = (
    input: GeneratedLocalTrusteeSetupStateInput,
    thresholdShareCommitmentRecipientRootValue: ProtocolHash,
    envelopeReferences: readonly PrivateVssEnvelopeVerificationReference[],
): Readonly<{
    readonly aggregateThresholdShareMaterial: JsonRecord;
    readonly compactVssRecipientShareOpeningCredentials: readonly CompactVssRecipientShareOpeningCredential[];
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
    const compactVssRecipientShareOpeningCredentials: CompactVssRecipientShareOpeningCredential[] =
        [];
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
            if (
                limbOpening.compactVssRecipientShareOpeningCredential !==
                undefined
            ) {
                const compactCredential = jsonRecord(
                    limbOpening.compactVssRecipientShareOpeningCredential,
                    'privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential',
                ) as unknown as CompactVssRecipientShareOpeningCredential;
                if (
                    compactCredential.sourceTrusteeIdentity !==
                        envelopeReference.sourceTrusteeIdentity ||
                    compactCredential.sourceTrusteeRosterPosition !==
                        envelopeReference.sourceTrusteeRosterPosition ||
                    compactCredential.recipientIdentity !==
                        envelopeReference.recipientIdentity ||
                    compactCredential.recipientRosterPosition !==
                        envelopeReference.recipientRosterPosition ||
                    compactCredential.rnsLimbIndex !== rnsLimbIndex ||
                    compactCredential.rnsPrime !== rnsPrime
                ) {
                    throw new Error(
                        'compact VSS recipient share opening credential must match its private VSS envelope limb binding.',
                    );
                }
                assertSameShareValues(
                    compactCredential.shareValues,
                    shareValues,
                    'privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareValues',
                    'the delivered private VSS share values',
                );
                compactVssRecipientShareOpeningCredentials.push(
                    compactCredential,
                );
            }
            const existingAccumulator = aggregateByLimb.get(rnsLimbIndex);
            if (existingAccumulator === undefined) {
                aggregateByLimb.set(rnsLimbIndex, {
                    rnsLimbIndex,
                    rnsPrime,
                    shareValues: shareValues.map((shareValue) =>
                        BigInt(shareValue),
                    ),
                });
                continue;
            }
            if (existingAccumulator.rnsPrime !== rnsPrime) {
                throw new Error(
                    'private VSS share values must use one rnsPrime per limb.',
                );
            }
            if (existingAccumulator.shareValues.length !== shareValues.length) {
                throw new Error(
                    'private VSS share vectors for the same limb must have equal length.',
                );
            }
            const rnsPrimeWide = BigInt(rnsPrime);
            shareValues.forEach((shareValue, shareValueIndex) => {
                existingAccumulator.shareValues[shareValueIndex] =
                    ((existingAccumulator.shareValues[shareValueIndex] ?? 0n) +
                        BigInt(shareValue)) %
                    rnsPrimeWide;
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
        compactVssRecipientShareOpeningCredentials,
    };
};

type AggregateThresholdShareLimbMaterial = Readonly<{
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shareValues: readonly number[];
}>;

const aggregateThresholdShareLimbMaterials = (
    aggregateThresholdShareMaterial: JsonRecord,
): readonly AggregateThresholdShareLimbMaterial[] =>
    jsonRecordArray(
        aggregateThresholdShareMaterial.aggregateShareByRnsLimb,
        'aggregateThresholdShareMaterial.aggregateShareByRnsLimb',
    ).map((limbMaterial, limbIndex) => {
        const objectPath = `aggregateThresholdShareMaterial.aggregateShareByRnsLimb.${String(limbIndex)}`;
        const rnsLimbIndex = nonNegativeIntegerField(
            limbMaterial,
            'rnsLimbIndex',
            objectPath,
        );
        const rnsPrime = nonNegativeIntegerField(
            limbMaterial,
            'rnsPrime',
            objectPath,
        );
        if (rnsPrime === 0) {
            throw new Error(
                `${objectPath}.rnsPrime must be a positive integer.`,
            );
        }
        const shareValues = numericVector(
            limbMaterial.shareValues,
            `${objectPath}.shareValues`,
        );
        shareValues.forEach((shareValue, shareValueIndex) => {
            if (shareValue < 0 || shareValue >= rnsPrime) {
                throw new TypeError(
                    `${objectPath}.shareValues.${String(shareValueIndex)} must be a residue below rnsPrime.`,
                );
            }
        });

        return {
            rnsLimbIndex,
            rnsPrime,
            shareValues,
        };
    });

const compactVssCredentialKey = (
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): string => `${String(recipientRosterPosition)}:${String(rnsLimbIndex)}`;

const aggregateCompactVssOpeningCredentialsFromRecipientCredentials = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
    readonly recipientShareOpeningCredentials: readonly CompactVssRecipientShareOpeningCredential[];
}): readonly CompactVssAggregateThresholdOpeningCredential[] => {
    const aggregateThresholdCommitmentSet =
        verifyCompactVssAggregateThresholdCommitmentSet({
            aggregateThresholdCommitmentSet:
                input.aggregateThresholdCommitmentSet,
        });
    const recipientRecords = aggregateThresholdCommitmentSet.recipientRecords
        .filter(
            (record) =>
                record.recipientIdentity === input.trusteeIdentity &&
                record.recipientRosterPosition === input.trusteeRosterPosition,
        )
        .sort((left, right) => left.rnsLimbIndex - right.rnsLimbIndex);
    return recipientRecords.map((record) => {
        const credentials = input.recipientShareOpeningCredentials
            .filter(
                (credential) =>
                    credential.recipientIdentity === input.trusteeIdentity &&
                    credential.recipientRosterPosition ===
                        input.trusteeRosterPosition &&
                    credential.rnsLimbIndex === record.rnsLimbIndex,
            )
            .sort(
                (left, right) =>
                    left.sourceTrusteeRosterPosition -
                    right.sourceTrusteeRosterPosition,
            );
        if (
            credentials.length !==
            aggregateThresholdCommitmentSet.participantCount
        ) {
            throw new Error(
                'compact VSS recipient share opening credentials must cover every source trustee for each local recipient limb.',
            );
        }
        const seenSourcePositions = new Set<number>();
        const sourceShareCommitmentRoots = new Set(
            record.sourceShareCommitmentRoots,
        );
        const aggregateShareValues = Array.from(
            { length: aggregateThresholdCommitmentSet.ringDegree },
            () => 0n,
        );
        const aggregateRandomnessByColumn: number[][] | undefined =
            credentials[0]?.randomnessByColumn.map((randomnessColumn) =>
                Array.from({ length: randomnessColumn.length }, () => 0),
            );
        if (aggregateRandomnessByColumn === undefined) {
            throw new Error(
                'compact VSS recipient share opening credentials must not be empty.',
            );
        }
        credentials.forEach((credential) => {
            if (
                seenSourcePositions.has(credential.sourceTrusteeRosterPosition)
            ) {
                throw new Error(
                    'compact VSS recipient share opening credentials must contain at most one credential per source trustee for each recipient limb.',
                );
            }
            seenSourcePositions.add(credential.sourceTrusteeRosterPosition);
            if (
                credential.rnsPrime !== record.rnsPrime ||
                credential.recipientTrusteePoint !==
                    record.recipientTrusteePoint ||
                credential.shareValues.length !==
                    aggregateThresholdCommitmentSet.ringDegree ||
                !sourceShareCommitmentRoots.has(credential.shareCommitmentRoot)
            ) {
                throw new Error(
                    'compact VSS recipient share opening credential must match the public aggregate threshold commitment record.',
                );
            }
            const recomputedCommitment = computeCompactVssCommitmentFromOpening(
                {
                    commitmentRole: 'recipient-share',
                    commitmentContext: {
                        objectType: 'CompactVssRecipientShareCommitmentContext',
                        objectVersion: 1,
                        ...setupContextFields(input.setupContext),
                        sourceTrusteeIdentity: credential.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition:
                            credential.sourceTrusteeRosterPosition,
                        recipientIdentity: credential.recipientIdentity,
                        recipientRosterPosition:
                            credential.recipientRosterPosition,
                        rnsLimbIndex: credential.rnsLimbIndex,
                        rnsPrime: credential.rnsPrime,
                    },
                    publicMatrixSeedHash:
                        aggregateThresholdCommitmentSet.publicMatrixSeedHash,
                    rnsLimbIndex: credential.rnsLimbIndex,
                    rnsPrime: credential.rnsPrime,
                    ringDegree: aggregateThresholdCommitmentSet.ringDegree,
                    messageCoefficients: credential.shareValues,
                    randomnessByColumn: credential.randomnessByColumn,
                },
            );
            if (
                recomputedCommitment.commitmentRoot !==
                    credential.shareCommitmentRoot ||
                recomputedCommitment.openingRoot !== credential.shareOpeningRoot
            ) {
                throw new Error(
                    'compact VSS recipient share opening credential does not open its public recipient-share commitment.',
                );
            }
            const rnsPrimeWide = BigInt(record.rnsPrime);
            credential.shareValues.forEach((shareValue, shareValueIndex) => {
                aggregateShareValues[shareValueIndex] =
                    ((aggregateShareValues[shareValueIndex] ?? 0n) +
                        BigInt(shareValue)) %
                    rnsPrimeWide;
            });
            credential.randomnessByColumn.forEach(
                (randomnessColumn, columnIndex) => {
                    const aggregateRandomnessColumn =
                        aggregateRandomnessByColumn[columnIndex];
                    if (
                        aggregateRandomnessColumn?.length !==
                        randomnessColumn.length
                    ) {
                        throw new Error(
                            'compact VSS recipient share opening credential randomness shape must match across source trustees.',
                        );
                    }
                    randomnessColumn.forEach(
                        (randomnessCoefficient, coefficientIndex) => {
                            aggregateRandomnessColumn[coefficientIndex] =
                                (aggregateRandomnessColumn[coefficientIndex] ??
                                    0) + randomnessCoefficient;
                        },
                    );
                },
            );
        });

        return {
            objectType: 'CompactVssAggregateThresholdOpeningCredential',
            objectVersion: 1,
            profileId: aggregateThresholdCommitmentSet.profileId,
            recipientIdentity: record.recipientIdentity,
            recipientRosterPosition: record.recipientRosterPosition,
            recipientTrusteePoint: record.recipientTrusteePoint,
            rnsLimbIndex: record.rnsLimbIndex,
            rnsPrime: record.rnsPrime,
            aggregateShareValues: aggregateShareValues.map((shareValue) =>
                Number(shareValue),
            ),
            aggregateRandomnessByColumn,
            aggregateCommitmentRoot: record.aggregateCommitmentRoot,
            aggregateOpeningRoot: record.aggregateOpeningRoot,
            sourceShareOpeningRoots: credentials.map(
                (credential) => credential.shareOpeningRoot,
            ),
        } satisfies CompactVssAggregateThresholdOpeningCredential;
    });
};

const buildTargetDecryptionProofWitnessMaterial = (
    input: GeneratedLocalTrusteeSetupStateInput,
    thresholdShareCommitmentRecipientRootValue: ProtocolHash,
    aggregateThresholdShareRoot: ProtocolHash,
    aggregateThresholdShareMaterial: JsonRecord,
    envelopeReferences: readonly PrivateVssEnvelopeVerificationReference[],
    deliveredCompactVssRecipientShareOpeningCredentials: readonly CompactVssRecipientShareOpeningCredential[],
): JsonRecord => {
    const commonWitnessFields = {
        objectType: 'LocalTrusteeTargetDecryptionProofWitnessMaterial',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ...setupContextFields(input.setupContext),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        thresholdShareCommitmentRecipientRoot:
            thresholdShareCommitmentRecipientRootValue,
        aggregateThresholdShareRoot,
        sourcePrivateEnvelopeReferences:
            sourcePrivateEnvelopeReferences(envelopeReferences),
        witnessOwnership: 'recipient-owned-restorable-local-state',
    } as const satisfies JsonRecord;

    if (input.compactVssTargetProofWitness === undefined) {
        return {
            ...commonWitnessFields,
            witnessUse:
                'target-decryption share proof generation after compact opening credential delivery is implemented',
            currentProofGenerationBoundary:
                'current full-material setup state does not yet contain compact aggregate opening credentials',
        };
    }

    const compactWitness = input.compactVssTargetProofWitness;
    const aggregateThresholdCommitmentSet =
        verifyCompactVssAggregateThresholdCommitmentSet({
            aggregateThresholdCommitmentSet:
                compactWitness.aggregateThresholdCommitmentSet,
        });

    const hasShareLinkageEvidence =
        compactWitness.coefficientCommitmentSet !== undefined ||
        compactWitness.recipientShareCommitmentSet !== undefined;
    if (
        hasShareLinkageEvidence &&
        (compactWitness.coefficientCommitmentSet === undefined ||
            compactWitness.recipientShareCommitmentSet === undefined)
    ) {
        throw new Error(
            'compact VSS target proof witness must include both coefficient and recipient-share commitment sets when linkage evidence is supplied.',
        );
    }
    const shareLinkageStatement = verifyCompactVssShareLinkageStatement(
        hasShareLinkageEvidence
            ? {
                  statement: compactWitness.shareLinkageStatement,
                  coefficientCommitmentSet:
                      compactWitness.coefficientCommitmentSet,
                  recipientShareCommitmentSet:
                      compactWitness.recipientShareCommitmentSet,
                  aggregateThresholdCommitmentSet,
              }
            : {
                  statement: compactWitness.shareLinkageStatement,
              },
    );
    const shareLinkageStatementRecord =
        shareLinkageStatement as unknown as JsonRecord;
    assertSetupContextBinding(
        input.setupContext,
        shareLinkageStatementRecord,
        'compactVssTargetProofWitness.shareLinkageStatement',
    );
    const targetBasisHash = protocolHashField(
        shareLinkageStatementRecord,
        'targetBasisHash',
        'compactVssTargetProofWitness.shareLinkageStatement',
    );
    if (
        shareLinkageStatement.aggregateThresholdCommitmentRoot !==
        aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot
    ) {
        throw new Error(
            'compact VSS share linkage statement must bind the aggregate threshold commitment set root.',
        );
    }
    if (
        shareLinkageStatement.publicMatrixSeedHash !==
        aggregateThresholdCommitmentSet.publicMatrixSeedHash
    ) {
        throw new Error(
            'compact VSS share linkage statement must bind the aggregate threshold commitment matrix seed.',
        );
    }

    const aggregateShareByLimb = new Map(
        aggregateThresholdShareLimbMaterials(
            aggregateThresholdShareMaterial,
        ).map((limbMaterial) => [limbMaterial.rnsLimbIndex, limbMaterial]),
    );
    const credentialsByCoordinate = new Map<
        string,
        CompactVssAggregateThresholdOpeningCredential
    >();
    const aggregateThresholdOpeningCredentials =
        compactWitness.aggregateThresholdOpeningCredentials ??
        aggregateCompactVssOpeningCredentialsFromRecipientCredentials({
            setupContext: input.setupContext,
            trusteeIdentity: input.trusteeIdentity,
            trusteeRosterPosition: input.trusteeRosterPosition,
            aggregateThresholdCommitmentSet,
            recipientShareOpeningCredentials: [
                ...deliveredCompactVssRecipientShareOpeningCredentials,
                ...(compactWitness.recipientShareOpeningCredentials ?? []),
            ],
        });
    aggregateThresholdOpeningCredentials
        .filter(
            (credential) =>
                credential.recipientIdentity === input.trusteeIdentity &&
                credential.recipientRosterPosition ===
                    input.trusteeRosterPosition,
        )
        .forEach((credential) => {
            const credentialKey = compactVssCredentialKey(
                credential.recipientRosterPosition,
                credential.rnsLimbIndex,
            );
            if (credentialsByCoordinate.has(credentialKey)) {
                throw new Error(
                    'compact VSS aggregate opening credentials must contain at most one credential for each recipient limb.',
                );
            }
            credentialsByCoordinate.set(credentialKey, credential);
        });

    const recipientRecords = aggregateThresholdCommitmentSet.recipientRecords
        .filter(
            (record) =>
                record.recipientIdentity === input.trusteeIdentity &&
                record.recipientRosterPosition === input.trusteeRosterPosition,
        )
        .sort((left, right) => left.rnsLimbIndex - right.rnsLimbIndex);
    if (recipientRecords.length === 0) {
        throw new Error(
            'compact VSS aggregate threshold commitment set must contain records for the local trustee.',
        );
    }
    if (credentialsByCoordinate.size !== recipientRecords.length) {
        throw new Error(
            'compact VSS aggregate opening credentials must cover every local recipient limb.',
        );
    }

    const compactAggregateOpeningCredentials = recipientRecords.map(
        (record) => {
            const credential = credentialsByCoordinate.get(
                compactVssCredentialKey(
                    record.recipientRosterPosition,
                    record.rnsLimbIndex,
                ),
            );
            if (credential === undefined) {
                throw new Error(
                    'compact VSS aggregate opening credential is missing for a local recipient limb.',
                );
            }
            if (
                credential.recipientTrusteePoint !==
                    record.recipientTrusteePoint ||
                credential.rnsPrime !== record.rnsPrime ||
                credential.aggregateCommitmentRoot !==
                    record.aggregateCommitmentRoot ||
                credential.aggregateOpeningRoot !== record.aggregateOpeningRoot
            ) {
                throw new Error(
                    'compact VSS aggregate opening credential must match its public aggregate commitment record.',
                );
            }
            const aggregateShareMaterial = aggregateShareByLimb.get(
                record.rnsLimbIndex,
            );
            if (aggregateShareMaterial === undefined) {
                throw new Error(
                    'compact VSS aggregate opening credential must have matching aggregate threshold share material.',
                );
            }
            if (aggregateShareMaterial.rnsPrime !== record.rnsPrime) {
                throw new Error(
                    'compact VSS aggregate opening credential rnsPrime must match aggregate threshold share material.',
                );
            }
            assertSameShareValues(
                credential.aggregateShareValues,
                aggregateShareMaterial.shareValues,
                'compactVssTargetProofWitness.aggregateThresholdOpeningCredentials.aggregateShareValues',
            );
            const recomputedCommitment = computeCompactVssCommitmentFromOpening(
                {
                    commitmentRole: 'aggregate-threshold-share',
                    commitmentContext: {
                        objectType:
                            'CompactVssAggregateThresholdShareCommitmentContext',
                        objectVersion: 1,
                        ...setupContextFields(input.setupContext),
                        recipientIdentity: credential.recipientIdentity,
                        recipientRosterPosition:
                            credential.recipientRosterPosition,
                        rnsLimbIndex: credential.rnsLimbIndex,
                        rnsPrime: credential.rnsPrime,
                    },
                    publicMatrixSeedHash:
                        aggregateThresholdCommitmentSet.publicMatrixSeedHash,
                    rnsLimbIndex: credential.rnsLimbIndex,
                    rnsPrime: credential.rnsPrime,
                    ringDegree: aggregateThresholdCommitmentSet.ringDegree,
                    messageCoefficients: credential.aggregateShareValues,
                    randomnessByColumn: credential.aggregateRandomnessByColumn,
                },
            );
            if (
                recomputedCommitment.commitmentRoot !==
                    credential.aggregateCommitmentRoot ||
                recomputedCommitment.openingRoot !==
                    credential.aggregateOpeningRoot
            ) {
                throw new Error(
                    'compact VSS aggregate opening credential does not open its public aggregate commitment.',
                );
            }

            return {
                objectType: 'LocalTrusteeCompactVssAggregateOpeningCredential',
                objectVersion: 1,
                recipientIdentity: credential.recipientIdentity,
                recipientRosterPosition: credential.recipientRosterPosition,
                recipientTrusteePoint: credential.recipientTrusteePoint,
                rnsLimbIndex: credential.rnsLimbIndex,
                rnsPrime: credential.rnsPrime,
                aggregateCommitmentRoot: credential.aggregateCommitmentRoot,
                aggregateOpeningRoot: credential.aggregateOpeningRoot,
                aggregateShareValues: credential.aggregateShareValues,
                aggregateRandomnessByColumn:
                    credential.aggregateRandomnessByColumn,
                sourceShareOpeningRoots: credential.sourceShareOpeningRoots,
            } satisfies JsonRecord;
        },
    );

    return {
        ...commonWitnessFields,
        witnessUse:
            'target-decryption share proof generation from the sealed compact aggregate opening',
        currentProofGenerationBoundary:
            'zero-knowledge target-decryption proof backend from compact local openings is not implemented yet',
        compactAggregateOpening: {
            objectType: 'LocalTrusteeCompactVssAggregateOpeningWitness',
            objectVersion: 1,
            profileId: aggregateThresholdCommitmentSet.profileId,
            developmentScope: aggregateThresholdCommitmentSet.developmentScope,
            publicMatrixSeedHash:
                aggregateThresholdCommitmentSet.publicMatrixSeedHash,
            targetBasisHash,
            shareLinkageStatementRoot: shareLinkageStatement.statementRoot,
            aggregateThresholdCommitmentRoot:
                aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot,
            compactAggregateOpeningCredentials,
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
    const targetDecryptionProofWitnessMaterial =
        buildTargetDecryptionProofWitnessMaterial(
            input,
            thresholdShareCommitmentRecipientRootValue,
            sealedAggregateThresholdShare.materialRoot,
            materialPlaintexts.aggregateThresholdShareMaterial,
            envelopeReferences,
            materialPlaintexts.compactVssRecipientShareOpeningCredentials,
        );
    const sealedTargetDecryptionProofWitness =
        await encryptLocalTrusteeSetupSealedMaterial({
            materialClass: 'target-decryption-proof-witness-sealed',
            materialPlaintext: targetDecryptionProofWitnessMaterial,
            setupContext: input.setupContext,
            trusteeIdentity: input.trusteeIdentity,
            trusteeRosterPosition: input.trusteeRosterPosition,
            thresholdShareCommitmentRecipientRoot:
                thresholdShareCommitmentRecipientRootValue,
            storageKeyBytesHex: input.storageKeyBytesHex,
            aeadNonceBytesHex:
                input.sealedTargetDecryptionProofWitnessAeadNonceBytesHex,
        });
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
        sealedTargetDecryptionProofWitness:
            sealedTargetDecryptionProofWitness.sealedMaterial,
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
        targetDecryptionProofWitnessRoot:
            sealedTargetDecryptionProofWitness.materialRoot,
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
