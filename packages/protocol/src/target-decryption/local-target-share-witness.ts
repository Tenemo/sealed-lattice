import { hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    isProtocolHashString,
    isRecord,
} from '../common/verification-helpers.js';

type JsonRecord = Record<string, unknown>;

const targetDecryptionSmudgingProfileId =
    'sealed-lattice-target-decryption-zero-share-smudging-v1';
const targetDecryptionSmudgingSeedHashDomain =
    'sealed-lattice-bgv-rns/target-decryption-smudging-seed-v1';
const targetDecryptionPlaintextMultiple = 65_537;

const textEncoder = new TextEncoder();

type TargetDecryptionSmudgingSeedDerivationInput = Readonly<{
    readonly setupPackage: unknown;
    readonly targetAcceptedRecord: unknown;
    readonly targetDecryptionCiphertextHash: ProtocolHash;
    readonly targetShareProfile: unknown;
}>;

type LocalTrusteeTargetDecryptionSmudgingWitness = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeTargetDecryptionSmudgingWitness';
        readonly objectVersion: 1;
        readonly profileId: typeof targetDecryptionSmudgingProfileId;
        readonly setupPackageHash: ProtocolHash;
        readonly targetAcceptedRecordHash: ProtocolHash;
        readonly targetContextHash: ProtocolHash;
        readonly targetCiphertextHash: ProtocolHash;
        readonly targetDecryptionCiphertextHash: ProtocolHash;
        readonly targetShareProfileHash: ProtocolHash;
        readonly targetBasisHash: ProtocolHash;
        readonly trusteeIdentity: string;
        readonly rosterPosition: number;
        readonly interpolationPoint: number;
        readonly plaintextMultiple: typeof targetDecryptionPlaintextMultiple;
    }
>;

type LocalTargetDecryptionShareWitnessPreparationInput = Readonly<{
    readonly restoredLocalTargetShareWitness: unknown;
    readonly setupPackage: unknown;
    readonly targetAcceptedRecord: unknown;
    readonly targetDecryptionCiphertextHash: ProtocolHash;
    readonly targetShareProfile: unknown;
    readonly trusteeIdentity: string;
}>;

type PreparedLocalTargetDecryptionShareWitness = Readonly<
    JsonRecord & {
        readonly targetDecryptionSmudging: LocalTrusteeTargetDecryptionSmudgingWitness;
    }
>;

const jsonRecord = (value: unknown, objectPath: string): JsonRecord => {
    if (!isRecord(value) || Array.isArray(value)) {
        throw new Error(`${objectPath} must be an object.`);
    }

    return value;
};

const nonEmptyStringField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): string => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'string' || fieldValue.length === 0) {
        throw new Error(
            `${objectPath}.${fieldName} must be a non-empty string.`,
        );
    }

    return fieldValue;
};

const protocolHashField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): ProtocolHash => {
    const fieldValue = value[fieldName];
    if (!isProtocolHashString(fieldValue)) {
        throw new Error(`${objectPath}.${fieldName} must be a protocol hash.`);
    }

    return fieldValue;
};

const nonNegativeIntegerField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = value[fieldName];
    if (
        typeof fieldValue !== 'number' ||
        !Number.isSafeInteger(fieldValue) ||
        fieldValue < 0 ||
        Object.is(fieldValue, -0)
    ) {
        throw new Error(
            `${objectPath}.${fieldName} must be a non-negative integer.`,
        );
    }

    return fieldValue;
};

const exactStringField = (
    value: JsonRecord,
    fieldName: string,
    expectedValue: string,
    objectPath: string,
): void => {
    const fieldValue = value[fieldName];
    if (fieldValue !== expectedValue) {
        throw new Error(`${objectPath}.${fieldName} must be ${expectedValue}.`);
    }
};

const exactVersionField = (
    value: JsonRecord,
    fieldName: string,
    expectedValue: number,
    objectPath: string,
): void => {
    const fieldValue = value[fieldName];
    if (fieldValue !== expectedValue) {
        throw new Error(
            `${objectPath}.${fieldName} must be ${String(expectedValue)}.`,
        );
    }
};

const compareProtocolHashField = (
    value: JsonRecord,
    fieldName: string,
    expectedValue: ProtocolHash,
    objectPath: string,
    expectedDescription: string,
): ProtocolHash => {
    const fieldValue = protocolHashField(value, fieldName, objectPath);
    if (fieldValue !== expectedValue) {
        throw new Error(
            `${objectPath}.${fieldName} must match ${expectedDescription}.`,
        );
    }

    return fieldValue;
};

const encoded = (value: string): Uint8Array => textEncoder.encode(value);

const targetBindingHashes = (
    setupPackageValue: unknown,
    targetAcceptedRecordValue: unknown,
    targetDecryptionCiphertextHashValue: ProtocolHash,
    targetShareProfileValue: unknown,
): Readonly<{
    readonly setupPackageHash: ProtocolHash;
    readonly targetAcceptedRecordHash: ProtocolHash;
    readonly targetContextHash: ProtocolHash;
    readonly targetCiphertextHash: ProtocolHash;
    readonly targetDecryptionCiphertextHash: ProtocolHash;
    readonly targetShareProfileHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
}> => {
    const setupPackage = jsonRecord(setupPackageValue, 'setupPackage');
    const targetAcceptedRecord = jsonRecord(
        targetAcceptedRecordValue,
        'targetAcceptedRecord',
    );
    const targetShareProfile = jsonRecord(
        targetShareProfileValue,
        'targetShareProfile',
    );
    if (!isProtocolHashString(targetDecryptionCiphertextHashValue)) {
        throw new Error(
            'targetDecryptionCiphertextHash must be a protocol hash.',
        );
    }

    return {
        setupPackageHash: protocolHashField(
            setupPackage,
            'setupPackageHash',
            'setupPackage',
        ),
        targetAcceptedRecordHash: protocolHashField(
            targetAcceptedRecord,
            'targetAcceptedRecordHash',
            'targetAcceptedRecord',
        ),
        targetContextHash: protocolHashField(
            targetAcceptedRecord,
            'targetContextHash',
            'targetAcceptedRecord',
        ),
        targetCiphertextHash: protocolHashField(
            targetAcceptedRecord,
            'targetCiphertextHash',
            'targetAcceptedRecord',
        ),
        targetDecryptionCiphertextHash: targetDecryptionCiphertextHashValue,
        targetShareProfileHash: protocolHashField(
            targetShareProfile,
            'targetShareProfileHash',
            'targetShareProfile',
        ),
        targetBasisHash: protocolHashField(
            targetAcceptedRecord,
            'targetBasisHash',
            'targetAcceptedRecord',
        ),
    };
};

const setupParticipant = (
    setupPackageValue: unknown,
    trusteeIdentity: string,
): Readonly<{
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly interpolationPoint: number;
}> => {
    const setupPackage = jsonRecord(setupPackageValue, 'setupPackage');
    const participants = setupPackage.participants;
    if (!Array.isArray(participants)) {
        throw new Error('setupPackage.participants must be an array.');
    }
    const participant = participants
        .map((participantValue, participantIndex) =>
            jsonRecord(
                participantValue,
                `setupPackage.participants.${String(participantIndex)}`,
            ),
        )
        .find(
            (participantValue) =>
                participantValue.trusteeIdentity === trusteeIdentity,
        );
    if (participant === undefined) {
        throw new Error('setupPackage.participants must contain the trustee.');
    }
    const participantObjectPath = 'setupPackage.participants.trustee';
    const rosterPosition = nonNegativeIntegerField(
        participant,
        'rosterPosition',
        participantObjectPath,
    );

    return {
        trusteeIdentity: nonEmptyStringField(
            participant,
            'trusteeIdentity',
            participantObjectPath,
        ),
        rosterPosition,
        interpolationPoint: rosterPosition + 1,
    };
};

const compactAggregateRecordKey = (
    recipientIdentity: string,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): string =>
    `${recipientIdentity}\u0000${String(recipientRosterPosition)}\u0000${String(rnsLimbIndex)}`;

const compactAggregateRecordsByRecipientLimb = (
    aggregateThresholdCommitmentSet: JsonRecord,
): ReadonlyMap<string, JsonRecord> => {
    const recipientRecords = aggregateThresholdCommitmentSet.recipientRecords;
    if (!Array.isArray(recipientRecords)) {
        throw new Error(
            'setupPackage.compactVssAggregateThresholdCommitmentSet.recipientRecords must be an array.',
        );
    }
    const recordsByRecipientLimb = new Map<string, JsonRecord>();
    recipientRecords.forEach((recordValue, recordIndex) => {
        const objectPath = `setupPackage.compactVssAggregateThresholdCommitmentSet.recipientRecords.${String(recordIndex)}`;
        const record = jsonRecord(recordValue, objectPath);
        const recipientIdentity = nonEmptyStringField(
            record,
            'recipientIdentity',
            objectPath,
        );
        const recipientRosterPosition = nonNegativeIntegerField(
            record,
            'recipientRosterPosition',
            objectPath,
        );
        const rnsLimbIndex = nonNegativeIntegerField(
            record,
            'rnsLimbIndex',
            objectPath,
        );
        protocolHashField(record, 'aggregateCommitmentRoot', objectPath);
        protocolHashField(record, 'aggregateOpeningRoot', objectPath);
        const recordKey = compactAggregateRecordKey(
            recipientIdentity,
            recipientRosterPosition,
            rnsLimbIndex,
        );
        if (recordsByRecipientLimb.has(recordKey)) {
            throw new Error(
                'setupPackage.compactVssAggregateThresholdCommitmentSet must contain at most one record per recipient limb.',
            );
        }
        recordsByRecipientLimb.set(recordKey, record);
    });

    return recordsByRecipientLimb;
};

const assertRestoredCompactAggregateOpeningBinding = (input: {
    readonly restoredLocalTargetShareWitness: JsonRecord;
    readonly setupPackage: JsonRecord;
    readonly targetAcceptedRecord: JsonRecord;
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
}): void => {
    const compactAggregateOpening = jsonRecord(
        input.restoredLocalTargetShareWitness.compactAggregateOpening,
        'restoredLocalTargetShareWitness.compactAggregateOpening',
    );
    exactStringField(
        compactAggregateOpening,
        'objectType',
        'LocalTrusteeCompactVssAggregateOpeningWitness',
        'restoredLocalTargetShareWitness.compactAggregateOpening',
    );
    exactVersionField(
        compactAggregateOpening,
        'objectVersion',
        1,
        'restoredLocalTargetShareWitness.compactAggregateOpening',
    );

    const commonRandomness = jsonRecord(
        input.setupPackage.commonRandomness,
        'setupPackage.commonRandomness',
    );
    compareProtocolHashField(
        compactAggregateOpening,
        'publicMatrixSeedHash',
        protocolHashField(
            commonRandomness,
            'publicMatrixSeedHash',
            'setupPackage.commonRandomness',
        ),
        'restoredLocalTargetShareWitness.compactAggregateOpening',
        'setupPackage.commonRandomness.publicMatrixSeedHash',
    );
    compareProtocolHashField(
        compactAggregateOpening,
        'targetBasisHash',
        protocolHashField(
            input.targetAcceptedRecord,
            'targetBasisHash',
            'targetAcceptedRecord',
        ),
        'restoredLocalTargetShareWitness.compactAggregateOpening',
        'targetAcceptedRecord.targetBasisHash',
    );

    const shareLinkageStatement = jsonRecord(
        input.setupPackage.compactVssShareLinkageStatement,
        'setupPackage.compactVssShareLinkageStatement',
    );
    compareProtocolHashField(
        compactAggregateOpening,
        'shareLinkageStatementRoot',
        protocolHashField(
            shareLinkageStatement,
            'statementRoot',
            'setupPackage.compactVssShareLinkageStatement',
        ),
        'restoredLocalTargetShareWitness.compactAggregateOpening',
        'setupPackage.compactVssShareLinkageStatement.statementRoot',
    );

    const aggregateThresholdCommitmentSet = jsonRecord(
        input.setupPackage.compactVssAggregateThresholdCommitmentSet,
        'setupPackage.compactVssAggregateThresholdCommitmentSet',
    );
    compareProtocolHashField(
        compactAggregateOpening,
        'aggregateThresholdCommitmentRoot',
        protocolHashField(
            aggregateThresholdCommitmentSet,
            'aggregateThresholdCommitmentRoot',
            'setupPackage.compactVssAggregateThresholdCommitmentSet',
        ),
        'restoredLocalTargetShareWitness.compactAggregateOpening',
        'setupPackage.compactVssAggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot',
    );

    const compactAggregateOpeningCredentials =
        compactAggregateOpening.compactAggregateOpeningCredentials;
    if (
        !Array.isArray(compactAggregateOpeningCredentials) ||
        compactAggregateOpeningCredentials.length === 0
    ) {
        throw new Error(
            'restoredLocalTargetShareWitness.compactAggregateOpening.compactAggregateOpeningCredentials must be a non-empty array.',
        );
    }
    const acceptedRecordsByRecipientLimb =
        compactAggregateRecordsByRecipientLimb(aggregateThresholdCommitmentSet);
    const seenCredentialKeys = new Set<string>();
    compactAggregateOpeningCredentials.forEach(
        (credentialValue, credentialIndex) => {
            const objectPath = `restoredLocalTargetShareWitness.compactAggregateOpening.compactAggregateOpeningCredentials.${String(credentialIndex)}`;
            const credential = jsonRecord(credentialValue, objectPath);
            exactStringField(
                credential,
                'objectType',
                'LocalTrusteeCompactVssAggregateOpeningCredential',
                objectPath,
            );
            exactVersionField(credential, 'objectVersion', 1, objectPath);
            const recipientIdentity = nonEmptyStringField(
                credential,
                'recipientIdentity',
                objectPath,
            );
            const recipientRosterPosition = nonNegativeIntegerField(
                credential,
                'recipientRosterPosition',
                objectPath,
            );
            if (
                recipientIdentity !== input.trusteeIdentity ||
                recipientRosterPosition !== input.rosterPosition
            ) {
                throw new Error(
                    `${objectPath} must belong to the target-decryption trustee.`,
                );
            }
            const rnsLimbIndex = nonNegativeIntegerField(
                credential,
                'rnsLimbIndex',
                objectPath,
            );
            const credentialKey = compactAggregateRecordKey(
                recipientIdentity,
                recipientRosterPosition,
                rnsLimbIndex,
            );
            if (seenCredentialKeys.has(credentialKey)) {
                throw new Error(
                    'restored compact aggregate opening credentials must contain at most one credential per recipient limb.',
                );
            }
            seenCredentialKeys.add(credentialKey);
            const acceptedRecord =
                acceptedRecordsByRecipientLimb.get(credentialKey);
            if (acceptedRecord === undefined) {
                throw new Error(
                    `${objectPath} must match an accepted compact aggregate commitment record.`,
                );
            }
            const rnsPrime = nonNegativeIntegerField(
                credential,
                'rnsPrime',
                objectPath,
            );
            if (
                rnsPrime !==
                nonNegativeIntegerField(
                    acceptedRecord,
                    'rnsPrime',
                    'setupPackage.compactVssAggregateThresholdCommitmentSet.recipientRecords',
                )
            ) {
                throw new Error(
                    `${objectPath}.rnsPrime must match the accepted compact aggregate commitment record.`,
                );
            }
            compareProtocolHashField(
                credential,
                'aggregateCommitmentRoot',
                protocolHashField(
                    acceptedRecord,
                    'aggregateCommitmentRoot',
                    'setupPackage.compactVssAggregateThresholdCommitmentSet.recipientRecords',
                ),
                objectPath,
                'the accepted compact aggregate commitment record',
            );
            compareProtocolHashField(
                credential,
                'aggregateOpeningRoot',
                protocolHashField(
                    acceptedRecord,
                    'aggregateOpeningRoot',
                    'setupPackage.compactVssAggregateThresholdCommitmentSet.recipientRecords',
                ),
                objectPath,
                'the accepted compact aggregate commitment record',
            );
        },
    );
};

export const deriveTargetDecryptionSmudgingSeedHex = (
    input: TargetDecryptionSmudgingSeedDerivationInput,
): string => {
    const bindingHashes = targetBindingHashes(
        input.setupPackage,
        input.targetAcceptedRecord,
        input.targetDecryptionCiphertextHash,
        input.targetShareProfile,
    );

    return hash512Hex(targetDecryptionSmudgingSeedHashDomain, [
        encoded(bindingHashes.setupPackageHash),
        encoded(bindingHashes.targetAcceptedRecordHash),
        encoded(bindingHashes.targetContextHash),
        encoded(bindingHashes.targetCiphertextHash),
        encoded(bindingHashes.targetDecryptionCiphertextHash),
        encoded(bindingHashes.targetShareProfileHash),
        encoded(bindingHashes.targetBasisHash),
    ]);
};

const createLocalTrusteeTargetDecryptionSmudgingWitness = (
    input: LocalTargetDecryptionShareWitnessPreparationInput,
): LocalTrusteeTargetDecryptionSmudgingWitness => {
    const trusteeIdentity = input.trusteeIdentity;
    if (trusteeIdentity.length === 0) {
        throw new Error('trusteeIdentity must not be empty.');
    }
    const participant = setupParticipant(input.setupPackage, trusteeIdentity);
    const bindingHashes = targetBindingHashes(
        input.setupPackage,
        input.targetAcceptedRecord,
        input.targetDecryptionCiphertextHash,
        input.targetShareProfile,
    );

    return {
        objectType: 'LocalTrusteeTargetDecryptionSmudgingWitness',
        objectVersion: 1,
        profileId: targetDecryptionSmudgingProfileId,
        setupPackageHash: bindingHashes.setupPackageHash,
        targetAcceptedRecordHash: bindingHashes.targetAcceptedRecordHash,
        targetContextHash: bindingHashes.targetContextHash,
        targetCiphertextHash: bindingHashes.targetCiphertextHash,
        targetDecryptionCiphertextHash:
            bindingHashes.targetDecryptionCiphertextHash,
        targetShareProfileHash: bindingHashes.targetShareProfileHash,
        targetBasisHash: bindingHashes.targetBasisHash,
        trusteeIdentity: participant.trusteeIdentity,
        rosterPosition: participant.rosterPosition,
        interpolationPoint: participant.interpolationPoint,
        plaintextMultiple: targetDecryptionPlaintextMultiple,
    };
};

export const prepareLocalTargetDecryptionShareWitness = (
    input: LocalTargetDecryptionShareWitnessPreparationInput,
): PreparedLocalTargetDecryptionShareWitness => {
    const restoredLocalTargetShareWitness = jsonRecord(
        input.restoredLocalTargetShareWitness,
        'restoredLocalTargetShareWitness',
    );
    if (
        restoredLocalTargetShareWitness.targetDecryptionSmudging !== undefined
    ) {
        throw new Error(
            'restoredLocalTargetShareWitness already contains target-decryption smudging material.',
        );
    }
    jsonRecord(
        restoredLocalTargetShareWitness.compactAggregateOpening,
        'restoredLocalTargetShareWitness.compactAggregateOpening',
    );
    const witnessTrusteeIdentity = nonEmptyStringField(
        restoredLocalTargetShareWitness,
        'trusteeIdentity',
        'restoredLocalTargetShareWitness',
    );
    if (witnessTrusteeIdentity !== input.trusteeIdentity) {
        throw new Error(
            'restoredLocalTargetShareWitness trustee identity must match the target-decryption trustee.',
        );
    }
    const witnessRosterPosition = nonNegativeIntegerField(
        restoredLocalTargetShareWitness,
        'trusteeRosterPosition',
        'restoredLocalTargetShareWitness',
    );
    const participant = setupParticipant(
        input.setupPackage,
        input.trusteeIdentity,
    );
    if (witnessRosterPosition !== participant.rosterPosition) {
        throw new Error(
            'restoredLocalTargetShareWitness roster position must match the setup package trustee.',
        );
    }
    assertRestoredCompactAggregateOpeningBinding({
        restoredLocalTargetShareWitness,
        setupPackage: jsonRecord(input.setupPackage, 'setupPackage'),
        targetAcceptedRecord: jsonRecord(
            input.targetAcceptedRecord,
            'targetAcceptedRecord',
        ),
        trusteeIdentity: input.trusteeIdentity,
        rosterPosition: participant.rosterPosition,
    });

    return {
        ...restoredLocalTargetShareWitness,
        targetDecryptionSmudging:
            createLocalTrusteeTargetDecryptionSmudgingWitness(input),
    };
};
