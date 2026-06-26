import { hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    isProtocolHashString,
    isRecord,
} from '../common/verification-helpers.js';

type JsonRecord = Record<string, unknown>;

export const targetDecryptionSmudgingProfileId =
    'sealed-lattice-target-decryption-zero-share-smudging-development-v1';
export const targetDecryptionSmudgingSeedHashDomain =
    'sealed-lattice-bgv-rns/target-decryption-smudging-seed-v1';
export const targetDecryptionPlaintextMultiple = 65_537;

const textEncoder = new TextEncoder();

export type TargetDecryptionSmudgingSeedDerivationInput = Readonly<{
    readonly localSmudgingSeedMaterial: string;
    readonly setupPackage: unknown;
    readonly targetAcceptedRecord: unknown;
    readonly targetDecryptionCiphertextHash: ProtocolHash;
    readonly targetShareProfile: unknown;
}>;

export type LocalTrusteeTargetDecryptionSmudgingWitness = Readonly<
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
        readonly smudgingSeedHex: string;
    }
>;

export type LocalTargetDecryptionShareWitnessPreparationInput = Readonly<{
    readonly restoredLocalTargetShareWitness: unknown;
    readonly setupPackage: unknown;
    readonly targetAcceptedRecord: unknown;
    readonly targetDecryptionCiphertextHash: ProtocolHash;
    readonly targetShareProfile: unknown;
    readonly trusteeIdentity: string;
    readonly localSmudgingSeedMaterial: string;
}>;

export type PreparedLocalTargetDecryptionShareWitness = Readonly<
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

const validateSmudgingSeedHex = (value: string): void => {
    if (!/^[0-9a-f]{128}$/u.test(value)) {
        throw new Error(
            'target-decryption smudging seed must be a 64-byte lowercase hexadecimal value.',
        );
    }
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

export const deriveTargetDecryptionSmudgingSeedHex = (
    input: TargetDecryptionSmudgingSeedDerivationInput,
): string => {
    if (input.localSmudgingSeedMaterial.length === 0) {
        throw new Error('localSmudgingSeedMaterial must not be empty.');
    }
    const bindingHashes = targetBindingHashes(
        input.setupPackage,
        input.targetAcceptedRecord,
        input.targetDecryptionCiphertextHash,
        input.targetShareProfile,
    );

    return hash512Hex(targetDecryptionSmudgingSeedHashDomain, [
        encoded(input.localSmudgingSeedMaterial),
        encoded(bindingHashes.setupPackageHash),
        encoded(bindingHashes.targetAcceptedRecordHash),
        encoded(bindingHashes.targetContextHash),
        encoded(bindingHashes.targetCiphertextHash),
        encoded(bindingHashes.targetDecryptionCiphertextHash),
        encoded(bindingHashes.targetShareProfileHash),
        encoded(bindingHashes.targetBasisHash),
    ]);
};

export const createLocalTrusteeTargetDecryptionSmudgingWitness = (
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
    const smudgingSeedHex = deriveTargetDecryptionSmudgingSeedHex(input);
    validateSmudgingSeedHex(smudgingSeedHex);

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
        smudgingSeedHex,
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

    return {
        ...restoredLocalTargetShareWitness,
        targetDecryptionSmudging:
            createLocalTrusteeTargetDecryptionSmudgingWitness(input),
    };
};
