import {
    decryptLocalTrusteeSetupSealedMaterial,
    decryptLocalTrusteeState,
    deriveCanonicalObjectHash,
    hash512Hex,
    type EncryptedLocalTrusteeSetupState,
    type LocalTrusteeSetupSealedMaterialDecryptionInput,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    isProtocolHashString,
    isRecord,
} from '../common/verification-helpers.js';
import { bytesFromHex } from '../setup/common-fields.js';
import type { CollectiveBgvSetupContext } from '../setup/vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

const targetDecryptionSmudgingProfileId =
    'sealed-lattice-target-decryption-zero-share-smudging';
const targetDecryptionSmudgingSeedHashDomain =
    'sealed-lattice-bgv-rns/target-decryption-smudging-seed';
const targetDecryptionPlaintextMultiple = 65_537;
const maximumAggregateOpeningCredentialCount = 17;
const maximumAggregateOpeningRingDegree = 32_768;

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

export type TargetDecryptionAggregateOpeningMaterialSource = Readonly<{
    readonly aggregateOpeningRoot: ProtocolHash;
    readonly totalByteLength: number;
    readonly pullChunk: (input: {
        readonly abortSignal?: AbortSignal;
        readonly chunkIndex: number;
        readonly expectedByteLength: number;
    }) => Promise<ArrayBuffer | undefined>;
}>;

export type PreparedLocalTargetDecryptionShareWitness = Readonly<{
    readonly aggregateOpeningMaterialSources: readonly TargetDecryptionAggregateOpeningMaterialSource[];
    readonly localTargetShareWitness: Readonly<
        JsonRecord & {
            readonly targetDecryptionSmudging: LocalTrusteeTargetDecryptionSmudgingWitness;
        }
    >;
}>;

export type RestoredLocalTargetDecryptionShareWitnessInput = Readonly<{
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly expectedLocalStateRoot: ProtocolHash;
    readonly setupContext: CollectiveBgvSetupContext;
    readonly storageKeyBytesHex: string;
    readonly setupPackage: unknown;
    readonly targetAcceptedRecord: unknown;
    readonly targetDecryptionCiphertextHash: ProtocolHash;
    readonly targetShareProfile: unknown;
}>;

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
        setupPackageHash: deriveCanonicalObjectHash(setupPackage),
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
    const aggregateThresholdCommitmentSet = jsonRecord(
        setupPackage.vssPublicAggregateThresholdCommitmentSet,
        'setupPackage.vssPublicAggregateThresholdCommitmentSet',
    );
    const recipientRecords = aggregateThresholdCommitmentSet.recipientRecords;
    if (!Array.isArray(recipientRecords)) {
        throw new Error(
            'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords must be an array.',
        );
    }
    const matchingRecipientRecords = recipientRecords
        .map((recipientRecord, recipientRecordIndex) =>
            jsonRecord(
                recipientRecord,
                `setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords.${String(recipientRecordIndex)}`,
            ),
        )
        .filter(
            (recipientRecord) =>
                recipientRecord.recipientIdentity === trusteeIdentity,
        );
    const participant = matchingRecipientRecords[0];
    if (participant === undefined) {
        throw new Error(
            'setupPackage.vssPublicAggregateThresholdCommitmentSet must contain the trustee.',
        );
    }
    const participantObjectPath =
        'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords.trustee';
    const rosterPosition = nonNegativeIntegerField(
        participant,
        'recipientRosterPosition',
        participantObjectPath,
    );
    matchingRecipientRecords.forEach((recipientRecord) => {
        if (
            nonNegativeIntegerField(
                recipientRecord,
                'recipientRosterPosition',
                participantObjectPath,
            ) !== rosterPosition
        ) {
            throw new Error(
                'setup package aggregate records must use one roster position per trustee identity.',
            );
        }
    });

    return {
        trusteeIdentity: nonEmptyStringField(
            participant,
            'recipientIdentity',
            participantObjectPath,
        ),
        rosterPosition,
        interpolationPoint: rosterPosition + 1,
    };
};

const aggregateRecordKey = (
    recipientIdentity: string,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): string =>
    `${recipientIdentity}\u0000${String(recipientRosterPosition)}\u0000${String(rnsLimbIndex)}`;

const aggregateRecordsByRecipientLimb = (
    aggregateThresholdCommitmentSet: JsonRecord,
): ReadonlyMap<string, JsonRecord> => {
    const recipientRecords = aggregateThresholdCommitmentSet.recipientRecords;
    if (!Array.isArray(recipientRecords)) {
        throw new Error(
            'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords must be an array.',
        );
    }
    const recordsByRecipientLimb = new Map<string, JsonRecord>();
    recipientRecords.forEach((recordValue, recordIndex) => {
        const objectPath = `setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords.${String(recordIndex)}`;
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
        const recordKey = aggregateRecordKey(
            recipientIdentity,
            recipientRosterPosition,
            rnsLimbIndex,
        );
        if (recordsByRecipientLimb.has(recordKey)) {
            throw new Error(
                'setupPackage.vssPublicAggregateThresholdCommitmentSet must contain at most one record per recipient limb.',
            );
        }
        recordsByRecipientLimb.set(recordKey, record);
    });

    return recordsByRecipientLimb;
};

const assertRestoredAggregateOpeningBinding = (input: {
    readonly restoredLocalTargetShareWitness: JsonRecord;
    readonly setupPackage: JsonRecord;
    readonly targetAcceptedRecord: JsonRecord;
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
}): number => {
    const aggregateOpening = jsonRecord(
        input.restoredLocalTargetShareWitness.aggregateOpening,
        'restoredLocalTargetShareWitness.aggregateOpening',
    );
    exactStringField(
        aggregateOpening,
        'objectType',
        'LocalTrusteeVssPublicAggregateOpeningWitness',
        'restoredLocalTargetShareWitness.aggregateOpening',
    );

    const commonRandomness = jsonRecord(
        input.setupPackage.commonRandomness,
        'setupPackage.commonRandomness',
    );
    compareProtocolHashField(
        aggregateOpening,
        'publicMatrixSeedHash',
        protocolHashField(
            commonRandomness,
            'publicMatrixSeedHash',
            'setupPackage.commonRandomness',
        ),
        'restoredLocalTargetShareWitness.aggregateOpening',
        'setupPackage.commonRandomness.publicMatrixSeedHash',
    );
    compareProtocolHashField(
        aggregateOpening,
        'targetBasisHash',
        protocolHashField(
            input.targetAcceptedRecord,
            'targetBasisHash',
            'targetAcceptedRecord',
        ),
        'restoredLocalTargetShareWitness.aggregateOpening',
        'targetAcceptedRecord.targetBasisHash',
    );

    const shareLinkageStatement = jsonRecord(
        input.setupPackage.vssShareLinkageStatement,
        'setupPackage.vssShareLinkageStatement',
    );
    compareProtocolHashField(
        aggregateOpening,
        'shareLinkageStatementRoot',
        protocolHashField(
            shareLinkageStatement,
            'statementRoot',
            'setupPackage.vssShareLinkageStatement',
        ),
        'restoredLocalTargetShareWitness.aggregateOpening',
        'setupPackage.vssShareLinkageStatement.statementRoot',
    );

    const aggregateThresholdCommitmentSet = jsonRecord(
        input.setupPackage.vssPublicAggregateThresholdCommitmentSet,
        'setupPackage.vssPublicAggregateThresholdCommitmentSet',
    );
    compareProtocolHashField(
        aggregateOpening,
        'aggregateThresholdCommitmentRoot',
        protocolHashField(
            aggregateThresholdCommitmentSet,
            'aggregateThresholdCommitmentRoot',
            'setupPackage.vssPublicAggregateThresholdCommitmentSet',
        ),
        'restoredLocalTargetShareWitness.aggregateOpening',
        'setupPackage.vssPublicAggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot',
    );

    const aggregateOpeningCredentials =
        aggregateOpening.aggregateOpeningCredentials;
    if (
        !Array.isArray(aggregateOpeningCredentials) ||
        aggregateOpeningCredentials.length === 0
    ) {
        throw new Error(
            'restoredLocalTargetShareWitness.aggregateOpening.aggregateOpeningCredentials must be a non-empty array.',
        );
    }
    if (
        aggregateOpeningCredentials.length >
        maximumAggregateOpeningCredentialCount
    ) {
        throw new Error(
            'restoredLocalTargetShareWitness aggregate opening credential count exceeds the supported RNS basis.',
        );
    }
    const ringDegree = nonNegativeIntegerField(
        aggregateThresholdCommitmentSet,
        'ringDegree',
        'setupPackage.vssPublicAggregateThresholdCommitmentSet',
    );
    if (ringDegree === 0 || ringDegree > maximumAggregateOpeningRingDegree) {
        throw new Error(
            'setupPackage.vssPublicAggregateThresholdCommitmentSet.ringDegree must be inside the supported target-decryption ring bound.',
        );
    }
    const acceptedRecordsByRecipientLimb = aggregateRecordsByRecipientLimb(
        aggregateThresholdCommitmentSet,
    );
    const seenCredentialKeys = new Set<string>();
    aggregateOpeningCredentials.forEach((credentialValue, credentialIndex) => {
        const objectPath = `restoredLocalTargetShareWitness.aggregateOpening.aggregateOpeningCredentials.${String(credentialIndex)}`;
        const credential = jsonRecord(credentialValue, objectPath);
        exactStringField(
            credential,
            'objectType',
            'LocalTrusteeVssPublicAggregateOpeningCredential',
            objectPath,
        );
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
        if (
            nonNegativeIntegerField(
                credential,
                'recipientTrusteePoint',
                objectPath,
            ) !==
            input.rosterPosition + 1
        ) {
            throw new Error(
                `${objectPath}.recipientTrusteePoint must match the target-decryption trustee interpolation point.`,
            );
        }
        const rnsLimbIndex = nonNegativeIntegerField(
            credential,
            'rnsLimbIndex',
            objectPath,
        );
        const credentialKey = aggregateRecordKey(
            recipientIdentity,
            recipientRosterPosition,
            rnsLimbIndex,
        );
        if (seenCredentialKeys.has(credentialKey)) {
            throw new Error(
                'restored aggregate opening credentials must contain at most one credential per recipient limb.',
            );
        }
        seenCredentialKeys.add(credentialKey);
        const acceptedRecord =
            acceptedRecordsByRecipientLimb.get(credentialKey);
        if (acceptedRecord === undefined) {
            throw new Error(
                `${objectPath} must match an accepted aggregate commitment record.`,
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
                'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords',
            )
        ) {
            throw new Error(
                `${objectPath}.rnsPrime must match the accepted aggregate commitment record.`,
            );
        }
        compareProtocolHashField(
            credential,
            'aggregateCommitmentRoot',
            protocolHashField(
                acceptedRecord,
                'aggregateCommitmentRoot',
                'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords',
            ),
            objectPath,
            'the accepted aggregate commitment record',
        );
        compareProtocolHashField(
            credential,
            'aggregateOpeningRoot',
            protocolHashField(
                acceptedRecord,
                'aggregateOpeningRoot',
                'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords',
            ),
            objectPath,
            'the accepted aggregate commitment record',
        );
    });

    return ringDegree;
};

const prepareAggregateOpeningMaterial = (input: {
    readonly credential: JsonRecord;
    readonly credentialIndex: number;
    readonly ringDegree: number;
}): Readonly<{
    readonly credential: JsonRecord;
    readonly source: TargetDecryptionAggregateOpeningMaterialSource;
}> => {
    const objectPath = `restoredLocalTargetShareWitness.aggregateOpening.aggregateOpeningCredentials.${String(input.credentialIndex)}`;
    const aggregateOpeningRoot = protocolHashField(
        input.credential,
        'aggregateOpeningRoot',
        objectPath,
    );
    const messageHex = nonEmptyStringField(
        input.credential,
        'aggregateCommitmentMessageValuesLeHex',
        objectPath,
    );
    const expectedByteLength = input.ringDegree * 8;
    if (
        !Number.isSafeInteger(expectedByteLength) ||
        expectedByteLength > maximumAggregateOpeningRingDegree * 8 ||
        messageHex.length !== expectedByteLength * 2
    ) {
        throw new Error(
            `${objectPath}.aggregateCommitmentMessageValuesLeHex must encode exactly ringDegree little-endian u64 values.`,
        );
    }
    const messageBytes = bytesFromHex(
        messageHex,
        `${objectPath}.aggregateCommitmentMessageValuesLeHex`,
    );

    const {
        aggregateCommitmentMessageValuesLeHex: _removedInlineMessage,
        ...credential
    } = input.credential;
    const source: TargetDecryptionAggregateOpeningMaterialSource = {
        aggregateOpeningRoot,
        totalByteLength: messageBytes.byteLength,
        pullChunk: ({
            abortSignal,
            chunkIndex,
            expectedByteLength: requestedByteLength,
        }): Promise<ArrayBuffer | undefined> => {
            if (abortSignal?.aborted === true) {
                return Promise.reject(
                    new Error(
                        'Aggregate opening material transport was cancelled.',
                    ),
                );
            }
            if (chunkIndex === 0) {
                if (requestedByteLength !== messageBytes.byteLength) {
                    return Promise.reject(
                        new Error(
                            'Aggregate opening material transport requested a non-canonical chunk length.',
                        ),
                    );
                }
                return Promise.resolve(messageBytes.slice().buffer);
            }
            if (chunkIndex === 1 && requestedByteLength === 0) {
                return Promise.resolve(undefined);
            }
            return Promise.reject(
                new Error(
                    'Aggregate opening material transport requested a non-canonical chunk index.',
                ),
            );
        },
    };

    return { credential, source };
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
        restoredLocalTargetShareWitness.aggregateOpening,
        'restoredLocalTargetShareWitness.aggregateOpening',
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
    const ringDegree = assertRestoredAggregateOpeningBinding({
        restoredLocalTargetShareWitness,
        setupPackage: jsonRecord(input.setupPackage, 'setupPackage'),
        targetAcceptedRecord: jsonRecord(
            input.targetAcceptedRecord,
            'targetAcceptedRecord',
        ),
        trusteeIdentity: input.trusteeIdentity,
        rosterPosition: participant.rosterPosition,
    });
    const restoredAggregateOpening = jsonRecord(
        restoredLocalTargetShareWitness.aggregateOpening,
        'restoredLocalTargetShareWitness.aggregateOpening',
    );
    const preparedAggregateOpeningMaterials = (
        restoredAggregateOpening.aggregateOpeningCredentials as readonly unknown[]
    ).map((credentialValue, credentialIndex) =>
        prepareAggregateOpeningMaterial({
            credential: jsonRecord(
                credentialValue,
                `restoredLocalTargetShareWitness.aggregateOpening.aggregateOpeningCredentials.${String(credentialIndex)}`,
            ),
            credentialIndex,
            ringDegree,
        }),
    );
    const localTargetShareWitness = {
        ...restoredLocalTargetShareWitness,
        aggregateOpening: {
            ...restoredAggregateOpening,
            aggregateOpeningCredentials: preparedAggregateOpeningMaterials.map(
                (prepared) => prepared.credential,
            ),
        },
        targetDecryptionSmudging:
            createLocalTrusteeTargetDecryptionSmudgingWitness(input),
    };

    return {
        aggregateOpeningMaterialSources: preparedAggregateOpeningMaterials.map(
            (prepared) => prepared.source,
        ),
        localTargetShareWitness,
    };
};

const assertRestoredSetupContext = (
    expectedContext: CollectiveBgvSetupContext,
    setupPackage: JsonRecord,
    aggregateThresholdShareMaterial: JsonRecord,
): void => {
    const setupPackageContext = jsonRecord(
        setupPackage.setupContext,
        'setupPackage.setupContext',
    );
    for (const fieldName of ['ceremonyId', 'setupEpoch'] as const) {
        const expectedValue = expectedContext[fieldName];
        if (
            nonEmptyStringField(
                setupPackageContext,
                fieldName,
                'setupPackage.setupContext',
            ) !== expectedValue ||
            nonEmptyStringField(
                aggregateThresholdShareMaterial,
                fieldName,
                'aggregateThresholdShareMaterial',
            ) !== expectedValue
        ) {
            throw new Error(
                `${fieldName} must match across the restored local state and setup package.`,
            );
        }
    }
    for (const fieldName of [
        'manifestHash',
        'rosterHash',
        'setupParametersHash',
    ] as const) {
        const expectedValue = expectedContext[fieldName];
        if (
            protocolHashField(
                setupPackageContext,
                fieldName,
                'setupPackage.setupContext',
            ) !== expectedValue ||
            protocolHashField(
                aggregateThresholdShareMaterial,
                fieldName,
                'aggregateThresholdShareMaterial',
            ) !== expectedValue
        ) {
            throw new Error(
                `${fieldName} must match across the restored local state and setup package.`,
            );
        }
    }
};

export const restoreAndPrepareLocalTargetDecryptionShareWitness = async (
    input: RestoredLocalTargetDecryptionShareWitnessInput,
): Promise<PreparedLocalTargetDecryptionShareWitness> => {
    const restoredLocalState = await decryptLocalTrusteeState({
        encryptedLocalState: input.encryptedLocalState,
        expectedLocalStateRoot: input.expectedLocalStateRoot,
        setupContext: input.setupContext,
        storageKeyBytesHex: input.storageKeyBytesHex,
    });
    const storageAad = jsonRecord(
        input.encryptedLocalState.storageAad,
        'encryptedLocalState.storageAad',
    );
    const localStateCommitment = jsonRecord(
        storageAad.localStateCommitment,
        'encryptedLocalState.storageAad.localStateCommitment',
    ) as LocalTrusteeSetupSealedMaterialDecryptionInput['localStateCommitment'];
    const aggregateThresholdShareRoot = protocolHashField(
        localStateCommitment,
        'aggregateThresholdShareRoot',
        'encryptedLocalState.storageAad.localStateCommitment',
    );
    const restoredAggregateThresholdShare =
        await decryptLocalTrusteeSetupSealedMaterial({
            sealedMaterial:
                restoredLocalState.localStatePlaintext
                    .sealedAggregateThresholdShare,
            expectedMaterialRoot: aggregateThresholdShareRoot,
            localStateCommitment,
            setupContext: input.setupContext,
            storageKeyBytesHex: input.storageKeyBytesHex,
        });
    const aggregateThresholdShareMaterial = jsonRecord(
        restoredAggregateThresholdShare.materialPlaintext,
        'aggregateThresholdShareMaterial',
    );
    exactStringField(
        aggregateThresholdShareMaterial,
        'objectType',
        'LocalTrusteeAggregateThresholdShareMaterial',
        'aggregateThresholdShareMaterial',
    );
    const setupPackage = jsonRecord(input.setupPackage, 'setupPackage');
    assertRestoredSetupContext(
        input.setupContext,
        setupPackage,
        aggregateThresholdShareMaterial,
    );
    const trusteeIdentity = nonEmptyStringField(
        aggregateThresholdShareMaterial,
        'trusteeIdentity',
        'aggregateThresholdShareMaterial',
    );
    const trusteeRosterPosition = nonNegativeIntegerField(
        aggregateThresholdShareMaterial,
        'trusteeRosterPosition',
        'aggregateThresholdShareMaterial',
    );
    const participant = setupParticipant(setupPackage, trusteeIdentity);
    if (participant.rosterPosition !== trusteeRosterPosition) {
        throw new Error(
            'restored aggregate threshold share roster position must match the supplied setup package.',
        );
    }
    compareProtocolHashField(
        aggregateThresholdShareMaterial,
        'thresholdShareCommitmentRecipientRoot',
        protocolHashField(
            restoredLocalState.localStatePlaintext,
            'thresholdShareCommitmentRecipientRoot',
            'localStatePlaintext',
        ),
        'aggregateThresholdShareMaterial',
        'the restored local state threshold-share commitment root',
    );
    const aggregateOpeningCredentialHandoff = jsonRecord(
        aggregateThresholdShareMaterial.aggregateOpeningCredentialHandoff,
        'aggregateThresholdShareMaterial.aggregateOpeningCredentialHandoff',
    );
    exactStringField(
        aggregateOpeningCredentialHandoff,
        'objectType',
        'LocalTrusteeVssPublicAggregateOpeningCredentialHandoff',
        'aggregateThresholdShareMaterial.aggregateOpeningCredentialHandoff',
    );
    if (
        nonEmptyStringField(
            aggregateOpeningCredentialHandoff,
            'trusteeIdentity',
            'aggregateThresholdShareMaterial.aggregateOpeningCredentialHandoff',
        ) !== trusteeIdentity ||
        nonNegativeIntegerField(
            aggregateOpeningCredentialHandoff,
            'trusteeRosterPosition',
            'aggregateThresholdShareMaterial.aggregateOpeningCredentialHandoff',
        ) !== trusteeRosterPosition
    ) {
        throw new Error(
            'restored aggregate opening credential handoff must belong to the local trustee.',
        );
    }

    const commonRandomness = jsonRecord(
        setupPackage.commonRandomness,
        'setupPackage.commonRandomness',
    );
    const shareLinkageStatement = jsonRecord(
        setupPackage.vssShareLinkageStatement,
        'setupPackage.vssShareLinkageStatement',
    );
    const aggregateThresholdCommitmentSet = jsonRecord(
        setupPackage.vssPublicAggregateThresholdCommitmentSet,
        'setupPackage.vssPublicAggregateThresholdCommitmentSet',
    );
    const targetAcceptedRecord = jsonRecord(
        input.targetAcceptedRecord,
        'targetAcceptedRecord',
    );
    const restoredLocalTargetShareWitness = {
        objectType: 'LocalTrusteeTargetDecryptionProofWitnessMaterial',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
        setupEpoch: input.setupContext.setupEpoch,
        trusteeIdentity,
        trusteeRosterPosition,
        aggregateOpening: {
            objectType: 'LocalTrusteeVssPublicAggregateOpeningWitness',
            publicMatrixSeedHash: protocolHashField(
                commonRandomness,
                'publicMatrixSeedHash',
                'setupPackage.commonRandomness',
            ),
            targetBasisHash: protocolHashField(
                targetAcceptedRecord,
                'targetBasisHash',
                'targetAcceptedRecord',
            ),
            shareLinkageStatementRoot: protocolHashField(
                shareLinkageStatement,
                'statementRoot',
                'setupPackage.vssShareLinkageStatement',
            ),
            aggregateThresholdCommitmentRoot: protocolHashField(
                aggregateThresholdCommitmentSet,
                'aggregateThresholdCommitmentRoot',
                'setupPackage.vssPublicAggregateThresholdCommitmentSet',
            ),
            aggregateOpeningCredentials:
                aggregateOpeningCredentialHandoff.aggregateOpeningCredentials,
        },
    };

    return prepareLocalTargetDecryptionShareWitness({
        restoredLocalTargetShareWitness,
        setupPackage,
        targetAcceptedRecord,
        targetDecryptionCiphertextHash: input.targetDecryptionCiphertextHash,
        targetShareProfile: input.targetShareProfile,
        trusteeIdentity,
    });
};
