import {
    deriveCanonicalObjectHash,
    deriveLocalTrusteeSetupStateCommitmentRoot,
    encryptLocalTrusteeSetupSealedMaterial,
    encryptLocalTrusteeState,
    type EncryptedLocalTrusteeSetupState,
    type LocalTrusteeSetupStateCommitment as StoredLocalTrusteeSetupStateCommitment,
    type LocalTrusteeSetupStateSealedPayload,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    assertJsonRecord,
    assertJsonRecordArray,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    assertSetupContextHashMatches,
    bytesFromHex,
    deriveCollectiveBgvSetupContextHash,
    type JsonRecord,
} from './common-fields.js';
import type { PrivateVssEnvelopeCommitment } from './private-vss-mailbox-delivery.js';
import type { LocalTrusteeVssPublicAggregateOpeningCredentialHandoff } from './vss-commitments/commitment-sets.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type LocalTrusteeSetupStateCommitmentInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
    readonly aggregateThresholdShareRoot: ProtocolHash;
};

type LocalTrusteeSetupStateEncryptionInput =
    LocalTrusteeSetupStateCommitmentInput & {
        readonly localStatePlaintext: LocalTrusteeSetupStateSealedPayload;
        readonly storageKeyBytesHex: string;
    };

type LocalTrusteeSetupStateEncryptionResult = Readonly<{
    readonly localStateCommitment: LocalTrusteeSetupStateCommitment;
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
}>;

type GeneratedLocalTrusteeSetupStateInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly participantCount: number;
    readonly thresholdShareCommitments: unknown;
    readonly privateVssEnvelopeCommitments: unknown;
    readonly verifiedPrivateVssShareEnvelopes: readonly unknown[];
    readonly localTrusteeAggregateOpeningCredentialHandoff: LocalTrusteeVssPublicAggregateOpeningCredentialHandoff;
    readonly storageKeyBytesHex: string;
}>;

type GeneratedLocalTrusteeSetupStateResult =
    LocalTrusteeSetupStateEncryptionResult;

export type LocalTrusteeSetupStateCommitment =
    StoredLocalTrusteeSetupStateCommitment;

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

const validateInput = (input: LocalTrusteeSetupStateCommitmentInput): void => {
    assertNonEmptyString(
        input.setupContext.ceremonyId,
        'setupContext.ceremonyId',
    );
    assertNonEmptyString(
        input.setupContext.setupEpoch,
        'setupContext.setupEpoch',
    );
    assertProtocolHash(
        input.setupContext.manifestHash,
        'setupContext.manifestHash',
    );
    assertProtocolHash(
        input.setupContext.rosterHash,
        'setupContext.rosterHash',
    );
    assertProtocolHash(
        input.setupContext.setupParametersHash,
        'setupContext.setupParametersHash',
    );
    assertPositiveSafeInteger(
        input.setupContext.participantCount,
        'setupContext.participantCount',
    );
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
};

export const createLocalTrusteeSetupStateCommitment = (
    input: LocalTrusteeSetupStateCommitmentInput,
): LocalTrusteeSetupStateCommitment => {
    validateInput(input);

    const localStateWithoutRoot = {
        objectType: 'LocalTrusteeSetupStateCommitment',
        setupContextHash: deriveCollectiveBgvSetupContextHash(
            input.setupContext,
        ),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        thresholdShareCommitmentRecipientRoot:
            input.thresholdShareCommitmentRecipientRoot,
        aggregateThresholdShareRoot: input.aggregateThresholdShareRoot,
    } as const satisfies JsonRecord;

    return {
        ...localStateWithoutRoot,
        localStateRoot: deriveLocalTrusteeSetupStateCommitmentRoot(
            localStateWithoutRoot,
        ),
    } satisfies LocalTrusteeSetupStateCommitment;
};

const thresholdShareCommitmentRecipientRoot = (
    input: GeneratedLocalTrusteeSetupStateInput,
): ProtocolHash => {
    const thresholdShareCommitments = assertJsonRecord(
        input.thresholdShareCommitments,
        'thresholdShareCommitments',
    );
    assertSetupContextHashMatches(
        input.setupContext,
        thresholdShareCommitments,
        'thresholdShareCommitments',
    );
    const recipientRecords = assertJsonRecordArray(
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
): readonly PrivateVssEnvelopeCommitment[] => {
    const privateVssEnvelopeCommitments = assertJsonRecord(
        input.privateVssEnvelopeCommitments,
        'privateVssEnvelopeCommitments',
    );
    const participantCount = input.participantCount;
    const envelopeReferences = assertJsonRecordArray(
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
    });

    return envelopeReferences as unknown as readonly PrivateVssEnvelopeCommitment[];
};

type AggregateLimbAccumulator = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    shareValues: bigint[];
};

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
    envelopeReference: PrivateVssEnvelopeCommitment,
): void => {
    assertSetupContextHashMatches(
        setupContext,
        privateEnvelope,
        'privateEnvelope',
    );
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
    envelopeReferences: readonly PrivateVssEnvelopeCommitment[],
): Readonly<{
    readonly aggregateThresholdShareMaterial: JsonRecord;
}> => {
    const privateEnvelopeByHash = new Map<ProtocolHash, JsonRecord>();
    for (const privateEnvelopeValue of input.verifiedPrivateVssShareEnvelopes) {
        const privateEnvelope = assertJsonRecord(
            privateEnvelopeValue,
            'verifiedPrivateVssShareEnvelopes',
        );
        const privateEnvelopeHash = deriveCanonicalObjectHash(privateEnvelope);
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
        const rnsShareOpenings = assertJsonRecordArray(
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
    const aggregateOpeningCredentialHandoff = assertJsonRecord(
        input.localTrusteeAggregateOpeningCredentialHandoff,
        'localTrusteeAggregateOpeningCredentialHandoff',
    );
    if (
        aggregateOpeningCredentialHandoff.objectType !==
        'LocalTrusteeVssPublicAggregateOpeningCredentialHandoff'
    ) {
        throw new TypeError(
            'localTrusteeAggregateOpeningCredentialHandoff.objectType must be LocalTrusteeVssPublicAggregateOpeningCredentialHandoff.',
        );
    }
    if (
        aggregateOpeningCredentialHandoff.trusteeIdentity !==
            input.trusteeIdentity ||
        aggregateOpeningCredentialHandoff.trusteeRosterPosition !==
            input.trusteeRosterPosition
    ) {
        throw new Error(
            'local aggregate opening credential handoff must belong to the local trustee.',
        );
    }
    const aggregateOpeningCredentials = assertJsonRecordArray(
        aggregateOpeningCredentialHandoff.aggregateOpeningCredentials,
        'localTrusteeAggregateOpeningCredentialHandoff.aggregateOpeningCredentials',
    );
    if (aggregateOpeningCredentials.length !== orderedAggregates.length) {
        throw new Error(
            'local aggregate opening credential handoff must contain one credential per aggregate RNS limb.',
        );
    }
    aggregateOpeningCredentials.forEach((credential, credentialIndex) => {
        const objectPath = `localTrusteeAggregateOpeningCredentialHandoff.aggregateOpeningCredentials.${String(credentialIndex)}`;
        const aggregate = orderedAggregates[credentialIndex];
        if (
            aggregate === undefined ||
            credential.objectType !==
                'LocalTrusteeVssPublicAggregateOpeningCredential' ||
            credential.recipientIdentity !== input.trusteeIdentity ||
            credential.recipientRosterPosition !==
                input.trusteeRosterPosition ||
            credential.rnsLimbIndex !== aggregate.rnsLimbIndex ||
            credential.rnsPrime !== aggregate.rnsPrime
        ) {
            throw new Error(
                `${objectPath} must match the local trustee and aggregate RNS limb.`,
            );
        }
        protocolHashField(credential, 'aggregateCommitmentRoot', objectPath);
        protocolHashField(credential, 'aggregateOpeningRoot', objectPath);
        protocolHashField(credential, 'aggregateMaterialSeedHex', objectPath);
        const encodedMessage = stringField(
            credential,
            'aggregateCommitmentMessageValuesLeHex',
            objectPath,
        );
        const messageBytes = bytesFromHex(
            encodedMessage,
            `${objectPath}.aggregateCommitmentMessageValuesLeHex`,
        );
        if (messageBytes.byteLength !== aggregate.shareValues.length * 8) {
            throw new Error(
                `${objectPath}.aggregateCommitmentMessageValuesLeHex must encode the complete aggregate share vector.`,
            );
        }
        const messageView = new DataView(
            messageBytes.buffer,
            messageBytes.byteOffset,
            messageBytes.byteLength,
        );
        aggregate.shareValues.forEach((shareValue, shareValueIndex) => {
            if (
                messageView.getBigUint64(shareValueIndex * 8, true) !==
                shareValue
            ) {
                throw new Error(
                    `${objectPath}.aggregateCommitmentMessageValuesLeHex must match the aggregate of the verified private VSS shares.`,
                );
            }
        });
    });
    return {
        aggregateThresholdShareMaterial: {
            objectType: 'LocalTrusteeAggregateThresholdShareMaterial',
            aggregateOpeningCredentialHandoff:
                input.localTrusteeAggregateOpeningCredentialHandoff,
        },
    };
};

async function encryptLocalTrusteeSetupState(
    input: LocalTrusteeSetupStateEncryptionInput,
): Promise<LocalTrusteeSetupStateEncryptionResult> {
    const localStateCommitment = createLocalTrusteeSetupStateCommitment(input);
    const encryptedLocalState = await encryptLocalTrusteeState({
        localStatePlaintext: input.localStatePlaintext,
        localStateCommitment,
        setupContextHash: deriveCollectiveBgvSetupContextHash(
            input.setupContext,
        ),
        storageKeyBytesHex: input.storageKeyBytesHex,
    });

    return {
        localStateCommitment,
        encryptedLocalState,
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
    assertNonNegativeSafeInteger(input.participantCount, 'participantCount');
    if (input.participantCount === 0) {
        throw new Error('participantCount must be positive.');
    }
    const thresholdShareCommitmentRecipientRootValue =
        thresholdShareCommitmentRecipientRoot(input);
    const envelopeReferences = recipientEnvelopeReferences(input);
    const materialPlaintexts = aggregateVerifiedPrivateVssMaterial(
        input,
        envelopeReferences,
    );
    const sealedAggregateThresholdShare =
        await encryptLocalTrusteeSetupSealedMaterial({
            materialPlaintext:
                materialPlaintexts.aggregateThresholdShareMaterial,
            setupContextHash: deriveCollectiveBgvSetupContextHash(
                input.setupContext,
            ),
            trusteeIdentity: input.trusteeIdentity,
            trusteeRosterPosition: input.trusteeRosterPosition,
            thresholdShareCommitmentRecipientRoot:
                thresholdShareCommitmentRecipientRootValue,
            storageKeyBytesHex: input.storageKeyBytesHex,
        });
    const localStatePlaintext = {
        objectType: 'LocalTrusteeSetupStateSealedPayload',
        sealedAggregateThresholdShare,
    } satisfies LocalTrusteeSetupStateSealedPayload;
    const encryptedLocalState = await encryptLocalTrusteeSetupState({
        setupContext: input.setupContext,
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        thresholdShareCommitmentRecipientRoot:
            thresholdShareCommitmentRecipientRootValue,
        aggregateThresholdShareRoot: sealedAggregateThresholdShare.materialRoot,
        localStatePlaintext,
        storageKeyBytesHex: input.storageKeyBytesHex,
    });

    return encryptedLocalState;
};
