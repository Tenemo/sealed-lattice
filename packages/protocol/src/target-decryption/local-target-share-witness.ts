import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    isProtocolHashString,
    isRecord,
} from '../common/verification-helpers.js';
import type { BrowserActionStorageCustody } from '../runtime/browser-action-storage-custody.js';
import {
    bytesFromHex,
    deriveCollectiveBgvSetupContextHash,
} from '../setup/common-fields.js';
import { decodeAggregateThresholdShareRecord } from '../setup/local-trustee-aggregate-threshold-share-record.js';
import {
    createLocalTrusteeSetupStateCommitment,
    type EncryptedLocalTrusteeSetupState,
    type LocalTrusteeSetupStateCommitment,
} from '../setup/local-trustee-setup-state.js';
import type { CollectiveBgvSetupContext } from '../setup/vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

const maximumAggregateOpeningCredentialCount = 17;
const maximumAggregateOpeningRingDegree = 32_768;

type LocalTargetDecryptionShareWitnessPreparationInput = Readonly<{
    readonly restoredLocalTargetShareWitness: unknown;
    readonly setupPackage: unknown;
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
    readonly localTargetShareWitness: Readonly<JsonRecord>;
}>;

export type RestoredLocalTargetDecryptionShareWitnessInput = Readonly<{
    readonly actionRandomnessCommitment: Uint8Array;
    readonly creationRecoveryEpoch: bigint;
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly localStateCommitment: LocalTrusteeSetupStateCommitment;
    readonly setupContext: CollectiveBgvSetupContext;
    readonly storageCustody: BrowserActionStorageCustody;
    readonly setupPackage: unknown;
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

const qShareRnsLimbCountFromShareLinkageStatement = (
    shareLinkageStatement: JsonRecord,
): number => {
    const qShareRnsLimbCount = nonNegativeIntegerField(
        shareLinkageStatement,
        'qShareRnsLimbCount',
        'setupPackage.vssShareLinkageStatement',
    );
    if (
        qShareRnsLimbCount === 0 ||
        qShareRnsLimbCount > maximumAggregateOpeningCredentialCount
    ) {
        throw new Error(
            'setupPackage.vssShareLinkageStatement.qShareRnsLimbCount must be inside the supported RNS basis.',
        );
    }

    return qShareRnsLimbCount;
};

const setupParticipant = (
    setupPackageValue: unknown,
    trusteeIdentity: string,
): Readonly<{
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
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
    const qShareRnsLimbCount = qShareRnsLimbCountFromShareLinkageStatement(
        jsonRecord(
            setupPackage.vssShareLinkageStatement,
            'setupPackage.vssShareLinkageStatement',
        ),
    );
    if (
        recipientRecords.length === 0 ||
        recipientRecords.length % qShareRnsLimbCount !== 0
    ) {
        throw new Error(
            'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords must cover complete recipient RNS groups.',
        );
    }
    const matchingRosterPositions = new Set<number>();
    const parsedRecipientRecords = recipientRecords.map(
        (recipientRecord, recipientRecordIndex) => {
            const objectPath =
                'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords.' +
                String(recipientRecordIndex);
            const record = jsonRecord(recipientRecord, objectPath);
            const recipientIdentity = nonEmptyStringField(
                record,
                'recipientIdentity',
                objectPath,
            );
            if (recipientIdentity === trusteeIdentity) {
                matchingRosterPositions.add(
                    Math.floor(recipientRecordIndex / qShareRnsLimbCount),
                );
            }
            return record;
        },
    );
    if (matchingRosterPositions.size !== 1) {
        throw new Error(
            'setupPackage.vssPublicAggregateThresholdCommitmentSet must contain exactly one recipient group for the trustee.',
        );
    }
    const rosterPosition = [...matchingRosterPositions][0];
    const participantRecordOffset = rosterPosition * qShareRnsLimbCount;
    parsedRecipientRecords
        .slice(
            participantRecordOffset,
            participantRecordOffset + qShareRnsLimbCount,
        )
        .forEach((participantRecord) => {
            if (participantRecord.recipientIdentity !== trusteeIdentity) {
                throw new Error(
                    'setup package aggregate records must use one trustee identity per canonical recipient group.',
                );
            }
        });

    return {
        trusteeIdentity,
        rosterPosition,
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
    qShareRnsLimbCount: number,
): ReadonlyMap<string, JsonRecord> => {
    const recipientRecords = aggregateThresholdCommitmentSet.recipientRecords;
    if (!Array.isArray(recipientRecords)) {
        throw new Error(
            'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords must be an array.',
        );
    }
    if (
        recipientRecords.length === 0 ||
        recipientRecords.length % qShareRnsLimbCount !== 0
    ) {
        throw new Error(
            'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords must cover complete recipient RNS groups.',
        );
    }
    const recordsByRecipientLimb = new Map<string, JsonRecord>();
    const recipientIdentitiesByRosterPosition = new Map<number, string>();
    recipientRecords.forEach((recordValue, recordIndex) => {
        const objectPath = `setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords.${String(recordIndex)}`;
        const record = jsonRecord(recordValue, objectPath);
        const recipientIdentity = nonEmptyStringField(
            record,
            'recipientIdentity',
            objectPath,
        );
        const recipientRosterPosition = Math.floor(
            recordIndex / qShareRnsLimbCount,
        );
        const rnsLimbIndex = recordIndex % qShareRnsLimbCount;
        const establishedRecipientIdentity =
            recipientIdentitiesByRosterPosition.get(recipientRosterPosition);
        if (
            establishedRecipientIdentity !== undefined &&
            establishedRecipientIdentity !== recipientIdentity
        ) {
            throw new Error(
                'setup package aggregate records must use one trustee identity per canonical recipient group.',
            );
        }
        recipientIdentitiesByRosterPosition.set(
            recipientRosterPosition,
            recipientIdentity,
        );
        protocolHashField(record, 'aggregateCommitmentRoot', objectPath);
        protocolHashField(record, 'aggregateOpeningRoot', objectPath);
        const recordKey = aggregateRecordKey(
            recipientIdentity,
            recipientRosterPosition,
            rnsLimbIndex,
        );
        recordsByRecipientLimb.set(recordKey, record);
    });

    return recordsByRecipientLimb;
};

const assertRestoredAggregateOpeningBinding = (input: {
    readonly restoredLocalTargetShareWitness: JsonRecord;
    readonly setupPackage: JsonRecord;
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

    const shareLinkageStatement = jsonRecord(
        input.setupPackage.vssShareLinkageStatement,
        'setupPackage.vssShareLinkageStatement',
    );

    const aggregateThresholdCommitmentSet = jsonRecord(
        input.setupPackage.vssPublicAggregateThresholdCommitmentSet,
        'setupPackage.vssPublicAggregateThresholdCommitmentSet',
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
    const acceptedRecordsByRecipientLimb = aggregateRecordsByRecipientLimb(
        aggregateThresholdCommitmentSet,
        qShareRnsLimbCountFromShareLinkageStatement(shareLinkageStatement),
    );
    const seenCredentialKeys = new Set<string>();
    let ringDegree: number | undefined;
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
        const acceptedCommitment = jsonRecord(
            acceptedRecord.commitment,
            'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords.commitment',
        );
        if (
            nonNegativeIntegerField(
                acceptedCommitment,
                'rnsLimbIndex',
                'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords.commitment',
            ) !== rnsLimbIndex
        ) {
            throw new Error(
                'accepted aggregate commitment rnsLimbIndex must match its canonical record position.',
            );
        }
        const acceptedRingDegree = nonNegativeIntegerField(
            acceptedCommitment,
            'ringDegree',
            'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords.commitment',
        );
        if (
            acceptedRingDegree === 0 ||
            acceptedRingDegree > maximumAggregateOpeningRingDegree
        ) {
            throw new Error(
                'accepted aggregate commitment ringDegree must be inside the supported target-decryption ring bound.',
            );
        }
        if (ringDegree !== undefined && ringDegree !== acceptedRingDegree) {
            throw new Error(
                'accepted aggregate commitments must use one ringDegree.',
            );
        }
        ringDegree = acceptedRingDegree;
        const rnsPrime = nonNegativeIntegerField(
            credential,
            'rnsPrime',
            objectPath,
        );
        if (
            rnsPrime !==
            nonNegativeIntegerField(
                acceptedCommitment,
                'rnsPrime',
                'setupPackage.vssPublicAggregateThresholdCommitmentSet.recipientRecords.commitment',
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

    if (ringDegree === undefined) {
        throw new Error(
            'restored aggregate opening credentials must match an accepted aggregate commitment.',
        );
    }
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

const prepareLocalTargetDecryptionShareWitness = (
    input: LocalTargetDecryptionShareWitnessPreparationInput,
): PreparedLocalTargetDecryptionShareWitness => {
    const restoredLocalTargetShareWitness = jsonRecord(
        input.restoredLocalTargetShareWitness,
        'restoredLocalTargetShareWitness',
    );
    exactStringField(
        restoredLocalTargetShareWitness,
        'objectType',
        'LocalTrusteeTargetDecryptionProofWitnessMaterial',
        'restoredLocalTargetShareWitness',
    );
    jsonRecord(
        restoredLocalTargetShareWitness.aggregateOpening,
        'restoredLocalTargetShareWitness.aggregateOpening',
    );
    const participant = setupParticipant(
        input.setupPackage,
        input.trusteeIdentity,
    );
    const ringDegree = assertRestoredAggregateOpeningBinding({
        restoredLocalTargetShareWitness,
        setupPackage: jsonRecord(input.setupPackage, 'setupPackage'),
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
            ) !== expectedValue
        ) {
            throw new Error(
                `${fieldName} must match the restored local-state context and setup package.`,
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
            ) !== expectedValue
        ) {
            throw new Error(
                `${fieldName} must match the restored local-state context and setup package.`,
            );
        }
    }
};

export const restoreAndPrepareLocalTargetDecryptionShareWitness = async (
    input: RestoredLocalTargetDecryptionShareWitnessInput,
): Promise<PreparedLocalTargetDecryptionShareWitness> => {
    const setupContextHash = deriveCollectiveBgvSetupContextHash(
        input.setupContext,
    );
    const localStateCommitment = jsonRecord(
        input.localStateCommitment,
        'localStateCommitment',
    );
    exactStringField(
        localStateCommitment,
        'objectType',
        'LocalTrusteeSetupStateCommitment',
        'localStateCommitment',
    );
    if (
        protocolHashField(
            localStateCommitment,
            'setupContextHash',
            'localStateCommitment',
        ) !== setupContextHash
    ) {
        throw new Error(
            'localStateCommitment.setupContextHash must match setupContext.',
        );
    }
    const trusteeIdentity = nonEmptyStringField(
        localStateCommitment,
        'trusteeIdentity',
        'localStateCommitment',
    );
    const trusteeRosterPosition = nonNegativeIntegerField(
        localStateCommitment,
        'trusteeRosterPosition',
        'localStateCommitment',
    );
    const thresholdShareCommitmentRecipientRoot = protocolHashField(
        localStateCommitment,
        'thresholdShareCommitmentRecipientRoot',
        'localStateCommitment',
    );
    const aggregateThresholdShareRoot = protocolHashField(
        localStateCommitment,
        'aggregateThresholdShareRoot',
        'localStateCommitment',
    );
    const canonicalLocalStateCommitment =
        createLocalTrusteeSetupStateCommitment({
            aggregateThresholdShareRoot,
            setupContext: input.setupContext,
            thresholdShareCommitmentRecipientRoot,
            trusteeIdentity,
            trusteeRosterPosition,
        });
    if (
        protocolHashField(
            localStateCommitment,
            'localStateRoot',
            'localStateCommitment',
        ) !== canonicalLocalStateCommitment.localStateRoot
    ) {
        throw new Error(
            'localStateCommitment.localStateRoot does not match the canonical local state commitment.',
        );
    }
    const localStatePlaintext = await input.storageCustody.openLocalRecord({
        actionRandomnessCommitment: input.actionRandomnessCommitment,
        creationRecoveryEpoch: input.creationRecoveryEpoch,
        envelope: input.encryptedLocalState,
        identifierInput: {
            recordType: 'aggregateThresholdShare',
            recipientInputRoot: bytesFromHex(
                thresholdShareCommitmentRecipientRoot,
                'localStateCommitment.thresholdShareCommitmentRecipientRoot',
            ),
        },
        recordVersion: 0n,
    });
    let aggregateOpeningCredentialHandoffValue: ReturnType<
        typeof decodeAggregateThresholdShareRecord
    >;
    try {
        aggregateOpeningCredentialHandoffValue =
            decodeAggregateThresholdShareRecord(localStatePlaintext);
    } finally {
        localStatePlaintext.fill(0);
    }
    const aggregateThresholdShareMaterial = {
        objectType: 'LocalTrusteeAggregateThresholdShareMaterial',
        aggregateOpeningCredentialHandoff:
            aggregateOpeningCredentialHandoffValue,
    } as const;
    if (
        deriveCanonicalObjectHash(aggregateThresholdShareMaterial) !==
        aggregateThresholdShareRoot
    ) {
        throw new Error(
            'restored aggregate threshold share does not match localStateCommitment.aggregateThresholdShareRoot.',
        );
    }
    const aggregateOpeningCredentialHandoff = jsonRecord(
        aggregateOpeningCredentialHandoffValue,
        'aggregateThresholdShareMaterial.aggregateOpeningCredentialHandoff',
    );
    const setupPackage = jsonRecord(input.setupPackage, 'setupPackage');
    assertRestoredSetupContext(input.setupContext, setupPackage);
    const participant = setupParticipant(setupPackage, trusteeIdentity);
    if (participant.rosterPosition !== trusteeRosterPosition) {
        throw new Error(
            'restored aggregate threshold share roster position must match the supplied setup package.',
        );
    }
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

    const restoredLocalTargetShareWitness = {
        objectType: 'LocalTrusteeTargetDecryptionProofWitnessMaterial',
        aggregateOpening: {
            objectType: 'LocalTrusteeVssPublicAggregateOpeningWitness',
            aggregateOpeningCredentials:
                aggregateOpeningCredentialHandoff.aggregateOpeningCredentials,
        },
    };

    return prepareLocalTargetDecryptionShareWitness({
        restoredLocalTargetShareWitness,
        setupPackage,
        trusteeIdentity,
    });
};
