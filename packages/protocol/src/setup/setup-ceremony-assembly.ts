import {
    decryptPrivateVssMailboxEnvelope,
    type PrivateVssEncryptedEnvelope,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    createEncryptedLocalTrusteeSetupStateFromVerifiedShares,
    type GeneratedLocalTrusteeSetupStateResult,
} from './local-trustee-setup-state.js';
import {
    createPrivateVssMailboxDeliverySet,
    type PrivateVssEnvelopeCommitment,
    type PrivateVssMailboxDeliveryKernel,
    type PrivateVssMailboxDeliverySet,
    type PrivateVssShareProofFactory,
    type PrivateVssShareProofRandomnessFactory,
} from './private-vss-mailbox-delivery.js';
import {
    createSetupContributionAssembly,
    type SetupContributionAssembly,
} from './setup-contribution-orchestration.js';
import {
    deriveThresholdShareCommitments,
    type ThresholdShareCommitmentSet,
} from './threshold-share-commitments.js';
import {
    createVssCoefficientCommitmentBundle,
    type VssCoefficientCommitmentMaterialSet,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeCoefficientOpeningState,
} from './vss-coefficient-commitments.js';
import {
    createVssShareAcceptanceRecord,
    createVssShareAcceptanceSet,
    type CollectiveBgvSetupContext,
    type PrivateVssEnvelopeVerificationReference,
    type ProtocolRootSigner,
    type VssShareAcceptanceRecord,
    type VssShareAcceptanceSet,
} from './vss-share-verification-records.js';
import type {
    PublicKeyShareProofRecord,
    PublicKeyShareRecord,
} from './public-key-share-records.js';
import type { SetupPhaseParticipantObject } from './setup-phase-records.js';

type JsonRecord = Record<string, unknown>;

export type SetupCeremonyTrusteeInput = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly mailboxPublicKeyBytesHex: string;
    readonly mailboxSecretKeyBytesHex: string;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly signRoot: ProtocolRootSigner;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly storageKeyBytesHex: string;
    readonly localStateAeadNonceBytesHex?: string;
    readonly sealedAggregateThresholdShareAeadNonceBytesHex?: string;
    readonly setupPhaseParticipantObjects?: readonly SetupPhaseParticipantObject[];
    readonly commonRandomnessCommitRoot?: ProtocolHash;
    readonly commonRandomnessRevealRoot?: ProtocolHash;
    readonly publicKeyShareRecord?: PublicKeyShareRecord;
    readonly publicKeyShareProofRecord?: PublicKeyShareProofRecord;
}>;

export type SetupCeremonyAssemblyInput = Readonly<{
    readonly kernel: PrivateVssMailboxDeliveryKernel;
    readonly setupContext: CollectiveBgvSetupContext;
    readonly phaseOrderHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly trustees: readonly SetupCeremonyTrusteeInput[];
    readonly sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[];
    readonly deliveryPhaseNumber: number;
    readonly verificationPhaseNumber: number;
    readonly privateVssShareProofMaterialEncoding?:
        | 'embedded-binary-proof-bytes-hex'
        | 'binary-chunked-proof-bytes';
    readonly privateVssShareProofFactory?: PrivateVssShareProofFactory;
    readonly privateVssShareProofRandomnessFactory?: PrivateVssShareProofRandomnessFactory;
}>;

export type SetupCeremonyLocalTrusteeState = Omit<
    GeneratedLocalTrusteeSetupStateResult,
    'localStatePlaintext'
> &
    Readonly<{
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
    }>;

export type SetupCeremonyAssembly = Readonly<{
    readonly objectType: 'SetupCeremonyAssembly';
    readonly objectVersion: 1;
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly setupContext: CollectiveBgvSetupContext;
    readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
    readonly vssCoefficientCommitmentMaterial: VssCoefficientCommitmentMaterialSet;
    readonly privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet;
    readonly vssShareAcceptances: VssShareAcceptanceSet;
    readonly thresholdShareCommitments: ThresholdShareCommitmentSet;
    readonly localTrusteeSetupStates: readonly SetupCeremonyLocalTrusteeState[];
    readonly setupContributions: readonly SetupContributionAssembly[];
}>;

const assertPositiveSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
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

const protocolHashPattern = /^[0-9a-f]{128}$/u;

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const stringField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): string => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'string' || fieldValue.length === 0) {
        throw new TypeError(`${objectPath}.${fieldName} must be non-empty.`);
    }

    return fieldValue;
};

const nonNegativeIntegerField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = value[fieldName];
    if (
        typeof fieldValue !== 'number' ||
        !Number.isSafeInteger(fieldValue) ||
        fieldValue < 0
    ) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a non-negative safe integer.`,
        );
    }

    return fieldValue;
};

const protocolHashField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): ProtocolHash => {
    const fieldValue = stringField(value, fieldName, objectPath);
    assertProtocolHash(fieldValue, `${objectPath}.${fieldName}`);

    return fieldValue;
};

const orderedTrustees = (
    trustees: readonly SetupCeremonyTrusteeInput[],
): readonly SetupCeremonyTrusteeInput[] => {
    const sortedTrustees = [...trustees].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (sortedTrustees.length === 0) {
        throw new Error('trustees must contain at least one trustee.');
    }
    const seenTrusteeIdentities = new Set<string>();
    sortedTrustees.forEach((trustee, expectedRosterPosition) => {
        assertNonEmptyString(trustee.trusteeIdentity, 'trusteeIdentity');
        assertNonEmptyString(
            trustee.mailboxPublicKeyBytesHex,
            'mailboxPublicKeyBytesHex',
        );
        assertNonEmptyString(
            trustee.mailboxSecretKeyBytesHex,
            'mailboxSecretKeyBytesHex',
        );
        assertNonEmptyString(trustee.storageKeyBytesHex, 'storageKeyBytesHex');
        assertProtocolHash(
            trustee.signingPublicKeyHash,
            'signingPublicKeyHash',
        );
        assertNonNegativeSafeInteger(
            trustee.trusteeRosterPosition,
            'trusteeRosterPosition',
        );
        assertNonNegativeSafeInteger(trustee.recoveryEpoch, 'recoveryEpoch');
        assertNonNegativeSafeInteger(trustee.deviceEpoch, 'deviceEpoch');
        if (trustee.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'trustees roster positions must be contiguous from zero.',
            );
        }
        if (seenTrusteeIdentities.has(trustee.trusteeIdentity)) {
            throw new Error('trustee identities must be distinct.');
        }
        seenTrusteeIdentities.add(trustee.trusteeIdentity);
    });

    return sortedTrustees;
};

const orderedOpeningStates = (
    sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[],
): readonly VssSourceTrusteeCoefficientOpeningState[] =>
    [...sourceTrusteeOpeningStates].sort(
        (left, right) =>
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition,
    );

const assertOpeningStatesMatchTrustees = (
    trustees: readonly SetupCeremonyTrusteeInput[],
    sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[],
): void => {
    const sortedOpeningStates = orderedOpeningStates(
        sourceTrusteeOpeningStates,
    );
    if (sortedOpeningStates.length !== trustees.length) {
        throw new Error(
            'sourceTrusteeOpeningStates must contain one state per trustee.',
        );
    }
    sortedOpeningStates.forEach((sourceTrusteeState, expectedPosition) => {
        const trustee = trustees[expectedPosition];
        if (
            sourceTrusteeState.sourceTrusteeRosterPosition !==
            expectedPosition
        ) {
            throw new Error(
                'sourceTrusteeOpeningStates roster positions must match trustees.',
            );
        }
        if (
            trustee === undefined ||
            sourceTrusteeState.sourceTrusteeIdentity !==
                trustee.trusteeIdentity
        ) {
            throw new Error(
                'sourceTrusteeOpeningStates identities must match trustees.',
            );
        }
    });
};

const trusteeByRecipientPosition = (
    trustees: readonly SetupCeremonyTrusteeInput[],
): ReadonlyMap<number, SetupCeremonyTrusteeInput> =>
    new Map(
        trustees.map((trustee) => [
            trustee.trusteeRosterPosition,
            trustee,
        ]),
    );

const envelopeVerificationReference = (
    reference: PrivateVssEnvelopeCommitment,
    objectPath: string,
): PrivateVssEnvelopeVerificationReference => {
    const referenceRecord = reference as Readonly<Record<string, unknown>>;
    stringField(referenceRecord, 'sourceTrusteeIdentity', objectPath);
    nonNegativeIntegerField(
        referenceRecord,
        'sourceTrusteeRosterPosition',
        objectPath,
    );
    stringField(referenceRecord, 'recipientIdentity', objectPath);
    nonNegativeIntegerField(
        referenceRecord,
        'recipientRosterPosition',
        objectPath,
    );
    protocolHashField(
        referenceRecord,
        'sourceTrusteeCommitmentRoot',
        objectPath,
    );
    protocolHashField(referenceRecord, 'privateEnvelopeHash', objectPath);
    protocolHashField(referenceRecord, 'encryptedEnvelopeHash', objectPath);
    protocolHashField(referenceRecord, 'localVerificationRoot', objectPath);
    protocolHashField(
        referenceRecord,
        'privateEnvelopeCommitmentRoot',
        objectPath,
    );

    return reference as PrivateVssEnvelopeVerificationReference;
};

const envelopeVerificationReferences = (
    privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet,
): readonly PrivateVssEnvelopeVerificationReference[] =>
    privateVssEnvelopeCommitments.envelopeReferences.map(
        (reference, referenceIndex) =>
            envelopeVerificationReference(
                reference,
                `privateVssEnvelopeCommitments.envelopeReferences.${String(
                    referenceIndex,
                )}`,
            ),
    );

const envelopeReferencesForRecipient = (
    privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet,
    recipientRosterPosition: number,
): readonly PrivateVssEnvelopeVerificationReference[] =>
    envelopeVerificationReferences(privateVssEnvelopeCommitments)
        .filter(
            (reference) =>
                reference.recipientRosterPosition === recipientRosterPosition,
        )
        .sort(
            (left, right) =>
                left.sourceTrusteeRosterPosition -
                right.sourceTrusteeRosterPosition,
        );

const envelopeReferencesForSource = (
    privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet,
    sourceTrusteeRosterPosition: number,
): readonly PrivateVssEnvelopeVerificationReference[] =>
    envelopeVerificationReferences(privateVssEnvelopeCommitments)
        .filter(
            (reference) =>
                reference.sourceTrusteeRosterPosition ===
                sourceTrusteeRosterPosition,
        )
        .sort(
            (left, right) =>
                left.recipientRosterPosition - right.recipientRosterPosition,
        );

const sourceTrusteeRecordForEnvelope = (
    vssCoefficientCommitments: VssCoefficientCommitmentSet,
    envelopeReference: PrivateVssEnvelopeVerificationReference,
) => {
    const sourceTrusteeRecord =
        vssCoefficientCommitments.sourceTrusteeRecords.find(
            (record) =>
                record.sourceTrusteeRosterPosition ===
                envelopeReference.sourceTrusteeRosterPosition,
        );
    if (sourceTrusteeRecord === undefined) {
        throw new Error(
            'private VSS envelope source trustee must have a matching VSS coefficient commitment record.',
        );
    }
    if (
        sourceTrusteeRecord.sourceTrusteeIdentity !==
            envelopeReference.sourceTrusteeIdentity ||
        sourceTrusteeRecord.sourceTrusteeCommitmentRoot !==
            envelopeReference.sourceTrusteeCommitmentRoot
    ) {
        throw new Error(
            'private VSS envelope source trustee binding must match the VSS coefficient commitment record.',
        );
    }

    return sourceTrusteeRecord;
};

const sourceTrusteeMaterialRecords = (
    vssCoefficientCommitmentMaterial: VssCoefficientCommitmentMaterialSet,
    envelopeReference: PrivateVssEnvelopeVerificationReference,
) => {
    const materialRecords =
        vssCoefficientCommitmentMaterial.coefficientCommitments.filter(
            (record) =>
                record.sourceTrusteeRosterPosition ===
                envelopeReference.sourceTrusteeRosterPosition,
        );
    if (materialRecords.length === 0) {
        throw new Error(
            'private VSS envelope source trustee must have public VSS coefficient material.',
        );
    }

    return materialRecords;
};

const decryptAndVerifyRecipientEnvelopes = async (
    input: Pick<
        SetupCeremonyAssemblyInput,
        'kernel' | 'setupContext' | 'publicMatrixSeedHash'
    > & {
        readonly trustee: SetupCeremonyTrusteeInput;
        readonly expectedParticipantCount: number;
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
        readonly vssCoefficientCommitmentMaterial: VssCoefficientCommitmentMaterialSet;
        readonly privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet;
    },
): Promise<readonly JsonRecord[]> => {
    const envelopeReferences = envelopeReferencesForRecipient(
        input.privateVssEnvelopeCommitments,
        input.trustee.trusteeRosterPosition,
    );
    if (
        envelopeReferences.length !==
        input.expectedParticipantCount
    ) {
        throw new Error(
            'private VSS envelope commitments must include one envelope from every source trustee for each recipient.',
        );
    }

    return Promise.all(
        envelopeReferences.map(async (envelopeReference) => {
            if (
                envelopeReference.encryptedEnvelope.encryptedEnvelopeHash !==
                envelopeReference.encryptedEnvelopeHash
            ) {
                throw new Error(
                    'encrypted private VSS envelope hash must match the public envelope reference.',
                );
            }
            const decryptedEnvelope = await decryptPrivateVssMailboxEnvelope({
                encryptedEnvelope:
                    envelopeReference.encryptedEnvelope as PrivateVssEncryptedEnvelope,
                recipientMailboxSecretKeyBytesHex:
                    input.trustee.mailboxSecretKeyBytesHex,
            });
            if (
                decryptedEnvelope.privateEnvelopeHash !==
                envelopeReference.privateEnvelopeHash
            ) {
                throw new Error(
                    'decrypted private VSS envelope hash must match the public envelope reference.',
                );
            }
            const localVerification =
                input.kernel.verifyPrivateVssShareEnvelope({
                    setupContext: input.setupContext,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    sourceTrusteeCoefficientCommitmentRecord:
                        sourceTrusteeRecordForEnvelope(
                            input.vssCoefficientCommitments,
                            envelopeReference,
                        ),
                    sourceTrusteeCoefficientCommitmentMaterialRecords:
                        sourceTrusteeMaterialRecords(
                            input.vssCoefficientCommitmentMaterial,
                            envelopeReference,
                        ),
                    privateEnvelope: decryptedEnvelope.privateEnvelope,
                    transportedPrivateVssShareProofMaterial:
                        envelopeReference.transportedPrivateVssShareProofMaterial,
                    expectedPrivateEnvelopeHash:
                        envelopeReference.privateEnvelopeHash,
                    expectedLocalVerificationRoot:
                        envelopeReference.localVerificationRoot,
                });
            if (
                !localVerification.ok ||
                localVerification.privateEnvelopeHash !==
                    envelopeReference.privateEnvelopeHash ||
                localVerification.localVerificationRoot !==
                    envelopeReference.localVerificationRoot
            ) {
                const refusal = localVerification.refusedObjects[0];
                throw new Error(
                    refusal === undefined
                        ? 'decrypted private VSS envelope failed recipient-local verification.'
                        : `decrypted private VSS envelope failed recipient-local verification: ${refusal.reasonCode}: ${refusal.message}`,
                );
            }

            return decryptedEnvelope.privateEnvelope as JsonRecord;
        }),
    );
};

const createAcceptanceRecords = async (
    setupContext: CollectiveBgvSetupContext,
    trustees: readonly SetupCeremonyTrusteeInput[],
    privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet,
): Promise<readonly VssShareAcceptanceRecord[]> => {
    const trusteeByPosition = trusteeByRecipientPosition(trustees);

    return Promise.all(
        [...envelopeVerificationReferences(privateVssEnvelopeCommitments)]
            .sort((left, right) => {
                const sourceOrder =
                    left.sourceTrusteeRosterPosition -
                    right.sourceTrusteeRosterPosition;

                return sourceOrder === 0
                    ? left.recipientRosterPosition -
                          right.recipientRosterPosition
                    : sourceOrder;
            })
            .map((envelopeReference) => {
                const recipientTrustee = trusteeByPosition.get(
                    envelopeReference.recipientRosterPosition,
                );
                if (recipientTrustee === undefined) {
                    throw new Error(
                        'private VSS envelope recipient must be an accepted trustee.',
                    );
                }

                return createVssShareAcceptanceRecord({
                    setupContext,
                    privateVssEnvelopeCommitmentRoot:
                        privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot,
                    envelopeReference,
                    recoveryEpoch: recipientTrustee.recoveryEpoch,
                    deviceEpoch: recipientTrustee.deviceEpoch,
                    signingPublicKeyHash:
                        recipientTrustee.signingPublicKeyHash,
                    signRoot: recipientTrustee.signRoot,
                });
            }),
    );
};

const createLocalTrusteeSetupStates = async (
    input: Pick<
        SetupCeremonyAssemblyInput,
        'setupContext'
    > & {
        readonly trustees: readonly SetupCeremonyTrusteeInput[];
        readonly thresholdShareCommitments: ThresholdShareCommitmentSet;
        readonly privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet;
        readonly verifiedPrivateVssShareEnvelopesByRecipient: ReadonlyMap<
            number,
            readonly JsonRecord[]
        >;
        readonly vssShareAcceptances: VssShareAcceptanceSet;
    },
): Promise<readonly SetupCeremonyLocalTrusteeState[]> =>
    Promise.all(
        input.trustees.map(async (trustee) => {
            const verifiedPrivateVssShareEnvelopes =
                input.verifiedPrivateVssShareEnvelopesByRecipient.get(
                    trustee.trusteeRosterPosition,
                );
            if (verifiedPrivateVssShareEnvelopes === undefined) {
                throw new Error(
                    'verified private VSS share envelopes are missing for a trustee.',
                );
            }
            const { localStatePlaintext, ...sealedLocalState } =
                await createEncryptedLocalTrusteeSetupStateFromVerifiedShares({
                    setupContext: input.setupContext,
                    trusteeIdentity: trustee.trusteeIdentity,
                    trusteeRosterPosition: trustee.trusteeRosterPosition,
                    deviceEpoch: trustee.deviceEpoch,
                    thresholdShareCommitments:
                        input.thresholdShareCommitments,
                    privateVssEnvelopeCommitments:
                        input.privateVssEnvelopeCommitments,
                    verifiedPrivateVssShareEnvelopes,
                    vssShareAcceptances: input.vssShareAcceptances,
                    storageKeyBytesHex: trustee.storageKeyBytesHex,
                    localStateAeadNonceBytesHex:
                        trustee.localStateAeadNonceBytesHex,
                    sealedAggregateThresholdShareAeadNonceBytesHex:
                        trustee.sealedAggregateThresholdShareAeadNonceBytesHex,
            });
            void localStatePlaintext;

            return {
                trusteeIdentity: trustee.trusteeIdentity,
                trusteeRosterPosition: trustee.trusteeRosterPosition,
                ...sealedLocalState,
            };
        }),
    );

const createSetupContributions = (
    input: Pick<
        SetupCeremonyAssemblyInput,
        'setupContext'
    > & {
        readonly trustees: readonly SetupCeremonyTrusteeInput[];
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
        readonly privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet;
        readonly vssShareAcceptances: VssShareAcceptanceSet;
        readonly localTrusteeSetupStates: readonly SetupCeremonyLocalTrusteeState[];
    },
): readonly SetupContributionAssembly[] =>
    input.trustees.map((trustee) => {
        const sourceTrusteeRecord =
            input.vssCoefficientCommitments.sourceTrusteeRecords[
                trustee.trusteeRosterPosition
            ];
        const localState = input.localTrusteeSetupStates.find(
            (candidateState) =>
                candidateState.localStateCommitment.trusteeRosterPosition ===
                trustee.trusteeRosterPosition,
        );
        if (sourceTrusteeRecord === undefined || localState === undefined) {
            throw new Error(
                'setup contribution assembly requires source trustee and local-state records for every trustee.',
            );
        }

        return createSetupContributionAssembly({
            setupContext: input.setupContext,
            trusteeIdentity: trustee.trusteeIdentity,
            trusteeRosterPosition: trustee.trusteeRosterPosition,
            setupPhaseParticipantObjects:
                trustee.setupPhaseParticipantObjects ?? [],
            commonRandomnessCommitRoot: trustee.commonRandomnessCommitRoot,
            commonRandomnessRevealRoot: trustee.commonRandomnessRevealRoot,
            vssSourceTrusteeRecord: sourceTrusteeRecord,
            privateVssEnvelopeReferences: envelopeReferencesForSource(
                input.privateVssEnvelopeCommitments,
                trustee.trusteeRosterPosition,
            ),
            vssShareAcceptanceRecords:
                input.vssShareAcceptances.acceptanceRecords.filter(
                    (acceptanceRecord) =>
                        acceptanceRecord.recipientRosterPosition ===
                        trustee.trusteeRosterPosition,
                ),
            localStateCommitment: localState.localStateCommitment,
            publicKeyShareRecord: trustee.publicKeyShareRecord,
            publicKeyShareProofRecord: trustee.publicKeyShareProofRecord,
        });
    });

export const createSetupCeremonyAssembly = async (
    input: SetupCeremonyAssemblyInput,
): Promise<SetupCeremonyAssembly> => {
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    assertPositiveSafeInteger(input.deliveryPhaseNumber, 'deliveryPhaseNumber');
    assertPositiveSafeInteger(
        input.verificationPhaseNumber,
        'verificationPhaseNumber',
    );
    const trustees = orderedTrustees(input.trustees);
    assertOpeningStatesMatchTrustees(trustees, input.sourceTrusteeOpeningStates);

    const vssCoefficientCommitmentBundle = createVssCoefficientCommitmentBundle(
        {
            setupContext: input.setupContext,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            qSharePrimes: input.qSharePrimes,
            ringDegree: input.ringDegree,
            participantCount: trustees.length,
            thresholdDegree: input.thresholdDegree,
            sourceTrusteeOpeningStates: input.sourceTrusteeOpeningStates,
        },
    );
    const privateVssEnvelopeCommitments =
        await createPrivateVssMailboxDeliverySet({
            kernel: input.kernel,
            setupContext: input.setupContext,
            phaseOrderHash: input.phaseOrderHash,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            vssCoefficientCommitmentRoot:
                vssCoefficientCommitmentBundle.commitmentSet
                    .vssCoefficientCommitmentRoot,
            qSharePrimes: input.qSharePrimes,
            ringDegree: input.ringDegree,
            participantCount: trustees.length,
            deliveryPhaseNumber: input.deliveryPhaseNumber,
            verificationPhaseNumber: input.verificationPhaseNumber,
            privateVssShareProofMaterialEncoding:
                input.privateVssShareProofMaterialEncoding,
            privateVssShareProofFactory: input.privateVssShareProofFactory,
            privateVssShareProofRandomnessFactory:
                input.privateVssShareProofRandomnessFactory,
            sourceTrusteeContributionStates:
                vssCoefficientCommitmentBundle.privateOpeningMaterialBySourceTrustee,
            recipients: trustees.map((trustee) => ({
                recipientIdentity: trustee.trusteeIdentity,
                recipientRosterPosition: trustee.trusteeRosterPosition,
                mailboxPublicKeyBytesHex: trustee.mailboxPublicKeyBytesHex,
            })),
        });
    const verifiedPrivateVssShareEnvelopesByRecipient = new Map<
        number,
        readonly JsonRecord[]
    >();
    await Promise.all(
        trustees.map(async (trustee) => {
            verifiedPrivateVssShareEnvelopesByRecipient.set(
                trustee.trusteeRosterPosition,
                await decryptAndVerifyRecipientEnvelopes({
                    kernel: input.kernel,
                    setupContext: input.setupContext,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    trustee,
                    expectedParticipantCount: trustees.length,
                    vssCoefficientCommitments:
                        vssCoefficientCommitmentBundle.commitmentSet,
                    vssCoefficientCommitmentMaterial:
                        vssCoefficientCommitmentBundle.materialSet,
                    privateVssEnvelopeCommitments,
                }),
            );
        }),
    );
    const acceptanceRecords = await createAcceptanceRecords(
        input.setupContext,
        trustees,
        privateVssEnvelopeCommitments,
    );
    const vssShareAcceptances = createVssShareAcceptanceSet({
        setupContext: input.setupContext,
        privateVssEnvelopeCommitmentRoot:
            privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot,
        acceptanceRecords,
    });
    const thresholdShareCommitments = deriveThresholdShareCommitments({
        setupContext: input.setupContext,
        vssCoefficientCommitments:
            vssCoefficientCommitmentBundle.commitmentSet,
        vssCoefficientCommitmentMaterial:
            vssCoefficientCommitmentBundle.materialSet,
    });
    const localTrusteeSetupStates = await createLocalTrusteeSetupStates({
        setupContext: input.setupContext,
        trustees,
        thresholdShareCommitments,
        privateVssEnvelopeCommitments,
        verifiedPrivateVssShareEnvelopesByRecipient,
        vssShareAcceptances,
    });
    const setupContributions = createSetupContributions({
        setupContext: input.setupContext,
        trustees,
        vssCoefficientCommitments:
            vssCoefficientCommitmentBundle.commitmentSet,
        privateVssEnvelopeCommitments,
        vssShareAcceptances,
        localTrusteeSetupStates,
    });

    return {
        objectType: 'SetupCeremonyAssembly',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupContext: input.setupContext,
        vssCoefficientCommitments:
            vssCoefficientCommitmentBundle.commitmentSet,
        vssCoefficientCommitmentMaterial:
            vssCoefficientCommitmentBundle.materialSet,
        privateVssEnvelopeCommitments,
        vssShareAcceptances,
        thresholdShareCommitments,
        localTrusteeSetupStates,
        setupContributions,
    };
};
