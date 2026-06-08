import { decryptPrivateVssMailboxEnvelope } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommonRandomness } from './common-randomness-records.js';
import {
    createGaloisKeyShareBatches,
    createPublicEvaluationKeySet,
    createRelinearizationKeyShareRounds,
    type EvaluationKeyShareProofGenerator,
    type GaloisKeyShareBatch,
    type GaloisKeyShareBatchContribution,
    type PublicEvaluationKeyMaterialReference,
    type PublicEvaluationKeySet,
    type RelinearizationKeyShareRounds,
    type RelinearizationRoundOneContribution,
    type RelinearizationRoundTwoContribution,
    type SameSecretProofReference,
} from './evaluation-key-proof-records.js';
import {
    createEvaluatorKeySchedule,
    type EvaluatorKeySchedule,
    type RequiredGaloisKeyScheduleEntry,
} from './evaluator-key-schedule.js';
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
    createPublicKeyShareLnpProofSet,
    createPublicKeyShareMaterialSet,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    type CollectivePublicKey,
    type PublicKeyShareLnpProofMaterial,
    type PublicKeyShareLnpProofSet,
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialContributionInput,
    type PublicKeyShareMaterialSet,
    type PublicKeyShareProofSet,
    type PublicKeyShareSet,
} from './public-key-share-records.js';
import {
    createSameSecretProofSet,
    createSameSecretConsistencyStatementSet,
    type SameSecretConsistencyStatementSet,
    type SameSecretProofMaterial,
    type SameSecretProofSet,
} from './same-secret-consistency-records.js';
import {
    createSetupContributionAssembly,
    type SetupContributionAssembly,
} from './setup-contribution-orchestration.js';
import {
    createSetupPackage,
    type SetupPackage,
    type SetupPackageCertificateInput,
} from './setup-package-assembly.js';
import type {
    SetupPhaseParticipantObject,
    SetupPhaseRecord,
} from './setup-phase-records.js';
import {
    deriveThresholdShareCommitments,
    type ThresholdShareCommitmentSet,
} from './threshold-share-commitments.js';
import {
    createBinaryChunkedVssCoefficientCommitmentMaterialTransport,
    createVssCoefficientCommitmentBundle,
    type SetupPackageVssCoefficientCommitmentMaterialSet,
    type SetupTransportedVssCoefficientCommitmentMaterial,
    type VssCoefficientCommitmentMaterialRecord,
    type VssCoefficientCommitmentMaterialSet,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeCoefficientCommitmentRecord,
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
}>;

export type SetupCeremonyAssemblyInput = Readonly<{
    readonly kernel: PrivateVssMailboxDeliveryKernel;
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qShare: JsonRecord;
    readonly phaseTranscript: readonly SetupPhaseRecord[];
    readonly commonRandomness: SetupCommonRandomness;
    readonly phaseOrderHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly publicKeyCrpRoot: ProtocolHash;
    readonly publicAPolynomialRoot: ProtocolHash;
    readonly setupProofBinding: JsonRecord;
    readonly sameSecretTboxParameterProfileHash: ProtocolHash;
    readonly sameSecretProofMaterials: readonly SameSecretProofMaterial[];
    readonly publicKeyShareMaterialContributions: readonly PublicKeyShareMaterialContributionInput[];
    readonly publicKeyShareTboxParameterProfileHash: ProtocolHash;
    readonly publicKeyShareLnpProofMaterials: readonly PublicKeyShareLnpProofMaterial[];
    readonly relinearizationCrpRoot: ProtocolHash;
    readonly galoisKeyCrpRoot: ProtocolHash;
    readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
    readonly relinearizationRoundOneContributions: readonly RelinearizationRoundOneContribution[];
    readonly relinearizationRoundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    readonly galoisKeyShareBatchContributions: readonly GaloisKeyShareBatchContribution[];
    readonly publicEvaluationKeyMaterialReference?: PublicEvaluationKeyMaterialReference;
    readonly evaluationKeyShareProofGenerator?: EvaluationKeyShareProofGenerator;
    readonly setupCertificateInput: SetupPackageCertificateInput;
    readonly trustees: readonly SetupCeremonyTrusteeInput[];
    readonly sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[];
    readonly deliveryPhaseNumber: number;
    readonly verificationPhaseNumber: number;
    readonly privateVssShareProofMaterialEncoding?:
        | 'embedded-binary-proof-bytes-hex'
        | 'binary-chunked-proof-bytes';
    readonly vssCoefficientCommitmentMaterialEncoding?:
        | 'full-public-setup-commitment-values'
        | 'binary-chunked-full-public-setup-commitment-values';
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
    readonly vssCoefficientCommitmentMaterial: SetupPackageVssCoefficientCommitmentMaterialSet;
    readonly transportedVssCoefficientCommitmentMaterial?: SetupTransportedVssCoefficientCommitmentMaterial;
    readonly privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet;
    readonly vssShareAcceptances: VssShareAcceptanceSet;
    readonly thresholdShareCommitments: ThresholdShareCommitmentSet;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly publicKeyShareMaterial: PublicKeyShareMaterialSet;
    readonly publicKeyShareLnpProofs: PublicKeyShareLnpProofSet;
    readonly collectivePublicKey: CollectivePublicKey;
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
    readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
    readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
    readonly evaluationKeys: PublicEvaluationKeySet;
    readonly setupPackage: SetupPackage;
    readonly localTrusteeSetupStates: readonly SetupCeremonyLocalTrusteeState[];
    readonly setupContributions: readonly SetupContributionAssembly[];
}>;

const assertPositiveSafeInteger = (value: number, fieldName: string): void => {
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

const assertJsonRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const setupCertificatePublicVssMaterialByteLength = (
    setupCertificateInput: SetupPackageCertificateInput,
): number => {
    const setupProfile = assertJsonRecord(
        setupCertificateInput.setupProfile,
        'setupCertificateInput.setupProfile',
    );
    const sizeProfile = assertJsonRecord(
        setupProfile.publicVssCommitmentMaterialSizeProfile,
        'setupCertificateInput.setupProfile.publicVssCommitmentMaterialSizeProfile',
    );
    const fullMaterialCoefficientBytes =
        sizeProfile.fullMaterialCoefficientBytes;
    if (
        typeof fullMaterialCoefficientBytes !== 'number' ||
        !Number.isSafeInteger(fullMaterialCoefficientBytes) ||
        fullMaterialCoefficientBytes <= 0
    ) {
        throw new TypeError(
            'setupCertificateInput.setupProfile.publicVssCommitmentMaterialSizeProfile.fullMaterialCoefficientBytes must be a positive safe integer.',
        );
    }

    return fullMaterialCoefficientBytes;
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
            sourceTrusteeState.sourceTrusteeRosterPosition !== expectedPosition
        ) {
            throw new Error(
                'sourceTrusteeOpeningStates roster positions must match trustees.',
            );
        }
        if (
            sourceTrusteeState.sourceTrusteeIdentity !==
            trustee?.trusteeIdentity
        ) {
            throw new Error(
                'sourceTrusteeOpeningStates identities must match trustees.',
            );
        }
    });
};

const publicKeyShareContributionsFromMaterial = (
    materialContributions: readonly PublicKeyShareMaterialContributionInput[],
): PublicKeyShareContributionInput[] =>
    materialContributions.map((contribution) => ({
        trusteeIdentity: contribution.trusteeIdentity,
        trusteeRosterPosition: contribution.trusteeRosterPosition,
        shareCoefficientVectorHash512ByLimb:
            contribution.shareCoefficientVectorsByLimb.map(
                (coefficientVector) => ({
                    rnsLimbIndex: coefficientVector.rnsLimbIndex,
                    rnsPrime: coefficientVector.rnsPrime,
                    component: coefficientVector.component,
                    coefficientVectorHash512:
                        coefficientVector.coefficientVectorHash512,
                }),
            ),
    }));

const sameSecretProofReferencesForConsistency = (
    sameSecretConsistency: SameSecretConsistencyStatementSet,
    sameSecretProofs: SameSecretProofSet,
): readonly SameSecretProofReference[] => {
    const sortedProofRecords = [...sameSecretProofs.proofRecords].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    const sortedStatements = [...sameSecretConsistency.statementRecords].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (
        sameSecretProofs.sameSecretConsistencyRoot !==
            sameSecretConsistency.sameSecretConsistencyRoot ||
        sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            sameSecretConsistency.sameSecretProofFamilyBindingRoot
    ) {
        throw new Error(
            'sameSecretProofs must bind the derived same-secret statement set.',
        );
    }
    if (sortedProofRecords.length !== sortedStatements.length) {
        throw new Error(
            'sameSecretProofs must contain one proof per same-secret statement.',
        );
    }
    sortedProofRecords.forEach((proofRecord, expectedRosterPosition) => {
        const statementRecord = sortedStatements[expectedRosterPosition];
        if (statementRecord === undefined) {
            throw new Error(
                'sameSecretProofs must match same-secret statement order.',
            );
        }
        assertNonEmptyString(
            proofRecord.trusteeIdentity,
            'sameSecretProofs.proofRecords.trusteeIdentity',
        );
        assertNonNegativeSafeInteger(
            proofRecord.trusteeRosterPosition,
            'sameSecretProofs.proofRecords.trusteeRosterPosition',
        );
        if (
            proofRecord.trusteeRosterPosition !== expectedRosterPosition ||
            proofRecord.trusteeIdentity !== statementRecord.trusteeIdentity ||
            proofRecord.sameSecretStatementRoot !==
                statementRecord.sameSecretStatementRoot ||
            proofRecord.trusteeSecretCommitmentRoot !==
                statementRecord.trusteeSecretCommitmentRoot
        ) {
            throw new Error(
                'sameSecretProofs must bind the derived same-secret statements.',
            );
        }
        assertProtocolHash(
            proofRecord.sameSecretProofRoot,
            'sameSecretProofs.proofRecords.sameSecretProofRoot',
        );
    });

    return sortedProofRecords.map((proofRecord) => ({
        trusteeIdentity: proofRecord.trusteeIdentity,
        trusteeRosterPosition: proofRecord.trusteeRosterPosition,
        sameSecretStatementRoot: proofRecord.sameSecretStatementRoot,
        trusteeSecretCommitmentRoot: proofRecord.trusteeSecretCommitmentRoot,
        sameSecretProofRoot: proofRecord.sameSecretProofRoot,
    }));
};

const trusteeByRecipientPosition = (
    trustees: readonly SetupCeremonyTrusteeInput[],
): ReadonlyMap<number, SetupCeremonyTrusteeInput> =>
    new Map(
        trustees.map((trustee) => [trustee.trusteeRosterPosition, trustee]),
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
): VssSourceTrusteeCoefficientCommitmentRecord => {
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
): readonly VssCoefficientCommitmentMaterialRecord[] => {
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
    if (envelopeReferences.length !== input.expectedParticipantCount) {
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
                encryptedEnvelope: envelopeReference.encryptedEnvelope,
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
                    signingPublicKeyHash: recipientTrustee.signingPublicKeyHash,
                    signRoot: recipientTrustee.signRoot,
                });
            }),
    );
};

const createLocalTrusteeSetupStates = async (
    input: Pick<SetupCeremonyAssemblyInput, 'setupContext'> & {
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
                    thresholdShareCommitments: input.thresholdShareCommitments,
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
    input: Pick<SetupCeremonyAssemblyInput, 'setupContext'> & {
        readonly trustees: readonly SetupCeremonyTrusteeInput[];
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
        readonly privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet;
        readonly vssShareAcceptances: VssShareAcceptanceSet;
        readonly publicKeyShares: PublicKeyShareSet;
        readonly publicKeyShareProofs: PublicKeyShareProofSet;
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
        const publicKeyShareRecord = input.publicKeyShares.shareRecords.find(
            (shareRecord) =>
                shareRecord.trusteeRosterPosition ===
                trustee.trusteeRosterPosition,
        );
        const publicKeyShareProofRecord =
            input.publicKeyShareProofs.proofRecords.find(
                (proofRecord) =>
                    proofRecord.trusteeRosterPosition ===
                    trustee.trusteeRosterPosition,
            );
        if (
            publicKeyShareRecord === undefined ||
            publicKeyShareProofRecord === undefined
        ) {
            throw new Error(
                'setup contribution assembly requires public-key share and proof records for every trustee.',
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
            publicKeyShareRecord,
            publicKeyShareProofRecord,
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
    assertProtocolHash(input.publicKeyCrpRoot, 'publicKeyCrpRoot');
    assertProtocolHash(input.publicAPolynomialRoot, 'publicAPolynomialRoot');
    assertProtocolHash(input.relinearizationCrpRoot, 'relinearizationCrpRoot');
    assertProtocolHash(input.galoisKeyCrpRoot, 'galoisKeyCrpRoot');
    const trustees = orderedTrustees(input.trustees);
    assertOpeningStatesMatchTrustees(
        trustees,
        input.sourceTrusteeOpeningStates,
    );

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
    const binaryVssMaterialTransport =
        input.vssCoefficientCommitmentMaterialEncoding ===
        'binary-chunked-full-public-setup-commitment-values'
            ? createBinaryChunkedVssCoefficientCommitmentMaterialTransport(
                  vssCoefficientCommitmentBundle.materialSet,
              )
            : undefined;
    const setupPackageVssCoefficientCommitmentMaterial =
        binaryVssMaterialTransport?.materialSet ??
        vssCoefficientCommitmentBundle.materialSet;
    if (binaryVssMaterialTransport !== undefined) {
        const declaredByteLength = setupCertificatePublicVssMaterialByteLength(
            input.setupCertificateInput,
        );
        if (
            declaredByteLength !==
            binaryVssMaterialTransport
                .transportedVssCoefficientCommitmentMaterial.totalByteLength
        ) {
            throw new Error(
                'setup certificate public VSS material byte length must match the binary transported material.',
            );
        }
    }
    const setupCertificateInput =
        binaryVssMaterialTransport === undefined
            ? input.setupCertificateInput
            : {
                  ...input.setupCertificateInput,
                  transport: {
                      fullObjectHash:
                          binaryVssMaterialTransport
                              .transportedVssCoefficientCommitmentMaterial
                              .fullObjectHash,
                      chunkHashes:
                          binaryVssMaterialTransport
                              .transportedVssCoefficientCommitmentMaterial
                              .chunkHashes,
                  },
              };
    const sameSecretConsistency = createSameSecretConsistencyStatementSet({
        setupContext: input.setupContext,
        qSharePrimes: input.qSharePrimes,
        participantCount: trustees.length,
        thresholdDegree: input.thresholdDegree,
        vssCoefficientCommitments: vssCoefficientCommitmentBundle.commitmentSet,
    });
    const sameSecretProofs = createSameSecretProofSet({
        setupContext: input.setupContext,
        qSharePrimes: input.qSharePrimes,
        participantCount: trustees.length,
        sameSecretConsistency,
        vssCoefficientCommitmentMaterial:
            setupPackageVssCoefficientCommitmentMaterial,
        setupProofBinding: input.setupProofBinding,
        sameSecretTboxParameterProfileHash:
            input.sameSecretTboxParameterProfileHash,
        proofMaterials: input.sameSecretProofMaterials,
    });
    const publicKeyShares = createPublicKeyShareSet({
        setupContext: input.setupContext,
        qSharePrimes: input.qSharePrimes,
        participantCount: trustees.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistency,
        shareContributions: publicKeyShareContributionsFromMaterial(
            input.publicKeyShareMaterialContributions,
        ),
    });
    const publicKeyShareProofs = createPublicKeyShareProofSet({
        setupContext: input.setupContext,
        qSharePrimes: input.qSharePrimes,
        participantCount: trustees.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistency,
        publicKeyShares,
    });
    const publicKeyShareMaterial = createPublicKeyShareMaterialSet({
        setupContext: input.setupContext,
        qSharePrimes: input.qSharePrimes,
        participantCount: trustees.length,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShares,
        materialContributions: input.publicKeyShareMaterialContributions,
    });
    const publicKeyShareLnpProofs = createPublicKeyShareLnpProofSet({
        setupContext: input.setupContext,
        qSharePrimes: input.qSharePrimes,
        participantCount: trustees.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistency,
        sameSecretProofs,
        publicKeyShares,
        publicKeyShareProofs,
        publicKeyShareMaterial,
        setupProofBinding: input.setupProofBinding,
        publicKeyShareTboxParameterProfileHash:
            input.publicKeyShareTboxParameterProfileHash,
        proofMaterials: input.publicKeyShareLnpProofMaterials,
    });
    const sameSecretProofReferences = sameSecretProofReferencesForConsistency(
        sameSecretConsistency,
        sameSecretProofs,
    );
    const evaluatorKeySchedule = createEvaluatorKeySchedule({
        setupContext: input.setupContext,
        qSharePrimes: input.qSharePrimes,
        participantCount: trustees.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        relinearizationCrpRoot: input.relinearizationCrpRoot,
        galoisKeyCrpRoot: input.galoisKeyCrpRoot,
        sameSecretConsistency,
        publicKeyShares,
        publicKeyShareProofs,
        requiredGaloisKeySchedule: input.requiredGaloisKeySchedule,
    });
    const evaluationKeyProofCommonInput = {
        setupContext: input.setupContext,
        qSharePrimes: input.qSharePrimes,
        participantCount: trustees.length,
        evaluatorKeySchedule,
        sameSecretProofSetRoot: sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        publicKeyShareLnpProofSetRoot:
            publicKeyShareLnpProofs.publicKeyShareLnpProofSetRoot,
        sameSecretProofReferences,
        evaluationKeyShareProofGenerator:
            input.evaluationKeyShareProofGenerator,
    } as const;
    const relinearizationKeyShareRounds = createRelinearizationKeyShareRounds({
        ...evaluationKeyProofCommonInput,
        roundOneContributions: input.relinearizationRoundOneContributions,
        roundTwoContributions: input.relinearizationRoundTwoContributions,
    });
    const galoisKeyShareBatches = createGaloisKeyShareBatches({
        ...evaluationKeyProofCommonInput,
        batchContributions: input.galoisKeyShareBatchContributions,
    });
    const evaluationKeys = createPublicEvaluationKeySet({
        ...evaluationKeyProofCommonInput,
        relinearizationKeyShareRounds,
        galoisKeyShareBatches,
        ...(input.publicEvaluationKeyMaterialReference === undefined
            ? {}
            : {
                  publicEvaluationKeyMaterialReference:
                      input.publicEvaluationKeyMaterialReference,
              }),
    });
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
        vssCoefficientCommitments: vssCoefficientCommitmentBundle.commitmentSet,
        vssCoefficientCommitmentMaterial:
            setupPackageVssCoefficientCommitmentMaterial,
        ...(binaryVssMaterialTransport === undefined
            ? {}
            : {
                  transportedVssCoefficientCommitmentMaterial:
                      binaryVssMaterialTransport.transportedVssCoefficientCommitmentMaterial,
              }),
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
        vssCoefficientCommitments: vssCoefficientCommitmentBundle.commitmentSet,
        privateVssEnvelopeCommitments,
        vssShareAcceptances,
        publicKeyShares,
        publicKeyShareProofs,
        localTrusteeSetupStates,
    });
    const setupPackage = createSetupPackage({
        setupContext: input.setupContext,
        qShare: input.qShare,
        phaseTranscript: input.phaseTranscript,
        commonRandomness: input.commonRandomness,
        vssCoefficientCommitments: vssCoefficientCommitmentBundle.commitmentSet,
        vssCoefficientCommitmentMaterial:
            setupPackageVssCoefficientCommitmentMaterial,
        ...(binaryVssMaterialTransport === undefined
            ? {}
            : {
                  transportedVssCoefficientCommitmentMaterial:
                      binaryVssMaterialTransport.transportedVssCoefficientCommitmentMaterial,
              }),
        privateVssEnvelopeCommitments,
        vssShareAcceptances,
        thresholdShareCommitments,
        sameSecretConsistency,
        sameSecretProofs,
        publicKeyShares,
        publicKeyShareProofs,
        publicKeyShareMaterial,
        publicKeyShareLnpProofs,
        evaluatorKeySchedule,
        relinearizationKeyShareRounds,
        galoisKeyShareBatches,
        evaluationKeys,
        setupCertificateInput,
    });
    const collectivePublicKey = setupPackage.collectivePublicKey as
        | CollectivePublicKey
        | undefined;
    if (collectivePublicKey === undefined) {
        throw new Error(
            'setup package assembly must derive a collective public key from accepted public-key material.',
        );
    }

    return {
        objectType: 'SetupCeremonyAssembly',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupContext: input.setupContext,
        vssCoefficientCommitments: vssCoefficientCommitmentBundle.commitmentSet,
        vssCoefficientCommitmentMaterial:
            setupPackageVssCoefficientCommitmentMaterial,
        ...(binaryVssMaterialTransport === undefined
            ? {}
            : {
                  transportedVssCoefficientCommitmentMaterial:
                      binaryVssMaterialTransport.transportedVssCoefficientCommitmentMaterial,
              }),
        privateVssEnvelopeCommitments,
        vssShareAcceptances,
        thresholdShareCommitments,
        sameSecretConsistency,
        sameSecretProofs,
        publicKeyShares,
        publicKeyShareProofs,
        publicKeyShareMaterial,
        publicKeyShareLnpProofs,
        collectivePublicKey,
        evaluatorKeySchedule,
        relinearizationKeyShareRounds,
        galoisKeyShareBatches,
        evaluationKeys,
        setupPackage,
        localTrusteeSetupStates,
        setupContributions,
    };
};
