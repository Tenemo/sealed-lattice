import { decryptPrivateVssMailboxEnvelope } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommonRandomness } from './common-randomness-records.js';
import {
    createBinaryChunkedEvaluationKeyShareMaterialTransport,
    createBinaryChunkedPublicEvaluationKeyMaterialTransport,
    createGaloisKeyShareBatches,
    createPublicEvaluationKeySet,
    createRelinearizationKeyShareRounds,
    createTrusteeEvaluationKeyProofs,
    transportTrusteeEvaluationKeyProofSet,
    type EvaluationKeyShareMaterial,
    type GaloisKeyShareBatch,
    type GaloisKeyShareBatchContribution,
    type PublicEvaluationKeyMaterialReference,
    type PublicEvaluationKeySet,
    type RelinearizationKeyShareRounds,
    type RelinearizationRoundOneContribution,
    type RelinearizationRoundTwoContribution,
    type SameSecretProofReference,
    type TransportedEvaluationKeyShareComponentMaterialSet,
    type TransportedEvaluationKeyShareProofMaterialSet,
    type TransportedPublicEvaluationKeyMaterialSet,
    type TrusteeEvaluationKeyProofGenerator,
    type TrusteeEvaluationKeyProofSet,
    type TrusteeEvaluationKeyWitnessInput,
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
    createPrivateVssMailboxDeliverySetFromReferences,
    createPrivateVssMailboxSourceTrusteeDeliveryReferences,
    type PrivateVssEnvelopeCommitment,
    type PrivateVssMailboxDeliveryKernel,
    type PrivateVssMailboxDeliverySet,
    type PrivateVssShareProofFactory,
    type PrivateVssShareProofRandomnessFactory,
} from './private-vss-mailbox-delivery.js';
import {
    createBinaryChunkedPublicKeyShareMaterialBundle,
    createPublicKeyShareLnpProofSet,
    createPublicKeyShareMaterialSet,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    publicKeyShareMaterialEncoding,
    publicKeyShareMaterialTransportEncoding,
    type CollectivePublicKey,
    type PublicKeyShareLnpProofMaterial,
    type PublicKeyShareLnpProofSet,
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialContributionInput,
    type SetupPackagePublicKeyShareMaterialSet,
    type SetupTransportedPublicKeyShareMaterial,
    type TransportedPublicKeyShareProofMaterialSet,
    type PublicKeyShareProofSet,
    type PublicKeyShareSet,
} from './public-key-share-records.js';
import {
    createSameSecretProofSet,
    createSameSecretConsistencyStatementSet,
    type SameSecretConsistencyStatementSet,
    type SameSecretProofMaterial,
    type SameSecretProofSet,
    type TransportedSameSecretProofMaterialSet,
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
    acceptedBgvProfileRingDegree,
    acceptedBgvSetupQShare,
    acceptedBgvSetupQShareHash,
    acceptedBgvSetupQSharePrimes,
    createBinaryChunkedVssCoefficientCommitmentBundle,
    createStreamingBinaryChunkedVssCoefficientCommitmentBundle,
    createVssSourceTrusteeCoefficientCommitmentContribution,
    createVssCoefficientCommitmentBundle,
    type SetupPackageVssCoefficientCommitmentMaterialSet,
    type SetupTransportedVssCoefficientCommitmentMaterialLike,
    type VerifiedVssCoefficientCommitmentMaterial,
    type VssCoefficientCommitmentMaterialRecord,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeCoefficientCommitmentRecord,
    type VssSourceTrusteeCoefficientOpeningState,
    type VssSourceTrusteeCoefficientOpeningStateProvider,
    type VssSourceTrusteeCoefficientOpeningStateReference,
    type VssSourceTrusteeOpeningMaterial,
    type VssSourceTrusteeOpeningMaterialSource,
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

const setupProofMaterialTransportEncoding = 'binary-chunked-proof-bytes';
const acceptedBgvProfileParticipantCount = 10;
const acceptedBgvProfileThresholdDegree = 4;
const sameSecretProofMaterialTransportSetObjectType =
    'SetupTransportedSameSecretProofMaterialSet';
const sameSecretProofMaterialTransportObjectType =
    'SetupTransportedSameSecretProofMaterial';
const publicKeyShareProofMaterialTransportSetObjectType =
    'SetupTransportedPublicKeyShareProofMaterialSet';
const publicKeyShareProofMaterialTransportObjectType =
    'SetupTransportedPublicKeyShareProofMaterial';
const keySwitchComponentMaterialTransportEncoding =
    'binary-chunked-key-switch-component-vectors';
const evaluationKeyShareProofMaterialTransportSetObjectType =
    'SetupTransportedEvaluationKeyShareProofMaterialSet';
const evaluationKeyShareProofMaterialTransportObjectType =
    'SetupTransportedEvaluationKeyShareProofMaterial';
const evaluationKeyShareComponentMaterialTransportSetObjectType =
    'SetupTransportedEvaluationKeyShareComponentMaterialSet';
const evaluationKeyShareComponentMaterialTransportObjectType =
    'SetupTransportedEvaluationKeyShareComponentMaterial';

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
    readonly sameSecretLinkageAnchorProofAccountingHash: ProtocolHash;
    readonly sameSecretProofMaterials: readonly SameSecretProofMaterial[];
    readonly transportedSameSecretProofMaterial?: TransportedSameSecretProofMaterialSet;
    readonly publicKeyShareMaterialContributions: readonly PublicKeyShareMaterialContributionInput[];
    readonly publicKeyShareTboxParameterProfileHash: ProtocolHash;
    readonly publicKeyShareLnpProofMaterials: readonly PublicKeyShareLnpProofMaterial[];
    readonly transportedPublicKeyShareProofMaterial?: TransportedPublicKeyShareProofMaterialSet;
    readonly relinearizationCrpRoot: ProtocolHash;
    readonly galoisKeyCrpRoot: ProtocolHash;
    readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
    readonly relinearizationRoundOneContributions: readonly RelinearizationRoundOneContribution[];
    readonly relinearizationRoundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    readonly galoisKeyShareBatchContributions: readonly GaloisKeyShareBatchContribution[];
    readonly transportedEvaluationKeyShareProofMaterial?: TransportedEvaluationKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
    readonly publicEvaluationKeyMaterialReference?: PublicEvaluationKeyMaterialReference;
    readonly transportedPublicEvaluationKeyMaterial?: TransportedPublicEvaluationKeyMaterialSet;
    readonly trusteeEvaluationKeyProofs?: TrusteeEvaluationKeyProofSet;
    readonly trusteeEvaluationKeyProofGenerator?: TrusteeEvaluationKeyProofGenerator;
    readonly trusteeEvaluationKeyWitnesses?: readonly TrusteeEvaluationKeyWitnessInput[];
    readonly keySwitchDecompositionHash?: ProtocolHash;
    readonly setupCertificateInput: SetupPackageCertificateInput;
    readonly trustees: readonly SetupCeremonyTrusteeInput[];
    readonly sourceTrusteeOpeningStates?: readonly VssSourceTrusteeCoefficientOpeningState[];
    readonly sourceTrusteeOpeningStateProvider?: VssSourceTrusteeCoefficientOpeningStateProvider;
    readonly deliveryPhaseNumber: number;
    readonly verificationPhaseNumber: number;
    readonly privateVssShareProofMaterialEncoding?:
        | 'embedded-binary-proof-bytes-hex'
        | 'binary-chunked-proof-bytes';
    readonly vssCoefficientCommitmentMaterialEncoding?:
        | 'full-public-setup-commitment-values'
        | 'binary-chunked-full-public-setup-commitment-values';
    readonly publicKeyShareMaterialEncoding?:
        | typeof publicKeyShareMaterialEncoding
        | typeof publicKeyShareMaterialTransportEncoding;
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
    readonly transportedVssCoefficientCommitmentMaterial?: SetupTransportedVssCoefficientCommitmentMaterialLike;
    readonly verifiedVssCoefficientCommitmentMaterial?: VerifiedVssCoefficientCommitmentMaterial;
    readonly privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet;
    readonly vssShareAcceptances: VssShareAcceptanceSet;
    readonly thresholdShareCommitments: ThresholdShareCommitmentSet;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
    readonly transportedSameSecretProofMaterial?: TransportedSameSecretProofMaterialSet;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly publicKeyShareMaterial: SetupPackagePublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial?: SetupTransportedPublicKeyShareMaterial;
    readonly publicKeyShareLnpProofs: PublicKeyShareLnpProofSet;
    readonly transportedPublicKeyShareProofMaterial?: TransportedPublicKeyShareProofMaterialSet;
    readonly collectivePublicKey: CollectivePublicKey;
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
    readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
    readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
    readonly trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet;
    readonly transportedEvaluationKeyShareProofMaterial?: TransportedEvaluationKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
    readonly evaluationKeys: PublicEvaluationKeySet;
    readonly transportedPublicEvaluationKeyMaterial?: TransportedPublicEvaluationKeyMaterialSet;
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

const assertProfileRingQShareMatchesAcceptedProfile = (
    input: SetupCeremonyAssemblyInput,
): void => {
    const qShareRecord = assertJsonRecord(input.qShare, 'qShare');
    if (
        qShareRecord.objectType !== acceptedBgvSetupQShare.objectType ||
        qShareRecord.objectVersion !== acceptedBgvSetupQShare.objectVersion ||
        qShareRecord.sharingDomain !== acceptedBgvSetupQShare.sharingDomain ||
        qShareRecord.primeOrder !== acceptedBgvSetupQShare.primeOrder ||
        qShareRecord.targetDecryptionReadiness !==
            acceptedBgvSetupQShare.targetDecryptionReadiness ||
        !Array.isArray(qShareRecord.primes) ||
        qShareRecord.primes.length !== acceptedBgvSetupQSharePrimes.length ||
        qShareRecord.primes.some(
            (qSharePrime, rnsLimbIndex) =>
                qSharePrime !== acceptedBgvSetupQSharePrimes[rnsLimbIndex],
        )
    ) {
        throw new Error(
            'profile-ring setup assembly requires the accepted Q_share object.',
        );
    }
    if (input.setupContext.qShareHash !== acceptedBgvSetupQShareHash) {
        throw new Error(
            'profile-ring setup assembly requires setupContext.qShareHash to match the accepted Q_share object.',
        );
    }
};

const assertProfileRingCommonRandomnessMatchesPublicDerivations = (
    input: SetupCeremonyAssemblyInput,
): void => {
    if (
        input.commonRandomness.publicMatrixSeedHash !==
        input.publicMatrixSeedHash
    ) {
        throw new Error(
            'profile-ring setup assembly requires publicMatrixSeedHash to match commonRandomness.publicMatrixSeedHash.',
        );
    }
    const publicDerivations = assertJsonRecord(
        input.commonRandomness.publicDerivations,
        'commonRandomness.publicDerivations',
    );
    if (
        publicDerivations.objectType !== 'SetupPublicDerivations' ||
        publicDerivations.objectVersion !== 1 ||
        publicDerivations.setupProfileId !== 'CollectiveBgvSetup-v1' ||
        publicDerivations.publicMatrixSeedHash !== input.publicMatrixSeedHash ||
        publicDerivations.status !== 'deterministic-public-derivations-bound'
    ) {
        throw new Error(
            'profile-ring setup assembly requires kernel-derived setup public derivations.',
        );
    }

    const crpRoots = assertJsonRecord(
        publicDerivations.crpRoots,
        'commonRandomness.publicDerivations.crpRoots',
    );
    if (crpRoots.publicKeyCrpRoot !== input.publicKeyCrpRoot) {
        throw new Error(
            'profile-ring setup assembly requires publicKeyCrpRoot to match commonRandomness public derivations.',
        );
    }
    if (crpRoots.relinearizationCrpRoot !== input.relinearizationCrpRoot) {
        throw new Error(
            'profile-ring setup assembly requires relinearizationCrpRoot to match commonRandomness public derivations.',
        );
    }
    if (crpRoots.galoisKeyCrpRoot !== input.galoisKeyCrpRoot) {
        throw new Error(
            'profile-ring setup assembly requires galoisKeyCrpRoot to match commonRandomness public derivations.',
        );
    }

    const bgvPublicA = assertJsonRecord(
        publicDerivations.bgvPublicA,
        'commonRandomness.publicDerivations.bgvPublicA',
    );
    if (bgvPublicA.publicPolynomialRoot !== input.publicAPolynomialRoot) {
        throw new Error(
            'profile-ring setup assembly requires publicAPolynomialRoot to match commonRandomness public derivations.',
        );
    }
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

const assertTransportedSetupProofMaterial = (
    proofMaterial: Readonly<Record<string, unknown>>,
    fieldName: string,
): void => {
    if (proofMaterial.proofBytesHex !== undefined) {
        throw new Error(
            `profile-ring setup assembly requires transported ${fieldName} proof material.`,
        );
    }
    if (
        proofMaterial.proofBytesEncoding !== setupProofMaterialTransportEncoding
    ) {
        throw new Error(
            `profile-ring setup assembly requires binary-chunked ${fieldName} proof material.`,
        );
    }
};

const transportedSetupProofMaterialRoot = (
    proofMaterial: Readonly<Record<string, unknown>>,
    fieldName: string,
): string => {
    assertTransportedSetupProofMaterial(proofMaterial, fieldName);
    if (typeof proofMaterial.proofMaterialRoot !== 'string') {
        throw new TypeError(
            `profile-ring setup assembly requires ${fieldName} proofMaterialRoot.`,
        );
    }

    return proofMaterial.proofMaterialRoot;
};

const proofMaterialSetRecord = (
    value: unknown,
    fieldName: string,
): Readonly<Record<string, unknown>> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as Readonly<Record<string, unknown>>;
};

const assertTransportedSetupProofMaterialSetCovers = (
    transportedProofMaterialSet: unknown,
    transportedSetFieldName: string,
    transportedSetObjectType: string,
    transportedObjectType: string,
    proofFamily: string,
    proofMaterials: readonly Readonly<Record<string, unknown>>[],
    proofMaterialFieldName: string,
): void => {
    const materialSet = proofMaterialSetRecord(
        transportedProofMaterialSet,
        transportedSetFieldName,
    );
    if (
        materialSet.objectType !== transportedSetObjectType ||
        materialSet.objectVersion !== 1 ||
        materialSet.setupProfileId !== 'CollectiveBgvSetup-v1' ||
        materialSet.setupProofProfileId !== 'SealedLattice-LNP-SetupProof-v1' ||
        materialSet.proofFamily !== proofFamily
    ) {
        throw new Error(
            `${transportedSetFieldName} must match the transported ${proofFamily} proof material set profile.`,
        );
    }
    if (!Array.isArray(materialSet.proofMaterials)) {
        throw new TypeError(
            `${transportedSetFieldName}.proofMaterials must be an array.`,
        );
    }
    const transportedRoots = new Set<string>();
    materialSet.proofMaterials.forEach(
        (transportedProofMaterial, proofIndex) => {
            const proofMaterial = proofMaterialSetRecord(
                transportedProofMaterial,
                `${transportedSetFieldName}.proofMaterials.${String(proofIndex)}`,
            );
            if (
                proofMaterial.objectType !== transportedObjectType ||
                proofMaterial.objectVersion !== 1 ||
                proofMaterial.setupProfileId !== 'CollectiveBgvSetup-v1' ||
                proofMaterial.setupProofProfileId !==
                    'SealedLattice-LNP-SetupProof-v1' ||
                proofMaterial.proofFamily !== proofFamily
            ) {
                throw new Error(
                    `${transportedSetFieldName}.proofMaterials.${String(proofIndex)} must match the transported ${proofFamily} proof material profile.`,
                );
            }
            if (typeof proofMaterial.proofMaterialRoot !== 'string') {
                throw new TypeError(
                    `${transportedSetFieldName}.proofMaterials.${String(proofIndex)}.proofMaterialRoot must be a string.`,
                );
            }
            if (transportedRoots.has(proofMaterial.proofMaterialRoot)) {
                throw new Error(
                    `${transportedSetFieldName}.proofMaterials contains duplicate proofMaterialRoot entries.`,
                );
            }
            transportedRoots.add(proofMaterial.proofMaterialRoot);
        },
    );
    proofMaterials.forEach((proofMaterial, proofIndex) => {
        const proofMaterialRoot = transportedSetupProofMaterialRoot(
            proofMaterial,
            `${proofMaterialFieldName}.${String(proofIndex)}`,
        );
        if (!transportedRoots.has(proofMaterialRoot)) {
            throw new Error(
                `${transportedSetFieldName}.proofMaterials must include ${proofMaterialFieldName}.${String(proofIndex)}.proofMaterialRoot.`,
            );
        }
    });
};

const transportedTrusteeEvaluationKeyProofMaterialRoots = (
    trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet,
): readonly string[] =>
    trusteeEvaluationKeyProofs.proofRecords.map((proofRecord, recordIndex) =>
        transportedSetupProofMaterialRoot(
            proofRecord as Readonly<Record<string, unknown>>,
            `trusteeEvaluationKeyProofs.proofRecords.${String(recordIndex)}`,
        ),
    );

const transportedEvaluationKeyComponentMaterialRoots = (
    input: SetupCeremonyAssemblyInput,
): readonly string[] => {
    const roots: string[] = [];
    const addRoot = (
        shareMaterial: EvaluationKeyShareMaterial,
        shareMaterialPath: string,
    ): void => {
        const material = proofMaterialSetRecord(
            shareMaterial,
            shareMaterialPath,
        );
        if (typeof material.keySwitchComponentMaterialRoot !== 'string') {
            throw new TypeError(
                `${shareMaterialPath}.keySwitchComponentMaterialRoot must be a string.`,
            );
        }
        roots.push(material.keySwitchComponentMaterialRoot);
    };
    input.relinearizationRoundOneContributions.forEach((contribution, index) =>
        addRoot(
            contribution.shareMaterial,
            `relinearizationRoundOneContributions.${String(index)}.shareMaterial`,
        ),
    );
    input.relinearizationRoundTwoContributions.forEach((contribution, index) =>
        addRoot(
            contribution.shareMaterial,
            `relinearizationRoundTwoContributions.${String(index)}.shareMaterial`,
        ),
    );
    input.galoisKeyShareBatchContributions.forEach(
        (batchContribution, batchIndex) =>
            batchContribution.galoisKeyShares.forEach(
                (shareContribution, shareIndex) =>
                    addRoot(
                        shareContribution.shareMaterial,
                        `galoisKeyShareBatchContributions.${String(batchIndex)}.galoisKeyShares.${String(shareIndex)}.shareMaterial`,
                    ),
            ),
    );

    return roots;
};

const assertTransportedEvaluationKeyProofMaterialSetCovers = (
    transportedProofMaterialSet: unknown,
    proofMaterialRoots: readonly string[],
): void => {
    const materialSet = proofMaterialSetRecord(
        transportedProofMaterialSet,
        'transportedEvaluationKeyShareProofMaterial',
    );
    if (
        materialSet.objectType !==
            evaluationKeyShareProofMaterialTransportSetObjectType ||
        materialSet.objectVersion !== 1 ||
        materialSet.setupProfileId !== 'CollectiveBgvSetup-v1' ||
        materialSet.setupProofProfileId !== 'SealedLattice-LNP-SetupProof-v1' ||
        materialSet.proofFamily !== 'trustee-evaluation-key'
    ) {
        throw new Error(
            'transportedEvaluationKeyShareProofMaterial must match the transported trustee evaluation-key proof material set profile.',
        );
    }
    if (!Array.isArray(materialSet.proofMaterials)) {
        throw new TypeError(
            'transportedEvaluationKeyShareProofMaterial.proofMaterials must be an array.',
        );
    }
    const transportedRoots = new Set<string>();
    materialSet.proofMaterials.forEach((transportedProofMaterial, index) => {
        const proofMaterial = proofMaterialSetRecord(
            transportedProofMaterial,
            `transportedEvaluationKeyShareProofMaterial.proofMaterials.${String(index)}`,
        );
        if (
            proofMaterial.objectType !==
                evaluationKeyShareProofMaterialTransportObjectType ||
            proofMaterial.objectVersion !== 1 ||
            proofMaterial.setupProfileId !== 'CollectiveBgvSetup-v1' ||
            proofMaterial.setupProofProfileId !==
                'SealedLattice-LNP-SetupProof-v1' ||
            proofMaterial.proofFamily !== 'trustee-evaluation-key'
        ) {
            throw new Error(
                `transportedEvaluationKeyShareProofMaterial.proofMaterials.${String(index)} must match the transported evaluation-key proof material profile.`,
            );
        }
        if (typeof proofMaterial.proofMaterialRoot !== 'string') {
            throw new TypeError(
                `transportedEvaluationKeyShareProofMaterial.proofMaterials.${String(index)}.proofMaterialRoot must be a string.`,
            );
        }
        if (transportedRoots.has(proofMaterial.proofMaterialRoot)) {
            throw new Error(
                'transportedEvaluationKeyShareProofMaterial.proofMaterials contains duplicate proofMaterialRoot entries.',
            );
        }
        transportedRoots.add(proofMaterial.proofMaterialRoot);
    });
    proofMaterialRoots.forEach((proofMaterialRoot, index) => {
        if (!transportedRoots.has(proofMaterialRoot)) {
            throw new Error(
                `transportedEvaluationKeyShareProofMaterial.proofMaterials must include evaluation key proof material root ${String(index)}.`,
            );
        }
    });
};

const assertTransportedEvaluationKeyComponentMaterialSetCovers = (
    transportedComponentMaterialSet: unknown,
    componentMaterialRoots: readonly string[],
): void => {
    const materialSet = proofMaterialSetRecord(
        transportedComponentMaterialSet,
        'transportedEvaluationKeyShareComponentMaterial',
    );
    if (
        materialSet.objectType !==
            evaluationKeyShareComponentMaterialTransportSetObjectType ||
        materialSet.objectVersion !== 1 ||
        materialSet.setupProfileId !== 'CollectiveBgvSetup-v1' ||
        materialSet.setupProofProfileId !== 'SealedLattice-LNP-SetupProof-v1'
    ) {
        throw new Error(
            'transportedEvaluationKeyShareComponentMaterial must match the transported evaluation-key component material set profile.',
        );
    }
    if (!Array.isArray(materialSet.componentMaterials)) {
        throw new TypeError(
            'transportedEvaluationKeyShareComponentMaterial.componentMaterials must be an array.',
        );
    }
    const transportedRoots = new Set<string>();
    materialSet.componentMaterials.forEach((componentMaterial, index) => {
        const material = proofMaterialSetRecord(
            componentMaterial,
            `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(index)}`,
        );
        if (
            material.objectType !==
                evaluationKeyShareComponentMaterialTransportObjectType ||
            material.objectVersion !== 1 ||
            material.setupProfileId !== 'CollectiveBgvSetup-v1' ||
            material.setupProofProfileId !==
                'SealedLattice-LNP-SetupProof-v1' ||
            (material.proofFamily !== 'relinearization-key-share' &&
                material.proofFamily !== 'galois-key-share') ||
            material.keySwitchMaterialEncoding !==
                keySwitchComponentMaterialTransportEncoding
        ) {
            throw new Error(
                `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(index)} must match the transported evaluation-key component material profile.`,
            );
        }
        if (typeof material.keySwitchComponentMaterialRoot !== 'string') {
            throw new TypeError(
                `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(index)}.keySwitchComponentMaterialRoot must be a string.`,
            );
        }
        if (transportedRoots.has(material.keySwitchComponentMaterialRoot)) {
            throw new Error(
                'transportedEvaluationKeyShareComponentMaterial.componentMaterials contains duplicate keySwitchComponentMaterialRoot entries.',
            );
        }
        transportedRoots.add(material.keySwitchComponentMaterialRoot);
    });
    componentMaterialRoots.forEach((componentMaterialRoot, index) => {
        if (!transportedRoots.has(componentMaterialRoot)) {
            throw new Error(
                `transportedEvaluationKeyShareComponentMaterial.componentMaterials must include evaluation key component material root ${String(index)}.`,
            );
        }
    });
};

const publicEvaluationKeyReferenceFieldPairs = [
    ['chunkSizeBytes', 'publicEvaluationKeyMaterialChunkSizeBytes'],
    ['chunkCount', 'publicEvaluationKeyMaterialChunkCount'],
    ['totalByteLength', 'publicEvaluationKeyMaterialTotalByteLength'],
    ['fullObjectHash', 'publicEvaluationKeyMaterialFullObjectHash'],
    ['chunkRoot', 'publicEvaluationKeyMaterialChunkRoot'],
] as const;

const assertTransportedPublicEvaluationKeyMaterialCoversReference = (
    transportedPublicEvaluationKeyMaterial: TransportedPublicEvaluationKeyMaterialSet,
    publicEvaluationKeyMaterialReference: PublicEvaluationKeyMaterialReference,
): void => {
    const materialSet = proofMaterialSetRecord(
        transportedPublicEvaluationKeyMaterial,
        'transportedPublicEvaluationKeyMaterial',
    );
    if (
        materialSet.objectType !==
            'SetupTransportedPublicEvaluationKeyMaterialSet' ||
        materialSet.objectVersion !== 1 ||
        materialSet.setupProfileId !== 'CollectiveBgvSetup-v1' ||
        materialSet.setupProofProfileId !== 'SealedLattice-LNP-SetupProof-v1' ||
        materialSet.materialEncoding !==
            'binary-chunked-public-evaluation-key-root-manifest'
    ) {
        throw new Error(
            'transportedPublicEvaluationKeyMaterial must match the transported public evaluation-key material set profile.',
        );
    }
    const publicEvaluationKeyMaterialsValue =
        materialSet.publicEvaluationKeyMaterials;
    if (!Array.isArray(publicEvaluationKeyMaterialsValue)) {
        throw new TypeError(
            'transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials must be an array.',
        );
    }
    const publicEvaluationKeyMaterials =
        publicEvaluationKeyMaterialsValue as readonly unknown[];
    const matchingMaterial = publicEvaluationKeyMaterials.find(
        (material) =>
            proofMaterialSetRecord(
                material,
                'transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials',
            ).publicEvaluationKeyMaterialRoot ===
            publicEvaluationKeyMaterialReference.publicEvaluationKeyMaterialRoot,
    );
    if (matchingMaterial === undefined) {
        throw new Error(
            'transportedPublicEvaluationKeyMaterial must include the supplied publicEvaluationKeyMaterialReference root.',
        );
    }
    const material = proofMaterialSetRecord(
        matchingMaterial,
        'transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials',
    );
    for (const [
        materialFieldName,
        referenceFieldName,
    ] of publicEvaluationKeyReferenceFieldPairs) {
        if (
            material[materialFieldName] !==
            publicEvaluationKeyMaterialReference[referenceFieldName]
        ) {
            throw new Error(
                `transportedPublicEvaluationKeyMaterial public ${materialFieldName} must match publicEvaluationKeyMaterialReference.${referenceFieldName}.`,
            );
        }
    }
    if (
        !Array.isArray(material.chunkHashes) ||
        material.chunkHashes.length !==
            publicEvaluationKeyMaterialReference
                .publicEvaluationKeyMaterialChunkHashes.length ||
        material.chunkHashes.some(
            (chunkHash, chunkIndex) =>
                chunkHash !==
                publicEvaluationKeyMaterialReference
                    .publicEvaluationKeyMaterialChunkHashes[chunkIndex],
        )
    ) {
        throw new Error(
            'transportedPublicEvaluationKeyMaterial chunkHashes must match publicEvaluationKeyMaterialReference.publicEvaluationKeyMaterialChunkHashes.',
        );
    }
};

const assertTransportedEvaluationKeyShareMaterial = (
    shareMaterial: EvaluationKeyShareMaterial,
    fieldName: string,
): void => {
    const material = proofMaterialSetRecord(shareMaterial, fieldName);
    if (material.keySwitchComponentVectors !== undefined) {
        throw new Error(
            `profile-ring setup assembly requires transported ${fieldName} key-switch component material.`,
        );
    }
    if (
        material.keySwitchMaterialEncoding !==
        keySwitchComponentMaterialTransportEncoding
    ) {
        throw new Error(
            `profile-ring setup assembly requires binary-chunked ${fieldName} key-switch component material.`,
        );
    }
};

// The ceremony either generates the per-trustee evaluation-key proofs through
// the injected kernel generator (and builds the chunked component and proof
// transports itself), or receives a pre-built trustee proof set with its
// transported proof material.
const usesGeneratedTrusteeEvaluationKeyProofs = (
    input: SetupCeremonyAssemblyInput,
): boolean => {
    if (
        (input.trusteeEvaluationKeyProofGenerator === undefined) ===
        (input.trusteeEvaluationKeyProofs === undefined)
    ) {
        throw new Error(
            'setup assembly requires exactly one of trusteeEvaluationKeyProofGenerator or trusteeEvaluationKeyProofs.',
        );
    }
    if (input.trusteeEvaluationKeyProofGenerator === undefined) {
        if (
            input.trusteeEvaluationKeyWitnesses !== undefined ||
            input.keySwitchDecompositionHash !== undefined
        ) {
            throw new Error(
                'setup assembly accepts trusteeEvaluationKeyWitnesses and keySwitchDecompositionHash only with trusteeEvaluationKeyProofGenerator.',
            );
        }

        return false;
    }
    if (
        input.trusteeEvaluationKeyWitnesses === undefined ||
        input.keySwitchDecompositionHash === undefined
    ) {
        throw new Error(
            'setup assembly requires trusteeEvaluationKeyWitnesses and keySwitchDecompositionHash when trusteeEvaluationKeyProofGenerator is supplied.',
        );
    }
    if (
        input.transportedEvaluationKeyShareProofMaterial !== undefined ||
        input.transportedEvaluationKeyShareComponentMaterial !== undefined
    ) {
        throw new Error(
            'setup assembly generates evaluation-key proof and component transports when trusteeEvaluationKeyProofGenerator is supplied.',
        );
    }

    return true;
};

const assertProfileRingUsesTerminalMaterialTransport = (
    input: SetupCeremonyAssemblyInput,
): void => {
    if (input.ringDegree !== acceptedBgvProfileRingDegree) {
        return;
    }
    if (input.trustees.length !== acceptedBgvProfileParticipantCount) {
        throw new Error(
            'profile-ring setup assembly requires the first-profile 10-trustee roster.',
        );
    }
    if (input.thresholdDegree !== acceptedBgvProfileThresholdDegree) {
        throw new Error(
            'profile-ring setup assembly requires first-profile q_dec 4 threshold shares.',
        );
    }
    if (
        input.qSharePrimes.length !== acceptedBgvSetupQSharePrimes.length ||
        input.qSharePrimes.some(
            (qSharePrime, rnsLimbIndex) =>
                qSharePrime !== acceptedBgvSetupQSharePrimes[rnsLimbIndex],
        )
    ) {
        throw new Error(
            'profile-ring setup assembly requires the accepted Q_share prime list.',
        );
    }
    assertProfileRingQShareMatchesAcceptedProfile(input);
    if (
        input.vssCoefficientCommitmentMaterialEncoding !==
        'binary-chunked-full-public-setup-commitment-values'
    ) {
        throw new Error(
            'profile-ring setup assembly requires binary-chunked VSS coefficient commitment material.',
        );
    }
    if (
        input.publicKeyShareMaterialEncoding !==
        publicKeyShareMaterialTransportEncoding
    ) {
        throw new Error(
            'profile-ring setup assembly requires binary-chunked public-key share material.',
        );
    }
    input.sameSecretProofMaterials.forEach((proofMaterial) =>
        assertTransportedSetupProofMaterial(proofMaterial, 'same-secret'),
    );
    assertTransportedSetupProofMaterialSetCovers(
        input.transportedSameSecretProofMaterial,
        'transportedSameSecretProofMaterial',
        sameSecretProofMaterialTransportSetObjectType,
        sameSecretProofMaterialTransportObjectType,
        'same-secret-linkage-anchor',
        input.sameSecretProofMaterials,
        'sameSecretProofMaterials',
    );
    input.publicKeyShareLnpProofMaterials.forEach((proofMaterial) =>
        assertTransportedSetupProofMaterial(proofMaterial, 'public-key share'),
    );
    assertTransportedSetupProofMaterialSetCovers(
        input.transportedPublicKeyShareProofMaterial,
        'transportedPublicKeyShareProofMaterial',
        publicKeyShareProofMaterialTransportSetObjectType,
        publicKeyShareProofMaterialTransportObjectType,
        'public-key-share',
        input.publicKeyShareLnpProofMaterials,
        'publicKeyShareLnpProofMaterials',
    );
    const generatedTrusteeEvaluationKeyProofs =
        usesGeneratedTrusteeEvaluationKeyProofs(input);
    if (!generatedTrusteeEvaluationKeyProofs) {
        input.relinearizationRoundOneContributions.forEach((contribution) =>
            assertTransportedEvaluationKeyShareMaterial(
                contribution.shareMaterial,
                'relinearization',
            ),
        );
        input.relinearizationRoundTwoContributions.forEach((contribution) =>
            assertTransportedEvaluationKeyShareMaterial(
                contribution.shareMaterial,
                'relinearization',
            ),
        );
        input.galoisKeyShareBatchContributions.forEach((batchContribution) =>
            batchContribution.galoisKeyShares.forEach((shareContribution) =>
                assertTransportedEvaluationKeyShareMaterial(
                    shareContribution.shareMaterial,
                    'Galois',
                ),
            ),
        );
        const trusteeEvaluationKeyProofs = input.trusteeEvaluationKeyProofs;
        if (trusteeEvaluationKeyProofs === undefined) {
            throw new Error(
                'profile-ring setup assembly requires a pre-built trustee evaluation-key proof set when no generator is supplied.',
            );
        }
        assertTransportedEvaluationKeyProofMaterialSetCovers(
            input.transportedEvaluationKeyShareProofMaterial,
            transportedTrusteeEvaluationKeyProofMaterialRoots(
                trusteeEvaluationKeyProofs,
            ),
        );
        assertTransportedEvaluationKeyComponentMaterialSetCovers(
            input.transportedEvaluationKeyShareComponentMaterial,
            transportedEvaluationKeyComponentMaterialRoots(input),
        );
    }
    if (
        input.sourceTrusteeOpeningStateProvider === undefined ||
        input.sourceTrusteeOpeningStates !== undefined
    ) {
        throw new Error(
            'profile-ring setup assembly requires provider-backed source trustee opening state loading.',
        );
    }
    assertProfileRingCommonRandomnessMatchesPublicDerivations(input);
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

const sourceTrusteeOpeningReferencesFromInput = (
    input: Pick<
        SetupCeremonyAssemblyInput,
        'sourceTrusteeOpeningStateProvider' | 'sourceTrusteeOpeningStates'
    >,
): readonly VssSourceTrusteeCoefficientOpeningStateReference[] => {
    if (
        input.sourceTrusteeOpeningStates !== undefined &&
        input.sourceTrusteeOpeningStateProvider !== undefined
    ) {
        throw new Error(
            'provide sourceTrusteeOpeningStates or sourceTrusteeOpeningStateProvider, not both.',
        );
    }
    if (input.sourceTrusteeOpeningStateProvider !== undefined) {
        return input.sourceTrusteeOpeningStateProvider.sourceTrusteeReferences;
    }
    if (input.sourceTrusteeOpeningStates === undefined) {
        throw new Error(
            'sourceTrusteeOpeningStates or sourceTrusteeOpeningStateProvider is required.',
        );
    }

    return input.sourceTrusteeOpeningStates.map(
        (sourceTrusteeOpeningState) => ({
            sourceTrusteeIdentity:
                sourceTrusteeOpeningState.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition:
                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
        }),
    );
};

const orderedOpeningReferences = (
    sourceTrusteeReferences: readonly VssSourceTrusteeCoefficientOpeningStateReference[],
): readonly VssSourceTrusteeCoefficientOpeningStateReference[] =>
    [...sourceTrusteeReferences].sort(
        (left, right) =>
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition,
    );

const assertOpeningStatesMatchTrustees = (
    trustees: readonly SetupCeremonyTrusteeInput[],
    input: Pick<
        SetupCeremonyAssemblyInput,
        'sourceTrusteeOpeningStateProvider' | 'sourceTrusteeOpeningStates'
    >,
): void => {
    const sortedOpeningReferences = orderedOpeningReferences(
        sourceTrusteeOpeningReferencesFromInput(input),
    );
    if (sortedOpeningReferences.length !== trustees.length) {
        throw new Error(
            'source trustee opening references must contain one state per trustee.',
        );
    }
    sortedOpeningReferences.forEach(
        (sourceTrusteeReference, expectedPosition) => {
            const trustee = trustees[expectedPosition];
            if (
                sourceTrusteeReference.sourceTrusteeRosterPosition !==
                expectedPosition
            ) {
                throw new Error(
                    'source trustee opening reference roster positions must match trustees.',
                );
            }
            if (
                sourceTrusteeReference.sourceTrusteeIdentity !==
                trustee?.trusteeIdentity
            ) {
                throw new Error(
                    'source trustee opening reference identities must match trustees.',
                );
            }
        },
    );
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
    sourceTrusteeOpeningMaterialBySourceTrustee: readonly VssSourceTrusteeOpeningMaterial[],
    envelopeReference: PrivateVssEnvelopeVerificationReference,
): readonly VssCoefficientCommitmentMaterialRecord[] => {
    const sourceTrusteeOpeningMaterial =
        sourceTrusteeOpeningMaterialBySourceTrustee.find(
            (candidateMaterial) =>
                candidateMaterial.sourceTrusteeRosterPosition ===
                envelopeReference.sourceTrusteeRosterPosition,
        );
    if (sourceTrusteeOpeningMaterial === undefined) {
        throw new Error(
            'private VSS envelope source trustee must have local source material.',
        );
    }
    if (
        sourceTrusteeOpeningMaterial.sourceTrusteeIdentity !==
            envelopeReference.sourceTrusteeIdentity ||
        sourceTrusteeOpeningMaterial.sourceTrusteeCommitmentRoot !==
            envelopeReference.sourceTrusteeCommitmentRoot
    ) {
        throw new Error(
            'private VSS envelope source material binding must match the public envelope reference.',
        );
    }
    const materialRecords =
        sourceTrusteeOpeningMaterial.sourceTrusteeCoefficientCommitmentMaterialRecords;
    if (materialRecords.length === 0) {
        throw new Error(
            'private VSS envelope source trustee must have public VSS coefficient material.',
        );
    }

    return materialRecords;
};

const sourceTrusteeOpeningStateFromOpeningMaterial = (
    sourceTrusteeOpeningMaterial: VssSourceTrusteeOpeningMaterial,
): VssSourceTrusteeCoefficientOpeningState => ({
    sourceTrusteeIdentity: sourceTrusteeOpeningMaterial.sourceTrusteeIdentity,
    sourceTrusteeRosterPosition:
        sourceTrusteeOpeningMaterial.sourceTrusteeRosterPosition,
    coefficientOpenings: sourceTrusteeOpeningMaterial.coefficientOpenings.map(
        (opening) => ({
            rnsLimbIndex: opening.rnsLimbIndex,
            rnsPrime: opening.rnsPrime,
            shamirCoefficientIndex: opening.shamirCoefficientIndex,
            coefficientMessage: opening.coefficientMessage,
            randomnessByColumn: opening.randomnessByColumn,
        }),
    ),
});

const sourceTrusteeOpeningMaterialWithMaterialRecords = (
    input: Pick<
        SetupCeremonyAssemblyInput,
        | 'setupContext'
        | 'publicMatrixSeedHash'
        | 'qSharePrimes'
        | 'ringDegree'
        | 'thresholdDegree'
    > & {
        readonly participantCount: number;
        readonly sourceTrusteeOpeningMaterial: VssSourceTrusteeOpeningMaterial;
    },
): VssSourceTrusteeOpeningMaterial => {
    if (
        input.sourceTrusteeOpeningMaterial
            .sourceTrusteeCoefficientCommitmentMaterialRecords.length > 0
    ) {
        return input.sourceTrusteeOpeningMaterial;
    }

    const contribution =
        createVssSourceTrusteeCoefficientCommitmentContribution({
            setupContext: input.setupContext,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            qSharePrimes: input.qSharePrimes,
            ringDegree: input.ringDegree,
            participantCount: input.participantCount,
            thresholdDegree: input.thresholdDegree,
            sourceTrusteeOpeningState:
                sourceTrusteeOpeningStateFromOpeningMaterial(
                    input.sourceTrusteeOpeningMaterial,
                ),
        });
    if (
        contribution.sourceTrusteeRecord.sourceTrusteeCommitmentRoot !==
            input.sourceTrusteeOpeningMaterial.sourceTrusteeCommitmentRoot ||
        contribution.sourceTrusteeRecord.sourceTrusteeIdentity !==
            input.sourceTrusteeOpeningMaterial.sourceTrusteeIdentity ||
        contribution.sourceTrusteeRecord.sourceTrusteeRosterPosition !==
            input.sourceTrusteeOpeningMaterial.sourceTrusteeRosterPosition
    ) {
        throw new Error(
            'rebuilt source trustee VSS material must match the accepted source trustee commitment root.',
        );
    }

    return contribution.privateOpeningMaterial;
};

const sourceTrusteeMaterialRecordsForEnvelopeVerification = (
    input: Pick<
        SetupCeremonyAssemblyInput,
        | 'setupContext'
        | 'publicMatrixSeedHash'
        | 'qSharePrimes'
        | 'ringDegree'
        | 'thresholdDegree'
    > & {
        readonly participantCount: number;
        readonly sourceTrusteeOpeningMaterialSource: VssSourceTrusteeOpeningMaterialSource;
        readonly rebuiltMaterialBySourceTrustee: Map<
            number,
            VssSourceTrusteeOpeningMaterial
        >;
        readonly envelopeReference: PrivateVssEnvelopeVerificationReference;
    },
): readonly VssCoefficientCommitmentMaterialRecord[] => {
    const cachedMaterial = input.rebuiltMaterialBySourceTrustee.get(
        input.envelopeReference.sourceTrusteeRosterPosition,
    );
    if (cachedMaterial !== undefined) {
        return sourceTrusteeMaterialRecords(
            [cachedMaterial],
            input.envelopeReference,
        );
    }

    const sourceTrusteeReference =
        input.sourceTrusteeOpeningMaterialSource.sourceTrusteeReferences.find(
            (candidateReference) =>
                candidateReference.sourceTrusteeRosterPosition ===
                input.envelopeReference.sourceTrusteeRosterPosition,
        );
    if (sourceTrusteeReference === undefined) {
        throw new Error(
            'private VSS envelope source trustee must have local source material.',
        );
    }
    if (
        sourceTrusteeReference.sourceTrusteeIdentity !==
            input.envelopeReference.sourceTrusteeIdentity ||
        sourceTrusteeReference.sourceTrusteeCommitmentRoot !==
            input.envelopeReference.sourceTrusteeCommitmentRoot
    ) {
        throw new Error(
            'private VSS envelope source material binding must match the public envelope reference.',
        );
    }

    const sourceTrusteeOpeningMaterial =
        input.sourceTrusteeOpeningMaterialSource.loadSourceTrusteeOpeningMaterial(
            sourceTrusteeReference,
        );
    try {
        return sourceTrusteeMaterialRecords(
            [sourceTrusteeOpeningMaterial],
            input.envelopeReference,
        );
    } catch (error) {
        if (
            !(error instanceof Error) ||
            error.message !==
                'private VSS envelope source trustee must have public VSS coefficient material.'
        ) {
            throw error;
        }
    }

    const rebuiltMaterial = sourceTrusteeOpeningMaterialWithMaterialRecords({
        setupContext: input.setupContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        qSharePrimes: input.qSharePrimes,
        ringDegree: input.ringDegree,
        participantCount: input.participantCount,
        thresholdDegree: input.thresholdDegree,
        sourceTrusteeOpeningMaterial,
    });
    input.rebuiltMaterialBySourceTrustee.set(
        rebuiltMaterial.sourceTrusteeRosterPosition,
        rebuiltMaterial,
    );

    return sourceTrusteeMaterialRecords(
        [rebuiltMaterial],
        input.envelopeReference,
    );
};

const decryptAndVerifyRecipientEnvelopes = async (
    input: Pick<
        SetupCeremonyAssemblyInput,
        | 'kernel'
        | 'setupContext'
        | 'publicMatrixSeedHash'
        | 'qSharePrimes'
        | 'ringDegree'
        | 'thresholdDegree'
    > & {
        readonly trustee: SetupCeremonyTrusteeInput;
        readonly expectedParticipantCount: number;
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
        readonly sourceTrusteeOpeningMaterialSource: VssSourceTrusteeOpeningMaterialSource;
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

    const verifiedEnvelopes: JsonRecord[] = [];
    const rebuiltMaterialBySourceTrustee = new Map<
        number,
        VssSourceTrusteeOpeningMaterial
    >();
    for (const envelopeReference of envelopeReferences) {
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
        const localVerification = input.kernel.verifyPrivateVssShareEnvelope({
            setupContext: input.setupContext,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            sourceTrusteeCoefficientCommitmentRecord:
                sourceTrusteeRecordForEnvelope(
                    input.vssCoefficientCommitments,
                    envelopeReference,
                ),
            sourceTrusteeCoefficientCommitmentMaterialRecords:
                sourceTrusteeMaterialRecordsForEnvelopeVerification({
                    setupContext: input.setupContext,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    qSharePrimes: input.qSharePrimes,
                    ringDegree: input.ringDegree,
                    participantCount: input.expectedParticipantCount,
                    thresholdDegree: input.thresholdDegree,
                    sourceTrusteeOpeningMaterialSource:
                        input.sourceTrusteeOpeningMaterialSource,
                    envelopeReference,
                    rebuiltMaterialBySourceTrustee,
                }),
            privateEnvelope: decryptedEnvelope.privateEnvelope,
            transportedPrivateVssShareProofMaterial:
                envelopeReference.transportedPrivateVssShareProofMaterial,
            expectedPrivateEnvelopeHash: envelopeReference.privateEnvelopeHash,
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
        verifiedEnvelopes.push(decryptedEnvelope.privateEnvelope as JsonRecord);
    }

    return verifiedEnvelopes;
};

type PrivateVssDeliveryAndVerification = Readonly<{
    readonly privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet;
    readonly loadVerifiedPrivateVssShareEnvelopes: (
        trustee: SetupCeremonyTrusteeInput,
    ) => Promise<readonly JsonRecord[]>;
}>;

const createBinaryVssPrivateDeliveryAndVerification = async (
    input: Pick<
        SetupCeremonyAssemblyInput,
        | 'kernel'
        | 'setupContext'
        | 'phaseOrderHash'
        | 'publicMatrixSeedHash'
        | 'qSharePrimes'
        | 'ringDegree'
        | 'thresholdDegree'
        | 'deliveryPhaseNumber'
        | 'verificationPhaseNumber'
        | 'privateVssShareProofMaterialEncoding'
        | 'privateVssShareProofFactory'
        | 'privateVssShareProofRandomnessFactory'
    > & {
        readonly trustees: readonly SetupCeremonyTrusteeInput[];
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
        readonly sourceTrusteeOpeningMaterialSource: VssSourceTrusteeOpeningMaterialSource;
    },
): Promise<PrivateVssDeliveryAndVerification> => {
    const recipients = input.trustees.map((trustee) => ({
        recipientIdentity: trustee.trusteeIdentity,
        recipientRosterPosition: trustee.trusteeRosterPosition,
        mailboxPublicKeyBytesHex: trustee.mailboxPublicKeyBytesHex,
    }));
    const envelopeReferences: PrivateVssEnvelopeCommitment[] = [];
    const sourceTrusteeReferences = [
        ...input.sourceTrusteeOpeningMaterialSource.sourceTrusteeReferences,
    ].sort(
        (left, right) =>
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition,
    );

    for (const sourceTrusteeReference of sourceTrusteeReferences) {
        const sourceTrusteeOpeningMaterial =
            input.sourceTrusteeOpeningMaterialSource.loadSourceTrusteeOpeningMaterial(
                sourceTrusteeReference,
            );
        const sourceTrusteeOpeningMaterialWithRecords =
            sourceTrusteeOpeningMaterialWithMaterialRecords({
                setupContext: input.setupContext,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                qSharePrimes: input.qSharePrimes,
                ringDegree: input.ringDegree,
                participantCount: input.trustees.length,
                thresholdDegree: input.thresholdDegree,
                sourceTrusteeOpeningMaterial,
            });
        const sourceEnvelopeReferences =
            await createPrivateVssMailboxSourceTrusteeDeliveryReferences({
                kernel: input.kernel,
                setupContext: input.setupContext,
                phaseOrderHash: input.phaseOrderHash,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                vssCoefficientCommitmentRoot:
                    input.vssCoefficientCommitments
                        .vssCoefficientCommitmentRoot,
                qSharePrimes: input.qSharePrimes,
                ringDegree: input.ringDegree,
                participantCount: input.trustees.length,
                deliveryPhaseNumber: input.deliveryPhaseNumber,
                verificationPhaseNumber: input.verificationPhaseNumber,
                privateVssShareProofMaterialEncoding:
                    input.privateVssShareProofMaterialEncoding,
                privateVssShareProofFactory: input.privateVssShareProofFactory,
                privateVssShareProofRandomnessFactory:
                    input.privateVssShareProofRandomnessFactory,
                sourceTrusteeContributionState:
                    sourceTrusteeOpeningMaterialWithRecords,
                recipients,
            });
        envelopeReferences.push(...sourceEnvelopeReferences);
    }
    const privateVssEnvelopeCommitments =
        createPrivateVssMailboxDeliverySetFromReferences({
            kernel: input.kernel,
            setupContext: input.setupContext,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            vssCoefficientCommitmentRoot:
                input.vssCoefficientCommitments.vssCoefficientCommitmentRoot,
            participantCount: input.trustees.length,
            deliveryPhaseNumber: input.deliveryPhaseNumber,
            verificationPhaseNumber: input.verificationPhaseNumber,
            envelopeReferences,
        });

    return {
        privateVssEnvelopeCommitments,
        loadVerifiedPrivateVssShareEnvelopes: (trustee) =>
            decryptAndVerifyRecipientEnvelopes({
                kernel: input.kernel,
                setupContext: input.setupContext,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                qSharePrimes: input.qSharePrimes,
                ringDegree: input.ringDegree,
                thresholdDegree: input.thresholdDegree,
                trustee,
                expectedParticipantCount: input.trustees.length,
                vssCoefficientCommitments: input.vssCoefficientCommitments,
                sourceTrusteeOpeningMaterialSource:
                    input.sourceTrusteeOpeningMaterialSource,
                privateVssEnvelopeCommitments,
            }),
    };
};

const createPrivateVssDeliveryAndVerification = async (
    input: Pick<
        SetupCeremonyAssemblyInput,
        | 'kernel'
        | 'setupContext'
        | 'phaseOrderHash'
        | 'publicMatrixSeedHash'
        | 'qSharePrimes'
        | 'ringDegree'
        | 'thresholdDegree'
        | 'deliveryPhaseNumber'
        | 'verificationPhaseNumber'
        | 'privateVssShareProofMaterialEncoding'
        | 'privateVssShareProofFactory'
        | 'privateVssShareProofRandomnessFactory'
    > & {
        readonly trustees: readonly SetupCeremonyTrusteeInput[];
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
        readonly sourceTrusteeOpeningMaterialSource: VssSourceTrusteeOpeningMaterialSource;
        readonly useSourceMajorMaterialRebuild: boolean;
    },
): Promise<PrivateVssDeliveryAndVerification> => {
    if (input.useSourceMajorMaterialRebuild) {
        return createBinaryVssPrivateDeliveryAndVerification(input);
    }

    const privateVssEnvelopeCommitments =
        await createPrivateVssMailboxDeliverySet({
            kernel: input.kernel,
            setupContext: input.setupContext,
            phaseOrderHash: input.phaseOrderHash,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            vssCoefficientCommitmentRoot:
                input.vssCoefficientCommitments.vssCoefficientCommitmentRoot,
            qSharePrimes: input.qSharePrimes,
            ringDegree: input.ringDegree,
            participantCount: input.trustees.length,
            deliveryPhaseNumber: input.deliveryPhaseNumber,
            verificationPhaseNumber: input.verificationPhaseNumber,
            privateVssShareProofMaterialEncoding:
                input.privateVssShareProofMaterialEncoding,
            privateVssShareProofFactory: input.privateVssShareProofFactory,
            privateVssShareProofRandomnessFactory:
                input.privateVssShareProofRandomnessFactory,
            sourceTrusteeContributionStates:
                input.sourceTrusteeOpeningMaterialSource.sourceTrusteeReferences.map(
                    (sourceTrusteeReference) =>
                        input.sourceTrusteeOpeningMaterialSource.loadSourceTrusteeOpeningMaterial(
                            sourceTrusteeReference,
                        ),
                ),
            recipients: input.trustees.map((trustee) => ({
                recipientIdentity: trustee.trusteeIdentity,
                recipientRosterPosition: trustee.trusteeRosterPosition,
                mailboxPublicKeyBytesHex: trustee.mailboxPublicKeyBytesHex,
            })),
        });

    return {
        privateVssEnvelopeCommitments,
        loadVerifiedPrivateVssShareEnvelopes: (trustee) =>
            decryptAndVerifyRecipientEnvelopes({
                kernel: input.kernel,
                setupContext: input.setupContext,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                qSharePrimes: input.qSharePrimes,
                ringDegree: input.ringDegree,
                thresholdDegree: input.thresholdDegree,
                trustee,
                expectedParticipantCount: input.trustees.length,
                vssCoefficientCommitments: input.vssCoefficientCommitments,
                sourceTrusteeOpeningMaterialSource:
                    input.sourceTrusteeOpeningMaterialSource,
                privateVssEnvelopeCommitments,
            }),
    };
};

const createAcceptanceRecords = async (
    setupContext: CollectiveBgvSetupContext,
    trustees: readonly SetupCeremonyTrusteeInput[],
    privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet,
): Promise<readonly VssShareAcceptanceRecord[]> => {
    const trusteeByPosition = trusteeByRecipientPosition(trustees);
    const acceptanceRecords: VssShareAcceptanceRecord[] = [];
    const sortedEnvelopeReferences = [
        ...envelopeVerificationReferences(privateVssEnvelopeCommitments),
    ].sort((left, right) => {
        const sourceOrder =
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition;

        return sourceOrder === 0
            ? left.recipientRosterPosition - right.recipientRosterPosition
            : sourceOrder;
    });

    for (const envelopeReference of sortedEnvelopeReferences) {
        const recipientTrustee = trusteeByPosition.get(
            envelopeReference.recipientRosterPosition,
        );
        if (recipientTrustee === undefined) {
            throw new Error(
                'private VSS envelope recipient must be an accepted trustee.',
            );
        }

        acceptanceRecords.push(
            await createVssShareAcceptanceRecord({
                setupContext,
                privateVssEnvelopeCommitmentRoot:
                    privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot,
                envelopeReference,
                recoveryEpoch: recipientTrustee.recoveryEpoch,
                deviceEpoch: recipientTrustee.deviceEpoch,
                signingPublicKeyHash: recipientTrustee.signingPublicKeyHash,
                signRoot: recipientTrustee.signRoot,
            }),
        );
    }

    return acceptanceRecords;
};

const createLocalTrusteeSetupStates = async (
    input: Pick<SetupCeremonyAssemblyInput, 'setupContext'> & {
        readonly trustees: readonly SetupCeremonyTrusteeInput[];
        readonly thresholdShareCommitments: ThresholdShareCommitmentSet;
        readonly privateVssEnvelopeCommitments: PrivateVssMailboxDeliverySet;
        readonly loadVerifiedPrivateVssShareEnvelopes: (
            trustee: SetupCeremonyTrusteeInput,
        ) => Promise<readonly JsonRecord[]>;
        readonly vssShareAcceptances: VssShareAcceptanceSet;
    },
): Promise<readonly SetupCeremonyLocalTrusteeState[]> => {
    const localTrusteeSetupStates: SetupCeremonyLocalTrusteeState[] = [];
    for (const trustee of input.trustees) {
        const verifiedPrivateVssShareEnvelopes =
            await input.loadVerifiedPrivateVssShareEnvelopes(trustee);
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
        localTrusteeSetupStates.push({
            trusteeIdentity: trustee.trusteeIdentity,
            trusteeRosterPosition: trustee.trusteeRosterPosition,
            ...sealedLocalState,
        });
    }

    return localTrusteeSetupStates;
};

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
    assertProfileRingUsesTerminalMaterialTransport(input);
    if (
        input.transportedPublicEvaluationKeyMaterial !== undefined &&
        input.publicEvaluationKeyMaterialReference === undefined
    ) {
        throw new Error(
            'transportedPublicEvaluationKeyMaterial requires publicEvaluationKeyMaterialReference; omit both to let profile-ring assembly generate the material.',
        );
    }
    if (
        input.transportedPublicEvaluationKeyMaterial !== undefined &&
        input.publicEvaluationKeyMaterialReference !== undefined
    ) {
        assertTransportedPublicEvaluationKeyMaterialCoversReference(
            input.transportedPublicEvaluationKeyMaterial,
            input.publicEvaluationKeyMaterialReference,
        );
    }
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
    assertOpeningStatesMatchTrustees(trustees, input);

    const vssCoefficientCommitmentBundleInput = {
        setupContext: input.setupContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        qSharePrimes: input.qSharePrimes,
        ringDegree: input.ringDegree,
        participantCount: trustees.length,
        thresholdDegree: input.thresholdDegree,
        ...(input.sourceTrusteeOpeningStates === undefined
            ? {}
            : { sourceTrusteeOpeningStates: input.sourceTrusteeOpeningStates }),
        ...(input.sourceTrusteeOpeningStateProvider === undefined
            ? {}
            : {
                  sourceTrusteeOpeningStateProvider:
                      input.sourceTrusteeOpeningStateProvider,
              }),
        setupCommitmentComputer: input.kernel.computeSetupCommitmentFromOpening,
    };
    const useBinaryVssCoefficientCommitmentMaterial =
        input.vssCoefficientCommitmentMaterialEncoding ===
        'binary-chunked-full-public-setup-commitment-values';
    const canStreamBinaryVssMaterial =
        input.kernel.beginThresholdShareCommitmentsFromTransportStream !==
            undefined &&
        input.kernel.absorbThresholdShareCommitmentsFromTransportStreamChunk !==
            undefined &&
        input.kernel.finishThresholdShareCommitmentsFromTransportStream !==
            undefined;
    if (
        useBinaryVssCoefficientCommitmentMaterial &&
        input.ringDegree === acceptedBgvProfileRingDegree &&
        !canStreamBinaryVssMaterial
    ) {
        throw new Error(
            'profile-ring setup assembly requires streaming kernel threshold-share derivation from transported VSS material.',
        );
    }
    const streamingBinaryVssCoefficientCommitmentBundle =
        useBinaryVssCoefficientCommitmentMaterial && canStreamBinaryVssMaterial
            ? createStreamingBinaryChunkedVssCoefficientCommitmentBundle({
                  ...vssCoefficientCommitmentBundleInput,
                  thresholdShareCommitmentTransportStreamer: {
                      beginThresholdShareCommitmentsFromTransportStream:
                          input.kernel
                              .beginThresholdShareCommitmentsFromTransportStream,
                      absorbThresholdShareCommitmentsFromTransportStreamChunk:
                          input.kernel
                              .absorbThresholdShareCommitmentsFromTransportStreamChunk,
                      finishThresholdShareCommitmentsFromTransportStream:
                          input.kernel
                              .finishThresholdShareCommitmentsFromTransportStream,
                  },
              })
            : undefined;
    const directBinaryVssCoefficientCommitmentBundle =
        useBinaryVssCoefficientCommitmentMaterial &&
        streamingBinaryVssCoefficientCommitmentBundle === undefined
            ? createBinaryChunkedVssCoefficientCommitmentBundle(
                  vssCoefficientCommitmentBundleInput,
              )
            : undefined;
    const binaryVssCoefficientCommitmentBundle =
        streamingBinaryVssCoefficientCommitmentBundle ??
        directBinaryVssCoefficientCommitmentBundle;
    const verifiedVssCoefficientCommitmentMaterial =
        binaryVssCoefficientCommitmentBundle !== undefined &&
        'verifiedVssCoefficientCommitmentMaterial' in
            binaryVssCoefficientCommitmentBundle
            ? binaryVssCoefficientCommitmentBundle.verifiedVssCoefficientCommitmentMaterial
            : undefined;
    const vssCoefficientCommitmentBundle =
        binaryVssCoefficientCommitmentBundle ??
        createVssCoefficientCommitmentBundle(
            vssCoefficientCommitmentBundleInput,
        );
    const binaryVssMaterialTransport =
        binaryVssCoefficientCommitmentBundle === undefined
            ? undefined
            : {
                  materialSet: binaryVssCoefficientCommitmentBundle.materialSet,
                  transportedVssCoefficientCommitmentMaterial:
                      binaryVssCoefficientCommitmentBundle.transportedVssCoefficientCommitmentMaterial,
              };
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
        proofAccountingHash: input.sameSecretLinkageAnchorProofAccountingHash,
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
    const publicKeyShareMaterialInput = {
        setupContext: input.setupContext,
        qSharePrimes: input.qSharePrimes,
        participantCount: trustees.length,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShares,
        materialContributions: input.publicKeyShareMaterialContributions,
    } as const;
    const directBinaryPublicKeyShareMaterialBundle =
        input.publicKeyShareMaterialEncoding ===
        publicKeyShareMaterialTransportEncoding
            ? createBinaryChunkedPublicKeyShareMaterialBundle(
                  publicKeyShareMaterialInput,
              )
            : undefined;
    const publicKeyShareMaterial =
        directBinaryPublicKeyShareMaterialBundle === undefined
            ? createPublicKeyShareMaterialSet(publicKeyShareMaterialInput)
            : directBinaryPublicKeyShareMaterialBundle.materialSet;
    const binaryPublicKeyShareMaterialTransport =
        directBinaryPublicKeyShareMaterialBundle === undefined
            ? undefined
            : {
                  materialSet:
                      directBinaryPublicKeyShareMaterialBundle.materialSet,
                  transportedPublicKeyShareMaterial:
                      directBinaryPublicKeyShareMaterialBundle.transportedPublicKeyShareMaterial,
              };
    const setupPackagePublicKeyShareMaterial =
        binaryPublicKeyShareMaterialTransport?.materialSet ??
        publicKeyShareMaterial;
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
    } as const;
    const generateTrusteeEvaluationKeyProofs =
        usesGeneratedTrusteeEvaluationKeyProofs(input);
    const generatedEvaluationKeyShareMaterialTransport =
        generateTrusteeEvaluationKeyProofs
            ? createBinaryChunkedEvaluationKeyShareMaterialTransport({
                  sameSecretProofReferences,
                  relinearizationRoundOneContributions:
                      input.relinearizationRoundOneContributions,
                  relinearizationRoundTwoContributions:
                      input.relinearizationRoundTwoContributions,
                  galoisKeyShareBatchContributions:
                      input.galoisKeyShareBatchContributions,
              })
            : undefined;
    const transportedEvaluationKeyShareComponentMaterial =
        generatedEvaluationKeyShareMaterialTransport?.transportedEvaluationKeyShareComponentMaterial ??
        input.transportedEvaluationKeyShareComponentMaterial;
    const relinearizationKeyShareRounds = createRelinearizationKeyShareRounds({
        ...evaluationKeyProofCommonInput,
        roundOneContributions:
            generatedEvaluationKeyShareMaterialTransport?.relinearizationRoundOneContributions ??
            input.relinearizationRoundOneContributions,
        roundTwoContributions:
            generatedEvaluationKeyShareMaterialTransport?.relinearizationRoundTwoContributions ??
            input.relinearizationRoundTwoContributions,
    });
    const galoisKeyShareBatches = createGaloisKeyShareBatches({
        ...evaluationKeyProofCommonInput,
        batchContributions:
            generatedEvaluationKeyShareMaterialTransport?.galoisKeyShareBatchContributions ??
            input.galoisKeyShareBatchContributions,
    });
    const generatedTrusteeEvaluationKeyProofTransport = (() => {
        if (!generateTrusteeEvaluationKeyProofs) {
            return undefined;
        }
        if (
            input.trusteeEvaluationKeyProofGenerator === undefined ||
            input.trusteeEvaluationKeyWitnesses === undefined ||
            input.keySwitchDecompositionHash === undefined
        ) {
            throw new Error(
                'setup assembly requires trusteeEvaluationKeyProofGenerator, trusteeEvaluationKeyWitnesses, and keySwitchDecompositionHash to generate trustee evaluation-key proofs.',
            );
        }

        return transportTrusteeEvaluationKeyProofSet(
            createTrusteeEvaluationKeyProofs({
                ...evaluationKeyProofCommonInput,
                relinearizationKeyShareRounds,
                galoisKeyShareBatches,
                keySwitchDecompositionHash: input.keySwitchDecompositionHash,
                trusteeWitnesses: input.trusteeEvaluationKeyWitnesses,
                trusteeEvaluationKeyProofGenerator:
                    input.trusteeEvaluationKeyProofGenerator,
                ...(transportedEvaluationKeyShareComponentMaterial === undefined
                    ? {}
                    : {
                          transportedEvaluationKeyShareComponentMaterial,
                      }),
            }),
        );
    })();
    const trusteeEvaluationKeyProofs =
        generatedTrusteeEvaluationKeyProofTransport?.trusteeEvaluationKeyProofs ??
        input.trusteeEvaluationKeyProofs;
    if (trusteeEvaluationKeyProofs === undefined) {
        throw new Error(
            'setup assembly requires a trustee evaluation-key proof set.',
        );
    }
    const transportedEvaluationKeyShareProofMaterial =
        generatedTrusteeEvaluationKeyProofTransport?.transportedEvaluationKeyShareProofMaterial ??
        input.transportedEvaluationKeyShareProofMaterial;
    const generatedPublicEvaluationKeyMaterialTransport =
        input.publicEvaluationKeyMaterialReference === undefined &&
        input.ringDegree === acceptedBgvProfileRingDegree
            ? createBinaryChunkedPublicEvaluationKeyMaterialTransport({
                  ...evaluationKeyProofCommonInput,
                  relinearizationKeyShareRounds,
                  galoisKeyShareBatches,
                  ...(transportedEvaluationKeyShareComponentMaterial ===
                  undefined
                      ? {}
                      : {
                            transportedEvaluationKeyShareComponentMaterial:
                                transportedEvaluationKeyShareComponentMaterial,
                        }),
              })
            : undefined;
    const evaluationKeys =
        generatedPublicEvaluationKeyMaterialTransport?.evaluationKeys ??
        createPublicEvaluationKeySet({
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
    const transportedPublicEvaluationKeyMaterial =
        generatedPublicEvaluationKeyMaterialTransport?.transportedPublicEvaluationKeyMaterial ??
        input.transportedPublicEvaluationKeyMaterial;
    const {
        privateVssEnvelopeCommitments,
        loadVerifiedPrivateVssShareEnvelopes,
    } = await createPrivateVssDeliveryAndVerification({
        kernel: input.kernel,
        setupContext: input.setupContext,
        phaseOrderHash: input.phaseOrderHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        qSharePrimes: input.qSharePrimes,
        ringDegree: input.ringDegree,
        thresholdDegree: input.thresholdDegree,
        trustees,
        vssCoefficientCommitments: vssCoefficientCommitmentBundle.commitmentSet,
        sourceTrusteeOpeningMaterialSource:
            vssCoefficientCommitmentBundle.sourceTrusteeOpeningMaterialSource,
        deliveryPhaseNumber: input.deliveryPhaseNumber,
        verificationPhaseNumber: input.verificationPhaseNumber,
        privateVssShareProofMaterialEncoding:
            input.privateVssShareProofMaterialEncoding,
        privateVssShareProofFactory: input.privateVssShareProofFactory,
        privateVssShareProofRandomnessFactory:
            input.privateVssShareProofRandomnessFactory,
        useSourceMajorMaterialRebuild: binaryVssMaterialTransport !== undefined,
    });
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
    const thresholdShareCommitments =
        streamingBinaryVssCoefficientCommitmentBundle !== undefined
            ? (streamingBinaryVssCoefficientCommitmentBundle.thresholdShareCommitments as ThresholdShareCommitmentSet)
            : binaryVssMaterialTransport !== undefined &&
                input.kernel.deriveThresholdShareCommitmentsFromTransport !==
                    undefined
              ? (() => {
                    const derivation =
                        input.kernel.deriveThresholdShareCommitmentsFromTransport(
                            {
                                setupContext: input.setupContext,
                                publicMatrixSeedHash:
                                    input.publicMatrixSeedHash,
                                vssCoefficientCommitmentRoot:
                                    vssCoefficientCommitmentBundle.commitmentSet
                                        .vssCoefficientCommitmentRoot,
                                sourceTrusteeCoefficientCommitmentRecords:
                                    vssCoefficientCommitmentBundle.commitmentSet
                                        .sourceTrusteeRecords,
                                transportedVssCoefficientCommitmentMaterial:
                                    binaryVssMaterialTransport.transportedVssCoefficientCommitmentMaterial,
                            },
                        );
                    const derivedMaterialRoot =
                        derivation.vssCoefficientCommitmentMaterial
                            .vssCoefficientCommitmentMaterialRoot;
                    if (
                        derivedMaterialRoot !==
                        setupPackageVssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot
                    ) {
                        throw new Error(
                            'kernel-derived transported VSS material root must match the setup package material root.',
                        );
                    }
                    if (
                        derivation.thresholdShareCommitments
                            .thresholdShareCommitmentRoot !==
                        derivation.thresholdShareCommitmentRoot
                    ) {
                        throw new Error(
                            'kernel-derived threshold-share commitment root must match the returned threshold-share commitments.',
                        );
                    }

                    return derivation.thresholdShareCommitments as ThresholdShareCommitmentSet;
                })()
              : (() => {
                    if (
                        binaryVssMaterialTransport !== undefined &&
                        input.ringDegree === acceptedBgvProfileRingDegree
                    ) {
                        throw new Error(
                            'profile-ring setup assembly requires kernel threshold-share derivation from transported VSS material.',
                        );
                    }

                    return deriveThresholdShareCommitments({
                        setupContext: input.setupContext,
                        vssCoefficientCommitments:
                            vssCoefficientCommitmentBundle.commitmentSet,
                        vssCoefficientCommitmentMaterial:
                            setupPackageVssCoefficientCommitmentMaterial,
                        ...(binaryVssMaterialTransport === undefined
                            ? {}
                            : {
                                  transportedVssCoefficientCommitmentMaterial:
                                      binaryVssMaterialTransport.transportedVssCoefficientCommitmentMaterial,
                              }),
                    });
                })();
    const localTrusteeSetupStates = await createLocalTrusteeSetupStates({
        setupContext: input.setupContext,
        trustees,
        thresholdShareCommitments,
        privateVssEnvelopeCommitments,
        loadVerifiedPrivateVssShareEnvelopes,
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
        ...(verifiedVssCoefficientCommitmentMaterial === undefined
            ? {}
            : {
                  verifiedVssCoefficientCommitmentMaterial,
              }),
        privateVssEnvelopeCommitments,
        vssShareAcceptances,
        thresholdShareCommitments,
        sameSecretConsistency,
        sameSecretProofs,
        ...(input.transportedSameSecretProofMaterial === undefined
            ? {}
            : {
                  transportedSameSecretProofMaterial:
                      input.transportedSameSecretProofMaterial,
              }),
        publicKeyShares,
        publicKeyShareProofs,
        publicKeyShareMaterial: setupPackagePublicKeyShareMaterial,
        ...(binaryPublicKeyShareMaterialTransport === undefined
            ? {}
            : {
                  transportedPublicKeyShareMaterial:
                      binaryPublicKeyShareMaterialTransport.transportedPublicKeyShareMaterial,
              }),
        publicKeyShareLnpProofs,
        ...(input.transportedPublicKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedPublicKeyShareProofMaterial:
                      input.transportedPublicKeyShareProofMaterial,
              }),
        evaluatorKeySchedule,
        relinearizationKeyShareRounds,
        galoisKeyShareBatches,
        trusteeEvaluationKeyProofs,
        ...(transportedEvaluationKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareProofMaterial:
                      transportedEvaluationKeyShareProofMaterial,
              }),
        ...(transportedEvaluationKeyShareComponentMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareComponentMaterial:
                      transportedEvaluationKeyShareComponentMaterial,
              }),
        evaluationKeys,
        ...(transportedPublicEvaluationKeyMaterial === undefined
            ? {}
            : {
                  transportedPublicEvaluationKeyMaterial:
                      transportedPublicEvaluationKeyMaterial,
              }),
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
        ...(verifiedVssCoefficientCommitmentMaterial === undefined
            ? {}
            : {
                  verifiedVssCoefficientCommitmentMaterial,
              }),
        privateVssEnvelopeCommitments,
        vssShareAcceptances,
        thresholdShareCommitments,
        sameSecretConsistency,
        sameSecretProofs,
        ...(input.transportedSameSecretProofMaterial === undefined
            ? {}
            : {
                  transportedSameSecretProofMaterial:
                      input.transportedSameSecretProofMaterial,
              }),
        publicKeyShares,
        publicKeyShareProofs,
        publicKeyShareMaterial: setupPackagePublicKeyShareMaterial,
        ...(binaryPublicKeyShareMaterialTransport === undefined
            ? {}
            : {
                  transportedPublicKeyShareMaterial:
                      binaryPublicKeyShareMaterialTransport.transportedPublicKeyShareMaterial,
              }),
        publicKeyShareLnpProofs,
        ...(input.transportedPublicKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedPublicKeyShareProofMaterial:
                      input.transportedPublicKeyShareProofMaterial,
              }),
        collectivePublicKey,
        evaluatorKeySchedule,
        relinearizationKeyShareRounds,
        galoisKeyShareBatches,
        trusteeEvaluationKeyProofs,
        ...(transportedEvaluationKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareProofMaterial:
                      transportedEvaluationKeyShareProofMaterial,
              }),
        ...(transportedEvaluationKeyShareComponentMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareComponentMaterial:
                      transportedEvaluationKeyShareComponentMaterial,
              }),
        evaluationKeys,
        ...(transportedPublicEvaluationKeyMaterial === undefined
            ? {}
            : {
                  transportedPublicEvaluationKeyMaterial:
                      transportedPublicEvaluationKeyMaterial,
              }),
        setupPackage,
        localTrusteeSetupStates,
        setupContributions,
    };
};
