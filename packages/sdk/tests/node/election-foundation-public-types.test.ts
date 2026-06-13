import { describe, expect, it } from 'vitest';

import type * as publicTypes from '#packages/sdk/src/index.js';

type BlockedTargetOpeningTypes = [
    // @ts-expect-error evaluator replay records are intentionally not public.
    publicTypes.EvaluatorReplayRecord,
    // @ts-expect-error accepted target records are intentionally not public.
    publicTypes.LocalReplayRecord,
    // @ts-expect-error accepted target records are intentionally not public.
    publicTypes.TargetAcceptedRecord,
    // @ts-expect-error target decryption share shells are intentionally not public.
    publicTypes.TopKDecryptionShareShell,
];

type BlockedPlaintextOracleTypes = [
    // @ts-expect-error field arithmetic types are intentionally not public.
    publicTypes.FieldElement,
    // @ts-expect-error Shamir helper types are intentionally not public.
    publicTypes.ShamirPolynomial,
    // @ts-expect-error plaintext oracle types are intentionally not public.
    publicTypes.PlaintextTopKOracle,
    // @ts-expect-error sparse target oracle types are intentionally not public.
    publicTypes.SparseTopKTarget,
];

type BlockedDirectInternalTypes = [
    // @ts-expect-error BGV setup packages are intentionally not public.
    publicTypes.BgvPassiveSetupPackage,
    // @ts-expect-error direct ballot witness material is intentionally not public.
    publicTypes.DirectEncryptedBallotWitness,
    // @ts-expect-error direct aggregate evaluator inputs are intentionally not public.
    publicTypes.TopKEvaluatorDirectAggregateInput,
];

type BlockedSetupWitnessTypes = [
    // @ts-expect-error evaluation-key proof-generation inputs carry raw witness material.
    publicTypes.EvaluationKeyProofCommonInput,
    // @ts-expect-error evaluation-key proof-generation inputs carry raw witness material.
    publicTypes.EvaluationKeyShareProofGenerationBase,
    // @ts-expect-error evaluation-key proof-generation outputs are not a public facade contract.
    publicTypes.EvaluationKeyShareProofGenerationOutput,
    // @ts-expect-error evaluation-key proof generators are not public facade inputs.
    publicTypes.EvaluationKeyShareProofGenerator,
    // @ts-expect-error evaluation-key proof-generation inputs carry raw witness material.
    publicTypes.GaloisKeyShareProofGeneration,
    // @ts-expect-error evaluation-key proof-generation inputs carry raw witness material.
    publicTypes.RelinearizationKeyShareProofGeneration,
];

type PublicFoundationTypes = [
    publicTypes.AcceptedTargetFinalityCheckpoint,
    publicTypes.BoardConsistencyInput,
    publicTypes.CastReceipt,
    publicTypes.ElectionManifest,
    publicTypes.FoundationTranscriptInput,
    publicTypes.FoundationTranscriptVerification,
    publicTypes.PollSpecInput,
    publicTypes.RegistrationEntry,
    publicTypes.RosterManifestTranscriptInput,
    publicTypes.TargetBoundShareSelectionProfile,
    publicTypes.TargetFinalityCheckpoint,
    publicTypes.TargetFinalityRecord,
    publicTypes.TargetFinalityVerificationInput,
    publicTypes.TargetProposal,
    publicTypes.ThresholdProfile,
    publicTypes.TrusteeSetupEntry,
];

type PublicSetupTypes = [
    publicTypes.BgvHeSecurityCertificate,
    publicTypes.BinaryChunkedSameSecretProofMaterialTransport,
    publicTypes.BinaryChunkedPublicKeyShareMaterialSet,
    publicTypes.BinaryChunkedPublicKeyShareMaterialTransport,
    publicTypes.BinaryChunkedPublicKeyShareProofMaterialTransport,
    publicTypes.BinaryChunkedEvaluationKeyShareMaterialTransport,
    publicTypes.BinaryChunkedPublicEvaluationKeyMaterialTransport,
    publicTypes.SetupPackageVssCoefficientCommitmentMaterialSet,
    publicTypes.SetupTransportedVssCoefficientCommitmentMaterial,
    publicTypes.SetupTransportedVssCoefficientCommitmentMaterialReference,
    publicTypes.SetupTransportedVssCoefficientCommitmentMaterialLike,
    publicTypes.VerifiedVssCoefficientCommitmentMaterial,
    publicTypes.VerifiedSetupProofMaterial,
    publicTypes.VerifiedSetupProofMaterialSet,
    publicTypes.CommonRandomnessCommit,
    publicTypes.CommonRandomnessCommitInput,
    publicTypes.CommonRandomnessReveal,
    publicTypes.CommonRandomnessRevealInput,
    publicTypes.CollectiveBgvSetupContext,
    publicTypes.EncryptedLocalTrusteeSetupState,
    publicTypes.EvaluatorKeySchedule,
    publicTypes.EvaluatorKeyScheduleInput,
    publicTypes.EvaluationKeyShareMaterial,
    publicTypes.EvaluationKeyShareMaterialTransportInput,
    publicTypes.ExportEncryptedLocalTrusteeSetupStateInput,
    publicTypes.ExportEncryptedLocalTrusteeSetupStateResult,
    publicTypes.GaloisKeyRootReference,
    publicTypes.GaloisKeyShareBatch,
    publicTypes.GaloisKeyShareBatchContribution,
    publicTypes.GaloisKeyShareBatchesInput,
    publicTypes.GaloisKeyShareBatchRootReference,
    publicTypes.GaloisKeyShareContribution,
    publicTypes.GaloisKeyShareMaterialRecord,
    publicTypes.GaloisKeyShareRootReference,
    publicTypes.LocalTrusteeSetupStateCommitment,
    publicTypes.LocalTrusteeSetupStateDeletionReceipt,
    publicTypes.LocalTrusteeSetupStateSealedMaterial,
    publicTypes.LocalTrusteeSetupStateSealedPayload,
    publicTypes.LocalTrusteeSetupStateVerification,
    publicTypes.PrivateVssEnvelopeVerificationReference,
    publicTypes.PrivateVssShareVerification,
    publicTypes.ProtocolRootSigner,
    publicTypes.PublicEvaluationKeySet,
    publicTypes.PublicEvaluationKeyMaterialTransportInput,
    publicTypes.PublicEvaluationKeySetInput,
    publicTypes.PublicKeyShareCoefficientVectorHash,
    publicTypes.PublicKeyShareCoefficientVectorMaterial,
    publicTypes.PublicKeyShareContributionInput,
    publicTypes.PublicKeyShareSuccinctProofMaterial,
    publicTypes.PublicKeyShareSuccinctProofRecord,
    publicTypes.PublicKeyShareSuccinctProofSet,
    publicTypes.PublicKeyShareSuccinctProofSetInput,
    publicTypes.PublicKeyShareMaterialContributionInput,
    publicTypes.PublicKeyShareMaterialRecord,
    publicTypes.PublicKeyShareMaterialSet,
    publicTypes.PublicKeyShareMaterialSetInput,
    publicTypes.SetupPackagePublicKeyShareMaterialSet,
    publicTypes.SetupTransportedPublicKeyShareMaterial,
    publicTypes.TransportedSameSecretProofMaterialSet,
    publicTypes.TransportedPublicKeyShareProofMaterialSet,
    publicTypes.TransportedEvaluationKeyShareProofMaterialSet,
    publicTypes.TransportedEvaluationKeyShareComponentMaterialSet,
    publicTypes.TransportedPublicEvaluationKeyMaterialSet,
    publicTypes.TrusteeEvaluationKeyProofRecord,
    publicTypes.TrusteeEvaluationKeyProofSet,
    publicTypes.PublicKeyShareProofRecord,
    publicTypes.PublicKeyShareProofSet,
    publicTypes.PublicKeyShareProofSetInput,
    publicTypes.PublicKeyShareRecord,
    publicTypes.PublicKeyShareSet,
    publicTypes.PublicKeyShareSetInput,
    publicTypes.RelinearizationKeyRootReference,
    publicTypes.RelinearizationKeyShareRoundOneRecord,
    publicTypes.RelinearizationKeyShareRoundTwoRecord,
    publicTypes.RelinearizationKeyShareRounds,
    publicTypes.RelinearizationKeyShareRoundsInput,
    publicTypes.RelinearizationLevelScheduleEntry,
    publicTypes.RelinearizationRoundOneContribution,
    publicTypes.RelinearizationRoundTwoContribution,
    publicTypes.RequiredGaloisKeyScheduleEntry,
    publicTypes.RequiredGaloisSet,
    publicTypes.RestoreLocalTrusteeSetupStateInput,
    publicTypes.RestoredLocalTrusteeSetupState,
    publicTypes.SameSecretProofMaterial,
    publicTypes.SameSecretProofRecord,
    publicTypes.SameSecretProofReference,
    publicTypes.SameSecretProofSet,
    publicTypes.SameSecretProofSetInput,
    publicTypes.SetupCertificateTransportInput,
    publicTypes.SetupCertificates,
    publicTypes.SetupCertificatesInput,
    publicTypes.SetupCommonRandomness,
    publicTypes.SetupCommonRandomnessInput,
    publicTypes.SetupCommitmentSecurityCertificate,
    publicTypes.SetupContribution,
    publicTypes.SetupContributionInput,
    publicTypes.SetupIntentInput,
    publicTypes.SetupPackage,
    publicTypes.SetupPackageInput,
    publicTypes.SetupPackageVerificationInputSource,
    publicTypes.SetupPackageVerification,
    publicTypes.SetupPhaseParticipantObject,
    publicTypes.SetupPhaseRecord,
    publicTypes.SetupPhaseRecordInput,
    publicTypes.SetupTransportCertificate,
    publicTypes.VerifySetupPackageInput,
    publicTypes.VerifyPrivateVssShareInput,
    publicTypes.VssComplaint,
    publicTypes.VssComplaintInput,
    publicTypes.VssShareAcceptance,
    publicTypes.VssShareAcceptanceInput,
];

type PublicTypeSurfaceProbe = {
    readonly blockedPlaintextOracleTypes: BlockedPlaintextOracleTypes;
    readonly blockedDirectInternalTypes: BlockedDirectInternalTypes;
    readonly blockedTargetOpeningTypes: BlockedTargetOpeningTypes;
    readonly blockedSetupWitnessTypes: BlockedSetupWitnessTypes;
    readonly publicFoundationTypes: PublicFoundationTypes;
    readonly publicSetupTypes: PublicSetupTypes;
};

type OptionalInputField<Input, FieldName extends keyof Input> = Exclude<
    Input[FieldName],
    undefined
>;

type VerifySetupPackageTransportFieldProbe = [
    OptionalInputField<
        publicTypes.VerifySetupPackageInput,
        'transportedVssCoefficientCommitmentMaterial'
    > extends publicTypes.SetupTransportedVssCoefficientCommitmentMaterialLike
        ? true
        : false,
    OptionalInputField<
        publicTypes.VerifySetupPackageInput,
        'verifiedVssCoefficientCommitmentMaterial'
    > extends publicTypes.VerifiedVssCoefficientCommitmentMaterial
        ? true
        : false,
    OptionalInputField<
        publicTypes.VerifySetupPackageInput,
        'verifiedSetupProofMaterials'
    > extends publicTypes.VerifiedSetupProofMaterialSet
        ? true
        : false,
    OptionalInputField<
        publicTypes.VerifySetupPackageInput,
        'transportedSameSecretProofMaterial'
    > extends publicTypes.TransportedSameSecretProofMaterialSet
        ? true
        : false,
    OptionalInputField<
        publicTypes.VerifySetupPackageInput,
        'transportedPublicKeyShareMaterial'
    > extends publicTypes.SetupTransportedPublicKeyShareMaterial
        ? true
        : false,
    OptionalInputField<
        publicTypes.VerifySetupPackageInput,
        'transportedPublicKeyShareProofMaterial'
    > extends publicTypes.TransportedPublicKeyShareProofMaterialSet
        ? true
        : false,
    OptionalInputField<
        publicTypes.VerifySetupPackageInput,
        'transportedEvaluationKeyShareProofMaterial'
    > extends publicTypes.TransportedEvaluationKeyShareProofMaterialSet
        ? true
        : false,
    OptionalInputField<
        publicTypes.VerifySetupPackageInput,
        'transportedEvaluationKeyShareComponentMaterial'
    > extends publicTypes.TransportedEvaluationKeyShareComponentMaterialSet
        ? true
        : false,
    OptionalInputField<
        publicTypes.VerifySetupPackageInput,
        'transportedPublicEvaluationKeyMaterial'
    > extends publicTypes.TransportedPublicEvaluationKeyMaterialSet
        ? true
        : false,
];

const verifySetupPackageTransportFieldProbe = [
    true,
    true,
    true,
    true,
    true,
    true,
    true,
    true,
    true,
] as const satisfies VerifySetupPackageTransportFieldProbe;

type SetupPackageTransportInputProbe = [
    OptionalInputField<
        publicTypes.SetupPackageInput,
        'transportedVssCoefficientCommitmentMaterial'
    > extends publicTypes.SetupTransportedVssCoefficientCommitmentMaterial
        ? true
        : false,
    OptionalInputField<
        publicTypes.SetupPackageInput,
        'transportedPublicKeyShareMaterial'
    > extends publicTypes.SetupTransportedPublicKeyShareMaterial
        ? true
        : false,
];

const setupPackageTransportInputProbe = [
    true,
    true,
] as const satisfies SetupPackageTransportInputProbe;

type PublicFoundationTypeNames = readonly string[] & {
    readonly length: PublicTypeSurfaceProbe['publicFoundationTypes']['length'];
};

const publicFoundationTypeNames = [
    'AcceptedTargetFinalityCheckpoint',
    'BoardConsistencyInput',
    'CastReceipt',
    'ElectionManifest',
    'FoundationTranscriptInput',
    'FoundationTranscriptVerification',
    'PollSpecInput',
    'RegistrationEntry',
    'RosterManifestTranscriptInput',
    'TargetBoundShareSelectionProfile',
    'TargetFinalityCheckpoint',
    'TargetFinalityRecord',
    'TargetFinalityVerificationInput',
    'TargetProposal',
    'ThresholdProfile',
    'TrusteeSetupEntry',
] as const satisfies PublicFoundationTypeNames;

type PublicSetupTypeNames = readonly string[] & {
    readonly length: PublicTypeSurfaceProbe['publicSetupTypes']['length'];
};

const publicSetupTypeNames = [
    'BgvHeSecurityCertificate',
    'BinaryChunkedSameSecretProofMaterialTransport',
    'BinaryChunkedPublicKeyShareMaterialSet',
    'BinaryChunkedPublicKeyShareMaterialTransport',
    'BinaryChunkedPublicKeyShareProofMaterialTransport',
    'BinaryChunkedEvaluationKeyShareMaterialTransport',
    'BinaryChunkedPublicEvaluationKeyMaterialTransport',
    'SetupPackageVssCoefficientCommitmentMaterialSet',
    'SetupTransportedVssCoefficientCommitmentMaterial',
    'SetupTransportedVssCoefficientCommitmentMaterialReference',
    'SetupTransportedVssCoefficientCommitmentMaterialLike',
    'VerifiedVssCoefficientCommitmentMaterial',
    'VerifiedSetupProofMaterial',
    'VerifiedSetupProofMaterialSet',
    'CommonRandomnessCommit',
    'CommonRandomnessCommitInput',
    'CommonRandomnessReveal',
    'CommonRandomnessRevealInput',
    'CollectiveBgvSetupContext',
    'EncryptedLocalTrusteeSetupState',
    'EvaluatorKeySchedule',
    'EvaluatorKeyScheduleInput',
    'EvaluationKeyShareMaterial',
    'EvaluationKeyShareMaterialTransportInput',
    'ExportEncryptedLocalTrusteeSetupStateInput',
    'ExportEncryptedLocalTrusteeSetupStateResult',
    'GaloisKeyRootReference',
    'GaloisKeyShareBatch',
    'GaloisKeyShareBatchContribution',
    'GaloisKeyShareBatchesInput',
    'GaloisKeyShareBatchRootReference',
    'GaloisKeyShareContribution',
    'GaloisKeyShareMaterialRecord',
    'GaloisKeyShareRootReference',
    'LocalTrusteeSetupStateCommitment',
    'LocalTrusteeSetupStateDeletionReceipt',
    'LocalTrusteeSetupStateSealedMaterial',
    'LocalTrusteeSetupStateSealedPayload',
    'LocalTrusteeSetupStateVerification',
    'PrivateVssEnvelopeVerificationReference',
    'PrivateVssShareVerification',
    'ProtocolRootSigner',
    'PublicEvaluationKeySet',
    'PublicEvaluationKeyMaterialTransportInput',
    'PublicEvaluationKeySetInput',
    'PublicKeyShareCoefficientVectorHash',
    'PublicKeyShareCoefficientVectorMaterial',
    'PublicKeyShareContributionInput',
    'PublicKeyShareSuccinctProofMaterial',
    'PublicKeyShareSuccinctProofRecord',
    'PublicKeyShareSuccinctProofSet',
    'PublicKeyShareSuccinctProofSetInput',
    'PublicKeyShareMaterialContributionInput',
    'PublicKeyShareMaterialRecord',
    'PublicKeyShareMaterialSet',
    'PublicKeyShareMaterialSetInput',
    'SetupPackagePublicKeyShareMaterialSet',
    'SetupTransportedPublicKeyShareMaterial',
    'TransportedSameSecretProofMaterialSet',
    'TransportedPublicKeyShareProofMaterialSet',
    'TransportedEvaluationKeyShareProofMaterialSet',
    'TransportedEvaluationKeyShareComponentMaterialSet',
    'TransportedPublicEvaluationKeyMaterialSet',
    'TrusteeEvaluationKeyProofRecord',
    'TrusteeEvaluationKeyProofSet',
    'PublicKeyShareProofRecord',
    'PublicKeyShareProofSet',
    'PublicKeyShareProofSetInput',
    'PublicKeyShareRecord',
    'PublicKeyShareSet',
    'PublicKeyShareSetInput',
    'RelinearizationKeyRootReference',
    'RelinearizationKeyShareRoundOneRecord',
    'RelinearizationKeyShareRoundTwoRecord',
    'RelinearizationKeyShareRounds',
    'RelinearizationKeyShareRoundsInput',
    'RelinearizationLevelScheduleEntry',
    'RelinearizationRoundOneContribution',
    'RelinearizationRoundTwoContribution',
    'RequiredGaloisKeyScheduleEntry',
    'RequiredGaloisSet',
    'RestoreLocalTrusteeSetupStateInput',
    'RestoredLocalTrusteeSetupState',
    'SameSecretProofMaterial',
    'SameSecretProofRecord',
    'SameSecretProofReference',
    'SameSecretProofSet',
    'SameSecretProofSetInput',
    'SetupCertificateTransportInput',
    'SetupCertificates',
    'SetupCertificatesInput',
    'SetupCommonRandomness',
    'SetupCommonRandomnessInput',
    'SetupCommitmentSecurityCertificate',
    'SetupContribution',
    'SetupContributionInput',
    'SetupIntentInput',
    'SetupPackage',
    'SetupPackageInput',
    'SetupPackageVerificationInputSource',
    'SetupPackageVerification',
    'SetupPhaseParticipantObject',
    'SetupPhaseRecord',
    'SetupPhaseRecordInput',
    'SetupTransportCertificate',
    'VerifySetupPackageInput',
    'VerifyPrivateVssShareInput',
    'VssComplaint',
    'VssComplaintInput',
    'VssShareAcceptance',
    'VssShareAcceptanceInput',
] as const satisfies PublicSetupTypeNames;

describe('election foundation public type surface', () => {
    it('keeps safe election foundation types available', () => {
        expect(publicFoundationTypeNames).toHaveLength(16);
    });

    it('keeps accepted setup phase, randomness, key-record, and local-state types available', () => {
        expect(publicSetupTypeNames).toHaveLength(111);
    });

    it('keeps setup verifier transport companions on concrete public types', () => {
        expect(verifySetupPackageTransportFieldProbe).toHaveLength(9);
    });

    it('keeps setup package transport companions on concrete public types', () => {
        expect(setupPackageTransportInputProbe).toHaveLength(2);
    });
});
