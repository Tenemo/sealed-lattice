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
    publicTypes.CommonRandomnessCommit,
    publicTypes.CommonRandomnessCommitInput,
    publicTypes.CommonRandomnessReveal,
    publicTypes.CommonRandomnessRevealInput,
    publicTypes.CollectiveBgvSetupContext,
    publicTypes.EncryptedLocalTrusteeSetupState,
    publicTypes.EvaluatorKeySchedule,
    publicTypes.EvaluatorKeyScheduleInput,
    publicTypes.ExportEncryptedLocalTrusteeSetupStateInput,
    publicTypes.ExportEncryptedLocalTrusteeSetupStateResult,
    publicTypes.GaloisKeyRootReference,
    publicTypes.GaloisKeyShareBatch,
    publicTypes.GaloisKeyShareBatchContribution,
    publicTypes.GaloisKeyShareBatchesInput,
    publicTypes.GaloisKeyShareBatchRootReference,
    publicTypes.GaloisKeyShareProof,
    publicTypes.GaloisKeyShareProofContribution,
    publicTypes.GaloisKeyShareProofMaterial,
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
    publicTypes.PublicEvaluationKeySetInput,
    publicTypes.PublicKeyShareCoefficientVectorHash,
    publicTypes.PublicKeyShareContributionInput,
    publicTypes.PublicKeyShareProofRecord,
    publicTypes.PublicKeyShareProofSet,
    publicTypes.PublicKeyShareProofSetInput,
    publicTypes.PublicKeyShareRecord,
    publicTypes.PublicKeyShareSet,
    publicTypes.PublicKeyShareSetInput,
    publicTypes.RelinearizationKeyRootReference,
    publicTypes.RelinearizationKeyShareProofMaterial,
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
    publicTypes.SameSecretProofReference,
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
    'CommonRandomnessCommit',
    'CommonRandomnessCommitInput',
    'CommonRandomnessReveal',
    'CommonRandomnessRevealInput',
    'CollectiveBgvSetupContext',
    'EncryptedLocalTrusteeSetupState',
    'EvaluatorKeySchedule',
    'EvaluatorKeyScheduleInput',
    'ExportEncryptedLocalTrusteeSetupStateInput',
    'ExportEncryptedLocalTrusteeSetupStateResult',
    'GaloisKeyRootReference',
    'GaloisKeyShareBatch',
    'GaloisKeyShareBatchContribution',
    'GaloisKeyShareBatchesInput',
    'GaloisKeyShareBatchRootReference',
    'GaloisKeyShareProof',
    'GaloisKeyShareProofContribution',
    'GaloisKeyShareProofMaterial',
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
    'PublicEvaluationKeySetInput',
    'PublicKeyShareCoefficientVectorHash',
    'PublicKeyShareContributionInput',
    'PublicKeyShareProofRecord',
    'PublicKeyShareProofSet',
    'PublicKeyShareProofSetInput',
    'PublicKeyShareRecord',
    'PublicKeyShareSet',
    'PublicKeyShareSetInput',
    'RelinearizationKeyRootReference',
    'RelinearizationKeyShareProofMaterial',
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
    'SameSecretProofReference',
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
        expect(publicSetupTypeNames).toHaveLength(74);
    });
});
