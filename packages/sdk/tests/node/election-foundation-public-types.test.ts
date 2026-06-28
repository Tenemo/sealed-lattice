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
    publicTypes.TargetDecryptionResultVerification,
    publicTypes.ThresholdProfile,
    publicTypes.TrusteeSetupEntry,
];

// Verifier-only setup type surface. The setup-assembly builders and their input/output
// types are no longer public; the relocated builders live in
// packages/sdk/tests/support/internal-setup-flow.ts.
type PublicSetupTypes = [
    publicTypes.AcceptedSetupHandoff,
    publicTypes.CollectiveBgvSetupContext,
    publicTypes.PrivateVssShareVerification,
    publicTypes.SetupPackage,
    publicTypes.SetupPackageVerification,
    publicTypes.SetupPackageVerificationInputSource,
    publicTypes.SetupTransportedPublicKeyShareMaterial,
    publicTypes.SetupTransportedVssCoefficientCommitmentMaterialLike,
    publicTypes.TransportedEvaluationKeyShareComponentMaterialSet,
    publicTypes.TransportedEvaluationKeyShareProofMaterialSet,
    publicTypes.TransportedPublicEvaluationKeyMaterialSet,
    publicTypes.TransportedPublicKeyShareProofMaterialSet,
    publicTypes.TransportedSameSecretProofMaterialSet,
    publicTypes.VerifiedVssCoefficientCommitmentMaterial,
    publicTypes.VerifyPrivateVssShareInput,
    publicTypes.VerifySetupPackageInput,
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
] as const satisfies VerifySetupPackageTransportFieldProbe;

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
    'TargetDecryptionResultVerification',
    'ThresholdProfile',
    'TrusteeSetupEntry',
] as const satisfies PublicFoundationTypeNames;

type PublicSetupTypeNames = readonly string[] & {
    readonly length: PublicTypeSurfaceProbe['publicSetupTypes']['length'];
};

const publicSetupTypeNames = [
    'AcceptedSetupHandoff',
    'CollectiveBgvSetupContext',
    'PrivateVssShareVerification',
    'SetupPackage',
    'SetupPackageVerification',
    'SetupPackageVerificationInputSource',
    'SetupTransportedPublicKeyShareMaterial',
    'SetupTransportedVssCoefficientCommitmentMaterialLike',
    'TransportedEvaluationKeyShareComponentMaterialSet',
    'TransportedEvaluationKeyShareProofMaterialSet',
    'TransportedPublicEvaluationKeyMaterialSet',
    'TransportedPublicKeyShareProofMaterialSet',
    'TransportedSameSecretProofMaterialSet',
    'VerifiedVssCoefficientCommitmentMaterial',
    'VerifyPrivateVssShareInput',
    'VerifySetupPackageInput',
] as const satisfies PublicSetupTypeNames;

describe('election foundation public type surface', () => {
    it('keeps safe election foundation types available', () => {
        expect(publicFoundationTypeNames).toHaveLength(17);
    });

    it('keeps the verifier-only accepted setup type surface available', () => {
        expect(publicSetupTypeNames).toHaveLength(16);
    });

    it('keeps setup verifier transport companions on concrete public types', () => {
        expect(verifySetupPackageTransportFieldProbe).toHaveLength(8);
    });
});
