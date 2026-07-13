import type {
    CanonicalError,
    ProtocolHash,
} from '@sealed-lattice/types';

import type {
    BgvCollectiveSetupTransportCompanions,
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupVerification,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyStatementDescription,
    BgvTrusteeEvaluationKeySameSecretBridge,
    BgvTrusteeEvaluationKeySameSecretLinkage,
    BgvTrusteeEvaluationKeyStatementContext,
    BgvTrusteeEvaluationKeyStatementKey,
    BgvLocalTrusteeSetupStateVerification,
    BgvPassiveSetupPackage,
    BgvPassiveSetupParticipantInput,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvRnsParametersDescription,
    BgvSameSecretBridgeProofContext,
    BgvSameSecretBridgeProofGeneration,
    BgvVssCommittedMaterialCommitmentComputation,
    BgvVssShareLinkageProofContext,
    BgvVssShareLinkageProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvTargetDecryptionReleaseSetupContext,
    BgvTargetDecryptionShare,
    BgvTargetDecryptionShareProofMaterial,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseCompletion,
} from './kernel-types/bgv.js';

export type {
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupVerification,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyStatementDescription,
    BgvTrusteeEvaluationKeySameSecretBridge,
    BgvTrusteeEvaluationKeySameSecretLinkage,
    BgvTrusteeEvaluationKeyStatementContext,
    BgvTrusteeEvaluationKeyStatementKey,
    BgvLocalTrusteeSetupStateVerification,
    BgvPassiveSetupPackage,
    BgvPassiveSetupParticipantInput,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvRnsParametersDescription,
    BgvSameSecretBridgeProofContext,
    BgvSameSecretBridgeProofGeneration,
    BgvVssCommittedMaterialCommitmentComputation,
    BgvVssShareLinkageProofContext,
    BgvVssShareLinkageProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvTargetDecryptionReleaseSetupContext,
    BgvTargetDecryptionShare,
    BgvTargetDecryptionShareProofMaterial,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseShareEvidence,
    BgvTargetDecryptionResultReleaseCompletion,
} from './kernel-types/bgv.js';
type BgvTargetDecryptionLocalCommandContext = Readonly<{
    readonly setupPackage: unknown;
    readonly targetAcceptedRecord: unknown;
    readonly targetCiphertexts: unknown;
    readonly targetCiphertextBinding: unknown;
    readonly targetShareProfile: unknown;
}>;

export type BgvCollectiveSetupVerificationInput = Readonly<
    {
        readonly setupPackage: unknown;
        readonly expectedSetupPackageHash?: ProtocolHash;
        readonly expectedManifestHash?: ProtocolHash;
        readonly expectedRosterHash?: ProtocolHash;
    } & BgvCollectiveSetupTransportCompanions
>;

export type AcceptedSetupSession = Readonly<{
    cancel(): void;
    verifyCollectiveBgvSetup(
        input: BgvCollectiveSetupVerificationInput,
    ): BgvCollectiveSetupVerification;
}>;

export type TranscriptCoreKernel = {
    readonly exportedFunctionNames: readonly string[];
    beginAcceptedSetupSession(): AcceptedSetupSession;
    deriveCanonicalObjectHash(input: { readonly value: unknown }): ProtocolHash;
    generateBgvTargetDecryptionShareFromLocalShare(
        input: BgvTargetDecryptionLocalCommandContext & {
            readonly trusteeIdentity: string;
            readonly localTargetShareWitness: unknown;
        },
    ): BgvTargetDecryptionShare;
    generateBgvTargetDecryptionShareProofMaterialFromLocalWitness(
        input: BgvTargetDecryptionLocalCommandContext & {
            readonly trusteeIdentity: string;
            readonly localTargetShareWitness: unknown;
            readonly targetDecryptionShare: unknown;
            readonly proofStatement: unknown;
            readonly proofRandomnessSeedHex: string;
            readonly proofRandomnessNonceHex: string;
        },
    ): BgvTargetDecryptionShareProofMaterial;
    describeBgvRnsParameters(): BgvRnsParametersDescription;
    describeCollectiveBgvSetupParameters(input?: {
        readonly participantCount?: number;
    }): BgvCollectiveSetupParametersDescription;
    generateBgvPassiveSetup(input: {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly thresholdParametersHash: ProtocolHash;
        readonly participants: readonly BgvPassiveSetupParticipantInput[];
        readonly setupSeed: string;
    }): BgvPassiveSetupPackage;
    verifyBgvPassiveSetup(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly expectedSetupPackageHash?: ProtocolHash;
        readonly expectedManifestHash?: ProtocolHash;
        readonly expectedRosterHash?: ProtocolHash;
        readonly expectedCollectivePublicKeyRoot?: ProtocolHash;
        readonly expectedRotSetHash?: ProtocolHash;
        readonly expectedEvaluationKeyRoot?: ProtocolHash;
    }): void;
    verifyPrivateVssShareEnvelope(input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
        readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
        readonly privateEnvelope: unknown;
        readonly transportedPrivateVssShareProofMaterial?: unknown;
        readonly expectedPrivateEnvelopeHash?: ProtocolHash;
        readonly expectedLocalVerificationRoot?: ProtocolHash;
    }): BgvPrivateVssShareEnvelopeVerification;
    generatePrivateVssShareProof(input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly privateEnvelopeAadHash: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
        readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly shareValues: readonly number[];
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
        readonly openingRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvPrivateVssShareProofGeneration;
    generateTrusteeEvaluationKeyProof(input: {
        readonly context: BgvTrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly keys: readonly BgvTrusteeEvaluationKeyStatementKey[];
        readonly sameSecretLinkage?: BgvTrusteeEvaluationKeySameSecretLinkage;
        readonly sameSecretBridge?: BgvTrusteeEvaluationKeySameSecretBridge;
        readonly secretCoefficients: readonly number[];
        readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
        readonly negativeIndicatorCoefficients?: readonly number[];
        readonly openingRandomnessByLimb?: readonly (readonly (readonly number[])[])[];
        readonly vssCommittedMaterialSeedsByBoundMessage?: readonly string[];
        readonly vssCommittedMaterialContextHashesByBoundMessage?: readonly string[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvTrusteeEvaluationKeyProofGeneration;
    describeTrusteeEvaluationKeyStatement(input: {
        readonly context: BgvTrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly keys: readonly BgvTrusteeEvaluationKeyStatementKey[];
        readonly sameSecretLinkage?: BgvTrusteeEvaluationKeySameSecretLinkage;
        readonly sameSecretBridge?: BgvTrusteeEvaluationKeySameSecretBridge;
    }): BgvTrusteeEvaluationKeyStatementDescription;
    computeSetupCommitmentFromOpening(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceRnsLimbIndex: number;
        readonly sourceMessageModulus: number;
        readonly shamirCoefficientIndex: number;
        readonly messageCoefficients: readonly number[];
        readonly randomnessByColumn: readonly (readonly number[])[];
        readonly ringDegree: number;
    }): BgvSetupCommitmentOpeningComputation;
    computeVssCommittedMaterialCommitment(input: {
        readonly commitmentRole: string;
        readonly commitmentContext: Record<string, unknown>;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly messageCoefficientBound?: number;
        readonly messageCoefficients: readonly number[];
        readonly materialSeedHex: string;
    }): BgvVssCommittedMaterialCommitmentComputation;
    generateVssShareLinkageProof(input: {
        readonly context: BgvVssShareLinkageProofContext;
        readonly ringDegree: number;
        readonly vssShareLinkage: Record<string, unknown>;
        readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
        readonly recipientShareMessagesByItem: readonly (readonly number[])[];
        readonly carryWitnessesByItem: readonly (readonly number[])[];
        readonly vssCommittedMaterialSeedsByBoundMessage: readonly string[];
        readonly vssCommittedMaterialContextHashesByBoundMessage: readonly string[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvVssShareLinkageProofGeneration;
    generateSameSecretBridgeProof(input: {
        readonly context: BgvSameSecretBridgeProofContext;
        readonly ringDegree: number;
        readonly sameSecretLinkage: BgvTrusteeEvaluationKeySameSecretLinkage;
        readonly sameSecretBridge: Record<string, unknown>;
        readonly secretCoefficients: readonly number[];
        readonly negativeIndicatorCoefficients: readonly number[];
        readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
        readonly vssCommittedMaterialSeedsByBoundMessage: readonly string[];
        readonly vssCommittedMaterialContextHashesByBoundMessage: readonly string[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvSameSecretBridgeProofGeneration;
    deriveBgvTargetDecryptionResultReleaseSetupContext(input: {
        readonly setupPackage: unknown;
    }): BgvTargetDecryptionReleaseSetupContext;
    beginBgvTargetDecryptionResultRelease(input: {
        readonly releaseVerificationId: string;
        readonly releaseSetupContext: unknown;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertexts: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetShareProfile: unknown;
    }): BgvTargetDecryptionResultReleaseBegin;
    absorbBgvTargetDecryptionResultReleaseShare(input: {
        readonly releaseVerificationId: string;
        readonly targetShareProof: unknown;
    }): void;
    finishBgvTargetDecryptionResultRelease(input: {
        readonly releaseVerificationId: string;
    }): BgvTargetDecryptionResultReleaseCompletion;
    verifyLocalTrusteeSetupState(input: {
        readonly setupContext: unknown;
        readonly localStateCommitment: unknown;
    }): BgvLocalTrusteeSetupStateVerification;
};

export type TranscriptCoreKernelContextOwner = Pick<
    TranscriptCoreKernel,
    'exportedFunctionNames'
>;

export type PublishedSdkKernel = Pick<
    TranscriptCoreKernel,
    | 'beginAcceptedSetupSession'
    | 'exportedFunctionNames'
    | 'generateBgvTargetDecryptionShareProofMaterialFromLocalWitness'
    | 'verifyPrivateVssShareEnvelope'
    | 'deriveBgvTargetDecryptionResultReleaseSetupContext'
    | 'beginBgvTargetDecryptionResultRelease'
    | 'absorbBgvTargetDecryptionResultReleaseShare'
    | 'finishBgvTargetDecryptionResultRelease'
>;

type KernelMethodInput<MethodName extends keyof TranscriptCoreKernel> =
    TranscriptCoreKernel[MethodName] extends (input: infer Input) => unknown
        ? NonNullable<Input>
        : never;

type KernelCommandFromMethod<
    CommandName extends string,
    MethodName extends keyof TranscriptCoreKernel,
> = Readonly<
    {
        readonly command: CommandName;
    } & KernelMethodInput<MethodName>
>;

type TranscriptCoreKernelCommand =
    | KernelCommandFromMethod<
          'DeriveCanonicalObjectHash',
          'deriveCanonicalObjectHash'
      >
    | KernelCommandFromMethod<
          'GenerateBgvTargetDecryptionShareFromLocalShare',
          'generateBgvTargetDecryptionShareFromLocalShare'
      >
    | KernelCommandFromMethod<
          'GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness',
          'generateBgvTargetDecryptionShareProofMaterialFromLocalWitness'
      >
    | {
          readonly command: 'DescribeBgvRnsParameters';
      }
    | KernelCommandFromMethod<
          'DescribeCollectiveBgvSetupParameters',
          'describeCollectiveBgvSetupParameters'
      >
    | KernelCommandFromMethod<
          'GenerateBgvPassiveSetup',
          'generateBgvPassiveSetup'
      >
    | KernelCommandFromMethod<'VerifyBgvPassiveSetup', 'verifyBgvPassiveSetup'>
    | Readonly<
          {
              readonly command: 'VerifyCollectiveBgvSetup';
          } & BgvCollectiveSetupVerificationInput
      >
    | KernelCommandFromMethod<
          'VerifyPrivateVssShareEnvelope',
          'verifyPrivateVssShareEnvelope'
      >
    | KernelCommandFromMethod<
          'GeneratePrivateVssShareProof',
          'generatePrivateVssShareProof'
      >
    | KernelCommandFromMethod<
          'GenerateTrusteeEvaluationKeyProof',
          'generateTrusteeEvaluationKeyProof'
      >
    | KernelCommandFromMethod<
          'DescribeTrusteeEvaluationKeyStatement',
          'describeTrusteeEvaluationKeyStatement'
      >
    | KernelCommandFromMethod<
          'ComputeSetupCommitmentFromOpening',
          'computeSetupCommitmentFromOpening'
      >
    | KernelCommandFromMethod<
          'ComputeVssCommittedMaterialCommitment',
          'computeVssCommittedMaterialCommitment'
      >
    | KernelCommandFromMethod<
          'GenerateVssShareLinkageProof',
          'generateVssShareLinkageProof'
      >
    | KernelCommandFromMethod<
          'GenerateSameSecretBridgeProof',
          'generateSameSecretBridgeProof'
      >
    | KernelCommandFromMethod<
          'DeriveBgvTargetDecryptionResultReleaseSetupContext',
          'deriveBgvTargetDecryptionResultReleaseSetupContext'
      >
    | KernelCommandFromMethod<
          'BeginBgvTargetDecryptionResultRelease',
          'beginBgvTargetDecryptionResultRelease'
      >
    | KernelCommandFromMethod<
          'AbsorbBgvTargetDecryptionResultReleaseShare',
          'absorbBgvTargetDecryptionResultReleaseShare'
      >
    | KernelCommandFromMethod<
          'FinishBgvTargetDecryptionResultRelease',
          'finishBgvTargetDecryptionResultRelease'
      >
    | KernelCommandFromMethod<
          'VerifyLocalTrusteeSetupState',
          'verifyLocalTrusteeSetupState'
      >
    | {
          readonly command: 'RunDirectEncryptedBallot';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly setupPrivateWitness: {
              readonly setupSeed: string;
          };
          readonly ballotEncryptionRandomness: {
              readonly encryptionSeedHexes: readonly string[];
          };
          readonly proofMaskRandomness: {
              readonly ballotProofRandomnessHexes: readonly string[];
          };
          readonly ballots: readonly {
              readonly voterIdentity: string;
              readonly actionContextHash: string;
              readonly scores: readonly number[];
              readonly oneHotWitnesses?: readonly (readonly number[])[];
          }[];
          readonly topCount?: number;
          readonly topCounts?: readonly number[];
          readonly targetFinalityPolicyHash?: string;
      };

type TranscriptCoreKernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_allocate?: (length: number) => number;
    sealed_lattice_accepted_setup_canonical_stream_begin?: (
        setupSessionHandle: number,
        setupCapabilityPointer: number,
        setupCapabilityLength: number,
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        descriptorPointer: number,
        descriptorLength: number,
        streamCapabilityPointer: number,
        streamCapabilityLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ) => number;
    sealed_lattice_accepted_setup_command_with_length?: (
        pointer: number,
        length: number,
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        outputLengthPointer: number,
    ) => number;
    sealed_lattice_accepted_setup_session_begin?: (
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_accepted_setup_session_cancel?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_bgv_canonical_stream_absorb_chunk?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    sealed_lattice_bgv_canonical_stream_begin?: (
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        descriptorPointer: number,
        descriptorLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ) => number;
    sealed_lattice_bgv_canonical_stream_cancel?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_bgv_canonical_stream_finish?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_bgv_canonical_material_reader_begin?: (
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ) => number;
    sealed_lattice_bgv_canonical_material_reader_cancel?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_bgv_canonical_material_reader_finish?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_bgv_canonical_material_reader_read_chunk?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
        chunkIndex: number,
        outputPointer: number,
        outputLength: number,
    ) => number;
    sealed_lattice_canonical_stream_absorb_chunk?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    sealed_lattice_canonical_stream_begin_verifier?: (
        streamDomain: number,
        descriptorPointer: number,
        descriptorLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ) => number;
    sealed_lattice_canonical_stream_begin_writer?: (
        streamDomain: number,
        totalByteLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
        chunkCountPointer: number,
    ) => number;
    sealed_lattice_canonical_stream_cancel?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_canonical_stream_finish_verifier?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_canonical_stream_finish_writer?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
        outputLengthPointer: number,
    ) => number;
    sealed_lattice_deallocate?: (pointer: number, length: number) => void;
    sealed_lattice_local_storage_root_command?: (
        command: number,
        inputPointer: number,
        inputLength: number,
        statusPointer: number,
        outputLengthPointer: number,
    ) => number;
    sealed_lattice_state_verifier_begin?: (
        configurationPointer: number,
        configurationLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_cancel?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_state_verifier_certify_intent?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedIntentHandle: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_describe?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
        outputPointer: number,
        outputLength: number,
    ) => number;
    sealed_lattice_state_verifier_release?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
    ) => number;
    sealed_lattice_state_verifier_finish_output?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        streamHandle: number,
        streamCapabilityPointer: number,
        streamCapabilityLength: number,
        verifiedReservationHandle: number,
        canonicalOutputIntentCarrierPointer: number,
        canonicalOutputIntentCarrierLength: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_prepare_output?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        streamHandle: number,
        streamCapabilityPointer: number,
        streamCapabilityLength: number,
        verifiedReservationHandle: number,
        canonicalOutputIntentCarrierPointer: number,
        canonicalOutputIntentCarrierLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_prepare_recovery?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        predecessorRecoveryHandle: number,
        preservedIntentHandle: number,
        canonicalRecoveryTransitionCarrierPointer: number,
        canonicalRecoveryTransitionCarrierLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_prepare_reservation?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        predecessorRecoveryHandle: number,
        expectedAuthorizationHashPointer: number,
        expectedAuthorizationHashLength: number,
        canonicalReservationIntentCarrierPointer: number,
        canonicalReservationIntentCarrierLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_verify_recovery?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        predecessorRecoveryHandle: number,
        preservedIntentHandle: number,
        canonicalRecoveryTransitionCarrierPointer: number,
        canonicalRecoveryTransitionCarrierLength: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_verify_reservation?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        predecessorRecoveryHandle: number,
        expectedAuthorizationHashPointer: number,
        expectedAuthorizationHashLength: number,
        canonicalReservationIntentCarrierPointer: number,
        canonicalReservationIntentCarrierLength: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_transcript_core_command_with_length?: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number;
};

type KernelSuccessResponse<T> = {
    readonly success: true;
    readonly value: T;
};

type KernelFailureResponse = {
    readonly success: false;
    readonly error: CanonicalError;
};

export type {
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
    KernelSuccessResponse,
    KernelFailureResponse,
};
