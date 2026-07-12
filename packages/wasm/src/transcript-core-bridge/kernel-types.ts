import type {
    CanonicalError,
    FieldElement,
    ParticipantIdentity,
    ProtocolHash,
} from '@sealed-lattice/types';

import type {
    BgvBatchPlaintextEncoding,
    BgvCanonicalObjectAnalysis,
    BgvCollectiveSetupTransportCompanions,
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupPublicDerivations,
    BgvCollectiveSetupVerification,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyStatementDescription,
    BgvTrusteeEvaluationKeySameSecretBridge,
    BgvTrusteeEvaluationKeySameSecretLinkage,
    BgvTrusteeEvaluationKeyStatementContext,
    BgvTrusteeEvaluationKeyStatementKey,
    BgvEvaluatorOperationValidation,
    BgvLocalTrusteeSetupStateVerification,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPassiveSetupParticipantInput,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvOperationRejection,
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
    BgvTargetDecryptionShareProofMaterialVerification,
    BgvTargetDecryptionShareProofStatement,
    BgvTargetDecryptionShareProofStatementBinding,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseShareAbsorption,
    BgvTargetDecryptionResultReleaseCompletion,
} from './kernel-types/bgv.js';

export type {
    BgvBatchPlaintextEncoding,
    BgvCanonicalObjectAnalysis,
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupPublicDerivations,
    BgvCollectiveSetupVerification,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyStatementDescription,
    BgvTrusteeEvaluationKeySameSecretBridge,
    BgvTrusteeEvaluationKeySameSecretLinkage,
    BgvTrusteeEvaluationKeyStatementContext,
    BgvTrusteeEvaluationKeyStatementKey,
    BgvEvaluatorOperationValidation,
    BgvLocalTrusteeSetupStateVerification,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPassiveSetupParticipantInput,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvOperationRejection,
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
    BgvTargetDecryptionShareProofMaterialVerification,
    BgvTargetDecryptionShareProofStatement,
    BgvTargetDecryptionShareProofStatementBinding,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseShareAbsorption,
    BgvTargetDecryptionResultReleaseShareEvidence,
    BgvTargetDecryptionResultReleaseCompletion,
} from './kernel-types/bgv.js';
export type TranscriptCoreKernelSharePoint = {
    readonly rosterPosition: number;
    readonly value: FieldElement;
};

export type TranscriptCorePlaintextComparison = {
    readonly greaterThan: FieldElement;
    readonly equal: FieldElement;
    readonly scoreDifference: number;
};

export type FoundationCanonicalTupleValidation = {
    readonly canonicalTupleHex: string;
    readonly schemaIdentifier: number;
    readonly schemaVersion: number;
    readonly itemCount: number;
};

export type FoundationSchemaObjectValidation = {
    readonly schemaIdentifier: number;
    readonly schemaVersion: number;
    readonly canonicalByteLength: number;
};

type BgvTargetDecryptionLocalCommandContext = Readonly<{
    readonly setupPackage: unknown;
    readonly targetAcceptedRecord: unknown;
    readonly targetCiphertexts: unknown;
    readonly targetCiphertextBinding: unknown;
    readonly targetShareProfile: unknown;
}>;

export type TranscriptCoreKernel = {
    readonly exportedFunctionNames: readonly string[];
    computeChunkRoot(input: {
        readonly inputHex: string;
        readonly chunkSize: number;
    }): string;
    computeFoundationHash512(input: {
        readonly domain: string;
        readonly canonicalItemsTupleHex: string;
    }): ProtocolHash;
    deriveFoundationParticipantIdentity(input: {
        readonly signingVerificationKeyHex: string;
    }): ParticipantIdentity;
    deriveCanonicalObjectHash(input: { readonly value: unknown }): ProtocolHash;
    evaluatePlaintextComparison(input: {
        readonly leftTotalScore: number;
        readonly rightTotalScore: number;
        readonly rosterSize: number;
    }): TranscriptCorePlaintextComparison;
    hashRaw(inputHex: string): string;
    interpolateShamirConstantTerm(input: {
        readonly sharePoints: readonly TranscriptCoreKernelSharePoint[];
    }): FieldElement;
    listCanonicalErrorCodes(): readonly string[];
    roundTripBytes(input: Uint8Array): Uint8Array;
    validateFoundationCanonicalTuple(input: {
        readonly canonicalTupleHex: string;
    }): FoundationCanonicalTupleValidation;
    validateFoundationSchemaObject(input: {
        readonly canonicalBytes: Uint8Array;
    }): FoundationSchemaObjectValidation;
    generateBgvTargetDecryptionShareFromLocalShare(
        input: BgvTargetDecryptionLocalCommandContext & {
            readonly trusteeIdentity: string;
            readonly localTargetShareWitness: unknown;
        },
    ): BgvTargetDecryptionShare;
    deriveBgvTargetDecryptionShareProofStatement(
        input: BgvTargetDecryptionLocalCommandContext & {
            readonly trusteeIdentity: string;
            readonly localTargetShareWitness: unknown;
            readonly targetDecryptionShare: unknown;
        },
    ): BgvTargetDecryptionShareProofStatement;
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
    verifyBgvTargetDecryptionShareProofMaterial(
        input: BgvTargetDecryptionLocalCommandContext & {
            readonly targetDecryptionShare: unknown;
            readonly proofStatement: unknown;
            readonly proofMaterial: unknown;
        },
    ): BgvTargetDecryptionShareProofMaterialVerification;
    verifyBgvTargetDecryptionShareProofStatementBinding(
        input: BgvTargetDecryptionLocalCommandContext & {
            readonly targetDecryptionShare: unknown;
            readonly proofStatement: unknown;
        },
    ): BgvTargetDecryptionShareProofStatementBinding;
    describeBgvRnsParameters(): BgvRnsParametersDescription;
    describeBgvOperationRegistry(): unknown;
    describeCollectiveBgvSetupParameters(input?: {
        readonly participantCount?: number;
    }): BgvCollectiveSetupParametersDescription;
    deriveCollectiveBgvSetupPublicDerivations(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly decryptionThreshold?: number;
    }): BgvCollectiveSetupPublicDerivations;
    generateBgvPassiveSetup(input: {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly thresholdParametersHash: ProtocolHash;
        readonly participants: readonly BgvPassiveSetupParticipantInput[];
        readonly setupSeed?: string;
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
    verifyCollectiveBgvSetup(
        input: Readonly<
            {
                readonly setupPackage: unknown;
                readonly expectedSetupPackageHash?: ProtocolHash;
                readonly expectedManifestHash?: ProtocolHash;
                readonly expectedRosterHash?: ProtocolHash;
            } & BgvCollectiveSetupTransportCompanions
        >,
    ): BgvCollectiveSetupVerification;
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
        readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
        readonly recipientShareMessagesByItem: readonly (readonly number[])[];
        readonly recipientShareOpeningRandomnessByItem: readonly (readonly (readonly number[])[])[];
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
    }): BgvTargetDecryptionResultReleaseShareAbsorption;
    finishBgvTargetDecryptionResultRelease(input: {
        readonly releaseVerificationId: string;
    }): BgvTargetDecryptionResultReleaseCompletion;
    verifyLocalTrusteeSetupState(input: {
        readonly setupContext: unknown;
        readonly localStateCommitment: unknown;
    }): BgvLocalTrusteeSetupStateVerification;
    encodeBgvBatchPlaintext(input: {
        readonly slots: readonly number[];
        readonly level?: number;
        readonly includeCanonicalBytesHex?: boolean;
    }): BgvBatchPlaintextEncoding | BgvOperationRejection;
    validateBgvPlaintextObject(input: {
        readonly canonicalBytesHex: string;
        readonly expectedPlaintextRoot?: string;
    }): BgvObjectValidation | BgvOperationRejection;
    validateBgvCiphertextObject(input: {
        readonly canonicalBytesHex: string;
        readonly expectedCiphertextRoot?: string;
    }): BgvObjectValidation | BgvOperationRejection;
    analyzeBgvCanonicalObject(input: {
        readonly canonicalBytesHex: string;
    }): BgvCanonicalObjectAnalysis | BgvOperationRejection;
    validateBgvEvaluatorOperation(input: {
        readonly operation: string;
    }): BgvEvaluatorOperationValidation;
};

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
    | KernelCommandFromMethod<'ComputeChunkRoot', 'computeChunkRoot'>
    | KernelCommandFromMethod<
          'ComputeFoundationHash512',
          'computeFoundationHash512'
      >
    | KernelCommandFromMethod<
          'DeriveFoundationParticipantIdentity',
          'deriveFoundationParticipantIdentity'
      >
    | KernelCommandFromMethod<
          'DeriveCanonicalObjectHash',
          'deriveCanonicalObjectHash'
      >
    | KernelCommandFromMethod<
          'EvaluatePlaintextComparison',
          'evaluatePlaintextComparison'
      >
    | {
          readonly command: 'HashRaw';
          readonly inputHex: string;
      }
    | KernelCommandFromMethod<
          'InterpolateShamirConstantTerm',
          'interpolateShamirConstantTerm'
      >
    | {
          readonly command: 'ListCanonicalErrorCodes';
      }
    | KernelCommandFromMethod<
          'ValidateFoundationCanonicalTuple',
          'validateFoundationCanonicalTuple'
      >
    | {
          readonly command: 'ValidateFoundationSchemaObject';
          readonly canonicalObjectHex: string;
      }
    | KernelCommandFromMethod<
          'GenerateBgvTargetDecryptionShareFromLocalShare',
          'generateBgvTargetDecryptionShareFromLocalShare'
      >
    | KernelCommandFromMethod<
          'DeriveBgvTargetDecryptionShareProofStatement',
          'deriveBgvTargetDecryptionShareProofStatement'
      >
    | KernelCommandFromMethod<
          'GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness',
          'generateBgvTargetDecryptionShareProofMaterialFromLocalWitness'
      >
    | KernelCommandFromMethod<
          'VerifyBgvTargetDecryptionShareProofMaterial',
          'verifyBgvTargetDecryptionShareProofMaterial'
      >
    | KernelCommandFromMethod<
          'VerifyBgvTargetDecryptionShareProofStatementBinding',
          'verifyBgvTargetDecryptionShareProofStatementBinding'
      >
    | {
          readonly command: 'DescribeBgvRnsParameters';
      }
    | {
          readonly command: 'DescribeBgvOperationRegistry';
      }
    | KernelCommandFromMethod<
          'ValidateBgvEvaluatorOperation',
          'validateBgvEvaluatorOperation'
      >
    | KernelCommandFromMethod<
          'DescribeCollectiveBgvSetupParameters',
          'describeCollectiveBgvSetupParameters'
      >
    | KernelCommandFromMethod<
          'DeriveCollectiveBgvSetupPublicDerivations',
          'deriveCollectiveBgvSetupPublicDerivations'
      >
    | KernelCommandFromMethod<
          'GenerateBgvPassiveSetup',
          'generateBgvPassiveSetup'
      >
    | KernelCommandFromMethod<'VerifyBgvPassiveSetup', 'verifyBgvPassiveSetup'>
    | KernelCommandFromMethod<
          'VerifyCollectiveBgvSetup',
          'verifyCollectiveBgvSetup'
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
    | KernelCommandFromMethod<
          'EncodeBgvBatchPlaintext',
          'encodeBgvBatchPlaintext'
      >
    | KernelCommandFromMethod<
          'ValidateBgvPlaintextObject',
          'validateBgvPlaintextObject'
      >
    | KernelCommandFromMethod<
          'ValidateBgvCiphertextObject',
          'validateBgvCiphertextObject'
      >
    | KernelCommandFromMethod<
          'AnalyzeBgvCanonicalObject',
          'analyzeBgvCanonicalObject'
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
    sealed_lattice_foundation_board_begin?: (
        configurationPointer: number,
        configurationLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_foundation_board_cancel?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_foundation_board_ingest?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
        canonicalCarrierPointer: number,
        canonicalCarrierLength: number,
        candidateHashPointer: number,
        candidateHashLength: number,
    ) => number;
    sealed_lattice_foundation_board_require_complete_carrier_graph?: (
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
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
    sealed_lattice_roundtrip?: (pointer: number, length: number) => number;
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
