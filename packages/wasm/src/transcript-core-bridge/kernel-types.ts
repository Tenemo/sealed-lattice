import type {
    CanonicalError,
    FieldElement,
    ProtocolHash,
    TranscriptCoreAnalysis,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';

import type {
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCanonicalObjectAnalysis,
    BgvCiphertextConventionFixture,
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
    BgvSetupProofMaterialTransportStreamBegin,
    BgvSetupProofMaterialTransportStreamChunkAbsorption,
    BgvSetupProofMaterialTransportStreamVerification,
    BgvEvaluationKeyShareComponentMaterialTransportStreamBegin,
    BgvEvaluationKeyShareComponentMaterialTransportStreamChunkAbsorption,
    BgvEvaluationKeyShareComponentMaterialTransportStreamVerification,
    BgvTargetDecryptionReleaseSetupContext,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseShareAbsorption,
    BgvTargetDecryptionResultReleaseCompletion,
} from './kernel-types/bgv.js';

export type {
    BgvAcceptedSetupHandoff,
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCanonicalObjectAnalysis,
    BgvCiphertextConventionFixture,
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
    BgvSetupProofMaterialTransportStreamBegin,
    BgvSetupProofMaterialTransportStreamChunkAbsorption,
    BgvSetupProofMaterialTransportStreamVerification,
    BgvEvaluationKeyShareComponentMaterialTransportStreamBegin,
    BgvEvaluationKeyShareComponentMaterialTransportStreamChunkAbsorption,
    BgvEvaluationKeyShareComponentMaterialTransportStreamVerification,
    BgvTargetDecryptionReleaseSetupContext,
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

export type TranscriptCoreKernel = {
    readonly exportedFunctionNames: readonly string[];
    analyzeCanonicalObject(input: {
        readonly canonicalBytesHex: string;
        readonly chunkSize: number;
    }): TranscriptCoreAnalysis;
    computeChunkRoot(input: {
        readonly inputHex: string;
        readonly chunkSize: number;
    }): string;
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
    verifyFixture(
        fixture: TranscriptCoreFixture,
    ): TranscriptCoreFixtureVerification;
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
    generateBgvEvaluationKeyMaterial(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly setupPrivateWitness: {
            readonly setupSeed: string;
        };
        readonly workingLevel?: number;
        readonly rotationKeys?: readonly {
            readonly rotation: number;
            readonly level: number;
        }[];
    }): Record<string, unknown>;
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
        readonly recipientShareMessages: readonly number[];
        readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
        readonly recipientShareOpeningRandomness: readonly (readonly number[])[];
        readonly carryWitnesses: readonly number[];
        readonly recipientShareMessagesByItem?: readonly (readonly number[])[];
        readonly recipientShareOpeningRandomnessByItem?: readonly (readonly (readonly number[])[])[];
        readonly carryWitnessesByItem?: readonly (readonly number[])[];
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
    beginSetupProofMaterialTransportStream(input: {
        readonly verificationId: string;
        readonly transportedSetupProofMaterial: unknown;
    }): BgvSetupProofMaterialTransportStreamBegin;
    absorbSetupProofMaterialTransportStreamChunk(input: {
        readonly verificationId: string;
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }): BgvSetupProofMaterialTransportStreamChunkAbsorption;
    finishSetupProofMaterialTransportStream(input: {
        readonly verificationId: string;
    }): BgvSetupProofMaterialTransportStreamVerification;
    beginEvaluationKeyShareComponentMaterialTransportStream(input: {
        readonly verificationId: string;
        readonly transportedEvaluationKeyShareComponentMaterial: unknown;
    }): BgvEvaluationKeyShareComponentMaterialTransportStreamBegin;
    absorbEvaluationKeyShareComponentMaterialTransportStreamChunk(input: {
        readonly verificationId: string;
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }): BgvEvaluationKeyShareComponentMaterialTransportStreamChunkAbsorption;
    finishEvaluationKeyShareComponentMaterialTransportStream(input: {
        readonly verificationId: string;
    }): BgvEvaluationKeyShareComponentMaterialTransportStreamVerification;
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
    generateBgvCiphertextConventionFixture(input: {
        readonly leftSlots: readonly number[];
        readonly rightSlots: readonly number[];
        readonly includeCanonicalBytesHex?: boolean;
    }): BgvCiphertextConventionFixture | BgvOperationRejection;
    generateBgvBaseConversionFixture(input: {
        readonly slots: readonly number[];
    }): BgvBaseConversionFixture | BgvOperationRejection;
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
    | KernelCommandFromMethod<
          'AnalyzeCanonicalObject',
          'analyzeCanonicalObject'
      >
    | KernelCommandFromMethod<'ComputeChunkRoot', 'computeChunkRoot'>
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
    | {
          readonly command: 'VerifyFixture';
          readonly fixture: TranscriptCoreFixture;
      }
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
    | KernelCommandFromMethod<
          'GenerateBgvEvaluationKeyMaterial',
          'generateBgvEvaluationKeyMaterial'
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
          'BeginSetupProofMaterialTransportStream',
          'beginSetupProofMaterialTransportStream'
      >
    | KernelCommandFromMethod<
          'AbsorbSetupProofMaterialTransportStreamChunk',
          'absorbSetupProofMaterialTransportStreamChunk'
      >
    | KernelCommandFromMethod<
          'FinishSetupProofMaterialTransportStream',
          'finishSetupProofMaterialTransportStream'
      >
    | KernelCommandFromMethod<
          'BeginEvaluationKeyShareComponentMaterialTransportStream',
          'beginEvaluationKeyShareComponentMaterialTransportStream'
      >
    | KernelCommandFromMethod<
          'AbsorbEvaluationKeyShareComponentMaterialTransportStreamChunk',
          'absorbEvaluationKeyShareComponentMaterialTransportStreamChunk'
      >
    | KernelCommandFromMethod<
          'FinishEvaluationKeyShareComponentMaterialTransportStream',
          'finishEvaluationKeyShareComponentMaterialTransportStream'
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
          'GenerateBgvCiphertextConventionFixture',
          'generateBgvCiphertextConventionFixture'
      >
    | KernelCommandFromMethod<
          'GenerateBgvBaseConversionFixture',
          'generateBgvBaseConversionFixture'
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
              readonly source:
                  | 'fresh-csprng'
                  | 'development-deterministic-fixture';
              readonly encryptionSeedHexes: readonly string[];
          };
          readonly proofMaskRandomness: {
              readonly source:
                  | 'fresh-csprng'
                  | 'development-deterministic-fixture';
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
          readonly publicEvaluationKeyMaterial?: unknown;
          readonly targetFinalityPolicyHash?: string;
      };

type TranscriptCoreKernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_allocate?: (length: number) => number;
    sealed_lattice_deallocate?: (pointer: number, length: number) => void;
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
