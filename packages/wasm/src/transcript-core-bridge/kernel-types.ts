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
    BgvTrusteeEvaluationKeySameSecretBridge,
    BgvTrusteeEvaluationKeySameSecretLinkage,
    BgvTrusteeEvaluationKeyStatementContext,
    BgvTrusteeEvaluationKeyStatementKey,
    BgvEvaluatorOperationValidation,
    BgvLocalTrusteeSetupStateVerification,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPassiveSetupParticipantInput,
    BgvPassiveSetupVerification,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvOperationRejection,
    BgvRnsParametersDescription,
    BgvSameSecretBridgeProofContext,
    BgvSameSecretBridgeProofGeneration,
    BgvVssPublicCommitmentOpeningComputation,
    BgvVssShareLinkageProofContext,
    BgvVssShareLinkageProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvSetupProofMaterialTransportStreamBegin,
    BgvSetupProofMaterialTransportStreamChunkAbsorption,
    BgvSetupProofMaterialTransportStreamVerification,
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
    BgvTrusteeEvaluationKeySameSecretBridge,
    BgvTrusteeEvaluationKeySameSecretLinkage,
    BgvTrusteeEvaluationKeyStatementContext,
    BgvTrusteeEvaluationKeyStatementKey,
    BgvEvaluatorOperationValidation,
    BgvLocalTrusteeSetupStateVerification,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPassiveSetupParticipantInput,
    BgvPassiveSetupVerification,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvOperationRejection,
    BgvRnsParametersDescription,
    BgvSameSecretBridgeProofContext,
    BgvSameSecretBridgeProofGeneration,
    BgvVssPublicCommitmentOpeningComputation,
    BgvVssShareLinkageProofContext,
    BgvVssShareLinkageProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvSetupProofMaterialTransportStreamBegin,
    BgvSetupProofMaterialTransportStreamChunkAbsorption,
    BgvSetupProofMaterialTransportStreamVerification,
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
    }): BgvPassiveSetupVerification;
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
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvTrusteeEvaluationKeyProofGeneration;
    computeSetupCommitmentFromOpening(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceRnsLimbIndex: number;
        readonly sourceMessageModulus: number;
        readonly shamirCoefficientIndex: number;
        readonly messageCoefficients: readonly number[];
        readonly randomnessByColumn: readonly (readonly number[])[];
        readonly ringDegree: number;
    }): BgvSetupCommitmentOpeningComputation;
    computeVssPublicCommitmentFromOpening(input: {
        readonly commitmentRole: string;
        readonly commitmentContext: Record<string, unknown>;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly messageCoefficientBound?: number;
        readonly messageCoefficients: readonly number[];
        readonly messageDigitColumns: readonly (readonly number[])[];
        readonly randomnessByColumn: readonly (readonly number[])[];
    }): BgvVssPublicCommitmentOpeningComputation;
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
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvVssShareLinkageProofGeneration;
    generateSameSecretBridgeProof(input: {
        readonly context: BgvSameSecretBridgeProofContext;
        readonly ringDegree: number;
        readonly sameSecretBridge: Record<string, unknown>;
        readonly secretCoefficients: readonly number[];
        readonly negativeIndicatorCoefficients: readonly number[];
        readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
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

type TranscriptCoreKernelCommand =
    | {
          readonly command: 'AnalyzeCanonicalObject';
          readonly canonicalBytesHex: string;
          readonly chunkSize: number;
      }
    | {
          readonly command: 'ComputeChunkRoot';
          readonly inputHex: string;
          readonly chunkSize: number;
      }
    | {
          readonly command: 'DeriveCanonicalObjectHash';
          readonly value: unknown;
      }
    | {
          readonly command: 'EvaluatePlaintextComparison';
          readonly leftTotalScore: number;
          readonly rightTotalScore: number;
          readonly rosterSize: number;
      }
    | {
          readonly command: 'HashRaw';
          readonly inputHex: string;
      }
    | {
          readonly command: 'InterpolateShamirConstantTerm';
          readonly sharePoints: readonly TranscriptCoreKernelSharePoint[];
      }
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
    | {
          readonly command: 'ValidateBgvEvaluatorOperation';
          readonly operation: string;
      }
    | {
          readonly command: 'DescribeCollectiveBgvSetupParameters';
          readonly participantCount?: number;
      }
    | {
          readonly command: 'DeriveCollectiveBgvSetupPublicDerivations';
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly decryptionThreshold?: number;
      }
    | {
          readonly command: 'GenerateBgvPassiveSetup';
          readonly ceremonyId: string;
          readonly manifestHash: ProtocolHash;
          readonly rosterHash: ProtocolHash;
          readonly thresholdParametersHash: ProtocolHash;
          readonly participants: readonly BgvPassiveSetupParticipantInput[];
          readonly setupSeed?: string;
      }
    | {
          readonly command: 'GenerateBgvEvaluationKeyMaterial';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly setupPrivateWitness: {
              readonly setupSeed: string;
          };
          readonly workingLevel?: number;
          readonly rotationKeys?: readonly {
              readonly rotation: number;
              readonly level: number;
          }[];
      }
    | {
          readonly command: 'VerifyBgvPassiveSetup';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly expectedSetupPackageHash?: ProtocolHash;
          readonly expectedManifestHash?: ProtocolHash;
          readonly expectedRosterHash?: ProtocolHash;
          readonly expectedCollectivePublicKeyRoot?: ProtocolHash;
          readonly expectedRotSetHash?: ProtocolHash;
          readonly expectedEvaluationKeyRoot?: ProtocolHash;
      }
    | Readonly<
          {
              readonly command: 'VerifyCollectiveBgvSetup';
              readonly setupPackage: unknown;
              readonly expectedSetupPackageHash?: ProtocolHash;
              readonly expectedManifestHash?: ProtocolHash;
              readonly expectedRosterHash?: ProtocolHash;
          } & BgvCollectiveSetupTransportCompanions
      >
    | {
          readonly command: 'VerifyPrivateVssShareEnvelope';
          readonly setupContext: unknown;
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
          readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
          readonly privateEnvelope: unknown;
          readonly transportedPrivateVssShareProofMaterial?: unknown;
          readonly expectedPrivateEnvelopeHash?: ProtocolHash;
          readonly expectedLocalVerificationRoot?: ProtocolHash;
      }
    | {
          readonly command: 'GeneratePrivateVssShareProof';
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
      }
    | {
          readonly command: 'GenerateTrusteeEvaluationKeyProof';
          readonly context: BgvTrusteeEvaluationKeyStatementContext;
          readonly ringDegree: number;
          readonly keys: readonly BgvTrusteeEvaluationKeyStatementKey[];
          readonly sameSecretLinkage?: BgvTrusteeEvaluationKeySameSecretLinkage;
          readonly sameSecretBridge?: BgvTrusteeEvaluationKeySameSecretBridge;
          readonly secretCoefficients: readonly number[];
          readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
          readonly negativeIndicatorCoefficients?: readonly number[];
          readonly openingRandomnessByLimb?: readonly (readonly (readonly number[])[])[];
          readonly proofRandomnessSeedHex: string;
          readonly proofRandomnessNonceHex: string;
      }
    | {
          readonly command: 'ComputeSetupCommitmentFromOpening';
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly sourceRnsLimbIndex: number;
          readonly sourceMessageModulus: number;
          readonly shamirCoefficientIndex: number;
          readonly messageCoefficients: readonly number[];
          readonly randomnessByColumn: readonly (readonly number[])[];
          readonly ringDegree: number;
      }
    | {
          readonly command: 'ComputeVssPublicCommitmentFromOpening';
          readonly commitmentRole: string;
          readonly commitmentContext: Record<string, unknown>;
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly rnsLimbIndex: number;
          readonly rnsPrime: number;
          readonly ringDegree: number;
          readonly messageCoefficientBound?: number;
          readonly messageCoefficients: readonly number[];
          readonly messageDigitColumns: readonly (readonly number[])[];
          readonly randomnessByColumn: readonly (readonly number[])[];
      }
    | {
          readonly command: 'GenerateVssShareLinkageProof';
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
          readonly proofRandomnessSeedHex: string;
          readonly proofRandomnessNonceHex: string;
      }
    | {
          readonly command: 'GenerateSameSecretBridgeProof';
          readonly context: BgvSameSecretBridgeProofContext;
          readonly ringDegree: number;
          readonly sameSecretBridge: Record<string, unknown>;
          readonly secretCoefficients: readonly number[];
          readonly negativeIndicatorCoefficients: readonly number[];
          readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
          readonly proofRandomnessSeedHex: string;
          readonly proofRandomnessNonceHex: string;
      }
    | {
          readonly command: 'BeginSetupProofMaterialTransportStream';
          readonly verificationId: string;
          readonly transportedSetupProofMaterial: unknown;
      }
    | {
          readonly command: 'AbsorbSetupProofMaterialTransportStreamChunk';
          readonly verificationId: string;
          readonly chunkIndex: number;
          readonly bytesHex: string;
      }
    | {
          readonly command: 'FinishSetupProofMaterialTransportStream';
          readonly verificationId: string;
      }
    | {
          readonly command: 'VerifyLocalTrusteeSetupState';
          readonly setupContext: unknown;
          readonly localStateCommitment: unknown;
      }
    | {
          readonly command: 'EncodeBgvBatchPlaintext';
          readonly slots: readonly number[];
          readonly level?: number;
          readonly includeCanonicalBytesHex?: boolean;
      }
    | {
          readonly command: 'ValidateBgvPlaintextObject';
          readonly canonicalBytesHex: string;
          readonly expectedPlaintextRoot?: string;
      }
    | {
          readonly command: 'ValidateBgvCiphertextObject';
          readonly canonicalBytesHex: string;
          readonly expectedCiphertextRoot?: string;
      }
    | {
          readonly command: 'GenerateBgvCiphertextConventionFixture';
          readonly leftSlots: readonly number[];
          readonly rightSlots: readonly number[];
          readonly includeCanonicalBytesHex?: boolean;
      }
    | {
          readonly command: 'GenerateBgvBaseConversionFixture';
          readonly slots: readonly number[];
      }
    | {
          readonly command: 'AnalyzeBgvCanonicalObject';
          readonly canonicalBytesHex: string;
      }
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
