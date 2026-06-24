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
    BgvTransportedVssCoefficientCommitmentMaterial,
    BgvCollectiveSetupPublicDerivations,
    BgvCollectiveSetupVerification,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyProofVerification,
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
    BgvSetupCommitmentOpeningComputation,
    BgvSetupProofMaterialTransportStreamBegin,
    BgvSetupProofMaterialTransportStreamChunkAbsorption,
    BgvSetupProofMaterialTransportStreamVerification,
    BgvTargetCiphertextPairInput,
    BgvTargetDecryptionResult,
    BgvTargetDecryptionShare,
    BgvThresholdShareCommitmentDerivation,
    BgvThresholdShareCommitmentTransportDerivation,
    BgvThresholdShareCommitmentTransportStreamAbort,
    BgvThresholdShareCommitmentTransportStreamBegin,
    BgvThresholdShareCommitmentTransportStreamChunkAbsorption,
    BgvThresholdShareCommitmentTransportStreamDerivation,
    BgvTransportedVssCoefficientCommitmentMaterialReference,
    BgvTransportedVssCoefficientCommitmentMaterialTemplate,
    BgvVerifiedTransportedVssMaterialRelease,
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
    BgvTrusteeEvaluationKeyProofVerification,
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
    BgvSetupCommitmentOpeningComputation,
    BgvSetupProofMaterialTransportStreamBegin,
    BgvSetupProofMaterialTransportStreamChunkAbsorption,
    BgvSetupProofMaterialTransportStreamVerification,
    BgvTargetCiphertextPairInput,
    BgvTargetDecryptionResult,
    BgvTargetDecryptionShare,
    BgvThresholdShareCommitmentDerivation,
    BgvThresholdShareCommitmentTransportDerivation,
    BgvThresholdShareCommitmentTransportStreamAbort,
    BgvThresholdShareCommitmentTransportStreamBegin,
    BgvThresholdShareCommitmentTransportStreamChunkAbsorption,
    BgvThresholdShareCommitmentTransportStreamDerivation,
    BgvTransportedVssCoefficientCommitmentMaterialReference,
    BgvTransportedVssCoefficientCommitmentMaterialTemplate,
    BgvVerifiedTransportedVssMaterialRelease,
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
    wasmMemoryByteLength(): number;
    analyzeCanonicalObject(input: {
        readonly canonicalBytesHex: string;
        readonly chunkSize: number;
    }): TranscriptCoreAnalysis;
    computeChunkRoot(input: {
        readonly inputHex: string;
        readonly chunkSize: number;
    }): string;
    deriveProtocolHash(input: {
        readonly namespace: string;
        readonly value: unknown;
    }): ProtocolHash;
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
    listReservedRootNamespaces(): readonly string[];
    roundTripBytes(input: Uint8Array): Uint8Array;
    verifyFixture(
        fixture: TranscriptCoreFixture,
    ): TranscriptCoreFixtureVerification;
    describeBgvRnsParameters(): BgvRnsParametersDescription;
    describeBgvOperationRegistry(): unknown;
    describeBgvPassiveSetupObjectModel(): unknown;
    describeCollectiveBgvSetupParameters(): BgvCollectiveSetupParametersDescription;
    deriveCollectiveBgvSetupPublicDerivations(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
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
    generateBgvTargetDecryptionShare(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly setupPrivateWitness: {
            readonly setupSeed: string;
        };
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareParameters: unknown;
        readonly trusteeIdentity: string;
    }): BgvTargetDecryptionShare;
    recombineBgvTargetDecryptionShares(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareParameters: unknown;
        readonly decryptionShares: readonly BgvTargetDecryptionShare[];
    }): BgvTargetDecryptionResult;
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
        readonly proofRandomnessSource?:
            | 'fresh-csprng'
            | 'development-deterministic-fixture';
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvPrivateVssShareProofGeneration;
    generateTrusteeEvaluationKeyProof(input: {
        readonly context: BgvTrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly keys: readonly BgvTrusteeEvaluationKeyStatementKey[];
        readonly sameSecretLinkage?: BgvTrusteeEvaluationKeySameSecretLinkage;
        readonly secretCoefficients: readonly number[];
        readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
        readonly negativeIndicatorCoefficients?: readonly number[];
        readonly openingRandomnessByLimb?: readonly (readonly (readonly number[])[])[];
        readonly proofRandomnessSource: string;
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvTrusteeEvaluationKeyProofGeneration;
    verifyTrusteeEvaluationKeyProof(input: {
        readonly context: BgvTrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly keys: readonly BgvTrusteeEvaluationKeyStatementKey[];
        readonly sameSecretLinkage?: BgvTrusteeEvaluationKeySameSecretLinkage;
        readonly proofBytesHex: string;
    }): BgvTrusteeEvaluationKeyProofVerification;
    computeSetupCommitmentFromOpening(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceRnsLimbIndex: number;
        readonly sourceMessageModulus: number;
        readonly shamirCoefficientIndex: number;
        readonly messageCoefficients: readonly number[];
        readonly randomnessByColumn: readonly (readonly number[])[];
        readonly ringDegree: number;
    }): BgvSetupCommitmentOpeningComputation;
    deriveThresholdShareCommitments(input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
        readonly coefficientCommitments: readonly unknown[];
    }): BgvThresholdShareCommitmentDerivation;
    deriveThresholdShareCommitmentsFromTransport(input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
        readonly transportedVssCoefficientCommitmentMaterial: BgvTransportedVssCoefficientCommitmentMaterial;
    }): BgvThresholdShareCommitmentTransportDerivation;
    beginThresholdShareCommitmentsFromTransportStream(input: {
        readonly derivationId: string;
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly transportedVssCoefficientCommitmentMaterial:
            | BgvTransportedVssCoefficientCommitmentMaterialReference
            | BgvTransportedVssCoefficientCommitmentMaterialTemplate;
    }): BgvThresholdShareCommitmentTransportStreamBegin;
    abortThresholdShareCommitmentsFromTransportStream(input: {
        readonly derivationId: string;
    }): BgvThresholdShareCommitmentTransportStreamAbort;
    absorbThresholdShareCommitmentsFromTransportStreamChunk(input: {
        readonly derivationId: string;
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }): BgvThresholdShareCommitmentTransportStreamChunkAbsorption;
    finishThresholdShareCommitmentsFromTransportStream(input: {
        readonly derivationId: string;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
    }): BgvThresholdShareCommitmentTransportStreamDerivation;
    releaseVerifiedTransportedVssMaterial(input: {
        readonly verificationId: string;
    }): BgvVerifiedTransportedVssMaterialRelease;
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
        readonly layoutBinding: unknown;
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
          readonly command: 'DeriveProtocolHash';
          readonly namespace: string;
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
          readonly command: 'ListReservedRootNamespaces';
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
          readonly command: 'DescribeBgvPassiveSetupObjectModel';
      }
    | {
          readonly command: 'DescribeCollectiveBgvSetupParameters';
      }
    | {
          readonly command: 'DeriveCollectiveBgvSetupPublicDerivations';
          readonly publicMatrixSeedHash: ProtocolHash;
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
          readonly command: 'GenerateBgvTargetDecryptionShare';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly setupPrivateWitness: {
              readonly setupSeed: string;
          };
          readonly targetAcceptedRecord: unknown;
          readonly targetCiphertextBinding: unknown;
          readonly targetCiphertexts: BgvTargetCiphertextPairInput;
          readonly targetShareParameters: unknown;
          readonly trusteeIdentity: string;
      }
    | {
          readonly command: 'RecombineBgvTargetDecryptionShares';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly targetAcceptedRecord: unknown;
          readonly targetCiphertextBinding: unknown;
          readonly targetCiphertexts: BgvTargetCiphertextPairInput;
          readonly targetShareParameters: unknown;
          readonly decryptionShares: readonly BgvTargetDecryptionShare[];
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
          readonly proofRandomnessSource?:
              | 'fresh-csprng'
              | 'development-deterministic-fixture';
          readonly proofRandomnessSeedHex: string;
          readonly proofRandomnessNonceHex: string;
      }
    | {
          readonly command: 'GenerateTrusteeEvaluationKeyProof';
          readonly context: BgvTrusteeEvaluationKeyStatementContext;
          readonly ringDegree: number;
          readonly keys: readonly BgvTrusteeEvaluationKeyStatementKey[];
          readonly sameSecretLinkage?: BgvTrusteeEvaluationKeySameSecretLinkage;
          readonly secretCoefficients: readonly number[];
          readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
          readonly negativeIndicatorCoefficients?: readonly number[];
          readonly openingRandomnessByLimb?: readonly (readonly (readonly number[])[])[];
          readonly proofRandomnessSource: string;
          readonly proofRandomnessSeedHex: string;
          readonly proofRandomnessNonceHex: string;
      }
    | {
          readonly command: 'VerifyTrusteeEvaluationKeyProof';
          readonly context: BgvTrusteeEvaluationKeyStatementContext;
          readonly ringDegree: number;
          readonly keys: readonly BgvTrusteeEvaluationKeyStatementKey[];
          readonly sameSecretLinkage?: BgvTrusteeEvaluationKeySameSecretLinkage;
          readonly proofBytesHex: string;
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
          readonly command: 'DeriveThresholdShareCommitments';
          readonly setupContext: unknown;
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
          readonly coefficientCommitments: readonly unknown[];
      }
    | {
          readonly command: 'DeriveThresholdShareCommitmentsFromTransport';
          readonly setupContext: unknown;
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly vssCoefficientCommitmentRoot: ProtocolHash;
          readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
          readonly transportedVssCoefficientCommitmentMaterial: BgvTransportedVssCoefficientCommitmentMaterial;
      }
    | {
          readonly command: 'BeginThresholdShareCommitmentsFromTransportStream';
          readonly derivationId: string;
          readonly setupContext: unknown;
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly transportedVssCoefficientCommitmentMaterial:
              | BgvTransportedVssCoefficientCommitmentMaterialReference
              | BgvTransportedVssCoefficientCommitmentMaterialTemplate;
      }
    | {
          readonly command: 'AbortThresholdShareCommitmentsFromTransportStream';
          readonly derivationId: string;
      }
    | {
          readonly command: 'AbsorbThresholdShareCommitmentsFromTransportStreamChunk';
          readonly derivationId: string;
          readonly chunkIndex: number;
          readonly bytesHex: string;
      }
    | {
          readonly command: 'FinishThresholdShareCommitmentsFromTransportStream';
          readonly derivationId: string;
          readonly vssCoefficientCommitmentRoot: ProtocolHash;
          readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
      }
    | {
          readonly command: 'ReleaseVerifiedTransportedVssMaterial';
          readonly verificationId: string;
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
          readonly layoutBinding: unknown;
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
