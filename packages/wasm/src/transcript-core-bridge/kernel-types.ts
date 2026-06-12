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
    BgvCollectiveSetupProfileDescription,
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
    BgvPublicKeyShareLnpProofGeneration,
    BgvProfileRejection,
    BgvReferenceOracleRejection,
    BgvRnsProfileDescription,
    BgvSameSecretLnpProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvTargetCiphertextPairInput,
    BgvTargetDecryptionResult,
    BgvTargetDecryptionShare,
    BgvThresholdShareCommitmentDerivation,
    BgvThresholdShareCommitmentTransportDerivation,
    BgvThresholdShareCommitmentTransportStreamBegin,
    BgvThresholdShareCommitmentTransportStreamChunkAbsorption,
    BgvThresholdShareCommitmentTransportStreamDerivation,
    BgvTransportedVssCoefficientCommitmentMaterialReference,
    BgvTransportedVssCoefficientCommitmentMaterialTemplate,
} from './kernel-types/bgv.js';

export type {
    BgvAcceptedSetupHandoff,
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCanonicalObjectAnalysis,
    BgvCiphertextConventionFixture,
    BgvCollectiveSetupProfileDescription,
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
    BgvPublicKeyShareLnpProofGeneration,
    BgvProfileRejection,
    BgvReferenceOracleRejection,
    BgvRnsProfileDescription,
    BgvSameSecretLnpProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvTargetCiphertextPairInput,
    BgvTargetDecryptionResult,
    BgvTargetDecryptionShare,
    BgvThresholdShareCommitmentDerivation,
    BgvThresholdShareCommitmentTransportDerivation,
    BgvThresholdShareCommitmentTransportStreamBegin,
    BgvThresholdShareCommitmentTransportStreamChunkAbsorption,
    BgvThresholdShareCommitmentTransportStreamDerivation,
    BgvTransportedVssCoefficientCommitmentMaterialReference,
    BgvTransportedVssCoefficientCommitmentMaterialTemplate,
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
    describeBgvRnsProfile(): BgvRnsProfileDescription;
    describeBgvOperationRegistry(): unknown;
    describeBgvPassiveSetupObjectModel(): unknown;
    describeCollectiveBgvSetupProfile(): BgvCollectiveSetupProfileDescription;
    deriveCollectiveBgvSetupPublicDerivations(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
    }): BgvCollectiveSetupPublicDerivations;
    generateBgvPassiveSetup(input: {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly thresholdProfileHash: ProtocolHash;
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
        readonly targetShareProfile: unknown;
        readonly trusteeIdentity: string;
    }): BgvTargetDecryptionShare;
    recombineBgvTargetDecryptionShares(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareProfile: unknown;
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
    }): BgvPrivateVssShareProofGeneration;
    generateSameSecretLnpProof(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly statementRecord: unknown;
        readonly constantCommitments: readonly unknown[];
        readonly setupProofBinding: unknown;
        readonly secretCoefficients: readonly number[];
        readonly openingRandomnessByLimb: readonly (readonly (readonly (
            | number
            | string
        )[])[])[];
        readonly proofRandomnessSource?:
            | 'fresh-csprng'
            | 'development-deterministic-fixture';
        readonly proofRandomnessSeedHex: string;
    }): BgvSameSecretLnpProofGeneration;
    generatePublicKeyShareLnpProof(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyShareRecord: unknown;
        readonly publicKeyShareProofRecord: unknown;
        readonly sameSecretStatementRecord: unknown;
        readonly constantCommitments: readonly unknown[];
        readonly publicShareCoefficientsByLimb: readonly (readonly number[])[];
        readonly setupProofBinding: unknown;
        readonly secretCoefficients: readonly number[];
        readonly openingRandomnessByLimb: readonly (readonly (readonly (
            | number
            | string
        )[])[])[];
        readonly errorCoefficientsByLimb: readonly (readonly number[])[];
        readonly proofRandomnessSource?:
            | 'fresh-csprng'
            | 'development-deterministic-fixture';
        readonly proofRandomnessSeedHex: string;
    }): BgvPublicKeyShareLnpProofGeneration;
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
    verifyLocalTrusteeSetupState(input: {
        readonly setupContext: unknown;
        readonly localStateCommitment: unknown;
    }): BgvLocalTrusteeSetupStateVerification;
    encodeBgvBatchPlaintext(input: {
        readonly slots: readonly number[];
        readonly level?: number;
        readonly layoutBinding: unknown;
        readonly includeCanonicalBytesHex?: boolean;
    }): BgvBatchPlaintextEncoding | BgvProfileRejection;
    validateBgvPlaintextObject(input: {
        readonly canonicalBytesHex: string;
        readonly expectedPlaintextRoot?: string;
    }): BgvObjectValidation | BgvProfileRejection;
    validateBgvCiphertextObject(input: {
        readonly canonicalBytesHex: string;
        readonly expectedCiphertextRoot?: string;
    }): BgvObjectValidation | BgvProfileRejection;
    generateBgvCiphertextConventionFixture(input: {
        readonly leftSlots: readonly number[];
        readonly rightSlots: readonly number[];
        readonly includeCanonicalBytesHex?: boolean;
    }): BgvCiphertextConventionFixture | BgvProfileRejection;
    generateBgvBaseConversionFixture(input: {
        readonly slots: readonly number[];
    }): BgvBaseConversionFixture | BgvProfileRejection;
    analyzeBgvCanonicalObject(input: {
        readonly canonicalBytesHex: string;
    }): BgvCanonicalObjectAnalysis | BgvProfileRejection;
    validateBgvEvaluatorOperation(input: {
        readonly operation: string;
    }): BgvEvaluatorOperationValidation;
    rejectBgvReferenceOracleArtifact(input: {
        readonly artifact: unknown;
    }): BgvReferenceOracleRejection;
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
          readonly command: 'DescribeBgvRnsProfile';
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
          readonly command: 'DescribeCollectiveBgvSetupProfile';
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
          readonly thresholdProfileHash: ProtocolHash;
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
          readonly targetShareProfile: unknown;
          readonly trusteeIdentity: string;
      }
    | {
          readonly command: 'RecombineBgvTargetDecryptionShares';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly targetAcceptedRecord: unknown;
          readonly targetCiphertextBinding: unknown;
          readonly targetCiphertexts: BgvTargetCiphertextPairInput;
          readonly targetShareProfile: unknown;
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
      }
    | {
          readonly command: 'GenerateSameSecretLnpProof';
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly statementRecord: unknown;
          readonly constantCommitments: readonly unknown[];
          readonly setupProofBinding: unknown;
          readonly secretCoefficients: readonly number[];
          readonly openingRandomnessByLimb: readonly (readonly (readonly (
              | number
              | string
          )[])[])[];
          readonly proofRandomnessSource?:
              | 'fresh-csprng'
              | 'development-deterministic-fixture';
          readonly proofRandomnessSeedHex: string;
      }
    | {
          readonly command: 'GeneratePublicKeyShareLnpProof';
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly publicKeyShareRecord: unknown;
          readonly publicKeyShareProofRecord: unknown;
          readonly sameSecretStatementRecord: unknown;
          readonly constantCommitments: readonly unknown[];
          readonly publicShareCoefficientsByLimb: readonly (readonly number[])[];
          readonly setupProofBinding: unknown;
          readonly secretCoefficients: readonly number[];
          readonly openingRandomnessByLimb: readonly (readonly (readonly (
              | number
              | string
          )[])[])[];
          readonly errorCoefficientsByLimb: readonly (readonly number[])[];
          readonly proofRandomnessSource?:
              | 'fresh-csprng'
              | 'development-deterministic-fixture';
          readonly proofRandomnessSeedHex: string;
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
          readonly command: 'RejectBgvReferenceOracleArtifact';
          readonly artifact: unknown;
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
