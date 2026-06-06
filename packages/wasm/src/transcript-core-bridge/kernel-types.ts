import type {
    CanonicalError,
    FieldElement,
    ProtocolHash,
    TranscriptCoreAnalysis,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';

import type { BridgeRandomnessSource } from './kernel-randomness.js';
import type {
    AggregateBridgeEncryptionGeneration,
    AggregateBridgeEncryptionVerification,
    AggregateBridgeRelationEvaluation,
} from './kernel-types/aggregate-bridge.js';
import type {
    BallotPrivacyEncodedRelationVectorVerification,
    BallotPrivacyKernelVerification,
    BallotPrivacyLinearProofVectorVerification,
    BallotPrivacyProofBackendStatus,
    BallotPrivacyProofGeneration,
    BallotPrivacyReceiverKeyProofGeneration,
    BallotPrivacyReceiverKeyProofGenerationPreparation,
    BallotPrivacyReceiverKeyVectorVerification,
} from './kernel-types/ballot-privacy.js';
import type {
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCanonicalObjectAnalysis,
    BgvCiphertextConventionFixture,
    BgvEvaluatorOperationValidation,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPassiveSetupParticipantInput,
    BgvPassiveSetupVerification,
    BgvProfileRejection,
    BgvReferenceOracleRejection,
    BgvRnsProfileDescription,
} from './kernel-types/bgv.js';

export type {
    AggregateBridgeEncryptionGeneration,
    AggregateBridgeEncryptionVerification,
    AggregateBridgeRelationEvaluation,
} from './kernel-types/aggregate-bridge.js';
export type {
    BallotPrivacyEncodedRelationVectorVerification,
    BallotPrivacyKernelVerification,
    BallotPrivacyLinearProofVectorVerification,
    BallotPrivacyProofBackendStatus,
    BallotPrivacyProofGeneration,
    BallotPrivacyReceiverKeyProofGeneration,
    BallotPrivacyReceiverKeyProofGenerationPreparation,
    BallotPrivacyReceiverKeyVectorVerification,
} from './kernel-types/ballot-privacy.js';
export type {
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCanonicalObjectAnalysis,
    BgvCiphertextConventionFixture,
    BgvEvaluatorOperationValidation,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPassiveSetupParticipantInput,
    BgvPassiveSetupVerification,
    BgvProfileRejection,
    BgvReferenceOracleRejection,
    BgvRnsProfileDescription,
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
    describeBallotPrivacyProofBackend(): BallotPrivacyProofBackendStatus;
    verifyBallotPrivacyLinearProofVector(input: {
        readonly vectorCase: unknown;
    }): BallotPrivacyLinearProofVectorVerification;
    verifyBallotPrivacyEncodedRelationVector(input: {
        readonly vectorCase: unknown;
    }): BallotPrivacyEncodedRelationVectorVerification;
    verifyBallotPrivacyReceiverKeyVector(input: {
        readonly vectorCase: unknown;
    }): BallotPrivacyReceiverKeyVectorVerification;
    verifyReceiverKeyProof(input: {
        readonly linearStatement?: unknown;
        readonly parameterSet?: unknown;
        readonly proofBytesHex?: string;
        readonly proofEncoding?: unknown;
        readonly publicRandomnessHex?: string;
        readonly receiverKeyProof: unknown;
    }): BallotPrivacyKernelVerification;
    prepareReceiverKeyProofGeneration(input: {
        readonly linearStatement: unknown;
        readonly parameterSet: unknown;
        readonly proofEncoding: unknown;
        readonly publicRandomnessHex: string;
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
    }): BallotPrivacyReceiverKeyProofGenerationPreparation;
    generateReceiverKeyProof(input: {
        readonly linearStatement: unknown;
        readonly parameterSet: unknown;
        readonly proofEncoding: unknown;
        readonly publicRandomnessHex?: string;
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
    }): BallotPrivacyReceiverKeyProofGeneration;
    generateBallotProof(input: {
        readonly linearStatement: unknown;
        readonly parameterSet: unknown;
        readonly proofEncoding: unknown;
        readonly publicRandomnessHex?: string;
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
    }): BallotPrivacyProofGeneration;
    generateBallotComponentProof(input: {
        readonly componentId: string;
        readonly proofInput: unknown;
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
    }): BallotPrivacyProofGeneration;
    generateBallotProofRecord(input: {
        readonly statement: unknown;
        readonly linearStatement: unknown;
        readonly parameterSet: unknown;
        readonly proofEncoding: unknown;
        readonly publicRandomnessHex?: string;
        readonly componentBundleStatement: unknown;
        readonly componentProofInputs: readonly unknown[];
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
        readonly componentProverRandomnessHexes?: Readonly<
            Record<string, string>
        >;
        readonly componentSecretStates?: Readonly<Record<string, unknown>>;
        readonly casualMicroRosterAcknowledged?: boolean;
    }): BallotPrivacyProofGeneration;
    verifyBallotProof(input: {
        readonly ballotProof: unknown;
        readonly componentBundleStatement?: unknown;
        readonly componentProofBundle?: unknown;
        readonly componentProofInputs?: readonly unknown[];
        readonly dynamicRosterProfileEvidence?: unknown;
        readonly linearStatement?: unknown;
        readonly parameterSet?: unknown;
        readonly proofBytesHex?: string;
        readonly proofEncoding?: unknown;
        readonly publicRandomnessHex?: string;
        readonly statement: unknown;
        readonly casualMicroRosterAcknowledged?: boolean;
    }): BallotPrivacyKernelVerification;
    verifyClaimBearingBallotPackage(input: {
        readonly ballotPackage: unknown;
        readonly dynamicRosterProfileEvidence?: unknown;
        readonly casualMicroRosterAcknowledged?: boolean;
    }): BallotPrivacyKernelVerification;
    generateAggregateDerivationProof(input: {
        readonly proofInput: unknown;
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
    }): BallotPrivacyProofGeneration;
    verifyAggregateDerivationProof(input: {
        readonly closeRecord: unknown;
        readonly component: unknown;
        readonly contributorActionContext: unknown;
        readonly countedBallotPackages?: readonly unknown[];
        readonly casualMicroRosterAcknowledged?: boolean;
    }): BallotPrivacyKernelVerification;
    generateAggregateBridgeEncryption(input: {
        readonly aggregateSelectionPolicyHash: ProtocolHash;
        readonly aggregateDerivationComponent: unknown;
        readonly aggregateWitness: unknown;
        readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
        readonly heParamHash: ProtocolHash;
        readonly setupPackage: unknown;
        readonly proverRandomnessHex?: string;
        readonly encryptionRandomnessSeedHex?: string;
        readonly developmentRandomnessOverrideAcknowledged?: boolean;
        readonly includeCanonicalBytesHex?: boolean;
        readonly closeRecord?: unknown;
        readonly contributorActionContext?: unknown;
        readonly countedBallotPackages?: readonly unknown[];
        readonly casualMicroRosterAcknowledged?: boolean;
    }): AggregateBridgeEncryptionGeneration | BallotPrivacyKernelVerification;
    evaluateAggregateBridgeRelation(input: {
        readonly aggregateSelectionPolicyHash: ProtocolHash;
        readonly aggregateDerivationComponent: unknown;
        readonly aggregateWitness: unknown;
        readonly bridgeEncryption: unknown;
        readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
        readonly heParamHash: ProtocolHash;
        readonly setupPackage: unknown;
        readonly proverRandomnessHex?: string;
        readonly encryptionRandomnessSeedHex?: string;
        readonly developmentRandomnessOverrideAcknowledged?: boolean;
        readonly closeRecord?: unknown;
        readonly contributorActionContext?: unknown;
        readonly countedBallotPackages?: readonly unknown[];
        readonly casualMicroRosterAcknowledged?: boolean;
    }): AggregateBridgeRelationEvaluation | BallotPrivacyKernelVerification;
    verifyAggregateBridgeEncryption(input: {
        readonly aggregateSelectionPolicyHash: ProtocolHash;
        readonly aggregateDerivationComponent: unknown;
        readonly bridgeEncryption: unknown;
        readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
        readonly heParamHash: ProtocolHash;
        readonly setupPackage: unknown;
        readonly closeRecord?: unknown;
        readonly contributorActionContext?: unknown;
        readonly countedBallotPackages?: readonly unknown[];
        readonly casualMicroRosterAcknowledged?: boolean;
    }): AggregateBridgeEncryptionVerification | BallotPrivacyKernelVerification;
    describeBgvRnsProfile(): BgvRnsProfileDescription;
    describeBgvOperationRegistry(): unknown;
    describeBgvPassiveSetupObjectModel(): unknown;
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
    prepareBgvEvaluationKeyMaterial(input: {
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
    describeMaskedRankRefreshProfile(): Record<string, unknown>;
    verifyMaskedRankRefreshTranscript(
        input: MaskedRankRefreshTranscriptVerificationInput,
    ): Record<string, unknown>;
    rejectBgvReferenceOracleArtifact(input: {
        readonly artifact: unknown;
    }): BgvReferenceOracleRejection;
    runDevelopmentTopKEvaluation(
        input: TopKEvaluatorDevelopmentEvaluationInput,
    ): TopKEvaluatorDevelopmentEvaluation;
    runEncryptedAggregateTopKEvaluation(
        input: TopKEvaluatorEncryptedAggregateEvaluationInput,
    ): TopKEvaluatorEncryptedAggregateEvaluation;
    runEncryptedAggregateTopKEvaluationSweep(
        input: TopKEvaluatorEncryptedAggregateEvaluationSweepInput,
    ): TopKEvaluatorEncryptedAggregateEvaluationSweep;
};

export type TopKEvaluatorDevelopmentEvaluationInput = {
    readonly scores: readonly number[];
    readonly topCount: number;
    readonly scoreDomainMax: number;
    readonly comparisonMethod?: 'bitSliced' | 'differencePolynomial';
    readonly rankPackingMethod?: 'perOptionBroadcast' | 'generatorOrdered';
    readonly workingLevel?: number;
    readonly seed?: string;
    readonly ceremonyId?: string;
    readonly manifestHash?: string;
    readonly rosterHash?: string;
    readonly canonicalBallotSetHash?: string;
    readonly aggregateReadyRecordHash?: string;
    readonly encryptedAggregateBridgeHash?: string;
    readonly encryptedAggregateTargetBasisDataRoot?: string;
    readonly bgvPublicKeyRoot?: string;
    readonly collectivePublicKeyRoot?: string;
    readonly evaluationKeyRoot?: string;
    readonly rotSetHash?: string;
    readonly preTargetBoardHead?: string;
    readonly evaluatorSignature?: string;
};

export type TopKEvaluatorDevelopmentEvaluation = {
    readonly ok: true;
    readonly operation: 'runDevelopmentTopKEvaluation';
    readonly comparisonProfile: string;
    readonly evaluationContextHash: string;
    readonly evaluationKeysValidated: boolean;
    readonly decodedTargetIdSlots: readonly number[];
    readonly decodedTargetOrderSlots: readonly number[];
    readonly decodedRanks: readonly number[];
    readonly rankPackingMethod: 'perOptionBroadcast' | 'generatorOrdered';
    readonly packedRankRoot: string | null;
    readonly packedTargetIdRoot: string | null;
    readonly packedTargetOrderRoot: string | null;
    readonly decodedPackedRanks: readonly number[] | null;
    readonly decodedPackedTargetIdSlots: readonly number[] | null;
    readonly decodedPackedTargetOrderSlots: readonly number[] | null;
    readonly program: Record<string, unknown>;
    readonly evaluationNoiseCertificate: Record<string, unknown>;
    readonly topKEvaluationRecord: Record<string, unknown>;
    readonly targetProposalHash: string;
    readonly appendixDPublicInputStatement: Record<string, unknown>;
    readonly statusLabels: readonly string[];
};

export type TopKEvaluatorEncryptedAggregateInput = {
    readonly aggregateContribution?: unknown;
    readonly aggregateDerivationComponent?: unknown;
    readonly aggregateDerivationComponentHash: ProtocolHash;
    readonly aggregateDerivationStatementHash: ProtocolHash;
    readonly bridgeEvidenceVerification?: unknown;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly bridgeEncryption: unknown;
};

export type MaskedRankRefreshTranscriptVerificationInput = {
    readonly rankRefreshTranscript: unknown;
    readonly setupPackage: unknown;
    readonly expectedAlgebraicShareVerificationKeyHash?: ProtocolHash;
    readonly expectedAlgebraicShareVerificationKeyRoot?: ProtocolHash;
    readonly expectedBgvPublicKeyRoot?: ProtocolHash;
    readonly expectedCollectivePublicKeyRoot?: ProtocolHash;
    readonly expectedEvaluationContextHash?: ProtocolHash;
    readonly expectedEvaluationKeyRoot?: ProtocolHash;
    readonly expectedInputRankCiphertextRoot?: ProtocolHash;
    readonly expectedRefreshedRankCiphertextRoot?: ProtocolHash;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedTargetLayoutHash?: ProtocolHash;
    readonly expectedThresholdShareVerificationKeyHash?: ProtocolHash;
    readonly expectedThresholdShareVerificationKeyRoot?: ProtocolHash;
    readonly expectedTopCount?: number;
};

export type TopKEvaluatorEncryptedAggregateEvaluationInput = {
    readonly setupPackage: BgvPassiveSetupPackage;
    readonly evaluationKeyMaterial?: unknown;
    readonly preparedEvaluationKeyMaterialHandle?: string;
    readonly aggregateReadyRecord: unknown;
    readonly encryptedAggregateInputs: readonly TopKEvaluatorEncryptedAggregateInput[];
    readonly topCount: number;
    readonly scoreDomainMax: number;
    readonly workingLevel?: number;
    readonly canonicalBallotSetHash: string;
    readonly preTargetBoardHead: string;
    readonly evaluatorSignature: string;
    readonly rankRefreshTranscript?: unknown;
    readonly rankRefreshTranscripts?: readonly unknown[];
};

export type TopKEvaluatorEncryptedAggregateEvaluationSweepInput = Omit<
    TopKEvaluatorEncryptedAggregateEvaluationInput,
    'topCount'
> & {
    readonly topCounts: readonly number[];
};

export type TopKEvaluatorEncryptedAggregateEvaluation = {
    readonly ok: true;
    readonly operation: 'runEncryptedAggregateTopKEvaluation';
    readonly comparisonProfile: string;
    readonly rankPackingMethod: string;
    readonly inputBindingStatus: string;
    readonly evaluationContextHash: string;
    readonly evaluationNoiseCertificate: Record<string, unknown>;
    readonly topKEvaluationRecord: Record<string, unknown>;
    readonly encryptedTopKBundle: Record<string, unknown>;
    readonly encryptedSparseTarget: Record<string, unknown>;
    readonly targetProposalHash: string;
    readonly appendixDPublicInputStatement: Record<string, unknown>;
    readonly statusLabels: readonly string[];
};

export type TopKEvaluatorEncryptedAggregateEvaluationSweep = {
    readonly ok: true;
    readonly operation: 'runEncryptedAggregateTopKEvaluationSweep';
    readonly comparisonProfile: string;
    readonly rankPackingMethod: string;
    readonly inputBindingStatus: string;
    readonly topCounts: readonly number[];
    readonly sharedEncryptedRankBundle: Record<string, unknown>;
    readonly evaluations: readonly Omit<
        TopKEvaluatorEncryptedAggregateEvaluation,
        'encryptedTopKBundle'
    >[];
    readonly statusLabels: readonly string[];
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
          readonly command: 'DescribeBallotPrivacyProofBackend';
      }
    | {
          readonly command: 'VerifyBallotPrivacyLinearProofVector';
          readonly vectorCase: unknown;
      }
    | {
          readonly command: 'VerifyBallotPrivacyEncodedRelationVector';
          readonly vectorCase: unknown;
      }
    | {
          readonly command: 'VerifyBallotPrivacyReceiverKeyVector';
          readonly vectorCase: unknown;
      }
    | {
          readonly command: 'VerifyReceiverKeyProof';
          readonly linearStatement?: unknown;
          readonly parameterSet?: unknown;
          readonly proofBytesHex?: string;
          readonly proofEncoding?: unknown;
          readonly publicRandomnessHex?: string;
          readonly receiverKeyProof: unknown;
      }
    | {
          readonly command: 'PrepareReceiverKeyProofGeneration';
          readonly linearStatement: unknown;
          readonly parameterSet: unknown;
          readonly proofEncoding: unknown;
          readonly publicRandomnessHex: string;
          readonly secretState: unknown;
          readonly proverRandomnessHex?: string;
      }
    | {
          readonly command: 'GenerateReceiverKeyProof';
          readonly linearStatement: unknown;
          readonly parameterSet: unknown;
          readonly proofEncoding: unknown;
          readonly publicRandomnessHex: string;
          readonly secretState: unknown;
          readonly proverRandomnessHex: string;
      }
    | {
          readonly command: 'GenerateBallotProof';
          readonly linearStatement: unknown;
          readonly parameterSet: unknown;
          readonly proofEncoding: unknown;
          readonly publicRandomnessHex: string;
          readonly secretState: unknown;
          readonly proverRandomnessHex: string;
      }
    | {
          readonly command: 'GenerateBallotComponentProof';
          readonly componentId: string;
          readonly proofInput: unknown;
          readonly secretState: unknown;
          readonly proverRandomnessHex: string;
      }
    | {
          readonly command: 'GenerateBallotProofRecord';
          readonly statement: unknown;
          readonly linearStatement: unknown;
          readonly parameterSet: unknown;
          readonly proofEncoding: unknown;
          readonly publicRandomnessHex: string;
          readonly componentBundleStatement: unknown;
          readonly componentProofInputs: readonly unknown[];
          readonly secretState: unknown;
          readonly proverRandomnessHex: string;
          readonly componentProverRandomnessHexes: Readonly<
              Record<string, string>
          >;
          readonly componentSecretStates?: Readonly<Record<string, unknown>>;
          readonly casualMicroRosterAcknowledged?: boolean;
      }
    | {
          readonly command: 'VerifyBallotProof';
          readonly ballotProof: unknown;
          readonly componentBundleStatement?: unknown;
          readonly componentProofBundle?: unknown;
          readonly componentProofInputs?: readonly unknown[];
          readonly dynamicRosterProfileEvidence?: unknown;
          readonly linearStatement?: unknown;
          readonly parameterSet?: unknown;
          readonly proofBytesHex?: string;
          readonly proofEncoding?: unknown;
          readonly publicRandomnessHex?: string;
          readonly statement: unknown;
          readonly casualMicroRosterAcknowledged?: boolean;
      }
    | {
          readonly command: 'VerifyClaimBearingBallotPackage';
          readonly ballotPackage: unknown;
          readonly dynamicRosterProfileEvidence?: unknown;
          readonly casualMicroRosterAcknowledged?: boolean;
      }
    | {
          readonly command: 'GenerateAggregateDerivationProof';
          readonly proofInput: unknown;
          readonly secretState: unknown;
          readonly proverRandomnessHex: string;
      }
    | {
          readonly command: 'VerifyAggregateDerivationProof';
          readonly closeRecord: unknown;
          readonly component: unknown;
          readonly contributorActionContext: unknown;
          readonly countedBallotPackages?: readonly unknown[];
          readonly casualMicroRosterAcknowledged?: boolean;
      }
    | {
          readonly command: 'GenerateAggregateBridgeEncryption';
          readonly aggregateSelectionPolicyHash: ProtocolHash;
          readonly aggregateDerivationComponent: unknown;
          readonly aggregateWitness: unknown;
          readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
          readonly heParamHash: ProtocolHash;
          readonly setupPackage: unknown;
          readonly proverRandomnessHex: string;
          readonly proverRandomnessSource: BridgeRandomnessSource;
          readonly encryptionRandomnessSeedHex: string;
          readonly encryptionRandomnessSeedSource: BridgeRandomnessSource;
          readonly developmentRandomnessOverrideAcknowledged?: boolean;
          readonly includeCanonicalBytesHex?: boolean;
          readonly closeRecord?: unknown;
          readonly contributorActionContext?: unknown;
          readonly countedBallotPackages?: readonly unknown[];
          readonly casualMicroRosterAcknowledged?: boolean;
      }
    | {
          readonly command: 'EvaluateAggregateBridgeRelation';
          readonly aggregateSelectionPolicyHash: ProtocolHash;
          readonly aggregateDerivationComponent: unknown;
          readonly aggregateWitness: unknown;
          readonly bridgeEncryption: unknown;
          readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
          readonly heParamHash: ProtocolHash;
          readonly setupPackage: unknown;
          readonly proverRandomnessHex: string;
          readonly proverRandomnessSource: BridgeRandomnessSource;
          readonly encryptionRandomnessSeedHex: string;
          readonly encryptionRandomnessSeedSource: BridgeRandomnessSource;
          readonly developmentRandomnessOverrideAcknowledged?: boolean;
          readonly closeRecord?: unknown;
          readonly contributorActionContext?: unknown;
          readonly countedBallotPackages?: readonly unknown[];
          readonly casualMicroRosterAcknowledged?: boolean;
      }
    | {
          readonly command: 'VerifyAggregateBridgeEncryption';
          readonly aggregateSelectionPolicyHash: ProtocolHash;
          readonly aggregateDerivationComponent: unknown;
          readonly bridgeEncryption: unknown;
          readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
          readonly heParamHash: ProtocolHash;
          readonly setupPackage: unknown;
          readonly closeRecord?: unknown;
          readonly contributorActionContext?: unknown;
          readonly countedBallotPackages?: readonly unknown[];
          readonly casualMicroRosterAcknowledged?: boolean;
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
          readonly command: 'DescribeMaskedRankRefreshProfile';
      }
    | ({
          readonly command: 'VerifyMaskedRankRefreshTranscript';
      } & MaskedRankRefreshTranscriptVerificationInput)
    | {
          readonly command: 'DescribeBgvPassiveSetupObjectModel';
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
          readonly command: 'PrepareBgvEvaluationKeyMaterial';
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
    | ({
          readonly command: 'RunDevelopmentTopKEvaluation';
      } & TopKEvaluatorDevelopmentEvaluationInput)
    | ({
          readonly command: 'RunEncryptedAggregateTopKEvaluation';
      } & TopKEvaluatorEncryptedAggregateEvaluationInput)
    | ({
          readonly command: 'RunEncryptedAggregateTopKEvaluationSweep';
      } & TopKEvaluatorEncryptedAggregateEvaluationSweepInput);

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
