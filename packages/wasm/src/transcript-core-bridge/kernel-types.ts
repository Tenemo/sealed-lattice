import type {
    CanonicalError,
    FieldElement,
    ProtocolHash,
    TranscriptCoreAnalysis,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';

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
    BgvRnsProfileReport,
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
    BgvRnsProfileReport,
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
        readonly unsafeSmallRosterAcknowledged?: boolean;
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
        readonly unsafeSmallRosterAcknowledged?: boolean;
    }): BallotPrivacyKernelVerification;
    verifyClaimBearingBallotPackage(input: {
        readonly ballotPackage: unknown;
        readonly dynamicRosterProfileEvidence?: unknown;
        readonly casualMicroRosterAcknowledged?: boolean;
        readonly unsafeSmallRosterAcknowledged?: boolean;
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
        readonly unsafeSmallRosterAcknowledged?: boolean;
    }): BallotPrivacyKernelVerification;
    generateAggregateBridgeEncryption(input: {
        readonly aggregateSelectionPolicyHash: ProtocolHash;
        readonly aggregateDerivationComponent: unknown;
        readonly aggregateWitness: unknown;
        readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
        readonly heParamHash: ProtocolHash;
        readonly setupPackage: unknown;
        readonly proverRandomnessHex?: string;
        readonly includeCanonicalBytesHex?: boolean;
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
    }): AggregateBridgeRelationEvaluation | BallotPrivacyKernelVerification;
    verifyAggregateBridgeEncryption(input: {
        readonly aggregateSelectionPolicyHash: ProtocolHash;
        readonly aggregateDerivationComponent: unknown;
        readonly bridgeEncryption: unknown;
        readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
        readonly heParamHash: ProtocolHash;
        readonly setupPackage: unknown;
    }): AggregateBridgeEncryptionVerification | BallotPrivacyKernelVerification;
    describeBgvRnsProfile(): BgvRnsProfileReport;
    describeBgvOperationRegistry(): unknown;
    generateBgvBackendReport(): unknown;
    describeBgvPassiveSetupObjectModel(): unknown;
    generateBgvPassiveSetup(input: {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly thresholdProfileHash: ProtocolHash;
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
          readonly unsafeSmallRosterAcknowledged?: boolean;
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
          readonly unsafeSmallRosterAcknowledged?: boolean;
      }
    | {
          readonly command: 'VerifyClaimBearingBallotPackage';
          readonly ballotPackage: unknown;
          readonly dynamicRosterProfileEvidence?: unknown;
          readonly casualMicroRosterAcknowledged?: boolean;
          readonly unsafeSmallRosterAcknowledged?: boolean;
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
          readonly unsafeSmallRosterAcknowledged?: boolean;
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
          readonly includeCanonicalBytesHex?: boolean;
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
      }
    | {
          readonly command: 'VerifyAggregateBridgeEncryption';
          readonly aggregateSelectionPolicyHash: ProtocolHash;
          readonly aggregateDerivationComponent: unknown;
          readonly bridgeEncryption: unknown;
          readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
          readonly heParamHash: ProtocolHash;
          readonly setupPackage: unknown;
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
          readonly command: 'GenerateBgvBackendReport';
      }
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
