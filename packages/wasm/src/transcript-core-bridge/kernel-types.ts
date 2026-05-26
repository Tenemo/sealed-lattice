import type {
    CanonicalError,
    FieldElement,
    ProtocolDigest,
    TranscriptCoreAnalysis,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';

export type TranscriptCoreKernelSharePoint = {
    readonly rosterPosition: number;
    readonly value: FieldElement;
};

export type TranscriptCorePlaintextComparison = {
    readonly greaterThan: FieldElement;
    readonly equal: FieldElement;
    readonly scoreDifference: number;
};

/** Runtime status reported by the ballot privacy proof backend. */
export type BallotPrivacyProofBackendStatus = {
    readonly backendName: string;
    readonly backendAvailable: boolean;
    readonly portableRustWasmPortRequired: boolean;
    readonly requiredComponents: readonly string[];
    readonly blockedReason: string | null;
};

/** Structured result returned by WASM ballot privacy proof verification commands. */
export type BallotPrivacyKernelVerification = {
    readonly ok: boolean;
    readonly backendAvailable: boolean;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly operation: string;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
        readonly objectDigest?: string;
    }[];
    readonly unresolvedReason: string | null;
};

export type BallotPrivacyLinearProofVectorVerification = {
    readonly ok: boolean;
    readonly backendAvailable: boolean;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
    }[];
    readonly unresolvedReason: string | null;
    readonly caseName?: string;
    readonly vectorAvailable?: boolean;
    readonly expectedOutcome?: string;
};

export type BallotPrivacyEncodedRelationVectorVerification = {
    readonly ok: boolean;
    readonly backendAvailable: boolean;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
    }[];
    readonly unresolvedReason: string | null;
    readonly caseName?: string;
    readonly vectorAvailable?: boolean;
    readonly expectedOutcome?: string;
};

export type BallotPrivacyReceiverKeyVectorVerification = {
    readonly ok: boolean;
    readonly backendAvailable: boolean;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
    }[];
    readonly unresolvedReason: string | null;
    readonly caseName?: string;
    readonly vectorAvailable?: boolean;
    readonly expectedOutcome?: string;
};

export type BallotPrivacyReceiverKeyProofGenerationPreparation =
    BallotPrivacyKernelVerification & {
        readonly generatedProofBytes?: false;
        readonly summary?: {
            readonly relationWitnessPolynomialCount: number;
            readonly shortWitnessPolynomialCount: number;
            readonly preparedShortWitnessPolynomialCount: number;
            readonly witnessL2Squared: string;
            readonly witnessL2BoundSquared: string;
            readonly normSlack: string;
            readonly abdlopCommitment?: {
                readonly compressedCommitmentPolynomialCount: number;
                readonly openingRandomnessPolynomialCount: number;
                readonly openingRemainderPolynomialCount: number;
                readonly proverRandomnessSeedBytes: number;
                readonly subprotocolSeedBytes: number;
                readonly abdlopCommitmentHash: string;
            } | null;
        };
    };

export type BallotPrivacyReceiverKeyProofGeneration =
    BallotPrivacyKernelVerification & {
        readonly generatedProofBytes?: true;
        readonly proofBytesHex?: string;
        readonly proofSizeBytes?: number;
        readonly summary?: {
            readonly abdlopCommitmentHash: string;
            readonly z34ChallengeHash: string;
            readonly generatorChallengeHash: string;
            readonly quadraticChallengeHash: string;
        };
    };

export type BallotPrivacyProofGeneration =
    BallotPrivacyReceiverKeyProofGeneration & {
        readonly ballotProof?: unknown;
        readonly componentProofBundle?: unknown;
        readonly componentProofInputs?: readonly unknown[];
        readonly parameterSet?: unknown;
        readonly proofEncoding?: unknown;
        readonly verification?: BallotPrivacyKernelVerification;
    };

export type BgvRnsProfileReport = {
    readonly profile: {
        readonly profileId: string;
        readonly backendProfileId: string;
        readonly polynomialDegree: number;
        readonly plaintextModulus: number;
        readonly dataBasisId: string;
        readonly extendedBasisId: string;
        readonly specialBasisId: string;
        readonly dataPrimes: readonly number[];
        readonly specialPrime: number;
        readonly dataPrimeBitLength: number;
        readonly dataLevels: number;
        readonly extendedLevels: number;
        readonly aggregateShareLayoutId: string;
        readonly batchEncoderId: string;
        readonly canonicalCiphertextConventionId: string;
    };
    readonly profileDigest: ProtocolDigest;
    readonly backendProfileDigest: ProtocolDigest;
    readonly batchEncoderDigest: ProtocolDigest;
    readonly encryptedAggregateInputLayoutDigest: ProtocolDigest;
    readonly batchLayoutBinding: unknown;
    readonly batchLayoutBindingDigest: ProtocolDigest;
    readonly ballotScoreEncodingProfileDigest: ProtocolDigest;
    readonly ballotShareLayoutProfileDigest: ProtocolDigest;
    readonly aggregateInputEncodingProfileDigest: ProtocolDigest;
    readonly encodedAggregateLayoutDigest: ProtocolDigest;
    readonly topKEvaluatorInputLayoutDigest: ProtocolDigest;
    readonly canonicalCiphertextConventionDigest: ProtocolDigest;
    readonly allowedEvaluatorOpsDigest: ProtocolDigest;
    readonly securityEstimatorInputDigest: string;
    readonly bigIntegerReferenceVectors: unknown;
    readonly bigIntegerReferenceVectorRoot: ProtocolDigest;
    readonly basisReports: readonly unknown[];
    readonly statusLabels: readonly string[];
    readonly nonClaims: readonly string[];
};

export type BgvObjectValidation = {
    readonly ok: boolean;
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly profileDigest: ProtocolDigest;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly layoutDigest: ProtocolDigest;
    readonly plaintextRoot?: ProtocolDigest;
    readonly ciphertextRoot?: ProtocolDigest;
    readonly canonicalBytesHash512: string;
    readonly statusLabels: readonly string[];
};

export type BgvCanonicalObjectAnalysis = {
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly profileDigest: ProtocolDigest;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly layoutDigest: ProtocolDigest;
    readonly statusLabels: readonly string[];
};

export type BgvProfileRejection = {
    readonly ok: false;
    readonly operation: string;
    readonly acceptedDigests: readonly ProtocolDigest[];
    readonly refusedObjects: readonly {
        readonly code: 'BGVProfileRejected';
        readonly reasonCode: string;
        readonly message: string;
        readonly objectDigest?: ProtocolDigest;
    }[];
    readonly unresolvedReason: 'BGVProfileRejected';
    readonly statusLabels: readonly string[];
};

export type BgvEvaluatorOperationValidation =
    | {
          readonly ok: true;
          readonly operation: 'validateBgvEvaluatorOperation';
          readonly acceptedOperation: string;
          readonly allowedEvaluatorOpsDigest: ProtocolDigest;
          readonly statusLabels: readonly string[];
      }
    | BgvProfileRejection;

export type BgvBatchPlaintextEncoding = {
    readonly profileDigest: ProtocolDigest;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly suppliedSlotCount: number;
    readonly slotCount: number;
    readonly plaintextRoot: ProtocolDigest;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly batchLayoutBindingDigest: ProtocolDigest;
    readonly sampledSlots: readonly {
        readonly position: number;
        readonly value: number;
    }[];
    readonly sampledCoefficientsModPlaintext: readonly {
        readonly position: number;
        readonly value: number;
    }[];
    readonly validation: BgvObjectValidation;
    readonly statusLabels: readonly string[];
    readonly canonicalBytesHex?: string;
};

export type BgvReferenceOracleRejection = {
    readonly ok: false;
    readonly artifactKind: string;
    readonly acceptedAsProtocolEvidence: false;
    readonly statusLabels: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
    }[];
};

export type BgvCiphertextConventionFixture = {
    readonly profileDigest: ProtocolDigest;
    readonly ciphertextRoot: ProtocolDigest;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly componentCount: number;
    readonly validation: BgvObjectValidation;
    readonly statusLabels: readonly string[];
    readonly canonicalBytesHex?: string;
};

export type BgvBaseConversionFixture = {
    readonly sourcePlaintextRoot: ProtocolDigest;
    readonly convertedPlaintextRoot: ProtocolDigest;
    readonly sourceCanonicalBytesHash512: string;
    readonly convertedCanonicalBytesHash512: string;
    readonly sourceBasisId: string;
    readonly convertedBasisId: string;
    readonly convertedModulusCount: number;
    readonly sampledConvertedResidues: readonly {
        readonly position: number;
        readonly value: number;
    }[];
    readonly statusLabels: readonly string[];
};

export type BgvPassiveSetupParticipantInput =
    | string
    | {
          readonly trusteeIdentity: string;
          readonly rosterPosition?: number;
          readonly boardPosition?: number;
          readonly recoveryEpoch?: number;
          readonly deviceEpoch?: number;
      };

export type BgvPassiveSetupPackage = {
    readonly objectType: 'BgvPassiveSetupPackage';
    readonly objectVersion: 1;
    readonly setupProfileId: string;
    readonly setupMode: string;
    readonly setupPackageDigest: ProtocolDigest;
    readonly setupInputs: {
        readonly ceremonyId: string;
        readonly manifestDigest: ProtocolDigest;
        readonly rosterDigest: ProtocolDigest;
        readonly thresholdProfileDigest: ProtocolDigest;
        readonly participantCount: number;
        readonly participantIdentities: readonly string[];
        readonly setupSeedDigest: string;
    };
    readonly profileBindings: Readonly<Record<string, unknown>>;
    readonly participants: readonly unknown[];
    readonly collectivePublicKey: {
        readonly collectivePublicKeyRoot: ProtocolDigest;
        readonly bgvPublicKeyRoot: ProtocolDigest;
        readonly statusLabels: readonly string[];
        readonly record: unknown;
    };
    readonly thresholdVerificationMaterial: Readonly<Record<string, unknown>>;
    readonly evaluationKeys: {
        readonly rotSetDigest: ProtocolDigest;
        readonly evaluationKeyRoot: ProtocolDigest;
        readonly relinearizationKeyRoot: ProtocolDigest;
        readonly keySwitchKeyRoot: ProtocolDigest;
        readonly keySwitchDecompositionDigest: ProtocolDigest;
        readonly rotationKeyRoots: readonly unknown[];
        readonly statusLabels: readonly string[];
        readonly record: unknown;
        readonly rotSet: unknown;
    };
    readonly developmentEncryptionFixture: Readonly<Record<string, unknown>>;
    readonly certificates: Readonly<Record<string, unknown>>;
    readonly trustedDealerBoundary: Readonly<Record<string, unknown>>;
    readonly kllpsCompatibility: {
        readonly thresholdDecryptionProfileId: string;
        readonly thresholdDecryptionProfileDigest: ProtocolDigest;
        readonly kllpsTargetDecryptionProfileDigest: ProtocolDigest;
        readonly setupMaterialCompatibleWithKLLPS: boolean;
        readonly KLLPSPartDecImplemented: boolean;
        readonly KLLPSC1C4Certified: boolean;
    };
    readonly statusLabels: readonly string[];
    readonly nonClaims: readonly string[];
};

export type BgvPassiveSetupVerification = {
    readonly ok: boolean;
    readonly operation: 'verifyBgvPassiveSetupPackage';
    readonly acceptedDigests: readonly ProtocolDigest[];
    readonly refusedObjects: readonly unknown[];
    readonly unresolvedReason: string | null;
    readonly statusLabels: readonly string[];
};

export type AggregateBridgeEncryptionGeneration = {
    readonly ok: boolean;
    readonly operation: 'generateAggregateBridgeEncryption';
    readonly profileDigest: ProtocolDigest;
    readonly rustBgvBackendProfileDigest: ProtocolDigest;
    readonly canonicalCiphertextConventionDigest: ProtocolDigest;
    readonly collectivePublicKeyRoot: ProtocolDigest;
    readonly bgvPublicKeyRoot: ProtocolDigest;
    readonly plaintextRoot: ProtocolDigest;
    readonly ciphertextRoot: ProtocolDigest;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolDigest;
    readonly aggregateRelationSubproofSizeBytes: number;
    readonly aggregateRelationChallengeHex: string;
    readonly aggregateRelationCommitmentDigest: ProtocolDigest;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateDerivationComponentDigest: ProtocolDigest;
    readonly aggregateDerivationStatementDigest: ProtocolDigest;
    readonly bridgeProofProfileDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
    readonly bridgeProofTargetContractDigest: ProtocolDigest;
    readonly bridgeProofBytesHex: string;
    readonly bridgeProofBytesDigest: ProtocolDigest;
    readonly bridgeProofRoot: ProtocolDigest;
    readonly bridgeProofVerificationStatus: 'BridgeProofRelationChecked';
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly suppliedSlotCount: number;
    readonly slotCount: number;
    readonly sampledPublicRelationChecks: readonly unknown[];
    readonly sampledPublicRelationCheckPolicy: {
        readonly acceptedForBridgeProofVerification: false;
        readonly diagnosticOnly: true;
        readonly fullBridgeProofRequired: true;
        readonly objectType: 'M9BridgeSampledRelationCheckPolicy';
        readonly objectVersion: 1;
        readonly relationCheckSource: 'first-data-prime-diagnostic';
        readonly sampledOnlyBridgeVerificationAccepted: false;
        readonly sampledRelationCheckCount: number;
    };
    readonly privateMaterialDisclosure: Readonly<Record<string, boolean>>;
    readonly statusLabels: readonly string[];
    readonly canonicalBytesHex?: string;
};

export type AggregateBridgeEncryptionVerification = {
    readonly ok: boolean;
    readonly backendAvailable: boolean;
    readonly operation: 'verifyAggregateBridgeEncryption';
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly ProtocolDigest[];
    readonly refusedObjects: readonly unknown[];
    readonly unresolvedReason: string | null;
    readonly bridgeProofVerificationStatus:
        | 'BridgeProofBackendPending'
        | 'BridgeProofRelationChecked';
    readonly bridgeEvidenceVerificationStatus: 'BridgeProofEvidenceChecked';
    readonly bridgeProofProfileDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
    readonly bridgeProofTargetContractDigest: ProtocolDigest;
    readonly bridgeProofBytesDigest: ProtocolDigest;
    readonly bridgeProofRoot: ProtocolDigest;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolDigest;
    readonly aggregateRelationSubproofSizeBytes: number;
    readonly aggregateRelationChallengeHex: string;
    readonly aggregateRelationCommitmentDigest: ProtocolDigest;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateQuotientCoordinateCount: number;
    readonly sharedWitnessChallengeHex?: string | null;
    readonly sharedResponseScalarCount?: number | null;
};

export type AggregateBridgeRelationEvaluation = {
    readonly ok: boolean;
    readonly operation: 'evaluateAggregateBridgeRelation';
    readonly relationEvaluationStatus?: 'AggregateBridgePrivateRelationSatisfied';
    readonly bridgeProofVerificationStatus?:
        | 'BridgeProofBackendPending'
        | 'BridgeProofRelationChecked';
    readonly bridgeEvidenceVerificationStatus?: 'BridgeProofEvidenceChecked';
    readonly publicArtifactWitnessCleanResult?: boolean;
    readonly bridgeProofBackendStillRequired?: boolean;
    readonly scopedBridgeRelationClosure?: boolean;
    readonly participantCount?: number;
    readonly optionCount?: number;
    readonly claimTier?: string;
    readonly shareVectorWidth?: number;
    readonly aggregateReducedCoordinateCount?: number;
    readonly aggregateQuotientCoordinateCount?: number;
    readonly proofByteLength?: number;
    readonly ciphertextShape?: unknown;
    readonly acceptedDigests?: readonly ProtocolDigest[];
    readonly statusLabels?: readonly string[];
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
    deriveProtocolDigest(input: {
        readonly namespace: string;
        readonly value: unknown;
    }): ProtocolDigest;
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
        readonly aggregateSelectionPolicyDigest: ProtocolDigest;
        readonly aggregateDerivationComponent: unknown;
        readonly aggregateWitness: unknown;
        readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
        readonly heParamDigest: ProtocolDigest;
        readonly setupPackage: unknown;
        readonly proverRandomnessHex?: string;
        readonly includeCanonicalBytesHex?: boolean;
    }): AggregateBridgeEncryptionGeneration | BallotPrivacyKernelVerification;
    evaluateAggregateBridgeRelation(input: {
        readonly aggregateSelectionPolicyDigest: ProtocolDigest;
        readonly aggregateDerivationComponent: unknown;
        readonly aggregateWitness: unknown;
        readonly bridgeEncryption: unknown;
        readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
        readonly heParamDigest: ProtocolDigest;
        readonly setupPackage: unknown;
        readonly proverRandomnessHex?: string;
    }): AggregateBridgeRelationEvaluation | BallotPrivacyKernelVerification;
    verifyAggregateBridgeEncryption(input: {
        readonly aggregateSelectionPolicyDigest: ProtocolDigest;
        readonly aggregateDerivationComponent: unknown;
        readonly bridgeEncryption: unknown;
        readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
        readonly heParamDigest: ProtocolDigest;
        readonly setupPackage: unknown;
    }): AggregateBridgeEncryptionVerification | BallotPrivacyKernelVerification;
    describeBgvRnsProfile(): BgvRnsProfileReport;
    describeBgvOperationRegistry(): unknown;
    generateBgvBackendReport(): unknown;
    describeBgvPassiveSetupObjectModel(): unknown;
    generateBgvPassiveSetup(input: {
        readonly ceremonyId: string;
        readonly manifestDigest: ProtocolDigest;
        readonly rosterDigest: ProtocolDigest;
        readonly thresholdProfileDigest: ProtocolDigest;
        readonly participants: readonly BgvPassiveSetupParticipantInput[];
        readonly setupSeed?: string;
    }): BgvPassiveSetupPackage;
    verifyBgvPassiveSetup(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly expectedSetupPackageDigest?: ProtocolDigest;
        readonly expectedManifestDigest?: ProtocolDigest;
        readonly expectedRosterDigest?: ProtocolDigest;
        readonly expectedCollectivePublicKeyRoot?: ProtocolDigest;
        readonly expectedRotSetDigest?: ProtocolDigest;
        readonly expectedEvaluationKeyRoot?: ProtocolDigest;
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
          readonly command: 'DeriveProtocolDigest';
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
          readonly aggregateSelectionPolicyDigest: ProtocolDigest;
          readonly aggregateDerivationComponent: unknown;
          readonly aggregateWitness: unknown;
          readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
          readonly heParamDigest: ProtocolDigest;
          readonly setupPackage: unknown;
          readonly proverRandomnessHex: string;
          readonly includeCanonicalBytesHex?: boolean;
      }
    | {
          readonly command: 'EvaluateAggregateBridgeRelation';
          readonly aggregateSelectionPolicyDigest: ProtocolDigest;
          readonly aggregateDerivationComponent: unknown;
          readonly aggregateWitness: unknown;
          readonly bridgeEncryption: unknown;
          readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
          readonly heParamDigest: ProtocolDigest;
          readonly setupPackage: unknown;
          readonly proverRandomnessHex: string;
      }
    | {
          readonly command: 'VerifyAggregateBridgeEncryption';
          readonly aggregateSelectionPolicyDigest: ProtocolDigest;
          readonly aggregateDerivationComponent: unknown;
          readonly bridgeEncryption: unknown;
          readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
          readonly heParamDigest: ProtocolDigest;
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
          readonly manifestDigest: ProtocolDigest;
          readonly rosterDigest: ProtocolDigest;
          readonly thresholdProfileDigest: ProtocolDigest;
          readonly participants: readonly BgvPassiveSetupParticipantInput[];
          readonly setupSeed?: string;
      }
    | {
          readonly command: 'VerifyBgvPassiveSetup';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly expectedSetupPackageDigest?: ProtocolDigest;
          readonly expectedManifestDigest?: ProtocolDigest;
          readonly expectedRosterDigest?: ProtocolDigest;
          readonly expectedCollectivePublicKeyRoot?: ProtocolDigest;
          readonly expectedRotSetDigest?: ProtocolDigest;
          readonly expectedEvaluationKeyRoot?: ProtocolDigest;
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
