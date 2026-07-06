import type { ProtocolHash } from '@sealed-lattice/types';

type BgvJsonRecord = Readonly<Record<string, unknown>>;

type BgvTransportedMaterialObject<ObjectType extends string> = Readonly<
    BgvJsonRecord & {
        readonly objectType: ObjectType;
    }
>;

export type BgvSetupTransportChunk = Readonly<
    BgvJsonRecord & {
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }
>;

export type BgvTransportedSetupProofMaterialSet<
    ObjectType extends string = string,
> = BgvTransportedMaterialObject<ObjectType> &
    Readonly<{
        readonly proofFamily: string;
        readonly proofMaterials: readonly BgvJsonRecord[];
    }>;

export type BgvVerifiedSetupProofMaterial = Readonly<
    BgvJsonRecord & {
        readonly objectType: 'VerifiedSetupProofMaterial';
        readonly verificationId: string;
        readonly proofFamily: string;
        readonly proofMaterialRoot: ProtocolHash;
        readonly proofBytesEncoding: string;
        readonly proofChunkSizeBytes: number;
        readonly proofChunkCount: number;
        readonly proofTotalByteLength: number;
        readonly proofFullObjectHash: ProtocolHash;
        readonly proofChunkRoot: ProtocolHash;
        readonly proofChunkHashes: readonly ProtocolHash[];
    }
>;

export type BgvVerifiedSetupProofMaterialSet = Readonly<
    BgvJsonRecord & {
        readonly objectType: 'VerifiedSetupProofMaterialSet';
        readonly proofMaterials: readonly BgvVerifiedSetupProofMaterial[];
    }
>;

export type BgvTransportedPublicKeyShareMaterial =
    BgvTransportedMaterialObject<'SetupTransportedPublicKeyShareMaterial'> &
        Readonly<{
            readonly binaryFormat: string;
            readonly chunkSizeBytes: number;
            readonly chunkCount: number;
            readonly totalByteLength: number;
            readonly fullObjectHash: ProtocolHash;
            readonly chunkHashes: readonly ProtocolHash[];
            readonly chunkRoot: ProtocolHash;
            readonly chunks: readonly BgvSetupTransportChunk[];
        }>;

export type BgvTransportedEvaluationKeyShareComponentMaterialSet =
    BgvTransportedMaterialObject<'SetupTransportedEvaluationKeyShareComponentMaterialSet'> &
        Readonly<{
            readonly componentMaterials: readonly BgvJsonRecord[];
        }>;

export type BgvTransportedPublicEvaluationKeyMaterialSet =
    BgvTransportedMaterialObject<'SetupTransportedPublicEvaluationKeyMaterialSet'> &
        Readonly<{
            readonly materialEncoding: string;
            readonly publicEvaluationKeyMaterials: readonly BgvJsonRecord[];
            readonly componentMaterials?: readonly BgvJsonRecord[];
        }>;

export type BgvCollectiveSetupTransportCompanions = Readonly<{
    readonly transportedSameSecretProofMaterial?: BgvTransportedSetupProofMaterialSet<'SetupTransportedSameSecretProofMaterialSet'>;
    readonly transportedPublicKeyShareMaterial?: BgvTransportedPublicKeyShareMaterial;
    readonly transportedPublicKeyShareProofMaterial?: BgvTransportedSetupProofMaterialSet<'SetupTransportedPublicKeyShareProofMaterialSet'>;
    readonly transportedEvaluationKeyShareProofMaterial?: BgvTransportedSetupProofMaterialSet<'SetupTransportedEvaluationKeyShareProofMaterialSet'>;
    readonly transportedEvaluationKeyShareComponentMaterial?: BgvTransportedEvaluationKeyShareComponentMaterialSet;
    readonly transportedPublicEvaluationKeyMaterial?: BgvTransportedPublicEvaluationKeyMaterialSet;
    readonly verifiedSetupProofMaterials?: BgvVerifiedSetupProofMaterialSet;
}>;

export type BgvRnsParametersDescription = {
    readonly parameters: {
        readonly polynomialDegree: number;
        readonly plaintextModulus: number;
        readonly dataPrimes: readonly number[];
        readonly specialPrime: number;
        readonly dataPrimeBitLength: number;
        readonly dataLevels: number;
        readonly extendedLevels: number;
        readonly scoreRange: {
            readonly minimum: number;
            readonly maximum: number;
        };
        readonly bucketCount: number;
        readonly coordinatesPerOption: number;
        readonly slotCount: number;
        readonly allowedOperations: readonly string[];
    };
    readonly bgvParametersHash: ProtocolHash;
};

export type BgvObjectValidation = {
    readonly isValid: boolean;
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly bgvParametersHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly plaintextRoot?: ProtocolHash;
    readonly ciphertextRoot?: ProtocolHash;
};

export type BgvCanonicalObjectAnalysis = {
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly bgvParametersHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
};

export type BgvOperationRejection = {
    readonly isValid: false;
    readonly operation: string;
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly refusedObjects: readonly {
        readonly code: 'BgvOperationRejected';
        readonly reasonCode: string;
        readonly message: string;
        readonly objectHash?: ProtocolHash;
    }[];
    readonly unresolvedReason: 'BgvOperationRejected';
};

export type BgvEvaluatorOperationValidation =
    | {
          readonly isValid: true;
          readonly operation: 'validateBgvEvaluatorOperation';
          readonly acceptedOperation: string;
          readonly bgvParametersHash: ProtocolHash;
      }
    | BgvOperationRejection;

export type BgvBatchPlaintextEncoding = {
    readonly bgvParametersHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly suppliedSlotCount: number;
    readonly slotCount: number;
    readonly plaintextRoot: ProtocolHash;
    readonly sampledSlots: readonly {
        readonly position: number;
        readonly value: number;
    }[];
    readonly sampledCoefficientsModPlaintext: readonly {
        readonly position: number;
        readonly value: number;
    }[];
    readonly validation: BgvObjectValidation;
    readonly canonicalBytesHex?: string;
};

export type BgvCiphertextConventionFixture = {
    readonly bgvParametersHash: ProtocolHash;
    readonly ciphertextRoot: ProtocolHash;
    readonly componentCount: number;
    readonly validation: BgvObjectValidation;
    readonly canonicalBytesHex?: string;
};

export type BgvBaseConversionFixture = {
    readonly sourcePlaintextRoot: ProtocolHash;
    readonly convertedPlaintextRoot: ProtocolHash;
    readonly sourceBasisId: string;
    readonly convertedBasisId: string;
    readonly convertedModulusCount: number;
    readonly sampledConvertedResidues: readonly {
        readonly position: number;
        readonly value: number;
    }[];
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
    readonly setupMode: string;
    readonly setupPackageHash: ProtocolHash;
    readonly setupInputs: {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly thresholdParametersHash: ProtocolHash;
        readonly participantCount: number;
        readonly participantIdentities: readonly string[];
        readonly setupSeedHash: string;
    };
    readonly parameterBindings: Readonly<Record<string, unknown>>;
    readonly participants: readonly unknown[];
    readonly collectivePublicKey: {
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
        readonly bgvPublicKeyRoot: ProtocolHash;
        readonly record: unknown;
        readonly coefficientMaterial: unknown;
    };
    readonly thresholdVerificationMaterial: Readonly<Record<string, unknown>>;
    readonly evaluationKeys: {
        readonly rotSetHash: ProtocolHash;
        readonly evaluationKeyRoot: ProtocolHash;
        readonly relinearizationKeyRoot: ProtocolHash;
        readonly keySwitchKeyRoot: ProtocolHash;
        readonly keySwitchDecompositionHash: ProtocolHash;
        readonly rotationKeyRoots: readonly unknown[];
        readonly record: unknown;
        readonly rotSet: unknown;
    };
    readonly certificates: Readonly<Record<string, unknown>>;
    readonly targetDecryptionParameters: {
        readonly targetDecryptionParametersHash: ProtocolHash;
        readonly targetDecryptionParametersBindingHash: ProtocolHash;
    };
};

export type BgvPassiveSetupVerification = {
    readonly operation: 'verifyBgvPassiveSetupPackage';
    readonly acceptedHashes: readonly ProtocolHash[];
};

export type BgvCollectiveSetupParametersDescription = {
    readonly setupParametersHash: ProtocolHash;
    readonly canonicalTargetBasisHash: ProtocolHash;
    readonly objectType: 'SetupPackage';
    readonly adversaryModel: 'active-static';
    readonly livenessModel: 'secure-with-abort';
    readonly sharingModel: 'recipient-verified-vss';
    readonly sharingDomain: 'per-rns-prime';
    readonly completionRule: 'full-roster';
    readonly participantCount: number;
    readonly qSetupComplete: number;
    readonly qBallotRelease: number;
    readonly qFinal: number;
    readonly qDec: number;
    readonly qShare: {
        readonly objectType: 'QSharePrimeList';
        readonly primes: readonly number[];
    };
    readonly carryAwareVssShareRelation: {
        readonly objectType: 'CarryAwareVssShareRelation';
        readonly trusteePointRule: 'roster-position-plus-one';
        readonly coefficientOrder: 'constant-first';
        readonly relation: string;
        readonly carryWitnessDomain: 'non-negative-bounded-integer';
        readonly commitmentReductionRule: 'open-unreduced-lifted-share-with-explicit-carry';
    };
    readonly commitment: {
        readonly objectType: 'BdlopCommitment';
        readonly construction: string;
        readonly ring: Readonly<Record<string, unknown>>;
        readonly matrixShape: Readonly<Record<string, unknown>>;
        readonly messageEncoding: Readonly<Record<string, unknown>>;
        readonly openingDistribution: Readonly<Record<string, unknown>>;
        readonly homomorphism: Readonly<Record<string, unknown>>;
        readonly assumptions: Readonly<Record<string, unknown>>;
        readonly serialization: Readonly<Record<string, unknown>>;
    };
    readonly setupProof: {
        readonly objectType: 'SetupProof';
        readonly proofBackendBoundary: string;
        readonly arbitraryRelationApi: string;
        readonly relationModel: Readonly<Record<string, unknown>>;
        readonly witnessBounds: Readonly<Record<string, unknown>>;
        readonly proofFamilies: readonly Readonly<Record<string, unknown>>[];
        readonly proofSerialization: Readonly<Record<string, unknown>>;
        readonly verificationPolicy: Readonly<Record<string, unknown>>;
    };
    readonly setupTransport: {
        readonly objectType: 'SetupTransport';
        readonly largeObjectEncoding: 'binary';
        readonly chunking: 'required';
        readonly chunkSizeBytes: number;
        readonly storageQuotaBytes: number;
        readonly largestSingleBufferBytes: number;
        readonly copyCountLimit: number;
        readonly streamVerificationOrder: string;
        readonly resumePolicy: string;
        readonly lazyLoadingPolicy: string;
        readonly requiredTransportedObjects: readonly Readonly<
            Record<string, unknown>
        >[];
    };
    readonly evaluatorKeySchedule: {
        readonly objectType: 'EvaluatorKeySchedule';
        readonly evaluatorScheme: 'direct-encrypted-ballot-evaluator-replay';
        readonly packingScheme: 'direct-score-packing-compact-generator-basis-direct-encrypted-score-comparison-generator-ordered-rank-packing';
        readonly participantCount: 10;
        readonly rnsLimbCount: number;
        readonly relinearizationLevelSchedule: readonly {
            readonly level: number;
            readonly proofFamily: 'relinearization-key-share';
            readonly keyShareRounds: readonly ['round-one', 'round-two'];
        }[];
        readonly requiredGaloisKeySchedule: readonly {
            readonly rotation: number;
            readonly level: number;
            readonly purpose: string;
            readonly proofFamily: 'galois-key-share';
        }[];
        readonly requiredGaloisSetHash: ProtocolHash;
    };
    readonly phaseOrder: readonly {
        readonly phaseId: string;
        readonly phaseNumber: number;
    }[];
    readonly phaseOrderHash: ProtocolHash;
    readonly requiredFinalObjects: readonly string[];
    readonly transportSchemeId: string;
};

export type BgvCollectiveSetupPublicDerivations = {
    readonly objectType: 'SetupPublicDerivations';
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly bgvPublicA: {
        readonly objectType: 'BgvPublicAPolynomial';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly derivationLabel: 'accepted-bgv-public-a';
        readonly basisId: string;
        readonly level: number;
        readonly coefficientCount: number;
        readonly modulusDerivations: readonly {
            readonly modulus: number;
            readonly coefficientDerivationHash: string;
        }[];
        readonly sampledResidues: readonly {
            readonly position: number;
            readonly modulus: number;
            readonly value: number;
        }[];
        readonly publicPolynomialRoot: ProtocolHash;
    };
    readonly publicMatrices: {
        readonly objectType: 'SetupPublicMatrixMaterial';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly commitmentMatrix: BgvCollectiveSetupPublicMatrix;
        readonly publicMatricesRoot: ProtocolHash;
    };
    readonly crpRoots: {
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly commitmentMatrixCrpRoot: ProtocolHash;
    };
    readonly publicDerivationRoot: ProtocolHash;
};

export type BgvCollectiveSetupPublicMatrix = {
    readonly objectType: 'SetupPublicMatrix';
    readonly matrixKind: 'commitment' | 'setupProof';
    readonly challengeDomainHash?: ProtocolHash;
    readonly challengeBits?: number;
    readonly challengeCount?: number;
    readonly commitmentModulusLimbs?: readonly {
        readonly commitmentModulusIndex: number;
        readonly modulus: number;
    }[];
    readonly commitmentModuleRank?: number;
    readonly commitmentRandomnessWidth?: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly crpRoot: ProtocolHash;
    readonly coordinateAxes: readonly string[];
    readonly rnsLimbCount: number;
    readonly ringDegree: number;
    readonly shamirCoefficientCount?: number;
    readonly proofFamilies?: readonly string[];
    readonly entryStreamEncoding:
        | 'xof-entry-derivation-hash'
        | 'xof-unbiased-residue-from-coordinate';
    readonly sampledEntries: readonly {
        readonly coordinate: Readonly<Record<string, string | number>>;
        readonly coefficientValue?: number;
        readonly entryDerivationHash: ProtocolHash;
    }[];
    readonly matrixRoot: ProtocolHash;
};

export type BgvAcceptedSetupHandoff = {
    readonly objectType: 'CollectiveBgvAcceptedSetupHandoff';
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly setupPackageHash: ProtocolHash;
    readonly directBallotEncryptionHandoff: {
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
    };
    readonly publicAggregationHandoff: {
        readonly thresholdShareCommitmentRoot: ProtocolHash;
    };
    readonly boundedEvaluatorReplayHandoff: {
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
        readonly trusteeEvaluationKeyProofSetRoot: ProtocolHash;
        readonly evaluationKeySetHash: ProtocolHash;
        readonly publicEvaluationKeyMaterialRoot?: ProtocolHash;
    };
    readonly certificateRoots: {
        readonly setupTransportCertificateHash: ProtocolHash;
    };
    readonly acceptedSetupHandoffRoot: ProtocolHash;
};

export type BgvCollectiveSetupVerification = {
    readonly isValid: boolean;
    readonly operation: 'verifyCollectiveBgvSetupPackage';
    readonly currentPhase: string | null;
    readonly phaseOrderHash: ProtocolHash;
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly acceptedSetupHandoff?: BgvAcceptedSetupHandoff;
    readonly missingObjects: readonly string[];
    readonly refusedObjects: readonly {
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
    }[];
};

export type BgvPrivateVssShareEnvelopeVerification = {
    readonly isValid: boolean;
    readonly operation: 'verifyPrivateVssShareEnvelope';
    readonly privateEnvelopeHash: ProtocolHash | null;
    readonly localVerificationRoot: ProtocolHash | null;
    readonly ringDegree?: number;
    readonly ringDegreeStatus?: 'full-ring' | 'development-reduced-ring';
    readonly verifiedRnsLimbCount?: number;
    readonly verifiedShamirCoefficientCommitmentCount?: number;
    readonly verifiedPrivateVssShareProofCount?: number;
    readonly limbVerifications: readonly {
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly shareValuesHash: ProtocolHash;
        readonly privateVssShareProofHash: ProtocolHash;
        readonly proofStatementRoot: ProtocolHash;
        readonly limbVerificationRoot: ProtocolHash;
    }[];
    readonly refusedObjects: readonly {
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
    }[];
};

export type BgvPrivateVssShareProofGeneration = {
    readonly operation: 'generatePrivateVssShareProof';
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly shareValuesHash: ProtocolHash;
    readonly privateVssShareProof: Record<string, unknown>;
};

// One key share inside a trustee evaluation-key proof statement. The
// component material is supplied either as embedded coefficient matrices or
// as canonical binary component-material bytes; round-two keys also carry the
// recomputed public round-one aggregate diagonals.
export type BgvTrusteeEvaluationKeyStatementKey = {
    readonly proofFamily:
        | 'relinearization-round-one'
        | 'relinearization-round-two'
        | 'galois-rotation'
        | 'public-key-share';
    readonly rotation?: number;
    readonly level: number;
    readonly keySwitchDomain: string;
    readonly keySwitchSeedHex: string;
    readonly componentBByDigit?: readonly (readonly (readonly number[])[])[];
    readonly componentMaterialBytesHex?: string;
    readonly roundOneAggregateDiagonal?: readonly (readonly number[])[];
};

// The kernel derives the proof family from the key list: a populated key
// list is the trustee evaluation-key family and binds the schedule roots; an
// empty key list is the keyless same-secret linkage anchor family and binds
// the accepted public VSS material root.
// These branches share fields and carry no discriminant, so which root set is mandatory is enforced by the kernel from the key list, not by the type.
export type BgvTrusteeEvaluationKeyStatementContext = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
} & (
    | {
          readonly requiredGaloisSetHash: ProtocolHash;
          readonly evaluatorKeyScheduleRoot: ProtocolHash;
          readonly keySwitchDecompositionHash: ProtocolHash;
          readonly sameSecretStatementRoot: ProtocolHash;
          readonly sameSecretProofRoot: ProtocolHash;
      }
    | {
          readonly sameSecretStatementRoot: ProtocolHash;
          readonly sameSecretProofRoot: ProtocolHash;
      }
    | {
          readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
      }
);

export type BgvTrusteeEvaluationKeySameSecretLinkage = {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly commitments: readonly unknown[];
};

export type BgvTrusteeEvaluationKeySameSecretBridge = {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly targetRnsPrimes: readonly number[];
    readonly targetConstantCommitmentRoots: readonly ProtocolHash[];
    readonly targetConstantCommitments: readonly unknown[];
};

export type BgvVssShareLinkageProofContext = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
    readonly shareLinkageStatementRoot: ProtocolHash;
};

export type BgvSameSecretBridgeProofContext = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
    readonly sameSecretBridgeStatementRoot: ProtocolHash;
    readonly sameSecretStatementRoot: ProtocolHash;
    readonly sameSecretProofRoot: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
};

export type BgvTrusteeEvaluationKeyProofGeneration = {
    readonly operation: 'generateTrusteeEvaluationKeyProof';
    readonly proofFamily:
        | 'trustee-evaluation-key'
        | 'same-secret-linkage-anchor'
        | 'public-key-share';
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly proofByteLength: number;
    readonly proofBytesHex: string;
};

export type BgvSetupCommitmentOpeningComputation = {
    readonly operation: 'computeSetupCommitmentFromOpening';
    readonly commitment: Record<string, unknown>;
    readonly commitmentRoot: ProtocolHash;
};

export type BgvVssPublicCommitmentOpeningComputation = {
    readonly operation: 'computeVssPublicCommitmentFromOpening';
    readonly commitment: Record<string, unknown>;
    readonly commitmentRoot: ProtocolHash;
    readonly openingRoot: ProtocolHash;
    readonly commitmentContextHash: ProtocolHash;
    readonly encodedCommitmentByteLength: number;
};

export type BgvVssShareLinkageProofGeneration = {
    readonly operation: 'generateVssShareLinkageProof';
    readonly proofFamily: 'vss-share-linkage';
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly coefficientCommitmentCount: number;
    readonly coefficientWitnessColumnCount: number;
    readonly proofByteLength: number;
    readonly proofBytesHex: string;
};

export type BgvSameSecretBridgeProofGeneration = {
    readonly operation: 'generateSameSecretBridgeProof';
    readonly proofFamily: 'same-secret-bridge';
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly targetRnsLimbCount: number;
    readonly proofByteLength: number;
    readonly proofBytesHex: string;
};

export type BgvSetupProofMaterialTransportStreamBegin = {
    readonly operation: 'beginSetupProofMaterialTransportStream';
    readonly verificationId: string;
    readonly proofFamily: string;
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofBytesEncoding: string;
    readonly transport: Readonly<Record<string, unknown>>;
};

export type BgvSetupProofMaterialTransportStreamChunkAbsorption = {
    readonly operation: 'absorbSetupProofMaterialTransportStreamChunk';
    readonly absorbedChunkIndex: number;
    readonly nextChunkIndex: number;
    readonly observedTotalByteLength: number;
};

export type BgvSetupProofMaterialTransportStreamVerification = {
    readonly operation: 'finishSetupProofMaterialTransportStream';
    readonly verificationId: string;
    readonly proofFamily: string;
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofBytesEncoding: string;
    readonly transport: Readonly<Record<string, unknown>>;
    readonly verifiedSetupProofMaterial: BgvVerifiedSetupProofMaterial;
};

export type BgvVerifiedEvaluationKeyShareComponentMaterial = Readonly<
    BgvJsonRecord & {
        readonly objectType: 'VerifiedEvaluationKeyShareComponentMaterial';
        readonly verificationId: string;
        readonly proofFamily: string;
        readonly keySwitchComponentMaterialRoot: ProtocolHash;
        readonly keySwitchMaterialEncoding: string;
        readonly chunkSizeBytes: number;
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly fullObjectHash: ProtocolHash;
        readonly chunkRoot: ProtocolHash;
        readonly chunkHashes: readonly ProtocolHash[];
    }
>;

export type BgvEvaluationKeyShareComponentMaterialTransportStreamBegin = {
    readonly operation: 'beginEvaluationKeyShareComponentMaterialTransportStream';
    readonly verificationId: string;
    readonly proofFamily: string;
    readonly keySwitchComponentMaterialRoot: ProtocolHash;
    readonly keySwitchMaterialEncoding: string;
    readonly transport: Readonly<Record<string, unknown>>;
};

export type BgvEvaluationKeyShareComponentMaterialTransportStreamChunkAbsorption =
    {
        readonly operation: 'absorbEvaluationKeyShareComponentMaterialTransportStreamChunk';
        readonly absorbedChunkIndex: number;
        readonly nextChunkIndex: number;
        readonly observedTotalByteLength: number;
    };

export type BgvEvaluationKeyShareComponentMaterialTransportStreamVerification =
    {
        readonly operation: 'finishEvaluationKeyShareComponentMaterialTransportStream';
        readonly verificationId: string;
        readonly proofFamily: string;
        readonly keySwitchComponentMaterialRoot: ProtocolHash;
        readonly keySwitchMaterialEncoding: string;
        readonly verifiedEvaluationKeyShareComponentMaterial: BgvVerifiedEvaluationKeyShareComponentMaterial;
    };

export type BgvLocalTrusteeSetupStateVerification = {
    readonly operation: 'verifyLocalTrusteeSetupState';
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly trusteePoint: number;
    readonly localStateRoot: ProtocolHash;
    readonly deletionReceiptRoot: ProtocolHash;
    readonly deletionBoundary: 'after-private-vss-aggregation';
};

// Opaque release setup context record derived from the accepted setup package.
// It is round-tripped byte-for-byte as the begin command's releaseSetupContext
// input; only objectType and releaseSetupContextHash are consumed on the
// TypeScript side, the remaining context fields are recomputed by the kernel.
export type BgvTargetDecryptionReleaseSetupContext = Readonly<
    BgvJsonRecord & {
        readonly objectType: 'BgvTargetDecryptionReleaseSetupContext';
        readonly releaseSetupContextHash: ProtocolHash;
    }
>;

export type BgvTargetDecryptionResultReleaseBegin = {
    readonly operation: 'beginBgvTargetDecryptionResultRelease';
    readonly releaseVerificationId: string;
};

export type BgvTargetDecryptionResultReleaseShareAbsorption = {
    readonly operation: 'absorbBgvTargetDecryptionResultReleaseShare';
    readonly absorbedShareCount: number;
    readonly requiredShareCount: number;
    readonly rosterPosition: number;
    readonly targetDecryptionShareHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
};

export type BgvTargetDecryptionResultReleaseShareEvidence = {
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly interpolationPoint: number;
    readonly targetDecryptionShareHash: ProtocolHash;
    readonly proofStatementRoot: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
};

export type BgvTargetDecryptionResultReleaseCompletion = {
    readonly operation: 'finishBgvTargetDecryptionResultRelease';
    readonly targetResultHash: ProtocolHash;
    readonly targetIdByOption: readonly number[];
    readonly targetOrderByOption: readonly number[];
    readonly topCount: number;
    readonly shareEvidence: readonly BgvTargetDecryptionResultReleaseShareEvidence[];
};
