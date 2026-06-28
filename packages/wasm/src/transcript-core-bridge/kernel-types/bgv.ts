import type { ProtocolHash } from '@sealed-lattice/types';

type BgvJsonRecord = Readonly<Record<string, unknown>>;

type BgvTransportedMaterialObject<ObjectType extends string> = Readonly<
    BgvJsonRecord & {
        readonly objectType: ObjectType;
        readonly objectVersion: 1;
    }
>;

export type BgvSetupTransportChunk = Readonly<
    BgvJsonRecord & {
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }
>;

export type BgvTransportedVssCoefficientCommitmentMaterial =
    BgvTransportedMaterialObject<'SetupTransportedVssCoefficientCommitmentMaterial'> &
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

export type BgvTransportedVssCoefficientCommitmentMaterialReference = Omit<
    BgvTransportedVssCoefficientCommitmentMaterial,
    'chunks'
>;

export type BgvTransportedVssCoefficientCommitmentMaterialTemplate = Omit<
    BgvTransportedVssCoefficientCommitmentMaterialReference,
    'fullObjectHash' | 'chunkHashes' | 'chunkRoot'
>;

export type BgvVerifiedVssCoefficientCommitmentMaterial = Readonly<
    BgvJsonRecord & {
        readonly objectType: 'VerifiedVssCoefficientCommitmentMaterial';
        readonly objectVersion: 1;
        readonly verificationId: string;
        readonly materialBinaryFormat: string;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
        readonly thresholdShareCommitmentRoot: ProtocolHash;
        readonly transportSchemeId: string;
        readonly transportChunkSizeBytes: number;
        readonly transportChunkCount: number;
        readonly transportTotalByteLength: number;
        readonly transportFullObjectHash: ProtocolHash;
        readonly transportChunkRoot: ProtocolHash;
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
        readonly objectVersion: 1;
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
        readonly objectVersion: 1;
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
    readonly transportedVssCoefficientCommitmentMaterial?:
        | BgvTransportedVssCoefficientCommitmentMaterial
        | BgvTransportedVssCoefficientCommitmentMaterialReference;
    readonly verifiedVssCoefficientCommitmentMaterial?: BgvVerifiedVssCoefficientCommitmentMaterial;
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
        readonly scalarOnlyAggregateLayout: boolean;
        readonly allowedOperations: readonly string[];
        readonly forbiddenOperations: readonly string[];
    };
    readonly bgvParametersHash: ProtocolHash;
    readonly batchLayoutBinding: {
        readonly scoreRange: {
            readonly minimum: number;
            readonly maximum: number;
        };
        readonly bucketCount: number;
        readonly slotCount: number;
        readonly coordinatesPerOption: number;
        readonly scalarOnlyAggregateLayout: boolean;
    };
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
    readonly canonicalBytesHash512: string;
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
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
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
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly componentCount: number;
    readonly validation: BgvObjectValidation;
    readonly canonicalBytesHex?: string;
};

export type BgvBaseConversionFixture = {
    readonly sourcePlaintextRoot: ProtocolHash;
    readonly convertedPlaintextRoot: ProtocolHash;
    readonly sourceCanonicalBytesHash512: string;
    readonly convertedCanonicalBytesHash512: string;
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
    readonly objectVersion: 1;
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
    readonly targetDecryptionStatus: {
        readonly targetDecryptionParametersHash: ProtocolHash;
        readonly targetDecryptionParametersBindingHash: ProtocolHash;
    };
};

export type BgvPassiveSetupVerification = {
    readonly isValid: boolean;
    readonly operation: 'verifyBgvPassiveSetupPackage';
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly refusedObjects: readonly unknown[];
    readonly unresolvedReason: string | null;
};

export type BgvCollectiveSetupParametersDescription = {
    readonly setupParametersHash: ProtocolHash;
    readonly objectType: 'SetupPackage';
    readonly adversaryModel: 'active-static';
    readonly livenessModel: 'secure-with-abort';
    readonly sharingModel: 'recipient-verified-vss';
    readonly sharingDomain: 'per-rns-prime';
    readonly completionRule: 'full-roster';
    readonly participantCount: 10;
    readonly qSetupComplete: 10;
    readonly qBallotRelease: 10;
    readonly qFinal: 10;
    readonly qDec: 4;
    readonly qShare: {
        readonly objectType: 'QSharePrimeList';
        readonly objectVersion: 1;
        readonly primes: readonly number[];
    };
    readonly carryAwareVssShareRelation: {
        readonly objectType: 'CarryAwareVssShareRelation';
        readonly objectVersion: 1;
        readonly trusteePointRule: 'roster-position-plus-one';
        readonly coefficientOrder: 'constant-first';
        readonly relation: string;
        readonly carryWitnessDomain: 'non-negative-bounded-integer';
        readonly commitmentReductionRule: 'open-unreduced-lifted-share-with-explicit-carry';
    };
    readonly commitment: {
        readonly objectType: 'BdlopCommitment';
        readonly objectVersion: 1;
        readonly construction: string;
        readonly ring: Readonly<Record<string, unknown>>;
        readonly matrixShape: Readonly<Record<string, unknown>>;
        readonly messageEncoding: Readonly<Record<string, unknown>>;
        readonly openingDistribution: Readonly<Record<string, unknown>>;
        readonly homomorphism: Readonly<Record<string, unknown>>;
        readonly assumptions: Readonly<Record<string, unknown>>;
        readonly serialization: Readonly<Record<string, unknown>>;
    };
    readonly publicVssCommitmentMaterialSize: {
        readonly objectType: 'PublicVssCommitmentMaterialSize';
        readonly objectVersion: 1;
        readonly measurementKind: string;
        readonly ringDegree: number;
        readonly ringDegreeStatus: 'full-ring';
        readonly participantCount: 10;
        readonly rnsLimbCount: number;
        readonly shamirCoefficientCount: 4;
        readonly commitmentModulusLimbCount: number;
        readonly commitmentRowCount: number;
        readonly bytesPerResidue: 8;
        readonly singleCommitmentCoefficientBytes: number;
        readonly publishedCommitmentCount: number;
        readonly fullMaterialCoefficientBytes: number;
        readonly fullMaterialCoefficientMebibytes: number;
        readonly jsonOverheadStatus: string;
        readonly streamingRequirement: string;
    };
    readonly setupProof: {
        readonly objectType: 'SetupProof';
        readonly objectVersion: 1;
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
        readonly objectVersion: 1;
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
        readonly objectVersion: 1;
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
        readonly genericKeySwitchPolicy: 'refused-unless-explicitly-required';
    };
    readonly phaseOrder: readonly {
        readonly phaseId: string;
        readonly phaseNumber: number;
    }[];
    readonly phaseOrderHash: ProtocolHash;
    readonly requiredFinalObjects: readonly string[];
    readonly genericKeySwitchPolicy: string;
    readonly transportSchemeId: string;
};

export type BgvCollectiveSetupPublicDerivations = {
    readonly objectType: 'SetupPublicDerivations';
    readonly objectVersion: 1;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly bgvPublicA: {
        readonly objectType: 'BgvPublicAPolynomial';
        readonly objectVersion: 1;
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
        readonly objectVersion: 1;
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
    readonly objectVersion: 1;
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
    readonly objectVersion: 1;
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
    readonly isValid: true;
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
    readonly proofRandomness: {
        readonly source: 'fresh-csprng' | 'development-deterministic-fixture';
        readonly binding?: string;
        readonly nonceHash?: ProtocolHash;
        readonly seedBytes: 64;
        readonly retention: string;
    };
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

export type BgvTrusteeEvaluationKeyProofGeneration = {
    readonly isValid: true;
    readonly operation: 'generateTrusteeEvaluationKeyProof';
    readonly proofFamily:
        | 'trustee-evaluation-key'
        | 'same-secret-linkage-anchor'
        | 'public-key-share';
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly keyCount: number;
    readonly sameSecretLinkageIncluded: boolean;
    readonly proofByteLength: number;
    readonly proofBytesHex: string;
    readonly proofRandomness: {
        readonly source: string;
        readonly binding?: string;
        readonly nonceHash?: ProtocolHash;
        readonly retention: string;
    };
};

export type BgvTrusteeEvaluationKeyProofVerification = {
    readonly isValid: true;
    readonly operation: 'verifyTrusteeEvaluationKeyProof';
    readonly proofFamily:
        | 'trustee-evaluation-key'
        | 'same-secret-linkage-anchor'
        | 'public-key-share';
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly keyCount: number;
    readonly sameSecretLinkageIncluded: boolean;
    readonly proofByteLength: number;
};

export type BgvThresholdShareCommitmentDerivation = {
    readonly isValid: true;
    readonly operation: 'deriveThresholdShareCommitments';
    readonly ringDegree: number;
    readonly ringDegreeStatus: 'full-ring' | 'development-reduced-ring';
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly derivedLimbCommitmentCount: number;
    readonly thresholdShareCommitmentRoot: ProtocolHash;
    readonly thresholdShareCommitments: Readonly<Record<string, unknown>>;
};

export type BgvSetupCommitmentOpeningComputation = {
    readonly isValid: true;
    readonly operation: 'computeSetupCommitmentFromOpening';
    readonly commitment: Record<string, unknown>;
    readonly commitmentRoot: ProtocolHash;
    readonly commitmentChunkRoot: ProtocolHash;
    readonly coefficientVectorHash512: string;
};

export type BgvThresholdShareCommitmentTransportDerivation = Omit<
    BgvThresholdShareCommitmentDerivation,
    'operation'
> & {
    readonly operation: 'deriveThresholdShareCommitmentsFromTransport';
    readonly materialBinaryFormat: string;
    readonly transport: Readonly<Record<string, unknown>>;
    readonly vssCoefficientCommitmentMaterial: Readonly<
        Record<string, unknown>
    >;
};

export type BgvThresholdShareCommitmentTransportStreamBegin = {
    readonly isValid: true;
    readonly operation: 'beginThresholdShareCommitmentsFromTransportStream';
    readonly derivationId: string;
    readonly materialBinaryFormat: string;
    readonly transport: Readonly<Record<string, unknown>>;
};

export type BgvThresholdShareCommitmentTransportStreamAbort = {
    readonly isValid: true;
    readonly operation: 'abortThresholdShareCommitmentsFromTransportStream';
    readonly derivationId: string;
    readonly aborted: boolean;
};

export type BgvThresholdShareCommitmentTransportStreamChunkAbsorption = {
    readonly isValid: true;
    readonly operation: 'absorbThresholdShareCommitmentsFromTransportStreamChunk';
    readonly absorbedChunkIndex: number;
    readonly absorbedByteLength: number;
    readonly nextChunkIndex: number;
    readonly observedTotalByteLength: number;
};

export type BgvThresholdShareCommitmentTransportStreamDerivation = Omit<
    BgvThresholdShareCommitmentTransportDerivation,
    'operation'
> & {
    readonly operation: 'finishThresholdShareCommitmentsFromTransportStream';
    readonly derivationId: string;
    readonly verifiedVssCoefficientCommitmentMaterial: BgvVerifiedVssCoefficientCommitmentMaterial;
};

export type BgvSetupProofMaterialTransportStreamBegin = {
    readonly isValid: true;
    readonly operation: 'beginSetupProofMaterialTransportStream';
    readonly verificationId: string;
    readonly proofFamily: string;
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofBytesEncoding: string;
    readonly transport: Readonly<Record<string, unknown>>;
};

export type BgvSetupProofMaterialTransportStreamChunkAbsorption = {
    readonly isValid: true;
    readonly operation: 'absorbSetupProofMaterialTransportStreamChunk';
    readonly absorbedChunkIndex: number;
    readonly nextChunkIndex: number;
    readonly observedTotalByteLength: number;
};

export type BgvSetupProofMaterialTransportStreamVerification = {
    readonly isValid: true;
    readonly operation: 'finishSetupProofMaterialTransportStream';
    readonly verificationId: string;
    readonly proofFamily: string;
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofBytesEncoding: string;
    readonly transport: Readonly<Record<string, unknown>>;
    readonly verifiedSetupProofMaterial: BgvVerifiedSetupProofMaterial;
};

export type BgvVerifiedTransportedVssMaterialRelease = {
    readonly isValid: true;
    readonly operation: 'releaseVerifiedTransportedVssMaterial';
    readonly verificationId: string;
    readonly released: boolean;
};

export type BgvLocalTrusteeSetupStateVerification = {
    readonly isValid: true;
    readonly operation: 'verifyLocalTrusteeSetupState';
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly trusteePoint: number;
    readonly localStateRoot: ProtocolHash;
    readonly deletionReceiptRoot: ProtocolHash;
    readonly exportPolicy: 'roots-only-no-raw-share-or-opening-export';
    readonly storageRequirement: 'encrypted-local-device-state-required';
    readonly deletionBoundary: 'after-private-vss-aggregation';
};

export type BgvTargetCiphertextPairInput = {
    readonly targetIdCanonicalBytesHex: string;
    readonly targetOrderCanonicalBytesHex: string;
};

export type BgvTargetDecryptionShare = Readonly<
    Record<string, unknown> & {
        readonly objectType: 'BgvTargetDecryptionShare';
        readonly objectVersion: 1;
        readonly targetDecryptionShareHash: ProtocolHash;
        readonly trusteeIdentity: string;
        readonly rosterPosition: number;
        readonly interpolationPoint: number;
        readonly targetAcceptedRecordHash: ProtocolHash;
        readonly targetContextHash: ProtocolHash;
        readonly targetCiphertextHash: ProtocolHash;
        readonly targetDecryptionCiphertextHash: ProtocolHash;
        readonly targetShareParametersHash: ProtocolHash;
        readonly shareRoot: ProtocolHash;
        readonly sharePayload: unknown;
    }
>;

export type BgvTargetDecryptionResult = {
    readonly isValid: true;
    readonly operation: 'recombineBgvTargetDecryptionShares';
    readonly targetDecryptionResultHash: ProtocolHash;
    readonly setupPackageHash: ProtocolHash;
    readonly targetAcceptedRecordHash: ProtocolHash;
    readonly targetContextHash: ProtocolHash;
    readonly targetCiphertextHash: ProtocolHash;
    readonly targetShareParametersHash: ProtocolHash;
    readonly targetDecryptionParametersHash: ProtocolHash;
    readonly minimumSharesForInterpolation: number;
    readonly decryptionThreshold: number;
    readonly decryptionShareQuorum: number;
    readonly selectedRosterPositions: readonly number[];
    readonly decodedTargetIds: readonly number[];
    readonly decodedTargetOrders: readonly number[];
    readonly decryptScaling: number;
};
