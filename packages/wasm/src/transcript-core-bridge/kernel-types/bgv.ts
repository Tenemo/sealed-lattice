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
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly verificationId: string;
        readonly materialBinaryFormat: string;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
        readonly thresholdShareCommitmentRoot: ProtocolHash;
        readonly transportProfileId: string;
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
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: string;
        readonly proofFamily: string;
        readonly proofMaterials: readonly BgvJsonRecord[];
    }>;

export type BgvVerifiedSetupProofMaterial = Readonly<
    BgvJsonRecord & {
        readonly objectType: 'VerifiedSetupProofMaterial';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: string;
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
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: string;
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
            readonly setupProfileId: 'CollectiveBgvSetup-v1';
            readonly setupProofProfileId: string;
            readonly componentMaterials: readonly BgvJsonRecord[];
        }>;

export type BgvTransportedPublicEvaluationKeyMaterialSet =
    BgvTransportedMaterialObject<'SetupTransportedPublicEvaluationKeyMaterialSet'> &
        Readonly<{
            readonly setupProfileId: 'CollectiveBgvSetup-v1';
            readonly setupProofProfileId: string;
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

export type BgvRnsProfileDescription = {
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
    readonly profileHash: ProtocolHash;
    readonly backendProfileHash: ProtocolHash;
    readonly batchEncoderHash: ProtocolHash;
    readonly encryptedBallotAggregateLayoutHash: ProtocolHash;
    readonly batchLayoutBinding: unknown;
    readonly batchLayoutBindingHash: ProtocolHash;
    readonly ballotScoreEncodingProfileHash: ProtocolHash;
    readonly encryptedBallotLayoutHash: ProtocolHash;
    readonly encryptedBallotAggregateProfileHash: ProtocolHash;
    readonly directAggregateLayoutHash: ProtocolHash;
    readonly directComparisonProfileHash: ProtocolHash;
    readonly canonicalCiphertextConventionHash: ProtocolHash;
    readonly allowedEvaluatorOpsHash: ProtocolHash;
    readonly securityEstimatorInputHash: string;
};

export type BgvObjectValidation = {
    readonly ok: boolean;
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly profileHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly layoutHash: ProtocolHash;
    readonly plaintextRoot?: ProtocolHash;
    readonly ciphertextRoot?: ProtocolHash;
    readonly canonicalBytesHash512: string;
};

export type BgvCanonicalObjectAnalysis = {
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly profileHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly layoutHash: ProtocolHash;
};

export type BgvProfileRejection = {
    readonly ok: false;
    readonly operation: string;
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly refusedObjects: readonly {
        readonly code: 'BGVProfileRejected';
        readonly reasonCode: string;
        readonly message: string;
        readonly objectHash?: ProtocolHash;
    }[];
    readonly unresolvedReason: 'BGVProfileRejected';
};

export type BgvEvaluatorOperationValidation =
    | {
          readonly ok: true;
          readonly operation: 'validateBgvEvaluatorOperation';
          readonly acceptedOperation: string;
          readonly allowedEvaluatorOpsHash: ProtocolHash;
      }
    | BgvProfileRejection;

export type BgvBatchPlaintextEncoding = {
    readonly profileHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly suppliedSlotCount: number;
    readonly slotCount: number;
    readonly plaintextRoot: ProtocolHash;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly batchLayoutBindingHash: ProtocolHash;
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
    readonly profileHash: ProtocolHash;
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
    readonly setupProfileId: string;
    readonly setupMode: string;
    readonly setupPackageHash: ProtocolHash;
    readonly setupInputs: {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly thresholdProfileHash: ProtocolHash;
        readonly participantCount: number;
        readonly participantIdentities: readonly string[];
        readonly setupSeedHash: string;
    };
    readonly profileBindings: Readonly<Record<string, unknown>>;
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
    readonly developmentEncryptionFixture: Readonly<Record<string, unknown>>;
    readonly certificates: Readonly<Record<string, unknown>>;
    readonly targetDecryptionProfileBinding: {
        readonly targetDecryptionProfileId: string;
        readonly targetDecryptionProfileHash: ProtocolHash;
        readonly targetDecryptionProfileBindingHash: ProtocolHash;
    };
};

export type BgvPassiveSetupVerification = {
    readonly ok: boolean;
    readonly operation: 'verifyBgvPassiveSetupPackage';
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly refusedObjects: readonly unknown[];
    readonly unresolvedReason: string | null;
};

export type BgvCollectiveSetupProfileDescription = {
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly setupProfileHash: ProtocolHash;
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
        readonly sharingDomain: 'per-rns-prime';
        readonly primeOrder: 'profile-order';
        readonly primes: readonly number[];
    };
    readonly qShareHash: ProtocolHash;
    readonly carryAwareVssShareRelationProfile: {
        readonly objectType: 'CarryAwareVssShareRelationProfile';
        readonly objectVersion: 1;
        readonly profileId: 'sealed-lattice-carry-aware-vss-share-opening-v1';
        readonly sharingDomain: 'per-rns-prime';
        readonly trusteePointRule: 'roster-position-plus-one';
        readonly coefficientOrder: 'constant-first';
        readonly relation: string;
        readonly carryWitnessDomain: 'non-negative-bounded-integer';
        readonly commitmentReductionRule: 'open-unreduced-lifted-share-with-explicit-carry';
    };
    readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
    readonly commitmentProfile: {
        readonly objectType: 'BdlopCommitmentProfile';
        readonly objectVersion: 1;
        readonly profileId: 'SealedLattice-BDLOP-Commitment-v1';
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly construction: string;
        readonly ring: Readonly<Record<string, unknown>>;
        readonly matrixShape: Readonly<Record<string, unknown>>;
        readonly messageEncoding: Readonly<Record<string, unknown>>;
        readonly openingDistribution: Readonly<Record<string, unknown>>;
        readonly homomorphism: Readonly<Record<string, unknown>>;
        readonly assumptions: Readonly<Record<string, unknown>>;
        readonly serialization: Readonly<Record<string, unknown>>;
    };
    readonly commitmentProfileHash: ProtocolHash;
    readonly canonicalTargetBasis: {
        readonly objectType: 'CanonicalTargetBasis';
        readonly objectVersion: 1;
        readonly basisId: string;
        readonly targetLevel: number;
        readonly primeOrder: 'profile-order-prefix';
        readonly targetPrimes: readonly number[];
        readonly modulusSwitchSchedule: Readonly<
            Record<string, string | number>
        >;
        readonly scalingNormalization: string;
        readonly targetCiphertextRule: string;
    };
    readonly canonicalTargetBasisHash: ProtocolHash;
    readonly compactVssMatrixExpansionProfile: {
        readonly objectType: 'CompactVssMatrixExpansionProfile';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: string;
        readonly matrixKind: 'compact-vss-commitment-key';
        readonly ringDegree: number;
        readonly commitmentModulusLimbIndices: readonly number[];
        readonly outputCoordinateCount: number;
        readonly messageCoverageTermsPerCoordinate: number;
        readonly randomnessProjectionWeight: number;
        readonly randomnessColumnCount: number;
        readonly inputColumnLabels: readonly string[];
        readonly matrixResidueHashDomain: string;
        readonly projectionIndexHashDomain: string;
        readonly rejectionSamplingRule: string;
        readonly matrixResiduePreimageFields: readonly string[];
        readonly projectionIndexPreimageFields: readonly string[];
        readonly coordinateCountPerCommitment: number;
        readonly messageMatrixResiduesPerCommitment: number;
        readonly randomnessMatrixResiduesPerCoordinate: number;
        readonly randomnessMatrixResiduesPerCommitment: number;
        readonly sampledMatrixResiduesPerCoordinate: number;
        readonly sampledRandomnessProjectionIndicesPerCoordinate: number;
        readonly sampledMatrixResiduesPerCommitment: number;
        readonly sampledRandomnessProjectionIndicesPerCommitment: number;
        readonly residueMultiplyAddsPerCommitment: number;
    };
    readonly compactVssMatrixExpansionProfileHash: ProtocolHash;
    readonly compactVssParameterCertificateInputBinding: {
        readonly objectType: 'CompactVssParameterCertificateInputBinding';
        readonly objectVersion: 8;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: string;
        readonly compactVssParameterCertificateInputBindingHash: ProtocolHash;
        readonly participantCount: number;
        readonly sourceRnsLimbCount: number;
        readonly targetRnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly ringDegree: number;
        readonly commitmentRelation: Readonly<Record<string, unknown>>;
        readonly commonCommitmentKey: Readonly<Record<string, unknown>>;
        readonly compactMaterialArtifactBoundary: Readonly<
            Record<string, unknown>
        >;
        readonly messageEncoding: Readonly<Record<string, unknown>>;
        readonly normInputClasses: readonly Readonly<Record<string, unknown>>[];
        readonly parameterReviewInputs: Readonly<Record<string, unknown>>;
        readonly estimatorInputRows: readonly Readonly<
            Record<string, unknown>
        >[];
        readonly sameSecretBridgeInput: Readonly<Record<string, unknown>>;
    };
    readonly compactVssParameterCertificateInputBindingHash: ProtocolHash;
    readonly currentVssMaterialBaselineReport: {
        readonly objectType: 'CurrentVssMaterialBaselineReport';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly participantCount: 10;
        readonly rnsLimbCount: number;
        readonly shamirCoefficientCount: 4;
        readonly ringDegree: number;
        readonly commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1';
        readonly commitmentModulusLimbCount: number;
        readonly commitmentRowCount: number;
        readonly bytesPerResidue: 8;
        readonly materialRecordCount: number;
        readonly singleCommitmentCoefficientBytes: number;
        readonly fullMaterialCoefficientBytes: number;
        readonly exactBinaryTransportBytes: number;
        readonly binaryTransportMetadataBytes: number;
        readonly publicVerificationMemoryEstimate: Readonly<
            Record<string, number | string>
        >;
        readonly trusteePointScalarBounds: Readonly<
            Record<string, number | string>
        >;
        readonly normModel: Readonly<Record<string, unknown>>;
    };
    readonly publicVssCommitmentMaterialSizeProfile: {
        readonly objectType: 'PublicVssCommitmentMaterialSizeProfile';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly ringDegree: number;
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
    };
    readonly publicVssCommitmentMaterialSizeProfileHash: ProtocolHash;
    readonly setupProofProfile: {
        readonly objectType: 'SetupProofProfile';
        readonly objectVersion: 1;
        readonly profileId: 'SealedLattice-SetupProof-v1';
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly relationModel: Readonly<Record<string, unknown>>;
        readonly witnessBounds: Readonly<Record<string, unknown>>;
        readonly proofFamilies: readonly Readonly<Record<string, unknown>>[];
        readonly proofSerialization: Readonly<Record<string, unknown>>;
    };
    readonly setupProofProfileHash: ProtocolHash;
    readonly setupTransportProfile: {
        readonly objectType: 'SetupTransportProfile';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly transportProfileId: 'sealed-lattice-setup-binary-chunked-transport-v1';
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
    readonly setupTransportProfileHash: ProtocolHash;
    readonly acceptedCertificateTemplates: Readonly<{
        readonly setupCommitmentSecurityCertificate: Readonly<
            Record<string, unknown>
        >;
        readonly setupProofAccountingCertificate: Readonly<
            Record<string, unknown>
        >;
        readonly heSecurityCertificate: Readonly<Record<string, unknown>>;
    }>;
    readonly evaluatorKeyScheduleProfile: {
        readonly objectType: 'EvaluatorKeyScheduleProfile';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: 'SealedLattice-SetupProof-v1';
        readonly evaluatorProfile: 'direct-encrypted-ballot-evaluator-replay';
        readonly packingProfile: 'direct-score-packing-compact-generator-basis-direct-encrypted-score-comparison-generator-ordered-rank-packing';
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
    readonly evaluatorKeyScheduleProfileHash: ProtocolHash;
    readonly phaseOrder: readonly {
        readonly phaseId: string;
        readonly phaseNumber: number;
    }[];
    readonly phaseOrderHash: ProtocolHash;
    readonly requiredFinalObjects: readonly string[];
    readonly transportProfileId: string;
};

export type BgvCollectiveSetupPublicDerivations = {
    readonly objectType: 'SetupPublicDerivations';
    readonly objectVersion: 1;
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly bgvPublicA: {
        readonly objectType: 'BgvPublicAPolynomial';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
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
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
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
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly matrixKind: 'commitment' | 'setupProof';
    readonly profileId: string;
    readonly commitmentProfileHash?: ProtocolHash;
    readonly setupProofProfileHash?: ProtocolHash;
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
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupProfileHash: ProtocolHash;
    readonly qShareHash: ProtocolHash;
    readonly commitmentProfileHash: ProtocolHash;
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
        readonly setupCommitmentSecurityCertificateHash: ProtocolHash;
        readonly setupTransportCertificateHash: ProtocolHash;
        readonly setupProofAccountingCertificateHash: ProtocolHash;
        readonly setupKeyCorrectnessCertificateHash: ProtocolHash;
        readonly activeStaticSetupTheoremCertificateHash: ProtocolHash;
        readonly heSecurityCertificateHash: ProtocolHash;
    };
    readonly acceptedSetupHandoffRoot: ProtocolHash;
};

export type BgvCollectiveSetupVerification = {
    readonly ok: boolean;
    readonly operation: 'verifyCollectiveBgvSetupPackage';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly verifierStatus:
        | 'accepted'
        | 'pending'
        | 'refused'
        | 'aborted'
        | 'forkDetected'
        | 'outsideProfile';
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
    readonly ok: boolean;
    readonly operation: 'verifyPrivateVssShareEnvelope';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly verifierStatus: 'accepted' | 'refused';
    readonly privateEnvelopeHash: ProtocolHash | null;
    readonly localVerificationRoot: ProtocolHash | null;
    readonly ringDegree?: number;
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
    readonly ok: true;
    readonly operation: 'generatePrivateVssShareProof';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
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

// The kernel derives the proof family from the statement shape, then enforces
// the matching ordered binding roots.
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
    | {
          readonly shareLinkageStatementRoot: ProtocolHash;
      }
    | {
          readonly compactSameSecretBridgeStatementRoot: ProtocolHash;
          readonly sameSecretStatementRoot: ProtocolHash;
          readonly sameSecretProofRoot: ProtocolHash;
          readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
      }
);

export type BgvTrusteeEvaluationKeySameSecretLinkage = {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly commitments: readonly unknown[];
};

export type BgvTrusteeEvaluationKeyProofGeneration = {
    readonly ok: true;
    readonly operation: 'generateTrusteeEvaluationKeyProof';
    readonly proofFamily:
        | 'trustee-evaluation-key'
        | 'same-secret-linkage-anchor'
        | 'public-key-share';
    readonly proofAccountingHash: ProtocolHash;
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly keyCount: number;
    readonly sameSecretLinkageIncluded: boolean;
    readonly proofByteLength: number;
    readonly proofBytesHex: string;
};

export type BgvTrusteeEvaluationKeyProofVerification = {
    readonly ok: true;
    readonly operation: 'verifyTrusteeEvaluationKeyProof';
    readonly proofFamily:
        | 'trustee-evaluation-key'
        | 'same-secret-linkage-anchor'
        | 'public-key-share';
    readonly proofAccountingHash: ProtocolHash;
    readonly proofAccounting: Readonly<Record<string, unknown>>;
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly keyCount: number;
    readonly sameSecretLinkageIncluded: boolean;
    readonly proofByteLength: number;
};

export type BgvThresholdShareCommitmentDerivation = {
    readonly ok: true;
    readonly operation: 'deriveThresholdShareCommitments';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly derivedLimbCommitmentCount: number;
    readonly thresholdShareCommitmentRoot: ProtocolHash;
    readonly thresholdShareCommitments: Readonly<Record<string, unknown>>;
};

export type BgvSetupCommitmentOpeningComputation = {
    readonly ok: true;
    readonly operation: 'computeSetupCommitmentFromOpening';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly commitment: Record<string, unknown>;
    readonly commitmentRoot: ProtocolHash;
    readonly commitmentChunkRoot: ProtocolHash;
    readonly coefficientVectorHash512: string;
};

export type BgvCompactVssCommitmentRole =
    | 'coefficient'
    | 'recipient-share'
    | 'aggregate-threshold-share'
    | 'target-decryption-smudging-polynomial-coefficient';

export type BgvCompactVssCommitmentOpeningInput = {
    readonly commitmentRole: BgvCompactVssCommitmentRole;
    readonly commitmentContext: Readonly<Record<string, unknown>>;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly messageCoefficients: readonly number[];
    readonly messageDigitColumns: readonly (readonly number[])[];
    readonly messageCoefficientBound?: number;
    readonly randomnessByColumn: readonly (readonly number[])[];
};

export type BgvCompactVssCommitmentOpeningComputation = {
    readonly ok: true;
    readonly operation: 'computeCompactVssCommitmentFromOpening';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly commitment: Readonly<Record<string, unknown>>;
    readonly commitmentRoot: ProtocolHash;
    readonly openingRoot: ProtocolHash;
    readonly commitmentContextHash: ProtocolHash;
    readonly encodedCommitmentByteLength: number;
};

export type BgvCompactVssCommitmentBodyMetadata = {
    readonly commitmentRole: BgvCompactVssCommitmentRole;
    readonly commitmentContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
};

export type BgvCompactVssCommitmentBodyEncoding = {
    readonly ok: true;
    readonly operation: 'encodeCompactVssCommitmentBody';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly profileId: string;
    readonly binaryFormat: string;
    readonly encodedCommitmentByteLength: number;
    readonly commitmentBodyBytes: Uint8Array;
};

export type BgvCompactVssCommitmentBodyDecoding = {
    readonly ok: true;
    readonly operation: 'decodeCompactVssCommitmentBody';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly profileId: string;
    readonly binaryFormat: string;
    readonly encodedCommitmentByteLength: number;
    readonly commitment: BgvJsonRecord;
    readonly commitmentRoot: ProtocolHash;
};

export type BgvCompactVssCommitmentOpeningVerification = {
    readonly ok: true;
    readonly operation: 'verifyCompactVssCommitmentOpening';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly commitmentRoot: ProtocolHash;
    readonly openingRoot: ProtocolHash;
};

export type BgvCompactVssCoefficientCommitmentSetVerification = {
    readonly ok: true;
    readonly operation: 'verifyCompactVssCoefficientCommitmentSet';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly ringDegree: number;
};

export type BgvCompactVssRecipientShareCommitmentSetVerification = {
    readonly ok: true;
    readonly operation: 'verifyCompactVssRecipientShareCommitmentSet';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly recipientShareCommitmentRoot: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly ringDegree: number;
};

export type BgvCompactVssAggregateThresholdCommitmentSetVerification = {
    readonly ok: true;
    readonly operation: 'verifyCompactVssAggregateThresholdCommitmentSet';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly aggregateThresholdCommitmentRoot: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly ringDegree: number;
};

export type BgvCompactVssShareLinkageStatementVerification = {
    readonly ok: true;
    readonly operation: 'verifyCompactVssShareLinkageStatement';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly statementRoot: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly recipientShareCommitmentRoot: ProtocolHash;
    readonly aggregateThresholdCommitmentRoot: ProtocolHash;
    readonly participantCount: number;
    readonly targetRnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly proofBatchingRule: string;
    readonly shamirEvaluationRule: string;
    readonly aggregateThresholdRule: string;
    readonly commonKeyRule: string;
};

export type BgvCompactVssShareLinkageProofStatementItem = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly sourceCoefficientCommitmentRoot: ProtocolHash;
    readonly sourceRecipientShareCommitmentRoot: ProtocolHash;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly sourceRnsLimbIndex: number;
    readonly sourceMessageModulus: number;
    readonly coefficientCommitmentRoots: readonly ProtocolHash[];
    readonly coefficientOpeningRoots: readonly ProtocolHash[];
    readonly coefficientCommitments: readonly Readonly<
        Record<string, unknown>
    >[];
    readonly recipientShareCommitmentRoot: ProtocolHash;
    readonly recipientShareOpeningRoot: ProtocolHash;
    readonly recipientShareCommitment: Readonly<Record<string, unknown>>;
};

export type BgvCompactVssShareLinkageProofStatement =
    BgvCompactVssShareLinkageProofStatementItem & {
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly shareLinkageStatementRoot: ProtocolHash;
        readonly additionalLinkageItems?: readonly BgvCompactVssShareLinkageProofStatementItem[];
    };

export type BgvCompactVssShareLinkageProofGeneration = {
    readonly ok: true;
    readonly operation: 'generateCompactVssShareLinkageProof';
    readonly proofFamily: 'compact-vss-share-linkage';
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly coefficientCommitmentCount: number;
    readonly coefficientWitnessColumnCount: number;
    readonly proofByteLength: number;
    readonly proofBytesHex: string;
};

export type BgvCompactVssShareLinkageProofVerification = {
    readonly ok: true;
    readonly operation: 'verifyCompactVssShareLinkageProof';
    readonly proofFamily: 'compact-vss-share-linkage';
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly coefficientCommitmentCount: number;
    readonly coefficientWitnessColumnCount: number;
    readonly proofByteLength: number;
};

export type BgvCompactVssShareLinkageProofMaterialSetVerification = {
    readonly ok: true;
    readonly operation: 'verifyCompactVssShareLinkageProofMaterialSet';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly proofFamily: 'compact-vss-share-linkage';
    readonly statementRoot: ProtocolHash;
    readonly proofMaterialSetRoot: ProtocolHash;
    readonly participantCount: number;
    readonly targetRnsLimbCount: number;
    readonly ringDegree: number;
    readonly proofRecordCount: number;
    readonly coveredLinkageItemCount: number;
    readonly totalProofByteLength: number;
    readonly proofVerificationCount: number;
};

export type BgvCompactSameSecretBridgeProofStatement = {
    readonly compactSameSecretBridgeStatementRoot: ProtocolHash;
    readonly sameSecretStatementRoot: ProtocolHash;
    readonly sameSecretProofRoot: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly targetBasisHash: ProtocolHash;
    readonly targetRnsPrimes: readonly number[];
    readonly targetConstantCommitmentRoots: readonly ProtocolHash[];
    readonly targetConstantCommitments: readonly Readonly<
        Record<string, unknown>
    >[];
};

export type BgvCompactSameSecretBridgeProofGeneration = {
    readonly ok: true;
    readonly operation: 'generateCompactSameSecretBridgeProof';
    readonly proofFamily: 'compact-same-secret-bridge';
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly targetRnsLimbCount: number;
    readonly proofByteLength: number;
    readonly proofBytesHex: string;
};

export type BgvCompactSameSecretBridgeProofVerification = {
    readonly ok: true;
    readonly operation: 'verifyCompactSameSecretBridgeProof';
    readonly proofFamily: 'compact-same-secret-bridge';
    readonly statementHash: ProtocolHash;
    readonly limbCount: number;
    readonly targetRnsLimbCount: number;
    readonly proofByteLength: number;
};

export type BgvCompactVssSameSecretBridgeStatementSetVerification = {
    readonly ok: true;
    readonly operation: 'verifyCompactVssSameSecretBridgeStatementSet';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly compactSameSecretBridgeStatementSetRoot: ProtocolHash;
    readonly participantCount: number;
    readonly targetRnsLimbCount: number;
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly targetBasisHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly compactCoefficientCommitmentRoot: ProtocolHash;
    readonly sameSecretConsistencyRoot: ProtocolHash;
    readonly sameSecretProofSetRoot: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
    readonly integerSupport: string;
    readonly signedRepresentativeConvention: string;
    readonly compactCommitmentEncoding: string;
    readonly targetBasisLimbOrder: string;
};

export type BgvCompactVssSameSecretBridgeProofMaterialSetVerification = {
    readonly ok: true;
    readonly operation: 'verifyCompactVssSameSecretBridgeProofMaterialSet';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly proofFamily: 'compact-same-secret-bridge';
    readonly compactSameSecretBridgeStatementSetRoot: ProtocolHash;
    readonly proofMaterialSetRoot: ProtocolHash;
    readonly participantCount: number;
    readonly proofRecordCount: number;
    readonly totalProofByteLength: number;
    readonly proofVerificationCount: number;
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
    readonly ok: true;
    readonly operation: 'beginThresholdShareCommitmentsFromTransportStream';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly derivationId: string;
    readonly materialBinaryFormat: string;
    readonly transport: Readonly<Record<string, unknown>>;
};

export type BgvThresholdShareCommitmentTransportStreamAbort = {
    readonly ok: true;
    readonly operation: 'abortThresholdShareCommitmentsFromTransportStream';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly derivationId: string;
    readonly aborted: boolean;
};

export type BgvThresholdShareCommitmentTransportStreamChunkAbsorption = {
    readonly ok: true;
    readonly operation: 'absorbThresholdShareCommitmentsFromTransportStreamChunk';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
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
    readonly ok: true;
    readonly operation: 'beginSetupProofMaterialTransportStream';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly setupProofProfileId: string;
    readonly verificationId: string;
    readonly proofFamily: string;
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofBytesEncoding: string;
    readonly transport: Readonly<Record<string, unknown>>;
};

export type BgvSetupProofMaterialTransportStreamChunkAbsorption = {
    readonly ok: true;
    readonly operation: 'absorbSetupProofMaterialTransportStreamChunk';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly setupProofProfileId: string;
    readonly absorbedChunkIndex: number;
    readonly nextChunkIndex: number;
    readonly observedTotalByteLength: number;
};

export type BgvSetupProofMaterialTransportStreamVerification = {
    readonly ok: true;
    readonly operation: 'finishSetupProofMaterialTransportStream';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly setupProofProfileId: string;
    readonly verificationId: string;
    readonly proofFamily: string;
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofBytesEncoding: string;
    readonly transport: Readonly<Record<string, unknown>>;
    readonly verifiedSetupProofMaterial: BgvVerifiedSetupProofMaterial;
};

export type BgvVerifiedTransportedVssMaterialRelease = {
    readonly ok: true;
    readonly operation: 'releaseVerifiedTransportedVssMaterial';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly verificationId: string;
    readonly released: boolean;
};

export type BgvLocalTrusteeSetupStateVerification = {
    readonly ok: true;
    readonly operation: 'verifyLocalTrusteeSetupState';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly trusteePoint: number;
    readonly localStateRoot: ProtocolHash;
    readonly targetDecryptionProofWitnessRoot: ProtocolHash;
    readonly deletionReceiptRoot: ProtocolHash;
};

export type BgvTargetCiphertextPairInput = {
    readonly targetIdCanonicalBytesHex: string;
    readonly targetOrderCanonicalBytesHex: string;
};

export type BgvTargetDecryptionDevelopmentFixture = Readonly<
    Record<string, unknown> & {
        readonly objectType: 'BgvTargetDecryptionDevelopmentFixture';
        readonly objectVersion: 1;
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly setupPrivateWitness: {
            readonly setupSeed: string;
        };
        readonly targetAcceptedRecord: Record<string, unknown>;
        readonly targetCiphertextBinding: Record<string, unknown>;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareProfile: Record<string, unknown>;
        readonly trusteeIdentity: string;
        readonly localTargetShareWitness: Record<string, unknown>;
        readonly quorumLocalTargetShareWitnesses: readonly {
            readonly trusteeIdentity: string;
            readonly localTargetShareWitness: Record<string, unknown>;
        }[];
    }
>;

export type BgvTargetDecryptionSmudgingInputReport = {
    readonly objectType: 'TargetDecryptionSmudgingInputReport';
    readonly objectVersion: 1;
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly targetDecryptionProfileId: 'BGV-RNS-AsyncTargetDecryption-v1';
    readonly smudgingProfileId: string;
    readonly setupPackageHash: ProtocolHash;
    readonly targetAcceptedRecordHash: ProtocolHash;
    readonly targetContextHash: ProtocolHash;
    readonly targetCiphertextHash: ProtocolHash;
    readonly targetDecryptionCiphertextHash: ProtocolHash;
    readonly targetShareProfileHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
    readonly targetIdRoot: ProtocolHash;
    readonly targetOrderRoot: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly boardPosition: number;
    readonly interpolationPoint: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly minimumSharesForInterpolation: number;
    readonly decryptionThreshold: number;
    readonly activeRnsLimbCount: number;
    readonly ringDegree: number;
    readonly smudgingCoefficientBound: number;
    readonly smudgingPolynomialDegree: number;
    readonly plaintextMultiple: number;
    readonly roleReports: readonly {
        readonly role: 'targetId' | 'targetOrder';
        readonly limbReports: readonly {
            readonly rnsLimbIndex: number;
            readonly rnsPrime: number;
            readonly maximumAbsoluteNoiseShare: number;
        }[];
    }[];
};

export type BgvTargetDecryptionSharePayload = {
    readonly objectType: 'BgvTargetDecryptionSharePayload';
    readonly objectVersion: 1;
    readonly encoding: string;
    readonly level: number;
    readonly smudgingInputReport: BgvTargetDecryptionSmudgingInputReport;
    readonly smudgingInputReportHash: ProtocolHash;
    readonly targetId: readonly unknown[];
    readonly targetOrder: readonly unknown[];
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
        readonly targetShareProfileHash: ProtocolHash;
        readonly shareRoot: ProtocolHash;
        readonly sharePayload: BgvTargetDecryptionSharePayload;
    }
>;

export type BgvTargetDecryptionShareProofStatement = Readonly<
    Record<string, unknown> & {
        readonly objectType: 'BgvTargetDecryptionShareProofStatement';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly targetDecryptionProfileId: 'BGV-RNS-AsyncTargetDecryption-v1';
        readonly proofStatementRoot: ProtocolHash;
        readonly setupPackageHash: ProtocolHash;
        readonly trusteeIdentity: string;
        readonly rosterPosition: number;
        readonly interpolationPoint: number;
        readonly targetAcceptedRecordHash: ProtocolHash;
        readonly targetContextHash: ProtocolHash;
        readonly targetCiphertextHash: ProtocolHash;
        readonly targetDecryptionCiphertextHash: ProtocolHash;
        readonly targetShareProfileHash: ProtocolHash;
        readonly targetBasisHash: ProtocolHash;
        readonly targetDecryptionShareHash: ProtocolHash;
        readonly shareRoot: ProtocolHash;
        readonly smudgingInputReportHash: ProtocolHash;
        readonly compactAggregateOpeningBinding: unknown;
    }
>;

export type BgvTargetDecryptionShareProofMaterial = Readonly<
    Record<string, unknown> & {
        readonly objectType: 'BgvTargetDecryptionShareProofMaterial';
        readonly objectVersion: 8;
        readonly proofRecords: readonly unknown[];
        readonly proofMaterialRoot: ProtocolHash;
    }
>;

export type BgvTargetDecryptionShareProofMaterialVerification = {
    readonly ok: true;
    readonly operation: 'verifyBgvTargetDecryptionShareProofMaterial';
    readonly proofMaterialRoot: ProtocolHash;
};

export type BgvTargetDecryptionShareBinaryProofMaterialTransport =
    BgvTransportedMaterialObject<'BgvTargetDecryptionShareBinaryProofMaterialTransport'> &
        Readonly<{
            readonly setupProfileId: 'CollectiveBgvSetup-v1';
            readonly targetDecryptionProfileId: string;
            readonly proofFamily: string;
            readonly binaryFormat: string;
            readonly proofMaterialRoot: ProtocolHash;
            readonly chunkSizeBytes: number;
            readonly chunkCount: number;
            readonly totalByteLength: number;
            readonly fullObjectHash: ProtocolHash;
            readonly chunkRoot: ProtocolHash;
            readonly chunkHashes: readonly ProtocolHash[];
            readonly chunks: readonly unknown[];
        }>;

export type BgvTargetDecryptionShareBinaryProofMaterialVerification = {
    readonly ok: true;
    readonly operation: 'verifyBgvTargetDecryptionShareBinaryProofMaterial';
    readonly proofFamily: string;
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofRecordCount: number;
    readonly totalProofByteLength: number;
    readonly binaryFormat: string;
    readonly binaryTotalByteLength: number;
    readonly binaryChunkCount: number;
    readonly binaryFullObjectHash: ProtocolHash;
    readonly binaryChunkRoot: ProtocolHash;
};

export type BgvTargetDecryptionShareProofStatementBindingVerification = {
    readonly ok: false;
    readonly operation: 'verifyBgvTargetDecryptionShareProofStatementBinding';
    readonly refusalReason: 'TargetDecryptionProofUnavailable';
};

export type BgvTargetDecryptionResultRelease = {
    readonly ok: true;
    readonly operation: 'verifyAndReleaseBgvTargetDecryptionResult';
    readonly targetResultHash: ProtocolHash;
    readonly targetIdByOption: readonly number[];
    readonly targetOrderByOption: readonly number[];
    readonly topCount: number;
    readonly shareEvidence: readonly {
        readonly trusteeIdentity: string;
        readonly rosterPosition: number;
        readonly interpolationPoint: number;
        readonly targetDecryptionShareHash: ProtocolHash;
        readonly proofStatementRoot: ProtocolHash;
        readonly proofMaterialRoot: ProtocolHash;
    }[];
};
