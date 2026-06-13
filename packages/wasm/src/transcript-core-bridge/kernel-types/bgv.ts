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
    readonly statusLabels: readonly string[];
};

export type BgvCanonicalObjectAnalysis = {
    readonly objectKind: 'plaintext' | 'ciphertext';
    readonly componentCount: number;
    readonly profileHash: ProtocolHash;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly layoutHash: ProtocolHash;
    readonly statusLabels: readonly string[];
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
    readonly statusLabels: readonly string[];
};

export type BgvEvaluatorOperationValidation =
    | {
          readonly ok: true;
          readonly operation: 'validateBgvEvaluatorOperation';
          readonly acceptedOperation: string;
          readonly allowedEvaluatorOpsHash: ProtocolHash;
          readonly statusLabels: readonly string[];
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
    readonly profileHash: ProtocolHash;
    readonly ciphertextRoot: ProtocolHash;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly componentCount: number;
    readonly validation: BgvObjectValidation;
    readonly statusLabels: readonly string[];
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
        readonly statusLabels: readonly string[];
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
        readonly statusLabels: readonly string[];
        readonly record: unknown;
        readonly rotSet: unknown;
    };
    readonly developmentEncryptionFixture: Readonly<Record<string, unknown>>;
    readonly certificates: Readonly<Record<string, unknown>>;
    readonly externallySuppliedSetupMaterialBoundary: Readonly<
        Record<string, unknown>
    >;
    readonly targetDecryptionStatus: {
        readonly targetDecryptionProfileId: string;
        readonly targetDecryptionProfileHash: ProtocolHash;
        readonly targetDecryptionProfileBindingHash: ProtocolHash;
        readonly setupMaterialMatchesTargetDecryption: boolean;
        readonly targetPartDecImplemented: boolean;
        readonly targetC1C4StatusAccepted: boolean;
    };
    readonly statusLabels: readonly string[];
    readonly nonClaims: readonly string[];
};

export type BgvPassiveSetupVerification = {
    readonly ok: boolean;
    readonly operation: 'verifyBgvPassiveSetupPackage';
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly refusedObjects: readonly unknown[];
    readonly unresolvedReason: string | null;
    readonly statusLabels: readonly string[];
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
        readonly targetDecryptionReadiness: string;
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
        readonly objectType: 'BdlopLnpCommitmentProfile';
        readonly objectVersion: 1;
        readonly profileId: 'SealedLattice-BDLOP-LNP-Commitment-v1';
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
    readonly publicVssCommitmentMaterialSizeProfile: {
        readonly objectType: 'PublicVssCommitmentMaterialSizeProfile';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly measurementKind: string;
        readonly ringDegree: number;
        readonly ringDegreeStatus: 'profile-ring';
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
        readonly mobileClosureStatus: string;
    };
    readonly publicVssCommitmentMaterialSizeProfileHash: ProtocolHash;
    readonly setupProofProfile: {
        readonly objectType: 'SetupProofProfile';
        readonly objectVersion: 1;
        readonly profileId: 'SealedLattice-LNP-SetupProof-v1';
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly proofSystem: string;
        readonly proofBackendBoundary: string;
        readonly arbitraryRelationApi: string;
        readonly relationModel: Readonly<Record<string, unknown>>;
        readonly challengeBinding: Readonly<Record<string, unknown>>;
        readonly witnessBounds: Readonly<Record<string, unknown>>;
        readonly proofFamilies: readonly Readonly<Record<string, unknown>>[];
        readonly proofSerialization: Readonly<Record<string, unknown>>;
        readonly matrixDerivation: Readonly<Record<string, unknown>>;
        readonly verificationPolicy: Readonly<Record<string, unknown>>;
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
        readonly setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1';
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
        readonly genericKeySwitchPolicy: 'refused-unless-explicitly-required';
        readonly genericKeySwitchProofStatus: 'not-required-for-first-profile';
        readonly scheduleBindingStatus: 'relinearization-and-galois-proof-verifiers-bound-by-accepted-setup-proof-accounting';
    };
    readonly evaluatorKeyScheduleProfileHash: ProtocolHash;
    readonly verifierStatuses: readonly [
        'accepted',
        'pending',
        'refused',
        'aborted',
        'forkDetected',
        'outsideProfile',
    ];
    readonly phaseOrder: readonly {
        readonly phaseId: string;
        readonly phaseNumber: number;
    }[];
    readonly phaseOrderHash: ProtocolHash;
    readonly requiredFinalObjects: readonly string[];
    readonly genericKeySwitchPolicy: string;
    readonly transportProfileId: string;
    readonly forbiddenAcceptedPathFields: readonly string[];
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
        readonly setupProofMatrix: BgvCollectiveSetupPublicMatrix;
        readonly materializationStatus: 'deterministic-entry-streams-bound';
        readonly publicMatricesRoot: ProtocolHash;
    };
    readonly crpRoots: {
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly commitmentMatrixCrpRoot: ProtocolHash;
        readonly proofMatrixCrpRoot: ProtocolHash;
    };
    readonly status: 'deterministic-public-derivations-bound';
    readonly publicDerivationRoot: ProtocolHash;
};

export type BgvCollectiveSetupPublicMatrix = {
    readonly objectType: 'SetupPublicMatrix';
    readonly objectVersion: 1;
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly matrixKind: 'commitment' | 'setupProof';
    readonly profileId: string;
    readonly profileStatus:
        | 'commitment-profile-bound'
        | 'setup-proof-profile-bound';
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
        readonly status: 'accepted-collective-public-key-root-bound-for-direct-ballot-encryption';
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
    };
    readonly publicAggregationHandoff: {
        readonly status: 'accepted-public-ciphertext-aggregation-bound-to-setup-context-and-collective-public-key-root';
        readonly thresholdShareCommitmentRoot: ProtocolHash;
    };
    readonly boundedEvaluatorReplayHandoff: {
        readonly status: 'accepted-public-evaluation-keys-bound-to-frozen-evaluator-schedule';
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
        readonly trusteeEvaluationKeyProofSetRoot: ProtocolHash;
        readonly evaluationKeySetHash: ProtocolHash;
        readonly publicEvaluationKeyMaterialRoot?: ProtocolHash;
    };
    readonly futureTargetDecryptionHandoff: {
        readonly status: string;
        readonly targetDecryptionProfileId: string;
        readonly claimBoundary: string;
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
    readonly ringDegreeStatus?: 'profile-ring' | 'development-reduced-ring';
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
    readonly ok: true;
    readonly operation: 'generateTrusteeEvaluationKeyProof';
    readonly proofFamily:
        | 'trustee-evaluation-key'
        | 'same-secret-linkage-anchor'
        | 'public-key-share';
    readonly proofModelStatus: string;
    readonly proofAccountingHash: ProtocolHash;
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
    readonly ok: true;
    readonly operation: 'verifyTrusteeEvaluationKeyProof';
    readonly proofFamily:
        | 'trustee-evaluation-key'
        | 'same-secret-linkage-anchor'
        | 'public-key-share';
    readonly proofModelStatus: string;
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
    readonly ringDegreeStatus: 'profile-ring' | 'development-reduced-ring';
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

export type BgvLocalTrusteeSetupStateVerification = {
    readonly ok: true;
    readonly operation: 'verifyLocalTrusteeSetupState';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly trusteePoint: number;
    readonly localStateRoot: ProtocolHash;
    readonly deletionReceiptRoot: ProtocolHash;
    readonly exportPolicy: 'roots-only-no-raw-share-or-opening-export';
    readonly storageProfile: 'encrypted-local-device-state-required';
    readonly deletionBoundary: 'after-private-vss-aggregation';
    readonly statusLabels: readonly string[];
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
        readonly targetShareProfileHash: ProtocolHash;
        readonly shareRoot: ProtocolHash;
        readonly sharePayload: unknown;
        readonly statusLabels: readonly string[];
    }
>;

export type BgvTargetDecryptionResult = {
    readonly ok: true;
    readonly operation: 'recombineBgvTargetDecryptionShares';
    readonly targetDecryptionResultHash: ProtocolHash;
    readonly setupPackageHash: ProtocolHash;
    readonly targetAcceptedRecordHash: ProtocolHash;
    readonly targetContextHash: ProtocolHash;
    readonly targetCiphertextHash: ProtocolHash;
    readonly targetShareProfileHash: ProtocolHash;
    readonly targetDecryptionProfileHash: ProtocolHash;
    readonly shareEquation: string;
    readonly recombinationEquation: string;
    readonly selectedShareRule: string;
    readonly minimumSharesForInterpolation: number;
    readonly decryptionThreshold: number;
    readonly decryptionShareQuorum: number;
    readonly selectedRosterPositions: readonly number[];
    readonly decodedTargetIds: readonly number[];
    readonly decodedTargetOrders: readonly number[];
    readonly decryptScaling: number;
    readonly statusLabels: readonly string[];
};
