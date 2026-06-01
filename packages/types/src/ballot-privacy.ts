import type { InterpolationCoefficientReport } from './plaintext-oracle.js';
import type { ProtocolHash } from './protocol-hash.js';
import type {
    ProtocolSignatureEnvelope,
    StructuredProtocolVerificationResult,
} from './protocol-objects.js';
import type {
    ActionContext,
    RecoveryEpochMapEntry,
} from './roster-recovery.js';

export type DecimalIntegerString = string;

export type ReceiverEncryptionProfile = {
    readonly objectType: 'ReceiverEncryptionProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly receiverEncryptionProfileHash: ProtocolHash;
    readonly scheme: 'LinearModuleLweRegev';
    readonly hardnessAssumption: 'Module-LWE';
    // Power-of-two cyclotomic ring Z_q[X]/(X^256 + 1) (negacyclic, degree 256).
    readonly ring: 'Z_q[X]/(X^256 + 1)';
    readonly moduleRank: 4;
    readonly moduleDegree: 256;
    readonly ciphertextModulus: DecimalIntegerString;
    readonly plaintextModulus: 2;
    // 17 = ceil(log2(65537)): each GF(65537) field element needs 17 bits, which the
    // bit-sliced encoding below spreads across the plaintextModulus-2 message slots.
    readonly fieldElementBitLength: 17;
    readonly messageEncoding: 'BitSlicedCanonicalGF65537LittleEndian';
    readonly publicMatrixDerivationDomain: string;
    readonly secretDistribution: 'CenteredBinomialEta2';
    readonly errorDistribution: 'CenteredBinomialEta2';
    readonly encryptionRandomnessDistribution: 'CenteredBinomialEta2';
    readonly parameterSecurityEvidenceStatus: 'ParameterCertificateMissing';
    readonly claimBoundary: 'ReceiverEncryptionParameterSecurityNotClosed';
    readonly payloadBinding: {
        readonly encryptsReceiverShareVector: true;
        readonly encryptsShareCommitmentOpening: true;
        readonly bindsReceiverIdentity: true;
        readonly bindsReceiverRosterPosition: true;
        readonly bindsManifestHash: true;
        readonly bindsRosterHash: true;
        readonly bindsPollSpecHash: true;
        readonly bindsVoterIdentityHash: true;
        readonly bindsActionContextHash: true;
    };
    readonly decryptionFailureTarget: '2^-128';
};

export type ShareCommitmentProfile = {
    readonly objectType: 'ShareCommitmentProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly shareCommitmentProfileHash: ProtocolHash;
    readonly scheme: 'AdditiveModuleSisCommitment';
    readonly hardnessAssumption: 'Module-SIS';
    readonly commitmentModulus: DecimalIntegerString;
    readonly moduleRank: 4;
    readonly moduleDegree: 256;
    readonly shareVectorWidth: number;
    readonly messageFieldModulus: 65537;
    readonly messageRepresentativeMinimum: 0;
    readonly messageRepresentativeMaximum: 65536;
    readonly messageEncoding: 'CanonicalGF65537RepresentativeVector';
    readonly commitmentFormula: 'A_message * EncodeShareVector(S) + A_randomness * rho mod q_commit';
    readonly matrixDerivationDomain: string;
    // Per-commitment opening randomness rho has 64 coordinates.
    readonly openingRandomnessDimension: 64;
    readonly openingRandomnessDistribution: 'UniformCenteredInteger';
    readonly openingRandomnessInfinityNormBound: number;
    readonly openingRandomnessRangeWidth: number;
    readonly openingRandomnessSampler: 'RejectionSampledLittleEndianUint16';
    readonly openingRandomnessSamplerDomain: string;
    readonly openingRandomnessSamplerWordBits: 16;
    // Turnout bound of 50 is what guarantees no aggregate-opening wraparound when
    // summing per-ballot openings (ties to ShareCommitmentMessageBoundCert's
    // noWraparoundCondition).
    readonly aggregateOpeningRandomnessMaximumTurnout: 50;
};

export type ScoreMembershipProfile = {
    readonly objectType: 'ScoreMembershipProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly scoreMembershipProfileHash: ProtocolHash;
    readonly relation: 'OneHotScoreMembership';
    readonly scoreMinimum: 1;
    readonly scoreMaximum: 10;
    readonly oneHotWidth: 10;
    readonly constraints: readonly [
        'sum(one_hot_score[1..10]) = 1',
        'score = sum(score_value * one_hot_score[score_value])',
        'one_hot_score entries are boolean',
    ];
};

export type BallotScoreEncodingProfile = {
    readonly objectType: 'BallotScoreEncodingProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly ballotScoreEncodingProfileHash: ProtocolHash;
    readonly encoding: 'ScalarScorePlusOneHotScoreBuckets';
    readonly scoreMinimum: 1;
    readonly scoreMaximum: 10;
    readonly oneHotWidth: 10;
    // 11 coordinates per option = 1 scalar score + 10 one-hot buckets; this is the
    // *11 / width-220 magic-number anchor referenced across the ballot relation.
    readonly coordinatesPerOption: 11;
    readonly scalarCoordinateOffset: 0;
    readonly scoreBucketCoordinateOffsets: readonly [
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
    ];
    readonly scalarConsistencyConstraint: 'scalar_score = sum(score_value * one_hot_score[score_value])';
    readonly oneHotConstraint: 'sum(one_hot_score[1..10]) = 1 and entries are boolean';
};

export type BallotShareLayoutProfile = {
    readonly objectType: 'BallotShareLayoutProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly ballotShareLayoutProfileHash: ProtocolHash;
    readonly layout: 'ScalarThenOneHotBucketsPerOption';
    readonly coordinatesPerOption: 11;
    readonly minimumOptionCount: 2;
    readonly maximumOptionCount: 20;
    readonly shareVectorWidth: number;
    // 11 coordinates per option (1 scalar + 10 one-hot), so width = 11 * optionCount
    // (e.g. 20 options -> width 220).
    readonly widthFormula: 'shareVectorWidth = 11 * optionCount';
    readonly paddingRule: 'unused coordinates must be zero';
};

export type AggregateInputEncodingProfile = {
    readonly objectType: 'AggregateInputEncodingProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly aggregateInputEncodingProfileHash: ProtocolHash;
    readonly encoding: 'AggregatedScoreHistogram';
    readonly scalarAggregateCoordinates: true;
    readonly oneHotBucketAggregateCoordinates: true;
    readonly coordinatesPerOption: 11;
    readonly maximumOptionCount: 20;
};

export type EncodedShareVectorLayoutProfile = {
    readonly objectType: 'EncodedShareVectorLayoutProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly encodedShareVectorLayoutHash: ProtocolHash;
    readonly layout: 'ScalarThenOneHotBucketsPerOption';
    readonly coordinatesPerOption: 11;
    readonly maximumOptionCount: 20;
    readonly shareVectorWidth: number;
    readonly coordinateOrder: 'score, score_bucket_1, ..., score_bucket_10 for each option';
};

export type EncodedAggregateLayoutProfile = {
    readonly objectType: 'EncodedAggregateLayoutProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly encodedAggregateLayoutHash: ProtocolHash;
    readonly layout: 'AggregatedScalarAndScoreBucketCoordinates';
    readonly coordinatesPerOption: 11;
    readonly maximumOptionCount: 20;
    readonly aggregateWidth: number;
    readonly aggregateCoordinateMeaning: 'sum of accepted receiver-share coordinates before bridge reduction';
};

export type BallotProofProfile = {
    readonly objectType: 'BallotProofProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly ballotProofProfileHash: ProtocolHash;
    readonly proofSystem: 'LocalLinearLatticeRelation';
    readonly backendConstruction: 'LyubashevskyNguyenPlancon2022LinearProofs';
    readonly relationShape: 'LinearLatticeRelationsWithShortVectorAndOneHotMembership';
    readonly fiatShamirHash: 'SHAKE128-256';
    readonly fiatShamirModel: 'QROMAccountedRequired';
    readonly challengeBits: 256;
    readonly soundnessBits: 128;
    readonly proofSizeTargetBytesMandatoryProfile: number;
    readonly proofSizeTargetBytesCertificateGatedProfile: number;
    readonly constantShapeForFixedRosterAndOptionCount: true;
    readonly postQuantumClaim: true;
    readonly pairingBasedWrapExcluded: true;
};

export type ShareCommitmentMessageBoundCert = {
    readonly objectType: 'ShareCommitmentMessageBoundCert';
    readonly objectVersion: 1;
    readonly shareCommitmentMessageBoundCertHash: ProtocolHash;
    readonly profileId: string;
    readonly profileHash: ProtocolHash;
    readonly shareCommitmentProfileHash: ProtocolHash;
    readonly fieldModulus: 65537;
    readonly shareVectorWidth: number;
    readonly perBallotShareRepresentativeRange: readonly [0, 65536];
    readonly maximumCanonicalTurnout: number;
    readonly maximumAggregateInteger: number;
    readonly commitmentMessageBound: DecimalIntegerString;
    readonly openingRandomnessSingleBound: number;
    readonly openingRandomnessAggregateBound: number;
    readonly quotientBoundForAggregateReduction: number;
    readonly noWraparoundCondition: {
        readonly maximumAggregateIntegerLessThanCommitmentMessageBound: true;
        readonly openingRandomnessAggregateBoundMatchesTurnout: true;
    };
};

export type BallotPrivacyProfileSet = {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly shareCommitmentProfile: ShareCommitmentProfile;
    readonly scoreMembershipProfile: ScoreMembershipProfile;
    readonly ballotScoreEncodingProfile: BallotScoreEncodingProfile;
    readonly ballotShareLayoutProfile: BallotShareLayoutProfile;
    readonly aggregateInputEncodingProfile: AggregateInputEncodingProfile;
    readonly encodedShareVectorLayoutProfile: EncodedShareVectorLayoutProfile;
    readonly encodedAggregateLayoutProfile: EncodedAggregateLayoutProfile;
    readonly ballotProofProfile: BallotProofProfile;
};

export type BallotPrivacyProfileHashes = {
    readonly receiverEncryptionProfileHash: ProtocolHash;
    readonly shareCommitmentProfileHash: ProtocolHash;
    readonly scoreMembershipProfileHash: ProtocolHash;
    readonly ballotScoreEncodingProfileHash: ProtocolHash;
    readonly ballotShareLayoutProfileHash: ProtocolHash;
    readonly aggregateInputEncodingProfileHash: ProtocolHash;
    readonly encodedShareVectorLayoutHash: ProtocolHash;
    readonly encodedAggregateLayoutHash: ProtocolHash;
    readonly ballotProofProfileHash: ProtocolHash;
};

export type ShareCommitmentMessageBoundCertVerification =
    StructuredProtocolVerificationResult & {
        readonly shareCommitmentMessageBoundCertHash?: ProtocolHash;
    };

/** Public receiver-key reference bound into a ballot proof statement. */
export type BallotProofReceiverPublicKeyReference = {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly receiverPublicKeyHash: ProtocolHash;
};

/** Public receiver-payload reference bound into a ballot proof statement. */
export type BallotProofReceiverPayloadReference = {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly receiverPayloadHash: ProtocolHash;
    readonly receiverPayloadCiphertextRoot: ProtocolHash;
};

/** Public share-commitment reference bound into a ballot proof statement. */
export type BallotProofShareCommitmentReference = {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly shareCommitmentHash: ProtocolHash;
};

/** Stable identifier for one component of the ballot privacy proof relation. */
export type BallotProofComponentId =
    | 'score-and-shamir-field-component'
    | 'payload-plaintext-field-component'
    | 'share-commitment-component'
    | 'receiver-encryption-component'
    | 'receiver-key-binding-component';

/** Hash-bearing proof record for one ballot privacy proof component. */
export type BallotProofComponentProofRecord = {
    readonly objectType: 'BallotProofComponentProofRecord';
    readonly objectVersion: 1;
    readonly componentProofRecordHash: ProtocolHash;
    readonly componentId: BallotProofComponentId;
    readonly componentStatementHash: ProtocolHash;
    readonly componentProofStatementHash: ProtocolHash;
    readonly backendStatementHash: ProtocolHash;
    readonly ballotProofStatementHash: ProtocolHash;
    readonly relationStatementHash: ProtocolHash;
    readonly proofBackend: 'LocalLinearLatticeRelation';
    readonly proofRoot: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofEncodingProfileHash: ProtocolHash;
    readonly proofParameterSetHash: ProtocolHash;
    readonly proofSizeBytes: number;
    readonly publicRandomnessHash: ProtocolHash;
};

/** Ordered proof bundle covering every required ballot proof component. */
export type BallotProofComponentProofBundle = {
    readonly objectType: 'BallotProofComponentProofBundle';
    readonly objectVersion: 1;
    readonly componentProofBundleHash: ProtocolHash;
    readonly componentBundleStatementHash: ProtocolHash;
    readonly backendStatementHash: ProtocolHash;
    readonly ballotProofStatementHash: ProtocolHash;
    readonly relationStatementHash: ProtocolHash;
    readonly bundleCoverage: 'full-encoded-score-ballot-relation';
    readonly requiredComponentIds: readonly BallotProofComponentId[];
    readonly componentProofs: readonly BallotProofComponentProofRecord[];
};

/** Supported public statement format for a component proof input. */
export type BallotProofComponentProofStatementFormat =
    | 'dense-polynomial-matrix-linear-proof-v1'
    | 'sparse-polynomial-matrix-linear-proof-v1'
    | 'structured-module-sis-share-commitment-v1'
    | 'structured-module-lwe-linear-proof-v1'
    | 'public-binding-check-only-v1';

/** Public proof bytes and verifier input for one ballot proof component. */
export type BallotProofComponentProofVerificationInput = {
    readonly componentId: BallotProofComponentId;
    readonly componentProofStatementHash: ProtocolHash;
    readonly proofBytesHex: string;
    readonly proofEncoding: unknown;
    readonly proofParameterSet: unknown;
    readonly proofStatement?: unknown;
    readonly proofStatementFormat: BallotProofComponentProofStatementFormat;
    readonly publicRandomnessHex: string;
    readonly statementHash: ProtocolHash;
};

/** Public receiver encryption key shell registered for ballot encryption. */
export type ReceiverEncryptionPublicKey = {
    readonly objectType: 'ReceiverEncryptionPublicKey';
    readonly objectVersion: 1;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly receiverEncryptionProfileHash: ProtocolHash;
    readonly keyMaterialHash: ProtocolHash;
    readonly receiverPublicKeyHash: ProtocolHash;
};

/** Proof shell binding a receiver encryption key to its registered public material. */
export type ReceiverKeyProof = {
    readonly objectType: 'ReceiverKeyProof';
    readonly objectVersion: 1;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly receiverPublicKeyHash: ProtocolHash;
    readonly receiverEncryptionProfileHash: ProtocolHash;
    readonly proofBackend: 'LocalLinearLatticeRelation';
    readonly backendStatementHash?: ProtocolHash;
    readonly linearStatementHash?: ProtocolHash;
    readonly proofBytesHash?: ProtocolHash;
    readonly proofEncodingProfileHash?: ProtocolHash;
    readonly proofParameterSetHash?: ProtocolHash;
    readonly proofSizeBytes?: number;
    readonly publicRandomnessHash?: ProtocolHash;
    readonly proofRoot: ProtocolHash;
    readonly receiverKeyProofRoot: ProtocolHash;
};

/** Accepted setup evidence for the receiver-key proof root bound into ballot packages. */
export type ReceiverKeyProofRootEvidence = {
    readonly objectType: 'ReceiverKeyProofRootEvidence';
    readonly objectVersion: 1;
    readonly receiverKeyProofRootEvidenceHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly receiverKeyRoot: ProtocolHash;
    readonly receiverKeyProofRoot: ProtocolHash;
    readonly receiverPublicKeys: readonly BallotProofReceiverPublicKeyReference[];
    readonly acceptedReceiverKeyProofCount: number;
    readonly evidenceStatus: 'ReceiverKeyProofRootAccepted';
};

/** Encrypted receiver payload shell referenced by a scoped relation-bearing ballot package. */
export type ReceiverPayload = {
    readonly objectType: 'ReceiverPayload';
    readonly objectVersion: 1;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly voterIdentityHash: ProtocolHash;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly receiverPublicKeyHash: ProtocolHash;
    readonly receiverEncryptionProfileHash: ProtocolHash;
    readonly payloadContextHash: ProtocolHash;
    readonly ciphertextBodyHash: ProtocolHash;
    readonly receiverPayloadCiphertextRoot: ProtocolHash;
    readonly receiverPayloadHash: ProtocolHash;
};

/** Public share commitment shell referenced by a scoped relation-bearing ballot package. */
export type ShareCommitment = {
    readonly objectType: 'ShareCommitment';
    readonly objectVersion: 1;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly shareCommitmentProfileHash: ProtocolHash;
    readonly shareVectorWidth: number;
    readonly commitmentPolynomialVector?: readonly (readonly DecimalIntegerString[])[];
    readonly commitmentBodyHash: ProtocolHash;
    readonly shareCommitmentHash: ProtocolHash;
};

/** Canonical statement for a scoped relation-bearing encoded-score ballot proof. */
export type BallotProofStatement = {
    readonly objectType: 'BallotProofStatement';
    readonly objectVersion: 1;
    readonly ballotProofStatementHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly thresholdProfileHash: ProtocolHash;
    readonly duplicateBallotPolicyHash: ProtocolHash;
    readonly scoreDomainHash: ProtocolHash;
    readonly tiePolicyHash: ProtocolHash;
    readonly topOptionCount: number;
    readonly optionCount: number;
    readonly shareVectorWidth: number;
    readonly voterIdentityHash: ProtocolHash;
    readonly voterRosterPosition: number;
    readonly voterSigningKeyHash: ProtocolHash;
    readonly actionContextHash: ProtocolHash;
    readonly rosterExternalAcceptanceHash: ProtocolHash;
    readonly receiverKeyRoot: ProtocolHash;
    readonly receiverKeyProofRoot: ProtocolHash;
    readonly receiverPublicKeys: readonly BallotProofReceiverPublicKeyReference[];
    readonly receiverPayloads: readonly BallotProofReceiverPayloadReference[];
    readonly shareCommitments: readonly BallotProofShareCommitmentReference[];
    readonly shareCommitmentProfileHash: ProtocolHash;
    readonly receiverEncryptionProfileHash: ProtocolHash;
    readonly ballotProofProfileHash: ProtocolHash;
    readonly scoreMembershipProfileHash: ProtocolHash;
    readonly ballotScoreEncodingProfileHash: ProtocolHash;
    readonly ballotShareLayoutProfileHash: ProtocolHash;
    readonly aggregateInputEncodingProfileHash: ProtocolHash;
    readonly encodedShareVectorLayoutHash: ProtocolHash;
    readonly encodedAggregateLayoutHash: ProtocolHash;
    readonly shareCommitmentMessageBoundCertHash: ProtocolHash;
    readonly ballotPackageHash: ProtocolHash;
    readonly challengeDomainHash: ProtocolHash;
};

/** Proof record binding ballot proof bytes, challenge material, and component coverage. */
export type BallotProofRecord = {
    readonly objectType: 'BallotProofRecord';
    readonly objectVersion: 1;
    readonly ballotProofRecordHash: ProtocolHash;
    readonly ballotProofStatementHash: ProtocolHash;
    readonly backendStatementHash?: ProtocolHash;
    readonly componentBundleStatementHash?: ProtocolHash;
    readonly componentProofBundleHash?: ProtocolHash;
    readonly relationStatementHash: ProtocolHash;
    readonly linearStatementHash?: ProtocolHash;
    readonly statementMatrixHash?: ProtocolHash;
    readonly targetVectorHash?: ProtocolHash;
    readonly ballotProofProfileHash: ProtocolHash;
    readonly proofBackend: 'LocalLinearLatticeRelation';
    readonly challengeHash: ProtocolHash;
    readonly proofRoot: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofEncodingProfileHash?: ProtocolHash;
    readonly proofParameterSetHash?: ProtocolHash;
    readonly proofSizeBytes: number;
    readonly publicRandomnessHash?: ProtocolHash;
};

/** Certificate/workbook row evidence for one frozen dynamic accepted ballot roster size. */
export type BallotPrivacyRosterProfileEvidence = {
    readonly objectType: 'BallotPrivacyRosterProfileEvidence';
    readonly objectVersion: 1;
    readonly rosterProfileEvidenceHash: ProtocolHash;
    readonly profileFamily: 'BalancedDefault';
    readonly frozenRosterSize: number;
    readonly optionCount: number;
    readonly thresholdProfileHash: ProtocolHash;
    readonly dynamicRosterProfileCertificateHash: ProtocolHash;
    readonly receiverCoverageProfile: 'AllFrozenRosterReceivers';
    readonly proofStatementShape: 'EncodedScoreBallotProof-v1';
};

/** Public ballot package shell containing the proof statement, proof record, and supplied verifier inputs. */
export type ClaimBearingBallotPackage = {
    readonly objectType: 'ClaimBearingBallotPackage';
    readonly objectVersion: 1;
    readonly ballotPackageHash: ProtocolHash;
    readonly ballotProofStatement: BallotProofStatement;
    readonly ballotProof: BallotProofRecord;
    readonly receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidence;
    readonly proofBytesHex?: string;
    readonly linearStatement?: unknown;
    readonly parameterSet?: unknown;
    readonly proofEncoding?: unknown;
    readonly publicRandomnessHex?: string;
    readonly dynamicRosterProfileEvidence?: BallotPrivacyRosterProfileEvidence;
    readonly componentBundleStatement?: unknown;
    readonly componentProofBundle?: BallotProofComponentProofBundle;
    readonly componentProofInputs?: readonly BallotProofComponentProofVerificationInput[];
    readonly receiverPayloads: readonly ReceiverPayload[];
    readonly shareCommitments: readonly ShareCommitment[];
};

/** Canonical public commitment to one contributor's post-close aggregate share opening. */
export type AggregateShareCommitment = {
    readonly objectType: 'AggregateShareCommitment';
    readonly objectVersion: 1;
    readonly aggregateShareCommitmentHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly ballotSetHash: ProtocolHash;
    readonly contributorIdentity: string;
    readonly contributorRosterPosition: number;
    readonly shareCommitmentProfileHash: ProtocolHash;
    readonly shareVectorWidth: number;
    readonly commitmentPolynomialVector: readonly (readonly DecimalIntegerString[])[];
    readonly commitmentBodyHash: ProtocolHash;
};

/** Public counted-ballot reference bound into an aggregate derivation statement. */
export type AggregateDerivationPackageReference = {
    readonly ballotPackageHash: ProtocolHash;
    readonly ballotProofStatementHash: ProtocolHash;
    readonly receiverPayloadHash: ProtocolHash;
    readonly receiverPayloadCiphertextRoot: ProtocolHash;
    readonly shareCommitmentHash: ProtocolHash;
};

/** Public statement for the aggregate derivation proof. */
export type AggregateDerivationStatement = {
    readonly objectType: 'AggregateDerivationStatement';
    readonly objectVersion: 1;
    readonly aggregateDerivationStatementHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly thresholdProfileHash: ProtocolHash;
    readonly ballotSetHash: ProtocolHash;
    readonly votingClosedBoardHeadHash: ProtocolHash;
    readonly closeRecordHash: ProtocolHash;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly contributorIdentity: string;
    readonly contributorRosterPosition: number;
    readonly contributorRosterExternalAcceptanceHash: ProtocolHash;
    readonly contributorActionContextHash: ProtocolHash;
    readonly packageReferences: readonly AggregateDerivationPackageReference[];
    readonly aggregateShareCommitmentHash: ProtocolHash;
    readonly aggregateCommitmentHash: ProtocolHash;
    readonly receiverEncryptionProfileHash: ProtocolHash;
    readonly shareCommitmentProfileHash: ProtocolHash;
    readonly shareCommitmentMessageBoundCertHash: ProtocolHash;
    readonly ballotScoreEncodingProfileHash: ProtocolHash;
    readonly ballotShareLayoutProfileHash: ProtocolHash;
    readonly aggregateInputEncodingProfileHash: ProtocolHash;
    readonly encodedShareVectorLayoutHash: ProtocolHash;
    readonly encodedAggregateLayoutHash: ProtocolHash;
    readonly optionCount: number;
    readonly participantCount: number;
    readonly casualMicroRosterAcknowledged?: true;
    readonly shareVectorWidth: number;
    readonly canonicalTurnout: number;
    readonly proofProfileId: string;
    readonly proofParameterProfileId: string;
    readonly proofEncodingProfileId: string;
    readonly challengeDomainHash: ProtocolHash;
};

/** Public proof verifier input for the aggregate derivation relation. */
export type AggregateDerivationProofVerificationInput = {
    readonly componentId: 'aggregate-derivation-component';
    readonly componentProofStatementHash: ProtocolHash;
    readonly proofBytesHex: string;
    readonly proofEncoding: unknown;
    readonly proofParameterSet: unknown;
    readonly proofStatement: unknown;
    readonly proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1';
    readonly publicRandomnessHex: string;
    readonly statementHash: ProtocolHash;
};

/** Proof-byte-bearing public record for the aggregate derivation component. */
export type AggregateDerivationProofRecord = {
    readonly objectType: 'AggregateDerivationProofRecord';
    readonly objectVersion: 1;
    readonly aggregateDerivationProofRecordHash: ProtocolHash;
    readonly aggregateDerivationStatementHash: ProtocolHash;
    readonly aggregateShareCommitmentHash: ProtocolHash;
    readonly componentId: 'aggregate-derivation-component';
    readonly componentProofStatementHash: ProtocolHash;
    readonly proofBackend: 'LocalLinearLatticeRelation';
    readonly proofRoot: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofEncodingProfileHash: ProtocolHash;
    readonly proofParameterSetHash: ProtocolHash;
    readonly proofSizeBytes: number;
    readonly publicRandomnessHash: ProtocolHash;
};

/** Public aggregate derivation component. */
export type AggregateDerivationComponent = {
    readonly objectType: 'AggregateDerivationComponent';
    readonly objectVersion: 1;
    readonly aggregateDerivationComponentHash: ProtocolHash;
    readonly statement: AggregateDerivationStatement;
    readonly aggregateCommitment: AggregateShareCommitment;
    readonly proofRecord: AggregateDerivationProofRecord;
    readonly proofInput: AggregateDerivationProofVerificationInput;
    readonly shareCommitmentMessageBoundCert: ShareCommitmentMessageBoundCert;
};

/** Structured result returned by aggregate derivation component verification. */
export type AggregateDerivationVerification =
    StructuredProtocolVerificationResult & {
        readonly backendAvailable: boolean;
        readonly aggregateDerivationComponentHash?: ProtocolHash;
    };

export type BridgeProofVerificationStatus =
    | 'BridgeProofBackendPending'
    | 'BridgeProofRelationChecked';

export type BridgeClaimVerificationStatus =
    | 'BridgeProofClaimClosureMissing'
    | 'BridgeProofClaimClosureVerified';

export type AggregateDerivationVerificationScope =
    | 'AggregateDerivationFullVerificationPreconditionNotBound'
    | 'AggregateDerivationFullVerificationChecked';

export type BridgeProofRecord = {
    readonly objectType: 'BridgeProofRecord';
    readonly objectVersion: 1;
    readonly aggregateDerivationComponentHash: ProtocolHash;
    readonly aggregateDerivationVerificationScope: AggregateDerivationVerificationScope;
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly aggregateShareCommitmentHash: ProtocolHash;
    readonly aggregateBridgeRelationHandoffRoot: ProtocolHash;
    readonly aggregateInputEncodingProfileHash: ProtocolHash;
    readonly ballotScoreEncodingProfileHash: ProtocolHash;
    readonly ballotSetHash: ProtocolHash;
    readonly ballotShareLayoutProfileHash: ProtocolHash;
    readonly bgvBatchEncoderHash: ProtocolHash;
    readonly bgvEncryptionKeyMaterialKind: 'passive-transcript-derived-collective-public-key';
    readonly bgvEncryptionProofSubrelation: 'SealedLatticePassiveCollectiveCiphertextEquationRelation';
    readonly bgvProfileHash: ProtocolHash;
    readonly bgvPublicKeyRoot: ProtocolHash;
    readonly bridgeLayoutHash: ProtocolHash;
    readonly bridgeProofProfileHash: ProtocolHash;
    readonly bridgeProofProfileId: string;
    readonly bridgeProofRecordHash: ProtocolHash;
    readonly bridgeProofChallengeContextHash: ProtocolHash;
    readonly bridgeProofTargetContractHash: ProtocolHash;
    readonly bridgeProofVerificationStatus: BridgeProofVerificationStatus;
    readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
    readonly bridgeClaimClosureVerified: boolean;
    readonly bridgeClaimVerificationStatus: BridgeClaimVerificationStatus;
    readonly claimBearingBridgeEncryption: boolean;
    readonly canonicalCiphertextConventionHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
    readonly contributorActionContextHash: ProtocolHash;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceHash: ProtocolHash;
    readonly contributorRosterPosition: number;
    readonly developmentKeyOnly: false;
    readonly encodedAggregateLayoutHash: ProtocolHash;
    readonly encodedShareVectorLayoutHash: ProtocolHash;
    readonly encryptedAggregateBridgeHash: ProtocolHash;
    readonly encryptedAggregateInputLayoutHash: ProtocolHash;
    readonly encryptedAggregateInputRoot: ProtocolHash;
    readonly encryptedAggregateReconstructionHash: ProtocolHash;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolHash;
    readonly encryptedAggregateTargetBasisRoot: ProtocolHash;
    readonly heParamHash: ProtocolHash;
    readonly manifestHash: ProtocolHash;
    readonly optionCount: number;
    readonly participantCount: number;
    readonly pollSpecHash: ProtocolHash;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly proofBackend: 'SealedLatticeBridgeRelation';
    readonly proofBytesHash: ProtocolHash;
    readonly proofEncodingProfileHash: ProtocolHash;
    readonly proofParameterSetHash: ProtocolHash;
    readonly proofRoot: ProtocolHash;
    readonly proofSizeBytes: number;
    readonly proofStatementHash: ProtocolHash;
    readonly publicRandomnessHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly rustBgvBackendProfileHash: ProtocolHash;
    readonly setupPackageHash: ProtocolHash;
    readonly shareCommitmentMessageBoundCertHash: ProtocolHash;
    readonly shareVectorWidth: number;
    readonly thresholdProfileHash: ProtocolHash;
    readonly thresholdDecryptable: true;
    readonly topKEvaluatorInputLayoutHash: ProtocolHash;
    readonly votingClosedBoardHeadHash: ProtocolHash;
};

export type AggregateContribution = {
    readonly objectType: 'AggregateContribution';
    readonly objectVersion: 1;
    readonly actionContext: ActionContext;
    readonly actionSequence: number;
    readonly aggregateContributionHash: ProtocolHash;
    readonly aggregateDerivationComponentHash: ProtocolHash;
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly aggregateShareCommitmentHash: ProtocolHash;
    readonly aggregateInputEncodingProfileHash: ProtocolHash;
    readonly ballotScoreEncodingProfileHash: ProtocolHash;
    readonly ballotSetHash: ProtocolHash;
    readonly ballotShareLayoutProfileHash: ProtocolHash;
    readonly bgvBatchEncoderHash: ProtocolHash;
    readonly bgvProfileHash: ProtocolHash;
    readonly bgvPublicKeyRoot: ProtocolHash;
    readonly boardPosition: number;
    readonly boardSequence: number;
    readonly bridgeLayoutHash: ProtocolHash;
    readonly bridgeProofProfileHash: ProtocolHash;
    readonly bridgeProofRecord: BridgeProofRecord;
    readonly bridgeProofRecordHash: ProtocolHash;
    readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
    readonly canonicalCiphertextConventionHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly closeRecordHash: ProtocolHash;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceHash: ProtocolHash;
    readonly contributorRosterPosition: number;
    readonly deviceEpoch: number;
    readonly encodedAggregateLayoutHash: ProtocolHash;
    readonly encodedShareVectorLayoutHash: ProtocolHash;
    readonly encryptedAggregateBridgeHash: ProtocolHash;
    readonly encryptedAggregateInputLayoutHash: ProtocolHash;
    readonly encryptedAggregateInputRoot: ProtocolHash;
    readonly encryptedAggregateReconstructionHash: ProtocolHash;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolHash;
    readonly encryptedAggregateTargetBasisRoot: ProtocolHash;
    readonly heParamHash: ProtocolHash;
    readonly manifestHash: ProtocolHash;
    readonly optionCount: number;
    readonly participantCount: number;
    readonly pollSpecHash: ProtocolHash;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly recoveryEpoch: number;
    readonly rosterHash: ProtocolHash;
    readonly rustBgvBackendProfileHash: ProtocolHash;
    readonly setupPackageHash: ProtocolHash;
    readonly shareCommitmentMessageBoundCertHash: ProtocolHash;
    readonly shareVectorWidth: number;
    readonly signature: ProtocolSignatureEnvelope;
    readonly thresholdProfileHash: ProtocolHash;
    readonly topKEvaluatorInputLayoutHash: ProtocolHash;
    readonly votingClosedBoardHeadHash: ProtocolHash;
};

export type AggregateContributionVerification =
    StructuredProtocolVerificationResult & {
        readonly aggregateContributionHash?: ProtocolHash;
        readonly backendAvailable: boolean;
        readonly bridgeProofRecordHash?: ProtocolHash;
    };

export type AggregateContributionSelectionInput = {
    readonly aggregateContributionQuorum: number;
    readonly contributions: readonly AggregateContribution[];
    readonly currentRecoveryEpochMap: Readonly<
        Record<string, RecoveryEpochMapEntry>
    >;
    readonly expectedAggregateSelectionPolicyHash: ProtocolHash;
    readonly requiredPostVotingClosedContextHash: ProtocolHash;
};

export type AggregateContributionSelection =
    StructuredProtocolVerificationResult & {
        readonly firstValidOrderHash?: ProtocolHash;
        readonly orderedContributionHashes: readonly ProtocolHash[];
        readonly selectedContributions: readonly AggregateContribution[];
    };

export type AggregateReadyRecordBuildInput = {
    readonly aggregateContributionQuorum: number;
    readonly firstValidOrderHash: ProtocolHash;
    readonly rosterSize: number;
    readonly selectedContributions: readonly AggregateContribution[];
    readonly suppliedInterpolationCoefficientReport?: InterpolationCoefficientReport;
};

export type AggregateReadyRecord = {
    readonly objectType: 'AggregateReadyRecord';
    readonly objectVersion: 1;
    readonly aggregateContributionQuorum: number;
    readonly aggregateReadyRecordHash: ProtocolHash;
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly ballotSetHash: ProtocolHash;
    readonly bgvBatchEncoderHash: ProtocolHash;
    readonly bgvProfileHash: ProtocolHash;
    readonly bridgeLayoutHash: ProtocolHash;
    readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
    readonly centeredL1CoefficientSum: number;
    readonly ceremonyId: string;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
    readonly encryptedAggregateBridgeHash: ProtocolHash;
    readonly encryptedAggregateInputLayoutHash: ProtocolHash;
    readonly encryptedAggregateReconstructionHash: ProtocolHash;
    readonly encryptedAggregateReconstructionRoot: ProtocolHash;
    readonly encryptedAggregateShareCiphertextRoots: readonly ProtocolHash[];
    readonly encryptedAggregateTargetBasisRoot: ProtocolHash;
    readonly firstValidOrderHash: ProtocolHash;
    readonly interpolationCoefficientReportHash: ProtocolHash;
    readonly interpolationCoefficients: InterpolationCoefficientReport['coefficients'];
    readonly manifestHash: ProtocolHash;
    readonly maxCenteredAbsCoefficient: number;
    readonly optionCount: number;
    readonly pollSpecHash: ProtocolHash;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly rosterSize: number;
    readonly selectedAggregateContributionHashes: readonly ProtocolHash[];
    readonly selectedContributorIdentities: readonly string[];
    readonly selectedContributorInterpolationPoints: readonly number[];
    readonly selectedContributorRosterPositions: readonly number[];
    readonly setupPackageHash: ProtocolHash;
    readonly shareVectorWidth: number;
    readonly thresholdProfileHash: ProtocolHash;
    readonly topKEvaluatorInputLayoutHash: ProtocolHash;
    readonly votingClosedBoardHeadHash: ProtocolHash;
};

/** Runtime status reported by the ballot privacy proof backend. */
export type BallotPrivacyProofBackendStatus = {
    readonly backendName: 'linear lattice proof backend';
    readonly backendAvailable: boolean;
    readonly portableRustWasmPortRequired: boolean;
    readonly requiredComponents: readonly string[];
    readonly blockedReason: string | null;
};

/** Structured verification result for ballot privacy shell and proof checks. */
export type BallotPrivacyVerification = StructuredProtocolVerificationResult & {
    readonly backendAvailable: boolean;
    readonly backendStatus?: BallotPrivacyProofBackendStatus;
};
