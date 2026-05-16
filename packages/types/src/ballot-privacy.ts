import type { ProtocolDigest } from './protocol-digest.js';
import type { StructuredProtocolVerificationResult } from './protocol-objects.js';

export type DecimalIntegerString = string;

export type ReceiverEncryptionProfile = {
    readonly objectType: 'ReceiverEncryptionProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly scheme: 'LinearModuleLweRegev';
    readonly hardnessAssumption: 'Module-LWE';
    readonly ring: 'Z_q[X]/(X^256 + 1)';
    readonly moduleRank: 4;
    readonly moduleDegree: 256;
    readonly ciphertextModulus: DecimalIntegerString;
    readonly plaintextModulus: 2;
    readonly fieldElementBitLength: 17;
    readonly messageEncoding: 'BitSlicedCanonicalGF65537LittleEndian';
    readonly publicMatrixDerivationDomain: string;
    readonly secretDistribution: 'CenteredBinomialEta2';
    readonly errorDistribution: 'CenteredBinomialEta2';
    readonly encryptionRandomnessDistribution: 'CenteredBinomialEta2';
    readonly payloadBinding: {
        readonly encryptsReceiverShareVector: true;
        readonly encryptsShareCommitmentOpening: true;
        readonly bindsReceiverIdentity: true;
        readonly bindsReceiverRosterPosition: true;
        readonly bindsManifestDigest: true;
        readonly bindsRosterDigest: true;
        readonly bindsPollSpecDigest: true;
        readonly bindsVoterIdentityDigest: true;
        readonly bindsActionContextDigest: true;
    };
    readonly decryptionFailureTarget: '2^-128';
};

export type ShareCommitmentProfile = {
    readonly objectType: 'ShareCommitmentProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly shareCommitmentProfileDigest: ProtocolDigest;
    readonly scheme: 'AdditiveModuleSisCommitment';
    readonly hardnessAssumption: 'Module-SIS';
    readonly commitmentModulus: DecimalIntegerString;
    readonly moduleRank: 4;
    readonly moduleDegree: 256;
    readonly shareVectorWidth: 20;
    readonly messageFieldModulus: 65537;
    readonly messageRepresentativeMinimum: 0;
    readonly messageRepresentativeMaximum: 65536;
    readonly messageEncoding: 'CanonicalGF65537RepresentativeVector';
    readonly commitmentFormula: 'A_message * EncodeShareVector(S) + A_randomness * rho mod q_commit';
    readonly matrixDerivationDomain: string;
    readonly openingRandomnessDimension: 64;
    readonly openingRandomnessInfinityNormBound: number;
    readonly aggregateOpeningRandomnessMaximumTurnout: 50;
};

export type ScoreMembershipProfile = {
    readonly objectType: 'ScoreMembershipProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly scoreMembershipProfileDigest: ProtocolDigest;
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

export type BallotProofProfile = {
    readonly objectType: 'BallotProofProfile';
    readonly objectVersion: 1;
    readonly profileId: string;
    readonly ballotProofProfileDigest: ProtocolDigest;
    readonly proofSystem: 'LaZerStyleLocalLatticeRelation';
    readonly backendConstruction: 'LyubashevskyNguyenPlancon2022LinearProofsViaLaZer';
    readonly relationShape: 'LinearLatticeRelationsWithShortVectorAndOneHotMembership';
    readonly fiatShamirHash: 'Hash512-SHAKE256';
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
    readonly shareCommitmentMessageBoundCertDigest: ProtocolDigest;
    readonly profileId: string;
    readonly profileDigest: ProtocolDigest;
    readonly shareCommitmentProfileDigest: ProtocolDigest;
    readonly fieldModulus: 65537;
    readonly shareVectorWidth: 20;
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
    readonly ballotProofProfile: BallotProofProfile;
};

export type BallotPrivacyProfileDigests = {
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly shareCommitmentProfileDigest: ProtocolDigest;
    readonly scoreMembershipProfileDigest: ProtocolDigest;
    readonly ballotProofProfileDigest: ProtocolDigest;
};

export type ShareCommitmentMessageBoundCertVerification =
    StructuredProtocolVerificationResult & {
        readonly shareCommitmentMessageBoundCertDigest?: ProtocolDigest;
    };

export type BallotProofReceiverPublicKeyReference = {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly receiverPublicKeyDigest: ProtocolDigest;
};

export type BallotProofReceiverPayloadReference = {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly receiverPayloadDigest: ProtocolDigest;
    readonly receiverPayloadCiphertextRoot: ProtocolDigest;
};

export type BallotProofShareCommitmentReference = {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly shareCommitmentDigest: ProtocolDigest;
};

export type ReceiverEncryptionPublicKey = {
    readonly objectType: 'ReceiverEncryptionPublicKey';
    readonly objectVersion: 1;
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly keyMaterialDigest: ProtocolDigest;
    readonly receiverPublicKeyDigest: ProtocolDigest;
};

export type ReceiverKeyProof = {
    readonly objectType: 'ReceiverKeyProof';
    readonly objectVersion: 1;
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly receiverPublicKeyDigest: ProtocolDigest;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly proofBackend: 'LaZerStyleLocalLatticeRelation';
    readonly proofRoot: ProtocolDigest;
    readonly receiverKeyProofRoot: ProtocolDigest;
};

export type ReceiverPayload = {
    readonly objectType: 'ReceiverPayload';
    readonly objectVersion: 1;
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly voterIdentityDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly receiverPublicKeyDigest: ProtocolDigest;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly payloadContextDigest: ProtocolDigest;
    readonly ciphertextBodyDigest: ProtocolDigest;
    readonly receiverPayloadCiphertextRoot: ProtocolDigest;
    readonly receiverPayloadDigest: ProtocolDigest;
};

export type ShareCommitment = {
    readonly objectType: 'ShareCommitment';
    readonly objectVersion: 1;
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly shareCommitmentProfileDigest: ProtocolDigest;
    readonly shareVectorWidth: 20;
    readonly commitmentBodyDigest: ProtocolDigest;
    readonly shareCommitmentDigest: ProtocolDigest;
};

export type BallotProofStatement = {
    readonly objectType: 'BallotProofStatement';
    readonly objectVersion: 1;
    readonly ballotProofStatementDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly duplicateBallotPolicyDigest: ProtocolDigest;
    readonly scoreDomainDigest: ProtocolDigest;
    readonly tiePolicyDigest: ProtocolDigest;
    readonly topOptionCount: number;
    readonly optionCount: number;
    readonly shareVectorWidth: 20;
    readonly voterIdentityDigest: ProtocolDigest;
    readonly voterRosterPosition: number;
    readonly voterSigningKeyDigest: ProtocolDigest;
    readonly actionContextDigest: ProtocolDigest;
    readonly rosterExternalAcceptanceDigest: ProtocolDigest;
    readonly receiverKeyRoot: ProtocolDigest;
    readonly receiverKeyProofRoot: ProtocolDigest;
    readonly receiverPublicKeys: readonly BallotProofReceiverPublicKeyReference[];
    readonly receiverPayloads: readonly BallotProofReceiverPayloadReference[];
    readonly shareCommitments: readonly BallotProofShareCommitmentReference[];
    readonly shareCommitmentProfileDigest: ProtocolDigest;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly ballotProofProfileDigest: ProtocolDigest;
    readonly scoreMembershipProfileDigest: ProtocolDigest;
    readonly shareCommitmentMessageBoundCertDigest: ProtocolDigest;
    readonly ballotPackageDigest: ProtocolDigest;
    readonly challengeDomainDigest: ProtocolDigest;
};

export type BallotProofRecord = {
    readonly objectType: 'BallotProofRecord';
    readonly objectVersion: 1;
    readonly ballotProofRecordDigest: ProtocolDigest;
    readonly ballotProofStatementDigest: ProtocolDigest;
    readonly ballotProofProfileDigest: ProtocolDigest;
    readonly proofBackend: 'LaZerStyleLocalLatticeRelation';
    readonly challengeDigest: ProtocolDigest;
    readonly proofRoot: ProtocolDigest;
    readonly proofBytesDigest: ProtocolDigest;
    readonly proofSizeBytes: number;
};

export type ClaimBearingBallotPackage = {
    readonly objectType: 'BallotPackage';
    readonly objectVersion: 1;
    readonly ballotPackageDigest: ProtocolDigest;
    readonly ballotProofStatement: BallotProofStatement;
    readonly ballotProof: BallotProofRecord;
    readonly receiverPayloads: readonly ReceiverPayload[];
    readonly shareCommitments: readonly ShareCommitment[];
};

export type BallotPrivacyProofBackendStatus = {
    readonly backendName: 'LaZer-style linear lattice proof backend';
    readonly backendAvailable: false;
    readonly upstreamReference: 'lazer-crypto/lazer';
    readonly upstreamDirectDependencyUsableInBrowser: false;
    readonly portableRustWasmPortRequired: true;
    readonly requiredComponents: readonly string[];
    readonly upstreamReferenceFiles: readonly string[];
    readonly blockedReason: string;
};

export type BallotPrivacyVerification = StructuredProtocolVerificationResult & {
    readonly backendAvailable: boolean;
    readonly backendStatus?: BallotPrivacyProofBackendStatus;
};
