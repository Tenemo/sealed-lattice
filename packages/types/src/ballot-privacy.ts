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
