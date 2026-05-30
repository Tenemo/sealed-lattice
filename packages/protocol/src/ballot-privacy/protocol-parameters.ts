// THREE RINGS + ONE FIELD. Each modulus below pins a distinct algebraic structure:
//   65537 = GF(65537) prime field -> PVSS/score arithmetic (Shamir shares).
//   12289 = Module-LWE prime -> receiver encryption in Z_q[X]/(X^256+1).
//   18446744069414584321 = Goldilocks prime -> Module-SIS share-commitment ring.
// The rings are kept deliberately distinct so no scheme reuses another's modulus.
export const ballotPrivacyMaximumOptionCount = 20 as const;
export const ballotPrivacyMinimumOptionCount = 2 as const;
export const ballotPrivacyScoreBucketCount = 10 as const;
export const ballotPrivacyEncodedCoordinatesPerOption = 11 as const;
export const ballotPrivacyMandatoryOptionCount = 20 as const;
export const ballotPrivacyMandatoryReceiverCount = 20 as const;
export const ballotPrivacyMandatoryThreshold = 7 as const;
export const ballotPrivacyMandatoryShareVectorWidth = 220 as const;
export const ballotPrivacyMinimumUnsafeParticipantCount = 3 as const;
export const ballotPrivacyMinimumSafeParticipantCount = 10 as const;
export const ballotPrivacyMinimumSafeClaimBearingParticipantCount = 10 as const;
export const ballotPrivacyMaximumParticipantCount = 50 as const;

// Fermat prime 2^16+1 = GF(65537), the PVSS/score field. Elements 0..65536 need 17 bits.
export const ballotPrivacyFieldModulus = 65_537 as const;
export const ballotPrivacyMaximumCanonicalFieldElement = 65_536 as const;
export const ballotPrivacyMaximumFieldElementBitLength = 17 as const;
export const ballotPrivacyMaximumCertificateGatedTurnout = 50 as const;
export const ballotPrivacyMinimumSupportedTurnout = 3 as const;

// NTT-friendly Module-LWE prime for receiver encryption in ring Z_q[X]/(X^256+1).
export const receiverEncryptionModulus = 12_289 as const;
export const receiverEncryptionCiphertextModulus = '12289' as const;
export const receiverEncryptionModuleRank = 4 as const;
export const receiverEncryptionModuleDegree = 256 as const;
// floor(q/2): the LWE "encode a plaintext bit as q/2" scaling for message coordinates.
export const receiverEncryptionMessageScale = Math.floor(
    receiverEncryptionModulus / 2,
);
export const receiverEncryptionCenteredBinomialEta = 2 as const;
export const receiverEncryptionShortVectorInfinityNormBound = 2 as const;
export const receiverShareRepresentativeBitLength = 17 as const;
export const receiverOpeningRandomnessBitLength = 12 as const;

// Goldilocks prime 2^64 - 2^32 + 1 for the Module-SIS commitment ring.
export const shareCommitmentModulusDecimal = '18446744069414584321' as const;
export const shareCommitmentModulus = 18_446_744_069_414_584_321n;
export const shareCommitmentModuleRank = 4 as const;
export const shareCommitmentModuleDegree = 256 as const;
export const shareCommitmentOpeningDimension = 64 as const;
// Also reused as the bit-decomposition recentre offset (signed opening + 1024 >= 0).
export const shareCommitmentOpeningInfinityNormBound = 1_024 as const;
// No-wraparound ceiling (~q_commit/4 = floor(q/4)) aggregate share sums must stay below.
export const shareCommitmentMessageBound = '4611686017353646080' as const;

export const shareCommitmentOpeningRandomnessRangeWidth =
    shareCommitmentOpeningInfinityNormBound * 2 + 1;
export const shareCommitmentOpeningRandomnessSamplerDomain =
    'sealed.vote/internal/share-commitment/opening-randomness-v1';

export const mandatoryProfileProofSizeTargetBytes = 4_194_304 as const;
export const certificateGatedProfileProofSizeTargetBytes = 10_485_760 as const;

// Per-option coordinate layout: each option owns 11 contiguous coordinates ->
//   index 0 = scalar score, indexes 1..10 = one-hot buckets for scores 1..10.
export const getBallotPrivacyEncodedShareVectorWidth = (
    optionCount: number,
): number => optionCount * ballotPrivacyEncodedCoordinatesPerOption;

export const getBallotPrivacyScalarCoordinateIndex = (
    optionIndex: number,
): number => optionIndex * ballotPrivacyEncodedCoordinatesPerOption;

export const getBallotPrivacyScoreBucketCoordinateIndex = (
    optionIndex: number,
    scoreBucketValue: number,
): number =>
    optionIndex * ballotPrivacyEncodedCoordinatesPerOption + scoreBucketValue;
