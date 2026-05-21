export const ballotPrivacyMaximumOptionCount = 20 as const;
export const ballotPrivacyMinimumOptionCount = 2 as const;
export const ballotPrivacyScoreBucketCount = 10 as const;
export const ballotPrivacyEncodedCoordinatesPerOption = 11 as const;
export const ballotPrivacyMandatoryOptionCount = 20 as const;
export const ballotPrivacyMandatoryReceiverCount = 20 as const;
export const ballotPrivacyMandatoryThreshold = 7 as const;
export const ballotPrivacyMandatoryShareVectorWidth = 220 as const;
export const ballotPrivacyMinimumUnsafeParticipantCount = 3 as const;
export const ballotPrivacyMinimumSafeParticipantCount = 20 as const;
export const ballotPrivacyMaximumParticipantCount = 50 as const;

export const ballotPrivacyFieldModulus = 65_537 as const;
export const ballotPrivacyMaximumCanonicalFieldElement = 65_536 as const;
export const ballotPrivacyMaximumFieldElementBitLength = 17 as const;
export const ballotPrivacyMaximumCertificateGatedTurnout = 50 as const;
export const ballotPrivacyMinimumSupportedTurnout = 3 as const;

export const receiverEncryptionModulus = 12_289 as const;
export const receiverEncryptionCiphertextModulus = '12289' as const;
export const receiverEncryptionModuleRank = 4 as const;
export const receiverEncryptionModuleDegree = 256 as const;
export const receiverEncryptionMessageScale = Math.floor(
    receiverEncryptionModulus / 2,
);
export const receiverEncryptionCenteredBinomialEta = 2 as const;
export const receiverEncryptionShortVectorInfinityNormBound = 2 as const;
export const receiverShareRepresentativeBitLength = 17 as const;
export const receiverOpeningRandomnessBitLength = 12 as const;

export const shareCommitmentModulusDecimal = '18446744069414584321' as const;
export const shareCommitmentModulus = 18_446_744_069_414_584_321n;
export const shareCommitmentModuleRank = 4 as const;
export const shareCommitmentModuleDegree = 256 as const;
export const shareCommitmentOpeningDimension = 64 as const;
export const shareCommitmentOpeningInfinityNormBound = 1_024 as const;
export const shareCommitmentMessageBound = '4611686017353646080' as const;

export const shareCommitmentOpeningRandomnessRangeWidth =
    shareCommitmentOpeningInfinityNormBound * 2 + 1;
export const shareCommitmentOpeningRandomnessSamplerDomain =
    'sealed.vote/internal/share-commitment/opening-randomness-v1';

export const mandatoryProfileProofSizeTargetBytes = 4_194_304 as const;
export const certificateGatedProfileProofSizeTargetBytes = 10_485_760 as const;

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
