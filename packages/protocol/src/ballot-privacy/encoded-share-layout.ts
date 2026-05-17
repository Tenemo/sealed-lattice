export const ballotPrivacyMaximumOptionCount = 20 as const;
export const ballotPrivacyScoreBucketCount = 10 as const;
export const ballotPrivacyEncodedCoordinatesPerOption = 11 as const;
export const ballotPrivacyMandatoryOptionCount = 20 as const;
export const ballotPrivacyMandatoryShareVectorWidth = 220 as const;

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
