// DFMS21 Corollary 4.8, specialized to a full-body hash commitment f(x,y)=y.
// Gamma=Gamma'=1. This is a QROM loss calculation, not a fixed-hash theorem.
export const compileCommitmentExtractionBound = (participantCount: number) => {
    if (
        !Number.isSafeInteger(participantCount) ||
        participantCount < 3 ||
        participantCount > 20
    )
        throw new RangeError('Unsupported participant count.');
    const corruptParticipantCount = Math.floor((participantCount - 1) / 3);
    const quantumQueryCount = 1n << 80n;
    const hashOutputBitLength = 512n;
    // Each honest participant freezes at most one complete inventory in each
    // of the seed and contribution commitment stages. Count losing views too.
    const extractedCommitmentCount =
        2n * BigInt(participantCount * corruptParticipantCount);
    const denominator = 1n << hashOutputBitLength;
    // sqrt(2)<3/2 and e<87/32 imply 8*sqrt(2)<12 and 40*e^2<296.
    const traceDistanceNumerator =
        12n *
        extractedCommitmentCount *
        (quantumQueryCount + extractedCommitmentCount) *
        (1n << (hashOutputBitLength / 2n));
    const openingMismatchNumerator =
        extractedCommitmentCount === 0n
            ? 0n
            : 12n *
                  extractedCommitmentCount *
                  (quantumQueryCount + 1n) *
                  (1n << (hashOutputBitLength / 2n)) +
              296n * (quantumQueryCount + extractedCommitmentCount + 1n) ** 3n +
              2n;
    const combinedFailureNumerator =
        traceDistanceNumerator + openingMismatchNumerator;
    let combinedFailureExponent: bigint | undefined;
    if (combinedFailureNumerator !== 0n) {
        combinedFailureExponent = 0n;
        while (
            combinedFailureNumerator << (combinedFailureExponent + 1n) <=
            denominator
        )
            combinedFailureExponent += 1n;
    }
    return {
        combinedFailureExponent,
        combinedFailureNumerator,
        denominator,
        extractedCommitmentCount,
        hashOutputBitLength,
        openingMismatchNumerator,
        quantumQueryCount,
        traceDistanceNumerator,
    };
};
