// The product goals, stated independently of the models: a poll has 3 to 20
// participants, at most f = floor((n - 1) / 3) of them are corrupt, and at
// most f ballots can be left out. Release needs shares from at least f + 1
// participants and never fewer than 2, a result needs at least f + 2 accepted
// ballots, and closing needs n - f participants.

export const supportedParticipantCounts: readonly number[] = Array.from(
    { length: 20 - 3 + 1 },
    (_unused, index) => 3 + index,
);

export const goalThresholds = (participantCount: number) => {
    if (!supportedParticipantCounts.includes(participantCount))
        throw new RangeError(
            `A poll has 3 to 20 participants, not ${String(participantCount)}.`,
        );
    const maximumCorruptParticipantCount = Math.floor(
        (participantCount - 1) / 3,
    );
    return {
        maximumCorruptParticipantCount,
        resultReleaseThreshold: Math.max(maximumCorruptParticipantCount + 1, 2),
        minimumTurnout: maximumCorruptParticipantCount + 2,
        inventoryCertificateThreshold:
            participantCount - maximumCorruptParticipantCount,
    };
};
