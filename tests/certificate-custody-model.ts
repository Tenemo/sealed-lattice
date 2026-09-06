const countBits = (mask: number): number => {
    let count = 0;
    for (let remaining = mask; remaining !== 0; remaining &= remaining - 1)
        count++;
    return count;
};

// Signature possession and full-certificate possession are separate facts.
// Missing senders' queued messages are not delivered in this experiment.
export const runCertificateCustodyCounterexample = (
    deliverEarlierHonestSends: boolean,
) => {
    const participantCount = 10;
    const quorum = 7;
    const collector = 0;
    const disappeared = new Set([0, 1, 2]);
    const corrupt = new Set([7, 8, 9]);
    const signers = Array.from({ length: quorum }, (_, position) => position);
    const signatureViews = Array.from(
        { length: participantCount },
        (_, position) => new Set(signers.includes(position) ? [position] : []),
    );
    signatureViews[collector] = new Set(signers);
    const continuingHonest = Array.from(
        { length: participantCount },
        (_, position) => position,
    ).filter(
        (position) => !disappeared.has(position) && !corrupt.has(position),
    );
    const recoverable = new Set<number>();
    for (const holder of continuingHonest)
        for (const signer of signatureViews[holder]) recoverable.add(signer);
    // All messages between continuing honest participants have now arrived.
    if (deliverEarlierHonestSends)
        for (const signer of signatureViews[collector]) recoverable.add(signer);
    return {
        quorum,
        fullCertificateExisted: signatureViews[collector].size === quorum,
        continuingHonestParticipants: continuingHonest.length,
        recoverableSignatures: recoverable.size,
        canRecoverCertificate: recoverable.size >= quorum,
    };
};

export const compileCertificateCustodyCensus = () => {
    const participantCount = 10;
    const corruptCount = Math.floor((participantCount - 1) / 3);
    const quorum = participantCount - corruptCount;
    const masks = Array.from(
        { length: 1 << participantCount },
        (_, mask) => mask,
    );
    const unavailableSets = masks.filter(
        (mask) => countBits(mask) === corruptCount,
    );
    const holderSets = masks.filter((mask) => countBits(mask) === quorum);
    let checkedConfigurations = 0;
    let minimumSurvivingHonestFullHolders = participantCount;
    for (const holders of holderSets)
        for (const corrupt of unavailableSets)
            for (const disappeared of unavailableSets) {
                const survivors = countBits(holders & ~(corrupt | disappeared));
                minimumSurvivingHonestFullHolders = Math.min(
                    minimumSurvivingHonestFullHolders,
                    survivors,
                );
                checkedConfigurations++;
            }
    return {
        participantCount,
        corruptCount,
        fullHolderThreshold: quorum,
        checkedConfigurations,
        minimumSurvivingHonestFullHolders,
        counterexample: runCertificateCustodyCounterexample(false),
    };
};
