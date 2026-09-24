type Payload = 'ballot' | 'close';
type QueueHead = Readonly<{ sender: number; round: number; payload: Payload }>;

// CKPS01 Figure 5 queue/proposal layer. Authentication and validated Byzantine
// agreement are ideal inputs; this is not an implementation of either one.
export const atomicCloseMarkerTrace = (participantCount: number) => {
    if (
        !Number.isSafeInteger(participantCount) ||
        participantCount < 4 ||
        participantCount > 20
    )
        throw new RangeError('Unsupported counterexample roster.');
    const faults = Math.floor((participantCount - 1) / 3);
    const quorum = participantCount - faults;
    const queues: Payload[][] = Array.from(
        { length: participantCount },
        () => [],
    );
    const signed = new Map<string, QueueHead>();
    const signHead = (
        sender: number,
        round: number,
        received?: QueueHead,
    ): QueueHead => {
        const scope = `${round}/${sender}`;
        if (signed.has(scope))
            throw new Error('A queue head was already signed.');
        // Figure 5 lines 3–6: use the oldest local item, or adopt the received
        // head when the local queue is empty. Adoption need not append to q.
        const payload = queues[sender][0] ?? received?.payload;
        if (!payload) throw new Error('No payload enables the round.');
        const head = { sender, round, payload };
        signed.set(scope, head);
        return head;
    };
    queues[0].push('ballot');
    const ballotHead = signHead(0, 0);
    queues[1].push('close');
    const closeHead = signHead(1, 0);
    for (let sender = 2; sender < participantCount; sender++)
        signHead(sender, 0, closeHead);

    const validates = (heads: readonly QueueHead[], round: number): boolean =>
        heads.length >= quorum &&
        new Set(heads.map((head) => head.sender)).size === heads.length &&
        heads.every(
            (head) =>
                signed.get(`${round}/${head.sender}`)?.payload ===
                    head.payload && head.round === round,
        );
    const including = [
        ballotHead,
        ...[...signed.values()]
            .filter((head) => head.sender !== 0)
            .slice(0, quorum - 1),
    ];
    const excluding = [...signed.values()]
        .filter((head) => head.sender !== 0)
        .slice(0, quorum);
    const deliver = (heads: readonly QueueHead[], round: number): Payload[] => {
        if (!validates(heads, round))
            throw new Error('Invalid queue-head certificate.');
        // A fixed order with ballots first is already the more favorable case.
        return [...new Set(heads.map((head) => head.payload))].sort();
    };
    const authenticatedPrefix = [...signed.values()];
    const firstBatch = deliver(including, 0);
    const closeFirstBatch = deliver(excluding, 0);
    // In the close-first branch, Figure 5 acknowledges/removes close. The
    // earlier ballot remains at participant zero's queue head in round one.
    queues[1].shift();
    const delayedBallotHead = signHead(0, 1);
    const secondRound = [delayedBallotHead];
    for (let sender = 1; sender < quorum; sender++)
        secondRound.push(signHead(sender, 1, delayedBallotHead));
    const completeAfterDelay = [...closeFirstBatch, ...deliver(secondRound, 1)];
    return {
        participantCount,
        quorum,
        invocationOrder: ['ballot', 'close'] as const,
        authenticatedPrefix,
        including,
        excluding,
        bothProposalsValidate:
            validates(including, 0) && validates(excluding, 0),
        delayedProposalValidates: validates(secondRound, 1),
        staleRoundProposalAccepted: validates(including, 1),
        firstBatch,
        completeAfterDelay,
        ballotBeforeCloseWithIncludingProposal:
            firstBatch.indexOf('ballot') < firstBatch.indexOf('close'),
        ballotBeforeCloseWithExcludingProposal:
            completeAfterDelay.indexOf('ballot') <
            completeAfterDelay.indexOf('close'),
        invalidDuplicateProposalAccepted: validates(
            [...excluding, excluding[0]],
            0,
        ),
    };
};
