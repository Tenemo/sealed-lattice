import type { PublicationBody } from '#tests/publication-cut-model.js';

type EnvelopeBatch = Readonly<{
    sender: number;
    bodies: readonly PublicationBody[];
}>;

type PublicationReport = Readonly<{
    sender: number;
    witnessBatches: readonly EnvelopeBatch[];
}>;

// One immutable authenticated batch per honest participant and purpose. The
// registry is an ideal signature boundary, not production authentication.
export const createBatchedPublicationModel = (
    participantCount: number,
    corruptPositions: readonly number[],
) => {
    if (
        !Number.isInteger(participantCount) ||
        participantCount < 3 ||
        participantCount > 20
    )
        throw new RangeError('Unsupported publication roster.');
    const corruptionBound = Math.floor((participantCount - 1) / 3);
    const quorum = participantCount - corruptionBound;
    const corrupt = new Set(corruptPositions);
    if (
        corrupt.size !== corruptPositions.length ||
        corrupt.size > corruptionBound ||
        [...corrupt].some(
            (position) =>
                !Number.isInteger(position) ||
                position < 0 ||
                position >= participantCount,
        )
    )
        throw new RangeError('Invalid corruption set.');
    const witnessed = new Set<number>();
    const reported = new Set<number>();
    const issuedBatches = new Set<string>();
    const issuedReports = new Set<string>();
    const authored = new Set<string>();
    const attempted = new Set<number>();
    const checkPosition = (position: number) => {
        if (
            !Number.isInteger(position) ||
            position < 0 ||
            position >= participantCount
        )
            throw new RangeError('Invalid participant position.');
    };
    const submit = (body: PublicationBody): boolean => {
        checkPosition(body.slot);
        if (
            !corrupt.has(body.slot) &&
            (attempted.has(body.slot) || witnessed.has(body.slot))
        )
            return false;
        attempted.add(body.slot);
        authored.add(JSON.stringify(body));
        return true;
    };
    const witnessBatch = (
        sender: number,
        received: readonly PublicationBody[],
    ): EnvelopeBatch | undefined => {
        checkPosition(sender);
        if (!corrupt.has(sender) && witnessed.has(sender)) return;
        const firstBySlot = new Map<number, PublicationBody>();
        for (const body of received) {
            if (
                !authored.has(JSON.stringify(body)) ||
                firstBySlot.has(body.slot)
            )
                continue;
            firstBySlot.set(body.slot, structuredClone(body));
        }
        const batch = {
            sender,
            bodies: [...firstBySlot.values()].sort(
                (left, right) => left.slot - right.slot,
            ),
        };
        witnessed.add(sender);
        issuedBatches.add(JSON.stringify(batch));
        return structuredClone(batch);
    };
    const report = (
        sender: number,
        received: readonly EnvelopeBatch[],
    ): PublicationReport | undefined => {
        checkPosition(sender);
        if (
            !witnessed.has(sender) ||
            (!corrupt.has(sender) && reported.has(sender))
        )
            return;
        if (
            received.length < quorum ||
            received.length > participantCount ||
            new Set(received.map((batch) => batch.sender)).size !==
                received.length ||
            received.some((batch) => !issuedBatches.has(JSON.stringify(batch)))
        )
            return;
        const message = {
            sender,
            witnessBatches: [...received].sort(
                (left, right) => left.sender - right.sender,
            ),
        };
        reported.add(sender);
        issuedReports.add(JSON.stringify(message));
        return structuredClone(message);
    };
    const supportedBodies = (
        message: PublicationReport,
    ): readonly PublicationBody[] | undefined => {
        if (!issuedReports.has(JSON.stringify(message))) return;
        const counts = new Map<
            string,
            { body: PublicationBody; count: number }
        >();
        for (const batch of message.witnessBatches)
            for (const body of batch.bodies) {
                const identity = JSON.stringify(body);
                const entry = counts.get(identity) ?? { body, count: 0 };
                entry.count++;
                counts.set(identity, entry);
            }
        return [...counts.values()]
            .filter(({ count }) => count >= quorum)
            .map(({ body }) => structuredClone(body));
    };
    const inventory = (
        reports: readonly PublicationReport[],
    ): readonly PublicationBody[] | undefined => {
        if (
            reports.length !== quorum ||
            new Set(reports.map(({ sender }) => sender)).size !== quorum
        )
            return;
        const union = new Map<number, PublicationBody>();
        for (const message of reports) {
            const bodies = supportedBodies(message);
            if (bodies === undefined) return;
            for (const body of bodies) {
                const previous = union.get(body.slot);
                if (
                    previous !== undefined &&
                    JSON.stringify(previous) !== JSON.stringify(body)
                )
                    return;
                union.set(body.slot, body);
            }
        }
        return [...union.values()].sort(
            (left, right) => left.slot - right.slot,
        );
    };
    return { quorum, submit, witnessBatch, report, supportedBodies, inventory };
};

export const compileBatchedPublicationVisitCensus = () => {
    const stages = [
        'registration-and-recipient-key',
        'roster-confirmation-and-setup-commitment',
        'setup-opening',
        'optional-ballot-attempt',
        'envelope-witness-batch',
        'publication-report',
        'target-signature',
        'release-share',
        'terminal-retrieval',
    ] as const;
    return {
        stages,
        maximumParticipantStages: stages.length,
        maximumNoResultStages: stages.filter(
            (stage) => stage !== 'release-share',
        ).length,
    };
};
